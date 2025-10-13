#!/usr/bin/env python3
"""
BGNN4VD: Bidirectional Graph Neural Network for Vulnerability Detection
Complete implementation with PyTorch Geometric integration for VulnHunter AI.
"""

import json
import logging
import os
import ast
import pickle
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
import warnings

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from torch_geometric.nn import GCNConv, GATConv, GraphConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
from torch_geometric.utils import to_networkx, from_networkx
import torch_geometric.transforms as T
from torch_geometric.loader import DataLoader as GeometricDataLoader

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report
)
from sklearn.preprocessing import StandardScaler
import networkx as nx

# Import existing components
import sys
sys.path.append('/Users/ankitthakur/vuln_ml_research/vertex_ai_setup/data_pipeline')
from feature_store import VulnHunterFeatureStore
from dataset_manager import VulnHunterDatasetManager

warnings.filterwarnings('ignore')

@dataclass
class BGNN4VDConfig:
    """Configuration for BGNN4VD model"""
    # Graph construction parameters
    max_ast_depth: int = 10
    max_sequence_length: int = 512
    node_feature_dim: int = 128
    edge_feature_dim: int = 64

    # Model architecture parameters
    hidden_dim: int = 256
    num_gnn_layers: int = 6
    num_attention_heads: int = 8
    dropout_rate: float = 0.3

    # CNN classifier parameters
    cnn_channels: List[int] = None
    cnn_kernel_sizes: List[int] = None
    cnn_dropout: float = 0.2

    # Training parameters
    learning_rate: float = 0.001
    batch_size: int = 32
    num_epochs: int = 100
    early_stopping_patience: int = 10
    weight_decay: float = 1e-5

    def __post_init__(self):
        if self.cnn_channels is None:
            self.cnn_channels = [128, 64, 32]
        if self.cnn_kernel_sizes is None:
            self.cnn_kernel_sizes = [3, 3, 3]

class CodeGraphBuilder:
    """
    Builds graph representations from code using AST, CFG, and DFG analysis
    """

    def __init__(self, config: BGNN4VDConfig):
        self.config = config
        self.logger = self._setup_logging()

        # Node type mappings
        self.ast_node_types = self._get_ast_node_types()
        self.edge_types = {
            'ast_child': 0,
            'ast_parent': 1,
            'cfg_next': 2,
            'cfg_prev': 3,
            'dfg_def': 4,
            'dfg_use': 5,
            'call': 6,
            'semantic': 7
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('CodeGraphBuilder')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _get_ast_node_types(self) -> Dict[str, int]:
        """Get AST node type mappings"""
        node_types = [
            'Module', 'FunctionDef', 'ClassDef', 'Return', 'Delete', 'Assign', 'AugAssign',
            'AnnAssign', 'For', 'While', 'If', 'With', 'Raise', 'Try', 'Assert', 'Import',
            'ImportFrom', 'Global', 'Nonlocal', 'Expr', 'Pass', 'Break', 'Continue',
            'BoolOp', 'BinOp', 'UnaryOp', 'Lambda', 'IfExp', 'Dict', 'Set', 'ListComp',
            'SetComp', 'DictComp', 'GeneratorExp', 'Await', 'Yield', 'YieldFrom',
            'Compare', 'Call', 'Num', 'Str', 'FormattedValue', 'JoinedStr', 'Bytes',
            'NameConstant', 'Ellipsis', 'Constant', 'Attribute', 'Subscript', 'Starred',
            'Name', 'List', 'Tuple', 'Unknown'
        ]
        return {node_type: idx for idx, node_type in enumerate(node_types)}

    def code_to_graph(self, code: str) -> Optional[Data]:
        """
        Convert code string to PyTorch Geometric Data object

        Args:
            code: Source code string

        Returns:
            PyTorch Geometric Data object or None if parsing fails
        """
        try:
            # Parse AST
            tree = ast.parse(code)

            # Build graph from AST
            graph_data = self._build_ast_graph(tree, code)

            # Add CFG edges
            self._add_cfg_edges(graph_data, tree)

            # Add DFG edges
            self._add_dfg_edges(graph_data, tree)

            # Create bidirectional edges
            self._make_bidirectional(graph_data)

            # Convert to PyTorch Geometric format
            return self._to_pyg_data(graph_data)

        except Exception as e:
            self.logger.warning(f"Failed to parse code: {e}")
            return None

    def _build_ast_graph(self, tree: ast.AST, code: str) -> Dict[str, Any]:
        """Build initial graph from AST"""
        nodes = []
        edges = []
        node_features = []
        edge_features = []

        node_id_map = {}
        node_counter = 0

        def visit_node(node: ast.AST, parent_id: Optional[int] = None) -> int:
            nonlocal node_counter

            current_id = node_counter
            node_counter += 1

            # Get node type
            node_type = type(node).__name__
            node_type_id = self.ast_node_types.get(node_type, self.ast_node_types['Unknown'])

            # Extract node features
            features = self._extract_node_features(node, code)

            nodes.append({
                'id': current_id,
                'type': node_type,
                'type_id': node_type_id,
                'ast_node': node
            })

            node_features.append(features)
            node_id_map[id(node)] = current_id

            # Add edge to parent
            if parent_id is not None:
                edges.append((parent_id, current_id, 'ast_child'))
                edge_features.append(self._extract_edge_features('ast_child', nodes[parent_id], nodes[current_id]))

            # Visit children
            for child in ast.iter_child_nodes(node):
                child_id = visit_node(child, current_id)

            return current_id

        visit_node(tree)

        return {
            'nodes': nodes,
            'edges': edges,
            'node_features': node_features,
            'edge_features': edge_features,
            'node_id_map': node_id_map
        }

    def _extract_node_features(self, node: ast.AST, code: str) -> torch.Tensor:
        """Extract features for AST node"""
        features = torch.zeros(self.config.node_feature_dim)

        # Node type one-hot encoding
        node_type = type(node).__name__
        node_type_id = self.ast_node_types.get(node_type, self.ast_node_types['Unknown'])
        if node_type_id < self.config.node_feature_dim:
            features[node_type_id] = 1.0

        # Additional features based on node type
        feature_idx = len(self.ast_node_types)

        # String/numeric literal features
        if isinstance(node, (ast.Str, ast.Constant)) and isinstance(getattr(node, 'value', None), str):
            features[feature_idx] = 1.0  # Has string literal
            features[feature_idx + 1] = len(str(node.value)) / 100.0  # String length (normalized)
        feature_idx += 2

        if isinstance(node, (ast.Num, ast.Constant)) and isinstance(getattr(node, 'value', None), (int, float)):
            features[feature_idx] = 1.0  # Has numeric literal
            features[feature_idx + 1] = min(abs(float(node.value)) / 1000.0, 1.0)  # Value magnitude
        feature_idx += 2

        # Function/variable name features
        if hasattr(node, 'name') and node.name:
            features[feature_idx] = 1.0  # Has name
            features[feature_idx + 1] = len(node.name) / 20.0  # Name length
            # Check for dangerous function names
            dangerous_names = ['eval', 'exec', 'system', 'popen', 'shell']
            if any(dangerous in node.name.lower() for dangerous in dangerous_names):
                features[feature_idx + 2] = 1.0
        feature_idx += 3

        # Control flow features
        if isinstance(node, (ast.If, ast.For, ast.While)):
            features[feature_idx] = 1.0  # Control flow node
        if isinstance(node, ast.Try):
            features[feature_idx + 1] = 1.0  # Exception handling
        feature_idx += 2

        # Security-relevant features
        if isinstance(node, ast.Call):
            features[feature_idx] = 1.0  # Function call
            if hasattr(node.func, 'id'):
                func_name = node.func.id.lower()
                security_functions = ['input', 'raw_input', 'open', 'file', 'execfile']
                if any(sec_func in func_name for sec_func in security_functions):
                    features[feature_idx + 1] = 1.0  # Potentially dangerous call
        feature_idx += 2

        return features

    def _extract_edge_features(self, edge_type: str, source_node: Dict, target_node: Dict) -> torch.Tensor:
        """Extract features for edges"""
        features = torch.zeros(self.config.edge_feature_dim)

        # Edge type one-hot encoding
        edge_type_id = self.edge_types.get(edge_type, 0)
        if edge_type_id < self.config.edge_feature_dim:
            features[edge_type_id] = 1.0

        # Additional edge features
        feature_idx = len(self.edge_types)

        # Node type compatibility
        source_type = source_node['type_id']
        target_type = target_node['type_id']
        features[feature_idx] = abs(source_type - target_type) / len(self.ast_node_types)

        return features

    def _add_cfg_edges(self, graph_data: Dict[str, Any], tree: ast.AST):
        """Add control flow graph edges"""
        # Simplified CFG construction
        nodes = graph_data['nodes']
        edges = graph_data['edges']
        edge_features = graph_data['edge_features']

        # Find control flow nodes
        control_nodes = []
        for i, node_data in enumerate(nodes):
            node = node_data['ast_node']
            if isinstance(node, (ast.If, ast.For, ast.While, ast.FunctionDef)):
                control_nodes.append(i)

        # Add CFG edges between consecutive control flow nodes
        for i in range(len(control_nodes) - 1):
            source_id = control_nodes[i]
            target_id = control_nodes[i + 1]

            edges.append((source_id, target_id, 'cfg_next'))
            edge_features.append(self._extract_edge_features('cfg_next', nodes[source_id], nodes[target_id]))

    def _add_dfg_edges(self, graph_data: Dict[str, Any], tree: ast.AST):
        """Add data flow graph edges"""
        nodes = graph_data['nodes']
        edges = graph_data['edges']
        edge_features = graph_data['edge_features']

        # Simple variable definition/use analysis
        var_defs = {}  # variable -> list of definition node ids
        var_uses = {}  # variable -> list of use node ids

        for i, node_data in enumerate(nodes):
            node = node_data['ast_node']

            # Variable definitions
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if var_name not in var_defs:
                            var_defs[var_name] = []
                        var_defs[var_name].append(i)

            # Variable uses
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                var_name = node.id
                if var_name not in var_uses:
                    var_uses[var_name] = []
                var_uses[var_name].append(i)

        # Add def-use edges
        for var_name in var_defs:
            if var_name in var_uses:
                for def_id in var_defs[var_name]:
                    for use_id in var_uses[var_name]:
                        if def_id != use_id:
                            edges.append((def_id, use_id, 'dfg_def'))
                            edge_features.append(self._extract_edge_features('dfg_def', nodes[def_id], nodes[use_id]))

    def _make_bidirectional(self, graph_data: Dict[str, Any]):
        """Add backward edges to make the graph bidirectional"""
        edges = graph_data['edges']
        edge_features = graph_data['edge_features']
        nodes = graph_data['nodes']

        # Create reverse edges
        reverse_edges = []
        reverse_edge_features = []

        for edge, edge_feature in zip(edges, edge_features):
            source_id, target_id, edge_type = edge

            # Create reverse edge type
            reverse_type_map = {
                'ast_child': 'ast_parent',
                'cfg_next': 'cfg_prev',
                'dfg_def': 'dfg_use'
            }

            reverse_type = reverse_type_map.get(edge_type, edge_type)
            reverse_edges.append((target_id, source_id, reverse_type))
            reverse_edge_features.append(self._extract_edge_features(reverse_type, nodes[target_id], nodes[source_id]))

        # Add reverse edges
        edges.extend(reverse_edges)
        edge_features.extend(reverse_edge_features)

    def _to_pyg_data(self, graph_data: Dict[str, Any]) -> Data:
        """Convert graph data to PyTorch Geometric Data object"""
        nodes = graph_data['nodes']
        edges = graph_data['edges']
        node_features = graph_data['node_features']
        edge_features = graph_data['edge_features']

        # Create node feature matrix
        x = torch.stack(node_features)

        # Create edge index and edge attributes
        if edges:
            edge_index = torch.tensor([(e[0], e[1]) for e in edges], dtype=torch.long).t().contiguous()
            edge_attr = torch.stack(edge_features)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, self.config.edge_feature_dim))

        # Create PyTorch Geometric Data object
        data = Data(
            x=x,
            edge_index=edge_index,
            edge_attr=edge_attr,
            num_nodes=len(nodes)
        )

        return data

class BidirectionalMessagePassing(nn.Module):
    """
    Bidirectional message passing layer for BGNN4VD
    """

    def __init__(self, in_channels: int, out_channels: int, edge_dim: int, heads: int = 1, dropout: float = 0.0):
        super().__init__()

        self.in_channels = in_channels
        self.out_channels = out_channels
        self.heads = heads
        self.dropout = dropout

        # Forward and backward message passing
        self.forward_conv = GATConv(in_channels, out_channels // 2, heads=heads, dropout=dropout, edge_dim=edge_dim)
        self.backward_conv = GATConv(in_channels, out_channels // 2, heads=heads, dropout=dropout, edge_dim=edge_dim)

        # Combination layer
        self.combine = nn.Linear(out_channels, out_channels)
        self.batch_norm = nn.BatchNorm1d(out_channels)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_attr: torch.Tensor) -> torch.Tensor:
        # Split edges into forward and backward
        forward_mask = self._get_forward_edges_mask(edge_attr)
        backward_mask = ~forward_mask

        forward_edge_index = edge_index[:, forward_mask]
        forward_edge_attr = edge_attr[forward_mask]

        backward_edge_index = edge_index[:, backward_mask]
        backward_edge_attr = edge_attr[backward_mask]

        # Forward message passing
        forward_out = self.forward_conv(x, forward_edge_index, forward_edge_attr)

        # Backward message passing
        backward_out = self.backward_conv(x, backward_edge_index, backward_edge_attr)

        # Combine forward and backward information
        combined = torch.cat([forward_out, backward_out], dim=1)
        out = self.combine(combined)
        out = self.batch_norm(out)

        return F.relu(out)

    def _get_forward_edges_mask(self, edge_attr: torch.Tensor) -> torch.Tensor:
        """Identify forward edges based on edge attributes"""
        # Forward edges: ast_child, cfg_next, dfg_def
        forward_edge_types = [0, 2, 4]  # Indices of forward edge types

        forward_mask = torch.zeros(edge_attr.size(0), dtype=torch.bool)
        for edge_type_idx in forward_edge_types:
            if edge_type_idx < edge_attr.size(1):
                forward_mask |= (edge_attr[:, edge_type_idx] == 1)

        return forward_mask

class CNNClassifier(nn.Module):
    """
    CNN classifier for final feature processing
    """

    def __init__(self, input_dim: int, channels: List[int], kernel_sizes: List[int], dropout: float = 0.2):
        super().__init__()

        self.input_dim = input_dim
        self.channels = channels
        self.dropout = dropout

        # CNN layers
        layers = []
        in_channels = 1

        for out_channels, kernel_size in zip(channels, kernel_sizes):
            layers.extend([
                nn.Conv1d(in_channels, out_channels, kernel_size, padding=kernel_size//2),
                nn.BatchNorm1d(out_channels),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Dropout(dropout)
            ])
            in_channels = out_channels

        self.cnn_layers = nn.Sequential(*layers)

        # Calculate output size after CNN
        with torch.no_grad():
            dummy_input = torch.randn(1, 1, input_dim)
            cnn_output = self.cnn_layers(dummy_input)
            self.cnn_output_size = cnn_output.numel()

        # Final classification layers
        self.classifier = nn.Sequential(
            nn.Linear(self.cnn_output_size, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 2)  # Binary classification
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Add channel dimension for CNN
        x = x.unsqueeze(1)  # (batch, 1, features)

        # Apply CNN layers
        x = self.cnn_layers(x)

        # Flatten for classification
        x = x.view(x.size(0), -1)

        # Final classification
        return self.classifier(x)

class BGNN4VD(nn.Module):
    """
    Complete BGNN4VD model for vulnerability detection
    """

    def __init__(self, config: BGNN4VDConfig):
        super().__init__()

        self.config = config

        # Initial node embedding
        self.node_embedding = nn.Linear(config.node_feature_dim, config.hidden_dim)

        # Bidirectional GNN layers
        self.gnn_layers = nn.ModuleList([
            BidirectionalMessagePassing(
                in_channels=config.hidden_dim if i > 0 else config.hidden_dim,
                out_channels=config.hidden_dim,
                edge_dim=config.edge_feature_dim,
                heads=config.num_attention_heads,
                dropout=config.dropout_rate
            )
            for i in range(config.num_gnn_layers)
        ])

        # Graph-level pooling
        self.graph_pooling = nn.Linear(config.hidden_dim * 2, config.hidden_dim)  # mean + max pooling

        # CNN classifier
        self.cnn_classifier = CNNClassifier(
            input_dim=config.hidden_dim,
            channels=config.cnn_channels,
            kernel_sizes=config.cnn_kernel_sizes,
            dropout=config.cnn_dropout
        )

        # Dropout
        self.dropout = nn.Dropout(config.dropout_rate)

    def forward(self, batch: Batch) -> torch.Tensor:
        x, edge_index, edge_attr, batch_idx = batch.x, batch.edge_index, batch.edge_attr, batch.batch

        # Initial node embedding
        x = self.node_embedding(x)
        x = F.relu(x)

        # Apply bidirectional GNN layers
        for gnn_layer in self.gnn_layers:
            residual = x
            x = gnn_layer(x, edge_index, edge_attr)
            x = self.dropout(x)
            # Residual connection
            if residual.size() == x.size():
                x = x + residual

        # Graph-level representation
        mean_pool = global_mean_pool(x, batch_idx)
        max_pool = global_max_pool(x, batch_idx)
        graph_repr = torch.cat([mean_pool, max_pool], dim=1)
        graph_repr = self.graph_pooling(graph_repr)
        graph_repr = F.relu(graph_repr)

        # CNN classification
        logits = self.cnn_classifier(graph_repr)

        return logits

class VulnGraphDataset(Dataset):
    """
    Dataset for vulnerability detection with graph representations
    """

    def __init__(self, codes: List[str], labels: List[int], config: BGNN4VDConfig):
        self.codes = codes
        self.labels = labels
        self.config = config
        self.graph_builder = CodeGraphBuilder(config)

        # Pre-build graphs
        self.graphs = []
        self.valid_indices = []

        for i, code in enumerate(codes):
            graph = self.graph_builder.code_to_graph(code)
            if graph is not None:
                self.graphs.append(graph)
                self.valid_indices.append(i)

        print(f"Successfully created {len(self.graphs)} graphs from {len(codes)} code samples")

    def __len__(self):
        return len(self.graphs)

    def __getitem__(self, idx):
        graph = self.graphs[idx]
        original_idx = self.valid_indices[idx]
        label = self.labels[original_idx]

        # Add label to graph data
        graph.y = torch.tensor(label, dtype=torch.long)

        return graph

class BGNN4VDTrainer:
    """
    Trainer for BGNN4VD model with comprehensive evaluation
    """

    def __init__(self, config: BGNN4VDConfig, project_id: str, location: str = "us-central1"):
        self.config = config
        self.project_id = project_id
        self.location = location

        # Initialize components
        self.feature_store = VulnHunterFeatureStore(project_id, location)
        self.dataset_manager = VulnHunterDatasetManager(project_id, location)

        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.logger = self._setup_logging()

        # Model and training components
        self.model = None
        self.optimizer = None
        self.criterion = nn.CrossEntropyLoss()

        # Training metrics
        self.train_losses = []
        self.val_losses = []
        self.train_accuracies = []
        self.val_accuracies = []

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('BGNN4VDTrainer')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def prepare_data(self, dataset_name: str = None, codes: List[str] = None, labels: List[int] = None) -> Tuple[VulnGraphDataset, VulnGraphDataset]:
        """
        Prepare training and validation datasets

        Args:
            dataset_name: Name of dataset to load from dataset manager
            codes: List of code strings (if not using dataset_name)
            labels: List of vulnerability labels (if not using dataset_name)

        Returns:
            Tuple of (train_dataset, val_dataset)
        """
        try:
            if dataset_name:
                # Load from dataset manager
                datasets = self.dataset_manager.list_datasets()
                target_dataset = next((d for d in datasets if d['name'] == dataset_name), None)

                if not target_dataset:
                    raise ValueError(f"Dataset {dataset_name} not found")

                # Load dataset data (implementation would vary based on your dataset format)
                self.logger.info(f"Loading dataset: {dataset_name}")
                # This is a placeholder - you'd implement the actual loading logic
                codes = ["sample_code_1", "sample_code_2"]  # Replace with actual loading
                labels = [0, 1]  # Replace with actual labels

            # Create datasets
            total_size = len(codes)
            train_size = int(0.8 * total_size)

            train_codes = codes[:train_size]
            train_labels = labels[:train_size]
            val_codes = codes[train_size:]
            val_labels = labels[train_size:]

            train_dataset = VulnGraphDataset(train_codes, train_labels, self.config)
            val_dataset = VulnGraphDataset(val_codes, val_labels, self.config)

            self.logger.info(f"Prepared datasets: {len(train_dataset)} train, {len(val_dataset)} validation")

            return train_dataset, val_dataset

        except Exception as e:
            self.logger.error(f"Error preparing data: {e}")
            raise

    def train(self, train_dataset: VulnGraphDataset, val_dataset: VulnGraphDataset) -> Dict[str, Any]:
        """
        Train the BGNN4VD model

        Args:
            train_dataset: Training dataset
            val_dataset: Validation dataset

        Returns:
            Training results and metrics
        """
        try:
            # Initialize model
            self.model = BGNN4VD(self.config).to(self.device)
            self.optimizer = torch.optim.Adam(
                self.model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )

            # Data loaders
            train_loader = GeometricDataLoader(
                train_dataset,
                batch_size=self.config.batch_size,
                shuffle=True
            )
            val_loader = GeometricDataLoader(
                val_dataset,
                batch_size=self.config.batch_size,
                shuffle=False
            )

            self.logger.info(f"Starting training on {self.device}")
            self.logger.info(f"Model parameters: {sum(p.numel() for p in self.model.parameters()):,}")

            # Training loop
            best_val_acc = 0.0
            patience_counter = 0

            for epoch in range(self.config.num_epochs):
                # Training phase
                train_loss, train_acc = self._train_epoch(train_loader)

                # Validation phase
                val_loss, val_acc = self._validate_epoch(val_loader)

                # Record metrics
                self.train_losses.append(train_loss)
                self.val_losses.append(val_loss)
                self.train_accuracies.append(train_acc)
                self.val_accuracies.append(val_acc)

                self.logger.info(
                    f"Epoch {epoch+1}/{self.config.num_epochs}: "
                    f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}, "
                    f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}"
                )

                # Early stopping
                if val_acc > best_val_acc:
                    best_val_acc = val_acc
                    patience_counter = 0
                    # Save best model
                    torch.save(self.model.state_dict(), 'best_bgnn4vd_model.pth')
                else:
                    patience_counter += 1
                    if patience_counter >= self.config.early_stopping_patience:
                        self.logger.info(f"Early stopping at epoch {epoch+1}")
                        break

            # Load best model
            self.model.load_state_dict(torch.load('best_bgnn4vd_model.pth'))

            # Final evaluation
            final_metrics = self.evaluate(val_dataset)

            training_results = {
                'best_val_accuracy': best_val_acc,
                'final_metrics': final_metrics,
                'training_history': {
                    'train_losses': self.train_losses,
                    'val_losses': self.val_losses,
                    'train_accuracies': self.train_accuracies,
                    'val_accuracies': self.val_accuracies
                },
                'model_parameters': sum(p.numel() for p in self.model.parameters()),
                'training_time': datetime.now().isoformat()
            }

            return training_results

        except Exception as e:
            self.logger.error(f"Error in training: {e}")
            raise

    def _train_epoch(self, train_loader: GeometricDataLoader) -> Tuple[float, float]:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0

        for batch in train_loader:
            batch = batch.to(self.device)

            self.optimizer.zero_grad()

            logits = self.model(batch)
            loss = self.criterion(logits, batch.y)

            loss.backward()
            self.optimizer.step()

            total_loss += loss.item()
            pred = logits.argmax(dim=1)
            correct += pred.eq(batch.y).sum().item()
            total += batch.y.size(0)

        avg_loss = total_loss / len(train_loader)
        accuracy = correct / total

        return avg_loss, accuracy

    def _validate_epoch(self, val_loader: GeometricDataLoader) -> Tuple[float, float]:
        """Validate for one epoch"""
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0

        with torch.no_grad():
            for batch in val_loader:
                batch = batch.to(self.device)

                logits = self.model(batch)
                loss = self.criterion(logits, batch.y)

                total_loss += loss.item()
                pred = logits.argmax(dim=1)
                correct += pred.eq(batch.y).sum().item()
                total += batch.y.size(0)

        avg_loss = total_loss / len(val_loader)
        accuracy = correct / total

        return avg_loss, accuracy

    def evaluate(self, test_dataset: VulnGraphDataset) -> Dict[str, Any]:
        """
        Comprehensive evaluation of the model

        Args:
            test_dataset: Test dataset

        Returns:
            Evaluation metrics
        """
        try:
            self.model.eval()
            test_loader = GeometricDataLoader(test_dataset, batch_size=self.config.batch_size, shuffle=False)

            all_preds = []
            all_labels = []
            all_probs = []

            with torch.no_grad():
                for batch in test_loader:
                    batch = batch.to(self.device)
                    logits = self.model(batch)

                    probs = F.softmax(logits, dim=1)
                    preds = logits.argmax(dim=1)

                    all_preds.extend(preds.cpu().numpy())
                    all_labels.extend(batch.y.cpu().numpy())
                    all_probs.extend(probs[:, 1].cpu().numpy())  # Probability of positive class

            # Calculate metrics
            accuracy = accuracy_score(all_labels, all_preds)
            precision = precision_score(all_labels, all_preds)
            recall = recall_score(all_labels, all_preds)
            f1 = f1_score(all_labels, all_preds)
            auc = roc_auc_score(all_labels, all_probs)
            ap = average_precision_score(all_labels, all_probs)

            # Confusion matrix
            cm = confusion_matrix(all_labels, all_preds)

            # Classification report
            class_report = classification_report(all_labels, all_preds, output_dict=True)

            evaluation_results = {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'auc_roc': float(auc),
                'average_precision': float(ap),
                'confusion_matrix': cm.tolist(),
                'classification_report': class_report,
                'total_samples': len(all_labels),
                'positive_samples': sum(all_labels),
                'negative_samples': len(all_labels) - sum(all_labels)
            }

            self.logger.info(f"Evaluation Results:")
            self.logger.info(f"  Accuracy: {accuracy:.4f}")
            self.logger.info(f"  Precision: {precision:.4f}")
            self.logger.info(f"  Recall: {recall:.4f}")
            self.logger.info(f"  F1-Score: {f1:.4f}")
            self.logger.info(f"  AUC-ROC: {auc:.4f}")

            return evaluation_results

        except Exception as e:
            self.logger.error(f"Error in evaluation: {e}")
            raise

    def save_model(self, filepath: str, metadata: Dict[str, Any] = None):
        """Save trained model with metadata"""
        try:
            save_data = {
                'model_state_dict': self.model.state_dict(),
                'config': self.config.__dict__,
                'metadata': metadata or {},
                'timestamp': datetime.now().isoformat()
            }

            torch.save(save_data, filepath)
            self.logger.info(f"Model saved to {filepath}")

        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            raise

def main():
    """Demo usage of BGNN4VD"""

    # Configuration
    PROJECT_ID = "your-gcp-project-id"
    LOCATION = "us-central1"

    # Create BGNN4VD configuration
    config = BGNN4VDConfig(
        hidden_dim=128,  # Reduced for demo
        num_gnn_layers=4,  # Reduced for demo
        batch_size=16,  # Reduced for demo
        num_epochs=5,  # Reduced for demo
        early_stopping_patience=3
    )

    # Sample data for demo
    sample_codes = [
        # Vulnerable code examples
        """
def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE id = '" + user_input + "'"
    return execute_query(query)
        """,
        """
import os
def dangerous_exec(command):
    os.system(command)
    return "Executed"
        """,
        """
def buffer_overflow(input_data):
    buffer = [0] * 100
    for i in range(len(input_data)):
        buffer[i] = input_data[i]
    return buffer
        """,
        # Safe code examples
        """
def safe_function(user_input):
    if user_input.isdigit():
        return int(user_input)
    return None
        """,
        """
def secure_query(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return execute_prepared_query(query, (user_id,))
        """,
        """
def validate_input(data):
    if len(data) > 1000:
        raise ValueError("Input too long")
    return data.strip()
        """
    ]

    sample_labels = [1, 1, 1, 0, 0, 0]  # 1 = vulnerable, 0 = safe

    try:
        print("🚀 BGNN4VD Vulnerability Detection Demo")

        # Initialize trainer
        print(f"\n⚙️ Initializing BGNN4VD trainer...")
        trainer = BGNN4VDTrainer(config, PROJECT_ID, LOCATION)
        print(f"✅ Trainer initialized with device: {trainer.device}")

        # Prepare datasets
        print(f"\n📊 Preparing graph datasets...")
        train_dataset = VulnGraphDataset(sample_codes[:4], sample_labels[:4], config)
        val_dataset = VulnGraphDataset(sample_codes[4:], sample_labels[4:], config)
        print(f"✅ Datasets prepared: {len(train_dataset)} train, {len(val_dataset)} validation")

        # Train model
        print(f"\n🎯 Training BGNN4VD model...")
        training_results = trainer.train(train_dataset, val_dataset)
        print(f"✅ Training completed!")
        print(f"   Best validation accuracy: {training_results['best_val_accuracy']:.4f}")

        # Evaluation
        print(f"\n📈 Final evaluation results:")
        final_metrics = training_results['final_metrics']
        print(f"   Accuracy: {final_metrics['accuracy']:.4f}")
        print(f"   Precision: {final_metrics['precision']:.4f}")
        print(f"   Recall: {final_metrics['recall']:.4f}")
        print(f"   F1-Score: {final_metrics['f1_score']:.4f}")
        print(f"   AUC-ROC: {final_metrics['auc_roc']:.4f}")

        # Save model
        print(f"\n💾 Saving trained model...")
        model_metadata = {
            'training_samples': len(train_dataset) + len(val_dataset),
            'model_architecture': 'BGNN4VD',
            'final_accuracy': final_metrics['accuracy']
        }
        trainer.save_model('bgnn4vd_trained_model.pth', model_metadata)
        print(f"✅ Model saved!")

        print(f"\n✅ BGNN4VD demo completed successfully!")
        print(f"   🧠 Bidirectional GNN with {config.num_gnn_layers} layers")
        print(f"   🔗 Graph-based code representation")
        print(f"   📊 CNN classifier for final predictions")
        print(f"   🎯 Comprehensive vulnerability detection")

    except Exception as e:
        print(f"❌ Error in demo: {e}")
        raise

if __name__ == "__main__":
    main()