#!/usr/bin/env python3
"""
Graph Neural Networks for Code Structure Analysis

This module implements advanced graph neural networks for understanding code structure:
- Code Abstract Syntax Tree (AST) analysis
- Control Flow Graph (CFG) analysis
- Data Flow Graph (DFG) analysis
- Call Graph analysis
- Combined multi-graph analysis
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple, Union
import networkx as nx
import numpy as np
from torch_geometric.nn import (
    GATConv, GCNConv, SAGEConv, TransformerConv,
    global_mean_pool, global_max_pool, global_add_pool
)
from torch_geometric.data import Data, Batch
import warnings

warnings.filterwarnings("ignore")


class ASTGraphEncoder(nn.Module):
    """Graph encoder for Abstract Syntax Trees"""

    def __init__(self, node_feature_dim: int, edge_feature_dim: int,
                 hidden_dim: int, num_layers: int = 3):
        super().__init__()

        self.node_feature_dim = node_feature_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # Node type embedding (for different AST node types)
        self.node_type_embedding = nn.Embedding(100, hidden_dim // 4)  # 100 different node types

        # Initial feature transformation
        self.node_projection = nn.Linear(node_feature_dim, hidden_dim)
        self.edge_projection = nn.Linear(edge_feature_dim, hidden_dim) if edge_feature_dim > 0 else None

        # Graph attention layers for AST structure
        self.ast_convs = nn.ModuleList([
            GATConv(
                hidden_dim,
                hidden_dim,
                heads=4,
                concat=False,
                dropout=0.1,
                edge_dim=hidden_dim if edge_feature_dim > 0 else None
            ) for _ in range(num_layers)
        ])

        # Normalization layers
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim) for _ in range(num_layers)
        ])

        # Hierarchical pooling for different AST levels
        self.hierarchical_pools = nn.ModuleList([
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Linear(hidden_dim, hidden_dim // 2)
        ])

        self.dropout = nn.Dropout(0.1)

    def forward(self, node_features: torch.Tensor, edge_index: torch.Tensor,
                node_types: torch.Tensor, edge_features: Optional[torch.Tensor] = None,
                batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Forward pass for AST graph encoder

        Args:
            node_features: Node features [num_nodes, node_feature_dim]
            edge_index: Edge connectivity [2, num_edges]
            node_types: Node types for embedding [num_nodes]
            edge_features: Edge features [num_edges, edge_feature_dim]
            batch: Batch assignment for nodes [num_nodes]

        Returns:
            Dictionary with graph embeddings and intermediate features
        """

        # Initial node embeddings
        x = self.node_projection(node_features)

        # Add node type embeddings
        type_emb = self.node_type_embedding(node_types)
        x = x + type_emb

        # Edge embeddings
        edge_attr = None
        if edge_features is not None and self.edge_projection is not None:
            edge_attr = self.edge_projection(edge_features)

        # Store intermediate representations for hierarchical analysis
        layer_outputs = []

        # Graph convolution layers
        for i, (conv, norm) in enumerate(zip(self.ast_convs, self.layer_norms)):
            residual = x
            x = conv(x, edge_index, edge_attr=edge_attr)
            x = norm(x + residual)  # Residual connection
            x = F.gelu(x)
            x = self.dropout(x)
            layer_outputs.append(x)

        # Hierarchical pooling at different levels
        if batch is not None:
            # Function-level pooling (top-level nodes)
            function_mask = node_types <= 5  # Assume first 5 types are function-level
            function_pool = global_mean_pool(x * function_mask.float().unsqueeze(-1), batch)

            # Statement-level pooling
            stmt_mask = (node_types > 5) & (node_types <= 20)  # Statement-level nodes
            stmt_pool = global_mean_pool(x * stmt_mask.float().unsqueeze(-1), batch)

            # Expression-level pooling
            expr_mask = node_types > 20  # Expression-level nodes
            expr_pool = global_mean_pool(x * expr_mask.float().unsqueeze(-1), batch)

            # Global pooling
            global_pool = global_mean_pool(x, batch)

            graph_embedding = torch.cat([function_pool, stmt_pool, expr_pool, global_pool], dim=-1)
        else:
            # Single graph case
            function_pool = torch.mean(x, dim=0, keepdim=True)
            graph_embedding = function_pool

        return {
            'node_embeddings': x,
            'graph_embedding': graph_embedding,
            'layer_outputs': layer_outputs,
            'hierarchical_pools': {
                'function': function_pool if batch is not None else function_pool,
                'statement': stmt_pool if batch is not None else torch.mean(x, dim=0, keepdim=True),
                'expression': expr_pool if batch is not None else torch.mean(x, dim=0, keepdim=True)
            }
        }


class ControlFlowGraphEncoder(nn.Module):
    """Graph encoder for Control Flow Graphs"""

    def __init__(self, node_feature_dim: int, hidden_dim: int, num_layers: int = 3):
        super().__init__()

        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # CFG-specific node features
        self.node_projection = nn.Linear(node_feature_dim, hidden_dim)

        # Control flow specific embeddings
        self.block_type_embedding = nn.Embedding(10, hidden_dim // 4)  # Basic block types

        # Graph convolutions for control flow
        self.cfg_convs = nn.ModuleList([
            SAGEConv(hidden_dim, hidden_dim, aggr='mean')
            for _ in range(num_layers)
        ])

        # Temporal/sequential modeling for control flow
        self.flow_lstm = nn.LSTM(hidden_dim, hidden_dim // 2, batch_first=True, bidirectional=True)

        # Branch and loop detection heads
        self.branch_detector = nn.Linear(hidden_dim, 3)  # if, switch, loop
        self.loop_detector = nn.Linear(hidden_dim, 4)    # for, while, do-while, none

        self.dropout = nn.Dropout(0.1)

    def forward(self, node_features: torch.Tensor, edge_index: torch.Tensor,
                block_types: torch.Tensor, batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """Forward pass for CFG encoder"""

        # Initial embeddings
        x = self.node_projection(node_features)

        # Add block type information
        block_emb = self.block_type_embedding(block_types)
        x = x + block_emb

        # Graph convolutions
        for conv in self.cfg_convs:
            x = F.gelu(conv(x, edge_index))
            x = self.dropout(x)

        # Sequential modeling using LSTM (approximate execution order)
        if batch is not None:
            # Process each graph separately
            unique_batches = torch.unique(batch)
            lstm_outputs = []

            for b in unique_batches:
                mask = batch == b
                graph_nodes = x[mask]

                # Simple ordering by node index (could be improved with topological sort)
                lstm_out, _ = self.flow_lstm(graph_nodes.unsqueeze(0))
                lstm_outputs.append(lstm_out.squeeze(0))

            x_lstm = torch.cat(lstm_outputs, dim=0)
        else:
            lstm_out, _ = self.flow_lstm(x.unsqueeze(0))
            x_lstm = lstm_out.squeeze(0)

        # Combine original and LSTM features
        x_combined = x + x_lstm

        # Control flow pattern detection
        branch_logits = self.branch_detector(x_combined)
        loop_logits = self.loop_detector(x_combined)

        # Global pooling
        if batch is not None:
            graph_embedding = global_mean_pool(x_combined, batch)
            branch_probs = global_mean_pool(F.softmax(branch_logits, dim=-1), batch)
            loop_probs = global_mean_pool(F.softmax(loop_logits, dim=-1), batch)
        else:
            graph_embedding = torch.mean(x_combined, dim=0, keepdim=True)
            branch_probs = torch.mean(F.softmax(branch_logits, dim=-1), dim=0, keepdim=True)
            loop_probs = torch.mean(F.softmax(loop_logits, dim=-1), dim=0, keepdim=True)

        return {
            'node_embeddings': x_combined,
            'graph_embedding': graph_embedding,
            'control_flow_features': {
                'branch_probabilities': branch_probs,
                'loop_probabilities': loop_probs,
                'sequential_features': x_lstm
            }
        }


class DataFlowGraphEncoder(nn.Module):
    """Graph encoder for Data Flow Graphs"""

    def __init__(self, node_feature_dim: int, hidden_dim: int, num_layers: int = 3):
        super().__init__()

        self.hidden_dim = hidden_dim

        # Variable and operation type embeddings
        self.var_type_embedding = nn.Embedding(20, hidden_dim // 4)  # Variable types
        self.op_type_embedding = nn.Embedding(30, hidden_dim // 4)   # Operation types

        self.node_projection = nn.Linear(node_feature_dim, hidden_dim)

        # Data flow specific convolutions
        self.dfg_convs = nn.ModuleList([
            TransformerConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim,
                heads=4,
                concat=False,
                dropout=0.1
            ) for _ in range(num_layers)
        ])

        # Taint analysis head
        self.taint_propagation = nn.GRU(hidden_dim, hidden_dim, batch_first=True)
        self.taint_classifier = nn.Linear(hidden_dim, 2)  # Tainted or not

        # Use-def chain analysis
        self.usedef_attention = nn.MultiheadAttention(hidden_dim, num_heads=4, batch_first=True)

        self.dropout = nn.Dropout(0.1)

    def forward(self, node_features: torch.Tensor, edge_index: torch.Tensor,
                var_types: torch.Tensor, op_types: torch.Tensor,
                batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """Forward pass for DFG encoder"""

        # Initial embeddings
        x = self.node_projection(node_features)

        # Add variable and operation type embeddings
        var_emb = self.var_type_embedding(var_types)
        op_emb = self.op_type_embedding(op_types)
        x = x + var_emb + op_emb

        # Data flow convolutions
        for conv in self.dfg_convs:
            x = F.gelu(conv(x, edge_index))
            x = self.dropout(x)

        # Taint propagation analysis
        if batch is not None:
            unique_batches = torch.unique(batch)
            taint_outputs = []

            for b in unique_batches:
                mask = batch == b
                graph_nodes = x[mask]

                # Simulate taint propagation through data flow
                taint_out, _ = self.taint_propagation(graph_nodes.unsqueeze(0))
                taint_outputs.append(taint_out.squeeze(0))

            taint_features = torch.cat(taint_outputs, dim=0)
        else:
            taint_out, _ = self.taint_propagation(x.unsqueeze(0))
            taint_features = taint_out.squeeze(0)

        # Taint classification
        taint_logits = self.taint_classifier(taint_features)

        # Use-def chain analysis with self-attention
        if batch is not None:
            usedef_outputs = []
            for b in unique_batches:
                mask = batch == b
                graph_nodes = x[mask]

                usedef_out, usedef_weights = self.usedef_attention(
                    graph_nodes.unsqueeze(0),
                    graph_nodes.unsqueeze(0),
                    graph_nodes.unsqueeze(0)
                )
                usedef_outputs.append(usedef_out.squeeze(0))

            usedef_features = torch.cat(usedef_outputs, dim=0)
        else:
            usedef_features, _ = self.usedef_attention(x.unsqueeze(0), x.unsqueeze(0), x.unsqueeze(0))
            usedef_features = usedef_features.squeeze(0)

        # Combine all features
        combined_features = x + taint_features + usedef_features

        # Global pooling
        if batch is not None:
            graph_embedding = global_mean_pool(combined_features, batch)
            taint_graph = global_mean_pool(F.softmax(taint_logits, dim=-1), batch)
        else:
            graph_embedding = torch.mean(combined_features, dim=0, keepdim=True)
            taint_graph = torch.mean(F.softmax(taint_logits, dim=-1), dim=0, keepdim=True)

        return {
            'node_embeddings': combined_features,
            'graph_embedding': graph_embedding,
            'data_flow_features': {
                'taint_probabilities': taint_graph,
                'taint_node_logits': taint_logits,
                'usedef_features': usedef_features
            }
        }


class MultiGraphVulnDetector(nn.Module):
    """Multi-graph vulnerability detector combining AST, CFG, and DFG"""

    def __init__(self, config: Dict):
        super().__init__()

        self.config = config
        self.hidden_dim = config.get('hidden_dim', 256)
        self.num_classes = config.get('num_classes', 25)

        # Graph encoders
        self.ast_encoder = ASTGraphEncoder(
            node_feature_dim=config.get('ast_node_dim', 128),
            edge_feature_dim=config.get('ast_edge_dim', 64),
            hidden_dim=self.hidden_dim
        )

        self.cfg_encoder = ControlFlowGraphEncoder(
            node_feature_dim=config.get('cfg_node_dim', 64),
            hidden_dim=self.hidden_dim
        )

        self.dfg_encoder = DataFlowGraphEncoder(
            node_feature_dim=config.get('dfg_node_dim', 64),
            hidden_dim=self.hidden_dim
        )

        # Cross-graph attention for combining different graph types
        self.cross_graph_attention = nn.MultiheadAttention(
            embed_dim=self.hidden_dim * 4,  # AST has 4x hidden_dim output
            num_heads=8,
            batch_first=True
        )

        # Graph type embeddings
        self.graph_type_embedding = nn.Embedding(3, self.hidden_dim)  # AST, CFG, DFG

        # Fusion layers
        total_dim = self.hidden_dim * 4 + self.hidden_dim + self.hidden_dim  # AST + CFG + DFG
        self.graph_fusion = nn.Sequential(
            nn.Linear(total_dim, self.hidden_dim * 2),
            nn.LayerNorm(self.hidden_dim * 2),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(self.hidden_dim * 2, self.hidden_dim),
            nn.LayerNorm(self.hidden_dim),
            nn.GELU()
        )

        # Vulnerability-specific heads
        self.vulnerability_patterns = nn.ModuleDict({
            'buffer_overflow': self._create_pattern_head(),
            'injection': self._create_pattern_head(),
            'xss': self._create_pattern_head(),
            'auth_bypass': self._create_pattern_head(),
            'race_condition': self._create_pattern_head()
        })

        # Main classification heads
        self.vulnerability_classifier = nn.Sequential(
            nn.Linear(self.hidden_dim, self.hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(self.hidden_dim // 2, 1)
        )

        self.type_classifier = nn.Sequential(
            nn.Linear(self.hidden_dim, self.hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(self.hidden_dim // 2, self.num_classes)
        )

        # Explainability components
        self.attention_weights_storage = {}

    def _create_pattern_head(self) -> nn.Module:
        """Create a vulnerability pattern-specific classification head"""
        return nn.Sequential(
            nn.Linear(self.hidden_dim, self.hidden_dim // 4),
            nn.GELU(),
            nn.Linear(self.hidden_dim // 4, 1),
            nn.Sigmoid()
        )

    def forward(self,
                ast_data: Optional[Dict] = None,
                cfg_data: Optional[Dict] = None,
                dfg_data: Optional[Dict] = None,
                return_attention: bool = False) -> Dict[str, torch.Tensor]:
        """
        Forward pass combining multiple graph types

        Args:
            ast_data: AST graph data dictionary
            cfg_data: CFG graph data dictionary
            dfg_data: DFG graph data dictionary
            return_attention: Whether to return attention weights

        Returns:
            Dictionary with predictions and optional attention weights
        """

        graph_embeddings = []
        graph_features = {}

        # Process AST
        if ast_data is not None:
            ast_output = self.ast_encoder(**ast_data)
            graph_embeddings.append(ast_output['graph_embedding'])
            graph_features['ast'] = ast_output

        # Process CFG
        if cfg_data is not None:
            cfg_output = self.cfg_encoder(**cfg_data)
            graph_embeddings.append(cfg_output['graph_embedding'])
            graph_features['cfg'] = cfg_output

        # Process DFG
        if dfg_data is not None:
            dfg_output = self.dfg_encoder(**dfg_data)
            graph_embeddings.append(dfg_output['graph_embedding'])
            graph_features['dfg'] = dfg_output

        if not graph_embeddings:
            raise ValueError("At least one graph type must be provided")

        # Combine graph embeddings
        if len(graph_embeddings) == 1:
            combined_embedding = graph_embeddings[0]
        else:
            # Stack embeddings for cross-attention
            stacked_embeddings = torch.stack(graph_embeddings, dim=1)  # [batch, num_graphs, hidden_dim]

            # Cross-graph attention
            attended_embeddings, attention_weights = self.cross_graph_attention(
                stacked_embeddings, stacked_embeddings, stacked_embeddings
            )

            if return_attention:
                self.attention_weights_storage['cross_graph'] = attention_weights

            # Combine attended embeddings
            combined_embedding = torch.sum(attended_embeddings, dim=1)

        # Apply fusion layers
        if len(graph_embeddings) > 1:
            concatenated = torch.cat(graph_embeddings, dim=-1)
            fused_embedding = self.graph_fusion(concatenated)
        else:
            fused_embedding = self.graph_fusion(combined_embedding)

        # Vulnerability pattern detection
        pattern_outputs = {}
        for pattern_name, pattern_head in self.vulnerability_patterns.items():
            pattern_outputs[pattern_name] = pattern_head(fused_embedding).squeeze(-1)

        # Main predictions
        vulnerability_logits = self.vulnerability_classifier(fused_embedding)
        type_logits = self.type_classifier(fused_embedding)

        outputs = {
            'vulnerability': vulnerability_logits.squeeze(-1),
            'vuln_type': type_logits,
            'pattern_scores': pattern_outputs,
            'graph_features': graph_features,
            'fused_embedding': fused_embedding
        }

        if return_attention and 'cross_graph' in self.attention_weights_storage:
            outputs['attention_weights'] = self.attention_weights_storage

        return outputs


def create_sample_graph_data(num_nodes: int = 50, num_edges: int = 80) -> Dict:
    """Create sample graph data for testing"""

    # Sample AST data
    ast_data = {
        'node_features': torch.randn(num_nodes, 128),
        'edge_index': torch.randint(0, num_nodes, (2, num_edges)),
        'node_types': torch.randint(0, 50, (num_nodes,)),
        'edge_features': torch.randn(num_edges, 64),
        'batch': torch.zeros(num_nodes, dtype=torch.long)
    }

    # Sample CFG data
    cfg_data = {
        'node_features': torch.randn(num_nodes // 2, 64),
        'edge_index': torch.randint(0, num_nodes // 2, (2, num_edges // 2)),
        'block_types': torch.randint(0, 8, (num_nodes // 2,)),
        'batch': torch.zeros(num_nodes // 2, dtype=torch.long)
    }

    # Sample DFG data
    dfg_data = {
        'node_features': torch.randn(num_nodes // 3, 64),
        'edge_index': torch.randint(0, num_nodes // 3, (2, num_edges // 3)),
        'var_types': torch.randint(0, 15, (num_nodes // 3,)),
        'op_types': torch.randint(0, 25, (num_nodes // 3,)),
        'batch': torch.zeros(num_nodes // 3, dtype=torch.long)
    }

    return {
        'ast_data': ast_data,
        'cfg_data': cfg_data,
        'dfg_data': dfg_data
    }


def test_graph_networks():
    """Test the graph neural networks"""
    print("Testing Graph Neural Networks...")

    config = {
        'hidden_dim': 256,
        'num_classes': 25,
        'ast_node_dim': 128,
        'ast_edge_dim': 64,
        'cfg_node_dim': 64,
        'dfg_node_dim': 64
    }

    # Create model
    model = MultiGraphVulnDetector(config)

    # Create sample data
    sample_data = create_sample_graph_data()

    print(f"Sample AST nodes: {sample_data['ast_data']['node_features'].shape[0]}")
    print(f"Sample CFG nodes: {sample_data['cfg_data']['node_features'].shape[0]}")
    print(f"Sample DFG nodes: {sample_data['dfg_data']['node_features'].shape[0]}")

    # Test forward pass
    with torch.no_grad():
        outputs = model(
            ast_data=sample_data['ast_data'],
            cfg_data=sample_data['cfg_data'],
            dfg_data=sample_data['dfg_data'],
            return_attention=True
        )

    print("\nModel outputs:")
    for key, value in outputs.items():
        if isinstance(value, torch.Tensor):
            print(f"  {key}: {value.shape}")
        elif isinstance(value, dict):
            print(f"  {key}: {list(value.keys())}")

    # Count parameters
    num_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"\nNumber of parameters: {num_params:,}")

    print("\nGraph networks test completed successfully!")


if __name__ == "__main__":
    test_graph_networks()