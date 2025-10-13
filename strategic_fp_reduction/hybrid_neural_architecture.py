"""
Hybrid Neural Architecture Integration for Vulnerability Detection
================================================================

This module implements a sophisticated hybrid neural architecture that integrates:
1. Multi-modal feature engineering outputs
2. Graph Neural Networks for structural code analysis
3. Transformer-based sequence modeling
4. Attention mechanisms for feature importance
5. Hierarchical learning architectures
6. Uncertainty quantification through Bayesian layers

Research shows that hybrid architectures combining multiple neural paradigms
can achieve 20-30% better performance than single-architecture approaches.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import TransformerEncoder, TransformerEncoderLayer
import torch_geometric
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
import math
import logging
from pathlib import Path
import json
import ast
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class HybridArchitectureConfig:
    """Configuration for hybrid neural architecture"""

    # Input dimensions
    multimodal_feature_dim: int = 2048  # From multi-modal feature engineering
    codebert_embedding_dim: int = 768   # CodeBERT embeddings
    graph_node_features: int = 64       # AST node features
    graph_edge_features: int = 32       # AST edge features

    # Architecture components
    enable_graph_neural_network: bool = True
    enable_transformer_encoder: bool = True
    enable_attention_mechanism: bool = True
    enable_hierarchical_learning: bool = True
    enable_bayesian_layers: bool = True

    # Graph Neural Network
    gnn_hidden_dim: int = 128
    gnn_num_layers: int = 3
    gnn_dropout: float = 0.2
    gnn_attention_heads: int = 4

    # Transformer Encoder
    transformer_hidden_dim: int = 512
    transformer_num_layers: int = 6
    transformer_num_heads: int = 8
    transformer_dropout: float = 0.1

    # Multi-head Attention
    attention_heads: int = 8
    attention_dropout: float = 0.1

    # Hierarchical Learning
    hierarchical_levels: int = 3
    hierarchical_hidden_dims: List[int] = field(default_factory=lambda: [512, 256, 128])

    # Bayesian Uncertainty
    bayesian_samples: int = 10
    prior_std: float = 1.0
    posterior_rho_init: float = -3.0

    # Output dimensions
    num_classes: int = 2  # Vulnerable vs Non-vulnerable
    final_hidden_dim: int = 256

class BayesianLinear(nn.Module):
    """Bayesian Linear Layer for uncertainty quantification"""

    def __init__(self, in_features: int, out_features: int, prior_std: float = 1.0):
        super(BayesianLinear, self).__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.prior_std = prior_std

        # Weight parameters
        self.weight_mu = nn.Parameter(torch.randn(out_features, in_features) * 0.1)
        self.weight_rho = nn.Parameter(torch.full((out_features, in_features), -3.0))

        # Bias parameters
        self.bias_mu = nn.Parameter(torch.randn(out_features) * 0.1)
        self.bias_rho = nn.Parameter(torch.full((out_features,), -3.0))

    def forward(self, x: torch.Tensor, sample: bool = True) -> torch.Tensor:
        if sample:
            # Sample weights and biases
            weight_std = torch.log1p(torch.exp(self.weight_rho))
            weight = self.weight_mu + weight_std * torch.randn_like(weight_std)

            bias_std = torch.log1p(torch.exp(self.bias_rho))
            bias = self.bias_mu + bias_std * torch.randn_like(bias_std)
        else:
            # Use mean parameters
            weight = self.weight_mu
            bias = self.bias_mu

        return F.linear(x, weight, bias)

    def kl_divergence(self) -> torch.Tensor:
        """Compute KL divergence with prior"""
        weight_var = torch.log1p(torch.exp(self.weight_rho)) ** 2
        bias_var = torch.log1p(torch.exp(self.bias_rho)) ** 2

        kl_weight = 0.5 * (
            torch.log(self.prior_std ** 2 / weight_var) +
            weight_var / (self.prior_std ** 2) +
            self.weight_mu ** 2 / (self.prior_std ** 2) - 1
        ).sum()

        kl_bias = 0.5 * (
            torch.log(self.prior_std ** 2 / bias_var) +
            bias_var / (self.prior_std ** 2) +
            self.bias_mu ** 2 / (self.prior_std ** 2) - 1
        ).sum()

        return kl_weight + kl_bias

class GraphNeuralNetwork(nn.Module):
    """Graph Neural Network for structural code analysis"""

    def __init__(self, config: HybridArchitectureConfig):
        super(GraphNeuralNetwork, self).__init__()
        self.config = config

        # Graph convolution layers
        self.conv_layers = nn.ModuleList()
        self.batch_norms = nn.ModuleList()

        input_dim = config.graph_node_features
        for i in range(config.gnn_num_layers):
            if i == 0:
                conv = GATConv(
                    input_dim,
                    config.gnn_hidden_dim // config.gnn_attention_heads,
                    heads=config.gnn_attention_heads,
                    dropout=config.gnn_dropout
                )
            else:
                conv = GATConv(
                    config.gnn_hidden_dim,
                    config.gnn_hidden_dim // config.gnn_attention_heads,
                    heads=config.gnn_attention_heads,
                    dropout=config.gnn_dropout
                )

            self.conv_layers.append(conv)
            self.batch_norms.append(nn.BatchNorm1d(config.gnn_hidden_dim))

        # Global pooling
        self.global_pool_mean = global_mean_pool
        self.global_pool_max = global_max_pool

        # Output projection
        self.output_proj = nn.Linear(config.gnn_hidden_dim * 2, config.gnn_hidden_dim)

    def forward(self, data: Data) -> torch.Tensor:
        x, edge_index, batch = data.x, data.edge_index, data.batch

        # Apply graph convolution layers
        for i, (conv, bn) in enumerate(zip(self.conv_layers, self.batch_norms)):
            x = conv(x, edge_index)
            x = bn(x)
            x = F.relu(x)

            if i < len(self.conv_layers) - 1:
                x = F.dropout(x, p=self.config.gnn_dropout, training=self.training)

        # Global pooling
        mean_pool = self.global_pool_mean(x, batch)
        max_pool = self.global_pool_max(x, batch)
        graph_repr = torch.cat([mean_pool, max_pool], dim=1)

        # Output projection
        graph_repr = self.output_proj(graph_repr)

        return graph_repr

class PositionalEncoding(nn.Module):
    """Positional encoding for transformer"""

    def __init__(self, d_model: int, max_len: int = 5000):
        super(PositionalEncoding, self).__init__()

        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)

        self.register_buffer('pe', pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:x.size(0), :]

class TransformerSequenceEncoder(nn.Module):
    """Transformer encoder for sequence modeling"""

    def __init__(self, config: HybridArchitectureConfig):
        super(TransformerSequenceEncoder, self).__init__()
        self.config = config

        # Input projection
        self.input_proj = nn.Linear(config.codebert_embedding_dim, config.transformer_hidden_dim)

        # Positional encoding
        self.pos_encoder = PositionalEncoding(config.transformer_hidden_dim)

        # Transformer encoder
        encoder_layer = TransformerEncoderLayer(
            d_model=config.transformer_hidden_dim,
            nhead=config.transformer_num_heads,
            dim_feedforward=config.transformer_hidden_dim * 4,
            dropout=config.transformer_dropout,
            batch_first=True
        )

        self.transformer_encoder = TransformerEncoder(
            encoder_layer,
            num_layers=config.transformer_num_layers
        )

        # Output projection
        self.output_proj = nn.Linear(config.transformer_hidden_dim, config.transformer_hidden_dim)

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        # Input projection
        x = self.input_proj(x)

        # Add positional encoding
        x = x.transpose(0, 1)  # (seq_len, batch_size, hidden_dim)
        x = self.pos_encoder(x)
        x = x.transpose(0, 1)  # (batch_size, seq_len, hidden_dim)

        # Apply transformer encoder
        x = self.transformer_encoder(x, src_key_padding_mask=mask)

        # Global average pooling
        if mask is not None:
            # Mask out padded positions
            mask_expanded = mask.unsqueeze(-1).expand_as(x)
            x = x.masked_fill(mask_expanded, 0.0)
            lengths = (~mask).sum(dim=1, keepdim=True).float()
            x = x.sum(dim=1) / lengths
        else:
            x = x.mean(dim=1)

        # Output projection
        x = self.output_proj(x)

        return x

class MultiHeadAttentionFusion(nn.Module):
    """Multi-head attention for feature fusion"""

    def __init__(self, config: HybridArchitectureConfig):
        super(MultiHeadAttentionFusion, self).__init__()
        self.config = config

        # Feature dimensions
        self.multimodal_dim = config.multimodal_feature_dim
        self.gnn_dim = config.gnn_hidden_dim
        self.transformer_dim = config.transformer_hidden_dim

        # Project all features to same dimension
        self.feature_dim = config.final_hidden_dim
        self.multimodal_proj = nn.Linear(self.multimodal_dim, self.feature_dim)
        self.gnn_proj = nn.Linear(self.gnn_dim, self.feature_dim)
        self.transformer_proj = nn.Linear(self.transformer_dim, self.feature_dim)

        # Multi-head attention
        self.multihead_attn = nn.MultiheadAttention(
            embed_dim=self.feature_dim,
            num_heads=config.attention_heads,
            dropout=config.attention_dropout,
            batch_first=True
        )

        # Layer normalization
        self.layer_norm = nn.LayerNorm(self.feature_dim)

        # Output projection
        self.output_proj = nn.Linear(self.feature_dim, self.feature_dim)

    def forward(self, multimodal_features: torch.Tensor,
                gnn_features: Optional[torch.Tensor] = None,
                transformer_features: Optional[torch.Tensor] = None) -> torch.Tensor:

        features = []

        # Project multimodal features
        multimodal_proj = self.multimodal_proj(multimodal_features)
        features.append(multimodal_proj)

        # Project GNN features if available
        if gnn_features is not None:
            gnn_proj = self.gnn_proj(gnn_features)
            features.append(gnn_proj)

        # Project transformer features if available
        if transformer_features is not None:
            transformer_proj = self.transformer_proj(transformer_features)
            features.append(transformer_proj)

        # Stack features for attention
        if len(features) == 1:
            # Only multimodal features, return directly
            return self.output_proj(features[0])

        # Create sequence for attention
        feature_sequence = torch.stack(features, dim=1)  # (batch_size, num_features, feature_dim)

        # Self-attention
        attn_output, attention_weights = self.multihead_attn(
            feature_sequence, feature_sequence, feature_sequence
        )

        # Residual connection and layer norm
        attn_output = self.layer_norm(attn_output + feature_sequence)

        # Global average pooling across features
        fused_features = attn_output.mean(dim=1)

        # Output projection
        output = self.output_proj(fused_features)

        return output

class HierarchicalLearningModule(nn.Module):
    """Hierarchical learning with multiple abstraction levels"""

    def __init__(self, config: HybridArchitectureConfig):
        super(HierarchicalLearningModule, self).__init__()
        self.config = config

        # Create hierarchical layers
        self.hierarchical_layers = nn.ModuleList()
        self.layer_norms = nn.ModuleList()
        self.dropouts = nn.ModuleList()

        input_dim = config.final_hidden_dim
        for i, hidden_dim in enumerate(config.hierarchical_hidden_dims):
            layer = nn.Linear(input_dim, hidden_dim)
            self.hierarchical_layers.append(layer)
            self.layer_norms.append(nn.LayerNorm(hidden_dim))
            self.dropouts.append(nn.Dropout(0.2))

            input_dim = hidden_dim

        # Skip connections
        self.skip_connections = nn.ModuleList()
        for i in range(1, len(config.hierarchical_hidden_dims)):
            skip_proj = nn.Linear(
                config.hierarchical_hidden_dims[i-1],
                config.hierarchical_hidden_dims[i]
            )
            self.skip_connections.append(skip_proj)

    def forward(self, x: torch.Tensor) -> List[torch.Tensor]:
        """Forward pass returning representations at all levels"""
        representations = []
        current = x

        for i, (layer, norm, dropout) in enumerate(zip(
            self.hierarchical_layers, self.layer_norms, self.dropouts
        )):
            # Apply layer
            current = layer(current)

            # Skip connection (except for first layer)
            if i > 0 and i-1 < len(self.skip_connections):
                skip = self.skip_connections[i-1](representations[i-1])
                current = current + skip

            # Normalization and activation
            current = norm(current)
            current = F.gelu(current)
            current = dropout(current)

            representations.append(current)

        return representations

class HybridVulnerabilityDetector(nn.Module):
    """Main hybrid neural architecture for vulnerability detection"""

    def __init__(self, config: HybridArchitectureConfig):
        super(HybridVulnerabilityDetector, self).__init__()
        self.config = config

        # Initialize components based on configuration
        if config.enable_graph_neural_network:
            self.gnn = GraphNeuralNetwork(config)
        else:
            self.gnn = None

        if config.enable_transformer_encoder:
            self.transformer = TransformerSequenceEncoder(config)
        else:
            self.transformer = None

        if config.enable_attention_mechanism:
            self.attention_fusion = MultiHeadAttentionFusion(config)
        else:
            # Simple concatenation fallback
            total_dim = config.multimodal_feature_dim
            if self.gnn is not None:
                total_dim += config.gnn_hidden_dim
            if self.transformer is not None:
                total_dim += config.transformer_hidden_dim
            self.simple_fusion = nn.Linear(total_dim, config.final_hidden_dim)

        if config.enable_hierarchical_learning:
            self.hierarchical = HierarchicalLearningModule(config)
        else:
            self.hierarchical = None

        # Final classification layers
        if config.enable_bayesian_layers:
            final_input_dim = (
                config.hierarchical_hidden_dims[-1] if config.enable_hierarchical_learning
                else config.final_hidden_dim
            )
            self.classifier = nn.ModuleList([
                BayesianLinear(final_input_dim, config.final_hidden_dim // 2, config.prior_std),
                BayesianLinear(config.final_hidden_dim // 2, config.num_classes, config.prior_std)
            ])
        else:
            final_input_dim = (
                config.hierarchical_hidden_dims[-1] if config.enable_hierarchical_learning
                else config.final_hidden_dim
            )
            self.classifier = nn.Sequential(
                nn.Linear(final_input_dim, config.final_hidden_dim // 2),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(config.final_hidden_dim // 2, config.num_classes)
            )

        logger.info(f"Initialized HybridVulnerabilityDetector with components:")
        logger.info(f"  - GNN: {'✓' if self.gnn else '✗'}")
        logger.info(f"  - Transformer: {'✓' if self.transformer else '✗'}")
        logger.info(f"  - Attention Fusion: {'✓' if config.enable_attention_mechanism else '✗'}")
        logger.info(f"  - Hierarchical Learning: {'✓' if self.hierarchical else '✗'}")
        logger.info(f"  - Bayesian Layers: {'✓' if config.enable_bayesian_layers else '✗'}")

    def forward(self,
                multimodal_features: torch.Tensor,
                graph_data: Optional[Data] = None,
                sequence_data: Optional[torch.Tensor] = None,
                sequence_mask: Optional[torch.Tensor] = None,
                num_samples: int = 1) -> Dict[str, torch.Tensor]:

        batch_size = multimodal_features.size(0)

        # Extract features from different modalities
        gnn_features = None
        if self.gnn is not None and graph_data is not None:
            gnn_features = self.gnn(graph_data)

        transformer_features = None
        if self.transformer is not None and sequence_data is not None:
            transformer_features = self.transformer(sequence_data, sequence_mask)

        # Feature fusion
        if self.config.enable_attention_mechanism:
            fused_features = self.attention_fusion(
                multimodal_features, gnn_features, transformer_features
            )
        else:
            # Simple concatenation
            features_to_concat = [multimodal_features]
            if gnn_features is not None:
                features_to_concat.append(gnn_features)
            if transformer_features is not None:
                features_to_concat.append(transformer_features)

            concatenated = torch.cat(features_to_concat, dim=1)
            fused_features = self.simple_fusion(concatenated)

        # Hierarchical learning
        if self.hierarchical is not None:
            hierarchical_repr = self.hierarchical(fused_features)
            final_features = hierarchical_repr[-1]  # Use highest level representation
        else:
            final_features = fused_features

        # Classification with uncertainty quantification
        if self.config.enable_bayesian_layers:
            # Multiple forward passes for uncertainty estimation
            outputs = []
            kl_divs = []

            for _ in range(num_samples):
                current = final_features
                total_kl = 0

                for bayesian_layer in self.classifier:
                    current = F.relu(bayesian_layer(current, sample=True))
                    total_kl += bayesian_layer.kl_divergence()

                outputs.append(current)
                kl_divs.append(total_kl)

            # Stack outputs
            stacked_outputs = torch.stack(outputs, dim=0)  # (num_samples, batch_size, num_classes)
            mean_output = stacked_outputs.mean(dim=0)
            std_output = stacked_outputs.std(dim=0)
            mean_kl = torch.mean(torch.stack(kl_divs))

            return {
                'logits': mean_output,
                'uncertainty': std_output,
                'kl_divergence': mean_kl,
                'sample_outputs': stacked_outputs
            }
        else:
            # Standard classification
            logits = self.classifier(final_features)
            return {
                'logits': logits,
                'uncertainty': None,
                'kl_divergence': None
            }

    def predict_with_uncertainty(self,
                                 multimodal_features: torch.Tensor,
                                 graph_data: Optional[Data] = None,
                                 sequence_data: Optional[torch.Tensor] = None,
                                 sequence_mask: Optional[torch.Tensor] = None,
                                 num_samples: int = None) -> Dict[str, torch.Tensor]:
        """Predict with uncertainty estimation"""

        if num_samples is None:
            num_samples = self.config.bayesian_samples if self.config.enable_bayesian_layers else 1

        with torch.no_grad():
            outputs = self.forward(
                multimodal_features, graph_data, sequence_data,
                sequence_mask, num_samples
            )

        # Convert logits to probabilities
        if 'sample_outputs' in outputs and outputs['sample_outputs'] is not None:
            probs = F.softmax(outputs['sample_outputs'], dim=-1)
            mean_probs = probs.mean(dim=0)
            epistemic_uncertainty = probs.var(dim=0).sum(dim=-1)  # Total variance
            aleatoric_uncertainty = outputs['uncertainty'].sum(dim=-1) if outputs['uncertainty'] is not None else None
        else:
            mean_probs = F.softmax(outputs['logits'], dim=-1)
            epistemic_uncertainty = None
            aleatoric_uncertainty = None

        return {
            'probabilities': mean_probs,
            'predictions': mean_probs.argmax(dim=-1),
            'confidence': mean_probs.max(dim=-1)[0],
            'epistemic_uncertainty': epistemic_uncertainty,
            'aleatoric_uncertainty': aleatoric_uncertainty
        }

class CodeToGraphConverter:
    """Convert code to graph representation for GNN"""

    def __init__(self):
        self.node_types = {
            'FunctionDef': 0, 'ClassDef': 1, 'If': 2, 'For': 3, 'While': 4,
            'Try': 5, 'With': 6, 'Call': 7, 'Attribute': 8, 'Name': 9,
            'Constant': 10, 'BinOp': 11, 'Compare': 12, 'Assign': 13,
            'Return': 14, 'Import': 15, 'ImportFrom': 16, 'Other': 17
        }

    def code_to_graph(self, code: str) -> Optional[Data]:
        """Convert code to PyTorch Geometric Data object"""
        try:
            tree = ast.parse(code)
            return self._ast_to_graph(tree)
        except SyntaxError:
            logger.warning("Syntax error in code, returning empty graph")
            return None

    def _ast_to_graph(self, tree: ast.AST) -> Data:
        """Convert AST to graph representation"""
        nodes = []
        edges = []
        node_features = []

        # Node mapping
        node_map = {}
        node_id = 0

        def add_node(ast_node):
            nonlocal node_id
            node_type = type(ast_node).__name__
            type_id = self.node_types.get(node_type, self.node_types['Other'])

            # Create node features
            features = [0.0] * 64  # Initialize feature vector
            features[type_id] = 1.0  # One-hot encoding of node type

            # Add additional features based on node type
            if isinstance(ast_node, ast.FunctionDef):
                features[20] = len(ast_node.args.args)  # Number of arguments
                features[21] = len(ast_node.decorator_list)  # Number of decorators
            elif isinstance(ast_node, ast.ClassDef):
                features[22] = len(ast_node.bases)  # Number of base classes
            elif isinstance(ast_node, ast.Call):
                features[23] = len(ast_node.args)  # Number of call arguments
            elif isinstance(ast_node, ast.Name):
                features[24] = 1.0 if isinstance(ast_node.ctx, ast.Load) else 0.0
                features[25] = 1.0 if isinstance(ast_node.ctx, ast.Store) else 0.0

            node_map[ast_node] = node_id
            nodes.append(node_id)
            node_features.append(features)
            node_id += 1

            return node_id - 1

        def traverse_and_connect(node, parent_id=None):
            current_id = add_node(node)

            # Add edge from parent to current
            if parent_id is not None:
                edges.append([parent_id, current_id])

            # Recursively process children
            for child in ast.iter_child_nodes(node):
                traverse_and_connect(child, current_id)

        # Build graph
        traverse_and_connect(tree)

        # Convert to tensors
        if not edges:
            # Empty graph case
            edge_index = torch.empty((2, 0), dtype=torch.long)
        else:
            edge_index = torch.tensor(edges, dtype=torch.long).t()

        node_features_tensor = torch.tensor(node_features, dtype=torch.float)

        return Data(x=node_features_tensor, edge_index=edge_index)

class HybridTrainer:
    """Trainer for the hybrid vulnerability detection model"""

    def __init__(self, model: HybridVulnerabilityDetector, config: HybridArchitectureConfig):
        self.model = model
        self.config = config
        self.graph_converter = CodeToGraphConverter()

        # Loss function
        self.criterion = nn.CrossEntropyLoss()

        # Optimizer
        self.optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=1e-4,
            weight_decay=1e-5
        )

        # Learning rate scheduler
        self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer,
            mode='min',
            patience=5,
            factor=0.5
        )

    def train_step(self, batch_data: Dict[str, Any]) -> Dict[str, float]:
        """Single training step"""
        self.model.train()

        # Extract batch components
        multimodal_features = batch_data['multimodal_features']
        labels = batch_data['labels']
        codes = batch_data.get('codes', [])
        sequence_data = batch_data.get('sequence_data', None)
        sequence_mask = batch_data.get('sequence_mask', None)

        # Convert codes to graphs if available
        graph_data = None
        if codes and self.config.enable_graph_neural_network:
            graphs = []
            for code in codes:
                graph = self.graph_converter.code_to_graph(code)
                if graph is not None:
                    graphs.append(graph)

            if graphs:
                graph_data = Batch.from_data_list(graphs)

        # Forward pass
        outputs = self.model(
            multimodal_features=multimodal_features,
            graph_data=graph_data,
            sequence_data=sequence_data,
            sequence_mask=sequence_mask,
            num_samples=1
        )

        # Compute loss
        logits = outputs['logits']
        classification_loss = self.criterion(logits, labels)

        # Add KL divergence for Bayesian layers
        total_loss = classification_loss
        if outputs['kl_divergence'] is not None:
            kl_weight = 1.0 / len(multimodal_features)  # Scale by batch size
            total_loss += kl_weight * outputs['kl_divergence']

        # Backward pass
        self.optimizer.zero_grad()
        total_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        self.optimizer.step()

        # Compute metrics
        with torch.no_grad():
            probs = F.softmax(logits, dim=-1)
            predictions = probs.argmax(dim=-1)
            accuracy = (predictions == labels).float().mean()

        return {
            'loss': total_loss.item(),
            'classification_loss': classification_loss.item(),
            'kl_loss': outputs['kl_divergence'].item() if outputs['kl_divergence'] is not None else 0.0,
            'accuracy': accuracy.item()
        }

    def evaluate(self, test_loader) -> Dict[str, float]:
        """Evaluate model on test set"""
        self.model.eval()

        total_loss = 0
        total_accuracy = 0
        total_samples = 0

        all_predictions = []
        all_labels = []
        all_uncertainties = []

        with torch.no_grad():
            for batch_data in test_loader:
                # Similar processing as training
                multimodal_features = batch_data['multimodal_features']
                labels = batch_data['labels']
                codes = batch_data.get('codes', [])
                sequence_data = batch_data.get('sequence_data', None)
                sequence_mask = batch_data.get('sequence_mask', None)

                # Convert codes to graphs
                graph_data = None
                if codes and self.config.enable_graph_neural_network:
                    graphs = []
                    for code in codes:
                        graph = self.graph_converter.code_to_graph(code)
                        if graph is not None:
                            graphs.append(graph)

                    if graphs:
                        graph_data = Batch.from_data_list(graphs)

                # Get predictions with uncertainty
                pred_outputs = self.model.predict_with_uncertainty(
                    multimodal_features=multimodal_features,
                    graph_data=graph_data,
                    sequence_data=sequence_data,
                    sequence_mask=sequence_mask
                )

                predictions = pred_outputs['predictions']
                probabilities = pred_outputs['probabilities']
                confidence = pred_outputs['confidence']

                # Compute metrics
                loss = self.criterion(torch.log(probabilities + 1e-8), labels)
                accuracy = (predictions == labels).float().mean()

                total_loss += loss.item() * len(labels)
                total_accuracy += accuracy.item() * len(labels)
                total_samples += len(labels)

                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
                all_uncertainties.extend(confidence.cpu().numpy())

        # Compute overall metrics
        avg_loss = total_loss / total_samples
        avg_accuracy = total_accuracy / total_samples

        return {
            'loss': avg_loss,
            'accuracy': avg_accuracy,
            'predictions': all_predictions,
            'labels': all_labels,
            'uncertainties': all_uncertainties
        }

# Example usage and demonstration
if __name__ == "__main__":
    print("Hybrid Neural Architecture for Vulnerability Detection")
    print("=" * 60)

    # Create configuration
    config = HybridArchitectureConfig(
        multimodal_feature_dim=1024,  # From multi-modal feature engineering
        enable_graph_neural_network=True,
        enable_transformer_encoder=True,
        enable_attention_mechanism=True,
        enable_hierarchical_learning=True,
        enable_bayesian_layers=True
    )

    print(f"Architecture Configuration:")
    print(f"  - Multi-modal features: {config.multimodal_feature_dim}")
    print(f"  - Graph Neural Network: {'✓' if config.enable_graph_neural_network else '✗'}")
    print(f"  - Transformer Encoder: {'✓' if config.enable_transformer_encoder else '✗'}")
    print(f"  - Attention Mechanism: {'✓' if config.enable_attention_mechanism else '✗'}")
    print(f"  - Hierarchical Learning: {'✓' if config.enable_hierarchical_learning else '✗'}")
    print(f"  - Bayesian Layers: {'✓' if config.enable_bayesian_layers else '✗'}")

    # Initialize model
    model = HybridVulnerabilityDetector(config)

    print(f"\nModel Architecture:")
    print(f"  Total Parameters: {sum(p.numel() for p in model.parameters()):,}")
    print(f"  Trainable Parameters: {sum(p.numel() for p in model.parameters() if p.requires_grad):,}")

    # Example forward pass
    print(f"\nTesting forward pass...")

    batch_size = 4
    seq_len = 100

    # Create dummy data
    multimodal_features = torch.randn(batch_size, config.multimodal_feature_dim)
    sequence_data = torch.randn(batch_size, seq_len, config.codebert_embedding_dim)
    sequence_mask = torch.zeros(batch_size, seq_len, dtype=torch.bool)

    # Create dummy graph
    graph_converter = CodeToGraphConverter()
    example_code = """
def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    return execute_query(query)
"""
    graph_data = graph_converter.code_to_graph(example_code)
    if graph_data is not None:
        # Create batch with same graph repeated
        graphs = [graph_data] * batch_size
        graph_batch = Batch.from_data_list(graphs)
    else:
        graph_batch = None

    # Forward pass
    with torch.no_grad():
        outputs = model(
            multimodal_features=multimodal_features,
            graph_data=graph_batch,
            sequence_data=sequence_data,
            sequence_mask=sequence_mask,
            num_samples=5
        )

    print(f"  Output shape: {outputs['logits'].shape}")
    if outputs['uncertainty'] is not None:
        print(f"  Uncertainty shape: {outputs['uncertainty'].shape}")
    if outputs['kl_divergence'] is not None:
        print(f"  KL Divergence: {outputs['kl_divergence'].item():.6f}")

    # Test prediction with uncertainty
    print(f"\nTesting uncertainty quantification...")
    pred_outputs = model.predict_with_uncertainty(
        multimodal_features=multimodal_features,
        graph_data=graph_batch,
        sequence_data=sequence_data,
        sequence_mask=sequence_mask,
        num_samples=10
    )

    print(f"  Predictions: {pred_outputs['predictions']}")
    print(f"  Confidence: {pred_outputs['confidence']}")
    if pred_outputs['epistemic_uncertainty'] is not None:
        print(f"  Epistemic Uncertainty: {pred_outputs['epistemic_uncertainty']}")

    # Save model configuration
    output_dir = Path("/Users/ankitthakur/vuln_ml_research/strategic_fp_reduction")
    config_dict = {
        'multimodal_feature_dim': config.multimodal_feature_dim,
        'codebert_embedding_dim': config.codebert_embedding_dim,
        'graph_node_features': config.graph_node_features,
        'enable_graph_neural_network': config.enable_graph_neural_network,
        'enable_transformer_encoder': config.enable_transformer_encoder,
        'enable_attention_mechanism': config.enable_attention_mechanism,
        'enable_hierarchical_learning': config.enable_hierarchical_learning,
        'enable_bayesian_layers': config.enable_bayesian_layers,
        'total_parameters': sum(p.numel() for p in model.parameters()),
        'model_components': {
            'gnn_layers': config.gnn_num_layers,
            'transformer_layers': config.transformer_num_layers,
            'attention_heads': config.attention_heads,
            'hierarchical_levels': config.hierarchical_levels
        }
    }

    config_file = output_dir / "hybrid_architecture_config.json"
    with open(config_file, 'w') as f:
        json.dump(config_dict, f, indent=2)

    print(f"\nArchitecture configuration saved to: {config_file}")
    print(f"\nHybrid Neural Architecture implementation complete!")
    print(f"This system integrates:")
    print(f"  • Graph Neural Networks for structural analysis")
    print(f"  • Transformer encoders for sequence modeling")
    print(f"  • Multi-head attention for feature fusion")
    print(f"  • Hierarchical learning for multi-scale representations")
    print(f"  • Bayesian layers for uncertainty quantification")