"""
VulnHunter PoC: Graph Neural Network Encoder
Advanced GNN models for learning structural vulnerability patterns
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, SAGEConv, GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
from typing import Optional, List, Tuple
import math

class GNNEncoder(nn.Module):
    """
    Advanced Graph Neural Network Encoder for code vulnerability detection
    Combines multiple GNN architectures for robust structural learning
    """

    def __init__(
        self,
        input_dim: int = 20,
        hidden_dim: int = 128,
        output_dim: int = 256,
        num_layers: int = 3,
        dropout: float = 0.1,
        model_type: str = "gcn"
    ):
        super(GNNEncoder, self).__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.num_layers = num_layers
        self.dropout = dropout
        self.model_type = model_type

        # Input projection
        self.input_projection = nn.Linear(input_dim, hidden_dim)

        # GNN layers based on model type
        self.gnn_layers = nn.ModuleList()

        if model_type == "gcn":
            self._build_gcn_layers()
        elif model_type == "sage":
            self._build_sage_layers()
        elif model_type == "gat":
            self._build_gat_layers()
        elif model_type == "hybrid":
            self._build_hybrid_layers()
        else:
            raise ValueError(f"Unknown model type: {model_type}")

        # Output projection
        self.output_projection = nn.Sequential(
            nn.Linear(hidden_dim, output_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(output_dim, output_dim)
        )

        # Batch normalization
        self.batch_norms = nn.ModuleList([
            nn.BatchNorm1d(hidden_dim) for _ in range(num_layers)
        ])

        # Attention mechanism for graph-level representation
        self.attention = GraphAttention(hidden_dim, output_dim)

    def _build_gcn_layers(self):
        """Build Graph Convolutional Network layers"""
        for i in range(self.num_layers):
            self.gnn_layers.append(GCNConv(self.hidden_dim, self.hidden_dim))

    def _build_sage_layers(self):
        """Build GraphSAGE layers"""
        for i in range(self.num_layers):
            self.gnn_layers.append(SAGEConv(self.hidden_dim, self.hidden_dim))

    def _build_gat_layers(self):
        """Build Graph Attention Network layers"""
        for i in range(self.num_layers):
            self.gnn_layers.append(GATConv(
                self.hidden_dim,
                self.hidden_dim // 8,  # 8 attention heads
                heads=8,
                dropout=self.dropout,
                concat=True
            ))

    def _build_hybrid_layers(self):
        """Build hybrid layers combining different GNN types"""
        layer_types = [GCNConv, SAGEConv, GATConv]
        for i in range(self.num_layers):
            layer_type = layer_types[i % len(layer_types)]
            if layer_type == GATConv:
                self.gnn_layers.append(GATConv(
                    self.hidden_dim,
                    self.hidden_dim // 4,
                    heads=4,
                    dropout=self.dropout,
                    concat=True
                ))
            else:
                self.gnn_layers.append(layer_type(self.hidden_dim, self.hidden_dim))

    def forward(self, data: Data) -> torch.Tensor:
        """
        Forward pass through GNN encoder

        Args:
            data: PyTorch Geometric Data object with node features and edge indices

        Returns:
            Graph-level embedding tensor
        """
        x, edge_index, batch = data.x, data.edge_index, data.batch

        # Input projection
        x = self.input_projection(x)
        x = F.relu(x)

        # Store intermediate representations for skip connections
        layer_outputs = []

        # Pass through GNN layers
        for i, gnn_layer in enumerate(self.gnn_layers):
            x_prev = x

            # Apply GNN layer
            x = gnn_layer(x, edge_index)

            # Batch normalization
            if x.size(0) > 1:  # Only apply if batch size > 1
                x = self.batch_norms[i](x)

            # Activation and dropout
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

            # Skip connection
            if i > 0:
                x = x + x_prev

            layer_outputs.append(x)

        # Global pooling to get graph-level representation
        graph_embedding = self._global_pooling(x, batch, layer_outputs)

        # Output projection
        output = self.output_projection(graph_embedding)

        return output

    def _global_pooling(self, x: torch.Tensor, batch: torch.Tensor, layer_outputs: List[torch.Tensor]) -> torch.Tensor:
        """
        Advanced global pooling combining multiple strategies

        Args:
            x: Node features
            batch: Batch assignment
            layer_outputs: Outputs from each GNN layer

        Returns:
            Graph-level representation
        """
        # Mean pooling
        mean_pool = global_mean_pool(x, batch)

        # Max pooling
        max_pool = global_max_pool(x, batch)

        # Attention pooling
        attn_pool = self.attention(x, batch)

        # Hierarchical pooling from different layers
        if len(layer_outputs) > 1:
            mid_layer = layer_outputs[len(layer_outputs) // 2]
            mid_pool = global_mean_pool(mid_layer, batch)

            # Combine all pooling strategies
            combined = torch.cat([mean_pool, max_pool, attn_pool, mid_pool], dim=1)
        else:
            combined = torch.cat([mean_pool, max_pool, attn_pool], dim=1)

        return combined

class GraphAttention(nn.Module):
    """Graph-level attention mechanism for pooling"""

    def __init__(self, input_dim: int, output_dim: int):
        super(GraphAttention, self).__init__()

        self.attention_layer = nn.Sequential(
            nn.Linear(input_dim, output_dim),
            nn.Tanh(),
            nn.Linear(output_dim, 1)
        )

    def forward(self, x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
        """
        Apply attention-based pooling

        Args:
            x: Node features [num_nodes, feature_dim]
            batch: Batch assignment [num_nodes]

        Returns:
            Graph-level representation [batch_size, feature_dim]
        """
        # Calculate attention weights
        attention_weights = self.attention_layer(x)  # [num_nodes, 1]
        attention_weights = F.softmax(attention_weights, dim=0)

        # Apply attention weights
        weighted_features = x * attention_weights

        # Pool by batch
        batch_size = batch.max().item() + 1
        graph_representations = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_repr = weighted_features[mask].sum(dim=0)
            graph_representations.append(graph_repr)

        return torch.stack(graph_representations)

class VulnerabilityGNN(nn.Module):
    """
    Specialized GNN for vulnerability pattern detection
    Incorporates domain knowledge about code vulnerabilities
    """

    def __init__(self, input_dim: int = 20, hidden_dim: int = 128, num_classes: int = 2):
        super(VulnerabilityGNN, self).__init__()

        self.encoder = GNNEncoder(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            output_dim=hidden_dim * 2,
            model_type="hybrid"
        )

        # Vulnerability-specific layers
        self.vulnerability_detector = nn.Sequential(
            nn.Linear(hidden_dim * 6, hidden_dim * 2),  # 6 = 3 pooling strategies * 2
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, num_classes)
        )

        # Pattern matching layers for specific vulnerability types
        self.pattern_layers = nn.ModuleDict({
            'sql_injection': nn.Linear(hidden_dim * 6, 1),
            'command_injection': nn.Linear(hidden_dim * 6, 1),
            'path_traversal': nn.Linear(hidden_dim * 6, 1),
            'xss': nn.Linear(hidden_dim * 6, 1)
        })

    def forward(self, data: Data) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass for vulnerability detection

        Args:
            data: Graph data

        Returns:
            Tuple of (vulnerability_prediction, pattern_predictions)
        """
        # Get graph embedding
        graph_embedding = self.encoder(data)

        # Main vulnerability prediction
        vuln_logits = self.vulnerability_detector(graph_embedding)

        # Pattern-specific predictions
        pattern_predictions = {}
        for pattern_name, pattern_layer in self.pattern_layers.items():
            pattern_predictions[pattern_name] = torch.sigmoid(pattern_layer(graph_embedding))

        return vuln_logits, pattern_predictions

def create_sample_graph() -> Data:
    """Create a sample graph for testing"""
    # Sample node features (20 dimensions)
    x = torch.randn(10, 20)

    # Sample edges (fully connected small graph)
    edge_index = torch.tensor([
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    ], dtype=torch.long)

    # Create batch (single graph)
    batch = torch.zeros(10, dtype=torch.long)

    return Data(x=x, edge_index=edge_index, batch=batch)

def test_gnn_encoder():
    """Test the GNN encoder"""
    print("=== Testing GNN Encoder ===")

    # Test different model types
    model_types = ["gcn", "sage", "gat", "hybrid"]

    for model_type in model_types:
        print(f"\nTesting {model_type.upper()} model:")

        # Create model
        encoder = GNNEncoder(model_type=model_type)

        # Create sample data
        data = create_sample_graph()

        # Forward pass
        with torch.no_grad():
            output = encoder(data)

        print(f"  Input shape: {data.x.shape}")
        print(f"  Output shape: {output.shape}")
        print(f"  Parameters: {sum(p.numel() for p in encoder.parameters()):,}")

    # Test vulnerability-specific GNN
    print(f"\nTesting VulnerabilityGNN:")
    vuln_gnn = VulnerabilityGNN()
    data = create_sample_graph()

    with torch.no_grad():
        vuln_logits, pattern_preds = vuln_gnn(data)

    print(f"  Vulnerability logits shape: {vuln_logits.shape}")
    print(f"  Pattern predictions: {len(pattern_preds)} patterns")
    print(f"  Total parameters: {sum(p.numel() for p in vuln_gnn.parameters()):,}")

if __name__ == "__main__":
    test_gnn_encoder()