"""
VulnHunter Blockchain: Enhanced GNN for Smart Contract Security
Specialized Graph Neural Networks for blockchain vulnerability detection
Targets: Reentrancy, Integer Overflow, Access Control, and 10+ threats
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, SAGEConv, global_mean_pool, global_max_pool, global_add_pool
from torch_geometric.data import Data, Batch
from typing import Dict, List, Tuple, Optional, Any
import math

class BlockchainGNN(nn.Module):
    """
    Advanced GNN specifically designed for blockchain vulnerability detection
    Incorporates domain knowledge about smart contract patterns and vulnerabilities
    """

    def __init__(
        self,
        input_dim: int = 30,  # Enhanced for Solidity features
        hidden_dim: int = 128,
        output_dim: int = 256,
        num_layers: int = 4,
        num_vulnerability_types: int = 10,
        dropout: float = 0.15,
        use_attention: bool = True
    ):
        super(BlockchainGNN, self).__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.num_layers = num_layers
        self.num_vulnerability_types = num_vulnerability_types
        self.dropout = dropout
        self.use_attention = use_attention

        # Input projection for Solidity-specific features
        self.input_projection = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        # Multi-layer GNN architecture combining different approaches
        self.gnn_layers = nn.ModuleList()
        self.batch_norms = nn.ModuleList()

        for i in range(num_layers):
            # Hybrid approach: GCN + GAT + SAGE
            if i % 3 == 0:
                # Graph Convolution for structural patterns
                self.gnn_layers.append(GCNConv(hidden_dim, hidden_dim))
            elif i % 3 == 1:
                # Graph Attention for important call patterns
                self.gnn_layers.append(GATConv(
                    hidden_dim, hidden_dim // 8, heads=8, dropout=dropout, concat=True
                ))
            else:
                # GraphSAGE for neighborhood aggregation
                self.gnn_layers.append(SAGEConv(hidden_dim, hidden_dim, aggr='mean'))

            self.batch_norms.append(nn.BatchNorm1d(hidden_dim))

        # Blockchain-specific vulnerability detection heads
        self.vulnerability_heads = nn.ModuleDict({
            'reentrancy': ReentrancyDetectionHead(hidden_dim),
            'integer_overflow': OverflowDetectionHead(hidden_dim),
            'access_control': AccessControlHead(hidden_dim),
            'unchecked_call': UncheckedCallHead(hidden_dim),
            'timestamp_dependence': TimestampDependenceHead(hidden_dim),
            'tx_origin': TxOriginHead(hidden_dim),
            'dos_gas_limit': DosGasLimitHead(hidden_dim),
            'uninitialized_storage': UninitializedStorageHead(hidden_dim),
            'front_running': FrontRunningHead(hidden_dim),
            'insufficient_gas_griefing': GasGriefingHead(hidden_dim)
        })

        # Graph-level attention for contract understanding
        if use_attention:
            self.contract_attention = ContractLevelAttention(hidden_dim, output_dim)

        # Output projection
        self.output_projection = nn.Sequential(
            nn.Linear(hidden_dim * 3, output_dim),  # 3 pooling strategies
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(output_dim, output_dim)
        )

        # Security level predictor
        self.security_predictor = nn.Sequential(
            nn.Linear(output_dim, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 5)  # 0=critical, 1=high, 2=medium, 3=low, 4=safe
        )

        # Gas complexity estimator
        self.gas_estimator = nn.Sequential(
            nn.Linear(output_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1)
        )

    def forward(self, data: Data) -> Dict[str, torch.Tensor]:
        """
        Forward pass through blockchain GNN

        Args:
            data: PyTorch Geometric Data object with Solidity graph

        Returns:
            Dictionary with vulnerability predictions and analysis
        """
        x, edge_index, batch = data.x, data.edge_index, data.batch

        # Input projection
        x = self.input_projection(x)

        # Store intermediate representations for skip connections
        layer_outputs = []

        # Multi-layer GNN processing
        for i, (gnn_layer, batch_norm) in enumerate(zip(self.gnn_layers, self.batch_norms)):
            x_prev = x

            # Apply GNN layer
            x = gnn_layer(x, edge_index)

            # Batch normalization (skip if batch size is 1)
            if x.size(0) > 1:
                x = batch_norm(x)

            # Activation and dropout
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

            # Skip connection (after first layer)
            if i > 0 and x.size() == x_prev.size():
                x = x + x_prev

            layer_outputs.append(x)

        # Global pooling strategies
        graph_embedding = self._global_pooling(x, batch, layer_outputs)

        # Vulnerability-specific predictions
        vulnerability_predictions = {}
        for vuln_type, head in self.vulnerability_heads.items():
            vulnerability_predictions[vuln_type] = head(x, batch, graph_embedding)

        # Overall security assessment
        security_level = self.security_predictor(graph_embedding)
        gas_complexity = self.gas_estimator(graph_embedding)

        # Output projection
        final_embedding = self.output_projection(graph_embedding)

        return {
            'graph_embedding': final_embedding,
            'vulnerability_predictions': vulnerability_predictions,
            'security_level': torch.softmax(security_level, dim=-1),
            'gas_complexity': gas_complexity,
            'node_embeddings': x,
            'intermediate_representations': layer_outputs
        }

    def _global_pooling(self, x: torch.Tensor, batch: torch.Tensor, layer_outputs: List[torch.Tensor]) -> torch.Tensor:
        """Advanced global pooling combining multiple strategies"""

        # Standard pooling
        mean_pool = global_mean_pool(x, batch)
        max_pool = global_max_pool(x, batch)
        sum_pool = global_add_pool(x, batch)

        # Attention pooling if enabled
        if self.use_attention:
            attn_pool = self.contract_attention(x, batch)
            combined = torch.cat([mean_pool, max_pool, attn_pool], dim=1)
        else:
            combined = torch.cat([mean_pool, max_pool, sum_pool], dim=1)

        return combined

class ReentrancyDetectionHead(nn.Module):
    """Specialized head for reentrancy vulnerability detection"""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.call_pattern_detector = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

        # Pattern weights for different reentrancy indicators
        self.pattern_weights = nn.Parameter(torch.tensor([
            1.5,  # external_call
            1.2,  # state_change_after_call
            1.0,  # payable_function
            0.8,  # fallback_function
            0.6   # complex_call_pattern
        ]))

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        """Detect reentrancy patterns in contract"""

        # Extract call-related features
        call_features = node_features[:, [8, 10, 14, 15]]  # external_call, payable, msg_sender, msg_value

        # Aggregate call patterns per graph
        batch_size = batch.max().item() + 1
        reentrancy_scores = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_call_features = call_features[mask]

            if graph_call_features.size(0) > 0:
                # Check for dangerous call patterns
                call_score = self.call_pattern_detector(graph_call_features.mean(dim=0))
                reentrancy_scores.append(call_score)
            else:
                reentrancy_scores.append(torch.tensor([0.0]).to(node_features.device))

        return torch.cat(reentrancy_scores)

class OverflowDetectionHead(nn.Module):
    """Specialized head for integer overflow/underflow detection"""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.arithmetic_detector = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        """Detect integer overflow/underflow vulnerabilities"""

        # Focus on arithmetic operations and SafeMath usage
        batch_size = batch.max().item() + 1
        overflow_scores = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_features = node_features[mask]

            if graph_features.size(0) > 0:
                # Check for SafeMath usage (feature 25) and arithmetic patterns
                safemath_usage = graph_features[:, 25].mean()
                arithmetic_complexity = graph_features[:, 9].mean()  # complexity_score

                # Higher risk if no SafeMath and high arithmetic complexity
                risk_features = torch.stack([1.0 - safemath_usage, arithmetic_complexity])
                overflow_score = self.arithmetic_detector(risk_features)
                overflow_scores.append(overflow_score)
            else:
                overflow_scores.append(torch.tensor([0.0]).to(node_features.device))

        return torch.cat(overflow_scores)

class AccessControlHead(nn.Module):
    """Specialized head for access control vulnerability detection"""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.access_detector = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        """Detect access control vulnerabilities"""

        batch_size = batch.max().item() + 1
        access_scores = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_features = node_features[mask]

            if graph_features.size(0) > 0:
                # Check for modifier usage (feature 11) and onlyOwner patterns (feature 24)
                modifier_usage = graph_features[:, 11].mean()
                owner_checks = graph_features[:, 24].mean()

                # Higher risk if functions lack proper access controls
                access_features = torch.stack([1.0 - modifier_usage, 1.0 - owner_checks])
                access_score = self.access_detector(access_features)
                access_scores.append(access_score)
            else:
                access_scores.append(torch.tensor([0.0]).to(node_features.device))

        return torch.cat(access_scores)

class UncheckedCallHead(nn.Module):
    """Detection head for unchecked external calls"""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.call_checker = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        batch_size = batch.max().item() + 1
        call_scores = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_features = node_features[mask]

            if graph_features.size(0) > 0:
                external_calls = graph_features[:, 8].mean()  # is_external_call
                require_usage = graph_features[:, 12].mean()  # has_require

                # Risk if external calls without require checks
                call_features = torch.stack([external_calls, 1.0 - require_usage])
                call_score = self.call_checker(call_features)
                call_scores.append(call_score)
            else:
                call_scores.append(torch.tensor([0.0]).to(node_features.device))

        return torch.cat(call_scores)

class TimestampDependenceHead(nn.Module):
    """Detection head for timestamp dependence vulnerabilities"""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.timestamp_detector = nn.Sequential(
            nn.Linear(hidden_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        batch_size = batch.max().item() + 1
        timestamp_scores = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_features = node_features[mask]

            if graph_features.size(0) > 0:
                timestamp_usage = graph_features[:, 16].mean()  # uses_block_timestamp
                timestamp_score = self.timestamp_detector(timestamp_usage.unsqueeze(0))
                timestamp_scores.append(timestamp_score)
            else:
                timestamp_scores.append(torch.tensor([0.0]).to(node_features.device))

        return torch.cat(timestamp_scores)

class TxOriginHead(nn.Module):
    """Detection head for tx.origin vulnerabilities"""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.tx_origin_detector = nn.Sequential(
            nn.Linear(hidden_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        batch_size = batch.max().item() + 1
        tx_origin_scores = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_features = node_features[mask]

            if graph_features.size(0) > 0:
                tx_origin_usage = graph_features[:, 17].mean()  # uses_tx_origin
                tx_origin_score = self.tx_origin_detector(tx_origin_usage.unsqueeze(0))
                tx_origin_scores.append(tx_origin_score)
            else:
                tx_origin_scores.append(torch.tensor([0.0]).to(node_features.device))

        return torch.cat(tx_origin_scores)

# Additional specialized heads following similar patterns
class DosGasLimitHead(nn.Module):
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.dos_detector = nn.Linear(hidden_dim, 1)

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.dos_detector(global_mean_pool(node_features, batch)))

class UninitializedStorageHead(nn.Module):
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.storage_detector = nn.Linear(hidden_dim, 1)

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.storage_detector(global_mean_pool(node_features, batch)))

class FrontRunningHead(nn.Module):
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.front_running_detector = nn.Linear(hidden_dim, 1)

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.front_running_detector(global_mean_pool(node_features, batch)))

class GasGriefingHead(nn.Module):
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.gas_griefing_detector = nn.Linear(hidden_dim, 1)

    def forward(self, node_features: torch.Tensor, batch: torch.Tensor, graph_embedding: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.gas_griefing_detector(global_mean_pool(node_features, batch)))

class ContractLevelAttention(nn.Module):
    """Contract-level attention mechanism for important pattern focus"""

    def __init__(self, input_dim: int, output_dim: int):
        super().__init__()
        self.attention_weights = nn.Sequential(
            nn.Linear(input_dim, output_dim),
            nn.Tanh(),
            nn.Linear(output_dim, 1)
        )

    def forward(self, x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
        """Apply attention-based pooling for contract understanding"""

        # Calculate attention weights for each node
        attention_weights = self.attention_weights(x)  # [num_nodes, 1]

        # Apply softmax per graph
        batch_size = batch.max().item() + 1
        attended_representations = []

        for i in range(batch_size):
            mask = (batch == i)
            graph_features = x[mask]
            graph_weights = attention_weights[mask]

            if graph_features.size(0) > 0:
                # Softmax attention weights for this graph
                graph_weights = F.softmax(graph_weights, dim=0)

                # Weighted sum of node features
                attended_repr = (graph_features * graph_weights).sum(dim=0)
                attended_representations.append(attended_repr)
            else:
                attended_representations.append(torch.zeros(x.size(1)).to(x.device))

        return torch.stack(attended_representations)

def test_blockchain_gnn():
    """Test the blockchain GNN with sample data"""
    print("=== Testing Blockchain GNN ===")

    # Create sample graph data
    num_nodes = 20
    x = torch.randn(num_nodes, 30)  # 30-dimensional Solidity features
    edge_index = torch.randint(0, num_nodes, (2, 40))
    batch = torch.zeros(num_nodes, dtype=torch.long)

    data = Data(x=x, edge_index=edge_index, batch=batch)

    # Create model
    model = BlockchainGNN(
        input_dim=30,
        hidden_dim=128,
        output_dim=256,
        num_vulnerability_types=10
    )

    # Forward pass
    with torch.no_grad():
        results = model(data)

    print(f"Graph embedding shape: {results['graph_embedding'].shape}")
    print(f"Security level predictions: {results['security_level']}")
    print(f"Gas complexity estimate: {results['gas_complexity'].item():.2f}")

    print("\nVulnerability predictions:")
    for vuln_type, score in results['vulnerability_predictions'].items():
        print(f"  {vuln_type}: {score.item():.3f}")

    print(f"\nTotal model parameters: {sum(p.numel() for p in model.parameters()):,}")

if __name__ == "__main__":
    test_blockchain_gnn()