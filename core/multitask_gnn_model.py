#!/usr/bin/env python3
"""
Multi-Task GNN-Transformer for Vulnerability Detection
Tasks: 1) Vulnerability Detection, 2) Validation Status, 3) False Positive Prediction
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, GCNConv, global_mean_pool, global_max_pool
from typing import Dict, Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MultiTaskGNNTransformer(nn.Module):
    """
    Multi-task learning for vulnerability analysis

    Outputs:
        1. Vulnerability: [safe, vulnerable] - binary classification
        2. Validation: [unknown, unconfirmed, validated] - 3-class classification
        3. False Positive: [not_fp, is_fp] - binary classification
    """

    def __init__(
        self,
        input_dim: int = 128,
        hidden_dim: int = 256,
        num_heads: int = 8,
        dropout: float = 0.3,
        num_transformer_layers: int = 6,
        use_validation_head: bool = True,
        use_fp_head: bool = True
    ):
        super().__init__()

        self.use_validation_head = use_validation_head
        self.use_fp_head = use_fp_head

        # Shared GNN encoder
        self.gnn1 = GATConv(input_dim, hidden_dim, heads=num_heads, dropout=dropout)
        self.gnn2 = GATConv(hidden_dim * num_heads, hidden_dim, heads=4, dropout=dropout)
        self.gnn3 = GCNConv(hidden_dim * 4, hidden_dim)

        # Shared Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout,
            activation='gelu',
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_transformer_layers)

        # Shared representation layers
        self.dropout = nn.Dropout(dropout)
        self.bn_shared = nn.BatchNorm1d(hidden_dim * 2)

        # Shared feature extraction
        self.shared_fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ELU(),
            nn.Dropout(dropout)
        )

        # Task-specific heads

        # Task 1: Vulnerability Detection (primary task)
        self.vulnerability_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ELU(),
            nn.Dropout(dropout / 2),
            nn.Linear(hidden_dim // 2, 2)  # [safe, vulnerable]
        )

        # Task 2: Validation Status (auxiliary task)
        if self.use_validation_head:
            self.validation_head = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.BatchNorm1d(hidden_dim // 2),
                nn.ELU(),
                nn.Dropout(dropout / 2),
                nn.Linear(hidden_dim // 2, 3)  # [unknown, unconfirmed, validated]
            )

        # Task 3: False Positive Detection (auxiliary task)
        if self.use_fp_head:
            self.fp_head = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.BatchNorm1d(hidden_dim // 2),
                nn.ELU(),
                nn.Dropout(dropout / 2),
                nn.Linear(hidden_dim // 2, 2)  # [not_fp, is_fp]
            )

        # Task attention (learns to weight task importance)
        num_tasks = 1 + int(use_validation_head) + int(use_fp_head)
        self.task_attention = nn.Linear(hidden_dim, num_tasks)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass with multi-task outputs

        Args:
            x: Node features (num_nodes, input_dim)
            edge_index: Edge indices (2, num_edges)
            batch: Batch assignment (num_nodes,)

        Returns:
            Dictionary with task outputs:
            {
                'vulnerability': (batch_size, 2),
                'validation': (batch_size, 3) if use_validation_head,
                'false_positive': (batch_size, 2) if use_fp_head,
                'shared_repr': (batch_size, hidden_dim)
            }
        """
        # Shared GNN encoding
        h1 = F.elu(self.gnn1(x, edge_index))
        h1 = self.dropout(h1)

        h2 = F.elu(self.gnn2(h1, edge_index))
        h2 = self.dropout(h2)

        h3 = F.elu(self.gnn3(h2, edge_index))

        # Shared Transformer encoding
        h_transformed = self.transformer(h3.unsqueeze(1)).squeeze(1)

        # Global pooling (combine mean and max)
        h_mean = global_mean_pool(h_transformed, batch)
        h_max = global_max_pool(h_transformed, batch)
        h_pooled = torch.cat([h_mean, h_max], dim=1)

        # Shared representation
        h_pooled = self.bn_shared(h_pooled)
        shared_repr = self.shared_fc(h_pooled)  # (batch_size, hidden_dim)

        # Task attention weights
        task_weights = torch.softmax(self.task_attention(shared_repr), dim=1)

        # Task 1: Vulnerability Detection (always computed)
        vuln_logits = self.vulnerability_head(shared_repr)

        outputs = {
            'vulnerability': vuln_logits,
            'shared_repr': shared_repr,
            'task_weights': task_weights
        }

        # Task 2: Validation Status (optional)
        if self.use_validation_head:
            validation_logits = self.validation_head(shared_repr)
            outputs['validation'] = validation_logits

        # Task 3: False Positive (optional)
        if self.use_fp_head:
            fp_logits = self.fp_head(shared_repr)
            outputs['false_positive'] = fp_logits

        return outputs


class MultiTaskLoss(nn.Module):
    """
    Multi-task loss with uncertainty weighting
    Automatically balances task losses during training

    Based on: "Multi-Task Learning Using Uncertainty to Weigh Losses for Scene Geometry and Semantics"
    """

    def __init__(
        self,
        use_validation: bool = True,
        use_fp: bool = True,
        vuln_weight: float = 1.0,
        validation_weight: float = 0.5,
        fp_weight: float = 0.7
    ):
        super().__init__()

        self.use_validation = use_validation
        self.use_fp = use_fp

        # Learnable task weights (log variance)
        self.log_var_vuln = nn.Parameter(torch.zeros(1))

        if use_validation:
            self.log_var_validation = nn.Parameter(torch.zeros(1))

        if use_fp:
            self.log_var_fp = nn.Parameter(torch.zeros(1))

        # Manual weights (fallback)
        self.vuln_weight = vuln_weight
        self.validation_weight = validation_weight
        self.fp_weight = fp_weight

        # Loss functions
        # Vulnerability: Use focal loss for imbalance
        self.vuln_criterion = FocalLoss(alpha=0.25, gamma=2.0)

        # Validation: Use cross-entropy (3 classes)
        self.validation_criterion = nn.CrossEntropyLoss()

        # False Positive: Use weighted cross-entropy (FPs are rare)
        fp_class_weights = torch.tensor([1.0, 5.0])  # Weight FP class higher
        self.fp_criterion = nn.CrossEntropyLoss(weight=fp_class_weights)

    def forward(
        self,
        predictions: Dict[str, torch.Tensor],
        labels: Dict[str, torch.Tensor],
        use_uncertainty_weighting: bool = True
    ) -> Tuple[torch.Tensor, Dict[str, torch.Tensor]]:
        """
        Compute multi-task loss

        Args:
            predictions: Dict with 'vulnerability', 'validation', 'false_positive'
            labels: Dict with same keys as predictions
            use_uncertainty_weighting: Use learnable uncertainty weights

        Returns:
            (total_loss, individual_losses_dict)
        """
        losses = {}

        # Task 1: Vulnerability Detection
        vuln_loss = self.vuln_criterion(
            predictions['vulnerability'],
            labels['vulnerability']
        )
        losses['vulnerability'] = vuln_loss

        # Task 2: Validation Status
        if self.use_validation and 'validation' in predictions:
            validation_loss = self.validation_criterion(
                predictions['validation'],
                labels['validation']
            )
            losses['validation'] = validation_loss

        # Task 3: False Positive
        if self.use_fp and 'false_positive' in predictions:
            fp_loss = self.fp_criterion(
                predictions['false_positive'],
                labels['false_positive']
            )
            losses['false_positive'] = fp_loss

        # Combine losses
        if use_uncertainty_weighting:
            # Uncertainty-based weighting
            total_loss = 0.0

            # Vulnerability
            precision_vuln = torch.exp(-self.log_var_vuln)
            total_loss += precision_vuln * vuln_loss + self.log_var_vuln

            # Validation
            if self.use_validation and 'validation' in losses:
                precision_val = torch.exp(-self.log_var_validation)
                total_loss += precision_val * losses['validation'] + self.log_var_validation

            # False Positive
            if self.use_fp and 'false_positive' in losses:
                precision_fp = torch.exp(-self.log_var_fp)
                total_loss += precision_fp * losses['false_positive'] + self.log_var_fp

        else:
            # Manual weighting
            total_loss = self.vuln_weight * vuln_loss

            if self.use_validation and 'validation' in losses:
                total_loss += self.validation_weight * losses['validation']

            if self.use_fp and 'false_positive' in losses:
                total_loss += self.fp_weight * losses['false_positive']

        losses['total'] = total_loss

        return total_loss, losses


class FocalLoss(nn.Module):
    """
    Focal Loss for imbalanced vulnerability detection
    """

    def __init__(self, alpha: float = 0.25, gamma: float = 2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1 - pt) ** self.gamma * ce_loss
        return focal_loss.mean()


# Example usage
if __name__ == "__main__":
    # Initialize model
    model = MultiTaskGNNTransformer(
        input_dim=128,
        hidden_dim=256,
        num_heads=8,
        dropout=0.3,
        use_validation_head=True,
        use_fp_head=True
    )

    # Dummy input
    batch_size = 4
    num_nodes = 50
    x = torch.randn(num_nodes, 128)
    edge_index = torch.randint(0, num_nodes, (2, 100))
    batch = torch.repeat_interleave(torch.arange(batch_size), num_nodes // batch_size)

    # Forward pass
    outputs = model(x, edge_index, batch)

    print("Multi-Task Model Test:")
    print(f"  Vulnerability output: {outputs['vulnerability'].shape}")
    if 'validation' in outputs:
        print(f"  Validation output: {outputs['validation'].shape}")
    if 'false_positive' in outputs:
        print(f"  False Positive output: {outputs['false_positive'].shape}")

    # Test loss
    loss_fn = MultiTaskLoss(use_validation=True, use_fp=True)

    labels = {
        'vulnerability': torch.randint(0, 2, (batch_size,)),
        'validation': torch.randint(0, 3, (batch_size,)),
        'false_positive': torch.randint(0, 2, (batch_size,))
    }

    total_loss, individual_losses = loss_fn(outputs, labels)

    print(f"\nLoss Test:")
    print(f"  Total loss: {total_loss.item():.4f}")
    for task, loss in individual_losses.items():
        print(f"  {task}: {loss.item():.4f}")

    print("\n✅ Multi-task model test passed!")
