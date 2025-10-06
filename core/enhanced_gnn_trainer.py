#!/usr/bin/env python3
"""
VulnHunter Enhanced GNN-Transformer Training Loop
Optimized for 96-98% accuracy with focal loss, cosine scheduling, and early stopping
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts
from torch.cuda.amp import autocast, GradScaler
from torch_geometric.loader import DataLoader
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support, confusion_matrix
import logging
from typing import Dict, Tuple, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FocalLoss(nn.Module):
    """
    Focal Loss for imbalanced classification (91% vulnerable / 9% safe)
    Focuses training on hard examples and down-weights easy examples
    """
    def __init__(self, alpha=0.25, gamma=2.0, reduction='mean'):
        """
        Args:
            alpha: Weight for positive class (0.25 for minority class emphasis)
            gamma: Focusing parameter (2.0 standard, higher = more focus on hard examples)
            reduction: 'mean' or 'sum'
        """
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, inputs, targets):
        """
        Args:
            inputs: Model predictions (batch_size, num_classes)
            targets: Ground truth labels (batch_size,)
        """
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)  # Probability of true class

        # Apply focal term: (1 - pt)^gamma
        focal_term = (1 - pt) ** self.gamma

        # Apply alpha weighting
        alpha_t = self.alpha * targets + (1 - self.alpha) * (1 - targets)

        focal_loss = alpha_t * focal_term * ce_loss

        if self.reduction == 'mean':
            return focal_loss.mean()
        elif self.reduction == 'sum':
            return focal_loss.sum()
        else:
            return focal_loss


class LabelSmoothingLoss(nn.Module):
    """
    Label smoothing regularization to prevent overconfidence
    Improves generalization by softening hard targets
    """
    def __init__(self, classes=2, smoothing=0.1):
        super().__init__()
        self.confidence = 1.0 - smoothing
        self.smoothing = smoothing
        self.classes = classes

    def forward(self, pred, target):
        pred = pred.log_softmax(dim=-1)
        with torch.no_grad():
            true_dist = torch.zeros_like(pred)
            true_dist.fill_(self.smoothing / (self.classes - 1))
            true_dist.scatter_(1, target.unsqueeze(1), self.confidence)
        return torch.mean(torch.sum(-true_dist * pred, dim=-1))


class EnhancedGNNTrainer:
    """
    Production-ready trainer for GNN-Transformer vulnerability detection
    Features: Focal loss, cosine annealing, mixed precision, early stopping
    """

    def __init__(
        self,
        model: nn.Module,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        loss_type: str = 'focal',  # 'focal', 'label_smoothing', or 'ce'
        focal_alpha: float = 0.25,  # Weight for safe class (minority)
        focal_gamma: float = 2.0,
        use_mixed_precision: bool = True,
        gradient_accumulation_steps: int = 1
    ):
        self.model = model.to(device)
        self.device = device
        self.use_mixed_precision = use_mixed_precision and torch.cuda.is_available()
        self.gradient_accumulation_steps = gradient_accumulation_steps

        # Loss function selection
        if loss_type == 'focal':
            self.criterion = FocalLoss(alpha=focal_alpha, gamma=focal_gamma)
            logger.info(f"Using Focal Loss (alpha={focal_alpha}, gamma={focal_gamma})")
        elif loss_type == 'label_smoothing':
            self.criterion = LabelSmoothingLoss(classes=2, smoothing=0.1)
            logger.info("Using Label Smoothing Loss")
        else:
            # Compute class weights for imbalanced data
            # For 91% vulnerable (class 1) and 9% safe (class 0)
            # Weight safe class higher: 0.09 -> ~11.0, vulnerable: 0.91 -> ~1.1
            class_weights = torch.tensor([10.0, 1.0]).to(device)
            self.criterion = nn.CrossEntropyLoss(weight=class_weights)
            logger.info("Using Weighted Cross Entropy")

        # Mixed precision scaler
        self.scaler = GradScaler() if self.use_mixed_precision else None

        # Metrics tracking
        self.train_losses = []
        self.val_losses = []
        self.val_f1_scores = []
        self.best_val_f1 = 0.0
        self.best_model_state = None

    def setup_optimizer_scheduler(
        self,
        learning_rate: float = 1e-3,
        weight_decay: float = 0.01,
        warmup_epochs: int = 5,
        max_epochs: int = 100
    ):
        """
        Configure AdamW optimizer with cosine annealing warm restarts
        """
        # AdamW optimizer (better than Adam for regularization)
        self.optimizer = AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay,  # L2 regularization
            betas=(0.9, 0.999),
            eps=1e-8
        )

        # Cosine Annealing with Warm Restarts
        # Restarts every T_0 epochs, with period multiplication by T_mult
        self.scheduler = CosineAnnealingWarmRestarts(
            self.optimizer,
            T_0=10,  # First restart after 10 epochs
            T_mult=2,  # Double the period after each restart
            eta_min=1e-6  # Minimum learning rate
        )

        logger.info(f"Optimizer: AdamW(lr={learning_rate}, weight_decay={weight_decay})")
        logger.info(f"Scheduler: CosineAnnealingWarmRestarts(T_0=10, T_mult=2)")

    def train_epoch(self, train_loader: DataLoader, epoch: int) -> float:
        """
        Train for one epoch with gradient accumulation and mixed precision
        """
        self.model.train()
        total_loss = 0.0
        num_batches = len(train_loader)

        self.optimizer.zero_grad()

        for batch_idx, batch in enumerate(train_loader):
            batch = batch.to(self.device)

            # Mixed precision forward pass
            if self.use_mixed_precision:
                with autocast():
                    out = self.model(batch.x, batch.edge_index, batch.batch)
                    loss = self.criterion(out, batch.y) / self.gradient_accumulation_steps

                # Scaled backward pass
                self.scaler.scale(loss).backward()

                # Gradient accumulation: update every N steps
                if (batch_idx + 1) % self.gradient_accumulation_steps == 0:
                    # Gradient clipping to prevent exploding gradients
                    self.scaler.unscale_(self.optimizer)
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

                    self.scaler.step(self.optimizer)
                    self.scaler.update()
                    self.optimizer.zero_grad()
            else:
                # Standard training (CPU or non-mixed precision)
                out = self.model(batch.x, batch.edge_index, batch.batch)
                loss = self.criterion(out, batch.y) / self.gradient_accumulation_steps
                loss.backward()

                if (batch_idx + 1) % self.gradient_accumulation_steps == 0:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                    self.optimizer.step()
                    self.optimizer.zero_grad()

            total_loss += loss.item() * self.gradient_accumulation_steps

            # Log progress every 10% of epoch
            if (batch_idx + 1) % max(1, num_batches // 10) == 0:
                logger.info(
                    f"Epoch {epoch} [{batch_idx + 1}/{num_batches}] "
                    f"Loss: {loss.item() * self.gradient_accumulation_steps:.4f}"
                )

        avg_loss = total_loss / num_batches
        return avg_loss

    def validate(self, val_loader: DataLoader) -> Dict[str, float]:
        """
        Validate model and return comprehensive metrics
        """
        self.model.eval()
        total_loss = 0.0
        all_preds = []
        all_labels = []
        all_probs = []

        with torch.no_grad():
            for batch in val_loader:
                batch = batch.to(self.device)

                if self.use_mixed_precision:
                    with autocast():
                        out = self.model(batch.x, batch.edge_index, batch.batch)
                        loss = self.criterion(out, batch.y)
                else:
                    out = self.model(batch.x, batch.edge_index, batch.batch)
                    loss = self.criterion(out, batch.y)

                total_loss += loss.item()

                # Get predictions
                probs = F.softmax(out, dim=1)
                preds = torch.argmax(out, dim=1)

                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch.y.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())  # Probability of vulnerable class

        # Compute metrics
        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)
        all_probs = np.array(all_probs)

        accuracy = accuracy_score(all_labels, all_preds)
        f1_weighted = f1_score(all_labels, all_preds, average='weighted')
        f1_macro = f1_score(all_labels, all_preds, average='macro')

        precision, recall, f1_per_class, support = precision_recall_fscore_support(
            all_labels, all_preds, average=None
        )

        # Confusion matrix
        cm = confusion_matrix(all_labels, all_preds)

        metrics = {
            'loss': total_loss / len(val_loader),
            'accuracy': accuracy,
            'f1_weighted': f1_weighted,
            'f1_macro': f1_macro,
            'f1_safe': f1_per_class[0],  # Safe class (minority)
            'f1_vulnerable': f1_per_class[1],  # Vulnerable class
            'precision_safe': precision[0],
            'recall_safe': recall[0],
            'precision_vulnerable': precision[1],
            'recall_vulnerable': recall[1],
            'confusion_matrix': cm
        }

        return metrics

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 100,
        early_stopping_patience: int = 20,
        save_path: str = 'best_gnn_model.pth'
    ) -> Dict:
        """
        Complete training loop with early stopping

        Returns:
            Training history and best metrics
        """
        logger.info("=" * 80)
        logger.info("Starting Enhanced GNN-Transformer Training")
        logger.info("=" * 80)
        logger.info(f"Device: {self.device}")
        logger.info(f"Mixed Precision: {self.use_mixed_precision}")
        logger.info(f"Gradient Accumulation Steps: {self.gradient_accumulation_steps}")
        logger.info(f"Total Epochs: {epochs}")
        logger.info(f"Early Stopping Patience: {early_stopping_patience}")
        logger.info("=" * 80)

        patience_counter = 0
        history = {
            'train_loss': [],
            'val_loss': [],
            'val_accuracy': [],
            'val_f1_weighted': [],
            'val_f1_safe': [],
            'learning_rates': []
        }

        for epoch in range(1, epochs + 1):
            # Training
            train_loss = self.train_epoch(train_loader, epoch)

            # Validation
            val_metrics = self.validate(val_loader)

            # Step scheduler
            self.scheduler.step()
            current_lr = self.optimizer.param_groups[0]['lr']

            # Log metrics
            logger.info(f"\n{'=' * 80}")
            logger.info(f"Epoch {epoch}/{epochs} Summary:")
            logger.info(f"  Train Loss: {train_loss:.4f}")
            logger.info(f"  Val Loss: {val_metrics['loss']:.4f}")
            logger.info(f"  Val Accuracy: {val_metrics['accuracy']:.4f}")
            logger.info(f"  Val F1 (weighted): {val_metrics['f1_weighted']:.4f}")
            logger.info(f"  Val F1 (macro): {val_metrics['f1_macro']:.4f}")
            logger.info(f"  Safe Class - P: {val_metrics['precision_safe']:.4f}, "
                       f"R: {val_metrics['recall_safe']:.4f}, F1: {val_metrics['f1_safe']:.4f}")
            logger.info(f"  Vulnerable Class - P: {val_metrics['precision_vulnerable']:.4f}, "
                       f"R: {val_metrics['recall_vulnerable']:.4f}, F1: {val_metrics['f1_vulnerable']:.4f}")
            logger.info(f"  Learning Rate: {current_lr:.6f}")
            logger.info(f"  Confusion Matrix:\n{val_metrics['confusion_matrix']}")

            # Save history
            history['train_loss'].append(train_loss)
            history['val_loss'].append(val_metrics['loss'])
            history['val_accuracy'].append(val_metrics['accuracy'])
            history['val_f1_weighted'].append(val_metrics['f1_weighted'])
            history['val_f1_safe'].append(val_metrics['f1_safe'])
            history['learning_rates'].append(current_lr)

            # Early stopping based on F1 score
            if val_metrics['f1_weighted'] > self.best_val_f1:
                self.best_val_f1 = val_metrics['f1_weighted']
                self.best_model_state = self.model.state_dict().copy()
                patience_counter = 0

                # Save best model
                torch.save({
                    'epoch': epoch,
                    'model_state_dict': self.model.state_dict(),
                    'optimizer_state_dict': self.optimizer.state_dict(),
                    'scheduler_state_dict': self.scheduler.state_dict(),
                    'val_metrics': val_metrics,
                    'best_f1': self.best_val_f1
                }, save_path)

                logger.info(f"  ✅ New best F1: {self.best_val_f1:.4f} - Model saved!")
            else:
                patience_counter += 1
                logger.info(f"  ⏳ No improvement. Patience: {patience_counter}/{early_stopping_patience}")

            # Early stopping
            if patience_counter >= early_stopping_patience:
                logger.info(f"\n🛑 Early stopping triggered at epoch {epoch}")
                logger.info(f"Best F1: {self.best_val_f1:.4f}")
                break

            logger.info("=" * 80)

        # Load best model
        if self.best_model_state:
            self.model.load_state_dict(self.best_model_state)
            logger.info("\n✅ Loaded best model weights")

        logger.info("\n" + "=" * 80)
        logger.info("Training Complete!")
        logger.info(f"Best Validation F1: {self.best_val_f1:.4f}")
        logger.info("=" * 80)

        return history


# Example usage
if __name__ == "__main__":
    from torch_geometric.nn import GATConv, GCNConv, global_mean_pool, global_max_pool

    class EnhancedGNNTransformer(nn.Module):
        """Enhanced GNN-Transformer from your code"""
        def __init__(self, input_dim, hidden_dim=256, num_heads=8, dropout=0.3):
            super().__init__()
            self.gnn1 = GATConv(input_dim, hidden_dim, heads=num_heads, dropout=dropout)
            self.gnn2 = GATConv(hidden_dim * num_heads, hidden_dim, heads=4, dropout=dropout)
            self.gnn3 = GCNConv(hidden_dim * 4, hidden_dim)

            encoder_layer = nn.TransformerEncoderLayer(
                d_model=hidden_dim, nhead=num_heads, dim_feedforward=hidden_dim * 4,
                dropout=dropout, activation='gelu', batch_first=True
            )
            self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=6)
            self.dropout = nn.Dropout(dropout)
            self.bn1 = nn.BatchNorm1d(hidden_dim * 2)
            self.fc1 = nn.Linear(hidden_dim * 2, hidden_dim // 2)
            self.bn2 = nn.BatchNorm1d(hidden_dim // 2)
            self.fc2 = nn.Linear(hidden_dim // 2, 2)

        def forward(self, x, edge_index, batch):
            h1 = F.elu(self.gnn1(x, edge_index))
            h2 = F.elu(self.gnn2(h1, edge_index))
            h3 = F.elu(self.gnn3(h2, edge_index))
            h_transformed = self.transformer(h3.unsqueeze(1)).squeeze(1)
            h_mean = global_mean_pool(h_transformed, batch)
            h_max = global_max_pool(h_transformed, batch)
            h = torch.cat([h_mean, h_max], dim=1)
            h = self.bn1(h)
            h = F.elu(self.fc1(h))
            h = self.dropout(h)
            h = self.bn2(h)
            out = self.fc2(h)
            return out

    # Initialize model
    model = EnhancedGNNTransformer(input_dim=128, hidden_dim=256, num_heads=8, dropout=0.3)

    # Create trainer
    trainer = EnhancedGNNTrainer(
        model=model,
        loss_type='focal',
        focal_alpha=0.25,  # Weight for safe class (9% minority)
        focal_gamma=2.0,
        use_mixed_precision=True,
        gradient_accumulation_steps=4  # For large models/small GPU memory
    )

    # Setup optimizer and scheduler
    trainer.setup_optimizer_scheduler(
        learning_rate=1e-3,
        weight_decay=0.01,
        max_epochs=100
    )

    # Train (with your data loaders)
    # history = trainer.train(
    #     train_loader=train_loader,
    #     val_loader=val_loader,
    #     epochs=100,
    #     early_stopping_patience=20,
    #     save_path='best_vulnhunter_gnn.pth'
    # )
