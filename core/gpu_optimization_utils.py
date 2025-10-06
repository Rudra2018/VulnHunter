#!/usr/bin/env python3
"""
VulnHunter GPU Optimization & Threshold Tuning Utilities
Handles OOM errors and optimizes classification thresholds for imbalanced data
"""

import torch
import torch.nn as nn
import numpy as np
from torch.cuda.amp import autocast, GradScaler
from typing import Dict, Optional, Tuple, List
import logging
from sklearn.metrics import (
    precision_recall_curve,
    f1_score,
    accuracy_score,
    precision_score,
    recall_score,
    roc_curve,
    auc
)
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GPUMemoryOptimizer:
    """
    GPU memory optimization utilities for large models
    Handles OOM errors through gradient accumulation, checkpointing, and mixed precision
    """

    @staticmethod
    def estimate_model_memory(model: nn.Module) -> Dict[str, float]:
        """
        Estimate GPU memory usage of model

        Returns:
            Dictionary with memory estimates in MB
        """
        param_size = 0
        buffer_size = 0

        for param in model.parameters():
            param_size += param.nelement() * param.element_size()

        for buffer in model.buffers():
            buffer_size += buffer.nelement() * buffer.element_size()

        total_size_mb = (param_size + buffer_size) / 1024**2

        return {
            'parameters_mb': param_size / 1024**2,
            'buffers_mb': buffer_size / 1024**2,
            'total_mb': total_size_mb
        }

    @staticmethod
    def optimize_batch_size(
        model: nn.Module,
        sample_input: Dict,
        max_memory_mb: float = 10000,
        initial_batch_size: int = 32
    ) -> int:
        """
        Find optimal batch size that fits in GPU memory

        Args:
            model: PyTorch model
            sample_input: Sample input dict (e.g., {'x': tensor, 'edge_index': tensor, 'batch': tensor})
            max_memory_mb: Maximum GPU memory to use (MB)
            initial_batch_size: Starting batch size to test

        Returns:
            Optimal batch size
        """
        if not torch.cuda.is_available():
            logger.warning("CUDA not available, returning initial batch size")
            return initial_batch_size

        device = torch.device('cuda')
        model = model.to(device)
        model.eval()

        batch_size = initial_batch_size

        while batch_size > 1:
            try:
                torch.cuda.empty_cache()

                # Create batched input
                batched_input = {}
                for key, value in sample_input.items():
                    if torch.is_tensor(value):
                        # Repeat tensor to simulate batch
                        batched_input[key] = value.repeat(batch_size, 1).to(device)

                # Test forward pass
                with torch.no_grad():
                    if 'edge_index' in batched_input:  # GNN model
                        _ = model(
                            batched_input['x'],
                            batched_input['edge_index'],
                            batched_input['batch']
                        )
                    else:  # Standard model
                        _ = model(**batched_input)

                # Check memory usage
                memory_used = torch.cuda.max_memory_allocated() / 1024**2

                if memory_used < max_memory_mb:
                    logger.info(f"✅ Batch size {batch_size} fits in {memory_used:.2f} MB")
                    return batch_size
                else:
                    logger.info(f"⚠️  Batch size {batch_size} uses {memory_used:.2f} MB, reducing...")
                    batch_size //= 2

            except RuntimeError as e:
                if 'out of memory' in str(e):
                    logger.warning(f"OOM at batch size {batch_size}, reducing...")
                    batch_size //= 2
                    torch.cuda.empty_cache()
                else:
                    raise e

        logger.warning(f"Minimum batch size reached: {batch_size}")
        return max(1, batch_size)

    @staticmethod
    def clear_gpu_memory():
        """Clear GPU cache and collect garbage"""
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()

        import gc
        gc.collect()

    @staticmethod
    def print_gpu_memory_summary():
        """Print GPU memory usage summary"""
        if not torch.cuda.is_available():
            logger.info("CUDA not available")
            return

        for i in range(torch.cuda.device_count()):
            device = torch.device(f'cuda:{i}')
            allocated = torch.cuda.memory_allocated(device) / 1024**2
            reserved = torch.cuda.memory_reserved(device) / 1024**2
            max_allocated = torch.cuda.max_memory_allocated(device) / 1024**2

            logger.info(f"\nGPU {i} Memory:")
            logger.info(f"  Allocated: {allocated:.2f} MB")
            logger.info(f"  Reserved: {reserved:.2f} MB")
            logger.info(f"  Max Allocated: {max_allocated:.2f} MB")


class GradientAccumulationTrainer:
    """
    Training with gradient accumulation to handle large models on limited GPU memory
    """

    def __init__(
        self,
        model: nn.Module,
        optimizer: torch.optim.Optimizer,
        criterion: nn.Module,
        accumulation_steps: int = 4,
        use_mixed_precision: bool = True,
        max_grad_norm: float = 1.0,
        device: str = None
    ):
        """
        Args:
            model: PyTorch model
            optimizer: Optimizer
            criterion: Loss function
            accumulation_steps: Number of steps to accumulate gradients
            use_mixed_precision: Use automatic mixed precision (AMP)
            max_grad_norm: Max norm for gradient clipping
            device: Device for training
        """
        self.model = model
        self.optimizer = optimizer
        self.criterion = criterion
        self.accumulation_steps = accumulation_steps
        self.use_mixed_precision = use_mixed_precision and torch.cuda.is_available()
        self.max_grad_norm = max_grad_norm
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')

        self.scaler = GradScaler() if self.use_mixed_precision else None

        logger.info("Gradient Accumulation Trainer initialized")
        logger.info(f"  Accumulation steps: {accumulation_steps}")
        logger.info(f"  Mixed precision: {self.use_mixed_precision}")
        logger.info(f"  Max grad norm: {max_grad_norm}")

    def train_step(self, batch, step_idx: int) -> float:
        """
        Single training step with gradient accumulation

        Args:
            batch: Training batch
            step_idx: Current step index

        Returns:
            Loss value
        """
        # Move batch to device
        batch = batch.to(self.device)

        # Mixed precision forward pass
        if self.use_mixed_precision:
            with autocast():
                output = self.model(batch.x, batch.edge_index, batch.batch)
                loss = self.criterion(output, batch.y)
                loss = loss / self.accumulation_steps  # Normalize loss

            # Scaled backward pass
            self.scaler.scale(loss).backward()

            # Update weights every accumulation_steps
            if (step_idx + 1) % self.accumulation_steps == 0:
                # Unscale and clip gradients
                self.scaler.unscale_(self.optimizer)
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(),
                    self.max_grad_norm
                )

                # Optimizer step
                self.scaler.step(self.optimizer)
                self.scaler.update()
                self.optimizer.zero_grad()

        else:
            # Standard training
            output = self.model(batch.x, batch.edge_index, batch.batch)
            loss = self.criterion(output, batch.y)
            loss = loss / self.accumulation_steps

            loss.backward()

            if (step_idx + 1) % self.accumulation_steps == 0:
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(),
                    self.max_grad_norm
                )
                self.optimizer.step()
                self.optimizer.zero_grad()

        return loss.item() * self.accumulation_steps


class ThresholdOptimizer:
    """
    Optimize classification threshold for imbalanced datasets
    Particularly useful for improving minority class (safe) F1 score
    """

    def __init__(self, target_metric: str = 'f1_weighted'):
        """
        Args:
            target_metric: Metric to optimize ('f1_weighted', 'f1_safe', 'f1_macro', 'balanced_accuracy')
        """
        self.target_metric = target_metric
        self.optimal_threshold = 0.5
        self.metrics_at_optimal = {}

        logger.info(f"Threshold Optimizer initialized (target metric: {target_metric})")

    def find_optimal_threshold(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        thresholds: Optional[np.ndarray] = None,
        plot_path: Optional[str] = None
    ) -> Tuple[float, Dict]:
        """
        Find optimal classification threshold

        Args:
            y_true: True labels (0 or 1)
            y_proba: Predicted probabilities for class 1
            thresholds: Array of thresholds to test (default: 0.01 to 0.99)
            plot_path: If provided, save threshold analysis plot

        Returns:
            (optimal_threshold, metrics_dict)
        """
        if thresholds is None:
            thresholds = np.arange(0.01, 1.00, 0.01)

        best_score = 0.0
        best_threshold = 0.5
        results = []

        logger.info(f"Testing {len(thresholds)} thresholds...")

        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)

            # Compute metrics
            accuracy = accuracy_score(y_true, y_pred)
            f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
            f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)

            # Per-class metrics
            precision_per_class = precision_score(y_true, y_pred, average=None, zero_division=0)
            recall_per_class = recall_score(y_true, y_pred, average=None, zero_division=0)
            f1_per_class = f1_score(y_true, y_pred, average=None, zero_division=0)

            f1_safe = f1_per_class[0] if len(f1_per_class) > 0 else 0
            f1_vulnerable = f1_per_class[1] if len(f1_per_class) > 1 else 0

            # Balanced accuracy (average of per-class recalls)
            balanced_acc = np.mean(recall_per_class)

            metrics = {
                'threshold': threshold,
                'accuracy': accuracy,
                'f1_weighted': f1_weighted,
                'f1_macro': f1_macro,
                'f1_safe': f1_safe,
                'f1_vulnerable': f1_vulnerable,
                'balanced_accuracy': balanced_acc,
                'precision_safe': precision_per_class[0] if len(precision_per_class) > 0 else 0,
                'recall_safe': recall_per_class[0] if len(recall_per_class) > 0 else 0,
                'precision_vulnerable': precision_per_class[1] if len(precision_per_class) > 1 else 0,
                'recall_vulnerable': recall_per_class[1] if len(recall_per_class) > 1 else 0
            }

            results.append(metrics)

            # Check if this is the best threshold
            score = metrics[self.target_metric]
            if score > best_score:
                best_score = score
                best_threshold = threshold
                self.metrics_at_optimal = metrics

        self.optimal_threshold = best_threshold

        logger.info("\n" + "=" * 80)
        logger.info(f"Optimal Threshold Found: {best_threshold:.3f}")
        logger.info("=" * 80)
        logger.info(f"Target Metric ({self.target_metric}): {best_score:.4f}")
        logger.info(f"\nMetrics at optimal threshold:")
        logger.info(f"  Accuracy: {self.metrics_at_optimal['accuracy']:.4f}")
        logger.info(f"  F1 (weighted): {self.metrics_at_optimal['f1_weighted']:.4f}")
        logger.info(f"  F1 (macro): {self.metrics_at_optimal['f1_macro']:.4f}")
        logger.info(f"  Balanced Accuracy: {self.metrics_at_optimal['balanced_accuracy']:.4f}")
        logger.info(f"\n  Safe Class:")
        logger.info(f"    Precision: {self.metrics_at_optimal['precision_safe']:.4f}")
        logger.info(f"    Recall: {self.metrics_at_optimal['recall_safe']:.4f}")
        logger.info(f"    F1: {self.metrics_at_optimal['f1_safe']:.4f}")
        logger.info(f"\n  Vulnerable Class:")
        logger.info(f"    Precision: {self.metrics_at_optimal['precision_vulnerable']:.4f}")
        logger.info(f"    Recall: {self.metrics_at_optimal['recall_vulnerable']:.4f}")
        logger.info(f"    F1: {self.metrics_at_optimal['f1_vulnerable']:.4f}")
        logger.info("=" * 80)

        # Plot analysis
        if plot_path:
            self._plot_threshold_analysis(results, plot_path)

        return best_threshold, self.metrics_at_optimal

    def _plot_threshold_analysis(self, results: List[Dict], save_path: str):
        """Plot threshold vs metrics"""
        thresholds = [r['threshold'] for r in results]

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))

        # Plot 1: F1 scores
        axes[0, 0].plot(thresholds, [r['f1_weighted'] for r in results], label='F1 Weighted', linewidth=2)
        axes[0, 0].plot(thresholds, [r['f1_macro'] for r in results], label='F1 Macro', linewidth=2)
        axes[0, 0].plot(thresholds, [r['f1_safe'] for r in results], label='F1 Safe', linewidth=2)
        axes[0, 0].plot(thresholds, [r['f1_vulnerable'] for r in results], label='F1 Vulnerable', linewidth=2)
        axes[0, 0].axvline(self.optimal_threshold, color='red', linestyle='--', label='Optimal')
        axes[0, 0].set_xlabel('Threshold')
        axes[0, 0].set_ylabel('F1 Score')
        axes[0, 0].set_title('F1 Scores vs Threshold')
        axes[0, 0].legend()
        axes[0, 0].grid(True)

        # Plot 2: Accuracy & Balanced Accuracy
        axes[0, 1].plot(thresholds, [r['accuracy'] for r in results], label='Accuracy', linewidth=2)
        axes[0, 1].plot(thresholds, [r['balanced_accuracy'] for r in results], label='Balanced Accuracy', linewidth=2)
        axes[0, 1].axvline(self.optimal_threshold, color='red', linestyle='--', label='Optimal')
        axes[0, 1].set_xlabel('Threshold')
        axes[0, 1].set_ylabel('Score')
        axes[0, 1].set_title('Accuracy vs Threshold')
        axes[0, 1].legend()
        axes[0, 1].grid(True)

        # Plot 3: Precision
        axes[1, 0].plot(thresholds, [r['precision_safe'] for r in results], label='Precision Safe', linewidth=2)
        axes[1, 0].plot(thresholds, [r['precision_vulnerable'] for r in results], label='Precision Vulnerable', linewidth=2)
        axes[1, 0].axvline(self.optimal_threshold, color='red', linestyle='--', label='Optimal')
        axes[1, 0].set_xlabel('Threshold')
        axes[1, 0].set_ylabel('Precision')
        axes[1, 0].set_title('Precision vs Threshold')
        axes[1, 0].legend()
        axes[1, 0].grid(True)

        # Plot 4: Recall
        axes[1, 1].plot(thresholds, [r['recall_safe'] for r in results], label='Recall Safe', linewidth=2)
        axes[1, 1].plot(thresholds, [r['recall_vulnerable'] for r in results], label='Recall Vulnerable', linewidth=2)
        axes[1, 1].axvline(self.optimal_threshold, color='red', linestyle='--', label='Optimal')
        axes[1, 1].set_xlabel('Threshold')
        axes[1, 1].set_ylabel('Recall')
        axes[1, 1].set_title('Recall vs Threshold')
        axes[1, 1].legend()
        axes[1, 1].grid(True)

        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        logger.info(f"Threshold analysis plot saved to {save_path}")
        plt.close()

    def predict_with_optimal_threshold(
        self,
        y_proba: np.ndarray
    ) -> np.ndarray:
        """
        Make predictions using the optimal threshold

        Args:
            y_proba: Predicted probabilities for class 1

        Returns:
            Binary predictions (0 or 1)
        """
        return (y_proba >= self.optimal_threshold).astype(int)


# Example usage and debugging utilities
def diagnose_gpu_oom_error(model: nn.Module, sample_batch):
    """
    Diagnose GPU OOM errors and suggest solutions
    """
    logger.info("\n" + "=" * 80)
    logger.info("GPU OOM Error Diagnosis")
    logger.info("=" * 80)

    optimizer = GPUMemoryOptimizer()

    # Check model size
    memory_info = optimizer.estimate_model_memory(model)
    logger.info(f"\nModel Memory Usage:")
    logger.info(f"  Parameters: {memory_info['parameters_mb']:.2f} MB")
    logger.info(f"  Buffers: {memory_info['buffers_mb']:.2f} MB")
    logger.info(f"  Total: {memory_info['total_mb']:.2f} MB")

    # Check GPU memory
    optimizer.print_gpu_memory_summary()

    # Suggest solutions
    logger.info("\n" + "=" * 80)
    logger.info("Suggested Solutions:")
    logger.info("=" * 80)
    logger.info("1. Reduce batch size (try batch_size = batch_size // 2)")
    logger.info("2. Use gradient accumulation (accumulation_steps=4 or 8)")
    logger.info("3. Enable mixed precision training (use_mixed_precision=True)")
    logger.info("4. Use gradient checkpointing for transformer layers")
    logger.info("5. Reduce model size (fewer layers or smaller hidden_dim)")
    logger.info("6. Clear GPU cache: torch.cuda.empty_cache()")

    # Find optimal batch size
    # optimal_bs = optimizer.optimize_batch_size(model, sample_batch)
    # logger.info(f"\nRecommended batch size: {optimal_bs}")


if __name__ == "__main__":
    logger.info("GPU Optimization & Threshold Tuning Utilities")

    # Test threshold optimization
    from sklearn.datasets import make_classification

    # Simulate imbalanced predictions
    y_true = np.random.choice([0, 1], size=1000, p=[0.09, 0.91])
    y_proba = np.random.random(1000)

    optimizer = ThresholdOptimizer(target_metric='f1_macro')
    optimal_threshold, metrics = optimizer.find_optimal_threshold(
        y_true,
        y_proba,
        plot_path='threshold_analysis.png'
    )
