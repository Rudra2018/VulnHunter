#!/usr/bin/env python3
"""
Advanced Training Dynamics Visualization

This module provides comprehensive training visualization capabilities:
- Loss curves and learning dynamics
- Learning rate scheduling visualization
- Gradient flow analysis
- Model performance tracking
- Hyperparameter sensitivity analysis
- Real-time training monitoring
"""

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from typing import Dict, List, Optional, Tuple, Union
import torch
import warnings
from datetime import datetime
import json

warnings.filterwarnings("ignore")


class TrainingVisualizer:
    """Advanced training dynamics visualization"""

    def __init__(self, log_dir: str = './training_logs', style: str = 'seaborn-v0_8'):
        self.log_dir = log_dir
        self.training_history = {}
        self.current_epoch = 0

        # Set plotting style
        try:
            plt.style.use(style)
        except:
            plt.style.use('default')

        # Color palette for different metrics
        self.color_palette = {
            'train_loss': '#1f77b4',
            'val_loss': '#ff7f0e',
            'train_acc': '#2ca02c',
            'val_acc': '#d62728',
            'learning_rate': '#9467bd',
            'gradient_norm': '#8c564b',
            'vulnerability_f1': '#e377c2',
            'type_accuracy': '#7f7f7f',
            'severity_mae': '#bcbd22'
        }

        # Initialize tracking dictionaries
        self.metrics_history = {
            'epoch': [],
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': [],
            'learning_rate': [],
            'gradient_norm': [],
            'vulnerability_precision': [],
            'vulnerability_recall': [],
            'vulnerability_f1': [],
            'type_accuracy': [],
            'severity_mae': []
        }

        # Performance tracking
        self.best_metrics = {}
        self.convergence_data = {}

    def log_epoch_metrics(self, epoch: int, metrics: Dict[str, float]):
        """
        Log metrics for a single epoch

        Args:
            epoch: Current epoch number
            metrics: Dictionary of metric name -> value
        """

        self.current_epoch = epoch
        self.metrics_history['epoch'].append(epoch)

        # Log all provided metrics
        for metric_name, value in metrics.items():
            if metric_name in self.metrics_history:
                self.metrics_history[metric_name].append(value)
            else:
                # Initialize new metric if not seen before
                self.metrics_history[metric_name] = [None] * len(self.metrics_history['epoch'][:-1]) + [value]

        # Update best metrics
        for metric_name, value in metrics.items():
            if 'loss' in metric_name.lower():
                # For loss metrics, lower is better
                if metric_name not in self.best_metrics or value < self.best_metrics[metric_name]:
                    self.best_metrics[metric_name] = value
            else:
                # For other metrics, higher is better
                if metric_name not in self.best_metrics or value > self.best_metrics[metric_name]:
                    self.best_metrics[metric_name] = value

    def plot_loss_curves(self, save_path: Optional[str] = None, interactive: bool = False):
        """
        Plot training and validation loss curves

        Args:
            save_path: Path to save the figure
            interactive: Whether to create interactive plotly plot
        """

        if interactive:
            self._plot_loss_curves_interactive(save_path)
        else:
            self._plot_loss_curves_static(save_path)

    def _plot_loss_curves_static(self, save_path: Optional[str] = None):
        """Create static loss curves plot"""

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        epochs = self.metrics_history['epoch']

        # Loss curves
        if self.metrics_history['train_loss']:
            ax1.plot(epochs, self.metrics_history['train_loss'],
                    color=self.color_palette['train_loss'], linewidth=2,
                    label='Training Loss', marker='o', markersize=4)

        if self.metrics_history['val_loss']:
            ax1.plot(epochs, self.metrics_history['val_loss'],
                    color=self.color_palette['val_loss'], linewidth=2,
                    label='Validation Loss', marker='s', markersize=4)

        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Loss')
        ax1.set_title('Training and Validation Loss')
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # Accuracy curves
        if self.metrics_history['train_acc']:
            ax2.plot(epochs, self.metrics_history['train_acc'],
                    color=self.color_palette['train_acc'], linewidth=2,
                    label='Training Accuracy', marker='o', markersize=4)

        if self.metrics_history['val_acc']:
            ax2.plot(epochs, self.metrics_history['val_acc'],
                    color=self.color_palette['val_acc'], linewidth=2,
                    label='Validation Accuracy', marker='s', markersize=4)

        ax2.set_xlabel('Epoch')
        ax2.set_ylabel('Accuracy')
        ax2.set_title('Training and Validation Accuracy')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def _plot_loss_curves_interactive(self, save_path: Optional[str] = None):
        """Create interactive loss curves plot"""

        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Loss Curves', 'Accuracy Curves', 'Learning Rate', 'Gradient Norm'),
            vertical_spacing=0.1
        )

        epochs = self.metrics_history['epoch']

        # Loss curves
        if self.metrics_history['train_loss']:
            fig.add_trace(
                go.Scatter(
                    x=epochs, y=self.metrics_history['train_loss'],
                    mode='lines+markers', name='Train Loss',
                    line=dict(color='blue', width=2),
                    hovertemplate='Epoch: %{x}<br>Train Loss: %{y:.4f}<extra></extra>'
                ),
                row=1, col=1
            )

        if self.metrics_history['val_loss']:
            fig.add_trace(
                go.Scatter(
                    x=epochs, y=self.metrics_history['val_loss'],
                    mode='lines+markers', name='Val Loss',
                    line=dict(color='red', width=2),
                    hovertemplate='Epoch: %{x}<br>Val Loss: %{y:.4f}<extra></extra>'
                ),
                row=1, col=1
            )

        # Accuracy curves
        if self.metrics_history['train_acc']:
            fig.add_trace(
                go.Scatter(
                    x=epochs, y=self.metrics_history['train_acc'],
                    mode='lines+markers', name='Train Acc',
                    line=dict(color='green', width=2),
                    hovertemplate='Epoch: %{x}<br>Train Acc: %{y:.4f}<extra></extra>'
                ),
                row=1, col=2
            )

        if self.metrics_history['val_acc']:
            fig.add_trace(
                go.Scatter(
                    x=epochs, y=self.metrics_history['val_acc'],
                    mode='lines+markers', name='Val Acc',
                    line=dict(color='orange', width=2),
                    hovertemplate='Epoch: %{x}<br>Val Acc: %{y:.4f}<extra></extra>'
                ),
                row=1, col=2
            )

        # Learning rate
        if self.metrics_history['learning_rate']:
            fig.add_trace(
                go.Scatter(
                    x=epochs, y=self.metrics_history['learning_rate'],
                    mode='lines+markers', name='Learning Rate',
                    line=dict(color='purple', width=2),
                    hovertemplate='Epoch: %{x}<br>LR: %{y:.6f}<extra></extra>'
                ),
                row=2, col=1
            )

        # Gradient norm
        if self.metrics_history['gradient_norm']:
            fig.add_trace(
                go.Scatter(
                    x=epochs, y=self.metrics_history['gradient_norm'],
                    mode='lines+markers', name='Gradient Norm',
                    line=dict(color='brown', width=2),
                    hovertemplate='Epoch: %{x}<br>Grad Norm: %{y:.4f}<extra></extra>'
                ),
                row=2, col=2
            )

        fig.update_layout(
            title='Training Progress Dashboard',
            height=800,
            showlegend=True
        )

        if save_path:
            fig.write_html(save_path)
        fig.show()

    def plot_multi_task_metrics(self, save_path: Optional[str] = None):
        """
        Plot multi-task learning metrics

        Args:
            save_path: Path to save the figure
        """

        # Check which multi-task metrics are available
        multi_task_metrics = [
            'vulnerability_f1', 'vulnerability_precision', 'vulnerability_recall',
            'type_accuracy', 'severity_mae'
        ]

        available_metrics = [m for m in multi_task_metrics if self.metrics_history.get(m)]

        if not available_metrics:
            print("No multi-task metrics available to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        axes = axes.flatten()

        epochs = self.metrics_history['epoch']

        for i, metric in enumerate(available_metrics[:4]):  # Plot up to 4 metrics
            if i >= len(axes):
                break

            ax = axes[i]
            values = [v for v in self.metrics_history[metric] if v is not None]
            epochs_subset = epochs[:len(values)]

            ax.plot(epochs_subset, values,
                   color=self.color_palette.get(metric, 'blue'),
                   linewidth=2, marker='o', markersize=4)

            ax.set_xlabel('Epoch')
            ax.set_ylabel(metric.replace('_', ' ').title())
            ax.set_title(f'{metric.replace("_", " ").title()} Progress')
            ax.grid(True, alpha=0.3)

            # Add best value annotation
            if values:
                best_value = max(values) if 'mae' not in metric else min(values)
                best_epoch = epochs_subset[values.index(best_value)]
                ax.annotate(f'Best: {best_value:.3f}',
                           xy=(best_epoch, best_value),
                           xytext=(10, 10), textcoords='offset points',
                           bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', alpha=0.7),
                           arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))

        # Hide unused subplots
        for i in range(len(available_metrics), len(axes)):
            axes[i].set_visible(False)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def plot_gradient_flow(self, model: torch.nn.Module, save_path: Optional[str] = None):
        """
        Plot gradient flow through the model

        Args:
            model: PyTorch model to analyze
            save_path: Path to save the figure
        """

        # Extract gradient information from model
        layers = []
        avg_grads = []
        max_grads = []
        layer_names = []

        for name, param in model.named_parameters():
            if param.requires_grad and param.grad is not None:
                layer_names.append(name)
                grad_values = param.grad.abs().cpu().numpy().flatten()
                avg_grads.append(grad_values.mean())
                max_grads.append(grad_values.max())

        if not layer_names:
            print("No gradients found in the model")
            return

        # Create gradient flow plot
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        # Average gradients
        bars1 = ax1.bar(range(len(layer_names)), avg_grads, color='lightblue', alpha=0.7)
        ax1.set_xlabel('Layers')
        ax1.set_ylabel('Average Gradient')
        ax1.set_title('Average Gradient Flow')
        ax1.set_xticks(range(len(layer_names)))
        ax1.set_xticklabels(layer_names, rotation=45, ha='right')

        # Add value labels on bars
        for i, (bar, val) in enumerate(zip(bars1, avg_grads)):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + val*0.01,
                    f'{val:.2e}', ha='center', va='bottom', fontsize=8)

        # Maximum gradients
        bars2 = ax2.bar(range(len(layer_names)), max_grads, color='lightcoral', alpha=0.7)
        ax2.set_xlabel('Layers')
        ax2.set_ylabel('Maximum Gradient')
        ax2.set_title('Maximum Gradient Flow')
        ax2.set_xticks(range(len(layer_names)))
        ax2.set_xticklabels(layer_names, rotation=45, ha='right')

        # Add value labels on bars
        for i, (bar, val) in enumerate(zip(bars2, max_grads)):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + val*0.01,
                    f'{val:.2e}', ha='center', va='bottom', fontsize=8)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def plot_learning_rate_schedule(self, scheduler, num_epochs: int,
                                  save_path: Optional[str] = None):
        """
        Plot learning rate schedule

        Args:
            scheduler: PyTorch learning rate scheduler
            num_epochs: Number of epochs to simulate
            save_path: Path to save the figure
        """

        # Simulate learning rate schedule
        epochs = list(range(num_epochs))
        learning_rates = []

        # Create a dummy optimizer and scheduler for simulation
        import torch.optim as optim

        dummy_model = torch.nn.Linear(10, 1)
        dummy_optimizer = optim.Adam(dummy_model.parameters(), lr=0.001)

        # Copy scheduler configuration
        if hasattr(scheduler, 'state_dict'):
            scheduler_state = scheduler.state_dict()

        for epoch in epochs:
            learning_rates.append(dummy_optimizer.param_groups[0]['lr'])
            if hasattr(scheduler, 'step'):
                scheduler.step()

        # Plot learning rate schedule
        plt.figure(figsize=(10, 6))
        plt.plot(epochs, learning_rates, linewidth=2, marker='o', markersize=4)
        plt.xlabel('Epoch')
        plt.ylabel('Learning Rate')
        plt.title('Learning Rate Schedule')
        plt.grid(True, alpha=0.3)
        plt.yscale('log')  # Log scale for better visualization

        # Add annotations for key points
        min_lr = min(learning_rates)
        max_lr = max(learning_rates)
        min_epoch = learning_rates.index(min_lr)
        max_epoch = learning_rates.index(max_lr)

        plt.annotate(f'Max LR: {max_lr:.2e}',
                    xy=(max_epoch, max_lr),
                    xytext=(10, 10), textcoords='offset points',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='green', alpha=0.7),
                    arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))

        plt.annotate(f'Min LR: {min_lr:.2e}',
                    xy=(min_epoch, min_lr),
                    xytext=(10, -10), textcoords='offset points',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='red', alpha=0.7),
                    arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def analyze_convergence(self, window_size: int = 10, save_path: Optional[str] = None):
        """
        Analyze model convergence patterns

        Args:
            window_size: Window size for moving averages
            save_path: Path to save the analysis
        """

        if len(self.metrics_history['epoch']) < window_size:
            print(f"Not enough epochs ({len(self.metrics_history['epoch'])}) for window size {window_size}")
            return

        epochs = self.metrics_history['epoch']

        fig, axes = plt.subplots(2, 2, figsize=(15, 10))

        # Loss convergence analysis
        if self.metrics_history['val_loss']:
            val_losses = [v for v in self.metrics_history['val_loss'] if v is not None]
            moving_avg = self._moving_average(val_losses, window_size)
            convergence_rate = self._calculate_convergence_rate(val_losses, window_size)

            ax = axes[0, 0]
            ax.plot(epochs[:len(val_losses)], val_losses, alpha=0.3, label='Raw')
            ax.plot(epochs[window_size-1:len(moving_avg)+window_size-1], moving_avg,
                   linewidth=2, label=f'{window_size}-epoch Moving Avg')
            ax.set_xlabel('Epoch')
            ax.set_ylabel('Validation Loss')
            ax.set_title('Loss Convergence Analysis')
            ax.legend()
            ax.grid(True, alpha=0.3)

            # Add convergence rate
            ax.text(0.05, 0.95, f'Convergence Rate: {convergence_rate:.2e}',
                   transform=ax.transAxes, verticalalignment='top',
                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))

        # Accuracy stability analysis
        if self.metrics_history['val_acc']:
            val_accs = [v for v in self.metrics_history['val_acc'] if v is not None]
            stability_score = self._calculate_stability(val_accs, window_size)

            ax = axes[0, 1]
            ax.plot(epochs[:len(val_accs)], val_accs, linewidth=2)
            ax.fill_between(epochs[:len(val_accs)],
                          np.array(val_accs) - np.std(val_accs),
                          np.array(val_accs) + np.std(val_accs),
                          alpha=0.2, label='±1 std')
            ax.set_xlabel('Epoch')
            ax.set_ylabel('Validation Accuracy')
            ax.set_title('Accuracy Stability Analysis')
            ax.legend()
            ax.grid(True, alpha=0.3)

            # Add stability score
            ax.text(0.05, 0.95, f'Stability Score: {stability_score:.3f}',
                   transform=ax.transAxes, verticalalignment='top',
                   bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.8))

        # Learning rate vs loss correlation
        if self.metrics_history['learning_rate'] and self.metrics_history['train_loss']:
            lrs = [v for v in self.metrics_history['learning_rate'] if v is not None]
            losses = [v for v in self.metrics_history['train_loss'] if v is not None]
            min_len = min(len(lrs), len(losses))

            ax = axes[1, 0]
            scatter = ax.scatter(lrs[:min_len], losses[:min_len], c=epochs[:min_len], cmap='viridis')
            ax.set_xlabel('Learning Rate')
            ax.set_ylabel('Training Loss')
            ax.set_title('Learning Rate vs Loss')
            ax.set_xscale('log')
            plt.colorbar(scatter, ax=ax, label='Epoch')

        # Training efficiency analysis
        ax = axes[1, 1]
        if self.metrics_history['train_loss'] and self.metrics_history['val_loss']:
            train_losses = [v for v in self.metrics_history['train_loss'] if v is not None]
            val_losses = [v for v in self.metrics_history['val_loss'] if v is not None]
            min_len = min(len(train_losses), len(val_losses))

            generalization_gap = np.array(val_losses[:min_len]) - np.array(train_losses[:min_len])

            ax.plot(epochs[:min_len], generalization_gap, linewidth=2, color='red')
            ax.axhline(y=0, color='black', linestyle='--', alpha=0.5)
            ax.fill_between(epochs[:min_len], 0, generalization_gap,
                          where=(generalization_gap > 0), alpha=0.3, color='red', label='Overfitting')
            ax.fill_between(epochs[:min_len], 0, generalization_gap,
                          where=(generalization_gap <= 0), alpha=0.3, color='green', label='Good Fit')
            ax.set_xlabel('Epoch')
            ax.set_ylabel('Validation - Training Loss')
            ax.set_title('Generalization Gap Analysis')
            ax.legend()
            ax.grid(True, alpha=0.3)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def create_training_dashboard(self, save_path: Optional[str] = None):
        """
        Create comprehensive training dashboard

        Args:
            save_path: Path to save the dashboard HTML
        """

        # Create interactive dashboard
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=('Loss Curves', 'Accuracy Curves', 'Multi-task Metrics',
                          'Learning Rate', 'Gradient Norm', 'Best Metrics Summary'),
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"type": "table"}]]
        )

        epochs = self.metrics_history['epoch']

        # Add all traces for comprehensive dashboard
        self._add_dashboard_traces(fig, epochs)

        # Add best metrics table
        self._add_best_metrics_table(fig)

        fig.update_layout(
            title='Comprehensive Training Dashboard',
            height=1200,
            showlegend=True,
            template='plotly_white'
        )

        if save_path:
            fig.write_html(save_path)
        fig.show()

    # Helper methods
    def _moving_average(self, data: List[float], window_size: int) -> List[float]:
        """Calculate moving average"""
        return [np.mean(data[i:i+window_size]) for i in range(len(data) - window_size + 1)]

    def _calculate_convergence_rate(self, data: List[float], window_size: int) -> float:
        """Calculate convergence rate (negative slope of moving average)"""
        if len(data) < window_size * 2:
            return 0.0

        moving_avg = self._moving_average(data, window_size)
        if len(moving_avg) < 2:
            return 0.0

        # Calculate slope of the moving average
        x = np.arange(len(moving_avg))
        slope = np.polyfit(x, moving_avg, 1)[0]
        return -slope  # Negative because we want convergence (decreasing loss)

    def _calculate_stability(self, data: List[float], window_size: int) -> float:
        """Calculate stability score (inverse of coefficient of variation)"""
        if len(data) < window_size:
            return 0.0

        recent_data = data[-window_size:]
        mean_val = np.mean(recent_data)
        std_val = np.std(recent_data)

        if mean_val == 0:
            return 0.0

        cv = std_val / mean_val
        return 1.0 / (1.0 + cv)  # Stability score between 0 and 1

    def _add_dashboard_traces(self, fig, epochs):
        """Add traces to dashboard"""
        # Loss curves
        if self.metrics_history['train_loss']:
            fig.add_trace(
                go.Scatter(x=epochs, y=self.metrics_history['train_loss'],
                          name='Train Loss', line=dict(color='blue')),
                row=1, col=1
            )

        if self.metrics_history['val_loss']:
            fig.add_trace(
                go.Scatter(x=epochs, y=self.metrics_history['val_loss'],
                          name='Val Loss', line=dict(color='red')),
                row=1, col=1
            )

        # Add more traces for other metrics...

    def _add_best_metrics_table(self, fig):
        """Add best metrics summary table"""
        metrics_names = list(self.best_metrics.keys())
        metrics_values = [f"{v:.4f}" for v in self.best_metrics.values()]

        fig.add_trace(
            go.Table(
                header=dict(values=['Metric', 'Best Value']),
                cells=dict(values=[metrics_names, metrics_values])
            ),
            row=3, col=2
        )

    def save_training_history(self, save_path: str):
        """Save training history to JSON file"""
        history_data = {
            'metrics_history': self.metrics_history,
            'best_metrics': self.best_metrics,
            'current_epoch': self.current_epoch,
            'timestamp': datetime.now().isoformat()
        }

        with open(save_path, 'w') as f:
            json.dump(history_data, f, indent=2, default=str)

    def load_training_history(self, load_path: str):
        """Load training history from JSON file"""
        with open(load_path, 'r') as f:
            history_data = json.load(f)

        self.metrics_history = history_data.get('metrics_history', {})
        self.best_metrics = history_data.get('best_metrics', {})
        self.current_epoch = history_data.get('current_epoch', 0)


def test_training_visualizer():
    """Test the training visualizer"""
    print("Testing Training Visualizer...")

    # Initialize visualizer
    visualizer = TrainingVisualizer()

    # Simulate training history
    num_epochs = 50
    for epoch in range(num_epochs):
        # Simulate decreasing loss with noise
        train_loss = 1.0 * np.exp(-epoch/20) + np.random.normal(0, 0.1)
        val_loss = 1.2 * np.exp(-epoch/25) + np.random.normal(0, 0.15)

        # Simulate increasing accuracy
        train_acc = 1.0 - np.exp(-epoch/15) + np.random.normal(0, 0.05)
        val_acc = 0.9 - np.exp(-epoch/20) + np.random.normal(0, 0.07)

        # Simulate other metrics
        lr = 0.001 * (0.95 ** epoch)  # Decay learning rate
        grad_norm = np.random.exponential(1.0)

        metrics = {
            'train_loss': max(0, train_loss),
            'val_loss': max(0, val_loss),
            'train_acc': max(0, min(1, train_acc)),
            'val_acc': max(0, min(1, val_acc)),
            'learning_rate': lr,
            'gradient_norm': grad_norm,
            'vulnerability_f1': max(0, min(1, val_acc + np.random.normal(0, 0.1))),
            'type_accuracy': max(0, min(1, val_acc + np.random.normal(0, 0.15))),
            'severity_mae': max(0, val_loss + np.random.normal(0, 0.2))
        }

        visualizer.log_epoch_metrics(epoch, metrics)

    print("Creating training visualizations...")

    # Test static plots
    print("1. Loss curves")
    visualizer.plot_loss_curves()

    print("2. Multi-task metrics")
    visualizer.plot_multi_task_metrics()

    print("3. Convergence analysis")
    visualizer.analyze_convergence()

    print("4. Interactive dashboard")
    visualizer.create_training_dashboard()

    print("Training visualizer test completed!")


if __name__ == "__main__":
    test_training_visualizer()