#!/usr/bin/env python3
"""
VulnHunter V15 - Real-Time Performance Monitoring & Accuracy Validation
Revolutionary AI Vulnerability Detection - Live Monitoring System

This module implements comprehensive real-time monitoring and validation
for VulnHunter V15 training and inference with advanced metrics tracking,
performance optimization, and accuracy validation.
"""

import os
import json
import time
import psutil
import GPUtil
import torch
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any, Union
import logging
from datetime import datetime, timedelta
from pathlib import Path
import threading
import queue
import subprocess
from dataclasses import dataclass, asdict
import matplotlib.pyplot as plt
import seaborn as sns
from collections import deque, defaultdict
import websocket
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, matthews_corrcoef,
    confusion_matrix, calibration_curve, brier_score_loss
)
import warnings
warnings.filterwarnings("ignore")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    gpu_usage: Optional[float]
    gpu_memory: Optional[float]
    disk_io_read: float
    disk_io_write: float
    network_io_sent: float
    network_io_recv: float
    training_loss: Optional[float]
    validation_loss: Optional[float]
    learning_rate: Optional[float]
    batch_size: Optional[int]
    throughput_samples_per_sec: Optional[float]

@dataclass
class AccuracyMetrics:
    """Accuracy validation metrics"""
    timestamp: datetime
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    pr_auc: float
    matthews_corrcoef: float
    brier_score: float
    calibration_error: float
    prediction_confidence: float
    uncertainty_score: float

class SystemMonitor:
    """Real-time system resource monitoring"""

    def __init__(self, update_interval: float = 1.0):
        self.update_interval = update_interval
        self.is_monitoring = False
        self.metrics_queue = queue.Queue()
        self.monitor_thread = None

        # Initialize baseline metrics
        self.baseline_metrics = self._get_baseline_metrics()

        # Historical data storage
        self.metrics_history = deque(maxlen=3600)  # Store last hour

    def _get_baseline_metrics(self) -> Dict[str, float]:
        """Get baseline system metrics"""
        baseline = {
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_io_read': psutil.disk_io_counters().read_bytes if psutil.disk_io_counters() else 0,
            'disk_io_write': psutil.disk_io_counters().write_bytes if psutil.disk_io_counters() else 0,
            'network_io_sent': psutil.net_io_counters().bytes_sent,
            'network_io_recv': psutil.net_io_counters().bytes_recv
        }

        # GPU baseline if available
        try:
            gpus = GPUtil.getGPUs()
            if gpus:
                baseline['gpu_usage'] = gpus[0].load * 100
                baseline['gpu_memory'] = gpus[0].memoryUtil * 100
        except:
            baseline['gpu_usage'] = None
            baseline['gpu_memory'] = None

        return baseline

    def start_monitoring(self):
        """Start real-time monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("🔍 System monitoring started")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        logger.info("⏹️ System monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_queue.put(metrics)
                self.metrics_history.append(metrics)
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(self.update_interval)

    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current system metrics"""
        # CPU and Memory
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        memory_usage = memory.percent

        # Disk I/O
        disk_io = psutil.disk_io_counters()
        disk_io_read = disk_io.read_bytes if disk_io else 0
        disk_io_write = disk_io.write_bytes if disk_io else 0

        # Network I/O
        net_io = psutil.net_io_counters()
        network_io_sent = net_io.bytes_sent
        network_io_recv = net_io.bytes_recv

        # GPU metrics
        gpu_usage = None
        gpu_memory = None
        try:
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu_usage = gpus[0].load * 100
                gpu_memory = gpus[0].memoryUtil * 100
        except:
            pass

        return PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            gpu_usage=gpu_usage,
            gpu_memory=gpu_memory,
            disk_io_read=disk_io_read,
            disk_io_write=disk_io_write,
            network_io_sent=network_io_sent,
            network_io_recv=network_io_recv,
            training_loss=None,
            validation_loss=None,
            learning_rate=None,
            batch_size=None,
            throughput_samples_per_sec=None
        )

    def get_latest_metrics(self) -> Optional[PerformanceMetrics]:
        """Get latest metrics"""
        try:
            return self.metrics_queue.get_nowait()
        except queue.Empty:
            return None

    def get_historical_metrics(self, duration_minutes: int = 10) -> List[PerformanceMetrics]:
        """Get historical metrics for specified duration"""
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        return [m for m in self.metrics_history if m.timestamp >= cutoff_time]

class TrainingMonitor:
    """Real-time training progress monitoring"""

    def __init__(self, log_interval: int = 10):
        self.log_interval = log_interval
        self.training_metrics = deque(maxlen=10000)
        self.validation_metrics = deque(maxlen=1000)

        # Performance tracking
        self.epoch_start_time = None
        self.batch_times = deque(maxlen=100)
        self.throughput_history = deque(maxlen=100)

        # Loss tracking
        self.loss_history = deque(maxlen=1000)
        self.best_loss = float('inf')
        self.best_accuracy = 0.0

        # Early stopping detection
        self.patience_counter = 0
        self.divergence_threshold = 2.0

    def log_training_step(self, step: int, loss: float, learning_rate: float,
                         batch_size: int, batch_time: float):
        """Log training step metrics"""
        # Calculate throughput
        throughput = batch_size / batch_time if batch_time > 0 else 0
        self.throughput_history.append(throughput)
        self.batch_times.append(batch_time)
        self.loss_history.append(loss)

        # Update best metrics
        if loss < self.best_loss:
            self.best_loss = loss

        # Store metrics
        training_metric = {
            'step': step,
            'loss': loss,
            'learning_rate': learning_rate,
            'batch_size': batch_size,
            'batch_time': batch_time,
            'throughput': throughput,
            'timestamp': datetime.now()
        }
        self.training_metrics.append(training_metric)

        # Log every N steps
        if step % self.log_interval == 0:
            avg_throughput = np.mean(list(self.throughput_history))
            avg_batch_time = np.mean(list(self.batch_times))

            logger.info(f"Step {step} | Loss: {loss:.4f} | "
                       f"LR: {learning_rate:.2e} | "
                       f"Throughput: {avg_throughput:.1f} samples/sec | "
                       f"Batch time: {avg_batch_time:.3f}s")

    def log_validation_step(self, epoch: int, val_loss: float, metrics: Dict[str, float]):
        """Log validation step metrics"""
        # Update best accuracy
        current_accuracy = metrics.get('accuracy', 0.0)
        if current_accuracy > self.best_accuracy:
            self.best_accuracy = current_accuracy
            self.patience_counter = 0
        else:
            self.patience_counter += 1

        # Store validation metrics
        validation_metric = {
            'epoch': epoch,
            'val_loss': val_loss,
            'metrics': metrics,
            'best_accuracy': self.best_accuracy,
            'patience_counter': self.patience_counter,
            'timestamp': datetime.now()
        }
        self.validation_metrics.append(validation_metric)

        logger.info(f"Epoch {epoch} Validation | Loss: {val_loss:.4f} | "
                   f"Accuracy: {current_accuracy:.4f} | "
                   f"F1: {metrics.get('f1_score', 0.0):.4f} | "
                   f"Best Acc: {self.best_accuracy:.4f}")

    def check_training_health(self) -> Dict[str, Any]:
        """Check training health and detect issues"""
        health_status = {
            'status': 'healthy',
            'issues': [],
            'recommendations': []
        }

        # Check for loss divergence
        if len(self.loss_history) >= 10:
            recent_losses = list(self.loss_history)[-10:]
            if recent_losses[-1] > self.divergence_threshold * min(recent_losses):
                health_status['status'] = 'warning'
                health_status['issues'].append('Loss divergence detected')
                health_status['recommendations'].append('Consider reducing learning rate')

        # Check for slow training
        if len(self.throughput_history) >= 10:
            avg_throughput = np.mean(list(self.throughput_history))
            if avg_throughput < 10:  # samples per second
                health_status['issues'].append('Low training throughput')
                health_status['recommendations'].append('Check data loading efficiency')

        # Check for overfitting
        if self.patience_counter > 10:
            health_status['issues'].append('Potential overfitting detected')
            health_status['recommendations'].append('Consider regularization or early stopping')

        return health_status

class AccuracyValidator:
    """Real-time accuracy validation and calibration monitoring"""

    def __init__(self, validation_interval: int = 100):
        self.validation_interval = validation_interval
        self.accuracy_history = deque(maxlen=1000)
        self.calibration_history = deque(maxlen=100)

        # Prediction tracking
        self.predictions_buffer = []
        self.targets_buffer = []
        self.confidences_buffer = []

    def add_predictions(self, predictions: np.ndarray, targets: np.ndarray,
                       confidences: np.ndarray):
        """Add predictions for validation"""
        self.predictions_buffer.extend(predictions)
        self.targets_buffer.extend(targets)
        self.confidences_buffer.extend(confidences)

        # Validate when buffer is full
        if len(self.predictions_buffer) >= self.validation_interval:
            self._validate_accuracy()
            self._clear_buffers()

    def _validate_accuracy(self):
        """Validate accuracy with comprehensive metrics"""
        if not self.predictions_buffer:
            return

        y_pred = np.array(self.predictions_buffer)
        y_true = np.array(self.targets_buffer)
        confidences = np.array(self.confidences_buffer)

        # Calculate metrics
        metrics = self._calculate_comprehensive_metrics(y_pred, y_true, confidences)

        # Store metrics
        accuracy_metric = AccuracyMetrics(
            timestamp=datetime.now(),
            **metrics
        )
        self.accuracy_history.append(accuracy_metric)

        # Log validation results
        logger.info(f"🎯 Accuracy Validation | "
                   f"Acc: {metrics['accuracy']:.4f} | "
                   f"F1: {metrics['f1_score']:.4f} | "
                   f"Cal Error: {metrics['calibration_error']:.4f}")

    def _calculate_comprehensive_metrics(self, y_pred: np.ndarray, y_true: np.ndarray,
                                       confidences: np.ndarray) -> Dict[str, float]:
        """Calculate comprehensive accuracy metrics"""
        # Ensure binary predictions
        if y_pred.ndim > 1:
            y_pred_binary = (y_pred > 0.5).astype(int)
            y_true_binary = y_true.astype(int)
        else:
            y_pred_binary = (y_pred > 0.5).astype(int)
            y_true_binary = y_true.astype(int)

        # Flatten for binary classification metrics
        y_pred_flat = y_pred_binary.flatten()
        y_true_flat = y_true_binary.flatten()

        metrics = {}

        try:
            # Basic metrics
            metrics['accuracy'] = accuracy_score(y_true_flat, y_pred_flat)
            metrics['precision'] = precision_score(y_true_flat, y_pred_flat, average='macro', zero_division=0)
            metrics['recall'] = recall_score(y_true_flat, y_pred_flat, average='macro', zero_division=0)
            metrics['f1_score'] = f1_score(y_true_flat, y_pred_flat, average='macro', zero_division=0)

            # ROC AUC
            try:
                if y_pred.ndim > 1:
                    metrics['roc_auc'] = roc_auc_score(y_true.flatten(), y_pred.flatten())
                else:
                    metrics['roc_auc'] = roc_auc_score(y_true_flat, y_pred_flat)
            except:
                metrics['roc_auc'] = 0.0

            # PR AUC
            try:
                if y_pred.ndim > 1:
                    metrics['pr_auc'] = average_precision_score(y_true.flatten(), y_pred.flatten())
                else:
                    metrics['pr_auc'] = average_precision_score(y_true_flat, y_pred_flat)
            except:
                metrics['pr_auc'] = 0.0

            # Matthews correlation coefficient
            try:
                metrics['matthews_corrcoef'] = matthews_corrcoef(y_true_flat, y_pred_flat)
            except:
                metrics['matthews_corrcoef'] = 0.0

            # Brier score
            try:
                if y_pred.ndim > 1:
                    metrics['brier_score'] = brier_score_loss(y_true.flatten(), y_pred.flatten())
                else:
                    metrics['brier_score'] = brier_score_loss(y_true_flat, y_pred_flat)
            except:
                metrics['brier_score'] = 1.0

            # Calibration error
            metrics['calibration_error'] = self._calculate_calibration_error(y_true_flat, y_pred_flat, confidences)

            # Prediction confidence
            metrics['prediction_confidence'] = np.mean(confidences) if len(confidences) > 0 else 0.0

            # Uncertainty score
            metrics['uncertainty_score'] = np.std(confidences) if len(confidences) > 0 else 1.0

        except Exception as e:
            logger.warning(f"Error calculating metrics: {e}")
            # Return default metrics
            metrics = {
                'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0,
                'roc_auc': 0.0, 'pr_auc': 0.0, 'matthews_corrcoef': 0.0,
                'brier_score': 1.0, 'calibration_error': 1.0,
                'prediction_confidence': 0.0, 'uncertainty_score': 1.0
            }

        return metrics

    def _calculate_calibration_error(self, y_true: np.ndarray, y_pred: np.ndarray,
                                   confidences: np.ndarray, n_bins: int = 10) -> float:
        """Calculate Expected Calibration Error (ECE)"""
        try:
            if len(confidences) == 0:
                return 1.0

            # Create bins
            bin_boundaries = np.linspace(0, 1, n_bins + 1)
            bin_lowers = bin_boundaries[:-1]
            bin_uppers = bin_boundaries[1:]

            ece = 0
            for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
                # Find predictions in bin
                in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
                prop_in_bin = in_bin.mean()

                if prop_in_bin > 0:
                    # Accuracy in bin
                    accuracy_in_bin = y_true[in_bin].mean()
                    # Average confidence in bin
                    avg_confidence_in_bin = confidences[in_bin].mean()
                    # Add to ECE
                    ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

            return ece

        except Exception as e:
            logger.warning(f"Error calculating calibration error: {e}")
            return 1.0

    def _clear_buffers(self):
        """Clear prediction buffers"""
        self.predictions_buffer = []
        self.targets_buffer = []
        self.confidences_buffer = []

    def get_accuracy_trend(self, duration_minutes: int = 30) -> Dict[str, List[float]]:
        """Get accuracy trend over time"""
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        recent_metrics = [m for m in self.accuracy_history if m.timestamp >= cutoff_time]

        if not recent_metrics:
            return {}

        trend = {
            'timestamps': [m.timestamp for m in recent_metrics],
            'accuracy': [m.accuracy for m in recent_metrics],
            'f1_score': [m.f1_score for m in recent_metrics],
            'calibration_error': [m.calibration_error for m in recent_metrics],
            'prediction_confidence': [m.prediction_confidence for m in recent_metrics]
        }

        return trend

class PerformanceDashboard:
    """Real-time performance dashboard and visualization"""

    def __init__(self, save_dir: str = "vulnhunter_v15_monitoring"):
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)

        # Database for metrics storage
        self.db_path = self.save_dir / "metrics.db"
        self._init_database()

        # Visualization settings
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")

    def _init_database(self):
        """Initialize SQLite database for metrics storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                timestamp TEXT PRIMARY KEY,
                cpu_usage REAL,
                memory_usage REAL,
                gpu_usage REAL,
                gpu_memory REAL,
                disk_io_read REAL,
                disk_io_write REAL,
                network_io_sent REAL,
                network_io_recv REAL,
                training_loss REAL,
                validation_loss REAL,
                learning_rate REAL,
                batch_size INTEGER,
                throughput_samples_per_sec REAL
            )
        ''')

        # Accuracy metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accuracy_metrics (
                timestamp TEXT PRIMARY KEY,
                accuracy REAL,
                precision_score REAL,
                recall REAL,
                f1_score REAL,
                roc_auc REAL,
                pr_auc REAL,
                matthews_corrcoef REAL,
                brier_score REAL,
                calibration_error REAL,
                prediction_confidence REAL,
                uncertainty_score REAL
            )
        ''')

        conn.commit()
        conn.close()

    def save_performance_metrics(self, metrics: PerformanceMetrics):
        """Save performance metrics to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO performance_metrics
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics.timestamp.isoformat(),
            metrics.cpu_usage,
            metrics.memory_usage,
            metrics.gpu_usage,
            metrics.gpu_memory,
            metrics.disk_io_read,
            metrics.disk_io_write,
            metrics.network_io_sent,
            metrics.network_io_recv,
            metrics.training_loss,
            metrics.validation_loss,
            metrics.learning_rate,
            metrics.batch_size,
            metrics.throughput_samples_per_sec
        ))

        conn.commit()
        conn.close()

    def save_accuracy_metrics(self, metrics: AccuracyMetrics):
        """Save accuracy metrics to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO accuracy_metrics
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics.timestamp.isoformat(),
            metrics.accuracy,
            metrics.precision,
            metrics.recall,
            metrics.f1_score,
            metrics.roc_auc,
            metrics.pr_auc,
            metrics.matthews_corrcoef,
            metrics.brier_score,
            metrics.calibration_error,
            metrics.prediction_confidence,
            metrics.uncertainty_score
        ))

        conn.commit()
        conn.close()

    def generate_performance_plots(self, duration_hours: int = 1):
        """Generate performance visualization plots"""
        # Load recent data
        conn = sqlite3.connect(self.db_path)

        # Performance data
        perf_query = f'''
            SELECT * FROM performance_metrics
            WHERE timestamp > datetime('now', '-{duration_hours} hours')
            ORDER BY timestamp
        '''
        perf_df = pd.read_sql_query(perf_query, conn)

        # Accuracy data
        acc_query = f'''
            SELECT * FROM accuracy_metrics
            WHERE timestamp > datetime('now', '-{duration_hours} hours')
            ORDER BY timestamp
        '''
        acc_df = pd.read_sql_query(acc_query, conn)

        conn.close()

        if perf_df.empty and acc_df.empty:
            logger.warning("No data available for plotting")
            return

        # Create subplots
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('VulnHunter V15 - Real-Time Performance Dashboard', fontsize=16, fontweight='bold')

        # System Performance Plots
        if not perf_df.empty:
            perf_df['timestamp'] = pd.to_datetime(perf_df['timestamp'])

            # CPU and Memory Usage
            axes[0, 0].plot(perf_df['timestamp'], perf_df['cpu_usage'], label='CPU Usage', color='blue')
            axes[0, 0].plot(perf_df['timestamp'], perf_df['memory_usage'], label='Memory Usage', color='red')
            if 'gpu_usage' in perf_df.columns and not perf_df['gpu_usage'].isna().all():
                axes[0, 0].plot(perf_df['timestamp'], perf_df['gpu_usage'], label='GPU Usage', color='green')
            axes[0, 0].set_title('System Resource Usage (%)')
            axes[0, 0].set_ylabel('Usage %')
            axes[0, 0].legend()
            axes[0, 0].grid(True, alpha=0.3)

            # Training Loss
            if 'training_loss' in perf_df.columns and not perf_df['training_loss'].isna().all():
                axes[0, 1].plot(perf_df['timestamp'], perf_df['training_loss'], label='Training Loss', color='orange')
            if 'validation_loss' in perf_df.columns and not perf_df['validation_loss'].isna().all():
                axes[0, 1].plot(perf_df['timestamp'], perf_df['validation_loss'], label='Validation Loss', color='purple')
            axes[0, 1].set_title('Training Progress')
            axes[0, 1].set_ylabel('Loss')
            axes[0, 1].legend()
            axes[0, 1].grid(True, alpha=0.3)

            # Throughput
            if 'throughput_samples_per_sec' in perf_df.columns and not perf_df['throughput_samples_per_sec'].isna().all():
                axes[0, 2].plot(perf_df['timestamp'], perf_df['throughput_samples_per_sec'], label='Throughput', color='teal')
            axes[0, 2].set_title('Training Throughput (samples/sec)')
            axes[0, 2].set_ylabel('Samples/sec')
            axes[0, 2].legend()
            axes[0, 2].grid(True, alpha=0.3)

        # Accuracy Performance Plots
        if not acc_df.empty:
            acc_df['timestamp'] = pd.to_datetime(acc_df['timestamp'])

            # Accuracy Metrics
            axes[1, 0].plot(acc_df['timestamp'], acc_df['accuracy'], label='Accuracy', color='blue')
            axes[1, 0].plot(acc_df['timestamp'], acc_df['f1_score'], label='F1 Score', color='red')
            axes[1, 0].plot(acc_df['timestamp'], acc_df['precision_score'], label='Precision', color='green')
            axes[1, 0].plot(acc_df['timestamp'], acc_df['recall'], label='Recall', color='orange')
            axes[1, 0].set_title('Accuracy Metrics')
            axes[1, 0].set_ylabel('Score')
            axes[1, 0].legend()
            axes[1, 0].grid(True, alpha=0.3)

            # Calibration and Confidence
            axes[1, 1].plot(acc_df['timestamp'], acc_df['calibration_error'], label='Calibration Error', color='red')
            axes[1, 1].plot(acc_df['timestamp'], acc_df['prediction_confidence'], label='Prediction Confidence', color='blue')
            axes[1, 1].set_title('Model Calibration')
            axes[1, 1].set_ylabel('Score')
            axes[1, 1].legend()
            axes[1, 1].grid(True, alpha=0.3)

            # Advanced Metrics
            axes[1, 2].plot(acc_df['timestamp'], acc_df['roc_auc'], label='ROC AUC', color='purple')
            axes[1, 2].plot(acc_df['timestamp'], acc_df['pr_auc'], label='PR AUC', color='brown')
            axes[1, 2].plot(acc_df['timestamp'], acc_df['matthews_corrcoef'], label='Matthews CC', color='pink')
            axes[1, 2].set_title('Advanced Metrics')
            axes[1, 2].set_ylabel('Score')
            axes[1, 2].legend()
            axes[1, 2].grid(True, alpha=0.3)

        # Format x-axis for all subplots
        for ax in axes.flat:
            ax.tick_params(axis='x', rotation=45)

        plt.tight_layout()

        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plot_path = self.save_dir / f"performance_dashboard_{timestamp}.png"
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()

        logger.info(f"📊 Performance dashboard saved: {plot_path}")
        return plot_path

    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive monitoring summary report"""
        conn = sqlite3.connect(self.db_path)

        # Get recent performance data (last 24 hours)
        perf_query = '''
            SELECT * FROM performance_metrics
            WHERE timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
        '''
        perf_df = pd.read_sql_query(perf_query, conn)

        # Get recent accuracy data (last 24 hours)
        acc_query = '''
            SELECT * FROM accuracy_metrics
            WHERE timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
        '''
        acc_df = pd.read_sql_query(acc_query, conn)

        conn.close()

        report = {
            'report_timestamp': datetime.now().isoformat(),
            'monitoring_period': '24 hours',
            'system_performance': {},
            'accuracy_performance': {},
            'alerts': [],
            'recommendations': []
        }

        # System performance summary
        if not perf_df.empty:
            report['system_performance'] = {
                'avg_cpu_usage': float(perf_df['cpu_usage'].mean()),
                'max_cpu_usage': float(perf_df['cpu_usage'].max()),
                'avg_memory_usage': float(perf_df['memory_usage'].mean()),
                'max_memory_usage': float(perf_df['memory_usage'].max()),
                'avg_gpu_usage': float(perf_df['gpu_usage'].mean()) if 'gpu_usage' in perf_df.columns and not perf_df['gpu_usage'].isna().all() else None,
                'avg_throughput': float(perf_df['throughput_samples_per_sec'].mean()) if 'throughput_samples_per_sec' in perf_df.columns and not perf_df['throughput_samples_per_sec'].isna().all() else None
            }

            # Performance alerts
            if report['system_performance']['max_cpu_usage'] > 90:
                report['alerts'].append('High CPU usage detected (>90%)')
            if report['system_performance']['max_memory_usage'] > 90:
                report['alerts'].append('High memory usage detected (>90%)')

        # Accuracy performance summary
        if not acc_df.empty:
            report['accuracy_performance'] = {
                'latest_accuracy': float(acc_df['accuracy'].iloc[0]),
                'avg_accuracy': float(acc_df['accuracy'].mean()),
                'latest_f1_score': float(acc_df['f1_score'].iloc[0]),
                'avg_f1_score': float(acc_df['f1_score'].mean()),
                'latest_calibration_error': float(acc_df['calibration_error'].iloc[0]),
                'avg_calibration_error': float(acc_df['calibration_error'].mean()),
                'prediction_confidence': float(acc_df['prediction_confidence'].mean())
            }

            # Accuracy alerts
            if report['accuracy_performance']['latest_calibration_error'] > 0.1:
                report['alerts'].append('High calibration error detected (>0.1)')
            if report['accuracy_performance']['latest_accuracy'] < 0.8:
                report['alerts'].append('Low accuracy detected (<0.8)')

        # Generate recommendations
        if not report['alerts']:
            report['recommendations'].append('Training is performing well - continue monitoring')
        else:
            if 'High CPU usage' in str(report['alerts']):
                report['recommendations'].append('Consider reducing batch size or increasing compute resources')
            if 'High memory usage' in str(report['alerts']):
                report['recommendations'].append('Monitor memory leaks and optimize data loading')
            if 'High calibration error' in str(report['alerts']):
                report['recommendations'].append('Consider calibration techniques like temperature scaling')
            if 'Low accuracy' in str(report['alerts']):
                report['recommendations'].append('Review model architecture and training hyperparameters')

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.save_dir / f"monitoring_report_{timestamp}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"📋 Monitoring report saved: {report_path}")
        return report

class VulnHunterV15MonitoringSystem:
    """Comprehensive monitoring system for VulnHunter V15"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._get_default_config()

        # Initialize components
        self.system_monitor = SystemMonitor(
            update_interval=self.config.get('system_monitor_interval', 1.0)
        )
        self.training_monitor = TrainingMonitor(
            log_interval=self.config.get('training_log_interval', 10)
        )
        self.accuracy_validator = AccuracyValidator(
            validation_interval=self.config.get('validation_interval', 100)
        )
        self.dashboard = PerformanceDashboard(
            save_dir=self.config.get('save_dir', 'vulnhunter_v15_monitoring')
        )

        # Monitoring state
        self.is_running = False
        self.monitoring_thread = None

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default monitoring configuration"""
        return {
            'system_monitor_interval': 1.0,
            'training_log_interval': 10,
            'validation_interval': 100,
            'dashboard_update_interval': 300,  # 5 minutes
            'save_dir': 'vulnhunter_v15_monitoring',
            'enable_alerts': True,
            'alert_thresholds': {
                'cpu_usage': 90,
                'memory_usage': 90,
                'calibration_error': 0.1,
                'accuracy_drop': 0.05
            }
        }

    def start_monitoring(self):
        """Start comprehensive monitoring"""
        if not self.is_running:
            self.is_running = True

            # Start system monitoring
            self.system_monitor.start_monitoring()

            # Start dashboard update thread
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()

            logger.info("🚀 VulnHunter V15 monitoring system started")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_running = False

        # Stop system monitoring
        self.system_monitor.stop_monitoring()

        if self.monitoring_thread:
            self.monitoring_thread.join()

        logger.info("⏹️ VulnHunter V15 monitoring system stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        dashboard_update_interval = self.config.get('dashboard_update_interval', 300)
        last_dashboard_update = time.time()

        while self.is_running:
            try:
                # Collect and save metrics
                latest_metrics = self.system_monitor.get_latest_metrics()
                if latest_metrics:
                    self.dashboard.save_performance_metrics(latest_metrics)

                # Update dashboard periodically
                current_time = time.time()
                if current_time - last_dashboard_update >= dashboard_update_interval:
                    self.dashboard.generate_performance_plots()
                    last_dashboard_update = current_time

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(10)

    def log_training_step(self, step: int, loss: float, learning_rate: float,
                         batch_size: int, batch_time: float):
        """Log training step (public interface)"""
        self.training_monitor.log_training_step(step, loss, learning_rate, batch_size, batch_time)

    def log_validation_step(self, epoch: int, val_loss: float, metrics: Dict[str, float]):
        """Log validation step (public interface)"""
        self.training_monitor.log_validation_step(epoch, val_loss, metrics)

    def validate_predictions(self, predictions: np.ndarray, targets: np.ndarray,
                           confidences: np.ndarray):
        """Validate predictions (public interface)"""
        self.accuracy_validator.add_predictions(predictions, targets, confidences)

    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive monitoring report"""
        # Generate dashboard plots
        plot_path = self.dashboard.generate_performance_plots()

        # Generate summary report
        summary_report = self.dashboard.generate_summary_report()

        # Add training health check
        training_health = self.training_monitor.check_training_health()
        summary_report['training_health'] = training_health

        # Add accuracy trends
        accuracy_trends = self.accuracy_validator.get_accuracy_trend()
        summary_report['accuracy_trends'] = accuracy_trends

        # Add system information
        summary_report['system_info'] = {
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / (1024**3),
            'gpu_info': self._get_gpu_info()
        }

        summary_report['dashboard_plot'] = str(plot_path) if plot_path else None

        return summary_report

    def _get_gpu_info(self) -> Dict[str, Any]:
        """Get GPU information"""
        try:
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu = gpus[0]
                return {
                    'name': gpu.name,
                    'memory_total_mb': gpu.memoryTotal,
                    'driver_version': gpu.driver
                }
        except:
            pass
        return {}

def demonstrate_monitoring_system():
    """Demonstrate the monitoring system"""
    print("🚀 VulnHunter V15 - Monitoring System Demonstration")
    print("=" * 70)

    # Initialize monitoring system
    monitoring_system = VulnHunterV15MonitoringSystem()

    # Start monitoring
    monitoring_system.start_monitoring()

    # Simulate training steps
    logger.info("🔄 Simulating training process...")

    for step in range(50):
        # Simulate training step
        loss = 1.0 * np.exp(-step * 0.1) + 0.1 + 0.05 * np.random.randn()
        learning_rate = 1e-4 * (0.99 ** (step // 10))
        batch_size = 64
        batch_time = 0.5 + 0.1 * np.random.randn()

        monitoring_system.log_training_step(step, loss, learning_rate, batch_size, batch_time)

        # Simulate validation every 10 steps
        if step % 10 == 0:
            val_loss = loss * 1.1
            val_metrics = {
                'accuracy': 0.7 + 0.3 * (1 - np.exp(-step * 0.05)) + 0.02 * np.random.randn(),
                'f1_score': 0.65 + 0.35 * (1 - np.exp(-step * 0.05)) + 0.02 * np.random.randn(),
                'precision': 0.6 + 0.4 * (1 - np.exp(-step * 0.05)) + 0.02 * np.random.randn(),
                'recall': 0.7 + 0.3 * (1 - np.exp(-step * 0.05)) + 0.02 * np.random.randn()
            }

            monitoring_system.log_validation_step(step // 10, val_loss, val_metrics)

            # Simulate prediction validation
            predictions = np.random.rand(100, 10)
            targets = np.random.randint(0, 2, (100, 10))
            confidences = np.random.rand(100)

            monitoring_system.validate_predictions(predictions, targets, confidences)

        time.sleep(0.1)  # Brief pause

    # Generate comprehensive report
    logger.info("📊 Generating comprehensive monitoring report...")
    report = monitoring_system.generate_comprehensive_report()

    # Stop monitoring
    monitoring_system.stop_monitoring()

    print("\n✅ Monitoring System Demonstration Completed!")
    print("=" * 70)
    print(f"📊 System Performance:")
    if 'system_performance' in report:
        perf = report['system_performance']
        print(f"   Average CPU Usage: {perf.get('avg_cpu_usage', 0):.1f}%")
        print(f"   Average Memory Usage: {perf.get('avg_memory_usage', 0):.1f}%")
        print(f"   Average Throughput: {perf.get('avg_throughput', 0):.1f} samples/sec")

    print(f"\n🎯 Accuracy Performance:")
    if 'accuracy_performance' in report:
        acc = report['accuracy_performance']
        print(f"   Latest Accuracy: {acc.get('latest_accuracy', 0):.4f}")
        print(f"   Latest F1 Score: {acc.get('latest_f1_score', 0):.4f}")
        print(f"   Calibration Error: {acc.get('latest_calibration_error', 0):.4f}")

    print(f"\n🔍 Training Health: {report.get('training_health', {}).get('status', 'unknown')}")

    if report.get('alerts'):
        print(f"\n⚠️  Alerts: {len(report['alerts'])}")
        for alert in report['alerts']:
            print(f"   - {alert}")

    if report.get('recommendations'):
        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"   - {rec}")

    return report

if __name__ == "__main__":
    # Run demonstration
    demo_report = demonstrate_monitoring_system()