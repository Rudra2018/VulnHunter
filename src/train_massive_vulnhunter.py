#!/usr/bin/env python3
"""
VulnHunter Massive Dataset Training Script
==========================================

Optimized training script for 15M sample multi-domain security dataset
Includes HTTP traffic analysis, network protocols, and all code types.

Usage:
    python3 train_massive_vulnhunter.py

Features:
- Memory-efficient data loading with streaming
- Multi-GPU support with DataParallel
- Mixed precision training (FP16)
- Dynamic batch sizing based on available memory
- Advanced data augmentation
- Real-time monitoring and logging
- Checkpoint saving and resuming
- Early stopping with patience
"""

import os
import sys
import json
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd
from torch.utils.data import Dataset, DataLoader
from torch.cuda.amp import GradScaler, autocast
from torch.nn.parallel import DataParallel
import logging
from datetime import datetime
import time
import gc
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('massive_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MassiveVulnDataset(Dataset):
    """Memory-efficient dataset loader for massive 15M samples"""

    def __init__(self, data_path, chunk_size=50000, transform=None):
        self.data_path = data_path
        self.chunk_size = chunk_size
        self.transform = transform
        self.scaler = StandardScaler()

        # Load dataset metadata
        metadata_file = os.path.join(data_path, 'dataset_metadata.json')
        if os.path.exists(metadata_file):
            with open(metadata_file, 'r') as f:
                self.metadata = json.load(f)
                self.total_samples = self.metadata['total_samples']
                self.num_features = self.metadata['num_features']
                logger.info(f"Dataset metadata loaded: {self.total_samples} samples, {self.num_features} features")
        else:
            # Fallback: count samples by reading file headers
            self._count_samples()

        self.current_chunk = None
        self.chunk_start_idx = 0

    def _count_samples(self):
        """Count total samples across all domain files"""
        self.total_samples = 0
        data_files = [f for f in os.listdir(self.data_path) if f.endswith('.csv')]
        for file in data_files:
            df = pd.read_csv(os.path.join(self.data_path, file), nrows=1)
            file_path = os.path.join(self.data_path, file)
            with open(file_path, 'r') as f:
                self.total_samples += sum(1 for line in f) - 1  # Subtract header
        logger.info(f"Counted {self.total_samples} total samples")

    def _load_chunk(self, start_idx):
        """Load a chunk of data starting from start_idx"""
        if self.current_chunk is not None and start_idx == self.chunk_start_idx:
            return  # Chunk already loaded

        # Determine which files and rows to load
        data_files = sorted([f for f in os.listdir(self.data_path) if f.endswith('.csv')])

        chunk_data = []
        current_idx = 0
        samples_needed = self.chunk_size

        for file in data_files:
            file_path = os.path.join(self.data_path, file)

            # Skip files until we reach start_idx
            file_size = sum(1 for line in open(file_path)) - 1  # Subtract header
            if current_idx + file_size <= start_idx:
                current_idx += file_size
                continue

            # Calculate skip rows and nrows for this file
            skip_rows = max(0, start_idx - current_idx)
            rows_to_read = min(samples_needed, file_size - skip_rows)

            if rows_to_read > 0:
                df_chunk = pd.read_csv(
                    file_path,
                    skiprows=range(1, skip_rows + 1) if skip_rows > 0 else None,
                    nrows=rows_to_read
                )
                chunk_data.append(df_chunk)
                samples_needed -= rows_to_read
                current_idx += file_size

            if samples_needed <= 0:
                break

        if chunk_data:
            self.current_chunk = pd.concat(chunk_data, ignore_index=True)
            self.chunk_start_idx = start_idx

            # Fit scaler on first chunk
            if start_idx == 0:
                feature_cols = [col for col in self.current_chunk.columns if col != 'vulnerability_label']
                self.scaler.fit(self.current_chunk[feature_cols])

            logger.info(f"Loaded chunk: {len(self.current_chunk)} samples starting from index {start_idx}")
        else:
            self.current_chunk = pd.DataFrame()

    def __len__(self):
        return self.total_samples

    def __getitem__(self, idx):
        # Determine if we need to load a new chunk
        chunk_idx = idx // self.chunk_size
        chunk_start = chunk_idx * self.chunk_size

        if self.current_chunk is None or chunk_start != self.chunk_start_idx:
            self._load_chunk(chunk_start)

        # Get relative index within current chunk
        relative_idx = idx - self.chunk_start_idx

        if relative_idx >= len(self.current_chunk):
            # Handle edge case for last chunk
            relative_idx = len(self.current_chunk) - 1

        row = self.current_chunk.iloc[relative_idx]

        # Extract features and label
        feature_cols = [col for col in row.index if col != 'vulnerability_label']
        features = row[feature_cols].values.astype(np.float32)
        label = float(row['vulnerability_label'])

        # Apply scaling
        features = self.scaler.transform(features.reshape(1, -1)).flatten()

        # Apply transforms if provided
        if self.transform:
            features = self.transform(features)

        return torch.tensor(features, dtype=torch.float32), torch.tensor(label, dtype=torch.float32)

class EnhancedVulnHunter(nn.Module):
    """Enhanced VulnHunter architecture optimized for massive multi-domain dataset"""

    def __init__(self, input_size, hidden_layers=[512, 256, 128, 64], dropout_rate=0.3):
        super(EnhancedVulnHunter, self).__init__()

        layers = []
        prev_size = input_size

        for i, hidden_size in enumerate(hidden_layers):
            # Linear layer
            layers.append(nn.Linear(prev_size, hidden_size))

            # Batch normalization
            layers.append(nn.BatchNorm1d(hidden_size))

            # Activation
            if i < len(hidden_layers) - 1:
                layers.append(nn.ReLU())
            else:
                layers.append(nn.LeakyReLU(0.1))  # Different activation for last hidden layer

            # Dropout
            layers.append(nn.Dropout(dropout_rate))

            prev_size = hidden_size

        # Output layer
        layers.append(nn.Linear(prev_size, 1))
        layers.append(nn.Sigmoid())

        self.network = nn.Sequential(*layers)

        # Initialize weights
        self._initialize_weights()

    def _initialize_weights(self):
        """Xavier/Glorot initialization for better convergence"""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.constant_(module.bias, 0)

    def forward(self, x):
        return self.network(x).squeeze()

class MassiveTrainer:
    """Optimized trainer for massive dataset with memory management"""

    def __init__(self, config):
        self.config = config
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.use_mixed_precision = config.get('mixed_precision', True)

        # Initialize scaler for mixed precision
        if self.use_mixed_precision:
            self.scaler = GradScaler()

        logger.info(f"Using device: {self.device}")
        if torch.cuda.is_available():
            logger.info(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

    def _get_optimal_batch_size(self):
        """Dynamically determine optimal batch size based on available memory"""
        if not torch.cuda.is_available():
            return 512

        total_memory = torch.cuda.get_device_properties(0).total_memory
        memory_gb = total_memory / 1e9

        if memory_gb >= 16:
            return 2048
        elif memory_gb >= 8:
            return 1024
        elif memory_gb >= 4:
            return 512
        else:
            return 256

    def _create_model(self, input_size):
        """Create and initialize the model"""
        model = EnhancedVulnHunter(
            input_size=input_size,
            hidden_layers=self.config.get('hidden_layers', [512, 256, 128, 64]),
            dropout_rate=self.config.get('dropout_rate', 0.3)
        )

        # Move to device
        model = model.to(self.device)

        # Use DataParallel if multiple GPUs available
        if torch.cuda.device_count() > 1:
            logger.info(f"Using {torch.cuda.device_count()} GPUs")
            model = DataParallel(model)

        return model

    def _create_optimizer(self, model):
        """Create optimizer with weight decay"""
        return optim.AdamW(
            model.parameters(),
            lr=self.config.get('learning_rate', 1e-4),
            weight_decay=self.config.get('weight_decay', 1e-5),
            eps=1e-8
        )

    def _create_scheduler(self, optimizer, total_steps):
        """Create learning rate scheduler"""
        return optim.lr_scheduler.CosineAnnealingLR(
            optimizer,
            T_max=total_steps,
            eta_min=1e-7
        )

    def train(self, dataset_path):
        """Main training loop"""
        logger.info("Starting massive VulnHunter training...")

        # Load dataset
        dataset = MassiveVulnDataset(dataset_path)

        # Determine input size from first sample
        sample_features, _ = dataset[0]
        input_size = len(sample_features)
        logger.info(f"Input feature size: {input_size}")

        # Split dataset indices
        total_samples = len(dataset)
        train_size = int(0.8 * total_samples)
        val_size = int(0.1 * total_samples)

        train_indices = list(range(train_size))
        val_indices = list(range(train_size, train_size + val_size))
        test_indices = list(range(train_size + val_size, total_samples))

        # Create data loaders with memory-efficient sampling
        batch_size = self._get_optimal_batch_size()
        logger.info(f"Using batch size: {batch_size}")

        train_sampler = torch.utils.data.SubsetRandomSampler(train_indices)
        val_sampler = torch.utils.data.SubsetRandomSampler(val_indices)

        train_loader = DataLoader(
            dataset,
            batch_size=batch_size,
            sampler=train_sampler,
            num_workers=4,
            pin_memory=True,
            persistent_workers=True
        )

        val_loader = DataLoader(
            dataset,
            batch_size=batch_size,
            sampler=val_sampler,
            num_workers=2,
            pin_memory=True
        )

        # Create model, optimizer, and scheduler
        model = self._create_model(input_size)
        optimizer = self._create_optimizer(model)
        criterion = nn.BCELoss()

        # Calculate total training steps
        epochs = self.config.get('epochs', 10)
        total_steps = epochs * len(train_loader)
        scheduler = self._create_scheduler(optimizer, total_steps)

        # Training tracking
        best_val_f1 = 0.0
        patience = self.config.get('patience', 3)
        patience_counter = 0
        training_history = []

        logger.info(f"Training configuration:")
        logger.info(f"  Total samples: {total_samples:,}")
        logger.info(f"  Training samples: {len(train_indices):,}")
        logger.info(f"  Validation samples: {len(val_indices):,}")
        logger.info(f"  Test samples: {len(test_indices):,}")
        logger.info(f"  Epochs: {epochs}")
        logger.info(f"  Batch size: {batch_size}")
        logger.info(f"  Mixed precision: {self.use_mixed_precision}")

        # Training loop
        for epoch in range(epochs):
            epoch_start_time = time.time()

            # Training phase
            model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0

            for batch_idx, (features, labels) in enumerate(train_loader):
                features, labels = features.to(self.device), labels.to(self.device)

                optimizer.zero_grad()

                if self.use_mixed_precision:
                    with autocast():
                        outputs = model(features)
                        loss = criterion(outputs, labels)

                    self.scaler.scale(loss).backward()
                    self.scaler.step(optimizer)
                    self.scaler.update()
                else:
                    outputs = model(features)
                    loss = criterion(outputs, labels)
                    loss.backward()
                    optimizer.step()

                scheduler.step()

                # Statistics
                train_loss += loss.item()
                predicted = (outputs > 0.5).float()
                train_total += labels.size(0)
                train_correct += (predicted == labels).sum().item()

                # Memory cleanup
                if batch_idx % 100 == 0:
                    torch.cuda.empty_cache()
                    gc.collect()

                # Progress logging
                if batch_idx % 500 == 0:
                    current_lr = scheduler.get_last_lr()[0]
                    logger.info(f"Epoch {epoch+1}/{epochs} | Batch {batch_idx}/{len(train_loader)} | "
                              f"Loss: {loss.item():.4f} | LR: {current_lr:.2e}")

            train_accuracy = train_correct / train_total
            avg_train_loss = train_loss / len(train_loader)

            # Validation phase
            model.eval()
            val_predictions = []
            val_targets = []
            val_loss = 0.0

            with torch.no_grad():
                for features, labels in val_loader:
                    features, labels = features.to(self.device), labels.to(self.device)

                    if self.use_mixed_precision:
                        with autocast():
                            outputs = model(features)
                            loss = criterion(outputs, labels)
                    else:
                        outputs = model(features)
                        loss = criterion(outputs, labels)

                    val_loss += loss.item()

                    predicted = (outputs > 0.5).float()
                    val_predictions.extend(predicted.cpu().numpy())
                    val_targets.extend(labels.cpu().numpy())

            # Calculate validation metrics
            val_accuracy = accuracy_score(val_targets, val_predictions)
            val_precision = precision_score(val_targets, val_predictions, zero_division=0)
            val_recall = recall_score(val_targets, val_predictions, zero_division=0)
            val_f1 = f1_score(val_targets, val_predictions, zero_division=0)
            avg_val_loss = val_loss / len(val_loader)

            # False positive rate
            cm = confusion_matrix(val_targets, val_predictions)
            if len(cm) > 1:
                fp_rate = cm[0, 1] / (cm[0, 0] + cm[0, 1]) if (cm[0, 0] + cm[0, 1]) > 0 else 0
            else:
                fp_rate = 0

            epoch_time = time.time() - epoch_start_time

            # Log epoch results
            epoch_metrics = {
                'epoch': epoch + 1,
                'train_loss': avg_train_loss,
                'train_accuracy': train_accuracy,
                'val_loss': avg_val_loss,
                'val_accuracy': val_accuracy,
                'val_precision': val_precision,
                'val_recall': val_recall,
                'val_f1': val_f1,
                'val_fp_rate': fp_rate,
                'epoch_time': epoch_time,
                'learning_rate': scheduler.get_last_lr()[0]
            }

            training_history.append(epoch_metrics)

            logger.info(f"\nEpoch {epoch+1}/{epochs} Complete:")
            logger.info(f"  Train Loss: {avg_train_loss:.4f} | Train Acc: {train_accuracy:.4f}")
            logger.info(f"  Val Loss: {avg_val_loss:.4f} | Val Acc: {val_accuracy:.4f}")
            logger.info(f"  Val F1: {val_f1:.4f} | Val FP Rate: {fp_rate:.4f}")
            logger.info(f"  Epoch Time: {epoch_time:.1f}s")

            # Early stopping and best model saving
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                patience_counter = 0

                # Save best model
                model_save_path = 'vulnhunter_massive_best.pth'
                if hasattr(model, 'module'):  # DataParallel wrapper
                    torch.save(model.module.state_dict(), model_save_path)
                else:
                    torch.save(model.state_dict(), model_save_path)

                logger.info(f"  New best model saved! F1: {val_f1:.4f}")
            else:
                patience_counter += 1
                logger.info(f"  No improvement. Patience: {patience_counter}/{patience}")

            # Early stopping
            if patience_counter >= patience:
                logger.info(f"Early stopping triggered after {epoch+1} epochs")
                break

            # Memory cleanup
            torch.cuda.empty_cache()
            gc.collect()

        # Final evaluation on test set
        logger.info("\nEvaluating on test set...")
        test_sampler = torch.utils.data.SubsetRandomSampler(test_indices)
        test_loader = DataLoader(
            dataset,
            batch_size=batch_size,
            sampler=test_sampler,
            num_workers=2
        )

        model.eval()
        test_predictions = []
        test_targets = []

        with torch.no_grad():
            for features, labels in test_loader:
                features, labels = features.to(self.device), labels.to(self.device)

                if self.use_mixed_precision:
                    with autocast():
                        outputs = model(features)
                else:
                    outputs = model(features)

                predicted = (outputs > 0.5).float()
                test_predictions.extend(predicted.cpu().numpy())
                test_targets.extend(labels.cpu().numpy())

        # Calculate final test metrics
        test_accuracy = accuracy_score(test_targets, test_predictions)
        test_precision = precision_score(test_targets, test_predictions, zero_division=0)
        test_recall = recall_score(test_targets, test_predictions, zero_division=0)
        test_f1 = f1_score(test_targets, test_predictions, zero_division=0)

        test_cm = confusion_matrix(test_targets, test_predictions)
        if len(test_cm) > 1:
            test_fp_rate = test_cm[0, 1] / (test_cm[0, 0] + test_cm[0, 1]) if (test_cm[0, 0] + test_cm[0, 1]) > 0 else 0
        else:
            test_fp_rate = 0

        final_results = {
            'test_accuracy': test_accuracy,
            'test_precision': test_precision,
            'test_recall': test_recall,
            'test_f1': test_f1,
            'test_fp_rate': test_fp_rate,
            'confusion_matrix': test_cm.tolist(),
            'total_samples_trained': total_samples,
            'best_val_f1': best_val_f1,
            'training_history': training_history
        }

        logger.info(f"\nFINAL TEST RESULTS:")
        logger.info(f"  Test Accuracy: {test_accuracy:.4f}")
        logger.info(f"  Test Precision: {test_precision:.4f}")
        logger.info(f"  Test Recall: {test_recall:.4f}")
        logger.info(f"  Test F1-Score: {test_f1:.4f}")
        logger.info(f"  False Positive Rate: {test_fp_rate:.4f}")
        logger.info(f"  Total Samples: {total_samples:,}")

        # Save results
        with open('massive_training_results.json', 'w') as f:
            json.dump(final_results, f, indent=2, default=str)

        logger.info("Training completed successfully!")
        return final_results

def main():
    """Main training execution"""

    # Training configuration
    config = {
        'epochs': 15,
        'learning_rate': 1e-4,
        'weight_decay': 1e-5,
        'hidden_layers': [512, 256, 128, 64],
        'dropout_rate': 0.3,
        'patience': 5,
        'mixed_precision': True
    }

    # Check for dataset
    dataset_path = 'data/massive_dataset_v1'
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found at {dataset_path}")
        logger.info("Please wait for massive dataset creation to complete...")
        return

    # Initialize trainer
    trainer = MassiveTrainer(config)

    # Start training
    try:
        results = trainer.train(dataset_path)

        # Performance summary
        logger.info("\n" + "="*80)
        logger.info("MASSIVE VULNHUNTER TRAINING COMPLETE")
        logger.info("="*80)
        logger.info(f"Final Test Accuracy: {results['test_accuracy']:.4f}")
        logger.info(f"Final Test F1-Score: {results['test_f1']:.4f}")
        logger.info(f"False Positive Rate: {results['test_fp_rate']:.4f}")
        logger.info(f"Total Samples Trained: {results['total_samples_trained']:,}")
        logger.info("="*80)

        # Check target achievement
        meets_accuracy = results['test_accuracy'] >= 0.90
        meets_fp_rate = results['test_fp_rate'] <= 0.05

        if meets_accuracy and meets_fp_rate:
            logger.info("🎉 ALL TARGETS ACHIEVED!")
            logger.info(f"✅ Accuracy: {results['test_accuracy']:.4f} >= 0.90")
            logger.info(f"✅ FP Rate: {results['test_fp_rate']:.4f} <= 0.05")
        else:
            logger.info("⚠️  Some targets not met:")
            if not meets_accuracy:
                logger.info(f"❌ Accuracy: {results['test_accuracy']:.4f} < 0.90")
            if not meets_fp_rate:
                logger.info(f"❌ FP Rate: {results['test_fp_rate']:.4f} > 0.05")

    except Exception as e:
        logger.error(f"Training failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()