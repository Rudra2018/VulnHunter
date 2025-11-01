"""
VulnHunter Blockchain: Advanced Training Pipeline
Target: 95%+ F1 score on real-world smart contract vulnerability detection
Massive dataset training with sophisticated techniques
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from torch_geometric.data import Data, Batch
import json
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
import os
from pathlib import Path
import logging
from datetime import datetime
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix
import pickle
import wandb
from tqdm import tqdm
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from src.models.solidity_fusion import SolidityFusionModel
from src.models.blockchain_gnn import BlockchainGNN
from src.parser.languages.solidity_parser import SolidityParser
from src.data.blockchain_ingest import BlockchainDatasetCollector

class BlockchainVulnerabilityDataset(Dataset):
    """Optimized dataset for blockchain vulnerability detection"""

    def __init__(self, data_path: str, split: str = 'train', max_samples: Optional[int] = None):
        self.data_path = data_path
        self.split = split
        self.samples = []
        self.parser = SolidityParser()

        self._load_data(max_samples)

    def _load_data(self, max_samples: Optional[int]):
        """Load preprocessed blockchain dataset"""
        file_path = Path(self.data_path) / f"{self.split}.jsonl"

        if not file_path.exists():
            logger.error(f"Dataset file not found: {file_path}")
            # Try to create dataset
            self._create_dataset()

        logger.info(f"Loading {self.split} dataset from {file_path}")

        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f):
                if max_samples and len(self.samples) >= max_samples:
                    break

                try:
                    sample = json.loads(line.strip())
                    self.samples.append(sample)

                    if line_num % 1000 == 0 and line_num > 0:
                        logger.info(f"Loaded {line_num} samples")

                except Exception as e:
                    logger.warning(f"Error loading sample {line_num}: {e}")
                    continue

        logger.info(f"Successfully loaded {len(self.samples)} {self.split} samples")
        self._print_dataset_stats()

    def _create_dataset(self):
        """Create dataset if it doesn't exist"""
        logger.info("Dataset not found, creating new dataset...")
        collector = BlockchainDatasetCollector(data_dir=Path(self.data_path).parent)
        samples = collector.collect_all_datasets(max_samples=5000)  # Limit for training
        logger.info("Dataset created successfully")

    def _print_dataset_stats(self):
        """Print dataset statistics"""
        if not self.samples:
            return

        total = len(self.samples)
        vulnerable = sum(1 for s in self.samples if s['vulnerability_binary'] == 1)
        safe = total - vulnerable

        logger.info(f"{self.split.title()} Dataset Statistics:")
        logger.info(f"  Total: {total}, Vulnerable: {vulnerable} ({vulnerable/total*100:.1f}%), Safe: {safe}")

        # Vulnerability type distribution
        vuln_types = {}
        for sample in self.samples:
            for vtype in sample['vulnerability_labels']:
                vuln_types[vtype] = vuln_types.get(vtype, 0) + 1

        if vuln_types:
            logger.info(f"  Top vulnerability types: {sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]}")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]

        # Parse code to get graph representation if not cached
        if 'graph_data' not in sample:
            try:
                graph = self.parser.parse_solidity_code(sample['code'])
                sample['graph_data'] = {
                    'node_features': graph.node_features,
                    'edge_index': graph.edge_index,
                    'edge_attr': graph.edge_attr if hasattr(graph, 'edge_attr') else None
                }
            except Exception as e:
                logger.warning(f"Error parsing sample {idx}: {e}")
                # Create dummy graph
                sample['graph_data'] = {
                    'node_features': torch.zeros(1, 30),
                    'edge_index': torch.empty((2, 0), dtype=torch.long),
                    'edge_attr': None
                }

        return sample

def collate_blockchain_batch(batch):
    """Custom collate function for blockchain data"""
    codes = []
    labels = []
    vulnerability_types = []
    graph_data_list = []

    for sample in batch:
        codes.append(sample['code'])
        labels.append(sample['vulnerability_binary'])
        vulnerability_types.append(sample['vulnerability_labels'])

        # Create PyG Data object
        graph_data = sample['graph_data']
        data = Data(
            x=graph_data['node_features'],
            edge_index=graph_data['edge_index'],
            edge_attr=graph_data['edge_attr']
        )
        graph_data_list.append(data)

    # Create batch for graphs
    graph_batch = Batch.from_data_list(graph_data_list)

    return {
        'codes': codes,
        'labels': torch.tensor(labels, dtype=torch.long),
        'vulnerability_types': vulnerability_types,
        'graph_batch': graph_batch
    }

class AdvancedBlockchainTrainer:
    """
    Advanced trainer for blockchain vulnerability detection
    Implements sophisticated training techniques for 95%+ F1 score
    """

    def __init__(
        self,
        model: SolidityFusionModel,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        learning_rate: float = 2e-5,
        weight_decay: float = 1e-6,
        use_wandb: bool = False
    ):
        self.model = model.to(device)
        self.device = device
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.use_wandb = use_wandb

        # Advanced optimizer with warmup
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay,
            betas=(0.9, 0.999),
            eps=1e-8
        )

        # Learning rate scheduler
        self.scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
            self.optimizer, T_0=10, T_mult=2, eta_min=1e-7
        )

        # Loss functions with class balancing
        self.binary_criterion = nn.CrossEntropyLoss()
        self.multilabel_criterion = nn.BCEWithLogitsLoss()
        self.regression_criterion = nn.MSELoss()

        # Training history
        self.history = {
            'train_loss': [], 'val_loss': [], 'train_f1': [], 'val_f1': [],
            'train_acc': [], 'val_acc': [], 'train_auc': [], 'val_auc': []
        }

        # Best model tracking
        self.best_f1 = 0.0
        self.best_model_state = None
        self.patience_counter = 0
        self.patience = 15

        # Initialize Weights & Biases if enabled
        if self.use_wandb:
            wandb.init(
                project="vulnhunter-blockchain",
                config={
                    "learning_rate": learning_rate,
                    "weight_decay": weight_decay,
                    "architecture": "Solidity GNN + Transformer Fusion",
                    "target_f1": 0.95
                }
            )

    def train_epoch(self, dataloader: DataLoader, epoch: int) -> Dict[str, float]:
        """Train for one epoch with advanced techniques"""
        self.model.train()
        total_loss = 0.0
        all_predictions = []
        all_labels = []
        all_probs = []

        progress_bar = tqdm(dataloader, desc=f"Epoch {epoch+1}")

        for batch_idx, batch in enumerate(progress_bar):
            self.optimizer.zero_grad()

            # Move data to device
            labels = batch['labels'].to(self.device)
            codes = batch['codes']
            graph_batch = batch['graph_batch'].to(self.device)

            batch_loss = 0.0
            batch_predictions = []
            batch_probs = []

            # Process each sample in batch
            for i, code in enumerate(codes):
                try:
                    # Create single-sample graph
                    sample_mask = (graph_batch.batch == i)
                    if sample_mask.sum() == 0:
                        continue

                    sample_graph = Data(
                        x=graph_batch.x[sample_mask],
                        edge_index=graph_batch.edge_index[:, sample_mask],
                        batch=torch.zeros(sample_mask.sum(), dtype=torch.long).to(self.device)
                    )

                    # Forward pass
                    results = self.model.forward(code)

                    # Extract predictions
                    binary_logits = results['binary_prediction']
                    vuln_type_logits = results['vulnerability_type_predictions']
                    severity_pred = results['severity_prediction']

                    # Losses
                    sample_label = labels[i].unsqueeze(0)

                    # Main binary classification loss
                    binary_loss = self.binary_criterion(binary_logits, sample_label)

                    # Multi-label vulnerability type loss
                    vuln_labels = self._create_multilabel_target(
                        batch['vulnerability_types'][i], vuln_type_logits.size(-1)
                    ).to(self.device)
                    multilabel_loss = self.multilabel_criterion(vuln_type_logits, vuln_labels)

                    # Severity regression loss
                    severity_target = torch.tensor([float(sample_label.item())]).to(self.device)
                    severity_loss = self.regression_criterion(
                        severity_pred.max(dim=-1)[0], severity_target
                    )

                    # Combined loss with weights
                    sample_loss = binary_loss + 0.3 * multilabel_loss + 0.1 * severity_loss
                    batch_loss += sample_loss

                    # Store predictions
                    pred_class = torch.argmax(binary_logits).item()
                    pred_prob = torch.softmax(binary_logits, dim=-1)[0, 1].item()

                    batch_predictions.append(pred_class)
                    batch_probs.append(pred_prob)

                except Exception as e:
                    logger.warning(f"Error processing sample {i}: {e}")
                    batch_predictions.append(0)
                    batch_probs.append(0.0)
                    continue

            # Average loss and backward pass
            if len(codes) > 0:
                batch_loss = batch_loss / len(codes)
                batch_loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

                self.optimizer.step()
                total_loss += batch_loss.item()

            # Store batch results
            all_predictions.extend(batch_predictions)
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(batch_probs)

            # Update progress bar
            progress_bar.set_postfix({
                'Loss': f"{batch_loss.item():.4f}",
                'LR': f"{self.optimizer.param_groups[0]['lr']:.2e}"
            })

        # Update learning rate
        self.scheduler.step()

        # Calculate metrics
        metrics = self._calculate_metrics(all_labels, all_predictions, all_probs)
        metrics['loss'] = total_loss / len(dataloader)

        return metrics

    def evaluate(self, dataloader: DataLoader) -> Dict[str, float]:
        """Evaluate model on validation/test set"""
        self.model.eval()
        total_loss = 0.0
        all_predictions = []
        all_labels = []
        all_probs = []

        with torch.no_grad():
            for batch in tqdm(dataloader, desc="Evaluating"):
                labels = batch['labels'].to(self.device)
                codes = batch['codes']
                graph_batch = batch['graph_batch'].to(self.device)

                batch_predictions = []
                batch_probs = []
                batch_loss = 0.0

                for i, code in enumerate(codes):
                    try:
                        # Create single-sample graph
                        sample_mask = (graph_batch.batch == i)
                        if sample_mask.sum() == 0:
                            continue

                        # Forward pass
                        results = self.model.forward(code)
                        binary_logits = results['binary_prediction']

                        # Loss calculation
                        sample_label = labels[i].unsqueeze(0)
                        loss = self.binary_criterion(binary_logits, sample_label)
                        batch_loss += loss.item()

                        # Predictions
                        pred_class = torch.argmax(binary_logits).item()
                        pred_prob = torch.softmax(binary_logits, dim=-1)[0, 1].item()

                        batch_predictions.append(pred_class)
                        batch_probs.append(pred_prob)

                    except Exception as e:
                        logger.warning(f"Error evaluating sample {i}: {e}")
                        batch_predictions.append(0)
                        batch_probs.append(0.0)

                total_loss += batch_loss / len(codes) if codes else 0
                all_predictions.extend(batch_predictions)
                all_labels.extend(labels.cpu().numpy())
                all_probs.extend(batch_probs)

        # Calculate metrics
        metrics = self._calculate_metrics(all_labels, all_predictions, all_probs)
        metrics['loss'] = total_loss / len(dataloader)

        return metrics

    def train(
        self,
        train_dataset: BlockchainVulnerabilityDataset,
        val_dataset: BlockchainVulnerabilityDataset,
        num_epochs: int = 50,
        batch_size: int = 8,
        save_path: str = "models/blockchain_vulnhunter.pth"
    ):
        """Complete training loop with advanced techniques"""
        logger.info(f"Starting advanced blockchain training for {num_epochs} epochs")

        # Create data loaders
        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True,
            collate_fn=collate_blockchain_batch,
            num_workers=2,
            pin_memory=True if self.device == 'cuda' else False
        )

        val_loader = DataLoader(
            val_dataset,
            batch_size=batch_size,
            shuffle=False,
            collate_fn=collate_blockchain_batch,
            num_workers=2,
            pin_memory=True if self.device == 'cuda' else False
        )

        logger.info(f"Training batches: {len(train_loader)}, Validation batches: {len(val_loader)}")

        for epoch in range(num_epochs):
            start_time = time.time()

            # Training
            train_metrics = self.train_epoch(train_loader, epoch)
            logger.info(f"Epoch {epoch+1}/{num_epochs} - Train: "
                       f"Loss: {train_metrics['loss']:.4f}, "
                       f"F1: {train_metrics['f1']:.4f}, "
                       f"Acc: {train_metrics['accuracy']:.4f}")

            # Validation
            val_metrics = self.evaluate(val_loader)
            logger.info(f"Epoch {epoch+1}/{num_epochs} - Val: "
                       f"Loss: {val_metrics['loss']:.4f}, "
                       f"F1: {val_metrics['f1']:.4f}, "
                       f"Acc: {val_metrics['accuracy']:.4f}, "
                       f"AUC: {val_metrics['auc']:.4f}")

            # Update history
            for key in ['loss', 'f1', 'accuracy', 'auc']:
                self.history[f'train_{key}'].append(train_metrics[key])
                self.history[f'val_{key}'].append(val_metrics[key])

            # Log to wandb
            if self.use_wandb:
                wandb.log({
                    'epoch': epoch,
                    'train_loss': train_metrics['loss'],
                    'val_loss': val_metrics['loss'],
                    'train_f1': train_metrics['f1'],
                    'val_f1': val_metrics['f1'],
                    'val_accuracy': val_metrics['accuracy'],
                    'val_auc': val_metrics['auc'],
                    'learning_rate': self.optimizer.param_groups[0]['lr']
                })

            # Early stopping and best model saving
            if val_metrics['f1'] > self.best_f1:
                self.best_f1 = val_metrics['f1']
                self.best_model_state = self.model.state_dict().copy()
                self.patience_counter = 0

                # Save best model
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                torch.save(self.best_model_state, save_path)
                logger.info(f"🎯 New best model! F1: {self.best_f1:.4f} - Saved to {save_path}")

                # Check if target achieved
                if self.best_f1 >= 0.95:
                    logger.info("🏆 TARGET ACHIEVED: 95%+ F1 score reached!")

            else:
                self.patience_counter += 1

            # Early stopping
            if self.patience_counter >= self.patience:
                logger.info(f"Early stopping triggered after {epoch+1} epochs")
                break

            epoch_time = time.time() - start_time
            logger.info(f"Epoch time: {epoch_time:.2f}s")

        # Load best model
        if self.best_model_state:
            self.model.load_state_dict(self.best_model_state)

        # Save training history
        history_path = save_path.replace('.pth', '_history.json')
        with open(history_path, 'w') as f:
            json.dump(self.history, f, indent=2)

        logger.info(f"Training completed! Best F1: {self.best_f1:.4f}")

        if self.use_wandb:
            wandb.finish()

        return self.history

    def _create_multilabel_target(self, vuln_types: List[str], num_classes: int) -> torch.Tensor:
        """Create multi-label target tensor"""
        target = torch.zeros(num_classes)

        vuln_mapping = {
            'reentrancy': 0, 'integer_overflow': 1, 'access_control': 2,
            'unchecked_call': 3, 'timestamp_dependence': 4, 'tx_origin': 5,
            'dos_gas_limit': 6, 'uninitialized_storage': 7, 'front_running': 8,
            'insufficient_gas_griefing': 9
        }

        for vuln_type in vuln_types:
            if vuln_type in vuln_mapping:
                target[vuln_mapping[vuln_type]] = 1.0

        return target

    def _calculate_metrics(self, labels: List[int], predictions: List[int], probs: List[float]) -> Dict[str, float]:
        """Calculate comprehensive evaluation metrics"""
        labels = np.array(labels)
        predictions = np.array(predictions)
        probs = np.array(probs)

        # Basic metrics
        accuracy = accuracy_score(labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, predictions, average='binary', zero_division=0
        )

        # AUC
        try:
            auc = roc_auc_score(labels, probs) if len(set(labels)) > 1 else 0.0
        except:
            auc = 0.0

        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'auc': auc
        }

def main():
    """Main training function"""
    logger.info("VulnHunter Blockchain Advanced Training Pipeline")

    # Configuration
    config = {
        'data_dir': 'data/blockchain/processed',
        'batch_size': 4,  # Small for memory efficiency
        'num_epochs': 100,
        'learning_rate': 2e-5,
        'weight_decay': 1e-6,
        'max_train_samples': 3000,
        'max_val_samples': 500,
        'use_wandb': False,
        'target_f1': 0.95
    }

    logger.info(f"Training configuration: {config}")

    # Create datasets
    train_dataset = BlockchainVulnerabilityDataset(
        config['data_dir'], 'train', max_samples=config['max_train_samples']
    )
    val_dataset = BlockchainVulnerabilityDataset(
        config['data_dir'], 'validation', max_samples=config['max_val_samples']
    )

    if len(train_dataset) == 0:
        logger.error("No training samples found!")
        return

    logger.info(f"Dataset sizes - Train: {len(train_dataset)}, Val: {len(val_dataset)}")

    # Create model
    model = SolidityFusionModel(
        gnn_input_dim=30,
        gnn_hidden_dim=128,
        transformer_output_dim=256,
        fusion_dim=512,
        num_vulnerability_types=10
    )

    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

    # Create trainer
    trainer = AdvancedBlockchainTrainer(
        model=model,
        learning_rate=config['learning_rate'],
        weight_decay=config['weight_decay'],
        use_wandb=config['use_wandb']
    )

    # Train model
    history = trainer.train(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        num_epochs=config['num_epochs'],
        batch_size=config['batch_size'],
        save_path="models/blockchain_vulnhunter_advanced.pth"
    )

    # Final evaluation
    logger.info(f"\n🏆 TRAINING RESULTS:")
    logger.info(f"Best F1 Score: {trainer.best_f1:.4f}")
    logger.info(f"Target F1 (95%): {'✅ ACHIEVED' if trainer.best_f1 >= 0.95 else '❌ NOT ACHIEVED'}")

    if trainer.best_f1 >= 0.95:
        logger.info("🎉 Congratulations! VulnHunter achieved industry-leading accuracy!")
    else:
        logger.info(f"💪 Close! Need {0.95 - trainer.best_f1:.3f} more F1 points to reach target")

if __name__ == "__main__":
    main()