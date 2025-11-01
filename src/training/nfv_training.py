"""
Neural-Formal Verification Training Pipeline
Trains VulnHunterNFV with proof-guided loss on smart contract datasets
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
import torch.nn.functional as F
from typing import Dict, List, Tuple, Any, Optional
import json
import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from src.models.vulnhunter_nfv import VulnHunterNFV
from src.parser.languages.solidity_parser import SolidityParser
from src.training.blockchain_training import SmartContractDataset

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nfv_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NFVDataset(Dataset):
    """
    Dataset for Neural-Formal Verification training
    Includes smart contract code with vulnerability labels and types
    """

    def __init__(
        self,
        data_path: str,
        parser: SolidityParser,
        max_samples: Optional[int] = None,
        min_code_length: int = 50
    ):
        self.parser = parser
        self.samples = []

        logger.info(f"Loading NFV dataset from {data_path}")

        # Load existing smart contract dataset
        base_dataset = SmartContractDataset(
            data_path=data_path,
            parser=parser,
            max_samples=max_samples
        )

        # Convert to NFV format with additional metadata
        for i in range(len(base_dataset)):
            try:
                sample = base_dataset[i]

                # Filter out very short code samples
                if len(sample['code']) < min_code_length:
                    continue

                # Enhanced sample for NFV training
                nfv_sample = {
                    'code': sample['code'],
                    'graph_data': sample['graph_data'],
                    'tokens': sample['tokens'],
                    'attention_mask': sample['attention_mask'],
                    'vulnerability_label': sample['vulnerability_label'],
                    'vulnerability_types': sample['vulnerability_types'],
                    'vulnerability_severity': sample.get('vulnerability_severity', 0),
                    'contract_metadata': {
                        'functions_count': sample.get('functions_count', 0),
                        'complexity_score': sample.get('complexity_score', 0.0),
                        'has_external_calls': sample.get('has_external_calls', False),
                        'has_state_changes': sample.get('has_state_changes', False)
                    }
                }

                self.samples.append(nfv_sample)

            except Exception as e:
                logger.warning(f"Error processing sample {i}: {e}")
                continue

        logger.info(f"Loaded {len(self.samples)} valid samples for NFV training")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]

class NFVTrainer:
    """
    Trainer for Neural-Formal Verification model with proof-guided loss
    """

    def __init__(
        self,
        model: VulnHunterNFV,
        train_dataset: NFVDataset,
        val_dataset: NFVDataset,
        learning_rate: float = 1e-4,
        batch_size: int = 8,
        num_epochs: int = 50,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        save_dir: str = 'models/nfv',
        proof_weight: float = 0.3,
        neural_weight: float = 0.5,
        path_weight: float = 0.2
    ):
        self.model = model.to(device)
        self.device = device
        self.train_dataset = train_dataset
        self.val_dataset = val_dataset
        self.batch_size = batch_size
        self.num_epochs = num_epochs
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)

        # Loss weights
        self.proof_weight = proof_weight
        self.neural_weight = neural_weight
        self.path_weight = path_weight

        # Data loaders
        self.train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True,
            collate_fn=self._collate_fn,
            num_workers=2
        )

        self.val_loader = DataLoader(
            val_dataset,
            batch_size=batch_size,
            shuffle=False,
            collate_fn=self._collate_fn,
            num_workers=2
        )

        # Optimizer and scheduler
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=1e-5
        )

        self.scheduler = optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer,
            T_max=num_epochs,
            eta_min=1e-6
        )

        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_accuracy': [],
            'val_accuracy': [],
            'neural_loss': [],
            'proof_loss': [],
            'proof_accuracy': [],
            'learning_rate': []
        }

        logger.info(f"NFV Trainer initialized:")
        logger.info(f"  Device: {device}")
        logger.info(f"  Train samples: {len(train_dataset)}")
        logger.info(f"  Val samples: {len(val_dataset)}")
        logger.info(f"  Batch size: {batch_size}")
        logger.info(f"  Epochs: {num_epochs}")
        logger.info(f"  Loss weights - Neural: {neural_weight}, Proof: {proof_weight}, Path: {path_weight}")

    def _collate_fn(self, batch):
        """Custom collate function for batch processing"""
        codes = [item['code'] for item in batch]
        graphs = [item['graph_data'] for item in batch]
        tokens = torch.stack([torch.tensor(item['tokens'][:512]) for item in batch])  # Truncate to max length
        attention_masks = torch.stack([torch.tensor(item['attention_mask'][:512]) for item in batch])
        vulnerability_labels = torch.tensor([item['vulnerability_label'] for item in batch], dtype=torch.float32)
        vulnerability_types = torch.stack([torch.tensor(item['vulnerability_types']) for item in batch])

        return {
            'codes': codes,
            'graphs': graphs,
            'tokens': tokens,
            'attention_masks': attention_masks,
            'vulnerability_labels': vulnerability_labels,
            'vulnerability_types': vulnerability_types
        }

    def train_epoch(self) -> Dict[str, float]:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0.0
        total_neural_loss = 0.0
        total_proof_loss = 0.0
        neural_predictions = []
        proof_predictions = []
        true_labels = []

        progress_bar = tqdm(self.train_loader, desc="Training")

        for batch_idx, batch in enumerate(progress_bar):
            self.optimizer.zero_grad()

            # Move to device
            tokens = batch['tokens'].to(self.device)
            attention_masks = batch['attention_masks'].to(self.device)
            vulnerability_labels = batch['vulnerability_labels'].to(self.device)
            vulnerability_types = batch['vulnerability_types'].to(self.device)

            batch_loss = 0.0
            batch_neural_loss = 0.0
            batch_proof_loss = 0.0
            batch_neural_preds = []
            batch_proof_preds = []

            # Process each sample in batch (NFV requires individual processing)
            for i in range(len(batch['codes'])):
                try:
                    # Single sample forward pass
                    output = self.model(
                        graph_data=batch['graphs'][i],
                        code_tokens=tokens[i:i+1],
                        attention_mask=attention_masks[i:i+1],
                        code_str=batch['codes'][i],
                        true_label=vulnerability_labels[i:i+1],
                        vulnerability_types=vulnerability_types[i:i+1]
                    )

                    if output['loss'] is not None:
                        batch_loss += output['loss']

                    if output['neural_loss'] is not None:
                        batch_neural_loss += output['neural_loss']

                    if output['proof_loss'] is not None:
                        batch_proof_loss += output['proof_loss']

                    # Collect predictions
                    batch_neural_preds.append(output['neural_prediction'])
                    batch_proof_preds.append(1.0 if output['proven_vulnerable'] else 0.0)

                except Exception as e:
                    logger.warning(f"Error processing sample {i} in batch {batch_idx}: {e}")
                    # Use dummy values for failed samples
                    batch_neural_preds.append(0.0)
                    batch_proof_preds.append(0.0)
                    continue

            # Average losses over batch
            if batch_loss > 0:
                batch_loss = batch_loss / len(batch['codes'])
                batch_loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

                self.optimizer.step()

            # Accumulate metrics
            total_loss += batch_loss.item() if torch.is_tensor(batch_loss) else 0.0
            total_neural_loss += batch_neural_loss.item() if torch.is_tensor(batch_neural_loss) else 0.0
            total_proof_loss += batch_proof_loss.item() if torch.is_tensor(batch_proof_loss) else 0.0

            neural_predictions.extend(batch_neural_preds)
            proof_predictions.extend(batch_proof_preds)
            true_labels.extend(vulnerability_labels.cpu().numpy())

            # Update progress bar
            progress_bar.set_postfix({
                'Loss': f"{total_loss/(batch_idx+1):.4f}",
                'Neural': f"{total_neural_loss/(batch_idx+1):.4f}",
                'Proof': f"{total_proof_loss/(batch_idx+1):.4f}"
            })

        # Calculate epoch metrics
        avg_loss = total_loss / len(self.train_loader)
        avg_neural_loss = total_neural_loss / len(self.train_loader)
        avg_proof_loss = total_proof_loss / len(self.train_loader)

        # Accuracy calculations
        neural_accuracy = accuracy_score(true_labels, [1 if p > 0.5 else 0 for p in neural_predictions])
        proof_accuracy = accuracy_score(true_labels, proof_predictions)

        return {
            'loss': avg_loss,
            'neural_loss': avg_neural_loss,
            'proof_loss': avg_proof_loss,
            'neural_accuracy': neural_accuracy,
            'proof_accuracy': proof_accuracy
        }

    def validate_epoch(self) -> Dict[str, float]:
        """Validate for one epoch"""
        self.model.eval()
        total_loss = 0.0
        neural_predictions = []
        proof_predictions = []
        final_predictions = []
        true_labels = []

        with torch.no_grad():
            for batch in tqdm(self.val_loader, desc="Validation"):
                # Move to device
                tokens = batch['tokens'].to(self.device)
                attention_masks = batch['attention_masks'].to(self.device)
                vulnerability_labels = batch['vulnerability_labels'].to(self.device)
                vulnerability_types = batch['vulnerability_types'].to(self.device)

                # Process each sample
                for i in range(len(batch['codes'])):
                    try:
                        output = self.model(
                            graph_data=batch['graphs'][i],
                            code_tokens=tokens[i:i+1],
                            attention_mask=attention_masks[i:i+1],
                            code_str=batch['codes'][i],
                            vulnerability_types=vulnerability_types[i:i+1]
                        )

                        neural_predictions.append(output['neural_prediction'])
                        proof_predictions.append(1.0 if output['proven_vulnerable'] else 0.0)
                        final_predictions.append(output['final_prediction'])

                    except Exception as e:
                        logger.warning(f"Error in validation: {e}")
                        neural_predictions.append(0.0)
                        proof_predictions.append(0.0)
                        final_predictions.append(0.0)

                true_labels.extend(vulnerability_labels.cpu().numpy())

        # Calculate validation metrics
        neural_accuracy = accuracy_score(true_labels, [1 if p > 0.5 else 0 for p in neural_predictions])
        proof_accuracy = accuracy_score(true_labels, proof_predictions)
        final_accuracy = accuracy_score(true_labels, [1 if p > 0.5 else 0 for p in final_predictions])

        # Additional metrics
        neural_precision, neural_recall, neural_f1, _ = precision_recall_fscore_support(
            true_labels, [1 if p > 0.5 else 0 for p in neural_predictions], average='binary'
        )

        try:
            neural_auc = roc_auc_score(true_labels, neural_predictions)
        except:
            neural_auc = 0.0

        return {
            'loss': 0.0,  # Validation loss not computed to save time
            'neural_accuracy': neural_accuracy,
            'proof_accuracy': proof_accuracy,
            'final_accuracy': final_accuracy,
            'neural_precision': neural_precision,
            'neural_recall': neural_recall,
            'neural_f1': neural_f1,
            'neural_auc': neural_auc
        }

    def train(self):
        """Full training loop"""
        logger.info("Starting NFV training...")
        best_val_accuracy = 0.0
        early_stopping_patience = 10
        early_stopping_counter = 0

        start_time = time.time()

        for epoch in range(self.num_epochs):
            logger.info(f"\nEpoch {epoch+1}/{self.num_epochs}")

            # Training
            train_metrics = self.train_epoch()

            # Validation
            val_metrics = self.validate_epoch()

            # Update scheduler
            self.scheduler.step()
            current_lr = self.scheduler.get_last_lr()[0]

            # Update history
            self.history['train_loss'].append(train_metrics['loss'])
            self.history['val_loss'].append(val_metrics['loss'])
            self.history['train_accuracy'].append(train_metrics['neural_accuracy'])
            self.history['val_accuracy'].append(val_metrics['final_accuracy'])
            self.history['neural_loss'].append(train_metrics['neural_loss'])
            self.history['proof_loss'].append(train_metrics['proof_loss'])
            self.history['proof_accuracy'].append(train_metrics['proof_accuracy'])
            self.history['learning_rate'].append(current_lr)

            # Log metrics
            logger.info(f"Train - Loss: {train_metrics['loss']:.4f}, Neural Acc: {train_metrics['neural_accuracy']:.3f}, Proof Acc: {train_metrics['proof_accuracy']:.3f}")
            logger.info(f"Val - Final Acc: {val_metrics['final_accuracy']:.3f}, Neural F1: {val_metrics['neural_f1']:.3f}, AUC: {val_metrics['neural_auc']:.3f}")
            logger.info(f"Learning Rate: {current_lr:.2e}")

            # Save best model
            if val_metrics['final_accuracy'] > best_val_accuracy:
                best_val_accuracy = val_metrics['final_accuracy']
                early_stopping_counter = 0

                self.save_model(f'nfv_best_acc_{best_val_accuracy:.3f}')
                logger.info(f"New best model saved! Accuracy: {best_val_accuracy:.3f}")
            else:
                early_stopping_counter += 1

            # Early stopping
            if early_stopping_counter >= early_stopping_patience:
                logger.info(f"Early stopping at epoch {epoch+1}")
                break

        training_time = time.time() - start_time
        logger.info(f"\nTraining completed in {training_time:.2f} seconds")
        logger.info(f"Best validation accuracy: {best_val_accuracy:.3f}")

        # Save final model and training history
        self.save_model('nfv_final')
        self.save_training_history()
        self.plot_training_curves()

        return self.history

    def save_model(self, name: str):
        """Save model checkpoint"""
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict(),
            'history': self.history,
            'model_config': self.model.get_model_info()
        }

        checkpoint_path = self.save_dir / f'{name}.pt'
        torch.save(checkpoint, checkpoint_path)
        logger.info(f"Model saved to {checkpoint_path}")

    def save_training_history(self):
        """Save training history to JSON"""
        history_path = self.save_dir / 'training_history.json'
        with open(history_path, 'w') as f:
            json.dump(self.history, f, indent=2)
        logger.info(f"Training history saved to {history_path}")

    def plot_training_curves(self):
        """Plot and save training curves"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))

        # Loss curves
        axes[0, 0].plot(self.history['train_loss'], label='Train Loss', color='blue')
        axes[0, 0].plot(self.history['val_loss'], label='Val Loss', color='red')
        axes[0, 0].set_title('Training and Validation Loss')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Loss')
        axes[0, 0].legend()
        axes[0, 0].grid(True)

        # Accuracy curves
        axes[0, 1].plot(self.history['train_accuracy'], label='Train Accuracy', color='green')
        axes[0, 1].plot(self.history['val_accuracy'], label='Val Accuracy', color='orange')
        axes[0, 1].set_title('Training and Validation Accuracy')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Accuracy')
        axes[0, 1].legend()
        axes[0, 1].grid(True)

        # Loss components
        axes[1, 0].plot(self.history['neural_loss'], label='Neural Loss', color='purple')
        axes[1, 0].plot(self.history['proof_loss'], label='Proof Loss', color='brown')
        axes[1, 0].set_title('Loss Components')
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('Loss')
        axes[1, 0].legend()
        axes[1, 0].grid(True)

        # Proof accuracy
        axes[1, 1].plot(self.history['proof_accuracy'], label='Proof Accuracy', color='red')
        axes[1, 1].set_title('Formal Proof Accuracy')
        axes[1, 1].set_xlabel('Epoch')
        axes[1, 1].set_ylabel('Accuracy')
        axes[1, 1].legend()
        axes[1, 1].grid(True)

        plt.tight_layout()
        plot_path = self.save_dir / 'training_curves.png'
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        logger.info(f"Training curves saved to {plot_path}")

def main():
    """Main training script"""

    # Configuration
    config = {
        'data_path': '/Users/ankitthakur/dataset',
        'model_config': {
            'd_model': 256,
            'num_heads': 8,
            'num_layers': 6,
            'vocab_size': 50000,
            'max_seq_len': 512,
            'num_vuln_types': 10,
            'k_paths': 3,
            'proof_weight': 0.3,
            'neural_weight': 0.5,
            'path_weight': 0.2
        },
        'training_config': {
            'learning_rate': 1e-4,
            'batch_size': 4,  # Small batch size for memory efficiency
            'num_epochs': 30,
            'max_train_samples': 1000,  # Limit for PoC
            'max_val_samples': 200
        }
    }

    # Initialize parser
    parser = SolidityParser()

    # Create datasets
    logger.info("Creating NFV datasets...")

    train_dataset = NFVDataset(
        data_path=config['data_path'],
        parser=parser,
        max_samples=config['training_config']['max_train_samples']
    )

    val_dataset = NFVDataset(
        data_path=config['data_path'],
        parser=parser,
        max_samples=config['training_config']['max_val_samples']
    )

    # Initialize model
    logger.info("Initializing VulnHunterNFV model...")
    model = VulnHunterNFV(**config['model_config'])

    # Initialize trainer
    trainer = NFVTrainer(
        model=model,
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        **config['training_config']
    )

    # Start training
    history = trainer.train()

    logger.info("NFV training completed successfully!")
    logger.info(f"Final metrics: {history}")

if __name__ == "__main__":
    main()