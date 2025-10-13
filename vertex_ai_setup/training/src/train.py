"""
VulnHunter AI - Vertex AI Training Script
Main training script for VulnHunter AI on Vertex AI with distributed training support
"""

import os
import sys
import json
import argparse
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

import torch
import torch.nn as nn
import torch.distributed as dist
import torch.multiprocessing as mp
from torch.nn.parallel import DistributedDataParallel as DDP
from torch.utils.data import DataLoader, DistributedSampler
import torch.optim as optim
from torch.utils.tensorboard import SummaryWriter

import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
import wandb
from transformers import RobertaTokenizer, RobertaModel, get_scheduler
from google.cloud import storage
from google.cloud import aiplatform
from google.cloud import monitoring_v3

# Import our strategic FP reduction components
sys.path.append('/app/strategic_fp_reduction')
from contextual_codebert_pipeline import ContextualCodeBERT, ContextualConfig
from multimodal_feature_engineering import MultiModalFeatureEngineer, FeatureConfig
from ensemble_confidence_scoring import EnsembleVulnerabilityDetector, EnsembleConfig
from hybrid_neural_architecture import HybridVulnerabilityDetector, HybridArchitectureConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnHunterDataset(torch.utils.data.Dataset):
    """Dataset class for VulnHunter AI training"""

    def __init__(self, data_path: str, tokenizer, max_length: int = 512,
                 feature_engineer: Optional[MultiModalFeatureEngineer] = None):
        self.data = self._load_data(data_path)
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.feature_engineer = feature_engineer

    def _load_data(self, data_path: str) -> List[Dict[str, Any]]:
        """Load training data from various formats"""
        data = []

        if data_path.startswith('gs://'):
            # Load from Google Cloud Storage
            storage_client = storage.Client()
            bucket_name = data_path.split('/')[2]
            blob_path = '/'.join(data_path.split('/')[3:])

            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(blob_path)

            content = blob.download_as_text()
            data = json.loads(content)

        else:
            # Load from local file
            with open(data_path, 'r') as f:
                data = json.load(f)

        logger.info(f"Loaded {len(data)} samples from {data_path}")
        return data

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        sample = self.data[idx]
        code = sample.get('code', '')
        label = sample.get('label', 0)

        # Tokenize code
        encoding = self.tokenizer(
            code,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        # Extract multi-modal features if available
        features = None
        if self.feature_engineer:
            try:
                features = self.feature_engineer.extract_features(code)
                features = torch.tensor(list(features.values()), dtype=torch.float32)
            except Exception as e:
                logger.warning(f"Feature extraction failed for sample {idx}: {e}")
                features = torch.zeros(1024, dtype=torch.float32)  # Fallback

        return {
            'input_ids': encoding['input_ids'].squeeze(),
            'attention_mask': encoding['attention_mask'].squeeze(),
            'features': features,
            'labels': torch.tensor(label, dtype=torch.long),
            'code': code,
            'vulnerability_type': sample.get('vulnerability_type', 'unknown')
        }

class VulnHunterTrainer:
    """Main trainer class for VulnHunter AI"""

    def __init__(self, args):
        self.args = args
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.world_size = args.world_size
        self.rank = args.rank

        # Initialize components
        self.tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
        self.feature_engineer = None
        self.model = None
        self.optimizer = None
        self.scheduler = None

        # Tracking
        self.writer = None
        self.monitoring_client = None

        # Setup distributed training if needed
        if args.distributed:
            self._setup_distributed()

        self._setup_logging()
        self._setup_monitoring()

    def _setup_distributed(self):
        """Setup distributed training"""
        os.environ['MASTER_ADDR'] = 'localhost'
        os.environ['MASTER_PORT'] = '12355'

        dist.init_process_group("nccl", rank=self.rank, world_size=self.world_size)
        torch.cuda.set_device(self.rank)

        logger.info(f"Distributed training initialized: rank {self.rank}/{self.world_size}")

    def _setup_logging(self):
        """Setup experiment tracking"""
        if self.rank == 0:  # Only main process
            # Setup TensorBoard
            log_dir = f"{self.args.job_dir}/logs"
            self.writer = SummaryWriter(log_dir)

            # Setup Weights & Biases if API key is provided
            if os.getenv('WANDB_API_KEY'):
                wandb.init(
                    project="vulnhunter-ai",
                    name=f"training-{int(time.time())}",
                    config=vars(self.args)
                )

    def _setup_monitoring(self):
        """Setup Google Cloud Monitoring"""
        try:
            self.monitoring_client = monitoring_v3.MetricServiceClient()
            self.project_path = f"projects/{os.getenv('GOOGLE_CLOUD_PROJECT')}"
            logger.info("Google Cloud Monitoring initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize monitoring: {e}")

    def _send_metric(self, metric_type: str, value: float, timestamp=None):
        """Send custom metric to Google Cloud Monitoring"""
        if not self.monitoring_client or self.rank != 0:
            return

        try:
            series = monitoring_v3.TimeSeries()
            series.metric.type = f"custom.googleapis.com/vulnhunter/{metric_type}"
            series.resource.type = "aiplatform_training_job"

            point = monitoring_v3.Point()
            point.value.double_value = value
            if timestamp:
                point.interval.end_time = timestamp
            else:
                point.interval.end_time = {"seconds": int(time.time())}

            series.points = [point]

            self.monitoring_client.create_time_series(
                name=self.project_path,
                time_series=[series]
            )
        except Exception as e:
            logger.warning(f"Failed to send metric {metric_type}: {e}")

    def _build_model(self):
        """Build VulnHunter AI model based on configuration"""
        if self.args.model_type == 'contextual_codebert':
            config = ContextualConfig()
            self.model = ContextualCodeBERT(config)

        elif self.args.model_type == 'hybrid_architecture':
            config = HybridArchitectureConfig(
                multimodal_feature_dim=1024,
                enable_graph_neural_network=True,
                enable_transformer_encoder=True,
                enable_attention_mechanism=True,
                enable_hierarchical_learning=True,
                enable_bayesian_layers=True
            )
            self.model = HybridVulnerabilityDetector(config)

        elif self.args.model_type == 'ensemble':
            config = EnsembleConfig(
                models=['codebert', 'multimodal', 'traditional'],
                ensemble_method='weighted_voting',
                confidence_calibration=True
            )
            self.model = EnsembleVulnerabilityDetector(config)

        else:
            # Default: Simple CodeBERT-based model
            self.model = nn.Sequential(
                RobertaModel.from_pretrained('microsoft/codebert-base'),
                nn.Dropout(0.1),
                nn.Linear(768, 256),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(256, 2)  # Binary classification
            )

        self.model = self.model.to(self.device)

        # Wrap with DDP for distributed training
        if self.args.distributed:
            self.model = DDP(self.model, device_ids=[self.rank])

        logger.info(f"Model built: {self.args.model_type}")

    def _build_feature_engineer(self):
        """Build multi-modal feature engineer"""
        if self.args.use_multimodal_features:
            config = FeatureConfig(
                enable_ast_features=True,
                enable_cfg_features=True,
                enable_dfg_features=True,
                enable_codebert_features=True,
                enable_statistical_features=True,
                enable_security_patterns=True
            )
            self.feature_engineer = MultiModalFeatureEngineer(config)
            logger.info("Multi-modal feature engineer initialized")

    def _build_optimizer_and_scheduler(self):
        """Build optimizer and learning rate scheduler"""
        # Optimizer
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=self.args.learning_rate,
            weight_decay=self.args.weight_decay,
            betas=(0.9, 0.999),
            eps=1e-8
        )

        # Learning rate scheduler
        if self.args.use_scheduler:
            self.scheduler = get_scheduler(
                "cosine",
                optimizer=self.optimizer,
                num_warmup_steps=self.args.warmup_steps,
                num_training_steps=self.args.max_steps
            )

        logger.info("Optimizer and scheduler initialized")

    def _create_data_loaders(self):
        """Create training and validation data loaders"""
        # Training dataset
        train_dataset = VulnHunterDataset(
            self.args.train_data_path,
            self.tokenizer,
            self.args.max_seq_length,
            self.feature_engineer
        )

        # Validation dataset
        val_dataset = VulnHunterDataset(
            self.args.val_data_path,
            self.tokenizer,
            self.args.max_seq_length,
            self.feature_engineer
        ) if self.args.val_data_path else None

        # Distributed samplers
        train_sampler = None
        val_sampler = None

        if self.args.distributed:
            train_sampler = DistributedSampler(
                train_dataset,
                num_replicas=self.world_size,
                rank=self.rank,
                shuffle=True
            )
            if val_dataset:
                val_sampler = DistributedSampler(
                    val_dataset,
                    num_replicas=self.world_size,
                    rank=self.rank,
                    shuffle=False
                )

        # Data loaders
        self.train_loader = DataLoader(
            train_dataset,
            batch_size=self.args.batch_size,
            sampler=train_sampler,
            shuffle=(train_sampler is None),
            num_workers=self.args.num_workers,
            pin_memory=True
        )

        self.val_loader = None
        if val_dataset:
            self.val_loader = DataLoader(
                val_dataset,
                batch_size=self.args.batch_size,
                sampler=val_sampler,
                shuffle=False,
                num_workers=self.args.num_workers,
                pin_memory=True
            )

        logger.info(f"Data loaders created: train={len(self.train_loader)}, val={len(self.val_loader) if self.val_loader else 0}")

    def _train_epoch(self, epoch: int):
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        total_samples = 0

        # For distributed training
        if self.args.distributed:
            self.train_loader.sampler.set_epoch(epoch)

        for batch_idx, batch in enumerate(self.train_loader):
            # Move to device
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            labels = batch['labels'].to(self.device)

            # Forward pass
            self.optimizer.zero_grad()

            # Handle different model types
            if hasattr(self.model, 'forward'):
                if 'features' in batch and batch['features'] is not None:
                    # Multi-modal model
                    features = batch['features'].to(self.device)
                    outputs = self.model(
                        multimodal_features=features,
                        sequence_data=input_ids.unsqueeze(1),
                        sequence_mask=attention_mask.unsqueeze(1)
                    )
                    logits = outputs.get('logits', outputs)
                else:
                    # Standard model
                    outputs = self.model(input_ids, attention_mask=attention_mask)
                    logits = outputs.logits if hasattr(outputs, 'logits') else outputs
            else:
                # Simple sequential model
                outputs = self.model[0](input_ids, attention_mask=attention_mask)
                logits = self.model[1:](outputs.pooler_output)

            # Compute loss
            criterion = nn.CrossEntropyLoss()
            loss = criterion(logits, labels)

            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.args.max_grad_norm)
            self.optimizer.step()

            if self.scheduler:
                self.scheduler.step()

            # Update metrics
            total_loss += loss.item()
            total_samples += labels.size(0)

            # Log progress
            if batch_idx % self.args.log_steps == 0 and self.rank == 0:
                avg_loss = total_loss / (batch_idx + 1)
                lr = self.optimizer.param_groups[0]['lr']

                logger.info(f"Epoch {epoch}, Batch {batch_idx}, Loss: {avg_loss:.4f}, LR: {lr:.6f}")

                # TensorBoard logging
                if self.writer:
                    step = epoch * len(self.train_loader) + batch_idx
                    self.writer.add_scalar('train/loss', avg_loss, step)
                    self.writer.add_scalar('train/lr', lr, step)

                # Weights & Biases logging
                if wandb.run:
                    wandb.log({
                        'train/loss': avg_loss,
                        'train/lr': lr,
                        'epoch': epoch,
                        'step': step
                    })

        return total_loss / len(self.train_loader)

    def _validate(self, epoch: int):
        """Validate model"""
        if not self.val_loader:
            return {}

        self.model.eval()
        total_loss = 0
        all_predictions = []
        all_labels = []
        all_probabilities = []

        with torch.no_grad():
            for batch in self.val_loader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['labels'].to(self.device)

                # Forward pass
                if hasattr(self.model, 'forward'):
                    if 'features' in batch and batch['features'] is not None:
                        features = batch['features'].to(self.device)
                        outputs = self.model(
                            multimodal_features=features,
                            sequence_data=input_ids.unsqueeze(1),
                            sequence_mask=attention_mask.unsqueeze(1)
                        )
                        logits = outputs.get('logits', outputs)
                    else:
                        outputs = self.model(input_ids, attention_mask=attention_mask)
                        logits = outputs.logits if hasattr(outputs, 'logits') else outputs
                else:
                    outputs = self.model[0](input_ids, attention_mask=attention_mask)
                    logits = self.model[1:](outputs.pooler_output)

                # Compute loss
                criterion = nn.CrossEntropyLoss()
                loss = criterion(logits, labels)
                total_loss += loss.item()

                # Get predictions
                probabilities = torch.softmax(logits, dim=-1)
                predictions = torch.argmax(logits, dim=-1)

                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
                all_probabilities.extend(probabilities[:, 1].cpu().numpy())  # Positive class probability

        # Compute metrics
        accuracy = accuracy_score(all_labels, all_predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_predictions, average='binary'
        )

        try:
            auc = roc_auc_score(all_labels, all_probabilities)
        except:
            auc = 0.5

        # Compute false positive rate
        tn = ((np.array(all_labels) == 0) & (np.array(all_predictions) == 0)).sum()
        fp = ((np.array(all_labels) == 0) & (np.array(all_predictions) == 1)).sum()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        metrics = {
            'val_loss': total_loss / len(self.val_loader),
            'val_accuracy': accuracy,
            'val_precision': precision,
            'val_recall': recall,
            'val_f1': f1,
            'val_auc': auc,
            'val_false_positive_rate': fpr
        }

        # Log metrics
        if self.rank == 0:
            logger.info(f"Validation - Epoch {epoch}: {metrics}")

            if self.writer:
                for key, value in metrics.items():
                    self.writer.add_scalar(key, value, epoch)

            if wandb.run:
                wandb.log({**metrics, 'epoch': epoch})

            # Send custom metrics to monitoring
            self._send_metric('training/false_positive_rate', fpr)
            self._send_metric('training/true_positive_rate', recall)
            self._send_metric('training/f1_score', f1)

        return metrics

    def _save_checkpoint(self, epoch: int, metrics: Dict[str, float]):
        """Save model checkpoint"""
        if self.rank != 0:  # Only save on main process
            return

        checkpoint = {
            'epoch': epoch,
            'model_state_dict': self.model.module.state_dict() if self.args.distributed else self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'metrics': metrics,
            'args': vars(self.args)
        }

        # Save locally
        checkpoint_path = os.path.join(self.args.job_dir, f'checkpoint_epoch_{epoch}.pt')
        torch.save(checkpoint, checkpoint_path)

        # Save to GCS
        if self.args.job_dir.startswith('gs://'):
            storage_client = storage.Client()
            bucket_name = self.args.job_dir.split('/')[2]
            blob_path = f"{''.join(self.args.job_dir.split('/')[3:])}/checkpoint_epoch_{epoch}.pt"

            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(blob_path)
            blob.upload_from_filename(checkpoint_path)

        logger.info(f"Checkpoint saved: epoch {epoch}")

    def train(self):
        """Main training loop"""
        logger.info("Starting VulnHunter AI training...")

        # Build components
        self._build_feature_engineer()
        self._build_model()
        self._build_optimizer_and_scheduler()
        self._create_data_loaders()

        best_f1 = 0
        patience_counter = 0

        for epoch in range(self.args.num_epochs):
            logger.info(f"Starting epoch {epoch + 1}/{self.args.num_epochs}")

            # Training
            train_loss = self._train_epoch(epoch)

            # Validation
            val_metrics = self._validate(epoch)

            # Early stopping
            current_f1 = val_metrics.get('val_f1', 0)
            if current_f1 > best_f1:
                best_f1 = current_f1
                patience_counter = 0

                # Save best model
                if self.rank == 0:
                    self._save_checkpoint(epoch, val_metrics)

            else:
                patience_counter += 1
                if patience_counter >= self.args.early_stopping_patience:
                    logger.info(f"Early stopping triggered at epoch {epoch}")
                    break

            # Save periodic checkpoint
            if (epoch + 1) % self.args.save_steps == 0:
                self._save_checkpoint(epoch, val_metrics)

        logger.info("Training completed!")

        # Cleanup
        if self.writer:
            self.writer.close()
        if wandb.run:
            wandb.finish()
        if self.args.distributed:
            dist.destroy_process_group()

def main():
    parser = argparse.ArgumentParser(description='VulnHunter AI Training on Vertex AI')

    # Data arguments
    parser.add_argument('--train-data-path', type=str, required=True,
                       help='Path to training data (local or GCS)')
    parser.add_argument('--val-data-path', type=str, default=None,
                       help='Path to validation data (local or GCS)')
    parser.add_argument('--job-dir', type=str, required=True,
                       help='Job directory for outputs (local or GCS)')

    # Model arguments
    parser.add_argument('--model-type', type=str, default='contextual_codebert',
                       choices=['contextual_codebert', 'hybrid_architecture', 'ensemble', 'simple'],
                       help='Type of model to train')
    parser.add_argument('--max-seq-length', type=int, default=512,
                       help='Maximum sequence length')
    parser.add_argument('--use-multimodal-features', action='store_true',
                       help='Use multi-modal features')

    # Training arguments
    parser.add_argument('--batch-size', type=int, default=16,
                       help='Training batch size')
    parser.add_argument('--num-epochs', type=int, default=10,
                       help='Number of training epochs')
    parser.add_argument('--learning-rate', type=float, default=2e-5,
                       help='Learning rate')
    parser.add_argument('--weight-decay', type=float, default=0.01,
                       help='Weight decay')
    parser.add_argument('--max-grad-norm', type=float, default=1.0,
                       help='Maximum gradient norm for clipping')
    parser.add_argument('--warmup-steps', type=int, default=1000,
                       help='Number of warmup steps')
    parser.add_argument('--max-steps', type=int, default=10000,
                       help='Maximum number of training steps')
    parser.add_argument('--use-scheduler', action='store_true',
                       help='Use learning rate scheduler')

    # Logging and checkpointing
    parser.add_argument('--log-steps', type=int, default=100,
                       help='Log every N steps')
    parser.add_argument('--save-steps', type=int, default=1000,
                       help='Save checkpoint every N epochs')
    parser.add_argument('--early-stopping-patience', type=int, default=5,
                       help='Early stopping patience')

    # System arguments
    parser.add_argument('--num-workers', type=int, default=4,
                       help='Number of data loading workers')
    parser.add_argument('--distributed', action='store_true',
                       help='Use distributed training')
    parser.add_argument('--world-size', type=int, default=1,
                       help='World size for distributed training')
    parser.add_argument('--rank', type=int, default=0,
                       help='Process rank for distributed training')

    args = parser.parse_args()

    # Initialize trainer and start training
    trainer = VulnHunterTrainer(args)
    trainer.train()

if __name__ == '__main__':
    main()