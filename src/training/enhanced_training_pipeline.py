#!/usr/bin/env python3
"""
Enhanced Training Pipeline for VulnHunter Ωmega
High-accuracy training on comprehensive real-world vulnerability dataset
"""

import os
import sys
import json
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from transformers import AutoTokenizer, get_linear_schedule_with_warmup
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_recall_curve
from sklearn.utils.class_weight import compute_class_weight
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm
import wandb
import pickle
from pathlib import Path
import time
import random
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
import warnings
warnings.filterwarnings('ignore')

# Add path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.vulnhunter_omega_math3_engine import VulnHunterOmegaMath3Engine as Math3Engine
from training.comprehensive_dataset_collector import VulnerabilityData

@dataclass
class TrainingConfig:
    """Training configuration"""
    model_type: str = "large"  # "omega_v3" or "large"
    batch_size: int = 32
    learning_rate: float = 2e-5
    num_epochs: int = 50
    max_seq_length: int = 512
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    gradient_clip_norm: float = 1.0
    save_steps: int = 1000
    eval_steps: int = 500
    early_stopping_patience: int = 5
    use_math3_engine: bool = True
    use_focal_loss: bool = True
    use_class_weights: bool = True
    use_adversarial_training: bool = True
    use_mixup: bool = True
    use_curriculum_learning: bool = True
    cross_validation_folds: int = 5

class VulnerabilityDataset(Dataset):
    """Enhanced dataset for comprehensive vulnerability training"""

    def __init__(self,
                 samples: List[Dict[str, Any]],
                 tokenizer,
                 math3_engine: Optional[Math3Engine] = None,
                 max_length: int = 512,
                 augment_data: bool = True):
        self.samples = samples
        self.tokenizer = tokenizer
        self.math3_engine = math3_engine
        self.max_length = max_length
        self.augment_data = augment_data

        # Create comprehensive label mappings
        self.vulnerability_types = list(set(s['vulnerability_type'] for s in samples))
        self.severity_levels = list(set(s['severity'] for s in samples))
        self.sources = list(set(s['source'] for s in samples))
        self.languages = list(set(s['language'] for s in samples))

        # Create label to index mappings
        self.vuln_type_to_idx = {vt: i for i, vt in enumerate(self.vulnerability_types)}
        self.severity_to_idx = {sv: i for i, sv in enumerate(self.severity_levels)}
        self.source_to_idx = {src: i for i, src in enumerate(self.sources)}
        self.language_to_idx = {lang: i for i, lang in enumerate(self.languages)}

        # Compute class weights
        self.class_weights = self._compute_class_weights()

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        sample = self.samples[idx]
        code = sample['code']

        # Data augmentation
        if self.augment_data and random.random() < 0.3:
            code = self._augment_code(code)

        # Tokenize code
        encoding = self.tokenizer(
            code,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        # Math³ engine analysis
        math3_features = torch.zeros(8)  # 7 frameworks + composite
        if self.math3_engine:
            try:
                math3_scores = self.math3_engine.analyze_vulnerability_pattern(code)
                math3_features = torch.tensor(list(math3_scores.values()), dtype=torch.float32)
            except:
                pass

        # Multi-task labels
        is_vulnerable = 1 if sample['is_vulnerable'] else 0
        vuln_type_idx = self.vuln_type_to_idx.get(sample['vulnerability_type'], 0)
        severity_idx = self.severity_to_idx.get(sample['severity'], 0)
        source_idx = self.source_to_idx.get(sample['source'], 0)
        language_idx = self.language_to_idx.get(sample['language'], 0)

        # Extract metadata features
        metadata_features = self._extract_metadata_features(sample.get('metadata', {}))

        return {
            'input_ids': encoding['input_ids'].squeeze(0),
            'attention_mask': encoding['attention_mask'].squeeze(0),
            'math3_features': math3_features,
            'metadata_features': metadata_features,
            'is_vulnerable': torch.tensor(is_vulnerable, dtype=torch.long),
            'vulnerability_type': torch.tensor(vuln_type_idx, dtype=torch.long),
            'severity': torch.tensor(severity_idx, dtype=torch.long),
            'source': torch.tensor(source_idx, dtype=torch.long),
            'language': torch.tensor(language_idx, dtype=torch.long),
            'sample_weight': torch.tensor(self.class_weights[is_vulnerable], dtype=torch.float32)
        }

    def _augment_code(self, code: str) -> str:
        """Apply data augmentation techniques"""
        augmentations = [
            self._add_comments,
            self._change_variable_names,
            self._add_whitespace,
            self._reorder_statements
        ]

        if random.random() < 0.5:
            augmentation = random.choice(augmentations)
            try:
                return augmentation(code)
            except:
                return code
        return code

    def _add_comments(self, code: str) -> str:
        """Add random comments to code"""
        comments = [
            "// Security note",
            "# TODO: Review this",
            "/* Processing data */",
            "// Input validation needed"
        ]
        lines = code.split('\\n')
        if lines:
            insert_pos = random.randint(0, len(lines))
            lines.insert(insert_pos, random.choice(comments))
        return '\\n'.join(lines)

    def _change_variable_names(self, code: str) -> str:
        """Change variable names while preserving functionality"""
        replacements = {
            'data': 'input_data',
            'user': 'current_user',
            'input': 'user_input',
            'result': 'query_result'
        }

        for old, new in replacements.items():
            if f" {old}" in code and random.random() < 0.3:
                code = code.replace(f" {old}", f" {new}")
        return code

    def _add_whitespace(self, code: str) -> str:
        """Add random whitespace"""
        if random.random() < 0.3:
            lines = code.split('\\n')
            for i in range(len(lines)):
                if random.random() < 0.2:
                    lines[i] = '    ' + lines[i]  # Add indentation
            return '\\n'.join(lines)
        return code

    def _reorder_statements(self, code: str) -> str:
        """Reorder independent statements"""
        # Simple reordering for demonstration
        lines = code.split('\\n')
        if len(lines) > 2 and random.random() < 0.2:
            # Swap two adjacent lines if they seem independent
            idx = random.randint(0, len(lines) - 2)
            if not any(keyword in lines[idx].lower() for keyword in ['if', 'for', 'while', 'def', 'function']):
                lines[idx], lines[idx + 1] = lines[idx + 1], lines[idx]
        return '\\n'.join(lines)

    def _extract_metadata_features(self, metadata: Dict[str, Any]) -> torch.Tensor:
        """Extract numerical features from metadata"""
        features = torch.zeros(10)  # 10 metadata features

        # CVE-specific features
        if 'cvss_score' in metadata:
            features[0] = metadata['cvss_score'] / 10.0  # Normalize to 0-1

        # Code complexity features
        if 'complexity' in metadata:
            features[1] = min(metadata['complexity'] / 100.0, 1.0)

        # Binary presence flags
        features[2] = 1.0 if 'cve_id' in metadata else 0.0
        features[3] = 1.0 if 'commit_hash' in metadata else 0.0
        features[4] = 1.0 if 'contract_address' in metadata else 0.0
        features[5] = 1.0 if 'owasp_category' in metadata else 0.0
        features[6] = 1.0 if 'platform' in metadata else 0.0
        features[7] = 1.0 if 'binary_type' in metadata else 0.0
        features[8] = 1.0 if 'patch_applied' in metadata else 0.0

        # Risk score based on source
        source_risk = {'cve': 0.9, 'github': 0.7, 'smart_contract': 0.8,
                      'web_app': 0.6, 'mobile': 0.7, 'binary': 0.9}
        features[9] = source_risk.get(metadata.get('source', ''), 0.5)

        return features

    def _compute_class_weights(self) -> Dict[int, float]:
        """Compute class weights for imbalanced dataset"""
        labels = [1 if s['is_vulnerable'] else 0 for s in self.samples]
        class_weights = compute_class_weight('balanced', classes=np.unique(labels), y=labels)
        return {0: class_weights[0], 1: class_weights[1]}

class FocalLoss(nn.Module):
    """Focal Loss for handling class imbalance"""

    def __init__(self, alpha: float = 1.0, gamma: float = 2.0, reduction: str = 'mean'):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1 - pt) ** self.gamma * ce_loss

        if self.reduction == 'mean':
            return focal_loss.mean()
        elif self.reduction == 'sum':
            return focal_loss.sum()
        return focal_loss

class EnhancedVulnHunterModel(nn.Module):
    """Enhanced VulnHunter model with multi-task learning"""

    def __init__(self,
                 vocab_size: int,
                 num_vuln_types: int,
                 num_severities: int,
                 num_sources: int,
                 num_languages: int,
                 embed_dim: int = 768,
                 num_heads: int = 12,
                 num_layers: int = 12,
                 dropout: float = 0.1):
        super().__init__()

        # Core transformer layers
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.position_embedding = nn.Embedding(512, embed_dim)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Math³ and metadata integration
        self.math3_projection = nn.Linear(8, embed_dim // 4)
        self.metadata_projection = nn.Linear(10, embed_dim // 4)

        # Feature fusion
        self.feature_fusion = nn.Linear(embed_dim + embed_dim // 2, embed_dim)

        # Multi-task prediction heads
        self.vulnerability_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, 2)  # Binary classification
        )

        self.vuln_type_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, num_vuln_types)
        )

        self.severity_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, num_severities)
        )

        self.source_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, num_sources)
        )

        self.language_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, num_languages)
        )

        # Layer normalization and dropout
        self.layer_norm = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self,
                input_ids: torch.Tensor,
                attention_mask: torch.Tensor,
                math3_features: Optional[torch.Tensor] = None,
                metadata_features: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:

        batch_size, seq_len = input_ids.shape
        device = input_ids.device

        # Token embeddings
        token_embeds = self.embedding(input_ids)

        # Position embeddings
        positions = torch.arange(seq_len, device=device).unsqueeze(0).expand(batch_size, -1)
        pos_embeds = self.position_embedding(positions)

        # Combined embeddings
        embeddings = token_embeds + pos_embeds
        embeddings = self.dropout(embeddings)

        # Apply attention mask
        attention_mask = attention_mask.float()
        attention_mask = attention_mask.masked_fill(attention_mask == 0, float('-inf'))
        attention_mask = attention_mask.masked_fill(attention_mask == 1, 0.0)

        # Transformer encoding
        transformer_output = self.transformer(embeddings, src_key_padding_mask=attention_mask)

        # Global average pooling
        mask_expanded = attention_mask.unsqueeze(-1).expand(transformer_output.size())
        sum_embeddings = torch.sum(transformer_output * mask_expanded, dim=1)
        sum_mask = torch.clamp(mask_expanded.sum(dim=1), min=1e-9)
        pooled_output = sum_embeddings / sum_mask

        # Integrate Math³ features
        additional_features = []
        if math3_features is not None:
            math3_proj = self.math3_projection(math3_features)
            additional_features.append(math3_proj)

        # Integrate metadata features
        if metadata_features is not None:
            metadata_proj = self.metadata_projection(metadata_features)
            additional_features.append(metadata_proj)

        # Feature fusion
        if additional_features:
            combined_additional = torch.cat(additional_features, dim=1)
            fused_features = torch.cat([pooled_output, combined_additional], dim=1)
            final_features = self.feature_fusion(fused_features)
        else:
            final_features = pooled_output

        final_features = self.layer_norm(final_features)

        # Multi-task predictions
        vulnerability_logits = self.vulnerability_head(final_features)
        vuln_type_logits = self.vuln_type_head(final_features)
        severity_logits = self.severity_head(final_features)
        source_logits = self.source_head(final_features)
        language_logits = self.language_head(final_features)

        return {
            'vulnerability_logits': vulnerability_logits,
            'vuln_type_logits': vuln_type_logits,
            'severity_logits': severity_logits,
            'source_logits': source_logits,
            'language_logits': language_logits,
            'hidden_states': final_features
        }

class EnhancedTrainer:
    """Enhanced trainer with advanced techniques for high accuracy"""

    def __init__(self,
                 model: nn.Module,
                 train_dataset: VulnerabilityDataset,
                 val_dataset: VulnerabilityDataset,
                 config: TrainingConfig,
                 device: torch.device):

        self.model = model.to(device)
        self.train_dataset = train_dataset
        self.val_dataset = val_dataset
        self.config = config
        self.device = device

        # Setup data loaders
        self.setup_data_loaders()

        # Setup optimizer and scheduler
        self.setup_optimizer_and_scheduler()

        # Setup loss functions
        self.setup_loss_functions()

        # Tracking
        self.best_f1_score = 0.0
        self.patience_counter = 0
        self.training_history = {
            'train_loss': [], 'val_loss': [], 'val_f1': [], 'val_precision': [], 'val_recall': []
        }

    def setup_data_loaders(self):
        """Setup data loaders with sampling"""
        # Weighted sampling for balanced training
        if self.config.use_class_weights:
            sample_weights = [self.train_dataset.class_weights[1 if s['is_vulnerable'] else 0]
                            for s in self.train_dataset.samples]
            sampler = WeightedRandomSampler(sample_weights, len(sample_weights))
            shuffle = False
        else:
            sampler = None
            shuffle = True

        self.train_loader = DataLoader(
            self.train_dataset,
            batch_size=self.config.batch_size,
            sampler=sampler,
            shuffle=shuffle,
            num_workers=4,
            pin_memory=True
        )

        self.val_loader = DataLoader(
            self.val_dataset,
            batch_size=self.config.batch_size,
            shuffle=False,
            num_workers=4,
            pin_memory=True
        )

    def setup_optimizer_and_scheduler(self):
        """Setup optimizer and learning rate scheduler"""
        # AdamW optimizer with weight decay
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
            eps=1e-8
        )

        # Learning rate scheduler
        num_training_steps = len(self.train_loader) * self.config.num_epochs
        num_warmup_steps = int(num_training_steps * self.config.warmup_ratio)

        self.scheduler = get_linear_schedule_with_warmup(
            self.optimizer,
            num_warmup_steps=num_warmup_steps,
            num_training_steps=num_training_steps
        )

    def setup_loss_functions(self):
        """Setup loss functions"""
        if self.config.use_focal_loss:
            self.vulnerability_criterion = FocalLoss(alpha=2.0, gamma=2.0)
        else:
            self.vulnerability_criterion = nn.CrossEntropyLoss()

        # Multi-task loss functions
        self.vuln_type_criterion = nn.CrossEntropyLoss()
        self.severity_criterion = nn.CrossEntropyLoss()
        self.source_criterion = nn.CrossEntropyLoss()
        self.language_criterion = nn.CrossEntropyLoss()

    def mixup_data(self, x: torch.Tensor, y: torch.Tensor, alpha: float = 1.0) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, float]:
        """Apply mixup data augmentation"""
        if alpha > 0:
            lam = np.random.beta(alpha, alpha)
        else:
            lam = 1

        batch_size = x.size(0)
        index = torch.randperm(batch_size).to(self.device)

        mixed_x = lam * x + (1 - lam) * x[index, :]
        y_a, y_b = y, y[index]
        return mixed_x, y_a, y_b, lam

    def mixup_criterion(self, criterion, pred: torch.Tensor, y_a: torch.Tensor, y_b: torch.Tensor, lam: float) -> torch.Tensor:
        """Mixup loss calculation"""
        return lam * criterion(pred, y_a) + (1 - lam) * criterion(pred, y_b)

    def train_epoch(self, epoch: int) -> float:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0.0
        num_batches = 0

        progress_bar = tqdm(self.train_loader, desc=f'Epoch {epoch+1}/{self.config.num_epochs}')

        for batch_idx, batch in enumerate(progress_bar):
            # Move batch to device
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            math3_features = batch['math3_features'].to(self.device)
            metadata_features = batch['metadata_features'].to(self.device)

            labels = {
                'vulnerability': batch['is_vulnerable'].to(self.device),
                'vuln_type': batch['vulnerability_type'].to(self.device),
                'severity': batch['severity'].to(self.device),
                'source': batch['source'].to(self.device),
                'language': batch['language'].to(self.device)
            }

            # Apply mixup if enabled
            if self.config.use_mixup and random.random() < 0.5:
                input_ids, y_a, y_b, lam = self.mixup_data(input_ids, labels['vulnerability'])
                use_mixup = True
            else:
                use_mixup = False

            # Forward pass
            outputs = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                math3_features=math3_features,
                metadata_features=metadata_features
            )

            # Calculate losses
            if use_mixup:
                vuln_loss = self.mixup_criterion(
                    self.vulnerability_criterion,
                    outputs['vulnerability_logits'],
                    y_a, y_b, lam
                )
            else:
                vuln_loss = self.vulnerability_criterion(
                    outputs['vulnerability_logits'],
                    labels['vulnerability']
                )

            # Multi-task losses
            vuln_type_loss = self.vuln_type_criterion(outputs['vuln_type_logits'], labels['vuln_type'])
            severity_loss = self.severity_criterion(outputs['severity_logits'], labels['severity'])
            source_loss = self.source_criterion(outputs['source_logits'], labels['source'])
            language_loss = self.language_criterion(outputs['language_logits'], labels['language'])

            # Combined loss with curriculum learning weights
            curriculum_weight = min(1.0, (epoch + 1) / 10)  # Gradually increase multi-task importance

            total_loss_batch = (
                vuln_loss +
                curriculum_weight * 0.3 * vuln_type_loss +
                curriculum_weight * 0.2 * severity_loss +
                curriculum_weight * 0.1 * source_loss +
                curriculum_weight * 0.1 * language_loss
            )

            # Backward pass
            self.optimizer.zero_grad()
            total_loss_batch.backward()

            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.config.gradient_clip_norm)

            self.optimizer.step()
            self.scheduler.step()

            total_loss += total_loss_batch.item()
            num_batches += 1

            # Update progress bar
            progress_bar.set_postfix({
                'Loss': f'{total_loss_batch.item():.4f}',
                'Avg Loss': f'{total_loss/num_batches:.4f}',
                'LR': f'{self.scheduler.get_last_lr()[0]:.2e}'
            })

        return total_loss / num_batches

    def evaluate(self) -> Dict[str, float]:
        """Evaluate model on validation set"""
        self.model.eval()
        total_loss = 0.0
        all_predictions = []
        all_labels = []

        with torch.no_grad():
            for batch in tqdm(self.val_loader, desc='Evaluating'):
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                math3_features = batch['math3_features'].to(self.device)
                metadata_features = batch['metadata_features'].to(self.device)
                labels = batch['is_vulnerable'].to(self.device)

                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    math3_features=math3_features,
                    metadata_features=metadata_features
                )

                loss = self.vulnerability_criterion(outputs['vulnerability_logits'], labels)
                total_loss += loss.item()

                predictions = torch.argmax(outputs['vulnerability_logits'], dim=-1)
                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

        # Calculate metrics
        f1 = f1_score(all_labels, all_predictions, average='weighted')
        precision = precision_score(all_labels, all_predictions, average='weighted')
        recall = recall_score(all_labels, all_predictions, average='weighted')

        return {
            'val_loss': total_loss / len(self.val_loader),
            'val_f1': f1,
            'val_precision': precision,
            'val_recall': recall
        }

    def train(self) -> Dict[str, List[float]]:
        """Full training loop"""
        print(f"🚀 Starting enhanced training for {self.config.num_epochs} epochs...")
        print(f"📊 Training samples: {len(self.train_dataset):,}")
        print(f"📊 Validation samples: {len(self.val_dataset):,}")

        for epoch in range(self.config.num_epochs):
            # Training
            train_loss = self.train_epoch(epoch)

            # Evaluation
            eval_metrics = self.evaluate()

            # Tracking
            self.training_history['train_loss'].append(train_loss)
            self.training_history['val_loss'].append(eval_metrics['val_loss'])
            self.training_history['val_f1'].append(eval_metrics['val_f1'])
            self.training_history['val_precision'].append(eval_metrics['val_precision'])
            self.training_history['val_recall'].append(eval_metrics['val_recall'])

            # Print metrics
            print(f"\\nEpoch {epoch+1}/{self.config.num_epochs}:")
            print(f"  Train Loss: {train_loss:.4f}")
            print(f"  Val Loss: {eval_metrics['val_loss']:.4f}")
            print(f"  Val F1: {eval_metrics['val_f1']:.4f}")
            print(f"  Val Precision: {eval_metrics['val_precision']:.4f}")
            print(f"  Val Recall: {eval_metrics['val_recall']:.4f}")

            # Save best model
            if eval_metrics['val_f1'] > self.best_f1_score:
                self.best_f1_score = eval_metrics['val_f1']
                self.save_model(f"best_{self.config.model_type}_model.pth")
                self.patience_counter = 0
                print(f"  💾 New best model saved! F1: {self.best_f1_score:.4f}")
            else:
                self.patience_counter += 1

            # Early stopping
            if self.patience_counter >= self.config.early_stopping_patience:
                print(f"\\n⏹️ Early stopping triggered after {epoch+1} epochs")
                break

            # Save checkpoint
            if (epoch + 1) % 10 == 0:
                self.save_model(f"{self.config.model_type}_checkpoint_epoch_{epoch+1}.pth")

        return self.training_history

    def save_model(self, filename: str):
        """Save model and training state"""
        model_path = Path("models") / filename
        model_path.parent.mkdir(exist_ok=True)

        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict(),
            'config': self.config,
            'training_history': self.training_history,
            'best_f1_score': self.best_f1_score,
            'vocab_mappings': {
                'vulnerability_types': self.train_dataset.vulnerability_types,
                'severity_levels': self.train_dataset.severity_levels,
                'sources': self.train_dataset.sources,
                'languages': self.train_dataset.languages
            }
        }, model_path)

def main():
    """Main training function"""
    # Configuration
    config = TrainingConfig(
        model_type="large",  # Train the large model
        batch_size=16,  # Reduced for large model
        learning_rate=1e-5,  # Lower LR for large model
        num_epochs=50,
        use_math3_engine=True,
        use_focal_loss=True,
        use_class_weights=True,
        use_adversarial_training=True,
        use_mixup=True,
        use_curriculum_learning=True
    )

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"🔥 Using device: {device}")

    # Load comprehensive dataset
    print("📚 Loading comprehensive vulnerability dataset...")
    with open('training_data/comprehensive_vulnerability_dataset.json', 'r') as f:
        dataset_samples = json.load(f)

    print(f"📊 Loaded {len(dataset_samples):,} samples")

    # Split dataset
    train_samples, temp_samples = train_test_split(
        dataset_samples,
        test_size=0.3,
        random_state=42,
        stratify=[s['is_vulnerable'] for s in dataset_samples]
    )
    val_samples, test_samples = train_test_split(
        temp_samples,
        test_size=0.5,
        random_state=42,
        stratify=[s['is_vulnerable'] for s in temp_samples]
    )

    print(f"📊 Train: {len(train_samples):,}, Val: {len(val_samples):,}, Test: {len(test_samples):,}")

    # Initialize tokenizer and Math³ engine
    tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    math3_engine = Math3Engine() if config.use_math3_engine else None

    # Create datasets
    train_dataset = VulnerabilityDataset(train_samples, tokenizer, math3_engine, augment_data=True)
    val_dataset = VulnerabilityDataset(val_samples, tokenizer, math3_engine, augment_data=False)

    # Initialize model
    model = EnhancedVulnHunterModel(
        vocab_size=tokenizer.vocab_size,
        num_vuln_types=len(train_dataset.vulnerability_types),
        num_severities=len(train_dataset.severity_levels),
        num_sources=len(train_dataset.sources),
        num_languages=len(train_dataset.languages),
        embed_dim=1024,  # Large model
        num_heads=16,
        num_layers=24,
        dropout=0.1
    )

    print(f"🏗️ Model parameters: {sum(p.numel() for p in model.parameters()):,}")

    # Initialize trainer
    trainer = EnhancedTrainer(model, train_dataset, val_dataset, config, device)

    # Start training
    training_history = trainer.train()

    print("\\n🎉 Enhanced training completed!")
    print(f"🏆 Best F1 Score: {trainer.best_f1_score:.4f}")

if __name__ == "__main__":
    # Import required modules
    from sklearn.metrics import precision_score, recall_score
    main()