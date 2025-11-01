"""
VulnHunter PoC: Fusion Model Training Pipeline
Training pipeline for GNN + Transformer fusion model
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
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
import pickle

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from src.models.vulnhunter_fusion import VulnHunterFusion, VulnHunterComplete
from src.parser.code_to_graph import CodeToGraphParser

class VulnerabilityDataset(Dataset):
    """Dataset for vulnerability detection training"""

    def __init__(self, data_path: str, max_samples: Optional[int] = None):
        self.data_path = data_path
        self.samples = []
        self.parser = CodeToGraphParser()

        self._load_data(max_samples)

    def _load_data(self, max_samples: Optional[int]):
        """Load and preprocess training data"""
        logger.info(f"Loading dataset from {self.data_path}")

        if not os.path.exists(self.data_path):
            logger.error(f"Dataset file not found: {self.data_path}")
            raise FileNotFoundError(f"Dataset file not found: {self.data_path}")

        with open(self.data_path, 'r') as f:
            raw_data = json.load(f)

        logger.info(f"Loaded {len(raw_data)} raw samples")

        # Process samples
        processed_count = 0
        for item in raw_data:
            if max_samples and processed_count >= max_samples:
                break

            try:
                # Extract required fields
                code = item.get('code', '')
                label = item.get('vulnerable', 0)
                vuln_type = item.get('vulnerability_type', 'unknown')

                if not code.strip():
                    continue

                # Parse code to graph
                graph = self.parser.parse_code_to_graph(code)

                # Create sample
                sample = {
                    'code': code,
                    'graph': graph,
                    'label': int(label),
                    'vulnerability_type': vuln_type,
                    'metadata': {
                        'source': item.get('source', 'unknown'),
                        'language': item.get('language', 'python'),
                        'cwe': item.get('cwe', 'unknown')
                    }
                }

                self.samples.append(sample)
                processed_count += 1

                if processed_count % 1000 == 0:
                    logger.info(f"Processed {processed_count} samples")

            except Exception as e:
                logger.warning(f"Error processing sample: {e}")
                continue

        logger.info(f"Successfully processed {len(self.samples)} samples")

        # Print dataset statistics
        self._print_dataset_stats()

    def _print_dataset_stats(self):
        """Print dataset statistics"""
        if not self.samples:
            return

        total = len(self.samples)
        vulnerable = sum(1 for s in self.samples if s['label'] == 1)
        safe = total - vulnerable

        vuln_types = {}
        languages = {}

        for sample in self.samples:
            vtype = sample['vulnerability_type']
            lang = sample['metadata']['language']

            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            languages[lang] = languages.get(lang, 0) + 1

        logger.info(f"Dataset Statistics:")
        logger.info(f"  Total samples: {total}")
        logger.info(f"  Vulnerable: {vulnerable} ({vulnerable/total*100:.1f}%)")
        logger.info(f"  Safe: {safe} ({safe/total*100:.1f}%)")
        logger.info(f"  Vulnerability types: {len(vuln_types)}")
        logger.info(f"  Languages: {len(languages)}")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]

def collate_fn(batch):
    """Custom collate function for batch processing"""
    codes = []
    graphs = []
    labels = []
    vuln_types = []

    for sample in batch:
        codes.append(sample['code'])
        graphs.append(sample['graph'])
        labels.append(sample['label'])
        vuln_types.append(sample['vulnerability_type'])

    return {
        'codes': codes,
        'graphs': graphs,
        'labels': torch.tensor(labels, dtype=torch.long),
        'vuln_types': vuln_types
    }

class FusionTrainer:
    """Trainer for VulnHunter Fusion Model"""

    def __init__(
        self,
        model: VulnHunterFusion,
        device: str = 'cpu',
        learning_rate: float = 1e-4,
        weight_decay: float = 1e-5
    ):
        self.model = model.to(device)
        self.device = device

        # Setup optimizer
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )

        # Setup loss functions
        self.criterion = nn.CrossEntropyLoss()
        self.aux_criterion = nn.BCELoss()

        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': [],
            'train_f1': [],
            'val_f1': []
        }

    def train_epoch(self, dataloader: DataLoader) -> Dict[str, float]:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0.0
        predictions = []
        true_labels = []

        for batch_idx, batch in enumerate(dataloader):
            self.optimizer.zero_grad()

            # Move batch to device
            labels = batch['labels'].to(self.device)
            codes = batch['codes']

            # Forward pass for each sample in batch
            batch_loss = 0.0
            batch_predictions = []

            for i, code in enumerate(codes):
                try:
                    # Get model predictions
                    results = self.model(code)

                    # Main vulnerability prediction
                    vuln_pred = results['vulnerability_prediction'].unsqueeze(0)  # Add batch dim
                    sample_label = labels[i].unsqueeze(0)

                    # Primary loss
                    primary_loss = self.criterion(vuln_pred, sample_label)

                    # Auxiliary losses
                    aux_loss = 0.0

                    # Severity prediction loss
                    if 'severity_score' in results:
                        severity_target = float(sample_label.item())  # Convert to float
                        severity_pred = results['severity_score']
                        aux_loss += self.aux_criterion(severity_pred, torch.tensor([severity_target]).to(self.device))

                    # Confidence loss (encourage high confidence for correct predictions)
                    if 'confidence_score' in results:
                        confidence_target = 0.8 if sample_label.item() == torch.argmax(vuln_pred).item() else 0.3
                        confidence_pred = results['confidence_score']
                        aux_loss += self.aux_criterion(confidence_pred, torch.tensor([confidence_target]).to(self.device))

                    # Combined loss
                    total_sample_loss = primary_loss + 0.1 * aux_loss
                    batch_loss += total_sample_loss

                    # Store predictions
                    pred_class = torch.argmax(vuln_pred).item()
                    batch_predictions.append(pred_class)

                except Exception as e:
                    logger.warning(f"Error processing sample {i}: {e}")
                    # Use default prediction for failed samples
                    batch_predictions.append(0)
                    continue

            # Average loss over batch
            if len(codes) > 0:
                batch_loss = batch_loss / len(codes)

                # Backward pass
                batch_loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                self.optimizer.step()

                total_loss += batch_loss.item()

            # Store predictions and labels
            predictions.extend(batch_predictions)
            true_labels.extend(labels.cpu().numpy())

            if batch_idx % 10 == 0:
                logger.info(f"Batch {batch_idx}, Loss: {batch_loss.item():.4f}")

        # Calculate metrics
        avg_loss = total_loss / len(dataloader)
        accuracy = accuracy_score(true_labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            true_labels, predictions, average='binary', zero_division=0
        )

        return {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }

    def evaluate(self, dataloader: DataLoader) -> Dict[str, float]:
        """Evaluate model on validation/test set"""
        self.model.eval()
        total_loss = 0.0
        predictions = []
        true_labels = []
        prediction_probs = []

        with torch.no_grad():
            for batch in dataloader:
                labels = batch['labels'].to(self.device)
                codes = batch['codes']

                batch_loss = 0.0
                batch_predictions = []
                batch_probs = []

                for i, code in enumerate(codes):
                    try:
                        results = self.model(code)

                        vuln_pred = results['vulnerability_prediction'].unsqueeze(0)
                        sample_label = labels[i].unsqueeze(0)

                        loss = self.criterion(vuln_pred, sample_label)
                        batch_loss += loss.item()

                        pred_class = torch.argmax(vuln_pred).item()
                        pred_prob = torch.softmax(vuln_pred, dim=-1)[0, 1].item()  # Probability of vulnerable

                        batch_predictions.append(pred_class)
                        batch_probs.append(pred_prob)

                    except Exception as e:
                        logger.warning(f"Error evaluating sample {i}: {e}")
                        batch_predictions.append(0)
                        batch_probs.append(0.0)
                        continue

                total_loss += batch_loss / len(codes) if codes else 0
                predictions.extend(batch_predictions)
                prediction_probs.extend(batch_probs)
                true_labels.extend(labels.cpu().numpy())

        # Calculate metrics
        avg_loss = total_loss / len(dataloader)
        accuracy = accuracy_score(true_labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            true_labels, predictions, average='binary', zero_division=0
        )

        # Calculate AUC if we have both classes
        auc = 0.0
        try:
            if len(set(true_labels)) > 1:
                auc = roc_auc_score(true_labels, prediction_probs)
        except Exception as e:
            logger.warning(f"Could not calculate AUC: {e}")

        return {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'auc': auc
        }

    def train(
        self,
        train_dataloader: DataLoader,
        val_dataloader: DataLoader,
        num_epochs: int = 10,
        save_path: str = "models/fusion_model.pth"
    ):
        """Complete training loop"""
        logger.info(f"Starting training for {num_epochs} epochs")

        best_val_f1 = 0.0
        best_model_state = None

        for epoch in range(num_epochs):
            logger.info(f"\nEpoch {epoch + 1}/{num_epochs}")

            # Training
            train_metrics = self.train_epoch(train_dataloader)
            logger.info(f"Train - Loss: {train_metrics['loss']:.4f}, "
                       f"Acc: {train_metrics['accuracy']:.4f}, "
                       f"F1: {train_metrics['f1']:.4f}")

            # Validation
            val_metrics = self.evaluate(val_dataloader)
            logger.info(f"Val   - Loss: {val_metrics['loss']:.4f}, "
                       f"Acc: {val_metrics['accuracy']:.4f}, "
                       f"F1: {val_metrics['f1']:.4f}, "
                       f"AUC: {val_metrics['auc']:.4f}")

            # Save best model
            if val_metrics['f1'] > best_val_f1:
                best_val_f1 = val_metrics['f1']
                best_model_state = self.model.state_dict().copy()
                logger.info(f"New best model! F1: {best_val_f1:.4f}")

            # Update history
            self.history['train_loss'].append(train_metrics['loss'])
            self.history['val_loss'].append(val_metrics['loss'])
            self.history['train_acc'].append(train_metrics['accuracy'])
            self.history['val_acc'].append(val_metrics['accuracy'])
            self.history['train_f1'].append(train_metrics['f1'])
            self.history['val_f1'].append(val_metrics['f1'])

        # Save best model
        if best_model_state:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            torch.save(best_model_state, save_path)
            logger.info(f"Best model saved to {save_path}")

        return self.history

def main():
    """Main training function"""
    logger.info("VulnHunter Fusion Model Training")

    # Configuration
    config = {
        'data_path': 'vulnhunter_pro/training_data/enhanced_real_world_dataset.json',
        'batch_size': 4,  # Small batch size for memory efficiency
        'num_epochs': 20,
        'learning_rate': 1e-4,
        'test_split': 0.2,
        'val_split': 0.1,
        'max_samples': 1000,  # Limit for PoC
        'device': 'cuda' if torch.cuda.is_available() else 'cpu'
    }

    logger.info(f"Configuration: {config}")

    # Create dataset
    try:
        dataset = VulnerabilityDataset(config['data_path'], max_samples=config['max_samples'])
    except FileNotFoundError:
        logger.error("Dataset not found. Creating synthetic dataset for demo...")
        create_demo_dataset(config['data_path'])
        dataset = VulnerabilityDataset(config['data_path'], max_samples=config['max_samples'])

    if len(dataset) == 0:
        logger.error("No valid samples in dataset")
        return

    # Split dataset
    indices = list(range(len(dataset)))
    train_indices, test_indices = train_test_split(
        indices, test_size=config['test_split'], random_state=42,
        stratify=[dataset[i]['label'] for i in indices]
    )

    train_indices, val_indices = train_test_split(
        train_indices, test_size=config['val_split'], random_state=42,
        stratify=[dataset[i]['label'] for i in train_indices]
    )

    # Create dataloaders
    train_dataset = torch.utils.data.Subset(dataset, train_indices)
    val_dataset = torch.utils.data.Subset(dataset, val_indices)
    test_dataset = torch.utils.data.Subset(dataset, test_indices)

    train_dataloader = DataLoader(
        train_dataset,
        batch_size=config['batch_size'],
        shuffle=True,
        collate_fn=collate_fn
    )
    val_dataloader = DataLoader(
        val_dataset,
        batch_size=config['batch_size'],
        shuffle=False,
        collate_fn=collate_fn
    )
    test_dataloader = DataLoader(
        test_dataset,
        batch_size=config['batch_size'],
        shuffle=False,
        collate_fn=collate_fn
    )

    logger.info(f"Data splits - Train: {len(train_dataset)}, "
               f"Val: {len(val_dataset)}, Test: {len(test_dataset)}")

    # Create model
    model = VulnHunterFusion()
    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

    # Create trainer
    trainer = FusionTrainer(
        model=model,
        device=config['device'],
        learning_rate=config['learning_rate']
    )

    # Train model
    history = trainer.train(
        train_dataloader=train_dataloader,
        val_dataloader=val_dataloader,
        num_epochs=config['num_epochs'],
        save_path="models/fusion_model_best.pth"
    )

    # Final evaluation
    logger.info("\nFinal evaluation on test set:")
    test_metrics = trainer.evaluate(test_dataloader)
    logger.info(f"Test - Acc: {test_metrics['accuracy']:.4f}, "
               f"F1: {test_metrics['f1']:.4f}, "
               f"AUC: {test_metrics['auc']:.4f}")

    # Save training history
    with open("models/fusion_training_history.json", 'w') as f:
        json.dump(history, f, indent=2)

    logger.info("Training completed successfully!")

def create_demo_dataset(output_path: str):
    """Create a synthetic dataset for demonstration"""
    logger.info("Creating synthetic demo dataset")

    demo_data = []

    # Vulnerable SQL injection examples
    vulnerable_sql = [
        "query = 'SELECT * FROM users WHERE id = ' + user_id\ncursor.execute(query)",
        "sql = f'DELETE FROM posts WHERE id = {post_id}'\ndb.execute(sql)",
        "cmd = 'SELECT * FROM accounts WHERE username = \"' + username + '\"'\nresult = db.query(cmd)"
    ]

    # Safe SQL examples
    safe_sql = [
        "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))",
        "sql = 'DELETE FROM posts WHERE id = %s'\ndb.execute(sql, (post_id,))",
        "cmd = 'SELECT * FROM accounts WHERE username = %s'\nresult = db.query(cmd, (username,))"
    ]

    # Vulnerable command injection examples
    vulnerable_cmd = [
        "os.system('convert ' + filename + ' output.pdf')",
        "subprocess.call('ping ' + hostname, shell=True)",
        "command = 'tar -czf backup.tar.gz ' + files\nos.system(command)"
    ]

    # Safe command examples
    safe_cmd = [
        "subprocess.run(['convert', filename, 'output.pdf'])",
        "subprocess.run(['ping', hostname])",
        "subprocess.run(['tar', '-czf', 'backup.tar.gz'] + files)"
    ]

    # Create samples
    sample_id = 0

    for code in vulnerable_sql:
        demo_data.append({
            'id': sample_id,
            'code': code,
            'vulnerable': 1,
            'vulnerability_type': 'sql_injection',
            'source': 'synthetic',
            'language': 'python'
        })
        sample_id += 1

    for code in safe_sql:
        demo_data.append({
            'id': sample_id,
            'code': code,
            'vulnerable': 0,
            'vulnerability_type': 'none',
            'source': 'synthetic',
            'language': 'python'
        })
        sample_id += 1

    for code in vulnerable_cmd:
        demo_data.append({
            'id': sample_id,
            'code': code,
            'vulnerable': 1,
            'vulnerability_type': 'command_injection',
            'source': 'synthetic',
            'language': 'python'
        })
        sample_id += 1

    for code in safe_cmd:
        demo_data.append({
            'id': sample_id,
            'code': code,
            'vulnerable': 0,
            'vulnerability_type': 'none',
            'source': 'synthetic',
            'language': 'python'
        })
        sample_id += 1

    # Save dataset
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(demo_data, f, indent=2)

    logger.info(f"Created demo dataset with {len(demo_data)} samples at {output_path}")

if __name__ == "__main__":
    main()