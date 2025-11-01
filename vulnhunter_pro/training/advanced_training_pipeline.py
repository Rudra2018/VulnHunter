#!/usr/bin/env python3
"""
Advanced ML Training Pipeline for VulnHunter Professional
========================================================

Trains multiple models on comprehensive vulnerability dataset with mathematical validation.
Implements transformer, GNN, and ensemble models for maximum accuracy.
"""

import os
import sys
import json
import random
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import numpy as np
from dataclasses import dataclass

# ML Libraries
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import Dataset, DataLoader
    from transformers import AutoTokenizer, AutoModel
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
    import pickle
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

logger = logging.getLogger(__name__)

@dataclass
class TrainingConfig:
    """Training configuration"""
    batch_size: int = 32
    learning_rate: float = 1e-4
    epochs: int = 10
    validation_split: float = 0.2
    test_split: float = 0.1
    max_sequence_length: int = 512
    dropout_rate: float = 0.1
    model_save_path: str = "models/"

if TORCH_AVAILABLE:
    class VulnDataset(Dataset):
        """PyTorch dataset for vulnerability data"""

        def __init__(self, examples: List[Dict[str, Any]], tokenizer=None, max_length: int = 512):
            self.examples = examples
            self.tokenizer = tokenizer
            self.max_length = max_length

            # Create label mapping
            self.label_to_id = self._create_label_mapping()
            self.id_to_label = {v: k for k, v in self.label_to_id.items()}

        def _create_label_mapping(self) -> Dict[str, int]:
            """Create mapping from vulnerability types to integers"""
            unique_labels = set()
            for example in self.examples:
                if example['is_vulnerable']:
                    unique_labels.add(example['vulnerability_type'])
                else:
                    unique_labels.add('safe')

            return {label: idx for idx, label in enumerate(sorted(unique_labels))}

        def __len__(self):
            return len(self.examples)

        def __getitem__(self, idx):
            example = self.examples[idx]
            code = example['code']

            # Determine label
            if example['is_vulnerable']:
                label = self.label_to_id[example['vulnerability_type']]
            else:
                label = self.label_to_id['safe']

            if self.tokenizer:
                # Tokenize code
                encoded = self.tokenizer(
                    code,
                    truncation=True,
                    padding='max_length',
                    max_length=self.max_length,
                    return_tensors='pt'
                )

                return {
                    'input_ids': encoded['input_ids'].squeeze(),
                    'attention_mask': encoded['attention_mask'].squeeze(),
                    'labels': torch.tensor(label, dtype=torch.long),
                    'code': code,
                    'vulnerability_type': example['vulnerability_type'],
                    'severity': example.get('severity', 'none')
                }
            else:
                return {
                    'code': code,
                    'labels': label,
                    'vulnerability_type': example['vulnerability_type'],
                    'severity': example.get('severity', 'none')
                }

    class TransformerVulnDetector(nn.Module):
        """Transformer-based vulnerability detector"""

        def __init__(self, num_classes: int, model_name: str = "microsoft/codebert-base", dropout_rate: float = 0.1):
        super().__init__()
        self.num_classes = num_classes
        self.model_name = model_name

        if TORCH_AVAILABLE:
            try:
                self.backbone = AutoModel.from_pretrained(model_name)
                self.hidden_size = self.backbone.config.hidden_size
            except Exception:
                # Fallback to simple embedding
                self.backbone = nn.Embedding(50000, 768)
                self.hidden_size = 768

            self.dropout = nn.Dropout(dropout_rate)
            self.classifier = nn.Linear(self.hidden_size, num_classes)
            self.vulnerability_classifier = nn.Linear(self.hidden_size, 2)  # Binary: vuln or safe

    def forward(self, input_ids, attention_mask=None):
        if hasattr(self.backbone, 'config'):
            # Real transformer model
            outputs = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
            pooled_output = outputs.last_hidden_state.mean(dim=1)  # Mean pooling
        else:
            # Simple embedding fallback
            pooled_output = self.backbone(input_ids).mean(dim=1)

        pooled_output = self.dropout(pooled_output)

        # Multi-task outputs
        vuln_logits = self.vulnerability_classifier(pooled_output)  # Binary classification
        type_logits = self.classifier(pooled_output)  # Multi-class classification

        return {
            'vulnerability_logits': vuln_logits,
            'type_logits': type_logits,
            'features': pooled_output
        }

class MathematicalVulnAnalyzer(nn.Module):
    """Neural network with mathematical feature integration"""

    def __init__(self, code_features: int, math_features: int, num_classes: int):
        super().__init__()

        self.code_encoder = nn.Sequential(
            nn.Linear(code_features, 512),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(512, 256)
        )

        self.math_encoder = nn.Sequential(
            nn.Linear(math_features, 128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64)
        )

        self.fusion_layer = nn.Sequential(
            nn.Linear(256 + 64, 512),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Linear(256, num_classes)
        )

    def forward(self, code_features, math_features):
        code_encoded = self.code_encoder(code_features)
        math_encoded = self.math_encoder(math_features)

        # Fusion
        fused = torch.cat([code_encoded, math_encoded], dim=1)
        output = self.fusion_layer(fused)

        return output

class AdvancedTrainingPipeline:
    """Advanced training pipeline for vulnerability detection"""

    def __init__(self, config: TrainingConfig):
        self.config = config
        self.models = {}
        self.tokenizer = None
        self.label_mappings = {}

        # Initialize tokenizer if available
        if TORCH_AVAILABLE:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
            except Exception:
                logger.warning("Failed to load CodeBERT tokenizer, using basic tokenization")

    def load_dataset(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Load vulnerability dataset"""
        with open(dataset_path, 'r') as f:
            dataset = json.load(f)

        logger.info(f"Loaded {len(dataset)} examples from {dataset_path}")
        return dataset

    def preprocess_dataset(self, dataset: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Preprocess and split dataset"""

        # Shuffle dataset
        random.shuffle(dataset)

        # Split dataset
        train_size = int(len(dataset) * (1 - self.config.validation_split - self.config.test_split))
        val_size = int(len(dataset) * self.config.validation_split)

        train_data = dataset[:train_size]
        val_data = dataset[train_size:train_size + val_size]
        test_data = dataset[train_size + val_size:]

        logger.info(f"Dataset split - Train: {len(train_data)}, Val: {len(val_data)}, Test: {len(test_data)}")

        return train_data, val_data, test_data

    def train_transformer_model(self, train_data: List[Dict[str, Any]], val_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train transformer-based model"""

        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available, skipping transformer training")
            return {'success': False, 'reason': 'PyTorch not available'}

        try:
            # Create datasets
            train_dataset = VulnDataset(train_data, self.tokenizer, self.config.max_sequence_length)
            val_dataset = VulnDataset(val_data, self.tokenizer, self.config.max_sequence_length)

            # Create data loaders
            train_loader = DataLoader(train_dataset, batch_size=self.config.batch_size, shuffle=True)
            val_loader = DataLoader(val_dataset, batch_size=self.config.batch_size, shuffle=False)

            # Initialize model
            num_classes = len(train_dataset.label_to_id)
            model = TransformerVulnDetector(num_classes, dropout_rate=self.config.dropout_rate)

            # Training setup
            optimizer = optim.AdamW(model.parameters(), lr=self.config.learning_rate)
            criterion = nn.CrossEntropyLoss()

            # Training loop
            model.train()
            best_val_acc = 0.0

            for epoch in range(self.config.epochs):
                total_loss = 0.0
                correct_predictions = 0
                total_predictions = 0

                for batch in train_loader:
                    optimizer.zero_grad()

                    input_ids = batch['input_ids']
                    attention_mask = batch['attention_mask']
                    labels = batch['labels']

                    outputs = model(input_ids, attention_mask)

                    # Multi-task loss
                    vuln_loss = criterion(outputs['vulnerability_logits'], (labels > 0).long())
                    type_loss = criterion(outputs['type_logits'], labels)
                    loss = vuln_loss + type_loss

                    loss.backward()
                    optimizer.step()

                    total_loss += loss.item()

                    # Calculate accuracy
                    predictions = torch.argmax(outputs['type_logits'], dim=1)
                    correct_predictions += (predictions == labels).sum().item()
                    total_predictions += labels.size(0)

                # Validation
                val_acc = self._evaluate_model(model, val_loader)

                train_acc = correct_predictions / total_predictions
                avg_loss = total_loss / len(train_loader)

                logger.info(f"Epoch {epoch+1}/{self.config.epochs}: "
                          f"Train Loss: {avg_loss:.4f}, Train Acc: {train_acc:.4f}, Val Acc: {val_acc:.4f}")

                # Save best model
                if val_acc > best_val_acc:
                    best_val_acc = val_acc
                    self._save_model(model, 'transformer_best', train_dataset.label_to_id)

            return {
                'success': True,
                'best_val_accuracy': best_val_acc,
                'model_type': 'transformer',
                'num_classes': num_classes,
                'label_mapping': train_dataset.label_to_id
            }

        except Exception as e:
            logger.error(f"Transformer training failed: {e}")
            return {'success': False, 'reason': str(e)}

    def train_sklearn_models(self, train_data: List[Dict[str, Any]], val_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train scikit-learn models"""

        if not SKLEARN_AVAILABLE:
            logger.warning("Scikit-learn not available, skipping sklearn training")
            return {'success': False, 'reason': 'Scikit-learn not available'}

        try:
            # Prepare data
            train_texts = [example['code'] for example in train_data]
            train_labels = []

            for example in train_data:
                if example['is_vulnerable']:
                    train_labels.append(example['vulnerability_type'])
                else:
                    train_labels.append('safe')

            val_texts = [example['code'] for example in val_data]
            val_labels = []

            for example in val_data:
                if example['is_vulnerable']:
                    val_labels.append(example['vulnerability_type'])
                else:
                    val_labels.append('safe')

            # Vectorize text
            vectorizer = TfidfVectorizer(
                max_features=10000,
                ngram_range=(1, 3),
                stop_words='english',
                lowercase=True
            )

            X_train = vectorizer.fit_transform(train_texts)
            X_val = vectorizer.transform(val_texts)

            # Train multiple models
            models = {
                'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
                'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42)
            }

            results = {}

            for model_name, model in models.items():
                logger.info(f"Training {model_name}...")

                # Train model
                model.fit(X_train, train_labels)

                # Evaluate
                train_pred = model.predict(X_train)
                val_pred = model.predict(X_val)

                train_acc = accuracy_score(train_labels, train_pred)
                val_acc = accuracy_score(val_labels, val_pred)

                # Save model
                self._save_sklearn_model(model, vectorizer, model_name, train_labels)

                results[model_name] = {
                    'train_accuracy': train_acc,
                    'val_accuracy': val_acc,
                    'model_type': 'sklearn'
                }

                logger.info(f"{model_name} - Train Acc: {train_acc:.4f}, Val Acc: {val_acc:.4f}")

            return {
                'success': True,
                'models': results,
                'vectorizer_features': X_train.shape[1]
            }

        except Exception as e:
            logger.error(f"Sklearn training failed: {e}")
            return {'success': False, 'reason': str(e)}

    def train_mathematical_model(self, train_data: List[Dict[str, Any]], val_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train model with mathematical features"""

        if not TORCH_AVAILABLE:
            return {'success': False, 'reason': 'PyTorch not available'}

        try:
            # Extract mathematical features
            train_features = self._extract_mathematical_features(train_data)
            val_features = self._extract_mathematical_features(val_data)

            # Convert to tensors
            train_code_features = torch.tensor(train_features['code_features'], dtype=torch.float32)
            train_math_features = torch.tensor(train_features['math_features'], dtype=torch.float32)
            train_labels = torch.tensor(train_features['labels'], dtype=torch.long)

            val_code_features = torch.tensor(val_features['code_features'], dtype=torch.float32)
            val_math_features = torch.tensor(val_features['math_features'], dtype=torch.float32)
            val_labels = torch.tensor(val_features['labels'], dtype=torch.long)

            # Initialize model
            code_dim = train_code_features.shape[1]
            math_dim = train_math_features.shape[1]
            num_classes = len(set(train_features['labels']))

            model = MathematicalVulnAnalyzer(code_dim, math_dim, num_classes)

            # Training setup
            optimizer = optim.Adam(model.parameters(), lr=self.config.learning_rate)
            criterion = nn.CrossEntropyLoss()

            # Training loop
            best_val_acc = 0.0

            for epoch in range(self.config.epochs):
                model.train()
                optimizer.zero_grad()

                outputs = model(train_code_features, train_math_features)
                loss = criterion(outputs, train_labels)

                loss.backward()
                optimizer.step()

                # Validation
                model.eval()
                with torch.no_grad():
                    val_outputs = model(val_code_features, val_math_features)
                    val_predictions = torch.argmax(val_outputs, dim=1)
                    val_acc = (val_predictions == val_labels).float().mean().item()

                if val_acc > best_val_acc:
                    best_val_acc = val_acc
                    self._save_model(model, 'mathematical_best', train_features['label_mapping'])

                logger.info(f"Math Model Epoch {epoch+1}: Loss: {loss.item():.4f}, Val Acc: {val_acc:.4f}")

            return {
                'success': True,
                'best_val_accuracy': best_val_acc,
                'model_type': 'mathematical',
                'code_features': code_dim,
                'math_features': math_dim
            }

        except Exception as e:
            logger.error(f"Mathematical model training failed: {e}")
            return {'success': False, 'reason': str(e)}

    def _extract_mathematical_features(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract mathematical features from code"""

        code_features = []
        math_features = []
        labels = []
        label_mapping = {}
        label_counter = 0

        for example in data:
            code = example['code']

            # Basic code features
            code_feat = [
                len(code),  # Length
                code.count('\n'),  # Lines
                code.count('if'),  # Conditionals
                code.count('for'),  # Loops
                code.count('while'),  # While loops
                code.count('='),  # Assignments
                code.count('('),  # Function calls
                code.count('+'),  # String concatenations
            ]

            # Mathematical/topological features
            math_feat = []
            if 'topology_features' in example and example['topology_features']:
                topo = example['topology_features']
                math_feat = [
                    topo.get('max_indentation_depth', 0),
                    topo.get('avg_indentation_depth', 0),
                    topo.get('total_lines', 0),
                    topo.get('complexity_estimate', 0)
                ]
            else:
                # Fallback mathematical features
                math_feat = [
                    len(code.split('\n')),  # Line count
                    max(len(line) - len(line.lstrip()) for line in code.split('\n') if line.strip()),  # Max indent
                    code.count('{') + code.count('('),  # Complexity
                    len([word for word in code.split() if word in ['if', 'else', 'while', 'for']])  # Control flow
                ]

            # Pad features to consistent length
            code_feat += [0] * (10 - len(code_feat))  # Pad to 10 features
            math_feat += [0] * (5 - len(math_feat))   # Pad to 5 features

            code_features.append(code_feat[:10])
            math_features.append(math_feat[:5])

            # Label encoding
            if example['is_vulnerable']:
                label_key = example['vulnerability_type']
            else:
                label_key = 'safe'

            if label_key not in label_mapping:
                label_mapping[label_key] = label_counter
                label_counter += 1

            labels.append(label_mapping[label_key])

        return {
            'code_features': code_features,
            'math_features': math_features,
            'labels': labels,
            'label_mapping': label_mapping
        }

    def _evaluate_model(self, model, data_loader) -> float:
        """Evaluate PyTorch model"""
        model.eval()
        correct = 0
        total = 0

        with torch.no_grad():
            for batch in data_loader:
                input_ids = batch['input_ids']
                attention_mask = batch['attention_mask']
                labels = batch['labels']

                outputs = model(input_ids, attention_mask)
                predictions = torch.argmax(outputs['type_logits'], dim=1)

                correct += (predictions == labels).sum().item()
                total += labels.size(0)

        return correct / total

    def _save_model(self, model, model_name: str, label_mapping: Dict[str, int]):
        """Save PyTorch model"""
        save_dir = Path(self.config.model_save_path)
        save_dir.mkdir(exist_ok=True)

        # Save model state
        torch.save({
            'model_state_dict': model.state_dict(),
            'model_config': {
                'num_classes': len(label_mapping),
                'label_mapping': label_mapping
            }
        }, save_dir / f"{model_name}.pth")

        # Save label mapping separately
        with open(save_dir / f"{model_name}_labels.json", 'w') as f:
            json.dump(label_mapping, f, indent=2)

        logger.info(f"Saved model: {model_name}")

    def _save_sklearn_model(self, model, vectorizer, model_name: str, labels: List[str]):
        """Save sklearn model"""
        save_dir = Path(self.config.model_save_path)
        save_dir.mkdir(exist_ok=True)

        # Save model and vectorizer
        with open(save_dir / f"{model_name}_sklearn.pkl", 'wb') as f:
            pickle.dump({
                'model': model,
                'vectorizer': vectorizer,
                'labels': list(set(labels))
            }, f)

        logger.info(f"Saved sklearn model: {model_name}")

    def train_all_models(self, dataset_path: str) -> Dict[str, Any]:
        """Train all models on the dataset"""

        # Load dataset
        dataset = self.load_dataset(dataset_path)

        # Preprocess
        train_data, val_data, test_data = self.preprocess_dataset(dataset)

        results = {
            'dataset_info': {
                'total_examples': len(dataset),
                'train_size': len(train_data),
                'val_size': len(val_data),
                'test_size': len(test_data)
            },
            'training_results': {}
        }

        # Train transformer model
        logger.info("Training transformer model...")
        transformer_results = self.train_transformer_model(train_data, val_data)
        results['training_results']['transformer'] = transformer_results

        # Train sklearn models
        logger.info("Training sklearn models...")
        sklearn_results = self.train_sklearn_models(train_data, val_data)
        results['training_results']['sklearn'] = sklearn_results

        # Train mathematical model
        logger.info("Training mathematical model...")
        math_results = self.train_mathematical_model(train_data, val_data)
        results['training_results']['mathematical'] = math_results

        return results

def main():
    """Main training pipeline"""

    # Configuration
    config = TrainingConfig(
        batch_size=16,  # Reduced for memory
        learning_rate=2e-5,
        epochs=5,  # Reduced for faster training
        validation_split=0.2,
        test_split=0.1
    )

    # Initialize pipeline
    pipeline = AdvancedTrainingPipeline(config)

    # Train all models
    dataset_path = Path(__file__).parent / "training_data" / "comprehensive_vulnerability_dataset.json"

    if not dataset_path.exists():
        print(f"❌ Dataset not found at {dataset_path}")
        print("Please run comprehensive_vuln_dataset.py first")
        return

    print("🚀 Starting advanced training pipeline...")
    results = pipeline.train_all_models(str(dataset_path))

    # Print results
    print("\n" + "="*80)
    print("🎯 TRAINING RESULTS SUMMARY")
    print("="*80)

    for model_type, result in results['training_results'].items():
        if result['success']:
            print(f"✅ {model_type.upper()} training successful")
            if 'best_val_accuracy' in result:
                print(f"   Best validation accuracy: {result['best_val_accuracy']:.4f}")
            elif 'models' in result:
                for submodel, metrics in result['models'].items():
                    print(f"   {submodel} validation accuracy: {metrics['val_accuracy']:.4f}")
        else:
            print(f"❌ {model_type.upper()} training failed: {result['reason']}")

    print(f"\n📊 Dataset: {results['dataset_info']['total_examples']} total examples")
    print(f"🎯 Models saved to: {config.model_save_path}")

if __name__ == "__main__":
    main()