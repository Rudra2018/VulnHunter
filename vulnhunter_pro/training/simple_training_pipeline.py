#!/usr/bin/env python3
"""
Simple ML Training Pipeline for VulnHunter Professional
=======================================================

Trains sklearn models on comprehensive vulnerability dataset.
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import numpy as np
from dataclasses import dataclass

# ML Libraries
try:
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
    import pickle
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

logger = logging.getLogger(__name__)

@dataclass
class TrainingConfig:
    """Training configuration"""
    validation_split: float = 0.2
    test_split: float = 0.1
    model_save_path: str = "models/"
    max_features: int = 10000

class SimpleTrainingPipeline:
    """Simple training pipeline for vulnerability detection"""

    def __init__(self, config: TrainingConfig):
        self.config = config
        self.models = {}
        self.vectorizer = None
        self.label_mapping = {}

        # Ensure model directory exists
        os.makedirs(self.config.model_save_path, exist_ok=True)

    def load_dataset(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Load the comprehensive vulnerability dataset"""
        try:
            with open(dataset_path, 'r') as f:
                data = json.load(f)

            print(f"Loaded {len(data)} examples from dataset")
            return data
        except Exception as e:
            print(f"Error loading dataset: {e}")
            return []

    def prepare_features(self, examples: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Extract features and labels from examples"""
        codes = []
        labels = []
        label_names = []

        for example in examples:
            codes.append(example['code'])

            if example['is_vulnerable']:
                labels.append(1)  # Vulnerable
                label_names.append(example['vulnerability_type'])
            else:
                labels.append(0)  # Safe
                label_names.append('safe')

        # Create TF-IDF features
        if self.vectorizer is None:
            self.vectorizer = TfidfVectorizer(
                max_features=self.config.max_features,
                stop_words='english',
                ngram_range=(1, 3),
                lowercase=True
            )
            features = self.vectorizer.fit_transform(codes)
        else:
            features = self.vectorizer.transform(codes)

        return features.toarray(), np.array(labels), label_names

    def train_models(self, X: np.ndarray, y: np.ndarray, label_names: List[str]):
        """Train multiple models"""
        print(f"Training on {len(X)} examples with {X.shape[1]} features")

        # Split the data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=self.config.validation_split + self.config.test_split,
            random_state=42, stratify=y
        )

        val_size = self.config.validation_split / (self.config.validation_split + self.config.test_split)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=1-val_size, random_state=42, stratify=y_temp
        )

        print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

        # Train Random Forest
        print("Training Random Forest...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train, y_train)
        self.models['random_forest'] = rf_model

        # Train Gradient Boosting
        print("Training Gradient Boosting...")
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        gb_model.fit(X_train, y_train)
        self.models['gradient_boosting'] = gb_model

        # Evaluate models
        results = {}
        for name, model in self.models.items():
            print(f"\nEvaluating {name}...")

            # Validation predictions
            val_pred = model.predict(X_val)
            val_acc = accuracy_score(y_val, val_pred)
            val_prec, val_rec, val_f1, _ = precision_recall_fscore_support(y_val, val_pred, average='weighted')

            # Test predictions
            test_pred = model.predict(X_test)
            test_acc = accuracy_score(y_test, test_pred)
            test_prec, test_rec, test_f1, _ = precision_recall_fscore_support(y_test, test_pred, average='weighted')

            results[name] = {
                'validation': {
                    'accuracy': val_acc,
                    'precision': val_prec,
                    'recall': val_rec,
                    'f1': val_f1
                },
                'test': {
                    'accuracy': test_acc,
                    'precision': test_prec,
                    'recall': test_rec,
                    'f1': test_f1
                }
            }

            print(f"  Validation - Acc: {val_acc:.3f}, F1: {val_f1:.3f}")
            print(f"  Test - Acc: {test_acc:.3f}, F1: {test_f1:.3f}")

        return results

    def save_models(self):
        """Save trained models"""
        for name, model in self.models.items():
            model_path = os.path.join(self.config.model_save_path, f"{name}_model.pkl")
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            print(f"Saved {name} model to {model_path}")

        # Save vectorizer
        if self.vectorizer:
            vectorizer_path = os.path.join(self.config.model_save_path, "vectorizer.pkl")
            with open(vectorizer_path, 'wb') as f:
                pickle.dump(self.vectorizer, f)
            print(f"Saved vectorizer to {vectorizer_path}")

    def run_full_training(self, dataset_path: str) -> Dict[str, Any]:
        """Run the complete training pipeline"""
        print("=== VulnHunter Pro Training Pipeline ===")

        # Load dataset
        examples = self.load_dataset(dataset_path)
        if not examples:
            print("No data loaded. Exiting.")
            return {}

        # Prepare features
        print("Extracting features...")
        X, y, label_names = self.prepare_features(examples)

        # Train models
        results = self.train_models(X, y, label_names)

        # Save models
        self.save_models()

        # Save results
        results_path = os.path.join(self.config.model_save_path, "training_results.json")
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Saved training results to {results_path}")

        print("\n=== Training Complete ===")
        return results

def main():
    """Main training function"""
    # Setup logging
    logging.basicConfig(level=logging.INFO)

    if not SKLEARN_AVAILABLE:
        print("scikit-learn not available. Please install: pip install scikit-learn")
        return

    # Configuration
    config = TrainingConfig()

    # Find dataset
    dataset_path = "vulnhunter_pro/training_data/comprehensive_vulnerability_dataset.json"
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        print("Please run the dataset generator first.")
        return

    # Run training
    pipeline = SimpleTrainingPipeline(config)
    results = pipeline.run_full_training(dataset_path)

    if results:
        print("\nTraining Results Summary:")
        for model_name, metrics in results.items():
            test_acc = metrics['test']['accuracy']
            test_f1 = metrics['test']['f1']
            print(f"{model_name}: Test Accuracy={test_acc:.3f}, Test F1={test_f1:.3f}")

if __name__ == "__main__":
    main()