#!/usr/bin/env python3
"""
Simple Real-World Training Pipeline for VulnHunter Professional
===============================================================

Trains ML models on combined synthetic + real-world vulnerability datasets.
Uses a simplified but robust approach for multi-language analysis.
"""

import os
import sys
import json
import logging
import re
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import numpy as np
from dataclasses import dataclass
import time

# ML Libraries
try:
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
    from sklearn.preprocessing import LabelEncoder
    import pickle
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

logger = logging.getLogger(__name__)

@dataclass
class SimpleTrainingConfig:
    """Simple training configuration for real-world data"""
    validation_split: float = 0.2
    test_split: float = 0.1
    model_save_path: str = "models/real_world/"
    max_features: int = 20000
    min_df: int = 2
    max_df: float = 0.95

class SimpleRealWorldTrainer:
    """Simple training pipeline for real-world vulnerability data"""

    def __init__(self, config: SimpleTrainingConfig):
        self.config = config
        self.models = {}
        self.vectorizer = None
        self.label_encoder = None

        # Ensure model directory exists
        os.makedirs(self.config.model_save_path, exist_ok=True)

    def load_enhanced_dataset(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Load the enhanced real-world dataset"""
        try:
            with open(dataset_path, 'r') as f:
                data = json.load(f)

            print(f"Loaded {len(data)} examples from enhanced dataset")
            return data
        except Exception as e:
            print(f"Error loading dataset: {e}")
            return []

    def preprocess_code(self, code: str, language: str) -> str:
        """Simple language-agnostic code preprocessing"""
        # Remove common comment patterns
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)  # Single-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # Multi-line comments
        code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)  # Python comments
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)  # Python docstrings
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)  # Python docstrings

        # Normalize whitespace
        code = re.sub(r'\s+', ' ', code)

        # Add language tag to help model distinguish languages
        code = f"LANG_{language.upper()} " + code

        return code.strip()

    def prepare_features(self, examples: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Extract features from multi-language examples"""
        print("Extracting features from multi-language dataset...")

        codes = []
        binary_labels = []
        vulnerability_types = []

        # Language distribution
        lang_counts = {}
        for example in examples:
            lang = example.get('language', 'unknown')
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        print(f"Language distribution: {lang_counts}")

        for example in examples:
            # Preprocess code
            code = self.preprocess_code(example['code'], example.get('language', 'unknown'))
            codes.append(code)

            # Binary labels (vulnerable vs safe)
            binary_labels.append(1 if example['is_vulnerable'] else 0)

            # Vulnerability types
            if example['is_vulnerable']:
                vulnerability_types.append(example['vulnerability_type'])
            else:
                vulnerability_types.append('safe')

        # Create global vectorizer
        print("Creating TF-IDF features...")
        if self.vectorizer is None:
            self.vectorizer = TfidfVectorizer(
                max_features=self.config.max_features,
                min_df=self.config.min_df,
                max_df=self.config.max_df,
                ngram_range=(1, 3),
                lowercase=True,
                token_pattern=r'\b\w+\b'
            )
            features = self.vectorizer.fit_transform(codes)
        else:
            features = self.vectorizer.transform(codes)

        print(f"Feature matrix shape: {features.shape}")
        print(f"Unique vulnerability types: {len(set(vulnerability_types))}")

        return features.toarray(), np.array(binary_labels), vulnerability_types

    def train_models(self, X: np.ndarray, y: np.ndarray, vuln_types: List[str]):
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

        # Calculate dataset composition
        train_vuln = np.sum(y_train)
        val_vuln = np.sum(y_val)
        test_vuln = np.sum(y_test)

        print(f"Vulnerable examples - Train: {train_vuln}/{len(y_train)} ({train_vuln/len(y_train)*100:.1f}%)")
        print(f"Vulnerable examples - Val: {val_vuln}/{len(y_val)} ({val_vuln/len(y_val)*100:.1f}%)")
        print(f"Vulnerable examples - Test: {test_vuln}/{len(y_test)} ({test_vuln/len(y_test)*100:.1f}%)")

        # Train Random Forest
        print("\nTraining Random Forest...")
        start_time = time.time()
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=25,
            min_samples_split=3,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        rf_model.fit(X_train, y_train)
        rf_training_time = time.time() - start_time
        self.models['random_forest_real_world'] = rf_model

        # Train Gradient Boosting
        print("Training Gradient Boosting...")
        start_time = time.time()
        gb_model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=8,
            random_state=42,
            subsample=0.8
        )
        gb_model.fit(X_train, y_train)
        gb_training_time = time.time() - start_time
        self.models['gradient_boosting_real_world'] = gb_model

        # Evaluate models
        results = {}
        for name, model in self.models.items():
            print(f"\nEvaluating {name}...")

            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5)

            # Validation predictions
            val_pred = model.predict(X_val)
            val_proba = model.predict_proba(X_val)[:, 1]
            val_acc = accuracy_score(y_val, val_pred)
            val_prec, val_rec, val_f1, _ = precision_recall_fscore_support(y_val, val_pred, average='weighted')

            # Test predictions
            test_pred = model.predict(X_test)
            test_proba = model.predict_proba(X_test)[:, 1]
            test_acc = accuracy_score(y_test, test_pred)
            test_prec, test_rec, test_f1, _ = precision_recall_fscore_support(y_test, test_pred, average='weighted')

            # Feature importance (for tree-based models)
            feature_importance = None
            if hasattr(model, 'feature_importances_'):
                # Get top 20 features
                feature_names = self.vectorizer.get_feature_names_out()
                importance_indices = np.argsort(model.feature_importances_)[-20:][::-1]
                feature_importance = [(feature_names[i], model.feature_importances_[i])
                                    for i in importance_indices]

            training_time = rf_training_time if 'random_forest' in name else gb_training_time

            results[name] = {
                'training_time': training_time,
                'cross_validation': {
                    'mean_score': cv_scores.mean(),
                    'std_score': cv_scores.std(),
                    'scores': cv_scores.tolist()
                },
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
                },
                'feature_importance': feature_importance
            }

            print(f"  CV Score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
            print(f"  Validation - Acc: {val_acc:.3f}, F1: {val_f1:.3f}")
            print(f"  Test - Acc: {test_acc:.3f}, F1: {test_f1:.3f}")
            print(f"  Training time: {training_time:.2f}s")

            if feature_importance:
                print(f"  Top 5 features: {[f[0] for f in feature_importance[:5]]}")

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
            vectorizer_path = os.path.join(self.config.model_save_path, "real_world_vectorizer.pkl")
            with open(vectorizer_path, 'wb') as f:
                pickle.dump(self.vectorizer, f)
            print(f"Saved vectorizer to {vectorizer_path}")

    def run_training(self, dataset_path: str) -> Dict[str, Any]:
        """Run the complete training pipeline"""
        print("=== VulnHunter Pro Real-World Training Pipeline ===")

        # Load dataset
        examples = self.load_enhanced_dataset(dataset_path)
        if not examples:
            print("No data loaded. Exiting.")
            return {}

        # Prepare features
        print("Extracting features...")
        X, y, vuln_types = self.prepare_features(examples)

        # Train models
        results = self.train_models(X, y, vuln_types)

        # Save models
        self.save_models()

        # Save results
        results_path = os.path.join(self.config.model_save_path, "real_world_training_results.json")
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Training results saved to {results_path}")

        print("\n=== Real-World Training Complete ===")
        return results

def main():
    """Main training function"""
    logging.basicConfig(level=logging.INFO)

    if not SKLEARN_AVAILABLE:
        print("scikit-learn not available. Please install: pip install scikit-learn")
        return

    # Configuration
    config = SimpleTrainingConfig()

    # Find dataset
    dataset_path = "vulnhunter_pro/training_data/enhanced_real_world_dataset.json"
    if not os.path.exists(dataset_path):
        print(f"Enhanced dataset not found at {dataset_path}")
        print("Please run the dataset parser first.")
        return

    # Run training
    trainer = SimpleRealWorldTrainer(config)
    results = trainer.run_training(dataset_path)

    if results:
        print("\n=== Real-World Training Results Summary ===")
        for model_name, metrics in results.items():
            test_acc = metrics['test']['accuracy']
            test_f1 = metrics['test']['f1']
            cv_score = metrics['cross_validation']['mean_score']
            print(f"{model_name}:")
            print(f"  CV Score: {cv_score:.3f}")
            print(f"  Test Accuracy: {test_acc:.3f}")
            print(f"  Test F1: {test_f1:.3f}")

if __name__ == "__main__":
    main()