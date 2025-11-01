#!/usr/bin/env python3
"""
Enhanced Real-World Training Pipeline for VulnHunter Professional
================================================================

Trains ML models on combined synthetic + real-world vulnerability datasets.
Supports multi-language analysis and advanced feature engineering.
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
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
    from sklearn.svm import SVC
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report, confusion_matrix
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
class EnhancedTrainingConfig:
    """Enhanced training configuration for real-world data"""
    validation_split: float = 0.2
    test_split: float = 0.1
    model_save_path: str = "models/enhanced/"
    max_features: int = 15000
    min_df: int = 2
    max_df: float = 0.95
    ngram_range: Tuple[int, int] = (1, 3)
    cross_validation_folds: int = 5

class EnhancedRealWorldTrainer:
    """Enhanced training pipeline for real-world vulnerability data"""

    def __init__(self, config: EnhancedTrainingConfig):
        self.config = config
        self.models = {}
        self.vectorizers = {}
        self.label_encoders = {}
        self.feature_stats = {}

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

    def prepare_enhanced_features(self, examples: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """Extract enhanced features from multi-language examples"""
        print("Extracting enhanced features from multi-language dataset...")

        # Separate by language for language-specific processing
        lang_groups = {}
        for example in examples:
            lang = example.get('language', 'unknown')
            if lang not in lang_groups:
                lang_groups[lang] = []
            lang_groups[lang].append(example)

        print(f"Language distribution: {[(lang, len(examples)) for lang, examples in lang_groups.items()]}")

        # Process each language group
        all_features = []
        all_binary_labels = []
        all_multiclass_labels = []
        all_sources = []

        for language, lang_examples in lang_groups.items():
            print(f"Processing {len(lang_examples)} {language} examples...")

            codes = []
            binary_labels = []
            multiclass_labels = []
            sources = []

            for example in lang_examples:
                # Enhanced code preprocessing
                code = self._preprocess_code(example['code'], language)
                codes.append(code)

                # Binary classification labels (vulnerable vs safe)
                binary_labels.append(1 if example['is_vulnerable'] else 0)

                # Multi-class labels (specific vulnerability types)
                if example['is_vulnerable']:
                    multiclass_labels.append(example['vulnerability_type'])
                else:
                    multiclass_labels.append('safe')

                sources.append(example.get('source_dataset', 'unknown'))

            # Create language-specific vectorizer
            vectorizer_name = f"tfidf_{language}"
            if vectorizer_name not in self.vectorizers:
                self.vectorizers[vectorizer_name] = TfidfVectorizer(
                    max_features=self.config.max_features,
                    min_df=self.config.min_df,
                    max_df=self.config.max_df,
                    ngram_range=self.config.ngram_range,
                    lowercase=True,
                    stop_words=None,  # Keep language-specific tokens
                    token_pattern=r'\b\w+\b',
                    analyzer='word'
                )
                features = self.vectorizers[vectorizer_name].fit_transform(codes)
            else:
                features = self.vectorizers[vectorizer_name].transform(codes)

            # Add language-specific features
            lang_features = self._extract_language_features(codes, language)

            # Combine TF-IDF with language-specific features
            if lang_features.shape[1] > 0:
                try:
                    from scipy.sparse import hstack, csr_matrix
                    lang_features_sparse = csr_matrix(lang_features)
                    combined_features = hstack([features, lang_features_sparse])
                except ImportError:
                    # Fallback if scipy not available
                    combined_features = features
            else:
                combined_features = features

            all_features.append(combined_features.toarray())
            all_binary_labels.extend(binary_labels)
            all_multiclass_labels.extend(multiclass_labels)
            all_sources.extend(sources)

        # Combine all features
        combined_features_array = np.vstack(all_features)

        # Encode multiclass labels
        if 'multiclass' not in self.label_encoders:
            self.label_encoders['multiclass'] = LabelEncoder()
            encoded_multiclass = self.label_encoders['multiclass'].fit_transform(all_multiclass_labels)
        else:
            encoded_multiclass = self.label_encoders['multiclass'].transform(all_multiclass_labels)

        print(f"Final feature matrix shape: {combined_features_array.shape}")
        print(f"Unique vulnerability types: {len(set(all_multiclass_labels))}")

        return (
            combined_features_array,
            np.array(all_binary_labels),
            np.array(encoded_multiclass),
            all_sources
        )

    def _preprocess_code(self, code: str, language: str) -> str:
        """Language-specific code preprocessing"""
        import re

        # Remove comments based on language
        if language == 'java':
            # Remove single-line and multi-line comments
            code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        elif language == 'c':
            # Remove C/C++ comments
            code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        elif language == 'python':
            # Remove Python comments
            code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)
            code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
            code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)

        # Normalize whitespace
        code = re.sub(r'\s+', ' ', code)

        # Extract function/method signatures and important patterns
        patterns = []

        if language == 'java':
            # Java-specific patterns
            patterns.extend([
                r'\b(HttpServletRequest|HttpServletResponse)\b',
                r'\b(getParameter|setAttribute|getWriter)\b',
                r'\b(executeQuery|prepareStatement|createStatement)\b',
                r'\b(exec|Runtime\.getRuntime)\b'
            ])
        elif language == 'c':
            # C-specific patterns
            patterns.extend([
                r'\b(strcpy|strcat|sprintf|gets|malloc|free)\b',
                r'\b(system|exec|popen)\b',
                r'\b(printf|scanf)\b'
            ])
        elif language == 'python':
            # Python-specific patterns
            patterns.extend([
                r'\b(exec|eval|compile)\b',
                r'\b(os\.system|subprocess)\b',
                r'\b(pickle|yaml)\b'
            ])

        # Extract pattern matches
        extracted_patterns = []
        for pattern in patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            extracted_patterns.extend(matches)

        # Combine original code with extracted patterns
        enhanced_code = code + ' ' + ' '.join(extracted_patterns)

        return enhanced_code.strip()

    def _extract_language_features(self, codes: List[str], language: str) -> np.ndarray:
        """Extract language-specific numerical features"""
        features = []

        for code in codes:
            lang_features = []

            if language == 'java':
                # Java-specific features
                lang_features.extend([
                    len(re.findall(r'\bgetParameter\b', code)),
                    len(re.findall(r'\bexecuteQuery\b', code)),
                    len(re.findall(r'\bexec\b', code)),
                    len(re.findall(r'\bHttpServlet\b', code)),
                    code.count('.'),
                    code.count(';'),
                ])
            elif language == 'c':
                # C-specific features
                lang_features.extend([
                    len(re.findall(r'\bstrcpy\b', code)),
                    len(re.findall(r'\bmalloc\b', code)),
                    len(re.findall(r'\bfree\b', code)),
                    len(re.findall(r'\bsystem\b', code)),
                    code.count('*'),
                    code.count('&'),
                ])
            elif language == 'python':
                # Python-specific features
                lang_features.extend([
                    len(re.findall(r'\bexec\b', code)),
                    len(re.findall(r'\beval\b', code)),
                    len(re.findall(r'\bpickle\b', code)),
                    len(re.findall(r'\bos\.system\b', code)),
                    code.count('import'),
                    code.count('def '),
                ])

            # Generic features
            lang_features.extend([
                len(code),
                len(code.split()),
                code.count('('),
                code.count(')'),
                code.count('{'),
                code.count('}'),
            ])

            features.append(lang_features)

        return np.array(features)

    def train_enhanced_models(self, X: np.ndarray, y_binary: np.ndarray, y_multiclass: np.ndarray, sources: List[str]):
        """Train multiple enhanced models"""
        print(f"Training enhanced models on {len(X)} examples with {X.shape[1]} features")

        # Split the data
        X_train, X_temp, y_bin_train, y_bin_temp, y_multi_train, y_multi_temp = train_test_split(
            X, y_binary, y_multiclass, test_size=self.config.validation_split + self.config.test_split,
            random_state=42, stratify=y_binary
        )

        val_size = self.config.validation_split / (self.config.validation_split + self.config.test_split)
        X_val, X_test, y_bin_val, y_bin_test, y_multi_val, y_multi_test = train_test_split(
            X_temp, y_bin_temp, y_multi_temp, test_size=1-val_size, random_state=42, stratify=y_bin_temp
        )

        print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

        # Define enhanced model configurations
        model_configs = {
            'random_forest_enhanced': RandomForestClassifier(
                n_estimators=200,
                max_depth=25,
                min_samples_split=3,
                min_samples_leaf=1,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            ),
            'gradient_boosting_enhanced': GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                random_state=42,
                subsample=0.8
            ),
            'extra_trees_enhanced': ExtraTreesClassifier(
                n_estimators=200,
                max_depth=25,
                min_samples_split=3,
                min_samples_leaf=1,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            ),
            'svm_enhanced': SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                random_state=42,
                class_weight='balanced',
                probability=True
            )
        }

        results = {}

        # Train binary classification models
        print("\n=== Training Binary Classification Models ===")
        for name, model in model_configs.items():
            print(f"\nTraining {name} for binary classification...")
            start_time = time.time()

            # Train model
            model.fit(X_train, y_bin_train)
            training_time = time.time() - start_time

            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_bin_train, cv=self.config.cross_validation_folds)

            # Validation predictions
            val_pred = model.predict(X_val)
            val_proba = model.predict_proba(X_val)[:, 1] if hasattr(model, 'predict_proba') else val_pred
            val_acc = accuracy_score(y_bin_val, val_pred)
            val_prec, val_rec, val_f1, _ = precision_recall_fscore_support(y_bin_val, val_pred, average='weighted')

            # Test predictions
            test_pred = model.predict(X_test)
            test_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else test_pred
            test_acc = accuracy_score(y_bin_test, test_pred)
            test_prec, test_rec, test_f1, _ = precision_recall_fscore_support(y_bin_test, test_pred, average='weighted')

            # Store results
            binary_name = f"{name}_binary"
            self.models[binary_name] = model
            results[binary_name] = {
                'type': 'binary_classification',
                'training_time': training_time,
                'cv_scores': {
                    'mean': cv_scores.mean(),
                    'std': cv_scores.std(),
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
                }
            }

            print(f"  CV Score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
            print(f"  Validation - Acc: {val_acc:.3f}, F1: {val_f1:.3f}")
            print(f"  Test - Acc: {test_acc:.3f}, F1: {test_f1:.3f}")
            print(f"  Training time: {training_time:.2f}s")

        # Train multiclass models (only on vulnerable examples)
        print("\n=== Training Multiclass Vulnerability Type Models ===")

        # Filter to only vulnerable examples for multiclass training
        vuln_mask_train = y_bin_train == 1
        vuln_mask_val = y_bin_val == 1
        vuln_mask_test = y_bin_test == 1

        if np.sum(vuln_mask_train) > 0:
            X_train_vuln = X_train[vuln_mask_train]
            y_multi_train_vuln = y_multi_train[vuln_mask_train]
            X_val_vuln = X_val[vuln_mask_val]
            y_multi_val_vuln = y_multi_val[vuln_mask_val]
            X_test_vuln = X_test[vuln_mask_test]
            y_multi_test_vuln = y_multi_test[vuln_mask_test]

            print(f"Multiclass training on {len(X_train_vuln)} vulnerable examples")

            for name, model_class in [('random_forest_multiclass', RandomForestClassifier),
                                     ('gradient_boosting_multiclass', GradientBoostingClassifier)]:
                print(f"\nTraining {name}...")
                start_time = time.time()

                model = model_class(
                    n_estimators=150,
                    max_depth=20,
                    random_state=42,
                    n_jobs=-1 if name.startswith('random_forest') else 1
                )

                model.fit(X_train_vuln, y_multi_train_vuln)
                training_time = time.time() - start_time

                # Validation predictions
                val_pred = model.predict(X_val_vuln)
                val_acc = accuracy_score(y_multi_val_vuln, val_pred)

                # Test predictions
                test_pred = model.predict(X_test_vuln)
                test_acc = accuracy_score(y_multi_test_vuln, test_pred)

                self.models[name] = model
                results[name] = {
                    'type': 'multiclass_classification',
                    'training_time': training_time,
                    'validation': {'accuracy': val_acc},
                    'test': {'accuracy': test_acc},
                    'num_classes': len(np.unique(y_multi_train_vuln))
                }

                print(f"  Validation Accuracy: {val_acc:.3f}")
                print(f"  Test Accuracy: {test_acc:.3f}")
                print(f"  Training time: {training_time:.2f}s")

        return results

    def save_enhanced_models(self):
        """Save all trained models and metadata"""
        print("\nSaving enhanced models...")

        for name, model in self.models.items():
            model_path = os.path.join(self.config.model_save_path, f"{name}_model.pkl")
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            print(f"Saved {name} to {model_path}")

        # Save vectorizers
        for name, vectorizer in self.vectorizers.items():
            vectorizer_path = os.path.join(self.config.model_save_path, f"{name}_vectorizer.pkl")
            with open(vectorizer_path, 'wb') as f:
                pickle.dump(vectorizer, f)
            print(f"Saved {name} to {vectorizer_path}")

        # Save label encoders
        for name, encoder in self.label_encoders.items():
            encoder_path = os.path.join(self.config.model_save_path, f"{name}_encoder.pkl")
            with open(encoder_path, 'wb') as f:
                pickle.dump(encoder, f)
            print(f"Saved {name} encoder to {encoder_path}")

    def run_enhanced_training(self, dataset_path: str) -> Dict[str, Any]:
        """Run the complete enhanced training pipeline"""
        print("=== VulnHunter Pro Enhanced Real-World Training Pipeline ===")

        # Load enhanced dataset
        examples = self.load_enhanced_dataset(dataset_path)
        if not examples:
            print("No data loaded. Exiting.")
            return {}

        # Prepare enhanced features
        print("Extracting enhanced features...")
        X, y_binary, y_multiclass, sources = self.prepare_enhanced_features(examples)

        # Train enhanced models
        results = self.train_enhanced_models(X, y_binary, y_multiclass, sources)

        # Save models
        self.save_enhanced_models()

        # Save results
        results_path = os.path.join(self.config.model_save_path, "enhanced_training_results.json")
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Enhanced training results saved to {results_path}")

        print("\n=== Enhanced Training Complete ===")
        return results

def main():
    """Main enhanced training function"""
    logging.basicConfig(level=logging.INFO)

    if not SKLEARN_AVAILABLE:
        print("scikit-learn not available. Please install: pip install scikit-learn")
        return

    # Configuration
    config = EnhancedTrainingConfig()

    # Find enhanced dataset
    dataset_path = "vulnhunter_pro/training_data/enhanced_real_world_dataset.json"
    if not os.path.exists(dataset_path):
        print(f"Enhanced dataset not found at {dataset_path}")
        print("Please run the dataset parser first.")
        return

    # Run enhanced training
    trainer = EnhancedRealWorldTrainer(config)
    results = trainer.run_enhanced_training(dataset_path)

    if results:
        print("\n=== Enhanced Training Results Summary ===")
        for model_name, metrics in results.items():
            if 'test' in metrics:
                if 'accuracy' in metrics['test']:
                    test_acc = metrics['test']['accuracy']
                    model_type = metrics.get('type', 'unknown')
                    print(f"{model_name} ({model_type}): Test Accuracy={test_acc:.3f}")

if __name__ == "__main__":
    main()