#!/usr/bin/env python3
"""
VulnGuard AI - Ultimate Training Pipeline
Combines HuggingFace and Kaggle datasets for maximum training data
"""

import numpy as np
import pandas as pd
import json
import logging
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
import pickle
import warnings
from typing import Dict, List, Any, Optional, Tuple
from core.huggingface_dataset_integrator import VulnGuardDatasetIntegrator
from core.kaggle_dataset_integrator import KaggleDatasetIntegrator
try:
    from core.ast_feature_extractor import AdvancedASTFeatureExtractor as ASTFeatureExtractor
except ImportError:
    ASTFeatureExtractor = None

warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UltimateVulnGuardTrainer:
    """Ultimate VulnGuard AI trainer with all available datasets and advanced features"""

    def __init__(self):
        self.models = {}
        self.hf_integrator = VulnGuardDatasetIntegrator()
        self.kaggle_integrator = KaggleDatasetIntegrator()
        self.ast_extractor = ASTFeatureExtractor() if ASTFeatureExtractor else None

        self.training_data = []
        self.feature_data = None
        self.labels = None

        # Enhanced feature extractors
        self.code_vectorizer = TfidfVectorizer(
            max_features=8000,
            ngram_range=(1, 4),
            analyzer='char',
            strip_accents='unicode',
            lowercase=True,
            min_df=2,
            max_df=0.95
        )

        self.token_vectorizer = TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 3),
            analyzer='word',
            strip_accents='unicode',
            lowercase=True,
            min_df=2,
            max_df=0.95
        )

        self.scaler = StandardScaler()

        logger.info("🦾 Ultimate VulnGuard AI Trainer initialized")

    def load_all_datasets(self, kaggle_data_path: str = None) -> bool:
        """Load all available datasets from HuggingFace and Kaggle"""
        logger.info("🚀 Loading ALL vulnerability datasets...")
        logger.info("=" * 80)

        all_data = []

        # 1. Load HuggingFace datasets
        logger.info("\n📂 PHASE 1: Loading HuggingFace Datasets")
        logger.info("-" * 80)

        try:
            if self.hf_integrator.load_all_datasets():
                hf_data = self.hf_integrator.process_all_datasets()
                logger.info(f"✅ HuggingFace: {len(hf_data)} samples")
                all_data.extend(hf_data)
            else:
                logger.warning("⚠️  HuggingFace datasets not available")
        except Exception as e:
            logger.warning(f"⚠️  Error loading HuggingFace datasets: {e}")

        # 2. Load Kaggle datasets
        logger.info("\n📂 PHASE 2: Loading Kaggle Datasets")
        logger.info("-" * 80)

        if kaggle_data_path:
            try:
                # Try to load each Kaggle dataset
                kaggle_datasets = [
                    'public-cve-2020-2024',
                    'cve-data',
                    'bug-bounty-writeups',
                    'cve-dataset',
                    'bug-bounty-openai'
                ]

                for dataset_name in kaggle_datasets:
                    dataset_path = f"{kaggle_data_path}/{dataset_name}"
                    try:
                        if self.kaggle_integrator.load_local_dataset(dataset_name, dataset_path):
                            logger.info(f"✅ Loaded {dataset_name}")
                    except Exception as e:
                        logger.warning(f"⚠️  Could not load {dataset_name}: {e}")

                kaggle_data = self.kaggle_integrator.process_all_datasets()
                logger.info(f"✅ Kaggle: {len(kaggle_data)} samples")
                all_data.extend(kaggle_data)

            except Exception as e:
                logger.warning(f"⚠️  Error loading Kaggle datasets: {e}")
        else:
            logger.info("💡 Kaggle data path not provided")
            logger.info("💡 To include Kaggle datasets:")
            logger.info("   1. Download datasets from Kaggle")
            logger.info("   2. Pass path with kaggle_data_path parameter")

        # 3. Combine and deduplicate
        logger.info("\n📊 PHASE 3: Combining and Processing Data")
        logger.info("-" * 80)

        if not all_data:
            logger.error("❌ No datasets loaded!")
            return False

        # Deduplicate based on code content
        seen_codes = set()
        unique_data = []

        for record in all_data:
            code = record.get('code', '').strip()
            if code and len(code) >= 10:
                # Create a hash of the code for deduplication
                code_hash = hash(code[:500])  # Use first 500 chars for hash
                if code_hash not in seen_codes:
                    seen_codes.add(code_hash)
                    unique_data.append(record)

        self.training_data = unique_data

        logger.info(f"✅ Total samples: {len(all_data)}")
        logger.info(f"✅ Unique samples: {len(unique_data)}")
        logger.info(f"📉 Duplicates removed: {len(all_data) - len(unique_data)}")

        # Statistics
        vulnerable_count = sum(1 for r in self.training_data if r.get('vulnerable') == 1)
        safe_count = len(self.training_data) - vulnerable_count

        logger.info(f"\n📊 Dataset Statistics:")
        logger.info(f"   Vulnerable: {vulnerable_count}")
        logger.info(f"   Safe: {safe_count}")

        # Count by source
        sources = {}
        for record in self.training_data:
            source = record.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1

        logger.info(f"\n📊 Samples by Source:")
        for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"   {source}: {count}")

        logger.info("=" * 80)
        return True

    def extract_ultimate_features(self, code_text: str) -> Dict[str, float]:
        """Extract comprehensive features from code"""
        import re

        features = {}

        # Basic metrics
        features['code_length'] = len(code_text)
        features['line_count'] = len(code_text.split('\n'))
        features['avg_line_length'] = features['code_length'] / max(features['line_count'], 1)

        # Character entropy
        if code_text:
            char_counts = {}
            for char in code_text:
                char_counts[char] = char_counts.get(char, 0) + 1
            entropy = 0.0
            for count in char_counts.values():
                prob = count / len(code_text)
                if prob > 0:
                    entropy -= prob * np.log2(prob)
            features['char_entropy'] = entropy
        else:
            features['char_entropy'] = 0.0

        # AST features (if possible)
        if self.ast_extractor:
            try:
                ast_features = self.ast_extractor.extract_features(code_text)
                for key, value in ast_features.items():
                    if isinstance(value, (int, float)) and key != 'error':
                        features[f'ast_{key}'] = value
            except:
                pass

        # Vulnerability patterns
        vuln_patterns = {
            'sql_injection': [
                r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)",
                r"(?i)(\'\s*or\s+\'\s*=\s*\')",
                r"(?i)(exec\s*\(|sp_executesql)"
            ],
            'xss': [
                r"(?i)(<script|javascript:|onerror=|onload=)",
                r"(?i)(alert\s*\(|document\.cookie)"
            ],
            'command_injection': [
                r"(?i)(system\s*\(|exec\s*\(|shell_exec)",
                r"(?i)(\|\s*nc\s|\|\s*wget)"
            ],
            'path_traversal': [
                r"(?i)(\.\.\/|%2e%2e%2f)"
            ],
            'buffer_overflow': [
                r"(?i)(strcpy|strcat|sprintf|gets)\s*\("
            ],
            'crypto_weak': [
                r"(?i)(md5|sha1|des|rc4)\s*\("
            ]
        }

        for vuln_type, patterns in vuln_patterns.items():
            count = 0
            for pattern in patterns:
                count += len(re.findall(pattern, code_text))
            features[f'vuln_{vuln_type}'] = count

        # Code structure
        features['function_count'] = len(re.findall(r'(?i)(def\s+\w+|function\s+\w+|public\s+\w+\s+\w+\s*\()', code_text))
        features['class_count'] = len(re.findall(r'(?i)(class\s+\w+)', code_text))
        features['import_count'] = len(re.findall(r'(?i)(import\s+\w+|from\s+\w+|require\s*\(|include\s+)', code_text))
        features['variable_count'] = len(re.findall(r'(?i)(var\s+|let\s+|const\s+|\w+\s*=)', code_text))
        features['string_count'] = len(re.findall(r'["\'].*?["\']', code_text))
        features['comment_count'] = len(re.findall(r'(?://.*?$|/\*.*?\*/|#.*?$)', code_text, re.MULTILINE))

        # Security keywords
        security_keywords = [
            'password', 'token', 'key', 'secret', 'auth', 'login', 'admin',
            'sql', 'query', 'execute', 'eval', 'system', 'shell', 'command',
            'file', 'path', 'upload', 'download', 'input', 'sanitize', 'validate'
        ]

        for keyword in security_keywords:
            features[f'kw_{keyword}'] = len(re.findall(f'(?i)\\b{keyword}\\b', code_text))

        # Complexity
        complexity_indicators = [r'\bif\b', r'\belse\b', r'\bwhile\b', r'\bfor\b', r'\bswitch\b']
        complexity = 1
        for pattern in complexity_indicators:
            complexity += len(re.findall(pattern, code_text, re.IGNORECASE))
        features['complexity'] = complexity

        return features

    def prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data with ultimate feature extraction"""
        if not self.training_data:
            logger.error("❌ No training data available")
            return None, None

        logger.info("🔄 Preparing training data with ultimate feature extraction...")

        feature_vectors = []
        labels = []
        code_texts = []

        for idx, record in enumerate(self.training_data):
            if idx % 1000 == 0:
                logger.info(f"   Processing: {idx}/{len(self.training_data)}")

            code = record.get('code', '').strip()
            if not code or len(code) < 10:
                continue

            # Extract features
            features = self.extract_ultimate_features(code)
            feature_vectors.append(features)
            labels.append(record.get('vulnerable', 1))
            code_texts.append(code)

        if not feature_vectors:
            logger.error("❌ No valid features extracted")
            return None, None

        logger.info(f"✅ Extracted features from {len(feature_vectors)} samples")

        # Convert to DataFrame
        features_df = pd.DataFrame(feature_vectors).fillna(0)

        # TF-IDF features
        logger.info("🔄 Creating TF-IDF features...")
        char_tfidf = self.code_vectorizer.fit_transform(code_texts)
        token_tfidf = self.token_vectorizer.fit_transform(code_texts)

        # Combine features
        char_tfidf_df = pd.DataFrame(
            char_tfidf.toarray(),
            columns=[f'char_tfidf_{i}' for i in range(char_tfidf.shape[1])]
        )
        token_tfidf_df = pd.DataFrame(
            token_tfidf.toarray(),
            columns=[f'token_tfidf_{i}' for i in range(token_tfidf.shape[1])]
        )

        combined_features = pd.concat([
            features_df.reset_index(drop=True),
            char_tfidf_df.reset_index(drop=True),
            token_tfidf_df.reset_index(drop=True)
        ], axis=1)

        X = combined_features.values
        y = np.array(labels)

        # Scale features
        logger.info("🔄 Scaling features...")
        X = self.scaler.fit_transform(X)

        logger.info(f"✅ Final training data: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"📊 Class distribution: Vulnerable={np.sum(y==1)}, Safe={np.sum(y==0)}")

        self.feature_data = X
        self.labels = y

        return X, y

    def train_ultimate_models(self, X: np.ndarray, y: np.ndarray):
        """Train ultimate ensemble of ML models"""
        logger.info("🤖 Training Ultimate VulnGuard AI Models...")
        logger.info("=" * 80)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        logger.info(f"📊 Training samples: {len(X_train)}")
        logger.info(f"📊 Test samples: {len(X_test)}")

        # Train models
        self.models = {}

        # 1. Random Forest
        logger.info("\n🌲 Training Random Forest...")
        rf = RandomForestClassifier(
            n_estimators=300,
            max_depth=25,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
        rf.fit(X_train, y_train)
        self.models['random_forest'] = rf
        logger.info("   ✅ Random Forest trained")

        # 2. Gradient Boosting
        logger.info("\n📈 Training Gradient Boosting...")
        gb = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=10,
            random_state=42,
            verbose=0
        )
        gb.fit(X_train, y_train)
        self.models['gradient_boosting'] = gb
        logger.info("   ✅ Gradient Boosting trained")

        # 3. XGBoost
        if HAS_XGBOOST:
            logger.info("\n🚀 Training XGBoost...")
            xgb_model = xgb.XGBClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=10,
                random_state=42,
                eval_metric='logloss',
                verbosity=0
            )
            xgb_model.fit(X_train, y_train)
            self.models['xgboost'] = xgb_model
            logger.info("   ✅ XGBoost trained")

        # 4. Neural Network
        logger.info("\n🧠 Training Neural Network...")
        nn = MLPClassifier(
            hidden_layer_sizes=(512, 256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.0001,
            batch_size=256,
            learning_rate='adaptive',
            max_iter=500,
            random_state=42,
            verbose=False
        )
        nn.fit(X_train, y_train)
        self.models['neural_network'] = nn
        logger.info("   ✅ Neural Network trained")

        # 5. SVM
        logger.info("\n🎯 Training SVM...")
        svm = SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            probability=True,
            random_state=42
        )
        svm.fit(X_train, y_train)
        self.models['svm'] = svm
        logger.info("   ✅ SVM trained")

        # 6. Logistic Regression
        logger.info("\n📊 Training Logistic Regression...")
        lr = LogisticRegression(
            max_iter=1000,
            random_state=42,
            C=1.0,
            verbose=0
        )
        lr.fit(X_train, y_train)
        self.models['logistic_regression'] = lr
        logger.info("   ✅ Logistic Regression trained")

        # Evaluate all models
        logger.info("\n" + "=" * 80)
        self._evaluate_models(X_test, y_test)

        logger.info(f"\n✅ Training complete: {len(self.models)} models trained")

    def _evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray):
        """Comprehensive model evaluation"""
        logger.info("📊 MODEL EVALUATION")
        logger.info("=" * 80)

        results = []

        for name, model in self.models.items():
            try:
                y_pred = model.predict(X_test)
                y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None

                accuracy = accuracy_score(y_test, y_pred)
                precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)

                results.append({
                    'model': name,
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1
                })

                logger.info(f"\n{name.upper()}:")
                logger.info(f"  Accuracy:  {accuracy:.4f}")
                logger.info(f"  Precision: {precision:.4f}")
                logger.info(f"  Recall:    {recall:.4f}")
                logger.info(f"  F1-Score:  {f1:.4f}")

            except Exception as e:
                logger.warning(f"⚠️  Error evaluating {name}: {e}")

        # Find best model
        if results:
            best = max(results, key=lambda x: x['f1'])
            logger.info("\n" + "=" * 80)
            logger.info(f"🏆 BEST MODEL: {best['model'].upper()}")
            logger.info(f"   F1-Score: {best['f1']:.4f}")
            logger.info("=" * 80)

    def save_models(self, filename: str = None) -> str:
        """Save all trained models"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ultimate_vulnguard_{timestamp}.pkl"

        model_data = {
            'models': self.models,
            'code_vectorizer': self.code_vectorizer,
            'token_vectorizer': self.token_vectorizer,
            'scaler': self.scaler,
            'feature_shape': self.feature_data.shape if self.feature_data is not None else None,
            'training_samples': len(self.training_data),
            'timestamp': datetime.now().isoformat()
        }

        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"💾 Models saved to {filename}")
        return filename

    def predict(self, code_text: str) -> Dict:
        """Predict vulnerability with ensemble"""
        if not self.models:
            raise ValueError("Models not trained")

        # Extract features
        features = self.extract_ultimate_features(code_text)
        feature_vector = pd.DataFrame([features]).fillna(0)

        # TF-IDF
        char_tfidf = self.code_vectorizer.transform([code_text])
        token_tfidf = self.token_vectorizer.transform([code_text])

        # Combine
        char_tfidf_df = pd.DataFrame(
            char_tfidf.toarray(),
            columns=[f'char_tfidf_{i}' for i in range(char_tfidf.shape[1])]
        )
        token_tfidf_df = pd.DataFrame(
            token_tfidf.toarray(),
            columns=[f'token_tfidf_{i}' for i in range(token_tfidf.shape[1])]
        )

        combined = pd.concat([feature_vector, char_tfidf_df, token_tfidf_df], axis=1)

        # Ensure correct feature count
        expected_features = self.feature_data.shape[1]
        if combined.shape[1] != expected_features:
            if combined.shape[1] < expected_features:
                padding = pd.DataFrame(np.zeros((1, expected_features - combined.shape[1])))
                combined = pd.concat([combined, padding], axis=1)
            else:
                combined = combined.iloc[:, :expected_features]

        X = self.scaler.transform(combined.values)

        # Get predictions
        predictions = {}
        probabilities = {}

        for name, model in self.models.items():
            try:
                pred = model.predict(X)[0]
                prob = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else [1-pred, pred]
                predictions[name] = int(pred)
                probabilities[name] = float(prob[1])
            except:
                predictions[name] = 0
                probabilities[name] = 0.0

        # Ensemble
        ensemble_prob = np.mean(list(probabilities.values()))
        ensemble_pred = 1 if ensemble_prob > 0.5 else 0

        return {
            'vulnerable': ensemble_pred,
            'confidence': ensemble_prob,
            'predictions': predictions,
            'probabilities': probabilities
        }


def main():
    """Main training pipeline"""
    logger.info("🚀 ULTIMATE VULNGUARD AI TRAINING PIPELINE")
    logger.info("=" * 80)

    trainer = UltimateVulnGuardTrainer()

    # Load datasets (provide kaggle_data_path if you have Kaggle datasets)
    if not trainer.load_all_datasets(kaggle_data_path=None):
        logger.error("❌ Failed to load datasets")
        return None

    # Prepare data
    X, y = trainer.prepare_training_data()
    if X is None:
        logger.error("❌ Failed to prepare training data")
        return None

    # Train models
    trainer.train_ultimate_models(X, y)

    # Save models
    model_file = trainer.save_models()

    logger.info("\n" + "=" * 80)
    logger.info("🎉 TRAINING COMPLETE!")
    logger.info(f"📁 Model file: {model_file}")
    logger.info("=" * 80)

    return trainer


if __name__ == "__main__":
    main()
