#!/usr/bin/env python3
"""
VulnGuard AI - Enhanced Training Pipeline
Advanced machine learning with integrated Hugging Face vulnerability datasets
"""

import numpy as np
import pandas as pd
import json
import logging
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler
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

warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnGuardEnhancedTrainer:
    """Enhanced VulnGuard AI trainer with integrated datasets and advanced ML"""

    def __init__(self):
        self.models = {}
        self.feature_extractors = {}
        self.scalers = {}
        self.dataset_integrator = VulnGuardDatasetIntegrator()
        self.training_data = []
        self.feature_data = None
        self.labels = None

        # Enhanced feature extraction
        self.code_vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            analyzer='char',
            strip_accents='unicode',
            lowercase=True
        )

        self.token_vectorizer = TfidfVectorizer(
            max_features=2000,
            ngram_range=(1, 2),
            analyzer='word',
            strip_accents='unicode',
            lowercase=True
        )

        self.scaler = StandardScaler()

        # Vulnerability patterns for enhanced feature extraction
        self.vulnerability_patterns = {
            'sql_injection': [
                r"(?i)(union\s+select|drop\s+table|insert\s+into|update\s+set|delete\s+from)",
                r"(?i)(\'\s*or\s+\'\s*=\s*\'|\'\s*or\s+1\s*=\s*1)",
                r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)",
                r"(?i)(waitfor\s+delay|benchmark\s*\()",
            ],
            'xss': [
                r"(?i)(<script|javascript:|onerror=|onload=|eval\s*\()",
                r"(?i)(alert\s*\(|prompt\s*\(|confirm\s*\()",
                r"(?i)(document\.cookie|window\.location|innerHTML)",
            ],
            'command_injection': [
                r"(?i)(system\s*\(|exec\s*\(|shell_exec|passthru)",
                r"(?i)(\|\s*nc\s|\|\s*netcat|\|\s*wget|\|\s*curl)",
                r"(?i)(&&\s*rm\s|;\s*rm\s|`rm\s)",
            ],
            'path_traversal': [
                r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
                r"(?i)(\/etc\/passwd|\/etc\/shadow|\.\.\/\.\.\/)",
            ],
            'buffer_overflow': [
                r"(?i)(strcpy\s*\(|strcat\s*\(|sprintf\s*\(|gets\s*\()",
                r"(?i)(memcpy\s*\(.*,.*,.*\))",
                r"(?i)(malloc\s*\(|calloc\s*\(|realloc\s*\()",
            ],
            'crypto_vulnerabilities': [
                r"(?i)(md5\s*\(|sha1\s*\(|des\s|rc4)",
                r"(?i)(rand\s*\(\)|random\s*\(\)|time\s*\(.*\)\s*%)",
                r"(?i)(ssl.*verify.*false|tls.*verify.*false)",
            ],
            'authentication_bypass': [
                r"(?i)(password\s*==?\s*['\"]|auth.*bypass)",
                r"(?i)(login\s*==?\s*true|authenticated\s*=\s*1)",
                r"(?i)(admin.*1.*=.*1|user.*role.*admin)",
            ]
        }

        logger.info("🦾 VulnGuard AI Enhanced Trainer initialized")

    def load_integrated_datasets(self) -> bool:
        """Load and integrate all Hugging Face vulnerability datasets"""
        logger.info("📂 Loading integrated vulnerability datasets...")

        # Load all datasets
        if not self.dataset_integrator.load_all_datasets():
            logger.error("❌ Failed to load datasets")
            return False

        # Process all datasets
        processed_data = self.dataset_integrator.process_all_datasets()
        if not processed_data:
            logger.error("❌ No processed data available")
            return False

        self.training_data = processed_data
        logger.info(f"✅ Loaded {len(self.training_data)} training samples")

        # Show dataset distribution
        vulnerable_count = sum(1 for record in self.training_data if record['vulnerable'] == 1)
        safe_count = len(self.training_data) - vulnerable_count

        logger.info(f"📊 Vulnerable samples: {vulnerable_count}")
        logger.info(f"📊 Safe samples: {safe_count}")

        return True

    def extract_advanced_features(self, code_text: str) -> Dict[str, float]:
        """Extract advanced vulnerability-specific features from code"""
        features = {}

        # Basic code metrics
        features['code_length'] = len(code_text)
        features['line_count'] = len(code_text.split('\n'))
        features['char_entropy'] = self._calculate_entropy(code_text)

        # Vulnerability pattern matching
        for vuln_type, patterns in self.vulnerability_patterns.items():
            pattern_count = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, code_text))
                pattern_count += matches
            features[f'{vuln_type}_patterns'] = pattern_count

        # Syntax and structure features
        features['function_count'] = len(re.findall(r'(?i)(def\s+\w+|function\s+\w+|public\s+\w+\s+\w+\s*\()', code_text))
        features['variable_count'] = len(re.findall(r'(?i)(var\s+\w+|let\s+\w+|const\s+\w+|\w+\s*=)', code_text))
        features['string_literal_count'] = len(re.findall(r'["\'].*?["\']', code_text))
        features['comment_count'] = len(re.findall(r'(?://.*?$|/\*.*?\*/|#.*?$)', code_text, re.MULTILINE | re.DOTALL))

        # Security-relevant keywords
        security_keywords = [
            'password', 'token', 'key', 'secret', 'auth', 'login', 'admin',
            'sql', 'query', 'execute', 'eval', 'system', 'shell', 'command',
            'file', 'path', 'directory', 'upload', 'download', 'input',
            'sanitize', 'validate', 'escape', 'filter', 'encode', 'decode'
        ]

        for keyword in security_keywords:
            features[f'keyword_{keyword}'] = len(re.findall(f'(?i)\\b{keyword}\\b', code_text))

        # Code complexity indicators
        features['cyclomatic_complexity'] = self._estimate_complexity(code_text)
        features['nested_blocks'] = len(re.findall(r'\{.*?\{', code_text))
        features['conditional_statements'] = len(re.findall(r'(?i)\b(if|else|switch|case|while|for)\b', code_text))

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        length = len(text)
        entropy = 0.0

        for count in char_counts.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * np.log2(prob)

        return entropy

    def _estimate_complexity(self, code_text: str) -> int:
        """Estimate cyclomatic complexity"""
        complexity_patterns = [
            r'(?i)\bif\b', r'(?i)\belse\b', r'(?i)\belif\b', r'(?i)\bwhile\b',
            r'(?i)\bfor\b', r'(?i)\bswitch\b', r'(?i)\bcase\b', r'(?i)\bcatch\b',
            r'(?i)\btry\b', r'(?i)\b&&\b', r'(?i)\b\|\|\b', r'\?.*:'
        ]

        complexity = 1  # Base complexity
        for pattern in complexity_patterns:
            complexity += len(re.findall(pattern, code_text))

        return complexity

    def prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data with advanced feature extraction"""
        if not self.training_data:
            logger.error("❌ No training data available")
            return None, None

        logger.info("🔄 Preparing training data with advanced feature extraction...")

        # Extract features from all samples
        feature_vectors = []
        labels = []
        code_texts = []

        for record in self.training_data:
            code = record.get('code', '')
            if not code or len(code.strip()) < 10:  # Skip very short code samples
                continue

            # Extract advanced features
            features = self.extract_advanced_features(code)
            feature_vectors.append(features)
            labels.append(record['vulnerable'])
            code_texts.append(code)

        if not feature_vectors:
            logger.error("❌ No valid features extracted")
            return None, None

        # Convert to DataFrame for easier handling
        features_df = pd.DataFrame(feature_vectors)
        features_df = features_df.fillna(0)  # Fill NaN values with 0

        # TF-IDF vectorization of code text
        logger.info("🔄 Creating TF-IDF features...")

        # Character-level TF-IDF
        char_tfidf = self.code_vectorizer.fit_transform(code_texts)
        char_feature_names = [f'char_tfidf_{i}' for i in range(char_tfidf.shape[1])]

        # Token-level TF-IDF
        token_tfidf = self.token_vectorizer.fit_transform(code_texts)
        token_feature_names = [f'token_tfidf_{i}' for i in range(token_tfidf.shape[1])]

        # Combine all features
        char_tfidf_df = pd.DataFrame(char_tfidf.toarray(), columns=char_feature_names)
        token_tfidf_df = pd.DataFrame(token_tfidf.toarray(), columns=token_feature_names)

        # Combine manual features with TF-IDF features
        combined_features = pd.concat([
            features_df.reset_index(drop=True),
            char_tfidf_df.reset_index(drop=True),
            token_tfidf_df.reset_index(drop=True)
        ], axis=1)

        # Convert to numpy arrays
        X = combined_features.values
        y = np.array(labels)

        # Scale features
        X = self.scaler.fit_transform(X)

        logger.info(f"✅ Prepared training data: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"📊 Class distribution: {np.bincount(y)}")

        self.feature_data = X
        self.labels = y

        return X, y

    def train_enhanced_models(self, X: np.ndarray, y: np.ndarray):
        """Train enhanced ensemble of ML models"""
        logger.info("🤖 Training VulnGuard AI enhanced models...")

        # Split data for training and validation
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Initialize models with enhanced parameters
        self.models = {}

        # Random Forest with enhanced parameters
        logger.info("🌲 Training Random Forest...")
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)
        self.models['random_forest'] = rf

        # Gradient Boosting with enhanced parameters
        logger.info("📈 Training Gradient Boosting...")
        gb = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=8,
            random_state=42
        )
        gb.fit(X_train, y_train)
        self.models['gradient_boosting'] = gb

        # XGBoost if available
        if HAS_XGBOOST:
            logger.info("🚀 Training XGBoost...")
            xgb_model = xgb.XGBClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                random_state=42,
                eval_metric='logloss'
            )
            xgb_model.fit(X_train, y_train)
            self.models['xgboost'] = xgb_model

        # Neural Network
        logger.info("🧠 Training Neural Network...")
        nn = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size=256,
            learning_rate='adaptive',
            max_iter=500,
            random_state=42
        )
        nn.fit(X_train, y_train)
        self.models['neural_network'] = nn

        # Logistic Regression for baseline
        logger.info("📊 Training Logistic Regression...")
        lr = LogisticRegression(
            max_iter=1000,
            random_state=42,
            C=1.0
        )
        lr.fit(X_train, y_train)
        self.models['logistic_regression'] = lr

        # SVM for complex patterns
        logger.info("🎯 Training SVM...")
        svm = SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            probability=True,
            random_state=42
        )
        svm.fit(X_train, y_train)
        self.models['svm'] = svm

        # Evaluate all models
        self._evaluate_enhanced_models(X_test, y_test)

        logger.info(f"✅ Training complete: {len(self.models)} models trained")

    def _evaluate_enhanced_models(self, X_test: np.ndarray, y_test: np.ndarray):
        """Enhanced model evaluation with detailed metrics"""
        logger.info("📊 Evaluating enhanced models...")

        model_scores = {}

        for name, model in self.models.items():
            try:
                # Predictions
                y_pred = model.predict(X_test)
                y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None

                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')

                model_scores[name] = {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1
                }

                logger.info(f"📈 {name}:")
                logger.info(f"   Accuracy: {accuracy:.4f}")
                logger.info(f"   Precision: {precision:.4f}")
                logger.info(f"   Recall: {recall:.4f}")
                logger.info(f"   F1-Score: {f1:.4f}")

            except Exception as e:
                logger.warning(f"⚠️  Error evaluating {name}: {e}")

        # Find best performing model
        best_model = max(model_scores.items(), key=lambda x: x[1]['f1_score'])
        logger.info(f"🏆 Best model: {best_model[0]} (F1: {best_model[1]['f1_score']:.4f})")

    def predict_vulnerability(self, code_text: str) -> Dict:
        """Predict vulnerability with ensemble approach"""
        if not self.models:
            raise ValueError("Models not trained. Call train_enhanced_models() first.")

        # Extract features
        features = self.extract_advanced_features(code_text)
        feature_vector = pd.DataFrame([features]).fillna(0)

        # TF-IDF features
        char_tfidf = self.code_vectorizer.transform([code_text])
        token_tfidf = self.token_vectorizer.transform([code_text])

        # Combine features
        char_tfidf_df = pd.DataFrame(char_tfidf.toarray(),
                                    columns=[f'char_tfidf_{i}' for i in range(char_tfidf.shape[1])])
        token_tfidf_df = pd.DataFrame(token_tfidf.toarray(),
                                     columns=[f'token_tfidf_{i}' for i in range(token_tfidf.shape[1])])

        combined_features = pd.concat([feature_vector, char_tfidf_df, token_tfidf_df], axis=1)

        # Handle missing columns
        expected_features = self.feature_data.shape[1]
        if combined_features.shape[1] != expected_features:
            # Pad with zeros or truncate as needed
            if combined_features.shape[1] < expected_features:
                padding = pd.DataFrame(np.zeros((1, expected_features - combined_features.shape[1])))
                combined_features = pd.concat([combined_features, padding], axis=1)
            else:
                combined_features = combined_features.iloc[:, :expected_features]

        X = self.scaler.transform(combined_features.values)

        # Get predictions from all models
        predictions = {}
        probabilities = {}

        for name, model in self.models.items():
            try:
                pred = model.predict(X)[0]
                prob = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else [1-pred, pred]

                predictions[name] = int(pred)
                probabilities[name] = float(prob[1])  # Probability of being vulnerable

            except Exception as e:
                logger.warning(f"⚠️  Error predicting with {name}: {e}")
                predictions[name] = 0
                probabilities[name] = 0.0

        # Ensemble prediction (majority vote with confidence weighting)
        ensemble_prob = np.mean(list(probabilities.values()))
        ensemble_pred = 1 if ensemble_prob > 0.5 else 0

        return {
            'ensemble_prediction': ensemble_pred,
            'ensemble_confidence': ensemble_prob,
            'individual_predictions': predictions,
            'individual_probabilities': probabilities,
            'feature_count': len(features),
            'code_length': len(code_text)
        }

    def save_enhanced_models(self, base_filename: str = "vulnguard_enhanced_models") -> str:
        """Save enhanced trained models and feature extractors"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{base_filename}_{timestamp}.pkl"

        model_data = {
            'models': self.models,
            'code_vectorizer': self.code_vectorizer,
            'token_vectorizer': self.token_vectorizer,
            'scaler': self.scaler,
            'vulnerability_patterns': self.vulnerability_patterns,
            'feature_shape': self.feature_data.shape if self.feature_data is not None else None,
            'training_samples': len(self.training_data),
            'timestamp': timestamp
        }

        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"💾 Enhanced models saved to {filename}")
        return filename

    def load_enhanced_models(self, filename: str) -> bool:
        """Load enhanced pre-trained models"""
        try:
            logger.info(f"📂 Loading enhanced models from {filename}")

            with open(filename, 'rb') as f:
                model_data = pickle.load(f)

            self.models = model_data['models']
            self.code_vectorizer = model_data['code_vectorizer']
            self.token_vectorizer = model_data['token_vectorizer']
            self.scaler = model_data['scaler']
            self.vulnerability_patterns = model_data.get('vulnerability_patterns', self.vulnerability_patterns)

            logger.info(f"✅ Enhanced models loaded: {len(self.models)} models available")
            return True

        except Exception as e:
            logger.error(f"❌ Error loading models: {e}")
            return False


def main():
    """Main function to demonstrate VulnGuard AI enhanced training"""
    logger.info("🚀 Starting VulnGuard AI Enhanced Training Pipeline")

    # Initialize enhanced trainer
    trainer = VulnGuardEnhancedTrainer()

    # Load integrated datasets
    if not trainer.load_integrated_datasets():
        logger.error("❌ Failed to load datasets")
        return None

    # Prepare training data
    X, y = trainer.prepare_training_data()
    if X is None or y is None:
        logger.error("❌ Failed to prepare training data")
        return None

    # Train enhanced models
    trainer.train_enhanced_models(X, y)

    # Save enhanced models
    model_filename = trainer.save_enhanced_models()

    logger.info("🎉 VulnGuard AI Enhanced Training Complete!")
    logger.info(f"📁 Model file: {model_filename}")

    return model_filename


if __name__ == "__main__":
    main()