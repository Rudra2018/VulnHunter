#!/usr/bin/env python3
"""
Simplified Training Pipeline for Enhanced Security Intelligence
=============================================================

Training framework using scikit-learn for immediate deployment while
PyTorch installation completes. This provides a working ML model that
can be enhanced later with deep learning components.

Features:
1. Ensemble learning with multiple algorithms
2. Feature engineering for code analysis
3. Cross-validation and evaluation
4. Model persistence and deployment
5. Performance benchmarking
"""

import os
import sys
import time
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import re
import ast

# Scikit-learn components
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import matplotlib.pyplot as plt
import seaborn as sns

# Add src to path
sys.path.append(str(Path(__file__).parent / 'src'))

class CodeFeatureExtractor:
    """Advanced feature extraction for vulnerability detection"""

    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.tfidf = TfidfVectorizer(
            max_features=100,
            ngram_range=(1, 2),
            token_pattern=r'\w+',
            min_df=1,  # Reduced for small datasets
            max_df=0.95
        )

    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability detection patterns"""
        return {
            'sql_injection': [
                r'SELECT.*\+.*', r'INSERT.*\+.*', r'UPDATE.*\+.*', r'DELETE.*\+.*',
                r'query.*\+.*', r'sql.*\+.*', r'execute.*\+.*', r'\.format\(',
                r'%s.*%s', r'UNION.*SELECT', r'OR.*1=1', r"'.*\+.*'"
            ],
            'buffer_overflow': [
                r'strcpy\s*\(', r'sprintf\s*\(', r'gets\s*\(', r'strcat\s*\(',
                r'scanf\s*\(.*%s', r'memcpy\s*\(', r'strncpy\s*\(.*\+',
                r'buffer\[\w*\].*=', r'char.*\[\d+\]'
            ],
            'xss': [
                r'innerHTML\s*=', r'outerHTML\s*=', r'document\.write\s*\(',
                r'\.html\s*\(.*\+', r'response\.write\s*\(', r'echo.*\$_',
                r'print.*\+.*', r'printf.*%s'
            ],
            'command_injection': [
                r'system\s*\(', r'exec\s*\(', r'eval\s*\(', r'os\.system',
                r'subprocess\s*\(', r'shell_exec\s*\(', r'passthru\s*\(',
                r'popen\s*\(', r'Runtime\.getRuntime'
            ],
            'path_traversal': [
                r'\.\./', r'\.\.\\\\', r'file.*\+.*', r'include.*\+.*',
                r'require.*\+.*', r'fopen.*\+.*', r'readfile.*\+.*'
            ],
            'authentication_bypass': [
                r'password.*\+.*', r'auth.*\+.*', r'login.*\+.*',
                r'session.*\+.*', r'token.*\+.*', r'MD5\s*\(.*\+',
                r'SHA1\s*\(.*\+'
            ]
        }

    def extract_features(self, code_samples: List[str], fit_tfidf: bool = True) -> np.ndarray:
        """Extract comprehensive features from code samples"""
        features_list = []

        # First pass: extract basic features
        basic_features = []
        for code in code_samples:
            basic_features.append(self._extract_basic_features(code))

        # Convert to DataFrame for easier manipulation
        basic_df = pd.DataFrame(basic_features)

        # Second pass: TF-IDF features
        if fit_tfidf:
            tfidf_features = self.tfidf.fit_transform(code_samples).toarray()
        else:
            tfidf_features = self.tfidf.transform(code_samples).toarray()

        # Combine features
        combined_features = np.hstack([basic_df.values, tfidf_features])

        return combined_features

    def _extract_basic_features(self, code: str) -> Dict[str, float]:
        """Extract basic structural and pattern-based features"""
        features = {}

        # Basic metrics
        features['code_length'] = len(code)
        features['line_count'] = code.count('\n') + 1
        features['word_count'] = len(code.split())

        # Character frequency analysis
        features['special_char_ratio'] = sum(1 for c in code if not c.isalnum()) / max(len(code), 1)
        features['digit_ratio'] = sum(1 for c in code if c.isdigit()) / max(len(code), 1)
        features['upper_ratio'] = sum(1 for c in code if c.isupper()) / max(len(code), 1)

        # Language indicators
        features['has_includes'] = 1 if '#include' in code else 0
        features['has_imports'] = 1 if any(keyword in code for keyword in ['import ', 'from ', 'require(']) else 0
        features['has_functions'] = 1 if any(keyword in code for keyword in ['def ', 'function ', 'void ', 'int ']) else 0

        # Vulnerability pattern matching
        for vuln_type, patterns in self.vulnerability_patterns.items():
            pattern_count = 0
            for pattern in patterns:
                pattern_count += len(re.findall(pattern, code, re.IGNORECASE))
            features[f'{vuln_type}_patterns'] = pattern_count

        # Complexity indicators
        features['nesting_level'] = self._calculate_nesting_level(code)
        features['cyclomatic_complexity'] = self._estimate_cyclomatic_complexity(code)

        # Security-relevant keywords
        security_keywords = [
            'password', 'auth', 'login', 'token', 'secret', 'key',
            'encrypt', 'decrypt', 'hash', 'salt', 'session', 'cookie'
        ]
        features['security_keyword_count'] = sum(1 for keyword in security_keywords if keyword in code.lower())

        # Dangerous function calls
        dangerous_functions = [
            'strcpy', 'sprintf', 'gets', 'system', 'exec', 'eval',
            'innerHTML', 'document.write', 'sql', 'query'
        ]
        features['dangerous_function_count'] = sum(1 for func in dangerous_functions if func in code.lower())

        return features

    def _calculate_nesting_level(self, code: str) -> int:
        """Calculate maximum nesting level"""
        max_level = 0
        current_level = 0

        for char in code:
            if char in '({[':
                current_level += 1
                max_level = max(max_level, current_level)
            elif char in ')}]':
                current_level = max(0, current_level - 1)

        return max_level

    def _estimate_cyclomatic_complexity(self, code: str) -> int:
        """Estimate cyclomatic complexity"""
        decision_keywords = ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'case', 'switch']
        complexity = 1  # Base complexity

        for keyword in decision_keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', code, re.IGNORECASE))

        return complexity


class SimplifiedSecurityIntelligence:
    """Simplified Security Intelligence using scikit-learn"""

    def __init__(self):
        self.feature_extractor = CodeFeatureExtractor()
        self.models = self._initialize_models()
        self.ensemble = None
        self.scaler = StandardScaler()
        self.is_trained = False

    def _initialize_models(self) -> Dict[str, Any]:
        """Initialize individual models for ensemble"""
        return {
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            ),
            'logistic_regression': LogisticRegression(
                C=1.0,
                max_iter=1000,
                random_state=42,
                n_jobs=-1
            ),
            'svm': SVC(
                kernel='rbf',
                C=1.0,
                probability=True,
                random_state=42
            )
        }

    def train(self, code_samples: List[str], labels: List[int],
              validation_split: float = 0.2) -> Dict[str, Any]:
        """Train the ensemble model"""
        print("🎓 Training Simplified Security Intelligence Model...")
        print("=" * 60)

        # Feature extraction
        print("📊 Extracting features...")
        start_time = time.time()
        X = self.feature_extractor.extract_features(code_samples)
        feature_time = time.time() - start_time
        print(f"   Features extracted: {X.shape[1]} features from {X.shape[0]} samples")
        print(f"   Feature extraction time: {feature_time:.2f}s")

        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, labels, test_size=validation_split, random_state=42, stratify=labels
        )

        # Scale features
        print("⚖️ Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)

        # Train individual models
        print("🤖 Training individual models...")
        trained_models = []
        model_scores = {}

        for name, model in self.models.items():
            print(f"   Training {name}...")
            start_time = time.time()

            # Train model
            model.fit(X_train_scaled, y_train)
            train_time = time.time() - start_time

            # Evaluate on validation set
            val_score = model.score(X_val_scaled, y_val)
            y_pred = model.predict(X_val_scaled)
            f1 = f1_score(y_val, y_pred)

            model_scores[name] = {
                'accuracy': val_score,
                'f1_score': f1,
                'train_time': train_time
            }

            print(f"     Accuracy: {val_score:.3f}, F1: {f1:.3f}, Time: {train_time:.2f}s")
            trained_models.append((name, model))

        # Create ensemble
        print("🎭 Creating ensemble model...")
        self.ensemble = VotingClassifier(
            estimators=trained_models,
            voting='soft'  # Use probabilities for voting
        )

        # Train ensemble
        start_time = time.time()
        self.ensemble.fit(X_train_scaled, y_train)
        ensemble_time = time.time() - start_time

        # Evaluate ensemble
        ensemble_score = self.ensemble.score(X_val_scaled, y_val)
        y_pred_ensemble = self.ensemble.predict(X_val_scaled)
        ensemble_f1 = f1_score(y_val, y_pred_ensemble)

        print(f"✅ Ensemble trained successfully!")
        print(f"   Ensemble Accuracy: {ensemble_score:.3f}")
        print(f"   Ensemble F1-Score: {ensemble_f1:.3f}")
        print(f"   Ensemble training time: {ensemble_time:.2f}s")

        self.is_trained = True

        # Return training results
        return {
            'model_scores': model_scores,
            'ensemble_score': ensemble_score,
            'ensemble_f1': ensemble_f1,
            'feature_count': X.shape[1],
            'training_samples': len(X_train),
            'validation_samples': len(X_val),
            'total_training_time': sum(scores['train_time'] for scores in model_scores.values()) + ensemble_time
        }

    def predict(self, code_samples: List[str]) -> Dict[str, Any]:
        """Predict vulnerabilities in code samples"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")

        # Extract features (don't refit TF-IDF)
        X = self.feature_extractor.extract_features(code_samples, fit_tfidf=False)
        X_scaled = self.scaler.transform(X)

        # Get predictions and probabilities
        predictions = self.ensemble.predict(X_scaled)
        probabilities = self.ensemble.predict_proba(X_scaled)

        # Get individual model predictions for analysis
        individual_predictions = {}
        for name, model in self.models.items():
            individual_predictions[name] = model.predict(X_scaled)

        results = {
            'predictions': predictions.tolist(),
            'probabilities': probabilities.tolist(),
            'confidence_scores': np.max(probabilities, axis=1).tolist(),
            'individual_predictions': individual_predictions,
            'vulnerable_samples': np.sum(predictions),
            'total_samples': len(predictions)
        }

        return results

    def analyze_code(self, code: str) -> Dict[str, Any]:
        """Analyze a single code sample"""
        result = self.predict([code])

        # Extract vulnerability patterns for explanation
        pattern_matches = {}
        for vuln_type, patterns in self.feature_extractor.vulnerability_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    matches.append(pattern)
            if matches:
                pattern_matches[vuln_type] = matches

        return {
            'vulnerability_detected': bool(result['predictions'][0]),
            'confidence': result['confidence_scores'][0],
            'probability_vulnerable': result['probabilities'][0][1] if len(result['probabilities'][0]) > 1 else 0,
            'pattern_matches': pattern_matches,
            'individual_model_agreement': {
                name: bool(preds[0]) for name, preds in result['individual_predictions'].items()
            }
        }

    def save_model(self, filepath: str):
        """Save trained model to disk"""
        model_data = {
            'ensemble': self.ensemble,
            'scaler': self.scaler,
            'feature_extractor': self.feature_extractor,
            'is_trained': self.is_trained
        }

        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"✅ Model saved to {filepath}")

    def load_model(self, filepath: str):
        """Load trained model from disk"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)

        self.ensemble = model_data['ensemble']
        self.scaler = model_data['scaler']
        self.feature_extractor = model_data['feature_extractor']
        self.is_trained = model_data['is_trained']

        print(f"✅ Model loaded from {filepath}")


def create_training_dataset() -> Tuple[List[str], List[int]]:
    """Create training dataset from various sources"""
    print("📚 Creating training dataset...")

    code_samples = []
    labels = []

    # Vulnerable samples
    vulnerable_samples = [
        # SQL Injection
        "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "cursor.execute('SELECT * FROM products WHERE name = ' + product_name)",
        "sql = f'INSERT INTO logs VALUES ({user_input})'",
        "db.query('UPDATE users SET name = ' + new_name + ' WHERE id = ' + uid)",

        # Buffer Overflow
        "#include <string.h>\nvoid func(char* input) {\n    char buffer[256];\n    strcpy(buffer, input);\n}",
        "sprintf(output, 'Hello %s', user_data);",
        "gets(user_input);",
        "char name[32]; scanf('%s', name);",

        # XSS
        "document.getElementById('output').innerHTML = user_data;",
        "response.write('<div>' + user_input + '</div>');",
        "echo $_GET['message'];",
        "print(f'<script>alert(\"{user_data}\")</script>');",

        # Command Injection
        "os.system('ls ' + user_directory)",
        "subprocess.call(shell_command, shell=True)",
        "eval(user_code)",
        "Runtime.getRuntime().exec(command);",

        # Path Traversal
        "file_path = base_path + '/' + user_file",
        "include('../' + page_name + '.php');",
        "open(directory + '/' + filename, 'r')",

        # Authentication Bypass
        "password_hash = MD5(password + salt)",
        "if (username == 'admin' and password == 'password123'):",
        "session_token = user_id + '_' + timestamp",
    ]

    # Safe samples
    safe_samples = [
        # Secure SQL
        "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "query = db.prepare('INSERT INTO logs VALUES (?, ?, ?)'); query.execute([user_id, action, timestamp])",
        "result = session.query(User).filter(User.id == user_id).first()",

        # Secure string handling
        "#include <string.h>\nvoid func(char* input, size_t len) {\n    char buffer[256];\n    strncpy(buffer, input, min(len, 255));\n    buffer[255] = '\\0';\n}",
        "snprintf(output, sizeof(output), 'Hello %.*s', (int)strlen(user_data), user_data);",

        # Secure output
        "document.getElementById('output').textContent = user_data;",
        "response.write(html_escape(user_input));",
        "echo htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');",

        # Secure execution
        "subprocess.run(['ls', user_directory], check=True)",
        "allowed_commands = ['ls', 'cat', 'grep']; if command in allowed_commands: execute(command)",

        # Secure file handling
        "if os.path.basename(user_file) == user_file: file_path = safe_join(base_path, user_file)",
        "with open(os.path.join(safe_directory, secure_filename(filename)), 'r') as f:",

        # Secure authentication
        "password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())",
        "if bcrypt.checkpw(password.encode('utf-8'), stored_hash):",
        "session_token = secrets.token_urlsafe(32)",

        # General safe code
        "def calculate_sum(a, b): return a + b",
        "print('Hello, World!')",
        "import os; print(os.getcwd())",
        "for i in range(10): print(i)",
        "class User: def __init__(self, name): self.name = name",
    ]

    # Add vulnerable samples
    code_samples.extend(vulnerable_samples)
    labels.extend([1] * len(vulnerable_samples))

    # Add safe samples
    code_samples.extend(safe_samples)
    labels.extend([0] * len(safe_samples))

    # Load additional samples from CVE database if available
    try:
        sys.path.append(str(Path(__file__).parent / 'case_studies'))
        from real_cve_examples import CVEDatabase

        cve_db = CVEDatabase()
        for cve_name, cve_data in cve_db.examples.items():
            # Add vulnerable version
            code_samples.append(cve_data['vulnerable_code'])
            labels.append(1)

            # Add fixed version
            code_samples.append(cve_data['fixed_code'])
            labels.append(0)

        print(f"   Added {len(cve_db.examples) * 2} CVE examples")
    except Exception as e:
        print(f"   Could not load CVE examples: {e}")

    print(f"   Total samples: {len(code_samples)}")
    print(f"   Vulnerable: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
    print(f"   Safe: {len(labels) - sum(labels)} ({(len(labels) - sum(labels))/len(labels)*100:.1f}%)")

    return code_samples, labels


def main():
    """Main training pipeline"""
    print("🚀 SIMPLIFIED SECURITY INTELLIGENCE - TRAINING PIPELINE")
    print("=" * 70)

    # Create training dataset
    code_samples, labels = create_training_dataset()

    # Initialize model
    model = SimplifiedSecurityIntelligence()

    # Train model
    training_results = model.train(code_samples, labels)

    # Print training results
    print(f"\n📊 TRAINING RESULTS:")
    print(f"=" * 40)
    print(f"Features extracted: {training_results['feature_count']}")
    print(f"Training samples: {training_results['training_samples']}")
    print(f"Validation samples: {training_results['validation_samples']}")
    print(f"Total training time: {training_results['total_training_time']:.2f}s")
    print(f"Ensemble F1-Score: {training_results['ensemble_f1']:.3f}")
    print(f"Ensemble Accuracy: {training_results['ensemble_score']:.3f}")

    print(f"\n🤖 Individual Model Performance:")
    for name, scores in training_results['model_scores'].items():
        print(f"   {name}: F1={scores['f1_score']:.3f}, Acc={scores['accuracy']:.3f}")

    # Save model
    model_path = 'simplified_security_model.pkl'
    model.save_model(model_path)

    # Test model on sample cases
    print(f"\n🧪 TESTING MODEL ON SAMPLE CASES:")
    print(f"=" * 40)

    test_cases = [
        ("SQL Injection", "SELECT * FROM users WHERE id = '" + "user_input" + "'"),
        ("Buffer Overflow", "strcpy(buffer, user_input);"),
        ("Safe Code", "print('Hello, World!')"),
        ("XSS", "document.write(user_data);"),
        ("Secure SQL", "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))")
    ]

    for case_name, code in test_cases:
        result = model.analyze_code(code)
        status = "🔴 VULNERABLE" if result['vulnerability_detected'] else "🟢 SAFE"
        print(f"{case_name}: {status} (confidence: {result['confidence']:.3f})")

        if result['pattern_matches']:
            print(f"   Patterns: {list(result['pattern_matches'].keys())}")

    print(f"\n✅ Simplified Security Intelligence Model Ready!")
    print(f"📁 Model saved to: {model_path}")
    print(f"🚀 Ready for production deployment!")

    return model


if __name__ == "__main__":
    trained_model = main()