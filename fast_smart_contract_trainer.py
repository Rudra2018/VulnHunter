#!/usr/bin/env python3
"""
🔐 Fast Smart Contract Vulnerability Detection Trainer
Optimized for quick training and high accuracy
"""

import numpy as np
import pandas as pd
import re
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# ML imports
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import xgboost as xgb
import joblib

class FastSmartContractTrainer:
    """Fast and efficient smart contract vulnerability trainer"""

    def __init__(self):
        self.output_dir = Path("smart_contract_models")
        self.output_dir.mkdir(exist_ok=True)

        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

        # Model storage
        self.models = {}
        self.vectorizers = {}
        self.encoders = {}
        self.scalers = {}

        # Vulnerability patterns for quick generation
        self.vulnerability_patterns = {
            'reentrancy': {
                'severity': 'Critical',
                'code_template': '''
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}''',
                'bounty_base': 150000
            },
            'integer_overflow': {
                'severity': 'High',
                'code_template': '''
function transfer(address to, uint256 value) public returns (bool) {
    balances[msg.sender] -= value;
    balances[to] += value;
    return true;
}''',
                'bounty_base': 80000
            },
            'access_control': {
                'severity': 'High',
                'code_template': '''
function changeOwner(address newOwner) external {
    owner = newOwner;
}

function emergencyWithdraw() external {
    payable(msg.sender).transfer(address(this).balance);
}''',
                'bounty_base': 100000
            },
            'unchecked_call': {
                'severity': 'Medium',
                'code_template': '''
function executeCall(address target, bytes calldata data) external onlyOwner {
    target.call(data);
    emit CallExecuted(target);
}''',
                'bounty_base': 50000
            },
            'timestamp_dependence': {
                'severity': 'Medium',
                'code_template': '''
function claimReward() external {
    require(block.timestamp > lastClaim[msg.sender] + 1 days);
    if (block.timestamp % 2 == 0) {
        payable(msg.sender).transfer(0.1 ether);
    }
}''',
                'bounty_base': 40000
            }
        }

    def generate_fast_dataset(self, n_samples: int = 2000) -> pd.DataFrame:
        """Generate a smaller, high-quality dataset for fast training"""
        self.logger.info(f"🔐 Generating {n_samples:,} smart contract samples...")

        protocols = ['Uniswap', 'Compound', 'Aave', 'MakerDAO', 'SushiSwap', 'Curve']
        contract_types = ['ERC20', 'Vault', 'DEX', 'Proxy', 'Governor']

        all_data = []

        # Generate balanced samples for each vulnerability type
        vulns_per_type = n_samples // len(self.vulnerability_patterns)

        for vuln_type, vuln_info in self.vulnerability_patterns.items():
            for i in range(vulns_per_type):
                protocol = np.random.choice(protocols)
                contract_type = np.random.choice(contract_types)

                # Calculate bounty with variation
                base_bounty = vuln_info['bounty_base']
                final_bounty = base_bounty * np.random.uniform(0.5, 2.0)

                # Extract basic features from code
                code = vuln_info['code_template']
                features = self._extract_quick_features(code)

                record = {
                    'id': f"sc_{vuln_type}_{i+1}",
                    'vulnerability_type': vuln_type,
                    'severity_level': vuln_info['severity'],
                    'protocol': protocol,
                    'contract_type': contract_type,
                    'code_snippet': code,
                    'bounty_amount': round(final_bounty, 2),
                    'description': f"{vuln_info['severity']} {vuln_type} in {protocol} {contract_type}",
                    **features
                }

                all_data.append(record)

        df = pd.DataFrame(all_data)

        # Save dataset
        csv_path = self.output_dir / f"fast_sc_dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(csv_path, index=False)

        self.logger.info(f"✅ Generated {len(df):,} samples")
        self.logger.info(f"💰 Bounty range: ${df['bounty_amount'].min():,.0f} - ${df['bounty_amount'].max():,.0f}")
        self.logger.info(f"🔐 Vulnerability distribution: {dict(df['vulnerability_type'].value_counts())}")

        return df

    def _extract_quick_features(self, code: str) -> Dict:
        """Extract essential features quickly"""
        return {
            'line_count': len(code.split('\n')),
            'function_count': len(re.findall(r'function\s+\w+', code)),
            'external_calls': len(re.findall(r'\.call\(|\.delegatecall\(|\.send\(|\.transfer\(', code)),
            'require_statements': len(re.findall(r'require\(', code)),
            'has_payable': 1 if 'payable' in code else 0,
            'has_external': 1 if 'external' in code else 0,
            'uses_msg_sender': 1 if 'msg.sender' in code else 0,
            'uses_block_timestamp': 1 if 'block.timestamp' in code else 0,
            'code_length': len(code)
        }

    def prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        """Prepare features for training"""
        self.logger.info("🔧 Preparing features...")

        features = []

        for _, row in df.iterrows():
            # Protocol tier scoring
            tier1_protocols = ['Uniswap', 'Compound', 'Aave', 'MakerDAO']
            protocol_score = 1.0 if row['protocol'] in tier1_protocols else 0.7

            # Contract type scoring
            high_risk_types = ['Vault', 'DEX', 'Proxy']
            contract_score = 1.0 if row['contract_type'] in high_risk_types else 0.6

            # Severity scoring
            severity_scores = {'Critical': 1.0, 'High': 0.8, 'Medium': 0.6, 'Low': 0.4}
            severity_score = severity_scores[row['severity_level']]

            feature_vector = [
                row['line_count'],
                row['function_count'],
                row['external_calls'],
                row['require_statements'],
                row['has_payable'],
                row['has_external'],
                row['uses_msg_sender'],
                row['uses_block_timestamp'],
                row['code_length'],
                protocol_score,
                contract_score,
                severity_score,
                # Vulnerability-specific patterns
                1 if 'call{value:' in row['code_snippet'] or '.call(' in row['code_snippet'] else 0,
                1 if 'delegatecall' in row['code_snippet'] else 0,
                1 if 'onlyOwner' not in row['code_snippet'] and 'require(' not in row['code_snippet'] else 0,
                1 if '-=' in row['code_snippet'] or '+=' in row['code_snippet'] else 0,
                1 if 'block.timestamp' in row['code_snippet'] else 0
            ]

            features.append(feature_vector)

        return np.array(features)

    def train_vulnerability_classifier(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """Train optimized vulnerability classifier"""
        self.logger.info("🤖 Training vulnerability classifier...")

        # Label encoding
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        self.encoders['vulnerability'] = label_encoder

        # Feature scaling
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers['vulnerability'] = scaler

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )

        # Fast but effective models
        models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'xgboost': xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            )
        }

        best_model = None
        best_score = -np.inf
        model_results = {}

        for name, model in models.items():
            self.logger.info(f"  Training {name}...")

            # Quick cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=3, scoring='accuracy')

            # Train and evaluate
            model.fit(X_train, y_train)
            y_pred_test = model.predict(X_test)
            test_accuracy = accuracy_score(y_test, y_pred_test)

            model_results[name] = {
                'cv_accuracy_mean': cv_scores.mean(),
                'cv_accuracy_std': cv_scores.std(),
                'test_accuracy': test_accuracy
            }

            self.logger.info(f"    CV: {cv_scores.mean():.3f}±{cv_scores.std():.3f}, Test: {test_accuracy:.3f}")

            if cv_scores.mean() > best_score:
                best_score = cv_scores.mean()
                best_model = model

        self.models['vulnerability_classifier'] = best_model

        # Final evaluation
        y_pred_final = best_model.predict(X_test)
        class_report = classification_report(
            y_test, y_pred_final,
            target_names=label_encoder.classes_,
            output_dict=True
        )

        results = {
            'best_model': type(best_model).__name__,
            'cv_accuracy_mean': best_score,
            'test_accuracy': accuracy_score(y_test, y_pred_final),
            'classification_report': class_report,
            'class_names': label_encoder.classes_.tolist(),
            'model_comparison': model_results
        }

        self.logger.info(f"✅ Best model: {results['best_model']} (Acc={best_score:.3f})")
        return results

    def train_severity_predictor(self, df: pd.DataFrame) -> Dict:
        """Train fast severity predictor"""
        self.logger.info("🎯 Training severity predictor...")

        # Prepare text features
        descriptions = []
        severities = []

        for _, row in df.iterrows():
            text = f"{row['code_snippet']} {row['description']} {row['vulnerability_type']}"
            descriptions.append(text)
            severities.append(row['severity_level'])

        # Fast text vectorization
        vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            stop_words=None
        )

        X_text = vectorizer.fit_transform(descriptions)
        self.vectorizers['severity'] = vectorizer

        # Encode severity
        severity_encoder = LabelEncoder()
        y_severity = severity_encoder.fit_transform(severities)
        self.encoders['severity'] = severity_encoder

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_text.toarray(), y_severity, test_size=0.2, random_state=42, stratify=y_severity
        )

        # Fast model
        model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)

        # Train and evaluate
        cv_scores = cross_val_score(model, X_train, y_train, cv=3, scoring='accuracy')
        model.fit(X_train, y_train)
        self.models['severity_predictor'] = model

        y_pred_test = model.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_pred_test)

        results = {
            'model_type': type(model).__name__,
            'cv_accuracy_mean': cv_scores.mean(),
            'test_accuracy': test_accuracy,
            'class_names': severity_encoder.classes_.tolist()
        }

        self.logger.info(f"✅ Severity predictor: Acc={cv_scores.mean():.3f}")
        return results

    def validate_models(self) -> Dict:
        """Quick validation with test cases"""
        self.logger.info("📋 Validating models...")

        test_cases = [
            {
                'code': 'function withdraw() { msg.sender.call{value: amount}(""); balance -= amount; }',
                'expected_vuln': 'reentrancy',
                'expected_severity': 'Critical'
            },
            {
                'code': 'function transfer(uint256 value) { balances[msg.sender] -= value; }',
                'expected_vuln': 'integer_overflow',
                'expected_severity': 'High'
            }
        ]

        correct_vuln = 0
        correct_severity = 0

        for case in test_cases:
            try:
                # Extract features
                features = self._extract_quick_features(case['code'])
                feature_vector = [
                    features['line_count'], features['function_count'], features['external_calls'],
                    features['require_statements'], features['has_payable'], features['has_external'],
                    features['uses_msg_sender'], features['uses_block_timestamp'], features['code_length'],
                    0.7, 0.7, 0.8,  # default scores
                    1 if '.call(' in case['code'] else 0,
                    1 if 'delegatecall' in case['code'] else 0,
                    1 if 'require(' not in case['code'] else 0,
                    1 if '-=' in case['code'] else 0,
                    1 if 'block.timestamp' in case['code'] else 0
                ]

                # Predict vulnerability
                if 'vulnerability_classifier' in self.models:
                    features_scaled = self.scalers['vulnerability'].transform([feature_vector])
                    vuln_pred = self.models['vulnerability_classifier'].predict(features_scaled)[0]
                    vuln_name = self.encoders['vulnerability'].inverse_transform([vuln_pred])[0]

                    if vuln_name == case['expected_vuln']:
                        correct_vuln += 1

                # Predict severity
                if 'severity_predictor' in self.models:
                    text_features = self.vectorizers['severity'].transform([case['code']])
                    sev_pred = self.models['severity_predictor'].predict(text_features.toarray())[0]
                    sev_name = self.encoders['severity'].inverse_transform([sev_pred])[0]

                    if sev_name == case['expected_severity']:
                        correct_severity += 1

            except Exception as e:
                self.logger.error(f"Validation error: {e}")

        results = {
            'vulnerability_accuracy': correct_vuln / len(test_cases),
            'severity_accuracy': correct_severity / len(test_cases)
        }

        self.logger.info(f"✅ Validation - Vuln: {results['vulnerability_accuracy']:.1%}, Severity: {results['severity_accuracy']:.1%}")
        return results

    def save_models(self):
        """Save all models"""
        self.logger.info("💾 Saving models...")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save models
        for model_name, model in self.models.items():
            model_path = self.output_dir / f"{model_name}_{timestamp}.pkl"
            joblib.dump(model, model_path)

        # Save preprocessors
        for name, obj in {**self.scalers, **self.vectorizers, **self.encoders}.items():
            obj_path = self.output_dir / f"{name}_{timestamp}.pkl"
            joblib.dump(obj, obj_path)

        self.logger.info(f"✅ Models saved with timestamp: {timestamp}")
        return timestamp

    def run_fast_training(self):
        """Run complete fast training pipeline"""
        self.logger.info("🚀 Starting fast smart contract training...")

        try:
            # Generate dataset
            df = self.generate_fast_dataset(n_samples=2000)

            # Prepare features
            X = self.prepare_features(df)
            y = df['vulnerability_type'].values

            # Train models
            vuln_results = self.train_vulnerability_classifier(X, y)
            severity_results = self.train_severity_predictor(df)

            # Validate
            validation_results = self.validate_models()

            # Save models
            timestamp = self.save_models()

            self.logger.info("✅ Fast training completed!")

            return {
                'status': 'success',
                'vulnerability_results': vuln_results,
                'severity_results': severity_results,
                'validation': validation_results,
                'timestamp': timestamp
            }

        except Exception as e:
            self.logger.error(f"❌ Training failed: {e}")
            return {'status': 'error', 'error': str(e)}

def main():
    """Main execution"""
    print("🔐 FAST SMART CONTRACT VULNERABILITY TRAINER")
    print("=" * 60)

    trainer = FastSmartContractTrainer()
    results = trainer.run_fast_training()

    if results['status'] == 'success':
        print(f"\n✅ TRAINING COMPLETE!")
        print(f"🤖 Vulnerability Classifier: {results['vulnerability_results']['best_model']}")
        print(f"   Accuracy: {results['vulnerability_results']['cv_accuracy_mean']:.3f}")
        print(f"🎯 Severity Predictor: {results['severity_results']['model_type']}")
        print(f"   Accuracy: {results['severity_results']['cv_accuracy_mean']:.3f}")
        print(f"📋 Validation Accuracy: {results['validation']['vulnerability_accuracy']:.1%}")
        print(f"💾 Models saved: {results['timestamp']}")
    else:
        print(f"\n❌ TRAINING FAILED: {results['error']}")

if __name__ == "__main__":
    main()