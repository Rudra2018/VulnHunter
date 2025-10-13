#!/usr/bin/env python3
"""
🔐 Enhanced Smart Contract Vulnerability Detector
Production-ready implementation with advanced ML techniques
"""

import numpy as np
import pandas as pd
import re
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Advanced ML imports
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, StackingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support
from sklearn.linear_model import LogisticRegression
from imblearn.over_sampling import SMOTE
import xgboost as xgb
import joblib

class EnhancedSmartContractDetector:
    """Production-ready smart contract vulnerability detector with advanced ML"""

    def __init__(self):
        self.output_dir = Path("enhanced_sc_models")
        self.output_dir.mkdir(exist_ok=True)

        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

        # Model storage
        self.models = {}
        self.vectorizers = {}
        self.encoders = {}
        self.scalers = {}
        self.feature_names = []

        # Enhanced vulnerability patterns with real-world examples
        self.vulnerability_patterns = {
            'reentrancy': {
                'severity': 'Critical',
                'patterns': ['call.value', 'send(', 'transfer(', 'external call before state change'],
                'real_examples': [
                    '''
function withdraw(uint256 _amount) public {
    require(balances[msg.sender] >= _amount);

    // Vulnerable: External call before state change
    (bool success, ) = msg.sender.call{value: _amount}("");
    require(success, "Transfer failed");

    // State change after external call - VULNERABLE!
    balances[msg.sender] -= _amount;
    totalSupply -= _amount;
}
                    ''',
                    '''
function emergencyWithdraw() external {
    uint256 balance = userBalances[msg.sender];
    require(balance > 0, "No balance");

    // Reentrancy vulnerability
    payable(msg.sender).transfer(balance);
    userBalances[msg.sender] = 0; // Too late!
}
                    '''
                ],
                'bounty_base': 200000
            },
            'integer_overflow': {
                'severity': 'High',
                'patterns': ['unchecked arithmetic', 'no SafeMath', 'overflow/underflow'],
                'real_examples': [
                    '''
function transfer(address to, uint256 value) public returns (bool) {
    // No overflow protection in Solidity < 0.8.0
    balances[msg.sender] -= value; // Underflow risk!
    balances[to] += value;         // Overflow risk!

    emit Transfer(msg.sender, to, value);
    return true;
}
                    ''',
                    '''
function mint(address to, uint256 amount) external onlyOwner {
    totalSupply += amount;        // Overflow possible
    balances[to] += amount;       // Overflow possible
    emit Mint(to, amount);
}
                    '''
                ],
                'bounty_base': 120000
            },
            'access_control': {
                'severity': 'High',
                'patterns': ['missing access control', 'onlyOwner', 'authorization bypass'],
                'real_examples': [
                    '''
function changeOwner(address newOwner) external {
    // Missing access control!
    owner = newOwner;
    emit OwnerChanged(owner, newOwner);
}

function withdraw() external {
    // Anyone can drain the contract!
    payable(msg.sender).transfer(address(this).balance);
}
                    ''',
                    '''
function emergencyPause() external {
    // Should have onlyOwner modifier!
    paused = true;
    emit EmergencyPause(msg.sender);
}
                    '''
                ],
                'bounty_base': 150000
            },
            'unchecked_call': {
                'severity': 'Medium',
                'patterns': ['unchecked external call', 'ignore return value'],
                'real_examples': [
                    '''
function executeTransaction(address target, bytes memory data) external onlyOwner {
    // Return value not checked!
    target.call(data);
    emit TransactionExecuted(target, data);
}
                    ''',
                    '''
function batchTransfer(address[] memory recipients, uint256[] memory amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        // Ignoring return value
        token.transfer(recipients[i], amounts[i]);
    }
}
                    '''
                ],
                'bounty_base': 60000
            },
            'timestamp_dependence': {
                'severity': 'Medium',
                'patterns': ['block.timestamp', 'now', 'time-based logic'],
                'real_examples': [
                    '''
function lottery() external payable {
    require(msg.value >= 0.1 ether);

    // Weak randomness based on timestamp
    uint256 random = uint256(keccak256(abi.encodePacked(
        block.timestamp,
        block.difficulty,
        msg.sender
    ))) % 100;

    if (random < 50) {
        payable(msg.sender).transfer(msg.value * 2);
    }
}
                    ''',
                    '''
function canClaim() public view returns (bool) {
    // Miners can manipulate timestamp within ~15 seconds
    return block.timestamp > lastClaim[msg.sender] + claimInterval;
}
                    '''
                ],
                'bounty_base': 40000
            },
            'delegatecall_injection': {
                'severity': 'Critical',
                'patterns': ['delegatecall', 'proxy pattern', 'code injection'],
                'real_examples': [
                    '''
contract VulnerableProxy {
    address public implementation;

    function upgrade(address newImplementation) external {
        // Missing access control!
        implementation = newImplementation;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
                    '''
                ],
                'bounty_base': 300000
            }
        }

    def generate_enhanced_dataset(self, n_samples: int = 5000) -> pd.DataFrame:
        """Generate enhanced dataset with diverse real-world patterns"""
        self.logger.info(f"🔐 Generating {n_samples:,} enhanced smart contract samples...")

        # DeFi protocols with tiers
        protocols = {
            'tier1': {'names': ['Uniswap', 'Compound', 'Aave', 'MakerDAO'], 'multiplier': 2.0},
            'tier2': {'names': ['SushiSwap', 'Curve', 'Yearn', 'Synthetix'], 'multiplier': 1.5},
            'tier3': {'names': ['PancakeSwap', 'dYdX', 'Balancer', '1inch'], 'multiplier': 1.0}
        }

        contract_types = {
            'token': ['ERC20', 'ERC721', 'ERC1155'],
            'defi': ['DEX', 'AMM', 'Vault', 'Pool', 'Strategy'],
            'infrastructure': ['Proxy', 'Factory', 'Router', 'Oracle'],
            'governance': ['Governor', 'Timelock', 'Voting']
        }

        all_data = []

        # Generate samples with realistic distribution
        samples_per_vuln = n_samples // len(self.vulnerability_patterns)

        for vuln_type, vuln_info in self.vulnerability_patterns.items():
            for i in range(samples_per_vuln):
                # Select protocol tier
                tier = np.random.choice(['tier1', 'tier2', 'tier3'], p=[0.3, 0.5, 0.2])
                protocol = np.random.choice(protocols[tier]['names'])
                tier_multiplier = protocols[tier]['multiplier']

                # Select contract type
                contract_category = np.random.choice(list(contract_types.keys()))
                contract_type = np.random.choice(contract_types[contract_category])

                # Select real example or generate variation
                if vuln_info['real_examples']:
                    base_code = np.random.choice(vuln_info['real_examples'])
                    # Add variations
                    code_snippet = self._add_code_variations(base_code, vuln_type)
                else:
                    code_snippet = self._generate_synthetic_code(vuln_type)

                # Calculate realistic bounty
                base_bounty = vuln_info['bounty_base']
                final_bounty = base_bounty * tier_multiplier * np.random.uniform(0.7, 1.8)

                # Extract comprehensive features
                features = self._extract_comprehensive_features(code_snippet)

                record = {
                    'id': f"enhanced_{vuln_type}_{i+1}",
                    'vulnerability_type': vuln_type,
                    'severity_level': vuln_info['severity'],
                    'protocol': protocol,
                    'protocol_tier': tier,
                    'contract_type': contract_type,
                    'contract_category': contract_category,
                    'code_snippet': code_snippet,
                    'bounty_amount': round(final_bounty, 2),
                    'description': f"{vuln_info['severity']} {vuln_type} in {protocol} {contract_type}",
                    'cve_score': self._calculate_cve_score(vuln_info['severity']),
                    **features
                }

                all_data.append(record)

        df = pd.DataFrame(all_data)

        # Add some noise and edge cases for robustness
        df = self._add_dataset_noise(df)

        # Save dataset
        csv_path = self.output_dir / f"enhanced_dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(csv_path, index=False)

        self.logger.info(f"✅ Generated {len(df):,} enhanced samples")
        self.logger.info(f"💰 Bounty range: ${df['bounty_amount'].min():,.0f} - ${df['bounty_amount'].max():,.0f}")
        self.logger.info(f"🔐 Vulnerability distribution: {dict(df['vulnerability_type'].value_counts())}")

        return df

    def _extract_comprehensive_features(self, code: str) -> Dict:
        """Extract comprehensive features using advanced analysis"""
        features = {}

        # Basic code metrics
        lines = code.split('\n')
        features['line_count'] = len(lines)
        features['non_empty_lines'] = len([line for line in lines if line.strip()])
        features['comment_lines'] = len([line for line in lines if line.strip().startswith('//')])

        # Function analysis
        functions = re.findall(r'function\s+(\w+)', code, re.IGNORECASE)
        features['function_count'] = len(functions)
        features['public_functions'] = len(re.findall(r'function\s+\w+.*public', code, re.IGNORECASE))
        features['external_functions'] = len(re.findall(r'function\s+\w+.*external', code, re.IGNORECASE))
        features['payable_functions'] = len(re.findall(r'function\s+\w+.*payable', code, re.IGNORECASE))

        # Security-related patterns
        features['require_count'] = len(re.findall(r'require\s*\(', code))
        features['assert_count'] = len(re.findall(r'assert\s*\(', code))
        features['revert_count'] = len(re.findall(r'revert\s*\(', code))

        # External interactions
        features['external_calls'] = len(re.findall(r'\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(', code))
        features['transfer_calls'] = len(re.findall(r'\.transfer\s*\(|\.send\s*\(', code))
        features['low_level_calls'] = len(re.findall(r'\.call\s*\{', code))

        # State variables and storage
        features['state_variables'] = len(re.findall(r'(mapping|uint\d*|int\d*|address|bool|string)\s+(public|private|internal)\s+\w+', code))
        features['mappings'] = len(re.findall(r'mapping\s*\(', code))

        # Modifiers and access control
        features['modifier_count'] = len(re.findall(r'modifier\s+\w+', code))
        features['onlyowner_usage'] = len(re.findall(r'onlyOwner', code, re.IGNORECASE))
        features['msg_sender_usage'] = len(re.findall(r'msg\.sender', code))

        # Arithmetic operations
        features['arithmetic_ops'] = len(re.findall(r'[+\-*/]', code))
        features['unchecked_arithmetic'] = 1 if 'SafeMath' not in code and 'unchecked' not in code else 0

        # Time-related
        features['timestamp_usage'] = len(re.findall(r'block\.timestamp|now', code))
        features['block_number_usage'] = len(re.findall(r'block\.number', code))

        # Assembly and low-level
        features['assembly_blocks'] = len(re.findall(r'assembly\s*\{', code))
        features['inline_assembly'] = 1 if 'assembly' in code else 0

        # Events and logging
        features['event_count'] = len(re.findall(r'event\s+\w+', code))
        features['emit_count'] = len(re.findall(r'emit\s+\w+', code))

        # Advanced patterns
        features['fallback_function'] = 1 if 'fallback' in code else 0
        features['receive_function'] = 1 if 'receive' in code else 0
        features['constructor_present'] = 1 if 'constructor' in code else 0

        # Complexity metrics
        features['cyclomatic_complexity'] = self._calculate_complexity(code)
        features['code_density'] = len(code.replace(' ', '').replace('\n', ''))
        features['avg_line_length'] = np.mean([len(line) for line in lines]) if lines else 0

        return features

    def _calculate_complexity(self, code: str) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity
        complexity_indicators = ['if', 'else', 'for', 'while', 'case', '&&', '||', '?']

        for indicator in complexity_indicators:
            complexity += len(re.findall(indicator, code, re.IGNORECASE))

        return complexity

    def _add_code_variations(self, base_code: str, vuln_type: str) -> str:
        """Add realistic variations to base code"""
        variations = [
            "// Additional security check needed here",
            "uint256 constant MAX_UINT = 2**256 - 1;",
            "event SecurityWarning(address indexed user, string message);",
            "modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }",
        ]

        variation = np.random.choice(variations)
        return f"{variation}\n{base_code}"

    def _generate_synthetic_code(self, vuln_type: str) -> str:
        """Generate synthetic vulnerable code"""
        templates = {
            'reentrancy': '''
function vulnerableWithdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    payable(msg.sender).transfer(amount);
    balances[msg.sender] -= amount;
}''',
            'access_control': '''
function sensitiveFunction() external {
    // Missing access control
    criticalOperation();
}'''
        }

        return templates.get(vuln_type, "function placeholder() {}")

    def _add_dataset_noise(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add realistic noise and edge cases"""
        # Add some contracts with multiple vulnerabilities
        noise_samples = int(len(df) * 0.1)

        for i in range(noise_samples):
            # Randomly combine vulnerabilities
            vuln_types = np.random.choice(list(self.vulnerability_patterns.keys()), size=2, replace=False)
            combined_vuln = f"{vuln_types[0]}+{vuln_types[1]}"

            base_row = df.sample(1).iloc[0].copy()
            base_row['vulnerability_type'] = combined_vuln
            base_row['severity_level'] = 'Critical'
            base_row['bounty_amount'] *= 1.5  # Higher bounty for multiple vulns

            df = pd.concat([df, pd.DataFrame([base_row])], ignore_index=True)

        return df

    def _calculate_cve_score(self, severity: str) -> float:
        """Calculate realistic CVE score"""
        ranges = {
            'Critical': (9.0, 10.0),
            'High': (7.0, 8.9),
            'Medium': (4.0, 6.9),
            'Low': (0.1, 3.9)
        }
        min_score, max_score = ranges[severity]
        return round(np.random.uniform(min_score, max_score), 1)

    def prepare_advanced_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """Prepare advanced feature matrix with feature names"""
        self.logger.info("🔧 Preparing advanced features...")

        feature_names = [
            'line_count', 'non_empty_lines', 'comment_lines', 'function_count',
            'public_functions', 'external_functions', 'payable_functions',
            'require_count', 'assert_count', 'revert_count', 'external_calls',
            'transfer_calls', 'low_level_calls', 'state_variables', 'mappings',
            'modifier_count', 'onlyowner_usage', 'msg_sender_usage',
            'arithmetic_ops', 'unchecked_arithmetic', 'timestamp_usage',
            'block_number_usage', 'assembly_blocks', 'inline_assembly',
            'event_count', 'emit_count', 'fallback_function', 'receive_function',
            'constructor_present', 'cyclomatic_complexity', 'code_density',
            'avg_line_length', 'cve_score', 'protocol_tier_1', 'protocol_tier_2',
            'protocol_tier_3', 'contract_token', 'contract_defi', 'contract_infra',
            'contract_gov', 'severity_score'
        ]

        features = []

        for _, row in df.iterrows():
            # Protocol tier encoding
            tier1 = 1 if row['protocol_tier'] == 'tier1' else 0
            tier2 = 1 if row['protocol_tier'] == 'tier2' else 0
            tier3 = 1 if row['protocol_tier'] == 'tier3' else 0

            # Contract category encoding
            contract_token = 1 if row['contract_category'] == 'token' else 0
            contract_defi = 1 if row['contract_category'] == 'defi' else 0
            contract_infra = 1 if row['contract_category'] == 'infrastructure' else 0
            contract_gov = 1 if row['contract_category'] == 'governance' else 0

            # Severity encoding
            severity_scores = {'Critical': 1.0, 'High': 0.8, 'Medium': 0.6, 'Low': 0.4}
            severity_score = severity_scores[row['severity_level']]

            feature_vector = [
                row['line_count'], row['non_empty_lines'], row['comment_lines'],
                row['function_count'], row['public_functions'], row['external_functions'],
                row['payable_functions'], row['require_count'], row['assert_count'],
                row['revert_count'], row['external_calls'], row['transfer_calls'],
                row['low_level_calls'], row['state_variables'], row['mappings'],
                row['modifier_count'], row['onlyowner_usage'], row['msg_sender_usage'],
                row['arithmetic_ops'], row['unchecked_arithmetic'], row['timestamp_usage'],
                row['block_number_usage'], row['assembly_blocks'], row['inline_assembly'],
                row['event_count'], row['emit_count'], row['fallback_function'],
                row['receive_function'], row['constructor_present'], row['cyclomatic_complexity'],
                row['code_density'], row['avg_line_length'], row['cve_score'],
                tier1, tier2, tier3, contract_token, contract_defi, contract_infra,
                contract_gov, severity_score
            ]

            features.append(feature_vector)

        self.feature_names = feature_names
        return np.array(features), feature_names

    def train_advanced_ensemble(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """Train advanced ensemble with hyperparameter tuning"""
        self.logger.info("🤖 Training advanced ensemble classifier...")

        # Handle imbalanced data with SMOTE
        smote = SMOTE(random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X, y)

        self.logger.info(f"Applied SMOTE: {X.shape[0]} → {X_resampled.shape[0]} samples")

        # Label encoding
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y_resampled)
        self.encoders['vulnerability'] = label_encoder

        # Feature scaling
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_resampled)
        self.scalers['vulnerability'] = scaler

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )

        # Advanced models with hyperparameter tuning
        base_models = [
            ('rf', RandomForestClassifier(random_state=42)),
            ('xgb', xgb.XGBClassifier(random_state=42, eval_metric='mlogloss')),
            ('gb', GradientBoostingClassifier(random_state=42))
        ]

        # Hyperparameter grids
        param_grids = {
            'rf': {
                'n_estimators': [100, 200],
                'max_depth': [10, 15],
                'min_samples_split': [5, 10]
            },
            'xgb': {
                'n_estimators': [100, 200],
                'max_depth': [6, 8],
                'learning_rate': [0.1, 0.2]
            }
        }

        # Tune and train base models
        tuned_models = []

        for name, model in base_models:
            if name in param_grids:
                self.logger.info(f"  Tuning {name}...")
                grid_search = GridSearchCV(
                    model, param_grids[name],
                    cv=3, scoring='accuracy', n_jobs=-1
                )
                grid_search.fit(X_train, y_train)
                best_model = grid_search.best_estimator_
                self.logger.info(f"    Best params: {grid_search.best_params_}")
            else:
                best_model = model
                best_model.fit(X_train, y_train)

            tuned_models.append((name, best_model))

        # Create stacking ensemble
        stacking_classifier = StackingClassifier(
            estimators=tuned_models,
            final_estimator=LogisticRegression(random_state=42),
            cv=StratifiedKFold(5, shuffle=True, random_state=42)
        )

        # Train ensemble
        self.logger.info("  Training stacking ensemble...")
        cv_scores = cross_val_score(stacking_classifier, X_train, y_train, cv=5, scoring='accuracy')
        stacking_classifier.fit(X_train, y_train)

        self.models['vulnerability_classifier'] = stacking_classifier

        # Evaluation
        y_pred_test = stacking_classifier.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_pred_test)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred_test, average='weighted')

        # Classification report
        class_report = classification_report(
            y_test, y_pred_test,
            target_names=label_encoder.classes_,
            output_dict=True
        )

        results = {
            'model_type': 'StackingClassifier',
            'cv_accuracy_mean': cv_scores.mean(),
            'cv_accuracy_std': cv_scores.std(),
            'test_accuracy': test_accuracy,
            'test_precision': precision,
            'test_recall': recall,
            'test_f1': f1,
            'classification_report': class_report,
            'class_names': label_encoder.classes_.tolist(),
            'samples_original': X.shape[0],
            'samples_after_smote': X_resampled.shape[0],
            'features_count': X.shape[1]
        }

        self.logger.info(f"✅ Ensemble trained: CV={cv_scores.mean():.3f}±{cv_scores.std():.3f}, Test={test_accuracy:.3f}")
        return results

    def create_vulnerability_predictor(self, code: str, description: str = "") -> Dict:
        """Predict vulnerabilities in smart contract code"""

        if 'vulnerability_classifier' not in self.models:
            return {'error': 'Model not trained yet'}

        try:
            # Extract features
            features = self._extract_comprehensive_features(code)

            # Create feature vector (using defaults for unknown values)
            feature_vector = [
                features.get('line_count', 0),
                features.get('non_empty_lines', 0),
                features.get('comment_lines', 0),
                features.get('function_count', 0),
                features.get('public_functions', 0),
                features.get('external_functions', 0),
                features.get('payable_functions', 0),
                features.get('require_count', 0),
                features.get('assert_count', 0),
                features.get('revert_count', 0),
                features.get('external_calls', 0),
                features.get('transfer_calls', 0),
                features.get('low_level_calls', 0),
                features.get('state_variables', 0),
                features.get('mappings', 0),
                features.get('modifier_count', 0),
                features.get('onlyowner_usage', 0),
                features.get('msg_sender_usage', 0),
                features.get('arithmetic_ops', 0),
                features.get('unchecked_arithmetic', 0),
                features.get('timestamp_usage', 0),
                features.get('block_number_usage', 0),
                features.get('assembly_blocks', 0),
                features.get('inline_assembly', 0),
                features.get('event_count', 0),
                features.get('emit_count', 0),
                features.get('fallback_function', 0),
                features.get('receive_function', 0),
                features.get('constructor_present', 0),
                features.get('cyclomatic_complexity', 1),
                features.get('code_density', 0),
                features.get('avg_line_length', 0),
                7.0,  # default cve_score
                0, 1, 0,  # protocol tiers (assume tier2)
                0, 1, 0, 0,  # contract categories (assume defi)
                0.8  # default severity score
            ]

            # Scale features
            features_scaled = self.scalers['vulnerability'].transform([feature_vector])

            # Predict
            prediction = self.models['vulnerability_classifier'].predict(features_scaled)[0]
            vulnerability = self.encoders['vulnerability'].inverse_transform([prediction])[0]

            # Get confidence
            probabilities = self.models['vulnerability_classifier'].predict_proba(features_scaled)[0]
            confidence = float(np.max(probabilities))

            # Calculate risk score
            risk_factors = {
                'external_calls': features.get('external_calls', 0) > 0,
                'unchecked_arithmetic': features.get('unchecked_arithmetic', 0) > 0,
                'low_level_calls': features.get('low_level_calls', 0) > 0,
                'assembly_usage': features.get('inline_assembly', 0) > 0,
                'missing_checks': features.get('require_count', 0) == 0
            }

            risk_score = sum(risk_factors.values()) / len(risk_factors) * confidence

            return {
                'vulnerability_type': vulnerability,
                'confidence': confidence,
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'features_detected': features,
                'recommendations': self._get_security_recommendations(vulnerability, features)
            }

        except Exception as e:
            return {'error': f'Prediction failed: {str(e)}'}

    def _get_security_recommendations(self, vulnerability: str, features: Dict) -> List[str]:
        """Get specific security recommendations"""
        recommendations = []

        if vulnerability == 'reentrancy':
            recommendations.extend([
                "Implement checks-effects-interactions pattern",
                "Use reentrancy guard (nonReentrant modifier)",
                "Update state before external calls",
                "Consider using pull over push payment pattern"
            ])
        elif vulnerability == 'integer_overflow':
            recommendations.extend([
                "Use SafeMath library for arithmetic operations",
                "Upgrade to Solidity 0.8+ with built-in overflow checks",
                "Add explicit bounds checking",
                "Use checked arithmetic blocks"
            ])
        elif vulnerability == 'access_control':
            recommendations.extend([
                "Implement proper access control modifiers",
                "Use OpenZeppelin's Ownable or AccessControl",
                "Add require statements for authorization",
                "Consider role-based access control"
            ])

        # Add general recommendations based on features
        if features.get('require_count', 0) == 0:
            recommendations.append("Add input validation with require statements")

        if features.get('external_calls', 0) > 0 and features.get('require_count', 0) == 0:
            recommendations.append("Check return values of external calls")

        return recommendations

    def save_enhanced_models(self):
        """Save all enhanced models and metadata"""
        self.logger.info("💾 Saving enhanced models...")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save models
        for model_name, model in self.models.items():
            model_path = self.output_dir / f"{model_name}_{timestamp}.pkl"
            joblib.dump(model, model_path)

        # Save preprocessors
        for name, obj in {**self.scalers, **self.vectorizers, **self.encoders}.items():
            obj_path = self.output_dir / f"{name}_{timestamp}.pkl"
            joblib.dump(obj, obj_path)

        # Save feature names
        feature_names_path = self.output_dir / f"feature_names_{timestamp}.json"
        with open(feature_names_path, 'w') as f:
            json.dump(self.feature_names, f)

        self.logger.info(f"✅ Enhanced models saved with timestamp: {timestamp}")
        return timestamp

    def run_enhanced_training(self):
        """Run complete enhanced training pipeline"""
        self.logger.info("🚀 Starting enhanced smart contract training...")

        try:
            # Generate enhanced dataset
            df = self.generate_enhanced_dataset(n_samples=3000)

            # Prepare advanced features
            X, feature_names = self.prepare_advanced_features(df)
            y = df['vulnerability_type'].values

            # Train advanced ensemble
            results = self.train_advanced_ensemble(X, y)

            # Save models
            timestamp = self.save_enhanced_models()

            self.logger.info("✅ Enhanced training completed!")

            return {
                'status': 'success',
                'results': results,
                'timestamp': timestamp,
                'dataset_size': len(df),
                'feature_count': len(feature_names)
            }

        except Exception as e:
            self.logger.error(f"❌ Enhanced training failed: {e}")
            return {'status': 'error', 'error': str(e)}

def main():
    """Main execution with real smart contract testing"""
    print("🔐 ENHANCED SMART CONTRACT VULNERABILITY DETECTOR")
    print("=" * 70)

    detector = EnhancedSmartContractDetector()

    # Train the enhanced model
    results = detector.run_enhanced_training()

    if results['status'] == 'success':
        print(f"\n✅ ENHANCED TRAINING COMPLETE!")
        print(f"📊 Dataset: {results['dataset_size']:,} samples")
        print(f"🔧 Features: {results['feature_count']} advanced features")
        print(f"🤖 Model: {results['results']['model_type']}")
        print(f"🎯 Accuracy: {results['results']['test_accuracy']:.3f}")
        print(f"📈 F1-Score: {results['results']['test_f1']:.3f}")
        print(f"💾 Saved: {results['timestamp']}")

        # Test with real vulnerable contract
        print(f"\n🧪 Testing with Real Vulnerable Smart Contract:")
        print("=" * 50)

        vulnerable_contract = '''
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state change (Reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State change happens after external call - TOO LATE!
        balances[msg.sender] -= amount;
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
        '''

        prediction = detector.create_vulnerability_predictor(
            vulnerable_contract,
            "Banking contract with withdraw function"
        )

        if 'error' not in prediction:
            print(f"🔍 Detected Vulnerability: {prediction['vulnerability_type']}")
            print(f"🎯 Confidence: {prediction['confidence']:.2%}")
            print(f"⚠️  Risk Score: {prediction['risk_score']:.2f}")
            print(f"📋 Security Recommendations:")
            for rec in prediction['recommendations']:
                print(f"   • {rec}")
        else:
            print(f"❌ Prediction Error: {prediction['error']}")

    else:
        print(f"\n❌ TRAINING FAILED: {results['error']}")

if __name__ == "__main__":
    main()