#!/usr/bin/env python3
"""
🔐 SMART CONTRACT VULNERABILITY DETECTION TRAINER
Specialized ML training for Solidity smart contract security analysis
"""

import numpy as np
import pandas as pd
import re
import ast
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import hashlib

# ML imports
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler, MultiLabelBinarizer
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix, roc_auc_score
)
from sklearn.multioutput import MultiOutputClassifier
from sklearn.neural_network import MLPClassifier
import xgboost as xgb
import joblib
import warnings
warnings.filterwarnings('ignore')

class SmartContractVulnTrainer:
    """Advanced smart contract vulnerability detection trainer"""

    def __init__(self, output_dir="smart_contract_models"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Setup logging
        self.logger = self._setup_logging()

        # Model storage
        self.models = {}
        self.vectorizers = {}
        self.encoders = {}
        self.scalers = {}

        # Training results
        self.training_results = {}

        # Smart contract vulnerability categories
        self.vulnerability_categories = {
            'reentrancy': {
                'severity': 'Critical',
                'patterns': ['call.value', 'send(', 'transfer(', 'external call'],
                'description': 'Recursive calling vulnerability allowing state manipulation'
            },
            'integer_overflow': {
                'severity': 'High',
                'patterns': ['++', '--', 'SafeMath', 'unchecked', 'overflow'],
                'description': 'Arithmetic operations that can exceed variable limits'
            },
            'unchecked_call': {
                'severity': 'Medium',
                'patterns': ['call(', '.call', 'delegatecall', 'staticcall'],
                'description': 'External calls without proper return value checking'
            },
            'access_control': {
                'severity': 'High',
                'patterns': ['onlyOwner', 'modifier', 'require', 'msg.sender'],
                'description': 'Improper access restrictions and authorization'
            },
            'timestamp_dependence': {
                'severity': 'Medium',
                'patterns': ['block.timestamp', 'now', 'block.number'],
                'description': 'Logic dependent on manipulable blockchain timestamps'
            },
            'tx_origin': {
                'severity': 'Medium',
                'patterns': ['tx.origin', 'msg.sender'],
                'description': 'Using tx.origin for authorization instead of msg.sender'
            },
            'uninitialized_storage': {
                'severity': 'High',
                'patterns': ['storage', 'uninitialized', 'pointer'],
                'description': 'Storage pointers that are not properly initialized'
            },
            'delegatecall_injection': {
                'severity': 'Critical',
                'patterns': ['delegatecall', 'callcode', 'assembly'],
                'description': 'Unsafe use of delegatecall allowing code injection'
            },
            'short_address': {
                'severity': 'Medium',
                'patterns': ['msg.data.length', 'address', 'parameter'],
                'description': 'Missing validation of address parameter length'
            },
            'dos_gas_limit': {
                'severity': 'Medium',
                'patterns': ['gas', 'loop', 'array', 'unbounded'],
                'description': 'Operations that can exceed gas limits causing DoS'
            },
            'random_weakness': {
                'severity': 'High',
                'patterns': ['random', 'blockhash', 'keccak256', 'predictable'],
                'description': 'Weak randomness that can be predicted or manipulated'
            },
            'front_running': {
                'severity': 'Medium',
                'patterns': ['mempool', 'transaction', 'order', 'MEV'],
                'description': 'Susceptible to transaction ordering manipulation'
            }
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('SmartContractVuln')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def generate_smart_contract_dataset(self, n_samples: int = 5000) -> pd.DataFrame:
        """Generate realistic smart contract vulnerability dataset"""
        self.logger.info(f"🔐 Generating {n_samples:,} smart contract vulnerability samples...")

        # DeFi protocols and contract types
        defi_protocols = [
            'Uniswap', 'SushiSwap', 'Compound', 'Aave', 'MakerDAO', 'Curve',
            'Yearn', 'Synthetix', 'Balancer', '1inch', 'PancakeSwap', 'dYdX',
            'Convex', 'Frax', 'Liquity', 'Euler', 'Rari', 'Alpha Homora'
        ]

        contract_types = [
            'ERC20', 'ERC721', 'ERC1155', 'Proxy', 'Factory', 'Router',
            'Pool', 'Vault', 'Strategy', 'Governor', 'Timelock', 'Oracle',
            'Bridge', 'Staking', 'Farming', 'Lending', 'DEX', 'AMM'
        ]

        # Generate samples
        all_data = []

        for i in range(n_samples):
            # Select vulnerability type
            vuln_type = np.random.choice(list(self.vulnerability_categories.keys()))
            vuln_info = self.vulnerability_categories[vuln_type]

            # Select protocol and contract type
            protocol = np.random.choice(defi_protocols)
            contract_type = np.random.choice(contract_types)

            # Generate realistic code snippet
            code_snippet = self._generate_vulnerable_code(vuln_type, vuln_info)

            # Calculate severity score and bounty
            severity_scores = {'Low': 0.3, 'Medium': 0.6, 'High': 0.8, 'Critical': 1.0}
            severity_score = severity_scores[vuln_info['severity']]

            # Generate bounty based on severity and protocol tier
            tier1_protocols = ['Uniswap', 'Compound', 'Aave', 'MakerDAO']
            tier2_protocols = ['SushiSwap', 'Curve', 'Yearn', 'Synthetix']

            if protocol in tier1_protocols:
                base_bounty = np.random.uniform(50000, 500000)
            elif protocol in tier2_protocols:
                base_bounty = np.random.uniform(25000, 250000)
            else:
                base_bounty = np.random.uniform(10000, 100000)

            final_bounty = base_bounty * severity_score * np.random.uniform(0.8, 1.3)

            # Generate additional features
            line_count = len(code_snippet.split('\n'))
            complexity_score = min(1.0, line_count / 50.0)

            # Function signatures and patterns
            function_patterns = self._extract_function_patterns(code_snippet)

            record = {
                'id': f"sc_{i+1}",
                'vulnerability_type': vuln_type,
                'severity_level': vuln_info['severity'],
                'protocol': protocol,
                'contract_type': contract_type,
                'code_snippet': code_snippet,
                'bounty_amount': round(final_bounty, 2),
                'line_count': line_count,
                'complexity_score': complexity_score,
                'severity_score': severity_score,
                'function_count': function_patterns['function_count'],
                'modifier_count': function_patterns['modifier_count'],
                'external_calls': function_patterns['external_calls'],
                'state_variables': function_patterns['state_variables'],
                'description': f"{vuln_info['severity']} {vuln_type} vulnerability in {protocol} {contract_type} contract",
                'cve_equivalent': self._generate_cve_score(vuln_info['severity']),
                'gas_complexity': np.random.uniform(0.1, 1.0),
                'audit_status': np.random.choice(['audited', 'unaudited'], p=[0.7, 0.3])
            }

            all_data.append(record)

        df = pd.DataFrame(all_data)

        # Save dataset
        csv_path = self.output_dir / f"smart_contract_vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(csv_path, index=False)

        self.logger.info(f"✅ Generated {len(df):,} smart contract vulnerability samples")
        self.logger.info(f"💰 Bounty range: ${df['bounty_amount'].min():,.0f} - ${df['bounty_amount'].max():,.0f}")
        self.logger.info(f"🔐 Vulnerability distribution: {dict(df['vulnerability_type'].value_counts())}")

        return df

    def _generate_vulnerable_code(self, vuln_type: str, vuln_info: Dict) -> str:
        """Generate realistic vulnerable Solidity code snippets"""

        code_templates = {
            'reentrancy': '''
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");

    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");

    balances[msg.sender] -= amount;
    totalSupply -= amount;
}

mapping(address => uint256) public balances;
uint256 public totalSupply;
            ''',

            'integer_overflow': '''
function transfer(address to, uint256 value) public returns (bool) {
    balances[msg.sender] -= value;
    balances[to] += value;

    emit Transfer(msg.sender, to, value);
    return true;
}

mapping(address => uint256) public balances;
            ''',

            'unchecked_call': '''
function executeTransaction(address target, bytes memory data) public onlyOwner {
    target.call(data);
    emit TransactionExecuted(target, data);
}

modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}
            ''',

            'access_control': '''
function changeOwner(address newOwner) public {
    owner = newOwner;
    emit OwnerChanged(owner, newOwner);
}

function withdraw() public {
    payable(msg.sender).transfer(address(this).balance);
}

address public owner;
            ''',

            'timestamp_dependence': '''
function claimReward() public {
    require(block.timestamp > lastClaimTime[msg.sender] + 1 days, "Too early");
    require(rewardPool > 0, "No rewards available");

    uint256 reward = calculateReward(msg.sender);
    lastClaimTime[msg.sender] = block.timestamp;

    payable(msg.sender).transfer(reward);
}

mapping(address => uint256) public lastClaimTime;
uint256 public rewardPool;
            ''',

            'delegatecall_injection': '''
function upgrade(address newImplementation) public onlyOwner {
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

address public implementation;
            ''',

            'uninitialized_storage': '''
function processArray(uint256[] memory data) public {
    uint256[] storage localArray;

    for (uint i = 0; i < data.length; i++) {
        localArray.push(data[i]);
    }

    emit ArrayProcessed(localArray.length);
}

uint256[] public storedData;
            ''',

            'random_weakness': '''
function generateRandom() public view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(
        block.timestamp,
        block.difficulty,
        msg.sender
    ))) % 100;
}

function lottery() public payable {
    require(msg.value >= 0.1 ether, "Minimum bet required");

    uint256 random = generateRandom();
    if (random < 50) {
        payable(msg.sender).transfer(msg.value * 2);
    }
}
            '''
        }

        base_code = code_templates.get(vuln_type, '''
function vulnerableFunction() public {
    // Generic vulnerable function
    require(msg.sender != address(0), "Invalid sender");

    uint256 value = someCalculation();
    balances[msg.sender] += value;
}

mapping(address => uint256) public balances;
        ''')

        # Add some variation
        variations = [
            "// Additional comment for variation",
            "event VulnerabilityTriggered(address indexed user, uint256 value);",
            "modifier whenNotPaused() { require(!paused, \"Paused\"); _; }",
            "uint256 constant MULTIPLIER = 1000;",
            "address public immutable FACTORY;"
        ]

        variation = np.random.choice(variations)
        return f"{variation}\n{base_code}"

    def _extract_function_patterns(self, code: str) -> Dict[str, int]:
        """Extract function patterns and complexity metrics from code"""
        patterns = {
            'function_count': len(re.findall(r'function\s+\w+', code)),
            'modifier_count': len(re.findall(r'modifier\s+\w+', code)),
            'external_calls': len(re.findall(r'\.call\(|\.delegatecall\(|\.send\(|\.transfer\(', code)),
            'state_variables': len(re.findall(r'(mapping|uint256|address|bool)\s+(public|private|internal)', code))
        }
        return patterns

    def _generate_cve_score(self, severity: str) -> float:
        """Generate CVE-like scores based on severity"""
        score_ranges = {
            'Critical': (9.0, 10.0),
            'High': (7.0, 8.9),
            'Medium': (4.0, 6.9),
            'Low': (0.1, 3.9)
        }
        min_score, max_score = score_ranges[severity]
        return round(np.random.uniform(min_score, max_score), 1)

    def prepare_smart_contract_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare specialized features for smart contract analysis"""
        self.logger.info("🔧 Preparing smart contract features...")

        features = []

        for _, row in df.iterrows():
            code = str(row['code_snippet'])

            # Code complexity features
            feature_vector = [
                # Basic metrics
                row['line_count'],
                row['function_count'],
                row['modifier_count'],
                row['external_calls'],
                row['state_variables'],
                row['complexity_score'],
                row['severity_score'],
                row['cve_equivalent'],
                row['gas_complexity'],

                # Protocol tier encoding
                1 if row['protocol'] in ['Uniswap', 'Compound', 'Aave', 'MakerDAO'] else 0,
                1 if row['protocol'] in ['SushiSwap', 'Curve', 'Yearn', 'Synthetix'] else 0,

                # Contract type encoding
                1 if row['contract_type'] in ['ERC20', 'ERC721', 'ERC1155'] else 0,
                1 if row['contract_type'] in ['Proxy', 'Factory', 'Router'] else 0,
                1 if row['contract_type'] in ['Pool', 'Vault', 'Strategy'] else 0,

                # Vulnerability pattern detection
                1 if 'call.value' in code or '.call(' in code else 0,
                1 if 'delegatecall' in code else 0,
                1 if 'tx.origin' in code else 0,
                1 if 'block.timestamp' in code or 'now' in code else 0,
                1 if 'onlyOwner' in code or 'require(' in code else 0,
                1 if 'SafeMath' in code or 'unchecked' in code else 0,
                1 if 'assembly' in code else 0,
                1 if 'random' in code or 'blockhash' in code else 0,

                # Code quality indicators
                len(re.findall(r'require\(', code)),  # Number of requires
                len(re.findall(r'emit\s+\w+', code)),  # Number of events
                1 if row['audit_status'] == 'audited' else 0,

                # Advanced patterns
                len(re.findall(r'mapping\(', code)),  # Number of mappings
                len(re.findall(r'modifier\s+\w+', code)),  # Modifier usage
                1 if 'payable' in code else 0,
                1 if 'view' in code or 'pure' in code else 0,
            ]

            features.append(feature_vector)

        return np.array(features), df['vulnerability_type'].values

    def train_vulnerability_classifier(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train multi-class vulnerability classifier"""
        self.logger.info("🤖 Training smart contract vulnerability classifier...")

        # Encode labels
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

        # Model ensemble
        models = {
            'xgboost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss'
            ),
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=12,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=150,
                max_depth=8,
                learning_rate=0.1,
                min_samples_split=10,
                random_state=42
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(256, 128, 64),
                activation='relu',
                solver='adam',
                alpha=0.001,
                learning_rate='adaptive',
                max_iter=500,
                random_state=42
            )
        }

        best_model = None
        best_score = -np.inf
        model_results = {}

        for name, model in models.items():
            self.logger.info(f"  Training {name}...")

            # Stratified cross-validation
            skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            cv_scores = cross_val_score(model, X_train, y_train, cv=skf, scoring='accuracy')

            # Train and evaluate
            model.fit(X_train, y_train)
            y_pred_test = model.predict(X_test)

            test_accuracy = accuracy_score(y_test, y_pred_test)
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred_test, average='weighted')

            model_results[name] = {
                'cv_accuracy_mean': cv_scores.mean(),
                'cv_accuracy_std': cv_scores.std(),
                'test_accuracy': test_accuracy,
                'test_precision': precision,
                'test_recall': recall,
                'test_f1': f1
            }

            self.logger.info(f"    CV Accuracy: {cv_scores.mean():.3f}±{cv_scores.std():.3f}")
            self.logger.info(f"    Test Accuracy: {test_accuracy:.3f}, F1: {f1:.3f}")

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
            'model_comparison': model_results,
            'samples_count': len(X),
            'features_count': X.shape[1]
        }

        self.training_results['vulnerability_classification'] = results
        self.logger.info(f"✅ Best vulnerability classifier: {results['best_model']} (Acc={best_score:.3f})")

        return results

    def train_severity_predictor(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Train severity prediction model"""
        self.logger.info("🎯 Training smart contract severity predictor...")

        # Prepare text features from code
        code_texts = []
        severities = []

        for _, row in df.iterrows():
            # Combine code and description for text analysis
            text = f"{row['code_snippet']} {row['description']} {row['vulnerability_type']}"
            code_texts.append(text)
            severities.append(row['severity_level'])

        # Text vectorization for code analysis
        vectorizer = TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 4),
            stop_words=None,  # Keep technical terms
            min_df=3,
            max_df=0.95,
            token_pattern=r'\b\w+\b'  # Include technical tokens
        )

        X_text = vectorizer.fit_transform(code_texts)
        self.vectorizers['severity'] = vectorizer

        # Encode severity labels
        severity_encoder = LabelEncoder()
        y_severity = severity_encoder.fit_transform(severities)
        self.encoders['severity'] = severity_encoder

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_text.toarray(), y_severity, test_size=0.2, random_state=42, stratify=y_severity
        )

        # Specialized model for severity prediction
        model = xgb.XGBClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            random_state=42,
            eval_metric='mlogloss'
        )

        # Cross-validation
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X_train, y_train, cv=skf, scoring='accuracy')

        # Train final model
        model.fit(X_train, y_train)
        self.models['severity_predictor'] = model

        # Evaluation
        y_pred_test = model.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_pred_test)

        class_report = classification_report(
            y_test, y_pred_test,
            target_names=severity_encoder.classes_,
            output_dict=True
        )

        results = {
            'model_type': type(model).__name__,
            'cv_accuracy_mean': cv_scores.mean(),
            'cv_accuracy_std': cv_scores.std(),
            'test_accuracy': test_accuracy,
            'classification_report': class_report,
            'class_names': severity_encoder.classes_.tolist(),
            'samples_count': len(X_text.toarray()),
            'features_count': X_text.shape[1]
        }

        self.training_results['severity_prediction'] = results
        self.logger.info(f"✅ Severity predictor: {results['model_type']} (Acc={cv_scores.mean():.3f})")

        return results

    def validate_smart_contract_models(self) -> Dict[str, Any]:
        """Validate models with real-world smart contract scenarios"""
        self.logger.info("📋 Validating smart contract models...")

        test_contracts = [
            {
                'name': 'Reentrancy in DeFi Withdraw',
                'code': '''
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}
                ''',
                'expected_vuln': 'reentrancy',
                'expected_severity': 'Critical'
            },
            {
                'name': 'Integer Overflow in Token Transfer',
                'code': '''
function transfer(address to, uint256 value) public returns (bool) {
    balances[msg.sender] -= value;
    balances[to] += value;
    return true;
}
                ''',
                'expected_vuln': 'integer_overflow',
                'expected_severity': 'High'
            },
            {
                'name': 'Unchecked External Call',
                'code': '''
function executeCall(address target, bytes calldata data) external onlyOwner {
    target.call(data);
    emit CallExecuted(target);
}
                ''',
                'expected_vuln': 'unchecked_call',
                'expected_severity': 'Medium'
            },
            {
                'name': 'Timestamp Dependence in Lottery',
                'code': '''
function playLottery() external payable {
    require(msg.value >= 0.1 ether);
    if (block.timestamp % 2 == 0) {
        payable(msg.sender).transfer(msg.value * 2);
    }
}
                ''',
                'expected_vuln': 'timestamp_dependence',
                'expected_severity': 'Medium'
            }
        ]

        successful_vuln_predictions = 0
        successful_severity_predictions = 0
        total_tests = len(test_contracts)

        test_results = []

        for test_case in test_contracts:
            try:
                # Extract features for vulnerability prediction
                patterns = self._extract_function_patterns(test_case['code'])

                # Create feature vector
                feature_vector = [
                    len(test_case['code'].split('\n')),  # line_count
                    patterns['function_count'],
                    patterns['modifier_count'],
                    patterns['external_calls'],
                    patterns['state_variables'],
                    0.5,  # complexity_score
                    0.8,  # severity_score
                    7.5,  # cve_equivalent
                    0.6,  # gas_complexity
                    1, 0,  # protocol tier (assume tier1)
                    1, 0, 0,  # contract type (assume ERC20)
                    1 if '.call(' in test_case['code'] else 0,
                    1 if 'delegatecall' in test_case['code'] else 0,
                    1 if 'tx.origin' in test_case['code'] else 0,
                    1 if 'block.timestamp' in test_case['code'] else 0,
                    1 if 'onlyOwner' in test_case['code'] or 'require(' in test_case['code'] else 0,
                    0,  # SafeMath
                    1 if 'assembly' in test_case['code'] else 0,
                    0,  # random patterns
                    len(re.findall(r'require\(', test_case['code'])),
                    len(re.findall(r'emit\s+\w+', test_case['code'])),
                    1,  # audited
                    len(re.findall(r'mapping\(', test_case['code'])),
                    len(re.findall(r'modifier\s+\w+', test_case['code'])),
                    1 if 'payable' in test_case['code'] else 0,
                    1 if 'view' in test_case['code'] or 'pure' in test_case['code'] else 0,
                ]

                # Predict vulnerability
                if 'vulnerability_classifier' in self.models and 'vulnerability' in self.scalers:
                    features_scaled = self.scalers['vulnerability'].transform([feature_vector])
                    vuln_pred_encoded = self.models['vulnerability_classifier'].predict(features_scaled)[0]
                    vuln_prediction = self.encoders['vulnerability'].inverse_transform([vuln_pred_encoded])[0]

                    vuln_match = vuln_prediction == test_case['expected_vuln']
                    if vuln_match:
                        successful_vuln_predictions += 1
                else:
                    vuln_prediction = 'unknown'
                    vuln_match = False

                # Predict severity
                if 'severity_predictor' in self.models and 'severity' in self.vectorizers:
                    text_features = self.vectorizers['severity'].transform([test_case['code']])
                    severity_pred_encoded = self.models['severity_predictor'].predict(text_features.toarray())[0]
                    severity_prediction = self.encoders['severity'].inverse_transform([severity_pred_encoded])[0]

                    severity_match = severity_prediction == test_case['expected_severity']
                    if severity_match:
                        successful_severity_predictions += 1
                else:
                    severity_prediction = 'unknown'
                    severity_match = False

                test_result = {
                    'test_name': test_case['name'],
                    'predicted_vulnerability': vuln_prediction,
                    'expected_vulnerability': test_case['expected_vuln'],
                    'vulnerability_match': vuln_match,
                    'predicted_severity': severity_prediction,
                    'expected_severity': test_case['expected_severity'],
                    'severity_match': severity_match
                }

                test_results.append(test_result)

                vuln_status = "✅" if vuln_match else "❌"
                sev_status = "✅" if severity_match else "❌"
                self.logger.info(f"  {vuln_status} {test_case['name']}: Vuln={vuln_prediction}, Sev={severity_prediction}")

            except Exception as e:
                self.logger.error(f"  ❌ {test_case['name']}: Validation failed - {e}")
                test_results.append({
                    'test_name': test_case['name'],
                    'error': str(e)
                })

        vuln_accuracy = successful_vuln_predictions / total_tests
        severity_accuracy = successful_severity_predictions / total_tests

        validation_results = {
            'vulnerability_accuracy': vuln_accuracy,
            'severity_accuracy': severity_accuracy,
            'successful_vuln_predictions': successful_vuln_predictions,
            'successful_severity_predictions': successful_severity_predictions,
            'total_tests': total_tests,
            'individual_results': test_results
        }

        self.training_results['validation'] = validation_results
        self.logger.info(f"✅ Validation - Vuln: {vuln_accuracy:.1%}, Severity: {severity_accuracy:.1%}")

        return validation_results

    def save_models(self):
        """Save all trained models"""
        self.logger.info("💾 Saving smart contract models...")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save models
        for model_name, model in self.models.items():
            model_path = self.output_dir / f"{model_name}_{timestamp}.pkl"
            joblib.dump(model, model_path)
            self.logger.info(f"  Saved {model_name}")

        # Save preprocessors
        for scaler_name, scaler in self.scalers.items():
            scaler_path = self.output_dir / f"scaler_{scaler_name}_{timestamp}.pkl"
            joblib.dump(scaler, scaler_path)

        for vec_name, vectorizer in self.vectorizers.items():
            vec_path = self.output_dir / f"vectorizer_{vec_name}_{timestamp}.pkl"
            joblib.dump(vectorizer, vec_path)

        for enc_name, encoder in self.encoders.items():
            enc_path = self.output_dir / f"encoder_{enc_name}_{timestamp}.pkl"
            joblib.dump(encoder, enc_path)

        # Save training results
        results_path = self.output_dir / f"smart_contract_training_results_{timestamp}.json"
        with open(results_path, 'w') as f:
            json.dump(self.training_results, f, indent=2, default=str)

        self.logger.info(f"✅ All models saved with timestamp: {timestamp}")
        return timestamp

    def run_complete_training(self) -> Dict[str, Any]:
        """Run complete smart contract vulnerability training pipeline"""
        self.logger.info("🚀 Starting smart contract vulnerability training...")

        try:
            # Generate dataset
            df = self.generate_smart_contract_dataset(n_samples=5000)

            # Prepare features
            X, y = self.prepare_smart_contract_features(df)

            # Train vulnerability classifier
            vuln_results = self.train_vulnerability_classifier(X, y)

            # Train severity predictor
            severity_results = self.train_severity_predictor(df)

            # Validate models
            validation_results = self.validate_smart_contract_models()

            # Save models
            timestamp = self.save_models()

            self.logger.info("✅ Smart contract training pipeline completed!")

            return {
                'status': 'success',
                'vulnerability_classification': vuln_results,
                'severity_prediction': severity_results,
                'validation': validation_results,
                'timestamp': timestamp,
                'dataset_size': len(df)
            }

        except Exception as e:
            self.logger.error(f"❌ Training pipeline failed: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                'status': 'error',
                'error': str(e)
            }

def main():
    """Main execution function"""
    print("🔐 SMART CONTRACT VULNERABILITY TRAINER")
    print("=" * 60)

    trainer = SmartContractVulnTrainer()
    results = trainer.run_complete_training()

    if results['status'] == 'success':
        print(f"\n✅ SMART CONTRACT TRAINING COMPLETE!")
        print(f"📊 Dataset Size: {results['dataset_size']:,} samples")

        if 'vulnerability_classification' in results:
            vc = results['vulnerability_classification']
            print(f"🤖 Vulnerability Classifier: {vc['best_model']} (Acc={vc['cv_accuracy_mean']:.3f})")

        if 'severity_prediction' in results:
            sp = results['severity_prediction']
            print(f"🎯 Severity Predictor: {sp['model_type']} (Acc={sp['cv_accuracy_mean']:.3f})")

        if 'validation' in results:
            val = results['validation']
            print(f"📋 Validation - Vuln: {val['vulnerability_accuracy']:.1%}, Severity: {val['severity_accuracy']:.1%}")

        print(f"💾 Models saved with timestamp: {results['timestamp']}")
        print(f"\n🚀 Ready for smart contract vulnerability detection!")

    else:
        print(f"\n❌ TRAINING FAILED: {results['error']}")

if __name__ == "__main__":
    main()