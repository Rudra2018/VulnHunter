#!/usr/bin/env python3
"""
VulnHunter V5 Pay-As-You-Go Enhanced Training
Trains on comprehensive smart contract dataset with target F1 > 0.97
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import json
import os
import argparse
from pathlib import Path
import logging
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_enhanced_smart_contract_dataset(size: int = 25000) -> pd.DataFrame:
    """Create enhanced smart contract dataset with comprehensive vulnerability patterns"""
    logger.info(f"Creating enhanced smart contract dataset with {size} samples")

    # Advanced vulnerability patterns
    vuln_patterns = {
        'reentrancy': {
            'code': [
                'function withdraw() public { msg.sender.call.value(balances[msg.sender])(""); balances[msg.sender] = 0; }',
                'function transfer(address to, uint amount) { to.call.value(amount)(""); balance[msg.sender] -= amount; }',
                'external_call(); state_variable = new_value; require(success);',
                'recipient.call.value(amount)(""); userBalances[msg.sender] = 0;'
            ],
            'cwe': 'CWE-362',
            'severity': 'high'
        },
        'timestamp_dependence': {
            'code': [
                'require(block.timestamp > deadline, "Too early");',
                'if (now > endTime) { payable(winner).transfer(prize); }',
                'uint random = uint(keccak256(abi.encodePacked(block.timestamp))) % 100;',
                'require(block.timestamp >= unlockTime, "Still locked");'
            ],
            'cwe': 'CWE-367',
            'severity': 'medium'
        },
        'tx_origin_auth': {
            'code': [
                'require(tx.origin == owner, "Not owner");',
                'if (tx.origin == msg.sender) { selfdestruct(payable(owner)); }',
                'modifier onlyOwner() { require(tx.origin == owner); _; }',
                'function emergencyWithdraw() { require(tx.origin == admin); }'
            ],
            'cwe': 'CWE-346',
            'severity': 'high'
        },
        'integer_overflow': {
            'code': [
                'balances[to] += amount; balances[from] -= amount;',
                'totalSupply = totalSupply + newTokens;',
                'function multiply(uint a, uint b) returns (uint) { return a * b; }',
                'price = basePrice + (bidCount * increment);'
            ],
            'cwe': 'CWE-190',
            'severity': 'high'
        },
        'unchecked_call': {
            'code': [
                'recipient.call.value(amount)("");',
                'target.delegatecall(data); balances[msg.sender] -= fee;',
                'someAddress.send(amount);',
                'proxy.delegatecall(abi.encodeWithSignature("transfer(address,uint256)", to, amount));'
            ],
            'cwe': 'CWE-252',
            'severity': 'medium'
        },
        'access_control': {
            'code': [
                'function setOwner(address _owner) public { owner = _owner; }',
                'function withdraw() public { payable(msg.sender).transfer(address(this).balance); }',
                'function emergencyStop() { stopped = true; }',
                'function mint(address to, uint amount) { balances[to] += amount; }'
            ],
            'cwe': 'CWE-284',
            'severity': 'high'
        },
        'weak_randomness': {
            'code': [
                'uint random = uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp))) % 100;',
                'bytes32 hash = blockhash(block.number - 1);',
                'uint seed = uint(keccak256(abi.encodePacked(block.coinbase, block.gaslimit)));',
                'uint winner = uint(keccak256(abi.encodePacked(now, block.difficulty))) % players.length;'
            ],
            'cwe': 'CWE-338',
            'severity': 'medium'
        }
    }

    safe_patterns = [
        'require(amount > 0, "Amount must be positive"); using SafeMath for uint256;',
        'require(balances[from] >= amount, "Insufficient balance"); balances[from] -= amount;',
        'function safeTransfer(address to, uint amount) internal { require(to != address(0)); require(amount <= balances[msg.sender]); }',
        'modifier nonReentrant() { require(!locked, "Reentrant call"); locked = true; _; locked = false; }',
        'require(msg.sender == owner, "Only owner can call"); require(_newOwner != address(0), "Invalid address");',
        'using SafeERC20 for IERC20; token.safeTransfer(recipient, amount);',
        'require(block.timestamp >= startTime && block.timestamp <= endTime, "Invalid time");',
        'function withdraw() external nonReentrant onlyOwner { (bool success, ) = payable(owner).call{value: address(this).balance}(""); require(success, "Transfer failed"); }'
    ]

    synthetic_data = []

    for i in range(size):
        if np.random.random() < 0.65:  # 65% vulnerable
            vuln_type = np.random.choice(list(vuln_patterns.keys()))
            pattern_info = vuln_patterns[vuln_type]
            code_pattern = np.random.choice(pattern_info['code'])
            is_vulnerable = True
            cwe_id = pattern_info['cwe']
            severity = pattern_info['severity']
        else:  # 35% safe
            code_pattern = np.random.choice(safe_patterns)
            is_vulnerable = False
            vuln_type = "safe"
            cwe_id = "SAFE"
            severity = "none"

        # Create comprehensive contract structure
        contract_template = f"""
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract EnhancedContract_{i} is ReentrancyGuard, Ownable {{
    using SafeMath for uint256;

    mapping(address => uint256) public balances;
    mapping(address => bool) public authorized;
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1000000;
    bool public paused = false;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier onlyAuthorized() {{
        require(authorized[msg.sender] || msg.sender == owner(), "Not authorized");
        _;
    }}

    modifier whenNotPaused() {{
        require(!paused, "Contract is paused");
        _;
    }}

    constructor() {{
        totalSupply = 100000;
        balances[msg.sender] = totalSupply;
        authorized[msg.sender] = true;
    }}

    {code_pattern}

    function deposit() public payable whenNotPaused {{
        require(msg.value > 0, "Amount must be positive");
        balances[msg.sender] = balances[msg.sender].add(msg.value);
        emit Deposit(msg.sender, msg.value);
    }}

    function getBalance(address account) public view returns (uint256) {{
        return balances[account];
    }}

    function pause() external onlyOwner {{
        paused = true;
    }}

    function unpause() external onlyOwner {{
        paused = false;
    }}
}}
"""

        # Extract comprehensive features
        features = extract_comprehensive_features(contract_template)

        synthetic_data.append({
            'code': contract_template,
            'contract_name': f'EnhancedContract_{i}',
            'language': 'solidity',
            'is_vulnerable': is_vulnerable,
            'vulnerability_type': vuln_type,
            'cwe_id': cwe_id,
            'severity': severity,
            'source': 'enhanced_synthetic',
            'file_size': len(contract_template),
            **features
        })

    return pd.DataFrame(synthetic_data)

def extract_comprehensive_features(code: str) -> dict:
    """Extract comprehensive features for smart contract analysis"""
    features = {}

    # Basic metrics
    lines = code.split('\n')
    features['line_count'] = len(lines)
    features['char_count'] = len(code)
    features['word_count'] = len(code.split())

    # Function and structure analysis
    features['function_count'] = len(re.findall(r'function\s+\w+', code))
    features['modifier_count'] = len(re.findall(r'modifier\s+\w+', code))
    features['event_count'] = len(re.findall(r'event\s+\w+', code))
    features['struct_count'] = len(re.findall(r'struct\s+\w+', code))
    features['enum_count'] = len(re.findall(r'enum\s+\w+', code))

    # Vulnerability indicators
    features['has_payable'] = int('payable' in code)
    features['has_selfdestruct'] = int('selfdestruct' in code)
    features['has_delegatecall'] = int('delegatecall' in code)
    features['has_assembly'] = int('assembly' in code)
    features['has_tx_origin'] = int('tx.origin' in code)
    features['has_block_timestamp'] = int('block.timestamp' in code or 'now' in code)
    features['has_call_value'] = int('.call.value(' in code or '.call{value:' in code)
    features['has_transfer'] = int('.transfer(' in code)
    features['has_send'] = int('.send(' in code)

    # Security patterns
    features['has_require'] = len(re.findall(r'require\s*\(', code))
    features['has_assert'] = len(re.findall(r'assert\s*\(', code))
    features['has_revert'] = len(re.findall(r'revert\s*\(', code))
    features['has_safemath'] = int('SafeMath' in code)
    features['has_reentrancy_guard'] = int('nonReentrant' in code or 'ReentrancyGuard' in code)

    # Advanced security features
    features['has_access_control'] = int('onlyOwner' in code or 'Ownable' in code)
    features['has_pausable'] = int('whenNotPaused' in code or 'Pausable' in code)
    features['has_upgradeable'] = int('Proxy' in code or 'Upgradeable' in code)
    features['has_multisig'] = int('multisig' in code or 'MultiSig' in code)

    # Complexity indicators
    features['pragma_count'] = len(re.findall(r'pragma\s+', code))
    features['import_count'] = len(re.findall(r'import\s+', code))
    features['contract_count'] = len(re.findall(r'contract\s+\w+', code))
    features['interface_count'] = len(re.findall(r'interface\s+\w+', code))
    features['library_count'] = len(re.findall(r'library\s+\w+', code))

    # Code quality metrics
    features['comment_count'] = len(re.findall(r'//.*$', code, re.MULTILINE))
    features['empty_line_count'] = len([line for line in lines if line.strip() == ''])
    features['max_line_length'] = max(len(line) for line in lines) if lines else 0
    features['avg_line_length'] = sum(len(line) for line in lines) / len(lines) if lines else 0

    # Mathematical operations
    features['arithmetic_ops'] = len(re.findall(r'[\+\-\*\/\%]', code))
    features['comparison_ops'] = len(re.findall(r'[<>=!]=?', code))
    features['logical_ops'] = len(re.findall(r'&&|\|\|', code))

    # Gas optimization indicators
    features['storage_variables'] = len(re.findall(r'(uint|int|bool|address|string|bytes)\s+\w+;', code))
    features['memory_usage'] = code.count('memory')
    features['storage_usage'] = code.count('storage')
    features['calldata_usage'] = code.count('calldata')

    # Business logic complexity
    features['conditional_count'] = len(re.findall(r'\bif\s*\(', code))
    features['loop_count'] = len(re.findall(r'\b(for|while)\s*\(', code))
    features['mapping_count'] = len(re.findall(r'mapping\s*\(', code))
    features['array_operations'] = len(re.findall(r'\[\w*\]', code))

    # External interaction patterns
    features['external_calls'] = len(re.findall(r'\.call\(', code))
    features['interface_calls'] = len(re.findall(r'\.\w+\(', code))
    features['low_level_calls'] = features['external_calls'] + features['has_delegatecall']

    return features

def main():
    parser = argparse.ArgumentParser(description='VulnHunter V5 Pay-As-You-Go Enhanced Training')
    parser.add_argument('--data-path', help='Path to existing dataset (optional)')
    parser.add_argument('--output-dir', default='./outputs', help='Output directory')
    parser.add_argument('--target-f1', type=float, default=0.97, help='Target F1 score')
    parser.add_argument('--dataset-size', type=int, default=25000, help='Enhanced dataset size')

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("🚀 VulnHunter V5 Pay-As-You-Go Enhanced Training")
    logger.info("=" * 50)

    # Create or load enhanced dataset
    if args.data_path and os.path.exists(args.data_path):
        logger.info(f"Loading existing dataset: {args.data_path}")
        df = pd.read_csv(args.data_path, low_memory=False)

        # Filter for smart contracts
        if 'language' in df.columns:
            df = df[df['language'].isin(['solidity', 'smart_contract'])].copy()

        logger.info(f"Loaded {len(df)} smart contract samples")
    else:
        logger.info("Creating enhanced smart contract dataset...")
        df = create_enhanced_smart_contract_dataset(args.dataset_size)

    # Prepare features
    feature_cols = [col for col in df.columns if col not in ['code', 'file_path', 'contract_name', 'vulnerability_type', 'source']]

    # Handle is_vulnerable column
    if 'is_vulnerable' in df.columns:
        y = df['is_vulnerable']
        feature_cols.remove('is_vulnerable')
    else:
        y = df.get('vulnerable', np.zeros(len(df)))

    X = df[feature_cols].copy()

    # Handle categorical data
    categorical_cols = X.select_dtypes(include=['object']).columns
    for col in categorical_cols:
        le = LabelEncoder()
        X.loc[:, col] = le.fit_transform(X[col].astype(str))

    X = X.fillna(0)

    logger.info(f"Features: {X.shape[1]}, Samples: {len(X)}")
    logger.info(f"Vulnerable samples: {sum(y):,} ({sum(y)/len(y)*100:.1f}%)")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Train enhanced model
    logger.info("🌲 Training Enhanced RandomForest for Smart Contracts...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')

    logger.info("📊 Enhanced Smart Contract Model Results:")
    logger.info(f"   Accuracy: {accuracy:.4f}")
    logger.info(f"   Precision: {precision:.4f}")
    logger.info(f"   Recall: {recall:.4f}")
    logger.info(f"   F1 Score: {f1:.4f}")

    # Feature importance analysis
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)

    logger.info("🔍 Top 15 Smart Contract Security Features:")
    for idx, row in feature_importance.head(15).iterrows():
        logger.info(f"   {row['feature']}: {row['importance']:.4f}")

    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='f1_weighted')
    logger.info(f"📈 Cross-validation F1: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    # Save enhanced model and results
    model_path = output_dir / 'vulnhunter_v5_enhanced_model.joblib'
    joblib.dump(model, model_path)

    results = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'cv_f1_mean': cv_scores.mean(),
        'cv_f1_std': cv_scores.std(),
        'target_f1_achieved': f1 >= args.target_f1,
        'dataset_size': len(X),
        'feature_count': len(feature_cols),
        'vulnerable_ratio': sum(y)/len(y),
        'top_features': feature_importance.head(15).to_dict('records')
    }

    results_path = output_dir / 'enhanced_training_results.json'
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)

    feature_names_path = output_dir / 'enhanced_feature_names.json'
    with open(feature_names_path, 'w') as f:
        json.dump(list(X.columns), f)

    # Save enhanced dataset
    dataset_path = output_dir / 'enhanced_smart_contract_dataset.csv'
    df.to_csv(dataset_path, index=False)

    logger.info("=" * 50)
    logger.info("🎯 ENHANCED TRAINING COMPLETE")
    logger.info(f"📊 F1 Score: {f1:.4f}")
    logger.info(f"✅ Target achieved: {f1 >= args.target_f1}")
    logger.info(f"🔒 Smart Contract Focus: {len(X):,} samples")
    logger.info(f"💾 Model: {model_path}")
    logger.info(f"📂 Dataset: {dataset_path}")
    logger.info("=" * 50)

    return 0 if f1 >= args.target_f1 else 1

if __name__ == '__main__':
    exit(main())