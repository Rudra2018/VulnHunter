#!/usr/bin/env python3
"""
VulnHunter V5 NCASv3_T4-Style Training
High-performance training optimized for dedicated vCPUs with GPU-style techniques
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
import joblib
import json
import os
import argparse
from pathlib import Path
import logging
import re
import time
import multiprocessing as mp
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_ncasv3_dataset(size: int = 30000) -> pd.DataFrame:
    """Create advanced dataset optimized for NCASv3_T4-style performance"""
    logger.info(f"🚀 Creating NCASv3_T4-style dataset with {size} samples")

    # High-performance vulnerability patterns
    vuln_patterns = {
        'critical_reentrancy': [
            'function withdraw() external { uint balance = balances[msg.sender]; require(balance > 0); (bool success,) = msg.sender.call{value: balance}(""); require(success); balances[msg.sender] = 0; emit Withdrawal(msg.sender, balance); }',
            'function batchWithdraw(address[] memory users) external { for(uint i = 0; i < users.length; i++) { uint balance = balances[users[i]]; users[i].call{value: balance}(""); balances[users[i]] = 0; } }',
            'function crossContractReentrancy() external { ITarget(target).call{value: deposits[msg.sender]}(abi.encodeWithSignature("complexWithdraw()")); deposits[msg.sender] = 0; }'
        ],
        'access_control_bypass': [
            'function emergencyWithdraw() external { require(tx.origin == owner || block.timestamp > emergencyTime); payable(msg.sender).transfer(address(this).balance); }',
            'function adminFunction() external { require(authorizedUsers[tx.origin] && msg.sender != tx.origin); criticalOperation(); }',
            'function roleBasedBypass() external { if(hasRole(ADMIN_ROLE, msg.sender) || tx.origin == deployer) { executePrivilegedAction(); } }'
        ],
        'timestamp_manipulation': [
            'function timeBasedLogic() external { require(block.timestamp >= releaseTime && block.timestamp <= releaseTime + 3600); require(block.number > startBlock + confirmations); executeTimedFunction(); }',
            'function randomSeed() external { uint entropy = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, block.coinbase))); winner = participants[entropy % participants.length]; }',
            'function auctionBid() external payable { require(block.timestamp <= auctionEnd && now >= auctionStart); require(msg.value > highestBid * 110 / 100); }'
        ],
        'integer_vulnerabilities': [
            'function unsafeMath() external { uint result = userInput * multiplier + bonus; require(result > userInput); balances[msg.sender] += result; totalSupply += result; }',
            'function batchProcess(uint[] memory amounts) external { uint total; for(uint i = 0; i < amounts.length; i++) { total += amounts[i]; } require(balances[msg.sender] >= total); }',
            'function compoundCalculation() external { uint interest = principal * rate / 100; uint newBalance = userBalance + interest; userBalance = newBalance; emit InterestAdded(interest); }'
        ],
        'delegatecall_risks': [
            'function proxyExecute(address target, bytes memory data) external onlyOwner { (bool success, bytes memory result) = target.delegatecall(data); require(success); emit ProxyCall(target, data); }',
            'function libraryCall(address lib, bytes calldata data) external { require(trustedLibraries[lib]); (bool success,) = lib.delegatecall(data); require(success); }',
            'function upgradeImplementation(address newImpl) external { implementation = newImpl; implementation.delegatecall(abi.encodeWithSignature("initialize(address)", msg.sender)); }'
        ],
        'gas_manipulation': [
            'function gasLimitedLoop() external { uint iterations = (gasleft() - 5000) / gasPerIteration; for(uint i = 0; i < iterations; i++) { processItem(i); } }',
            'function dynamicGasUsage() external { require(tx.gasprice <= maxGasPrice && gasleft() > minGasRequired); uint startGas = gasleft(); executeOperation(); gasUsage[msg.sender] = startGas - gasleft(); }',
            'function gasOracle() external { require(block.gaslimit > targetGasLimit); uint gasPrice = tx.gasprice; require(gasPrice >= minGasPrice && gasPrice <= maxGasPrice); }'
        ]
    }

    safe_patterns = [
        'using SafeMath for uint256; using ReentrancyGuard for modifier; require(_amount > 0 && _amount <= balances[msg.sender], "Invalid amount"); balances[msg.sender] = balances[msg.sender].sub(_amount); emit Transfer(msg.sender, _to, _amount);',
        'modifier onlyValidAddress(address _addr) { require(_addr != address(0) && _addr != address(this) && _addr != msg.sender, "Invalid address"); _; } function secureTransfer(address _to, uint _amount) external onlyValidAddress(_to) nonReentrant whenNotPaused { _transfer(msg.sender, _to, _amount); }',
        'using AccessControl for role management; using Pausable for emergency; require(hasRole(TRANSFER_ROLE, msg.sender) && !paused(), "Unauthorized or paused"); require(_amount <= transferLimit && _amount >= minTransfer, "Amount out of bounds");',
        'using SafeERC20 for IERC20; using Address for address payable; require(_recipient != address(0), "Invalid recipient"); IERC20(token).safeTransfer(_recipient, _amount); emit SafeTransfer(msg.sender, _recipient, _amount);',
        'modifier validTimeframe() { require(block.timestamp >= startTime && block.timestamp <= endTime, "Invalid timeframe"); require(block.number >= startBlock, "Too early"); _; } function timedOperation() external validTimeframe onlyAuthorized nonReentrant { executeSecureOperation(); }'
    ]

    synthetic_data = []

    for i in range(size):
        if np.random.random() < 0.72:  # 72% vulnerable
            vuln_type = np.random.choice(list(vuln_patterns.keys()))
            code_pattern = np.random.choice(vuln_patterns[vuln_type])
            is_vulnerable = True
            severity = 'high' if 'critical' in vuln_type else 'medium'
            cwe_mapping = {
                'critical_reentrancy': 'CWE-362',
                'access_control_bypass': 'CWE-284',
                'timestamp_manipulation': 'CWE-367',
                'integer_vulnerabilities': 'CWE-190',
                'delegatecall_risks': 'CWE-829',
                'gas_manipulation': 'CWE-400'
            }
            cwe_id = cwe_mapping.get(vuln_type, 'CWE-Other')
        else:  # 28% safe
            code_pattern = np.random.choice(safe_patterns)
            is_vulnerable = False
            vuln_type = "safe"
            severity = "none"
            cwe_id = "SAFE"

        # Create advanced contract structure
        contract_template = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract NCASv3Contract_{i} is ReentrancyGuard, Pausable, AccessControl {{
    using SafeMath for uint256;
    using SafeERC20 for IERC20;
    using Address for address payable;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant TRANSFER_ROLE = keccak256("TRANSFER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => bool) public authorizedUsers;
    mapping(address => uint256) public stakingBalances;
    mapping(address => uint256) public rewardsClaimed;
    mapping(bytes32 => bool) public processedTransactions;

    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1000000 * 10**18;
    uint256 public transferLimit = 10000 * 10**18;
    uint256 public minTransfer = 1 * 10**18;
    uint256 public stakingRewardRate = 500; // 5%
    uint256 public lastRewardCalculation;

    address public implementation;
    address public emergencyMultisig;
    address[] public validators;

    bool public emergencyMode = false;
    uint256 public emergencyTime;
    uint256 public gasPerIteration = 20000;
    uint256 public maxGasPrice = 50 gwei;
    uint256 public minGasPrice = 1 gwei;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event EmergencyActivated(address indexed activator, uint256 timestamp);
    event StakingRewardCalculated(address indexed user, uint256 reward);
    event SecurityAlert(string indexed alertType, address indexed user, uint256 value);

    modifier onlyAuthorized() {{
        require(
            hasRole(ADMIN_ROLE, msg.sender) ||
            hasRole(TRANSFER_ROLE, msg.sender) ||
            authorizedUsers[msg.sender],
            "Unauthorized access"
        );
        _;
    }}

    modifier validAmount(uint256 _amount) {{
        require(_amount > 0 && _amount <= balances[msg.sender], "Invalid amount");
        require(_amount >= minTransfer && _amount <= transferLimit, "Amount out of bounds");
        _;
    }}

    modifier emergencyStop() {{
        if (emergencyMode) {{
            require(hasRole(EMERGENCY_ROLE, msg.sender), "Emergency mode active");
        }}
        _;
    }}

    modifier gasOptimized() {{
        uint256 gasStart = gasleft();
        _;
        uint256 gasUsed = gasStart - gasleft();
        require(gasUsed <= 200000, "Gas limit exceeded");
    }}

    constructor(address _emergencyMultisig) {{
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(TRANSFER_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        emergencyMultisig = _emergencyMultisig;
        totalSupply = 500000 * 10**18;
        balances[msg.sender] = totalSupply;
        lastRewardCalculation = block.timestamp;

        emit Transfer(address(0), msg.sender, totalSupply);
    }}

    {code_pattern}

    function batchTransferSecure(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external nonReentrant whenNotPaused gasOptimized onlyAuthorized {{
        require(recipients.length == amounts.length, "Array length mismatch");
        require(recipients.length <= 50, "Too many recipients");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {{
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0 && amounts[i] <= transferLimit, "Invalid amount");
            totalAmount = totalAmount.add(amounts[i]);
        }}

        require(balances[msg.sender] >= totalAmount, "Insufficient balance");
        balances[msg.sender] = balances[msg.sender].sub(totalAmount);

        for (uint256 i = 0; i < recipients.length; i++) {{
            balances[recipients[i]] = balances[recipients[i]].add(amounts[i]);
            emit Transfer(msg.sender, recipients[i], amounts[i]);
        }}
    }}

    function calculateStakingRewards() external onlyRole(ADMIN_ROLE) {{
        uint256 timePassed = block.timestamp.sub(lastRewardCalculation);
        require(timePassed >= 86400, "Too early for reward calculation");

        for (uint256 i = 0; i < validators.length; i++) {{
            address validator = validators[i];
            uint256 stake = stakingBalances[validator];

            if (stake > 0) {{
                uint256 reward = stake.mul(stakingRewardRate).mul(timePassed).div(365 days).div(10000);
                rewardsClaimed[validator] = rewardsClaimed[validator].add(reward);
                balances[validator] = balances[validator].add(reward);

                emit StakingRewardCalculated(validator, reward);
            }}
        }}

        lastRewardCalculation = block.timestamp;
    }}

    function emergencyPause() external onlyRole(EMERGENCY_ROLE) {{
        emergencyMode = true;
        emergencyTime = block.timestamp;
        _pause();
        emit EmergencyActivated(msg.sender, block.timestamp);
    }}

    function emergencyUnpause() external {{
        require(
            hasRole(EMERGENCY_ROLE, msg.sender) &&
            block.timestamp >= emergencyTime.add(3600),
            "Emergency cooldown not met"
        );
        emergencyMode = false;
        _unpause();
    }}

    receive() external payable {{
        require(msg.value >= 0.001 ether, "Minimum deposit required");
        require(!emergencyMode, "Emergency mode active");
        balances[msg.sender] = balances[msg.sender].add(msg.value);
    }}

    fallback() external payable {{
        revert("Function not found");
    }}
}}
"""

        # Extract comprehensive features
        features = extract_ncasv3_features(contract_template)

        synthetic_data.append({
            'code': contract_template,
            'contract_name': f'NCASv3Contract_{i}',
            'language': 'solidity',
            'is_vulnerable': is_vulnerable,
            'vulnerability_type': vuln_type,
            'severity': severity,
            'cwe_id': cwe_id,
            'source': 'ncasv3_synthetic',
            'file_size': len(contract_template),
            **features
        })

    logger.info(f"✅ Generated {len(synthetic_data)} NCASv3-style samples")
    return pd.DataFrame(synthetic_data)

def extract_ncasv3_features(code: str) -> dict:
    """Extract features optimized for NCASv3_T4 analysis"""
    features = {}

    lines = code.split('\n')
    words = code.split()

    # Core metrics
    features['line_count'] = len(lines)
    features['char_count'] = len(code)
    features['word_count'] = len(words)
    features['non_empty_lines'] = len([line for line in lines if line.strip()])

    # Advanced Solidity structures
    features['pragma_count'] = len(re.findall(r'pragma\s+', code))
    features['import_count'] = len(re.findall(r'import\s+', code))
    features['contract_count'] = len(re.findall(r'contract\s+\w+', code))
    features['interface_count'] = len(re.findall(r'interface\s+\w+', code))
    features['library_count'] = len(re.findall(r'library\s+\w+', code))

    # Functions and modifiers
    features['function_count'] = len(re.findall(r'function\s+\w+', code))
    features['modifier_count'] = len(re.findall(r'modifier\s+\w+', code))
    features['constructor_count'] = len(re.findall(r'constructor\s*\(', code))
    features['fallback_count'] = len(re.findall(r'fallback\s*\(', code))
    features['receive_count'] = len(re.findall(r'receive\s*\(', code))

    # Events and structures
    features['event_count'] = len(re.findall(r'event\s+\w+', code))
    features['struct_count'] = len(re.findall(r'struct\s+\w+', code))
    features['enum_count'] = len(re.findall(r'enum\s+\w+', code))
    features['mapping_count'] = len(re.findall(r'mapping\s*\(', code))

    # Security frameworks
    features['has_reentrancy_guard'] = int('ReentrancyGuard' in code or 'nonReentrant' in code)
    features['has_access_control'] = int('AccessControl' in code or 'hasRole' in code)
    features['has_pausable'] = int('Pausable' in code or 'whenNotPaused' in code)
    features['has_safemath'] = int('SafeMath' in code or 'using SafeMath' in code)
    features['has_safeerc20'] = int('SafeERC20' in code or 'safeTransfer' in code)
    features['has_address_utils'] = int('using Address' in code)

    # Vulnerability indicators
    features['has_delegatecall'] = int('delegatecall' in code)
    features['has_selfdestruct'] = int('selfdestruct' in code)
    features['has_tx_origin'] = int('tx.origin' in code)
    features['has_block_timestamp'] = int('block.timestamp' in code or 'now' in code)
    features['has_block_number'] = int('block.number' in code)
    features['has_block_difficulty'] = int('block.difficulty' in code)
    features['has_block_coinbase'] = int('block.coinbase' in code)
    features['has_call_value'] = int('.call{value:' in code or '.call.value(' in code)
    features['has_send'] = int('.send(' in code)
    features['has_transfer'] = int('.transfer(' in code)

    # Gas-related patterns
    features['has_gasleft'] = int('gasleft()' in code)
    features['has_gas_limit'] = int('gaslimit' in code)
    features['has_gas_price'] = int('gasprice' in code)
    features['gas_optimization_count'] = code.count('gas')

    # Security checks
    features['require_count'] = len(re.findall(r'require\s*\(', code))
    features['assert_count'] = len(re.findall(r'assert\s*\(', code))
    features['revert_count'] = len(re.findall(r'revert\s*\(', code))

    # Control flow
    features['conditional_count'] = len(re.findall(r'\bif\s*\(', code))
    features['loop_count'] = len(re.findall(r'\b(for|while)\s*\(', code))
    features['try_catch_count'] = len(re.findall(r'\btry\s+', code))

    # Mathematical operations
    features['arithmetic_ops'] = len(re.findall(r'[\+\-\*\/\%]', code))
    features['comparison_ops'] = len(re.findall(r'[<>=!]=?', code))
    features['logical_ops'] = len(re.findall(r'&&|\|\|', code))
    features['bitwise_ops'] = len(re.findall(r'[&|^~]', code))

    # Memory usage patterns
    features['memory_usage'] = code.count('memory')
    features['storage_usage'] = code.count('storage')
    features['calldata_usage'] = code.count('calldata')

    # Function visibility and state mutability
    features['external_functions'] = len(re.findall(r'function\s+\w+[^{]*\bexternal\b', code))
    features['public_functions'] = len(re.findall(r'function\s+\w+[^{]*\bpublic\b', code))
    features['internal_functions'] = len(re.findall(r'function\s+\w+[^{]*\binternal\b', code))
    features['private_functions'] = len(re.findall(r'function\s+\w+[^{]*\bprivate\b', code))
    features['view_functions'] = len(re.findall(r'function\s+\w+[^{]*\bview\b', code))
    features['pure_functions'] = len(re.findall(r'function\s+\w+[^{]*\bpure\b', code))
    features['payable_functions'] = len(re.findall(r'function\s+\w+[^{]*\bpayable\b', code))

    # Advanced security patterns
    features['emergency_patterns'] = code.count('emergency') + code.count('Emergency')
    features['multisig_patterns'] = code.count('multisig') + code.count('MultiSig')
    features['proxy_patterns'] = code.count('proxy') + code.count('Proxy')
    features['upgrade_patterns'] = code.count('upgrade') + code.count('Upgrade')

    # Role-based access control
    features['role_definitions'] = len(re.findall(r'ROLE\s*=', code))
    features['role_checks'] = len(re.findall(r'hasRole\s*\(', code))
    features['role_grants'] = len(re.findall(r'grantRole\s*\(', code))

    # Complex patterns
    features['array_operations'] = len(re.findall(r'\[\w*\]', code))
    features['external_calls'] = len(re.findall(r'\.\w+\(', code))
    features['low_level_calls'] = features['has_delegatecall'] + features['has_call_value']

    # Code quality indicators
    features['comment_lines'] = len(re.findall(r'//.*|/\*.*?\*/', code, re.DOTALL))
    features['empty_lines'] = len([line for line in lines if not line.strip()])
    features['max_line_length'] = max(len(line) for line in lines) if lines else 0
    features['avg_line_length'] = sum(len(line) for line in lines) / len(lines) if lines else 0

    return features

def main():
    parser = argparse.ArgumentParser(description='VulnHunter V5 NCASv3_T4-Style Training')
    parser.add_argument('--dataset-size', type=int, default=30000, help='Dataset size')
    parser.add_argument('--output-dir', default='./outputs', help='Output directory')
    parser.add_argument('--target-f1', type=float, default=0.98, help='Target F1 score')

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("🚀 VulnHunter V5 NCASv3_T4-Style Training")
    logger.info("=" * 60)
    logger.info(f"⚡ Optimized for dedicated vCPU performance")

    # Create dataset
    start_time = time.time()
    df = create_ncasv3_dataset(args.dataset_size)
    dataset_time = time.time() - start_time
    logger.info(f"📊 Dataset created in {dataset_time:.2f}s")

    # Prepare features
    feature_cols = [col for col in df.columns if col not in ['code', 'contract_name', 'vulnerability_type', 'source', 'is_vulnerable']]
    X = df[feature_cols].copy()
    y = df['is_vulnerable']

    # Handle categorical data
    categorical_cols = X.select_dtypes(include=['object']).columns
    for col in categorical_cols:
        le = LabelEncoder()
        X.loc[:, col] = le.fit_transform(X[col].astype(str))

    X = X.fillna(0)

    logger.info(f"📊 Features: {X.shape[1]}, Samples: {len(X):,}")
    logger.info(f"🎯 Vulnerable: {sum(y):,} ({sum(y)/len(y)*100:.1f}%)")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Train optimized models
    logger.info("🔥 Training NCASv3_T4-Style Ensemble...")

    models = {
        'advanced_rf': RandomForestClassifier(
            n_estimators=400,
            max_depth=28,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features='log2',
            bootstrap=True,
            oob_score=True,
            n_jobs=-1,
            random_state=42,
            class_weight='balanced'
        ),
        'extra_trees': ExtraTreesClassifier(
            n_estimators=300,
            max_depth=25,
            min_samples_split=6,
            min_samples_leaf=3,
            max_features='sqrt',
            bootstrap=False,
            n_jobs=-1,
            random_state=42,
            class_weight='balanced'
        ),
        'gradient_boost': GradientBoostingClassifier(
            n_estimators=250,
            learning_rate=0.12,
            max_depth=10,
            min_samples_split=8,
            min_samples_leaf=4,
            subsample=0.85,
            random_state=42
        )
    }

    results = {}
    best_model = None
    best_score = 0
    best_name = ""

    for name, model in models.items():
        logger.info(f"⚡ Training {name}...")
        start_time = time.time()

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')

        training_time = time.time() - start_time

        results[name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'training_time': training_time
        }

        logger.info(f"📊 {name}: F1={f1:.4f}, Time={training_time:.2f}s")

        if f1 > best_score:
            best_score = f1
            best_model = model
            best_name = name

    # Feature importance
    if hasattr(best_model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': best_model.feature_importances_
        }).sort_values('importance', ascending=False)

        logger.info("🔍 Top 12 NCASv3_T4 Features:")
        for idx, row in feature_importance.head(12).iterrows():
            logger.info(f"   {row['feature']}: {row['importance']:.4f}")

    # Save results
    model_path = output_dir / f'vulnhunter_v5_ncasv3_{best_name}.joblib'
    joblib.dump(best_model, model_path)

    final_results = {
        'best_model': best_name,
        'best_f1': best_score,
        'target_achieved': best_score >= args.target_f1,
        'dataset_size': len(X),
        'feature_count': len(feature_cols),
        'all_results': results
    }

    results_path = output_dir / 'ncasv3_results.json'
    with open(results_path, 'w') as f:
        json.dump(final_results, f, indent=2)

    dataset_path = output_dir / 'ncasv3_dataset.csv'
    df.to_csv(dataset_path, index=False)

    logger.info("=" * 60)
    logger.info("🎯 NCASv3_T4-STYLE TRAINING COMPLETE")
    logger.info(f"🏆 Best Model: {best_name}")
    logger.info(f"📊 F1 Score: {best_score:.4f}")
    logger.info(f"✅ Target Achieved: {best_score >= args.target_f1}")
    logger.info(f"💾 Model: {model_path}")
    logger.info("=" * 60)

    return 0 if best_score >= args.target_f1 else 1

if __name__ == '__main__':
    exit(main())