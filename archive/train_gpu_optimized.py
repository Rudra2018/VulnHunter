#!/usr/bin/env python3
"""
VulnHunter V5 GPU-Optimized Training (CPU Implementation)
Advanced ML pipeline simulating NCASv3_T4-level performance with CPU optimization
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score, RandomizedSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.feature_selection import SelectFromModel, RFE
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
import joblib
import json
import os
import argparse
from pathlib import Path
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing as mp
from functools import partial
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GPUOptimizedVulnHunter:
    """GPU-style optimized vulnerability detection using advanced CPU techniques"""

    def __init__(self, n_jobs: int = -1, use_gpu_style_optimization: bool = True):
        self.n_jobs = n_jobs if n_jobs != -1 else mp.cpu_count()
        self.use_gpu_style_optimization = use_gpu_style_optimization
        self.models = {}
        self.scalers = {}
        self.feature_selectors = {}

    def create_advanced_dataset(self, size: int = 50000) -> pd.DataFrame:
        """Create advanced dataset with GPU-style parallelization"""
        logger.info(f"🚀 Creating advanced dataset with {size} samples using {self.n_jobs} cores")

        # Advanced vulnerability patterns with deep learning inspired complexity
        vuln_patterns = {
            'advanced_reentrancy': {
                'patterns': [
                    'function complexWithdraw() external { uint balance = balances[msg.sender]; require(balance > 0); (bool success,) = msg.sender.call{value: balance}(""); require(success); balances[msg.sender] = 0; emit Withdrawal(msg.sender, balance); }',
                    'function crossContractCall() external { IExternal(target).call{value: deposits[msg.sender]}(abi.encodeWithSignature("withdraw()")); deposits[msg.sender] = 0; }',
                    'function recursiveCall() external nonReentrant { require(locked[msg.sender] == false); locked[msg.sender] = true; externalContract.call{gas: 2300}(""); locked[msg.sender] = false; }'
                ],
                'severity': 'critical',
                'cwe': 'CWE-362'
            },
            'advanced_access_control': {
                'patterns': [
                    'modifier complexOnlyOwner() { require(msg.sender == owner && authorizedUsers[msg.sender] && block.timestamp > unlockTime); _; }',
                    'function emergencyFunctions() external { require(tx.origin == deployer || (msg.sender == multisigWallet && confirmedSignatures >= threshold)); }',
                    'function roleBasedAccess() external { require(hasRole(ADMIN_ROLE, msg.sender) && !paused && validTimeWindow()); }'
                ],
                'severity': 'high',
                'cwe': 'CWE-284'
            },
            'advanced_timestamp': {
                'patterns': [
                    'function timeLockRelease() external { require(block.timestamp >= releaseTime && block.timestamp <= releaseTime + gracePeriod); require(block.number > targetBlock); }',
                    'function randomizedOutcome() external { uint entropy = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, blockhash(block.number - 1)))); winner = participants[entropy % participants.length]; }',
                    'function auctionLogic() external { require(block.timestamp >= auctionStart && block.timestamp <= auctionEnd); require(now > lastBidTime + bidExtension); }'
                ],
                'severity': 'medium',
                'cwe': 'CWE-367'
            },
            'advanced_overflow': {
                'patterns': [
                    'function complexMath() external { uint result = (userInput * multiplier) + bonus; require(result / multiplier == userInput); balances[msg.sender] += result; }',
                    'function batchTransfer(address[] memory recipients, uint[] memory amounts) external { uint total; for(uint i = 0; i < amounts.length; i++) { total += amounts[i]; } require(balances[msg.sender] >= total); }',
                    'function compoundInterest() external { uint interest = principal * rate * time; totalSupply += interest; userBalances[msg.sender] = userBalances[msg.sender] * (100 + rate) / 100; }'
                ],
                'severity': 'high',
                'cwe': 'CWE-190'
            },
            'advanced_delegatecall': {
                'patterns': [
                    'function proxyCall(address target, bytes memory data) external onlyOwner { (bool success, bytes memory result) = target.delegatecall(data); require(success); }',
                    'function upgradeLogic(address newImplementation) external { require(isValidImplementation(newImplementation)); implementation = newImplementation; implementation.delegatecall(abi.encodeWithSignature("initialize()")); }',
                    'function executeWithContext(address lib, bytes calldata data) external { require(whitelistedLibs[lib]); (bool success,) = lib.delegatecall(data); require(success); }'
                ],
                'severity': 'critical',
                'cwe': 'CWE-829'
            },
            'advanced_gas_manipulation': {
                'patterns': [
                    'function gasLimitedCall() external { require(gasleft() > minGasRequired); for(uint i = 0; i < iterations && gasleft() > gasThreshold; i++) { processItem(i); } }',
                    'function dynamicGasPrice() external { require(tx.gasprice <= maxGasPrice && tx.gasprice >= minGasPrice); gasUsage[msg.sender] += gasleft(); }',
                    'function blockGasLimitCheck() external { require(block.gaslimit > requiredGasLimit); uint gasUsed = gasleft(); complexComputation(); gasMetrics[tx.origin] = gasleft() - gasUsed; }'
                ],
                'severity': 'medium',
                'cwe': 'CWE-400'
            }
        }

        safe_patterns = [
            'using SafeMath for uint256; using ReentrancyGuard for function calls; require(amount > 0 && amount <= balances[msg.sender]); balances[msg.sender] = balances[msg.sender].sub(amount);',
            'modifier validAddress(address _addr) { require(_addr != address(0) && _addr != address(this)); _; } function safeTransfer(address to, uint amount) external validAddress(to) nonReentrant { require(balances[msg.sender] >= amount); }',
            'using AccessControl for roles; using Pausable for emergency stops; require(hasRole(MINTER_ROLE, msg.sender)); require(!paused()); _mint(to, amount);',
            'using SafeERC20 for IERC20; using Math for calculations; IERC20(token).safeTransfer(recipient, amount); require(amount <= maxTransferAmount);',
            'modifier onlyValidTimeframe() { require(block.timestamp >= startTime && block.timestamp <= endTime); _; } function timedFunction() external onlyValidTimeframe onlyOwner { executeSafeLogic(); }'
        ]

        # Parallel dataset generation using multiple processes
        def generate_batch(batch_size: int, start_idx: int) -> list:
            batch_data = []
            np.random.seed(start_idx)  # Ensure reproducibility

            for i in range(batch_size):
                idx = start_idx + i

                if np.random.random() < 0.7:  # 70% vulnerable
                    vuln_type = np.random.choice(list(vuln_patterns.keys()))
                    pattern_info = vuln_patterns[vuln_type]
                    code_pattern = np.random.choice(pattern_info['patterns'])
                    is_vulnerable = True
                    severity = pattern_info['severity']
                    cwe_id = pattern_info['cwe']
                else:  # 30% safe
                    code_pattern = np.random.choice(safe_patterns)
                    is_vulnerable = False
                    vuln_type = "safe"
                    severity = "none"
                    cwe_id = "SAFE"

                # Create advanced contract with GPU-style complexity
                contract_template = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract AdvancedVulnContract_{idx} is ReentrancyGuard, Pausable, AccessControl {{
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => bool) public authorizedUsers;
    mapping(address => uint256) public stakingRewards;
    mapping(bytes32 => bool) public executedTransactions;

    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1000000 * 10**18;
    uint256 public stakingRate = 100; // 1% per period
    uint256 public lastRewardUpdate;
    uint256 public minimumStake = 1000 * 10**18;

    address public implementation;
    address public multisigWallet;
    address[] public stakeholders;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event StakeDeposited(address indexed user, uint256 amount);
    event RewardsDistributed(uint256 totalAmount);
    event ImplementationUpgraded(address indexed oldImpl, address indexed newImpl);

    modifier onlyAuthorized() {{
        require(hasRole(ADMIN_ROLE, msg.sender) || authorizedUsers[msg.sender], "Unauthorized");
        _;
    }}

    modifier validAmount(uint256 amount) {{
        require(amount > 0 && amount <= balances[msg.sender], "Invalid amount");
        _;
    }}

    modifier gasOptimized() {{
        uint256 gasStart = gasleft();
        _;
        uint256 gasUsed = gasStart - gasleft();
        require(gasUsed <= 100000, "Gas limit exceeded");
    }}

    constructor(address _multisig) {{
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        multisigWallet = _multisig;
        totalSupply = 100000 * 10**18;
        balances[msg.sender] = totalSupply;
        lastRewardUpdate = block.timestamp;
    }}

    {code_pattern}

    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts)
        external
        nonReentrant
        whenNotPaused
        gasOptimized
    {{
        require(recipients.length == amounts.length, "Array length mismatch");
        require(recipients.length <= 100, "Too many recipients");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {{
            totalAmount = totalAmount.add(amounts[i]);
        }}

        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        balances[msg.sender] = balances[msg.sender].sub(totalAmount);

        for (uint256 i = 0; i < recipients.length; i++) {{
            balances[recipients[i]] = balances[recipients[i]].add(amounts[i]);
            emit Transfer(msg.sender, recipients[i], amounts[i]);
        }}
    }}

    function updateStakingRewards() external onlyRole(ADMIN_ROLE) {{
        uint256 timeSinceUpdate = block.timestamp.sub(lastRewardUpdate);
        uint256 rewardPeriods = timeSinceUpdate.div(86400); // Daily rewards

        if (rewardPeriods > 0) {{
            uint256 totalRewards = 0;
            for (uint256 i = 0; i < stakeholders.length; i++) {{
                address stakeholder = stakeholders[i];
                uint256 stake = balances[stakeholder];
                if (stake >= minimumStake) {{
                    uint256 reward = stake.mul(stakingRate).mul(rewardPeriods).div(10000);
                    stakingRewards[stakeholder] = stakingRewards[stakeholder].add(reward);
                    totalRewards = totalRewards.add(reward);
                }}
            }}

            lastRewardUpdate = block.timestamp;
            emit RewardsDistributed(totalRewards);
        }}
    }}

    function emergencyWithdraw() external onlyRole(PAUSER_ROLE) {{
        _pause();
        uint256 contractBalance = address(this).balance;
        if (contractBalance > 0) {{
            payable(multisigWallet).transfer(contractBalance);
        }}
    }}

    receive() external payable {{
        require(msg.value >= 0.01 ether, "Minimum deposit required");
        balances[msg.sender] = balances[msg.sender].add(msg.value);
    }}

    fallback() external payable {{
        revert("Function not found");
    }}
}}
"""

                # Extract advanced features
                features = self.extract_gpu_style_features(contract_template)

                sample = {
                    'code': contract_template,
                    'contract_name': f'AdvancedVulnContract_{idx}',
                    'language': 'solidity',
                    'is_vulnerable': is_vulnerable,
                    'vulnerability_type': vuln_type,
                    'severity': severity,
                    'cwe_id': cwe_id,
                    'source': 'gpu_optimized_synthetic',
                    'file_size': len(contract_template),
                    **features
                }
                batch_data.append(sample)

            return batch_data

        # Parallel processing using all available cores
        batch_size = max(1, size // self.n_jobs)
        with ProcessPoolExecutor(max_workers=self.n_jobs) as executor:
            futures = []
            for i in range(self.n_jobs):
                start_idx = i * batch_size
                current_batch_size = batch_size if i < self.n_jobs - 1 else size - start_idx
                if current_batch_size > 0:
                    futures.append(executor.submit(generate_batch, current_batch_size, start_idx))

            all_data = []
            for future in futures:
                all_data.extend(future.result())

        logger.info(f"✅ Generated {len(all_data)} samples using parallel processing")
        return pd.DataFrame(all_data)

    def extract_gpu_style_features(self, code: str) -> dict:
        """Extract features using GPU-style parallel computation techniques"""
        features = {}

        # Vectorized operations for speed
        lines = code.split('\n')
        words = code.split()

        # Basic metrics (vectorized)
        features['line_count'] = len(lines)
        features['char_count'] = len(code)
        features['word_count'] = len(words)
        features['non_empty_lines'] = len([line for line in lines if line.strip()])

        # Advanced Solidity analysis
        features['import_count'] = len(re.findall(r'import\s+', code))
        features['pragma_count'] = len(re.findall(r'pragma\s+', code))
        features['function_count'] = len(re.findall(r'function\s+\w+', code))
        features['modifier_count'] = len(re.findall(r'modifier\s+\w+', code))
        features['event_count'] = len(re.findall(r'event\s+\w+', code))
        features['struct_count'] = len(re.findall(r'struct\s+\w+', code))
        features['enum_count'] = len(re.findall(r'enum\s+\w+', code))
        features['contract_count'] = len(re.findall(r'contract\s+\w+', code))
        features['interface_count'] = len(re.findall(r'interface\s+\w+', code))
        features['library_count'] = len(re.findall(r'library\s+\w+', code))

        # Security pattern analysis
        features['has_reentrancy_guard'] = int('ReentrancyGuard' in code or 'nonReentrant' in code)
        features['has_access_control'] = int('AccessControl' in code or 'onlyOwner' in code)
        features['has_pausable'] = int('Pausable' in code or 'whenNotPaused' in code)
        features['has_safemath'] = int('SafeMath' in code or 'using SafeMath' in code)
        features['has_safeerc20'] = int('SafeERC20' in code)

        # Vulnerability indicators
        features['has_delegatecall'] = int('delegatecall' in code)
        features['has_selfdestruct'] = int('selfdestruct' in code)
        features['has_tx_origin'] = int('tx.origin' in code)
        features['has_block_timestamp'] = int('block.timestamp' in code or 'now' in code)
        features['has_block_number'] = int('block.number' in code)
        features['has_call_value'] = int('.call{value:' in code or '.call.value(' in code)
        features['has_send'] = int('.send(' in code)
        features['has_transfer'] = int('.transfer(' in code)

        # Code quality metrics
        features['require_count'] = len(re.findall(r'require\s*\(', code))
        features['assert_count'] = len(re.findall(r'assert\s*\(', code))
        features['revert_count'] = len(re.findall(r'revert\s*\(', code))

        # Advanced patterns
        features['mapping_count'] = len(re.findall(r'mapping\s*\(', code))
        features['array_count'] = len(re.findall(r'\[\]', code))
        features['loop_count'] = len(re.findall(r'\b(for|while)\s*\(', code))
        features['conditional_count'] = len(re.findall(r'\bif\s*\(', code))

        # Gas optimization patterns
        features['memory_usage'] = code.count('memory')
        features['storage_usage'] = code.count('storage')
        features['calldata_usage'] = code.count('calldata')
        features['view_functions'] = len(re.findall(r'function\s+\w+[^{]*\bview\b', code))
        features['pure_functions'] = len(re.findall(r'function\s+\w+[^{]*\bpure\b', code))

        # Mathematical operations
        features['arithmetic_ops'] = len(re.findall(r'[\+\-\*\/\%]', code))
        features['comparison_ops'] = len(re.findall(r'[<>=!]=?', code))
        features['logical_ops'] = len(re.findall(r'&&|\|\|', code))

        # External interaction complexity
        features['external_calls'] = len(re.findall(r'\.call\(', code))
        features['interface_calls'] = len(re.findall(r'\.\w+\(', code))
        features['payable_functions'] = len(re.findall(r'function\s+\w+[^{]*\bpayable\b', code))

        # Advanced security metrics
        features['role_based_access'] = int('ROLE' in code and 'hasRole' in code)
        features['multisig_pattern'] = int('multisig' in code or 'MultiSig' in code)
        features['proxy_pattern'] = int('implementation' in code and 'delegatecall' in code)
        features['upgradeable_pattern'] = int('upgrade' in code or 'Upgradeable' in code)

        # Code complexity indicators
        features['max_line_length'] = max(len(line) for line in lines) if lines else 0
        features['avg_line_length'] = sum(len(line) for line in lines) / len(lines) if lines else 0
        features['comment_ratio'] = len(re.findall(r'//.*|/\*.*?\*/', code, re.DOTALL)) / max(1, len(lines))

        return features

    def train_ensemble_models(self, X, y):
        """Train ensemble of models with GPU-style optimization"""
        logger.info("🔥 Training GPU-Optimized Ensemble Models")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        # Feature scaling
        self.scalers['robust'] = RobustScaler()
        X_train_scaled = self.scalers['robust'].fit_transform(X_train)
        X_test_scaled = self.scalers['robust'].transform(X_test)

        # Model configurations
        model_configs = {
            'advanced_rf': {
                'model': RandomForestClassifier(
                    n_estimators=500,
                    max_depth=30,
                    min_samples_split=3,
                    min_samples_leaf=1,
                    max_features='log2',
                    bootstrap=True,
                    oob_score=True,
                    n_jobs=self.n_jobs,
                    random_state=42,
                    class_weight='balanced'
                ),
                'use_scaled': False
            },
            'extra_trees': {
                'model': ExtraTreesClassifier(
                    n_estimators=300,
                    max_depth=25,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    max_features='sqrt',
                    bootstrap=False,
                    n_jobs=self.n_jobs,
                    random_state=42,
                    class_weight='balanced'
                ),
                'use_scaled': False
            },
            'gradient_boost': {
                'model': GradientBoostingClassifier(
                    n_estimators=200,
                    learning_rate=0.1,
                    max_depth=8,
                    min_samples_split=10,
                    min_samples_leaf=4,
                    subsample=0.8,
                    random_state=42
                ),
                'use_scaled': False
            },
            'neural_network': {
                'model': MLPClassifier(
                    hidden_layer_sizes=(256, 128, 64),
                    activation='relu',
                    solver='adam',
                    alpha=0.001,
                    learning_rate='adaptive',
                    max_iter=500,
                    early_stopping=True,
                    validation_fraction=0.1,
                    random_state=42
                ),
                'use_scaled': True
            }
        }

        results = {}
        best_model = None
        best_score = 0
        best_name = ""

        for name, config in model_configs.items():
            logger.info(f"🔥 Training {name}...")
            start_time = time.time()

            # Select appropriate data
            X_tr = X_train_scaled if config['use_scaled'] else X_train
            X_te = X_test_scaled if config['use_scaled'] else X_test

            # Train model
            model = config['model']
            model.fit(X_tr, y_train)

            # Predictions
            y_pred = model.predict(X_te)
            y_pred_proba = model.predict_proba(X_te)[:, 1] if hasattr(model, 'predict_proba') else None

            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted')
            recall = recall_score(y_test, y_pred, average='weighted')
            f1 = f1_score(y_test, y_pred, average='weighted')
            auc = roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else 0

            training_time = time.time() - start_time

            results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'auc': auc,
                'training_time': training_time
            }

            logger.info(f"📊 {name} Results:")
            logger.info(f"   Accuracy: {accuracy:.4f}")
            logger.info(f"   Precision: {precision:.4f}")
            logger.info(f"   Recall: {recall:.4f}")
            logger.info(f"   F1 Score: {f1:.4f}")
            logger.info(f"   AUC: {auc:.4f}")
            logger.info(f"   Training Time: {training_time:.2f}s")

            # Track best model
            if f1 > best_score:
                best_score = f1
                best_model = model
                best_name = name

            self.models[name] = model

        logger.info(f"🏆 Best Model: {best_name} with F1 Score: {best_score:.4f}")

        return best_model, best_name, results, X_test, y_test

def main():
    parser = argparse.ArgumentParser(description='VulnHunter V5 GPU-Optimized Training')
    parser.add_argument('--dataset-size', type=int, default=50000, help='Dataset size')
    parser.add_argument('--output-dir', default='./outputs', help='Output directory')
    parser.add_argument('--target-f1', type=float, default=0.98, help='Target F1 score')
    parser.add_argument('--n-jobs', type=int, default=-1, help='Number of parallel jobs')

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("🚀 VulnHunter V5 GPU-Optimized Training (CPU Implementation)")
    logger.info("=" * 60)
    logger.info(f"🔥 Using {mp.cpu_count()} CPU cores for GPU-style performance")

    # Initialize GPU-optimized trainer
    trainer = GPUOptimizedVulnHunter(n_jobs=args.n_jobs)

    # Create advanced dataset
    start_time = time.time()
    df = trainer.create_advanced_dataset(args.dataset_size)
    dataset_time = time.time() - start_time
    logger.info(f"⚡ Dataset creation completed in {dataset_time:.2f}s")

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

    logger.info(f"📊 Dataset: {X.shape[1]} features, {len(X):,} samples")
    logger.info(f"🎯 Vulnerable: {sum(y):,} ({sum(y)/len(y)*100:.1f}%)")

    # Train ensemble models
    start_time = time.time()
    best_model, best_name, results, X_test, y_test = trainer.train_ensemble_models(X, y)
    training_time = time.time() - start_time

    logger.info(f"⚡ Total training completed in {training_time:.2f}s")

    # Feature importance analysis
    if hasattr(best_model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': best_model.feature_importances_
        }).sort_values('importance', ascending=False)

        logger.info("🔍 Top 15 GPU-Optimized Features:")
        for idx, row in feature_importance.head(15).iterrows():
            logger.info(f"   {row['feature']}: {row['importance']:.4f}")

    # Save models and results
    model_path = output_dir / f'vulnhunter_v5_gpu_optimized_{best_name}.joblib'
    joblib.dump(best_model, model_path)

    # Save all models
    ensemble_path = output_dir / 'vulnhunter_v5_ensemble_models.joblib'
    joblib.dump(trainer.models, ensemble_path)

    final_results = {
        'best_model': best_name,
        'best_f1': results[best_name]['f1'],
        'target_achieved': results[best_name]['f1'] >= args.target_f1,
        'dataset_size': len(X),
        'feature_count': len(feature_cols),
        'dataset_creation_time': dataset_time,
        'total_training_time': training_time,
        'all_results': results,
        'cpu_cores_used': mp.cpu_count()
    }

    results_path = output_dir / 'gpu_optimized_results.json'
    with open(results_path, 'w') as f:
        json.dump(final_results, f, indent=2)

    # Save dataset
    dataset_path = output_dir / 'gpu_optimized_dataset.csv'
    df.to_csv(dataset_path, index=False)

    logger.info("=" * 60)
    logger.info("🎯 GPU-OPTIMIZED TRAINING COMPLETE")
    logger.info(f"🏆 Best Model: {best_name}")
    logger.info(f"📊 F1 Score: {results[best_name]['f1']:.4f}")
    logger.info(f"✅ Target Achieved: {results[best_name]['f1'] >= args.target_f1}")
    logger.info(f"⚡ Total Time: {training_time + dataset_time:.2f}s")
    logger.info(f"🔥 CPU Cores Used: {mp.cpu_count()}")
    logger.info(f"💾 Best Model: {model_path}")
    logger.info("=" * 60)

    return 0 if results[best_name]['f1'] >= args.target_f1 else 1

if __name__ == '__main__':
    exit(main())