#!/usr/bin/env python3
"""
VulnHunter V5 Production Dataset Preparation
Comprehensive dataset preparation for full-scale training on new Azure account
"""

import os
import sys
import asyncio
import requests
import json
import pandas as pd
import numpy as np
from pathlib import Path
import logging
from typing import Dict, List, Any, Tuple, Optional
import zipfile
import tarfile
import git
import pickle
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import time
import re
from urllib.parse import urljoin, urlparse
import subprocess
import multiprocessing as mp

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProductionDatasetLoader:
    """Production-scale dataset loader for comprehensive vulnerability training"""

    def __init__(self, cache_dir: str = "./data/production_datasets", max_workers: int = 16):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers

        # Comprehensive dataset sources
        self.dataset_sources = {
            'juliet_comprehensive': {
                'urls': [
                    'https://samate.nist.gov/SARD/downloads/test-suites/juliet-test-suite-for-c-cpp-v1-3.zip',
                    'https://github.com/sei-cmu/juliet-test-suite-c/archive/main.zip'
                ],
                'target_samples': 75000,
                'description': 'Complete Juliet Test Suite for C/C++'
            },
            'smartbugs_complete': {
                'repos': [
                    'https://github.com/smartbugs/smartbugs.git',
                    'https://github.com/smartbugs/smartbugs-wild.git',
                    'https://github.com/smartbugs/smartbugs-curated.git'
                ],
                'target_samples': 50000,
                'description': 'Complete SmartBugs vulnerability collection'
            },
            'bigvul_extended': {
                'repos': [
                    'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset.git',
                    'https://github.com/VulnTotal-Team/VulnTotal.git',
                    'https://github.com/VulnPecker/VulnPecker.git'
                ],
                'target_samples': 25000,
                'description': 'Extended Big-Vul and related datasets'
            },
            'real_world_contracts': {
                'description': 'Real-world smart contracts from multiple sources',
                'target_samples': 30000,
                'sources': [
                    'ethereum_mainnet',
                    'polygon_contracts',
                    'bsc_contracts',
                    'verified_contracts'
                ]
            },
            'cve_database': {
                'description': 'CVE database vulnerability patterns',
                'target_samples': 15000,
                'sources': ['mitre_cve', 'nvd_database']
            }
        }

    def create_comprehensive_synthetic_dataset(self, size: int = 100000) -> pd.DataFrame:
        """Create comprehensive synthetic dataset for production training"""
        logger.info(f"🚀 Creating comprehensive synthetic dataset with {size} samples")

        # Production-level vulnerability patterns
        vuln_categories = {
            'memory_corruption': {
                'patterns': [
                    'char buffer[256]; strcpy(buffer, user_input); return buffer;',
                    'int* ptr = malloc(size); free(ptr); return *ptr;',
                    'void vulnerable_function(char* input) { char buf[100]; strcpy(buf, input); }',
                    'int array[10]; for(int i = 0; i <= 10; i++) { array[i] = user_data[i]; }'
                ],
                'cwe': ['CWE-119', 'CWE-120', 'CWE-416', 'CWE-787'],
                'severity': 'critical'
            },
            'injection_attacks': {
                'patterns': [
                    'query = "SELECT * FROM users WHERE id = " + user_id; execute_query(query);',
                    'system("rm -rf " + user_path);',
                    'eval(user_input);',
                    'document.innerHTML = user_content;'
                ],
                'cwe': ['CWE-89', 'CWE-78', 'CWE-79', 'CWE-94'],
                'severity': 'high'
            },
            'authentication_bypass': {
                'patterns': [
                    'if(password == "admin123") { grant_access(); }',
                    'token = md5(username); if(token == user_token) { authenticate(); }',
                    'if(user.role || user.is_admin) { admin_function(); }',
                    'session_id = time(); return session_id;'
                ],
                'cwe': ['CWE-287', 'CWE-290', 'CWE-798', 'CWE-330'],
                'severity': 'high'
            },
            'cryptographic_issues': {
                'patterns': [
                    'key = "1234567890123456"; encrypt_data(data, key);',
                    'hash = md5(password); store_hash(hash);',
                    'random_value = time() % 1000;',
                    'private_key = generate_key(seed=1);'
                ],
                'cwe': ['CWE-327', 'CWE-338', 'CWE-326', 'CWE-311'],
                'severity': 'medium'
            },
            'race_conditions': {
                'patterns': [
                    'if(balance >= amount) { sleep(1); balance -= amount; }',
                    'file_exists = check_file(path); create_file(path);',
                    'lock(mutex); shared_var++; unlock(mutex);',
                    'temp_file = create_temp(); write_data(temp_file);'
                ],
                'cwe': ['CWE-362', 'CWE-367', 'CWE-364', 'CWE-366'],
                'severity': 'medium'
            },
            'smart_contract_vulnerabilities': {
                'patterns': [
                    'function withdraw() { msg.sender.call.value(balances[msg.sender])(); balances[msg.sender] = 0; }',
                    'require(tx.origin == owner);',
                    'uint random = block.timestamp % 100;',
                    'balances[to] += amount; balances[from] -= amount;'
                ],
                'cwe': ['CWE-362', 'CWE-346', 'CWE-367', 'CWE-190'],
                'severity': 'high'
            },
            'integer_vulnerabilities': {
                'patterns': [
                    'size_t total = count * size; buffer = malloc(total);',
                    'int result = a + b; if(result < a) { overflow_detected(); }',
                    'unsigned int index = user_input - 1; return array[index];',
                    'short value = large_number; process_value(value);'
                ],
                'cwe': ['CWE-190', 'CWE-191', 'CWE-128', 'CWE-681'],
                'severity': 'high'
            },
            'information_disclosure': {
                'patterns': [
                    'printf("Debug: password = %s\\n", password);',
                    'error_msg = "Database connection failed: " + db_error;',
                    'stack_trace = get_full_stack_trace(); return stack_trace;',
                    'temp_file = "/tmp/debug_" + user_id + ".log";'
                ],
                'cwe': ['CWE-200', 'CWE-209', 'CWE-532', 'CWE-215'],
                'severity': 'medium'
            }
        }

        safe_patterns = [
            'if(input_length > 0 && input_length < MAX_SIZE) { strncpy(buffer, input, input_length); buffer[input_length] = \'\\0\'; }',
            'query = prepare_statement("SELECT * FROM users WHERE id = ?"); bind_parameter(query, user_id); execute_prepared(query);',
            'if(authenticate_user(username, password_hash) && check_permissions(user, action)) { execute_action(action); }',
            'random_bytes = secure_random_generator(32); key = derive_key(random_bytes, salt);',
            'mutex_lock(&data_mutex); shared_data = new_value; mutex_unlock(&data_mutex);',
            'require(msg.sender == owner && amount > 0 && amount <= balances[msg.sender]); balances[msg.sender] -= amount;',
            'if(a > 0 && b > 0 && a <= (SIZE_MAX / b)) { result = a * b; } else { handle_overflow(); }',
            'sanitized_input = escape_html(user_input); log_info("User action: " + sanitized_input);'
        ]

        # Generate samples using multiple processes for performance
        def generate_batch(start_idx: int, batch_size: int) -> List[Dict]:
            batch_data = []
            np.random.seed(start_idx)  # Reproducible randomness

            for i in range(batch_size):
                idx = start_idx + i

                if np.random.random() < 0.75:  # 75% vulnerable
                    category = np.random.choice(list(vuln_categories.keys()))
                    category_info = vuln_categories[category]
                    code_pattern = np.random.choice(category_info['patterns'])
                    cwe_id = np.random.choice(category_info['cwe'])
                    is_vulnerable = True
                    severity = category_info['severity']
                    vuln_type = category
                else:  # 25% safe
                    code_pattern = np.random.choice(safe_patterns)
                    is_vulnerable = False
                    vuln_type = "safe"
                    severity = "none"
                    cwe_id = "SAFE"

                # Create realistic code structure
                languages = ['c', 'cpp', 'java', 'python', 'javascript', 'solidity']
                language = np.random.choice(languages)

                if language == 'solidity':
                    code_template = f"""
pragma solidity ^0.8.0;

contract VulnContract_{idx} {{
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {{
        owner = msg.sender;
    }}

    {code_pattern}

    function getBalance() public view returns (uint256) {{
        return balances[msg.sender];
    }}
}}
"""
                elif language in ['c', 'cpp']:
                    code_template = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vulnerable_function_{idx}(char* user_input, int size) {{
    {code_pattern}
    return 0;
}}

int main() {{
    char input[1024];
    gets(input);
    return vulnerable_function_{idx}(input, strlen(input));
}}
"""
                else:
                    code_template = f"""
def vulnerable_function_{idx}(user_input, size):
    {code_pattern}
    return True

if __name__ == "__main__":
    user_data = input("Enter data: ")
    vulnerable_function_{idx}(user_data, len(user_data))
"""

                # Extract comprehensive features
                features = self.extract_production_features(code_template, language)

                sample = {
                    'code': code_template,
                    'language': language,
                    'is_vulnerable': is_vulnerable,
                    'vulnerability_type': vuln_type,
                    'severity': severity,
                    'cwe_id': cwe_id,
                    'source': 'production_synthetic',
                    'file_size': len(code_template),
                    'sample_id': f'prod_sample_{idx}',
                    **features
                }
                batch_data.append(sample)

            return batch_data

        # Parallel generation for performance
        logger.info(f"Using {self.max_workers} processes for parallel generation...")
        batch_size = max(1, size // self.max_workers)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for i in range(self.max_workers):
                start_idx = i * batch_size
                current_batch_size = batch_size if i < self.max_workers - 1 else size - start_idx
                if current_batch_size > 0:
                    futures.append(executor.submit(generate_batch, start_idx, current_batch_size))

            all_data = []
            for future in as_completed(futures):
                all_data.extend(future.result())

        logger.info(f"✅ Generated {len(all_data)} comprehensive samples")
        return pd.DataFrame(all_data)

    def extract_production_features(self, code: str, language: str) -> Dict:
        """Extract comprehensive features for production training"""
        features = {}

        # Basic metrics
        lines = code.split('\n')
        words = code.split()
        features['line_count'] = len(lines)
        features['char_count'] = len(code)
        features['word_count'] = len(words)
        features['non_empty_lines'] = len([line for line in lines if line.strip()])

        # Language-specific features
        features['is_c'] = int(language in ['c', 'cpp'])
        features['is_java'] = int(language == 'java')
        features['is_python'] = int(language == 'python')
        features['is_javascript'] = int(language == 'javascript')
        features['is_solidity'] = int(language == 'solidity')

        # Vulnerability indicators
        features['has_malloc'] = int('malloc(' in code)
        features['has_free'] = int('free(' in code)
        features['has_strcpy'] = int('strcpy(' in code)
        features['has_system'] = int('system(' in code)
        features['has_eval'] = int('eval(' in code)
        features['has_sql_keywords'] = int(any(kw in code.lower() for kw in ['select', 'insert', 'update', 'delete']))

        # Security patterns
        features['has_input_validation'] = int(any(pattern in code for pattern in ['check_', 'validate_', 'sanitize_']))
        features['has_bounds_check'] = int('if(' in code and any(op in code for op in ['<', '>', '<=', '>=']))
        features['has_null_check'] = int('!= NULL' in code or '== NULL' in code)
        features['has_secure_functions'] = int(any(func in code for func in ['strncpy', 'snprintf', 'secure_']))

        # Complexity metrics
        features['function_count'] = len(re.findall(r'function\s+\w+|def\s+\w+|int\s+\w+\s*\(', code))
        features['conditional_count'] = len(re.findall(r'\bif\s*\(', code))
        features['loop_count'] = len(re.findall(r'\b(for|while)\s*\(', code))
        features['assignment_count'] = len(re.findall(r'\w+\s*=\s*', code))

        # Mathematical operations
        features['arithmetic_ops'] = len(re.findall(r'[\+\-\*\/\%]', code))
        features['comparison_ops'] = len(re.findall(r'[<>=!]=?', code))
        features['logical_ops'] = len(re.findall(r'&&|\|\|', code))

        # Memory operations
        features['pointer_ops'] = len(re.findall(r'[\*&]', code))
        features['array_access'] = len(re.findall(r'\[\w*\]', code))
        features['memory_functions'] = len(re.findall(r'\b(malloc|calloc|realloc|free)\b', code))

        # Code quality indicators
        features['comment_count'] = len(re.findall(r'//.*|/\*.*?\*/|#.*', code, re.DOTALL))
        features['string_literals'] = len(re.findall(r'"[^"]*"', code))
        features['numeric_literals'] = len(re.findall(r'\b\d+\b', code))

        # Advanced patterns
        features['crypto_keywords'] = int(any(kw in code.lower() for kw in ['encrypt', 'decrypt', 'hash', 'key', 'crypto']))
        features['network_keywords'] = int(any(kw in code.lower() for kw in ['socket', 'connect', 'send', 'recv', 'http']))
        features['file_operations'] = int(any(kw in code.lower() for kw in ['fopen', 'fread', 'fwrite', 'fclose', 'file']))

        return features

    def load_existing_datasets(self) -> List[pd.DataFrame]:
        """Load all existing datasets for comprehensive training"""
        datasets = []

        # Load previous datasets if they exist
        existing_paths = [
            "./data/production/vulnhunter_v5_full_dataset.csv",
            "./payg_production_output/enhanced_smart_contract_dataset.csv",
            "./ncasv3_output/ncasv3_dataset.csv",
            "./gpu_optimized_output/gpu_optimized_dataset.csv"
        ]

        for path in existing_paths:
            if os.path.exists(path):
                try:
                    df = pd.read_csv(path, low_memory=False)
                    logger.info(f"Loaded {len(df)} samples from {path}")
                    datasets.append(df)
                except Exception as e:
                    logger.warning(f"Failed to load {path}: {e}")

        return datasets

    def prepare_production_dataset(self, target_size: int = 200000) -> str:
        """Prepare comprehensive production dataset"""
        logger.info("🚀 Starting Production Dataset Preparation")
        logger.info("=" * 60)

        all_datasets = []

        # 1. Load existing datasets
        logger.info("📂 Loading existing datasets...")
        existing_datasets = self.load_existing_datasets()
        all_datasets.extend(existing_datasets)

        # 2. Create comprehensive synthetic dataset
        logger.info(f"🧬 Creating comprehensive synthetic dataset ({target_size} samples)...")
        synthetic_df = self.create_comprehensive_synthetic_dataset(target_size)
        all_datasets.append(synthetic_df)

        # 3. Combine all datasets
        if all_datasets:
            logger.info("🔄 Combining all datasets...")
            combined_df = pd.concat(all_datasets, ignore_index=True, sort=False)
        else:
            combined_df = synthetic_df

        # 4. Clean and standardize
        logger.info("🧹 Cleaning and standardizing data...")

        # Standardize column names
        if 'vulnerable' in combined_df.columns and 'is_vulnerable' not in combined_df.columns:
            combined_df['is_vulnerable'] = combined_df['vulnerable']

        # Fill missing values
        combined_df = combined_df.fillna(0)

        # Remove duplicates
        initial_size = len(combined_df)
        combined_df = combined_df.drop_duplicates(subset=['code'], keep='first')
        logger.info(f"Removed {initial_size - len(combined_df)} duplicate samples")

        # 5. Feature engineering
        logger.info("⚙️ Advanced feature engineering...")

        # Ensure all samples have required features
        required_features = [
            'line_count', 'char_count', 'word_count', 'function_count',
            'conditional_count', 'loop_count', 'assignment_count'
        ]

        for feature in required_features:
            if feature not in combined_df.columns:
                if feature == 'line_count':
                    combined_df[feature] = combined_df['code'].str.count('\n') + 1
                elif feature == 'char_count':
                    combined_df[feature] = combined_df['code'].str.len()
                elif feature == 'word_count':
                    combined_df[feature] = combined_df['code'].str.split().str.len()
                else:
                    combined_df[feature] = 0

        # 6. Save production dataset
        output_dir = Path("./data/production_full")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save as multiple formats for flexibility
        csv_path = output_dir / "vulnhunter_v5_production_full_dataset.csv"
        parquet_path = output_dir / "vulnhunter_v5_production_full_dataset.parquet"

        combined_df.to_csv(csv_path, index=False)
        logger.info(f"💾 Saved CSV dataset: {csv_path}")

        try:
            combined_df.to_parquet(parquet_path, index=False)
            logger.info(f"💾 Saved Parquet dataset: {parquet_path}")
        except:
            logger.warning("Could not save Parquet format")

        # Save metadata
        metadata = {
            'total_samples': len(combined_df),
            'vulnerable_samples': int(combined_df['is_vulnerable'].sum()),
            'safe_samples': int((~combined_df['is_vulnerable']).sum()),
            'vulnerability_ratio': float(combined_df['is_vulnerable'].mean()),
            'features_count': len([col for col in combined_df.columns if col not in ['code', 'file_path']]),
            'languages': list(combined_df.get('language', pd.Series(['mixed'])).unique()),
            'sources': list(combined_df.get('source', pd.Series(['production'])).unique()),
            'creation_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'dataset_paths': {
                'csv': str(csv_path),
                'parquet': str(parquet_path)
            }
        }

        metadata_path = output_dir / "dataset_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info("=" * 60)
        logger.info("✅ Production Dataset Preparation Complete!")
        logger.info(f"📊 Total Samples: {len(combined_df):,}")
        logger.info(f"🎯 Vulnerable: {int(combined_df['is_vulnerable'].sum()):,} ({combined_df['is_vulnerable'].mean()*100:.1f}%)")
        logger.info(f"🔧 Features: {len([col for col in combined_df.columns if col not in ['code', 'file_path']]):,}")
        logger.info(f"💾 Dataset Path: {csv_path}")
        logger.info("=" * 60)

        return str(csv_path)

def main():
    """Main execution function"""
    import argparse

    parser = argparse.ArgumentParser(description='Prepare production datasets for VulnHunter V5')
    parser.add_argument('--size', type=int, default=200000, help='Target dataset size')
    parser.add_argument('--workers', type=int, default=16, help='Number of worker processes')

    args = parser.parse_args()

    loader = ProductionDatasetLoader(max_workers=args.workers)
    dataset_path = loader.prepare_production_dataset(args.size)

    print(f"\n🎉 Production dataset ready at: {dataset_path}")
    return dataset_path

if __name__ == '__main__':
    main()