#!/usr/bin/env python3
"""
Full-scale dataset preparation for VulnHunter V5
Downloads and processes complete vulnerability datasets for production training
"""

import os
import sys
import requests
import json
import pandas as pd
import numpy as np
from pathlib import Path
import logging
from typing import Dict, List, Any, Tuple
import zipfile
import tarfile
import git
import pickle
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import time
import re

# Add src to path
sys.path.append('.')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FullDatasetLoader:
    """Production-scale dataset loader for vulnerability detection"""

    def __init__(self, cache_dir: str = "./data/full_datasets", max_workers: int = 8):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers

        # Dataset URLs and configurations
        self.dataset_configs = {
            'juliet': {
                'url': 'https://samate.nist.gov/SARD/downloads/test-suites/juliet-test-suite-for-c-cpp-v1-3.zip',
                'target_samples': 50000,
                'file_patterns': ['*.c', '*.cpp', '*.h']
            },
            'bigvul': {
                'repo': 'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset.git',
                'target_samples': 10000,
                'file_patterns': ['*.csv']
            },
            'sard': {
                'base_url': 'https://samate.nist.gov/SARD/downloads',
                'target_samples': 20000,
                'categories': ['buffer-overflow', 'injection', 'crypto']
            },
            'smart_contracts': {
                'sources': [
                    'https://github.com/smartbugs/smartbugs-wild.git',
                    'https://github.com/crytic/not-so-smart-contracts.git'
                ],
                'target_samples': 5000
            }
        }

    def download_with_retry(self, url: str, filepath: Path, max_retries: int = 3) -> bool:
        """Download file with retry logic"""
        for attempt in range(max_retries):
            try:
                logger.info(f"Downloading {url} (attempt {attempt + 1}/{max_retries})")
                response = requests.get(url, stream=True, timeout=30)
                response.raise_for_status()

                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                logger.info(f"Successfully downloaded {filepath}")
                return True

            except Exception as e:
                logger.warning(f"Download attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff

        return False

    def fetch_juliet_dataset(self) -> pd.DataFrame:
        """Fetch complete Juliet Test Suite"""
        logger.info("Fetching complete Juliet Test Suite...")

        juliet_dir = self.cache_dir / "juliet_full"
        juliet_dir.mkdir(exist_ok=True)

        # Try to download from multiple mirrors
        urls = [
            'https://samate.nist.gov/SARD/downloads/test-suites/juliet-test-suite-for-c-cpp-v1-3.zip',
            'https://github.com/juli1/juliet-test-suite-c/archive/refs/heads/master.zip'
        ]

        juliet_file = None
        for url in urls:
            try:
                juliet_file = juliet_dir / f"juliet_{hashlib.md5(url.encode()).hexdigest()}.zip"
                if not juliet_file.exists():
                    if self.download_with_retry(url, juliet_file):
                        break
                else:
                    break
            except Exception as e:
                logger.warning(f"Failed to download from {url}: {e}")
                continue

        if not juliet_file or not juliet_file.exists():
            logger.warning("Could not download Juliet dataset, creating synthetic data")
            return self._create_synthetic_juliet_data(50000)

        # Extract and process
        extract_dir = juliet_dir / "extracted"
        if not extract_dir.exists():
            logger.info("Extracting Juliet dataset...")
            with zipfile.ZipFile(juliet_file, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

        return self._process_juliet_files(extract_dir)

    def _process_juliet_files(self, extract_dir: Path) -> pd.DataFrame:
        """Process Juliet files in parallel"""
        logger.info("Processing Juliet files...")

        # Find all C/C++ files
        files = []
        for pattern in ['**/*.c', '**/*.cpp', '**/*.h']:
            files.extend(extract_dir.glob(pattern))

        logger.info(f"Found {len(files)} Juliet files to process")

        data = []

        def process_file(file_path: Path) -> Dict[str, Any]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Extract CWE and vulnerability info from filename and content
                filename = file_path.name
                cwe_match = filename.split('_')[0] if '_' in filename else 'Unknown'
                is_vulnerable = 1 if '_bad' in filename or 'FLAW' in content else 0

                # Extract function-level code
                functions = self._extract_functions(content)

                results = []
                for func_name, func_code in functions:
                    if len(func_code.strip()) > 50:  # Skip very short functions
                        results.append({
                            'code': func_code,
                            'function_name': func_name,
                            'file_path': str(file_path),
                            'cwe_id': cwe_match,
                            'vulnerability_type': self._map_cwe_to_type(cwe_match),
                            'is_vulnerable': is_vulnerable,
                            'dataset_source': 'juliet',
                            'language': 'c' if filename.endswith('.c') else 'cpp',
                            'file_size': len(content),
                            'complexity_score': self._calculate_complexity(func_code)
                        })

                return results

            except Exception as e:
                logger.warning(f"Error processing {file_path}: {e}")
                return []

        # Process files in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(process_file, f): f for f in files[:5000]}  # Limit for demo

            for future in as_completed(future_to_file):
                try:
                    results = future.result()
                    data.extend(results)

                    if len(data) % 1000 == 0:
                        logger.info(f"Processed {len(data)} code samples")

                except Exception as e:
                    logger.warning(f"Failed to process file: {e}")

        logger.info(f"Extracted {len(data)} code samples from Juliet dataset")
        return pd.DataFrame(data)

    def _extract_functions(self, code: str) -> List[Tuple[str, str]]:
        """Extract functions from C/C++ code"""
        functions = []
        lines = code.split('\n')

        in_function = False
        current_function = []
        function_name = ""
        brace_count = 0

        for line in lines:
            stripped = line.strip()

            # Simple function detection
            if not in_function and '(' in stripped and ')' in stripped and '{' in line:
                # Likely function start
                function_name = stripped.split('(')[0].split()[-1]
                in_function = True
                current_function = [line]
                brace_count = line.count('{') - line.count('}')

            elif in_function:
                current_function.append(line)
                brace_count += line.count('{') - line.count('}')

                if brace_count <= 0:
                    # Function end
                    function_code = '\n'.join(current_function)
                    if len(function_code.strip()) > 50:
                        functions.append((function_name, function_code))

                    in_function = False
                    current_function = []
                    function_name = ""
                    brace_count = 0

        return functions

    def _calculate_complexity(self, code: str) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity

        # Count decision points
        complexity += code.count('if')
        complexity += code.count('while')
        complexity += code.count('for')
        complexity += code.count('case')
        complexity += code.count('catch')
        complexity += code.count('&&')
        complexity += code.count('||')
        complexity += code.count('?')  # Ternary operator

        return complexity

    def fetch_bigvul_dataset(self) -> pd.DataFrame:
        """Fetch complete Big-Vul dataset"""
        logger.info("Fetching complete Big-Vul dataset...")

        bigvul_dir = self.cache_dir / "bigvul_full"
        bigvul_dir.mkdir(exist_ok=True)

        # Clone multiple Big-Vul repositories
        repos = [
            'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset.git',
            'https://github.com/davidhin/linevul.git',
            'https://github.com/saikat107/Vulnerability-Detection.git'
        ]

        all_data = []

        for i, repo_url in enumerate(repos):
            try:
                repo_dir = bigvul_dir / f"repo_{i}"
                if not repo_dir.exists():
                    logger.info(f"Cloning {repo_url}...")
                    git.Repo.clone_from(repo_url, repo_dir, depth=1)

                # Process CSV files in repository
                csv_files = list(repo_dir.rglob("*.csv"))
                logger.info(f"Found {len(csv_files)} CSV files in {repo_url}")

                for csv_file in csv_files:
                    try:
                        df = pd.read_csv(csv_file, encoding='utf-8', on_bad_lines='skip')

                        # Standardize columns
                        if 'func_before' in df.columns:
                            df = df.rename(columns={'func_before': 'code', 'target': 'is_vulnerable'})
                        elif 'code' in df.columns or 'function' in df.columns:
                            if 'function' in df.columns:
                                df = df.rename(columns={'function': 'code'})
                        else:
                            continue

                        # Add metadata
                        df['dataset_source'] = 'bigvul'
                        df['language'] = 'c'
                        df['repository'] = repo_url.split('/')[-1].replace('.git', '')

                        all_data.append(df)
                        logger.info(f"Loaded {len(df)} samples from {csv_file}")

                    except Exception as e:
                        logger.warning(f"Failed to process {csv_file}: {e}")

            except Exception as e:
                logger.warning(f"Failed to process repository {repo_url}: {e}")

        if not all_data:
            logger.warning("No Big-Vul data found, creating synthetic data")
            return self._create_synthetic_bigvul_data(10000)

        # Combine all data
        combined_df = pd.concat(all_data, ignore_index=True)

        # Clean and filter
        combined_df = combined_df.dropna(subset=['code'])
        combined_df = combined_df[combined_df['code'].str.len() > 20]

        # Ensure vulnerability labels
        if 'is_vulnerable' not in combined_df.columns:
            # Heuristic vulnerability detection
            combined_df['is_vulnerable'] = combined_df['code'].apply(self._detect_vulnerability_heuristic)

        logger.info(f"Processed {len(combined_df)} Big-Vul samples")
        return combined_df.head(10000)  # Limit for processing

    def _detect_vulnerability_heuristic(self, code: str) -> int:
        """Heuristic vulnerability detection for unlabeled data"""
        vulnerable_patterns = [
            'strcpy', 'strcat', 'sprintf', 'gets',  # Buffer overflow
            'malloc', 'free',  # Memory management
            'system(', 'exec(',  # Command injection
            'SELECT.*' + '+',  # SQL injection patterns
        ]

        return 1 if any(pattern in code for pattern in vulnerable_patterns) else 0

    def fetch_smart_contract_datasets(self) -> pd.DataFrame:
        """Fetch comprehensive smart contract vulnerability datasets"""
        logger.info("Fetching smart contract vulnerability datasets...")

        sc_dir = self.cache_dir / "smart_contracts_full"
        sc_dir.mkdir(exist_ok=True)

        # Smart contract repositories
        repos = [
            'https://github.com/smartbugs/smartbugs-wild.git',
            'https://github.com/crytic/not-so-smart-contracts.git',
            'https://github.com/ConsenSys/mythril.git',
            'https://github.com/ethereum/solidity-examples.git'
        ]

        all_contracts = []

        for i, repo_url in enumerate(repos):
            try:
                repo_dir = sc_dir / f"sc_repo_{i}"
                if not repo_dir.exists():
                    logger.info(f"Cloning smart contract repo {repo_url}...")
                    git.Repo.clone_from(repo_url, repo_dir, depth=1)

                # Find Solidity files
                sol_files = list(repo_dir.rglob("*.sol"))
                logger.info(f"Found {len(sol_files)} Solidity files")

                for sol_file in sol_files[:1000]:  # Limit per repo
                    try:
                        with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        # Extract contracts
                        contracts = self._extract_smart_contracts(content, str(sol_file))
                        all_contracts.extend(contracts)

                    except Exception as e:
                        logger.warning(f"Failed to process {sol_file}: {e}")

            except Exception as e:
                logger.warning(f"Failed to clone {repo_url}: {e}")

        if not all_contracts:
            logger.warning("No smart contracts found, creating synthetic data")
            return self._create_synthetic_smart_contracts(5000)

        logger.info(f"Extracted {len(all_contracts)} smart contract samples")
        return pd.DataFrame(all_contracts)

    def _extract_smart_contracts(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Extract individual contracts and functions from Solidity code"""
        contracts = []

        # Extract contract definitions
        import re
        contract_pattern = r'contract\s+(\w+).*?\{(.*?)\n\}'
        matches = re.findall(contract_pattern, content, re.DOTALL)

        for contract_name, contract_body in matches:
            # Analyze contract for vulnerabilities
            vuln_indicators = self._analyze_solidity_vulnerabilities(contract_body)

            contracts.append({
                'code': f"contract {contract_name} {{{contract_body}}}",
                'contract_name': contract_name,
                'file_path': file_path,
                'vulnerability_type': vuln_indicators['primary_vuln'],
                'is_vulnerable': vuln_indicators['is_vulnerable'],
                'dataset_source': 'smart_contracts',
                'language': 'solidity',
                'gas_complexity': self._estimate_gas_complexity(contract_body),
                'function_count': contract_body.count('function'),
                'has_payable': 1 if 'payable' in contract_body else 0,
                'has_external_calls': 1 if '.call(' in contract_body else 0
            })

        return contracts

    def _analyze_solidity_vulnerabilities(self, code: str) -> Dict[str, Any]:
        """Analyze Solidity code for vulnerabilities"""
        vulnerabilities = {
            'reentrancy': bool(re.search(r'\.call\s*\([^)]*\)\s*;\s*\w+\s*[-+*/]?=', code)),
            'integer_overflow': bool(re.search(r'[+\-*/]\s*=|[+\-*/]{2}', code) and 'SafeMath' not in code),
            'unchecked_return': bool('.call(' in code and 'require(' not in code),
            'access_control': bool(re.search(r'onlyOwner|onlyAdmin', code) == None and 'public' in code),
            'timestamp_dependence': bool('block.timestamp' in code or 'now' in code),
            'dos_gas': bool('while' in code or 'for' in code)
        }

        # Determine primary vulnerability
        primary_vuln = 'none'
        is_vulnerable = 0

        for vuln_type, detected in vulnerabilities.items():
            if detected:
                primary_vuln = vuln_type
                is_vulnerable = 1
                break

        return {
            'primary_vuln': primary_vuln,
            'is_vulnerable': is_vulnerable,
            'vulnerabilities': vulnerabilities
        }

    def _estimate_gas_complexity(self, code: str) -> int:
        """Estimate gas complexity of smart contract"""
        complexity = 0
        complexity += code.count('for') * 10
        complexity += code.count('while') * 10
        complexity += code.count('mapping') * 5
        complexity += code.count('storage') * 3
        complexity += code.count('.call(') * 8
        return complexity

    def create_comprehensive_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create comprehensive 38 static + 10 dynamic features"""
        logger.info("Creating comprehensive feature set...")

        # Static features (38 total)
        logger.info("Extracting static features...")
        static_features = df['code'].apply(self._extract_static_features)
        static_df = pd.DataFrame(list(static_features))

        # Dynamic features (10 total) - simulated for now
        logger.info("Extracting dynamic features...")
        dynamic_features = df.apply(lambda row: self._extract_dynamic_features(row['code'], row.get('language', 'c')), axis=1)
        dynamic_df = pd.DataFrame(list(dynamic_features))

        # Combine all features
        feature_df = pd.concat([df, static_df, dynamic_df], axis=1)

        logger.info(f"Created {len(static_df.columns)} static + {len(dynamic_df.columns)} dynamic features")
        return feature_df

    def _extract_static_features(self, code: str) -> Dict[str, float]:
        """Extract 38 static features from code"""
        features = {}

        # Basic metrics (10 features)
        features['lines_of_code'] = len(code.split('\n'))
        features['char_count'] = len(code)
        features['word_count'] = len(code.split())
        features['function_count'] = code.count('function') + code.count('def') + code.count('int ') + code.count('void ')
        features['variable_count'] = len(re.findall(r'\b[a-zA-Z_]\w*\b', code))
        features['comment_count'] = code.count('//') + code.count('/*') + code.count('#')
        features['string_count'] = code.count('"') + code.count("'")
        features['number_count'] = len(re.findall(r'\b\d+\b', code))
        features['operator_count'] = code.count('+') + code.count('-') + code.count('*') + code.count('/')
        features['bracket_count'] = code.count('(') + code.count('[') + code.count('{')

        # Complexity metrics (8 features)
        features['cyclomatic_complexity'] = self._calculate_complexity(code)
        features['nesting_depth'] = max((line.count('\t') + line.count('    ')//4) for line in code.split('\n'))
        features['max_line_length'] = max(len(line) for line in code.split('\n')) if code.split('\n') else 0
        features['avg_line_length'] = sum(len(line) for line in code.split('\n')) / len(code.split('\n')) if code.split('\n') else 0
        features['halstead_length'] = len(code.split())
        features['halstead_vocabulary'] = len(set(code.split()))
        features['halstead_difficulty'] = features['halstead_vocabulary'] / 2 if features['halstead_vocabulary'] > 0 else 0
        features['maintainability_index'] = max(0, 171 - 5.2 * np.log(features['halstead_length']) - 0.23 * features['cyclomatic_complexity'] - 16.2 * np.log(features['lines_of_code'])) if features['halstead_length'] > 0 and features['lines_of_code'] > 0 else 0

        # Security-specific features (20 features)
        # Dangerous function calls
        features['dangerous_functions'] = sum([
            code.count('strcpy'), code.count('strcat'), code.count('sprintf'),
            code.count('gets'), code.count('scanf'), code.count('system')
        ])

        # Memory management
        features['memory_functions'] = code.count('malloc') + code.count('free') + code.count('alloc')
        features['pointer_usage'] = code.count('*') + code.count('->')
        features['array_access'] = code.count('[') + code.count(']')

        # Control flow
        features['conditional_statements'] = code.count('if') + code.count('else') + code.count('switch')
        features['loop_statements'] = code.count('for') + code.count('while') + code.count('do')
        features['jump_statements'] = code.count('goto') + code.count('break') + code.count('continue')
        features['exception_handling'] = code.count('try') + code.count('catch') + code.count('throw')

        # Solidity-specific
        features['solidity_keywords'] = sum([
            code.count('payable'), code.count('external'), code.count('internal'),
            code.count('require'), code.count('assert'), code.count('revert')
        ])
        features['state_variables'] = code.count('storage') + code.count('mapping')
        features['external_calls'] = code.count('.call(') + code.count('.delegatecall(') + code.count('.send(')
        features['gas_operations'] = code.count('gas') + code.count('gasleft')
        features['time_operations'] = code.count('timestamp') + code.count('now') + code.count('block.')
        features['crypto_operations'] = code.count('hash') + code.count('keccak') + code.count('sha')
        features['access_modifiers'] = code.count('public') + code.count('private') + code.count('protected')

        # Pattern-based features
        features['assignment_operations'] = code.count('=') - code.count('==') - code.count('!=')
        features['comparison_operations'] = code.count('==') + code.count('!=') + code.count('<') + code.count('>')
        features['logical_operations'] = code.count('&&') + code.count('||') + code.count('!')
        features['bitwise_operations'] = code.count('&') + code.count('|') + code.count('^') + code.count('<<') + code.count('>>')
        features['increment_operations'] = code.count('++') + code.count('--')

        return features

    def _extract_dynamic_features(self, code: str, language: str) -> Dict[str, float]:
        """Extract 10 dynamic features (simulated)"""
        features = {}

        # Simulate execution-based features
        features['execution_paths'] = min(100, max(1, self._calculate_complexity(code) * 2))
        features['branch_coverage'] = min(1.0, 0.3 + (len(code.split('\n')) * 0.01))
        features['loop_iterations'] = code.count('for') * 10 + code.count('while') * 15
        features['memory_allocations'] = code.count('malloc') * 5 + code.count('new') * 3
        features['function_calls_dynamic'] = len(re.findall(r'\w+\s*\(', code))
        features['exception_throws'] = code.count('throw') + code.count('revert') + code.count('assert')
        features['external_interactions'] = code.count('.call(') + code.count('http') + code.count('socket')
        features['resource_usage'] = min(100, len(code) // 10)
        features['timing_analysis'] = 1 if any(t in code for t in ['time', 'clock', 'timestamp']) else 0
        features['concurrency_indicators'] = code.count('thread') + code.count('async') + code.count('lock')

        return features

    def balance_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Balance vulnerable/non-vulnerable samples using advanced SMOTE"""
        logger.info("Balancing dataset with SMOTE...")

        from imblearn.over_sampling import SMOTE
        from imblearn.under_sampling import RandomUnderSampler
        from imblearn.pipeline import Pipeline

        # Separate features and labels
        feature_cols = [col for col in df.columns if col.startswith(('lines_', 'char_', 'word_', 'function_', 'execution_', 'branch_'))]

        if len(feature_cols) == 0:
            logger.warning("No numeric features found for balancing")
            return df

        X = df[feature_cols].fillna(0)
        y = df['is_vulnerable'].fillna(0)

        # Create balanced pipeline
        pipeline = Pipeline([
            ('smote', SMOTE(random_state=42, k_neighbors=min(5, len(X)-1))),
            ('undersample', RandomUnderSampler(random_state=42))
        ])

        try:
            X_balanced, y_balanced = pipeline.fit_resample(X, y)

            # Reconstruct DataFrame
            balanced_df = pd.DataFrame(X_balanced, columns=feature_cols)
            balanced_df['is_vulnerable'] = y_balanced

            # Add back metadata columns (duplicate for synthetic samples)
            for col in df.columns:
                if col not in feature_cols and col != 'is_vulnerable':
                    if len(df) > 0:
                        # Duplicate original metadata for synthetic samples
                        original_values = df[col].dropna().tolist()
                        if original_values:
                            balanced_values = np.random.choice(original_values, len(balanced_df))
                            balanced_df[col] = balanced_values
                        else:
                            balanced_df[col] = 'unknown'

            logger.info(f"Balanced dataset: {len(balanced_df)} samples")
            logger.info(f"Vulnerable: {sum(y_balanced)}, Non-vulnerable: {len(y_balanced) - sum(y_balanced)}")

            return balanced_df

        except Exception as e:
            logger.error(f"SMOTE balancing failed: {e}")
            return df

    def _create_synthetic_juliet_data(self, target_count: int) -> pd.DataFrame:
        """Create synthetic Juliet-style data"""
        logger.info(f"Creating {target_count} synthetic Juliet samples...")

        # Template vulnerable patterns
        vulnerable_templates = [
            # Buffer overflow patterns
            '''void CWE{cwe}_bad() {{
    char buffer[{size}];
    char input[{large_size}];
    strcpy(buffer, input);  // FLAW: Buffer overflow
}}''',
            # Integer overflow
            '''int CWE{cwe}_bad(int x) {{
    int result = x + 1000000;  // FLAW: Potential overflow
    return result;
}}''',
            # Memory leak
            '''void CWE{cwe}_bad() {{
    char *ptr = malloc({size});
    // FLAW: Missing free()
}}''',
            # Use after free
            '''void CWE{cwe}_bad() {{
    char *ptr = malloc({size});
    free(ptr);
    strcpy(ptr, "data");  // FLAW: Use after free
}}'''
        ]

        safe_templates = [
            # Safe buffer operations
            '''void CWE{cwe}_good() {{
    char buffer[{size}];
    char input[{size}];
    strncpy(buffer, input, {size}-1);
    buffer[{size}-1] = '\\0';  // FIX: Proper bounds
}}''',
            # Safe arithmetic
            '''int CWE{cwe}_good(int x) {{
    if (x > INT_MAX - 1000000) return -1;
    int result = x + 1000000;  // FIX: Overflow check
    return result;
}}''',
            # Proper memory management
            '''void CWE{cwe}_good() {{
    char *ptr = malloc({size});
    if (ptr) {{
        free(ptr);  // FIX: Proper cleanup
    }}
}}'''
        ]

        data = []

        for i in range(target_count):
            is_vulnerable = i % 2  # Alternate vulnerable/safe
            templates = vulnerable_templates if is_vulnerable else safe_templates

            template = np.random.choice(templates)
            cwe = np.random.choice([120, 121, 122, 190, 416, 415])
            size = np.random.choice([10, 16, 32, 64, 128])
            large_size = size * 2

            code = template.format(cwe=cwe, size=size, large_size=large_size)

            data.append({
                'code': code,
                'cwe_id': f'CWE-{cwe}',
                'vulnerability_type': self._map_cwe_to_type(f'CWE{cwe}'),
                'is_vulnerable': is_vulnerable,
                'dataset_source': 'juliet_synthetic',
                'language': 'c',
                'function_name': f'CWE{cwe}_{"bad" if is_vulnerable else "good"}',
                'complexity_score': np.random.randint(1, 10)
            })

        return pd.DataFrame(data)

    def _create_synthetic_bigvul_data(self, target_count: int) -> pd.DataFrame:
        """Create synthetic Big-Vul style data"""
        logger.info(f"Creating {target_count} synthetic Big-Vul samples...")

        projects = ['openssl', 'linux', 'apache', 'nginx', 'mysql', 'postgres']

        data = []
        for i in range(target_count):
            is_vulnerable = np.random.choice([0, 1], p=[0.3, 0.7])  # More vulnerable samples

            if is_vulnerable:
                code_templates = [
                    f'int vuln_func_{i}(char *input) {{ char buf[10]; strcpy(buf, input); return 0; }}',
                    f'void process_{i}(int size) {{ char *ptr = malloc(size); /* missing free */ }}',
                    f'int check_{i}(char *data) {{ return system(data); /* command injection */ }}'
                ]
            else:
                code_templates = [
                    f'int safe_func_{i}(char *input, size_t max) {{ char buf[10]; strncpy(buf, input, max-1); buf[max-1]=0; return 0; }}',
                    f'void process_{i}(int size) {{ char *ptr = malloc(size); if(ptr) free(ptr); }}',
                    f'int check_{i}(char *data) {{ if(validate(data)) return process(data); return -1; }}'
                ]

            code = np.random.choice(code_templates)

            data.append({
                'code': code,
                'is_vulnerable': is_vulnerable,
                'vulnerability_type': 'buffer_overflow' if 'strcpy' in code else 'memory_leak' if 'malloc' in code else 'command_injection',
                'dataset_source': 'bigvul_synthetic',
                'language': 'c',
                'project': np.random.choice(projects),
                'commit_hash': f'synthetic_{i:06d}'
            })

        return pd.DataFrame(data)

    def _create_synthetic_smart_contracts(self, target_count: int) -> pd.DataFrame:
        """Create synthetic smart contract data"""
        logger.info(f"Creating {target_count} synthetic smart contract samples...")

        data = []
        for i in range(target_count):
            is_vulnerable = np.random.choice([0, 1])

            if is_vulnerable:
                # Vulnerable patterns
                contracts = [
                    f'''contract Vulnerable{i} {{
    mapping(address => uint) balances;
    function withdraw(uint amount) {{
        require(balances[msg.sender] >= amount);
        msg.sender.call{{value: amount}}("");  // Reentrancy
        balances[msg.sender] -= amount;
    }}
}}''',
                    f'''contract IntOverflow{i} {{
    mapping(address => uint) balances;
    function transfer(address to, uint amount) {{
        balances[msg.sender] -= amount;  // Underflow
        balances[to] += amount;          // Overflow
    }}
}}'''
                ]
            else:
                # Safe patterns
                contracts = [
                    f'''contract Safe{i} {{
    mapping(address => uint) balances;
    function withdraw(uint amount) {{
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;  // State change first
        msg.sender.call{{value: amount}}("");
    }}
}}''',
                    f'''contract SafeMath{i} {{
    mapping(address => uint) balances;
    function transfer(address to, uint amount) {{
        require(balances[msg.sender] >= amount);
        require(balances[to] + amount >= balances[to]);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }}
}}'''
                ]

            code = np.random.choice(contracts)
            vuln_type = 'reentrancy' if 'call{' in code and 'balances[msg.sender] -=' in code.split('call{')[1] else 'integer_overflow'

            data.append({
                'code': code,
                'is_vulnerable': is_vulnerable,
                'vulnerability_type': vuln_type if is_vulnerable else 'none',
                'dataset_source': 'smart_contracts_synthetic',
                'language': 'solidity',
                'contract_name': f'Contract{i}',
                'gas_complexity': np.random.randint(1000, 50000)
            })

        return pd.DataFrame(data)

    def _map_cwe_to_type(self, cwe: str) -> str:
        """Map CWE ID to vulnerability type"""
        mapping = {
            'CWE120': 'buffer_overflow', 'CWE121': 'buffer_overflow', 'CWE122': 'buffer_overflow',
            'CWE78': 'command_injection', 'CWE89': 'sql_injection', 'CWE79': 'xss',
            'CWE190': 'integer_overflow', 'CWE191': 'integer_underflow',
            'CWE476': 'null_pointer', 'CWE416': 'use_after_free', 'CWE415': 'double_free',
            'CWE252': 'unchecked_return', 'CWE835': 'infinite_loop'
        }
        return mapping.get(cwe.replace('-', ''), 'unknown')

    def save_production_dataset(self, df: pd.DataFrame, output_path: str) -> str:
        """Save production-ready dataset"""
        logger.info(f"Saving production dataset to {output_path}")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save as multiple formats
        try:
            # Parquet for Azure ML
            parquet_path = output_path.with_suffix('.parquet')
            df.to_parquet(parquet_path, index=False, compression='snappy')
            logger.info(f"Saved Parquet dataset: {parquet_path}")
        except:
            logger.warning("Could not save as Parquet, saving as CSV")
            parquet_path = output_path.with_suffix('.csv')
            df.to_csv(parquet_path, index=False)

        # CSV for inspection
        csv_path = output_path.with_suffix('.csv')
        df.to_csv(csv_path, index=False)

        # Pickle for fast loading
        pickle_path = output_path.with_suffix('.pkl')
        with open(pickle_path, 'wb') as f:
            pickle.dump(df, f)

        # Metadata
        metadata = {
            'dataset_info': {
                'total_samples': len(df),
                'vulnerable_samples': int(df['is_vulnerable'].sum()),
                'non_vulnerable_samples': int(len(df) - df['is_vulnerable'].sum()),
                'languages': df['language'].value_counts().to_dict(),
                'sources': df['dataset_source'].value_counts().to_dict(),
                'vulnerability_types': df['vulnerability_type'].value_counts().to_dict()
            },
            'feature_info': {
                'total_features': len(df.columns),
                'static_features': len([col for col in df.columns if any(col.startswith(prefix) for prefix in ['lines_', 'char_', 'word_', 'function_', 'dangerous_'])]),
                'dynamic_features': len([col for col in df.columns if col.startswith(('execution_', 'branch_', 'loop_', 'memory_'))])
            },
            'file_info': {
                'parquet_path': str(parquet_path),
                'csv_path': str(csv_path),
                'pickle_path': str(pickle_path),
                'creation_time': pd.Timestamp.now().isoformat()
            }
        }

        metadata_path = output_path.with_suffix('.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Production dataset ready: {len(df)} samples with {len(df.columns)} features")
        return str(parquet_path)

def main():
    """Main function for full dataset preparation"""
    logger.info("🚀 Starting VulnHunter V5 Full Dataset Preparation")

    # Enable pandas parallel processing
    try:
        import pandarallel
        pandarallel.pandarallel.initialize(progress_bar=True)
        logger.info("Enabled parallel pandas processing")
    except ImportError:
        logger.warning("pandarallel not available, using standard pandas")

    loader = FullDatasetLoader()

    try:
        # Download all datasets
        logger.info("Phase 1: Downloading datasets...")
        juliet_df = loader.fetch_juliet_dataset()
        bigvul_df = loader.fetch_bigvul_dataset()
        sc_df = loader.fetch_smart_contract_datasets()

        # Combine datasets
        logger.info("Phase 2: Combining datasets...")
        all_datasets = [juliet_df, bigvul_df, sc_df]
        combined_df = pd.concat(all_datasets, ignore_index=True, sort=False)

        # Create comprehensive features
        logger.info("Phase 3: Feature engineering...")
        featured_df = loader.create_comprehensive_features(combined_df)

        # Balance dataset
        logger.info("Phase 4: Dataset balancing...")
        balanced_df = loader.balance_dataset(featured_df)

        # Save production dataset
        logger.info("Phase 5: Saving production dataset...")
        output_path = "./data/production/vulnhunter_v5_full_dataset.parquet"
        final_path = loader.save_production_dataset(balanced_df, output_path)

        logger.info("✅ Full dataset preparation completed successfully!")
        logger.info(f"📊 Final dataset: {len(balanced_df)} samples")
        logger.info(f"📂 Saved to: {final_path}")

        return final_path

    except Exception as e:
        logger.error(f"❌ Dataset preparation failed: {e}")
        raise

if __name__ == "__main__":
    main()