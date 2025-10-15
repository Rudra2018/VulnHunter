#!/usr/bin/env python3
"""
Enhanced Smart Contract Dataset Preparation for VulnHunter V5
Integrates comprehensive blockchain data sources for advanced vulnerability detection
"""

import os
import sys
import asyncio
import aiohttp
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
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedSmartContractDatasetLoader:
    """Enhanced loader for comprehensive smart contract vulnerability datasets"""

    def __init__(self, cache_dir: str = "./data/enhanced_datasets", max_workers: int = 16):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers

        # Enhanced dataset sources
        self.dataset_sources = {
            'smartbugs': {
                'repo': 'https://github.com/smartbugs/smartbugs.git',
                'description': 'SmartBugs vulnerability analysis framework',
                'target_samples': 15000
            },
            'smartbugs_wild': {
                'repo': 'https://github.com/smartbugs/smartbugs-wild.git',
                'description': 'Wild smart contracts dataset',
                'target_samples': 47000
            },
            'ethgraph': {
                'repo': 'https://github.com/ethgraph/dataset.git',
                'description': 'Ethereum graph dataset',
                'target_samples': 10000
            },
            'sobigdata': {
                'repo': 'https://github.com/sobigdata/ethereum.git',
                'description': 'SoBigData Ethereum analysis',
                'target_samples': 5000
            },
            'ganache_contracts': {
                'description': 'Ganache test contracts and patterns',
                'target_samples': 2000
            },
            'hardhat_examples': {
                'description': 'Hardhat network examples and forks',
                'target_samples': 1500
            },
            'foundry_anvil': {
                'description': 'Foundry Anvil test patterns',
                'target_samples': 1000
            }
        }

        # API endpoints for live data
        self.api_endpoints = {
            'etherscan': 'https://api.etherscan.io/api',
            'blockscout': 'https://blockscout.com/eth/mainnet/api'
        }

    async def fetch_etherscan_contracts(self, limit: int = 1000) -> List[Dict]:
        """Fetch verified contracts from Etherscan"""
        logger.info("Fetching verified contracts from Etherscan...")

        contracts = []
        page = 1

        # Sample of known vulnerable contract addresses for analysis
        known_addresses = [
            "0xd654bdd32fc99471455e86c2e7f7d7b6437e9179",  # Polygon Bridge
            "0xa0b86a33e6fd05c6dd7b7c7e4cd9eda1e9e14b5f",  # Example DeFi
            "0x5c6b0f7bf3e7ce046039bd8fabdfce3e4f8d7f8f",  # Example Token
        ]

        for address in known_addresses[:10]:  # Limited sample
            try:
                url = f"{self.api_endpoints['etherscan']}?module=contract&action=getsourcecode&address={address}&apikey=YourApiKeyToken"

                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data['status'] == '1' and data['result'][0]['SourceCode']:
                                contract_info = {
                                    'address': address,
                                    'source_code': data['result'][0]['SourceCode'],
                                    'contract_name': data['result'][0]['ContractName'],
                                    'compiler_version': data['result'][0]['CompilerVersion'],
                                    'is_vulnerable': self._analyze_vulnerability_patterns(data['result'][0]['SourceCode']),
                                    'source': 'etherscan'
                                }
                                contracts.append(contract_info)

                        await asyncio.sleep(0.2)  # Rate limiting

            except Exception as e:
                logger.warning(f"Failed to fetch contract {address}: {e}")
                continue

        return contracts

    def _analyze_vulnerability_patterns(self, source_code: str) -> bool:
        """Analyze source code for known vulnerability patterns"""
        vulnerable_patterns = [
            r'\.call\.value\(',  # Reentrancy
            r'tx\.origin',  # tx.origin usage
            r'block\.timestamp',  # Timestamp dependence
            r'selfdestruct\(',  # Selfdestruct calls
            r'delegatecall\(',  # Delegatecall usage
            r'assembly\s*\{',  # Inline assembly
            r'\.transfer\(',  # Transfer without checks
            r'\.send\(',  # Send without checks
        ]

        for pattern in vulnerable_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                return True
        return False

    def fetch_smartbugs_datasets(self) -> pd.DataFrame:
        """Fetch SmartBugs datasets"""
        logger.info("Fetching SmartBugs datasets...")

        datasets = []

        for name, config in self.dataset_sources.items():
            if 'repo' not in config:
                continue

            try:
                repo_dir = self.cache_dir / f"{name}_repo"

                if not repo_dir.exists():
                    logger.info(f"Cloning {config['repo']}...")
                    git.Repo.clone_from(config['repo'], repo_dir, depth=1)

                # Process Solidity files
                sol_files = list(repo_dir.rglob("*.sol"))
                logger.info(f"Found {len(sol_files)} Solidity files in {name}")

                for sol_file in sol_files[:config['target_samples']]:
                    try:
                        with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        if len(content) > 100:  # Skip very small files
                            datasets.append({
                                'code': content,
                                'file_path': str(sol_file),
                                'contract_name': sol_file.stem,
                                'language': 'solidity',
                                'is_vulnerable': self._analyze_vulnerability_patterns(content),
                                'source': name,
                                'file_size': len(content)
                            })

                    except Exception as e:
                        logger.warning(f"Failed to process {sol_file}: {e}")
                        continue

            except Exception as e:
                logger.warning(f"Failed to process {name}: {e}")
                continue

        return pd.DataFrame(datasets)

    def create_synthetic_blockchain_patterns(self, count: int = 5000) -> pd.DataFrame:
        """Create synthetic smart contract patterns for testing"""
        logger.info(f"Creating {count} synthetic blockchain vulnerability patterns...")

        # Vulnerability patterns
        vuln_patterns = {
            'reentrancy': [
                'function withdraw() public { msg.sender.call.value(balances[msg.sender])(""); balances[msg.sender] = 0; }',
                'function transfer(address to, uint amount) { to.call.value(amount)(""); }',
                'external_call(); state_variable = new_value;'
            ],
            'timestamp_dependence': [
                'require(block.timestamp > deadline);',
                'if (now > endTime) { payable(winner).transfer(prize); }',
                'uint random = uint(keccak256(abi.encodePacked(block.timestamp))) % 100;'
            ],
            'tx_origin': [
                'require(tx.origin == owner);',
                'if (tx.origin == msg.sender) { selfdestruct(payable(owner)); }',
                'modifier onlyOwner() { require(tx.origin == owner); _; }'
            ],
            'integer_overflow': [
                'balances[to] += amount;',
                'totalSupply = totalSupply + newTokens;',
                'function multiply(uint a, uint b) returns (uint) { return a * b; }'
            ],
            'unchecked_call': [
                'recipient.call.value(amount)("");',
                'target.delegatecall(data);',
                'someAddress.send(amount);'
            ]
        }

        safe_patterns = [
            'require(amount > 0, "Amount must be positive");',
            'using SafeMath for uint256;',
            'require(balances[from] >= amount, "Insufficient balance");',
            'function safeTransfer(address to, uint amount) internal { require(to != address(0)); }',
            'modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }'
        ]

        synthetic_data = []

        for i in range(count):
            if np.random.random() < 0.6:  # 60% vulnerable
                vuln_type = np.random.choice(list(vuln_patterns.keys()))
                code_pattern = np.random.choice(vuln_patterns[vuln_type])
                is_vulnerable = True
                cwe_id = f"CWE-{np.random.choice([78, 190, 191, 362, 367])}"
            else:  # 40% safe
                code_pattern = np.random.choice(safe_patterns)
                is_vulnerable = False
                vuln_type = "safe"
                cwe_id = "SAFE"

            # Create realistic contract structure
            contract_template = f"""
pragma solidity ^0.8.0;

contract TestContract_{i} {{
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked = false;

    constructor() {{
        owner = msg.sender;
    }}

    {code_pattern}

    function getBalance(address account) public view returns (uint256) {{
        return balances[account];
    }}
}}
"""

            synthetic_data.append({
                'code': contract_template,
                'contract_name': f'TestContract_{i}',
                'language': 'solidity',
                'is_vulnerable': is_vulnerable,
                'vulnerability_type': vuln_type,
                'cwe_id': cwe_id,
                'source': 'synthetic_blockchain',
                'file_size': len(contract_template),
                'complexity_score': np.random.uniform(0.1, 0.9),
                'function_count': np.random.randint(1, 10),
                'line_count': len(contract_template.split('\\n'))
            })

        return pd.DataFrame(synthetic_data)

    def extract_enhanced_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract enhanced features for smart contract analysis"""
        logger.info("Extracting enhanced smart contract features...")

        def extract_solidity_features(code: str) -> Dict:
            """Extract Solidity-specific features"""
            features = {}

            # Basic metrics
            features['line_count'] = len(code.split('\\n'))
            features['char_count'] = len(code)
            features['function_count'] = len(re.findall(r'function\\s+\\w+', code))
            features['modifier_count'] = len(re.findall(r'modifier\\s+\\w+', code))
            features['event_count'] = len(re.findall(r'event\\s+\\w+', code))

            # Vulnerability indicators
            features['has_payable'] = int('payable' in code)
            features['has_selfdestruct'] = int('selfdestruct' in code)
            features['has_delegatecall'] = int('delegatecall' in code)
            features['has_assembly'] = int('assembly' in code)
            features['has_tx_origin'] = int('tx.origin' in code)
            features['has_block_timestamp'] = int('block.timestamp' in code or 'now' in code)
            features['has_call_value'] = int('.call.value(' in code)
            features['has_transfer'] = int('.transfer(' in code)
            features['has_send'] = int('.send(' in code)

            # Security patterns
            features['has_require'] = int('require(' in code)
            features['has_assert'] = int('assert(' in code)
            features['has_revert'] = int('revert(' in code)
            features['has_safemath'] = int('SafeMath' in code)
            features['has_reentrancy_guard'] = int('nonReentrant' in code or 'ReentrancyGuard' in code)

            # Complexity indicators
            features['pragma_count'] = len(re.findall(r'pragma\\s+', code))
            features['import_count'] = len(re.findall(r'import\\s+', code))
            features['contract_count'] = len(re.findall(r'contract\\s+\\w+', code))
            features['interface_count'] = len(re.findall(r'interface\\s+\\w+', code))
            features['library_count'] = len(re.findall(r'library\\s+\\w+', code))

            # Advanced patterns
            features['external_calls'] = len(re.findall(r'\\.call\\(', code))
            features['state_variables'] = len(re.findall(r'\\s+(uint|int|bool|address|string|bytes)\\s+\\w+;', code))
            features['loop_count'] = len(re.findall(r'\\b(for|while)\\s*\\(', code))
            features['conditional_count'] = len(re.findall(r'\\b(if|else)\\s*\\(', code))

            return features

        # Extract features for each contract
        feature_data = []
        for idx, row in df.iterrows():
            if idx % 1000 == 0:
                logger.info(f"Processing contract {idx+1}/{len(df)}")

            try:
                features = extract_solidity_features(row['code'])
                features.update({
                    'original_index': idx,
                    'source': row.get('source', 'unknown'),
                    'file_size': row.get('file_size', len(row['code'])),
                    'is_vulnerable': row.get('is_vulnerable', False)
                })
                feature_data.append(features)

            except Exception as e:
                logger.warning(f"Failed to extract features for contract {idx}: {e}")
                continue

        features_df = pd.DataFrame(feature_data)

        # Merge with original data
        result_df = df.reset_index(drop=True).merge(
            features_df,
            left_index=True,
            right_on='original_index',
            how='inner'
        )

        logger.info(f"Extracted {len(features_df.columns)-3} enhanced features")
        return result_df

    async def enhance_with_live_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enhance dataset with live blockchain data"""
        logger.info("Enhancing with live blockchain data...")

        try:
            # Fetch live contracts (limited sample)
            live_contracts = await self.fetch_etherscan_contracts(limit=100)

            if live_contracts:
                live_df = pd.DataFrame(live_contracts)
                live_df['file_size'] = live_df['source_code'].str.len()

                # Combine with existing data
                combined_df = pd.concat([df, live_df], ignore_index=True)
                logger.info(f"Added {len(live_df)} live contracts")
                return combined_df

        except Exception as e:
            logger.warning(f"Failed to fetch live data: {e}")

        return df

    async def prepare_enhanced_dataset(self) -> str:
        """Prepare comprehensive enhanced smart contract dataset"""
        logger.info("🚀 Starting Enhanced Smart Contract Dataset Preparation")
        logger.info("=" * 60)

        all_datasets = []

        # 1. Load existing VulnHunter dataset
        existing_path = "./data/production/vulnhunter_v5_full_dataset.csv"
        if os.path.exists(existing_path):
            logger.info("Loading existing VulnHunter V5 dataset...")
            existing_df = pd.read_csv(existing_path, low_memory=False)

            # Filter for smart contracts only
            smart_contract_df = existing_df[
                existing_df['language'].isin(['solidity', 'smart_contract'])
            ].copy()

            if len(smart_contract_df) > 0:
                all_datasets.append(smart_contract_df)
                logger.info(f"Found {len(smart_contract_df)} existing smart contract samples")

        # 2. Fetch SmartBugs datasets
        try:
            smartbugs_df = self.fetch_smartbugs_datasets()
            if len(smartbugs_df) > 0:
                all_datasets.append(smartbugs_df)
                logger.info(f"Added {len(smartbugs_df)} SmartBugs samples")
        except Exception as e:
            logger.warning(f"Failed to fetch SmartBugs data: {e}")

        # 3. Create synthetic blockchain patterns
        synthetic_df = self.create_synthetic_blockchain_patterns(count=10000)
        all_datasets.append(synthetic_df)
        logger.info(f"Generated {len(synthetic_df)} synthetic blockchain samples")

        # 4. Combine all datasets
        if all_datasets:
            combined_df = pd.concat(all_datasets, ignore_index=True, sort=False)
        else:
            combined_df = synthetic_df

        logger.info(f"Combined dataset size: {len(combined_df)} samples")

        # 5. Enhance with live data
        enhanced_df = await self.enhance_with_live_data(combined_df)

        # 6. Extract enhanced features
        final_df = self.extract_enhanced_features(enhanced_df)

        # 7. Save enhanced dataset
        output_dir = Path("./data/enhanced_production")
        output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / "vulnhunter_v5_enhanced_smart_contracts.csv"
        final_df.to_csv(output_path, index=False)

        logger.info("=" * 60)
        logger.info("✅ Enhanced Smart Contract Dataset Complete!")
        logger.info(f"📊 Total samples: {len(final_df):,}")
        logger.info(f"🔧 Features: {len([c for c in final_df.columns if c not in ['code', 'file_path']]):,}")
        logger.info(f"🎯 Vulnerable samples: {final_df['is_vulnerable'].sum():,}")
        logger.info(f"💾 Saved to: {output_path}")
        logger.info("=" * 60)

        return str(output_path)

async def main():
    """Main execution function"""
    loader = EnhancedSmartContractDatasetLoader()
    dataset_path = await loader.prepare_enhanced_dataset()
    return dataset_path

if __name__ == '__main__':
    dataset_path = asyncio.run(main())