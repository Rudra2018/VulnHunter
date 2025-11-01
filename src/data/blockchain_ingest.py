"""
VulnHunter Blockchain: Real-World Dataset Ingestion
Collects and processes multiple blockchain security datasets
Target: 500K+ labeled contracts from DISL, SB Curated, Slither Audited
"""

import json
import os
import requests
import subprocess
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datasets import load_dataset
import hashlib

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add src to path for imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from src.parser.languages.solidity_parser import SolidityParser

@dataclass
class BlockchainSample:
    """Structured blockchain vulnerability sample"""
    id: str
    code: str
    vulnerability_labels: List[str]
    vulnerability_binary: int  # 0=safe, 1=vulnerable
    source: str
    metadata: Dict[str, Any]
    contract_address: Optional[str] = None
    deployment_block: Optional[int] = None

class BlockchainDatasetCollector:
    """Comprehensive blockchain dataset collector"""

    def __init__(self, data_dir: str = "data/blockchain"):
        self.data_dir = Path(data_dir)
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        self.parser = SolidityParser()

        # Create directories
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)

        # Dataset configurations
        self.dataset_configs = {
            'smartbugs_curated': {
                'source': 'github',
                'url': 'https://api.github.com/repos/smartbugs/smartbugs-curated/contents/dataset',
                'size': 143,
                'quality': 'high',
                'labels': 'manual'
            },
            'slither_audited': {
                'source': 'huggingface',
                'dataset_name': 'mwritescode/slither-audited-smart-contracts',
                'size': 10000,
                'quality': 'medium',
                'labels': 'automated'
            },
            'disl': {
                'source': 'huggingface',
                'dataset_name': 'ASSERT-KTH/DISL',
                'subset': 'solidity_dedup',
                'size': 514000,
                'quality': 'raw',
                'labels': 'none'
            },
            'vulnerable_verified': {
                'source': 'custom',
                'url': 'https://figshare.com/articles/dataset/Vulnerable_Verified_Smart_Contracts/21063996',
                'size': 609,
                'quality': 'high',
                'labels': 'expert'
            }
        }

        # Vulnerability type mapping
        self.vulnerability_mapping = {
            'reentrancy': ['reentrancy', 'DAO', 're-entrancy'],
            'integer_overflow': ['integer-overflow', 'overflow', 'underflow', 'arithmetic'],
            'access_control': ['access-control', 'unauthorized', 'privilege'],
            'unchecked_call': ['unchecked-send', 'unchecked-call', 'failed-send'],
            'timestamp_dependence': ['timestamp', 'block-timestamp', 'time-manipulation'],
            'tx_origin': ['tx-origin', 'tx.origin'],
            'dos_gas_limit': ['dos', 'gas-limit', 'denial-of-service'],
            'uninitialized_storage': ['uninitialized', 'storage-pointer'],
            'front_running': ['front-running', 'mev', 'race-condition'],
            'insufficient_gas_griefing': ['gas-griefing', 'out-of-gas']
        }

    def collect_all_datasets(self, max_samples: Optional[int] = None) -> List[BlockchainSample]:
        """Collect and process all blockchain datasets"""
        logger.info("Starting comprehensive blockchain dataset collection")

        all_samples = []

        # Collect each dataset
        for dataset_name, config in self.dataset_configs.items():
            logger.info(f"Collecting {dataset_name}...")

            try:
                if config['source'] == 'github':
                    samples = self._collect_github_dataset(dataset_name, config)
                elif config['source'] == 'huggingface':
                    samples = self._collect_huggingface_dataset(dataset_name, config)
                elif config['source'] == 'custom':
                    samples = self._collect_custom_dataset(dataset_name, config)
                else:
                    logger.warning(f"Unknown source for {dataset_name}")
                    continue

                logger.info(f"Collected {len(samples)} samples from {dataset_name}")
                all_samples.extend(samples)

                if max_samples and len(all_samples) >= max_samples:
                    logger.info(f"Reached maximum samples limit: {max_samples}")
                    break

            except Exception as e:
                logger.error(f"Error collecting {dataset_name}: {e}")
                continue

        logger.info(f"Total samples collected: {len(all_samples)}")

        # Process and label samples
        processed_samples = self._process_samples(all_samples, max_samples)

        # Save processed dataset
        self._save_processed_dataset(processed_samples)

        return processed_samples

    def _collect_huggingface_dataset(self, dataset_name: str, config: Dict) -> List[BlockchainSample]:
        """Collect dataset from Hugging Face"""
        samples = []

        try:
            # Load dataset
            if 'subset' in config:
                dataset = load_dataset(config['dataset_name'], config['subset'], split='train')
            else:
                dataset = load_dataset(config['dataset_name'], split='train')

            logger.info(f"Loaded {len(dataset)} samples from {config['dataset_name']}")

            # Process samples
            for i, item in enumerate(dataset):
                try:
                    if dataset_name == 'slither_audited':
                        sample = self._process_slither_audited_sample(item, i)
                    elif dataset_name == 'disl':
                        sample = self._process_disl_sample(item, i)
                    else:
                        continue

                    if sample:
                        samples.append(sample)

                    if i % 1000 == 0:
                        logger.info(f"Processed {i} samples from {dataset_name}")

                except Exception as e:
                    logger.warning(f"Error processing sample {i}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error loading dataset {dataset_name}: {e}")

        return samples

    def _process_slither_audited_sample(self, item: Dict, sample_id: int) -> Optional[BlockchainSample]:
        """Process Slither audited dataset sample"""
        try:
            code = item.get('source_code', '')
            if not code or len(code) < 50:
                return None

            # Extract vulnerability labels
            labels = item.get('labels', [])
            vulnerability_labels = []
            is_vulnerable = 0

            if isinstance(labels, list) and len(labels) > 0:
                # Map Slither detectors to our vulnerability types
                for label in labels:
                    if isinstance(label, (int, float)) and label > 0:
                        is_vulnerable = 1
                    elif isinstance(label, str):
                        mapped_vuln = self._map_vulnerability_type(label)
                        if mapped_vuln:
                            vulnerability_labels.append(mapped_vuln)
                            is_vulnerable = 1

            metadata = {
                'slither_detectors': labels,
                'bytecode_size': item.get('bytecode_size', 0),
                'deployment_bytecode': item.get('deployment_bytecode', ''),
                'runtime_bytecode': item.get('runtime_bytecode', ''),
                'compiler_version': item.get('compiler_version', ''),
                'optimization': item.get('optimization', False),
                'verification_status': item.get('verification_status', 'unknown')
            }

            return BlockchainSample(
                id=f"slither_{sample_id}",
                code=code,
                vulnerability_labels=vulnerability_labels,
                vulnerability_binary=is_vulnerable,
                source='slither_audited',
                metadata=metadata,
                contract_address=item.get('address', None)
            )

        except Exception as e:
            logger.warning(f"Error processing Slither sample: {e}")
            return None

    def _process_disl_sample(self, item: Dict, sample_id: int) -> Optional[BlockchainSample]:
        """Process DISL dataset sample"""
        try:
            code = item.get('content', '') or item.get('source_code', '')
            if not code or len(code) < 50:
                return None

            # DISL is unlabeled, so we'll auto-label with our parser
            graph = self.parser.parse_solidity_code(code)

            vulnerability_labels = []
            is_vulnerable = 0

            # Extract vulnerabilities from parser
            for node in graph.nodes:
                if node.vulnerability_markers:
                    vulnerability_labels.extend(node.vulnerability_markers)
                    is_vulnerable = 1

            # Remove duplicates
            vulnerability_labels = list(set(vulnerability_labels))

            metadata = {
                'file_path': item.get('path', ''),
                'file_size': len(code),
                'auto_labeled': True,
                'parser_detected_vulns': len(vulnerability_labels),
                'security_level': min(node.security_level for node in graph.nodes) if graph.nodes else 4
            }

            return BlockchainSample(
                id=f"disl_{sample_id}",
                code=code,
                vulnerability_labels=vulnerability_labels,
                vulnerability_binary=is_vulnerable,
                source='disl',
                metadata=metadata
            )

        except Exception as e:
            logger.warning(f"Error processing DISL sample: {e}")
            return None

    def _collect_github_dataset(self, dataset_name: str, config: Dict) -> List[BlockchainSample]:
        """Collect dataset from GitHub (SmartBugs Curated)"""
        samples = []

        if dataset_name == 'smartbugs_curated':
            # Download SmartBugs Curated
            repo_url = "https://github.com/smartbugs/smartbugs-curated.git"
            repo_path = self.raw_dir / "smartbugs-curated"

            if not repo_path.exists():
                logger.info("Cloning SmartBugs Curated repository...")
                subprocess.run(['git', 'clone', repo_url, str(repo_path)], check=True)

            # Process contracts
            dataset_path = repo_path / "dataset"
            if dataset_path.exists():
                for contract_file in dataset_path.rglob("*.sol"):
                    try:
                        with open(contract_file, 'r', encoding='utf-8') as f:
                            code = f.read()

                        # Extract vulnerability type from file path
                        vuln_type = contract_file.parent.name
                        mapped_vuln = self._map_vulnerability_type(vuln_type)

                        vulnerability_labels = [mapped_vuln] if mapped_vuln else []
                        is_vulnerable = 1 if vulnerability_labels else 0

                        metadata = {
                            'file_path': str(contract_file.relative_to(repo_path)),
                            'vulnerability_category': vuln_type,
                            'manual_labeled': True,
                            'curated_quality': True
                        }

                        sample = BlockchainSample(
                            id=f"sb_{contract_file.stem}",
                            code=code,
                            vulnerability_labels=vulnerability_labels,
                            vulnerability_binary=is_vulnerable,
                            source='smartbugs_curated',
                            metadata=metadata
                        )

                        samples.append(sample)

                    except Exception as e:
                        logger.warning(f"Error processing {contract_file}: {e}")

        return samples

    def _collect_custom_dataset(self, dataset_name: str, config: Dict) -> List[BlockchainSample]:
        """Collect custom datasets"""
        samples = []

        if dataset_name == 'vulnerable_verified':
            # Create synthetic high-quality samples for demo
            samples.extend(self._create_demo_samples())

        return samples

    def _create_demo_samples(self) -> List[BlockchainSample]:
        """Create high-quality demo samples for testing"""
        demo_samples = []

        # Reentrancy vulnerable contract
        reentrancy_vuln = '''
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // State change after call!
    }
}
'''

        # Integer overflow vulnerable contract
        overflow_vuln = '''
pragma solidity ^0.7.0;  // Older version without automatic checks

contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;  // Can underflow!
        balances[to] += amount;          // Can overflow!
    }

    function mint(uint256 amount) external {
        totalSupply += amount;           // Can overflow!
        balances[msg.sender] += amount;
    }
}
'''

        # Safe contract
        safe_contract = '''
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract SafeBank is ReentrancyGuard {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] = balances[msg.sender].add(msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] = balances[msg.sender].sub(amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
'''

        # Create samples
        demo_data = [
            (reentrancy_vuln, ['reentrancy'], 1, "Classic DAO-style reentrancy vulnerability"),
            (overflow_vuln, ['integer_overflow'], 1, "Integer overflow in token transfer"),
            (safe_contract, [], 0, "Safe implementation with protection mechanisms")
        ]

        for i, (code, vulns, is_vuln, description) in enumerate(demo_data):
            sample = BlockchainSample(
                id=f"demo_{i}",
                code=code,
                vulnerability_labels=vulns,
                vulnerability_binary=is_vuln,
                source='demo',
                metadata={
                    'description': description,
                    'quality': 'expert_crafted',
                    'purpose': 'testing'
                }
            )
            demo_samples.append(sample)

        return demo_samples

    def _map_vulnerability_type(self, vuln_string: str) -> Optional[str]:
        """Map various vulnerability string formats to our standard types"""
        vuln_lower = vuln_string.lower()

        for standard_type, variants in self.vulnerability_mapping.items():
            for variant in variants:
                if variant.lower() in vuln_lower:
                    return standard_type

        return None

    def _process_samples(self, samples: List[BlockchainSample], max_samples: Optional[int]) -> List[Dict]:
        """Process samples for training"""
        logger.info(f"Processing {len(samples)} samples for training")

        processed = []

        # Limit samples if specified
        if max_samples:
            samples = samples[:max_samples]

        for i, sample in enumerate(samples):
            try:
                # Parse contract to extract graph features
                graph = self.parser.parse_solidity_code(sample.code)

                # Create training sample
                processed_sample = {
                    'id': sample.id,
                    'code': sample.code,
                    'vulnerability_binary': sample.vulnerability_binary,
                    'vulnerability_labels': sample.vulnerability_labels,
                    'source': sample.source,
                    'metadata': sample.metadata,
                    'graph_features': {
                        'node_count': len(graph.nodes),
                        'edge_count': len(graph.edges),
                        'contract_features': graph.contract_features,
                        'security_level': min(node.security_level for node in graph.nodes) if graph.nodes else 4,
                        'vulnerability_markers': [node.vulnerability_markers for node in graph.nodes],
                        'gas_estimate': sum(node.gas_estimate for node in graph.nodes)
                    }
                }

                processed.append(processed_sample)

                if i % 100 == 0:
                    logger.info(f"Processed {i}/{len(samples)} samples")

            except Exception as e:
                logger.warning(f"Error processing sample {sample.id}: {e}")
                continue

        return processed

    def _save_processed_dataset(self, samples: List[Dict]):
        """Save processed dataset to files"""
        logger.info(f"Saving {len(samples)} processed samples")

        # Split into train/val/test
        total = len(samples)
        train_size = int(0.8 * total)
        val_size = int(0.1 * total)

        train_samples = samples[:train_size]
        val_samples = samples[train_size:train_size + val_size]
        test_samples = samples[train_size + val_size:]

        # Save splits
        splits = {
            'train': train_samples,
            'validation': val_samples,
            'test': test_samples
        }

        for split_name, split_samples in splits.items():
            output_file = self.processed_dir / f"{split_name}.jsonl"

            with open(output_file, 'w') as f:
                for sample in split_samples:
                    f.write(json.dumps(sample, default=str) + '\n')

            logger.info(f"Saved {len(split_samples)} samples to {output_file}")

        # Save dataset statistics
        stats = self._calculate_dataset_stats(samples)
        stats_file = self.processed_dir / "dataset_stats.json"

        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2, default=str)

        logger.info(f"Dataset statistics saved to {stats_file}")

    def _calculate_dataset_stats(self, samples: List[Dict]) -> Dict:
        """Calculate comprehensive dataset statistics"""
        total_samples = len(samples)
        vulnerable_samples = sum(1 for s in samples if s['vulnerability_binary'] == 1)

        # Count by source
        source_counts = {}
        for sample in samples:
            source = sample['source']
            source_counts[source] = source_counts.get(source, 0) + 1

        # Count by vulnerability type
        vuln_type_counts = {}
        for sample in samples:
            for vuln in sample['vulnerability_labels']:
                vuln_type_counts[vuln] = vuln_type_counts.get(vuln, 0) + 1

        # Graph statistics
        total_nodes = sum(s['graph_features']['node_count'] for s in samples)
        total_edges = sum(s['graph_features']['edge_count'] for s in samples)
        avg_nodes = total_nodes / total_samples if total_samples > 0 else 0
        avg_edges = total_edges / total_samples if total_samples > 0 else 0

        stats = {
            'total_samples': total_samples,
            'vulnerable_samples': vulnerable_samples,
            'safe_samples': total_samples - vulnerable_samples,
            'vulnerability_ratio': vulnerable_samples / total_samples if total_samples > 0 else 0,
            'source_distribution': source_counts,
            'vulnerability_type_distribution': vuln_type_counts,
            'graph_statistics': {
                'total_nodes': total_nodes,
                'total_edges': total_edges,
                'average_nodes_per_contract': avg_nodes,
                'average_edges_per_contract': avg_edges
            },
            'collection_timestamp': time.time()
        }

        return stats

def main():
    """Main data collection function"""
    logger.info("VulnHunter Blockchain Dataset Collection")

    collector = BlockchainDatasetCollector()

    # Collect all datasets (limit for demo)
    samples = collector.collect_all_datasets(max_samples=1000)

    logger.info("Dataset collection completed successfully!")

    # Print summary
    stats_file = collector.processed_dir / "dataset_stats.json"
    if stats_file.exists():
        with open(stats_file, 'r') as f:
            stats = json.load(f)

        print(f"\n=== Dataset Collection Summary ===")
        print(f"Total samples: {stats['total_samples']}")
        print(f"Vulnerable: {stats['vulnerable_samples']} ({stats['vulnerability_ratio']:.1%})")
        print(f"Source distribution: {stats['source_distribution']}")
        print(f"Vulnerability types: {len(stats['vulnerability_type_distribution'])}")

if __name__ == "__main__":
    main()