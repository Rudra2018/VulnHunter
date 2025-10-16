#!/usr/bin/env python3
"""
Azure ML Pipeline for Smart Contract Security Model Retraining
Comprehensive pipeline for training ML models on smart contract vulnerability data

This module integrates multiple data sources:
- GitHub repositories with smart contract frameworks
- Bug bounty platforms (Sherlock, Immunefi, etc.)
- Hugging Face datasets
- Audit competition data

Author: VulnHunter ML Team
Version: 2.0.0
"""

import os
import json
import logging
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import asyncio
import aiohttp
import git
import zipfile
import requests
from urllib.parse import urljoin

# Azure ML imports
try:
    from azureml.core import Workspace, Dataset, Environment, ScriptRunConfig, Experiment
    from azureml.core.compute import ComputeTarget, AmlCompute
    from azureml.core.compute_target import ComputeTargetException
    from azureml.train.automl import AutoMLConfig
    from azureml.pipeline.core import Pipeline, PipelineData
    from azureml.pipeline.steps import PythonScriptStep
    from azureml.core.runconfig import RunConfiguration
    from azureml.data.data_reference import DataReference
    AZURE_ML_AVAILABLE = True
except ImportError:
    AZURE_ML_AVAILABLE = False
    logging.warning("Azure ML SDK not available. Install with: pip install azureml-sdk")

# Hugging Face imports
try:
    from datasets import load_dataset
    import huggingface_hub
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False
    logging.warning("Hugging Face datasets not available. Install with: pip install datasets")

# Import our learning module
import sys
sys.path.append('/Users/ankitthakur/vuln_ml_research/models')
try:
    from learning_module import FalsePositiveFilter, SmartContractFeatureExtractor
    LEARNING_MODULE_AVAILABLE = True
except ImportError:
    LEARNING_MODULE_AVAILABLE = False
    logging.warning("Learning module not available")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DataSourceError(Exception):
    """Custom exception for data source errors."""
    pass


class AzureMLTrainingError(Exception):
    """Custom exception for Azure ML training errors."""
    pass


class SmartContractDataCollector:
    """
    Comprehensive data collector for smart contract security datasets.
    Integrates multiple sources for training the false positive filter.
    """

    def __init__(self, output_dir: str = "./smart_contract_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Data source configurations
        self.github_repos = [
            "https://github.com/PatrickAlphaC/smart-contract-frameworks",
            "https://github.com/tintinweb/smart-contract-sanctuary",
            "https://github.com/TokenMarketNet/smart-contracts"
        ]

        self.bug_bounty_platforms = [
            "https://audits.sherlock.xyz/bug-bounties",
            "https://hashlock.com/bug-bounty",
            "https://immunefi.com/bug-bounty/",
            "https://immunefi.com/audit-competition/",
            "https://yeswehack.com/programs",
            "https://hackenproof.com/programs"
        ]

        self.hf_datasets = [
            "Blockmates/smart-contracts-verified",
            "SarthakG/smart_contract"
        ]

        self.collected_data = {
            'contracts': [],
            'vulnerabilities': [],
            'bug_bounties': [],
            'audit_results': []
        }

        logger.info(f"Initialized data collector with output directory: {output_dir}")

    async def collect_github_repositories(self) -> Dict[str, Any]:
        """
        Collect smart contract code from GitHub repositories.
        """
        logger.info("Collecting GitHub repositories...")

        github_data = {
            'repositories': [],
            'contracts': [],
            'frameworks': []
        }

        for repo_url in self.github_repos:
            try:
                logger.info(f"Cloning repository: {repo_url}")

                # Extract repo name from URL
                repo_name = repo_url.split('/')[-1]
                local_path = self.output_dir / "github" / repo_name

                # Clone repository
                if local_path.exists():
                    logger.info(f"Repository already exists, pulling updates: {local_path}")
                    repo = git.Repo(local_path)
                    repo.remotes.origin.pull()
                else:
                    logger.info(f"Cloning repository to: {local_path}")
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    repo = git.Repo.clone_from(repo_url, local_path)

                # Analyze repository structure
                repo_info = self._analyze_repository(local_path, repo_url)
                github_data['repositories'].append(repo_info)

                # Extract smart contracts
                contracts = self._extract_smart_contracts(local_path)
                github_data['contracts'].extend(contracts)

                # Extract framework information
                frameworks = self._extract_framework_info(local_path)
                github_data['frameworks'].extend(frameworks)

            except Exception as e:
                logger.error(f"Error processing repository {repo_url}: {e}")
                continue

        logger.info(f"Collected {len(github_data['contracts'])} contracts from {len(github_data['repositories'])} repositories")
        return github_data

    def _analyze_repository(self, repo_path: Path, repo_url: str) -> Dict[str, Any]:
        """Analyze repository structure and metadata."""

        # Count file types
        file_counts = {}
        contract_files = []

        for file_path in repo_path.rglob("*"):
            if file_path.is_file():
                suffix = file_path.suffix.lower()
                file_counts[suffix] = file_counts.get(suffix, 0) + 1

                if suffix == '.sol':
                    contract_files.append(str(file_path.relative_to(repo_path)))

        # Get repository metadata
        try:
            repo = git.Repo(repo_path)
            commits = list(repo.iter_commits())
            last_commit = commits[0] if commits else None

            repo_info = {
                'url': repo_url,
                'name': repo_path.name,
                'path': str(repo_path),
                'file_counts': file_counts,
                'contract_files': contract_files,
                'total_contracts': len(contract_files),
                'last_commit': {
                    'hash': str(last_commit.hexsha) if last_commit else None,
                    'date': str(last_commit.committed_datetime) if last_commit else None,
                    'author': str(last_commit.author) if last_commit else None
                },
                'total_commits': len(commits)
            }

        except Exception as e:
            logger.warning(f"Could not get git metadata for {repo_path}: {e}")
            repo_info = {
                'url': repo_url,
                'name': repo_path.name,
                'path': str(repo_path),
                'file_counts': file_counts,
                'contract_files': contract_files,
                'total_contracts': len(contract_files)
            }

        return repo_info

    def _extract_smart_contracts(self, repo_path: Path) -> List[Dict[str, Any]]:
        """Extract smart contract information from repository."""
        contracts = []

        for sol_file in repo_path.rglob("*.sol"):
            try:
                with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                contract_info = {
                    'file_path': str(sol_file.relative_to(repo_path)),
                    'absolute_path': str(sol_file),
                    'name': sol_file.stem,
                    'size': len(content),
                    'lines': len(content.splitlines()),
                    'content': content,
                    'solidity_version': self._extract_solidity_version(content),
                    'contract_names': self._extract_contract_names(content),
                    'functions': self._extract_function_signatures(content),
                    'has_vulnerabilities': self._detect_potential_vulnerabilities(content),
                    'security_patterns': self._analyze_security_patterns(content),
                    'repository': repo_path.name
                }

                contracts.append(contract_info)

            except Exception as e:
                logger.warning(f"Error processing contract {sol_file}: {e}")
                continue

        return contracts

    def _extract_solidity_version(self, content: str) -> Optional[str]:
        """Extract Solidity version from contract."""
        import re
        version_match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
        return version_match.group(1) if version_match else None

    def _extract_contract_names(self, content: str) -> List[str]:
        """Extract contract names from source code."""
        import re
        contracts = re.findall(r'(?:contract|interface|library)\s+(\w+)', content)
        return contracts

    def _extract_function_signatures(self, content: str) -> List[str]:
        """Extract function signatures from contract."""
        import re
        functions = re.findall(r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|private|internal|external)?', content)
        return functions

    def _detect_potential_vulnerabilities(self, content: str) -> Dict[str, bool]:
        """Detect potential vulnerability patterns in contract."""
        import re

        vulnerabilities = {
            'reentrancy': bool(re.search(r'\.call\s*\(|\.send\s*\(|\.transfer\s*\(', content)),
            'overflow': bool(re.search(r'[+\-*/]\s*(?!SafeMath)', content)) and 'SafeMath' not in content,
            'unchecked_external_call': bool(re.search(r'\.call\s*\([^)]*\)(?!\s*(?:require|assert))', content)),
            'timestamp_dependency': bool(re.search(r'block\.timestamp|now', content)),
            'tx_origin': bool(re.search(r'tx\.origin', content)),
            'uninitialized_storage': bool(re.search(r'storage\s+\w+;', content)),
            'delegatecall': bool(re.search(r'delegatecall', content)),
            'selfdestruct': bool(re.search(r'selfdestruct|suicide', content))
        }

        return vulnerabilities

    def _analyze_security_patterns(self, content: str) -> Dict[str, bool]:
        """Analyze security patterns and protections in contract."""
        import re

        patterns = {
            'has_access_control': bool(re.search(r'onlyOwner|onlyRole|require.*msg\.sender', content)),
            'has_reentrancy_guard': bool(re.search(r'nonReentrant|ReentrancyGuard', content)),
            'uses_safe_math': bool(re.search(r'SafeMath|using.*for', content)),
            'has_pause_mechanism': bool(re.search(r'pause|Pausable', content)),
            'has_emergency_stop': bool(re.search(r'emergency|circuit.*breaker', content)),
            'uses_checks_effects_interactions': self._check_cei_pattern(content),
            'has_input_validation': bool(re.search(r'require\s*\(|assert\s*\(', content)),
            'uses_events': bool(re.search(r'emit\s+\w+|event\s+\w+', content))
        }

        return patterns

    def _check_cei_pattern(self, content: str) -> bool:
        """Check if contract follows Checks-Effects-Interactions pattern."""
        # Simplified heuristic for CEI pattern
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if '.call(' in line or '.send(' in line or '.transfer(' in line:
                # Check if there are state changes after external calls
                remaining_lines = lines[i+1:i+10]  # Check next 10 lines
                for remaining_line in remaining_lines:
                    if ('=' in remaining_line and
                        any(keyword in remaining_line for keyword in ['balance', 'amount', 'state'])):
                        return False  # State change after external call
        return True

    def _extract_framework_info(self, repo_path: Path) -> List[Dict[str, Any]]:
        """Extract framework and tooling information."""
        frameworks = []

        # Check for common framework files
        framework_files = {
            'hardhat.config.js': 'hardhat',
            'hardhat.config.ts': 'hardhat',
            'truffle-config.js': 'truffle',
            'foundry.toml': 'foundry',
            'brownie-config.yaml': 'brownie',
            'package.json': 'npm',
            'requirements.txt': 'python'
        }

        for file_name, framework_type in framework_files.items():
            config_file = repo_path / file_name
            if config_file.exists():
                try:
                    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    framework_info = {
                        'type': framework_type,
                        'config_file': file_name,
                        'content': content,
                        'repository': repo_path.name
                    }

                    # Extract dependencies for package.json
                    if file_name == 'package.json':
                        try:
                            package_data = json.loads(content)
                            framework_info['dependencies'] = package_data.get('dependencies', {})
                            framework_info['dev_dependencies'] = package_data.get('devDependencies', {})
                        except json.JSONDecodeError:
                            pass

                    frameworks.append(framework_info)

                except Exception as e:
                    logger.warning(f"Error reading framework file {config_file}: {e}")

        return frameworks

    async def collect_bug_bounty_data(self) -> Dict[str, Any]:
        """
        Collect bug bounty and audit data from security platforms.
        """
        logger.info("Collecting bug bounty data...")

        bug_bounty_data = {
            'programs': [],
            'vulnerabilities': [],
            'payouts': []
        }

        # Note: This is a simplified version. In practice, you'd need to implement
        # specific scrapers for each platform following their terms of service

        for platform_url in self.bug_bounty_platforms:
            try:
                logger.info(f"Collecting data from: {platform_url}")

                # Sherlock specific collection
                if 'sherlock.xyz' in platform_url:
                    sherlock_data = await self._collect_sherlock_data()
                    bug_bounty_data['vulnerabilities'].extend(sherlock_data)

                # Immunefi specific collection
                elif 'immunefi.com' in platform_url:
                    immunefi_data = await self._collect_immunefi_data()
                    bug_bounty_data['programs'].extend(immunefi_data)

                # Add other platform collectors as needed

            except Exception as e:
                logger.error(f"Error collecting from {platform_url}: {e}")
                continue

        logger.info(f"Collected bug bounty data: {len(bug_bounty_data['programs'])} programs, {len(bug_bounty_data['vulnerabilities'])} vulnerabilities")
        return bug_bounty_data

    async def _collect_sherlock_data(self) -> List[Dict[str, Any]]:
        """Collect audit findings from Sherlock platform."""
        # This would implement Sherlock-specific data collection
        # For now, return structured placeholder data

        sherlock_findings = [
            {
                'platform': 'sherlock',
                'type': 'audit_finding',
                'severity': 'high',
                'title': 'Reentrancy vulnerability in DeFi protocol',
                'description': 'Missing reentrancy guard allows attackers to drain funds',
                'contract_type': 'defi',
                'vulnerability_category': 'reentrancy',
                'bounty_amount': 50000,
                'is_false_positive': False,
                'validation_notes': ['Genuine vulnerability', 'Production impact confirmed']
            }
        ]

        return sherlock_findings

    async def _collect_immunefi_data(self) -> List[Dict[str, Any]]:
        """Collect bug bounty programs from Immunefi."""
        # This would implement Immunefi-specific data collection

        immunefi_programs = [
            {
                'platform': 'immunefi',
                'protocol_name': 'Sample DeFi Protocol',
                'max_bounty': 1000000,
                'asset_types': ['smart_contract'],
                'blockchain': 'ethereum',
                'program_type': 'bug_bounty'
            }
        ]

        return immunefi_programs

    def collect_huggingface_datasets(self) -> Dict[str, Any]:
        """
        Collect smart contract datasets from Hugging Face.
        """
        if not HF_AVAILABLE:
            logger.warning("Hugging Face datasets not available")
            return {'datasets': []}

        logger.info("Collecting Hugging Face datasets...")

        hf_data = {
            'datasets': [],
            'contracts': [],
            'metadata': []
        }

        for dataset_name in self.hf_datasets:
            try:
                logger.info(f"Loading dataset: {dataset_name}")

                # Load dataset
                dataset = load_dataset(dataset_name, split='train')

                # Convert to pandas for easier processing
                df = dataset.to_pandas()

                dataset_info = {
                    'name': dataset_name,
                    'size': len(df),
                    'columns': list(df.columns),
                    'description': getattr(dataset, 'description', ''),
                    'features': getattr(dataset, 'features', {})
                }

                hf_data['datasets'].append(dataset_info)

                # Process contract data
                contracts = self._process_hf_contracts(df, dataset_name)
                hf_data['contracts'].extend(contracts)

            except Exception as e:
                logger.error(f"Error loading dataset {dataset_name}: {e}")
                continue

        logger.info(f"Collected {len(hf_data['contracts'])} contracts from {len(hf_data['datasets'])} HF datasets")
        return hf_data

    def _process_hf_contracts(self, df: pd.DataFrame, dataset_name: str) -> List[Dict[str, Any]]:
        """Process smart contracts from Hugging Face dataset."""
        contracts = []

        for _, row in df.iterrows():
            try:
                # Adapt to different dataset schemas
                if 'source_code' in row:
                    source_code = row['source_code']
                elif 'code' in row:
                    source_code = row['code']
                elif 'contract' in row:
                    source_code = row['contract']
                else:
                    continue

                contract_info = {
                    'source': 'huggingface',
                    'dataset': dataset_name,
                    'content': source_code,
                    'size': len(source_code),
                    'lines': len(source_code.splitlines()),
                    'name': row.get('name', 'unknown'),
                    'address': row.get('address', ''),
                    'verified': row.get('verified', False),
                    'compiler_version': row.get('compiler_version', ''),
                    'has_vulnerabilities': self._detect_potential_vulnerabilities(source_code),
                    'security_patterns': self._analyze_security_patterns(source_code)
                }

                contracts.append(contract_info)

            except Exception as e:
                logger.warning(f"Error processing contract row: {e}")
                continue

        return contracts

    async def collect_all_data(self) -> Dict[str, Any]:
        """
        Collect data from all sources.
        """
        logger.info("Starting comprehensive data collection...")

        all_data = {
            'github': {},
            'bug_bounties': {},
            'huggingface': {},
            'collection_metadata': {
                'timestamp': datetime.now().isoformat(),
                'sources': {
                    'github_repos': len(self.github_repos),
                    'bug_bounty_platforms': len(self.bug_bounty_platforms),
                    'hf_datasets': len(self.hf_datasets)
                }
            }
        }

        # Collect GitHub data
        try:
            all_data['github'] = await self.collect_github_repositories()
        except Exception as e:
            logger.error(f"GitHub collection failed: {e}")
            all_data['github'] = {}

        # Collect bug bounty data
        try:
            all_data['bug_bounties'] = await self.collect_bug_bounty_data()
        except Exception as e:
            logger.error(f"Bug bounty collection failed: {e}")
            all_data['bug_bounties'] = {}

        # Collect Hugging Face data
        try:
            all_data['huggingface'] = self.collect_huggingface_datasets()
        except Exception as e:
            logger.error(f"Hugging Face collection failed: {e}")
            all_data['huggingface'] = {}

        # Save collected data
        output_file = self.output_dir / "collected_data.json"
        with open(output_file, 'w') as f:
            json.dump(all_data, f, indent=2, default=str)

        logger.info(f"Data collection completed. Saved to: {output_file}")
        return all_data


class AzureMLTrainingPipeline:
    """
    Azure ML pipeline for training the smart contract false positive filter.
    """

    def __init__(self, workspace_config: Dict[str, str], compute_name: str = "ml-compute"):
        if not AZURE_ML_AVAILABLE:
            raise AzureMLTrainingError("Azure ML SDK not available")

        self.workspace = None
        self.compute_target = None
        self.workspace_config = workspace_config
        self.compute_name = compute_name

        logger.info("Initializing Azure ML training pipeline")

    def setup_workspace(self) -> None:
        """Setup Azure ML workspace."""
        try:
            # Try to load existing workspace
            self.workspace = Workspace.from_config()
            logger.info("Loaded existing workspace configuration")
        except:
            # Create new workspace
            self.workspace = Workspace.create(
                name=self.workspace_config['workspace_name'],
                subscription_id=self.workspace_config['subscription_id'],
                resource_group=self.workspace_config['resource_group'],
                location=self.workspace_config['location'],
                create_resource_group=True,
                exist_ok=True
            )
            logger.info("Created new Azure ML workspace")

    def setup_compute(self, vm_size: str = "Standard_DS3_v2", max_nodes: int = 4) -> None:
        """Setup compute cluster for training."""
        try:
            self.compute_target = ComputeTarget(workspace=self.workspace, name=self.compute_name)
            logger.info(f"Found existing compute target: {self.compute_name}")
        except ComputeTargetException:
            logger.info(f"Creating new compute target: {self.compute_name}")

            compute_config = AmlCompute.provisioning_configuration(
                vm_size=vm_size,
                max_nodes=max_nodes,
                min_nodes=0,
                idle_seconds_before_scaledown=300
            )

            self.compute_target = ComputeTarget.create(
                self.workspace,
                self.compute_name,
                compute_config
            )

            self.compute_target.wait_for_completion(show_output=True)

    def create_training_environment(self) -> Environment:
        """Create conda environment for training."""
        env = Environment(name="smart-contract-security-env")

        # Define conda dependencies
        conda_deps = {
            'channels': ['conda-forge', 'defaults'],
            'dependencies': [
                'python=3.8',
                'pip',
                {
                    'pip': [
                        'scikit-learn==1.1.3',
                        'pandas==1.5.2',
                        'numpy==1.21.6',
                        'joblib==1.2.0',
                        'azureml-sdk',
                        'datasets',
                        'transformers',
                        'torch',
                        'matplotlib',
                        'seaborn'
                    ]
                }
            ]
        }

        env.python.conda_dependencies.set_python_version("3.8")
        env.python.conda_dependencies._from_conda_specification(conda_deps)

        return env

    def prepare_training_data(self, collected_data: Dict[str, Any]) -> pd.DataFrame:
        """
        Prepare training data from collected sources.
        """
        logger.info("Preparing training data...")

        training_samples = []

        # Process GitHub contracts
        github_contracts = collected_data.get('github', {}).get('contracts', [])
        for contract in github_contracts:
            # Create training samples with different vulnerability patterns
            vulnerabilities = contract.get('has_vulnerabilities', {})
            security_patterns = contract.get('security_patterns', {})

            for vuln_type, has_vuln in vulnerabilities.items():
                sample = {
                    'finding_id': f"github_{contract['repository']}_{contract['name']}_{vuln_type}",
                    'original_severity': 'High' if has_vuln else 'Medium',
                    'validated_severity': 'False Positive' if not has_vuln else 'High',
                    'confidence': 0.8 if has_vuln else 0.3,
                    'adjusted_confidence': 0.8 if has_vuln else 0.2,
                    'validation_score': 3.5 if has_vuln else 1.5,
                    'confidence_level': 'Medium' if has_vuln else 'Very Low',
                    'file_path': contract['file_path'],
                    'line_number': 100,  # Placeholder
                    'code_snippet': contract['content'][:200],  # First 200 chars
                    'validation_notes': self._generate_validation_notes(vuln_type, has_vuln, security_patterns),
                    'production_impact': 'High - Fund loss potential' if has_vuln else 'Minimal - No significant impact',
                    'is_false_positive': not has_vuln,
                    'vulnerability_type': vuln_type,
                    'source': 'github',
                    'repository': contract['repository']
                }

                training_samples.append(sample)

        # Process bug bounty data
        bug_bounty_vulns = collected_data.get('bug_bounties', {}).get('vulnerabilities', [])
        for vuln in bug_bounty_vulns:
            sample = {
                'finding_id': f"bounty_{vuln.get('platform')}_{hash(vuln.get('title', ''))}",
                'original_severity': vuln.get('severity', 'Medium').title(),
                'validated_severity': 'False Positive' if vuln.get('is_false_positive', False) else vuln.get('severity', 'Medium').title(),
                'confidence': 0.9 if not vuln.get('is_false_positive', False) else 0.2,
                'adjusted_confidence': 0.9 if not vuln.get('is_false_positive', False) else 0.1,
                'validation_score': 4.0 if not vuln.get('is_false_positive', False) else 1.0,
                'confidence_level': 'High' if not vuln.get('is_false_positive', False) else 'Very Low',
                'file_path': f"/contracts/{vuln.get('contract_type', 'unknown')}.sol",
                'line_number': 50,
                'code_snippet': vuln.get('description', '')[:200],
                'validation_notes': vuln.get('validation_notes', []),
                'production_impact': 'High - Production vulnerability' if not vuln.get('is_false_positive', False) else 'Minimal - False alarm',
                'is_false_positive': vuln.get('is_false_positive', False),
                'vulnerability_type': vuln.get('vulnerability_category', 'unknown'),
                'source': 'bug_bounty',
                'platform': vuln.get('platform', 'unknown')
            }

            training_samples.append(sample)

        # Process Hugging Face contracts
        hf_contracts = collected_data.get('huggingface', {}).get('contracts', [])
        for contract in hf_contracts:
            vulnerabilities = contract.get('has_vulnerabilities', {})

            for vuln_type, has_vuln in vulnerabilities.items():
                sample = {
                    'finding_id': f"hf_{contract['dataset']}_{contract['name']}_{vuln_type}",
                    'original_severity': 'High' if has_vuln else 'Low',
                    'validated_severity': 'Medium' if has_vuln else 'False Positive',
                    'confidence': 0.7 if has_vuln else 0.2,
                    'adjusted_confidence': 0.7 if has_vuln else 0.15,
                    'validation_score': 3.0 if has_vuln else 1.2,
                    'confidence_level': 'Medium' if has_vuln else 'Very Low',
                    'file_path': f"/hf_contracts/{contract['name']}.sol",
                    'line_number': 75,
                    'code_snippet': contract['content'][:200],
                    'validation_notes': [f"HuggingFace dataset: {contract['dataset']}", f"Verified: {contract.get('verified', False)}"],
                    'production_impact': 'Medium - Potential issue' if has_vuln else 'Minimal - No impact',
                    'is_false_positive': not has_vuln,
                    'vulnerability_type': vuln_type,
                    'source': 'huggingface',
                    'dataset': contract['dataset']
                }

                training_samples.append(sample)

        df = pd.DataFrame(training_samples)
        logger.info(f"Created training dataset with {len(df)} samples")
        logger.info(f"False positive ratio: {df['is_false_positive'].mean():.3f}")

        return df

    def _generate_validation_notes(self, vuln_type: str, has_vuln: bool, security_patterns: Dict[str, bool]) -> List[str]:
        """Generate realistic validation notes based on vulnerability type and security patterns."""
        notes = []

        if not has_vuln:
            notes.append("FALSE_POSITIVE_INDICATOR: No genuine vulnerability found")

            if security_patterns.get('has_access_control', False):
                notes.append("PROTECTED_FUNCTION: Function has proper access controls")

            if security_patterns.get('has_reentrancy_guard', False):
                notes.append("PROPER_VALIDATION: Reentrancy protection in place")

            if security_patterns.get('uses_safe_math', False):
                notes.append("SAFE_MATH_USAGE: SafeMath library prevents overflow")

            notes.append("LEGITIMATE_EXTERNAL_CALL: Pattern appears to be legitimate protocol interaction")
        else:
            notes.append("POTENTIAL_VULNERABILITY: Code pattern shows vulnerability indicators")
            notes.append(f"VULNERABILITY_TYPE: {vuln_type} detected")

            if vuln_type == 'reentrancy' and not security_patterns.get('has_reentrancy_guard', False):
                notes.append("MISSING_REENTRANCY_GUARD: No protection against reentrancy attacks")

            if vuln_type == 'overflow' and not security_patterns.get('uses_safe_math', False):
                notes.append("OVERFLOW_RISK: No SafeMath usage detected")

        return notes

    def create_training_script(self, output_dir: Path) -> str:
        """Create training script for Azure ML."""
        script_content = '''
import os
import json
import joblib
import pandas as pd
from sklearn.metrics import classification_report
import argparse
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import our learning module (would be included in the environment)
try:
    from learning_module import FalsePositiveFilter
except ImportError:
    logger.error("Learning module not available")
    raise

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input_data', type=str, help='Path to training data')
    parser.add_argument('--output_model', type=str, help='Path to save trained model')
    parser.add_argument('--domain', type=str, default='smart_contract', help='Security domain')

    args = parser.parse_args()

    logger.info("Starting Azure ML training...")
    logger.info(f"Input data: {args.input_data}")
    logger.info(f"Output model: {args.output_model}")
    logger.info(f"Domain: {args.domain}")

    # Initialize false positive filter
    fp_filter = FalsePositiveFilter(domain=args.domain)

    # Train model
    results = fp_filter.train(args.input_data, test_size=0.2, random_state=42)

    # Log training results
    logger.info(f"Training completed!")
    logger.info(f"Test accuracy: {results['test_accuracy']:.3f}")
    logger.info(f"CV accuracy: {results['cv_mean_accuracy']:.3f} (+/- {results['cv_std_accuracy'] * 2:.3f})")

    # Save model
    fp_filter.save_model(args.output_model)

    # Save training results
    results_file = os.path.join(os.path.dirname(args.output_model), 'training_results.json')
    with open(results_file, 'w') as f:
        # Convert numpy types to Python types for JSON serialization
        json_results = {}
        for key, value in results.items():
            if key == 'feature_importance':
                json_results[key] = {k: float(v) for k, v in value.items()}
            elif isinstance(value, (int, float, str, list)):
                json_results[key] = value
            else:
                json_results[key] = str(value)

        json.dump(json_results, f, indent=2)

    logger.info(f"Training results saved to: {results_file}")

if __name__ == "__main__":
    main()
'''

        script_path = output_dir / "azure_training_script.py"
        with open(script_path, 'w') as f:
            f.write(script_content)

        return str(script_path)

    def run_training_pipeline(self, training_data: pd.DataFrame) -> None:
        """
        Run the complete training pipeline on Azure ML.
        """
        logger.info("Starting Azure ML training pipeline...")

        # Create experiment
        experiment = Experiment(workspace=self.workspace, name="smart-contract-fp-filter")

        # Save training data to workspace
        training_data_path = "./training_data.json"
        training_data.to_json(training_data_path, orient='records', indent=2)

        # Upload data to Azure ML datastore
        datastore = self.workspace.get_default_datastore()
        training_data_ref = datastore.upload_files(
            files=[training_data_path],
            target_path='training_data',
            overwrite=True
        )

        # Create training script
        script_dir = Path("./azure_scripts")
        script_dir.mkdir(exist_ok=True)
        training_script = self.create_training_script(script_dir)

        # Setup environment
        env = self.create_training_environment()

        # Create run configuration
        run_config = ScriptRunConfig(
            source_directory=str(script_dir),
            script='azure_training_script.py',
            arguments=[
                '--input_data', training_data_path,
                '--output_model', './outputs/fp_filter_model.joblib',
                '--domain', 'smart_contract'
            ],
            compute_target=self.compute_target,
            environment=env
        )

        # Submit the run
        run = experiment.submit(run_config)

        logger.info(f"Training run submitted: {run.id}")
        logger.info("Waiting for run completion...")

        # Wait for completion
        run.wait_for_completion(show_output=True)

        # Download results
        run.download_files(prefix='outputs', output_directory='./azure_outputs')

        logger.info("Training pipeline completed!")

    def setup_automl_experiment(self, training_data: pd.DataFrame) -> AutoMLConfig:
        """
        Setup AutoML experiment for automated model selection.
        """
        logger.info("Setting up AutoML experiment...")

        # Prepare features and target
        feature_columns = [col for col in training_data.columns if col != 'is_false_positive']

        automl_config = AutoMLConfig(
            task='classification',
            primary_metric='accuracy',
            training_data=training_data,
            label_column_name='is_false_positive',
            compute_target=self.compute_target,
            experiment_timeout_minutes=60,
            max_concurrent_iterations=4,
            max_cores_per_iteration=-1,
            enable_early_stopping=True,
            featurization='auto',
            debug_log='automl_errors.log'
        )

        return automl_config

    def run_automl_training(self, training_data: pd.DataFrame) -> None:
        """
        Run AutoML training for automated model selection.
        """
        logger.info("Starting AutoML training...")

        # Create AutoML experiment
        automl_experiment = Experiment(self.workspace, "smart-contract-automl")

        # Setup AutoML configuration
        automl_config = self.setup_automl_experiment(training_data)

        # Submit AutoML run
        automl_run = automl_experiment.submit(automl_config, show_output=True)

        # Wait for completion
        automl_run.wait_for_completion(show_output=True)

        # Get best model
        best_run, fitted_model = automl_run.get_output()

        logger.info(f"Best model: {fitted_model}")
        logger.info(f"Best run metrics: {best_run.get_metrics()}")

        # Register the best model
        model = automl_run.register_model(
            model_name='smart-contract-fp-filter-automl',
            description='AutoML trained false positive filter for smart contracts'
        )

        logger.info(f"Model registered: {model.name}")


async def main():
    """
    Main execution function for the Azure ML retraining pipeline.
    """
    logger.info("Starting Smart Contract Security Model Retraining Pipeline")

    # Step 1: Collect data from all sources
    logger.info("=" * 60)
    logger.info("STEP 1: DATA COLLECTION")
    logger.info("=" * 60)

    data_collector = SmartContractDataCollector(output_dir="./smart_contract_data")
    collected_data = await data_collector.collect_all_data()

    # Step 2: Setup Azure ML environment
    logger.info("=" * 60)
    logger.info("STEP 2: AZURE ML SETUP")
    logger.info("=" * 60)

    # Azure ML configuration (update with your actual values)
    azure_config = {
        'workspace_name': 'smart-contract-security-ws',
        'subscription_id': 'your-subscription-id',
        'resource_group': 'smart-contract-rg',
        'location': 'eastus'
    }

    if AZURE_ML_AVAILABLE:
        try:
            training_pipeline = AzureMLTrainingPipeline(azure_config)
            training_pipeline.setup_workspace()
            training_pipeline.setup_compute()

            # Step 3: Prepare training data
            logger.info("=" * 60)
            logger.info("STEP 3: TRAINING DATA PREPARATION")
            logger.info("=" * 60)

            training_data = training_pipeline.prepare_training_data(collected_data)

            # Step 4: Run training
            logger.info("=" * 60)
            logger.info("STEP 4: MODEL TRAINING")
            logger.info("=" * 60)

            # Option 1: Custom training pipeline
            training_pipeline.run_training_pipeline(training_data)

            # Option 2: AutoML training (comment out if not needed)
            # training_pipeline.run_automl_training(training_data)

        except Exception as e:
            logger.error(f"Azure ML training failed: {e}")
            logger.info("Falling back to local training...")

            # Fallback to local training
            if LEARNING_MODULE_AVAILABLE:
                local_training_fallback(collected_data)
    else:
        logger.warning("Azure ML not available, running local training only")
        if LEARNING_MODULE_AVAILABLE:
            local_training_fallback(collected_data)

def local_training_fallback(collected_data: Dict[str, Any]) -> None:
    """
    Fallback to local training if Azure ML is not available.
    """
    logger.info("Running local training fallback...")

    # Create mock training data from collected data
    training_samples = []

    github_contracts = collected_data.get('github', {}).get('contracts', [])
    for i, contract in enumerate(github_contracts[:100]):  # Limit for demo
        vulnerabilities = contract.get('has_vulnerabilities', {})

        for vuln_type, has_vuln in vulnerabilities.items():
            sample = {
                'finding_id': f"local_{i}_{vuln_type}",
                'original_severity': 'High' if has_vuln else 'Low',
                'validated_severity': 'Medium' if has_vuln else 'False Positive',
                'confidence': 0.8 if has_vuln else 0.2,
                'file_path': contract['file_path'],
                'validation_notes': ['Local training sample'],
                'is_false_positive': not has_vuln
            }
            training_samples.append(sample)

    if training_samples:
        # Save training data
        training_file = "local_training_data.json"
        with open(training_file, 'w') as f:
            json.dump({'findings': training_samples}, f, indent=2)

        try:
            # Train model locally
            fp_filter = FalsePositiveFilter(domain='smart_contract')
            results = fp_filter.train(training_file)

            logger.info("Local training completed!")
            logger.info(f"Test accuracy: {results['test_accuracy']:.3f}")

            # Save model
            fp_filter.save_model("local_fp_model.joblib")

        except Exception as e:
            logger.error(f"Local training failed: {e}")
        finally:
            # Clean up
            if os.path.exists(training_file):
                os.remove(training_file)


if __name__ == "__main__":
    """
    Entry point for the Azure ML retraining pipeline.
    """
    print("Smart Contract Security Model Retraining Pipeline")
    print("=" * 60)
    print("Data Sources:")
    print("- GitHub: Smart contract frameworks and repositories")
    print("- Bug Bounty: Sherlock, Immunefi, HackenProof, etc.")
    print("- Hugging Face: Verified smart contract datasets")
    print("=" * 60)

    asyncio.run(main())