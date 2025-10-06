#!/usr/bin/env python3
"""
GitHub Vulnerability Dataset Loader
Supports PrimeVul, DiverseVul, and other GitHub-based vulnerability datasets
Extracts code, commit metadata (diffs, messages), and issue discussions
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import requests
from datetime import datetime
import re
import difflib

try:
    from datasets import load_dataset
    DATASETS_AVAILABLE = True
except ImportError:
    DATASETS_AVAILABLE = False

try:
    from github import Github
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GitHubDatasetLoader:
    """
    Load and process GitHub vulnerability datasets
    Supports: PrimeVul, DiverseVul, BigVul, CodeXGLUE
    """

    def __init__(self, github_token: Optional[str] = None):
        """
        Args:
            github_token: GitHub API token for accessing repositories
        """
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.github_client = None

        if GITHUB_AVAILABLE and self.github_token:
            try:
                self.github_client = Github(self.github_token)
                logger.info("GitHub API client initialized")
            except Exception as e:
                logger.warning(f"GitHub API client failed: {e}")

        self.datasets = {}
        self.processed_data = []

    def load_primevul(self) -> bool:
        """
        Load PrimeVul dataset from HuggingFace
        PrimeVul: Large-scale vulnerability dataset from GitHub
        """
        logger.info("Loading PrimeVul dataset...")

        if not DATASETS_AVAILABLE:
            logger.error("datasets library not available. Install with: pip install datasets")
            return False

        try:
            # PrimeVul is available on HuggingFace
            dataset = load_dataset("ASSERT-KTH/PrimeVul", split='train')

            logger.info(f"✅ Loaded PrimeVul: {len(dataset)} samples")

            # Store dataset
            self.datasets['primevul'] = dataset

            # Show sample
            if len(dataset) > 0:
                sample = dataset[0]
                logger.info(f"\nSample keys: {sample.keys()}")

            return True

        except Exception as e:
            logger.error(f"Failed to load PrimeVul: {e}")
            logger.info("Alternative: Download from https://huggingface.co/datasets/ASSERT-KTH/PrimeVul")
            return False

    def load_diversevul(self) -> bool:
        """
        Load DiverseVul dataset
        DiverseVul: Diverse vulnerability dataset with commit metadata
        """
        logger.info("Loading DiverseVul dataset...")

        if not DATASETS_AVAILABLE:
            logger.error("datasets library not available")
            return False

        try:
            # Try loading from HuggingFace
            dataset = load_dataset("ISSTA2023/DiverseVul", split='train')

            logger.info(f"✅ Loaded DiverseVul: {len(dataset)} samples")
            self.datasets['diversevul'] = dataset

            return True

        except Exception as e:
            logger.warning(f"HuggingFace load failed: {e}")
            logger.info("Trying alternative sources...")

            # Alternative: Load from GitHub releases
            return self._load_diversevul_from_github()

    def _load_diversevul_from_github(self) -> bool:
        """Load DiverseVul from GitHub releases"""
        try:
            url = "https://github.com/ISSTA2023/DiverseVul/raw/main/dataset/diversevul.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()
            logger.info(f"✅ Loaded DiverseVul from GitHub: {len(data)} samples")

            self.datasets['diversevul'] = data
            return True

        except Exception as e:
            logger.error(f"Failed to load DiverseVul from GitHub: {e}")
            return False

    def load_bigvul(self, data_path: Optional[str] = None) -> bool:
        """
        Load BigVul dataset
        BigVul: Large-scale C/C++ vulnerability dataset
        """
        logger.info("Loading BigVul dataset...")

        # BigVul is typically distributed as CSV/JSON
        if data_path and Path(data_path).exists():
            import pandas as pd

            try:
                if data_path.endswith('.csv'):
                    df = pd.read_csv(data_path)
                elif data_path.endswith('.json'):
                    df = pd.read_json(data_path)
                else:
                    logger.error(f"Unsupported format: {data_path}")
                    return False

                logger.info(f"✅ Loaded BigVul: {len(df)} samples")
                self.datasets['bigvul'] = df.to_dict('records')
                return True

            except Exception as e:
                logger.error(f"Failed to load BigVul: {e}")
                return False

        logger.info("BigVul path not provided. Download from:")
        logger.info("  https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset")
        return False

    def extract_commit_metadata(
        self,
        repo_url: str,
        commit_hash: str
    ) -> Dict:
        """
        Extract commit metadata from GitHub

        Args:
            repo_url: GitHub repository URL
            commit_hash: Commit SHA hash

        Returns:
            Dict with commit metadata (diff, message, files, etc.)
        """
        metadata = {
            'commit_hash': commit_hash,
            'repo_url': repo_url,
            'diff': None,
            'message': None,
            'files_changed': [],
            'additions': 0,
            'deletions': 0,
            'author': None,
            'date': None,
            'error': None
        }

        if not self.github_client:
            logger.warning("GitHub client not available. Using API fallback.")
            return self._extract_commit_via_api(repo_url, commit_hash)

        try:
            # Parse repo owner and name
            repo_name = self._parse_repo_name(repo_url)
            if not repo_name:
                metadata['error'] = "Invalid repo URL"
                return metadata

            # Get repository
            repo = self.github_client.get_repo(repo_name)

            # Get commit
            commit = repo.get_commit(commit_hash)

            # Extract metadata
            metadata['message'] = commit.commit.message
            metadata['author'] = commit.commit.author.name
            metadata['date'] = commit.commit.author.date.isoformat()

            # Get diff and file changes
            metadata['additions'] = commit.stats.additions
            metadata['deletions'] = commit.stats.deletions

            # Extract file-level changes
            for file in commit.files:
                metadata['files_changed'].append({
                    'filename': file.filename,
                    'status': file.status,
                    'additions': file.additions,
                    'deletions': file.deletions,
                    'changes': file.changes,
                    'patch': file.patch if hasattr(file, 'patch') else None
                })

            # Combine patches into full diff
            patches = [f['patch'] for f in metadata['files_changed'] if f['patch']]
            metadata['diff'] = '\n\n'.join(patches) if patches else None

            logger.debug(f"Extracted metadata for commit {commit_hash[:8]}")

        except Exception as e:
            logger.warning(f"Failed to extract commit metadata: {e}")
            metadata['error'] = str(e)

        return metadata

    def _extract_commit_via_api(self, repo_url: str, commit_hash: str) -> Dict:
        """Fallback: Extract commit using GitHub REST API"""
        metadata = {
            'commit_hash': commit_hash,
            'repo_url': repo_url,
            'diff': None,
            'message': None,
            'error': None
        }

        try:
            repo_name = self._parse_repo_name(repo_url)
            api_url = f"https://api.github.com/repos/{repo_name}/commits/{commit_hash}"

            headers = {}
            if self.github_token:
                headers['Authorization'] = f"token {self.github_token}"

            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()

            data = response.json()

            metadata['message'] = data.get('commit', {}).get('message')
            metadata['author'] = data.get('commit', {}).get('author', {}).get('name')
            metadata['date'] = data.get('commit', {}).get('author', {}).get('date')

            # Get diff
            diff_response = requests.get(
                api_url,
                headers={**headers, 'Accept': 'application/vnd.github.v3.diff'},
                timeout=10
            )
            if diff_response.ok:
                metadata['diff'] = diff_response.text

        except Exception as e:
            logger.warning(f"API fallback failed: {e}")
            metadata['error'] = str(e)

        return metadata

    def extract_issue_discussions(
        self,
        repo_url: str,
        issue_number: Optional[int] = None,
        cve_id: Optional[str] = None
    ) -> List[Dict]:
        """
        Extract issue discussions for validation

        Args:
            repo_url: GitHub repository URL
            issue_number: Issue number (if known)
            cve_id: CVE ID to search for

        Returns:
            List of discussion threads
        """
        discussions = []

        if not self.github_client:
            logger.warning("GitHub client not available for issue extraction")
            return discussions

        try:
            repo_name = self._parse_repo_name(repo_url)
            if not repo_name:
                return discussions

            repo = self.github_client.get_repo(repo_name)

            # If issue number provided, get specific issue
            if issue_number:
                issue = repo.get_issue(issue_number)
                discussions.append(self._parse_issue(issue))

            # If CVE ID provided, search for related issues
            elif cve_id:
                query = f"repo:{repo_name} {cve_id}"
                issues = self.github_client.search_issues(query)

                for issue in issues[:5]:  # Limit to 5 results
                    discussions.append(self._parse_issue(issue))

        except Exception as e:
            logger.warning(f"Failed to extract issue discussions: {e}")

        return discussions

    def _parse_issue(self, issue) -> Dict:
        """Parse GitHub issue into structured format"""
        return {
            'number': issue.number,
            'title': issue.title,
            'body': issue.body,
            'state': issue.state,
            'created_at': issue.created_at.isoformat(),
            'updated_at': issue.updated_at.isoformat(),
            'labels': [label.name for label in issue.labels],
            'comments_count': issue.comments,
            'comments': [
                {
                    'author': comment.user.login,
                    'body': comment.body,
                    'created_at': comment.created_at.isoformat()
                }
                for comment in issue.get_comments()
            ]
        }

    def _parse_repo_name(self, repo_url: str) -> Optional[str]:
        """
        Parse repository name from URL
        Examples:
          https://github.com/owner/repo -> owner/repo
          github.com/owner/repo -> owner/repo
        """
        patterns = [
            r'github\.com[/:]([^/]+)/([^/\.]+)',
            r'([^/]+)/([^/\.]+)$'
        ]

        for pattern in patterns:
            match = re.search(pattern, repo_url)
            if match:
                return f"{match.group(1)}/{match.group(2)}"

        return None

    def process_primevul(self) -> List[Dict]:
        """Process PrimeVul dataset into unified format"""
        if 'primevul' not in self.datasets:
            logger.error("PrimeVul not loaded")
            return []

        logger.info("Processing PrimeVul dataset...")
        processed = []
        dataset = self.datasets['primevul']

        for idx, sample in enumerate(dataset):
            if idx % 1000 == 0:
                logger.info(f"  Processed {idx}/{len(dataset)}")

            try:
                record = {
                    'source': 'primevul',
                    'code': sample.get('func', ''),
                    'vulnerable': 1 if sample.get('target') == 1 else 0,
                    'cve_id': sample.get('cve_id', ''),
                    'cwe_id': sample.get('cwe_id', ''),
                    'project': sample.get('project', ''),
                    'commit_hash': sample.get('commit_id', ''),
                    'commit_message': None,
                    'diff': None,
                    'issue_discussions': []
                }

                # Optionally fetch commit metadata
                if self.github_client and record['commit_hash'] and record['project']:
                    repo_url = f"https://github.com/{record['project']}"
                    metadata = self.extract_commit_metadata(repo_url, record['commit_hash'])
                    record['commit_message'] = metadata.get('message')
                    record['diff'] = metadata.get('diff')

                processed.append(record)

            except Exception as e:
                logger.warning(f"Failed to process sample {idx}: {e}")

        logger.info(f"✅ Processed {len(processed)} PrimeVul samples")
        return processed

    def process_diversevul(self) -> List[Dict]:
        """Process DiverseVul dataset into unified format"""
        if 'diversevul' not in self.datasets:
            logger.error("DiverseVul not loaded")
            return []

        logger.info("Processing DiverseVul dataset...")
        processed = []
        dataset = self.datasets['diversevul']

        # Handle both HuggingFace Dataset and list of dicts
        if hasattr(dataset, '__iter__'):
            items = dataset
        else:
            items = [dataset[i] for i in range(len(dataset))]

        for idx, sample in enumerate(items):
            if idx % 1000 == 0:
                logger.info(f"  Processed {idx}/{len(items)}")

            try:
                record = {
                    'source': 'diversevul',
                    'code': sample.get('func', '') or sample.get('code', ''),
                    'vulnerable': sample.get('target', 0),
                    'cve_id': sample.get('cve_id', ''),
                    'cwe_id': sample.get('cwe', ''),
                    'project': sample.get('project', ''),
                    'commit_hash': sample.get('commit_id', ''),
                    'commit_message': sample.get('commit_message', ''),
                    'diff': sample.get('diff', ''),
                    'issue_discussions': []
                }

                processed.append(record)

            except Exception as e:
                logger.warning(f"Failed to process sample {idx}: {e}")

        logger.info(f"✅ Processed {len(processed)} DiverseVul samples")
        return processed

    def process_all_datasets(self) -> List[Dict]:
        """Process all loaded datasets into unified format"""
        all_data = []

        if 'primevul' in self.datasets:
            all_data.extend(self.process_primevul())

        if 'diversevul' in self.datasets:
            all_data.extend(self.process_diversevul())

        if 'bigvul' in self.datasets:
            all_data.extend(self._process_bigvul())

        logger.info(f"\n✅ Total processed samples: {len(all_data)}")

        # Statistics
        sources = {}
        vulnerable_count = 0

        for record in all_data:
            source = record['source']
            sources[source] = sources.get(source, 0) + 1
            if record['vulnerable'] == 1:
                vulnerable_count += 1

        logger.info(f"\nDataset Statistics:")
        logger.info(f"  Total: {len(all_data)}")
        logger.info(f"  Vulnerable: {vulnerable_count} ({vulnerable_count/len(all_data)*100:.1f}%)")
        logger.info(f"  Safe: {len(all_data) - vulnerable_count}")
        logger.info(f"\nSources:")
        for source, count in sources.items():
            logger.info(f"  {source}: {count}")

        self.processed_data = all_data
        return all_data

    def _process_bigvul(self) -> List[Dict]:
        """Process BigVul dataset"""
        processed = []
        dataset = self.datasets.get('bigvul', [])

        for sample in dataset:
            record = {
                'source': 'bigvul',
                'code': sample.get('func', ''),
                'vulnerable': sample.get('target', 0),
                'cve_id': sample.get('CVE ID', ''),
                'cwe_id': sample.get('CWE ID', ''),
                'project': sample.get('project', ''),
                'commit_hash': sample.get('commit_id', ''),
                'commit_message': None,
                'diff': None,
                'issue_discussions': []
            }
            processed.append(record)

        return processed

    def save_processed_data(self, output_path: str):
        """Save processed data to JSON"""
        if not self.processed_data:
            logger.warning("No processed data to save")
            return

        with open(output_path, 'w') as f:
            json.dump(self.processed_data, f, indent=2)

        logger.info(f"💾 Saved {len(self.processed_data)} samples to {output_path}")


if __name__ == "__main__":
    # Example usage
    loader = GitHubDatasetLoader(github_token=os.getenv('GITHUB_TOKEN'))

    # Load datasets
    loader.load_primevul()
    loader.load_diversevul()

    # Process all
    data = loader.process_all_datasets()

    # Save
    loader.save_processed_data('github_vuln_dataset.json')

    print(f"\n✅ Loaded {len(data)} vulnerability samples")
