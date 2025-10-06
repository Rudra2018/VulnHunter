#!/usr/bin/env python3
"""
Enhanced GitHub Data Integrator
Processes commits, issues, and extracts validation/false positive labels
Supports PrimeVul, DiverseVul with multi-label annotations
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path

try:
    from github import Github
    PYGITHUB_AVAILABLE = True
except ImportError:
    PYGITHUB_AVAILABLE = False
    Github = None

from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedGitHubIntegrator:
    """
    Advanced GitHub data integration with validation/FP extraction
    Extracts: code, commits, issues, validation status, false positive flags
    """

    # Validation patterns (indicates confirmed vulnerability)
    VALIDATION_PATTERNS = {
        'validated': [
            r'validated\s+(?:via|through|by)\s+(?:fuzzing|testing|exploit)',
            r'confirmed\s+(?:vulnerability|exploit|bug)',
            r'reproduced\s+(?:the\s+)?(?:vulnerability|bug|issue)',
            r'CVE\s*-\s*\d{4}\s*-\s*\d+\s+assigned',
            r'security\s+fix\s+applied',
            r'patch\s+(?:merged|applied|committed)',
            r'exploit\s+(?:successful|verified|confirmed)'
        ],
        'unconfirmed': [
            r'under\s+investigation',
            r'needs?\s+(?:more\s+)?(?:testing|verification)',
            r'cannot\s+reproduce',
            r'(?:pending|awaiting)\s+(?:review|verification)',
            r'requires?\s+more\s+(?:info|information|details)'
        ]
    }

    # False positive patterns
    FALSE_POSITIVE_PATTERNS = [
        r'false\s+positive',
        r'not\s+(?:a\s+)?(?:vulnerability|bug|issue)',
        r'dismissed\s+(?:after\s+)?(?:review|analysis)',
        r'(?:incorrectly|wrongly)\s+(?:reported|flagged)',
        r'closed\s+as\s+(?:invalid|wontfix|not\s+a\s+bug)',
        r'benign\s+(?:code|pattern)',
        r'(?:safe|secure)\s+(?:by\s+design|implementation)',
        r'no\s+(?:security\s+)?(?:risk|impact|threat)'
    ]

    # Validation method patterns
    VALIDATION_METHOD_PATTERNS = {
        'fuzzing': r'(?:fuzz|afl|libfuzzer|honggfuzz)',
        'exploit': r'(?:exploit|poc|proof\s+of\s+concept)',
        'testing': r'(?:unit\s+test|integration\s+test|regression\s+test)',
        'manual': r'(?:manual\s+(?:review|analysis|testing))',
        'automated': r'(?:static\s+analysis|sast|dast|scanner)'
    }

    def __init__(self, github_token: Optional[str] = None):
        """
        Args:
            github_token: GitHub API token for accessing repositories
        """
        self.github_token = github_token

        if PYGITHUB_AVAILABLE and github_token:
            self.github_client = Github(github_token)
            logger.info("GitHub API client initialized")
        else:
            self.github_client = None
            if not PYGITHUB_AVAILABLE:
                logger.warning("PyGithub not installed - commit/issue extraction will be limited")
            elif not github_token:
                logger.warning("No GitHub token - commit/issue extraction will be limited")

    def extract_validation_status(self, text: str) -> Dict:
        """
        Extract validation status from commit message or issue text

        Returns:
            {
                'status': 'validated' | 'unconfirmed' | 'unknown',
                'method': 'fuzzing' | 'exploit' | 'testing' | etc.,
                'confidence': float (0-1)
            }
        """
        text_lower = text.lower()

        # Check for validation
        validated_count = 0
        for pattern in self.VALIDATION_PATTERNS['validated']:
            if re.search(pattern, text_lower):
                validated_count += 1

        # Check for unconfirmed
        unconfirmed_count = 0
        for pattern in self.VALIDATION_PATTERNS['unconfirmed']:
            if re.search(pattern, text_lower):
                unconfirmed_count += 1

        # Determine status
        if validated_count > unconfirmed_count:
            status = 'validated'
            confidence = min(validated_count / 3.0, 1.0)
        elif unconfirmed_count > 0:
            status = 'unconfirmed'
            confidence = min(unconfirmed_count / 2.0, 1.0)
        else:
            status = 'unknown'
            confidence = 0.0

        # Extract validation method
        method = None
        for method_name, pattern in self.VALIDATION_METHOD_PATTERNS.items():
            if re.search(pattern, text_lower):
                method = method_name
                break

        return {
            'status': status,
            'method': method,
            'confidence': confidence
        }

    def detect_false_positive(self, text: str) -> Dict:
        """
        Detect false positive indicators in text

        Returns:
            {
                'is_false_positive': bool,
                'confidence': float (0-1),
                'reason': str
            }
        """
        text_lower = text.lower()

        # Count FP indicators
        fp_matches = []
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            matches = re.findall(pattern, text_lower)
            fp_matches.extend(matches)

        is_fp = len(fp_matches) > 0
        confidence = min(len(fp_matches) / 2.0, 1.0)

        # Extract reason if FP
        reason = None
        if is_fp:
            # Find most specific reason
            if re.search(r'dismissed\s+(?:after\s+)?review', text_lower):
                reason = 'dismissed_after_review'
            elif re.search(r'safe\s+by\s+design', text_lower):
                reason = 'safe_by_design'
            elif re.search(r'closed\s+as\s+(?:invalid|wontfix)', text_lower):
                reason = 'closed_invalid'
            else:
                reason = 'false_positive_mentioned'

        return {
            'is_false_positive': is_fp,
            'confidence': confidence,
            'reason': reason
        }

    def process_commit_metadata(self, commit_url: str) -> Dict:
        """
        Extract enhanced metadata from GitHub commit

        Returns:
            {
                'message': str,
                'diff': str,
                'validation': dict,
                'false_positive': dict,
                'files_changed': list
            }
        """
        if not self.github_client:
            return {
                'message': '',
                'diff': '',
                'validation': {'status': 'unknown', 'method': None, 'confidence': 0.0},
                'false_positive': {'is_false_positive': False, 'confidence': 0.0, 'reason': None},
                'files_changed': []
            }

        try:
            # Parse commit URL
            # Example: https://github.com/owner/repo/commit/sha
            parts = commit_url.rstrip('/').split('/')
            owner = parts[-4]
            repo_name = parts[-3]
            commit_sha = parts[-1]

            # Get repository and commit
            repo = self.github_client.get_repo(f"{owner}/{repo_name}")
            commit = repo.get_commit(commit_sha)

            # Extract commit message
            message = commit.commit.message

            # Extract diff
            diff_parts = []
            for file in commit.files:
                if file.patch:
                    diff_parts.append(f"--- {file.filename}\n{file.patch}")

            diff = '\n\n'.join(diff_parts)

            # Extract validation status from commit message
            validation = self.extract_validation_status(message)

            # Check for false positive indicators
            false_positive = self.detect_false_positive(message)

            # Extract files changed
            files_changed = [
                {
                    'filename': file.filename,
                    'additions': file.additions,
                    'deletions': file.deletions,
                    'status': file.status
                }
                for file in commit.files
            ]

            return {
                'message': message,
                'diff': diff,
                'validation': validation,
                'false_positive': false_positive,
                'files_changed': files_changed
            }

        except Exception as e:
            logger.warning(f"Failed to process commit {commit_url}: {e}")
            return {
                'message': '',
                'diff': '',
                'validation': {'status': 'unknown', 'method': None, 'confidence': 0.0},
                'false_positive': {'is_false_positive': False, 'confidence': 0.0, 'reason': None},
                'files_changed': []
            }

    def extract_issue_discussions(self, commit_url: str, search_window: int = 30) -> List[Dict]:
        """
        Extract related issue discussions for commit

        Args:
            commit_url: GitHub commit URL
            search_window: Days before commit to search for issues

        Returns:
            List of issue discussions with validation/FP indicators
        """
        if not self.github_client:
            return []

        try:
            # Parse commit URL
            parts = commit_url.rstrip('/').split('/')
            owner = parts[-4]
            repo_name = parts[-3]
            commit_sha = parts[-1]

            repo = self.github_client.get_repo(f"{owner}/{repo_name}")

            # Search for issues mentioning this commit
            discussions = []

            # Search in pull requests
            pulls = repo.get_pulls(state='all', sort='updated', direction='desc')

            for pr in list(pulls)[:20]:  # Limit to 20 most recent PRs
                # Check if commit is mentioned
                if commit_sha[:7] in (pr.body or '') or commit_sha[:7] in (pr.title or ''):
                    # Extract validation and FP info
                    combined_text = f"{pr.title} {pr.body}"

                    validation = self.extract_validation_status(combined_text)
                    false_positive = self.detect_false_positive(combined_text)

                    # Get comments
                    comments = []
                    for comment in pr.get_comments():
                        comments.append({
                            'author': comment.user.login,
                            'text': comment.body,
                            'created_at': comment.created_at.isoformat()
                        })

                    discussions.append({
                        'type': 'pull_request',
                        'number': pr.number,
                        'title': pr.title,
                        'body': pr.body,
                        'state': pr.state,
                        'validation': validation,
                        'false_positive': false_positive,
                        'comments': comments
                    })

            return discussions

        except Exception as e:
            logger.warning(f"Failed to extract issues for {commit_url}: {e}")
            return []

    def process_primevul_dataset(
        self,
        data_path: str,
        max_samples: Optional[int] = None,
        use_github_api: bool = True
    ) -> List[Dict]:
        """
        Process PrimeVul dataset with enhanced metadata

        Args:
            data_path: Path to PrimeVul JSONL file
            max_samples: Limit number of samples (for testing)
            use_github_api: Whether to fetch commit/issue data from GitHub

        Returns:
            List of enhanced samples
        """
        logger.info(f"Processing PrimeVul dataset from {data_path}")

        # Load data
        df = pd.read_json(data_path, lines=True)

        if max_samples:
            df = df.head(max_samples)

        logger.info(f"Loaded {len(df)} samples")

        # Process each sample
        processed_samples = []

        for idx, row in df.iterrows():
            if idx % 100 == 0:
                logger.info(f"Processing {idx}/{len(df)}")

            sample = {
                'id': idx,
                'code': row.get('func', ''),
                'label': int(row.get('target', 0)),  # 0=safe, 1=vulnerable
                'cve_id': row.get('cve_id', ''),
                'cwe_id': row.get('cwe_id', ''),
                'project': row.get('project', ''),
                'commit_url': row.get('commit_id', ''),  # Often a URL
                'commit_message': row.get('commit_message', ''),
                'validation_status': 'unknown',  # To be populated
                'validation_method': None,
                'validation_confidence': 0.0,
                'is_false_positive': False,
                'fp_confidence': 0.0,
                'fp_reason': None,
                'commit_diff': '',
                'issue_discussions': []
            }

            # Extract from commit message (always available)
            if sample['commit_message']:
                validation = self.extract_validation_status(sample['commit_message'])
                sample['validation_status'] = validation['status']
                sample['validation_method'] = validation['method']
                sample['validation_confidence'] = validation['confidence']

                fp = self.detect_false_positive(sample['commit_message'])
                sample['is_false_positive'] = fp['is_false_positive']
                sample['fp_confidence'] = fp['confidence']
                sample['fp_reason'] = fp['reason']

            # Fetch from GitHub API (if enabled)
            if use_github_api and sample['commit_url']:
                commit_meta = self.process_commit_metadata(sample['commit_url'])
                sample['commit_diff'] = commit_meta['diff']

                # Update validation if GitHub data is more confident
                if commit_meta['validation']['confidence'] > sample['validation_confidence']:
                    sample['validation_status'] = commit_meta['validation']['status']
                    sample['validation_method'] = commit_meta['validation']['method']
                    sample['validation_confidence'] = commit_meta['validation']['confidence']

                # Update FP if GitHub data is more confident
                if commit_meta['false_positive']['confidence'] > sample['fp_confidence']:
                    sample['is_false_positive'] = commit_meta['false_positive']['is_false_positive']
                    sample['fp_confidence'] = commit_meta['false_positive']['confidence']
                    sample['fp_reason'] = commit_meta['false_positive']['reason']

                # Get issue discussions
                sample['issue_discussions'] = self.extract_issue_discussions(sample['commit_url'])

                # Check issue discussions for validation/FP
                for discussion in sample['issue_discussions']:
                    # Aggregate validation
                    if discussion['validation']['confidence'] > sample['validation_confidence']:
                        sample['validation_status'] = discussion['validation']['status']
                        sample['validation_method'] = discussion['validation']['method']
                        sample['validation_confidence'] = discussion['validation']['confidence']

                    # Aggregate FP
                    if discussion['false_positive']['confidence'] > sample['fp_confidence']:
                        sample['is_false_positive'] = discussion['false_positive']['is_false_positive']
                        sample['fp_confidence'] = discussion['false_positive']['confidence']
                        sample['fp_reason'] = discussion['false_positive']['reason']

            processed_samples.append(sample)

        logger.info(f"✅ Processed {len(processed_samples)} samples")

        # Statistics
        validated = sum(1 for s in processed_samples if s['validation_status'] == 'validated')
        fps = sum(1 for s in processed_samples if s['is_false_positive'])

        logger.info(f"\nStatistics:")
        logger.info(f"  Validated: {validated} ({validated/len(processed_samples)*100:.1f}%)")
        logger.info(f"  False Positives: {fps} ({fps/len(processed_samples)*100:.1f}%)")
        logger.info(f"  Vulnerable: {sum(s['label'] for s in processed_samples)}")
        logger.info(f"  Safe: {len(processed_samples) - sum(s['label'] for s in processed_samples)}")

        return processed_samples

    def save_processed_data(
        self,
        processed_samples: List[Dict],
        output_path: str,
        train_ratio: float = 0.8
    ):
        """
        Save processed data with train/test split

        Args:
            processed_samples: List of processed samples
            output_path: Output JSON file path
            train_ratio: Train/test split ratio
        """
        # Extract labels for stratification
        labels = [s['label'] for s in processed_samples]

        # Split data
        indices = np.arange(len(processed_samples))
        train_idx, test_idx = train_test_split(
            indices,
            test_size=1 - train_ratio,
            random_state=42,
            stratify=labels
        )

        train_data = [processed_samples[i] for i in train_idx]
        test_data = [processed_samples[i] for i in test_idx]

        # Save
        output = {
            'train': train_data,
            'test': test_data,
            'metadata': {
                'total_samples': len(processed_samples),
                'train_samples': len(train_data),
                'test_samples': len(test_data),
                'train_ratio': train_ratio
            }
        }

        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)

        logger.info(f"💾 Saved to {output_path}")
        logger.info(f"  Train: {len(train_data)} samples")
        logger.info(f"  Test: {len(test_data)} samples")


if __name__ == "__main__":
    # Example usage
    import os

    integrator = EnhancedGitHubIntegrator(
        github_token=os.getenv('GITHUB_TOKEN')
    )

    # Process PrimeVul dataset
    processed = integrator.process_primevul_dataset(
        data_path='data/primevul_train.jsonl',
        max_samples=1000,  # Test with subset
        use_github_api=True
    )

    # Save
    integrator.save_processed_data(
        processed,
        output_path='data/enhanced_primevul_processed.json',
        train_ratio=0.8
    )

    print("\n✅ Data processing complete!")
