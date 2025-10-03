#!/usr/bin/env python3
"""
Real-World Repository Scanner
Scans actual GitHub repositories for vulnerabilities
"""

import os
import sys
import subprocess
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from huntr_bounty_hunter import HuntrBountyHunter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealWorldScanner:
    """Scan actual GitHub repositories for vulnerabilities"""

    def __init__(self):
        self.hunter = HuntrBountyHunter()
        self.temp_dir = None

        # High-value targets: AI/ML + Traditional vulnerabilities
        self.targets = [
            # ===== AI/ML TARGETS (PRIMARY - High bounties on huntr.com) =====

            # LLM Frameworks (CRITICAL for huntr.com)
            {
                'url': 'https://github.com/langchain-ai/langchain',
                'name': 'langchain',
                'language': 'python',
                'files': ['libs/langchain/langchain/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'Code execution, PythonREPL vulnerabilities'
            },
            {
                'url': 'https://github.com/run-llama/llama_index',
                'name': 'llama_index',
                'language': 'python',
                'files': ['llama_index/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'Query engines, tool execution'
            },

            # Model Loading (CRITICAL - CVE-2025-1550 style)
            {
                'url': 'https://github.com/keras-team/keras',
                'name': 'keras',
                'language': 'python',
                'files': ['keras/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'Model deserialization RCE'
            },
            {
                'url': 'https://github.com/huggingface/transformers',
                'name': 'transformers',
                'language': 'python',
                'files': ['src/transformers/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'trust_remote_code vulnerabilities'
            },

            # ML Operations
            {
                'url': 'https://github.com/mlflow/mlflow',
                'name': 'mlflow',
                'language': 'python',
                'files': ['mlflow/**/*.py'],
                'priority': 'HIGH',
                'type': 'AI/ML',
                'focus': 'Model loading, artifact deserialization'
            },
            {
                'url': 'https://github.com/scikit-learn/scikit-learn',
                'name': 'scikit-learn',
                'language': 'python',
                'files': ['sklearn/**/*.py'],
                'priority': 'HIGH',
                'type': 'AI/ML',
                'focus': 'Joblib pickle vulnerabilities'
            },

            # ===== TRADITIONAL TARGETS (SECONDARY - Other platforms) =====

            # Python packages
            {
                'url': 'https://github.com/psf/requests',
                'name': 'requests',
                'language': 'python',
                'files': ['requests/**/*.py'],
                'priority': 'HIGH',
                'type': 'Traditional',
                'focus': 'HTTP security, SSRF'
            },
            {
                'url': 'https://github.com/yaml/pyyaml',
                'name': 'pyyaml',
                'language': 'python',
                'files': ['lib/**/*.py'],
                'priority': 'HIGH',
                'type': 'Traditional',
                'focus': 'YAML deserialization'
            },

            # Authentication libraries
            {
                'url': 'https://github.com/jpadilla/pyjwt',
                'name': 'pyjwt',
                'language': 'python',
                'files': ['jwt/**/*.py'],
                'priority': 'HIGH',
                'type': 'Traditional',
                'focus': 'JWT algorithm confusion'
            },

            # JavaScript libraries
            {
                'url': 'https://github.com/lodash/lodash',
                'name': 'lodash',
                'language': 'javascript',
                'files': ['*.js'],
                'priority': 'MEDIUM',
                'type': 'Traditional',
                'focus': 'Prototype pollution'
            },
            {
                'url': 'https://github.com/auth0/node-jsonwebtoken',
                'name': 'jsonwebtoken',
                'language': 'javascript',
                'files': ['**/*.js'],
                'priority': 'MEDIUM',
                'type': 'Traditional',
                'focus': 'JWT vulnerabilities'
            },
            {
                'url': 'https://github.com/pugjs/pug',
                'name': 'pug',
                'language': 'javascript',
                'files': ['lib/**/*.js'],
                'priority': 'MEDIUM',
                'type': 'Traditional',
                'focus': 'Template injection'
            }
        ]

    def clone_repository(self, repo: Dict[str, str]) -> Optional[str]:
        """Clone repository to temporary directory"""
        try:
            # Create temp directory
            self.temp_dir = tempfile.mkdtemp(prefix='huntr_scan_')
            repo_path = os.path.join(self.temp_dir, repo['name'])

            logger.info(f"📥 Cloning {repo['name']} to {repo_path}")

            # Clone with shallow depth for speed
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo['url'], repo_path],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                logger.info(f"✅ Successfully cloned {repo['name']}")
                return repo_path
            else:
                logger.error(f"❌ Failed to clone {repo['name']}: {result.stderr}")
                return None

        except Exception as e:
            logger.error(f"❌ Error cloning repository: {e}")
            return None

    def scan_files(self, repo_path: str, file_patterns: List[str]) -> List[Dict[str, Any]]:
        """Scan files in repository matching patterns"""
        code_samples = []

        for pattern in file_patterns:
            # Find files matching pattern
            if '**' in pattern:
                # Recursive glob
                files = list(Path(repo_path).rglob(pattern.replace('**/', '')))
            else:
                files = list(Path(repo_path).glob(pattern))

            logger.info(f"🔍 Found {len(files)} files matching {pattern}")

            for file_path in files[:50]:  # Limit to 50 files per pattern
                try:
                    # Skip large files (>500KB)
                    if file_path.stat().st_size > 500000:
                        continue

                    # Read file
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()

                    # Skip very short files
                    if len(code) < 100:
                        continue

                    code_samples.append({
                        'file': str(file_path.relative_to(repo_path)),
                        'code': code,
                        'location': str(file_path.relative_to(repo_path))
                    })

                except Exception as e:
                    logger.debug(f"Skipping {file_path}: {e}")
                    continue

        return code_samples

    def scan_repository(self, repo: Dict[str, str]) -> Dict[str, Any]:
        """Scan a single repository"""
        logger.info(f"\n{'='*70}")
        logger.info(f"🎯 Scanning: {repo['name']} ({repo['priority']} priority)")
        logger.info(f"📦 Type: {repo.get('type', 'General')}")
        logger.info(f"🔍 Focus: {repo.get('focus', 'General vulnerabilities')}")
        logger.info(f"{'='*70}")

        # Clone repository
        repo_path = self.clone_repository(repo)
        if not repo_path:
            return {
                'repository': repo['name'],
                'status': 'failed',
                'error': 'Clone failed'
            }

        try:
            # Scan files
            code_samples = self.scan_files(repo_path, repo['files'])
            logger.info(f"📊 Analyzing {len(code_samples)} code files")

            # Analyze each file
            all_findings = []
            for sample in code_samples:
                result = self.hunter.analyze_single_code(
                    sample['code'],
                    component=f"{repo['name']}/{sample['location']}"
                )

                if result.get('verified'):
                    all_findings.extend(result['verified'])

            return {
                'repository': repo['name'],
                'status': 'completed',
                'files_scanned': len(code_samples),
                'vulnerabilities_found': len(all_findings),
                'findings': all_findings
            }

        finally:
            # Cleanup
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f"🧹 Cleaned up temp directory")

    def scan_all_targets(self, max_repos: int = 12) -> Dict[str, Any]:
        """Scan multiple repositories"""
        logger.info(f"🚀 Starting Real-World Repository Scan")
        logger.info(f"🎯 Targets: {min(max_repos, len(self.targets))} repositories")

        results = []
        total_vulns = 0

        for i, repo in enumerate(self.targets[:max_repos], 1):
            logger.info(f"\n[{i}/{max_repos}] Processing {repo['name']}...")

            result = self.scan_repository(repo)
            results.append(result)

            if result['status'] == 'completed':
                total_vulns += result['vulnerabilities_found']
                logger.info(f"✅ {repo['name']}: {result['vulnerabilities_found']} verified vulnerabilities")

        summary = {
            'total_repositories': len(results),
            'total_vulnerabilities': total_vulns,
            'results': results
        }

        logger.info(f"\n{'='*70}")
        logger.info(f"🎉 Real-World Scan Complete!")
        logger.info(f"📊 Repositories Scanned: {len(results)}")
        logger.info(f"✅ Verified Vulnerabilities: {total_vulns}")
        logger.info(f"{'='*70}")

        return summary


def main():
    """Run real-world scanner"""
    print("🦾 REAL-WORLD VULNERABILITY SCANNER")
    print("="*70)
    print("Scanning actual GitHub repositories for vulnerabilities")
    print("="*70)

    scanner = RealWorldScanner()

    # Scan all 12 repositories (6 AI/ML + 6 Traditional)
    summary = scanner.scan_all_targets(max_repos=12)

    # Display results
    if summary['total_vulnerabilities'] > 0:
        print(f"\n🎯 VULNERABILITIES FOUND!")
        print(f"Ready for huntr.dev submission")
    else:
        print(f"\n✅ No high-confidence vulnerabilities found")
        print(f"Zero-FP engine is working correctly")

    return summary


if __name__ == "__main__":
    main()
