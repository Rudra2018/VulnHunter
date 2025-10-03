#!/usr/bin/env python3
"""
AI/ML Model Library Vulnerability Scanner
Specialized scanner for ML frameworks and model loading vulnerabilities
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

class MLModelScanner:
    """Scan AI/ML libraries and frameworks for vulnerabilities"""

    def __init__(self):
        self.hunter = HuntrBountyHunter()
        self.temp_dir = None

        # High-value AI/ML targets based on huntr.com focus
        self.ml_targets = [
            # Deep Learning Frameworks
            {
                'url': 'https://github.com/keras-team/keras',
                'name': 'keras',
                'language': 'python',
                'files': ['keras/**/*.py'],
                'priority': 'CRITICAL',
                'focus': 'Model deserialization, CVE-2025-1550 similar patterns'
            },
            {
                'url': 'https://github.com/pytorch/pytorch',
                'name': 'pytorch',
                'language': 'python',
                'files': ['torch/**/*.py'],
                'priority': 'CRITICAL',
                'focus': 'Pickle deserialization, torch.load vulnerabilities'
            },
            {
                'url': 'https://github.com/tensorflow/tensorflow',
                'name': 'tensorflow',
                'language': 'python',
                'files': ['tensorflow/**/*.py'],
                'priority': 'CRITICAL',
                'focus': 'SavedModel loading, custom ops'
            },
            # Model Serialization
            {
                'url': 'https://github.com/onnx/onnx',
                'name': 'onnx',
                'language': 'python',
                'files': ['onnx/**/*.py'],
                'priority': 'HIGH',
                'focus': 'ONNX model parsing, operator exploits'
            },
            # HuggingFace Ecosystem
            {
                'url': 'https://github.com/huggingface/transformers',
                'name': 'transformers',
                'language': 'python',
                'files': ['src/transformers/**/*.py'],
                'priority': 'CRITICAL',
                'focus': 'trust_remote_code vulnerabilities, model hub loading'
            },
            {
                'url': 'https://github.com/huggingface/diffusers',
                'name': 'diffusers',
                'language': 'python',
                'files': ['src/diffusers/**/*.py'],
                'priority': 'HIGH',
                'focus': 'Model loading, pipeline vulnerabilities'
            },
            # ML Operations
            {
                'url': 'https://github.com/mlflow/mlflow',
                'name': 'mlflow',
                'language': 'python',
                'files': ['mlflow/**/*.py'],
                'priority': 'HIGH',
                'focus': 'Model loading, artifact deserialization'
            },
            # LLM Frameworks
            {
                'url': 'https://github.com/langchain-ai/langchain',
                'name': 'langchain',
                'language': 'python',
                'files': ['libs/langchain/langchain/**/*.py'],
                'priority': 'CRITICAL',
                'focus': 'Code execution tools, agent vulnerabilities'
            },
            {
                'url': 'https://github.com/run-llama/llama_index',
                'name': 'llama_index',
                'language': 'python',
                'files': ['llama_index/**/*.py'],
                'priority': 'HIGH',
                'focus': 'Query engines, tool execution'
            },
            # Traditional ML
            {
                'url': 'https://github.com/scikit-learn/scikit-learn',
                'name': 'scikit-learn',
                'language': 'python',
                'files': ['sklearn/**/*.py'],
                'priority': 'HIGH',
                'focus': 'Joblib pickle vulnerabilities'
            },
            # Model Formats
            {
                'url': 'https://github.com/microsoft/onnxruntime',
                'name': 'onnxruntime',
                'language': 'python',
                'files': ['onnxruntime/python/**/*.py'],
                'priority': 'HIGH',
                'focus': 'Runtime inference vulnerabilities'
            },
            # Computer Vision
            {
                'url': 'https://github.com/open-mmlab/mmdetection',
                'name': 'mmdetection',
                'language': 'python',
                'files': ['mmdet/**/*.py'],
                'priority': 'MEDIUM',
                'focus': 'Model loading, config parsing'
            }
        ]

    def clone_repository(self, repo: Dict[str, str]) -> Optional[str]:
        """Clone ML repository to temporary directory"""
        try:
            self.temp_dir = tempfile.mkdtemp(prefix='ml_scan_')
            repo_path = os.path.join(self.temp_dir, repo['name'])

            logger.info(f"📥 Cloning {repo['name']} (Focus: {repo['focus']})")

            # Shallow clone for speed
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo['url'], repo_path],
                capture_output=True,
                text=True,
                timeout=600
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
        """Scan ML library files matching patterns"""
        code_samples = []

        for pattern in file_patterns:
            # Find files matching pattern
            if '**' in pattern:
                files = list(Path(repo_path).rglob(pattern.replace('**/', '')))
            else:
                files = list(Path(repo_path).glob(pattern))

            logger.info(f"🔍 Found {len(files)} files matching {pattern}")

            # Focus on key vulnerability areas
            priority_keywords = [
                'load', 'deserialize', 'pickle', 'model', 'save',
                'checkpoint', 'config', 'yaml', 'trust_remote',
                'execute', 'eval', 'compile', 'import'
            ]

            prioritized_files = []
            for file_path in files:
                try:
                    # Quick scan for priority keywords
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content_preview = f.read(5000)  # First 5KB

                    if any(keyword in content_preview.lower() for keyword in priority_keywords):
                        prioritized_files.append(file_path)
                except:
                    continue

            logger.info(f"🎯 Prioritized {len(prioritized_files)} high-value files")

            # Analyze prioritized files
            for file_path in prioritized_files[:100]:  # Limit to 100 per pattern
                try:
                    # Skip large files
                    if file_path.stat().st_size > 1000000:  # 1MB limit
                        continue

                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()

                    # Skip test files (but less aggressively than before)
                    if len(code) < 200:
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

    def scan_ml_repository(self, repo: Dict[str, str]) -> Dict[str, Any]:
        """Scan a single ML repository"""
        logger.info(f"\n{'='*80}")
        logger.info(f"🤖 ML SCAN: {repo['name']} ({repo['priority']} priority)")
        logger.info(f"🎯 Focus Area: {repo['focus']}")
        logger.info(f"{'='*80}")

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
            logger.info(f"📊 Analyzing {len(code_samples)} ML code files")

            # Analyze each file
            all_findings = []
            high_confidence_findings = []

            for i, sample in enumerate(code_samples, 1):
                if i % 10 == 0:
                    logger.info(f"  Progress: {i}/{len(code_samples)} files analyzed...")

                result = self.hunter.analyze_single_code(
                    sample['code'],
                    component=f"{repo['name']}/{sample['location']}"
                )

                if result.get('verified'):
                    findings = result['verified']
                    all_findings.extend(findings)

                    # Filter for ML-specific vulnerabilities
                    ml_specific = [
                        f for f in findings
                        if any(keyword in f.get('title', '').lower()
                               for keyword in ['keras', 'pytorch', 'tensorflow',
                                             'pickle', 'model', 'deserialize',
                                             'langchain', 'hugging', 'ml'])
                    ]
                    high_confidence_findings.extend(ml_specific)

            result_summary = {
                'repository': repo['name'],
                'status': 'completed',
                'focus_area': repo['focus'],
                'files_scanned': len(code_samples),
                'vulnerabilities_found': len(all_findings),
                'ml_specific_vulns': len(high_confidence_findings),
                'findings': all_findings,
                'high_confidence_ml_findings': high_confidence_findings
            }

            if high_confidence_findings:
                logger.info(f"🎉 {repo['name']}: {len(high_confidence_findings)} ML-SPECIFIC vulnerabilities!")

            return result_summary

        finally:
            # Cleanup
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f"🧹 Cleaned up temp directory")

    def scan_ml_targets(self, max_repos: int = 12) -> Dict[str, Any]:
        """Scan multiple ML repositories"""
        logger.info(f"🤖 Starting AI/ML Model Library Vulnerability Scan")
        logger.info(f"🎯 Targets: {min(max_repos, len(self.ml_targets))} ML repositories")
        logger.info(f"🔍 Focus: Model deserialization, pickle exploits, code execution\n")

        results = []
        total_vulns = 0
        total_ml_specific = 0

        for i, repo in enumerate(self.ml_targets[:max_repos], 1):
            logger.info(f"\n[{i}/{max_repos}] Processing {repo['name']}...")

            result = self.scan_ml_repository(repo)
            results.append(result)

            if result['status'] == 'completed':
                total_vulns += result['vulnerabilities_found']
                total_ml_specific += result['ml_specific_vulns']

                if result['ml_specific_vulns'] > 0:
                    logger.info(f"✅ {repo['name']}: {result['ml_specific_vulns']} ML-specific vulnerabilities")
                else:
                    logger.info(f"✅ {repo['name']}: {result['vulnerabilities_found']} total detections")

        summary = {
            'scan_type': 'AI/ML Model Libraries',
            'total_repositories': len(results),
            'total_vulnerabilities': total_vulns,
            'ml_specific_vulnerabilities': total_ml_specific,
            'results': results
        }

        logger.info(f"\n{'='*80}")
        logger.info(f"🎉 AI/ML Vulnerability Scan Complete!")
        logger.info(f"📊 Repositories Scanned: {len(results)}")
        logger.info(f"✅ Total Vulnerabilities: {total_vulns}")
        logger.info(f"🤖 ML-Specific Vulnerabilities: {total_ml_specific}")
        logger.info(f"{'='*80}")

        return summary


def main():
    """Run ML model vulnerability scanner"""
    print("🤖 AI/ML MODEL LIBRARY VULNERABILITY SCANNER")
    print("="*80)
    print("Scanning ML frameworks for model deserialization and code execution vulns")
    print("="*80)

    scanner = MLModelScanner()

    # Scan first 5 critical ML repositories
    summary = scanner.scan_ml_targets(max_repos=5)

    # Display results
    if summary['ml_specific_vulnerabilities'] > 0:
        print(f"\n🎯 ML-SPECIFIC VULNERABILITIES FOUND!")
        print(f"Ready for huntr.com submission")
        print(f"\nHigh-value targets detected:")
        for result in summary['results']:
            if result.get('ml_specific_vulns', 0) > 0:
                print(f"  • {result['repository']}: {result['ml_specific_vulns']} ML vulns")
    elif summary['total_vulnerabilities'] > 0:
        print(f"\n✅ {summary['total_vulnerabilities']} vulnerabilities found")
        print(f"Review findings for ML-specific patterns")
    else:
        print(f"\n✅ No high-confidence vulnerabilities found")
        print(f"Zero-FP engine is working correctly")

    return summary


if __name__ == "__main__":
    main()
