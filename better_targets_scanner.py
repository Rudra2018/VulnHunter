#!/usr/bin/env python3
"""
Better-Targeted AI/ML Scanner
Focuses on newer, less-audited libraries with higher vulnerability potential
"""

import os
import sys
import subprocess
import tempfile
import shutil
import logging
import glob
from pathlib import Path
from typing import Dict, List, Any, Optional
from huntr_bounty_hunter import HuntrBountyHunter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BetterTargetsScanner:
    """Scan better-targeted AI/ML repositories for higher success rate"""

    def __init__(self):
        self.hunter = HuntrBountyHunter()
        self.temp_dir = None

        # Better targets: Newer, smaller, less-audited AI/ML libraries
        self.targets = [
            # ===== LLM INFRASTRUCTURE (High-value, newer) =====
            {
                'url': 'https://github.com/BerriAI/litellm',
                'name': 'litellm',
                'language': 'python',
                'files': ['litellm/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'LLM proxy, routing, API security',
                'bounty_estimate': '$1,500-$2,500',
                'why': 'Newer project, complex routing, API layer vulnerabilities'
            },
            {
                'url': 'https://github.com/vllm-project/vllm',
                'name': 'vllm',
                'language': 'python',
                'files': ['vllm/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'Fast inference, model loading, C++/Python interface',
                'bounty_estimate': '$1,000-$2,000',
                'why': 'Newer, C++ bindings, performance-focused = security tradeoffs'
            },
            {
                'url': 'https://github.com/guidance-ai/guidance',
                'name': 'guidance',
                'language': 'python',
                'files': ['guidance/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'Constrained generation, eval() usage, code execution',
                'bounty_estimate': '$1,000-$2,000',
                'why': 'Newer, likely uses eval/exec for code generation'
            },

            # ===== LANGCHAIN ECOSYSTEM (Active bug bounty) =====
            {
                'url': 'https://github.com/langchain-ai/langserve',
                'name': 'langserve',
                'language': 'python',
                'files': ['langserve/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'LangChain deployment, API layer, serialization',
                'bounty_estimate': '$1,500-$2,500',
                'why': 'Newer, API security, deserialization vulnerabilities'
            },
            {
                'url': 'https://github.com/langchain-ai/langgraph',
                'name': 'langgraph',
                'language': 'python',
                'files': ['langgraph/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'Graph-based agents, state management, persistence',
                'bounty_estimate': '$1,500-$2,500',
                'why': 'Newer, complex state management, agent vulnerabilities'
            },

            # ===== AGENT FRAMEWORKS (High attack surface) =====
            {
                'url': 'https://github.com/Significant-Gravitas/AutoGPT',
                'name': 'autogpt',
                'language': 'python',
                'files': ['autogpt/**/*.py', 'forge/**/*.py'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'Agent framework, plugin system, command execution',
                'bounty_estimate': '$1,500-$2,500',
                'why': 'Plugin system = high attack surface, command execution'
            },
            {
                'url': 'https://github.com/reworkd/AgentGPT',
                'name': 'agentgpt',
                'language': 'python',
                'files': ['platform/**/*.py', 'next/**/*.ts'],
                'priority': 'HIGH',
                'type': 'AI/ML',
                'focus': 'Web-based agents, API integration',
                'bounty_estimate': '$1,000-$2,000',
                'why': 'Newer, web interface, API vulnerabilities'
            },

            # ===== VECTOR DATABASES (AI infrastructure) =====
            {
                'url': 'https://github.com/chroma-core/chroma',
                'name': 'chroma',
                'language': 'python',
                'files': ['chromadb/**/*.py'],
                'priority': 'HIGH',
                'type': 'AI/ML',
                'focus': 'Vector DB, API layer, deserialization',
                'bounty_estimate': '$1,000-$2,000',
                'why': 'Newer, database = injection risks, API layer'
            },
            {
                'url': 'https://github.com/weaviate/weaviate',
                'name': 'weaviate',
                'language': 'go',
                'files': ['**/*.go'],
                'priority': 'HIGH',
                'type': 'AI/ML',
                'focus': 'Vector DB, GraphQL API, query injection',
                'bounty_estimate': '$1,000-$2,000',
                'why': 'GraphQL = injection risks, newer vector DB'
            },

            # ===== MODEL TOOLS (Newer format handlers) =====
            {
                'url': 'https://github.com/ggerganov/llama.cpp',
                'name': 'llama.cpp',
                'language': 'cpp',
                'files': ['**/*.cpp', '**/*.h'],
                'priority': 'CRITICAL',
                'type': 'AI/ML',
                'focus': 'C++ model loading, buffer overflows, memory safety',
                'bounty_estimate': '$2,000-$4,000',
                'why': 'C++ = memory vulnerabilities, widely used'
            },
        ]

    def scan_repository(self, repo: Dict[str, str]) -> Dict[str, Any]:
        """Scan a single repository"""
        logger.info(f"\n{'='*70}")
        logger.info(f"🎯 Scanning: {repo['name']} ({repo['priority']} priority)")
        logger.info(f"📦 Type: {repo['type']}")
        logger.info(f"🔍 Focus: {repo['focus']}")
        logger.info(f"💰 Estimated Bounty: {repo['bounty_estimate']}")
        logger.info(f"{'='*70}")

        # Clone repository
        repo_path = os.path.join(self.temp_dir, repo['name'])
        try:
            logger.info(f"📥 Cloning {repo['name']} to {repo_path}")
            subprocess.run(
                ['git', 'clone', '--depth=1', repo['url'], repo_path],
                check=True,
                capture_output=True,
                timeout=180
            )
            logger.info(f"✅ Successfully cloned {repo['name']}")
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Timeout cloning {repo['name']}")
            return {'error': 'Clone timeout'}
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to clone {repo['name']}: {e}")
            return {'error': str(e)}

        # Find files matching patterns
        all_files = []
        for pattern in repo['files']:
            file_pattern = os.path.join(repo_path, pattern)
            matched_files = glob.glob(file_pattern, recursive=True)
            all_files.extend(matched_files)

        # Filter to actual files (not directories)
        code_files = [f for f in all_files if os.path.isfile(f)]
        logger.info(f"🔍 Found {len(code_files)} files matching {repo['files']}")

        if len(code_files) == 0:
            logger.warning(f"⚠️  No files found for {repo['name']}")
            return {'files_found': 0, 'detections': 0}

        # Prioritize files with vulnerability keywords
        priority_keywords = [
            'load', 'deserialize', 'pickle', 'model', 'save',
            'execute', 'eval', 'exec', 'compile', 'import',
            'plugin', 'tool', 'agent', 'command', 'shell',
            'api', 'endpoint', 'route', 'query', 'search'
        ]

        def file_priority(filepath):
            filename = os.path.basename(filepath).lower()
            return sum(1 for kw in priority_keywords if kw in filename)

        code_files.sort(key=file_priority, reverse=True)

        # Limit files to analyze
        max_files = min(30, len(code_files))
        logger.info(f"📊 Analyzing top {max_files} priority files")

        # Scan files
        verified_vulns = []
        total_detections = 0

        for i, file_path in enumerate(code_files[:max_files], 1):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()

                # Analyze with enhanced component info
                relative_path = os.path.relpath(file_path, repo_path)
                component = f"{repo['name']}/{relative_path}"

                logger.info(f"  [{i}/{max_files}] Analyzing: {relative_path}")

                result = self.hunter.analyze_single_code(code, component=component)

                if result.get('vulnerabilities_found'):
                    total_detections += len(result.get('detections', []))
                    verified = result.get('verified', [])
                    if verified:
                        for vuln in verified:
                            vuln['file'] = relative_path
                            vuln['repository'] = repo['name']
                            verified_vulns.append(vuln)
                            logger.info(f"    🚨 VERIFIED: {vuln['detection'].pattern_matched}")

            except Exception as e:
                logger.debug(f"    ⚠️  Error analyzing {file_path}: {e}")
                continue

        # Cleanup
        logger.info("🧹 Cleaned up temp directory")
        shutil.rmtree(repo_path, ignore_errors=True)

        logger.info(f"✅ {repo['name']}: {len(verified_vulns)} verified vulnerabilities")

        return {
            'repository': repo['name'],
            'files_analyzed': max_files,
            'total_detections': total_detections,
            'verified_vulnerabilities': len(verified_vulns),
            'vulnerabilities': verified_vulns,
            'bounty_estimate': repo['bounty_estimate']
        }

    def scan_all_targets(self, max_repos: int = 10):
        """Scan all target repositories"""
        logger.info("\n" + "="*70)
        logger.info("🦾 BETTER-TARGETED AI/ML VULNERABILITY SCANNER")
        logger.info("="*70)
        logger.info(f"Scanning {min(max_repos, len(self.targets))} repositories with higher success potential")
        logger.info("="*70 + "\n")

        # Create temp directory
        self.temp_dir = tempfile.mkdtemp(prefix='better_targets_scan_')

        results = []
        total_verified = 0

        for i, repo in enumerate(self.targets[:max_repos], 1):
            logger.info(f"\n[{i}/{min(max_repos, len(self.targets))}] Processing {repo['name']}...")

            result = self.scan_repository(repo)
            results.append(result)

            if not result.get('error'):
                total_verified += result.get('verified_vulnerabilities', 0)

        # Cleanup main temp directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)

        # Summary
        logger.info("\n" + "="*70)
        logger.info("🎉 Better-Targeted Scan Complete!")
        logger.info(f"📊 Repositories Scanned: {len(results)}")
        logger.info(f"✅ Verified Vulnerabilities: {total_verified}")
        logger.info("="*70)

        return {
            'scanned': len(results),
            'verified_total': total_verified,
            'results': results
        }


def main():
    """Main entry point"""
    logger.info("Starting Better-Targeted AI/ML Scanner...")

    scanner = BetterTargetsScanner()
    summary = scanner.scan_all_targets(max_repos=10)

    # Display results
    print("\n" + "="*70)
    print("📋 SCAN SUMMARY")
    print("="*70)

    for result in summary['results']:
        if result.get('error'):
            print(f"\n❌ {result.get('repository', 'Unknown')}: {result['error']}")
        else:
            print(f"\n✅ {result['repository']}:")
            print(f"   Files analyzed: {result['files_analyzed']}")
            print(f"   Verified vulnerabilities: {result['verified_vulnerabilities']}")
            print(f"   Estimated bounty: {result['bounty_estimate']}")

            if result['verified_vulnerabilities'] > 0:
                print(f"   🚨 HIGH-VALUE TARGET - Manual review recommended")

    print("\n" + "="*70)
    print(f"🎯 Total Verified Vulnerabilities: {summary['verified_total']}")
    print("="*70)

    if summary['verified_total'] > 0:
        print("\n✅ High-confidence vulnerabilities found!")
        print("📝 Next step: Manual review and PoC development")
    else:
        print("\n⚠️  No auto-verified vulnerabilities")
        print("💡 This is expected - manual review of detections needed")

if __name__ == "__main__":
    main()
