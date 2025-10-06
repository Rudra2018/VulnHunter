#!/usr/bin/env python3
"""
New Relic Agent Security Scanner
Focuses on bug bounty scope: default configuration, data transmission, agent integration security
"""

import os
import re
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict
import json

@dataclass
class AgentVulnerability:
    file: str
    line_number: int
    line_content: str
    category: str
    severity: str
    cwe: str
    description: str
    context: List[str]
    confidence: float
    agent_specific: bool
    default_config_impact: bool

class NewRelicAgentScanner:
    """
    Security scanner specialized for New Relic agents
    """

    def __init__(self, repo_path: str, agent_name: str):
        self.repo_path = Path(repo_path)
        self.agent_name = agent_name
        self.vulnerabilities: List[AgentVulnerability] = []
        self.stats = defaultdict(int)

        # New Relic agent-specific vulnerability patterns
        self.agent_patterns = {
            # Hardcoded credentials/API keys (CRITICAL for agents)
            'hardcoded_credentials': {
                'patterns': [
                    r'license_key\s*=\s*["\'][a-zA-Z0-9]{40}["\']',
                    r'api_key\s*=\s*["\'][^"\']{20,}["\']',
                    r'apiKey:\s*["\'][^"\']{20,}["\']',
                    r'NEWRELIC.*KEY.*=.*["\'][^"\']{20,}["\']',
                    r'password\s*=\s*["\'][^"\']{8,}["\']',
                ],
                'severity': 'CRITICAL',
                'cwe': 'CWE-798',
                'category': 'Hardcoded Credentials',
                'description': 'Hardcoded API key or credential in agent code'
            },

            # Insecure data transmission
            'insecure_transmission': {
                'patterns': [
                    r'http://.*newrelic',
                    r'verify\s*[:=]\s*[Ff]alse',
                    r'ssl.*verify.*false',
                    r'CERT.*NONE',
                    r'disable.*ssl',
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-319',
                'category': 'Insecure Data Transmission',
                'description': 'Insecure or disabled TLS/SSL verification'
            },

            # Command injection in telemetry
            'command_injection': {
                'patterns': [
                    r'exec\s*\(',
                    r'eval\s*\(',
                    r'subprocess\.call\(',
                    r'os\.system\(',
                    r'child_process\.exec\(',
                    r'Runtime\.getRuntime\(\)\.exec',
                ],
                'severity': 'CRITICAL',
                'cwe': 'CWE-78',
                'category': 'Command Injection',
                'description': 'Potential command injection in agent code'
            },

            # SQL injection in agent queries
            'sql_injection': {
                'patterns': [
                    r'query.*\+.*',
                    r'execute\(.*%.*\)',
                    r'SELECT.*\+',
                    r'INSERT.*\+',
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-89',
                'category': 'SQL Injection',
                'description': 'SQL injection vulnerability in agent database queries'
            },

            # Path traversal in log/config files
            'path_traversal': {
                'patterns': [
                    r'open\([^)]*\.\.\/',
                    r'readFile.*\.\.\/',
                    r'File\([^)]*\.\.\/',
                    r'log.*path.*\+',
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-22',
                'category': 'Path Traversal',
                'description': 'Path traversal vulnerability in file operations'
            },

            # Information disclosure
            'information_disclosure': {
                'patterns': [
                    r'console\.log\(.*password',
                    r'print.*api.*key',
                    r'logger.*secret',
                    r'debug.*credential',
                ],
                'severity': 'MEDIUM',
                'cwe': 'CWE-200',
                'category': 'Information Disclosure',
                'description': 'Sensitive information logged or exposed'
            },

            # Weak cryptography
            'weak_crypto': {
                'patterns': [
                    r'\bMD5\s*\(',
                    r'\bSHA1\s*\(',
                    r'\.md5\s*\(',
                    r'hashlib\.md5',
                    r'crypto\.createHash\(["\']md5',
                ],
                'severity': 'MEDIUM',
                'cwe': 'CWE-327',
                'category': 'Weak Cryptography',
                'description': 'Weak cryptographic algorithm detected'
            },

            # Insecure deserialization
            'insecure_deserialize': {
                'patterns': [
                    r'pickle\.loads?\(',
                    r'yaml\.load\(',
                    r'JSON\.parse.*user',
                    r'unserialize\(',
                ],
                'severity': 'CRITICAL',
                'cwe': 'CWE-502',
                'category': 'Insecure Deserialization',
                'description': 'Unsafe deserialization of untrusted data'
            },

            # XML external entity (XXE)
            'xxe_vulnerability': {
                'patterns': [
                    r'XMLParser.*external',
                    r'EntityResolver',
                    r'FEATURE_SECURE_PROCESSING.*false',
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-611',
                'category': 'XXE Vulnerability',
                'description': 'XML external entity vulnerability'
            },

            # Race conditions
            'race_condition': {
                'patterns': [
                    r'threading\.Thread.*shared',
                    r'asyncio.*shared.*state',
                ],
                'severity': 'MEDIUM',
                'cwe': 'CWE-362',
                'category': 'Race Condition',
                'description': 'Potential race condition in concurrent code'
            },
        }

        # Test/example file patterns (exclude from analysis)
        self.exclude_patterns = [
            r'/tests?/',
            r'/test/',
            r'_test\.(py|js|go)$',
            r'/examples?/',
            r'/sample',
            r'\.test\.',
            r'\.spec\.',
            r'/fixtures/',
            r'/mocks?/',
        ]

    def is_excluded_file(self, file_path: str) -> bool:
        """Check if file should be excluded from analysis"""
        for pattern in self.exclude_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def get_context(self, file_path: Path, line_num: int, context_size: int = 5) -> List[str]:
        """Get surrounding lines for context"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                start = max(0, line_num - context_size - 1)
                end = min(len(lines), line_num + context_size)
                return [line.rstrip() for line in lines[start:end]]
        except Exception:
            return []

    def is_default_config_impact(self, category: str, line: str, file_path: str) -> bool:
        """
        Determine if vulnerability affects default configuration
        Bug bounty scope: rewards based on default settings
        """
        # Check if in config/default files
        if any(pattern in file_path.lower() for pattern in [
            'config', 'default', 'settings', '.env.example'
        ]):
            return True

        # Hardcoded credentials are always default impact
        if category == 'Hardcoded Credentials':
            return True

        # SSL/TLS disabled by default
        if category == 'Insecure Data Transmission':
            if any(keyword in line.lower() for keyword in [
                'verify = false', 'ssl_verify: false', 'verifySsl: false'
            ]):
                return True

        return False

    def calculate_confidence(self, category: str, line: str, context: List[str]) -> float:
        """Calculate confidence score for finding"""
        base_confidence = 0.6

        # Boost for agent-critical categories
        if category in ['Hardcoded Credentials', 'Insecure Data Transmission', 'Command Injection']:
            base_confidence = 0.8

        # Boost for exact pattern matches
        if re.search(r'\w+\s*[:=]\s*["\']', line):
            base_confidence += 0.1

        # Reduce for comments
        if re.match(r'\s*(//|#|/\*|\*)', line.strip()):
            base_confidence *= 0.2

        # Reduce for example/test-like content
        if any(keyword in line.lower() for keyword in ['example', 'sample', 'test']):
            base_confidence *= 0.5

        return min(1.0, base_confidence)

    def scan_file(self, file_path: Path) -> None:
        """Scan a single file for vulnerabilities"""
        relative_path = str(file_path.relative_to(self.repo_path))

        # Skip excluded files
        if self.is_excluded_file(relative_path):
            self.stats['excluded_files'] += 1
            return

        # Only scan relevant file types
        valid_extensions = ['.py', '.js', '.go', '.java', '.rb', '.php', '.yml', '.yaml', '.json', '.conf']
        if not any(file_path.suffix == ext for ext in valid_extensions):
            return

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            self.stats['files_scanned'] += 1

            for line_num, line in enumerate(lines, 1):
                self.stats['lines_scanned'] += 1

                # Check each vulnerability pattern
                for vuln_type, vuln_config in self.agent_patterns.items():
                    for pattern in vuln_config['patterns']:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Get context
                            context = self.get_context(file_path, line_num)

                            # Calculate confidence
                            confidence = self.calculate_confidence(
                                vuln_config['category'], line, context
                            )

                            # Only report medium+ confidence
                            if confidence < 0.5:
                                self.stats['low_confidence_excluded'] += 1
                                continue

                            # Check default config impact
                            default_impact = self.is_default_config_impact(
                                vuln_config['category'], line, relative_path
                            )

                            # Create vulnerability record
                            vuln = AgentVulnerability(
                                file=relative_path,
                                line_number=line_num,
                                line_content=line.strip(),
                                category=vuln_config['category'],
                                severity=vuln_config['severity'],
                                cwe=vuln_config['cwe'],
                                description=vuln_config['description'],
                                context=context,
                                confidence=confidence,
                                agent_specific=True,
                                default_config_impact=default_impact
                            )

                            self.vulnerabilities.append(vuln)
                            self.stats['vulnerabilities_found'] += 1

        except Exception as e:
            self.stats['errors'] += 1

    def scan_all(self) -> None:
        """Scan entire agent repository"""
        print(f"\n{'='*80}")
        print(f"New Relic {self.agent_name} Agent Security Scanner")
        print(f"{'='*80}")
        print(f"Scanning: {self.repo_path}")

        # Find all relevant files
        for file_path in self.repo_path.rglob('*'):
            if file_path.is_file():
                self.scan_file(file_path)

        print(f"\n{'='*80}")
        print("Scan Complete")
        print(f"{'='*80}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"Files scanned: {self.stats['files_scanned']}")
        print(f"Lines scanned: {self.stats['lines_scanned']:,}")
        print(f"Files excluded: {self.stats['excluded_files']}")

    def generate_report(self, output_file: str) -> None:
        """Generate JSON report"""
        # Group by category
        by_category = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_category[vuln.category].append(asdict(vuln))

        # Separate default config impact
        default_config_vulns = [v for v in self.vulnerabilities if v.default_config_impact]

        report = {
            'scan_date': datetime.now().isoformat(),
            'agent_name': self.agent_name,
            'repository': str(self.repo_path),
            'total_vulnerabilities': len(self.vulnerabilities),
            'default_config_vulnerabilities': len(default_config_vulns),
            'statistics': dict(self.stats),
            'by_category': dict(by_category),
            'by_severity': {
                'CRITICAL': len([v for v in self.vulnerabilities if v.severity == 'CRITICAL']),
                'HIGH': len([v for v in self.vulnerabilities if v.severity == 'HIGH']),
                'MEDIUM': len([v for v in self.vulnerabilities if v.severity == 'MEDIUM']),
            },
            'all_vulnerabilities': [asdict(v) for v in self.vulnerabilities]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n✓ Report saved: {output_file}")

        # Print summary
        print(f"\n{'='*80}")
        print("Vulnerability Summary by Category")
        print(f"{'='*80}")
        for category, vulns in sorted(by_category.items(), key=lambda x: len(x[1]), reverse=True):
            default_count = len([v for v in vulns if v.get('default_config_impact')])
            print(f"{category:40s} {len(vulns):4d} ({default_count} default config)")

        if default_config_vulns:
            print(f"\n⚠️  {len(default_config_vulns)} vulnerabilities affect DEFAULT configuration")
            print("   These are highest priority for bug bounty reporting!")

def main():
    import sys

    if len(sys.argv) < 3:
        print("Usage: python newrelic_security_scanner.py <repo_path> <agent_name>")
        sys.exit(1)

    repo_path = sys.argv[1]
    agent_name = sys.argv[2]

    scanner = NewRelicAgentScanner(repo_path, agent_name)
    scanner.scan_all()
    scanner.generate_report(f'{agent_name}_scan_results.json')

if __name__ == '__main__':
    main()
