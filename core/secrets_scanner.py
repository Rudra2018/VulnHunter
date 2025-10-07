#!/usr/bin/env python3
"""
Secrets and Credentials Scanner
Detects hardcoded secrets, API keys, passwords, and other sensitive credentials
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecretSeverity(Enum):
    """Severity of secret exposure"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class SecretFinding:
    """A secret/credential finding"""
    id: str
    secret_type: str
    severity: SecretSeverity
    description: str
    affected_file: str
    affected_line: int
    evidence: str  # Redacted
    full_match: str  # For internal use only
    confidence: float  # 0.0 - 1.0
    impact: str
    remediation: str
    cvss_score: float
    cwe: str = "CWE-798"


class SecretsScanner:
    """
    Scan for hardcoded secrets and credentials
    """

    # Secret patterns with confidence scores
    SECRET_PATTERNS = {
        # AWS
        'aws_access_key': {
            'pattern': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'confidence': 0.95,
            'severity': SecretSeverity.CRITICAL,
            'description': 'AWS Access Key ID'
        },
        'aws_secret_key': {
            'pattern': r'(?i)aws(.{0,20})?[\'"\s]*[=:]\s*[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'confidence': 0.85,
            'severity': SecretSeverity.CRITICAL,
            'description': 'AWS Secret Access Key'
        },

        # Google Cloud
        'gcp_api_key': {
            'pattern': r'AIza[0-9A-Za-z\-_]{35}',
            'confidence': 0.95,
            'severity': SecretSeverity.CRITICAL,
            'description': 'Google Cloud Platform API Key'
        },
        'gcp_service_account': {
            'pattern': r'"type":\s*"service_account"',
            'confidence': 0.90,
            'severity': SecretSeverity.CRITICAL,
            'description': 'Google Cloud Service Account JSON'
        },

        # GitHub
        'github_token': {
            'pattern': r'gh[pousr]_[A-Za-z0-9]{36,255}',
            'confidence': 0.95,
            'severity': SecretSeverity.CRITICAL,
            'description': 'GitHub Personal Access Token'
        },
        'github_oauth': {
            'pattern': r'gho_[A-Za-z0-9]{36,255}',
            'confidence': 0.95,
            'severity': SecretSeverity.CRITICAL,
            'description': 'GitHub OAuth Access Token'
        },

        # Private Keys
        'rsa_private_key': {
            'pattern': r'-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----',
            'confidence': 1.0,
            'severity': SecretSeverity.CRITICAL,
            'description': 'RSA Private Key'
        },
        'dsa_private_key': {
            'pattern': r'-----BEGIN DSA PRIVATE KEY-----',
            'confidence': 1.0,
            'severity': SecretSeverity.CRITICAL,
            'description': 'DSA Private Key'
        },
        'ec_private_key': {
            'pattern': r'-----BEGIN EC PRIVATE KEY-----',
            'confidence': 1.0,
            'severity': SecretSeverity.CRITICAL,
            'description': 'EC Private Key'
        },
        'pgp_private_key': {
            'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'confidence': 1.0,
            'severity': SecretSeverity.CRITICAL,
            'description': 'PGP Private Key'
        },

        # Generic API Keys
        'generic_api_key': {
            'pattern': r'(?i)(?:api[_-]?key|apikey)[\s]*[=:][\'"\s]*([0-9a-zA-Z\-_]{20,})[\'"]',
            'confidence': 0.75,
            'severity': SecretSeverity.HIGH,
            'description': 'Generic API Key'
        },
        'generic_secret': {
            'pattern': r'(?i)(?:secret[_-]?key|secret)[\s]*[=:][\'"\s]*([0-9a-zA-Z\-_]{20,})[\'"]',
            'confidence': 0.75,
            'severity': SecretSeverity.HIGH,
            'description': 'Generic Secret Key'
        },

        # Tokens
        'bearer_token': {
            'pattern': r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*',
            'confidence': 0.80,
            'severity': SecretSeverity.HIGH,
            'description': 'Bearer Token'
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*',
            'confidence': 0.90,
            'severity': SecretSeverity.HIGH,
            'description': 'JWT Token'
        },

        # Database Connection Strings
        'postgres_url': {
            'pattern': r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+',
            'confidence': 0.90,
            'severity': SecretSeverity.CRITICAL,
            'description': 'PostgreSQL Connection String with Credentials'
        },
        'mysql_url': {
            'pattern': r'mysql://[^:]+:[^@]+@[^/]+/\w+',
            'confidence': 0.90,
            'severity': SecretSeverity.CRITICAL,
            'description': 'MySQL Connection String with Credentials'
        },
        'mongodb_url': {
            'pattern': r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+',
            'confidence': 0.90,
            'severity': SecretSeverity.CRITICAL,
            'description': 'MongoDB Connection String with Credentials'
        },

        # Slack
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
            'confidence': 0.95,
            'severity': SecretSeverity.HIGH,
            'description': 'Slack Token'
        },
        'slack_webhook': {
            'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}',
            'confidence': 0.95,
            'severity': SecretSeverity.MEDIUM,
            'description': 'Slack Webhook URL'
        },

        # Passwords
        'password_assignment': {
            'pattern': r'(?i)(?:password|passwd|pwd)[\s]*[=:][\'"\s]*([^\s\'";]{8,})[\'"]',
            'confidence': 0.60,
            'severity': SecretSeverity.HIGH,
            'description': 'Hardcoded Password'
        },

        # SSH
        'ssh_password': {
            'pattern': r'(?i)ssh.*password[\s]*[=:][\s]*[\'"]([^\'"]+)[\'"]',
            'confidence': 0.85,
            'severity': SecretSeverity.CRITICAL,
            'description': 'SSH Password'
        },

        # Cloud providers
        'azure_key': {
            'pattern': r'(?i)(?:azure|az)(?:[_-]?key|[_-]?password)[\s]*[=:][\'"\s]*([0-9a-zA-Z+/]{40,})[\'"]',
            'confidence': 0.80,
            'severity': SecretSeverity.CRITICAL,
            'description': 'Azure Key or Password'
        },
        'heroku_api_key': {
            'pattern': r'(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'confidence': 0.85,
            'severity': SecretSeverity.HIGH,
            'description': 'Heroku API Key'
        },

        # Payment/Financial
        'stripe_key': {
            'pattern': r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
            'confidence': 0.95,
            'severity': SecretSeverity.CRITICAL,
            'description': 'Stripe API Key'
        },

        # Generic patterns
        'generic_credential': {
            'pattern': r'(?i)(?:token|key|secret|password|passwd|pwd|api_key)[\s]*[=:][\'"\s]*([0-9a-zA-Z\-_@.+/]{16,})[\'"]',
            'confidence': 0.50,
            'severity': SecretSeverity.MEDIUM,
            'description': 'Potential Credential'
        },
    }

    # Files to exclude
    EXCLUDE_PATTERNS = [
        '*.pyc', '__pycache__', '.git', '.svn', '.hg',
        'node_modules', 'vendor', 'venv', 'env', '.venv',
        '*.min.js', '*.map', 'package-lock.json', 'yarn.lock',
        '.egg-info', 'dist', 'build', '.pytest_cache',
        '*.log', '*.lock'
    ]

    # Common false positive indicators
    FALSE_POSITIVE_INDICATORS = [
        'example', 'sample', 'test', 'dummy', 'fake', 'placeholder',
        'your_', 'my_', '<', '>', 'xxx', '***', '...', 'todo',
        'replace_', 'change_', 'insert_', 'enter_', 'put_your_',
        'xxxxxx', '123456', 'password123', 'test123'
    ]

    def __init__(self, project_path: str, max_file_size: int = 1024 * 1024):
        """
        Initialize secrets scanner

        Args:
            project_path: Path to scan
            max_file_size: Maximum file size to scan (default 1MB)
        """
        self.project_path = Path(project_path).resolve()
        self.max_file_size = max_file_size
        self.findings: List[SecretFinding] = []
        self._finding_counter = 0

    def scan(self) -> List[SecretFinding]:
        """
        Scan for secrets

        Returns:
            List of secret findings
        """
        logger.info(f"Scanning for secrets in: {self.project_path}")
        self.findings = []

        files_scanned = 0
        for filepath in self._get_files_to_scan():
            try:
                self._scan_file(filepath)
                files_scanned += 1
            except Exception as e:
                logger.debug(f"Error scanning {filepath}: {e}")

        logger.info(f"Secrets scan complete: {len(self.findings)} findings in {files_scanned} files")
        return self.findings

    def _get_files_to_scan(self):
        """Get list of files to scan"""
        for filepath in self.project_path.rglob('*'):
            # Skip if not a file
            if not filepath.is_file():
                continue

            # Skip if too large
            try:
                if filepath.stat().st_size > self.max_file_size:
                    continue
            except:
                continue

            # Skip excluded patterns
            if any(filepath.match(pattern) for pattern in self.EXCLUDE_PATTERNS):
                continue

            # Skip binary files
            if self._is_binary(filepath):
                continue

            yield filepath

    def _is_binary(self, filepath: Path) -> bool:
        """Check if file is binary"""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                # Check for null bytes
                return b'\x00' in chunk
        except:
            return True

    def _scan_file(self, filepath: Path):
        """Scan a single file for secrets"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                # Skip comments
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue

                # Check each pattern
                for secret_type, pattern_info in self.SECRET_PATTERNS.items():
                    matches = re.finditer(pattern_info['pattern'], line)
                    for match in matches:
                        matched_text = match.group(0)

                        # Check for false positives
                        if self._is_false_positive(matched_text, line):
                            continue

                        # Create finding
                        self._add_finding(
                            secret_type=secret_type,
                            severity=pattern_info['severity'],
                            description=pattern_info['description'],
                            affected_file=str(filepath.relative_to(self.project_path)),
                            affected_line=line_num,
                            evidence=matched_text,
                            full_line=line,
                            confidence=pattern_info['confidence']
                        )

        except Exception as e:
            logger.debug(f"Error scanning file {filepath}: {e}")

    def _is_false_positive(self, matched_text: str, full_line: str) -> bool:
        """Check if match is likely a false positive"""
        # Check for placeholder text
        text_lower = matched_text.lower()
        line_lower = full_line.lower()

        for indicator in self.FALSE_POSITIVE_INDICATORS:
            if indicator in text_lower or indicator in line_lower:
                return True

        # Check for common test/example patterns
        if 'test' in line_lower or 'example' in line_lower:
            return True

        # Check for documentation
        if any(marker in full_line for marker in ['"""', "'''", '///', '<!--']):
            return True

        return False

    def _add_finding(self, secret_type: str, severity: SecretSeverity,
                     description: str, affected_file: str, affected_line: int,
                     evidence: str, full_line: str, confidence: float):
        """Add a secret finding"""
        self._finding_counter += 1
        finding_id = f"SECRET-{self._finding_counter:03d}"

        # Redact the secret in evidence
        redacted = self._redact_secret(evidence)

        # Calculate CVSS score based on severity
        cvss_scores = {
            SecretSeverity.CRITICAL: 9.8,
            SecretSeverity.HIGH: 8.5,
            SecretSeverity.MEDIUM: 6.5,
            SecretSeverity.LOW: 4.0
        }

        impact = self._get_impact(secret_type)
        remediation = self._get_remediation(secret_type)

        finding = SecretFinding(
            id=finding_id,
            secret_type=secret_type,
            severity=severity,
            description=description,
            affected_file=affected_file,
            affected_line=affected_line,
            evidence=redacted,
            full_match=evidence,  # Store full match internally
            confidence=confidence,
            impact=impact,
            remediation=remediation,
            cvss_score=cvss_scores[severity]
        )

        self.findings.append(finding)

    def _redact_secret(self, secret: str) -> str:
        """Redact sensitive parts of secret"""
        if len(secret) <= 8:
            return '*' * len(secret)

        # Show first 4 and last 4 characters
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def _get_impact(self, secret_type: str) -> str:
        """Get impact description for secret type"""
        impacts = {
            'aws_access_key': "Full access to AWS account resources, data exfiltration, resource hijacking",
            'aws_secret_key': "Full access to AWS account resources, data exfiltration, resource hijacking",
            'gcp_api_key': "Unauthorized access to Google Cloud Platform services and data",
            'gcp_service_account': "Full service account privileges on Google Cloud Platform",
            'github_token': "Access to private repositories, ability to modify code, create releases",
            'rsa_private_key': "Ability to decrypt encrypted data, impersonate identity, access systems",
            'postgres_url': "Complete access to database, data theft, data manipulation",
            'mysql_url': "Complete access to database, data theft, data manipulation",
            'mongodb_url': "Complete access to database, data theft, data manipulation",
            'stripe_key': "Unauthorized payment processing, financial fraud",
        }
        return impacts.get(secret_type, "Unauthorized access and potential system compromise")

    def _get_remediation(self, secret_type: str) -> str:
        """Get remediation guidance for secret type"""
        remediations = {
            'aws_access_key': "1. Rotate AWS access key immediately 2. Use AWS Secrets Manager 3. Use IAM roles instead of hardcoded keys",
            'gcp_api_key': "1. Revoke exposed API key 2. Use Google Secret Manager 3. Implement API key restrictions",
            'github_token': "1. Revoke token immediately 2. Use GitHub Secrets for CI/CD 3. Use short-lived tokens",
            'rsa_private_key': "1. Rotate key pair 2. Store keys in secure key management system 3. Never commit keys to version control",
        }
        return remediations.get(secret_type, "1. Remove from code 2. Rotate credential 3. Use environment variables or secret management system")


def main():
    """Test the scanner"""
    import sys

    if len(sys.argv) > 1:
        project_path = sys.argv[1]
    else:
        project_path = '.'

    scanner = SecretsScanner(project_path)
    findings = scanner.scan()

    print(f"\n{'='*80}")
    print(f"SECRETS SCAN RESULTS")
    print(f"{'='*80}")
    print(f"Project: {project_path}")
    print(f"Findings: {len(findings)}")
    print(f"{'='*80}\n")

    # Group by severity
    by_severity = {}
    for finding in findings:
        severity = finding.severity.value
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)

    # Print summary
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if severity in by_severity:
            count = len(by_severity[severity])
            emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
            print(f"{emoji.get(severity, '')} {severity}: {count}")

    # Print details for critical findings
    if 'Critical' in by_severity:
        print(f"\n{'='*80}")
        print("CRITICAL FINDINGS:")
        print(f"{'='*80}")
        for finding in by_severity['Critical'][:10]:
            print(f"\n[{finding.id}] {finding.description}")
            print(f"Type: {finding.secret_type}")
            print(f"File: {finding.affected_file}:{finding.affected_line}")
            print(f"Evidence: {finding.evidence}")
            print(f"Confidence: {finding.confidence:.0%}")
            print(f"Impact: {finding.impact[:100]}...")


if __name__ == '__main__':
    main()
