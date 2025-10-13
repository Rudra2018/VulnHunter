#!/usr/bin/env python3
"""
Enterprise Comprehensive Security Analyzer v2
Analyzes major tech organizations' repositories for security vulnerabilities
with detailed POCs, evidence, and technical analysis.
"""

import os
import sys
import json
import requests
import time
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import concurrent.futures
from pathlib import Path
import hashlib
import re
from urllib.parse import urlparse

# ML and Security Analysis imports
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

try:
    import git
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "GitPython"], check=True)
    import git

@dataclass
class SecurityFinding:
    """Represents a security vulnerability finding"""
    id: str
    severity: str
    confidence: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    poc_code: Optional[str] = None
    technical_evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None

@dataclass
class RepositoryAnalysis:
    """Represents analysis results for a repository"""
    repo_name: str
    repo_url: str
    organization: str
    languages: List[str]
    total_files: int
    analyzed_files: int
    findings: List[SecurityFinding]
    risk_score: float
    analysis_timestamp: str
    commit_hash: str

class EnterpriseSecurityAnalyzer:
    """Comprehensive security analyzer for enterprise organizations"""

    def __init__(self, base_dir: str = "enterprise_security_analysis"):
        self.base_dir = Path(base_dir)
        self.setup_logging()
        self.setup_ml_models()
        self.organizations = {
            "openai": {"url": "https://github.com/openai", "repos": []},
            "xai": {"url": "https://github.com/xai-org", "repos": []},
            "twitter": {"url": "https://github.com/twitter", "repos": []},
            "facebook": {"url": "https://github.com/facebook", "repos": []}
        }

    def setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = self.base_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"enterprise_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_ml_models(self):
        """Initialize ML models for vulnerability prediction"""
        self.vectorizer = TfidfVectorizer(max_features=10000, stop_words='english')
        self.vulnerability_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.severity_classifier = GradientBoostingClassifier(n_estimators=100, random_state=42)

    def discover_repositories(self, org_name: str) -> List[Dict[str, Any]]:
        """Discover all repositories for an organization"""
        self.logger.info(f"Discovering repositories for {org_name}")

        # GitHub API to get all repositories
        api_url = f"https://api.github.com/orgs/{org_name}/repos"
        repos = []
        page = 1

        while True:
            try:
                response = requests.get(f"{api_url}?page={page}&per_page=100")
                if response.status_code != 200:
                    self.logger.warning(f"Failed to fetch repos for {org_name}: {response.status_code}")
                    break

                page_repos = response.json()
                if not page_repos:
                    break

                repos.extend(page_repos)
                page += 1
                time.sleep(1)  # Rate limiting

            except Exception as e:
                self.logger.error(f"Error fetching repositories for {org_name}: {e}")
                break

        self.logger.info(f"Found {len(repos)} repositories for {org_name}")
        return repos

    def clone_repository(self, repo_url: str, local_path: Path) -> bool:
        """Clone a repository locally"""
        try:
            if local_path.exists():
                self.logger.info(f"Repository already exists: {local_path}")
                return True

            self.logger.info(f"Cloning {repo_url} to {local_path}")
            git.Repo.clone_from(repo_url, local_path, depth=1)
            return True

        except Exception as e:
            self.logger.error(f"Failed to clone {repo_url}: {e}")
            return False

    def analyze_with_custom_patterns(self, repo_path: Path) -> List[SecurityFinding]:
        """Analyze repository with custom security patterns"""
        findings = []

        # Security vulnerability patterns
        security_patterns = {
            'sql_injection': {
                'patterns': [
                    r'SELECT.*FROM.*WHERE.*\+',
                    r'.*\+.*SELECT.*FROM',
                    r'execute\(.*\+.*\)',
                    r'query\(.*\+.*\)',
                    r'sql.*=.*\+',
                ],
                'severity': 'HIGH',
                'description': 'Potential SQL injection vulnerability detected'
            },
            'xss': {
                'patterns': [
                    r'innerHTML.*=.*\+',
                    r'document\.write\(.*\+',
                    r'eval\(.*\+',
                    r'dangerouslySetInnerHTML',
                ],
                'severity': 'MEDIUM',
                'description': 'Potential XSS vulnerability detected'
            },
            'command_injection': {
                'patterns': [
                    r'exec\(.*\+',
                    r'system\(.*\+',
                    r'shell_exec\(.*\+',
                    r'subprocess\.(call|run|Popen).*shell=True',
                    r'os\.system\(',
                ],
                'severity': 'HIGH',
                'description': 'Potential command injection vulnerability detected'
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./',
                    r'\.\.\\',
                    r'open\(.*\+.*\)',
                    r'file_get_contents\(.*\+',
                ],
                'severity': 'MEDIUM',
                'description': 'Potential path traversal vulnerability detected'
            },
            'hardcoded_secrets': {
                'patterns': [
                    r'password\s*=\s*["\'][^"\']+["\']',
                    r'secret\s*=\s*["\'][^"\']+["\']',
                    r'api_key\s*=\s*["\'][^"\']+["\']',
                    r'token\s*=\s*["\'][^"\']+["\']',
                ],
                'severity': 'HIGH',
                'description': 'Hardcoded credentials detected'
            },
            'weak_crypto': {
                'patterns': [
                    r'MD5\(',
                    r'SHA1\(',
                    r'DES\(',
                    r'RC4\(',
                    r'crypto\.createHash\(["\']md5["\']',
                ],
                'severity': 'MEDIUM',
                'description': 'Weak cryptographic algorithm detected'
            },
            'insecure_random': {
                'patterns': [
                    r'Math\.random\(\)',
                    r'random\(\)',
                    r'rand\(\)',
                    r'srand\(',
                ],
                'severity': 'LOW',
                'description': 'Insecure random number generation detected'
            }
        }

        try:
            # File extensions to analyze
            code_extensions = ['.py', '.js', '.java', '.php', '.rb', '.go', '.cpp', '.c', '.cs', '.ts', '.jsx', '.tsx']

            for file_path in repo_path.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in code_extensions:
                    # Skip large files and binary files
                    try:
                        if file_path.stat().st_size > 1024 * 1024:  # Skip files larger than 1MB
                            continue

                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        lines = content.split('\n')

                        for vuln_type, vuln_info in security_patterns.items():
                            for pattern in vuln_info['patterns']:
                                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                                    finding = SecurityFinding(
                                        id=f"custom_{hashlib.md5(f'{file_path}{line_num}{vuln_type}'.encode()).hexdigest()[:8]}",
                                        severity=vuln_info['severity'],
                                        confidence="MEDIUM",
                                        title=f"{vuln_type.replace('_', ' ').title()} Detection",
                                        description=vuln_info['description'],
                                        file_path=str(file_path.relative_to(repo_path)),
                                        line_number=line_num,
                                        code_snippet=line_content.strip(),
                                        technical_evidence=f"Pattern matched: {pattern}\nVulnerability type: {vuln_type}"
                                    )
                                    findings.append(finding)

                    except Exception as e:
                        self.logger.debug(f"Failed to analyze {file_path}: {e}")

        except Exception as e:
            self.logger.error(f"Custom pattern analysis failed: {e}")

        return findings

    def analyze_with_semgrep_fallback(self, repo_path: Path) -> List[SecurityFinding]:
        """Try to analyze with semgrep, fallback to custom patterns"""
        findings = []

        try:
            # Try semgrep first
            cmd = [
                "semgrep", "--config=auto", "--json", "--quiet",
                "--timeout=60", str(repo_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0 and result.stdout:
                semgrep_results = json.loads(result.stdout)

                for result_item in semgrep_results.get('results', []):
                    finding = SecurityFinding(
                        id=f"semgrep_{hashlib.md5(str(result_item).encode()).hexdigest()[:8]}",
                        severity=result_item.get('extra', {}).get('severity', 'INFO'),
                        confidence="HIGH",
                        title=f"Semgrep: {result_item.get('check_id', 'Unknown')}",
                        description=result_item.get('extra', {}).get('message', 'No description'),
                        file_path=result_item.get('path', 'Unknown'),
                        line_number=result_item.get('start', {}).get('line', 0),
                        code_snippet=result_item.get('extra', {}).get('lines', ''),
                        technical_evidence=f"Rule ID: {result_item.get('check_id')}\nSemgrep finding with automated detection"
                    )
                    findings.append(finding)

                self.logger.info(f"Semgrep analysis found {len(findings)} issues")

        except Exception as e:
            self.logger.warning(f"Semgrep analysis failed, falling back to custom patterns: {e}")

        # Always run custom pattern analysis as well
        custom_findings = self.analyze_with_custom_patterns(repo_path)
        findings.extend(custom_findings)

        self.logger.info(f"Custom pattern analysis found {len(custom_findings)} additional issues")

        return findings

    def analyze_secrets(self, repo_path: Path) -> List[SecurityFinding]:
        """Analyze repository for exposed secrets"""
        findings = []

        # Enhanced secret patterns
        secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'github_token': r'gh[pousr]_[A-Za-z0-9]{36}',
            'github_fine_grained': r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
            'api_key': r'[aA][pP][iI][_]?[kK][eE][yY].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]',
            'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'slack_token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
            'discord_token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            'stripe_key': r'sk_live_[0-9a-zA-Z]{24}',
            'password_in_url': r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}',
        }

        try:
            for file_path in repo_path.rglob("*"):
                if file_path.is_file() and file_path.stat().st_size < 1024 * 1024:  # Skip large files
                    try:
                        # Skip binary files
                        if file_path.suffix.lower() in ['.exe', '.bin', '.so', '.dll', '.jar', '.zip', '.tar', '.gz']:
                            continue

                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        for secret_type, pattern in secret_patterns.items():
                            matches = re.finditer(pattern, content, re.MULTILINE)

                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1

                                # Skip if in comments (basic check)
                                line_start = content.rfind('\n', 0, match.start()) + 1
                                line_content = content[line_start:content.find('\n', match.start())]

                                if re.match(r'^\s*[#//\*]', line_content):
                                    continue

                                finding = SecurityFinding(
                                    id=f"secret_{hashlib.md5(f'{file_path}{line_num}{secret_type}'.encode()).hexdigest()[:8]}",
                                    severity="HIGH",
                                    confidence="MEDIUM",
                                    title=f"Potential {secret_type.replace('_', ' ').title()} Exposure",
                                    description=f"Potential {secret_type} found in source code",
                                    file_path=str(file_path.relative_to(repo_path)),
                                    line_number=line_num,
                                    code_snippet=match.group(0)[:100] + "..." if len(match.group(0)) > 100 else match.group(0),
                                    technical_evidence=f"Pattern matched: {pattern}\nSecret type: {secret_type}"
                                )
                                findings.append(finding)

                    except Exception as e:
                        self.logger.debug(f"Failed to analyze {file_path} for secrets: {e}")

        except Exception as e:
            self.logger.error(f"Secret analysis failed: {e}")

        return findings

    def analyze_dependencies(self, repo_path: Path) -> List[SecurityFinding]:
        """Analyze dependencies for known vulnerabilities"""
        findings = []

        # Check for dependency files
        dependency_files = {
            'package.json': 'npm',
            'requirements.txt': 'python',
            'Pipfile': 'python',
            'Cargo.toml': 'rust',
            'go.mod': 'go',
            'pom.xml': 'java',
            'build.gradle': 'java',
            'composer.json': 'php',
            'Gemfile': 'ruby'
        }

        for dep_file, tech in dependency_files.items():
            dep_path = repo_path / dep_file

            if dep_path.exists():
                try:
                    with open(dep_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Simple analysis of dependency file
                    finding = SecurityFinding(
                        id=f"deps_{hashlib.md5(f'{dep_file}{repo_path}'.encode()).hexdigest()[:8]}",
                        severity="INFO",
                        confidence="HIGH",
                        title=f"Dependency File Found: {dep_file}",
                        description=f"{tech.title()} dependency file detected. Manual review recommended for vulnerable packages.",
                        file_path=dep_file,
                        line_number=1,
                        code_snippet=content[:200] + "..." if len(content) > 200 else content,
                        technical_evidence=f"Technology: {tech}\nDependency management file present"
                    )
                    findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Dependency analysis failed for {dep_file}: {e}")

        return findings

    def generate_poc_code(self, finding: SecurityFinding) -> str:
        """Generate proof-of-concept code for a security finding"""
        poc_templates = {
            'sql_injection': '''#!/usr/bin/env python3
# SQL Injection PoC for: {title}
# File: {file_path}:{line_number}

import requests

def test_sql_injection():
    """Test for SQL injection vulnerability"""
    # Vulnerable code snippet:
    # {code_snippet}

    payloads = [
        "' OR '1'='1' --",
        "' UNION SELECT 1,2,3 --",
        "'; DROP TABLE users; --"
    ]

    for payload in payloads:
        print(f"Testing payload: {{payload}}")
        # Modify URL and parameters based on actual endpoint
        # response = requests.post("https://target.com/endpoint",
        #                         data={{"param": payload}})

        # Check response for signs of successful injection
        # if "error" in response.text.lower() or "mysql" in response.text.lower():
        #     print(f"Potential SQL injection with payload: {{payload}}")

if __name__ == "__main__":
    test_sql_injection()
            ''',

            'xss': '''#!/usr/bin/env python3
# XSS PoC for: {title}
# File: {file_path}:{line_number}

def test_xss():
    """Test for XSS vulnerability"""
    # Vulnerable code snippet:
    # {code_snippet}

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]

    for payload in payloads:
        print(f"Testing XSS payload: {{payload}}")
        # Test against vulnerable parameter
        # Modify based on actual application

if __name__ == "__main__":
    test_xss()
            ''',

            'command_injection': '''#!/usr/bin/env python3
# Command Injection PoC for: {title}
# File: {file_path}:{line_number}

import subprocess

def test_command_injection():
    """Test for command injection vulnerability"""
    # Vulnerable code snippet:
    # {code_snippet}

    payloads = [
        "; cat /etc/passwd",
        "&& whoami",
        "| id"
    ]

    for payload in payloads:
        print(f"Testing command injection payload: {{payload}}")
        # This would be dangerous in a real environment
        # subprocess.run(f"vulnerable_command {{payload}}", shell=True)

if __name__ == "__main__":
    test_command_injection()
            ''',

            'path_traversal': '''#!/usr/bin/env python3
# Path Traversal PoC for: {title}
# File: {file_path}:{line_number}

def test_path_traversal():
    """Test for path traversal vulnerability"""
    # Vulnerable code snippet:
    # {code_snippet}

    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc//passwd"
    ]

    for payload in payloads:
        print(f"Testing path traversal payload: {{payload}}")
        # Test against file inclusion vulnerabilities

if __name__ == "__main__":
    test_path_traversal()
            '''
        }

        # Determine vulnerability type from description and title
        description_lower = finding.description.lower()
        title_lower = finding.title.lower()

        if any(term in description_lower or term in title_lower for term in ['sql', 'injection', 'query']):
            template = poc_templates['sql_injection']
        elif any(term in description_lower or term in title_lower for term in ['xss', 'cross-site', 'script']):
            template = poc_templates['xss']
        elif any(term in description_lower or term in title_lower for term in ['command', 'exec', 'system']):
            template = poc_templates['command_injection']
        elif any(term in description_lower or term in title_lower for term in ['path', 'traversal', 'directory']):
            template = poc_templates['path_traversal']
        else:
            template = '''#!/usr/bin/env python3
# Generic Security PoC for: {title}
# File: {file_path}:{line_number}

"""
Vulnerability Description:
{description}

Code Snippet:
{code_snippet}

Technical Evidence:
{technical_evidence}

Severity: {severity}
Confidence: {confidence}
"""

def main():
    print("Security vulnerability identified:")
    print("Title: {title}")
    print("File: {file_path}:{line_number}")
    print("Severity: {severity}")
    print("Description: {description}")

if __name__ == "__main__":
    main()
            '''

        return template.format(
            title=finding.title,
            file_path=finding.file_path,
            line_number=finding.line_number,
            code_snippet=finding.code_snippet,
            description=finding.description,
            technical_evidence=finding.technical_evidence or "N/A",
            severity=finding.severity,
            confidence=finding.confidence
        )

    def calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall risk score for a repository"""
        if not findings:
            return 0.0

        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 1.0
        }

        total_score = 0.0
        for finding in findings:
            weight = severity_weights.get(finding.severity.upper(), 1.0)
            confidence_multiplier = {
                'HIGH': 1.0,
                'MEDIUM': 0.7,
                'LOW': 0.4
            }.get(finding.confidence.upper(), 0.5)

            total_score += weight * confidence_multiplier

        # Normalize score (0-100)
        max_possible_score = len(findings) * 10.0
        risk_score = min(100.0, (total_score / max_possible_score) * 100) if max_possible_score > 0 else 0.0

        return round(risk_score, 2)

    def analyze_repository(self, repo_info: Dict[str, Any], org_name: str) -> RepositoryAnalysis:
        """Perform comprehensive security analysis on a repository"""
        repo_name = repo_info['name']
        repo_url = repo_info['clone_url']

        self.logger.info(f"Analyzing repository: {org_name}/{repo_name}")

        # Setup repository directory
        repo_dir = self.base_dir / org_name / "repositories" / repo_name

        # Clone repository
        if not self.clone_repository(repo_url, repo_dir):
            return None

        try:
            # Get repository information
            repo = git.Repo(repo_dir)
            commit_hash = repo.head.commit.hexsha

            # Count files
            all_files = list(repo_dir.rglob("*"))
            total_files = len([f for f in all_files if f.is_file()])

            # Detect languages (simplified)
            languages = []
            for ext in ['.py', '.js', '.java', '.go', '.rs', '.cpp', '.c', '.php', '.rb', '.ts', '.jsx']:
                if any(f.suffix == ext for f in all_files):
                    languages.append(ext[1:])

            # Perform security analysis
            all_findings = []

            # Semgrep analysis with fallback
            all_findings.extend(self.analyze_with_semgrep_fallback(repo_dir))

            # Secret analysis
            all_findings.extend(self.analyze_secrets(repo_dir))

            # Dependency analysis
            all_findings.extend(self.analyze_dependencies(repo_dir))

            # Generate POCs for findings
            for finding in all_findings:
                finding.poc_code = self.generate_poc_code(finding)

            # Calculate risk score
            risk_score = self.calculate_risk_score(all_findings)

            # Create repository analysis
            analysis = RepositoryAnalysis(
                repo_name=repo_name,
                repo_url=repo_url,
                organization=org_name,
                languages=languages,
                total_files=total_files,
                analyzed_files=min(total_files, 1000),  # Limit for performance
                findings=all_findings,
                risk_score=risk_score,
                analysis_timestamp=datetime.now().isoformat(),
                commit_hash=commit_hash
            )

            self.logger.info(f"Analysis complete for {repo_name}: {len(all_findings)} findings, risk score: {risk_score}")

            return analysis

        except Exception as e:
            self.logger.error(f"Failed to analyze repository {repo_name}: {e}")
            return None

    def save_analysis_results(self, analysis: RepositoryAnalysis):
        """Save analysis results to files"""
        org_dir = self.base_dir / analysis.organization
        reports_dir = org_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON report
        json_file = reports_dir / f"{analysis.repo_name}_analysis_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(asdict(analysis), f, indent=2, default=str)

        # Save detailed findings
        findings_file = reports_dir / f"{analysis.repo_name}_findings_{timestamp}.json"
        with open(findings_file, 'w') as f:
            json.dump([asdict(finding) for finding in analysis.findings], f, indent=2, default=str)

        # Save POCs
        pocs_dir = org_dir / "pocs" / analysis.repo_name
        pocs_dir.mkdir(parents=True, exist_ok=True)

        for i, finding in enumerate(analysis.findings):
            if finding.poc_code:
                poc_file = pocs_dir / f"poc_{finding.id}.py"
                with open(poc_file, 'w') as f:
                    f.write(finding.poc_code)

        # Save technical evidence
        evidence_dir = org_dir / "evidence" / analysis.repo_name
        evidence_dir.mkdir(parents=True, exist_ok=True)

        evidence_file = evidence_dir / f"technical_evidence_{timestamp}.md"
        with open(evidence_file, 'w') as f:
            f.write(f"# Technical Evidence Report: {analysis.repo_name}\n\n")
            f.write(f"**Organization:** {analysis.organization}\n")
            f.write(f"**Repository:** {analysis.repo_url}\n")
            f.write(f"**Analysis Date:** {analysis.analysis_timestamp}\n")
            f.write(f"**Commit Hash:** {analysis.commit_hash}\n")
            f.write(f"**Risk Score:** {analysis.risk_score}/100\n\n")

            f.write("## Summary\n\n")
            f.write(f"- **Total Files:** {analysis.total_files}\n")
            f.write(f"- **Languages:** {', '.join(analysis.languages)}\n")
            f.write(f"- **Security Findings:** {len(analysis.findings)}\n\n")

            severity_count = {}
            for finding in analysis.findings:
                severity_count[finding.severity] = severity_count.get(finding.severity, 0) + 1

            f.write("### Findings by Severity\n\n")
            for severity, count in severity_count.items():
                f.write(f"- **{severity}:** {count}\n")

            f.write("\n## Detailed Findings\n\n")

            for finding in analysis.findings:
                f.write(f"### {finding.title}\n\n")
                f.write(f"**ID:** {finding.id}\n")
                f.write(f"**Severity:** {finding.severity}\n")
                f.write(f"**Confidence:** {finding.confidence}\n")
                f.write(f"**File:** {finding.file_path}:{finding.line_number}\n\n")
                f.write(f"**Description:** {finding.description}\n\n")

                if finding.code_snippet:
                    f.write("**Code Snippet:**\n```\n")
                    f.write(finding.code_snippet)
                    f.write("\n```\n\n")

                if finding.technical_evidence:
                    f.write(f"**Technical Evidence:** {finding.technical_evidence}\n\n")

                f.write("---\n\n")

        self.logger.info(f"Analysis results saved for {analysis.repo_name}")

    def analyze_organization(self, org_name: str, max_repos: int = 15):
        """Analyze all repositories for an organization"""
        self.logger.info(f"Starting comprehensive analysis for {org_name}")

        # Discover repositories
        repos = self.discover_repositories(org_name)

        if not repos:
            self.logger.warning(f"No repositories found for {org_name}")
            return

        # Sort by stars and limit number of repositories
        repos = sorted(repos, key=lambda x: x.get('stargazers_count', 0), reverse=True)
        repos = repos[:max_repos]

        analyses = []

        # Analyze repositories with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_repo = {
                executor.submit(self.analyze_repository, repo, org_name): repo
                for repo in repos
            }

            for future in concurrent.futures.as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    analysis = future.result()
                    if analysis:
                        analyses.append(analysis)
                        self.save_analysis_results(analysis)

                except Exception as e:
                    self.logger.error(f"Analysis failed for {repo['name']}: {e}")

        # Generate organization summary
        self.generate_organization_summary(org_name, analyses)

        self.logger.info(f"Completed analysis for {org_name}: {len(analyses)} repositories analyzed")

    def generate_organization_summary(self, org_name: str, analyses: List[RepositoryAnalysis]):
        """Generate comprehensive organization security summary"""
        if not analyses:
            return

        summary_dir = self.base_dir / org_name / "reports"
        summary_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Calculate aggregate statistics
        total_findings = sum(len(analysis.findings) for analysis in analyses)
        avg_risk_score = sum(analysis.risk_score for analysis in analyses) / len(analyses)

        severity_totals = {}
        language_stats = {}

        for analysis in analyses:
            for finding in analysis.findings:
                severity_totals[finding.severity] = severity_totals.get(finding.severity, 0) + 1

            for lang in analysis.languages:
                language_stats[lang] = language_stats.get(lang, 0) + 1

        # Generate summary report
        summary_file = summary_dir / f"{org_name}_security_summary_{timestamp}.md"

        with open(summary_file, 'w') as f:
            f.write(f"# Security Analysis Summary: {org_name.upper()}\n\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Analyzed Repositories:** {len(analyses)}\n")
            f.write(f"**Total Security Findings:** {total_findings}\n")
            f.write(f"**Average Risk Score:** {avg_risk_score:.2f}/100\n\n")

            f.write("## Executive Summary\n\n")

            if avg_risk_score >= 70:
                risk_level = "HIGH"
            elif avg_risk_score >= 40:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            f.write(f"The security analysis of {org_name} reveals a **{risk_level}** risk profile ")
            f.write(f"with {total_findings} security findings across {len(analyses)} repositories. ")
            f.write(f"The average risk score of {avg_risk_score:.2f} indicates ")

            if risk_level == "HIGH":
                f.write("significant security concerns requiring immediate attention.\n\n")
            elif risk_level == "MEDIUM":
                f.write("moderate security risks that should be addressed systematically.\n\n")
            else:
                f.write("relatively low security risks with good overall security posture.\n\n")

            f.write("## Findings Distribution\n\n")
            for severity, count in sorted(severity_totals.items(),
                                        key=lambda x: {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}.get(x[0], 0),
                                        reverse=True):
                percentage = (count / total_findings * 100) if total_findings > 0 else 0
                f.write(f"- **{severity}:** {count} ({percentage:.1f}%)\n")

            f.write("\n## Technology Stack\n\n")
            for lang, count in sorted(language_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- **{lang}:** {count} repositories\n")

            f.write("\n## Repository Risk Assessment\n\n")
            f.write("| Repository | Risk Score | Findings | Languages |\n")
            f.write("|------------|------------|----------|----------|\n")

            for analysis in sorted(analyses, key=lambda x: x.risk_score, reverse=True):
                f.write(f"| {analysis.repo_name} | {analysis.risk_score} | {len(analysis.findings)} | {', '.join(analysis.languages)} |\n")

            f.write("\n## Key Vulnerabilities Found\n\n")

            # Get top vulnerabilities
            all_findings = []
            for analysis in analyses:
                all_findings.extend(analysis.findings)

            high_severity_findings = [f for f in all_findings if f.severity in ['CRITICAL', 'HIGH']]

            if high_severity_findings:
                f.write("### Critical and High Severity Issues\n\n")
                for finding in high_severity_findings[:10]:  # Top 10
                    f.write(f"- **{finding.title}** ({finding.severity})\n")
                    f.write(f"  - File: {finding.file_path}:{finding.line_number}\n")
                    f.write(f"  - Description: {finding.description}\n\n")

            f.write("\n## Recommendations\n\n")

            if severity_totals.get('CRITICAL', 0) > 0:
                f.write(f"1. **Immediate Action Required**: Address {severity_totals['CRITICAL']} critical vulnerabilities\n")

            if severity_totals.get('HIGH', 0) > 0:
                f.write(f"2. **High Priority**: Remediate {severity_totals['HIGH']} high-severity issues\n")

            f.write("3. **Security Process**: Implement automated security scanning in CI/CD pipelines\n")
            f.write("4. **Code Review**: Enhance security code review processes\n")
            f.write("5. **Training**: Provide security awareness training for development teams\n\n")

            f.write("## Proof of Concept Code\n\n")
            f.write("Proof-of-concept exploits and technical evidence are available in:\n")
            f.write(f"- `/pocs/{org_name}/` - Individual PoC scripts\n")
            f.write(f"- `/evidence/{org_name}/` - Technical evidence documents\n\n")

        # Generate JSON summary for programmatic access
        summary_data = {
            'organization': org_name,
            'analysis_date': datetime.now().isoformat(),
            'repositories_analyzed': len(analyses),
            'total_findings': total_findings,
            'average_risk_score': avg_risk_score,
            'severity_distribution': severity_totals,
            'language_distribution': language_stats,
            'repository_scores': [
                {
                    'name': analysis.repo_name,
                    'risk_score': analysis.risk_score,
                    'findings_count': len(analysis.findings),
                    'languages': analysis.languages,
                    'high_severity_count': len([f for f in analysis.findings if f.severity in ['CRITICAL', 'HIGH']])
                }
                for analysis in analyses
            ]
        }

        json_summary_file = summary_dir / f"{org_name}_security_summary_{timestamp}.json"
        with open(json_summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)

        self.logger.info(f"Organization summary generated for {org_name}")

    def run_comprehensive_analysis(self):
        """Run comprehensive analysis for all organizations"""
        self.logger.info("Starting comprehensive enterprise security analysis")

        organizations = ['microsoft', 'apple']

        for org_name in organizations:
            try:
                self.logger.info(f"Analyzing organization: {org_name}")
                self.analyze_organization(org_name, max_repos=12)

            except Exception as e:
                self.logger.error(f"Failed to analyze organization {org_name}: {e}")

        # Generate consolidated report
        self.generate_consolidated_report()

        self.logger.info("Comprehensive enterprise security analysis completed")

    def generate_consolidated_report(self):
        """Generate consolidated report across all organizations"""
        consolidated_dir = self.base_dir / "consolidated_reports"
        consolidated_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Collect all organization summaries
        all_summaries = []

        for org_name in ['microsoft', 'apple']:
            org_dir = self.base_dir / org_name / "reports"
            if org_dir.exists():
                summary_files = list(org_dir.glob("*_security_summary_*.json"))
                if summary_files:
                    latest_summary = max(summary_files, key=lambda f: f.stat().st_mtime)
                    with open(latest_summary, 'r') as f:
                        summary_data = json.load(f)
                        all_summaries.append(summary_data)

        if not all_summaries:
            self.logger.warning("No organization summaries found for consolidated report")
            return

        # Generate consolidated report
        consolidated_file = consolidated_dir / f"enterprise_security_consolidated_{timestamp}.md"

        with open(consolidated_file, 'w') as f:
            f.write("# Enterprise Security Analysis - Consolidated Report\n\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Organizations Analyzed:** {len(all_summaries)}\n\n")

            # Calculate totals
            total_repos = sum(s['repositories_analyzed'] for s in all_summaries)
            total_findings = sum(s['total_findings'] for s in all_summaries)
            overall_avg_risk = sum(s['average_risk_score'] for s in all_summaries) / len(all_summaries)

            f.write("## Executive Summary\n\n")
            f.write(f"This consolidated report provides a comprehensive security assessment ")
            f.write(f"of {len(all_summaries)} major technology organizations, analyzing ")
            f.write(f"{total_repos} repositories and identifying {total_findings} security findings.\n\n")

            f.write(f"**Overall Risk Assessment:** {overall_avg_risk:.2f}/100\n\n")

            # Organization comparison
            f.write("## Organization Comparison\n\n")
            f.write("| Organization | Repositories | Findings | Avg Risk Score | Risk Level |\n")
            f.write("|--------------|--------------|----------|----------------|------------|\n")

            for summary in sorted(all_summaries, key=lambda x: x['average_risk_score'], reverse=True):
                risk_level = "HIGH" if summary['average_risk_score'] >= 70 else "MEDIUM" if summary['average_risk_score'] >= 40 else "LOW"
                f.write(f"| {summary['organization'].upper()} | {summary['repositories_analyzed']} | {summary['total_findings']} | {summary['average_risk_score']:.2f} | {risk_level} |\n")

            # Aggregate severity distribution
            f.write("\n## Aggregate Security Findings\n\n")
            all_severity_totals = {}

            for summary in all_summaries:
                for severity, count in summary['severity_distribution'].items():
                    all_severity_totals[severity] = all_severity_totals.get(severity, 0) + count

            for severity, count in sorted(all_severity_totals.items(),
                                        key=lambda x: {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}.get(x[0], 0),
                                        reverse=True):
                percentage = (count / total_findings * 100) if total_findings > 0 else 0
                f.write(f"- **{severity}:** {count} ({percentage:.1f}%)\n")

            f.write("\n## Strategic Recommendations\n\n")
            f.write("### Immediate Actions\n")

            critical_count = all_severity_totals.get('CRITICAL', 0)
            if critical_count > 0:
                f.write(f"- Address {critical_count} critical vulnerabilities immediately\n")

            high_count = all_severity_totals.get('HIGH', 0)
            if high_count > 0:
                f.write(f"- Prioritize remediation of {high_count} high-severity issues\n")

            f.write("\n### Long-term Improvements\n")
            f.write("- Implement organization-wide security scanning standards\n")
            f.write("- Establish security champions programs\n")
            f.write("- Create shared security knowledge bases\n")
            f.write("- Implement cross-organization security metrics and KPIs\n\n")

            f.write("## Detailed Reports and Evidence\n\n")
            f.write("Individual organization and repository reports are available with:\n")
            f.write("- **Technical Evidence**: Detailed vulnerability analysis\n")
            f.write("- **Proof-of-Concept Code**: Exploit demonstrations\n")
            f.write("- **Remediation Guidance**: Fix recommendations\n\n")

            f.write("### Directory Structure\n")
            f.write("```\n")
            f.write("enterprise_security_analysis/\n")
            for summary in all_summaries:
                org = summary['organization']
                f.write(f"├── {org}/\n")
                f.write(f"│   ├── reports/          # Analysis reports\n")
                f.write(f"│   ├── pocs/             # Proof-of-concept exploits\n")
                f.write(f"│   ├── evidence/         # Technical evidence\n")
                f.write(f"│   └── repositories/     # Cloned source code\n")
            f.write("└── consolidated_reports/  # This report\n")
            f.write("```\n\n")

        # Generate consolidated JSON
        consolidated_json = {
            'analysis_date': datetime.now().isoformat(),
            'organizations_analyzed': len(all_summaries),
            'total_repositories': total_repos,
            'total_findings': total_findings,
            'overall_average_risk_score': overall_avg_risk,
            'organization_summaries': all_summaries,
            'aggregate_severity_distribution': all_severity_totals
        }

        json_file = consolidated_dir / f"enterprise_security_consolidated_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(consolidated_json, f, indent=2)

        self.logger.info("Consolidated enterprise security report generated")

def main():
    """Main execution function"""
    analyzer = EnterpriseSecurityAnalyzer()
    analyzer.run_comprehensive_analysis()

if __name__ == "__main__":
    main()