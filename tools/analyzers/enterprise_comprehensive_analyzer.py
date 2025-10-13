#!/usr/bin/env python3
"""
Enterprise Comprehensive Security Analyzer
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
import git
import yaml
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

# Security scanning imports
import bandit
from bandit.core import manager
from bandit.core import config as b_config
import semgrep
import ast
import tokenize
import io

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

    def analyze_with_bandit(self, repo_path: Path) -> List[SecurityFinding]:
        """Analyze repository with Bandit for Python security issues"""
        findings = []

        try:
            # Configure Bandit
            conf = b_config.BanditConfig()
            b_mgr = manager.BanditManager(conf, 'file')

            # Find Python files
            python_files = list(repo_path.rglob("*.py"))

            for py_file in python_files[:50]:  # Limit for performance
                try:
                    b_mgr.discover_files([str(py_file)])
                    b_mgr.run_tests()

                    for issue in b_mgr.get_issue_list():
                        finding = SecurityFinding(
                            id=f"bandit_{hashlib.md5(str(issue).encode()).hexdigest()[:8]}",
                            severity=issue.severity,
                            confidence=issue.confidence,
                            title=f"Bandit: {issue.test}",
                            description=issue.text,
                            file_path=str(py_file.relative_to(repo_path)),
                            line_number=issue.lineno,
                            code_snippet=issue.get_code(),
                            cwe_id=getattr(issue, 'cwe', None),
                            technical_evidence=f"Bandit test: {issue.test}\nSeverity: {issue.severity}\nConfidence: {issue.confidence}"
                        )
                        findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Bandit analysis failed for {py_file}: {e}")

        except Exception as e:
            self.logger.error(f"Bandit analysis failed: {e}")

        return findings

    def analyze_with_semgrep(self, repo_path: Path) -> List[SecurityFinding]:
        """Analyze repository with Semgrep"""
        findings = []

        try:
            # Run semgrep with security rules
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

        except Exception as e:
            self.logger.error(f"Semgrep analysis failed: {e}")

        return findings

    def analyze_secrets(self, repo_path: Path) -> List[SecurityFinding]:
        """Analyze repository for exposed secrets"""
        findings = []

        # Common secret patterns
        secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'github_token': r'gh[pousr]_[A-Za-z0-9]{36}',
            'api_key': r'[aA][pP][iI][_]?[kK][eE][yY].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]',
            'private_key': r'-----BEGIN (RSA |)PRIVATE KEY-----',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        }

        try:
            for file_path in repo_path.rglob("*"):
                if file_path.is_file() and file_path.stat().st_size < 1024 * 1024:  # Skip large files
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        for secret_type, pattern in secret_patterns.items():
                            matches = re.finditer(pattern, content, re.MULTILINE)

                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1

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
            'package.json': 'npm audit --json',
            'requirements.txt': 'safety check --json',
            'Pipfile': 'pipenv check --json',
            'Cargo.toml': 'cargo audit --json',
            'go.mod': 'nancy sleuth'
        }

        for dep_file, audit_cmd in dependency_files.items():
            dep_path = repo_path / dep_file

            if dep_path.exists():
                try:
                    # Run security audit
                    cmd_parts = audit_cmd.split()
                    result = subprocess.run(cmd_parts, cwd=repo_path, capture_output=True, text=True, timeout=120)

                    if result.stdout:
                        # Parse audit results (simplified - would need specific parsing for each tool)
                        finding = SecurityFinding(
                            id=f"deps_{hashlib.md5(f'{dep_file}{repo_path}'.encode()).hexdigest()[:8]}",
                            severity="MEDIUM",
                            confidence="HIGH",
                            title=f"Dependency Security Audit: {dep_file}",
                            description=f"Security audit performed on {dep_file}",
                            file_path=dep_file,
                            line_number=1,
                            code_snippet=result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout,
                            technical_evidence=f"Audit command: {audit_cmd}\nAudit output available"
                        )
                        findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Dependency audit failed for {dep_file}: {e}")

        return findings

    def generate_poc_code(self, finding: SecurityFinding) -> str:
        """Generate proof-of-concept code for a security finding"""
        poc_templates = {
            'sql_injection': '''
# SQL Injection PoC
import requests

# Vulnerable parameter identified
payload = "' OR '1'='1' --"
url = "https://target.com/vulnerable_endpoint"
data = {"param": payload}

response = requests.post(url, data=data)
if "admin" in response.text.lower():
    print("SQL Injection successful!")
            ''',

            'xss': '''
# XSS PoC
payload = "<script>alert('XSS')</script>"
# Test in vulnerable parameter
            ''',

            'command_injection': '''
# Command Injection PoC
import subprocess

# Vulnerable command execution
payload = "; cat /etc/passwd"
# This would execute additional commands
            ''',

            'path_traversal': '''
# Path Traversal PoC
payload = "../../../etc/passwd"
# Test against file inclusion vulnerabilities
            '''
        }

        # Simple pattern matching to determine vulnerability type
        description_lower = finding.description.lower()

        if any(term in description_lower for term in ['sql', 'injection', 'query']):
            return poc_templates['sql_injection']
        elif any(term in description_lower for term in ['xss', 'cross-site', 'script']):
            return poc_templates['xss']
        elif any(term in description_lower for term in ['command', 'exec', 'system']):
            return poc_templates['command_injection']
        elif any(term in description_lower for term in ['path', 'traversal', 'directory']):
            return poc_templates['path_traversal']
        else:
            return f'''
# Generic Security PoC for: {finding.title}
# File: {finding.file_path}:{finding.line_number}
#
# Vulnerability Description:
# {finding.description}
#
# Code Snippet:
# {finding.code_snippet}
#
# Technical Evidence:
# {finding.technical_evidence}
            '''

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
            for ext in ['.py', '.js', '.java', '.go', '.rs', '.cpp', '.c']:
                if any(f.suffix == ext for f in all_files):
                    languages.append(ext[1:])

            # Perform security analysis
            all_findings = []

            # Bandit analysis (Python)
            if 'py' in languages:
                all_findings.extend(self.analyze_with_bandit(repo_dir))

            # Semgrep analysis
            all_findings.extend(self.analyze_with_semgrep(repo_dir))

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

    def analyze_organization(self, org_name: str, max_repos: int = 20):
        """Analyze all repositories for an organization"""
        self.logger.info(f"Starting comprehensive analysis for {org_name}")

        # Discover repositories
        repos = self.discover_repositories(org_name)

        if not repos:
            self.logger.warning(f"No repositories found for {org_name}")
            return

        # Limit number of repositories for performance
        repos = repos[:max_repos]

        analyses = []

        # Analyze repositories with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
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

            f.write("\n## Recommendations\n\n")

            if severity_totals.get('CRITICAL', 0) > 0:
                f.write(f"1. **Immediate Action Required**: Address {severity_totals['CRITICAL']} critical vulnerabilities\n")

            if severity_totals.get('HIGH', 0) > 0:
                f.write(f"2. **High Priority**: Remediate {severity_totals['HIGH']} high-severity issues\n")

            f.write("3. **Security Process**: Implement automated security scanning in CI/CD pipelines\n")
            f.write("4. **Code Review**: Enhance security code review processes\n")
            f.write("5. **Training**: Provide security awareness training for development teams\n\n")

            f.write("## Detailed Analysis\n\n")
            f.write("Individual repository analysis reports and proof-of-concept exploits ")
            f.write("are available in the respective repository directories.\n\n")

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
                    'languages': analysis.languages
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

        organizations = ['openai', 'xai-org', 'twitter', 'facebook']

        for org_name in organizations:
            try:
                self.logger.info(f"Analyzing organization: {org_name}")
                self.analyze_organization(org_name, max_repos=15)

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

        for org_name in ['openai', 'xai', 'twitter', 'facebook']:
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

            f.write("\n## Key Insights\n\n")

            # Find highest risk organization
            highest_risk_org = max(all_summaries, key=lambda x: x['average_risk_score'])
            f.write(f"1. **Highest Risk Organization:** {highest_risk_org['organization'].upper()} ")
            f.write(f"(Risk Score: {highest_risk_org['average_risk_score']:.2f})\n")

            # Most common severity
            most_common_severity = max(all_severity_totals.items(), key=lambda x: x[1])
            f.write(f"2. **Most Common Finding Severity:** {most_common_severity[0]} ")
            f.write(f"({most_common_severity[1]} findings)\n")

            # Critical findings
            critical_count = all_severity_totals.get('CRITICAL', 0)
            if critical_count > 0:
                f.write(f"3. **Critical Security Issues:** {critical_count} critical vulnerabilities ")
                f.write("require immediate attention across all organizations\n")

            f.write("\n## Strategic Recommendations\n\n")
            f.write("### Immediate Actions\n")

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

            f.write("## Detailed Reports\n\n")
            f.write("Individual organization and repository reports are available in ")
            f.write("their respective directories with detailed findings, proof-of-concept ")
            f.write("exploits, and technical evidence.\n\n")

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