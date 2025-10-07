#!/usr/bin/env python3
"""
Supply Chain Vulnerability Analyzer
Detects supply chain security issues in dependencies and build processes
"""

import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SupplyChainSeverity(Enum):
    """Supply chain vulnerability severity"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class SupplyChainFinding:
    """A supply chain security finding"""
    id: str
    title: str
    severity: SupplyChainSeverity
    category: str  # "dependency", "build", "install", "credential"
    description: str
    affected_file: str
    affected_line: Optional[int]
    evidence: str
    impact: str
    remediation: str
    cvss_score: float
    cwe: str
    references: List[str]


class SupplyChainAnalyzer:
    """
    Analyze supply chain security for Google OSS VRP
    """

    # Dangerous build commands
    DANGEROUS_BUILD_COMMANDS = [
        'curl.*bash',
        'wget.*bash',
        'curl.*sh',
        'wget.*sh',
        'eval.*http',
        'exec.*http',
        r'\|\s*sh\b',
        r'\|\s*bash\b',
    ]

    # Suspicious package patterns
    TYPOSQUATTING_TARGETS = {
        'python': ['requests', 'urllib3', 'numpy', 'pandas', 'tensorflow', 'django', 'flask'],
        'npm': ['react', 'angular', 'express', 'lodash', 'webpack', 'babel', 'typescript'],
        'go': ['grpc', 'protobuf', 'kubernetes', 'docker', 'prometheus'],
    }

    # Insecure protocols
    INSECURE_PROTOCOLS = [
        r'http://(?!localhost|127\.0\.0\.1)',  # HTTP (not localhost)
        r'ftp://',
        r'telnet://',
    ]

    # Credential patterns
    CREDENTIAL_PATTERNS = [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
        r'secret[_-]?key\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']',
        r'aws[_-]?access[_-]?key',
        r'private[_-]?key\s*=',
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        self.findings: List[SupplyChainFinding] = []
        self._finding_counter = 0

    def analyze(self) -> List[SupplyChainFinding]:
        """
        Run complete supply chain analysis

        Returns:
            List of supply chain findings
        """
        logger.info("Starting supply chain analysis...")

        self.findings = []

        # Analyze different aspects
        self._analyze_dependencies()
        self._analyze_build_scripts()
        self._analyze_install_scripts()
        self._analyze_credentials()
        self._analyze_network_requests()

        logger.info(f"Supply chain analysis complete: {len(self.findings)} findings")
        return self.findings

    def _analyze_dependencies(self):
        """Analyze dependency files for vulnerabilities"""
        logger.info("Analyzing dependencies...")

        # Python dependencies
        for req_file in ['requirements.txt', 'requirements-lock.txt', 'Pipfile', 'pyproject.toml']:
            filepath = self.project_path / req_file
            if filepath.exists():
                self._check_python_dependencies(filepath)

        # Node.js dependencies
        package_json = self.project_path / 'package.json'
        if package_json.exists():
            self._check_npm_dependencies(package_json)

        # Go dependencies
        go_mod = self.project_path / 'go.mod'
        if go_mod.exists():
            self._check_go_dependencies(go_mod)

        # Ruby dependencies
        gemfile = self.project_path / 'Gemfile'
        if gemfile.exists():
            self._check_ruby_dependencies(gemfile)

    def _check_python_dependencies(self, filepath: Path):
        """Check Python dependencies for issues"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                lines = content.split('\n')

            # Check for unpinned versions
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Check for unpinned versions (no ==)
                if '==' not in line and '~=' not in line and line:
                    package_name = line.split('[')[0].split('>')[0].split('<')[0].strip()
                    if package_name and not package_name.startswith('-'):
                        self._add_finding(
                            title=f"Unpinned dependency: {package_name}",
                            severity=SupplyChainSeverity.MEDIUM,
                            category="dependency",
                            description=f"Package '{package_name}' does not have a pinned version",
                            affected_file=str(filepath),
                            affected_line=i,
                            evidence=line,
                            impact="Unpinned dependencies can lead to supply chain attacks where newer malicious versions are automatically installed",
                            remediation=f"Pin to specific version: {package_name}==X.Y.Z",
                            cvss_score=6.5,
                            cwe="CWE-1357",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Dependency_confusion",
                                "https://cwe.mitre.org/data/definitions/1357.html"
                            ]
                        )

                # Check for HTTP index URLs
                if 'http://' in line and 'index-url' in line:
                    self._add_finding(
                        title="Insecure package index URL",
                        severity=SupplyChainSeverity.HIGH,
                        category="dependency",
                        description="Package index URL uses insecure HTTP protocol",
                        affected_file=str(filepath),
                        affected_line=i,
                        evidence=line,
                        impact="Packages could be intercepted and replaced with malicious versions via MITM attacks",
                        remediation="Use HTTPS: --index-url https://...",
                        cvss_score=7.5,
                        cwe="CWE-319",
                        references=["https://cwe.mitre.org/data/definitions/319.html"]
                    )

        except Exception as e:
            logger.debug(f"Error checking Python dependencies: {e}")

    def _check_npm_dependencies(self, filepath: Path):
        """Check npm dependencies for issues"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            # Check dependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for package, version in data[dep_type].items():
                        # Check for wildcard versions
                        if '*' in version or 'latest' in version:
                            self._add_finding(
                                title=f"Wildcard dependency version: {package}",
                                severity=SupplyChainSeverity.HIGH,
                                category="dependency",
                                description=f"Package '{package}' uses wildcard or 'latest' version",
                                affected_file=str(filepath),
                                affected_line=None,
                                evidence=f'"{package}": "{version}"',
                                impact="Wildcard versions can automatically install compromised package versions",
                                remediation=f"Pin to specific version: \"{package}\": \"X.Y.Z\"",
                                cvss_score=7.0,
                                cwe="CWE-1357",
                                references=["https://cwe.mitre.org/data/definitions/1357.html"]
                            )

                        # Check for Git URLs (can be modified)
                        if 'git://' in version or 'git+' in version:
                            self._add_finding(
                                title=f"Git dependency: {package}",
                                severity=SupplyChainSeverity.MEDIUM,
                                category="dependency",
                                description=f"Package '{package}' installed from Git repository",
                                affected_file=str(filepath),
                                affected_line=None,
                                evidence=f'"{package}": "{version}"',
                                impact="Git dependencies can be modified or deleted, leading to supply chain compromise",
                                remediation="Use published npm package with SRI: https://docs.npmjs.com/about-npm",
                                cvss_score=6.0,
                                cwe="CWE-494",
                                references=["https://cwe.mitre.org/data/definitions/494.html"]
                            )

            # Check for preinstall/postinstall scripts
            if 'scripts' in data:
                for script_name in ['preinstall', 'postinstall', 'install']:
                    if script_name in data['scripts']:
                        script_content = data['scripts'][script_name]

                        # Check for dangerous commands
                        for pattern in self.DANGEROUS_BUILD_COMMANDS:
                            if re.search(pattern, script_content, re.IGNORECASE):
                                self._add_finding(
                                    title=f"Dangerous {script_name} script",
                                    severity=SupplyChainSeverity.CRITICAL,
                                    category="install",
                                    description=f"The {script_name} script executes potentially dangerous commands",
                                    affected_file=str(filepath),
                                    affected_line=None,
                                    evidence=script_content,
                                    impact="Installation scripts can execute arbitrary code, potentially compromising the system during package installation",
                                    remediation=f"Remove dangerous commands from {script_name} script or use safer alternatives",
                                    cvss_score=9.0,
                                    cwe="CWE-78",
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/78.html",
                                        "https://blog.sonatype.com/npm-install-scripts-an-overlooked-attack-vector"
                                    ]
                                )

        except Exception as e:
            logger.debug(f"Error checking npm dependencies: {e}")

    def _check_go_dependencies(self, filepath: Path):
        """Check Go dependencies for issues"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                line = line.strip()

                # Check for replace directives pointing to local paths
                if line.startswith('replace ') and '=>' in line:
                    if '../' in line or './' in line:
                        self._add_finding(
                            title="Local dependency replacement",
                            severity=SupplyChainSeverity.MEDIUM,
                            category="dependency",
                            description="Go module uses local path replacement",
                            affected_file=str(filepath),
                            affected_line=i,
                            evidence=line,
                            impact="Local replacements may not be reproducible across different environments",
                            remediation="Use published module versions or git references",
                            cvss_score=5.5,
                            cwe="CWE-494",
                            references=["https://cwe.mitre.org/data/definitions/494.html"]
                        )

        except Exception as e:
            logger.debug(f"Error checking Go dependencies: {e}")

    def _check_ruby_dependencies(self, filepath: Path):
        """Check Ruby dependencies for issues"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                line = line.strip()

                # Check for git sources
                if "gem " in line and ":git" in line:
                    self._add_finding(
                        title="Git-based gem dependency",
                        severity=SupplyChainSeverity.MEDIUM,
                        category="dependency",
                        description="Gem installed from Git repository instead of RubyGems",
                        affected_file=str(filepath),
                        affected_line=i,
                        evidence=line,
                        impact="Git dependencies can be modified or compromised",
                        remediation="Use published gem from rubygems.org",
                        cvss_score=6.0,
                        cwe="CWE-494",
                        references=["https://cwe.mitre.org/data/definitions/494.html"]
                    )

        except Exception as e:
            logger.debug(f"Error checking Ruby dependencies: {e}")

    def _analyze_build_scripts(self):
        """Analyze build scripts for security issues"""
        logger.info("Analyzing build scripts...")

        build_files = [
            'Makefile', 'makefile',
            'build.sh', 'build.bash',
            'CMakeLists.txt',
            'BUILD', 'BUILD.bazel',
            'setup.py', 'setup.cfg',
        ]

        for filename in build_files:
            filepath = self.project_path / filename
            if filepath.exists():
                self._check_build_script(filepath)

        # Check for scripts in .github/workflows
        workflows_dir = self.project_path / '.github' / 'workflows'
        if workflows_dir.exists():
            for workflow_file in workflows_dir.glob('*.yml'):
                self._check_build_script(workflow_file)

    def _check_build_script(self, filepath: Path):
        """Check a build script for security issues"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                # Check for dangerous curl/wget patterns
                for pattern in self.DANGEROUS_BUILD_COMMANDS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self._add_finding(
                            title="Dangerous command in build script",
                            severity=SupplyChainSeverity.CRITICAL,
                            category="build",
                            description="Build script executes code from remote source",
                            affected_file=str(filepath),
                            affected_line=i,
                            evidence=line.strip(),
                            impact="Build process can be compromised by replacing remote scripts with malicious code",
                            remediation="Download scripts, verify checksums, then execute locally",
                            cvss_score=9.0,
                            cwe="CWE-494",
                            references=[
                                "https://cwe.mitre.org/data/definitions/494.html",
                                "https://owasp.org/www-community/attacks/Build_Injection"
                            ]
                        )

                # Check for insecure protocols
                for pattern in self.INSECURE_PROTOCOLS:
                    if re.search(pattern, line):
                        self._add_finding(
                            title="Insecure protocol in build script",
                            severity=SupplyChainSeverity.HIGH,
                            category="build",
                            description="Build script uses insecure HTTP protocol",
                            affected_file=str(filepath),
                            affected_line=i,
                            evidence=line.strip(),
                            impact="Files downloaded over HTTP can be intercepted and replaced via MITM attacks",
                            remediation="Use HTTPS for all external resources",
                            cvss_score=7.5,
                            cwe="CWE-319",
                            references=["https://cwe.mitre.org/data/definitions/319.html"]
                        )

        except Exception as e:
            logger.debug(f"Error checking build script {filepath}: {e}")

    def _analyze_install_scripts(self):
        """Analyze installation scripts"""
        logger.info("Analyzing installation scripts...")

        install_files = [
            'install.sh', 'install.bash',
            'setup.sh', 'setup.bash',
            'bootstrap.sh', 'bootstrap.bash',
        ]

        for filename in install_files:
            filepath = self.project_path / filename
            if filepath.exists():
                self._check_install_script(filepath)

    def _check_install_script(self, filepath: Path):
        """Check installation script for security issues"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                # Check for sudo without user input
                if 'sudo' in line and 'rm -rf' in line:
                    self._add_finding(
                        title="Dangerous sudo command in install script",
                        severity=SupplyChainSeverity.CRITICAL,
                        category="install",
                        description="Install script executes 'sudo rm -rf' which can delete critical system files",
                        affected_file=str(filepath),
                        affected_line=i,
                        evidence=line.strip(),
                        impact="Installation can accidentally or intentionally destroy system data",
                        remediation="Avoid sudo in install scripts or require explicit user confirmation",
                        cvss_score=9.5,
                        cwe="CWE-78",
                        references=["https://cwe.mitre.org/data/definitions/78.html"]
                    )

                # Check for writing to system directories without checking
                if re.search(r'(cp|mv|install).*(/usr/|/etc/|/bin/|/sbin/)', line):
                    if 'sudo' not in line:
                        self._add_finding(
                            title="System file modification without sudo",
                            severity=SupplyChainSeverity.HIGH,
                            category="install",
                            description="Install script attempts to modify system directories",
                            affected_file=str(filepath),
                            affected_line=i,
                            evidence=line.strip(),
                            impact="Installation may fail or behave unexpectedly on different systems",
                            remediation="Check permissions and use sudo where appropriate",
                            cvss_score=6.5,
                            cwe="CWE-732",
                            references=["https://cwe.mitre.org/data/definitions/732.html"]
                        )

        except Exception as e:
            logger.debug(f"Error checking install script {filepath}: {e}")

    def _analyze_credentials(self):
        """Analyze for hardcoded credentials"""
        logger.info("Analyzing for credentials...")

        # Check common config files
        config_files = [
            '.env', '.env.example',
            'config.json', 'config.yml', 'config.yaml',
            'settings.py', 'settings.json',
        ]

        for filename in config_files:
            filepath = self.project_path / filename
            if filepath.exists():
                self._check_credentials(filepath)

    def _check_credentials(self, filepath: Path):
        """Check file for hardcoded credentials"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                for pattern in self.CREDENTIAL_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if it's a placeholder
                        if any(placeholder in line.lower() for placeholder in ['xxx', 'example', 'placeholder', 'your_', '<', '>']):
                            continue

                        self._add_finding(
                            title="Potential hardcoded credential",
                            severity=SupplyChainSeverity.CRITICAL,
                            category="credential",
                            description="File contains what appears to be a hardcoded credential",
                            affected_file=str(filepath),
                            affected_line=i,
                            evidence=line.strip()[:100],  # Truncate sensitive data
                            impact="Hardcoded credentials can be extracted by attackers and used to compromise systems",
                            remediation="Use environment variables or secret management systems",
                            cvss_score=9.8,
                            cwe="CWE-798",
                            references=[
                                "https://cwe.mitre.org/data/definitions/798.html",
                                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
                            ]
                        )

        except Exception as e:
            logger.debug(f"Error checking credentials in {filepath}: {e}")

    def _analyze_network_requests(self):
        """Analyze for insecure network requests"""
        logger.info("Analyzing network requests...")

        # Check source files
        for ext in ['.py', '.js', '.ts', '.go', '.java', '.sh']:
            for filepath in self.project_path.rglob(f'*{ext}'):
                if 'node_modules' in str(filepath) or 'vendor' in str(filepath):
                    continue
                self._check_network_requests(filepath)

    def _check_network_requests(self, filepath: Path):
        """Check file for insecure network requests"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                # Check for insecure URLs in code
                if 'http://' in line and not any(safe in line for safe in ['localhost', '127.0.0.1', '0.0.0.0', 'example.com']):
                    # Check if it's in a string
                    if '"http://' in line or "'http://" in line or '`http://' in line:
                        self._add_finding(
                            title="Insecure HTTP request",
                            severity=SupplyChainSeverity.MEDIUM,
                            category="network",
                            description="Code makes request over insecure HTTP protocol",
                            affected_file=str(filepath),
                            affected_line=i,
                            evidence=line.strip()[:200],
                            impact="Data transmitted over HTTP can be intercepted and modified",
                            remediation="Use HTTPS for all external requests",
                            cvss_score=6.5,
                            cwe="CWE-319",
                            references=["https://cwe.mitre.org/data/definitions/319.html"]
                        )

        except Exception as e:
            logger.debug(f"Error checking network requests in {filepath}: {e}")

    def _add_finding(self, title: str, severity: SupplyChainSeverity, category: str,
                     description: str, affected_file: str, affected_line: Optional[int],
                     evidence: str, impact: str, remediation: str, cvss_score: float,
                     cwe: str, references: List[str]):
        """Add a finding to the results"""
        self._finding_counter += 1
        finding_id = f"SC-{self._finding_counter:03d}"

        self.findings.append(SupplyChainFinding(
            id=finding_id,
            title=title,
            severity=severity,
            category=category,
            description=description,
            affected_file=affected_file,
            affected_line=affected_line,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            cvss_score=cvss_score,
            cwe=cwe,
            references=references
        ))


def main():
    """Test the analyzer"""
    import sys

    if len(sys.argv) > 1:
        project_path = sys.argv[1]
    else:
        project_path = '.'

    analyzer = SupplyChainAnalyzer(project_path)
    findings = analyzer.analyze()

    print(f"\n{'='*80}")
    print(f"SUPPLY CHAIN ANALYSIS RESULTS")
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

    # Print details
    for finding in findings[:5]:  # Show first 5
        print(f"\n{'-'*80}")
        print(f"[{finding.id}] {finding.title}")
        print(f"Severity: {finding.severity.value} (CVSS {finding.cvss_score})")
        print(f"File: {finding.affected_file}:{finding.affected_line or 'N/A'}")
        print(f"Evidence: {finding.evidence[:100]}...")

    if len(findings) > 5:
        print(f"\n... and {len(findings) - 5} more findings")


if __name__ == '__main__':
    main()
