#!/usr/bin/env python3
"""
Comprehensive Mobile Security Analyzer
=====================================

Advanced security analysis framework for Android APK and iOS IPA files.
Performs static analysis, dynamic analysis, vulnerability detection, and generates detailed PDF reports.

Author: Ankit Thakur
Date: October 10, 2025
"""

import os
import sys
import json
import time
import hashlib
import zipfile
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import logging
import re
import base64
import sqlite3
from dataclasses import dataclass, asdict

# PDF Generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus.tableofcontents import TableOfContents
except ImportError:
    print("Installing reportlab for PDF generation...")
    subprocess.run([sys.executable, "-m", "pip", "install", "reportlab"], check=True)
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch

@dataclass
class SecurityFinding:
    """Represents a security finding with severity and details"""
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    impact: str
    recommendation: str
    evidence: List[str]
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    poc_code: Optional[str] = None

@dataclass
class AppMetadata:
    """Basic application metadata"""
    filename: str
    file_type: str  # APK or IPA
    file_size: int
    md5_hash: str
    sha1_hash: str
    sha256_hash: str
    package_name: Optional[str] = None
    version: Optional[str] = None
    target_sdk: Optional[str] = None
    min_sdk: Optional[str] = None

class MobileSecurityAnalyzer:
    """Comprehensive mobile application security analyzer"""

    def __init__(self, output_dir: str = "~/Downloads"):
        self.output_dir = Path(output_dir).expanduser()
        self.findings: List[SecurityFinding] = []
        self.metadata: Optional[AppMetadata] = None

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Vulnerability patterns
        self.vuln_patterns = {
            'hardcoded_secrets': [
                r'["\'](?:password|pwd|pass|secret|key|token|api[_-]?key)["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\'](?:aws|amazon)[_-]?(?:access[_-]?key|secret)["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\'](?:firebase|google)[_-]?(?:api[_-]?key|secret)["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\'](?:database|db)[_-]?(?:password|pass|pwd)["\']?\s*[:=]\s*["\'][^"\']+["\']'
            ],
            'crypto_issues': [
                r'DES|3DES|RC4|MD5|SHA1(?![-_])',
                r'ECB|PKCS1Padding',
                r'TrustAllX509TrustManager|NullHostnameVerifier',
                r'SSLContext\.getInstance\("SSL"\)|"TLS"'
            ],
            'network_security': [
                r'http://(?!localhost|127\.0\.0\.1)',
                r'allowBackup\s*=\s*["\']true["\']',
                r'android:exported\s*=\s*["\']true["\']',
                r'usesCleartextTraffic\s*=\s*["\']true["\']'
            ],
            'sql_injection': [
                r'(?:SELECT|INSERT|UPDATE|DELETE).*\+.*["\']',
                r'execSQL\([^)]*\+[^)]*\)',
                r'rawQuery\([^)]*\+[^)]*\)'
            ],
            'path_traversal': [
                r'\.\./',
                r'File\([^)]*\+[^)]*\)',
                r'openFileInput\([^)]*\+[^)]*\)'
            ]
        }

        # iOS specific patterns
        self.ios_patterns = {
            'plist_issues': [
                r'NSAllowsArbitraryLoads.*true',
                r'NSExceptionAllowsInsecureHTTPLoads.*true',
                r'UIRequiresPersistentWiFi.*true'
            ],
            'keychain_issues': [
                r'kSecAttrAccessibleAlways',
                r'kSecAttrAccessibleWhenUnlocked'
            ]
        }

    def calculate_hashes(self, file_path: Path) -> Tuple[str, str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of the file"""
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)

        return hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest()

    def extract_apk_metadata(self, apk_path: Path) -> AppMetadata:
        """Extract metadata from APK file"""
        try:
            # Use aapt to get APK info if available
            try:
                result = subprocess.run([
                    'aapt', 'dump', 'badging', str(apk_path)
                ], capture_output=True, text=True, timeout=30)

                package_name = None
                version = None
                target_sdk = None
                min_sdk = None

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('package:'):
                            match = re.search(r"name='([^']+)'", line)
                            if match:
                                package_name = match.group(1)
                            match = re.search(r"versionName='([^']+)'", line)
                            if match:
                                version = match.group(1)
                        elif line.startswith('targetSdkVersion:'):
                            match = re.search(r"'(\d+)'", line)
                            if match:
                                target_sdk = match.group(1)
                        elif line.startswith('sdkVersion:'):
                            match = re.search(r"'(\d+)'", line)
                            if match:
                                min_sdk = match.group(1)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.logger.warning("aapt not available, using basic analysis")
                package_name = version = target_sdk = min_sdk = None

            # Fallback: Extract from AndroidManifest.xml
            if not package_name:
                try:
                    with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                        if 'AndroidManifest.xml' in apk_zip.namelist():
                            # Note: AndroidManifest.xml is usually binary in APK
                            # For proper parsing, we'd need aapt or specialized tools
                            pass
                except Exception as e:
                    self.logger.error(f"Error reading APK manifest: {e}")

            md5, sha1, sha256 = self.calculate_hashes(apk_path)

            return AppMetadata(
                filename=apk_path.name,
                file_type="APK",
                file_size=apk_path.stat().st_size,
                md5_hash=md5,
                sha1_hash=sha1,
                sha256_hash=sha256,
                package_name=package_name,
                version=version,
                target_sdk=target_sdk,
                min_sdk=min_sdk
            )

        except Exception as e:
            self.logger.error(f"Error extracting APK metadata: {e}")
            md5, sha1, sha256 = self.calculate_hashes(apk_path)
            return AppMetadata(
                filename=apk_path.name,
                file_type="APK",
                file_size=apk_path.stat().st_size,
                md5_hash=md5,
                sha1_hash=sha1,
                sha256_hash=sha256
            )

    def extract_ipa_metadata(self, ipa_path: Path) -> AppMetadata:
        """Extract metadata from IPA file"""
        try:
            package_name = None
            version = None

            # Extract Info.plist from IPA
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                # Find Info.plist in Payload/App.app/
                for file_path in ipa_zip.namelist():
                    if file_path.endswith('Info.plist') and 'Payload/' in file_path:
                        try:
                            plist_data = ipa_zip.read(file_path)
                            # Parse plist (simplified - would need plistlib for proper parsing)
                            plist_str = plist_data.decode('utf-8', errors='ignore')

                            # Extract bundle identifier
                            bundle_match = re.search(r'<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>', plist_str)
                            if bundle_match:
                                package_name = bundle_match.group(1)

                            # Extract version
                            version_match = re.search(r'<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>', plist_str)
                            if version_match:
                                version = version_match.group(1)

                            break
                        except Exception as e:
                            self.logger.warning(f"Error parsing Info.plist: {e}")

            md5, sha1, sha256 = self.calculate_hashes(ipa_path)

            return AppMetadata(
                filename=ipa_path.name,
                file_type="IPA",
                file_size=ipa_path.stat().st_size,
                md5_hash=md5,
                sha1_hash=sha1,
                sha256_hash=sha256,
                package_name=package_name,
                version=version
            )

        except Exception as e:
            self.logger.error(f"Error extracting IPA metadata: {e}")
            md5, sha1, sha256 = self.calculate_hashes(ipa_path)
            return AppMetadata(
                filename=ipa_path.name,
                file_type="IPA",
                file_size=ipa_path.stat().st_size,
                md5_hash=md5,
                sha1_hash=sha1,
                sha256_hash=sha256
            )

    def analyze_apk_static(self, apk_path: Path) -> List[SecurityFinding]:
        """Perform static analysis on APK file"""
        findings = []

        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Analyze AndroidManifest.xml
                findings.extend(self._analyze_android_manifest(apk_zip))

                # Analyze DEX files
                findings.extend(self._analyze_dex_files(apk_zip))

                # Analyze resources
                findings.extend(self._analyze_android_resources(apk_zip))

                # Analyze native libraries
                findings.extend(self._analyze_native_libraries(apk_zip))

        except Exception as e:
            self.logger.error(f"Error during APK static analysis: {e}")
            findings.append(SecurityFinding(
                category="Analysis Error",
                severity="HIGH",
                title="APK Analysis Failed",
                description=f"Failed to perform complete static analysis: {str(e)}",
                impact="Unable to identify potential security vulnerabilities",
                recommendation="Manual analysis required",
                evidence=[str(e)]
            ))

        return findings

    def analyze_ipa_static(self, ipa_path: Path) -> List[SecurityFinding]:
        """Perform static analysis on IPA file"""
        findings = []

        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                # Analyze Info.plist
                findings.extend(self._analyze_ios_plist(ipa_zip))

                # Analyze binary
                findings.extend(self._analyze_ios_binary(ipa_zip))

                # Analyze resources
                findings.extend(self._analyze_ios_resources(ipa_zip))

        except Exception as e:
            self.logger.error(f"Error during IPA static analysis: {e}")
            findings.append(SecurityFinding(
                category="Analysis Error",
                severity="HIGH",
                title="IPA Analysis Failed",
                description=f"Failed to perform complete static analysis: {str(e)}",
                impact="Unable to identify potential security vulnerabilities",
                recommendation="Manual analysis required",
                evidence=[str(e)]
            ))

        return findings

    def _analyze_android_manifest(self, apk_zip: zipfile.ZipFile) -> List[SecurityFinding]:
        """Analyze AndroidManifest.xml for security issues"""
        findings = []

        try:
            if 'AndroidManifest.xml' in apk_zip.namelist():
                manifest_data = apk_zip.read('AndroidManifest.xml')
                manifest_str = manifest_data.decode('utf-8', errors='ignore')

                # Check for dangerous permissions
                dangerous_perms = [
                    'android.permission.WRITE_EXTERNAL_STORAGE',
                    'android.permission.READ_EXTERNAL_STORAGE',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.CAMERA',
                    'android.permission.RECORD_AUDIO',
                    'android.permission.READ_CONTACTS',
                    'android.permission.READ_SMS',
                    'android.permission.SEND_SMS'
                ]

                for perm in dangerous_perms:
                    if perm in manifest_str:
                        findings.append(SecurityFinding(
                            category="Permissions",
                            severity="MEDIUM",
                            title=f"Dangerous Permission: {perm}",
                            description=f"Application requests dangerous permission: {perm}",
                            impact="Potential privacy violation or data access",
                            recommendation="Verify permission is necessary and implement runtime permission checks",
                            evidence=[f"Permission found in AndroidManifest.xml: {perm}"]
                        ))

                # Check for backup allowance
                if 'android:allowBackup="true"' in manifest_str:
                    findings.append(SecurityFinding(
                        category="Data Security",
                        severity="MEDIUM",
                        title="Backup Allowed",
                        description="Application allows backup of its data",
                        impact="Sensitive data may be accessible through device backups",
                        recommendation="Set android:allowBackup=\"false\" unless backup is required",
                        evidence=["android:allowBackup=\"true\" found in AndroidManifest.xml"]
                    ))

                # Check for debug mode
                if 'android:debuggable="true"' in manifest_str:
                    findings.append(SecurityFinding(
                        category="Application Security",
                        severity="HIGH",
                        title="Debug Mode Enabled",
                        description="Application is debuggable in production",
                        impact="Application can be debugged and reverse engineered",
                        recommendation="Set android:debuggable=\"false\" for production builds",
                        evidence=["android:debuggable=\"true\" found in AndroidManifest.xml"]
                    ))

        except Exception as e:
            self.logger.error(f"Error analyzing AndroidManifest.xml: {e}")

        return findings

    def _analyze_dex_files(self, apk_zip: zipfile.ZipFile) -> List[SecurityFinding]:
        """Analyze DEX files for security issues"""
        findings = []

        # Look for DEX files
        dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]

        for dex_file in dex_files:
            try:
                dex_data = apk_zip.read(dex_file)
                dex_str = dex_data.decode('utf-8', errors='ignore')

                # Check for hardcoded secrets
                for pattern in self.vuln_patterns['hardcoded_secrets']:
                    matches = re.finditer(pattern, dex_str, re.IGNORECASE)
                    for match in matches:
                        findings.append(SecurityFinding(
                            category="Cryptography",
                            severity="HIGH",
                            title="Hardcoded Secret Detected",
                            description="Potential hardcoded secret or API key found in application code",
                            impact="Sensitive credentials may be exposed to attackers",
                            recommendation="Move secrets to secure storage or environment variables",
                            evidence=[f"Pattern match in {dex_file}: {match.group()[:50]}..."],
                            cwe_id="CWE-798"
                        ))

                # Check for crypto issues
                for pattern in self.vuln_patterns['crypto_issues']:
                    if re.search(pattern, dex_str, re.IGNORECASE):
                        findings.append(SecurityFinding(
                            category="Cryptography",
                            severity="HIGH",
                            title="Weak Cryptography Detected",
                            description=f"Weak cryptographic algorithm or implementation detected: {pattern}",
                            impact="Data encryption may be easily broken",
                            recommendation="Use strong cryptographic algorithms (AES-256, RSA-2048+, SHA-256+)",
                            evidence=[f"Pattern found in {dex_file}: {pattern}"],
                            cwe_id="CWE-327"
                        ))

                # Check for SQL injection vulnerabilities
                for pattern in self.vuln_patterns['sql_injection']:
                    matches = re.finditer(pattern, dex_str, re.IGNORECASE)
                    for match in matches:
                        findings.append(SecurityFinding(
                            category="Injection",
                            severity="HIGH",
                            title="Potential SQL Injection",
                            description="SQL query construction using string concatenation detected",
                            impact="Database injection attacks possible",
                            recommendation="Use parameterized queries or prepared statements",
                            evidence=[f"Pattern match in {dex_file}: {match.group()[:100]}..."],
                            cwe_id="CWE-89"
                        ))

            except Exception as e:
                self.logger.error(f"Error analyzing {dex_file}: {e}")

        return findings

    def _analyze_android_resources(self, apk_zip: zipfile.ZipFile) -> List[SecurityFinding]:
        """Analyze Android resources for security issues"""
        findings = []

        # Check network security config
        network_configs = [f for f in apk_zip.namelist() if 'network_security_config' in f]

        for config_file in network_configs:
            try:
                config_data = apk_zip.read(config_file)
                config_str = config_data.decode('utf-8', errors='ignore')

                if 'cleartextTrafficPermitted="true"' in config_str:
                    findings.append(SecurityFinding(
                        category="Network Security",
                        severity="MEDIUM",
                        title="Cleartext Traffic Permitted",
                        description="Application allows cleartext HTTP traffic",
                        impact="Network communications may be intercepted",
                        recommendation="Use HTTPS only and disable cleartext traffic",
                        evidence=[f"Found in {config_file}: cleartextTrafficPermitted=\"true\""]
                    ))

            except Exception as e:
                self.logger.error(f"Error analyzing {config_file}: {e}")

        return findings

    def _analyze_native_libraries(self, apk_zip: zipfile.ZipFile) -> List[SecurityFinding]:
        """Analyze native libraries for security issues"""
        findings = []

        # Look for native libraries
        lib_files = [f for f in apk_zip.namelist() if f.startswith('lib/') and f.endswith('.so')]

        if lib_files:
            findings.append(SecurityFinding(
                category="Application Security",
                severity="INFO",
                title="Native Libraries Present",
                description=f"Application contains {len(lib_files)} native libraries",
                impact="Native code may be harder to analyze and could contain vulnerabilities",
                recommendation="Ensure native libraries are from trusted sources and regularly updated",
                evidence=[f"Native libraries found: {', '.join(lib_files[:5])}{'...' if len(lib_files) > 5 else ''}"]
            ))

        return findings

    def _analyze_ios_plist(self, ipa_zip: zipfile.ZipFile) -> List[SecurityFinding]:
        """Analyze iOS Info.plist for security issues"""
        findings = []

        for file_path in ipa_zip.namelist():
            if file_path.endswith('Info.plist') and 'Payload/' in file_path:
                try:
                    plist_data = ipa_zip.read(file_path)
                    plist_str = plist_data.decode('utf-8', errors='ignore')

                    # Check for ATS bypass
                    if 'NSAllowsArbitraryLoads' in plist_str and 'true' in plist_str:
                        findings.append(SecurityFinding(
                            category="Network Security",
                            severity="HIGH",
                            title="App Transport Security Disabled",
                            description="NSAllowsArbitraryLoads is set to true, disabling ATS",
                            impact="Network communications are not protected by ATS",
                            recommendation="Remove NSAllowsArbitraryLoads or set to false",
                            evidence=["NSAllowsArbitraryLoads=true found in Info.plist"]
                        ))

                    # Check for URL schemes
                    url_schemes = re.findall(r'<key>CFBundleURLSchemes</key>.*?<array>(.*?)</array>', plist_str, re.DOTALL)
                    if url_schemes:
                        findings.append(SecurityFinding(
                            category="Application Security",
                            severity="MEDIUM",
                            title="Custom URL Schemes Defined",
                            description="Application defines custom URL schemes",
                            impact="Potential for URL scheme hijacking or deeplink attacks",
                            recommendation="Validate all incoming URL scheme parameters",
                            evidence=[f"URL schemes found in Info.plist"]
                        ))

                except Exception as e:
                    self.logger.error(f"Error analyzing Info.plist: {e}")
                break

        return findings

    def _analyze_ios_binary(self, ipa_zip: zipfile.ZipFile) -> List[SecurityFinding]:
        """Analyze iOS binary for security issues"""
        findings = []

        # Find main binary
        for file_path in ipa_zip.namelist():
            if 'Payload/' in file_path and not file_path.endswith('/') and '.' not in file_path.split('/')[-1]:
                try:
                    binary_data = ipa_zip.read(file_path)

                    # Check for binary protections (simplified)
                    if b'LC_ENCRYPTION_INFO' in binary_data:
                        findings.append(SecurityFinding(
                            category="Application Security",
                            severity="INFO",
                            title="Binary Encryption Present",
                            description="Application binary appears to be encrypted",
                            impact="Positive security measure",
                            recommendation="Ensure encryption is properly implemented",
                            evidence=["LC_ENCRYPTION_INFO found in binary"]
                        ))

                    # Check for stack canaries
                    if b'__stack_chk_fail' in binary_data:
                        findings.append(SecurityFinding(
                            category="Application Security",
                            severity="INFO",
                            title="Stack Protection Present",
                            description="Binary compiled with stack protection",
                            impact="Positive security measure against buffer overflows",
                            recommendation="Continue using stack protection",
                            evidence=["__stack_chk_fail found in binary"]
                        ))

                except Exception as e:
                    self.logger.error(f"Error analyzing binary: {e}")
                break

        return findings

    def _analyze_ios_resources(self, ipa_zip: zipfile.ZipFile) -> List[SecurityFinding]:
        """Analyze iOS resources for security issues"""
        findings = []

        # Check for embedded provisioning profile
        provisioning_files = [f for f in ipa_zip.namelist() if 'embedded.mobileprovision' in f]

        if provisioning_files:
            findings.append(SecurityFinding(
                category="Application Security",
                severity="INFO",
                title="Provisioning Profile Present",
                description="Application contains embedded provisioning profile",
                impact="Profile may contain development certificates or debugging capabilities",
                recommendation="Ensure production profile is used for release builds",
                evidence=[f"Provisioning profile found: {provisioning_files[0]}"]
            ))

        return findings

    def generate_poc_code(self, finding: SecurityFinding) -> str:
        """Generate proof-of-concept code for a finding"""
        poc_templates = {
            "Hardcoded Secret Detected": """
# Proof of Concept: Extracting Hardcoded Secrets
import zipfile
import re

def extract_secrets(apk_path):
    secrets = []
    with zipfile.ZipFile(apk_path, 'r') as apk:
        for file in apk.namelist():
            if file.endswith('.dex'):
                data = apk.read(file).decode('utf-8', errors='ignore')
                patterns = [
                    r'[\"\\'](?:password|pwd|pass|secret|key|token)[\"\\']?\\s*[:=]\\s*[\"\\'][^\"\\']+'
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, data, re.IGNORECASE)
                    secrets.extend(matches)
    return secrets

# Usage: secrets = extract_secrets('app.apk')
            """,
            "Weak Cryptography Detected": """
# Proof of Concept: Identifying Weak Crypto
import zipfile

def find_weak_crypto(apk_path):
    weak_patterns = ['DES', 'MD5', 'SHA1', 'RC4']
    findings = []

    with zipfile.ZipFile(apk_path, 'r') as apk:
        for file in apk.namelist():
            if file.endswith('.dex'):
                data = apk.read(file).decode('utf-8', errors='ignore')
                for pattern in weak_patterns:
                    if pattern in data:
                        findings.append(f"Weak crypto found: {pattern}")
    return findings

# Usage: findings = find_weak_crypto('app.apk')
            """,
            "Debug Mode Enabled": """
# Proof of Concept: Checking Debug Mode
import zipfile
import xml.etree.ElementTree as ET

def check_debug_mode(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as apk:
        if 'AndroidManifest.xml' in apk.namelist():
            manifest = apk.read('AndroidManifest.xml')
            # Note: Real AndroidManifest.xml is binary, needs aapt
            if b'android:debuggable="true"' in manifest:
                return True
    return False

# Usage: is_debug = check_debug_mode('app.apk')
            """
        }

        return poc_templates.get(finding.title, "# No specific POC available for this finding")

    def generate_pdf_report(self, app_path: Path) -> str:
        """Generate comprehensive PDF security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{app_path.stem}_security_report_{timestamp}.pdf"
        report_path = self.output_dir / report_filename

        # Create PDF document
        doc = SimpleDocTemplate(str(report_path), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred
        )

        # Title page
        story.append(Paragraph("Mobile Application Security Analysis Report", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"Application: {self.metadata.filename}", styles['Heading2']))
        story.append(Paragraph(f"Analysis Date: {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
        story.append(Paragraph(f"Report Generated by: Comprehensive Mobile Security Analyzer", styles['Normal']))
        story.append(PageBreak())

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))

        # Count findings by severity
        severity_counts = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        summary_text = f"""
        This report presents the results of a comprehensive security analysis performed on {self.metadata.filename}.
        The analysis identified {len(self.findings)} potential security issues across various categories.

        Findings Summary:
        • Critical: {severity_counts.get('CRITICAL', 0)}
        • High: {severity_counts.get('HIGH', 0)}
        • Medium: {severity_counts.get('MEDIUM', 0)}
        • Low: {severity_counts.get('LOW', 0)}
        • Info: {severity_counts.get('INFO', 0)}
        """

        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))

        # Application Metadata
        story.append(Paragraph("Application Metadata", heading_style))

        metadata_data = [
            ['Property', 'Value'],
            ['Filename', self.metadata.filename],
            ['File Type', self.metadata.file_type],
            ['File Size', f"{self.metadata.file_size:,} bytes"],
            ['MD5 Hash', self.metadata.md5_hash],
            ['SHA1 Hash', self.metadata.sha1_hash],
            ['SHA256 Hash', self.metadata.sha256_hash],
            ['Package Name', self.metadata.package_name or 'N/A'],
            ['Version', self.metadata.version or 'N/A'],
            ['Target SDK', self.metadata.target_sdk or 'N/A'],
            ['Min SDK', self.metadata.min_sdk or 'N/A']
        ]

        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(metadata_table)
        story.append(PageBreak())

        # Security Findings
        story.append(Paragraph("Security Findings", heading_style))

        # Group findings by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        findings_by_severity = {sev: [] for sev in severity_order}

        for finding in self.findings:
            findings_by_severity[finding.severity].append(finding)

        finding_counter = 1
        for severity in severity_order:
            if findings_by_severity[severity]:
                story.append(Paragraph(f"{severity} Severity Findings", styles['Heading3']))

                for finding in findings_by_severity[severity]:
                    # Finding header
                    safe_title = finding.title.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(f"Finding {finding_counter}: {safe_title}", styles['Heading4']))

                    # Finding details - escape HTML entities
                    safe_category = finding.category.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    safe_description = finding.description.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    safe_impact = finding.impact.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    safe_recommendation = finding.recommendation.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

                    story.append(Paragraph(f"<b>Category:</b> {safe_category}", styles['Normal']))
                    story.append(Paragraph(f"<b>Severity:</b> {finding.severity}", styles['Normal']))
                    story.append(Paragraph(f"<b>Description:</b> {safe_description}", styles['Normal']))
                    story.append(Paragraph(f"<b>Impact:</b> {safe_impact}", styles['Normal']))
                    story.append(Paragraph(f"<b>Recommendation:</b> {safe_recommendation}", styles['Normal']))

                    if finding.cwe_id:
                        story.append(Paragraph(f"<b>CWE ID:</b> {finding.cwe_id}", styles['Normal']))

                    if finding.cvss_score:
                        story.append(Paragraph(f"<b>CVSS Score:</b> {finding.cvss_score}", styles['Normal']))

                    # Evidence
                    if finding.evidence:
                        story.append(Paragraph("<b>Evidence:</b>", styles['Normal']))
                        for evidence in finding.evidence[:3]:  # Limit evidence items
                            # Escape HTML entities in evidence
                            safe_evidence = evidence.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                            story.append(Paragraph(f"• {safe_evidence}", styles['Normal']))

                    # POC Code
                    poc_code = self.generate_poc_code(finding)
                    if poc_code and poc_code != "# No specific POC available for this finding":
                        story.append(Paragraph("<b>Proof of Concept:</b>", styles['Normal']))
                        # Escape HTML entities in POC code and truncate if too long
                        safe_poc = poc_code.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        if len(safe_poc) > 1000:
                            safe_poc = safe_poc[:1000] + "..."
                        story.append(Paragraph(f"<font name='Courier' size=8>{safe_poc}</font>", styles['Normal']))

                    story.append(Spacer(1, 20))
                    finding_counter += 1

                story.append(PageBreak())

        # Risk Assessment
        story.append(Paragraph("Risk Assessment", heading_style))

        risk_score = (
            severity_counts.get('CRITICAL', 0) * 10 +
            severity_counts.get('HIGH', 0) * 7 +
            severity_counts.get('MEDIUM', 0) * 4 +
            severity_counts.get('LOW', 0) * 2 +
            severity_counts.get('INFO', 0) * 1
        )

        if risk_score >= 50:
            risk_level = "HIGH RISK"
            risk_color = colors.red
        elif risk_score >= 25:
            risk_level = "MEDIUM RISK"
            risk_color = colors.orange
        elif risk_score >= 10:
            risk_level = "LOW RISK"
            risk_color = colors.yellow
        else:
            risk_level = "MINIMAL RISK"
            risk_color = colors.green

        story.append(Paragraph(f"Overall Risk Level: <b>{risk_level}</b>", styles['Normal']))
        story.append(Paragraph(f"Risk Score: {risk_score}/100", styles['Normal']))

        # Recommendations Summary
        story.append(Spacer(1, 20))
        story.append(Paragraph("Key Recommendations", styles['Heading3']))

        key_recommendations = [
            "Review and address all CRITICAL and HIGH severity findings immediately",
            "Implement secure coding practices to prevent injection vulnerabilities",
            "Use strong cryptographic algorithms and proper key management",
            "Disable debug mode and remove development artifacts from production builds",
            "Implement proper input validation and output encoding",
            "Regular security testing and code reviews",
            "Keep all dependencies and libraries updated"
        ]

        for rec in key_recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))

        # Build PDF
        doc.build(story)

        self.logger.info(f"PDF report generated: {report_path}")
        return str(report_path)

    def analyze_mobile_app(self, app_path: str) -> str:
        """Main analysis function that coordinates all security checks"""
        app_path = Path(app_path)

        if not app_path.exists():
            raise FileNotFoundError(f"Application file not found: {app_path}")

        self.logger.info(f"Starting security analysis of {app_path.name}")

        # Reset findings for new analysis
        self.findings = []

        # Extract metadata
        if app_path.suffix.lower() == '.apk':
            self.metadata = self.extract_apk_metadata(app_path)
            self.findings.extend(self.analyze_apk_static(app_path))
        elif app_path.suffix.lower() == '.ipa':
            self.metadata = self.extract_ipa_metadata(app_path)
            self.findings.extend(self.analyze_ipa_static(app_path))
        else:
            raise ValueError(f"Unsupported file type: {app_path.suffix}")

        self.logger.info(f"Analysis complete. Found {len(self.findings)} security issues.")

        # Generate PDF report
        report_path = self.generate_pdf_report(app_path)

        return report_path

def main():
    """Main function to run comprehensive mobile security analysis"""

    # Application paths
    apps_to_analyze = [
        "~/Downloads/H4C.apk",
        "~/Downloads/H4D.apk",
        "~/Downloads/H4C.ipa"
    ]

    analyzer = MobileSecurityAnalyzer()

    print("🔒 Comprehensive Mobile Security Analyzer")
    print("=" * 50)

    for app_path in apps_to_analyze:
        expanded_path = Path(app_path).expanduser()

        print(f"\n📱 Analyzing: {expanded_path.name}")

        if not expanded_path.exists():
            print(f"❌ File not found: {expanded_path}")
            continue

        try:
            report_path = analyzer.analyze_mobile_app(str(expanded_path))
            print(f"✅ Analysis complete. Report saved to: {report_path}")

        except Exception as e:
            print(f"❌ Analysis failed for {expanded_path.name}: {str(e)}")
            # Create error report
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                error_report = analyzer.output_dir / f"{expanded_path.stem}_error_report_{timestamp}.txt"
                with open(error_report, 'w') as f:
                    f.write(f"Error analyzing {expanded_path.name}\n")
                    f.write(f"Error: {str(e)}\n")
                    f.write(f"Timestamp: {datetime.now()}\n")
                print(f"Error report saved to: {error_report}")
            except:
                pass

    print(f"\n🎉 Analysis complete! All reports saved to: {analyzer.output_dir}")

if __name__ == "__main__":
    main()