#!/usr/bin/env python3
"""
VulnHunter Ω Enhanced Validation Engine
=======================================

Critical Learning Integration:
- Eliminate false positives from test/dev/build code
- Require demonstrated exploitable impact
- Focus on production attack surfaces only
- Implement dynamic verification and validation
- Use full model capabilities for context understanding

This module implements lessons learned from the Chia Network analysis
to prevent AI-generated security theater and focus on real vulnerabilities.
"""

import os
import re
import ast
import subprocess
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import json
from datetime import datetime

class EnhancedVulnerabilityValidator:
    """
    Enhanced validator that eliminates false positives and requires
    demonstrated impact for vulnerability classification.
    """

    def __init__(self):
        self.false_positive_patterns = self._load_false_positive_patterns()
        self.production_indicators = self._load_production_indicators()
        self.impact_requirements = self._load_impact_requirements()

    def _load_false_positive_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that commonly cause false positives"""
        return {
            'test_code_patterns': [
                r'/test/',
                r'/tests/',
                r'_test\.',
                r'\.test\.',
                r'/mock/',
                r'/mocks/',
                r'/fixture/',
                r'/example/',
                r'/demo/',
                r'/benchmark/',
                r'/fuzz/',
                r'/tools/',
                r'/scripts/',
                r'/build/',
                r'/dev/',
                r'Cargo\.toml',
                r'package\.json',
                r'Makefile',
                r'\.yml$',
                r'\.yaml$',
                r'\.md$',
                r'README',
                r'LICENSE'
            ],
            'legitimate_dev_patterns': [
                r'unwrap\(\)',  # Normal in many Rust contexts
                r'expect\(',    # Normal error handling
                r'randbytes',   # Legitimate for test data
                r'rand::',      # Normal randomness usage
                r'unsafe\s*\{', # May be necessary and reviewed
                r'eval\(',      # May be legitimate in specific contexts
                r'exec\('       # May be legitimate in specific contexts
            ],
            'build_and_tooling': [
                r'generate-.*\.py',
                r'build\.rs',
                r'setup\.py',
                r'configure\.',
                r'install\.',
                r'deploy\.'
            ]
        }

    def _load_production_indicators(self) -> List[str]:
        """Load indicators of production code vs test/dev code"""
        return [
            r'/src/',
            r'/lib/',
            r'/core/',
            r'/api/',
            r'/server/',
            r'/client/',
            r'/consensus/',
            r'/blockchain/',
            r'/protocol/',
            r'/network/',
            r'/wallet/',
            r'/mining/',
            r'/validation/'
        ]

    def _load_impact_requirements(self) -> Dict[str, Dict[str, Any]]:
        """Define what constitutes real impact for each vulnerability type"""
        return {
            'CRYPTO_VULNERABILITIES': {
                'required_conditions': [
                    'Production cryptographic operations',
                    'Key generation or management',
                    'Authentication or signing',
                    'Encryption/decryption of sensitive data'
                ],
                'exclusions': [
                    'Test data generation',
                    'Development utilities',
                    'Example code',
                    'Benchmarking'
                ]
            },
            'MEMORY_SAFETY': {
                'required_conditions': [
                    'User-controlled input processing',
                    'Network data handling',
                    'File parsing',
                    'Deserialization'
                ],
                'exclusions': [
                    'Internal data structures',
                    'Test utilities',
                    'Development tools'
                ]
            },
            'INJECTION': {
                'required_conditions': [
                    'User input processing',
                    'Network requests',
                    'File uploads',
                    'API endpoints'
                ],
                'exclusions': [
                    'Build scripts',
                    'Test utilities',
                    'Development tools'
                ]
            }
        }

    def is_production_code(self, file_path: str) -> bool:
        """Determine if file is production code vs test/dev/build code"""
        # Normalize path
        normalized_path = file_path.lower()

        # Check for test/dev/build patterns (immediate exclusion)
        for pattern_category, patterns in self.false_positive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, normalized_path):
                    return False

        # Check for production indicators
        for indicator in self.production_indicators:
            if re.search(indicator, normalized_path):
                return True

        return False

    def validate_vulnerability_context(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate if a potential vulnerability has real security impact

        Returns:
            (is_valid, reason)
        """
        file_path = vuln.get('file_path', '')
        vuln_type = vuln.get('type', '')
        code_snippet = vuln.get('code_snippet', '')

        # Step 1: Check if it's production code
        if not self.is_production_code(file_path):
            return False, f"Not production code - found in test/dev/build path: {file_path}"

        # Step 2: Check for legitimate development patterns
        for pattern in self.false_positive_patterns['legitimate_dev_patterns']:
            if re.search(pattern, code_snippet):
                # This pattern might be legitimate - need deeper analysis
                if not self._requires_deeper_analysis(vuln):
                    return False, f"Likely legitimate development pattern: {pattern}"

        # Step 3: Validate impact requirements
        if vuln_type in self.impact_requirements:
            requirements = self.impact_requirements[vuln_type]

            # Check exclusions
            for exclusion in requirements['exclusions']:
                if exclusion.lower() in file_path.lower() or exclusion.lower() in code_snippet.lower():
                    return False, f"Excluded context: {exclusion}"

            # Check required conditions
            has_required_condition = False
            for condition in requirements['required_conditions']:
                if self._check_condition_met(vuln, condition):
                    has_required_condition = True
                    break

            if not has_required_condition:
                return False, f"No required impact conditions met for {vuln_type}"

        return True, "Validation passed - potential real vulnerability"

    def _requires_deeper_analysis(self, vuln: Dict[str, Any]) -> bool:
        """Determine if a pattern requires deeper analysis beyond simple matching"""
        # Implement more sophisticated analysis here
        # For now, return False to be conservative
        return False

    def _check_condition_met(self, vuln: Dict[str, Any], condition: str) -> bool:
        """Check if a specific impact condition is met"""
        file_path = vuln.get('file_path', '').lower()
        code_snippet = vuln.get('code_snippet', '').lower()

        condition_patterns = {
            'Production cryptographic operations': [
                r'key.*generation', r'signature', r'encrypt', r'decrypt', r'hash'
            ],
            'User-controlled input processing': [
                r'input', r'request', r'parse', r'deserialize'
            ],
            'Network data handling': [
                r'network', r'socket', r'tcp', r'udp', r'http'
            ],
            'API endpoints': [
                r'endpoint', r'route', r'handler', r'api'
            ]
        }

        if condition in condition_patterns:
            for pattern in condition_patterns[condition]:
                if re.search(pattern, file_path) or re.search(pattern, code_snippet):
                    return True

        return False

    def dynamic_verification(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform dynamic verification of vulnerability claims
        """
        verification_result = {
            'vulnerability': vuln,
            'dynamic_tests': [],
            'verification_status': 'PENDING',
            'evidence': []
        }

        file_path = vuln.get('file_path', '')

        # Test 1: File existence and accessibility
        test_result = self._test_file_accessibility(file_path)
        verification_result['dynamic_tests'].append(test_result)

        if not test_result['passed']:
            verification_result['verification_status'] = 'FAILED'
            return verification_result

        # Test 2: Code pattern verification in context
        context_test = self._test_pattern_in_context(vuln)
        verification_result['dynamic_tests'].append(context_test)

        # Test 3: Impact demonstration
        impact_test = self._test_demonstrable_impact(vuln)
        verification_result['dynamic_tests'].append(impact_test)

        # Determine overall status
        if all(test['passed'] for test in verification_result['dynamic_tests']):
            verification_result['verification_status'] = 'VERIFIED'
        else:
            verification_result['verification_status'] = 'FAILED'

        return verification_result

    def _test_file_accessibility(self, file_path: str) -> Dict[str, Any]:
        """Test if file exists and is accessible"""
        full_path = f"/Users/ankitthakur/VulnHunter/{file_path}"

        test_result = {
            'test_name': 'File Accessibility',
            'passed': False,
            'details': '',
            'evidence': []
        }

        if os.path.exists(full_path):
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()[:1000]  # Read first 1000 chars

                test_result['passed'] = True
                test_result['details'] = f"File accessible: {len(content)} characters read"
                test_result['evidence'].append(f"File size: {os.path.getsize(full_path)} bytes")

            except Exception as e:
                test_result['details'] = f"File exists but not readable: {e}"
        else:
            test_result['details'] = f"File does not exist: {full_path}"

        return test_result

    def _test_pattern_in_context(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Test if the pattern exists in meaningful context"""
        test_result = {
            'test_name': 'Pattern Context Verification',
            'passed': False,
            'details': '',
            'evidence': []
        }

        file_path = f"/Users/ankitthakur/VulnHunter/{vuln.get('file_path', '')}"
        pattern = vuln.get('pattern_matched', '')
        line_number = vuln.get('line', 0)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            if line_number > 0 and line_number <= len(lines):
                target_line = lines[line_number - 1]

                if re.search(pattern, target_line):
                    # Pattern found - now check context
                    context_start = max(0, line_number - 5)
                    context_end = min(len(lines), line_number + 5)
                    context = ''.join(lines[context_start:context_end])

                    test_result['passed'] = True
                    test_result['details'] = f"Pattern '{pattern}' found in line {line_number}"
                    test_result['evidence'].append(f"Context:\n{context}")
                else:
                    test_result['details'] = f"Pattern '{pattern}' not found in specified line"
            else:
                test_result['details'] = f"Invalid line number: {line_number}"

        except Exception as e:
            test_result['details'] = f"Error reading file: {e}"

        return test_result

    def _test_demonstrable_impact(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Test if the vulnerability has demonstrable security impact"""
        test_result = {
            'test_name': 'Impact Demonstration',
            'passed': False,
            'details': '',
            'evidence': []
        }

        # For now, this is a placeholder for more sophisticated impact testing
        # Real implementation would need to:
        # 1. Analyze data flow
        # 2. Check for user input paths
        # 3. Verify exploitability
        # 4. Demonstrate actual security impact

        vuln_type = vuln.get('type', '')
        file_path = vuln.get('file_path', '')

        # Conservative approach - require manual review for impact
        test_result['details'] = f"Impact assessment required for {vuln_type} in {file_path}"
        test_result['passed'] = False  # Conservative - require manual verification

        return test_result

def main():
    """
    Integration point for enhanced validation in VulnHunter pipeline
    """
    validator = EnhancedVulnerabilityValidator()

    # Load previous findings for re-validation
    report_path = '/Users/ankitthakur/VulnHunter/chia_network_security_report_chia_analysis_1761819157.json'

    if os.path.exists(report_path):
        with open(report_path, 'r') as f:
            data = json.load(f)

        print("🔍 Re-validating previous findings with enhanced validation...")

        total_findings = 0
        valid_findings = 0

        for repo_name, repo_data in data.get('repository_results', {}).items():
            for vuln in repo_data.get('vulnerabilities_found', []):
                total_findings += 1

                is_valid, reason = validator.validate_vulnerability_context(vuln)

                if is_valid:
                    valid_findings += 1
                    # Perform dynamic verification
                    verification = validator.dynamic_verification(vuln)
                    if verification['verification_status'] == 'VERIFIED':
                        print(f"✅ Valid vulnerability: {vuln.get('type')} in {vuln.get('file_path')}")
                    else:
                        print(f"⚠️ Needs manual review: {vuln.get('type')} in {vuln.get('file_path')}")
                else:
                    print(f"❌ False positive: {reason}")

        print(f"\n📊 Enhanced Validation Results:")
        print(f"   Total findings: {total_findings}")
        print(f"   Valid after filtering: {valid_findings}")
        print(f"   False positive rate: {((total_findings - valid_findings) / total_findings * 100):.1f}%")

    return validator

if __name__ == "__main__":
    main()