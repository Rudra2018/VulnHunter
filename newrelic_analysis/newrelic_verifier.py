#!/usr/bin/env python3
"""
New Relic Agent Vulnerability Verifier
Rigorous verification with false positive detection for agent-specific patterns
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict

@dataclass
class VerificationResult:
    original_finding: Dict
    file_exists: bool
    line_verified: bool
    is_false_positive: bool
    false_positive_reason: str
    actual_line: str
    verification_status: str
    confidence_adjusted: float

class NewRelicVerifier:
    """
    Verifies New Relic agent vulnerability findings with agent-specific false positive detection
    """

    def __init__(self, repo_path: str, results_file: str, agent_name: str):
        self.repo_path = Path(repo_path)
        self.results_file = results_file
        self.agent_name = agent_name

        # Load scan results
        with open(results_file, 'r') as f:
            self.scan_data = json.load(f)

        self.verified_results: List[VerificationResult] = []
        self.stats = defaultdict(int)

        # Test/example patterns
        self.test_patterns = [
            r'/tests?/',
            r'/test/',
            r'_test\.(py|js|go)$',
            r'\.test\.',
            r'\.spec\.',
            r'/examples?/',
            r'/sample',
            r'/fixtures/',
            r'/mocks?/',
            r'testing_support',
            r'cross_agent_tests',
        ]

    def is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file"""
        for pattern in self.test_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def detect_agent_false_positive(self, category: str, line_content: str,
                                    actual_line: str, file_path: str,
                                    context: List[str]) -> Tuple[bool, str]:
        """
        Agent-specific false positive detection
        """

        # Test files are always false positives for bug bounty
        if self.is_test_file(file_path):
            return (True, 'test_or_example_file')

        # Category-specific checks
        if category == "Hardcoded Credentials":
            # Test data, example keys
            if any(keyword in line_content.lower() for keyword in [
                'test', 'example', 'sample', 'fake', 'mock', 'dummy',
                'your_key_here', 'insert_key_here', 'license_key_here'
            ]):
                return (True, 'test_or_example_credential')

            # Variable declarations without actual keys
            if re.search(r'(license_key|api_key|apiKey)\s*[:=]\s*["\']?$', line_content):
                return (True, 'empty_key_declaration')

            # Environment variable references
            if any(pattern in line_content for pattern in [
                'os.environ', 'process.env', 'ENV[', 'getenv'
            ]):
                return (True, 'environment_variable_reference')

        if category == "Insecure Data Transmission":
            # Debug/testing SSL disable
            if any(keyword in file_path.lower() or keyword in line_content.lower()
                   for keyword in ['test', 'debug', 'development']):
                return (True, 'debug_or_test_ssl_disable')

            # Configuration option (not default enabled)
            if 'debug.disable_certificate_validation' in line_content:
                # This is a config option, not a default setting
                return (True, 'optional_debug_configuration')

            # Requests/urllib with verify parameter but not hardcoded False
            if 'verify' in line_content and 'False' not in actual_line:
                return (True, 'configurable_ssl_verification')

        if category == "Command Injection":
            # eval() with controlled input
            if 'eval' in line_content:
                # Check if input is sanitized or controlled
                for ctx_line in context:
                    if any(safe in ctx_line for safe in [
                        'lambda ', 'callable_vars', 'safe_eval',
                        '# noqa', '# nosec'
                    ]):
                        # Note: eval() CAN still be vulnerable even with # noqa
                        # Only mark as FP if clearly controlled scope
                        if 'callable_vars' in ctx_line or 'lambda ' in line_content:
                            return (True, 'controlled_eval_scope')

            # subprocess with literal strings
            if 'subprocess' in line_content or 'exec(' in line_content:
                # Check if using literal commands
                if re.search(r'(subprocess|exec)\(["\']', line_content):
                    return (True, 'literal_command_string')

        if category == "SQL Injection":
            # String formatting in non-SQL contexts
            if any(keyword in line_content.lower() for keyword in [
                'query = "select', 'sql = "select'
            ]) and '+' in line_content:
                # Check if it's parameterized
                for ctx_line in context:
                    if any(safe in ctx_line for safe in ['?', '%s', 'execute(', 'bind']):
                        return (True, 'parameterized_query')

            # Error messages with string concat (not SQL)
            if any(keyword in line_content for keyword in [
                'throw', 'error', 'Error(', 'raise', 'Exception'
            ]):
                return (True, 'error_message_not_sql')

            # URL building (not SQL)
            if 'http' in line_content.lower() or 'url' in line_content.lower():
                return (True, 'url_building_not_sql')

        if category == "Weak Cryptography":
            # MD5 for checksums (not crypto)
            if 'md5' in line_content.lower():
                for ctx_line in context:
                    if any(keyword in ctx_line.lower() for keyword in [
                        'checksum', 'hash', 'digest', 'fingerprint', 'etag'
                    ]):
                        return (True, 'md5_for_checksum_not_crypto')

        if category == "Path Traversal":
            # Path joining with safe methods
            if any(safe in line_content for safe in [
                'os.path.join', 'path.join', 'pathlib', 'Path('
            ]):
                return (True, 'safe_path_joining')

        if category == "Information Disclosure":
            # Logging in development/debug mode
            if any(keyword in file_path.lower() for keyword in ['debug', 'test']):
                return (True, 'debug_or_test_logging')

        return (False, '')

    def verify_finding(self, finding: Dict) -> VerificationResult:
        """
        Verify a single finding against local repository
        """
        file_path = finding['file']
        line_number = finding['line_number']
        line_content = finding['line_content']
        category = finding['category']
        context = finding.get('context', [])

        result = VerificationResult(
            original_finding=finding,
            file_exists=False,
            line_verified=False,
            is_false_positive=False,
            false_positive_reason='',
            actual_line='',
            verification_status='PENDING',
            confidence_adjusted=finding.get('confidence', 0.0)
        )

        # Check if file exists
        full_path = self.repo_path / file_path
        if not full_path.exists():
            result.verification_status = 'FILE_NOT_FOUND'
            self.stats['file_not_found'] += 1
            return result

        result.file_exists = True
        self.stats['files_verified'] += 1

        try:
            # Read file content
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Verify line number and content
            if line_number <= len(lines):
                actual_line = lines[line_number - 1]
                result.actual_line = actual_line.strip()

                # Check if line content matches (fuzzy match)
                if line_content.strip() in actual_line or actual_line.strip() in line_content:
                    result.line_verified = True
                    self.stats['lines_verified'] += 1

                # Detect false positives
                is_fp, fp_reason = self.detect_agent_false_positive(
                    category, line_content, actual_line, file_path, context
                )

                if is_fp:
                    result.is_false_positive = True
                    result.false_positive_reason = fp_reason
                    result.confidence_adjusted = 0.0
                    result.verification_status = 'FALSE_POSITIVE'
                    self.stats['false_positives'] += 1
                else:
                    result.verification_status = 'VERIFIED'
                    self.stats['verified_vulnerabilities'] += 1
            else:
                result.verification_status = 'LINE_OUT_OF_RANGE'

        except Exception as e:
            result.verification_status = f'ERROR: {str(e)[:50]}'

        return result

    def verify_all(self) -> None:
        """
        Verify all findings
        """
        print(f"\n{'='*80}")
        print(f"New Relic {self.agent_name} Agent Vulnerability Verification")
        print(f"{'='*80}")

        all_vulns = self.scan_data.get('all_vulnerabilities', [])
        total = len(all_vulns)

        print(f"Verifying all {total} findings against local repository")
        print(f"Repository: {self.repo_path}\n")

        # Verify each finding
        for idx, vuln in enumerate(all_vulns, 1):
            if idx % 20 == 0:
                print(f"Progress: {idx}/{total} ({idx*100//total}%)")

            result = self.verify_finding(vuln)
            self.verified_results.append(result)

        # Print statistics
        print(f"\n{'='*80}")
        print("Verification Statistics")
        print(f"{'='*80}")
        print(f"Total findings processed: {len(self.verified_results)}")
        print(f"Files verified: {self.stats['files_verified']}")
        print(f"Lines verified: {self.stats['lines_verified']}")
        print(f"False positives identified: {self.stats['false_positives']}")
        print(f"Verified vulnerabilities: {self.stats['verified_vulnerabilities']}")
        print(f"Files not found: {self.stats['file_not_found']}")

        # False positive breakdown
        if self.stats['false_positives'] > 0:
            print(f"\n{'='*80}")
            print("False Positive Breakdown")
            print(f"{'='*80}")

            fp_reasons = defaultdict(int)
            for result in self.verified_results:
                if result.is_false_positive:
                    fp_reasons[result.false_positive_reason] += 1

            for reason, count in sorted(fp_reasons.items(), key=lambda x: x[1], reverse=True):
                print(f"{reason:50s} {count:4d}")

    def save_results(self, output_file: str) -> None:
        """
        Save verification results
        """
        # Separate verified vulnerabilities from false positives
        verified_vulns = [
            r for r in self.verified_results
            if not r.is_false_positive and r.verification_status == 'VERIFIED'
        ]

        false_positives = [
            r for r in self.verified_results
            if r.is_false_positive
        ]

        report = {
            'verification_date': self.scan_data['scan_date'],
            'agent_name': self.agent_name,
            'repository': str(self.repo_path),
            'total_findings': len(self.verified_results),
            'verified_vulnerabilities': len(verified_vulns),
            'false_positives': len(false_positives),
            'statistics': dict(self.stats),
            'verified_vulnerabilities_list': [asdict(v) for v in verified_vulns],
            'false_positives_list': [asdict(v) for v in false_positives],
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n✓ Verification results saved: {output_file}")

        # Print final summary
        print(f"\n{'='*80}")
        print("FINAL VERIFICATION SUMMARY")
        print(f"{'='*80}")
        print(f"✓ Verified Vulnerabilities: {len(verified_vulns)}")
        print(f"✗ False Positives: {len(false_positives)}")
        if len(self.verified_results) > 0:
            print(f"⚠ True Positive Rate: {len(verified_vulns)*100/len(self.verified_results):.1f}%")

        if len(verified_vulns) > 0:
            # Show verified vulnerabilities by category
            print(f"\n{'='*80}")
            print("Verified Vulnerabilities by Category")
            print(f"{'='*80}")

            by_category = defaultdict(list)
            for v in verified_vulns:
                by_category[v.original_finding['category']].append(v)

            for category, vulns in sorted(by_category.items(), key=lambda x: len(x[1]), reverse=True):
                # Count default config impact
                default_count = len([v for v in vulns if v.original_finding.get('default_config_impact')])
                print(f"{category:40s} {len(vulns):4d} ({default_count} default config)")

            # Show top 10 verified vulnerabilities
            print(f"\n{'='*80}")
            print("Top 10 Verified Vulnerabilities")
            print(f"{'='*80}")

            critical_vulns = [v for v in verified_vulns if v.original_finding['severity'] == 'CRITICAL']
            high_vulns = [v for v in verified_vulns if v.original_finding['severity'] == 'HIGH']
            top_vulns = (critical_vulns + high_vulns)[:10]

            for idx, result in enumerate(top_vulns, 1):
                vuln = result.original_finding
                print(f"\n{idx}. {vuln['category']} - {vuln['severity']}")
                print(f"   File: {vuln['file']}:{vuln['line_number']}")
                print(f"   Code: {vuln['line_content'][:80]}")
                print(f"   CWE: {vuln['cwe']}")
                if vuln.get('default_config_impact'):
                    print(f"   ⚠️  DEFAULT CONFIG IMPACT")
        else:
            print(f"\n✅ No verified vulnerabilities found after rigorous verification!")
            print(f"   All {len(false_positives)} findings were false positives.")

def main():
    import sys

    if len(sys.argv) < 4:
        print("Usage: python newrelic_verifier.py <repo_path> <results_file> <agent_name>")
        sys.exit(1)

    repo_path = sys.argv[1]
    results_file = sys.argv[2]
    agent_name = sys.argv[3]

    verifier = NewRelicVerifier(repo_path, results_file, agent_name)
    verifier.verify_all()
    verifier.save_results(f'{agent_name}_verified_results.json')

if __name__ == '__main__':
    main()
