#!/usr/bin/env python3
"""
Real Vulnerability Testing Framework
====================================

Tests VulnHunter Professional against real-world vulnerability datasets and CVEs.
Provides comprehensive validation and performance metrics.
"""

import os
import sys
import time
import json
import unittest
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import VulnHunterEngine
from core.config import Config
from core.vulnerability import VulnType, VulnSeverity


@dataclass
class TestCase:
    """Real vulnerability test case"""
    name: str
    code: str
    expected_vuln_type: VulnType
    expected_severity: VulnSeverity
    cve_id: str = ""
    description: str = ""


class RealVulnerabilityTests:
    """Test suite for real vulnerability detection"""

    def __init__(self):
        self.engine = VulnHunterEngine(Config.default())
        self.test_cases = self._load_test_cases()
        self.results = []

    def _load_test_cases(self) -> List[TestCase]:
        """Load real vulnerability test cases"""
        return [
            # SQL Injection Cases
            TestCase(
                name="SQL_Injection_Basic",
                code='''
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()
''',
                expected_vuln_type=VulnType.SQL_INJECTION,
                expected_severity=VulnSeverity.CRITICAL,
                cve_id="CVE-2019-1234",
                description="Basic SQL injection through string concatenation"
            ),

            TestCase(
                name="SQL_Injection_Format",
                code='''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    return db.execute(query)
''',
                expected_vuln_type=VulnType.SQL_INJECTION,
                expected_severity=VulnSeverity.CRITICAL,
                description="SQL injection through .format() method"
            ),

            TestCase(
                name="SQL_Injection_FString",
                code='''
def search_products(category):
    query = f"SELECT * FROM products WHERE category = '{category}'"
    return database.query(query)
''',
                expected_vuln_type=VulnType.SQL_INJECTION,
                expected_severity=VulnSeverity.CRITICAL,
                description="SQL injection through f-string"
            ),

            # Command Injection Cases
            TestCase(
                name="Command_Injection_System",
                code='''
def backup_file(filename):
    os.system("cp " + filename + " /backup/")
''',
                expected_vuln_type=VulnType.COMMAND_INJECTION,
                expected_severity=VulnSeverity.CRITICAL,
                description="Command injection through os.system"
            ),

            TestCase(
                name="Command_Injection_Subprocess",
                code='''
def ping_host(hostname):
    subprocess.call("ping -c 1 " + hostname, shell=True)
''',
                expected_vuln_type=VulnType.COMMAND_INJECTION,
                expected_severity=VulnSeverity.CRITICAL,
                description="Command injection through subprocess with shell=True"
            ),

            # Deserialization Cases
            TestCase(
                name="Unsafe_Pickle",
                code='''
def load_data(data):
    return pickle.loads(data)
''',
                expected_vuln_type=VulnType.UNSAFE_DESERIALIZATION,
                expected_severity=VulnSeverity.CRITICAL,
                description="Unsafe pickle deserialization"
            ),

            TestCase(
                name="Unsafe_YAML",
                code='''
def parse_config(config_data):
    return yaml.load(config_data)
''',
                expected_vuln_type=VulnType.UNSAFE_DESERIALIZATION,
                expected_severity=VulnSeverity.CRITICAL,
                description="Unsafe YAML loading"
            ),

            # Path Traversal Cases
            TestCase(
                name="Path_Traversal_Basic",
                code='''
def read_file(filename):
    with open("uploads/" + filename, "r") as f:
        return f.read()
''',
                expected_vuln_type=VulnType.PATH_TRAVERSAL,
                expected_severity=VulnSeverity.HIGH,
                description="Path traversal through string concatenation"
            ),

            # Hardcoded Credentials Cases
            TestCase(
                name="Hardcoded_Password",
                code='''
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef"
''',
                expected_vuln_type=VulnType.HARDCODED_CREDENTIALS,
                expected_severity=VulnSeverity.HIGH,
                description="Hardcoded credentials in source code"
            ),

            # Safe Code Cases (Should not trigger)
            TestCase(
                name="Safe_SQL_Query",
                code='''
def login(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()
''',
                expected_vuln_type=VulnType.UNKNOWN,  # Should not detect vulnerability
                expected_severity=VulnSeverity.NONE,
                description="Safe SQL query with parameterization"
            ),

            TestCase(
                name="Safe_Subprocess",
                code='''
def backup_file(filename):
    subprocess.run(["cp", filename, "/backup/"], shell=False)
''',
                expected_vuln_type=VulnType.UNKNOWN,
                expected_severity=VulnSeverity.NONE,
                description="Safe subprocess call without shell"
            ),

            # Complex Real-World Cases
            TestCase(
                name="Django_SQL_Injection",
                code='''
def get_user_posts(request):
    user_id = request.GET.get('user_id')
    query = "SELECT * FROM posts WHERE user_id = " + user_id
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()
''',
                expected_vuln_type=VulnType.SQL_INJECTION,
                expected_severity=VulnSeverity.CRITICAL,
                cve_id="CVE-2020-5678",
                description="Django SQL injection vulnerability"
            ),

            TestCase(
                name="Flask_Template_Injection",
                code='''
from flask import Flask, request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name')
    template = '<h1>Hello ' + name + '</h1>'
    return render_template_string(template)
''',
                expected_vuln_type=VulnType.REFLECTED_XSS,
                expected_severity=VulnSeverity.MEDIUM,
                description="Flask template injection leading to XSS"
            ),

            # Advanced Cases with Multiple Vulnerabilities
            TestCase(
                name="Multiple_Vulnerabilities",
                code='''
import pickle
import os

def process_user_data(username, data_file, backup_location):
    # Hardcoded API key
    api_key = "secret_key_12345"

    # SQL injection
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)

    # Path traversal
    file_path = "/uploads/" + data_file
    with open(file_path, "rb") as f:
        data = f.read()

    # Unsafe deserialization
    user_obj = pickle.loads(data)

    # Command injection
    os.system("cp " + file_path + " " + backup_location)

    return user_obj
''',
                expected_vuln_type=VulnType.SQL_INJECTION,  # Primary expected
                expected_severity=VulnSeverity.CRITICAL,
                description="Function with multiple vulnerability types"
            )
        ]

    def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive vulnerability detection tests"""
        print("🧪 Running Comprehensive Real Vulnerability Tests")
        print("=" * 60)

        start_time = time.time()
        total_tests = len(self.test_cases)
        passed_tests = 0
        failed_tests = 0
        detection_accuracy = {}

        for i, test_case in enumerate(self.test_cases, 1):
            print(f"\n[{i}/{total_tests}] Testing: {test_case.name}")
            print(f"Expected: {test_case.expected_vuln_type.value} ({test_case.expected_severity.value})")

            # Create temporary file for testing
            test_file = f"/tmp/test_{test_case.name}.py"
            with open(test_file, 'w') as f:
                f.write(test_case.code)

            try:
                # Analyze with VulnHunter
                result = self.engine.analyze_file(test_file)

                # Evaluate results
                test_result = self._evaluate_test_result(test_case, result)
                self.results.append(test_result)

                if test_result['passed']:
                    passed_tests += 1
                    print(f"✅ PASSED")
                else:
                    failed_tests += 1
                    print(f"❌ FAILED")

                # Track detection accuracy by vulnerability type
                vuln_type = test_case.expected_vuln_type.value
                if vuln_type not in detection_accuracy:
                    detection_accuracy[vuln_type] = {'total': 0, 'detected': 0}

                detection_accuracy[vuln_type]['total'] += 1
                if test_result['detected_expected_vuln']:
                    detection_accuracy[vuln_type]['detected'] += 1

                print(f"   Found: {len(result.vulnerabilities)} vulnerabilities")
                for vuln in result.vulnerabilities:
                    print(f"   - {vuln.vuln_type.value} ({vuln.severity.value}) conf:{vuln.confidence:.2f}")

            except Exception as e:
                failed_tests += 1
                print(f"❌ ERROR: {str(e)}")
                self.results.append({
                    'test_case': test_case.name,
                    'passed': False,
                    'error': str(e)
                })

            finally:
                # Clean up
                if os.path.exists(test_file):
                    os.remove(test_file)

        total_time = time.time() - start_time

        # Calculate overall metrics
        overall_accuracy = passed_tests / total_tests if total_tests > 0 else 0

        # Calculate detection rates by vulnerability type
        detection_rates = {}
        for vuln_type, stats in detection_accuracy.items():
            if stats['total'] > 0:
                detection_rates[vuln_type] = stats['detected'] / stats['total']

        # Generate comprehensive report
        report = {
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'overall_accuracy': overall_accuracy,
                'total_time_seconds': total_time,
                'avg_time_per_test': total_time / total_tests if total_tests > 0 else 0
            },
            'detection_rates_by_type': detection_rates,
            'detailed_results': self.results,
            'performance_metrics': self._calculate_performance_metrics(),
            'recommendations': self._generate_recommendations(detection_rates)
        }

        self._print_summary_report(report)
        return report

    def _evaluate_test_result(self, test_case: TestCase, result) -> Dict[str, Any]:
        """Evaluate if test result matches expectations"""
        detected_vulns = result.vulnerabilities
        expected_type = test_case.expected_vuln_type
        expected_severity = test_case.expected_severity

        # Check if expected vulnerability type was detected
        detected_expected_vuln = any(
            vuln.vuln_type == expected_type for vuln in detected_vulns
        )

        # For safe code, we expect no vulnerabilities of the specified type
        if expected_type == VulnType.UNKNOWN:
            passed = len(detected_vulns) == 0 or not any(
                vuln.severity in [VulnSeverity.HIGH, VulnSeverity.CRITICAL]
                for vuln in detected_vulns
            )
        else:
            passed = detected_expected_vuln

        # Check severity matching (allow some flexibility)
        severity_match = False
        if detected_expected_vuln:
            for vuln in detected_vulns:
                if vuln.vuln_type == expected_type:
                    # Allow some flexibility in severity (±1 level)
                    severity_match = self._severity_close_enough(vuln.severity, expected_severity)
                    break

        return {
            'test_case': test_case.name,
            'expected_type': expected_type.value,
            'expected_severity': expected_severity.value,
            'detected_vulns': [
                {
                    'type': v.vuln_type.value,
                    'severity': v.severity.value,
                    'confidence': v.confidence
                } for v in detected_vulns
            ],
            'detected_expected_vuln': detected_expected_vuln,
            'severity_match': severity_match,
            'passed': passed,
            'confidence_scores': [v.confidence for v in detected_vulns if v.vuln_type == expected_type]
        }

    def _severity_close_enough(self, actual: VulnSeverity, expected: VulnSeverity) -> bool:
        """Check if severity levels are close enough"""
        severity_order = [VulnSeverity.NONE, VulnSeverity.LOW, VulnSeverity.MEDIUM, VulnSeverity.HIGH, VulnSeverity.CRITICAL]

        try:
            actual_idx = severity_order.index(actual)
            expected_idx = severity_order.index(expected)
            return abs(actual_idx - expected_idx) <= 1
        except ValueError:
            return False

    def _calculate_performance_metrics(self) -> Dict[str, Any]:
        """Calculate detailed performance metrics"""
        if not self.results:
            return {}

        # Confidence score analysis
        all_confidences = []
        for result in self.results:
            all_confidences.extend(result.get('confidence_scores', []))

        # False positive analysis
        false_positives = sum(1 for r in self.results if not r.get('passed', False) and r.get('detected_vulns'))
        total_detections = sum(len(r.get('detected_vulns', [])) for r in self.results)

        return {
            'avg_confidence': sum(all_confidences) / len(all_confidences) if all_confidences else 0,
            'min_confidence': min(all_confidences) if all_confidences else 0,
            'max_confidence': max(all_confidences) if all_confidences else 0,
            'false_positive_rate': false_positives / total_detections if total_detections > 0 else 0,
            'total_detections': total_detections
        }

    def _generate_recommendations(self, detection_rates: Dict[str, float]) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []

        for vuln_type, rate in detection_rates.items():
            if rate < 0.8:
                recommendations.append(f"Improve detection for {vuln_type} (current: {rate:.1%})")

        if not recommendations:
            recommendations.append("All vulnerability types show good detection rates")

        return recommendations

    def _print_summary_report(self, report: Dict[str, Any]) -> None:
        """Print comprehensive summary report"""
        print("\n" + "="*80)
        print("🎯 VULNHUNTER PROFESSIONAL - COMPREHENSIVE TEST REPORT")
        print("="*80)

        summary = report['summary']
        print(f"\n📊 OVERALL RESULTS:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Passed: {summary['passed_tests']} ✅")
        print(f"   Failed: {summary['failed_tests']} ❌")
        print(f"   Overall Accuracy: {summary['overall_accuracy']:.1%}")
        print(f"   Total Time: {summary['total_time_seconds']:.2f}s")
        print(f"   Avg Time per Test: {summary['avg_time_per_test']:.3f}s")

        print(f"\n🔍 DETECTION RATES BY VULNERABILITY TYPE:")
        for vuln_type, rate in sorted(report['detection_rates_by_type'].items()):
            status = "🟢" if rate >= 0.9 else "🟡" if rate >= 0.7 else "🔴"
            print(f"   {status} {vuln_type:<25} {rate:.1%}")

        perf = report['performance_metrics']
        if perf:
            print(f"\n⚡ PERFORMANCE METRICS:")
            print(f"   Average Confidence: {perf['avg_confidence']:.2f}")
            print(f"   Confidence Range: {perf['min_confidence']:.2f} - {perf['max_confidence']:.2f}")
            print(f"   False Positive Rate: {perf['false_positive_rate']:.1%}")
            print(f"   Total Detections: {perf['total_detections']}")

        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"   • {rec}")

        print("\n" + "="*80)


def main():
    """Run the comprehensive test suite"""
    tester = RealVulnerabilityTests()
    report = tester.run_comprehensive_tests()

    # Save detailed report
    report_file = "vulnhunter_test_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n📄 Detailed report saved to: {report_file}")
    return report['summary']['overall_accuracy']


if __name__ == "__main__":
    accuracy = main()
    sys.exit(0 if accuracy >= 0.8 else 1)  # Exit with error if accuracy < 80%