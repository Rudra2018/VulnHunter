#!/usr/bin/env python3
"""
VulnHunter V4 Enhanced Model Validation Test
Comprehensive testing of the enhanced model against known patterns
"""

import json
import sys
import os
from pathlib import Path

# Add the model path to import the predictor
sys.path.append('/Users/ankitthakur/vuln_ml_research/data/models/vulnhunter_v4')

from vulnhunter_v4_enhanced_predictor import VulnHunterV4EnhancedPredictor

class ModelValidationTest:
    """Comprehensive validation testing for VulnHunter V4 Enhanced."""

    def __init__(self):
        """Initialize the validation test."""
        self.predictor = VulnHunterV4EnhancedPredictor()
        self.test_results = []

    def test_gemini_cli_false_positives(self):
        """Test against the Gemini CLI false positives we identified."""
        print("Testing Gemini CLI False Positive Detection...")

        gemini_fp_tests = [
            {
                "test_id": "GEMINI-001-FP",
                "description": "Command injection false positive from Gemini CLI analysis",
                "claim": {
                    "id": "GEMINI-001",
                    "file_path": "packages/core/src/ide/process-utils.ts",
                    "function_name": "executeCommand",
                    "line_number": 42,
                    "vulnerability_type": "command injection",
                    "severity": "Critical",
                    "confidence": 0.85,
                    "framework": "typescript"
                },
                "expected": "REJECT",
                "reason": "Function does not exist, file path fabricated"
            },
            {
                "test_id": "GEMINI-002-FP",
                "description": "Path traversal false positive",
                "claim": {
                    "id": "GEMINI-002",
                    "file_path": "packages/core/src/file-system/file-operations.ts",
                    "function_name": "readUserFile",
                    "line_number": 156,
                    "vulnerability_type": "path traversal",
                    "severity": "High",
                    "confidence": 0.78,
                    "framework": "node.js"
                },
                "expected": "REJECT",
                "reason": "File and function fabricated, actual implementation has security controls"
            },
            {
                "test_id": "GEMINI-004-FP",
                "description": "Input validation false positive with Express.js protection",
                "claim": {
                    "id": "GEMINI-004",
                    "file_path": "packages/a2a-server/src/api/endpoints.ts",
                    "function_name": "handleApiRequest",
                    "line_number": 203,
                    "vulnerability_type": "json parsing",
                    "severity": "Medium",
                    "confidence": 0.68,
                    "framework": "express"
                },
                "expected": "REJECT",
                "reason": "Express.js provides JSON middleware protection"
            }
        ]

        for test in gemini_fp_tests:
            result = self.predictor.analyze_vulnerability_claim(test["claim"])
            self._evaluate_test_result(test, result)

    def test_legitimate_vulnerabilities(self):
        """Test against legitimate vulnerability patterns."""
        print("Testing Legitimate Vulnerability Recognition...")

        legitimate_tests = [
            {
                "test_id": "LEGIT-001",
                "description": "Real SQL injection vulnerability",
                "claim": {
                    "id": "LEGIT-001",
                    "file_path": "src/auth/login.py",
                    "function_name": "authenticate_user",
                    "line_number": 45,
                    "vulnerability_type": "sql injection",
                    "severity": "Critical",
                    "confidence": 0.88,
                    "framework": "django"
                },
                "expected": "ACCEPT",
                "reason": "Realistic file path, function name, and vulnerability type"
            },
            {
                "test_id": "LEGIT-002",
                "description": "Real XSS vulnerability",
                "claim": {
                    "id": "LEGIT-002",
                    "file_path": "components/UserProfile.jsx",
                    "function_name": "renderUserContent",
                    "line_number": 78,
                    "vulnerability_type": "xss",
                    "severity": "High",
                    "confidence": 0.82,
                    "framework": "react"
                },
                "expected": "REVIEW",
                "reason": "React has some XSS protection, but vulnerability could still exist"
            }
        ]

        for test in legitimate_tests:
            result = self.predictor.analyze_vulnerability_claim(test["claim"])
            self._evaluate_test_result(test, result)

    def test_framework_protection_scenarios(self):
        """Test framework protection recognition."""
        print("Testing Framework Protection Recognition...")

        framework_tests = [
            {
                "test_id": "FRAMEWORK-001",
                "description": "Express.js JSON parsing protection",
                "claim": {
                    "id": "FRAMEWORK-001",
                    "file_path": "routes/api.js",
                    "function_name": "parseRequest",
                    "line_number": 25,
                    "vulnerability_type": "json parsing",
                    "severity": "Medium",
                    "confidence": 0.70,
                    "framework": "express"
                },
                "expected": "MEDIUM_RISK",
                "reason": "Express provides JSON middleware but vulnerability could still exist"
            },
            {
                "test_id": "FRAMEWORK-002",
                "description": "TypeScript type safety protection",
                "claim": {
                    "id": "FRAMEWORK-002",
                    "file_path": "src/utils/validator.ts",
                    "function_name": "validateInput",
                    "line_number": 30,
                    "vulnerability_type": "type confusion",
                    "severity": "Medium",
                    "confidence": 0.65,
                    "framework": "typescript"
                },
                "expected": "MEDIUM_RISK",
                "reason": "TypeScript provides type safety but runtime issues could exist"
            }
        ]

        for test in framework_tests:
            result = self.predictor.analyze_vulnerability_claim(test["claim"])
            self._evaluate_test_result(test, result)

    def test_statistical_realism(self):
        """Test statistical realism detection."""
        print("Testing Statistical Realism Detection...")

        realism_tests = [
            {
                "test_id": "REALISM-001",
                "description": "Unrealistic confidence for low severity",
                "claim": {
                    "id": "REALISM-001",
                    "file_path": "src/utils/helper.js",
                    "function_name": "formatDate",
                    "line_number": 10,
                    "vulnerability_type": "information disclosure",
                    "severity": "Low",
                    "confidence": 0.95,  # Too high for low severity
                    "framework": "node.js"
                },
                "expected": "REVIEW",
                "reason": "Confidence too high for low severity issue"
            },
            {
                "test_id": "REALISM-002",
                "description": "Artificial precision in confidence",
                "claim": {
                    "id": "REALISM-002",
                    "file_path": "src/auth/token.js",
                    "function_name": "verifyToken",
                    "line_number": 55,
                    "vulnerability_type": "jwt bypass",
                    "severity": "High",
                    "confidence": 0.789315515599868,  # Too precise
                    "framework": "node.js"
                },
                "expected": "HIGH_RISK",
                "reason": "Artificially precise confidence indicates possible fabrication"
            }
        ]

        for test in realism_tests:
            result = self.predictor.analyze_vulnerability_claim(test["claim"])
            self._evaluate_test_result(test, result)

    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        print("Testing Edge Cases...")

        edge_tests = [
            {
                "test_id": "EDGE-001",
                "description": "Missing file path",
                "claim": {
                    "id": "EDGE-001",
                    "file_path": "",
                    "function_name": "processData",
                    "line_number": 0,
                    "vulnerability_type": "buffer overflow",
                    "severity": "Critical",
                    "confidence": 0.90,
                    "framework": "unknown"
                },
                "expected": "REJECT",
                "reason": "Missing file path indicates fabrication"
            },
            {
                "test_id": "EDGE-002",
                "description": "Extremely high line number",
                "claim": {
                    "id": "EDGE-002",
                    "file_path": "src/main.js",
                    "function_name": "main",
                    "line_number": 50000,  # Unrealistic
                    "vulnerability_type": "injection",
                    "severity": "High",
                    "confidence": 0.75,
                    "framework": "node.js"
                },
                "expected": "HIGH_RISK",
                "reason": "Unrealistic line number"
            }
        ]

        for test in edge_tests:
            result = self.predictor.analyze_vulnerability_claim(test["claim"])
            self._evaluate_test_result(test, result)

    def _evaluate_test_result(self, test: dict, result: dict):
        """Evaluate a single test result."""
        analysis = result["analysis_results"]
        recommendation = analysis["recommendation"]
        fp_probability = analysis["false_positive_probability"]

        # Determine if test passed based on recommendation
        expected = test["expected"]
        passed = False

        if expected == "REJECT" and ("REJECT" in recommendation or "HIGH_RISK" in recommendation):
            passed = True
        elif expected == "ACCEPT" and ("ACCEPT" in recommendation or "REVIEW" in recommendation):
            passed = True
        elif expected == "MEDIUM_RISK" and ("MEDIUM_RISK" in recommendation or "REVIEW" in recommendation):
            passed = True
        elif expected == "HIGH_RISK" and ("HIGH_RISK" in recommendation or "REJECT" in recommendation):
            passed = True
        elif expected == "REVIEW" and "REVIEW" in recommendation:
            passed = True

        # Store result
        test_result = {
            "test_id": test["test_id"],
            "description": test["description"],
            "expected": expected,
            "actual_recommendation": recommendation,
            "false_positive_probability": fp_probability,
            "adjusted_confidence": analysis["adjusted_confidence"],
            "passed": passed,
            "reason": test["reason"]
        }

        self.test_results.append(test_result)

        # Print result
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test['test_id']}: {test['description']}")
        print(f"   Expected: {expected}, Got: {recommendation}")
        print(f"   FP Probability: {fp_probability:.2f}, Adjusted Confidence: {analysis['adjusted_confidence']:.2f}")
        print()

    def run_all_tests(self):
        """Run all validation tests."""
        print("="*80)
        print("VULNHUNTER V4 ENHANCED MODEL VALIDATION")
        print("="*80)
        print()

        # Run test suites
        self.test_gemini_cli_false_positives()
        self.test_legitimate_vulnerabilities()
        self.test_framework_protection_scenarios()
        self.test_statistical_realism()
        self.test_edge_cases()

        # Calculate summary statistics
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r["passed"])
        pass_rate = passed_tests / total_tests if total_tests > 0 else 0

        print("="*80)
        print("VALIDATION SUMMARY")
        print("="*80)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Pass Rate: {pass_rate:.1%}")
        print()

        # Show failed tests
        failed_tests = [r for r in self.test_results if not r["passed"]]
        if failed_tests:
            print("FAILED TESTS:")
            for test in failed_tests:
                print(f"❌ {test['test_id']}: {test['description']}")
                print(f"   Expected: {test['expected']}, Got: {test['actual_recommendation']}")
        else:
            print("🎉 ALL TESTS PASSED!")

        print("="*80)

        return self.test_results

def main():
    """Main validation function."""
    validator = ModelValidationTest()
    results = validator.run_all_tests()

    # Save detailed results
    output_file = "/Users/ankitthakur/vuln_ml_research/data/models/vulnhunter_v4/validation_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Detailed results saved to: {output_file}")

if __name__ == "__main__":
    main()