#!/usr/bin/env python3
"""
📊 Baseline Comparison Framework - Phase 3 Production Enhancement
===============================================================
Benchmarks VulnHunter against established industry tools
Key objectives:
1. Compare against CodeQL, Semgrep baselines
2. Measure precision/recall metrics on holdout sets
3. Provide transparency in performance claims
4. Enable continuous improvement through benchmarking

Addresses 1.txt requirement: "No comparison against CodeQL, Semgrep baselines"
"""

import os
import json
import subprocess
import tempfile
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import statistics
import time

@dataclass
class BenchmarkResult:
    tool_name: str
    findings_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    execution_time: float
    confidence_scores: List[float]

@dataclass
class ComparisonReport:
    vulnhunter_result: BenchmarkResult
    baseline_results: List[BenchmarkResult]
    ground_truth_validated: int
    performance_ranking: Dict[str, int]
    recommendations: List[str]
    timestamp: str

class GroundTruthValidator:
    """Validates findings against known ground truth datasets"""

    def __init__(self):
        self.known_vulnerabilities = {
            # Real CVE examples for validation
            'CVE-2021-44228': {
                'type': 'log4j_rce',
                'patterns': ['log4j', 'jndi', 'lookup'],
                'files': ['log4j-core', 'LogManager.java'],
                'severity': 'critical'
            },
            'CVE-2022-22965': {
                'type': 'spring_rce',
                'patterns': ['DataBinder', 'class.module'],
                'files': ['spring-webmvc', 'RequestMapping'],
                'severity': 'critical'
            }
        }

    def validate_finding_against_ground_truth(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Validate if a finding corresponds to known vulnerabilities"""

        file_path = finding.get('file_path', '')
        description = finding.get('description', '').lower()
        vulnerability_type = finding.get('type', '')

        for cve_id, cve_data in self.known_vulnerabilities.items():
            # Check if finding matches known CVE patterns
            pattern_matches = sum(1 for pattern in cve_data['patterns']
                                if pattern in description or pattern in file_path)

            file_matches = sum(1 for file_hint in cve_data['files']
                             if file_hint in file_path)

            confidence = (pattern_matches + file_matches) / (len(cve_data['patterns']) + len(cve_data['files']))

            if confidence > 0.5:
                return {
                    'is_ground_truth': True,
                    'cve_match': cve_id,
                    'confidence': confidence,
                    'severity': cve_data['severity']
                }

        return {
            'is_ground_truth': False,
            'cve_match': None,
            'confidence': 0.0,
            'severity': 'unknown'
        }

class CodeQLRunner:
    """Runs CodeQL analysis for baseline comparison"""

    def __init__(self):
        self.available = self._check_codeql_availability()

    def _check_codeql_availability(self) -> bool:
        """Check if CodeQL is available"""
        try:
            result = subprocess.run(['codeql', '--version'],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    def analyze_repository(self, repo_path: str, language: str = 'java') -> BenchmarkResult:
        """Run CodeQL analysis on repository"""

        if not self.available:
            return BenchmarkResult(
                tool_name='CodeQL',
                findings_count=0,
                true_positives=0,
                false_positives=0,
                false_negatives=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                execution_time=0.0,
                confidence_scores=[]
            )

        start_time = time.time()

        try:
            # Create CodeQL database
            with tempfile.TemporaryDirectory() as temp_dir:
                db_path = os.path.join(temp_dir, 'codeql-db')

                # Create database
                create_cmd = [
                    'codeql', 'database', 'create', db_path,
                    '--language', language,
                    '--source-root', repo_path
                ]

                subprocess.run(create_cmd, capture_output=True, timeout=300)

                # Run analysis
                query_suite = f'{language}-security-and-quality'
                analysis_cmd = [
                    'codeql', 'database', 'analyze', db_path,
                    query_suite,
                    '--format=sarif-latest',
                    '--output=/tmp/codeql-results.sarif'
                ]

                subprocess.run(analysis_cmd, capture_output=True, timeout=600)

                # Parse results
                findings = self._parse_codeql_results('/tmp/codeql-results.sarif')

        except Exception as e:
            print(f"CodeQL analysis failed: {e}")
            findings = []

        execution_time = time.time() - start_time

        return BenchmarkResult(
            tool_name='CodeQL',
            findings_count=len(findings),
            true_positives=0,  # Would be calculated against ground truth
            false_positives=0,
            false_negatives=0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            execution_time=execution_time,
            confidence_scores=[f.get('confidence', 0.5) for f in findings]
        )

    def _parse_codeql_results(self, sarif_file: str) -> List[Dict[str, Any]]:
        """Parse CodeQL SARIF results"""
        try:
            with open(sarif_file, 'r') as f:
                sarif_data = json.load(f)

            findings = []
            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    finding = {
                        'rule_id': result.get('ruleId', ''),
                        'message': result.get('message', {}).get('text', ''),
                        'severity': result.get('level', 'note'),
                        'file_path': self._extract_file_path(result),
                        'confidence': 0.8  # CodeQL typically has high confidence
                    }
                    findings.append(finding)

            return findings

        except Exception as e:
            print(f"Failed to parse CodeQL results: {e}")
            return []

    def _extract_file_path(self, result: Dict) -> str:
        """Extract file path from CodeQL result"""
        locations = result.get('locations', [])
        if locations:
            physical_location = locations[0].get('physicalLocation', {})
            artifact_location = physical_location.get('artifactLocation', {})
            return artifact_location.get('uri', '')
        return ''

class SemgrepRunner:
    """Runs Semgrep analysis for baseline comparison"""

    def __init__(self):
        self.available = self._check_semgrep_availability()

    def _check_semgrep_availability(self) -> bool:
        """Check if Semgrep is available"""
        try:
            result = subprocess.run(['semgrep', '--version'],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    def analyze_repository(self, repo_path: str) -> BenchmarkResult:
        """Run Semgrep analysis on repository"""

        if not self.available:
            return BenchmarkResult(
                tool_name='Semgrep',
                findings_count=0,
                true_positives=0,
                false_positives=0,
                false_negatives=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                execution_time=0.0,
                confidence_scores=[]
            )

        start_time = time.time()

        try:
            # Run Semgrep with security ruleset
            cmd = [
                'semgrep',
                '--config=auto',  # Use automatic rule selection
                '--json',
                '--output=/tmp/semgrep-results.json',
                repo_path
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                findings = self._parse_semgrep_results('/tmp/semgrep-results.json')
            else:
                print(f"Semgrep analysis failed: {result.stderr}")
                findings = []

        except Exception as e:
            print(f"Semgrep analysis failed: {e}")
            findings = []

        execution_time = time.time() - start_time

        return BenchmarkResult(
            tool_name='Semgrep',
            findings_count=len(findings),
            true_positives=0,  # Would be calculated against ground truth
            false_positives=0,
            false_negatives=0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            execution_time=execution_time,
            confidence_scores=[f.get('confidence', 0.7) for f in findings]
        )

    def _parse_semgrep_results(self, json_file: str) -> List[Dict[str, Any]]:
        """Parse Semgrep JSON results"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            findings = []
            for result in data.get('results', []):
                finding = {
                    'rule_id': result.get('check_id', ''),
                    'message': result.get('extra', {}).get('message', ''),
                    'severity': result.get('extra', {}).get('severity', 'INFO'),
                    'file_path': result.get('path', ''),
                    'confidence': result.get('extra', {}).get('metadata', {}).get('confidence', 0.7)
                }
                findings.append(finding)

            return findings

        except Exception as e:
            print(f"Failed to parse Semgrep results: {e}")
            return []

class BaselineComparisonFramework:
    """
    Main baseline comparison framework - Phase 3 enhancement
    Benchmarks VulnHunter against industry standard tools
    """

    def __init__(self):
        self.ground_truth_validator = GroundTruthValidator()
        self.codeql_runner = CodeQLRunner()
        self.semgrep_runner = SemgrepRunner()

    def run_comprehensive_benchmark(self, repo_path: str, vulnhunter_results: List[Dict]) -> ComparisonReport:
        """
        Run comprehensive benchmark against baseline tools
        """

        print(f"🔬 Running baseline comparison on: {repo_path}")

        # Run baseline tools
        print("Running CodeQL analysis...")
        codeql_result = self.codeql_runner.analyze_repository(repo_path)

        print("Running Semgrep analysis...")
        semgrep_result = self.semgrep_runner.analyze_repository(repo_path)

        # Process VulnHunter results
        print("Processing VulnHunter results...")
        vulnhunter_result = self._process_vulnhunter_results(vulnhunter_results)

        # Validate against ground truth
        print("Validating against ground truth...")
        ground_truth_count = self._validate_against_ground_truth([
            vulnhunter_result, codeql_result, semgrep_result
        ])

        # Calculate performance metrics
        results = [vulnhunter_result, codeql_result, semgrep_result]
        performance_ranking = self._calculate_performance_ranking(results)

        # Generate recommendations
        recommendations = self._generate_recommendations(vulnhunter_result, [codeql_result, semgrep_result])

        return ComparisonReport(
            vulnhunter_result=vulnhunter_result,
            baseline_results=[codeql_result, semgrep_result],
            ground_truth_validated=ground_truth_count,
            performance_ranking=performance_ranking,
            recommendations=recommendations,
            timestamp=datetime.now().isoformat()
        )

    def _process_vulnhunter_results(self, results: List[Dict]) -> BenchmarkResult:
        """Process VulnHunter results into benchmark format"""

        # Filter out findings that failed validation
        validated_findings = []
        confidence_scores = []

        for result in results:
            # Check if finding passed Phase 1 + Phase 2 validation
            if result.get('phase_1_validation', {}).get('mathematically_valid', False):
                # Apply Phase 2 security context filtering
                security_context = result.get('security_context', {})
                if security_context.get('context') not in ['false_positive', 'intended_behavior']:
                    validated_findings.append(result)
                    confidence_scores.append(result.get('mathematical_confidence', 0.0))

        return BenchmarkResult(
            tool_name='VulnHunter Ω (Fixed)',
            findings_count=len(validated_findings),
            true_positives=0,  # Would be calculated against ground truth
            false_positives=0,
            false_negatives=0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            execution_time=0.0,  # Would be measured
            confidence_scores=confidence_scores
        )

    def _validate_against_ground_truth(self, results: List[BenchmarkResult]) -> int:
        """Validate all results against ground truth"""
        # This would implement comprehensive ground truth validation
        # For now, return a placeholder
        return 0

    def _calculate_performance_ranking(self, results: List[BenchmarkResult]) -> Dict[str, int]:
        """Calculate performance ranking across tools"""

        # Rank by F1 score (when available), then by findings count
        ranking = {}
        sorted_results = sorted(results,
                              key=lambda x: (x.f1_score, x.findings_count),
                              reverse=True)

        for i, result in enumerate(sorted_results):
            ranking[result.tool_name] = i + 1

        return ranking

    def _generate_recommendations(self, vulnhunter: BenchmarkResult, baselines: List[BenchmarkResult]) -> List[str]:
        """Generate improvement recommendations based on comparison"""

        recommendations = []

        # Compare findings count
        baseline_avg = statistics.mean([b.findings_count for b in baselines])
        if vulnhunter.findings_count < baseline_avg * 0.5:
            recommendations.append("Consider increasing sensitivity - finding fewer issues than baseline tools")
        elif vulnhunter.findings_count > baseline_avg * 2:
            recommendations.append("Consider improving precision - finding significantly more issues than baselines")

        # Compare confidence scores
        if vulnhunter.confidence_scores:
            avg_confidence = statistics.mean(vulnhunter.confidence_scores)
            if avg_confidence < 0.3:
                recommendations.append("Improve confidence calibration - scores appear underconfident")
            elif avg_confidence > 0.9:
                recommendations.append("Review confidence calibration - scores may be overconfident")

        # Tool availability recommendations
        available_baselines = [b for b in baselines if b.findings_count > 0]
        if not available_baselines:
            recommendations.append("Install CodeQL and Semgrep for comprehensive baseline comparison")

        return recommendations

def test_baseline_comparison():
    """Test the baseline comparison framework"""
    print("📊 Testing Baseline Comparison Framework - Phase 3")
    print("=" * 50)

    framework = BaselineComparisonFramework()

    # Simulate VulnHunter results (would come from actual analysis)
    mock_vulnhunter_results = [
        {
            'type': 'access_control',
            'mathematical_confidence': 0.3,  # Low due to Phase 1 validation
            'phase_1_validation': {'mathematically_valid': True},
            'security_context': {'context': 'intended_behavior'}  # Phase 2 filtered out
        },
        {
            'type': 'injection',
            'mathematical_confidence': 0.8,
            'phase_1_validation': {'mathematically_valid': True},
            'security_context': {'context': 'potential_vulnerability'}  # Phase 2 approved
        }
    ]

    # Test with small repository
    repo_path = "/tmp"  # Small test path

    comparison = framework.run_comprehensive_benchmark(repo_path, mock_vulnhunter_results)

    print(f"\nComparison Results:")
    print(f"VulnHunter findings: {comparison.vulnhunter_result.findings_count}")
    print(f"Ground truth validated: {comparison.ground_truth_validated}")
    print(f"Performance ranking: {comparison.performance_ranking}")
    print("\nRecommendations:")
    for rec in comparison.recommendations:
        print(f"  • {rec}")

if __name__ == "__main__":
    test_baseline_comparison()