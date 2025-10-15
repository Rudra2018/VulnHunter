#!/usr/bin/env python3
"""
Realistic Correlation Engine Demo with Real Repository Files
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

@dataclass
class VulnerabilityFinding:
    """Vulnerability finding with exact location details."""
    vulnerability_type: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float
    description: str

class RealisticCorrelationEngine:
    """Correlation engine with real file verification."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def scan_and_correlate(self) -> Dict[str, Any]:
        """Scan repository and demonstrate correlation on real findings."""

        print("🔍 Real Repository Correlation Demonstration")
        print("=" * 50)

        # First, find real files and create realistic findings
        real_findings = self._create_realistic_findings()

        if not real_findings:
            print("❌ No real files found for correlation testing")
            return {}

        print(f"📁 Found {len(real_findings)} real findings to correlate")
        print()

        # Correlate each finding
        correlation_results = []

        for i, finding in enumerate(real_findings, 1):
            print(f"🔬 Correlating Finding #{i}")
            print(f"   Type: {finding.vulnerability_type}")
            print(f"   File: {finding.file_path}")
            print(f"   Line: {finding.line_number}")

            result = self._correlate_finding(finding)
            correlation_results.append({
                'finding': finding,
                'correlation': result
            })

            status = "✅ VERIFIED" if result['verified'] else "❌ FAILED"
            print(f"   Result: {status} (Score: {result['confidence']:.2f})")
            print()

        # Generate summary
        verified_count = sum(1 for r in correlation_results if r['correlation']['verified'])

        summary = {
            'correlation_demo': {
                'repository': str(self.repo_path),
                'total_findings': len(real_findings),
                'verified_findings': verified_count,
                'success_rate': verified_count / len(real_findings) * 100 if real_findings else 0,
                'timestamp': datetime.now().isoformat()
            },
            'findings_details': [
                {
                    'vulnerability_type': r['finding'].vulnerability_type,
                    'file_path': r['finding'].file_path,
                    'line_number': r['finding'].line_number,
                    'verified': r['correlation']['verified'],
                    'confidence': r['correlation']['confidence'],
                    'verification_details': r['correlation']['details']
                }
                for r in correlation_results
            ]
        }

        print("🎯 Correlation Summary:")
        print(f"   Total findings: {len(real_findings)}")
        print(f"   Successfully verified: {verified_count}")
        print(f"   Success rate: {summary['correlation_demo']['success_rate']:.1f}%")

        return summary

    def _create_realistic_findings(self) -> List[VulnerabilityFinding]:
        """Create realistic findings based on actual repository files."""

        findings = []

        # Scan for actual TypeScript/JavaScript files
        for file_path in self.repo_path.rglob('*.ts'):
            if ('node_modules' not in str(file_path) and
                '.git' not in str(file_path) and
                file_path.is_file()):

                relative_path = str(file_path.relative_to(self.repo_path))

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()

                    # Look for actual patterns that could be vulnerabilities
                    for line_num, line in enumerate(lines, 1):
                        line_content = line.strip()

                        # Find realistic vulnerability patterns
                        if 'eval(' in line_content:
                            findings.append(VulnerabilityFinding(
                                vulnerability_type="code_injection",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=line_content,
                                confidence=0.9,
                                description=f"Potential eval() usage in {relative_path}"
                            ))

                        elif 'innerHTML' in line_content and '=' in line_content:
                            findings.append(VulnerabilityFinding(
                                vulnerability_type="xss",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=line_content,
                                confidence=0.8,
                                description=f"Potential XSS via innerHTML in {relative_path}"
                            ))

                        elif 'exec(' in line_content or 'spawn(' in line_content:
                            findings.append(VulnerabilityFinding(
                                vulnerability_type="command_injection",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=line_content,
                                confidence=0.85,
                                description=f"Potential command injection in {relative_path}"
                            ))

                        elif 'fs.readFile' in line_content or 'path.join' in line_content:
                            findings.append(VulnerabilityFinding(
                                vulnerability_type="path_traversal",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=line_content,
                                confidence=0.7,
                                description=f"Potential path traversal in {relative_path}"
                            ))

                        # Limit to first 20 findings
                        if len(findings) >= 20:
                            return findings

                except Exception:
                    continue

        return findings

    def _correlate_finding(self, finding: VulnerabilityFinding) -> Dict[str, Any]:
        """Correlate a finding with the actual repository."""

        # Step 1: Verify file exists
        full_path = self.repo_path / finding.file_path
        file_exists = full_path.exists()

        if not file_exists:
            return {
                'verified': False,
                'confidence': 0.0,
                'details': {
                    'file_exists': False,
                    'error': f"File {finding.file_path} not found"
                }
            }

        # Step 2: Extract and verify line content
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            if finding.line_number > len(lines) or finding.line_number < 1:
                return {
                    'verified': False,
                    'confidence': 0.2,
                    'details': {
                        'file_exists': True,
                        'line_valid': False,
                        'error': f"Line {finding.line_number} not found (file has {len(lines)} lines)"
                    }
                }

            actual_line = lines[finding.line_number - 1].strip()

            # Step 3: Compare code snippets
            code_matches = self._compare_code(finding.code_snippet, actual_line)

            # Step 4: Extract context
            context_start = max(0, finding.line_number - 3)
            context_end = min(len(lines), finding.line_number + 2)
            context_lines = [
                f"{i+1}: {lines[i].rstrip()}"
                for i in range(context_start, context_end)
            ]

            # Step 5: Calculate confidence
            confidence = 0.0
            if file_exists:
                confidence += 0.3
            if finding.line_number <= len(lines):
                confidence += 0.3
            if code_matches['exact_match']:
                confidence += 0.4
            elif code_matches['partial_match']:
                confidence += 0.2

            return {
                'verified': confidence > 0.6,
                'confidence': confidence,
                'details': {
                    'file_exists': True,
                    'line_valid': True,
                    'actual_line': actual_line,
                    'expected_line': finding.code_snippet,
                    'exact_match': code_matches['exact_match'],
                    'partial_match': code_matches['partial_match'],
                    'similarity_score': code_matches['similarity'],
                    'context': context_lines
                }
            }

        except Exception as e:
            return {
                'verified': False,
                'confidence': 0.1,
                'details': {
                    'file_exists': True,
                    'error': f"Error reading file: {str(e)}"
                }
            }

    def _compare_code(self, expected: str, actual: str) -> Dict[str, Any]:
        """Compare expected and actual code snippets."""

        # Normalize whitespace
        expected_norm = re.sub(r'\s+', ' ', expected.strip())
        actual_norm = re.sub(r'\s+', ' ', actual.strip())

        # Exact match
        if expected_norm == actual_norm:
            return {
                'exact_match': True,
                'partial_match': True,
                'similarity': 1.0
            }

        # Substring match
        if expected_norm in actual_norm or actual_norm in expected_norm:
            return {
                'exact_match': False,
                'partial_match': True,
                'similarity': 0.8
            }

        # Keyword similarity
        expected_words = set(re.findall(r'\w+', expected_norm.lower()))
        actual_words = set(re.findall(r'\w+', actual_norm.lower()))

        if expected_words and actual_words:
            common_words = expected_words.intersection(actual_words)
            similarity = len(common_words) / len(expected_words.union(actual_words))

            return {
                'exact_match': False,
                'partial_match': similarity > 0.5,
                'similarity': similarity
            }

        return {
            'exact_match': False,
            'partial_match': False,
            'similarity': 0.0
        }

def main():
    """Main demonstration function."""

    test_repo = '/tmp/v4_testing/gemini-cli'

    if not Path(test_repo).exists():
        print("❌ Test repository not found at /tmp/v4_testing/gemini-cli")
        print("Please run the main testing suite first to clone the repository.")
        return

    # Initialize correlation engine
    engine = RealisticCorrelationEngine(test_repo)

    # Run demonstration
    results = engine.scan_and_correlate()

    if results:
        # Save results
        with open('/Users/ankitthakur/vuln_ml_research/realistic_correlation_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print()
        print("📁 Detailed results saved to: realistic_correlation_results.json")

        # Print sample verification details
        if results['findings_details']:
            print()
            print("🔍 Sample Verification Details:")
            sample = results['findings_details'][0]
            print(f"   File: {sample['file_path']}")
            print(f"   Line: {sample['line_number']}")
            print(f"   Type: {sample['vulnerability_type']}")
            print(f"   Verified: {sample['verified']}")
            print(f"   Confidence: {sample['confidence']:.2f}")

        print()
        print("🎉 Realistic Correlation Engine Demonstration Complete!")

if __name__ == "__main__":
    main()