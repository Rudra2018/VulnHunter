#!/usr/bin/env python3
"""
VulnHunter V4 Correlation Engine Demonstration
Demonstrates verification and correlation capabilities
"""

import os
import re
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict

@dataclass
class VulnerabilityFinding:
    """Structured vulnerability finding with location details."""
    vulnerability_type: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float
    description: str
    pattern_matched: str
    severity: str

@dataclass
class CorrelationResult:
    """Result of correlation verification."""
    finding_exists: bool
    file_exists: bool
    line_matches: bool
    code_matches: bool
    confidence_score: float
    verification_method: str
    additional_context: Dict[str, Any]

class CorrelationEngine:
    """Live repository correlation engine for verification."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        print(f"🔧 Correlation Engine initialized for: {repo_path}")

    def verify_file_exists(self, file_path: str) -> bool:
        """Verify if the specified file exists in the repository."""
        full_path = self.repo_path / file_path
        return full_path.exists() and full_path.is_file()

    def extract_line_content(self, file_path: str, line_number: int,
                           context_lines: int = 3) -> Optional[Dict[str, Any]]:
        """Extract content around the specified line number."""
        full_path = self.repo_path / file_path

        if not full_path.exists():
            return None

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            if line_number > len(lines) or line_number < 1:
                return None

            start_line = max(1, line_number - context_lines)
            end_line = min(len(lines), line_number + context_lines)

            context = {}
            for i in range(start_line, end_line + 1):
                if i <= len(lines):
                    context[i] = lines[i - 1].rstrip()

            return {
                'target_line': lines[line_number - 1].rstrip() if line_number <= len(lines) else "",
                'line_number': line_number,
                'context': context,
                'total_lines': len(lines),
                'file_path': str(full_path)
            }

        except Exception as e:
            return {"error": str(e)}

    def verify_code_pattern(self, file_path: str, line_number: int,
                          expected_pattern: str) -> Tuple[bool, str]:
        """Verify if the code pattern exists at the specified location."""
        content = self.extract_line_content(file_path, line_number, context_lines=5)

        if not content or 'error' in content:
            return False, "Could not extract file content"

        target_line = content['target_line']

        # Direct substring match
        if expected_pattern.strip() in target_line:
            return True, f"Exact match found: '{target_line}'"

        # Pattern-based matching
        expected_keywords = re.findall(r'\w+', expected_pattern.lower())
        target_keywords = re.findall(r'\w+', target_line.lower())

        matches = sum(1 for keyword in expected_keywords if keyword in target_keywords)
        similarity = matches / len(expected_keywords) if expected_keywords else 0

        if similarity > 0.6:  # 60% keyword similarity
            return True, f"Pattern similarity: {similarity:.1%} - '{target_line}'"

        # Check surrounding context for pattern
        for line_num, line_content in content['context'].items():
            if expected_pattern.strip() in line_content:
                return True, f"Found in context at line {line_num}: '{line_content}'"

        return False, f"No match found. Target line: '{target_line}'"

    def correlate_finding(self, finding: VulnerabilityFinding) -> CorrelationResult:
        """Correlate a vulnerability finding with the live repository."""

        print(f"🔍 Correlating: {finding.file_path}:{finding.line_number}")

        # Step 1: Verify file exists
        file_exists = self.verify_file_exists(finding.file_path)
        print(f"   📁 File exists: {file_exists}")

        if not file_exists:
            return CorrelationResult(
                finding_exists=False,
                file_exists=False,
                line_matches=False,
                code_matches=False,
                confidence_score=0.0,
                verification_method="file_existence_check",
                additional_context={"error": f"File {finding.file_path} not found"}
            )

        # Step 2: Extract line content
        line_content = self.extract_line_content(finding.file_path, finding.line_number)

        if not line_content or 'error' in line_content:
            return CorrelationResult(
                finding_exists=False,
                file_exists=True,
                line_matches=False,
                code_matches=False,
                confidence_score=0.1,
                verification_method="line_extraction_failed",
                additional_context={"error": "Could not extract line content"}
            )

        print(f"   📍 Line {finding.line_number}: '{line_content['target_line']}'")

        # Step 3: Verify code pattern
        code_matches, match_details = self.verify_code_pattern(
            finding.file_path,
            finding.line_number,
            finding.code_snippet
        )

        print(f"   🎯 Code matches: {code_matches} - {match_details}")

        # Step 4: Calculate confidence score
        confidence_factors = []

        # File existence (25%)
        confidence_factors.append(0.25 if file_exists else 0.0)

        # Line number validity (25%)
        line_valid = (finding.line_number <= line_content['total_lines'])
        confidence_factors.append(0.25 if line_valid else 0.0)

        # Code pattern match (40%)
        confidence_factors.append(0.4 if code_matches else 0.0)

        # Context analysis (10%)
        context_score = self._analyze_vulnerability_context(finding, line_content)
        confidence_factors.append(context_score * 0.1)

        final_confidence = sum(confidence_factors)

        print(f"   📊 Confidence: {final_confidence:.2f}")

        return CorrelationResult(
            finding_exists=(final_confidence > 0.6),
            file_exists=file_exists,
            line_matches=line_valid,
            code_matches=code_matches,
            confidence_score=final_confidence,
            verification_method="comprehensive_correlation",
            additional_context={
                "line_content": line_content['target_line'],
                "context_lines": len(line_content['context']),
                "match_details": match_details,
                "verification_timestamp": datetime.now().isoformat()
            }
        )

    def _analyze_vulnerability_context(self, finding: VulnerabilityFinding,
                                     line_content: Dict[str, Any]) -> float:
        """Analyze context relevance for additional confidence."""

        vuln_keywords = {
            'command_injection': ['exec', 'system', 'eval', 'shell', 'spawn', 'run'],
            'sql_injection': ['query', 'select', 'insert', 'update', 'delete', 'sql'],
            'xss': ['innerHTML', 'document.write', 'eval', 'html', 'script'],
            'path_traversal': ['../', '..\\', 'path', 'file', 'directory'],
            'weak_crypto': ['md5', 'sha1', 'des', 'random', 'crypto', 'hash']
        }

        keywords = vuln_keywords.get(finding.vulnerability_type, [])

        context_lines = list(line_content['context'].values())
        context_text = ' '.join(context_lines).lower()

        matches = sum(1 for keyword in keywords if keyword in context_text)

        return min(1.0, matches / len(keywords)) if keywords else 0.5

def create_sample_findings(repo_path: str) -> List[VulnerabilityFinding]:
    """Create sample vulnerability findings based on actual repository scan."""

    findings = []
    repo = Path(repo_path)

    # Scan for real patterns in the repository
    patterns = {
        'command_injection': [r'exec\s*\(', r'spawn\s*\(', r'eval\s*\('],
        'xss': [r'innerHTML\s*=', r'document\.write\s*\('],
        'path_traversal': [r'path\.join', r'fs\.readFile'],
    }

    print(f"🔍 Scanning {repo_path} for real vulnerabilities...")

    file_count = 0
    for file_path in repo.rglob('*.ts'):
        if ('node_modules' not in str(file_path) and
            '.git' not in str(file_path) and
            'test' not in str(file_path).lower() and
            file_count < 50):  # Limit scan

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                relative_path = str(file_path.relative_to(repo))

                for line_num, line in enumerate(lines, 1):
                    for vuln_type, pattern_list in patterns.items():
                        for pattern in pattern_list:
                            if re.search(pattern, line, re.IGNORECASE):
                                finding = VulnerabilityFinding(
                                    vulnerability_type=vuln_type,
                                    file_path=relative_path,
                                    line_number=line_num,
                                    code_snippet=line.strip(),
                                    confidence=0.85,
                                    description=f"Potential {vuln_type} in {relative_path}",
                                    pattern_matched=pattern,
                                    severity="medium"
                                )
                                findings.append(finding)

                                if len(findings) >= 10:  # Limit findings
                                    return findings

                file_count += 1

            except Exception:
                continue

    return findings

def demonstrate_correlation_engine():
    """Demonstrate the correlation engine capabilities."""

    print("🚀 VulnHunter V4 Correlation Engine Demonstration")
    print("=" * 60)

    # Use Gemini CLI repository for testing
    test_repo = '/tmp/v4_testing/gemini-cli'

    if not Path(test_repo).exists():
        print("❌ Test repository not found. Please run the main testing suite first.")
        return

    # Initialize correlation engine
    engine = CorrelationEngine(test_repo)

    # Create sample findings from real repository scan
    findings = create_sample_findings(test_repo)

    if not findings:
        print("ℹ️ No sample findings generated. Creating synthetic examples...")

        # Create synthetic findings for demonstration
        findings = [
            VulnerabilityFinding(
                vulnerability_type="command_injection",
                file_path="packages/cli/src/commands/process.ts",
                line_number=45,
                code_snippet="exec(userInput)",
                confidence=0.9,
                description="Command injection in CLI processing",
                pattern_matched="exec\\s*\\(",
                severity="high"
            ),
            VulnerabilityFinding(
                vulnerability_type="path_traversal",
                file_path="packages/core/src/fileHandler.ts",
                line_number=122,
                code_snippet="path.join(basePath, userPath)",
                confidence=0.8,
                description="Path traversal in file handler",
                pattern_matched="path\\.join",
                severity="medium"
            )
        ]

    print(f"📊 Testing {len(findings)} vulnerability findings...")
    print()

    results = []
    verified_count = 0

    for i, finding in enumerate(findings, 1):
        print(f"🔬 Test {i}/{len(findings)}: {finding.vulnerability_type} in {finding.file_path}")

        correlation_result = engine.correlate_finding(finding)

        if correlation_result.finding_exists:
            verified_count += 1
            status = "✅ VERIFIED"
        else:
            status = "❌ NOT VERIFIED"

        print(f"   {status} (Confidence: {correlation_result.confidence_score:.2f})")
        print()

        results.append({
            'finding': asdict(finding),
            'correlation': asdict(correlation_result)
        })

    # Generate summary report
    summary = {
        'demonstration_summary': {
            'test_repository': test_repo,
            'total_findings_tested': len(findings),
            'verified_findings': verified_count,
            'verification_rate': verified_count / len(findings) * 100 if findings else 0,
            'correlation_engine_version': "1.0.0",
            'test_timestamp': datetime.now().isoformat()
        },
        'correlation_capabilities': [
            "File existence verification",
            "Line number validation",
            "Code pattern matching",
            "Context-aware analysis",
            "Confidence scoring",
            "Multi-approach validation"
        ],
        'detailed_results': results
    }

    # Save results
    with open('/Users/ankitthakur/vuln_ml_research/correlation_engine_demo_results.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print("🎉 Correlation Engine Demonstration Complete!")
    print("=" * 60)
    print(f"📊 Summary:")
    print(f"   Findings tested: {len(findings)}")
    print(f"   Verified: {verified_count}")
    print(f"   Verification rate: {summary['demonstration_summary']['verification_rate']:.1f}%")
    print()
    print("🔧 Correlation Engine Features Demonstrated:")
    for feature in summary['correlation_capabilities']:
        print(f"   ✅ {feature}")
    print()
    print("📁 Detailed results saved to: correlation_engine_demo_results.json")

    return summary

if __name__ == "__main__":
    demonstrate_correlation_engine()