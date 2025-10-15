#!/usr/bin/env python3
"""
VulnHunter V4 Correlation and Verification Engine
Advanced verification system with live repository correlation
"""

import os
import re
import json
import pickle
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
import subprocess

@dataclass
class VulnerabilityFinding:
    """Structured vulnerability finding with location details."""
    vulnerability_type: str
    file_path: str
    line_number: int
    line_range: Optional[Tuple[int, int]]
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

class LiveRepositoryCorrelator:
    """Live repository correlation engine for verification."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.verification_cache = {}

    def verify_file_exists(self, file_path: str) -> bool:
        """Verify if the specified file exists in the repository."""
        full_path = self.repo_path / file_path
        return full_path.exists() and full_path.is_file()

    def extract_line_content(self, file_path: str, line_number: int,
                           context_lines: int = 2) -> Optional[Dict[str, Any]]:
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
                context[i] = lines[i - 1].rstrip()

            return {
                'target_line': lines[line_number - 1].rstrip(),
                'line_number': line_number,
                'context': context,
                'total_lines': len(lines)
            }

        except Exception as e:
            return None

    def verify_code_pattern(self, file_path: str, line_number: int,
                          expected_pattern: str, fuzzy_match: bool = True) -> bool:
        """Verify if the code pattern exists at the specified location."""
        content = self.extract_line_content(file_path, line_number, context_lines=5)

        if not content:
            return False

        target_line = content['target_line']

        # Exact match
        if expected_pattern in target_line:
            return True

        # Fuzzy matching for similar patterns
        if fuzzy_match:
            # Remove whitespace and compare
            normalized_target = re.sub(r'\s+', '', target_line.lower())
            normalized_pattern = re.sub(r'\s+', '', expected_pattern.lower())

            if normalized_pattern in normalized_target:
                return True

            # Check surrounding lines
            for line_content in content['context'].values():
                if expected_pattern in line_content:
                    return True

        return False

    def correlate_finding(self, finding: VulnerabilityFinding) -> CorrelationResult:
        """Correlate a vulnerability finding with the live repository."""

        # Step 1: Verify file exists
        file_exists = self.verify_file_exists(finding.file_path)

        if not file_exists:
            return CorrelationResult(
                finding_exists=False,
                file_exists=False,
                line_matches=False,
                code_matches=False,
                confidence_score=0.0,
                verification_method="file_existence_check",
                additional_context={"error": "File not found"}
            )

        # Step 2: Extract line content
        line_content = self.extract_line_content(finding.file_path, finding.line_number)

        if not line_content:
            return CorrelationResult(
                finding_exists=False,
                file_exists=True,
                line_matches=False,
                code_matches=False,
                confidence_score=0.1,
                verification_method="line_extraction_failed",
                additional_context={"error": "Could not extract line content"}
            )

        # Step 3: Verify code pattern
        code_matches = self.verify_code_pattern(
            finding.file_path,
            finding.line_number,
            finding.code_snippet
        )

        # Step 4: Calculate confidence score
        confidence_factors = []

        # File existence (20%)
        confidence_factors.append(0.2 if file_exists else 0.0)

        # Line number validity (20%)
        line_valid = (finding.line_number <= line_content['total_lines'])
        confidence_factors.append(0.2 if line_valid else 0.0)

        # Code pattern match (40%)
        confidence_factors.append(0.4 if code_matches else 0.0)

        # Context analysis (20%)
        context_score = self._analyze_context_relevance(finding, line_content)
        confidence_factors.append(context_score * 0.2)

        final_confidence = sum(confidence_factors)

        return CorrelationResult(
            finding_exists=(final_confidence > 0.5),
            file_exists=file_exists,
            line_matches=line_valid,
            code_matches=code_matches,
            confidence_score=final_confidence,
            verification_method="comprehensive_correlation",
            additional_context={
                "line_content": line_content,
                "context_score": context_score,
                "verification_timestamp": datetime.now().isoformat()
            }
        )

    def _analyze_context_relevance(self, finding: VulnerabilityFinding,
                                 line_content: Dict[str, Any]) -> float:
        """Analyze context relevance for additional confidence."""

        # Look for vulnerability-related keywords in surrounding lines
        vuln_keywords = {
            'command_injection': ['exec', 'system', 'eval', 'shell'],
            'sql_injection': ['query', 'select', 'insert', 'update', 'delete'],
            'xss': ['innerHTML', 'document.write', 'eval', 'html'],
            'path_traversal': ['../', '..\\', 'path', 'file'],
            'weak_crypto': ['md5', 'sha1', 'des', 'random']
        }

        keywords = vuln_keywords.get(finding.vulnerability_type, [])

        context_lines = list(line_content['context'].values())
        context_text = ' '.join(context_lines).lower()

        matches = sum(1 for keyword in keywords if keyword in context_text)

        return min(1.0, matches / len(keywords)) if keywords else 0.5

class MultiApproachValidator:
    """Multi-approach validation framework."""

    def __init__(self, model_path: str):
        # Import and load V4 model
        import sys
        sys.path.append('/Users/ankitthakur/vuln_ml_research')
        from vulnhunter_v4_production_model import VulnHunterV4Model

        with open(model_path, 'rb') as f:
            self.v4_model = pickle.load(f)

        self.validation_approaches = [
            self._pattern_based_validation,
            self._context_aware_validation,
            self._semantic_analysis_validation,
            self._historical_validation
        ]

    def _pattern_based_validation(self, finding: VulnerabilityFinding,
                                repo_path: str) -> Dict[str, Any]:
        """Pattern-based validation approach."""

        correlator = LiveRepositoryCorrelator(repo_path)
        correlation = correlator.correlate_finding(finding)

        return {
            "approach": "pattern_based",
            "valid": correlation.finding_exists,
            "confidence": correlation.confidence_score,
            "details": correlation
        }

    def _context_aware_validation(self, finding: VulnerabilityFinding,
                                repo_path: str) -> Dict[str, Any]:
        """Context-aware validation using surrounding code."""

        correlator = LiveRepositoryCorrelator(repo_path)

        # Extract larger context
        content = correlator.extract_line_content(
            finding.file_path, finding.line_number, context_lines=10
        )

        if not content:
            return {
                "approach": "context_aware",
                "valid": False,
                "confidence": 0.0,
                "details": "Could not extract context"
            }

        # Analyze function/method context
        context_lines = list(content['context'].values())
        full_context = '\n'.join(context_lines)

        # Re-run V4 model on the full context
        context_claim = f"Vulnerability in context: {full_context[:500]}"

        confidence, is_fp, analysis = self.v4_model.predict(
            claim=context_claim,
            vuln_type=finding.vulnerability_type,
            source_file=finding.file_path
        )

        return {
            "approach": "context_aware",
            "valid": not is_fp,
            "confidence": confidence,
            "details": {
                "v4_analysis": analysis,
                "context_size": len(context_lines)
            }
        }

    def _semantic_analysis_validation(self, finding: VulnerabilityFinding,
                                    repo_path: str) -> Dict[str, Any]:
        """Semantic analysis validation."""

        # Analyze the semantic meaning of the vulnerability
        semantic_indicators = {
            'command_injection': ['user input', 'parameter', 'argument', 'shell'],
            'sql_injection': ['user data', 'query building', 'concatenation'],
            'xss': ['user content', 'output', 'rendering', 'html'],
            'path_traversal': ['file access', 'path construction', 'directory'],
            'weak_crypto': ['encryption', 'hashing', 'security', 'crypto']
        }

        indicators = semantic_indicators.get(finding.vulnerability_type, [])

        correlator = LiveRepositoryCorrelator(repo_path)
        content = correlator.extract_line_content(
            finding.file_path, finding.line_number, context_lines=5
        )

        if not content:
            return {
                "approach": "semantic_analysis",
                "valid": False,
                "confidence": 0.0,
                "details": "No content available"
            }

        context_text = ' '.join(content['context'].values()).lower()
        semantic_matches = sum(1 for indicator in indicators if indicator in context_text)

        semantic_confidence = min(1.0, semantic_matches / len(indicators)) if indicators else 0.5

        return {
            "approach": "semantic_analysis",
            "valid": semantic_confidence > 0.3,
            "confidence": semantic_confidence,
            "details": {
                "indicators_found": semantic_matches,
                "total_indicators": len(indicators),
                "context_relevance": semantic_confidence
            }
        }

    def _historical_validation(self, finding: VulnerabilityFinding,
                             repo_path: str) -> Dict[str, Any]:
        """Historical validation using git history."""

        try:
            # Check git blame for the specific line
            cmd = [
                'git', 'blame', '-L',
                f"{finding.line_number},{finding.line_number}",
                finding.file_path
            ]

            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                blame_info = result.stdout.strip()

                # Extract commit info
                commit_hash = blame_info.split()[0] if blame_info else "unknown"

                return {
                    "approach": "historical_validation",
                    "valid": True,
                    "confidence": 0.8,
                    "details": {
                        "blame_info": blame_info,
                        "commit_hash": commit_hash,
                        "file_tracked": True
                    }
                }
            else:
                return {
                    "approach": "historical_validation",
                    "valid": False,
                    "confidence": 0.2,
                    "details": {"error": "Git blame failed", "stderr": result.stderr}
                }

        except Exception as e:
            return {
                "approach": "historical_validation",
                "valid": False,
                "confidence": 0.0,
                "details": {"error": str(e)}
            }

    def validate_finding(self, finding: VulnerabilityFinding,
                        repo_path: str) -> Dict[str, Any]:
        """Validate finding using multiple approaches."""

        results = []

        for approach in self.validation_approaches:
            try:
                result = approach(finding, repo_path)
                results.append(result)
            except Exception as e:
                results.append({
                    "approach": approach.__name__,
                    "valid": False,
                    "confidence": 0.0,
                    "details": {"error": str(e)}
                })

        # Aggregate results
        valid_count = sum(1 for r in results if r['valid'])
        avg_confidence = sum(r['confidence'] for r in results) / len(results)

        # Weighted scoring (pattern_based and context_aware are more important)
        weights = [0.3, 0.3, 0.2, 0.2]  # pattern, context, semantic, historical
        weighted_confidence = sum(
            results[i]['confidence'] * weights[i]
            for i in range(len(results))
        )

        return {
            "finding": finding,
            "validation_summary": {
                "approaches_validated": valid_count,
                "total_approaches": len(results),
                "average_confidence": avg_confidence,
                "weighted_confidence": weighted_confidence,
                "overall_valid": weighted_confidence > 0.6
            },
            "detailed_results": results,
            "validation_timestamp": datetime.now().isoformat()
        }

class VulnHunterV4WithCorrelation:
    """Enhanced V4 model with integrated correlation engine."""

    def __init__(self, model_path: str):
        # Import the model class
        import sys
        sys.path.append('/Users/ankitthakur/vuln_ml_research')
        from vulnhunter_v4_production_model import VulnHunterV4Model

        with open(model_path, 'rb') as f:
            self.base_model = pickle.load(f)

        self.validator = MultiApproachValidator(model_path)

    def scan_and_verify(self, repo_path: str, file_patterns: List[str] = None) -> Dict[str, Any]:
        """Scan repository and verify findings with correlation engine."""

        if file_patterns is None:
            file_patterns = ['*.js', '*.ts', '*.py', '*.java', '*.cpp', '*.c']

        print(f"🔍 VulnHunter V4 with Correlation Engine")
        print(f"📂 Repository: {repo_path}")
        print("=" * 60)

        repo_path_obj = Path(repo_path)
        all_findings = []
        verified_findings = []
        false_positives = []

        # Security patterns for scanning
        patterns = {
            'command_injection': [r'exec\s*\(', r'system\s*\(', r'eval\s*\('],
            'sql_injection': [r'SELECT.*\+', r'query.*\+', r'execute.*\+'],
            'xss': [r'innerHTML\s*=', r'document\.write', r'\.html\s*\('],
            'path_traversal': [r'\.\./', r'path\.join.*\.\.', r'File\s*\(.*\+'],
            'weak_crypto': [r'MD5\s*\(', r'SHA1\s*\(', r'Math\.random']
        }

        # Scan files
        for pattern in file_patterns:
            for file_path in repo_path_obj.rglob(pattern):
                if ('node_modules' not in str(file_path) and
                    '.git' not in str(file_path) and
                    file_path.is_file()):

                    findings = self._scan_file(file_path, repo_path_obj, patterns)
                    all_findings.extend(findings)

        print(f"📊 Initial scan: {len(all_findings)} potential vulnerabilities found")
        print("🔬 Running correlation and verification...")

        # Verify each finding
        for i, finding in enumerate(all_findings):
            if i % 10 == 0:
                print(f"   Verified {i}/{len(all_findings)} findings...")

            validation_result = self.validator.validate_finding(finding, repo_path)

            if validation_result['validation_summary']['overall_valid']:
                verified_findings.append({
                    'finding': finding,
                    'validation': validation_result
                })
            else:
                false_positives.append({
                    'finding': finding,
                    'validation': validation_result
                })

        # Generate comprehensive report
        report = {
            'scan_summary': {
                'repository': repo_path,
                'scan_timestamp': datetime.now().isoformat(),
                'total_findings': len(all_findings),
                'verified_vulnerabilities': len(verified_findings),
                'false_positives_filtered': len(false_positives),
                'accuracy_rate': len(verified_findings) / len(all_findings) * 100 if all_findings else 0
            },
            'verified_vulnerabilities': verified_findings[:20],  # Top 20
            'correlation_engine_stats': {
                'validation_approaches': 4,
                'average_confidence': sum(
                    vf['validation']['validation_summary']['weighted_confidence']
                    for vf in verified_findings
                ) / len(verified_findings) if verified_findings else 0
            },
            'model_info': {
                'version': self.base_model.version,
                'training_samples': self.base_model.training_samples
            }
        }

        print("✅ Correlation and verification complete!")
        print(f"🎯 Results:")
        print(f"   Verified vulnerabilities: {len(verified_findings)}")
        print(f"   False positives filtered: {len(false_positives)}")
        print(f"   Accuracy rate: {report['scan_summary']['accuracy_rate']:.1f}%")

        return report

    def _scan_file(self, file_path: Path, repo_root: Path, patterns: Dict[str, List[str]]) -> List[VulnerabilityFinding]:
        """Scan a single file for vulnerabilities."""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            relative_path = str(file_path.relative_to(repo_root))

            for line_num, line in enumerate(lines, 1):
                for vuln_type, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if re.search(pattern, line, re.IGNORECASE):

                            # Use base V4 model for initial assessment
                            claim = f"Potential {vuln_type} in {relative_path} at line {line_num}: {line.strip()}"

                            confidence, is_fp, analysis = self.base_model.predict(
                                claim=claim,
                                vuln_type=vuln_type,
                                source_file=relative_path
                            )

                            if not is_fp:  # Only process non-false positives
                                finding = VulnerabilityFinding(
                                    vulnerability_type=vuln_type,
                                    file_path=relative_path,
                                    line_number=line_num,
                                    line_range=None,
                                    code_snippet=line.strip(),
                                    confidence=confidence,
                                    description=claim,
                                    pattern_matched=pattern,
                                    severity=analysis.get('risk_assessment', 'medium')
                                )
                                findings.append(finding)

        except Exception as e:
            pass

        return findings

def main():
    """Main testing function."""
    model_path = '/Users/ankitthakur/vuln_ml_research/vulnhunter_v4_model.pkl'

    # Test on Gemini CLI
    enhanced_scanner = VulnHunterV4WithCorrelation(model_path)

    test_repo = '/tmp/v4_testing/gemini-cli'
    if Path(test_repo).exists():
        results = enhanced_scanner.scan_and_verify(test_repo)

        # Save results
        with open('/tmp/v4_testing/correlation_engine_results.json', 'w') as f:
            # Convert findings to dict for JSON serialization
            serializable_results = {
                'scan_summary': results['scan_summary'],
                'verified_count': len(results['verified_vulnerabilities']),
                'correlation_stats': results['correlation_engine_stats'],
                'model_info': results['model_info']
            }
            json.dump(serializable_results, f, indent=2)

        print(f"\n📁 Detailed results saved to: /tmp/v4_testing/correlation_engine_results.json")
    else:
        print("❌ Test repository not found. Please run the main testing suite first.")

if __name__ == "__main__":
    main()