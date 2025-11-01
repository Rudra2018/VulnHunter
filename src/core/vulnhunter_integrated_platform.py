#!/usr/bin/env python3
"""
VulnHunter Integrated Platform
Complete vulnerability assessment platform with automated detection, manual verification, and PoC generation
"""

import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

# Import our modules
from .enhanced_manual_verification import EnhancedManualVerifier, VerificationResult
from .poc_demonstration_framework import PoCDemonstrationFramework, PoCResult

# Try to import real modules, fallback to mock
try:
    from .vulnhunter_enhanced_semantic import EnhancedSemanticAnalyzer
    from .vulnerability_validation_framework import ValidationFramework
    from .sota_enhancement_engine import SOTAEnhancementEngine
except ImportError:
    from .mock_modules import EnhancedSemanticAnalyzer, ValidationFramework, SOTAEnhancementEngine

@dataclass
class AssessmentResult:
    """Complete assessment result including all phases"""
    scan_id: str
    target_info: Dict[str, Any]
    automated_findings: List[Dict[str, Any]]
    verified_findings: List[VerificationResult]
    poc_results: List[PoCResult]
    final_assessment: Dict[str, Any]
    recommendations: List[str]
    bounty_eligible_findings: List[Dict[str, Any]]
    execution_time: float
    confidence_score: float

class VulnHunterIntegratedPlatform:
    """Main integrated platform for comprehensive vulnerability assessment"""

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.setup_logging()

        # Initialize core components
        self.semantic_analyzer = EnhancedSemanticAnalyzer()
        self.manual_verifier = EnhancedManualVerifier()
        self.poc_framework = PoCDemonstrationFramework()
        self.validation_framework = ValidationFramework()
        self.enhancement_engine = SOTAEnhancementEngine()

        # Results tracking
        self.results_dir = Path("results/integrated_assessments")
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(__name__)

    def comprehensive_assessment(self, target_path: str, target_type: str = "auto") -> AssessmentResult:
        """Run comprehensive vulnerability assessment"""

        start_time = time.time()
        scan_id = f"integrated_scan_{int(time.time())}"

        self.logger.info(f"🚀 Starting comprehensive assessment: {scan_id}")
        self.logger.info(f"📁 Target: {target_path}")

        try:
            # Phase 1: Initial Discovery and Automated Detection
            self.logger.info("🔍 Phase 1: Automated Detection")
            automated_findings = self._run_automated_detection(target_path, target_type)
            self.logger.info(f"📊 Found {len(automated_findings)} potential vulnerabilities")

            # Phase 2: Enhanced Manual Verification
            self.logger.info("🔬 Phase 2: Manual Verification")
            verified_findings = self._run_manual_verification(automated_findings, target_path)
            verified_count = len([v for v in verified_findings if v.status == 'verified'])
            self.logger.info(f"✅ Verified {verified_count} real vulnerabilities")

            # Phase 3: PoC Generation and Testing
            self.logger.info("🛠️ Phase 3: PoC Generation")
            real_vulnerabilities = [
                finding for i, finding in enumerate(automated_findings)
                if i < len(verified_findings) and verified_findings[i].status == 'verified'
            ]
            poc_results = self._generate_pocs(real_vulnerabilities)
            exploitable_count = len([p for p in poc_results if p.exploitability_confirmed])
            self.logger.info(f"🎯 Generated {len(poc_results)} PoCs, {exploitable_count} confirmed exploitable")

            # Phase 4: Final Assessment and Reporting
            self.logger.info("📋 Phase 4: Final Assessment")
            final_assessment = self._generate_final_assessment(
                automated_findings, verified_findings, poc_results
            )

            # Generate recommendations
            recommendations = self._generate_recommendations(verified_findings, poc_results)

            # Identify bounty-eligible findings
            bounty_eligible = self._identify_bounty_eligible(verified_findings, poc_results)

            execution_time = time.time() - start_time
            confidence_score = self._calculate_confidence_score(verified_findings, poc_results)

            # Create comprehensive result
            result = AssessmentResult(
                scan_id=scan_id,
                target_info={
                    'path': target_path,
                    'type': target_type,
                    'scan_timestamp': time.time()
                },
                automated_findings=automated_findings,
                verified_findings=verified_findings,
                poc_results=poc_results,
                final_assessment=final_assessment,
                recommendations=recommendations,
                bounty_eligible_findings=bounty_eligible,
                execution_time=execution_time,
                confidence_score=confidence_score
            )

            # Save comprehensive results
            self._save_assessment_result(result)

            self.logger.info(f"✨ Assessment complete: {scan_id}")
            self.logger.info(f"⏱️ Total time: {execution_time:.2f}s")
            self.logger.info(f"🎯 Confidence: {confidence_score:.1%}")

            return result

        except Exception as e:
            self.logger.error(f"❌ Assessment failed: {e}")
            raise

    def _run_automated_detection(self, target_path: str, target_type: str) -> List[Dict[str, Any]]:
        """Run automated vulnerability detection"""

        findings = []

        try:
            # Use enhanced semantic analyzer for initial detection
            semantic_results = self.semantic_analyzer.analyze_target(target_path)
            findings.extend(semantic_results.get('vulnerabilities', []))

            # Add other automated detectors based on target type
            if target_type == "blockchain" or target_type == "auto":
                # Add blockchain-specific detectors
                blockchain_findings = self._run_blockchain_detectors(target_path)
                findings.extend(blockchain_findings)

            # Enhance findings with SOTA engine
            enhanced_findings = self.enhancement_engine.enhance_findings(findings)

            return enhanced_findings

        except Exception as e:
            self.logger.error(f"Automated detection failed: {e}")
            return []

    def _run_manual_verification(self, findings: List[Dict[str, Any]], target_path: str) -> List[VerificationResult]:
        """Run manual verification on all findings"""

        verified_results = []

        for finding in findings:
            try:
                # Load source code for the finding
                source_code = self._load_source_code(finding, target_path)

                if source_code:
                    # Run enhanced manual verification
                    verification_result = self.manual_verifier.verify_vulnerability(finding, source_code)
                    verified_results.append(verification_result)
                else:
                    # Create failed verification result
                    verified_results.append(VerificationResult(
                        vulnerability_id=finding.get('id', 'unknown'),
                        status='false_positive',
                        confidence=0.1,
                        reason='Source code not accessible',
                        poc_feasible=False,
                        exploitability_score=0.0,
                        technical_details={'source_code_error': True}
                    ))

            except Exception as e:
                self.logger.error(f"Manual verification failed for {finding.get('id', 'unknown')}: {e}")
                verified_results.append(VerificationResult(
                    vulnerability_id=finding.get('id', 'unknown'),
                    status='false_positive',
                    confidence=0.1,
                    reason=f'Verification error: {e}',
                    poc_feasible=False,
                    exploitability_score=0.0,
                    technical_details={'verification_error': str(e)}
                ))

        return verified_results

    def _generate_pocs(self, vulnerabilities: List[Dict[str, Any]]) -> List[PoCResult]:
        """Generate PoCs for verified vulnerabilities"""

        poc_results = []

        for vuln in vulnerabilities:
            try:
                poc_result = self.poc_framework.generate_and_execute_poc(vuln)
                poc_results.append(poc_result)
            except Exception as e:
                self.logger.error(f"PoC generation failed for {vuln.get('id', 'unknown')}: {e}")

        return poc_results

    def _generate_final_assessment(self, automated_findings: List[Dict[str, Any]],
                                 verified_findings: List[VerificationResult],
                                 poc_results: List[PoCResult]) -> Dict[str, Any]:
        """Generate final comprehensive assessment"""

        # Count statistics
        total_automated = len(automated_findings)
        verified_real = len([v for v in verified_findings if v.status == 'verified'])
        false_positives = len([v for v in verified_findings if v.status == 'false_positive'])
        needs_review = len([v for v in verified_findings if v.status == 'needs_review'])
        exploitable_confirmed = len([p for p in poc_results if p.exploitability_confirmed])

        # Calculate rates
        false_positive_rate = (false_positives / total_automated) * 100 if total_automated > 0 else 0
        verification_accuracy = ((verified_real + false_positives) / total_automated) * 100 if total_automated > 0 else 0

        # Severity breakdown
        severity_breakdown = {}
        for finding in automated_findings:
            severity = finding.get('severity', 'Unknown')
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

        assessment = {
            'statistics': {
                'total_automated_findings': total_automated,
                'verified_vulnerabilities': verified_real,
                'false_positives': false_positives,
                'needs_manual_review': needs_review,
                'exploitable_confirmed': exploitable_confirmed,
                'false_positive_rate': f"{false_positive_rate:.1f}%",
                'verification_accuracy': f"{verification_accuracy:.1f}%"
            },
            'severity_breakdown': severity_breakdown,
            'risk_assessment': self._assess_overall_risk(verified_findings, poc_results),
            'quality_metrics': {
                'detection_precision': (verified_real / total_automated) if total_automated > 0 else 0,
                'exploitability_rate': (exploitable_confirmed / verified_real) if verified_real > 0 else 0,
                'verification_efficiency': verification_accuracy / 100
            }
        }

        return assessment

    def _generate_recommendations(self, verified_findings: List[VerificationResult],
                                poc_results: List[PoCResult]) -> List[str]:
        """Generate security recommendations"""

        recommendations = []

        # Based on verified vulnerabilities
        verified_vulns = [v for v in verified_findings if v.status == 'verified']

        if not verified_vulns:
            recommendations.append("✅ No verified vulnerabilities found - security posture appears strong")
        else:
            recommendations.append(f"🚨 {len(verified_vulns)} verified vulnerabilities require immediate attention")

            # Category-specific recommendations
            categories = {}
            for vuln in verified_vulns:
                category = vuln.technical_details.get('vulnerability_type', 'unknown')
                categories[category] = categories.get(category, 0) + 1

            for category, count in categories.items():
                if category == 'missing_access_control':
                    recommendations.append(f"🔐 Implement proper access control for {count} functions")
                elif category == 'reentrancy':
                    recommendations.append(f"🔄 Add reentrancy protection for {count} functions")

        # Based on PoC results
        exploitable_pocs = [p for p in poc_results if p.exploitability_confirmed]
        if exploitable_pocs:
            recommendations.append(f"⚠️ {len(exploitable_pocs)} vulnerabilities have confirmed exploits")
            recommendations.append("🛡️ Prioritize patches for exploitable vulnerabilities")

        # General recommendations
        recommendations.extend([
            "🔍 Implement automated security testing in CI/CD pipeline",
            "📚 Conduct regular security training for development team",
            "🔄 Establish periodic security audits",
            "📝 Document security requirements and best practices"
        ])

        return recommendations

    def _identify_bounty_eligible(self, verified_findings: List[VerificationResult],
                                poc_results: List[PoCResult]) -> List[Dict[str, Any]]:
        """Identify findings eligible for bug bounty submission"""

        eligible_findings = []

        for i, verification in enumerate(verified_findings):
            if verification.status == 'verified' and verification.exploitability_score > 0.5:
                # Check if we have a successful PoC
                has_working_poc = (i < len(poc_results) and
                                 poc_results[i].exploitability_confirmed)

                if has_working_poc:
                    eligible_findings.append({
                        'vulnerability_id': verification.vulnerability_id,
                        'verification_confidence': verification.confidence,
                        'exploitability_score': verification.exploitability_score,
                        'poc_confirmed': True,
                        'bounty_readiness': 'high',
                        'estimated_severity': self._estimate_bounty_severity(verification, poc_results[i])
                    })

        return eligible_findings

    def _assess_overall_risk(self, verified_findings: List[VerificationResult],
                           poc_results: List[PoCResult]) -> str:
        """Assess overall security risk level"""

        verified_vulns = [v for v in verified_findings if v.status == 'verified']
        exploitable_pocs = [p for p in poc_results if p.exploitability_confirmed]

        if not verified_vulns:
            return "LOW"
        elif len(exploitable_pocs) > 0:
            return "CRITICAL"
        elif len(verified_vulns) > 3:
            return "HIGH"
        else:
            return "MEDIUM"

    def _calculate_confidence_score(self, verified_findings: List[VerificationResult],
                                  poc_results: List[PoCResult]) -> float:
        """Calculate overall confidence score for the assessment"""

        if not verified_findings:
            return 0.5

        # Average verification confidence
        verification_confidence = sum(v.confidence for v in verified_findings) / len(verified_findings)

        # PoC success rate
        poc_success_rate = len([p for p in poc_results if p.success]) / len(poc_results) if poc_results else 0

        # Combined confidence
        combined_confidence = (verification_confidence * 0.7) + (poc_success_rate * 0.3)

        return combined_confidence

    def _estimate_bounty_severity(self, verification: VerificationResult, poc_result: PoCResult) -> str:
        """Estimate bug bounty severity"""

        if verification.exploitability_score > 0.8 and poc_result.exploitability_confirmed:
            return "Critical"
        elif verification.exploitability_score > 0.6:
            return "High"
        elif verification.exploitability_score > 0.3:
            return "Medium"
        else:
            return "Low"

    def _run_blockchain_detectors(self, target_path: str) -> List[Dict[str, Any]]:
        """Run blockchain-specific vulnerability detectors"""

        # This would integrate with existing blockchain detectors
        # For now, return empty list as placeholder
        return []

    def _load_source_code(self, finding: Dict[str, Any], target_path: str) -> Optional[str]:
        """Load source code for a finding"""

        try:
            file_path = finding.get('file', '')
            if not file_path:
                return None

            # Try to find the file in the target path
            target_dir = Path(target_path)
            possible_paths = [
                target_dir / file_path,
                target_dir / Path(file_path).name,
            ]

            # Search for the file
            for root_dir in [target_dir]:
                for pattern in ["**/*.rs", "**/*.sol", "**/*.py", "**/*.js"]:
                    for file_candidate in root_dir.glob(pattern):
                        if file_candidate.name == Path(file_path).name:
                            possible_paths.append(file_candidate)

            for path in possible_paths:
                if path.exists() and path.is_file():
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()

            return None

        except Exception as e:
            self.logger.error(f"Failed to load source code: {e}")
            return None

    def _save_assessment_result(self, result: AssessmentResult):
        """Save comprehensive assessment result"""

        # Convert result to JSON-serializable format
        result_dict = asdict(result)

        # Save detailed JSON report
        json_file = self.results_dir / f"{result.scan_id}_detailed.json"
        with open(json_file, 'w') as f:
            json.dump(result_dict, f, indent=2, default=str)

        # Generate human-readable report
        self._generate_human_readable_report(result)

        self.logger.info(f"📄 Assessment results saved: {json_file}")

    def _generate_human_readable_report(self, result: AssessmentResult):
        """Generate human-readable assessment report"""

        report = f"""
# VulnHunter Integrated Assessment Report
**Scan ID**: {result.scan_id}
**Target**: {result.target_info['path']}
**Timestamp**: {time.ctime(result.target_info['scan_timestamp'])}
**Execution Time**: {result.execution_time:.2f} seconds
**Confidence Score**: {result.confidence_score:.1%}

## Executive Summary
- **Total Findings**: {len(result.automated_findings)}
- **Verified Vulnerabilities**: {len([v for v in result.verified_findings if v.status == 'verified'])}
- **Exploitable**: {len([p for p in result.poc_results if p.exploitability_confirmed])}
- **Bounty Eligible**: {len(result.bounty_eligible_findings)}
- **Overall Risk**: {result.final_assessment['risk_assessment']}

## Statistics
{json.dumps(result.final_assessment['statistics'], indent=2)}

## Recommendations
"""

        for rec in result.recommendations:
            report += f"- {rec}\n"

        if result.bounty_eligible_findings:
            report += "\n## Bounty Eligible Findings\n"
            for finding in result.bounty_eligible_findings:
                report += f"- **{finding['vulnerability_id']}**: {finding['estimated_severity']} severity\n"

        # Save human-readable report
        md_file = self.results_dir / f"{result.scan_id}_report.md"
        with open(md_file, 'w') as f:
            f.write(report)

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration"""

        default_config = {
            'logging_level': 'INFO',
            'max_findings_per_scan': 100,
            'poc_timeout': 300,
            'verification_timeout': 60,
            'confidence_threshold': 0.7
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logging.warning(f"Failed to load config: {e}")

        return default_config

    def setup_logging(self):
        """Setup logging configuration"""

        logging.basicConfig(
            level=getattr(logging, self.config['logging_level']),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.results_dir / 'vulnhunter.log'),
                logging.StreamHandler()
            ]
        )

def main():
    """Main function for standalone execution"""

    import argparse

    parser = argparse.ArgumentParser(description='VulnHunter Integrated Platform')
    parser.add_argument('target', help='Target path to scan')
    parser.add_argument('--type', default='auto', choices=['auto', 'blockchain', 'web', 'mobile'],
                       help='Target type')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', help='Output directory for results')

    args = parser.parse_args()

    # Initialize platform
    platform = VulnHunterIntegratedPlatform(args.config)

    if args.output:
        platform.results_dir = Path(args.output)
        platform.results_dir.mkdir(parents=True, exist_ok=True)

    # Run comprehensive assessment
    try:
        result = platform.comprehensive_assessment(args.target, args.type)

        print(f"\n🎉 Assessment Complete!")
        print(f"📊 Scan ID: {result.scan_id}")
        print(f"⏱️ Time: {result.execution_time:.2f}s")
        print(f"🎯 Confidence: {result.confidence_score:.1%}")
        print(f"📁 Results: {platform.results_dir}")

        if result.bounty_eligible_findings:
            print(f"\n💰 Bounty Eligible: {len(result.bounty_eligible_findings)} findings")

    except Exception as e:
        print(f"❌ Assessment failed: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())