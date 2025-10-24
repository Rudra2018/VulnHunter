#!/usr/bin/env python3
"""
BNB Chain Security Findings Validator
Validates high-risk findings from our security assessment using VulnForge models
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent / 'src'))

try:
    from vulnforge_production_ensemble import VulnForgeProductionEnsemble
    from vulnhunter_unified_production import VulnHunterUnified
except ImportError as e:
    print(f"Warning: Could not import VulnHunter modules: {e}")

class BNBChainFindingsValidator:
    """Validates BNB Chain security findings using VulnForge ensemble"""

    def __init__(self):
        self.validation_results = []
        self.timestamp = datetime.now().isoformat()

        # Initialize VulnForge if available
        self.vulnforge = None
        try:
            self.vulnforge = VulnForgeProductionEnsemble()
            print("✅ VulnForge Production Ensemble initialized for validation")
        except Exception as e:
            print(f"⚠️  VulnForge not available: {e}")

        # Initialize VulnHunter if available
        self.vulnhunter = None
        try:
            self.vulnhunter = VulnHunterUnified()
            print("✅ VulnHunter Unified initialized for validation")
        except Exception as e:
            print(f"⚠️  VulnHunter not available: {e}")

    def load_security_report(self, report_path: str) -> dict:
        """Load the generated security report"""
        try:
            with open(report_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading report: {e}")
            return {}

    def validate_high_risk_findings(self, report_data: dict) -> dict:
        """Validate high-risk findings using ensemble models"""
        print("🔍 Validating High-Risk Findings...")

        validation_results = {
            'validation_timestamp': self.timestamp,
            'total_files_validated': 0,
            'confirmed_vulnerabilities': [],
            'false_positives': [],
            'validation_summary': {}
        }

        files_analyzed = report_data.get('detailed_findings', {}).get('files_analyzed', [])
        high_risk_files = [f for f in files_analyzed if f.get('risk_score', 0) > 0.7]

        print(f"📊 Found {len(high_risk_files)} high-risk files to validate")

        for file_data in high_risk_files[:5]:  # Validate top 5 high-risk files
            file_path = file_data.get('file', 'unknown')
            risk_score = file_data.get('risk_score', 0)
            vulnerabilities = file_data.get('vulnerabilities', [])

            print(f"🔍 Validating: {Path(file_path).name} (Risk: {risk_score:.2f})")

            # Try to read the actual file content for validation
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    validation_result = self.validate_file_content(file_path, content, vulnerabilities)
                    validation_results['confirmed_vulnerabilities'].append(validation_result)

                else:
                    print(f"   ⚠️  File not found for validation: {file_path}")

            except Exception as e:
                print(f"   ❌ Validation error for {file_path}: {e}")

        validation_results['total_files_validated'] = len(validation_results['confirmed_vulnerabilities'])
        validation_results['validation_summary'] = self.generate_validation_summary(validation_results)

        return validation_results

    def validate_file_content(self, file_path: str, content: str, vulnerabilities: list) -> dict:
        """Validate a single file's vulnerabilities using VulnForge ensemble"""

        validation_result = {
            'file': file_path,
            'original_vulnerabilities': len(vulnerabilities),
            'confirmed_by_vulnforge': 0,
            'confidence_scores': [],
            'validation_details': [],
            'recommended_actions': []
        }

        # VulnForge validation
        if self.vulnforge:
            try:
                # Analyze with VulnForge ensemble using correct method
                vulnforge_result = self.vulnforge.predict_vulnerability(
                    code_sample=content[:2000],  # First 2KB for analysis
                    app_type='blockchain'
                )

                if vulnforge_result.get('is_vulnerable', False):
                    validation_result['confirmed_by_vulnforge'] = 1
                    validation_result['confidence_scores'].append(vulnforge_result.get('confidence', 0))

                    print(f"   ✅ VulnForge confirms vulnerability (Confidence: {vulnforge_result.get('confidence', 0):.2f})")

                    validation_result['validation_details'].append({
                        'validator': 'VulnForge_Ensemble',
                        'confirmed': True,
                        'confidence': vulnforge_result.get('confidence', 0),
                        'detected_types': vulnforge_result.get('vulnerability_types', []),
                        'risk_level': vulnforge_result.get('risk_level', 'UNKNOWN')
                    })
                else:
                    print(f"   ⚠️  VulnForge: No high-confidence vulnerabilities detected")
                    validation_result['validation_details'].append({
                        'validator': 'VulnForge_Ensemble',
                        'confirmed': False,
                        'confidence': vulnforge_result.get('confidence', 0),
                        'notes': 'No vulnerabilities confirmed by ensemble'
                    })

            except Exception as e:
                print(f"   ❌ VulnForge validation failed: {e}")

        # VulnHunter validation
        if self.vulnhunter:
            try:
                # Use VulnHunter predict method
                vh_assessment = self.vulnhunter.predict(
                    code_content=content[:1500]
                )

                if vh_assessment.get('has_vulnerabilities', False):
                    validation_result['confirmed_by_vulnforge'] += 1
                    validation_result['confidence_scores'].append(vh_assessment.get('confidence', 0))

                    print(f"   ✅ VulnHunter confirms security concerns")

                    validation_result['validation_details'].append({
                        'validator': 'VulnHunter_Unified',
                        'confirmed': True,
                        'impact_score': vh_assessment.get('impact_score', 0),
                        'security_concerns': vh_assessment.get('security_concerns', [])
                    })

            except Exception as e:
                print(f"   ⚠️  VulnHunter validation method not available: {e}")

        # Generate recommendations based on validation
        if validation_result['confirmed_by_vulnforge'] > 0:
            validation_result['recommended_actions'] = [
                "Conduct immediate manual code review",
                "Implement additional security controls",
                "Consider formal verification for critical functions",
                "Add comprehensive unit tests for security edge cases"
            ]
        else:
            validation_result['recommended_actions'] = [
                "Review static analysis patterns for false positives",
                "Conduct additional testing with different inputs",
                "Consider consulting security experts for second opinion"
            ]

        return validation_result

    def generate_validation_summary(self, validation_results: dict) -> dict:
        """Generate summary of validation results"""
        confirmed_files = validation_results['confirmed_vulnerabilities']

        total_confirmed = len([f for f in confirmed_files if f['confirmed_by_vulnforge'] > 0])
        avg_confidence = 0

        if confirmed_files:
            all_scores = []
            for f in confirmed_files:
                all_scores.extend(f.get('confidence_scores', []))
            if all_scores:
                avg_confidence = sum(all_scores) / len(all_scores)

        return {
            'files_validated': len(confirmed_files),
            'vulnerabilities_confirmed': total_confirmed,
            'confirmation_rate': total_confirmed / len(confirmed_files) if confirmed_files else 0,
            'average_confidence': avg_confidence,
            'validation_status': 'HIGH_CONFIDENCE' if avg_confidence > 0.8 else 'MEDIUM_CONFIDENCE' if avg_confidence > 0.5 else 'LOW_CONFIDENCE'
        }

    def generate_validation_report(self, validation_results: dict, output_file: str):
        """Generate comprehensive validation report"""

        report = {
            'validation_info': {
                'target': 'BNB Chain Bug Bounty - High Risk Findings Validation',
                'validator': 'VulnForge Production Ensemble + VulnHunter Unified',
                'timestamp': self.timestamp,
                'methodology': 'Multi-model ensemble validation with confidence scoring'
            },
            'validation_summary': validation_results.get('validation_summary', {}),
            'detailed_validation': validation_results,
            'recommendations': {
                'immediate_actions': [
                    'Focus manual review on confirmed high-confidence findings',
                    'Prioritize smart contracts with multiple model confirmations',
                    'Implement recommended security controls for validated vulnerabilities'
                ],
                'bug_bounty_strategy': [
                    'Submit confirmed vulnerabilities with highest confidence scores',
                    'Prepare detailed proof-of-concept for validated findings',
                    'Document validation methodology in submission'
                ]
            }
        }

        # Save validation report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📋 Validation report saved: {output_file}")
        return report

def main():
    """Main validation execution"""
    print("🛡️ BNB Chain Security Findings Validator")
    print("🎯 Using VulnForge Ensemble + VulnHunter Unified")
    print("=" * 60)

    validator = BNBChainFindingsValidator()

    # Load the security report
    report_path = 'results/reconnaissance_security_report.json'
    if not os.path.exists(report_path):
        print(f"❌ Security report not found: {report_path}")
        return

    print(f"📊 Loading security report: {report_path}")
    report_data = validator.load_security_report(report_path)

    if not report_data:
        print("❌ Failed to load security report")
        return

    # Validate high-risk findings
    validation_results = validator.validate_high_risk_findings(report_data)

    # Generate validation report
    validation_report_path = 'results/bnb_chain_validation_report.json'
    validation_report = validator.generate_validation_report(validation_results, validation_report_path)

    # Print summary
    print("\n✅ BNB Chain Findings Validation Complete!")
    print("=" * 60)
    print(f"📊 Validation Summary:")
    summary = validation_results.get('validation_summary', {})
    print(f"   Files Validated: {summary.get('files_validated', 0)}")
    print(f"   Vulnerabilities Confirmed: {summary.get('vulnerabilities_confirmed', 0)}")
    print(f"   Confirmation Rate: {summary.get('confirmation_rate', 0)*100:.1f}%")
    print(f"   Average Confidence: {summary.get('average_confidence', 0):.2f}")
    print(f"   Validation Status: {summary.get('validation_status', 'UNKNOWN')}")
    print()
    print(f"📋 Validation report saved: {validation_report_path}")
    print("🔍 Review validated findings for bug bounty submissions")

if __name__ == "__main__":
    main()