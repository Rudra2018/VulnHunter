#!/usr/bin/env python3
"""
VulnHunter Learning Module - False Positive Detection and Real-World Validation
Critical Learnings from Sherlock Usual DAO Analysis

Key Learning: Analysis based on sample code != Production vulnerabilities
The comprehensive analysis incorrectly identified 31 vulnerabilities in sample contracts,
but these do not exist in the audited, production USD0 protocol.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Set, Optional
from dataclasses import dataclass

@dataclass
class LearningPoint:
    category: str
    issue: str
    reality_check: str
    model_improvement: str
    confidence_adjustment: float

class VulnHunterLearningModule:
    def __init__(self):
        self.learning_points = []
        self.false_positive_patterns = set()
        self.validation_requirements = {}

        # Initialize with Sherlock Usual DAO learnings
        self._initialize_sherlock_learnings()

    def _initialize_sherlock_learnings(self):
        """Initialize learning points from Sherlock Usual DAO analysis"""

        # Critical Learning 1: Sample Code vs Production
        self.add_learning_point(LearningPoint(
            category="Source Code Validation",
            issue="Analyzed sample contracts with planted vulnerabilities instead of production code",
            reality_check="Production USD0 protocol has 0 Critical, 2 High (fixed), clean audit history",
            model_improvement="ALWAYS verify contract source from Etherscan/official sources before analysis",
            confidence_adjustment=-0.8
        ))

        # Critical Learning 2: Audit History Research
        self.add_learning_point(LearningPoint(
            category="Audit Context",
            issue="Failed to research existing audit reports before claiming vulnerabilities",
            reality_check="Usual Labs: Multiple audits (Sherlock, Spearbit, Halborn) with clean results",
            model_improvement="Mandatory audit history check before vulnerability claims",
            confidence_adjustment=-0.7
        ))

        # Critical Learning 3: Bug Bounty Scope Understanding
        self.add_learning_point(LearningPoint(
            category="Bounty Program Rules",
            issue="Claimed vulnerabilities that are explicitly out-of-scope",
            reality_check="Many findings (oracle issues, gas optimizations, theoretical attacks) excluded",
            model_improvement="Parse bounty scope carefully, exclude known out-of-scope patterns",
            confidence_adjustment=-0.6
        ))

        # Critical Learning 4: Duplicate Detection
        self.add_learning_point(LearningPoint(
            category="Duplicate Identification",
            issue="Claimed 'new' findings that were already identified and fixed in audits",
            reality_check="Sherlock explicitly excludes known issues and duplicates",
            model_improvement="Cross-reference findings against historical audit reports",
            confidence_adjustment=-0.9
        ))

        # Critical Learning 5: Production vs Development Code
        self.add_learning_point(LearningPoint(
            category="Code Environment",
            issue="Analyzed development/sample code instead of deployed mainnet contracts",
            reality_check="Sample code had explicit '// Vulnerable' comments - not production",
            model_improvement="Distinguish between sample/test code and audited production deployments",
            confidence_adjustment=-0.95
        ))

    def add_learning_point(self, learning_point: LearningPoint):
        """Add a new learning point to the module"""
        self.learning_points.append(learning_point)

    def validate_vulnerability_claim(self,
                                   vulnerability: Dict,
                                   contract_address: str,
                                   program_context: Dict) -> Dict:
        """
        Validate vulnerability claims against learned patterns
        Returns validation result with confidence adjustments
        """
        validation_result = {
            "original_confidence": vulnerability.get("confidence", 0.5),
            "adjusted_confidence": vulnerability.get("confidence", 0.5),
            "validation_flags": [],
            "reality_check_required": False,
            "recommended_action": "proceed"
        }

        # Check 1: Source Code Validation
        if self._is_sample_code_pattern(vulnerability):
            validation_result["validation_flags"].append("SAMPLE_CODE_PATTERN_DETECTED")
            validation_result["adjusted_confidence"] *= 0.1
            validation_result["reality_check_required"] = True

        # Check 2: Audit History Check
        if not self._has_audit_verification(program_context):
            validation_result["validation_flags"].append("MISSING_AUDIT_HISTORY_CHECK")
            validation_result["adjusted_confidence"] *= 0.3

        # Check 3: Bug Bounty Scope Check
        if self._is_out_of_scope_pattern(vulnerability, program_context):
            validation_result["validation_flags"].append("LIKELY_OUT_OF_SCOPE")
            validation_result["adjusted_confidence"] *= 0.2
            validation_result["recommended_action"] = "reject"

        # Check 4: Known Issue Pattern
        if self._matches_known_issue_pattern(vulnerability):
            validation_result["validation_flags"].append("MATCHES_KNOWN_FIXED_ISSUE")
            validation_result["adjusted_confidence"] *= 0.05
            validation_result["recommended_action"] = "reject"

        # Final recommendation
        if validation_result["adjusted_confidence"] < 0.1:
            validation_result["recommended_action"] = "reject"
        elif validation_result["adjusted_confidence"] < 0.3:
            validation_result["recommended_action"] = "investigate"
        elif validation_result["reality_check_required"]:
            validation_result["recommended_action"] = "verify_production_code"

        return validation_result

    def _is_sample_code_pattern(self, vulnerability: Dict) -> bool:
        """Detect if vulnerability is from sample/test code"""
        code_snippet = vulnerability.get("code_snippet", "")
        file_path = vulnerability.get("file_path", "")

        sample_indicators = [
            "// Vulnerable:",
            "// VULNERABLE",
            "Sample implementation",
            "sample_",
            "test_",
            "example_",
            "demo_",
            "planted vulnerability"
        ]

        return any(indicator.lower() in code_snippet.lower() or
                  indicator.lower() in file_path.lower()
                  for indicator in sample_indicators)

    def _has_audit_verification(self, program_context: Dict) -> bool:
        """Check if audit history was verified"""
        return program_context.get("audit_history_checked", False)

    def _is_out_of_scope_pattern(self, vulnerability: Dict, program_context: Dict) -> bool:
        """Check if vulnerability matches out-of-scope patterns"""

        # Common out-of-scope patterns for bug bounty programs
        out_of_scope_patterns = [
            "pure gas optimization",
            "theoretical attack",
            "third-party oracle",
            "frontend vulnerability",
            "known issue",
            "timestamp manipulation by miners",
            "unbounded loop gas",
            "minor informational"
        ]

        vuln_description = vulnerability.get("description", "").lower()
        vuln_title = vulnerability.get("title", "").lower()

        return any(pattern in vuln_description or pattern in vuln_title
                  for pattern in out_of_scope_patterns)

    def _matches_known_issue_pattern(self, vulnerability: Dict) -> bool:
        """Check if vulnerability matches known fixed issues"""

        # Patterns that commonly appear in audits but are fixed pre-deployment
        known_fixed_patterns = [
            "missing reentrancy guard",
            "unchecked external call",
            "missing access control on update",
            "oracle staleness check",
            "pausing mechanism bypass"
        ]

        vuln_description = vulnerability.get("description", "").lower()

        return any(pattern in vuln_description for pattern in known_fixed_patterns)

    def get_production_code_verification_steps(self, contract_address: str) -> List[str]:
        """Get steps to verify production code"""
        return [
            f"1. Verify contract source code at Etherscan: https://etherscan.io/address/{contract_address}#code",
            "2. Check if contract is verified and matches claimed vulnerabilities",
            "3. Review recent audit reports for the protocol",
            "4. Check bug bounty program for known exclusions",
            "5. Search for recent security incidents or disclosures",
            "6. Verify deployment date vs audit completion dates",
            "7. Check if issues were fixed in post-audit deployments"
        ]

    def generate_reality_check_report(self, findings: List[Dict], program_name: str) -> str:
        """Generate a reality check report for findings"""

        total_findings = len(findings)
        high_confidence = len([f for f in findings if f.get("confidence", 0) > 0.7])
        sample_code_flags = len([f for f in findings if self._is_sample_code_pattern(f)])

        report = f"""
# 🔍 VulnHunter Reality Check Report - {program_name}

## 📊 Analysis Summary
- **Total Findings:** {total_findings}
- **High Confidence (>70%):** {high_confidence}
- **Sample Code Patterns Detected:** {sample_code_flags}

## 🚨 Critical Validation Alerts

"""

        if sample_code_flags > 0:
            report += f"""
### ⚠️ SAMPLE CODE DETECTION
- **{sample_code_flags} findings** appear to be from sample/test code
- **Action Required:** Verify against production deployed contracts
- **Risk:** High false positive rate

"""

        if total_findings > 0 and sample_code_flags / total_findings > 0.5:
            report += """
### 🛑 ANALYSIS VALIDITY CONCERN
- **>50% of findings** show sample code patterns
- **Recommendation:** HALT submission process
- **Next Steps:** Re-analyze production contracts only

"""

        report += f"""
## 📋 Required Validation Steps

{chr(10).join(self.get_production_code_verification_steps("TARGET_CONTRACT"))}

## 🎯 Learning Points Applied

"""

        for i, learning in enumerate(self.learning_points, 1):
            report += f"""
### {i}. {learning.category}
- **Issue:** {learning.issue}
- **Reality:** {learning.reality_check}
- **Improvement:** {learning.model_improvement}

"""

        return report

    def update_scanner_patterns(self) -> Dict:
        """Update scanner patterns based on learnings"""

        updated_patterns = {
            "pre_analysis_checks": [
                "verify_contract_source_from_etherscan",
                "check_audit_history",
                "review_bug_bounty_scope",
                "identify_sample_vs_production_code"
            ],

            "validation_filters": [
                "exclude_sample_code_patterns",
                "exclude_known_fixed_issues",
                "exclude_out_of_scope_patterns",
                "require_production_verification"
            ],

            "confidence_adjustments": {
                "sample_code_detected": -0.8,
                "audit_history_missing": -0.3,
                "out_of_scope_pattern": -0.7,
                "known_fixed_pattern": -0.9,
                "production_unverified": -0.6
            }
        }

        return updated_patterns

def main():
    """Demonstrate the learning module"""
    learning_module = VulnHunterLearningModule()

    # Example: Validate the Sherlock findings
    sample_vulnerability = {
        "title": "Oracle Price Manipulation",
        "confidence": 0.88,
        "description": "Oracle price manipulation vulnerability in ClassicalOracle",
        "code_snippet": "// Vulnerable: No staleness check",
        "file_path": "sample_usd0_contracts/ClassicalOracle.sol"
    }

    program_context = {
        "name": "Sherlock Usual DAO",
        "audit_history_checked": False,
        "production_verified": False
    }

    # Validate the vulnerability
    validation_result = learning_module.validate_vulnerability_claim(
        sample_vulnerability,
        "0x73a15fed60bf67631dc6cd7bc5b6e8da8190acf5",
        program_context
    )

    print("🔍 Vulnerability Validation Result:")
    print(f"Original Confidence: {validation_result['original_confidence']}")
    print(f"Adjusted Confidence: {validation_result['adjusted_confidence']:.3f}")
    print(f"Flags: {validation_result['validation_flags']}")
    print(f"Recommendation: {validation_result['recommended_action']}")

    # Generate reality check report
    findings = [sample_vulnerability]
    reality_report = learning_module.generate_reality_check_report(findings, "Sherlock Usual DAO")

    # Save learning session
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    with open(f'/Users/ankitthakur/vuln_ml_research/production/LEARNING_SESSION_REPORT.md', 'w') as f:
        f.write(reality_report)

    print(f"\n✅ Learning module updated with Sherlock insights")
    print(f"📄 Reality check report saved")

if __name__ == "__main__":
    main()