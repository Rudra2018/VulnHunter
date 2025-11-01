#!/usr/bin/env python3
"""
🔒 Security Context Analyzer - Phase 2 Core Enhancement
=======================================================
Addresses the critical gap identified in Phase 1:
"System detects real code patterns but lacks security expertise
to distinguish intended behavior from vulnerabilities"

Key Functions:
1. Threat model alignment verification
2. Attack scenario plausibility assessment
3. Intended vs vulnerable behavior classification
4. Security expert knowledge integration
"""

import os
import re
import json
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class SecurityContext(Enum):
    INTENDED_BEHAVIOR = "intended_behavior"
    POTENTIAL_VULNERABILITY = "potential_vulnerability"
    FALSE_POSITIVE = "false_positive"
    NEEDS_EXPERT_REVIEW = "needs_expert_review"

@dataclass
class SecurityAssessment:
    context: SecurityContext
    confidence: float
    reasoning: List[str]
    threat_model_alignment: bool
    attack_scenarios: List[str]
    mitigation_present: bool
    documentation_evidence: Optional[str] = None

class ThreatModelAnalyzer:
    """Analyzes code patterns against established threat models"""

    def __init__(self):
        self.threat_models = {
            'flutter_deep_linking': {
                'legitimate_patterns': [
                    r'return true.*deep.*link.*flag.*not.*found',  # Documented Flutter behavior
                    r'Handle.*deep.*link.*enable.*by.*default',
                    r'Intent.*ACTION_VIEW.*handling',
                ],
                'vulnerable_patterns': [
                    r'Intent.*data.*without.*validation',
                    r'deep.*link.*bypass.*authentication',
                    r'url.*scheme.*injection',
                ],
                'security_controls': [
                    r'require.*authentication',
                    r'validate.*intent.*data',
                    r'whitelist.*allowed.*schemes',
                ]
            },
            'access_control': {
                'legitimate_patterns': [
                    r'onlyOwner.*modifier',
                    r'require.*msg\.sender.*==.*owner',
                    r'permission.*check.*before.*action',
                ],
                'vulnerable_patterns': [
                    r'public.*function.*without.*modifier',
                    r'missing.*access.*control',
                    r'privilege.*escalation',
                ],
                'security_controls': [
                    r'modifier.*access.*control',
                    r'role.*based.*permission',
                    r'authorization.*check',
                ]
            }
        }

    def analyze_threat_model_alignment(self, code_pattern: str, vulnerability_type: str) -> Dict[str, Any]:
        """Determine if detected pattern aligns with known threat models"""

        if vulnerability_type not in self.threat_models:
            return {
                'aligned': False,
                'reason': f'Unknown vulnerability type: {vulnerability_type}',
                'confidence': 0.0
            }

        threat_model = self.threat_models[vulnerability_type]

        # Check for legitimate patterns (intended behavior)
        legitimate_matches = []
        for pattern in threat_model['legitimate_patterns']:
            if re.search(pattern, code_pattern, re.IGNORECASE):
                legitimate_matches.append(pattern)

        # Check for vulnerable patterns
        vulnerable_matches = []
        for pattern in threat_model['vulnerable_patterns']:
            if re.search(pattern, code_pattern, re.IGNORECASE):
                vulnerable_matches.append(pattern)

        # Check for security controls
        control_matches = []
        for pattern in threat_model['security_controls']:
            if re.search(pattern, code_pattern, re.IGNORECASE):
                control_matches.append(pattern)

        # Determine alignment
        if legitimate_matches and not vulnerable_matches:
            alignment = True
            reason = f"Matches legitimate patterns: {legitimate_matches}"
            confidence = 0.8
        elif vulnerable_matches and not control_matches:
            alignment = True
            reason = f"Matches vulnerable patterns: {vulnerable_matches}"
            confidence = 0.9
        elif vulnerable_matches and control_matches:
            alignment = False
            reason = f"Vulnerable patterns present but mitigated: {control_matches}"
            confidence = 0.7
        else:
            alignment = False
            reason = "Pattern doesn't match established threat models"
            confidence = 0.3

        return {
            'aligned': alignment,
            'reason': reason,
            'confidence': confidence,
            'legitimate_matches': legitimate_matches,
            'vulnerable_matches': vulnerable_matches,
            'control_matches': control_matches
        }

class AttackScenarioValidator:
    """Validates the plausibility of attack scenarios"""

    def __init__(self):
        self.attack_vectors = {
            'deep_link_manipulation': {
                'prerequisites': ['Intent handling', 'Custom URL schemes', 'No input validation'],
                'impact_levels': ['Data theft', 'Privilege escalation', 'Bypass authentication'],
                'exploitability': 0.7
            },
            'access_control_bypass': {
                'prerequisites': ['Public function', 'Missing modifiers', 'Administrative functionality'],
                'impact_levels': ['Unauthorized access', 'Data modification', 'System compromise'],
                'exploitability': 0.9
            }
        }

    def validate_attack_scenario(self, code_context: str, claimed_vulnerability: str) -> Dict[str, Any]:
        """Validate if the claimed attack scenario is actually plausible"""

        scenarios = []
        total_plausibility = 0.0

        for attack_type, details in self.attack_vectors.items():
            if attack_type.replace('_', ' ') in claimed_vulnerability.lower():

                # Check prerequisites
                prerequisites_met = 0
                for prereq in details['prerequisites']:
                    if re.search(prereq.replace(' ', '.*'), code_context, re.IGNORECASE):
                        prerequisites_met += 1

                prereq_score = prerequisites_met / len(details['prerequisites'])
                plausibility = prereq_score * details['exploitability']

                scenarios.append({
                    'attack_type': attack_type,
                    'prerequisites_met': f"{prerequisites_met}/{len(details['prerequisites'])}",
                    'plausibility': plausibility,
                    'potential_impact': details['impact_levels']
                })

                total_plausibility = max(total_plausibility, plausibility)

        return {
            'scenarios': scenarios,
            'overall_plausibility': total_plausibility,
            'is_plausible': total_plausibility > 0.5,
            'reasoning': f"Attack plausibility: {total_plausibility:.2f} based on prerequisite analysis"
        }

class IntendedBehaviorClassifier:
    """Classifies whether detected patterns represent intended behavior or vulnerabilities"""

    def __init__(self):
        self.documentation_patterns = {
            'flutter': [
                r'Return true if.*deep.*link.*flag.*not found.*metadata',
                r'Default behavior.*enable.*deep.*linking',
                r'Framework.*intended.*behavior',
            ],
            'android': [
                r'Standard.*Intent.*handling',
                r'Recommended.*implementation',
                r'Security.*by.*design',
            ],
            'general': [
                r'By.*design',
                r'Intentional.*behavior',
                r'Default.*configuration',
                r'Framework.*standard',
            ]
        }

    def classify_behavior(self, code_pattern: str, context: str, documentation: str = "") -> SecurityAssessment:
        """Classify whether behavior is intended or vulnerable"""

        reasoning = []

        # Check for documentation evidence
        documentation_evidence = None
        for framework, patterns in self.documentation_patterns.items():
            for pattern in patterns:
                if re.search(pattern, documentation + context, re.IGNORECASE):
                    documentation_evidence = f"Matches {framework} documented pattern: {pattern}"
                    reasoning.append(documentation_evidence)
                    break

        # Check for explicit security controls
        security_controls = [
            r'validation',
            r'authentication',
            r'authorization',
            r'sanitization',
            r'whitelist',
            r'permission.*check'
        ]

        mitigation_present = any(re.search(control, context, re.IGNORECASE)
                               for control in security_controls)

        if mitigation_present:
            reasoning.append("Security controls detected in code context")

        # Classification logic
        if documentation_evidence and not any(vuln in context.lower() for vuln in ['exploit', 'attack', 'bypass']):
            context_classification = SecurityContext.INTENDED_BEHAVIOR
            confidence = 0.8
            reasoning.append("Documented intended behavior with no exploit indicators")

        elif mitigation_present and documentation_evidence:
            context_classification = SecurityContext.INTENDED_BEHAVIOR
            confidence = 0.9
            reasoning.append("Both documentation and security controls present")

        elif not documentation_evidence and not mitigation_present:
            context_classification = SecurityContext.POTENTIAL_VULNERABILITY
            confidence = 0.7
            reasoning.append("No documentation or security controls found")

        else:
            context_classification = SecurityContext.NEEDS_EXPERT_REVIEW
            confidence = 0.5
            reasoning.append("Mixed indicators require expert assessment")

        return SecurityAssessment(
            context=context_classification,
            confidence=confidence,
            reasoning=reasoning,
            threat_model_alignment=True,  # Will be set by threat model analyzer
            attack_scenarios=[],  # Will be populated by attack scenario validator
            mitigation_present=mitigation_present,
            documentation_evidence=documentation_evidence
        )

class SecurityContextAnalyzer:
    """
    Main security context analyzer - Phase 2 core enhancement
    Addresses the critical gap: mathematical analysis without security context
    """

    def __init__(self):
        self.threat_analyzer = ThreatModelAnalyzer()
        self.attack_validator = AttackScenarioValidator()
        self.behavior_classifier = IntendedBehaviorClassifier()
        self.expert_review_threshold = 0.6

    def analyze_security_context(self, finding: Dict[str, Any]) -> SecurityAssessment:
        """
        Comprehensive security context analysis
        Main entry point for Phase 2 enhancement
        """

        # Extract key information from finding
        code_pattern = finding.get('code_pattern', '')
        vulnerability_type = finding.get('type', '')
        file_path = finding.get('file_path', '')
        mathematical_confidence = finding.get('mathematical_confidence', 0.0)

        # Get additional context (would integrate with repository analysis)
        context = self._gather_code_context(file_path, code_pattern)
        documentation = self._gather_documentation_context(file_path)

        # Phase 2.1: Threat model alignment analysis
        threat_analysis = self.threat_analyzer.analyze_threat_model_alignment(
            code_pattern, vulnerability_type
        )

        # Phase 2.2: Attack scenario validation
        attack_analysis = self.attack_validator.validate_attack_scenario(
            context, finding.get('description', '')
        )

        # Phase 2.3: Intended behavior classification
        behavior_assessment = self.behavior_classifier.classify_behavior(
            code_pattern, context, documentation
        )

        # Phase 2.4: Integration and expert review decision
        final_assessment = self._integrate_assessments(
            behavior_assessment, threat_analysis, attack_analysis, mathematical_confidence
        )

        return final_assessment

    def _gather_code_context(self, file_path: str, code_pattern: str) -> str:
        """Gather surrounding code context for analysis"""
        # This would integrate with the repository analysis to get actual code context
        # For now, return the pattern itself
        return code_pattern

    def _gather_documentation_context(self, file_path: str) -> str:
        """Gather relevant documentation for the code"""
        # This would search for README files, API docs, comments, etc.
        # For now, simulate based on file path
        if 'flutter' in file_path.lower():
            return "Flutter framework default behavior for deep linking"
        return ""

    def _integrate_assessments(self, behavior: SecurityAssessment, threat: Dict, attack: Dict, math_conf: float) -> SecurityAssessment:
        """Integrate all assessments into final security context determination"""

        # Combine reasoning from all analyses
        combined_reasoning = behavior.reasoning.copy()
        combined_reasoning.append(f"Threat model alignment: {threat['reason']}")
        combined_reasoning.append(f"Attack plausibility: {attack['reasoning']}")

        # Determine final context based on multiple factors
        if (behavior.context == SecurityContext.INTENDED_BEHAVIOR and
            threat['aligned'] and not attack['is_plausible']):
            final_context = SecurityContext.INTENDED_BEHAVIOR
            final_confidence = min(0.9, behavior.confidence + 0.1)

        elif (behavior.context == SecurityContext.POTENTIAL_VULNERABILITY and
              threat['aligned'] and attack['is_plausible']):
            final_context = SecurityContext.POTENTIAL_VULNERABILITY
            final_confidence = min(0.9, behavior.confidence + 0.2)

        elif behavior.confidence < self.expert_review_threshold:
            final_context = SecurityContext.NEEDS_EXPERT_REVIEW
            final_confidence = behavior.confidence

        else:
            final_context = SecurityContext.FALSE_POSITIVE
            final_confidence = 0.8
            combined_reasoning.append("Multiple indicators suggest false positive")

        return SecurityAssessment(
            context=final_context,
            confidence=final_confidence,
            reasoning=combined_reasoning,
            threat_model_alignment=threat['aligned'],
            attack_scenarios=attack['scenarios'],
            mitigation_present=behavior.mitigation_present,
            documentation_evidence=behavior.documentation_evidence
        )

def test_security_context_analyzer():
    """Test the security context analyzer with Flutter example"""
    print("🔒 Testing Security Context Analyzer - Phase 2")
    print("=" * 50)

    analyzer = SecurityContextAnalyzer()

    # Test case: Flutter deep linking (the actual case we encountered)
    flutter_finding = {
        'code_pattern': 'return true; // Return true if the deep linking flag is not found in metadata',
        'type': 'access_control_bypass',
        'file_path': 'flutter/engine/android/FlutterActivityLaunchConfigs.java',
        'description': 'Deep linking defaults to true when metadata missing',
        'mathematical_confidence': 0.7
    }

    assessment = analyzer.analyze_security_context(flutter_finding)

    print(f"Security Context: {assessment.context.value}")
    print(f"Confidence: {assessment.confidence:.2f}")
    print(f"Threat Model Aligned: {assessment.threat_model_alignment}")
    print(f"Mitigation Present: {assessment.mitigation_present}")
    print(f"Documentation Evidence: {assessment.documentation_evidence}")
    print("\nReasoning:")
    for reason in assessment.reasoning:
        print(f"  • {reason}")

    print(f"\nAttack Scenarios:")
    for scenario in assessment.attack_scenarios:
        print(f"  • {scenario}")

if __name__ == "__main__":
    test_security_context_analyzer()