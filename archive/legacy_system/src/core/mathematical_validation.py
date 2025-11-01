#!/usr/bin/env python3
"""
🔬 Mathematical Validation Framework - Phase 1 Foundation Fix
===========================================================
Prevents mathematically impossible results and fabricated outputs
Based on 1.txt Phase 1.2: Math Rigor requirements

Key Goals:
- Eliminate negative spectral gaps
- Validate Ricci curvature bounds
- Ensure persistent homology consistency
- Prevent arbitrary confidence scores
"""

import numpy as np
import math
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
import warnings

@dataclass
class ValidationResult:
    """Structured validation result"""
    is_valid: bool
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    corrected_value: Optional[Any] = None
    confidence_impact: float = 0.0  # How much this reduces confidence

class MathematicalValidator:
    """
    Phase 1.2 Mathematical Rigor Implementation
    Validates all mathematical results to prevent impossible outputs
    """

    def __init__(self):
        self.validation_failed = []
        self.corrections_applied = []

    def validate_spectral_gap(self, spectral_gap: float, eigenvalues: List[float] = None) -> ValidationResult:
        """
        CRITICAL FIX: Ensure spectral gap is always non-negative
        From 1.txt: "Spectral Gap Error: Used lambda_min - lambda_max (negative result)"
        """
        # Rule 1: Spectral gaps must be non-negative
        if spectral_gap < 0:
            if eigenvalues and len(eigenvalues) > 1:
                sorted_eigenvalues = np.sort(eigenvalues)
                # Correct formula: difference between 2nd smallest and smallest
                corrected_gap = abs(sorted_eigenvalues[1] - sorted_eigenvalues[0])
            else:
                corrected_gap = 0.0

            return ValidationResult(
                is_valid=False,
                error_type="NEGATIVE_SPECTRAL_GAP",
                error_message=f"Spectral gap cannot be negative: {spectral_gap}. Mathematical impossibility.",
                corrected_value=corrected_gap,
                confidence_impact=-0.5  # Major confidence reduction
            )

        # Rule 2: Spectral gaps should be bounded for finite graphs
        if spectral_gap > 100.0:  # Unrealistic for most code graphs
            return ValidationResult(
                is_valid=False,
                error_type="EXCESSIVE_SPECTRAL_GAP",
                error_message=f"Spectral gap too large: {spectral_gap}. Likely computational error.",
                corrected_value=min(spectral_gap, 10.0),
                confidence_impact=-0.2
            )

        return ValidationResult(is_valid=True)

    def validate_ricci_curvature(self, ricci_value: float, context: str = "") -> ValidationResult:
        """
        Validate Ricci curvature bounds for discrete graphs
        From 1.txt: "Ricci Curvature Misapplication: Differential geometry on discrete graphs"
        """
        # Rule 1: Ricci curvature on graphs should be bounded
        if ricci_value < -2.0 or ricci_value > 2.0:
            corrected_value = max(-2.0, min(2.0, ricci_value))
            return ValidationResult(
                is_valid=False,
                error_type="RICCI_OUT_OF_BOUNDS",
                error_message=f"Ricci curvature {ricci_value} outside reasonable bounds [-2, 2] for discrete graphs",
                corrected_value=corrected_value,
                confidence_impact=-0.3
            )

        # Rule 2: Check for systematic misapplication
        if ricci_value == -1.0 and "terminal" in context.lower():
            return ValidationResult(
                is_valid=False,
                error_type="RICCI_TERMINAL_MISAPPLICATION",
                error_message="Ricci curvature -1.0 systematically assigned to terminal nodes (false positive pattern)",
                corrected_value=0.0,  # Neutral for normal terminals
                confidence_impact=-0.4
            )

        return ValidationResult(is_valid=True)

    def validate_persistent_homology(self, holes: int, persistence: float, points_count: int) -> ValidationResult:
        """
        Validate persistent homology results for code analysis
        From 1.txt: "Persistent Homology Misuse: Applied to code graphs without meaning"
        """
        # Rule 1: Holes count should be reasonable for code graphs
        if holes < 0:
            return ValidationResult(
                is_valid=False,
                error_type="NEGATIVE_HOLES",
                error_message=f"Negative hole count: {holes}. Mathematical impossibility.",
                corrected_value=0,
                confidence_impact=-0.4
            )

        # Rule 2: Too many holes relative to points suggests computational error
        if points_count > 0 and holes > points_count:
            return ValidationResult(
                is_valid=False,
                error_type="EXCESSIVE_HOLES",
                error_message=f"More holes ({holes}) than points ({points_count}). Computational error.",
                corrected_value=min(holes, points_count // 2),
                confidence_impact=-0.3
            )

        # Rule 3: Persistence should be non-negative
        if persistence < 0:
            return ValidationResult(
                is_valid=False,
                error_type="NEGATIVE_PERSISTENCE",
                error_message=f"Negative persistence: {persistence}. Mathematical impossibility.",
                corrected_value=0.0,
                confidence_impact=-0.3
            )

        return ValidationResult(is_valid=True)

    def validate_confidence_score(self, confidence: float, basis: str = "") -> ValidationResult:
        """
        Validate confidence scores to prevent arbitrary/fabricated values
        From 1.txt: "Overconfidence in AI outputs without validation"
        """
        # Rule 1: Confidence must be in [0, 1]
        if confidence < 0 or confidence > 1:
            corrected_value = max(0.0, min(1.0, confidence))
            return ValidationResult(
                is_valid=False,
                error_type="CONFIDENCE_OUT_OF_BOUNDS",
                error_message=f"Confidence {confidence} outside [0,1] range",
                corrected_value=corrected_value,
                confidence_impact=-0.2
            )

        # Rule 2: Suspiciously high confidence without strong basis
        if confidence > 0.8 and "mathematical" in basis.lower():
            return ValidationResult(
                is_valid=False,
                error_type="OVERCONFIDENT_MATHEMATICAL",
                error_message=f"Confidence {confidence} too high for mathematical analysis without code validation",
                corrected_value=min(confidence, 0.6),
                confidence_impact=-0.2
            )

        # Rule 3: Specific suspicious values (from fabrication analysis)
        suspicious_values = [0.7, 0.75, 0.8, 0.85, 0.9, 0.95]
        if any(abs(confidence - val) < 0.001 for val in suspicious_values):
            if "calibrated" not in basis.lower() and "validated" not in basis.lower():
                return ValidationResult(
                    is_valid=False,
                    error_type="SUSPICIOUS_CONFIDENCE_VALUE",
                    error_message=f"Confidence {confidence} appears to be arbitrary/uncalibrated",
                    corrected_value=confidence * 0.7,  # Reduce by 30%
                    confidence_impact=-0.1
                )

        return ValidationResult(is_valid=True)

    def validate_eigenvalues(self, eigenvalues: List[float], matrix_size: int) -> ValidationResult:
        """
        Validate eigenvalue computations for graph Laplacians
        """
        if not eigenvalues:
            return ValidationResult(
                is_valid=False,
                error_type="EMPTY_EIGENVALUES",
                error_message="Empty eigenvalue list",
                confidence_impact=-0.3
            )

        # Rule 1: For graph Laplacians, smallest eigenvalue should be 0 (or very close)
        sorted_eigenvalues = np.sort(eigenvalues)
        if abs(sorted_eigenvalues[0]) > 1e-6:
            return ValidationResult(
                is_valid=False,
                error_type="LAPLACIAN_ZERO_EIGENVALUE",
                error_message=f"Graph Laplacian should have zero eigenvalue, got {sorted_eigenvalues[0]}",
                confidence_impact=-0.2
            )

        # Rule 2: All eigenvalues should be non-negative for Laplacian
        if any(eig < -1e-6 for eig in eigenvalues):
            return ValidationResult(
                is_valid=False,
                error_type="NEGATIVE_LAPLACIAN_EIGENVALUE",
                error_message="Graph Laplacian eigenvalues should be non-negative",
                confidence_impact=-0.3
            )

        # Rule 3: Number of eigenvalues should match matrix size
        if len(eigenvalues) != matrix_size:
            return ValidationResult(
                is_valid=False,
                error_type="EIGENVALUE_COUNT_MISMATCH",
                error_message=f"Expected {matrix_size} eigenvalues, got {len(eigenvalues)}",
                confidence_impact=-0.2
            )

        return ValidationResult(is_valid=True)

    def validate_mathematical_output(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive validation of mathematical analysis results
        Implementation of 1.txt requirement: "Add mathematical validation functions"
        """
        validated_result = result.copy()
        validation_issues = []
        total_confidence_impact = 0.0

        # Validate spectral analysis
        if 'spectral_analysis' in result:
            spectral = result['spectral_analysis']
            if 'spectral_gap' in spectral:
                eigenvalues = spectral.get('eigenvalues', [])
                gap_validation = self.validate_spectral_gap(
                    spectral['spectral_gap'],
                    eigenvalues
                )
                if not gap_validation.is_valid:
                    validation_issues.append(gap_validation)
                    validated_result['spectral_analysis']['spectral_gap'] = gap_validation.corrected_value
                    total_confidence_impact += gap_validation.confidence_impact

                # Validate eigenvalues if present
                if eigenvalues:
                    matrix_size = len(eigenvalues)
                    eig_validation = self.validate_eigenvalues(eigenvalues, matrix_size)
                    if not eig_validation.is_valid:
                        validation_issues.append(eig_validation)
                        total_confidence_impact += eig_validation.confidence_impact

        # Validate Ricci curvature analysis
        if 'ricci_analysis' in result:
            ricci = result['ricci_analysis']
            if 'ricci_curvatures' in ricci:
                for edge, curvature in ricci['ricci_curvatures'].items():
                    ricci_validation = self.validate_ricci_curvature(curvature)
                    if not ricci_validation.is_valid:
                        validation_issues.append(ricci_validation)
                        validated_result['ricci_analysis']['ricci_curvatures'][edge] = ricci_validation.corrected_value
                        total_confidence_impact += ricci_validation.confidence_impact

        # Validate persistent homology
        if 'homology_analysis' in result:
            homology = result['homology_analysis']
            if 'homology_analysis' in homology:
                h_result = homology['homology_analysis']
                holes = h_result.get('h1_holes', 0)
                persistence = h_result.get('max_persistence', 0.0)
                points = h_result.get('points_analyzed', 0)

                homology_validation = self.validate_persistent_homology(holes, persistence, points)
                if not homology_validation.is_valid:
                    validation_issues.append(homology_validation)
                    total_confidence_impact += homology_validation.confidence_impact

        # Validate confidence scores
        if 'mathematical_confidence' in result:
            confidence = result['mathematical_confidence']
            confidence_validation = self.validate_confidence_score(confidence, "mathematical analysis")
            if not confidence_validation.is_valid:
                validation_issues.append(confidence_validation)
                validated_result['mathematical_confidence'] = confidence_validation.corrected_value
                total_confidence_impact += confidence_validation.confidence_impact

        # Apply total confidence impact
        if total_confidence_impact < 0 and 'mathematical_confidence' in validated_result:
            original_confidence = validated_result['mathematical_confidence']
            adjusted_confidence = max(0.0, original_confidence + total_confidence_impact)
            validated_result['mathematical_confidence'] = adjusted_confidence

        # Add validation metadata
        validated_result['validation_metadata'] = {
            'validator_version': "Phase_1_Mathematical_Validator_v1.0",
            'validation_issues_count': len(validation_issues),
            'validation_issues': [
                {
                    'type': issue.error_type,
                    'message': issue.error_message,
                    'confidence_impact': issue.confidence_impact
                }
                for issue in validation_issues
            ],
            'total_confidence_reduction': abs(total_confidence_impact),
            'mathematically_valid': len(validation_issues) == 0
        }

        # Store issues for debugging
        self.validation_failed.extend(validation_issues)

        return validated_result

    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of all validation issues encountered"""
        issue_counts = {}
        for issue in self.validation_failed:
            issue_type = issue.error_type
            issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1

        return {
            'total_validation_failures': len(self.validation_failed),
            'issue_breakdown': issue_counts,
            'most_common_issues': sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            'corrections_applied': len(self.corrections_applied)
        }

def validate_mathematical_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function for validating mathematical analysis results
    Usage: validated_result = validate_mathematical_result(analysis_result)
    """
    validator = MathematicalValidator()
    return validator.validate_mathematical_output(result)

def test_mathematical_validation():
    """Test the mathematical validation framework"""
    print("🔬 Testing Mathematical Validation Framework")
    print("=" * 50)

    validator = MathematicalValidator()

    # Test 1: Invalid spectral gap (the exact error from Flutter analysis)
    print("Test 1: Negative Spectral Gap")
    result = validator.validate_spectral_gap(-0.9999)
    print(f"Valid: {result.is_valid}")
    print(f"Error: {result.error_message}")
    print(f"Corrected: {result.corrected_value}")
    print()

    # Test 2: Invalid Ricci curvature
    print("Test 2: Invalid Ricci Curvature")
    result = validator.validate_ricci_curvature(-1.0, "terminal node")
    print(f"Valid: {result.is_valid}")
    print(f"Error: {result.error_message}")
    print()

    # Test 3: Suspicious confidence score
    print("Test 3: Suspicious Confidence Score")
    result = validator.validate_confidence_score(0.7, "mathematical analysis")
    print(f"Valid: {result.is_valid}")
    print(f"Error: {result.error_message}")
    print()

    # Test 4: Complete result validation
    print("Test 4: Complete Result Validation")
    fake_result = {
        'mathematical_confidence': 0.7,
        'spectral_analysis': {
            'spectral_gap': -0.9999,
            'eigenvalues': [0.0, 0.5, 1.2]
        },
        'ricci_analysis': {
            'ricci_curvatures': {('node1', 'node2'): -1.0}
        },
        'homology_analysis': {
            'homology_analysis': {
                'h1_holes': -5,  # Invalid
                'max_persistence': 2.5,
                'points_analyzed': 3
            }
        }
    }

    validated = validator.validate_mathematical_output(fake_result)
    print(f"Original confidence: {fake_result['mathematical_confidence']}")
    print(f"Validated confidence: {validated['mathematical_confidence']}")
    print(f"Issues found: {validated['validation_metadata']['validation_issues_count']}")

    for issue in validated['validation_metadata']['validation_issues']:
        print(f"  • {issue['type']}: {issue['message']}")

if __name__ == "__main__":
    test_mathematical_validation()