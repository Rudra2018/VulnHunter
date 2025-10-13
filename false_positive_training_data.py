#!/usr/bin/env python3
"""
False Positive Training Data Generator for VulnHunter ML Model

This module generates training data based on real-world validation of a fabricated
vulnerability analysis report. It helps train ML models to distinguish between
legitimate and false security vulnerabilities.

Based on comprehensive validation of OpenAI Codex analysis report dated 2025-10-12.
"""

import json
import datetime
from typing import Dict, List, Tuple, Any
import pickle
import os

class FalsePositiveTrainingGenerator:
    """Generate training data for detecting false positive vulnerability reports."""

    def __init__(self):
        self.validation_timestamp = datetime.datetime.now().isoformat()
        self.case_study_id = "openai_codex_fabricated_analysis_2025_10_12"

    def generate_training_data(self) -> Dict[str, Any]:
        """Generate comprehensive training data from the false positive case study."""

        training_data = {
            "metadata": {
                "case_study_id": self.case_study_id,
                "validation_date": self.validation_timestamp,
                "repository_analyzed": "/Users/ankitthakur/codex",
                "false_report_source": "/Users/ankitthakur/Downloads/openai_codex_analysis/",
                "validation_method": "manual_code_inspection_cross_reference"
            },

            "false_positive_patterns": self.generate_false_positive_patterns(),
            "legitimate_patterns": self.generate_legitimate_patterns(),
            "validation_features": self.generate_validation_features(),
            "ml_training_labels": self.generate_ml_labels(),
            "detection_rules": self.generate_detection_rules()
        }

        return training_data

    def generate_false_positive_patterns(self) -> List[Dict[str, Any]]:
        """Generate patterns that indicate false positive vulnerabilities."""

        return [
            {
                "pattern_type": "fabricated_unsafe_code",
                "description": "Claims of dangerous unsafe code that doesn't exist",
                "false_claims": [
                    {
                        "claim": "unsafe { transmute(raw_ptr) }",
                        "file_reference": "oauth.rs:715",
                        "reality": "safe std::env::set_var() call",
                        "validation_method": "direct_line_inspection",
                        "severity_claimed": "CRITICAL",
                        "actual_severity": "NONE"
                    },
                    {
                        "claim": "unsafe { std::ptr::write(ptr, value) }",
                        "file_reference": "rmcp_client.rs:596",
                        "reality": "file only has 332 lines, line doesn't exist",
                        "validation_method": "line_count_verification",
                        "severity_claimed": "CRITICAL",
                        "actual_severity": "NONE"
                    },
                    {
                        "claim": "unsafe { slice::from_raw_parts(ptr, len) }",
                        "file_reference": "shell.rs:144",
                        "reality": "proper FFI call to getpwuid()",
                        "validation_method": "context_analysis",
                        "severity_claimed": "CRITICAL",
                        "actual_severity": "NONE"
                    }
                ],
                "red_flags": [
                    "specific_dangerous_patterns_not_found",
                    "line_numbers_beyond_file_length",
                    "mischaracterization_of_safe_operations"
                ]
            },

            {
                "pattern_type": "inflated_vulnerability_counts",
                "description": "Dramatically inflated vulnerability counts vs reality",
                "false_claims": [
                    {
                        "claim": "2,553 dangerous .unwrap() calls",
                        "reality": "811 total .unwrap() calls, mostly in tests",
                        "inflation_factor": 3.14,
                        "validation_method": "grep_pattern_counting",
                        "severity_claimed": "HIGH",
                        "actual_severity": "LOW"
                    }
                ],
                "red_flags": [
                    "unrealistic_vulnerability_density",
                    "lack_of_context_for_unwrap_usage",
                    "test_code_treated_as_production"
                ]
            },

            {
                "pattern_type": "fabricated_hardcoded_secrets",
                "description": "Claims of hardcoded secrets that don't exist",
                "false_claims": [
                    {
                        "claim": 'const API_KEY: &str = "sk-1234567890abcdef...";',
                        "file_reference": "multiple files",
                        "reality": "only environment variable references and test dummies",
                        "validation_method": "regex_pattern_search",
                        "severity_claimed": "CRITICAL",
                        "actual_severity": "NONE"
                    }
                ],
                "red_flags": [
                    "generic_secret_patterns_not_found",
                    "misidentification_of_env_var_names",
                    "test_dummy_values_flagged_as_real"
                ]
            },

            {
                "pattern_type": "wrong_repository_analysis",
                "description": "Analysis claims to target different repository than actual",
                "false_claims": [
                    {
                        "claim": "OpenAI Codex repository analysis",
                        "reality": "Anthropic Claude Code repository",
                        "validation_method": "repository_path_verification",
                        "severity_claimed": "N/A",
                        "actual_severity": "ANALYSIS_ERROR"
                    }
                ],
                "red_flags": [
                    "repository_identity_mismatch",
                    "path_references_to_nonexistent_locations",
                    "vendor_confusion_in_analysis"
                ]
            }
        ]

    def generate_legitimate_patterns(self) -> List[Dict[str, Any]]:
        """Generate patterns that indicate legitimate security practices."""

        return [
            {
                "pattern_type": "proper_unsafe_usage",
                "description": "Legitimate unsafe code usage in Rust",
                "examples": [
                    {
                        "code": "unsafe { std::env::set_var(\"CODEX_HOME\", dir.path()); }",
                        "file": "oauth.rs:715-717",
                        "justification": "Test utility for environment setup",
                        "safety_measures": "controlled_test_context",
                        "severity": "NONE"
                    },
                    {
                        "code": "unsafe { libc::getpwuid(uid) }",
                        "file": "shell.rs:144-146",
                        "justification": "FFI call to get user shell information",
                        "safety_measures": "null_pointer_checks",
                        "severity": "NONE"
                    }
                ]
            },

            {
                "pattern_type": "appropriate_error_handling",
                "description": "Reasonable error handling patterns in Rust",
                "examples": [
                    {
                        "code": ".unwrap_or_else(PoisonError::into_inner)",
                        "context": "mutex_lock_handling",
                        "justification": "poison error recovery in test code",
                        "severity": "NONE"
                    }
                ]
            },

            {
                "pattern_type": "secure_credential_handling",
                "description": "Proper credential management practices",
                "examples": [
                    {
                        "pattern": "env::var(OPENAI_API_KEY_ENV_VAR)",
                        "description": "Reading API key from environment variable",
                        "security_level": "SECURE"
                    },
                    {
                        "pattern": '.env("OPENAI_API_KEY", "dummy")',
                        "context": "test_code",
                        "description": "Test dummy value, not real credential",
                        "security_level": "SECURE"
                    }
                ]
            }
        ]

    def generate_validation_features(self) -> List[Dict[str, Any]]:
        """Generate features that can be used for ML-based validation."""

        return [
            {
                "feature_name": "line_number_validity",
                "description": "Check if referenced line numbers exist in files",
                "implementation": "file_length_vs_reference_line",
                "weight": 0.9,
                "false_positive_indicator": True
            },
            {
                "feature_name": "pattern_existence",
                "description": "Verify claimed vulnerable patterns actually exist",
                "implementation": "regex_search_validation",
                "weight": 0.95,
                "false_positive_indicator": True
            },
            {
                "feature_name": "vulnerability_density",
                "description": "Check for unrealistic vulnerability per file ratios",
                "implementation": "statistical_analysis",
                "weight": 0.7,
                "suspicious_threshold": 10.0  # vulnerabilities per file
            },
            {
                "feature_name": "context_appropriateness",
                "description": "Analyze if flagged code is appropriate for its context",
                "implementation": "ast_analysis",
                "weight": 0.8,
                "factors": ["test_code", "ffi_usage", "legitimate_unsafe"]
            },
            {
                "feature_name": "repository_consistency",
                "description": "Verify analysis targets correct repository",
                "implementation": "path_verification",
                "weight": 1.0,
                "false_positive_indicator": True
            }
        ]

    def generate_ml_labels(self) -> Dict[str, Any]:
        """Generate ML training labels for the case study."""

        return {
            "overall_analysis_validity": 0,  # 0 = invalid, 1 = valid
            "vulnerability_classifications": {
                "memory_safety_critical": {
                    "claimed_count": 49,
                    "actual_count": 0,
                    "label": 0,  # false positive
                    "confidence": 0.99
                },
                "error_handling_medium": {
                    "claimed_count": 2553,
                    "actual_count": 811,
                    "label": 0.3,  # partially false, inflated
                    "confidence": 0.95
                },
                "api_security_high": {
                    "claimed_count": 164,
                    "actual_count": 0,
                    "label": 0,  # false positive
                    "confidence": 0.99
                },
                "serialization_high": {
                    "claimed_count": 195,
                    "actual_count": "unknown",  # requires deeper analysis
                    "label": 0.1,  # likely false positive
                    "confidence": 0.8
                }
            },
            "analysis_quality_score": 0.05,  # very poor quality
            "false_positive_probability": 0.95
        }

    def generate_detection_rules(self) -> List[Dict[str, Any]]:
        """Generate rules for detecting false positive vulnerability reports."""

        return [
            {
                "rule_id": "FP001",
                "name": "line_number_beyond_file",
                "description": "Vulnerability reference points to line number beyond file length",
                "logic": "IF (referenced_line > file_length) THEN flag_as_false_positive",
                "confidence": 0.99,
                "severity": "HIGH_FALSE_POSITIVE"
            },
            {
                "rule_id": "FP002",
                "name": "pattern_not_found",
                "description": "Claimed vulnerable pattern not found in referenced file",
                "logic": "IF (pattern_search(file, claimed_pattern) == NOT_FOUND) THEN flag_as_false_positive",
                "confidence": 0.95,
                "severity": "HIGH_FALSE_POSITIVE"
            },
            {
                "rule_id": "FP003",
                "name": "unrealistic_vulnerability_density",
                "description": "Vulnerability count per file exceeds realistic thresholds",
                "logic": "IF (vulnerabilities_per_file > 10) THEN flag_as_suspicious",
                "confidence": 0.8,
                "severity": "MEDIUM_FALSE_POSITIVE"
            },
            {
                "rule_id": "FP004",
                "name": "repository_path_mismatch",
                "description": "Analysis references wrong repository or non-existent paths",
                "logic": "IF (path_exists(referenced_path) == FALSE) THEN flag_as_false_positive",
                "confidence": 0.99,
                "severity": "HIGH_FALSE_POSITIVE"
            },
            {
                "rule_id": "FP005",
                "name": "test_code_as_production",
                "description": "Test code patterns flagged as production vulnerabilities",
                "logic": "IF (file_path.contains('test') AND severity == 'CRITICAL') THEN flag_as_false_positive",
                "confidence": 0.7,
                "severity": "MEDIUM_FALSE_POSITIVE"
            }
        ]

    def save_training_data(self, filename: str = None) -> str:
        """Save the training data to a file."""

        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"false_positive_training_{timestamp}.json"

        filepath = os.path.join("/Users/ankitthakur/vuln_ml_research/", filename)

        training_data = self.generate_training_data()

        with open(filepath, 'w') as f:
            json.dump(training_data, f, indent=2)

        return filepath

    def generate_model_improvement_recommendations(self) -> Dict[str, Any]:
        """Generate recommendations for improving ML model accuracy."""

        return {
            "model_improvements": [
                {
                    "area": "feature_engineering",
                    "recommendation": "Add file existence and line number validation features",
                    "priority": "HIGH",
                    "implementation_complexity": "LOW"
                },
                {
                    "area": "pattern_matching",
                    "recommendation": "Implement code pattern verification against actual repository",
                    "priority": "HIGH",
                    "implementation_complexity": "MEDIUM"
                },
                {
                    "area": "context_awareness",
                    "recommendation": "Add AST-based analysis to understand code context",
                    "priority": "MEDIUM",
                    "implementation_complexity": "HIGH"
                },
                {
                    "area": "repository_verification",
                    "recommendation": "Verify analysis target matches actual repository",
                    "priority": "HIGH",
                    "implementation_complexity": "LOW"
                },
                {
                    "area": "statistical_validation",
                    "recommendation": "Add statistical anomaly detection for vulnerability counts",
                    "priority": "MEDIUM",
                    "implementation_complexity": "MEDIUM"
                }
            ],

            "training_data_needs": [
                {
                    "type": "false_positive_examples",
                    "description": "More examples of fabricated vulnerability reports",
                    "current_coverage": "LOW",
                    "target_samples": 1000
                },
                {
                    "type": "legitimate_vulnerabilities",
                    "description": "Verified real vulnerabilities for positive training",
                    "current_coverage": "MEDIUM",
                    "target_samples": 5000
                },
                {
                    "type": "context_variations",
                    "description": "Different repository types and languages",
                    "current_coverage": "LOW",
                    "target_samples": 500
                }
            ],

            "validation_pipeline": [
                {
                    "stage": "file_verification",
                    "description": "Verify all referenced files and lines exist",
                    "automation_level": "FULL"
                },
                {
                    "stage": "pattern_validation",
                    "description": "Confirm vulnerable patterns exist in claimed locations",
                    "automation_level": "FULL"
                },
                {
                    "stage": "context_analysis",
                    "description": "Analyze code context for appropriateness",
                    "automation_level": "PARTIAL"
                },
                {
                    "stage": "cross_reference",
                    "description": "Cross-reference with known vulnerability databases",
                    "automation_level": "FULL"
                }
            ]
        }


def main():
    """Generate and save training data for false positive detection."""

    generator = FalsePositiveTrainingGenerator()

    # Generate and save training data
    training_file = generator.save_training_data()
    print(f"✅ Training data saved to: {training_file}")

    # Generate model improvement recommendations
    recommendations = generator.generate_model_improvement_recommendations()

    recommendations_file = os.path.join(
        "/Users/ankitthakur/vuln_ml_research/",
        "model_improvement_recommendations.json"
    )

    with open(recommendations_file, 'w') as f:
        json.dump(recommendations, f, indent=2)

    print(f"✅ Model improvement recommendations saved to: {recommendations_file}")

    # Print summary
    training_data = generator.generate_training_data()
    print(f"\n📊 Training Data Summary:")
    print(f"   • False Positive Patterns: {len(training_data['false_positive_patterns'])}")
    print(f"   • Legitimate Patterns: {len(training_data['legitimate_patterns'])}")
    print(f"   • Validation Features: {len(training_data['validation_features'])}")
    print(f"   • Detection Rules: {len(training_data['detection_rules'])}")
    print(f"   • Overall Analysis Validity: {training_data['ml_training_labels']['overall_analysis_validity']}")
    print(f"   • False Positive Probability: {training_data['ml_training_labels']['false_positive_probability']}")

    return training_file, recommendations_file


if __name__ == "__main__":
    main()