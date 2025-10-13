#!/usr/bin/env python3
"""
Microsoft Bounty Analysis Training Data Generator

Generates training data for the VulnHunter model based on the validation
of the Microsoft bounty analysis. This focuses on detecting overly optimistic
or potentially fabricated bounty opportunity analyses.
"""

import json
import datetime
import numpy as np
from typing import Dict, List, Any

class MicrosoftBountyTrainingDataGenerator:
    """Generate training data for detecting suspicious bounty analyses."""

    def __init__(self):
        self.validation_timestamp = datetime.datetime.now().isoformat()
        self.case_study_id = "microsoft_bounty_overly_optimistic_analysis_2025_10_13"

    def generate_training_data(self) -> Dict[str, Any]:
        """Generate comprehensive training data from the Microsoft bounty analysis."""

        training_data = {
            "metadata": {
                "case_study_id": self.case_study_id,
                "validation_date": self.validation_timestamp,
                "analysis_type": "bounty_opportunity_analysis",
                "target_organization": "Microsoft",
                "validation_method": "market_reality_cross_reference",
                "assessment": "QUESTIONABLE - Overly Optimistic"
            },

            "suspicious_patterns": self.generate_suspicious_patterns(),
            "realistic_benchmarks": self.generate_realistic_benchmarks(),
            "detection_features": self.generate_detection_features(),
            "ml_training_labels": self.generate_ml_labels(),
            "validation_rules": self.generate_validation_rules()
        }

        return training_data

    def generate_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """Generate patterns that indicate overly optimistic or suspicious bounty analyses."""

        return [
            {
                "pattern_type": "unrealistic_vulnerability_density",
                "description": "Claims unrealistically high number of vulnerabilities",
                "suspicious_indicators": {
                    "total_vulnerabilities": 1125,
                    "compared_to_major_event": "1.9x Microsoft's Zero Day Quest submissions (600+)",
                    "industry_context": "Single analysis claiming more vulnerabilities than major industry events",
                    "red_flag_threshold": ">1000 vulnerabilities from single analysis"
                },
                "detection_features": [
                    "vulnerability_count_vs_historical_submissions",
                    "vulnerability_density_per_program",
                    "single_source_discovery_rate"
                ]
            },

            {
                "pattern_type": "artificial_confidence_generation",
                "description": "Detection confidence values show signs of artificial generation",
                "suspicious_indicators": {
                    "unique_confidence_values": 1125,  # Every value unique
                    "total_vulnerabilities": 1125,
                    "uniqueness_ratio": 1.0,  # 100% unique values
                    "statistical_uniformity": "Unrealistically uniform distribution",
                    "generation_method": "Likely programmatically generated random values"
                },
                "detection_features": [
                    "confidence_value_uniqueness_ratio",
                    "confidence_distribution_entropy",
                    "statistical_uniformity_measures"
                ]
            },

            {
                "pattern_type": "inflated_market_valuation",
                "description": "Total claimed value significantly exceeds market reality",
                "suspicious_indicators": {
                    "claimed_total_value": 32607412,  # $32.6M
                    "microsoft_annual_payout_2024": 17000000,  # $17M
                    "market_multiple": 1.9,  # 1.9x entire Microsoft annual budget
                    "average_value_per_vuln": 28984,  # $29K average (very high)
                    "historical_average": 49400  # Microsoft's actual average in 2024
                },
                "detection_features": [
                    "total_value_vs_historical_payouts",
                    "average_bounty_vs_market_average",
                    "market_size_realism_ratio"
                ]
            },

            {
                "pattern_type": "ml_pattern_analysis_overconfidence",
                "description": "Claims to use ML analysis but shows signs of artificial generation",
                "suspicious_indicators": {
                    "discovery_method": "ML_Pattern_Analysis (claimed for all 1125 vulnerabilities)",
                    "method_diversity": "Zero diversity in discovery methods",
                    "confidence_range": "70-94% (artificially narrow range)",
                    "precision_claims": "Extremely precise confidence values (e.g., 0.7893155155998688)"
                },
                "detection_features": [
                    "method_diversity_analysis",
                    "confidence_precision_realism",
                    "ml_claims_vs_actual_patterns"
                ]
            }
        ]

    def generate_realistic_benchmarks(self) -> Dict[str, Any]:
        """Generate realistic benchmarks based on actual Microsoft bounty data."""

        return {
            "historical_microsoft_data": {
                "annual_payout_2024": 17000000,
                "researchers_paid_2024": 344,
                "average_payout_per_researcher": 49418,
                "largest_single_award": 200000,
                "major_event_submissions": 600,  # Zero Day Quest
                "major_event_payout": 1600000
            },

            "realistic_vulnerability_discovery": {
                "individual_researcher_annual": "5-50 valid vulnerabilities",
                "team_annual_capacity": "50-200 valid vulnerabilities",
                "single_analysis_realistic": "1-20 high-confidence vulnerabilities",
                "quality_vs_quantity": "Focus should be on exploitation quality, not volume"
            },

            "bounty_amount_reality": {
                "average_microsoft_bounty": 49418,
                "median_likely_range": "5000-25000",
                "critical_vulnerability_range": "25000-100000",
                "hypervisor_exceptional_range": "100000-250000",
                "realistic_total_per_researcher": "50000-500000 annually"
            },

            "detection_confidence_reality": {
                "realistic_range": "60-90%",
                "high_confidence_rare": ">90% should be <10% of findings",
                "low_confidence_common": "<70% should be >30% of findings",
                "distribution_shape": "Normal distribution with long tail"
            }
        }

    def generate_detection_features(self) -> List[Dict[str, Any]]:
        """Generate features for ML-based detection of suspicious bounty analyses."""

        return [
            {
                "feature_name": "vulnerability_count_ratio",
                "description": "Ratio of claimed vulnerabilities to historical benchmarks",
                "implementation": "claimed_count / historical_major_event_submissions",
                "suspicious_threshold": 2.0,
                "weight": 0.8
            },

            {
                "feature_name": "market_value_multiple",
                "description": "Multiple of claimed value vs actual market size",
                "implementation": "claimed_total_value / annual_market_payout",
                "suspicious_threshold": 1.5,
                "weight": 0.9
            },

            {
                "feature_name": "confidence_uniqueness_ratio",
                "description": "Ratio of unique confidence values to total vulnerabilities",
                "implementation": "unique_confidence_count / total_vulnerability_count",
                "suspicious_threshold": 0.9,  # >90% unique values is suspicious
                "weight": 0.7
            },

            {
                "feature_name": "average_bounty_inflation",
                "description": "How inflated average bounty is vs market reality",
                "implementation": "average_claimed_bounty / historical_average_bounty",
                "suspicious_threshold": 2.0,
                "weight": 0.8
            },

            {
                "feature_name": "method_diversity_score",
                "description": "Diversity of discovery methods claimed",
                "implementation": "unique_methods / total_vulnerabilities",
                "suspicious_threshold": 0.1,  # <10% diversity is suspicious
                "weight": 0.6,
                "direction": "low_is_suspicious"
            },

            {
                "feature_name": "confidence_distribution_entropy",
                "description": "Statistical entropy of confidence value distribution",
                "implementation": "shannon_entropy(confidence_values)",
                "suspicious_threshold": 8.0,  # Very high entropy suggests artificial generation
                "weight": 0.7
            }
        ]

    def generate_ml_labels(self) -> Dict[str, Any]:
        """Generate ML training labels for the Microsoft bounty analysis."""

        return {
            "overall_analysis_credibility": 0.3,  # 0 = not credible, 1 = fully credible
            "category_assessments": {
                "vulnerability_count_realism": {
                    "claimed": 1125,
                    "realistic_range": "50-200",
                    "credibility": 0.2,
                    "confidence": 0.9
                },
                "bounty_value_realism": {
                    "claimed_total": 32607412,
                    "realistic_range": "500000-5000000",
                    "credibility": 0.3,
                    "confidence": 0.85
                },
                "technical_methodology": {
                    "claimed_method": "ML_Pattern_Analysis",
                    "evidence_quality": "Low - no technical details",
                    "credibility": 0.4,
                    "confidence": 0.8
                },
                "market_understanding": {
                    "claimed_expertise": "Advanced ML-based Security Assessment",
                    "actual_demonstration": "Overly optimistic projections",
                    "credibility": 0.3,
                    "confidence": 0.9
                }
            },
            "risk_assessment": {
                "financial_risk": "HIGH - Could lead to unrealistic investment decisions",
                "operational_risk": "MEDIUM - May waste security research resources",
                "reputational_risk": "LOW - Claims are optimistic but not malicious"
            },
            "classification": "OVERLY_OPTIMISTIC",  # Not fraudulent, but unrealistic
            "recommendation": "USE_WITH_HEAVY_DISCOUNTING"
        }

    def generate_validation_rules(self) -> List[Dict[str, Any]]:
        """Generate validation rules for detecting overly optimistic bounty analyses."""

        return [
            {
                "rule_id": "OPT001",
                "name": "unrealistic_vulnerability_volume",
                "description": "Analysis claims unrealistically high number of vulnerabilities",
                "logic": "IF (vulnerability_count > major_event_submissions * 1.5) THEN flag_as_overly_optimistic",
                "confidence": 0.8,
                "severity": "HIGH_OPTIMISM"
            },

            {
                "rule_id": "OPT002",
                "name": "artificial_confidence_generation",
                "description": "Confidence values show signs of artificial generation",
                "logic": "IF (unique_confidence_ratio > 0.9 AND total_vulns > 100) THEN flag_as_artificially_generated",
                "confidence": 0.9,
                "severity": "MEDIUM_OPTIMISM"
            },

            {
                "rule_id": "OPT003",
                "name": "market_value_inflation",
                "description": "Total claimed value exceeds realistic market expectations",
                "logic": "IF (claimed_value > historical_annual_payout * 1.5) THEN flag_as_overvalued",
                "confidence": 0.85,
                "severity": "HIGH_OPTIMISM"
            },

            {
                "rule_id": "OPT004",
                "name": "average_bounty_inflation",
                "description": "Average bounty per vulnerability is unrealistically high",
                "logic": "IF (average_bounty > historical_average * 2) THEN flag_as_inflated",
                "confidence": 0.7,
                "severity": "MEDIUM_OPTIMISM"
            },

            {
                "rule_id": "OPT005",
                "name": "method_oversimplification",
                "description": "Claims single method discovered all vulnerabilities",
                "logic": "IF (method_diversity < 0.1 AND vulnerability_count > 100) THEN flag_as_oversimplified",
                "confidence": 0.6,
                "severity": "LOW_OPTIMISM"
            }
        ]

    def save_training_data(self, filename: str = None) -> str:
        """Save the training data to a file."""

        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"microsoft_bounty_training_{timestamp}.json"

        filepath = f"/Users/ankitthakur/vuln_ml_research/{filename}"

        training_data = self.generate_training_data()

        with open(filepath, 'w') as f:
            json.dump(training_data, f, indent=2)

        return filepath

    def generate_model_enhancement_recommendations(self) -> Dict[str, Any]:
        """Generate recommendations for enhancing the VulnHunter model."""

        return {
            "model_enhancements": [
                {
                    "area": "market_reality_validation",
                    "recommendation": "Add market size validation against historical data",
                    "priority": "HIGH",
                    "implementation": "Create market size database and validation rules"
                },
                {
                    "area": "statistical_analysis",
                    "recommendation": "Implement statistical anomaly detection for confidence values",
                    "priority": "HIGH",
                    "implementation": "Add entropy analysis and distribution shape validation"
                },
                {
                    "area": "methodology_validation",
                    "recommendation": "Validate claimed discovery methods against known capabilities",
                    "priority": "MEDIUM",
                    "implementation": "Cross-reference claimed methods with technical evidence"
                },
                {
                    "area": "benchmarking_integration",
                    "recommendation": "Integrate real-time bounty program data for validation",
                    "priority": "MEDIUM",
                    "implementation": "API integration with public bounty statistics"
                }
            ],

            "training_data_expansion": [
                {
                    "type": "overly_optimistic_examples",
                    "description": "More examples of unrealistically optimistic analyses",
                    "current_coverage": "LOW",
                    "target_samples": 500
                },
                {
                    "type": "realistic_analyses",
                    "description": "Validated realistic bounty opportunity assessments",
                    "current_coverage": "NONE",
                    "target_samples": 200
                },
                {
                    "type": "market_context_data",
                    "description": "Historical bounty payout data across vendors",
                    "current_coverage": "LOW",
                    "target_samples": 1000
                }
            ],

            "validation_pipeline_improvements": [
                {
                    "stage": "market_reality_check",
                    "description": "Validate against known market constraints",
                    "automation_level": "FULL"
                },
                {
                    "stage": "statistical_analysis",
                    "description": "Analyze value distributions for realism",
                    "automation_level": "FULL"
                },
                {
                    "stage": "methodology_verification",
                    "description": "Verify claimed methodologies against evidence",
                    "automation_level": "PARTIAL"
                },
                {
                    "stage": "expert_review_flagging",
                    "description": "Flag analyses exceeding realistic thresholds",
                    "automation_level": "FULL"
                }
            ]
        }


def main():
    """Generate and save training data for Microsoft bounty analysis detection."""

    generator = MicrosoftBountyTrainingDataGenerator()

    # Generate and save training data
    training_file = generator.save_training_data()
    print(f"✅ Training data saved to: {training_file}")

    # Generate enhancement recommendations
    recommendations = generator.generate_model_enhancement_recommendations()

    recommendations_file = "/Users/ankitthakur/vuln_ml_research/microsoft_bounty_model_recommendations.json"

    with open(recommendations_file, 'w') as f:
        json.dump(recommendations, f, indent=2)

    print(f"✅ Model enhancement recommendations saved to: {recommendations_file}")

    # Print summary
    training_data = generator.generate_training_data()
    print(f"\n📊 Training Data Summary:")
    print(f"   • Suspicious Patterns: {len(training_data['suspicious_patterns'])}")
    print(f"   • Detection Features: {len(training_data['detection_features'])}")
    print(f"   • Validation Rules: {len(training_data['validation_rules'])}")
    print(f"   • Overall Credibility: {training_data['ml_training_labels']['overall_analysis_credibility']}")
    print(f"   • Classification: {training_data['ml_training_labels']['classification']}")

    return training_file, recommendations_file


if __name__ == "__main__":
    main()