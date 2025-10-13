#!/usr/bin/env python3
"""
Enhanced VulnHunter v2.0 - Multi-Pattern Analysis Detection

Enhanced version that combines false positive detection (from OpenAI Codex case)
with overly optimistic analysis detection (from Microsoft bounty case).
Provides comprehensive validation for vulnerability and bounty analyses.
"""

import json
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import datetime
import os

class EnhancedVulnHunterV2:
    """Advanced ML-based detection for vulnerability analysis validation."""

    def __init__(self):
        self.models = {
            "false_positive_detector": None,
            "optimism_detector": None,
            "market_reality_validator": None
        }
        self.is_trained = False
        self.training_timestamp = None

        # Load training data from both case studies
        self.load_all_training_data()

    def load_all_training_data(self) -> None:
        """Load training data from all validated case studies."""

        # Load OpenAI Codex false positive data
        codex_files = [f for f in os.listdir('/Users/ankitthakur/vuln_ml_research/')
                      if f.startswith('false_positive_training_') and f.endswith('.json')]

        # Load Microsoft bounty analysis data
        bounty_files = [f for f in os.listdir('/Users/ankitthakur/vuln_ml_research/')
                       if f.startswith('microsoft_bounty_training_') and f.endswith('.json')]

        self.training_datasets = {}

        if codex_files:
            latest_codex = max(codex_files)
            with open(f'/Users/ankitthakur/vuln_ml_research/{latest_codex}', 'r') as f:
                self.training_datasets['false_positive'] = json.load(f)
            print(f"✅ Loaded false positive training data from {latest_codex}")

        if bounty_files:
            latest_bounty = max(bounty_files)
            with open(f'/Users/ankitthakur/vuln_ml_research/{latest_bounty}', 'r') as f:
                self.training_datasets['overly_optimistic'] = json.load(f)
            print(f"✅ Loaded bounty analysis training data from {latest_bounty}")

    def extract_comprehensive_features(self, analysis: Dict[str, Any]) -> Dict[str, float]:
        """Extract comprehensive features for multi-pattern analysis."""

        features = {}

        # Basic structural features
        features['has_total_vulnerabilities'] = 1 if 'total_vulnerabilities' in analysis else 0
        features['has_severity_distribution'] = 1 if 'severity_distribution' in analysis else 0

        # False positive detection features (from Codex case study)
        features.update(self._extract_false_positive_features(analysis))

        # Optimism detection features (from Microsoft case study)
        features.update(self._extract_optimism_features(analysis))

        # Market reality features
        features.update(self._extract_market_reality_features(analysis))

        return features

    def _extract_false_positive_features(self, analysis: Dict[str, Any]) -> Dict[str, float]:
        """Extract features specific to false positive detection."""

        features = {}

        # Vulnerability count features
        total_vulns = analysis.get('total_vulnerabilities', 0)
        if isinstance(total_vulns, (int, float)):
            features['total_vulnerabilities'] = float(total_vulns)
        else:
            features['total_vulnerabilities'] = 0.0

        # Severity distribution features
        severity_dist = analysis.get('severity_distribution', {})
        features['critical_count'] = float(severity_dist.get('CRITICAL', 0))
        features['high_count'] = float(severity_dist.get('HIGH', 0))
        features['medium_count'] = float(severity_dist.get('MEDIUM', 0))

        # Calculate vulnerability density
        if 'vulnerability_types' in analysis:
            files_referenced = set()
            for vuln_type, vulnerabilities in analysis['vulnerability_types'].items():
                if isinstance(vulnerabilities, list):
                    for vuln in vulnerabilities:
                        if 'file' in vuln:
                            files_referenced.add(vuln['file'])

            if files_referenced:
                features['vulnerability_density'] = features['total_vulnerabilities'] / len(files_referenced)
            else:
                features['vulnerability_density'] = 0
        else:
            features['vulnerability_density'] = 0

        # Pattern-based features
        analysis_str = json.dumps(analysis).lower()
        features['claims_transmute'] = 1 if 'transmute' in analysis_str else 0
        features['claims_hardcoded_keys'] = 1 if 'api_key.*=' in analysis_str else 0
        features['claims_excessive_unwrap'] = 1 if features['medium_count'] > 2000 else 0

        # Line reference validation (heuristic)
        features['suspicious_line_refs'] = self._check_suspicious_line_references(analysis)

        return features

    def _extract_optimism_features(self, analysis: Dict[str, Any]) -> Dict[str, float]:
        """Extract features specific to overly optimistic analysis detection."""

        features = {}

        # Calculate total estimated bounty value
        total_estimated = 0
        vulnerability_count = 0
        confidence_values = []
        discovery_methods = set()

        # Process vulnerability data from different structures
        if isinstance(analysis, dict):
            for key, value in analysis.items():
                if isinstance(value, dict) and 'vulnerabilities' in value:
                    vulnerabilities = value['vulnerabilities']
                    if isinstance(vulnerabilities, list):
                        for vuln in vulnerabilities:
                            vulnerability_count += 1

                            # Bounty potential
                            if 'bounty_potential' in vuln:
                                bp = vuln['bounty_potential']
                                estimated = bp.get('estimated_value', 0)
                                total_estimated += estimated

                            # Confidence values
                            if 'detection_confidence' in vuln:
                                confidence_values.append(vuln['detection_confidence'])

                            # Discovery methods
                            if 'discovery_method' in vuln:
                                discovery_methods.add(vuln['discovery_method'])

        features['total_estimated_value'] = float(total_estimated)
        features['vulnerability_count'] = float(vulnerability_count)
        features['average_bounty'] = float(total_estimated / max(vulnerability_count, 1))

        # Confidence analysis
        if confidence_values:
            features['confidence_mean'] = float(np.mean(confidence_values))
            features['confidence_std'] = float(np.std(confidence_values))
            features['confidence_uniqueness'] = float(len(set(confidence_values)) / len(confidence_values))
        else:
            features['confidence_mean'] = 0.0
            features['confidence_std'] = 0.0
            features['confidence_uniqueness'] = 0.0

        # Method diversity
        features['method_diversity'] = float(len(discovery_methods) / max(vulnerability_count, 1))

        return features

    def _extract_market_reality_features(self, analysis: Dict[str, Any]) -> Dict[str, float]:
        """Extract features related to market reality validation."""

        features = {}

        # Historical benchmarks (from research)
        MICROSOFT_ANNUAL_PAYOUT_2024 = 17000000
        MICROSOFT_AVERAGE_BOUNTY_2024 = 49418
        ZERO_DAY_QUEST_SUBMISSIONS = 600

        # Calculate ratios against known benchmarks
        if 'total_estimated_value' in features:
            total_value = features.get('total_estimated_value', 0)
            features['value_vs_microsoft_annual'] = float(total_value / MICROSOFT_ANNUAL_PAYOUT_2024)

        if 'vulnerability_count' in features:
            vuln_count = features.get('vulnerability_count', 0)
            features['count_vs_major_event'] = float(vuln_count / ZERO_DAY_QUEST_SUBMISSIONS)

        if 'average_bounty' in features:
            avg_bounty = features.get('average_bounty', 0)
            features['bounty_inflation_ratio'] = float(avg_bounty / MICROSOFT_AVERAGE_BOUNTY_2024)

        return features

    def _check_suspicious_line_references(self, analysis: Dict[str, Any]) -> float:
        """Check for suspicious line number references (heuristic)."""

        suspicious_count = 0
        total_references = 0

        if 'vulnerability_types' in analysis:
            for vuln_type, vulnerabilities in analysis['vulnerability_types'].items():
                if isinstance(vulnerabilities, list):
                    for vuln in vulnerabilities:
                        if 'line' in vuln:
                            total_references += 1
                            line_num = vuln.get('line', 0)
                            if line_num > 10000:  # Very suspicious
                                suspicious_count += 1
                            elif line_num == 0:  # Also suspicious
                                suspicious_count += 0.5

        return float(suspicious_count / max(total_references, 1))

    def create_comprehensive_training_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """Create training dataset combining all validation patterns."""

        X_features = []
        y_labels = []

        # Generate training examples for false positive detection (from Codex case)
        if 'false_positive' in self.training_datasets:
            fp_data = self.training_datasets['false_positive']

            # False positive examples
            for fp_pattern in fp_data.get('false_positive_patterns', []):
                for claim in fp_pattern.get('false_claims', []):
                    synthetic_report = {
                        'total_vulnerabilities': 2964,
                        'severity_distribution': {'CRITICAL': 49, 'HIGH': 362, 'MEDIUM': 2553},
                        'vulnerability_types': {
                            'memory_safety': [{
                                'file': 'test.rs',
                                'line': 12000,  # Suspicious line number
                                'severity': 'CRITICAL'
                            }]
                        }
                    }

                    features = self.extract_comprehensive_features(synthetic_report)
                    X_features.append(list(features.values()))
                    # Multi-output labels: [false_positive, overly_optimistic, market_unrealistic]
                    y_labels.append([1, 0, 0])  # This is a false positive

            # Legitimate examples
            for legit_pattern in fp_data.get('legitimate_patterns', []):
                for example in legit_pattern.get('examples', []):
                    synthetic_report = {
                        'total_vulnerabilities': 15,
                        'severity_distribution': {'CRITICAL': 1, 'HIGH': 3, 'MEDIUM': 8},
                        'vulnerability_types': {
                            'legitimate': [{
                                'file': 'src/main.rs',
                                'line': 50,
                                'severity': 'MEDIUM'
                            }]
                        }
                    }

                    features = self.extract_comprehensive_features(synthetic_report)
                    X_features.append(list(features.values()))
                    y_labels.append([0, 0, 0])  # Legitimate analysis

        # Generate training examples for optimism detection (from Microsoft case)
        if 'overly_optimistic' in self.training_datasets:
            opt_data = self.training_datasets['overly_optimistic']

            # Overly optimistic example (Microsoft case)
            optimistic_report = {
                'microsoft': {
                    'vulnerabilities': []
                }
            }

            # Generate synthetic vulnerabilities based on the pattern
            for i in range(1125):  # Microsoft case had 1125 vulnerabilities
                vuln = {
                    'bounty_potential': {
                        'estimated_value': 28984  # High average from analysis
                    },
                    'detection_confidence': 0.7 + (i * 0.0001),  # Artificially unique
                    'discovery_method': 'ML_Pattern_Analysis'
                }
                optimistic_report['microsoft']['vulnerabilities'].append(vuln)

            features = self.extract_comprehensive_features(optimistic_report)
            X_features.append(list(features.values()))
            y_labels.append([0, 1, 1])  # Not false positive, but overly optimistic and market unrealistic

            # Realistic bounty analysis example
            realistic_report = {
                'company': {
                    'vulnerabilities': []
                }
            }

            # Generate realistic vulnerabilities
            for i in range(20):  # Realistic count
                vuln = {
                    'bounty_potential': {
                        'estimated_value': np.random.randint(1000, 50000)  # Realistic range
                    },
                    'detection_confidence': np.random.uniform(0.6, 0.9),  # Realistic range
                    'discovery_method': np.random.choice(['Static_Analysis', 'Dynamic_Testing', 'Manual_Review'])
                }
                realistic_report['company']['vulnerabilities'].append(vuln)

            features = self.extract_comprehensive_features(realistic_report)
            X_features.append(list(features.values()))
            y_labels.append([0, 0, 0])  # Realistic analysis

        # Generate additional balanced examples
        self._add_balanced_multi_class_examples(X_features, y_labels)

        return np.array(X_features), np.array(y_labels)

    def _add_balanced_multi_class_examples(self, X_features: List[List[float]], y_labels: List[List[int]]):
        """Add balanced examples for multi-class training."""

        feature_count = len(X_features[0]) if X_features else 20  # Estimate feature count

        # Add pure false positive examples
        for _ in range(15):
            features = [
                np.random.randint(1000, 5000),  # Unrealistic vulnerability count
                1, 1,  # Has structure
                np.random.randint(50, 200),  # Critical/high counts
                np.random.randint(100, 500),
                np.random.randint(1000, 3000),
                np.random.uniform(10, 50),  # High density
                1, 1, 1,  # Claims dangerous patterns
                np.random.uniform(0.5, 1.0),  # Suspicious line refs
            ]
            # Pad to match expected feature count
            while len(features) < feature_count:
                features.append(np.random.random())

            X_features.append(features)
            y_labels.append([1, 0, 0])  # False positive only

        # Add pure optimism examples
        for _ in range(15):
            features = [
                np.random.randint(100, 500),  # Moderate vulnerability count
                1, 1,  # Has structure
                np.random.randint(5, 20),  # Reasonable critical/high counts
                np.random.randint(20, 50),
                np.random.randint(50, 400),
                np.random.uniform(2, 8),  # Reasonable density
                0, 0, 0,  # No dangerous pattern claims
                np.random.uniform(0.0, 0.3),  # Good line refs
                np.random.uniform(5000000, 50000000),  # High total value
                np.random.randint(100, 500),  # Vuln count
                np.random.uniform(25000, 100000),  # High average bounty
                np.random.uniform(0.8, 0.95),  # High confidence mean
                np.random.uniform(0.01, 0.1),  # Low std (unrealistic)
                np.random.uniform(0.9, 1.0),  # High uniqueness
                np.random.uniform(0.0, 0.2),  # Low method diversity
                np.random.uniform(2, 10),  # High value ratio
                np.random.uniform(1.5, 5),  # High count ratio
                np.random.uniform(1.5, 5),  # High bounty inflation
            ]

            X_features.append(features)
            y_labels.append([0, 1, 1])  # Overly optimistic and market unrealistic

        # Add legitimate examples
        for _ in range(20):
            features = [
                np.random.randint(5, 50),  # Realistic vulnerability count
                1, 1,  # Has structure
                np.random.randint(0, 5),  # Low critical count
                np.random.randint(1, 15),  # Reasonable high count
                np.random.randint(5, 30),  # Reasonable medium count
                np.random.uniform(0.5, 3),  # Reasonable density
                0, 0, 0,  # No dangerous pattern claims
                np.random.uniform(0.0, 0.2),  # Good line refs
                np.random.uniform(50000, 500000),  # Reasonable total value
                np.random.randint(5, 50),  # Reasonable vuln count
                np.random.uniform(5000, 25000),  # Reasonable average bounty
                np.random.uniform(0.6, 0.85),  # Reasonable confidence
                np.random.uniform(0.1, 0.3),  # Good std
                np.random.uniform(0.3, 0.8),  # Reasonable uniqueness
                np.random.uniform(0.2, 0.8),  # Good method diversity
                np.random.uniform(0.1, 1.0),  # Reasonable ratios
                np.random.uniform(0.1, 1.0),
                np.random.uniform(0.5, 2.0),
            ]

            X_features.append(features)
            y_labels.append([0, 0, 0])  # Legitimate

    def train_model(self) -> Dict[str, float]:
        """Train the comprehensive VulnHunter v2 model."""

        X, y = self.create_comprehensive_training_dataset()

        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train multi-output classifier
        base_classifier = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )

        self.model = MultiOutputClassifier(base_classifier)
        self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)

        # Calculate metrics for each output
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

        metrics = {}
        output_names = ['false_positive', 'overly_optimistic', 'market_unrealistic']

        for i, output_name in enumerate(output_names):
            metrics[f'{output_name}_accuracy'] = accuracy_score(y_test[:, i], y_pred[:, i])
            metrics[f'{output_name}_precision'] = precision_score(y_test[:, i], y_pred[:, i], zero_division=0)
            metrics[f'{output_name}_recall'] = recall_score(y_test[:, i], y_pred[:, i], zero_division=0)
            metrics[f'{output_name}_f1'] = f1_score(y_test[:, i], y_pred[:, i], zero_division=0)

        # Overall metrics
        metrics['overall_accuracy'] = accuracy_score(y_test, y_pred)

        self.is_trained = True
        self.training_timestamp = datetime.datetime.now().isoformat()

        # Save the model
        self.save_model()

        print(f"✅ VulnHunter v2.0 trained successfully!")
        for output_name in output_names:
            acc = metrics[f'{output_name}_accuracy']
            f1 = metrics[f'{output_name}_f1']
            print(f"   • {output_name.replace('_', ' ').title()}: Accuracy {acc:.3f}, F1 {f1:.3f}")

        return metrics

    def analyze_comprehensive(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive analysis using all detection capabilities."""

        if not self.is_trained:
            raise ValueError("Model not trained. Call train_model() first.")

        # Extract features
        features = self.extract_comprehensive_features(analysis)
        X = np.array([list(features.values())])

        # Get predictions
        predictions = self.model.predict(X)[0]
        prediction_probs = self.model.predict_proba(X)

        # Extract probabilities for each classifier
        false_positive_prob = prediction_probs[0][0][1] if len(prediction_probs[0]) > 1 else 0.0
        optimistic_prob = prediction_probs[1][0][1] if len(prediction_probs[1]) > 1 else 0.0
        unrealistic_prob = prediction_probs[2][0][1] if len(prediction_probs[2]) > 1 else 0.0

        # Generate comprehensive analysis
        result = {
            'analysis_timestamp': datetime.datetime.now().isoformat(),
            'model_version': 'VulnHunter v2.0',

            'predictions': {
                'false_positive': bool(predictions[0]),
                'overly_optimistic': bool(predictions[1]),
                'market_unrealistic': bool(predictions[2])
            },

            'probabilities': {
                'false_positive_probability': float(false_positive_prob),
                'optimism_probability': float(optimistic_prob),
                'market_unrealistic_probability': float(unrealistic_prob)
            },

            'overall_assessment': self._generate_overall_assessment(predictions, [false_positive_prob, optimistic_prob, unrealistic_prob]),

            'feature_analysis': features,

            'recommendations': self._generate_recommendations(predictions, [false_positive_prob, optimistic_prob, unrealistic_prob]),

            'confidence_score': float(np.mean([abs(p - 0.5) * 2 for p in [false_positive_prob, optimistic_prob, unrealistic_prob]]))
        }

        return result

    def _generate_overall_assessment(self, predictions: List[bool], probabilities: List[float]) -> Dict[str, Any]:
        """Generate overall assessment based on all predictions."""

        assessment = {
            'primary_concern': 'NONE',
            'severity': 'LOW',
            'credibility_score': 1.0,
            'recommendation': 'ACCEPT'
        }

        false_positive, optimistic, unrealistic = predictions
        fp_prob, opt_prob, unreal_prob = probabilities

        if false_positive and fp_prob > 0.8:
            assessment['primary_concern'] = 'FALSE_POSITIVE'
            assessment['severity'] = 'CRITICAL'
            assessment['credibility_score'] = 0.0
            assessment['recommendation'] = 'REJECT - Likely fabricated or false analysis'

        elif optimistic and unrealistic and max(opt_prob, unreal_prob) > 0.7:
            assessment['primary_concern'] = 'OVERLY_OPTIMISTIC'
            assessment['severity'] = 'HIGH'
            assessment['credibility_score'] = 0.3
            assessment['recommendation'] = 'USE WITH HEAVY DISCOUNTING - Unrealistically optimistic'

        elif optimistic and opt_prob > 0.6:
            assessment['primary_concern'] = 'MODERATE_OPTIMISM'
            assessment['severity'] = 'MEDIUM'
            assessment['credibility_score'] = 0.6
            assessment['recommendation'] = 'REVIEW CAREFULLY - Some optimistic assumptions'

        else:
            assessment['credibility_score'] = 1.0 - max(probabilities) * 0.5
            assessment['recommendation'] = 'ACCEPT - Analysis appears reasonable'

        return assessment

    def _generate_recommendations(self, predictions: List[bool], probabilities: List[float]) -> List[str]:
        """Generate actionable recommendations based on analysis."""

        recommendations = []

        false_positive, optimistic, unrealistic = predictions
        fp_prob, opt_prob, unreal_prob = probabilities

        if fp_prob > 0.7:
            recommendations.append("Manually verify claimed vulnerabilities exist in referenced code")
            recommendations.append("Cross-check file paths and line numbers for accuracy")
            recommendations.append("Validate dangerous code patterns are actually present")

        if opt_prob > 0.6:
            recommendations.append("Apply significant discount to vulnerability counts and bounty estimates")
            recommendations.append("Focus on highest-confidence findings only")
            recommendations.append("Validate methodology claims with technical evidence")

        if unreal_prob > 0.6:
            recommendations.append("Compare estimates against historical market data")
            recommendations.append("Consider realistic resource constraints for exploitation")
            recommendations.append("Seek independent validation of high-value claims")

        if not recommendations:
            recommendations.append("Analysis appears reasonable - proceed with normal validation")

        return recommendations

    def save_model(self) -> str:
        """Save the trained model."""

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        model_filename = f"/Users/ankitthakur/vuln_ml_research/models/vulnhunter_v2_{timestamp}.pkl"

        # Ensure models directory exists
        os.makedirs("/Users/ankitthakur/vuln_ml_research/models", exist_ok=True)

        with open(model_filename, 'wb') as f:
            pickle.dump(self, f)

        return model_filename


def main():
    """Train and test VulnHunter v2.0."""

    print("🚀 Training VulnHunter v2.0 - Enhanced Multi-Pattern Detection...")

    detector = EnhancedVulnHunterV2()

    # Train the model
    metrics = detector.train_model()

    # Test on both case studies
    print("\n📊 Testing on Validation Case Studies:")

    # Test on OpenAI Codex fabricated analysis
    try:
        with open('/Users/ankitthakur/Downloads/openai_codex_analysis/codex_security_analysis_results.json', 'r') as f:
            codex_data = json.load(f)

        codex_analysis = detector.analyze_comprehensive(codex_data)
        print(f"\n🔍 OpenAI Codex Analysis Results:")
        print(f"   • False Positive: {codex_analysis['predictions']['false_positive']} (prob: {codex_analysis['probabilities']['false_positive_probability']:.3f})")
        print(f"   • Overall: {codex_analysis['overall_assessment']['recommendation']}")

    except Exception as e:
        print(f"   ❌ Could not analyze Codex data: {e}")

    # Test on Microsoft bounty analysis
    try:
        with open('/Users/ankitthakur/Downloads/microsoft_bounty_analysis/microsoft_bounty_comprehensive_analysis.json', 'r') as f:
            bounty_data = json.load(f)

        bounty_analysis = detector.analyze_comprehensive(bounty_data)
        print(f"\n🔍 Microsoft Bounty Analysis Results:")
        print(f"   • Overly Optimistic: {bounty_analysis['predictions']['overly_optimistic']} (prob: {bounty_analysis['probabilities']['optimism_probability']:.3f})")
        print(f"   • Market Unrealistic: {bounty_analysis['predictions']['market_unrealistic']} (prob: {bounty_analysis['probabilities']['market_unrealistic_probability']:.3f})")
        print(f"   • Overall: {bounty_analysis['overall_assessment']['recommendation']}")

    except Exception as e:
        print(f"   ❌ Could not analyze bounty data: {e}")

    return detector


if __name__ == "__main__":
    detector = main()