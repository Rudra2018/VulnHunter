#!/usr/bin/env python3
"""
INTEGRATED MODEL EVALUATOR
Combines new vulnerability_ml_models with existing infrastructure for comprehensive testing
"""

import sys
import os
import joblib
import pandas as pd
import numpy as np
import json
from datetime import datetime
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Add vulnerability_ml_models to path
sys.path.append('./vulnerability_ml_models')

# Import the new predictors
from vulnerability_ml_models.production_predictor import ProductionVulnPredictor
from vulnerability_ml_models.optimized_predictor import OptimizedVulnPredictor

class IntegratedModelEvaluator:
    """Comprehensive evaluator for all vulnerability prediction models."""

    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}
        self.test_data = []
        self.load_all_models()
        self.prepare_test_data()

    def load_all_models(self):
        """Load all available models for comparison."""
        self.models = {}

        # Load new models from vulnerability_ml_models
        try:
            self.models['production'] = ProductionVulnPredictor('./vulnerability_ml_models')
            print("✅ Production model loaded")
        except Exception as e:
            print(f"⚠️ Production model failed: {e}")

        try:
            self.models['optimized'] = OptimizedVulnPredictor('./vulnerability_ml_models')
            print("✅ Optimized model loaded")
        except Exception as e:
            print(f"⚠️ Optimized model failed: {e}")

        # Load existing models if available
        self.load_existing_models()

    def load_existing_models(self):
        """Load existing models from the project."""
        # Smart contract models
        try:
            if os.path.exists('smart_contract_models'):
                sc_files = os.listdir('smart_contract_models')
                for file in sc_files:
                    if file.endswith('_classifier.pkl'):
                        model_path = f'smart_contract_models/{file}'
                        model = joblib.load(model_path)
                        self.models[f'sc_{file.replace(".pkl", "")}'] = model
                        print(f"✅ Smart contract model loaded: {file}")
        except Exception as e:
            print(f"⚠️ Smart contract models loading failed: {e}")

        # Working models
        try:
            if os.path.exists('working_sc_models'):
                working_files = os.listdir('working_sc_models')
                for file in working_files:
                    if file.endswith('_classifier.pkl'):
                        model_path = f'working_sc_models/{file}'
                        model = joblib.load(model_path)
                        self.models[f'working_{file.replace(".pkl", "")}'] = model
                        print(f"✅ Working model loaded: {file}")
        except Exception as e:
            print(f"⚠️ Working models loading failed: {e}")

    def prepare_test_data(self):
        """Prepare comprehensive test dataset."""
        # High-severity vulnerabilities (should be classified as 1/High/Critical)
        high_severity = [
            "Remote code execution vulnerability in Apache Struts allowing arbitrary code execution",
            "Buffer overflow in Windows kernel leading to privilege escalation and root access",
            "SQL injection in web application allowing database compromise and data extraction",
            "Privilege escalation vulnerability in Linux sudo allowing local users to gain root privileges",
            "Unauthenticated remote code execution in network service with CVSS score 9.8",
            "Buffer overflow in network daemon allowing arbitrary code execution as root",
            "Cross-site scripting leading to session hijacking and administrative access",
            "Authentication bypass vulnerability allowing unauthorized administrative access",
            "Heap-based buffer overflow enabling arbitrary code execution with high impact",
            "Directory traversal vulnerability leading to arbitrary file read and system compromise"
        ]

        # Low-medium severity vulnerabilities (should be classified as 0/Low/Medium)
        low_severity = [
            "Information disclosure vulnerability revealing system version",
            "Cross-site scripting in non-critical page with limited impact",
            "Denial of service vulnerability causing temporary service disruption",
            "Minor information leak through error messages",
            "Local file inclusion with limited impact and no code execution",
            "Weak cryptographic algorithm usage in non-critical component",
            "CSRF vulnerability in user profile update functionality",
            "Open redirect vulnerability with minimal security impact",
            "Insecure direct object reference with limited data exposure",
            "Missing security headers with low security impact"
        ]

        # Create labeled test dataset
        for desc in high_severity:
            self.test_data.append({
                'description': desc,
                'true_severity': 1,
                'severity_label': 'High/Critical'
            })

        for desc in low_severity:
            self.test_data.append({
                'description': desc,
                'true_severity': 0,
                'severity_label': 'Low/Medium'
            })

        print(f"📊 Test dataset prepared: {len(self.test_data)} samples")
        print(f"   - High severity: {len(high_severity)}")
        print(f"   - Low severity: {len(low_severity)}")

    def evaluate_new_models(self):
        """Evaluate the new vulnerability ML models."""
        print("\n🔍 EVALUATING NEW VULNERABILITY ML MODELS")
        print("=" * 60)

        for model_name in ['production', 'optimized']:
            if model_name not in self.models:
                continue

            model = self.models[model_name]
            predictions = []
            confidences = []
            details = []

            print(f"\n📈 Testing {model_name.upper()} model...")

            for i, test_case in enumerate(self.test_data):
                try:
                    if hasattr(model, 'predict'):
                        result = model.predict(test_case['description'])

                        # Extract prediction (convert severity to binary)
                        if 'severity' in result:
                            pred = 1 if 'High' in result['severity'] or 'Critical' in result['severity'] else 0
                        else:
                            pred = 0

                        # Extract confidence
                        conf = result.get('confidence', result.get('severity_confidence', 0.5))

                        predictions.append(pred)
                        confidences.append(conf)
                        details.append(result)

                        if i < 3:  # Show first 3 predictions as examples
                            print(f"   Example {i+1}: '{test_case['description'][:50]}...'")
                            print(f"      Prediction: {result.get('severity', 'Unknown')}")
                            print(f"      Confidence: {conf:.3f}")
                            print(f"      True Label: {test_case['severity_label']}")
                            print()

                except Exception as e:
                    print(f"   Error predicting case {i}: {e}")
                    predictions.append(0)
                    confidences.append(0.0)
                    details.append({'error': str(e)})

            # Calculate metrics
            true_labels = [case['true_severity'] for case in self.test_data]
            metrics = self.calculate_metrics(true_labels, predictions, confidences)
            metrics['model_type'] = model_name
            metrics['predictions'] = predictions
            metrics['confidences'] = confidences
            metrics['details'] = details

            self.results[model_name] = metrics
            self.print_metrics(model_name, metrics)

    def calculate_metrics(self, true_labels, predictions, confidences):
        """Calculate comprehensive evaluation metrics."""
        metrics = {}

        # Basic metrics
        metrics['accuracy'] = accuracy_score(true_labels, predictions)
        metrics['precision'] = precision_score(true_labels, predictions, zero_division=0)
        metrics['recall'] = recall_score(true_labels, predictions, zero_division=0)
        metrics['f1'] = f1_score(true_labels, predictions, zero_division=0)

        # Confusion matrix
        cm = confusion_matrix(true_labels, predictions)
        metrics['confusion_matrix'] = cm.tolist()

        # True/False Positives/Negatives
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        metrics['true_negatives'] = int(tn)
        metrics['false_positives'] = int(fp)
        metrics['false_negatives'] = int(fn)
        metrics['true_positives'] = int(tp)

        # Additional metrics
        metrics['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0
        metrics['mean_confidence'] = np.mean(confidences)
        metrics['std_confidence'] = np.std(confidences)

        # Critical security metrics
        high_severity_indices = [i for i, label in enumerate(true_labels) if label == 1]
        if high_severity_indices:
            high_severity_predictions = [predictions[i] for i in high_severity_indices]
            metrics['high_severity_recall'] = sum(high_severity_predictions) / len(high_severity_predictions)
        else:
            metrics['high_severity_recall'] = 0

        return metrics

    def print_metrics(self, model_name, metrics):
        """Print formatted metrics for a model."""
        print(f"\n📊 {model_name.upper()} MODEL RESULTS:")
        print("-" * 40)
        print(f"Accuracy:     {metrics['accuracy']:.3f}")
        print(f"Precision:    {metrics['precision']:.3f}")
        print(f"Recall:       {metrics['recall']:.3f}")
        print(f"F1 Score:     {metrics['f1']:.3f}")
        print(f"Specificity:  {metrics['specificity']:.3f}")
        print(f"High-Sev Recall: {metrics['high_severity_recall']:.3f}")
        print(f"Mean Confidence: {metrics['mean_confidence']:.3f}")

        print(f"\nConfusion Matrix:")
        print(f"  TN: {metrics['true_negatives']}, FP: {metrics['false_positives']}")
        print(f"  FN: {metrics['false_negatives']}, TP: {metrics['true_positives']}")

    def compare_models(self):
        """Compare all models side by side."""
        print(f"\n🏆 MODEL COMPARISON SUMMARY")
        print("=" * 80)

        comparison_data = []
        for model_name, metrics in self.results.items():
            comparison_data.append({
                'Model': model_name,
                'Accuracy': f"{metrics['accuracy']:.3f}",
                'Precision': f"{metrics['precision']:.3f}",
                'Recall': f"{metrics['recall']:.3f}",
                'F1': f"{metrics['f1']:.3f}",
                'High-Sev Recall': f"{metrics['high_severity_recall']:.3f}",
                'Mean Confidence': f"{metrics['mean_confidence']:.3f}"
            })

        # Create comparison DataFrame
        df = pd.DataFrame(comparison_data)
        print(df.to_string(index=False))

        # Find best model for each metric
        print(f"\n🥇 BEST PERFORMERS:")
        best_accuracy = max(self.results.items(), key=lambda x: x[1]['accuracy'])
        best_precision = max(self.results.items(), key=lambda x: x[1]['precision'])
        best_recall = max(self.results.items(), key=lambda x: x[1]['recall'])
        best_f1 = max(self.results.items(), key=lambda x: x[1]['f1'])

        print(f"Best Accuracy:    {best_accuracy[0]} ({best_accuracy[1]['accuracy']:.3f})")
        print(f"Best Precision:   {best_precision[0]} ({best_precision[1]['precision']:.3f})")
        print(f"Best Recall:      {best_recall[0]} ({best_recall[1]['recall']:.3f})")
        print(f"Best F1:          {best_f1[0]} ({best_f1[1]['f1']:.3f})")

    def generate_detailed_report(self):
        """Generate comprehensive evaluation report."""
        report = {
            'evaluation_timestamp': self.timestamp,
            'test_dataset_size': len(self.test_data),
            'models_evaluated': list(self.results.keys()),
            'results': self.results,
            'summary': self.get_summary()
        }

        # Save detailed report
        report_file = f'integrated_model_evaluation_{self.timestamp}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n📄 Detailed report saved: {report_file}")
        return report

    def get_summary(self):
        """Get evaluation summary."""
        if not self.results:
            return "No models evaluated"

        # Find overall best model
        best_model = max(self.results.items(), key=lambda x: x[1]['f1'])

        summary = {
            'best_overall_model': best_model[0],
            'best_f1_score': best_model[1]['f1'],
            'average_accuracy': np.mean([r['accuracy'] for r in self.results.values()]),
            'models_with_high_recall': [
                name for name, metrics in self.results.items()
                if metrics['high_severity_recall'] >= 0.8
            ]
        }

        return summary

    def run_full_evaluation(self):
        """Run complete evaluation pipeline."""
        print("🚀 STARTING INTEGRATED MODEL EVALUATION")
        print("=" * 60)
        print(f"Timestamp: {self.timestamp}")
        print(f"Models to test: {len(self.models)}")
        print(f"Test cases: {len(self.test_data)}")

        # Run evaluations
        self.evaluate_new_models()

        # Compare results
        if self.results:
            self.compare_models()

            # Generate report
            report = self.generate_detailed_report()

            print(f"\n✅ EVALUATION COMPLETE!")
            print(f"📊 Summary: {len(self.results)} models evaluated")

            if self.results:
                best_model = max(self.results.items(), key=lambda x: x[1]['f1'])
                print(f"🏆 Best Model: {best_model[0]} (F1: {best_model[1]['f1']:.3f})")

            return report
        else:
            print("❌ No models successfully evaluated")
            return None

def main():
    """Main evaluation function."""
    evaluator = IntegratedModelEvaluator()
    return evaluator.run_full_evaluation()

if __name__ == "__main__":
    main()