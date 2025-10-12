#!/usr/bin/env python3
"""
QUICK ACCURACY TEST
Fast evaluation of the integrated vulnerability models
"""

import sys
import json
from datetime import datetime

# Add vulnerability_ml_models to path
sys.path.append('./vulnerability_ml_models')

# Import the new predictors
from vulnerability_ml_models.production_predictor import ProductionVulnPredictor
from vulnerability_ml_models.optimized_predictor import OptimizedVulnPredictor

def run_quick_test():
    """Run a quick accuracy test with known test cases."""

    print("🚀 QUICK ACCURACY TEST")
    print("=" * 50)

    # Test dataset with known expected results
    test_cases = [
        # High severity cases (should predict High/Critical)
        {
            'description': "Remote code execution vulnerability allowing arbitrary code execution",
            'expected': 'High/Critical',
            'label': 1
        },
        {
            'description': "Buffer overflow in network service leading to privilege escalation and root access",
            'expected': 'High/Critical',
            'label': 1
        },
        {
            'description': "SQL injection vulnerability allowing database compromise and administrative access",
            'expected': 'High/Critical',
            'label': 1
        },
        {
            'description': "Privilege escalation vulnerability allowing local users to gain root privileges",
            'expected': 'High/Critical',
            'label': 1
        },
        {
            'description': "Unauthenticated remote code execution with CVSS score 9.8",
            'expected': 'High/Critical',
            'label': 1
        },

        # Low severity cases (should predict Low/Medium)
        {
            'description': "Information disclosure vulnerability revealing system version",
            'expected': 'Low/Medium',
            'label': 0
        },
        {
            'description': "Cross-site scripting in non-critical page with minimal impact",
            'expected': 'Low/Medium',
            'label': 0
        },
        {
            'description': "Denial of service vulnerability causing temporary service disruption",
            'expected': 'Low/Medium',
            'label': 0
        },
        {
            'description': "Minor information leak through error messages",
            'expected': 'Low/Medium',
            'label': 0
        },
        {
            'description': "CSRF vulnerability in user profile update functionality",
            'expected': 'Low/Medium',
            'label': 0
        }
    ]

    # Test both models
    models = {}

    try:
        models['production'] = ProductionVulnPredictor('./vulnerability_ml_models')
        print("✅ Production model loaded")
    except Exception as e:
        print(f"❌ Production model failed: {e}")

    try:
        models['optimized'] = OptimizedVulnPredictor('./vulnerability_ml_models')
        print("✅ Optimized model loaded")
    except Exception as e:
        print(f"❌ Optimized model failed: {e}")

    results = {}

    for model_name, model in models.items():
        print(f"\n🔍 Testing {model_name.upper()} model...")

        correct = 0
        total = len(test_cases)
        predictions = []
        confidences = []

        for i, test_case in enumerate(test_cases):
            try:
                result = model.predict(test_case['description'])

                # Extract prediction
                predicted_severity = result.get('severity', 'Unknown')
                confidence = result.get('confidence', result.get('severity_confidence', 0.0))

                # Check if prediction is correct
                is_correct = predicted_severity == test_case['expected']
                if is_correct:
                    correct += 1

                predictions.append(predicted_severity)
                confidences.append(confidence)

                # Show details for first few cases
                if i < 3:
                    print(f"   Test {i+1}: '{test_case['description'][:60]}...'")
                    print(f"      Expected: {test_case['expected']}")
                    print(f"      Predicted: {predicted_severity}")
                    print(f"      Confidence: {confidence:.3f}")
                    print(f"      Correct: {'✅' if is_correct else '❌'}")
                    print()

            except Exception as e:
                print(f"   Error on test {i+1}: {e}")
                predictions.append('Error')
                confidences.append(0.0)

        accuracy = correct / total
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        # Count correct high-severity predictions (critical for security)
        high_severity_cases = [tc for tc in test_cases if tc['label'] == 1]
        high_severity_correct = sum(
            1 for i, tc in enumerate(test_cases)
            if tc['label'] == 1 and predictions[i] == tc['expected']
        )
        high_severity_recall = high_severity_correct / len(high_severity_cases) if high_severity_cases else 0

        results[model_name] = {
            'accuracy': accuracy,
            'correct': correct,
            'total': total,
            'avg_confidence': avg_confidence,
            'high_severity_recall': high_severity_recall,
            'predictions': predictions
        }

        print(f"\n📊 {model_name.upper()} RESULTS:")
        print(f"   Accuracy: {accuracy:.3f} ({correct}/{total})")
        print(f"   High-Severity Recall: {high_severity_recall:.3f}")
        print(f"   Average Confidence: {avg_confidence:.3f}")

    # Compare models
    if len(results) > 1:
        print(f"\n🏆 MODEL COMPARISON:")
        for model_name, metrics in results.items():
            print(f"   {model_name}: Accuracy {metrics['accuracy']:.3f}, "
                  f"High-Sev Recall {metrics['high_severity_recall']:.3f}")

        best_accuracy = max(results.items(), key=lambda x: x[1]['accuracy'])
        best_recall = max(results.items(), key=lambda x: x[1]['high_severity_recall'])

        print(f"\n🥇 Best Accuracy: {best_accuracy[0]} ({best_accuracy[1]['accuracy']:.3f})")
        print(f"🥇 Best High-Severity Recall: {best_recall[0]} ({best_recall[1]['high_severity_recall']:.3f})")

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        'timestamp': timestamp,
        'test_cases_count': len(test_cases),
        'models_tested': list(results.keys()),
        'results': results,
        'test_cases': test_cases
    }

    filename = f'quick_accuracy_test_{timestamp}.json'
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n📄 Results saved to: {filename}")

    return results

if __name__ == "__main__":
    run_quick_test()