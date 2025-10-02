#!/usr/bin/env python3
"""
VulnGuard AI - Comprehensive Vulnerability Detection Demo
Advanced machine learning with integrated Hugging Face datasets
"""

import logging
import time
import json
from datetime import datetime
from core.http_security_trainer import VulnGuardIntegratedTrainer

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnGuardAIDemo:
    """VulnGuard AI demonstration with real vulnerability detection"""

    def __init__(self):
        self.trainer = VulnGuardIntegratedTrainer()
        self.model_file = None

        logger.info("🦾 VulnGuard AI Demo initialized")

    def display_banner(self):
        """Display VulnGuard AI banner"""
        print("=" * 70)
        print("🦾 VulnGuard AI - Advanced Vulnerability Detection System")
        print("=" * 70)
        print("   • Trained on 55,000+ vulnerability samples from Hugging Face")
        print("   • Multi-model ensemble for high accuracy detection")
        print("   • Real-time code analysis with advanced ML algorithms")
        print("   • CVE database integration and pattern matching")
        print("=" * 70)

    def train_models(self):
        """Train VulnGuard AI models with integrated datasets"""
        print("\n🔄 VulnGuard AI Training Phase...")
        print("   Loading datasets from Hugging Face Hub...")

        start_time = time.time()

        if self.trainer.train_integrated_models():
            # Save models
            self.model_file = self.trainer.save_models()

            training_time = time.time() - start_time
            print(f"\n✅ Training Complete!")
            print(f"   Training time: {training_time:.1f} seconds")
            print(f"   Models saved: {self.model_file}")
            print(f"   Samples trained: {len(self.trainer.integrated_data)}")

            return True
        else:
            print("❌ Training failed!")
            return False

    def demonstrate_vulnerability_detection(self):
        """Demonstrate vulnerability detection on test cases"""
        print("\n🔍 VulnGuard AI Vulnerability Detection Demo")
        print("=" * 50)

        # Test cases with various vulnerabilities
        test_cases = [
            {
                "name": "SQL Injection Vulnerability",
                "code": """
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()
                """,
                "expected": "Vulnerable"
            },
            {
                "name": "Buffer Overflow Risk",
                "code": """
#include <string.h>
#include <stdio.h>

void vulnerable_function(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // No bounds checking
    printf("Data: %s\\n", buffer);
}
                """,
                "expected": "Vulnerable"
            },
            {
                "name": "Command Injection",
                "code": """
import os

def execute_command(user_input):
    command = "ls " + user_input
    os.system(command)  # Direct execution without sanitization
                """,
                "expected": "Vulnerable"
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "code": """
def render_user_content(user_data):
    html = "<div>" + user_data + "</div>"  # No escaping
    return html
                """,
                "expected": "Vulnerable"
            },
            {
                "name": "Secure Code Example",
                "code": """
import hashlib
import secrets

def secure_hash_password(password):
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256',
                                       password.encode('utf-8'),
                                       salt.encode('utf-8'),
                                       100000)
    return salt + password_hash.hex()
                """,
                "expected": "Safe"
            },
            {
                "name": "Parameterized Query (Safe)",
                "code": """
def safe_login(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()
                """,
                "expected": "Safe"
            }
        ]

        results = []

        for i, test_case in enumerate(test_cases, 1):
            print(f"\n📋 Test Case {i}: {test_case['name']}")
            print(f"Expected: {test_case['expected']}")

            try:
                # Analyze with VulnGuard AI
                result = self.trainer.predict_vulnerability(test_case['code'])

                prediction = "Vulnerable" if result['ensemble_prediction'] == 1 else "Safe"
                confidence = result['ensemble_confidence']

                print(f"🎯 VulnGuard AI Prediction: {prediction}")
                print(f"🎯 Confidence: {confidence:.1%}")

                # Show individual model predictions
                print("   📊 Individual Model Results:")
                for model_name, model_pred in result['model_predictions'].items():
                    model_result = "Vulnerable" if model_pred == 1 else "Safe"
                    model_conf = result['model_confidences'][model_name]
                    print(f"      {model_name}: {model_result} ({model_conf:.1%})")

                # Check if prediction matches expectation
                status = "✅" if prediction == test_case['expected'] else "❌"
                print(f"   {status} Result: {'CORRECT' if prediction == test_case['expected'] else 'INCORRECT'}")

                results.append({
                    'test_case': test_case['name'],
                    'expected': test_case['expected'],
                    'predicted': prediction,
                    'confidence': confidence,
                    'correct': prediction == test_case['expected']
                })

            except Exception as e:
                print(f"❌ Error analyzing test case: {e}")
                results.append({
                    'test_case': test_case['name'],
                    'expected': test_case['expected'],
                    'predicted': 'Error',
                    'confidence': 0.0,
                    'correct': False
                })

        # Summary
        print(f"\n📊 VulnGuard AI Detection Summary")
        print("=" * 40)

        correct_predictions = sum(1 for r in results if r['correct'])
        total_predictions = len(results)
        accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0

        print(f"Total test cases: {total_predictions}")
        print(f"Correct predictions: {correct_predictions}")
        print(f"Accuracy: {accuracy:.1%}")

        # Show detailed results
        print(f"\n📋 Detailed Results:")
        for result in results:
            status = "✅" if result['correct'] else "❌"
            print(f"   {status} {result['test_case']}: {result['predicted']} ({result['confidence']:.1%})")

        return results

    def interactive_analysis(self):
        """Interactive code analysis"""
        print("\n🔧 Interactive VulnGuard AI Analysis")
        print("=" * 40)
        print("Enter code to analyze (type 'quit' to exit):")

        while True:
            print("\n" + "─" * 50)
            user_code = input("Enter code snippet: ").strip()

            if user_code.lower() in ['quit', 'exit', 'q']:
                break

            if not user_code:
                print("⚠️  Please enter some code to analyze")
                continue

            try:
                result = self.trainer.predict_vulnerability(user_code)

                prediction = "Vulnerable" if result['ensemble_prediction'] == 1 else "Safe"
                confidence = result['ensemble_confidence']

                print(f"\n🎯 VulnGuard AI Analysis:")
                print(f"   Prediction: {prediction}")
                print(f"   Confidence: {confidence:.1%}")

                if result['ensemble_prediction'] == 1:
                    print("   ⚠️  Potential security vulnerabilities detected!")
                    print("   💡 Recommendation: Review and remediate before deployment")
                else:
                    print("   ✅ Code appears to be secure")

                # Show model consensus
                vulnerable_models = sum(1 for pred in result['model_predictions'].values() if pred == 1)
                total_models = len(result['model_predictions'])
                consensus = vulnerable_models / total_models

                print(f"   📊 Model consensus: {vulnerable_models}/{total_models} models flagged as vulnerable")

            except Exception as e:
                print(f"❌ Error analyzing code: {e}")

    def export_demo_results(self, results: list) -> str:
        """Export demo results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnguard_demo_results_{timestamp}.json"

        demo_data = {
            'timestamp': timestamp,
            'system': 'VulnGuard AI',
            'version': '1.0',
            'model_file': self.model_file,
            'training_samples': len(self.trainer.integrated_data) if self.trainer.integrated_data else 0,
            'test_results': results,
            'summary': {
                'total_tests': len(results),
                'correct_predictions': sum(1 for r in results if r['correct']),
                'accuracy': sum(1 for r in results if r['correct']) / len(results) if results else 0
            }
        }

        with open(filename, 'w') as f:
            json.dump(demo_data, f, indent=2)

        logger.info(f"📄 Demo results exported to {filename}")
        return filename

    def run_comprehensive_demo(self):
        """Run the complete VulnGuard AI demonstration"""
        logger.info("🚀 Starting VulnGuard AI Comprehensive Demo")

        # Display banner
        self.display_banner()

        # Train models
        print(f"\n{'='*20} TRAINING PHASE {'='*20}")
        if not self.train_models():
            print("❌ Demo cannot continue without trained models")
            return

        # Demonstrate vulnerability detection
        print(f"\n{'='*20} DETECTION DEMO {'='*20}")
        results = self.demonstrate_vulnerability_detection()

        # Export results
        results_file = self.export_demo_results(results)

        # Interactive analysis option
        print(f"\n{'='*20} INTERACTIVE MODE {'='*20}")
        response = input("Would you like to try interactive analysis? (y/n): ").strip().lower()

        if response in ['y', 'yes']:
            self.interactive_analysis()

        # Final summary
        print(f"\n{'='*20} DEMO COMPLETE {'='*20}")
        print("🎉 VulnGuard AI Demo Complete!")
        print(f"📁 Model file: {self.model_file}")
        print(f"📄 Results file: {results_file}")
        print("🦾 VulnGuard AI successfully demonstrated advanced vulnerability detection!")

        return {
            'model_file': self.model_file,
            'results_file': results_file,
            'demo_results': results
        }


def main():
    """Main function to run VulnGuard AI demo"""
    demo = VulnGuardAIDemo()
    return demo.run_comprehensive_demo()


if __name__ == "__main__":
    main()