#!/usr/bin/env python3
"""
Production Deployment Script for Enhanced Security Intelligence
=============================================================

Deploys the trained simplified model for immediate vulnerability detection.
Provides REST API endpoint for integration with existing security tools.
"""

import os
import sys
import json
import pickle
import time
from pathlib import Path
from typing import Dict, List, Any
from flask import Flask, request, jsonify
import logging

# Add project path
sys.path.append(str(Path(__file__).parent))

# Import our training script for model classes
from train_simplified_model import SimplifiedSecurityIntelligence, CodeFeatureExtractor

class ProductionSecurityAPI:
    """Production-ready API for vulnerability detection"""

    def __init__(self, model_path: str = "simplified_security_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.load_model()

    def load_model(self):
        """Load the trained model"""
        try:
            print("🔄 Loading trained model...")

            # Create a new model instance
            self.model = SimplifiedSecurityIntelligence()

            # Run the training pipeline from the training script
            print("🎓 Training model for production deployment...")

            # Import the main training function and run it
            from train_simplified_model import main as train_main
            trained_model = train_main()

            # Use the trained model
            self.model = trained_model

            print("✅ Model loaded and ready for production!")

        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            raise

    def analyze_code(self, code: str, include_details: bool = True) -> Dict[str, Any]:
        """Analyze code for vulnerabilities"""
        start_time = time.time()

        try:
            # Get prediction from model
            result = self.model.analyze_code(code)

            analysis_time = time.time() - start_time

            # Format response
            response = {
                "vulnerable": result["vulnerable"],
                "confidence": float(result["confidence"]),
                "risk_level": result["risk_level"],
                "patterns_detected": result.get("patterns_detected", []),
                "analysis_time": round(analysis_time, 4),
                "timestamp": time.time()
            }

            if include_details:
                response.update({
                    "code_length": len(code),
                    "line_count": code.count('\\n') + 1,
                    "model_info": {
                        "type": "SimplifiedSecurityIntelligence",
                        "version": "1.0",
                        "ensemble_models": ["random_forest", "gradient_boosting", "logistic_regression", "svm"]
                    }
                })

            return response

        except Exception as e:
            return {
                "error": str(e),
                "vulnerable": False,
                "confidence": 0.0,
                "risk_level": "unknown",
                "analysis_time": time.time() - start_time
            }

# Flask API setup
app = Flask(__name__)
security_api = None

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "model_loaded": security_api is not None,
        "timestamp": time.time()
    })

@app.route('/analyze', methods=['POST'])
def analyze_code_endpoint():
    """Analyze code for vulnerabilities"""
    try:
        data = request.get_json()

        if not data or 'code' not in data:
            return jsonify({
                "error": "Missing 'code' field in request body"
            }), 400

        code = data['code']
        include_details = data.get('include_details', True)

        # Analyze the code
        result = security_api.analyze_code(code, include_details)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "error": f"Analysis failed: {str(e)}",
            "vulnerable": False,
            "confidence": 0.0
        }), 500

@app.route('/batch_analyze', methods=['POST'])
def batch_analyze_endpoint():
    """Analyze multiple code samples"""
    try:
        data = request.get_json()

        if not data or 'code_samples' not in data:
            return jsonify({
                "error": "Missing 'code_samples' field in request body"
            }), 400

        code_samples = data['code_samples']
        include_details = data.get('include_details', False)

        if not isinstance(code_samples, list):
            return jsonify({
                "error": "'code_samples' must be a list"
            }), 400

        # Analyze each sample
        results = []
        for i, code in enumerate(code_samples):
            result = security_api.analyze_code(code, include_details)
            result['sample_id'] = i
            results.append(result)

        # Summary statistics
        vulnerable_count = sum(1 for r in results if r.get('vulnerable', False))

        return jsonify({
            "results": results,
            "summary": {
                "total_samples": len(code_samples),
                "vulnerable_samples": vulnerable_count,
                "safe_samples": len(code_samples) - vulnerable_count,
                "vulnerability_rate": vulnerable_count / len(code_samples) if code_samples else 0
            }
        })

    except Exception as e:
        return jsonify({
            "error": f"Batch analysis failed: {str(e)}"
        }), 500

def main():
    """Main deployment function"""
    global security_api

    print("🚀 ENHANCED SECURITY INTELLIGENCE - PRODUCTION DEPLOYMENT")
    print("=" * 60)

    # Initialize the security API
    print("🔧 Initializing production security API...")
    security_api = ProductionSecurityAPI()

    # Test the system
    print("\\n🧪 Running production tests...")
    test_cases = [
        "SELECT * FROM users WHERE id = '" + "user_input" + "'",  # SQL injection
        "strcpy(buffer, user_input);",  # Buffer overflow
        "print('Hello, World!')"  # Safe code
    ]

    for i, code in enumerate(test_cases, 1):
        print(f"   Test {i}: {code[:30]}...")
        result = security_api.analyze_code(code, include_details=False)
        status = "🔴 VULNERABLE" if result["vulnerable"] else "🟢 SAFE"
        print(f"      {status} (confidence: {result['confidence']:.3f})")

    print("\\n✅ Production system ready!")
    print("🌐 Starting Flask API server...")
    print("📡 Endpoints available:")
    print("   - GET  /health        - Health check")
    print("   - POST /analyze       - Single code analysis")
    print("   - POST /batch_analyze - Batch code analysis")
    print("\\n🚀 Starting server on http://localhost:8080")

    # Configure logging
    logging.basicConfig(level=logging.INFO)

    # Start the Flask server
    app.run(
        host='0.0.0.0',
        port=8080,  # Use different port to avoid conflicts
        debug=False,  # Production mode
        threaded=True
    )

if __name__ == "__main__":
    main()