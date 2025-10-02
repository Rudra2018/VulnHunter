#!/usr/bin/env python3
"""
BEAST MODE HTTP Security Demo
Demonstrates trained HTTP vulnerability detection models
"""

import json
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.http_security_trainer import HTTPSecurityTrainer
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Demonstrate HTTP security vulnerability detection"""
    logger.info("🚀 BEAST MODE HTTP Security Detection Demo")

    # Initialize trainer and load models
    trainer = HTTPSecurityTrainer()

    try:
        trainer.load_models("http_security_models_20251002_144030.pkl")
        logger.info("✅ Models loaded successfully")
    except FileNotFoundError:
        logger.error("❌ Model file not found. Please run the trainer first.")
        return

    # Test cases demonstrating different attack types
    test_cases = [
        {
            'name': '🔴 SQL Injection Attack',
            'request': {
                'method': 'GET',
                'url': "https://vulnerable-site.com/login?username=admin' OR '1'='1' --&password=anything",
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'Accept': 'text/html,application/xhtml+xml'
                },
                'body': ''
            }
        },
        {
            'name': '🟠 Cross-Site Scripting (XSS)',
            'request': {
                'method': 'GET',
                'url': "https://vulnerable-site.com/search?q=<script>alert('XSS Attack!')</script>",
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'Referer': 'https://google.com'
                },
                'body': ''
            }
        },
        {
            'name': '🔴 Server-Side Request Forgery (SSRF)',
            'request': {
                'method': 'POST',
                'url': "https://vulnerable-site.com/api/fetch",
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'Content-Type': 'application/json'
                },
                'body': '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
            }
        },
        {
            'name': '🔴 Remote Code Execution (RCE)',
            'request': {
                'method': 'POST',
                'url': "https://vulnerable-site.com/eval",
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                'body': 'code=__import__("os").system("whoami")'
            }
        },
        {
            'name': '🟡 Security Scanner Detection',
            'request': {
                'method': 'GET',
                'url': "https://target-site.com/admin/",
                'headers': {
                    'User-Agent': 'Mozilla/5.00 (Nikto/2.1.6)',
                    'Connection': 'close'
                },
                'body': ''
            }
        },
        {
            'name': '🟢 Normal Web Request',
            'request': {
                'method': 'GET',
                'url': "https://example.com/api/users/profile",
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer valid-token-123'
                },
                'body': ''
            }
        }
    ]

    logger.info(f"\\n🔍 Analyzing {len(test_cases)} test cases...")
    logger.info("=" * 80)

    results = []

    for i, test_case in enumerate(test_cases, 1):
        logger.info(f"\\n{i}. {test_case['name']}")
        logger.info("-" * 60)

        # Analyze the request
        result = trainer.predict_vulnerability(test_case['request'])
        results.append({
            'test_case': test_case['name'],
            'prediction': result['prediction'],
            'confidence': result['confidence'],
            'model_predictions': result['model_predictions']
        })

        # Display results
        prediction = result['prediction']
        confidence = result['confidence']

        if prediction == 'normal':
            logger.info(f"✅ Status: SAFE")
        else:
            logger.info(f"⚠️  Status: THREAT DETECTED")

        logger.info(f"🎯 Primary Threat: {prediction.upper()}")
        logger.info(f"🎲 Confidence: {confidence:.1%}")

        # Show individual model predictions
        logger.info("🤖 Model Predictions:")
        for model_name, model_pred in result['model_predictions'].items():
            model_conf = result['model_confidences'][model_name]
            logger.info(f"   {model_name}: {model_pred} ({model_conf:.1%})")

        # Security assessment
        if prediction != 'normal':
            risk_level = _assess_risk_level(prediction, confidence)
            logger.info(f"🚨 Risk Level: {risk_level}")

            recommendations = _get_recommendations(prediction)
            logger.info("💡 Recommendations:")
            for rec in recommendations[:2]:  # Show top 2 recommendations
                logger.info(f"   • {rec}")

    # Summary statistics
    logger.info("\\n" + "=" * 80)
    logger.info("📊 ANALYSIS SUMMARY")
    logger.info("=" * 80)

    total_tests = len(results)
    threats_detected = sum(1 for r in results if r['prediction'] != 'normal')

    logger.info(f"🎯 Total Tests: {total_tests}")
    logger.info(f"⚠️  Threats Detected: {threats_detected}")
    logger.info(f"✅ Safe Requests: {total_tests - threats_detected}")
    logger.info(f"📊 Threat Detection Rate: {(threats_detected/total_tests)*100:.1f}%")

    # Threat breakdown
    threat_types = {}
    for result in results:
        pred = result['prediction']
        if pred != 'normal':
            threat_types[pred] = threat_types.get(pred, 0) + 1

    if threat_types:
        logger.info("\\n🔍 Threat Breakdown:")
        for threat_type, count in sorted(threat_types.items()):
            logger.info(f"   {threat_type.upper()}: {count} instances")

    # Average confidence
    avg_confidence = sum(r['confidence'] for r in results) / len(results)
    logger.info(f"\\n🎲 Average Confidence: {avg_confidence:.1%}")

    logger.info("\\n🎉 HTTP Security Analysis Complete!")
    logger.info("🦾 BEAST MODE successfully demonstrated comprehensive threat detection!")

    return results

def _assess_risk_level(threat_type, confidence):
    """Assess risk level based on threat type and confidence"""
    risk_scores = {
        'rce': 10,
        'sqli': 9,
        'ssrf': 8,
        'xss': 7,
        'scanner': 3
    }

    base_risk = risk_scores.get(threat_type, 5)
    adjusted_risk = base_risk * confidence

    if adjusted_risk >= 8:
        return "🔴 CRITICAL"
    elif adjusted_risk >= 6:
        return "🟠 HIGH"
    elif adjusted_risk >= 4:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"

def _get_recommendations(threat_type):
    """Get security recommendations for threat type"""
    recommendations = {
        'sqli': [
            "Use parameterized queries/prepared statements",
            "Implement strict input validation",
            "Apply principle of least privilege",
            "Enable SQL injection detection in WAF"
        ],
        'xss': [
            "Implement output encoding/escaping",
            "Use Content Security Policy (CSP)",
            "Validate and sanitize user input",
            "Use secure template engines"
        ],
        'ssrf': [
            "Implement URL validation and allowlisting",
            "Use network segmentation",
            "Disable dangerous URL schemes",
            "Implement request monitoring"
        ],
        'rce': [
            "Avoid dynamic code execution",
            "Implement strict input validation",
            "Use sandboxing and containers",
            "Apply security patches immediately"
        ],
        'scanner': [
            "Implement rate limiting",
            "Use CAPTCHA for suspicious traffic",
            "Deploy Web Application Firewall",
            "Monitor and block scanner IPs"
        ]
    }

    return recommendations.get(threat_type, ["Implement general security hardening"])

if __name__ == "__main__":
    main()