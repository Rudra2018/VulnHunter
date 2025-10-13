#!/usr/bin/env python3
"""
VulnHunter API Integration Examples

Demonstrates how to integrate with the VulnHunter API for vulnerability analysis validation.
"""

import requests
import json
from typing import Dict, Any, List
import time

class VulnHunterAPIClient:
    """Client for VulnHunter API integration."""

    def __init__(self, base_url: str = "http://localhost:5000", api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()

        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            })

    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

    def validate_single(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a single vulnerability analysis."""
        response = self.session.post(
            f"{self.base_url}/validate",
            json=analysis_data
        )
        response.raise_for_status()
        return response.json()

    def validate_batch(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate multiple analyses in batch."""
        batch_data = {"analyses": analyses}
        response = self.session.post(
            f"{self.base_url}/batch-validate",
            json=batch_data
        )
        response.raise_for_status()
        return response.json()

    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        response = self.session.get(f"{self.base_url}/stats")
        response.raise_for_status()
        return response.json()

def example_fabricated_analysis():
    """Example of a fabricated analysis (similar to OpenAI Codex pattern)."""
    return {
        "security_analysis": {
            "tool": "CustomSecurityScanner",
            "version": "2.1.0",
            "scan_timestamp": "2025-10-13T14:30:00Z",
            "target_repository": "example/repo",
            "vulnerabilities_found": 1247,
            "critical_vulnerabilities": 89,
            "high_vulnerabilities": 234,
            "medium_vulnerabilities": 567,
            "low_vulnerabilities": 357,
            "confidence_metrics": {
                "overall_confidence": 0.97,
                "false_positive_rate": 0.03,
                "detection_accuracy": 0.98
            },
            "vulnerability_details": [
                {
                    "cve_id": "CVE-2025-XXXX",
                    "severity": "CRITICAL",
                    "description": "Buffer overflow in authentication module",
                    "file_path": "src/auth/login.cpp",
                    "line_numbers": [147, 152, 158],
                    "code_snippet": "char buffer[256]; strcpy(buffer, user_input);",
                    "exploit_likelihood": 0.95,
                    "patch_complexity": "HIGH"
                }
            ]
        },
        "market_analysis": {
            "estimated_bounty_value": 125000,
            "vendor_response_time": "24-48 hours",
            "disclosure_timeline": "90 days"
        },
        "metadata": {
            "analysis_type": "automated_security_scan",
            "analyst": "AI-Security-Bot",
            "review_status": "pending"
        }
    }

def example_optimistic_analysis():
    """Example of overly optimistic analysis (similar to Microsoft bounty pattern)."""
    return {
        "security_analysis": {
            "tool": "BountyHunterPro",
            "version": "3.2.1",
            "scan_timestamp": "2025-10-13T15:00:00Z",
            "target_programs": ["Microsoft", "Google", "Apple", "Meta"],
            "total_opportunities": 2847,
            "estimated_total_value": 8950000,
            "confidence_metrics": {
                "success_probability": 0.89,
                "average_payout": 3143,
                "market_saturation": 0.23
            },
            "opportunity_breakdown": {
                "web_application": 1234,
                "mobile_application": 567,
                "cloud_infrastructure": 389,
                "api_security": 657
            }
        },
        "market_projections": {
            "12_month_revenue": 2400000,
            "roi_percentage": 340,
            "market_growth_rate": 0.78
        },
        "metadata": {
            "analysis_type": "market_opportunity",
            "analyst": "Market-AI-Analyzer",
            "confidence_level": "HIGH"
        }
    }

def example_legitimate_analysis():
    """Example of a legitimate analysis that should pass validation."""
    return {
        "security_analysis": {
            "tool": "OWASP ZAP",
            "version": "2.12.0",
            "scan_timestamp": "2025-10-13T16:00:00Z",
            "target": "https://example.com",
            "vulnerabilities_found": 3,
            "findings": [
                {
                    "type": "Missing Security Headers",
                    "severity": "MEDIUM",
                    "description": "X-Frame-Options header not set",
                    "recommendation": "Add X-Frame-Options: DENY header"
                },
                {
                    "type": "Information Disclosure",
                    "severity": "LOW",
                    "description": "Server version disclosed in headers",
                    "recommendation": "Configure server to hide version information"
                },
                {
                    "type": "SSL Configuration",
                    "severity": "MEDIUM",
                    "description": "Weak cipher suites enabled",
                    "recommendation": "Disable weak SSL/TLS cipher suites"
                }
            ]
        },
        "metadata": {
            "analysis_type": "web_security_scan",
            "analyst": "security-team@example.com",
            "verified": true
        }
    }

def run_integration_examples():
    """Run comprehensive integration examples."""

    print("🚀 VulnHunter API Integration Examples")
    print("=" * 50)

    # Initialize client
    client = VulnHunterAPIClient()

    try:
        # Health check
        print("\n1️⃣  Health Check")
        print("-" * 20)
        health = client.health_check()
        print(f"Status: {health['status']}")
        print(f"Model Status: {health['model_status']}")
        print(f"Version: {health['version']}")

        # Get statistics
        print("\n2️⃣  Model Statistics")
        print("-" * 25)
        stats = client.get_stats()
        print(f"Model: {stats['model_info']['name']}")
        print(f"Training Cases: {stats['validation_history']['total_claims_validated']}")
        print(f"False Positive Detection: {stats['performance']['overall_false_positive_rate']}")

        # Test fabricated analysis (should be detected)
        print("\n3️⃣  Testing Fabricated Analysis")
        print("-" * 35)
        fabricated_analysis = example_fabricated_analysis()
        result1 = client.validate_single(fabricated_analysis)

        classification1 = result1['overall_assessment']['primary_classification']
        confidence1 = result1['historical_context']['validation_confidence']

        print(f"Classification: {classification1}")
        print(f"Confidence: {confidence1:.3f}")
        print(f"Recommendation: {result1['overall_assessment']['recommendation']}")

        # Test optimistic analysis (should be detected)
        print("\n4️⃣  Testing Optimistic Analysis")
        print("-" * 35)
        optimistic_analysis = example_optimistic_analysis()
        result2 = client.validate_single(optimistic_analysis)

        classification2 = result2['overall_assessment']['primary_classification']
        confidence2 = result2['historical_context']['validation_confidence']

        print(f"Classification: {classification2}")
        print(f"Confidence: {confidence2:.3f}")
        print(f"Recommendation: {result2['overall_assessment']['recommendation']}")

        # Test legitimate analysis (should pass)
        print("\n5️⃣  Testing Legitimate Analysis")
        print("-" * 35)
        legitimate_analysis = example_legitimate_analysis()
        result3 = client.validate_single(legitimate_analysis)

        classification3 = result3['overall_assessment']['primary_classification']
        confidence3 = result3['historical_context']['validation_confidence']

        print(f"Classification: {classification3}")
        print(f"Confidence: {confidence3:.3f}")
        print(f"Recommendation: {result3['overall_assessment']['recommendation']}")

        # Test batch validation
        print("\n6️⃣  Testing Batch Validation")
        print("-" * 30)
        batch_analyses = [
            fabricated_analysis,
            optimistic_analysis,
            legitimate_analysis
        ]

        batch_result = client.validate_batch(batch_analyses)
        print(f"Total Analyses: {batch_result['total_analyses']}")
        print(f"Successful: {batch_result['successful']}")
        print(f"Failed: {batch_result['failed']}")

        print("\n✅ All integration examples completed successfully!")

    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Is the VulnHunter API server running?")
        print("Start it with: python vulnhunter_api.py")
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    run_integration_examples()