#!/usr/bin/env python3
"""
Mock modules for missing VulnHunter components
Provides fallback implementations for testing
"""

from typing import List, Dict, Any

class EnhancedSemanticAnalyzer:
    """Mock semantic analyzer"""

    def analyze_target(self, target_path: str) -> Dict[str, Any]:
        return {
            'vulnerabilities': [
                {
                    'id': 'MOCK-SEM-001',
                    'category': 'access_control',
                    'title': 'Mock Semantic Finding',
                    'file': 'test.rs',
                    'line': 42,
                    'severity': 'Medium'
                }
            ]
        }

class ValidationFramework:
    """Mock validation framework"""

    def validate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return findings

class SOTAEnhancementEngine:
    """Mock SOTA enhancement engine"""

    def enhance_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Add enhancement metadata
        for finding in findings:
            finding['enhanced'] = True
            finding['confidence'] = finding.get('confidence', 0.7)
        return findings