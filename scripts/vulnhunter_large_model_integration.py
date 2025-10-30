#!/usr/bin/env python3
"""
VulnHunter Ω Large Model Integration
Integration of 1.5GB trained model with existing VulnHunter infrastructure

Features:
- Seamless integration with production platform
- Large model support with existing mathematical framework
- Performance optimization and memory management
- Unified API for all model sizes
"""

import os
import sys
import json
import time
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import existing VulnHunter components
try:
    from vulnhunter_production_platform import VulnHunterProductionPlatform
    from vulnhunter_large_model_engine import LargeModelEngine, LargeModelConfig
    from vulnhunter_transformer_lite import VulnHunterTransformerLiteEngine
except ImportError as e:
    logging.warning(f"Could not import VulnHunter components: {e}")

import torch
import numpy as np

logging.basicConfig(level=logging.INFO)

class VulnHunterLargeModelIntegration:
    """
    Integration class for using large trained models with VulnHunter Ω

    Combines:
    - Large model engine (1.5GB+ models)
    - Existing mathematical framework (24 layers)
    - Production platform features
    - Real-time monitoring capabilities
    """

    def __init__(self, large_model_path: Optional[str] = None):
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize components
        self.large_model_engine = None
        self.production_platform = None
        self.lite_engine = None

        # Model availability flags
        self.large_model_available = False
        self.production_platform_available = False
        self.lite_engine_available = False

        # Performance tracking
        self.analysis_history = []

        # Initialize available components
        self._initialize_components(large_model_path)

    def _initialize_components(self, large_model_path: Optional[str]):
        """Initialize all available VulnHunter components"""

        # Initialize large model engine if path provided
        if large_model_path and os.path.exists(large_model_path):
            try:
                config = LargeModelConfig(
                    model_path=large_model_path,
                    model_size_gb=1.5,
                    max_memory_gb=8.0,
                    enable_quantization=True,
                    enable_gpu=torch.cuda.is_available()
                )
                self.large_model_engine = LargeModelEngine(config)
                self.large_model_engine.load_large_model(large_model_path)
                self.large_model_available = True
                self.logger.info("✅ Large model engine initialized")
            except Exception as e:
                self.logger.warning(f"Large model engine initialization failed: {e}")

        # Initialize production platform
        try:
            self.production_platform = VulnHunterProductionPlatform()
            self.production_platform_available = True
            self.logger.info("✅ Production platform initialized")
        except Exception as e:
            self.logger.warning(f"Production platform initialization failed: {e}")

        # Initialize lite transformer engine
        try:
            self.lite_engine = VulnHunterTransformerLiteEngine()
            self.lite_engine_available = True
            self.logger.info("✅ Lite transformer engine initialized")
        except Exception as e:
            self.logger.warning(f"Lite engine initialization failed: {e}")

        # Report initialization status
        self.logger.info(f"Initialization complete:")
        self.logger.info(f"  Large Model: {'✅' if self.large_model_available else '❌'}")
        self.logger.info(f"  Production Platform: {'✅' if self.production_platform_available else '❌'}")
        self.logger.info(f"  Lite Engine: {'✅' if self.lite_engine_available else '❌'}")

    def analyze_vulnerability_comprehensive(self, code: str, analysis_mode: str = 'auto', **kwargs) -> Dict[str, Any]:
        """
        Comprehensive vulnerability analysis using available models

        Args:
            code: Source code to analyze
            analysis_mode: 'auto', 'large_model', 'production', 'lite', 'ensemble'
            **kwargs: Additional analysis parameters

        Returns:
            Comprehensive analysis results
        """
        start_time = time.time()
        self.logger.info(f"Starting comprehensive analysis (mode: {analysis_mode})")

        # Determine analysis strategy
        if analysis_mode == 'auto':
            analysis_mode = self._select_optimal_analysis_mode(code)

        results = {}

        try:
            if analysis_mode == 'large_model' and self.large_model_available:
                results = self._analyze_with_large_model(code, **kwargs)

            elif analysis_mode == 'production' and self.production_platform_available:
                results = self._analyze_with_production_platform(code, **kwargs)

            elif analysis_mode == 'lite' and self.lite_engine_available:
                results = self._analyze_with_lite_engine(code, **kwargs)

            elif analysis_mode == 'ensemble':
                results = self._analyze_with_ensemble(code, **kwargs)

            else:
                # Fallback analysis
                results = self._analyze_with_fallback(code, **kwargs)

            # Add analysis metadata
            analysis_time = time.time() - start_time
            results.update({
                'analysis_mode_used': analysis_mode,
                'total_analysis_time': analysis_time,
                'available_engines': {
                    'large_model': self.large_model_available,
                    'production': self.production_platform_available,
                    'lite': self.lite_engine_available
                }
            })

            # Track analysis history
            self.analysis_history.append({
                'timestamp': time.time(),
                'mode': analysis_mode,
                'analysis_time': analysis_time,
                'vulnerability_detected': results.get('vulnerability_detected', False),
                'confidence': results.get('confidence', 0.0)
            })

            self.logger.info(f"Analysis completed in {analysis_time:.3f}s using {analysis_mode}")
            return results

        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {
                'error': str(e),
                'analysis_mode_attempted': analysis_mode,
                'fallback_available': True
            }

    def _select_optimal_analysis_mode(self, code: str) -> str:
        """Select optimal analysis mode based on code and available resources"""

        code_length = len(code)

        # Large model for complex code if available
        if self.large_model_available and code_length > 1000:
            return 'large_model'

        # Production platform for comprehensive analysis
        elif self.production_platform_available:
            return 'production'

        # Lite engine for quick analysis
        elif self.lite_engine_available:
            return 'lite'

        # Fallback
        else:
            return 'fallback'

    def _analyze_with_large_model(self, code: str, **kwargs) -> Dict[str, Any]:
        """Analyze using large model engine"""
        self.logger.debug("Analyzing with large model engine")

        # Get large model analysis
        large_model_results = self.large_model_engine.analyze_with_large_model(code, **kwargs)

        # Enhance with mathematical analysis if production platform available
        if self.production_platform_available:
            try:
                math_results = self.production_platform.analyze_vulnerability_production(
                    code, 'quick', {'mathematical_only': True}
                )

                # Combine results
                large_model_results['mathematical_analysis'] = math_results.get('mathematical_evidence', {})
                large_model_results['ricci_curvature'] = math_results.get('ricci_curvature_analysis', {})
                large_model_results['persistent_homology'] = math_results.get('persistent_homology_analysis', {})

            except Exception as e:
                self.logger.warning(f"Mathematical enhancement failed: {e}")

        large_model_results['primary_engine'] = 'large_model'
        return large_model_results

    def _analyze_with_production_platform(self, code: str, **kwargs) -> Dict[str, Any]:
        """Analyze using production platform"""
        self.logger.debug("Analyzing with production platform")

        analysis_mode = kwargs.get('mode', 'comprehensive')
        production_results = self.production_platform.analyze_vulnerability_production(
            code, analysis_mode, kwargs
        )

        production_results['primary_engine'] = 'production_platform'
        return production_results

    def _analyze_with_lite_engine(self, code: str, **kwargs) -> Dict[str, Any]:
        """Analyze using lite transformer engine"""
        self.logger.debug("Analyzing with lite engine")

        lite_results = self.lite_engine.analyze_code_transformer(code)

        # Convert to consistent format
        standardized_results = {
            'vulnerability_detected': lite_results.get('vulnerability_detected', False),
            'confidence': lite_results.get('vulnerability_confidence', 0.0),
            'vulnerability_type': lite_results.get('vulnerability_type', 'unknown'),
            'analysis_method': lite_results.get('analysis_method', 'transformer_lite'),
            'primary_engine': 'lite_engine'
        }

        return standardized_results

    def _analyze_with_ensemble(self, code: str, **kwargs) -> Dict[str, Any]:
        """Analyze using ensemble of available engines"""
        self.logger.debug("Analyzing with ensemble approach")

        ensemble_results = []
        weights = []

        # Large model analysis
        if self.large_model_available:
            try:
                large_result = self._analyze_with_large_model(code, **kwargs)
                ensemble_results.append(large_result)
                weights.append(0.5)  # Highest weight for large model
                self.logger.debug("Large model analysis added to ensemble")
            except Exception as e:
                self.logger.warning(f"Large model analysis failed in ensemble: {e}")

        # Production platform analysis
        if self.production_platform_available:
            try:
                prod_result = self._analyze_with_production_platform(code, **kwargs)
                ensemble_results.append(prod_result)
                weights.append(0.3)  # Medium weight for production
                self.logger.debug("Production platform analysis added to ensemble")
            except Exception as e:
                self.logger.warning(f"Production analysis failed in ensemble: {e}")

        # Lite engine analysis
        if self.lite_engine_available:
            try:
                lite_result = self._analyze_with_lite_engine(code, **kwargs)
                ensemble_results.append(lite_result)
                weights.append(0.2)  # Lower weight for lite engine
                self.logger.debug("Lite engine analysis added to ensemble")
            except Exception as e:
                self.logger.warning(f"Lite analysis failed in ensemble: {e}")

        if not ensemble_results:
            return self._analyze_with_fallback(code, **kwargs)

        # Combine ensemble results
        return self._combine_ensemble_results(ensemble_results, weights)

    def _combine_ensemble_results(self, results: List[Dict], weights: List[float]) -> Dict[str, Any]:
        """Combine results from multiple engines"""

        if not results:
            return {'error': 'No results to combine'}

        # Normalize weights
        total_weight = sum(weights)
        normalized_weights = [w / total_weight for w in weights]

        # Weighted voting for vulnerability detection
        vulnerability_votes = []
        confidence_scores = []

        for i, result in enumerate(results):
            weight = normalized_weights[i]

            # Vulnerability detection vote
            if result.get('vulnerability_detected', False):
                vulnerability_votes.append(weight)

            # Confidence score
            confidence = result.get('confidence', 0.0)
            confidence_scores.append(confidence * weight)

        # Calculate ensemble predictions
        vulnerability_score = sum(vulnerability_votes)
        ensemble_confidence = sum(confidence_scores)
        vulnerability_detected = vulnerability_score > 0.5

        # Collect vulnerability types
        vulnerability_types = [r.get('vulnerability_type', 'unknown') for r in results if r.get('vulnerability_detected')]
        most_common_type = max(set(vulnerability_types), key=vulnerability_types.count) if vulnerability_types else 'unknown'

        return {
            'vulnerability_detected': vulnerability_detected,
            'confidence': ensemble_confidence,
            'vulnerability_score': vulnerability_score,
            'vulnerability_type': most_common_type,
            'ensemble_size': len(results),
            'individual_results': results,
            'weights_used': normalized_weights,
            'primary_engine': 'ensemble',
            'analysis_method': 'ensemble_voting'
        }

    def _analyze_with_fallback(self, code: str, **kwargs) -> Dict[str, Any]:
        """Fallback analysis using pattern matching"""
        self.logger.debug("Using fallback pattern matching analysis")

        import re

        vulnerability_patterns = {
            'buffer_overflow': [r'strcpy\s*\(', r'sprintf\s*\(', r'gets\s*\('],
            'injection': [r'execute\s*\(\s*["\'].*\+.*["\']', r'eval\s*\('],
            'xss': [r'innerHTML\s*=', r'document\.write\s*\('],
            'reentrancy': [r'\.call\s*\{.*value.*\}', r'\.send\s*\('],
            'access_control': [r'require\s*\(\s*msg\.sender\s*==', r'onlyOwner']
        }

        detected_vulnerabilities = []
        for vuln_type, patterns in vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    detected_vulnerabilities.append(vuln_type)
                    break

        vulnerability_detected = len(detected_vulnerabilities) > 0
        primary_vuln = detected_vulnerabilities[0] if detected_vulnerabilities else 'unknown'

        return {
            'vulnerability_detected': vulnerability_detected,
            'confidence': 0.7 if vulnerability_detected else 0.3,
            'vulnerability_type': primary_vuln,
            'detected_patterns': detected_vulnerabilities,
            'primary_engine': 'fallback',
            'analysis_method': 'pattern_matching'
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""

        status = {
            'engines': {
                'large_model': {
                    'available': self.large_model_available,
                    'status': 'active' if self.large_model_available else 'unavailable'
                },
                'production_platform': {
                    'available': self.production_platform_available,
                    'status': 'active' if self.production_platform_available else 'unavailable'
                },
                'lite_engine': {
                    'available': self.lite_engine_available,
                    'status': 'active' if self.lite_engine_available else 'unavailable'
                }
            },
            'analysis_history': {
                'total_analyses': len(self.analysis_history),
                'recent_analyses': self.analysis_history[-5:] if self.analysis_history else []
            }
        }

        # Add performance stats if available
        if self.large_model_available:
            try:
                large_model_stats = self.large_model_engine.get_performance_stats()
                status['engines']['large_model']['performance'] = large_model_stats
            except Exception as e:
                self.logger.warning(f"Could not get large model stats: {e}")

        return status

    def demonstrate_integration(self):
        """Demonstrate the integrated large model system"""

        self.logger.info("🚀 VulnHunter Ω Large Model Integration Demo")
        self.logger.info("=" * 60)

        # Test cases
        test_cases = [
            {
                'name': 'Smart Contract Reentrancy (Complex)',
                'code': '''
                pragma solidity ^0.8.0;

                contract ComplexVulnerableContract {
                    mapping(address => uint256) public balances;
                    mapping(address => bool) public locked;

                    event Withdrawal(address indexed user, uint256 amount);

                    modifier nonReentrant() {
                        require(!locked[msg.sender], "Reentrant call");
                        locked[msg.sender] = true;
                        _;
                        locked[msg.sender] = false;
                    }

                    function deposit() public payable {
                        balances[msg.sender] += msg.value;
                    }

                    function withdraw(uint256 amount) public {
                        require(balances[msg.sender] >= amount, "Insufficient balance");

                        // Vulnerable: External call before state change
                        (bool success, ) = msg.sender.call{value: amount}("");
                        require(success, "Transfer failed");

                        balances[msg.sender] -= amount;  // State change after external call
                        emit Withdrawal(msg.sender, amount);
                    }

                    function emergencyWithdraw() public nonReentrant {
                        uint256 balance = balances[msg.sender];
                        balances[msg.sender] = 0;
                        payable(msg.sender).transfer(balance);
                    }
                }
                ''',
                'expected_vulnerable': True
            },
            {
                'name': 'Buffer Overflow (C/C++)',
                'code': '''
                #include <stdio.h>
                #include <string.h>
                #include <stdlib.h>

                int process_user_input(char* user_data) {
                    char buffer[256];
                    char formatted_output[512];

                    // Vulnerable: No bounds checking
                    strcpy(buffer, user_data);

                    // Additional vulnerability: Format string
                    sprintf(formatted_output, buffer);

                    printf("Processed: %s\\n", formatted_output);
                    return strlen(buffer);
                }

                int main(int argc, char* argv[]) {
                    if (argc > 1) {
                        process_user_input(argv[1]);
                    }
                    return 0;
                }
                ''',
                'expected_vulnerable': True
            },
            {
                'name': 'Safe Implementation',
                'code': '''
                import hashlib
                import secrets
                from typing import Optional

                class SecureUserManager:
                    def __init__(self):
                        self.users = {}
                        self.sessions = {}

                    def hash_password(self, password: str) -> str:
                        salt = secrets.token_hex(16)
                        return hashlib.pbkdf2_hmac('sha256',
                                                 password.encode(),
                                                 salt.encode(),
                                                 100000).hex() + ':' + salt

                    def verify_password(self, password: str, hash_with_salt: str) -> bool:
                        hash_part, salt = hash_with_salt.split(':')
                        return secrets.compare_digest(
                            hashlib.pbkdf2_hmac('sha256',
                                              password.encode(),
                                              salt.encode(),
                                              100000).hex(),
                            hash_part
                        )

                    def create_user(self, username: str, password: str) -> bool:
                        if username in self.users:
                            return False

                        self.users[username] = {
                            'password_hash': self.hash_password(password),
                            'created_at': time.time()
                        }
                        return True
                ''',
                'expected_vulnerable': False
            }
        ]

        # Test different analysis modes
        analysis_modes = ['auto', 'large_model', 'production', 'lite', 'ensemble']

        all_results = []

        for test_case in test_cases:
            self.logger.info(f"\n🧪 Testing: {test_case['name']}")
            self.logger.info("-" * 50)

            case_results = {}

            for mode in analysis_modes:
                if (mode == 'large_model' and not self.large_model_available) or \
                   (mode == 'production' and not self.production_platform_available) or \
                   (mode == 'lite' and not self.lite_engine_available):
                    continue

                try:
                    self.logger.info(f"  📊 Analyzing with mode: {mode}")

                    start_time = time.time()
                    result = self.analyze_vulnerability_comprehensive(
                        test_case['code'],
                        analysis_mode=mode
                    )
                    analysis_time = time.time() - start_time

                    vulnerability_detected = result.get('vulnerability_detected', False)
                    confidence = result.get('confidence', 0.0)

                    self.logger.info(f"    🎯 Vulnerable: {vulnerability_detected}")
                    self.logger.info(f"    🔍 Confidence: {confidence:.3f}")
                    self.logger.info(f"    ⏱️  Time: {analysis_time:.3f}s")

                    case_results[mode] = {
                        'vulnerability_detected': vulnerability_detected,
                        'confidence': confidence,
                        'analysis_time': analysis_time,
                        'correct': vulnerability_detected == test_case['expected_vulnerable']
                    }

                except Exception as e:
                    self.logger.error(f"    ❌ Analysis failed: {e}")
                    case_results[mode] = {'error': str(e)}

            all_results.append({
                'test_case': test_case['name'],
                'expected': test_case['expected_vulnerable'],
                'results': case_results
            })

        # Summary
        self.logger.info("\n" + "=" * 60)
        self.logger.info("🚀 INTEGRATION ANALYSIS SUMMARY")
        self.logger.info("=" * 60)

        for result in all_results:
            self.logger.info(f"\n📋 {result['test_case']}")
            self.logger.info(f"Expected: {result['expected']}")

            for mode, mode_result in result['results'].items():
                if 'error' in mode_result:
                    status = "❌ ERROR"
                elif mode_result.get('correct', False):
                    status = "✅ CORRECT"
                else:
                    status = "❌ INCORRECT"

                confidence = mode_result.get('confidence', 0.0)
                time_taken = mode_result.get('analysis_time', 0.0)
                self.logger.info(f"  {mode:15} | {status} | Conf: {confidence:.3f} | Time: {time_taken:.3f}s")

        # System status
        status = self.get_system_status()
        self.logger.info(f"\n📊 System Status:")
        self.logger.info(f"Total Analyses: {status['analysis_history']['total_analyses']}")

        for engine, info in status['engines'].items():
            status_icon = "✅" if info['available'] else "❌"
            self.logger.info(f"{engine:20} | {status_icon} {info['status']}")

        self.logger.info("\n🚀 VulnHunter Ω Large Model Integration - Demo Complete!")

        return all_results

def main():
    """Main function for large model integration demo"""

    print("🚀 VulnHunter Ω Large Model Integration")
    print("=" * 50)

    # Check for large model
    large_model_path = "models/vulnhunter_large_model_1.5gb.pth"

    if not os.path.exists(large_model_path):
        print("📦 Large model not found. Creating...")
        from vulnhunter_large_model_engine import create_sample_large_model
        create_sample_large_model(large_model_path, size_gb=1.5)

    # Initialize integration
    integration = VulnHunterLargeModelIntegration(large_model_path)

    # Run demonstration
    results = integration.demonstrate_integration()

    print(f"\n✅ Integration demonstration completed!")
    print(f"📊 Tested {len(results)} test cases")

if __name__ == "__main__":
    main()