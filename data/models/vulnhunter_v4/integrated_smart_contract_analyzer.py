#!/usr/bin/env python3
"""
VulnHunter V4 Integrated Smart Contract Security Analyzer
Combines static analysis, dynamic testing, and ML-powered vulnerability detection
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import pickle
import numpy as np
from dataclasses import asdict

# Import VulnHunter V4 components
from smart_contract_security_tester import SmartContractSecurityTester
from dynamic_contract_tester import DynamicContractTester

class VulnHunterV4SmartContract:
    """Integrated smart contract security analysis system"""

    def __init__(self, model_path: Optional[str] = None):
        self.static_analyzer = SmartContractSecurityTester()
        self.dynamic_tester = DynamicContractTester()
        self.ml_model = None
        self.analysis_results = {}

        # Load ML model if provided
        if model_path and os.path.exists(model_path):
            self.load_ml_model(model_path)

        # Smart contract specific vulnerability patterns
        self.smart_contract_patterns = {
            'defi_vulnerabilities': {
                'flash_loan_attack': [
                    r'flashLoan\(',
                    r'borrow.*repay',
                    r'temporary.*liquidity'
                ],
                'oracle_manipulation': [
                    r'getPrice\(',
                    r'latestRoundData\(',
                    r'oracle\.price',
                    r'priceOracle'
                ],
                'sandwich_attack': [
                    r'swap\(',
                    r'slippage',
                    r'amountOutMin',
                    r'deadline'
                ],
                'governance_attack': [
                    r'propose\(',
                    r'vote\(',
                    r'governance',
                    r'timelock'
                ]
            },
            'nft_vulnerabilities': {
                'metadata_manipulation': [
                    r'tokenURI\(',
                    r'metadata',
                    r'baseURI'
                ],
                'mint_vulnerabilities': [
                    r'mint\(',
                    r'safeMint\(',
                    r'totalSupply',
                    r'maxSupply'
                ]
            },
            'bridge_vulnerabilities': {
                'cross_chain_issues': [
                    r'bridge\(',
                    r'crossChain',
                    r'relay',
                    r'validator'
                ]
            }
        }

    def load_ml_model(self, model_path: str):
        """Load pre-trained VulnHunter V4 model"""
        try:
            with open(model_path, 'rb') as f:
                self.ml_model = pickle.load(f)
            print(f"✅ Loaded ML model from {model_path}")
        except Exception as e:
            print(f"❌ Failed to load ML model: {e}")

    async def comprehensive_analysis(self, repo_url: str, analysis_type: str = "full") -> Dict[str, Any]:
        """Perform comprehensive smart contract security analysis"""
        print(f"🔍 Starting comprehensive analysis of {repo_url}")
        print(f"📊 Analysis type: {analysis_type}")

        repo_name = repo_url.split('/')[-1]
        clone_path = f"/tmp/smart_contract_analysis_{repo_name}"

        analysis_results = {
            'repository': repo_url,
            'repository_name': repo_name,
            'analysis_type': analysis_type,
            'timestamp': datetime.now().isoformat(),
            'static_analysis': {},
            'dynamic_analysis': {},
            'ml_analysis': {},
            'integrated_findings': {},
            'risk_assessment': {},
            'recommendations': []
        }

        try:
            # 1. Static Analysis
            print("🔬 Performing static analysis...")
            static_results = self.static_analyzer.analyze_smart_contract_repository(repo_url, clone_path)
            analysis_results['static_analysis'] = static_results

            # 2. Dynamic Analysis (if requested)
            if analysis_type in ['full', 'dynamic']:
                print("🧪 Performing dynamic analysis...")
                dynamic_results = await self._perform_dynamic_analysis(clone_path)
                analysis_results['dynamic_analysis'] = dynamic_results

            # 3. ML-Enhanced Analysis
            if self.ml_model:
                print("🤖 Performing ML-enhanced analysis...")
                ml_results = self._perform_ml_analysis(static_results)
                analysis_results['ml_analysis'] = ml_results

            # 4. Integrate findings
            print("🔗 Integrating findings...")
            integrated_findings = self._integrate_findings(analysis_results)
            analysis_results['integrated_findings'] = integrated_findings

            # 5. Risk Assessment
            print("⚖️ Performing risk assessment...")
            risk_assessment = self._perform_risk_assessment(integrated_findings)
            analysis_results['risk_assessment'] = risk_assessment

            # 6. Generate recommendations
            print("💡 Generating recommendations...")
            recommendations = self._generate_comprehensive_recommendations(analysis_results)
            analysis_results['recommendations'] = recommendations

            # Save results
            self._save_analysis_results(analysis_results, repo_name)

            print("✅ Comprehensive analysis complete!")
            return analysis_results

        except Exception as e:
            print(f"❌ Analysis failed: {e}")
            analysis_results['error'] = str(e)
            return analysis_results

    async def _perform_dynamic_analysis(self, contract_path: str) -> Dict[str, Any]:
        """Perform dynamic analysis on smart contracts"""
        dynamic_results = {
            'setup_successful': False,
            'contracts_deployed': [],
            'test_results': [],
            'vulnerabilities_found': []
        }

        try:
            # Setup test environment
            setup_success = self.dynamic_tester.setup_test_environment()
            dynamic_results['setup_successful'] = setup_success

            if not setup_success:
                return dynamic_results

            # Find and deploy contracts
            contracts_deployed = await self._deploy_contracts_for_testing(contract_path)
            dynamic_results['contracts_deployed'] = contracts_deployed

            # Generate and execute tests
            all_test_results = []
            for contract_info in contracts_deployed:
                test_cases = self.dynamic_tester.generate_dynamic_test_cases(
                    contract_info['address'], contract_info['abi']
                )
                test_results = await self.dynamic_tester.execute_dynamic_tests(test_cases)
                all_test_results.extend(test_results)

            dynamic_results['test_results'] = [asdict(result) for result in all_test_results]

            # Extract vulnerabilities
            vulnerabilities = [result for result in all_test_results if result.vulnerability_detected]
            dynamic_results['vulnerabilities_found'] = [asdict(vuln) for vuln in vulnerabilities]

        except Exception as e:
            dynamic_results['error'] = str(e)

        return dynamic_results

    async def _deploy_contracts_for_testing(self, contract_path: str) -> List[Dict[str, Any]]:
        """Deploy contracts for dynamic testing"""
        deployed = []

        # Find Solidity files
        for root, dirs, files in os.walk(contract_path):
            for file in files:
                if file.endswith('.sol'):
                    contract_file = os.path.join(root, file)
                    contract_name = file[:-4]  # Remove .sol extension

                    # Try to deploy contract
                    address = self.dynamic_tester.deploy_contract_for_testing(contract_file, contract_name)
                    if address:
                        contract_info = self.dynamic_tester.deployed_contracts.get(contract_name)
                        if contract_info:
                            deployed.append({
                                'name': contract_name,
                                'address': address,
                                'abi': contract_info['abi'],
                                'source_file': contract_file
                            })

        return deployed

    def _perform_ml_analysis(self, static_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform ML-enhanced vulnerability analysis"""
        ml_results = {
            'model_version': '4.0.0-smart-contract',
            'vulnerabilities_analyzed': 0,
            'ml_predictions': [],
            'confidence_scores': [],
            'enhanced_findings': []
        }

        if not self.ml_model:
            ml_results['error'] = 'No ML model loaded'
            return ml_results

        try:
            # Extract vulnerabilities from static analysis
            vulnerabilities = static_results.get('static_analysis_results', [])
            ml_results['vulnerabilities_analyzed'] = len(vulnerabilities)

            for vuln in vulnerabilities:
                # Prepare features for ML model
                features = self._extract_ml_features(vuln)

                # Make prediction
                prediction = self.ml_model.predict([features])[0]
                confidence = float(np.max(self.ml_model.predict_proba([features])[0]))

                ml_prediction = {
                    'vulnerability_id': f"{vuln['contract_file']}:{vuln['line_number']}",
                    'original_severity': vuln['severity'],
                    'ml_prediction': 'REAL_VULNERABILITY' if prediction == 1 else 'FALSE_POSITIVE',
                    'confidence_score': confidence,
                    'ml_severity': self._calculate_ml_severity(confidence, vuln['vulnerability_type']),
                    'enhanced_description': self._enhance_vulnerability_description(vuln, confidence)
                }

                ml_results['ml_predictions'].append(ml_prediction)

                # If high confidence real vulnerability, add to enhanced findings
                if prediction == 1 and confidence > 0.8:
                    enhanced_vuln = vuln.copy()
                    enhanced_vuln['ml_enhanced'] = True
                    enhanced_vuln['ml_confidence'] = confidence
                    enhanced_vuln['ml_severity'] = ml_prediction['ml_severity']
                    ml_results['enhanced_findings'].append(enhanced_vuln)

        except Exception as e:
            ml_results['error'] = str(e)

        return ml_results

    def _extract_ml_features(self, vulnerability: Dict[str, Any]) -> List[float]:
        """Extract features for ML model prediction"""
        features = [
            len(vulnerability.get('code_snippet', '')),  # Code length
            len(vulnerability.get('description', '')),   # Description length
            vulnerability.get('line_number', 0),         # Line number
            1.0 if vulnerability.get('reentrancy_risk', False) else 0.0,
            1.0 if vulnerability.get('overflow_risk', False) else 0.0,
            1.0 if vulnerability.get('access_control_issue', False) else 0.0,
            vulnerability.get('confidence_score', 0.0),
            self._encode_vulnerability_type(vulnerability.get('vulnerability_type', '')),
            self._encode_severity(vulnerability.get('severity', 'LOW'))
        ]

        # Pad or truncate to expected feature count
        while len(features) < 10:
            features.append(0.0)

        return features[:10]

    def _encode_vulnerability_type(self, vuln_type: str) -> float:
        """Encode vulnerability type as numeric feature"""
        type_mapping = {
            'reentrancy': 1.0,
            'integer_overflow': 2.0,
            'access_control': 3.0,
            'gas_limit': 4.0,
            'timestamp_dependency': 5.0,
            'unhandled_exceptions': 6.0,
            'price_manipulation': 7.0,
            'flash_loan_attack': 8.0,
            'oracle_manipulation': 9.0
        }
        return type_mapping.get(vuln_type, 0.0)

    def _encode_severity(self, severity: str) -> float:
        """Encode severity as numeric feature"""
        severity_mapping = {
            'LOW': 1.0,
            'MEDIUM': 2.0,
            'HIGH': 3.0,
            'CRITICAL': 4.0
        }
        return severity_mapping.get(severity, 1.0)

    def _calculate_ml_severity(self, confidence: float, vuln_type: str) -> str:
        """Calculate ML-enhanced severity based on confidence and type"""
        base_severity = {
            'reentrancy': 'CRITICAL',
            'integer_overflow': 'HIGH',
            'access_control': 'HIGH',
            'flash_loan_attack': 'CRITICAL',
            'oracle_manipulation': 'CRITICAL',
            'price_manipulation': 'HIGH'
        }.get(vuln_type, 'MEDIUM')

        # Adjust severity based on confidence
        if confidence > 0.95:
            return base_severity
        elif confidence > 0.8:
            if base_severity == 'CRITICAL':
                return 'HIGH'
            elif base_severity == 'HIGH':
                return 'MEDIUM'
        else:
            return 'MEDIUM' if base_severity in ['CRITICAL', 'HIGH'] else 'LOW'

    def _enhance_vulnerability_description(self, vuln: Dict[str, Any], confidence: float) -> str:
        """Enhance vulnerability description with ML insights"""
        base_desc = vuln.get('description', '')
        vuln_type = vuln.get('vulnerability_type', '')

        enhancement = f" [ML Confidence: {confidence:.2%}]"

        if confidence > 0.95:
            enhancement += " - High confidence real vulnerability requiring immediate attention"
        elif confidence > 0.8:
            enhancement += " - Likely real vulnerability, manual review recommended"
        else:
            enhancement += " - Potential vulnerability, thorough analysis needed"

        return base_desc + enhancement

    def _integrate_findings(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Integrate findings from static, dynamic, and ML analysis"""
        integrated = {
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': [],
            'high_priority_issues': [],
            'confirmed_vulnerabilities': [],
            'potential_false_positives': [],
            'vulnerability_correlations': []
        }

        # Process static analysis results
        static_vulns = analysis_results.get('static_analysis', {}).get('static_analysis_results', [])

        # Process ML-enhanced results
        ml_vulns = analysis_results.get('ml_analysis', {}).get('enhanced_findings', [])

        # Process dynamic test results
        dynamic_vulns = analysis_results.get('dynamic_analysis', {}).get('vulnerabilities_found', [])

        # Combine and deduplicate
        all_vulnerabilities = static_vulns + ml_vulns

        # Find correlations between static and dynamic findings
        correlations = self._find_vulnerability_correlations(static_vulns, dynamic_vulns)
        integrated['vulnerability_correlations'] = correlations

        # Categorize vulnerabilities
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            ml_confidence = vuln.get('ml_confidence', 0.0)

            if severity == 'CRITICAL':
                integrated['critical_vulnerabilities'].append(vuln)
            elif severity == 'HIGH' or ml_confidence > 0.9:
                integrated['high_priority_issues'].append(vuln)

            # Mark as confirmed if found in both static and dynamic analysis
            if any(self._vulnerabilities_match(vuln, dyn_vuln) for dyn_vuln in dynamic_vulns):
                integrated['confirmed_vulnerabilities'].append(vuln)
            elif ml_confidence < 0.5:
                integrated['potential_false_positives'].append(vuln)

        integrated['total_vulnerabilities'] = len(all_vulnerabilities)

        return integrated

    def _find_vulnerability_correlations(self, static_vulns: List[Dict], dynamic_vulns: List[Dict]) -> List[Dict]:
        """Find correlations between static and dynamic analysis findings"""
        correlations = []

        for static_vuln in static_vulns:
            for dynamic_vuln in dynamic_vulns:
                if self._vulnerabilities_match(static_vuln, dynamic_vuln):
                    correlations.append({
                        'static_vulnerability': static_vuln,
                        'dynamic_confirmation': dynamic_vuln,
                        'correlation_strength': 'HIGH',
                        'confidence_boost': 0.2
                    })

        return correlations

    def _vulnerabilities_match(self, static_vuln: Dict, dynamic_vuln: Dict) -> bool:
        """Check if static and dynamic vulnerabilities match"""
        # Simple matching based on vulnerability type and location
        static_type = static_vuln.get('vulnerability_type', '')
        dynamic_type = dynamic_vuln.get('test_case', {}).get('test_type', '')

        # Map dynamic test types to static vulnerability types
        type_mapping = {
            'attack_reentrancy': 'reentrancy',
            'attack_overflow': 'integer_overflow',
            'attack_access_control': 'access_control'
        }

        return type_mapping.get(dynamic_type) == static_type

    def _perform_risk_assessment(self, integrated_findings: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        critical_count = len(integrated_findings.get('critical_vulnerabilities', []))
        high_count = len(integrated_findings.get('high_priority_issues', []))
        confirmed_count = len(integrated_findings.get('confirmed_vulnerabilities', []))
        total_count = integrated_findings.get('total_vulnerabilities', 0)

        # Calculate risk score
        risk_score = (critical_count * 10) + (high_count * 5) + (confirmed_count * 3)

        # Determine risk level
        if risk_score >= 30 or critical_count >= 3:
            risk_level = 'CRITICAL'
        elif risk_score >= 15 or critical_count >= 1:
            risk_level = 'HIGH'
        elif risk_score >= 5 or high_count >= 3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        return {
            'overall_risk_level': risk_level,
            'risk_score': risk_score,
            'vulnerability_counts': {
                'critical': critical_count,
                'high': high_count,
                'confirmed': confirmed_count,
                'total': total_count
            },
            'deployment_recommendation': self._get_deployment_recommendation(risk_level),
            'audit_requirements': self._get_audit_requirements(risk_level, critical_count)
        }

    def _get_deployment_recommendation(self, risk_level: str) -> str:
        """Get deployment recommendation based on risk level"""
        recommendations = {
            'CRITICAL': 'DO NOT DEPLOY - Critical vulnerabilities must be fixed before deployment',
            'HIGH': 'DEPLOY WITH CAUTION - Address high-priority issues before mainnet deployment',
            'MEDIUM': 'CONDITIONAL DEPLOYMENT - Consider fixes for medium-priority issues',
            'LOW': 'APPROVED FOR DEPLOYMENT - Monitor for any emerging issues'
        }
        return recommendations.get(risk_level, 'UNKNOWN')

    def _get_audit_requirements(self, risk_level: str, critical_count: int) -> Dict[str, Any]:
        """Get audit requirements based on risk assessment"""
        if risk_level == 'CRITICAL' or critical_count > 0:
            return {
                'audit_required': True,
                'audit_type': 'COMPREHENSIVE',
                'estimated_duration': '4-6 weeks',
                'formal_verification_recommended': True
            }
        elif risk_level == 'HIGH':
            return {
                'audit_required': True,
                'audit_type': 'FOCUSED',
                'estimated_duration': '2-3 weeks',
                'formal_verification_recommended': False
            }
        else:
            return {
                'audit_required': False,
                'audit_type': 'OPTIONAL',
                'estimated_duration': '1 week',
                'formal_verification_recommended': False
            }

    def _generate_comprehensive_recommendations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate comprehensive security recommendations"""
        recommendations = []

        # Static analysis recommendations
        static_results = analysis_results.get('static_analysis', {})
        if static_results.get('recommendations'):
            recommendations.extend(static_results['recommendations'])

        # Dynamic analysis recommendations
        dynamic_results = analysis_results.get('dynamic_analysis', {})
        if dynamic_results.get('test_results'):
            dynamic_rec = self.dynamic_tester._generate_dynamic_recommendations(
                [r for r in dynamic_results['test_results'] if r.get('vulnerability_detected')]
            )
            recommendations.extend(dynamic_rec)

        # ML-enhanced recommendations
        ml_results = analysis_results.get('ml_analysis', {})
        if ml_results.get('enhanced_findings'):
            ml_recommendations = self._generate_ml_recommendations(ml_results['enhanced_findings'])
            recommendations.extend(ml_recommendations)

        # Integrated recommendations
        integrated_rec = self._generate_integrated_recommendations(analysis_results)
        recommendations.extend(integrated_rec)

        return recommendations

    def _generate_ml_recommendations(self, ml_findings: List[Dict]) -> List[Dict[str, Any]]:
        """Generate ML-specific recommendations"""
        recommendations = []

        high_confidence_vulns = [f for f in ml_findings if f.get('ml_confidence', 0) > 0.9]

        if high_confidence_vulns:
            recommendations.append({
                'category': 'ML_ANALYSIS',
                'priority': 'HIGH',
                'title': 'High-Confidence ML Vulnerabilities Detected',
                'description': f'ML analysis identified {len(high_confidence_vulns)} high-confidence vulnerabilities',
                'action': 'Prioritize review and remediation of ML-flagged vulnerabilities'
            })

        return recommendations

    def _generate_integrated_recommendations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate integrated analysis recommendations"""
        recommendations = []

        risk_level = analysis_results.get('risk_assessment', {}).get('overall_risk_level', 'UNKNOWN')

        if risk_level == 'CRITICAL':
            recommendations.append({
                'category': 'DEPLOYMENT',
                'priority': 'CRITICAL',
                'title': 'Deployment Blocked - Critical Issues Found',
                'description': 'Critical vulnerabilities detected that prevent safe deployment',
                'action': 'Address all critical vulnerabilities before proceeding with deployment'
            })

        # Add correlation-based recommendations
        correlations = analysis_results.get('integrated_findings', {}).get('vulnerability_correlations', [])
        if correlations:
            recommendations.append({
                'category': 'VALIDATION',
                'priority': 'HIGH',
                'title': 'Vulnerabilities Confirmed by Multiple Analysis Methods',
                'description': f'{len(correlations)} vulnerabilities confirmed by both static and dynamic analysis',
                'action': 'Prioritize fixing vulnerabilities confirmed by multiple analysis methods'
            })

        return recommendations

    def _save_analysis_results(self, results: Dict[str, Any], repo_name: str):
        """Save analysis results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"/Users/ankitthakur/vuln_ml_research/smart_contract_analysis_{repo_name}_{timestamp}.json"

        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"💾 Analysis results saved to: {filename}")
        except Exception as e:
            print(f"❌ Failed to save results: {e}")

async def main():
    """Main function for integrated smart contract analysis"""
    print("🚀 VulnHunter V4 Integrated Smart Contract Security Analyzer")
    print("=" * 60)

    # Initialize analyzer
    analyzer = VulnHunterV4SmartContract()

    # Chainlink repositories for testing
    test_repos = [
        "https://github.com/smartcontractkit/staking-v0.1",
        "https://github.com/smartcontractkit/chainlink-solana",
        # Add more repos as needed
    ]

    # Analyze first repository
    if test_repos:
        repo_url = test_repos[0]
        print(f"🔍 Analyzing: {repo_url}")

        results = await analyzer.comprehensive_analysis(repo_url, analysis_type="full")

        # Print summary
        print("\n📊 ANALYSIS SUMMARY")
        print("=" * 40)

        static_results = results.get('static_analysis', {})
        print(f"Contracts analyzed: {static_results.get('contracts_analyzed', 0)}")
        print(f"Total vulnerabilities: {static_results.get('total_vulnerabilities', 0)}")

        risk_assessment = results.get('risk_assessment', {})
        print(f"Risk level: {risk_assessment.get('overall_risk_level', 'UNKNOWN')}")
        print(f"Risk score: {risk_assessment.get('risk_score', 0)}")

        recommendations = results.get('recommendations', [])
        print(f"Recommendations: {len(recommendations)}")

        print("\n✅ Analysis complete!")

if __name__ == "__main__":
    asyncio.run(main())