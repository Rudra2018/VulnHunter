#!/usr/bin/env python3
"""
VulnHunter V4 Smart Contract Comprehensive Security Testing System
Integrates static analysis, dynamic testing, and behavioral validation
"""

import os
import json
import re
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import hashlib
import requests
from pathlib import Path

@dataclass
class SmartContractVulnerability:
    """Smart contract vulnerability finding"""
    contract_file: str
    line_number: int
    vulnerability_type: str
    severity: str
    description: str
    code_snippet: str
    gas_cost_impact: Optional[int] = None
    reentrancy_risk: bool = False
    overflow_risk: bool = False
    access_control_issue: bool = False
    function_name: Optional[str] = None
    confidence_score: float = 0.0
    mitigation: str = ""

@dataclass
class DynamicTestResult:
    """Dynamic test execution result"""
    test_name: str
    contract_address: str
    function_called: str
    gas_used: int
    transaction_hash: str
    success: bool
    revert_reason: Optional[str] = None
    state_changes: Dict[str, Any] = None
    execution_time: float = 0.0

class SmartContractSecurityTester:
    """Comprehensive smart contract security testing system"""

    def __init__(self):
        self.vulnerabilities = []
        self.dynamic_results = []
        self.contract_cache = {}
        self.analysis_timestamp = datetime.now().isoformat()

        # Smart contract vulnerability patterns
        self.vulnerability_patterns = {
            'reentrancy': [
                r'call\.value\(',
                r'\.call\(',
                r'\.send\(',
                r'\.transfer\(',
                r'external.*call'
            ],
            'integer_overflow': [
                r'\+\+',
                r'\-\-',
                r'\*=',
                r'\+=',
                r'\-=',
                r'uint\d+.*\+',
                r'uint\d+.*\*'
            ],
            'access_control': [
                r'onlyOwner',
                r'require\s*\(\s*msg\.sender',
                r'modifier\s+\w+.*\{',
                r'\_authorized',
                r'admin'
            ],
            'gas_limit': [
                r'for\s*\(',
                r'while\s*\(',
                r'\.length',
                r'gasleft\(\)',
                r'block\.gaslimit'
            ],
            'timestamp_dependency': [
                r'block\.timestamp',
                r'now',
                r'block\.number'
            ],
            'unhandled_exceptions': [
                r'\.call\(',
                r'\.delegatecall\(',
                r'\.staticcall\(',
                r'assembly\s*\{'
            ],
            'price_manipulation': [
                r'oracle',
                r'price',
                r'getPrice',
                r'latestRoundData',
                r'aggregator'
            ]
        }

        # Critical functions to monitor
        self.critical_functions = [
            'transfer', 'transferFrom', 'approve', 'mint', 'burn',
            'withdraw', 'deposit', 'stake', 'unstake', 'claim',
            'updatePrice', 'setPrice', 'oracle', 'feed'
        ]

    def analyze_smart_contract_repository(self, repo_url: str, clone_path: str = "/tmp/contract_analysis") -> Dict[str, Any]:
        """Analyze entire smart contract repository"""
        print(f"🔍 Starting comprehensive analysis of {repo_url}")

        # Clone repository
        if os.path.exists(clone_path):
            subprocess.run(['rm', '-rf', clone_path], check=True)

        subprocess.run(['git', 'clone', repo_url, clone_path], check=True)

        # Find all Solidity files
        solidity_files = []
        for root, dirs, files in os.walk(clone_path):
            for file in files:
                if file.endswith('.sol'):
                    solidity_files.append(os.path.join(root, file))

        print(f"📁 Found {len(solidity_files)} Solidity contracts")

        # Analyze each contract
        all_vulnerabilities = []
        for contract_file in solidity_files:
            vulnerabilities = self.static_analysis(contract_file)
            all_vulnerabilities.extend(vulnerabilities)

        # Generate dynamic tests
        dynamic_tests = self.generate_dynamic_tests(clone_path)

        # Behavioral validation
        behavioral_issues = self.behavioral_validation(clone_path)

        return {
            'repository_url': repo_url,
            'analysis_timestamp': self.analysis_timestamp,
            'contracts_analyzed': len(solidity_files),
            'total_vulnerabilities': len(all_vulnerabilities),
            'vulnerability_breakdown': self._categorize_vulnerabilities(all_vulnerabilities),
            'static_analysis_results': [asdict(v) for v in all_vulnerabilities],
            'dynamic_test_results': dynamic_tests,
            'behavioral_validation': behavioral_issues,
            'risk_assessment': self._assess_overall_risk(all_vulnerabilities),
            'recommendations': self._generate_recommendations(all_vulnerabilities)
        }

    def static_analysis(self, contract_file: str) -> List[SmartContractVulnerability]:
        """Perform static analysis on Solidity contract"""
        vulnerabilities = []

        try:
            with open(contract_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            # Analyze each line for vulnerabilities
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('//'):
                    continue

                # Check for each vulnerability type
                for vuln_type, patterns in self.vulnerability_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            vulnerability = self._create_vulnerability(
                                contract_file, line_num, line, vuln_type, pattern
                            )
                            vulnerabilities.append(vulnerability)

            # Advanced analysis
            vulnerabilities.extend(self._analyze_contract_structure(contract_file, content))
            vulnerabilities.extend(self._analyze_function_security(contract_file, content))

        except Exception as e:
            print(f"❌ Error analyzing {contract_file}: {e}")

        return vulnerabilities

    def _create_vulnerability(self, file_path: str, line_num: int, code: str,
                            vuln_type: str, pattern: str) -> SmartContractVulnerability:
        """Create vulnerability object with detailed analysis"""

        severity_map = {
            'reentrancy': 'CRITICAL',
            'integer_overflow': 'HIGH',
            'access_control': 'HIGH',
            'gas_limit': 'MEDIUM',
            'timestamp_dependency': 'MEDIUM',
            'unhandled_exceptions': 'HIGH',
            'price_manipulation': 'CRITICAL'
        }

        description_map = {
            'reentrancy': 'Potential reentrancy vulnerability detected',
            'integer_overflow': 'Integer overflow/underflow risk',
            'access_control': 'Access control mechanism detected - verify implementation',
            'gas_limit': 'Gas limit DoS vulnerability potential',
            'timestamp_dependency': 'Timestamp dependency detected',
            'unhandled_exceptions': 'Unhandled low-level call',
            'price_manipulation': 'Price oracle manipulation risk'
        }

        mitigation_map = {
            'reentrancy': 'Use ReentrancyGuard or checks-effects-interactions pattern',
            'integer_overflow': 'Use SafeMath library or Solidity 0.8+ overflow protection',
            'access_control': 'Implement proper role-based access control',
            'gas_limit': 'Implement pagination or gas-efficient loops',
            'timestamp_dependency': 'Use block.number or external oracle for timing',
            'unhandled_exceptions': 'Always check return values of low-level calls',
            'price_manipulation': 'Use multiple price feeds and implement price deviation checks'
        }

        # Calculate confidence score based on pattern specificity
        confidence = 0.8
        if 'call.value' in code or 'external' in code:
            confidence = 0.95
        elif any(func in code.lower() for func in self.critical_functions):
            confidence = 0.9

        return SmartContractVulnerability(
            contract_file=file_path,
            line_number=line_num,
            vulnerability_type=vuln_type,
            severity=severity_map.get(vuln_type, 'MEDIUM'),
            description=description_map.get(vuln_type, 'Security issue detected'),
            code_snippet=code.strip(),
            reentrancy_risk=(vuln_type == 'reentrancy'),
            overflow_risk=(vuln_type == 'integer_overflow'),
            access_control_issue=(vuln_type == 'access_control'),
            confidence_score=confidence,
            mitigation=mitigation_map.get(vuln_type, 'Review and validate implementation')
        )

    def _analyze_contract_structure(self, file_path: str, content: str) -> List[SmartContractVulnerability]:
        """Analyze overall contract structure for security issues"""
        vulnerabilities = []

        # Check for missing events
        if 'emit ' not in content and ('transfer' in content.lower() or 'mint' in content.lower()):
            vulnerabilities.append(SmartContractVulnerability(
                contract_file=file_path,
                line_number=1,
                vulnerability_type='missing_events',
                severity='MEDIUM',
                description='Critical functions should emit events for transparency',
                code_snippet='Contract structure analysis',
                confidence_score=0.7,
                mitigation='Add appropriate event emissions for state changes'
            ))

        # Check for upgrade mechanisms
        if 'proxy' in content.lower() or 'upgrade' in content.lower():
            vulnerabilities.append(SmartContractVulnerability(
                contract_file=file_path,
                line_number=1,
                vulnerability_type='upgrade_risk',
                severity='HIGH',
                description='Upgradeable contract detected - ensure proper access controls',
                code_snippet='Upgrade mechanism detected',
                confidence_score=0.8,
                mitigation='Implement multi-sig or timelock for upgrades'
            ))

        return vulnerabilities

    def _analyze_function_security(self, file_path: str, content: str) -> List[SmartContractVulnerability]:
        """Analyze individual functions for security issues"""
        vulnerabilities = []

        # Extract functions
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\s*\{'
        functions = re.finditer(function_pattern, content, re.MULTILINE)

        for match in functions:
            func_name = match.group(1)
            func_modifiers = match.group(2)
            line_num = content[:match.start()].count('\n') + 1

            # Check for public functions without access control
            if 'public' in func_modifiers and func_name in self.critical_functions:
                if not any(mod in func_modifiers for mod in ['onlyOwner', 'onlyAdmin', 'require']):
                    vulnerabilities.append(SmartContractVulnerability(
                        contract_file=file_path,
                        line_number=line_num,
                        vulnerability_type='access_control',
                        severity='HIGH',
                        description=f'Public critical function {func_name} lacks access control',
                        code_snippet=match.group(0),
                        function_name=func_name,
                        access_control_issue=True,
                        confidence_score=0.85,
                        mitigation='Add appropriate access control modifiers'
                    ))

        return vulnerabilities

    def generate_dynamic_tests(self, contract_path: str) -> List[Dict[str, Any]]:
        """Generate dynamic tests for smart contracts"""
        print("🧪 Generating dynamic tests...")

        dynamic_tests = []

        # Find test files
        test_files = []
        for root, dirs, files in os.walk(contract_path):
            for file in files:
                if file.endswith('.test.js') or file.endswith('.test.ts') or 'test' in file.lower():
                    test_files.append(os.path.join(root, file))

        # Analyze existing tests
        for test_file in test_files:
            try:
                with open(test_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Extract test scenarios
                test_scenarios = self._extract_test_scenarios(content)
                dynamic_tests.extend(test_scenarios)

            except Exception as e:
                print(f"❌ Error reading test file {test_file}: {e}")

        # Generate additional security tests
        security_tests = self._generate_security_tests(contract_path)
        dynamic_tests.extend(security_tests)

        return dynamic_tests

    def _extract_test_scenarios(self, test_content: str) -> List[Dict[str, Any]]:
        """Extract test scenarios from existing test files"""
        scenarios = []

        # Find test cases
        test_pattern = r'(it|test)\s*\(\s*["\']([^"\']+)["\']'
        tests = re.finditer(test_pattern, test_content, re.MULTILINE)

        for match in tests:
            test_name = match.group(2)
            scenarios.append({
                'test_type': 'existing_test',
                'test_name': test_name,
                'security_focus': self._classify_test_security_focus(test_name),
                'priority': 'HIGH' if any(keyword in test_name.lower()
                                        for keyword in ['revert', 'fail', 'unauthorized', 'overflow']) else 'MEDIUM'
            })

        return scenarios

    def _classify_test_security_focus(self, test_name: str) -> str:
        """Classify test security focus"""
        test_name_lower = test_name.lower()

        if any(keyword in test_name_lower for keyword in ['reentrancy', 'reentrant']):
            return 'reentrancy'
        elif any(keyword in test_name_lower for keyword in ['overflow', 'underflow']):
            return 'integer_overflow'
        elif any(keyword in test_name_lower for keyword in ['access', 'auth', 'owner', 'admin']):
            return 'access_control'
        elif any(keyword in test_name_lower for keyword in ['gas', 'limit']):
            return 'gas_optimization'
        else:
            return 'general'

    def _generate_security_tests(self, contract_path: str) -> List[Dict[str, Any]]:
        """Generate additional security-focused tests"""
        security_tests = [
            {
                'test_type': 'security_generated',
                'test_name': 'Reentrancy Attack Simulation',
                'description': 'Test contract resilience against reentrancy attacks',
                'attack_vector': 'reentrancy',
                'priority': 'CRITICAL',
                'test_script': self._generate_reentrancy_test()
            },
            {
                'test_type': 'security_generated',
                'test_name': 'Integer Overflow/Underflow Test',
                'description': 'Test arithmetic operations for overflow/underflow',
                'attack_vector': 'integer_overflow',
                'priority': 'HIGH',
                'test_script': self._generate_overflow_test()
            },
            {
                'test_type': 'security_generated',
                'test_name': 'Access Control Bypass Test',
                'description': 'Test unauthorized access to restricted functions',
                'attack_vector': 'access_control',
                'priority': 'HIGH',
                'test_script': self._generate_access_control_test()
            },
            {
                'test_type': 'security_generated',
                'test_name': 'Gas Limit DoS Test',
                'description': 'Test contract behavior under gas limit conditions',
                'attack_vector': 'gas_limit',
                'priority': 'MEDIUM',
                'test_script': self._generate_gas_limit_test()
            }
        ]

        return security_tests

    def _generate_reentrancy_test(self) -> str:
        """Generate reentrancy attack test code"""
        return '''
        // Reentrancy attack test
        contract ReentrancyAttacker {
            uint public reentryCount = 0;

            function attack(address target) external payable {
                (bool success,) = target.call{value: msg.value}("");
                require(success, "Attack failed");
            }

            receive() external payable {
                reentryCount++;
                if (reentryCount < 3) {
                    (bool success,) = msg.sender.call("");
                    require(success, "Reentry failed");
                }
            }
        }
        '''

    def _generate_overflow_test(self) -> str:
        """Generate integer overflow test code"""
        return '''
        // Integer overflow test
        function testOverflow(uint256 value) external {
            uint256 maxValue = type(uint256).max;
            // Test overflow
            try this.unsafeAdd(maxValue, value) {
                // Should revert in Solidity 0.8+
                revert("Overflow protection failed");
            } catch {
                // Expected behavior
            }
        }
        '''

    def _generate_access_control_test(self) -> str:
        """Generate access control test code"""
        return '''
        // Access control bypass test
        function testUnauthorizedAccess() external {
            address unauthorizedUser = address(0x123);
            vm.prank(unauthorizedUser);

            try target.restrictedFunction() {
                revert("Access control bypass detected");
            } catch {
                // Expected behavior - access denied
            }
        }
        '''

    def _generate_gas_limit_test(self) -> str:
        """Generate gas limit test code"""
        return '''
        // Gas limit DoS test
        function testGasLimitDoS() external {
            uint256 gasLimit = block.gaslimit;
            uint256 gasUsed = 0;

            while (gasUsed < gasLimit * 80 / 100) {
                gasUsed = gasleft();
                // Perform expensive operation
                keccak256(abi.encode(block.timestamp, block.number));
            }
        }
        '''

    def behavioral_validation(self, contract_path: str) -> Dict[str, Any]:
        """Perform behavioral validation of smart contracts"""
        print("🔬 Performing behavioral validation...")

        behavioral_issues = {
            'unexpected_behaviors': [],
            'state_consistency_issues': [],
            'gas_optimization_opportunities': [],
            'compliance_issues': []
        }

        # Check for unexpected state changes
        behavioral_issues['unexpected_behaviors'] = self._check_unexpected_behaviors(contract_path)

        # Validate state consistency
        behavioral_issues['state_consistency_issues'] = self._check_state_consistency(contract_path)

        # Identify gas optimization opportunities
        behavioral_issues['gas_optimization_opportunities'] = self._identify_gas_optimizations(contract_path)

        # Check compliance with standards
        behavioral_issues['compliance_issues'] = self._check_compliance(contract_path)

        return behavioral_issues

    def _check_unexpected_behaviors(self, contract_path: str) -> List[Dict[str, Any]]:
        """Check for unexpected contract behaviors"""
        issues = []

        # Pattern-based behavior checks
        behavior_patterns = {
            'silent_failures': r'\.call\([^)]*\)(?!\s*;)',
            'unbounded_loops': r'for\s*\([^)]*;\s*[^;]*\.length\s*;',
            'external_calls_in_loops': r'for\s*\([^}]*\.(call|transfer|send)',
            'delegatecall_usage': r'\.delegatecall\(',
        }

        for root, dirs, files in os.walk(contract_path):
            for file in files:
                if file.endswith('.sol'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()

                        for pattern_name, pattern in behavior_patterns.items():
                            matches = re.finditer(pattern, content, re.MULTILINE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                issues.append({
                                    'file': file_path,
                                    'line': line_num,
                                    'issue_type': pattern_name,
                                    'code_snippet': match.group(0),
                                    'severity': 'HIGH' if 'call' in pattern_name else 'MEDIUM'
                                })

                    except Exception as e:
                        print(f"❌ Error checking behaviors in {file_path}: {e}")

        return issues

    def _check_state_consistency(self, contract_path: str) -> List[Dict[str, Any]]:
        """Check for state consistency issues"""
        issues = []

        # Look for state variables that might become inconsistent
        state_patterns = {
            'unprotected_state_changes': r'(\w+)\s*=\s*[^;]+;(?!.*require)',
            'missing_state_validation': r'function\s+\w+[^{]*{[^}]*(\w+)\s*=\s*[^;]+;',
        }

        # Implementation would analyze state changes across functions
        # This is a simplified version

        return issues

    def _identify_gas_optimizations(self, contract_path: str) -> List[Dict[str, Any]]:
        """Identify gas optimization opportunities"""
        optimizations = []

        gas_patterns = {
            'storage_vs_memory': r'(\w+\[\])\s+(\w+)\s*=',
            'redundant_storage_reads': r'(\w+\.length)',
            'inefficient_loops': r'for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length',
            'unnecessary_storage': r'(\w+)\s*=\s*(\w+);\s*return\s+\1;'
        }

        # Implementation would analyze gas usage patterns
        # This is a simplified version

        return optimizations

    def _check_compliance(self, contract_path: str) -> List[Dict[str, Any]]:
        """Check compliance with ERC standards and best practices"""
        compliance_issues = []

        # Check for ERC20/ERC721/ERC1155 compliance
        standard_patterns = {
            'erc20_missing_events': r'function\s+transfer[^{]*{[^}]*(?!.*emit)',
            'erc20_missing_return': r'function\s+transfer[^{]*{[^}]*(?!.*return)',
            'missing_interface': r'contract\s+\w+(?!\s+is\s+)',
        }

        # Implementation would check standard compliance
        # This is a simplified version

        return compliance_issues

    def _categorize_vulnerabilities(self, vulnerabilities: List[SmartContractVulnerability]) -> Dict[str, int]:
        """Categorize vulnerabilities by type and severity"""
        categorization = {
            'by_type': {},
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }

        for vuln in vulnerabilities:
            # Count by type
            vuln_type = vuln.vulnerability_type
            categorization['by_type'][vuln_type] = categorization['by_type'].get(vuln_type, 0) + 1

            # Count by severity
            categorization['by_severity'][vuln.severity] += 1

        return categorization

    def _assess_overall_risk(self, vulnerabilities: List[SmartContractVulnerability]) -> Dict[str, Any]:
        """Assess overall risk level of the smart contract system"""
        if not vulnerabilities:
            return {'risk_level': 'LOW', 'score': 0, 'reasoning': 'No vulnerabilities detected'}

        # Calculate risk score
        severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
        total_score = sum(severity_weights.get(v.severity, 0) for v in vulnerabilities)

        # Determine risk level
        if total_score >= 20:
            risk_level = 'CRITICAL'
        elif total_score >= 10:
            risk_level = 'HIGH'
        elif total_score >= 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        critical_count = sum(1 for v in vulnerabilities if v.severity == 'CRITICAL')
        high_count = sum(1 for v in vulnerabilities if v.severity == 'HIGH')

        reasoning = f"{len(vulnerabilities)} total vulnerabilities: {critical_count} critical, {high_count} high severity"

        return {
            'risk_level': risk_level,
            'score': total_score,
            'reasoning': reasoning,
            'immediate_action_required': critical_count > 0
        }

    def _generate_recommendations(self, vulnerabilities: List[SmartContractVulnerability]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings"""
        recommendations = []

        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)

        # Generate recommendations for each type
        for vuln_type, vulns in vuln_types.items():
            if vuln_type == 'reentrancy':
                recommendations.append({
                    'priority': 'CRITICAL',
                    'category': 'Reentrancy Protection',
                    'recommendation': 'Implement ReentrancyGuard or use checks-effects-interactions pattern',
                    'affected_files': len(set(v.contract_file for v in vulns)),
                    'implementation': 'Add OpenZeppelin ReentrancyGuard modifier to vulnerable functions'
                })
            elif vuln_type == 'access_control':
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Access Control',
                    'recommendation': 'Implement comprehensive role-based access control',
                    'affected_files': len(set(v.contract_file for v in vulns)),
                    'implementation': 'Use OpenZeppelin AccessControl or Ownable contracts'
                })
            # Add more recommendation types...

        # General recommendations
        recommendations.extend([
            {
                'priority': 'HIGH',
                'category': 'Testing',
                'recommendation': 'Implement comprehensive security testing suite',
                'implementation': 'Add unit tests, integration tests, and formal verification'
            },
            {
                'priority': 'MEDIUM',
                'category': 'Monitoring',
                'recommendation': 'Implement runtime monitoring and alerting',
                'implementation': 'Add event logging and monitoring for critical functions'
            }
        ])

        return recommendations

def main():
    """Main execution function for smart contract security testing"""
    tester = SmartContractSecurityTester()

    # Chainlink repositories to test
    chainlink_repos = [
        "https://github.com/smartcontractkit/staking-v0.1",
        "https://github.com/smartcontractkit/chainlink-solana",
        "https://github.com/smartcontractkit/chainlink-evm",
        "https://github.com/smartcontractkit/chainlink",
        "https://github.com/smartcontractkit/external-adapters-js"
    ]

    print("🚀 VulnHunter V4 Smart Contract Security Testing System")
    print("=" * 60)

    all_results = {}

    for repo_url in chainlink_repos:
        try:
            print(f"\n📊 Analyzing repository: {repo_url}")
            repo_name = repo_url.split('/')[-1]
            clone_path = f"/tmp/contract_analysis_{repo_name}"

            results = tester.analyze_smart_contract_repository(repo_url, clone_path)
            all_results[repo_name] = results

            print(f"✅ Completed analysis of {repo_name}")
            print(f"   Contracts: {results['contracts_analyzed']}")
            print(f"   Vulnerabilities: {results['total_vulnerabilities']}")
            print(f"   Risk Level: {results['risk_assessment']['risk_level']}")

        except Exception as e:
            print(f"❌ Error analyzing {repo_url}: {e}")
            all_results[repo_url.split('/')[-1]] = {'error': str(e)}

    # Save comprehensive results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"/Users/ankitthakur/vuln_ml_research/smart_contract_security_results_{timestamp}.json"

    with open(results_file, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n💾 Results saved to: {results_file}")
    print("🎯 Smart contract security analysis complete!")

if __name__ == "__main__":
    main()