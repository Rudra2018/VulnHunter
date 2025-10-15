#!/usr/bin/env python3
"""
VulnHunter V4 Dynamic Smart Contract Testing Framework
Interacts with deployed contracts to validate behavior and detect runtime vulnerabilities
"""

import json
import time
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import os
from web3 import Web3
from web3.middleware import geth_poa_middleware

@dataclass
class DynamicTestCase:
    """Dynamic test case for smart contract interaction"""
    test_id: str
    contract_address: str
    function_name: str
    function_args: List[Any]
    test_type: str  # 'normal', 'attack', 'edge_case', 'gas_test'
    expected_behavior: str
    gas_limit: int = 1000000
    value: int = 0  # ETH value to send
    description: str = ""

@dataclass
class DynamicTestResult:
    """Result of dynamic test execution"""
    test_case: DynamicTestCase
    success: bool
    transaction_hash: Optional[str]
    gas_used: int
    execution_time: float
    revert_reason: Optional[str]
    state_changes: Dict[str, Any]
    events_emitted: List[Dict[str, Any]]
    vulnerability_detected: bool = False
    vulnerability_type: Optional[str] = None
    severity: str = "LOW"

class DynamicContractTester:
    """Dynamic testing framework for smart contracts"""

    def __init__(self, rpc_url: str = "http://localhost:8545"):
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.test_results = []
        self.deployed_contracts = {}

    def setup_test_environment(self):
        """Setup local blockchain testing environment"""
        print("🔧 Setting up test environment...")

        # Start local Ganache instance
        try:
            # Check if Ganache is already running
            accounts = self.web3.eth.accounts
            print(f"✅ Connected to blockchain with {len(accounts)} accounts")
            return True
        except Exception:
            print("🚀 Starting local Ganache instance...")
            # Start Ganache programmatically
            ganache_cmd = [
                "npx", "ganache-cli",
                "--accounts", "10",
                "--balance", "1000",
                "--gasLimit", "10000000",
                "--port", "8545"
            ]

            subprocess.Popen(ganache_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(5)  # Wait for Ganache to start

            try:
                accounts = self.web3.eth.accounts
                print(f"✅ Ganache started with {len(accounts)} accounts")
                return True
            except Exception as e:
                print(f"❌ Failed to start test environment: {e}")
                return False

    def deploy_contract_for_testing(self, contract_source: str, contract_name: str) -> Optional[str]:
        """Deploy contract to test environment"""
        print(f"📋 Deploying {contract_name} for testing...")

        try:
            # Compile contract
            compile_result = self._compile_contract(contract_source)
            if not compile_result:
                return None

            bytecode = compile_result['bytecode']
            abi = compile_result['abi']

            # Deploy contract
            contract = self.web3.eth.contract(abi=abi, bytecode=bytecode)
            tx_hash = contract.constructor().transact({
                'from': self.web3.eth.accounts[0],
                'gas': 3000000
            })

            tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            contract_address = tx_receipt.contractAddress

            self.deployed_contracts[contract_name] = {
                'address': contract_address,
                'abi': abi,
                'contract': self.web3.eth.contract(address=contract_address, abi=abi)
            }

            print(f"✅ {contract_name} deployed at {contract_address}")
            return contract_address

        except Exception as e:
            print(f"❌ Failed to deploy {contract_name}: {e}")
            return None

    def _compile_contract(self, contract_source: str) -> Optional[Dict[str, Any]]:
        """Compile Solidity contract"""
        try:
            # Use solc to compile
            compile_cmd = ["solc", "--combined-json", "abi,bin", contract_source]
            result = subprocess.run(compile_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"❌ Compilation error: {result.stderr}")
                return None

            compiled = json.loads(result.stdout)
            contract_data = list(compiled['contracts'].values())[0]

            return {
                'bytecode': contract_data['bin'],
                'abi': json.loads(contract_data['abi'])
            }

        except Exception as e:
            print(f"❌ Compilation failed: {e}")
            return None

    def generate_dynamic_test_cases(self, contract_address: str, abi: List[Dict]) -> List[DynamicTestCase]:
        """Generate comprehensive dynamic test cases"""
        print("🧪 Generating dynamic test cases...")

        test_cases = []

        # Analyze contract ABI to generate tests
        for item in abi:
            if item['type'] == 'function' and item['stateMutability'] != 'view':
                function_name = item['name']

                # Generate normal operation tests
                test_cases.extend(self._generate_normal_tests(contract_address, function_name, item))

                # Generate attack simulation tests
                test_cases.extend(self._generate_attack_tests(contract_address, function_name, item))

                # Generate edge case tests
                test_cases.extend(self._generate_edge_case_tests(contract_address, function_name, item))

                # Generate gas optimization tests
                test_cases.extend(self._generate_gas_tests(contract_address, function_name, item))

        print(f"📊 Generated {len(test_cases)} dynamic test cases")
        return test_cases

    def _generate_normal_tests(self, contract_address: str, function_name: str,
                             function_abi: Dict) -> List[DynamicTestCase]:
        """Generate normal operation test cases"""
        tests = []

        # Basic function call with normal parameters
        normal_args = self._generate_normal_args(function_abi['inputs'])

        tests.append(DynamicTestCase(
            test_id=f"normal_{function_name}_basic",
            contract_address=contract_address,
            function_name=function_name,
            function_args=normal_args,
            test_type="normal",
            expected_behavior="successful_execution",
            description=f"Normal execution of {function_name} with valid parameters"
        ))

        return tests

    def _generate_attack_tests(self, contract_address: str, function_name: str,
                             function_abi: Dict) -> List[DynamicTestCase]:
        """Generate attack simulation test cases"""
        tests = []

        # Reentrancy attack test
        if any(keyword in function_name.lower() for keyword in ['withdraw', 'transfer', 'send']):
            tests.append(DynamicTestCase(
                test_id=f"attack_{function_name}_reentrancy",
                contract_address=contract_address,
                function_name=function_name,
                function_args=self._generate_attack_args(function_abi['inputs'], 'reentrancy'),
                test_type="attack",
                expected_behavior="should_revert",
                description=f"Reentrancy attack simulation on {function_name}"
            ))

        # Integer overflow attack
        if any(keyword in function_name.lower() for keyword in ['add', 'mint', 'increase']):
            tests.append(DynamicTestCase(
                test_id=f"attack_{function_name}_overflow",
                contract_address=contract_address,
                function_name=function_name,
                function_args=self._generate_attack_args(function_abi['inputs'], 'overflow'),
                test_type="attack",
                expected_behavior="should_revert",
                description=f"Integer overflow attack on {function_name}"
            ))

        # Access control bypass
        if any(keyword in function_name.lower() for keyword in ['admin', 'owner', 'restricted']):
            tests.append(DynamicTestCase(
                test_id=f"attack_{function_name}_access_control",
                contract_address=contract_address,
                function_name=function_name,
                function_args=self._generate_normal_args(function_abi['inputs']),
                test_type="attack",
                expected_behavior="should_revert",
                description=f"Unauthorized access attempt on {function_name}"
            ))

        return tests

    def _generate_edge_case_tests(self, contract_address: str, function_name: str,
                                function_abi: Dict) -> List[DynamicTestCase]:
        """Generate edge case test cases"""
        tests = []

        # Zero value tests
        zero_args = self._generate_zero_args(function_abi['inputs'])
        tests.append(DynamicTestCase(
            test_id=f"edge_{function_name}_zero_values",
            contract_address=contract_address,
            function_name=function_name,
            function_args=zero_args,
            test_type="edge_case",
            expected_behavior="defined_behavior",
            description=f"Edge case: {function_name} with zero values"
        ))

        # Maximum value tests
        max_args = self._generate_max_args(function_abi['inputs'])
        tests.append(DynamicTestCase(
            test_id=f"edge_{function_name}_max_values",
            contract_address=contract_address,
            function_name=function_name,
            function_args=max_args,
            test_type="edge_case",
            expected_behavior="defined_behavior",
            description=f"Edge case: {function_name} with maximum values"
        ))

        return tests

    def _generate_gas_tests(self, contract_address: str, function_name: str,
                          function_abi: Dict) -> List[DynamicTestCase]:
        """Generate gas optimization test cases"""
        tests = []

        # Gas limit test
        tests.append(DynamicTestCase(
            test_id=f"gas_{function_name}_limit",
            contract_address=contract_address,
            function_name=function_name,
            function_args=self._generate_normal_args(function_abi['inputs']),
            test_type="gas_test",
            expected_behavior="gas_efficient",
            gas_limit=100000,  # Low gas limit
            description=f"Gas efficiency test for {function_name}"
        ))

        return tests

    def _generate_normal_args(self, inputs: List[Dict]) -> List[Any]:
        """Generate normal arguments for function inputs"""
        args = []
        for input_param in inputs:
            param_type = input_param['type']

            if 'uint' in param_type:
                args.append(100)  # Normal uint value
            elif 'int' in param_type:
                args.append(50)   # Normal int value
            elif param_type == 'address':
                args.append(self.web3.eth.accounts[1])  # Use test account
            elif param_type == 'bool':
                args.append(True)
            elif param_type == 'string':
                args.append("test_string")
            elif 'bytes' in param_type:
                args.append(b"test_bytes")
            else:
                args.append(0)  # Default value

        return args

    def _generate_attack_args(self, inputs: List[Dict], attack_type: str) -> List[Any]:
        """Generate arguments for attack simulations"""
        args = []
        for input_param in inputs:
            param_type = input_param['type']

            if attack_type == 'overflow' and 'uint' in param_type:
                # Use values that might cause overflow
                args.append(2**256 - 1)
            elif attack_type == 'reentrancy':
                # Use attacker contract address
                args.append(self.web3.eth.accounts[9])  # Last account as attacker
            else:
                args.append(self._generate_normal_args([input_param])[0])

        return args

    def _generate_zero_args(self, inputs: List[Dict]) -> List[Any]:
        """Generate zero/empty arguments"""
        args = []
        for input_param in inputs:
            param_type = input_param['type']

            if 'uint' in param_type or 'int' in param_type:
                args.append(0)
            elif param_type == 'address':
                args.append('0x0000000000000000000000000000000000000000')
            elif param_type == 'bool':
                args.append(False)
            elif param_type == 'string':
                args.append("")
            elif 'bytes' in param_type:
                args.append(b"")
            else:
                args.append(0)

        return args

    def _generate_max_args(self, inputs: List[Dict]) -> List[Any]:
        """Generate maximum value arguments"""
        args = []
        for input_param in inputs:
            param_type = input_param['type']

            if 'uint256' in param_type:
                args.append(2**256 - 1)
            elif 'uint128' in param_type:
                args.append(2**128 - 1)
            elif 'uint64' in param_type:
                args.append(2**64 - 1)
            elif 'uint32' in param_type:
                args.append(2**32 - 1)
            elif 'int' in param_type:
                args.append(2**255 - 1)  # Max positive int256
            else:
                args.append(self._generate_normal_args([input_param])[0])

        return args

    async def execute_dynamic_tests(self, test_cases: List[DynamicTestCase]) -> List[DynamicTestResult]:
        """Execute all dynamic test cases"""
        print(f"🚀 Executing {len(test_cases)} dynamic tests...")

        results = []
        for i, test_case in enumerate(test_cases):
            print(f"  [{i+1}/{len(test_cases)}] {test_case.test_id}")
            result = await self._execute_single_test(test_case)
            results.append(result)

            # Analyze result for vulnerabilities
            self._analyze_test_result(result)

        print(f"✅ Completed {len(results)} dynamic tests")
        return results

    async def _execute_single_test(self, test_case: DynamicTestCase) -> DynamicTestResult:
        """Execute single dynamic test case"""
        start_time = time.time()

        try:
            # Get contract instance
            contract_info = None
            for name, info in self.deployed_contracts.items():
                if info['address'] == test_case.contract_address:
                    contract_info = info
                    break

            if not contract_info:
                raise Exception("Contract not found in deployed contracts")

            contract = contract_info['contract']

            # Prepare transaction
            tx_params = {
                'from': self.web3.eth.accounts[0],
                'gas': test_case.gas_limit,
                'value': test_case.value
            }

            # For attack tests, use different account
            if test_case.test_type == 'attack':
                tx_params['from'] = self.web3.eth.accounts[9]  # Attacker account

            # Execute function call
            function = getattr(contract.functions, test_case.function_name)
            tx_hash = function(*test_case.function_args).transact(tx_params)

            # Wait for transaction receipt
            tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

            execution_time = time.time() - start_time

            # Extract events
            events = self._extract_events(tx_receipt, contract)

            # Get state changes (simplified)
            state_changes = self._get_state_changes(contract, test_case)

            return DynamicTestResult(
                test_case=test_case,
                success=tx_receipt.status == 1,
                transaction_hash=tx_hash.hex(),
                gas_used=tx_receipt.gasUsed,
                execution_time=execution_time,
                revert_reason=None,
                state_changes=state_changes,
                events_emitted=events
            )

        except Exception as e:
            execution_time = time.time() - start_time

            return DynamicTestResult(
                test_case=test_case,
                success=False,
                transaction_hash=None,
                gas_used=0,
                execution_time=execution_time,
                revert_reason=str(e),
                state_changes={},
                events_emitted=[]
            )

    def _extract_events(self, tx_receipt, contract) -> List[Dict[str, Any]]:
        """Extract events from transaction receipt"""
        events = []
        try:
            # Process logs to extract events
            for log in tx_receipt.logs:
                try:
                    decoded_log = contract.events.get_event_data(log)
                    events.append({
                        'event': decoded_log.event,
                        'args': dict(decoded_log.args)
                    })
                except:
                    # Skip logs that can't be decoded
                    pass
        except Exception as e:
            print(f"❌ Error extracting events: {e}")

        return events

    def _get_state_changes(self, contract, test_case: DynamicTestCase) -> Dict[str, Any]:
        """Get state changes from contract execution"""
        # This is a simplified implementation
        # In a real implementation, you'd compare contract state before/after
        return {
            'function_called': test_case.function_name,
            'args_used': test_case.function_args,
            'timestamp': datetime.now().isoformat()
        }

    def _analyze_test_result(self, result: DynamicTestResult):
        """Analyze test result for vulnerabilities"""
        test_case = result.test_case

        # Check for reentrancy vulnerability
        if test_case.test_type == 'attack' and 'reentrancy' in test_case.test_id:
            if result.success and test_case.expected_behavior == 'should_revert':
                result.vulnerability_detected = True
                result.vulnerability_type = 'reentrancy'
                result.severity = 'CRITICAL'

        # Check for integer overflow vulnerability
        if test_case.test_type == 'attack' and 'overflow' in test_case.test_id:
            if result.success and test_case.expected_behavior == 'should_revert':
                result.vulnerability_detected = True
                result.vulnerability_type = 'integer_overflow'
                result.severity = 'HIGH'

        # Check for access control bypass
        if test_case.test_type == 'attack' and 'access_control' in test_case.test_id:
            if result.success and test_case.expected_behavior == 'should_revert':
                result.vulnerability_detected = True
                result.vulnerability_type = 'access_control_bypass'
                result.severity = 'HIGH'

        # Check for gas issues
        if test_case.test_type == 'gas_test':
            if result.gas_used > test_case.gas_limit * 0.9:
                result.vulnerability_detected = True
                result.vulnerability_type = 'gas_limit_dos'
                result.severity = 'MEDIUM'

    def generate_dynamic_test_report(self, results: List[DynamicTestResult]) -> Dict[str, Any]:
        """Generate comprehensive dynamic test report"""
        vulnerabilities_found = [r for r in results if r.vulnerability_detected]
        successful_tests = [r for r in results if r.success]
        failed_tests = [r for r in results if not r.success]

        # Categorize vulnerabilities
        vuln_categories = {}
        for result in vulnerabilities_found:
            vuln_type = result.vulnerability_type
            if vuln_type not in vuln_categories:
                vuln_categories[vuln_type] = []
            vuln_categories[vuln_type].append(result)

        # Calculate risk score
        severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
        risk_score = sum(severity_weights.get(r.severity, 0) for r in vulnerabilities_found)

        return {
            'dynamic_test_summary': {
                'total_tests': len(results),
                'successful_tests': len(successful_tests),
                'failed_tests': len(failed_tests),
                'vulnerabilities_detected': len(vulnerabilities_found),
                'risk_score': risk_score
            },
            'vulnerability_breakdown': {
                vuln_type: {
                    'count': len(results),
                    'severity_distribution': {
                        result.severity: sum(1 for r in results if r.severity == result.severity)
                        for result in results
                    }
                }
                for vuln_type, results in vuln_categories.items()
            },
            'detailed_results': [asdict(result) for result in results],
            'recommendations': self._generate_dynamic_recommendations(vulnerabilities_found)
        }

    def _generate_dynamic_recommendations(self, vulnerabilities: List[DynamicTestResult]) -> List[Dict[str, Any]]:
        """Generate recommendations based on dynamic test results"""
        recommendations = []

        vuln_types = set(r.vulnerability_type for r in vulnerabilities if r.vulnerability_type)

        for vuln_type in vuln_types:
            if vuln_type == 'reentrancy':
                recommendations.append({
                    'vulnerability': 'reentrancy',
                    'priority': 'CRITICAL',
                    'recommendation': 'Implement reentrancy guards on all external calls',
                    'fix': 'Add ReentrancyGuard modifier from OpenZeppelin'
                })
            elif vuln_type == 'integer_overflow':
                recommendations.append({
                    'vulnerability': 'integer_overflow',
                    'priority': 'HIGH',
                    'recommendation': 'Use SafeMath or upgrade to Solidity 0.8+',
                    'fix': 'Implement overflow protection in arithmetic operations'
                })
            elif vuln_type == 'access_control_bypass':
                recommendations.append({
                    'vulnerability': 'access_control_bypass',
                    'priority': 'HIGH',
                    'recommendation': 'Strengthen access control mechanisms',
                    'fix': 'Review and enhance permission checks'
                })

        return recommendations

def main():
    """Main function for dynamic contract testing"""
    print("🧪 VulnHunter V4 Dynamic Smart Contract Tester")
    print("=" * 50)

    tester = DynamicContractTester()

    # Setup test environment
    if not tester.setup_test_environment():
        print("❌ Failed to setup test environment")
        return

    print("✅ Dynamic testing framework ready")
    print("📋 Deploy contracts and run: python dynamic_contract_tester.py")

if __name__ == "__main__":
    main()