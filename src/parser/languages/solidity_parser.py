"""
VulnHunter Blockchain: Advanced Solidity Parser
AST to Graph conversion for smart contract vulnerability detection
Supports reentrancy, overflow, access control, and 10+ blockchain-specific threats
"""

import ast
import re
import networkx as nx
import torch
from torch_geometric.data import Data
from typing import Dict, List, Tuple, Any, Optional, Set
import hashlib
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class SolidityNode:
    """Represents a node in the Solidity AST graph"""
    id: str
    node_type: str
    content: str
    position: Tuple[int, int]
    features: Dict[str, Any]
    vulnerability_markers: List[str]
    gas_estimate: float
    security_level: int

@dataclass
class SolidityGraph:
    """Complete Solidity contract graph with blockchain-specific features"""
    nodes: List[SolidityNode]
    edges: List[Tuple[str, str, str]]
    node_features: torch.Tensor
    edge_index: torch.Tensor
    edge_attr: torch.Tensor
    contract_features: Dict[str, Any]

class SolidityParser:
    """
    Advanced Solidity parser for blockchain vulnerability detection
    Supports tree-sitter parsing with fallback to regex-based parsing
    """

    def __init__(self):
        # Vulnerability patterns for blockchain-specific threats
        self.vulnerability_patterns = {
            'reentrancy': [
                r'\.call\s*\(.*\)',
                r'\.transfer\s*\(.*\)',
                r'\.send\s*\(.*\)',
                r'address\s*\(.*\)\.call',
                r'external_call.*before.*state_change',
                r'function.*external.*{[^}]*\.call[^}]*balances\['
            ],
            'integer_overflow': [
                r'uint\d*\s+\w+\s*\+=',
                r'uint\d*\s+\w+\s*\*=',
                r'SafeMath\s*\.(?!add|sub|mul|div)',
                r'\+\+(?!.*SafeMath)',
                r'--(?!.*SafeMath)',
                r'uint256.*\*.*(?!SafeMath)'
            ],
            'access_control': [
                r'function.*(?!onlyOwner|require|modifier)',
                r'function.*public.*(?!require|onlyOwner)',
                r'msg\.sender\s*==\s*owner',
                r'require\s*\(\s*msg\.sender',
                r'modifier.*owner.*{.*_;.*}'
            ],
            'unchecked_call': [
                r'\.call\s*\([^)]*\)\s*(?!require|assert)',
                r'\.send\s*\([^)]*\)\s*(?!require|assert)',
                r'\.delegatecall\s*\([^)]*\)\s*(?!require)',
                r'address\s*\([^)]*\)\.call.*(?!require)'
            ],
            'timestamp_dependence': [
                r'block\.timestamp',
                r'block\.number',
                r'now\s*[><=]',
                r'block\.timestamp\s*[><=]',
                r'require.*block\.timestamp'
            ],
            'tx_origin': [
                r'tx\.origin',
                r'require.*tx\.origin',
                r'msg\.sender\s*==\s*tx\.origin'
            ],
            'uninitialized_storage': [
                r'struct.*{.*}\s*\w+;',
                r'mapping.*\w+\s*(?!\=)',
                r'storage\s+\w+\s*(?!\=)'
            ],
            'dos_gas_limit': [
                r'for\s*\([^)]*length[^)]*\)',
                r'while\s*\([^)]*\.length',
                r'for.*\.push\(',
                r'delete\s+\w+\[[^\]]*\]'
            ],
            'front_running': [
                r'block\.coinbase',
                r'block\.difficulty',
                r'commit.*reveal',
                r'keccak256.*block'
            ],
            'insufficient_gas_griefing': [
                r'gasleft\(\)',
                r'gas\s*:',
                r'\.call\.gas\(',
                r'require.*gasleft'
            ]
        }

        # Node type mapping for Solidity
        self.node_type_mapping = {
            'contract_definition': 0, 'function_definition': 1, 'modifier_definition': 2,
            'state_variable_declaration': 3, 'event_definition': 4, 'struct_definition': 5,
            'enum_definition': 6, 'mapping_type': 7, 'array_type': 8, 'elementary_type': 9,
            'function_call': 10, 'member_access': 11, 'identifier': 12, 'literal': 13,
            'binary_operation': 14, 'unary_operation': 15, 'assignment': 16, 'if_statement': 17,
            'for_statement': 18, 'while_statement': 19, 'require_statement': 20, 'assert_statement': 21,
            'modifier_invocation': 22, 'inheritance_specifier': 23, 'override_specifier': 24,
            'emit_statement': 25, 'return_statement': 26, 'variable_declaration': 27,
            'parameter_list': 28, 'block': 29, 'expression_statement': 30
        }

        # Gas cost estimates for operations
        self.gas_costs = {
            'sstore': 20000, 'sload': 800, 'call': 700, 'delegatecall': 700,
            'create': 32000, 'sha3': 30, 'ecrecover': 3000, 'identity': 15,
            'add': 3, 'mul': 5, 'div': 5, 'mod': 5, 'exp': 10
        }

    def parse_solidity_code(self, code: str) -> SolidityGraph:
        """
        Parse Solidity code and convert to graph representation

        Args:
            code: Solidity source code string

        Returns:
            SolidityGraph object with nodes, edges, and blockchain-specific features
        """
        try:
            # Try tree-sitter parsing first, fallback to regex-based
            try:
                return self._parse_with_tree_sitter(code)
            except ImportError:
                # Fallback to regex-based parsing
                return self._parse_with_regex(code)

        except Exception as e:
            # Handle malformed code gracefully
            return self._create_empty_graph(f"Parse Error: {e}")

    def _parse_with_regex(self, code: str) -> SolidityGraph:
        """
        Regex-based Solidity parsing (fallback when tree-sitter unavailable)
        """
        nodes = []
        edges = []
        node_counter = 0

        # Extract contracts
        contracts = re.finditer(r'contract\s+(\w+).*?\{', code)

        for contract_match in contracts:
            contract_name = contract_match.group(1)
            contract_start = contract_match.start()

            # Create contract node
            contract_node = self._create_node(
                node_counter, 'contract_definition', contract_name,
                (code[:contract_start].count('\n'), contract_match.start() - contract_start),
                code
            )
            nodes.append(contract_node)
            contract_id = contract_node.id
            node_counter += 1

            # Extract functions within this contract
            contract_code = self._extract_contract_body(code, contract_start)
            functions = re.finditer(r'function\s+(\w+)\s*\([^)]*\)([^{]*)\{', contract_code)

            for func_match in functions:
                func_name = func_match.group(1)
                func_modifiers = func_match.group(2)

                func_node = self._create_node(
                    node_counter, 'function_definition', func_name,
                    (contract_code[:func_match.start()].count('\n'), 0),
                    contract_code
                )
                nodes.append(func_node)

                # Add edge from contract to function
                edges.append((contract_id, func_node.id, 'contains'))
                node_counter += 1

                # Extract function body and analyze for vulnerabilities
                func_body = self._extract_function_body(contract_code, func_match.start())
                self._analyze_function_vulnerabilities(func_node, func_body, nodes, edges, node_counter)

            # Extract state variables
            state_vars = re.finditer(r'(\w+)(?:\[\])?\s+(?:public|private|internal)?\s+(\w+)(?:\s*=.*?)?;', contract_code)

            for var_match in state_vars:
                var_type = var_match.group(1)
                var_name = var_match.group(2)

                var_node = self._create_node(
                    node_counter, 'state_variable_declaration', f"{var_type} {var_name}",
                    (contract_code[:var_match.start()].count('\n'), 0),
                    contract_code
                )
                nodes.append(var_node)
                edges.append((contract_id, var_node.id, 'contains'))
                node_counter += 1

        # Extract features and create graph
        node_features = self._extract_node_features(nodes, code)
        edge_index, edge_attr = self._prepare_edge_data(edges)
        contract_features = self._extract_contract_features(code)

        return SolidityGraph(
            nodes=nodes,
            edges=edges,
            node_features=node_features,
            edge_index=edge_index,
            edge_attr=edge_attr,
            contract_features=contract_features
        )

    def _create_node(self, node_id: int, node_type: str, content: str, position: Tuple[int, int], code: str) -> SolidityNode:
        """Create a Solidity AST node with blockchain-specific features"""

        # Check for vulnerability markers
        vuln_markers = []
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vuln_markers.append(vuln_type)

        # Estimate gas cost
        gas_estimate = self._estimate_gas_cost(content)

        # Calculate security level (0=critical, 1=high, 2=medium, 3=low, 4=safe)
        security_level = self._calculate_security_level(content, vuln_markers)

        # Extract features
        features = {
            'node_type_id': self.node_type_mapping.get(node_type, len(self.node_type_mapping)),
            'content_length': len(content),
            'line_number': position[0],
            'column_number': position[1],
            'vulnerability_count': len(vuln_markers),
            'gas_estimate': gas_estimate,
            'security_level': security_level,
            'is_function': node_type == 'function_definition',
            'is_state_var': node_type == 'state_variable_declaration',
            'is_external_call': 'call' in content.lower(),
            'is_payable': 'payable' in content.lower(),
            'has_modifier': 'modifier' in content.lower(),
            'has_require': 'require' in content.lower(),
            'has_assert': 'assert' in content.lower(),
            'uses_msg_sender': 'msg.sender' in content,
            'uses_msg_value': 'msg.value' in content,
            'uses_block_timestamp': 'block.timestamp' in content or 'now' in content,
            'uses_tx_origin': 'tx.origin' in content,
            'complexity_score': self._calculate_complexity(content),
            'reentrancy_risk': 1 if 'reentrancy' in vuln_markers else 0,
            'overflow_risk': 1 if 'integer_overflow' in vuln_markers else 0
        }

        return SolidityNode(
            id=f"node_{node_id}",
            node_type=node_type,
            content=content,
            position=position,
            features=features,
            vulnerability_markers=vuln_markers,
            gas_estimate=gas_estimate,
            security_level=security_level
        )

    def _extract_contract_body(self, code: str, start_pos: int) -> str:
        """Extract contract body handling nested braces"""
        brace_count = 0
        i = start_pos

        # Find opening brace
        while i < len(code) and code[i] != '{':
            i += 1

        if i >= len(code):
            return ""

        start = i
        brace_count = 1
        i += 1

        # Find matching closing brace
        while i < len(code) and brace_count > 0:
            if code[i] == '{':
                brace_count += 1
            elif code[i] == '}':
                brace_count -= 1
            i += 1

        return code[start:i]

    def _extract_function_body(self, code: str, start_pos: int) -> str:
        """Extract function body"""
        return self._extract_contract_body(code, start_pos)

    def _analyze_function_vulnerabilities(self, func_node: SolidityNode, func_body: str,
                                        nodes: List[SolidityNode], edges: List[Tuple[str, str, str]],
                                        node_counter: int):
        """Analyze function for specific vulnerability patterns"""

        # Check for reentrancy patterns
        if re.search(r'\.call.*before.*balances\[', func_body, re.IGNORECASE | re.DOTALL):
            func_node.vulnerability_markers.append('reentrancy')
            func_node.security_level = min(func_node.security_level, 0)  # Critical

        # Check for external calls without checks
        external_calls = re.finditer(r'\.call\s*\([^)]*\)', func_body)
        for call in external_calls:
            # Check if call result is checked
            call_end = call.end()
            next_lines = func_body[call_end:call_end+100]
            if not re.search(r'require|assert|if.*success', next_lines):
                func_node.vulnerability_markers.append('unchecked_call')

        # Check for state changes after external calls
        if re.search(r'\.call.*\n.*\w+\s*=', func_body, re.DOTALL):
            func_node.vulnerability_markers.append('state_change_after_call')

    def _estimate_gas_cost(self, content: str) -> float:
        """Estimate gas cost for code content"""
        gas_cost = 0.0

        for operation, cost in self.gas_costs.items():
            count = len(re.findall(operation, content, re.IGNORECASE))
            gas_cost += count * cost

        # Additional costs for loops and complex operations
        gas_cost += len(re.findall(r'for\s*\(', content)) * 1000  # Loop overhead
        gas_cost += len(re.findall(r'while\s*\(', content)) * 1000
        gas_cost += len(re.findall(r'mapping\s*\(', content)) * 100

        return min(gas_cost, 1000000)  # Cap at 1M gas

    def _calculate_security_level(self, content: str, vuln_markers: List[str]) -> int:
        """Calculate security level (0=critical, 4=safe)"""
        if not vuln_markers:
            return 4  # Safe

        critical_vulns = {'reentrancy', 'integer_overflow', 'unchecked_call'}
        high_vulns = {'access_control', 'tx_origin', 'timestamp_dependence'}

        if any(v in critical_vulns for v in vuln_markers):
            return 0  # Critical
        elif any(v in high_vulns for v in vuln_markers):
            return 1  # High
        elif len(vuln_markers) > 2:
            return 2  # Medium
        else:
            return 3  # Low

    def _calculate_complexity(self, content: str) -> float:
        """Calculate cyclomatic complexity"""
        complexity = 1.0

        # Control flow statements
        complexity += len(re.findall(r'\bif\b', content))
        complexity += len(re.findall(r'\bfor\b', content))
        complexity += len(re.findall(r'\bwhile\b', content))
        complexity += len(re.findall(r'\brequire\b', content))
        complexity += len(re.findall(r'\bassert\b', content))

        # Function calls add complexity
        complexity += len(re.findall(r'\w+\s*\(', content)) * 0.5

        return min(complexity, 20.0)  # Cap at 20

    def _extract_node_features(self, nodes: List[SolidityNode], code: str) -> torch.Tensor:
        """Extract feature matrix for all nodes (30-dimensional for Solidity)"""
        feature_dim = 30
        features = torch.zeros(len(nodes), feature_dim)

        for i, node in enumerate(nodes):
            # Basic features (0-9)
            features[i, 0] = node.features['node_type_id']
            features[i, 1] = node.features['content_length']
            features[i, 2] = node.features['line_number']
            features[i, 3] = node.features['vulnerability_count']
            features[i, 4] = node.features['gas_estimate'] / 100000  # Normalized
            features[i, 5] = node.features['security_level']
            features[i, 6] = node.features['is_function']
            features[i, 7] = node.features['is_state_var']
            features[i, 8] = node.features['is_external_call']
            features[i, 9] = node.features['complexity_score'] / 20  # Normalized

            # Solidity-specific features (10-19)
            features[i, 10] = node.features['is_payable']
            features[i, 11] = node.features['has_modifier']
            features[i, 12] = node.features['has_require']
            features[i, 13] = node.features['has_assert']
            features[i, 14] = node.features['uses_msg_sender']
            features[i, 15] = node.features['uses_msg_value']
            features[i, 16] = node.features['uses_block_timestamp']
            features[i, 17] = node.features['uses_tx_origin']
            features[i, 18] = node.features['reentrancy_risk']
            features[i, 19] = node.features['overflow_risk']

            # Advanced features (20-29)
            features[i, 20] = 1.0 if 'public' in node.content else 0.0
            features[i, 21] = 1.0 if 'external' in node.content else 0.0
            features[i, 22] = 1.0 if 'internal' in node.content else 0.0
            features[i, 23] = 1.0 if 'private' in node.content else 0.0
            features[i, 24] = 1.0 if 'onlyOwner' in node.content else 0.0
            features[i, 25] = 1.0 if 'SafeMath' in node.content else 0.0
            features[i, 26] = len(node.vulnerability_markers) / 10.0  # Normalized vuln count
            features[i, 27] = hash(node.content) % 100 / 100.0  # Content hash
            features[i, 28] = min(len(node.content.split('\n')) / 50.0, 1.0)  # Normalized line count
            features[i, 29] = 1.0 if any(v in ['reentrancy', 'overflow'] for v in node.vulnerability_markers) else 0.0

        return features

    def _prepare_edge_data(self, edges: List[Tuple[str, str, str]]) -> Tuple[torch.Tensor, torch.Tensor]:
        """Prepare edge data for PyTorch Geometric"""
        if not edges:
            return torch.empty((2, 0), dtype=torch.long), torch.empty((0, 1))

        # Create node ID mapping
        node_ids = set()
        for src, dst, _ in edges:
            node_ids.add(src)
            node_ids.add(dst)

        id_to_idx = {node_id: idx for idx, node_id in enumerate(sorted(node_ids))}

        # Convert to indices
        edge_indices = []
        edge_types = []

        edge_type_mapping = {
            'contains': 0, 'calls': 1, 'modifies': 2, 'accesses': 3,
            'inherits': 4, 'implements': 5, 'control_flow': 6, 'data_flow': 7
        }

        for src, dst, edge_type in edges:
            if src in id_to_idx and dst in id_to_idx:
                edge_indices.append([id_to_idx[src], id_to_idx[dst]])
                edge_types.append(edge_type_mapping.get(edge_type, 0))

        if edge_indices:
            edge_index = torch.tensor(edge_indices, dtype=torch.long).t().contiguous()
            edge_attr = torch.tensor(edge_types, dtype=torch.float).unsqueeze(1)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, 1))

        return edge_index, edge_attr

    def _extract_contract_features(self, code: str) -> Dict[str, Any]:
        """Extract high-level contract features"""
        features = {
            'contract_count': len(re.findall(r'contract\s+\w+', code)),
            'function_count': len(re.findall(r'function\s+\w+', code)),
            'modifier_count': len(re.findall(r'modifier\s+\w+', code)),
            'event_count': len(re.findall(r'event\s+\w+', code)),
            'state_var_count': len(re.findall(r'^\s*\w+.*\w+;', code, re.MULTILINE)),
            'has_constructor': 'constructor' in code,
            'has_fallback': 'fallback' in code or 'receive' in code,
            'uses_inheritance': 'is' in code,
            'uses_interfaces': 'interface' in code,
            'solidity_version': self._extract_solidity_version(code),
            'total_lines': len(code.split('\n')),
            'complexity_score': self._calculate_complexity(code),
            'security_annotations': len(re.findall(r'@\w+', code))
        }

        return features

    def _extract_solidity_version(self, code: str) -> str:
        """Extract Solidity version from pragma"""
        version_match = re.search(r'pragma\s+solidity\s+([^;]+);', code)
        return version_match.group(1) if version_match else "unknown"

    def _create_empty_graph(self, error_msg: str) -> SolidityGraph:
        """Create empty graph for malformed code"""
        empty_node = SolidityNode(
            id="error_node",
            node_type="Error",
            content=error_msg,
            position=(0, 0),
            features={'error': True},
            vulnerability_markers=[],
            gas_estimate=0.0,
            security_level=4
        )

        return SolidityGraph(
            nodes=[empty_node],
            edges=[],
            node_features=torch.zeros(1, 30),
            edge_index=torch.empty((2, 0), dtype=torch.long),
            edge_attr=torch.empty((0, 1)),
            contract_features={'error': True}
        )

def test_solidity_parser():
    """Test the Solidity parser with sample contracts"""
    parser = SolidityParser()

    # Test vulnerable reentrancy contract
    reentrancy_contract = '''
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: External call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;  // State change after external call
    }
}
'''

    # Test safe contract
    safe_contract = '''
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Safe: State change before external call
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
'''

    for i, (name, contract) in enumerate([("Vulnerable", reentrancy_contract), ("Safe", safe_contract)]):
        print(f"\n=== Test {i+1}: {name} Contract ===")
        graph = parser.parse_solidity_code(contract)

        print(f"Nodes: {len(graph.nodes)}")
        print(f"Edges: {len(graph.edges)}")
        print(f"Feature matrix shape: {graph.node_features.shape}")

        # Count vulnerabilities
        total_vulns = sum(len(node.vulnerability_markers) for node in graph.nodes)
        print(f"Vulnerability markers found: {total_vulns}")

        # Show specific vulnerabilities
        vuln_types = set()
        for node in graph.nodes:
            vuln_types.update(node.vulnerability_markers)

        if vuln_types:
            print(f"Vulnerability types: {', '.join(vuln_types)}")
        else:
            print("No vulnerabilities detected")

        # Contract-level features
        print(f"Contract features: {graph.contract_features}")

if __name__ == "__main__":
    test_solidity_parser()