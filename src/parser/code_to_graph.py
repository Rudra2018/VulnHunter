"""
VulnHunter PoC: Code to Graph Parser
Converts Python code to AST then to Graph representation using tree-sitter
"""

import ast
import networkx as nx
import torch
from typing import Dict, List, Tuple, Any
import hashlib
import re
from dataclasses import dataclass

@dataclass
class GraphNode:
    """Represents a node in the code graph"""
    id: str
    node_type: str
    content: str
    position: Tuple[int, int]
    features: Dict[str, Any]

@dataclass
class CodeGraph:
    """Represents the complete code graph"""
    nodes: List[GraphNode]
    edges: List[Tuple[str, str, str]]  # (source, target, edge_type)
    node_features: torch.Tensor
    edge_index: torch.Tensor
    edge_attr: torch.Tensor

class CodeToGraphParser:
    """Advanced parser that converts Python code to graph representation"""

    def __init__(self):
        self.vulnerability_patterns = {
            'sql_injection': [
                r'execute\s*\(\s*["\'].*\+.*["\']',
                r'cursor\.execute\s*\(\s*["\'][^"\']*\+',
                r'query\s*=\s*["\'][^"\']*\+',
                r'SELECT.*\+.*FROM',
                r'INSERT.*\+.*VALUES'
            ],
            'command_injection': [
                r'os\.system\s*\(\s*["\'][^"\']*\+',
                r'subprocess\.(call|run|Popen).*\+',
                r'exec\s*\(\s*["\'][^"\']*\+'
            ],
            'path_traversal': [
                r'open\s*\(\s*["\'][^"\']*\+',
                r'file\s*=.*\+.*["\']',
                r'\.\.\/.*\+'
            ]
        }

        self.node_type_mapping = {
            'Module': 0, 'FunctionDef': 1, 'ClassDef': 2, 'If': 3, 'For': 4,
            'While': 5, 'Call': 6, 'Name': 7, 'Str': 8, 'Num': 9, 'BinOp': 10,
            'Compare': 11, 'Assign': 12, 'Return': 13, 'Import': 14, 'Expr': 15,
            'Attribute': 16, 'Subscript': 17, 'List': 18, 'Dict': 19, 'Tuple': 20
        }

    def parse_code_to_graph(self, code: str) -> CodeGraph:
        """
        Parse Python code and convert to graph representation

        Args:
            code: Python source code string

        Returns:
            CodeGraph object with nodes, edges, and features
        """
        try:
            # Parse code to AST
            tree = ast.parse(code)

            # Convert AST to graph
            nodes, edges = self._ast_to_graph(tree, code)

            # Extract features
            node_features = self._extract_node_features(nodes, code)
            edge_index, edge_attr = self._prepare_edge_data(edges)

            return CodeGraph(
                nodes=nodes,
                edges=edges,
                node_features=node_features,
                edge_index=edge_index,
                edge_attr=edge_attr
            )

        except SyntaxError as e:
            # Handle malformed code gracefully
            return self._create_empty_graph(f"Syntax Error: {e}")

    def _ast_to_graph(self, tree: ast.AST, code: str) -> Tuple[List[GraphNode], List[Tuple[str, str, str]]]:
        """Convert AST to graph nodes and edges"""
        nodes = []
        edges = []
        node_counter = 0

        def traverse(node, parent_id=None, depth=0):
            nonlocal node_counter

            # Create unique node ID
            node_id = f"node_{node_counter}"
            node_counter += 1

            # Get node type and content
            node_type = type(node).__name__
            content = self._extract_node_content(node, code)

            # Get position information
            position = (getattr(node, 'lineno', 0), getattr(node, 'col_offset', 0))

            # Extract features for this node
            features = self._extract_single_node_features(node, content, depth)

            # Create graph node
            graph_node = GraphNode(
                id=node_id,
                node_type=node_type,
                content=content,
                position=position,
                features=features
            )
            nodes.append(graph_node)

            # Add parent-child edge
            if parent_id:
                edges.append((parent_id, node_id, "child"))

            # Add control flow edges
            if isinstance(node, (ast.If, ast.For, ast.While)):
                # Add control flow edges for conditional nodes
                for i, child in enumerate(ast.iter_child_nodes(node)):
                    child_id = f"node_{node_counter + i}"
                    edges.append((node_id, child_id, "control_flow"))

            # Add data flow edges for assignments and calls
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Track variable assignments for data flow
                        edges.append((node_id, node_id, "data_flow"))

            # Recursively process children
            for child in ast.iter_child_nodes(node):
                traverse(child, node_id, depth + 1)

        traverse(tree)
        return nodes, edges

    def _extract_node_content(self, node: ast.AST, code: str) -> str:
        """Extract meaningful content from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Str):
            return node.s[:100]  # Truncate long strings
        elif isinstance(node, ast.Num):
            return str(node.n)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"call_{node.func.id}"
            elif isinstance(node.func, ast.Attribute):
                return f"call_{node.func.attr}"
        elif isinstance(node, ast.FunctionDef):
            return f"func_{node.name}"
        elif isinstance(node, ast.ClassDef):
            return f"class_{node.name}"

        return type(node).__name__.lower()

    def _extract_single_node_features(self, node: ast.AST, content: str, depth: int) -> Dict[str, Any]:
        """Extract features for a single node"""
        features = {
            'node_type_id': self.node_type_mapping.get(type(node).__name__, len(self.node_type_mapping)),
            'depth': depth,
            'content_length': len(content),
            'is_vulnerable': self._check_vulnerability_patterns(content),
            'is_function': isinstance(node, ast.FunctionDef),
            'is_call': isinstance(node, ast.Call),
            'is_string': isinstance(node, ast.Str),
            'is_control': isinstance(node, (ast.If, ast.For, ast.While)),
            'line_number': getattr(node, 'lineno', 0),
            'complexity_score': self._calculate_complexity(node)
        }
        return features

    def _check_vulnerability_patterns(self, content: str) -> int:
        """Check if content matches vulnerability patterns"""
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return 1
        return 0

    def _calculate_complexity(self, node: ast.AST) -> float:
        """Calculate complexity score for node"""
        complexity = 1.0

        if isinstance(node, (ast.If, ast.For, ast.While)):
            complexity += 2.0
        elif isinstance(node, ast.FunctionDef):
            complexity += len(node.args.args) * 0.5
        elif isinstance(node, ast.Call):
            complexity += len(node.args) * 0.2

        return min(complexity, 10.0)  # Cap at 10

    def _extract_node_features(self, nodes: List[GraphNode], code: str) -> torch.Tensor:
        """Extract feature matrix for all nodes"""
        feature_dim = 20  # Increased feature dimension
        features = torch.zeros(len(nodes), feature_dim)

        for i, node in enumerate(nodes):
            # Basic features
            features[i, 0] = node.features['node_type_id']
            features[i, 1] = node.features['depth']
            features[i, 2] = node.features['content_length']
            features[i, 3] = node.features['is_vulnerable']
            features[i, 4] = node.features['is_function']
            features[i, 5] = node.features['is_call']
            features[i, 6] = node.features['is_string']
            features[i, 7] = node.features['is_control']
            features[i, 8] = node.features['line_number']
            features[i, 9] = node.features['complexity_score']

            # Advanced features
            features[i, 10] = len(node.content)
            features[i, 11] = 1.0 if 'execute' in node.content.lower() else 0.0
            features[i, 12] = 1.0 if 'query' in node.content.lower() else 0.0
            features[i, 13] = 1.0 if '+' in node.content else 0.0
            features[i, 14] = 1.0 if 'SELECT' in node.content.upper() else 0.0
            features[i, 15] = 1.0 if 'INSERT' in node.content.upper() else 0.0
            features[i, 16] = 1.0 if 'DELETE' in node.content.upper() else 0.0
            features[i, 17] = 1.0 if 'UPDATE' in node.content.upper() else 0.0
            features[i, 18] = hash(node.content) % 100 / 100.0  # Content hash feature
            features[i, 19] = min(node.position[0] / 1000.0, 1.0)  # Normalized line position

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

        edge_type_mapping = {'child': 0, 'control_flow': 1, 'data_flow': 2}

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

    def _create_empty_graph(self, error_msg: str) -> CodeGraph:
        """Create empty graph for malformed code"""
        empty_node = GraphNode(
            id="error_node",
            node_type="Error",
            content=error_msg,
            position=(0, 0),
            features={'error': True}
        )

        return CodeGraph(
            nodes=[empty_node],
            edges=[],
            node_features=torch.zeros(1, 20),
            edge_index=torch.empty((2, 0), dtype=torch.long),
            edge_attr=torch.empty((0, 1))
        )

def test_parser():
    """Test the parser with sample code"""
    parser = CodeToGraphParser()

    # Test vulnerable code
    vulnerable_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
'''

    # Test safe code
    safe_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
'''

    for i, code in enumerate([vulnerable_code, safe_code]):
        print(f"\n=== Test {i+1} ===")
        graph = parser.parse_code_to_graph(code)
        print(f"Nodes: {len(graph.nodes)}")
        print(f"Edges: {len(graph.edges)}")
        print(f"Feature matrix shape: {graph.node_features.shape}")
        print(f"Vulnerable patterns found: {sum(1 for node in graph.nodes if node.features.get('is_vulnerable', 0))}")

if __name__ == "__main__":
    test_parser()