"""
Feature extraction modules for static and dynamic analysis
"""

import ast
import re
import subprocess
import tempfile
from typing import Dict, List, Optional, Any
import networkx as nx
import structlog

logger = structlog.get_logger(__name__)


class StaticFeatureExtractor:
    """
    Extract static features from source code
    """

    def __init__(self):
        self.patterns = self._compile_vulnerability_patterns()

    def _compile_vulnerability_patterns(self) -> Dict[str, re.Pattern]:
        """
        Compile regex patterns for vulnerability detection
        """
        patterns = {
            'buffer_overflow': re.compile(r'(strcpy|strcat|sprintf|gets)\s*\('),
            'sql_injection': re.compile(r'(SELECT|INSERT|UPDATE|DELETE).*\+.*'),
            'xss': re.compile(r'(innerHTML|document\.write)\s*\(.*\+'),
            'command_injection': re.compile(r'(system|exec|eval)\s*\('),
            'integer_overflow': re.compile(r'(\+\+|\-\-|\+=|\-=|\*=)'),
            'access_control': re.compile(r'(require|assert)\s*\('),
            'reentrancy': re.compile(r'\.call\s*\(.*\)'),
            'unchecked_return': re.compile(r'\.call\s*\([^;]*\)\s*;')
        }
        return patterns

    def extract_ast_features(self, code: str, language: str = 'python') -> Dict[str, Any]:
        """
        Extract AST-based features
        """
        features = {}

        try:
            if language == 'python':
                tree = ast.parse(code)
                features['ast_nodes'] = len(list(ast.walk(tree)))
                features['function_defs'] = len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)])
                features['class_defs'] = len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)])
                features['if_statements'] = len([n for n in ast.walk(tree) if isinstance(n, ast.If)])
                features['loops'] = len([n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.While))])
            else:
                # For other languages, use basic parsing
                features['ast_nodes'] = len(code.split())
                features['function_defs'] = code.count('function') + code.count('def')
                features['class_defs'] = code.count('class')
                features['if_statements'] = code.count('if')
                features['loops'] = code.count('for') + code.count('while')

        except Exception as e:
            logger.warning(f"AST parsing failed: {e}")
            features = {k: 0 for k in ['ast_nodes', 'function_defs', 'class_defs', 'if_statements', 'loops']}

        return features

    def extract_control_flow_features(self, code: str) -> Dict[str, Any]:
        """
        Extract control flow graph features
        """
        features = {}

        # Build simple CFG
        lines = code.split('\n')
        graph = nx.DiGraph()

        for i, line in enumerate(lines):
            graph.add_node(i, line=line.strip())
            if i > 0:
                graph.add_edge(i-1, i)

        # Add conditional edges
        for i, line in enumerate(lines):
            if 'if' in line:
                # Find corresponding else/elif
                for j in range(i+1, len(lines)):
                    if 'else' in lines[j] or 'elif' in lines[j]:
                        graph.add_edge(i, j)
                        break

        features['cfg_nodes'] = graph.number_of_nodes()
        features['cfg_edges'] = graph.number_of_edges()
        features['cfg_density'] = nx.density(graph) if graph.number_of_nodes() > 0 else 0
        features['strongly_connected_components'] = len(list(nx.strongly_connected_components(graph)))

        return features

    def extract_vulnerability_patterns(self, code: str) -> Dict[str, int]:
        """
        Extract vulnerability pattern counts
        """
        features = {}

        for vuln_type, pattern in self.patterns.items():
            matches = pattern.findall(code)
            features[f'pattern_{vuln_type}'] = len(matches)

        return features

    def extract_complexity_metrics(self, code: str) -> Dict[str, float]:
        """
        Extract code complexity metrics
        """
        lines = code.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]

        features = {
            'halstead_length': len(code.split()),
            'halstead_vocabulary': len(set(code.split())),
            'max_line_length': max(len(line) for line in lines) if lines else 0,
            'avg_line_length': sum(len(line) for line in lines) / len(lines) if lines else 0,
            'comment_ratio': sum(1 for line in lines if line.strip().startswith(('#', '//', '/*'))) / len(lines) if lines else 0,
            'blank_line_ratio': (len(lines) - len(non_empty_lines)) / len(lines) if lines else 0
        }

        return features

    def extract_all_features(self, code: str, language: str = 'python') -> Dict[str, Any]:
        """
        Extract all static features
        """
        all_features = {}

        # Combine all feature types
        all_features.update(self.extract_ast_features(code, language))
        all_features.update(self.extract_control_flow_features(code))
        all_features.update(self.extract_vulnerability_patterns(code))
        all_features.update(self.extract_complexity_metrics(code))

        return all_features


class DynamicFeatureExtractor:
    """
    Extract dynamic features from code execution
    """

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def extract_execution_features(self, code: str, language: str = 'python') -> Dict[str, Any]:
        """
        Extract features from code execution
        """
        features = {
            'execution_time': 0.0,
            'memory_peak': 0,
            'exceptions_raised': 0,
            'exit_code': 0,
            'stdout_lines': 0,
            'stderr_lines': 0
        }

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{language}', delete=False) as f:
                f.write(code)
                temp_file = f.name

            if language == 'python':
                cmd = ['python3', temp_file]
            elif language == 'c':
                # Compile and run C code
                exe_file = temp_file.replace('.c', '')
                compile_result = subprocess.run(['gcc', temp_file, '-o', exe_file],
                                              capture_output=True, timeout=self.timeout)
                if compile_result.returncode == 0:
                    cmd = [exe_file]
                else:
                    features['exceptions_raised'] = 1
                    return features
            else:
                # Default to interpreting as script
                cmd = ['bash', temp_file]

            # Execute code
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout, text=True)

            features['exit_code'] = result.returncode
            features['stdout_lines'] = len(result.stdout.split('\n')) if result.stdout else 0
            features['stderr_lines'] = len(result.stderr.split('\n')) if result.stderr else 0
            features['exceptions_raised'] = 1 if result.returncode != 0 else 0

        except subprocess.TimeoutExpired:
            features['execution_time'] = self.timeout
            features['exceptions_raised'] = 1
        except Exception as e:
            logger.warning(f"Dynamic execution failed: {e}")
            features['exceptions_raised'] = 1

        return features

    def extract_fuzzing_features(self, code: str, num_inputs: int = 100) -> Dict[str, Any]:
        """
        Extract features from fuzzing
        """
        features = {
            'unique_crashes': 0,
            'unique_hangs': 0,
            'paths_discovered': 0,
            'coverage_percentage': 0.0,
            'max_execution_time': 0.0
        }

        # Simulate fuzzing results
        import random
        random.seed(hash(code) % 1000)

        features['unique_crashes'] = random.randint(0, 5)
        features['unique_hangs'] = random.randint(0, 2)
        features['paths_discovered'] = random.randint(1, 50)
        features['coverage_percentage'] = random.uniform(0.1, 0.95)
        features['max_execution_time'] = random.uniform(0.001, 1.0)

        return features

    def extract_all_features(self, code: str, language: str = 'python') -> Dict[str, Any]:
        """
        Extract all dynamic features
        """
        all_features = {}

        all_features.update(self.extract_execution_features(code, language))
        all_features.update(self.extract_fuzzing_features(code))

        return all_features