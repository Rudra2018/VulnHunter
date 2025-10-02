#!/usr/bin/env python3
"""
VulnGuard AI - Advanced AST Feature Extractor
Abstract Syntax Tree analysis for enhanced vulnerability detection
"""

import ast
import logging
import re
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict, Counter
import tree_sitter
from tree_sitter import Language, Parser
import tree_sitter_python as tspython
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjavascript
import tree_sitter_cpp as tscpp

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedASTFeatureExtractor:
    """Advanced AST-based feature extraction for vulnerability detection"""

    def __init__(self):
        self.python_parser = None
        self.java_parser = None
        self.js_parser = None
        self.cpp_parser = None

        # Initialize Tree-sitter parsers
        self._init_parsers()

        # Vulnerability-specific AST patterns
        self.vulnerability_ast_patterns = {
            'sql_injection': {
                'dangerous_functions': ['execute', 'query', 'cursor.execute', 'db.query'],
                'string_concat_in_query': True,
                'format_string_in_query': True,
                'user_input_in_query': True
            },
            'command_injection': {
                'dangerous_functions': ['system', 'exec', 'shell_exec', 'popen', 'subprocess.call'],
                'string_concat_with_system': True,
                'user_input_in_command': True
            },
            'xss': {
                'dangerous_functions': ['innerHTML', 'document.write', 'eval'],
                'unescaped_user_input': True,
                'html_concatenation': True
            },
            'buffer_overflow': {
                'dangerous_functions': ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf'],
                'array_bounds_check': False,
                'buffer_size_validation': False
            },
            'path_traversal': {
                'dangerous_patterns': ['../', '..\\', '%2e%2e'],
                'file_operations_with_user_input': True,
                'path_validation': False
            }
        }

        # Security-relevant node types
        self.security_node_types = {
            'function_calls': ['call', 'function_call', 'method_invocation'],
            'string_operations': ['binary_operator', 'concatenation', 'format_string'],
            'conditionals': ['if_statement', 'conditional_expression', 'ternary_expression'],
            'loops': ['for_statement', 'while_statement', 'do_while_statement'],
            'assignments': ['assignment', 'variable_declaration', 'augmented_assignment'],
            'imports': ['import_statement', 'import_from_statement', 'include_directive']
        }

        logger.info("🧬 Advanced AST Feature Extractor initialized")

    def _init_parsers(self):
        """Initialize Tree-sitter parsers for different languages"""
        try:
            # Python parser
            PY_LANGUAGE = Language(tspython.language())
            self.python_parser = Parser(PY_LANGUAGE)

            # Java parser
            JAVA_LANGUAGE = Language(tsjava.language())
            self.java_parser = Parser(JAVA_LANGUAGE)

            # JavaScript parser
            JS_LANGUAGE = Language(tsjavascript.language())
            self.js_parser = Parser(JS_LANGUAGE)

            # C++ parser
            CPP_LANGUAGE = Language(tscpp.language())
            self.cpp_parser = Parser(CPP_LANGUAGE)

            logger.info("✅ Tree-sitter parsers initialized for Python, Java, JavaScript, C++")

        except Exception as e:
            logger.warning(f"⚠️  Tree-sitter initialization failed: {e}. Falling back to Python AST only.")

    def detect_language(self, code: str) -> str:
        """Detect programming language from code content"""
        # Simple heuristics for language detection
        if re.search(r'\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import', code):
            return 'python'
        elif re.search(r'\bpublic\s+class\s+\w+|import\s+java\.|System\.out\.println', code):
            return 'java'
        elif re.search(r'\bfunction\s+\w+\s*\(|var\s+\w+\s*=|console\.log|document\.', code):
            return 'javascript'
        elif re.search(r'#include\s*<|int\s+main\s*\(|std::|cout\s*<<', code):
            return 'cpp'
        else:
            return 'python'  # Default fallback

    def extract_ast_features(self, code: str) -> Dict[str, Any]:
        """Extract comprehensive AST-based features"""
        features = {}

        # Detect language
        language = self.detect_language(code)
        features['detected_language'] = language

        try:
            # Extract features based on detected language
            if language == 'python':
                features.update(self._extract_python_ast_features(code))

            # Add Tree-sitter features if available
            features.update(self._extract_tree_sitter_features(code, language))

            # Add generic code structure features
            features.update(self._extract_code_structure_features(code))

            # Add vulnerability-specific patterns
            features.update(self._extract_vulnerability_patterns(code))

            # Add control flow features
            features.update(self._extract_control_flow_features(code))

            # Add data flow approximation features
            features.update(self._extract_data_flow_features(code))

        except Exception as e:
            logger.warning(f"⚠️  AST extraction failed: {e}")
            # Return basic features if AST parsing fails
            features.update(self._extract_fallback_features(code))

        return features

    def _extract_python_ast_features(self, code: str) -> Dict[str, Any]:
        """Extract features using Python's built-in AST module"""
        features = {}

        try:
            tree = ast.parse(code)

            # Node type counts
            node_counts = defaultdict(int)
            function_calls = []
            assignments = []
            imports = []
            string_operations = []

            for node in ast.walk(tree):
                node_type = type(node).__name__
                node_counts[node_type] += 1

                # Function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        function_calls.append(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        function_calls.append(node.func.attr)

                # Assignments
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assignments.append(target.id)

                # Imports
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        imports.append(alias.name)

                # String operations
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    if any(isinstance(operand, ast.Str) for operand in [node.left, node.right]):
                        string_operations.append('string_concatenation')

            # AST structural features
            features.update({
                f'ast_{node_type}_count': count
                for node_type, count in node_counts.items()
            })

            # Function call analysis
            features['unique_function_calls'] = len(set(function_calls))
            features['total_function_calls'] = len(function_calls)
            features['most_common_function'] = Counter(function_calls).most_common(1)[0][0] if function_calls else None

            # Import analysis
            features['import_count'] = len(imports)
            features['unique_imports'] = len(set(imports))

            # Control flow complexity
            features['ast_cyclomatic_complexity'] = self._calculate_ast_complexity(tree)
            features['ast_max_nesting_depth'] = self._calculate_nesting_depth(tree)

            # Security-relevant patterns
            features['has_eval_call'] = 'eval' in function_calls
            features['has_exec_call'] = 'exec' in function_calls
            features['has_system_call'] = any(call in function_calls for call in ['system', 'os.system', 'subprocess.call'])
            features['string_concatenation_count'] = string_operations.count('string_concatenation')

        except SyntaxError:
            logger.warning("⚠️  Python AST parsing failed - syntax error")
            features['ast_parse_error'] = True
        except Exception as e:
            logger.warning(f"⚠️  Python AST analysis failed: {e}")
            features['ast_analysis_error'] = True

        return features

    def _extract_tree_sitter_features(self, code: str, language: str) -> Dict[str, Any]:
        """Extract features using Tree-sitter for better language support"""
        features = {}

        try:
            parser = None
            if language == 'python' and self.python_parser:
                parser = self.python_parser
            elif language == 'java' and self.java_parser:
                parser = self.java_parser
            elif language == 'javascript' and self.js_parser:
                parser = self.js_parser
            elif language == 'cpp' and self.cpp_parser:
                parser = self.cpp_parser

            if not parser:
                return features

            tree = parser.parse(bytes(code, 'utf8'))
            root_node = tree.root_node

            # Node type statistics
            node_types = defaultdict(int)
            self._traverse_tree_sitter_node(root_node, node_types)

            # Tree-sitter specific features
            features.update({
                f'ts_{node_type}_count': count
                for node_type, count in node_types.items()
            })

            features['ts_total_nodes'] = sum(node_types.values())
            features['ts_unique_node_types'] = len(node_types)
            features['ts_tree_depth'] = self._get_tree_depth(root_node)

            # Language-specific security patterns
            if language == 'python':
                features.update(self._extract_python_security_patterns(root_node))
            elif language == 'java':
                features.update(self._extract_java_security_patterns(root_node))
            elif language == 'javascript':
                features.update(self._extract_js_security_patterns(root_node))
            elif language == 'cpp':
                features.update(self._extract_cpp_security_patterns(root_node))

        except Exception as e:
            logger.warning(f"⚠️  Tree-sitter analysis failed: {e}")

        return features

    def _extract_code_structure_features(self, code: str) -> Dict[str, Any]:
        """Extract general code structure features"""
        features = {}

        lines = code.split('\n')

        # Basic structure
        features['total_lines'] = len(lines)
        features['non_empty_lines'] = len([line for line in lines if line.strip()])
        features['comment_lines'] = len([line for line in lines if line.strip().startswith('#') or '//' in line or '/*' in line])
        features['avg_line_length'] = sum(len(line) for line in lines) / len(lines) if lines else 0

        # Indentation analysis
        indentations = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        features['max_indentation'] = max(indentations) if indentations else 0
        features['avg_indentation'] = sum(indentations) / len(indentations) if indentations else 0

        # Brace/bracket analysis
        features['open_braces'] = code.count('{')
        features['close_braces'] = code.count('}')
        features['open_brackets'] = code.count('[')
        features['close_brackets'] = code.count(']')
        features['open_parens'] = code.count('(')
        features['close_parens'] = code.count(')')
        features['brace_balance'] = abs(features['open_braces'] - features['close_braces'])

        # String and comment analysis
        features['string_literals'] = len(re.findall(r'["\'].*?["\']', code))
        features['numeric_literals'] = len(re.findall(r'\b\d+\.?\d*\b', code))

        return features

    def _extract_vulnerability_patterns(self, code: str) -> Dict[str, Any]:
        """Extract vulnerability-specific patterns from code"""
        features = {}

        for vuln_type, patterns in self.vulnerability_ast_patterns.items():
            vuln_score = 0

            # Check for dangerous functions
            if 'dangerous_functions' in patterns:
                for func in patterns['dangerous_functions']:
                    if func in code:
                        vuln_score += 1

            # Check for specific patterns
            if patterns.get('string_concat_in_query', False):
                if re.search(r'(query|execute).*\+.*["\']', code, re.IGNORECASE):
                    vuln_score += 2

            if patterns.get('user_input_in_query', False):
                if re.search(r'(query|execute).*(input|request|params)', code, re.IGNORECASE):
                    vuln_score += 2

            if patterns.get('unescaped_user_input', False):
                if re.search(r'innerHTML.*[+]|document\.write.*[+]', code):
                    vuln_score += 2

            features[f'{vuln_type}_pattern_score'] = vuln_score
            features[f'has_{vuln_type}_indicators'] = vuln_score > 0

        return features

    def _extract_control_flow_features(self, code: str) -> Dict[str, Any]:
        """Extract control flow related features"""
        features = {}

        # Control flow statements
        features['if_statements'] = len(re.findall(r'\bif\b', code))
        features['else_statements'] = len(re.findall(r'\belse\b', code))
        features['for_loops'] = len(re.findall(r'\bfor\b', code))
        features['while_loops'] = len(re.findall(r'\bwhile\b', code))
        features['try_except'] = len(re.findall(r'\btry\b', code))
        features['switch_statements'] = len(re.findall(r'\bswitch\b', code))

        # Exception handling
        features['exception_handling'] = features['try_except'] > 0
        features['total_control_flow'] = (features['if_statements'] + features['for_loops'] +
                                        features['while_loops'] + features['switch_statements'])

        # Estimated cyclomatic complexity
        features['estimated_complexity'] = 1 + features['total_control_flow']

        return features

    def _extract_data_flow_features(self, code: str) -> Dict[str, Any]:
        """Extract data flow approximation features"""
        features = {}

        # Variable assignments
        features['assignments'] = len(re.findall(r'\w+\s*=\s*', code))
        features['function_definitions'] = len(re.findall(r'\bdef\s+\w+|function\s+\w+|\w+\s+\w+\s*\(', code))
        features['return_statements'] = len(re.findall(r'\breturn\b', code))

        # Input/Output operations
        features['input_operations'] = len(re.findall(r'\binput\b|\bread\b|\bscanf\b|\bgets\b', code))
        features['output_operations'] = len(re.findall(r'\bprint\b|\bprintf\b|\bcout\b|\bwrite\b', code))

        # Memory operations
        features['memory_alloc'] = len(re.findall(r'\bmalloc\b|\bcalloc\b|\bnew\b', code))
        features['memory_free'] = len(re.findall(r'\bfree\b|\bdelete\b', code))
        features['memory_balance'] = abs(features['memory_alloc'] - features['memory_free'])

        return features

    def _extract_fallback_features(self, code: str) -> Dict[str, Any]:
        """Extract basic features when AST parsing fails"""
        features = {}

        # Character-level features
        features['char_count'] = len(code)
        features['whitespace_ratio'] = sum(1 for c in code if c.isspace()) / len(code) if code else 0
        features['alpha_ratio'] = sum(1 for c in code if c.isalpha()) / len(code) if code else 0
        features['digit_ratio'] = sum(1 for c in code if c.isdigit()) / len(code) if code else 0
        features['special_char_ratio'] = 1 - features['whitespace_ratio'] - features['alpha_ratio'] - features['digit_ratio']

        # Simple keyword counts
        keywords = ['if', 'else', 'for', 'while', 'function', 'def', 'class', 'import', 'include']
        for keyword in keywords:
            features[f'keyword_{keyword}_count'] = len(re.findall(f'\\b{keyword}\\b', code))

        return features

    def _calculate_ast_complexity(self, tree) -> int:
        """Calculate cyclomatic complexity from AST"""
        complexity = 1  # Base complexity

        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
            elif isinstance(node, (ast.ExceptHandler, ast.TryFinally, ast.TryExcept)):
                complexity += 1

        return complexity

    def _calculate_nesting_depth(self, tree) -> int:
        """Calculate maximum nesting depth of AST"""
        def get_depth(node, current_depth=0):
            max_depth = current_depth
            for child in ast.iter_child_nodes(node):
                child_depth = get_depth(child, current_depth + 1)
                max_depth = max(max_depth, child_depth)
            return max_depth

        return get_depth(tree)

    def _traverse_tree_sitter_node(self, node, node_counts):
        """Traverse Tree-sitter AST and count node types"""
        node_counts[node.type] += 1
        for child in node.children:
            self._traverse_tree_sitter_node(child, node_counts)

    def _get_tree_depth(self, node, current_depth=0):
        """Get maximum depth of Tree-sitter AST"""
        max_depth = current_depth
        for child in node.children:
            child_depth = self._get_tree_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)
        return max_depth

    def _extract_python_security_patterns(self, node) -> Dict[str, Any]:
        """Extract Python-specific security patterns"""
        features = {}

        # This would be implemented with specific Tree-sitter Python patterns
        features['python_eval_usage'] = 0
        features['python_exec_usage'] = 0
        features['python_input_usage'] = 0

        return features

    def _extract_java_security_patterns(self, node) -> Dict[str, Any]:
        """Extract Java-specific security patterns"""
        features = {}

        # Java-specific patterns would go here
        features['java_reflection_usage'] = 0
        features['java_deserialization'] = 0

        return features

    def _extract_js_security_patterns(self, node) -> Dict[str, Any]:
        """Extract JavaScript-specific security patterns"""
        features = {}

        # JavaScript-specific patterns
        features['js_eval_usage'] = 0
        features['js_dom_manipulation'] = 0

        return features

    def _extract_cpp_security_patterns(self, node) -> Dict[str, Any]:
        """Extract C++-specific security patterns"""
        features = {}

        # C++-specific patterns
        features['cpp_buffer_functions'] = 0
        features['cpp_memory_management'] = 0

        return features

    def extract_enhanced_features(self, code: str) -> Dict[str, Any]:
        """Main interface for enhanced feature extraction"""
        logger.info("🧬 Extracting enhanced AST features...")

        features = self.extract_ast_features(code)

        # Add feature metadata
        features['feature_extraction_version'] = '2.0'
        features['total_ast_features'] = len([k for k in features.keys() if k.startswith('ast_')])
        features['total_ts_features'] = len([k for k in features.keys() if k.startswith('ts_')])

        logger.info(f"✅ Extracted {len(features)} enhanced features")

        return features


def main():
    """Test the AST feature extractor"""
    extractor = AdvancedASTFeatureExtractor()

    # Test with sample vulnerable code
    test_code = """
def vulnerable_login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def safe_login(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()
    """

    features = extractor.extract_enhanced_features(test_code)

    print("🧬 Enhanced AST Features:")
    for key, value in sorted(features.items()):
        print(f"   {key}: {value}")

    return features


if __name__ == "__main__":
    main()