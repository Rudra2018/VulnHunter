"""
Advanced Static Analysis Engine

This module provides comprehensive static analysis capabilities:
- Multi-language AST and CFG generation
- Control flow and data flow analysis
- Call graph construction and analysis
- Symbol table and scope analysis
- Integration with multiple analysis backends
"""

import ast
import os
import subprocess
import json
import logging
import hashlib
import tempfile
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import networkx as nx
import pickle

try:
    import tree_sitter
    import tree_sitter_python
    import tree_sitter_c
    import tree_sitter_cpp
    import tree_sitter_javascript
    import tree_sitter_java
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    logging.warning("Tree-sitter not available. Install with: pip install tree-sitter tree-sitter-languages")

try:
    import clang.cindex as clang
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False
    logging.warning("Clang Python bindings not available")

class Language(Enum):
    """Supported programming languages"""
    PYTHON = "python"
    C = "c"
    CPP = "cpp"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    UNKNOWN = "unknown"

class NodeType(Enum):
    """AST node types"""
    FUNCTION = "function"
    CLASS = "class"
    VARIABLE = "variable"
    CALL = "call"
    ASSIGNMENT = "assignment"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    RETURN = "return"
    IMPORT = "import"
    UNKNOWN = "unknown"

@dataclass
class SourceLocation:
    """Source code location"""
    file_path: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None

@dataclass
class ASTNode:
    """Abstract syntax tree node"""
    node_id: str
    node_type: NodeType
    name: str
    location: SourceLocation
    children: List['ASTNode'] = field(default_factory=list)
    parent: Optional['ASTNode'] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    raw_node: Any = None

@dataclass
class CFGNode:
    """Control flow graph node"""
    node_id: str
    ast_node: Optional[ASTNode]
    predecessors: Set[str] = field(default_factory=set)
    successors: Set[str] = field(default_factory=set)
    dominators: Set[str] = field(default_factory=set)
    post_dominators: Set[str] = field(default_factory=set)
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Function:
    """Function representation"""
    name: str
    parameters: List[str]
    return_type: Optional[str]
    location: SourceLocation
    ast_node: ASTNode
    cfg: Optional[nx.DiGraph] = None
    local_variables: List[str] = field(default_factory=list)
    called_functions: Set[str] = field(default_factory=set)
    complexity: int = 0
    lines_of_code: int = 0

@dataclass
class Class:
    """Class representation"""
    name: str
    methods: List[Function]
    attributes: List[str]
    parent_classes: List[str]
    location: SourceLocation
    ast_node: ASTNode

@dataclass
class Variable:
    """Variable representation"""
    name: str
    var_type: Optional[str]
    scope: str
    location: SourceLocation
    assignments: List[SourceLocation] = field(default_factory=list)
    uses: List[SourceLocation] = field(default_factory=list)

@dataclass
class CallSite:
    """Function call site"""
    caller: str
    callee: str
    location: SourceLocation
    arguments: List[str] = field(default_factory=list)
    call_type: str = "direct"  # direct, indirect, virtual

@dataclass
class AnalysisResult:
    """Static analysis result"""
    file_path: str
    language: Language
    ast: ASTNode
    functions: List[Function]
    classes: List[Class]
    variables: List[Variable]
    call_graph: nx.DiGraph
    imports: List[str]
    complexity_metrics: Dict[str, float]
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

class LanguageDetector:
    """Detects programming language from file extension and content"""

    def __init__(self):
        self.extension_mapping = {
            '.py': Language.PYTHON,
            '.c': Language.C,
            '.h': Language.C,
            '.cpp': Language.CPP,
            '.cxx': Language.CPP,
            '.cc': Language.CPP,
            '.hpp': Language.CPP,
            '.js': Language.JAVASCRIPT,
            '.ts': Language.JAVASCRIPT,
            '.java': Language.JAVA,
            '.go': Language.GO,
            '.rs': Language.RUST,
        }

        self.content_patterns = {
            Language.PYTHON: [b'def ', b'import ', b'class ', b'if __name__'],
            Language.C: [b'#include', b'int main', b'void ', b'char '],
            Language.CPP: [b'#include', b'class ', b'namespace ', b'std::'],
            Language.JAVASCRIPT: [b'function ', b'var ', b'let ', b'const '],
            Language.JAVA: [b'public class', b'import java', b'public static void main'],
        }

    def detect_language(self, file_path: str) -> Language:
        """Detect programming language"""
        path = Path(file_path)

        # Check file extension
        extension = path.suffix.lower()
        if extension in self.extension_mapping:
            return self.extension_mapping[extension]

        # Check file content
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB

            for language, patterns in self.content_patterns.items():
                if any(pattern in content for pattern in patterns):
                    return language

        except Exception as e:
            logging.error(f"Failed to read file for language detection: {e}")

        return Language.UNKNOWN

class TreeSitterParser:
    """Tree-sitter based parser for multiple languages"""

    def __init__(self):
        self.parsers = {}
        self.languages = {}

        if TREE_SITTER_AVAILABLE:
            self._initialize_parsers()

    def _initialize_parsers(self):
        """Initialize Tree-sitter parsers"""
        try:
            # Python
            self.languages[Language.PYTHON] = tree_sitter.Language(tree_sitter_python.language(), "python")
            parser = tree_sitter.Parser()
            parser.set_language(self.languages[Language.PYTHON])
            self.parsers[Language.PYTHON] = parser

            # C
            self.languages[Language.C] = tree_sitter.Language(tree_sitter_c.language(), "c")
            parser = tree_sitter.Parser()
            parser.set_language(self.languages[Language.C])
            self.parsers[Language.C] = parser

            # C++
            self.languages[Language.CPP] = tree_sitter.Language(tree_sitter_cpp.language(), "cpp")
            parser = tree_sitter.Parser()
            parser.set_language(self.languages[Language.CPP])
            self.parsers[Language.CPP] = parser

            # JavaScript
            self.languages[Language.JAVASCRIPT] = tree_sitter.Language(tree_sitter_javascript.language(), "javascript")
            parser = tree_sitter.Parser()
            parser.set_language(self.languages[Language.JAVASCRIPT])
            self.parsers[Language.JAVASCRIPT] = parser

            # Java
            self.languages[Language.JAVA] = tree_sitter.Language(tree_sitter_java.language(), "java")
            parser = tree_sitter.Parser()
            parser.set_language(self.languages[Language.JAVA])
            self.parsers[Language.JAVA] = parser

        except Exception as e:
            logging.error(f"Failed to initialize Tree-sitter parsers: {e}")

    def parse_file(self, file_path: str, language: Language) -> Optional[ASTNode]:
        """Parse file using Tree-sitter"""
        if not TREE_SITTER_AVAILABLE or language not in self.parsers:
            return None

        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()

            parser = self.parsers[language]
            tree = parser.parse(source_code)

            return self._convert_tree_sitter_node(tree.root_node, file_path, source_code)

        except Exception as e:
            logging.error(f"Tree-sitter parsing failed: {e}")
            return None

    def _convert_tree_sitter_node(self, ts_node, file_path: str, source_code: bytes, parent: Optional[ASTNode] = None) -> ASTNode:
        """Convert Tree-sitter node to ASTNode"""
        node_id = f"{file_path}:{ts_node.start_point[0]}:{ts_node.start_point[1]}"

        location = SourceLocation(
            file_path=file_path,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            end_line=ts_node.end_point[0] + 1,
            end_column=ts_node.end_point[1]
        )

        node_type = self._map_tree_sitter_type(ts_node.type)

        # Extract node name/text
        node_text = source_code[ts_node.start_byte:ts_node.end_byte].decode('utf-8', errors='ignore')
        name = node_text[:100] if len(node_text) <= 100 else node_text[:100] + "..."

        ast_node = ASTNode(
            node_id=node_id,
            node_type=node_type,
            name=name,
            location=location,
            parent=parent,
            attributes={'tree_sitter_type': ts_node.type},
            raw_node=ts_node
        )

        # Convert children
        for child in ts_node.children:
            child_node = self._convert_tree_sitter_node(child, file_path, source_code, ast_node)
            ast_node.children.append(child_node)

        return ast_node

    def _map_tree_sitter_type(self, ts_type: str) -> NodeType:
        """Map Tree-sitter node type to our NodeType enum"""
        type_mapping = {
            'function_definition': NodeType.FUNCTION,
            'function_declarator': NodeType.FUNCTION,
            'method_definition': NodeType.FUNCTION,
            'class_definition': NodeType.CLASS,
            'class_declaration': NodeType.CLASS,
            'variable_declarator': NodeType.VARIABLE,
            'assignment_expression': NodeType.ASSIGNMENT,
            'call_expression': NodeType.CALL,
            'if_statement': NodeType.CONDITIONAL,
            'while_statement': NodeType.LOOP,
            'for_statement': NodeType.LOOP,
            'return_statement': NodeType.RETURN,
            'import_statement': NodeType.IMPORT,
            'import_declaration': NodeType.IMPORT,
        }

        return type_mapping.get(ts_type, NodeType.UNKNOWN)

class PythonASTParser:
    """Python-specific AST parser using built-in ast module"""

    def parse_file(self, file_path: str) -> Optional[ASTNode]:
        """Parse Python file using ast module"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            tree = ast.parse(source_code, filename=file_path)
            return self._convert_python_ast(tree, file_path)

        except Exception as e:
            logging.error(f"Python AST parsing failed: {e}")
            return None

    def _convert_python_ast(self, py_node, file_path: str, parent: Optional[ASTNode] = None) -> ASTNode:
        """Convert Python AST node to ASTNode"""
        node_id = f"{file_path}:{getattr(py_node, 'lineno', 0)}:{getattr(py_node, 'col_offset', 0)}"

        location = SourceLocation(
            file_path=file_path,
            line=getattr(py_node, 'lineno', 0),
            column=getattr(py_node, 'col_offset', 0),
            end_line=getattr(py_node, 'end_lineno', None),
            end_column=getattr(py_node, 'end_col_offset', None)
        )

        node_type = self._map_python_type(type(py_node).__name__)
        name = self._extract_python_name(py_node)

        ast_node = ASTNode(
            node_id=node_id,
            node_type=node_type,
            name=name,
            location=location,
            parent=parent,
            attributes={'python_type': type(py_node).__name__},
            raw_node=py_node
        )

        # Convert children
        for field, value in ast.iter_fields(py_node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        child_node = self._convert_python_ast(item, file_path, ast_node)
                        ast_node.children.append(child_node)
            elif isinstance(value, ast.AST):
                child_node = self._convert_python_ast(value, file_path, ast_node)
                ast_node.children.append(child_node)

        return ast_node

    def _map_python_type(self, py_type: str) -> NodeType:
        """Map Python AST type to NodeType"""
        type_mapping = {
            'FunctionDef': NodeType.FUNCTION,
            'AsyncFunctionDef': NodeType.FUNCTION,
            'ClassDef': NodeType.CLASS,
            'Assign': NodeType.ASSIGNMENT,
            'AugAssign': NodeType.ASSIGNMENT,
            'AnnAssign': NodeType.ASSIGNMENT,
            'Call': NodeType.CALL,
            'If': NodeType.CONDITIONAL,
            'While': NodeType.LOOP,
            'For': NodeType.LOOP,
            'AsyncFor': NodeType.LOOP,
            'Return': NodeType.RETURN,
            'Import': NodeType.IMPORT,
            'ImportFrom': NodeType.IMPORT,
            'Name': NodeType.VARIABLE,
        }

        return type_mapping.get(py_type, NodeType.UNKNOWN)

    def _extract_python_name(self, py_node) -> str:
        """Extract name from Python AST node"""
        if hasattr(py_node, 'name'):
            return py_node.name
        elif hasattr(py_node, 'id'):
            return py_node.id
        elif isinstance(py_node, ast.Call) and hasattr(py_node.func, 'id'):
            return py_node.func.id
        else:
            return type(py_node).__name__

class CFGBuilder:
    """Builds control flow graphs from AST"""

    def __init__(self):
        self.cfg_cache = {}

    def build_cfg(self, ast_node: ASTNode) -> nx.DiGraph:
        """Build control flow graph from AST"""
        cfg = nx.DiGraph()

        if ast_node.node_type == NodeType.FUNCTION:
            self._build_function_cfg(ast_node, cfg)
        else:
            # Build CFG for entire file/module
            self._build_module_cfg(ast_node, cfg)

        return cfg

    def _build_function_cfg(self, func_node: ASTNode, cfg: nx.DiGraph):
        """Build CFG for a single function"""
        entry_node = CFGNode(
            node_id=f"{func_node.node_id}_entry",
            ast_node=func_node
        )
        cfg.add_node(entry_node.node_id, data=entry_node)

        exit_node = CFGNode(
            node_id=f"{func_node.node_id}_exit",
            ast_node=None
        )
        cfg.add_node(exit_node.node_id, data=exit_node)

        current_nodes = {entry_node.node_id}

        for child in func_node.children:
            current_nodes = self._process_ast_node(child, cfg, current_nodes, exit_node.node_id)

        # Connect remaining nodes to exit
        for node_id in current_nodes:
            cfg.add_edge(node_id, exit_node.node_id)

    def _build_module_cfg(self, module_node: ASTNode, cfg: nx.DiGraph):
        """Build CFG for entire module"""
        # For modules, build separate CFGs for each function
        for child in module_node.children:
            if child.node_type == NodeType.FUNCTION:
                self._build_function_cfg(child, cfg)

    def _process_ast_node(self, node: ASTNode, cfg: nx.DiGraph,
                         current_nodes: Set[str], exit_node_id: str) -> Set[str]:
        """Process AST node and update CFG"""
        cfg_node = CFGNode(
            node_id=node.node_id,
            ast_node=node
        )
        cfg.add_node(cfg_node.node_id, data=cfg_node)

        # Connect from current nodes
        for current_id in current_nodes:
            cfg.add_edge(current_id, cfg_node.node_id)

        new_current_nodes = {cfg_node.node_id}

        if node.node_type == NodeType.CONDITIONAL:
            # Handle if statements
            new_current_nodes = self._handle_conditional(node, cfg, {cfg_node.node_id}, exit_node_id)

        elif node.node_type == NodeType.LOOP:
            # Handle loops
            new_current_nodes = self._handle_loop(node, cfg, {cfg_node.node_id}, exit_node_id)

        elif node.node_type == NodeType.RETURN:
            # Return statements connect to exit
            cfg.add_edge(cfg_node.node_id, exit_node_id)
            new_current_nodes = set()

        else:
            # Process children sequentially
            for child in node.children:
                new_current_nodes = self._process_ast_node(child, cfg, new_current_nodes, exit_node_id)

        return new_current_nodes

    def _handle_conditional(self, node: ASTNode, cfg: nx.DiGraph,
                           current_nodes: Set[str], exit_node_id: str) -> Set[str]:
        """Handle conditional statements"""
        # Simplified: assume first child is condition, rest are body
        if len(node.children) < 2:
            return current_nodes

        condition_nodes = current_nodes
        body_nodes = condition_nodes

        # Process body
        for child in node.children[1:]:
            body_nodes = self._process_ast_node(child, cfg, body_nodes, exit_node_id)

        # Both paths (condition true/false) merge
        return body_nodes.union(condition_nodes)

    def _handle_loop(self, node: ASTNode, cfg: nx.DiGraph,
                    current_nodes: Set[str], exit_node_id: str) -> Set[str]:
        """Handle loop statements"""
        loop_header = current_nodes
        body_nodes = loop_header

        # Process loop body
        for child in node.children[1:]:
            body_nodes = self._process_ast_node(child, cfg, body_nodes, exit_node_id)

        # Body connects back to header
        for body_id in body_nodes:
            for header_id in loop_header:
                cfg.add_edge(body_id, header_id)

        # Loop can exit
        return loop_header

class CallGraphBuilder:
    """Builds call graphs from AST"""

    def build_call_graph(self, functions: List[Function]) -> nx.DiGraph:
        """Build call graph from functions"""
        call_graph = nx.DiGraph()

        # Add function nodes
        for func in functions:
            call_graph.add_node(func.name, data=func)

        # Add call edges
        for func in functions:
            for called_func in func.called_functions:
                if call_graph.has_node(called_func):
                    call_graph.add_edge(func.name, called_func)

        return call_graph

    def extract_function_calls(self, ast_node: ASTNode) -> Set[str]:
        """Extract function calls from AST node"""
        calls = set()

        if ast_node.node_type == NodeType.CALL:
            calls.add(ast_node.name)

        for child in ast_node.children:
            calls.update(self.extract_function_calls(child))

        return calls

class ComplexityAnalyzer:
    """Analyzes code complexity metrics"""

    def calculate_cyclomatic_complexity(self, cfg: nx.DiGraph) -> int:
        """Calculate cyclomatic complexity"""
        if cfg.number_of_nodes() == 0:
            return 1

        # Cyclomatic complexity = E - N + 2P
        # E = edges, N = nodes, P = connected components
        edges = cfg.number_of_edges()
        nodes = cfg.number_of_nodes()
        components = nx.number_weakly_connected_components(cfg)

        return max(1, edges - nodes + 2 * components)

    def calculate_halstead_metrics(self, ast_node: ASTNode) -> Dict[str, float]:
        """Calculate Halstead complexity metrics"""
        operators = set()
        operands = set()
        operator_count = 0
        operand_count = 0

        self._collect_halstead_elements(ast_node, operators, operands, operator_count, operand_count)

        n1 = len(operators)  # Number of distinct operators
        n2 = len(operands)   # Number of distinct operands
        N1 = operator_count  # Total operators
        N2 = operand_count   # Total operands

        if n1 == 0 or n2 == 0:
            return {'length': 0, 'vocabulary': 0, 'volume': 0, 'difficulty': 0, 'effort': 0}

        length = N1 + N2
        vocabulary = n1 + n2
        volume = length * (vocabulary.bit_length() if vocabulary > 0 else 0)
        difficulty = (n1 / 2) * (N2 / n2) if n2 > 0 else 0
        effort = difficulty * volume

        return {
            'length': length,
            'vocabulary': vocabulary,
            'volume': volume,
            'difficulty': difficulty,
            'effort': effort
        }

    def _collect_halstead_elements(self, node: ASTNode, operators: set, operands: set,
                                  op_count: int, operand_count: int):
        """Collect operators and operands for Halstead metrics"""
        if node.node_type in [NodeType.ASSIGNMENT, NodeType.CALL, NodeType.CONDITIONAL]:
            operators.add(node.node_type.value)
            op_count += 1
        elif node.node_type == NodeType.VARIABLE:
            operands.add(node.name)
            operand_count += 1

        for child in node.children:
            self._collect_halstead_elements(child, operators, operands, op_count, operand_count)

class StaticAnalyzer:
    """Main static analysis engine"""

    def __init__(self, cache_dir: str = "/tmp/static_analysis_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        self.language_detector = LanguageDetector()
        self.tree_sitter_parser = TreeSitterParser()
        self.python_parser = PythonASTParser()
        self.cfg_builder = CFGBuilder()
        self.call_graph_builder = CallGraphBuilder()
        self.complexity_analyzer = ComplexityAnalyzer()

        self.analysis_cache = {}

    def analyze_file(self, file_path: str, force_language: Optional[Language] = None) -> Optional[AnalysisResult]:
        """Analyze single source file"""
        file_path = str(Path(file_path).resolve())

        # Check cache
        cache_key = self._get_cache_key(file_path)
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        try:
            # Detect language
            language = force_language or self.language_detector.detect_language(file_path)

            if language == Language.UNKNOWN:
                logging.warning(f"Unknown language for file {file_path}")
                return None

            # Parse AST
            ast_root = self._parse_file(file_path, language)
            if ast_root is None:
                return None

            # Extract components
            functions = self._extract_functions(ast_root)
            classes = self._extract_classes(ast_root)
            variables = self._extract_variables(ast_root)
            imports = self._extract_imports(ast_root)

            # Build call graph
            call_graph = self.call_graph_builder.build_call_graph(functions)

            # Calculate complexity metrics
            complexity_metrics = self._calculate_file_complexity(ast_root, functions)

            result = AnalysisResult(
                file_path=file_path,
                language=language,
                ast=ast_root,
                functions=functions,
                classes=classes,
                variables=variables,
                call_graph=call_graph,
                imports=imports,
                complexity_metrics=complexity_metrics,
                analysis_metadata={
                    'analysis_time': __import__('time').time(),
                    'parser_used': 'tree_sitter' if TREE_SITTER_AVAILABLE else 'python_ast',
                    'file_size': os.path.getsize(file_path),
                    'lines_of_code': self._count_lines_of_code(file_path)
                }
            )

            self.analysis_cache[cache_key] = result
            return result

        except Exception as e:
            logging.error(f"Static analysis failed for {file_path}: {e}")
            return None

    def analyze_project(self, project_path: str, file_patterns: List[str] = None) -> Dict[str, AnalysisResult]:
        """Analyze entire project"""
        project_path = Path(project_path)

        if not project_path.exists():
            logging.error(f"Project path does not exist: {project_path}")
            return {}

        # Default file patterns
        if file_patterns is None:
            file_patterns = ['*.py', '*.c', '*.cpp', '*.h', '*.hpp', '*.js', '*.java']

        # Find source files
        source_files = []
        for pattern in file_patterns:
            source_files.extend(project_path.rglob(pattern))

        # Analyze each file
        results = {}
        for file_path in source_files:
            try:
                result = self.analyze_file(str(file_path))
                if result:
                    results[str(file_path)] = result
            except Exception as e:
                logging.error(f"Failed to analyze {file_path}: {e}")

        logging.info(f"Analyzed {len(results)} files in project {project_path}")
        return results

    def _parse_file(self, file_path: str, language: Language) -> Optional[ASTNode]:
        """Parse file using appropriate parser"""
        if language == Language.PYTHON and hasattr(self, 'python_parser'):
            return self.python_parser.parse_file(file_path)
        elif TREE_SITTER_AVAILABLE:
            return self.tree_sitter_parser.parse_file(file_path, language)
        else:
            logging.error(f"No parser available for language {language}")
            return None

    def _extract_functions(self, ast_root: ASTNode) -> List[Function]:
        """Extract function definitions from AST"""
        functions = []

        def visit_node(node: ASTNode):
            if node.node_type == NodeType.FUNCTION:
                func = Function(
                    name=node.name,
                    parameters=self._extract_function_parameters(node),
                    return_type=self._extract_return_type(node),
                    location=node.location,
                    ast_node=node,
                    local_variables=self._extract_local_variables(node),
                    called_functions=self.call_graph_builder.extract_function_calls(node),
                    lines_of_code=self._count_node_lines(node)
                )

                # Build CFG for function
                func.cfg = self.cfg_builder.build_cfg(node)
                func.complexity = self.complexity_analyzer.calculate_cyclomatic_complexity(func.cfg)

                functions.append(func)

            for child in node.children:
                visit_node(child)

        visit_node(ast_root)
        return functions

    def _extract_classes(self, ast_root: ASTNode) -> List[Class]:
        """Extract class definitions from AST"""
        classes = []

        def visit_node(node: ASTNode):
            if node.node_type == NodeType.CLASS:
                methods = []
                attributes = []

                # Extract methods and attributes
                for child in node.children:
                    if child.node_type == NodeType.FUNCTION:
                        func = Function(
                            name=child.name,
                            parameters=self._extract_function_parameters(child),
                            return_type=self._extract_return_type(child),
                            location=child.location,
                            ast_node=child,
                            called_functions=self.call_graph_builder.extract_function_calls(child)
                        )
                        methods.append(func)
                    elif child.node_type == NodeType.VARIABLE:
                        attributes.append(child.name)

                cls = Class(
                    name=node.name,
                    methods=methods,
                    attributes=attributes,
                    parent_classes=self._extract_parent_classes(node),
                    location=node.location,
                    ast_node=node
                )
                classes.append(cls)

            for child in node.children:
                visit_node(child)

        visit_node(ast_root)
        return classes

    def _extract_variables(self, ast_root: ASTNode) -> List[Variable]:
        """Extract variable definitions and uses"""
        variables = {}

        def visit_node(node: ASTNode, scope: str = "global"):
            if node.node_type == NodeType.VARIABLE:
                var_name = node.name
                if var_name not in variables:
                    variables[var_name] = Variable(
                        name=var_name,
                        var_type=None,
                        scope=scope,
                        location=node.location
                    )
                variables[var_name].uses.append(node.location)

            elif node.node_type == NodeType.ASSIGNMENT:
                # Extract assignment targets
                for child in node.children:
                    if child.node_type == NodeType.VARIABLE:
                        var_name = child.name
                        if var_name not in variables:
                            variables[var_name] = Variable(
                                name=var_name,
                                var_type=None,
                                scope=scope,
                                location=child.location
                            )
                        variables[var_name].assignments.append(child.location)

            # Update scope for functions and classes
            new_scope = scope
            if node.node_type in [NodeType.FUNCTION, NodeType.CLASS]:
                new_scope = f"{scope}.{node.name}"

            for child in node.children:
                visit_node(child, new_scope)

        visit_node(ast_root)
        return list(variables.values())

    def _extract_imports(self, ast_root: ASTNode) -> List[str]:
        """Extract import statements"""
        imports = []

        def visit_node(node: ASTNode):
            if node.node_type == NodeType.IMPORT:
                imports.append(node.name)

            for child in node.children:
                visit_node(child)

        visit_node(ast_root)
        return imports

    def _extract_function_parameters(self, func_node: ASTNode) -> List[str]:
        """Extract function parameters"""
        # Simplified implementation
        parameters = []

        # Look for parameter patterns in raw node
        if hasattr(func_node, 'raw_node'):
            raw_node = func_node.raw_node

            # Python AST
            if hasattr(raw_node, 'args') and hasattr(raw_node.args, 'args'):
                for arg in raw_node.args.args:
                    if hasattr(arg, 'arg'):
                        parameters.append(arg.arg)
                    elif hasattr(arg, 'id'):
                        parameters.append(arg.id)

        return parameters

    def _extract_return_type(self, func_node: ASTNode) -> Optional[str]:
        """Extract function return type"""
        # Simplified implementation
        if hasattr(func_node, 'raw_node'):
            raw_node = func_node.raw_node

            # Python AST with type hints
            if hasattr(raw_node, 'returns') and raw_node.returns:
                if hasattr(raw_node.returns, 'id'):
                    return raw_node.returns.id

        return None

    def _extract_local_variables(self, func_node: ASTNode) -> List[str]:
        """Extract local variables from function"""
        variables = set()

        def visit_node(node: ASTNode):
            if node.node_type == NodeType.VARIABLE:
                variables.add(node.name)
            for child in node.children:
                visit_node(child)

        visit_node(func_node)
        return list(variables)

    def _extract_parent_classes(self, class_node: ASTNode) -> List[str]:
        """Extract parent classes"""
        # Simplified implementation
        if hasattr(class_node, 'raw_node'):
            raw_node = class_node.raw_node

            # Python AST
            if hasattr(raw_node, 'bases'):
                parents = []
                for base in raw_node.bases:
                    if hasattr(base, 'id'):
                        parents.append(base.id)
                return parents

        return []

    def _calculate_file_complexity(self, ast_root: ASTNode, functions: List[Function]) -> Dict[str, float]:
        """Calculate complexity metrics for entire file"""
        metrics = {}

        # Cyclomatic complexity
        total_complexity = sum(func.complexity for func in functions)
        metrics['total_cyclomatic_complexity'] = total_complexity
        metrics['average_cyclomatic_complexity'] = total_complexity / max(len(functions), 1)

        # Halstead metrics
        halstead = self.complexity_analyzer.calculate_halstead_metrics(ast_root)
        metrics.update(halstead)

        # Lines of code
        metrics['total_lines_of_code'] = sum(func.lines_of_code for func in functions)
        metrics['number_of_functions'] = len(functions)

        return metrics

    def _count_lines_of_code(self, file_path: str) -> int:
        """Count lines of code in file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return len([line for line in f if line.strip() and not line.strip().startswith('#')])
        except Exception:
            return 0

    def _count_node_lines(self, node: ASTNode) -> int:
        """Count lines of code in AST node"""
        if node.location.end_line and node.location.line:
            return node.location.end_line - node.location.line + 1
        return 1

    def _get_cache_key(self, file_path: str) -> str:
        """Generate cache key for file"""
        try:
            stat = os.stat(file_path)
            return hashlib.md5(f"{file_path}:{stat.st_mtime}:{stat.st_size}".encode()).hexdigest()
        except Exception:
            return hashlib.md5(file_path.encode()).hexdigest()

    def save_analysis_cache(self):
        """Save analysis cache to disk"""
        try:
            cache_file = self.cache_dir / "analysis_cache.pkl"
            with open(cache_file, 'wb') as f:
                pickle.dump(self.analysis_cache, f)
        except Exception as e:
            logging.error(f"Failed to save analysis cache: {e}")

    def load_analysis_cache(self):
        """Load analysis cache from disk"""
        try:
            cache_file = self.cache_dir / "analysis_cache.pkl"
            if cache_file.exists():
                with open(cache_file, 'rb') as f:
                    self.analysis_cache = pickle.load(f)
        except Exception as e:
            logging.error(f"Failed to load analysis cache: {e}")

    def generate_analysis_report(self, results: Dict[str, AnalysisResult]) -> str:
        """Generate comprehensive analysis report"""
        report = []
        report.append("Static Analysis Report")
        report.append("=" * 50)
        report.append(f"Files Analyzed: {len(results)}")
        report.append("")

        # Summary statistics
        total_functions = sum(len(result.functions) for result in results.values())
        total_classes = sum(len(result.classes) for result in results.values())
        total_loc = sum(result.complexity_metrics.get('total_lines_of_code', 0) for result in results.values())

        report.append("Summary Statistics:")
        report.append(f"  Total Functions: {total_functions}")
        report.append(f"  Total Classes: {total_classes}")
        report.append(f"  Total Lines of Code: {total_loc}")
        report.append("")

        # Language breakdown
        languages = {}
        for result in results.values():
            lang = result.language.value
            languages[lang] = languages.get(lang, 0) + 1

        report.append("Languages:")
        for lang, count in sorted(languages.items()):
            report.append(f"  {lang}: {count} files")
        report.append("")

        # Complexity metrics
        if results:
            avg_complexity = sum(
                result.complexity_metrics.get('average_cyclomatic_complexity', 0)
                for result in results.values()
            ) / len(results)

            report.append(f"Average Cyclomatic Complexity: {avg_complexity:.2f}")

        # Most complex functions
        all_functions = []
        for file_path, result in results.items():
            for func in result.functions:
                all_functions.append((func.complexity, func.name, file_path))

        all_functions.sort(reverse=True)

        if all_functions:
            report.append("")
            report.append("Most Complex Functions:")
            for complexity, func_name, file_path in all_functions[:10]:
                report.append(f"  {func_name} ({Path(file_path).name}): {complexity}")

        return "\n".join(report)