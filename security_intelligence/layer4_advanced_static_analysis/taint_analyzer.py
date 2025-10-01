"""
Advanced Taint Analysis Engine

This module provides comprehensive taint analysis capabilities:
- Inter-procedural taint propagation
- Context-sensitive analysis
- Field-sensitive analysis for objects/structures
- Sanitization tracking and validation
- Advanced taint sources and sinks detection
"""

import logging
import json
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import networkx as nx
from collections import defaultdict, deque

from .static_analyzer import ASTNode, Function, AnalysisResult, NodeType, SourceLocation

class TaintLevel(Enum):
    """Taint levels"""
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class TaintType(Enum):
    """Types of taint"""
    USER_INPUT = "user_input"
    NETWORK_DATA = "network_data"
    FILE_DATA = "file_data"
    DATABASE_DATA = "database_data"
    ENVIRONMENT_DATA = "environment_data"
    COMMAND_LINE_DATA = "command_line_data"
    CRYPTO_KEY = "crypto_key"
    SENSITIVE_DATA = "sensitive_data"

@dataclass
class TaintInfo:
    """Information about taint"""
    taint_type: TaintType
    taint_level: TaintLevel
    source_location: SourceLocation
    propagation_path: List[SourceLocation] = field(default_factory=list)
    sanitizations: List[str] = field(default_factory=list)
    transformations: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TaintSource:
    """Taint source definition"""
    name: str
    taint_type: TaintType
    taint_level: TaintLevel
    parameters: List[int] = field(default_factory=list)  # Which parameters are tainted
    return_tainted: bool = False
    description: str = ""

@dataclass
class TaintSink:
    """Taint sink definition"""
    name: str
    vulnerable_parameters: List[int] = field(default_factory=list)
    vulnerability_type: str = ""
    severity: str = "medium"
    description: str = ""

@dataclass
class Sanitizer:
    """Sanitization function definition"""
    name: str
    input_parameters: List[int] = field(default_factory=list)
    output_clean: bool = True
    sanitization_type: str = ""
    effectiveness: float = 1.0  # 0.0 to 1.0

@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink"""
    source: TaintSource
    sink: TaintSink
    source_location: SourceLocation
    sink_location: SourceLocation
    flow_path: List[SourceLocation]
    taint_info: TaintInfo
    vulnerability_confirmed: bool = False
    exploitability_score: float = 0.0

@dataclass
class VariableTaint:
    """Taint information for a variable"""
    variable_name: str
    taint_info: TaintInfo
    location: SourceLocation
    scope: str
    last_assignment: Optional[SourceLocation] = None

class TaintSourceManager:
    """Manages taint sources"""

    def __init__(self):
        self.sources = self._load_default_sources()
        self.custom_sources = {}

    def _load_default_sources(self) -> Dict[str, TaintSource]:
        """Load default taint sources"""
        sources = {}

        # User input sources
        user_input_sources = [
            ('input', 'Python input function'),
            ('raw_input', 'Python raw input function'),
            ('sys.argv', 'Command line arguments'),
            ('os.environ', 'Environment variables'),
            ('request.GET', 'HTTP GET parameters'),
            ('request.POST', 'HTTP POST parameters'),
            ('request.json', 'HTTP JSON data'),
            ('request.form', 'HTTP form data'),
            ('request.args', 'HTTP arguments'),
            ('flask.request', 'Flask request data'),
            ('django.request', 'Django request data'),
        ]

        for name, desc in user_input_sources:
            sources[name] = TaintSource(
                name=name,
                taint_type=TaintType.USER_INPUT,
                taint_level=TaintLevel.HIGH,
                return_tainted=True,
                description=desc
            )

        # Network sources
        network_sources = [
            ('socket.recv', 'Socket receive'),
            ('socket.recvfrom', 'Socket receive from'),
            ('urllib.request.urlopen', 'URL open'),
            ('requests.get', 'HTTP GET request'),
            ('requests.post', 'HTTP POST request'),
            ('httplib.getresponse', 'HTTP response'),
        ]

        for name, desc in network_sources:
            sources[name] = TaintSource(
                name=name,
                taint_type=TaintType.NETWORK_DATA,
                taint_level=TaintLevel.HIGH,
                return_tainted=True,
                description=desc
            )

        # File sources
        file_sources = [
            ('open', 'File open'),
            ('file.read', 'File read'),
            ('file.readline', 'File readline'),
            ('file.readlines', 'File readlines'),
            ('os.read', 'OS read'),
            ('fread', 'C fread function'),
            ('fgets', 'C fgets function'),
        ]

        for name, desc in file_sources:
            sources[name] = TaintSource(
                name=name,
                taint_type=TaintType.FILE_DATA,
                taint_level=TaintLevel.MEDIUM,
                return_tainted=True,
                description=desc
            )

        # Database sources
        db_sources = [
            ('cursor.execute', 'Database query execution'),
            ('cursor.fetchone', 'Database fetch one'),
            ('cursor.fetchall', 'Database fetch all'),
            ('db.query', 'Database query'),
            ('sql.execute', 'SQL execution'),
        ]

        for name, desc in db_sources:
            sources[name] = TaintSource(
                name=name,
                taint_type=TaintType.DATABASE_DATA,
                taint_level=TaintLevel.MEDIUM,
                return_tainted=True,
                description=desc
            )

        return sources

    def is_source(self, function_name: str) -> Optional[TaintSource]:
        """Check if function is a taint source"""
        # Exact match
        if function_name in self.sources:
            return self.sources[function_name]

        # Partial match
        for source_name, source in self.sources.items():
            if source_name in function_name or function_name in source_name:
                return source

        return None

    def add_custom_source(self, source: TaintSource):
        """Add custom taint source"""
        self.custom_sources[source.name] = source

class TaintSinkManager:
    """Manages taint sinks"""

    def __init__(self):
        self.sinks = self._load_default_sinks()
        self.custom_sinks = {}

    def _load_default_sinks(self) -> Dict[str, TaintSink]:
        """Load default taint sinks"""
        sinks = {}

        # Command injection sinks
        command_sinks = [
            ('os.system', 'OS system command'),
            ('os.popen', 'OS popen'),
            ('subprocess.call', 'Subprocess call'),
            ('subprocess.run', 'Subprocess run'),
            ('subprocess.Popen', 'Subprocess Popen'),
            ('exec', 'Python exec'),
            ('eval', 'Python eval'),
            ('system', 'C system function'),
            ('popen', 'C popen function'),
        ]

        for name, desc in command_sinks:
            sinks[name] = TaintSink(
                name=name,
                vulnerable_parameters=[0],
                vulnerability_type='command_injection',
                severity='critical',
                description=desc
            )

        # SQL injection sinks
        sql_sinks = [
            ('cursor.execute', 'Database query execution'),
            ('db.execute', 'Database execution'),
            ('sql.execute', 'SQL execution'),
            ('query', 'Database query'),
            ('mysql_query', 'MySQL query'),
            ('sqlite3.execute', 'SQLite execution'),
        ]

        for name, desc in sql_sinks:
            sinks[name] = TaintSink(
                name=name,
                vulnerable_parameters=[0],
                vulnerability_type='sql_injection',
                severity='critical',
                description=desc
            )

        # Path traversal sinks
        path_sinks = [
            ('open', 'File open'),
            ('file', 'File constructor'),
            ('os.remove', 'File remove'),
            ('os.unlink', 'File unlink'),
            ('shutil.copy', 'File copy'),
            ('shutil.move', 'File move'),
            ('include', 'File include'),
            ('require', 'File require'),
        ]

        for name, desc in path_sinks:
            sinks[name] = TaintSink(
                name=name,
                vulnerable_parameters=[0],
                vulnerability_type='path_traversal',
                severity='high',
                description=desc
            )

        # XSS sinks
        xss_sinks = [
            ('print', 'Print output'),
            ('echo', 'Echo output'),
            ('write', 'Write output'),
            ('response.write', 'HTTP response write'),
            ('document.write', 'Document write'),
            ('innerHTML', 'Inner HTML'),
            ('outerHTML', 'Outer HTML'),
        ]

        for name, desc in xss_sinks:
            sinks[name] = TaintSink(
                name=name,
                vulnerable_parameters=[0],
                vulnerability_type='xss',
                severity='high',
                description=desc
            )

        return sinks

    def is_sink(self, function_name: str) -> Optional[TaintSink]:
        """Check if function is a taint sink"""
        # Exact match
        if function_name in self.sinks:
            return self.sinks[function_name]

        # Partial match
        for sink_name, sink in self.sinks.items():
            if sink_name in function_name or function_name in sink_name:
                return sink

        return None

    def add_custom_sink(self, sink: TaintSink):
        """Add custom taint sink"""
        self.custom_sinks[sink.name] = sink

class SanitizerManager:
    """Manages sanitization functions"""

    def __init__(self):
        self.sanitizers = self._load_default_sanitizers()
        self.custom_sanitizers = {}

    def _load_default_sanitizers(self) -> Dict[str, Sanitizer]:
        """Load default sanitizers"""
        sanitizers = {}

        # HTML sanitizers
        html_sanitizers = [
            ('html.escape', 'HTML escape'),
            ('cgi.escape', 'CGI escape'),
            ('bleach.clean', 'Bleach HTML cleaner'),
            ('escape', 'Generic escape'),
            ('htmlentities', 'HTML entities'),
            ('htmlspecialchars', 'HTML special chars'),
        ]

        for name, desc in html_sanitizers:
            sanitizers[name] = Sanitizer(
                name=name,
                input_parameters=[0],
                sanitization_type='html',
                effectiveness=0.9
            )

        # SQL sanitizers
        sql_sanitizers = [
            ('escape_string', 'SQL escape string'),
            ('quote', 'SQL quote'),
            ('prepare', 'SQL prepare statement'),
            ('parameterize', 'SQL parameterize'),
        ]

        for name, desc in sql_sanitizers:
            sanitizers[name] = Sanitizer(
                name=name,
                input_parameters=[0],
                sanitization_type='sql',
                effectiveness=0.95
            )

        # Path sanitizers
        path_sanitizers = [
            ('os.path.normpath', 'Normalize path'),
            ('os.path.abspath', 'Absolute path'),
            ('pathlib.Path', 'Path object'),
            ('realpath', 'Real path'),
            ('canonicalize', 'Canonicalize path'),
        ]

        for name, desc in path_sanitizers:
            sanitizers[name] = Sanitizer(
                name=name,
                input_parameters=[0],
                sanitization_type='path',
                effectiveness=0.8
            )

        # Input validation
        validation_sanitizers = [
            ('validate', 'Generic validation'),
            ('filter', 'Filter input'),
            ('clean', 'Clean input'),
            ('sanitize', 'Sanitize input'),
            ('strip', 'Strip input'),
            ('re.sub', 'Regex substitution'),
        ]

        for name, desc in validation_sanitizers:
            sanitizers[name] = Sanitizer(
                name=name,
                input_parameters=[0],
                sanitization_type='validation',
                effectiveness=0.7
            )

        return sanitizers

    def is_sanitizer(self, function_name: str) -> Optional[Sanitizer]:
        """Check if function is a sanitizer"""
        # Exact match
        if function_name in self.sanitizers:
            return self.sanitizers[function_name]

        # Partial match
        for sanitizer_name, sanitizer in self.sanitizers.items():
            if sanitizer_name in function_name or function_name in sanitizer_name:
                return sanitizer

        return None

    def add_custom_sanitizer(self, sanitizer: Sanitizer):
        """Add custom sanitizer"""
        self.custom_sanitizers[sanitizer.name] = sanitizer

class TaintPropagator:
    """Handles taint propagation through code"""

    def __init__(self):
        self.propagation_rules = self._load_propagation_rules()

    def _load_propagation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load taint propagation rules"""
        return {
            'assignment': {
                'type': 'direct',
                'preserves_taint': True,
                'taint_reduction': 0.0
            },
            'string_concatenation': {
                'type': 'merge',
                'preserves_taint': True,
                'taint_reduction': 0.1
            },
            'function_call': {
                'type': 'context_dependent',
                'preserves_taint': 'depends',
                'taint_reduction': 0.0
            },
            'arithmetic': {
                'type': 'conditional',
                'preserves_taint': False,
                'taint_reduction': 0.8
            },
            'comparison': {
                'type': 'conditional',
                'preserves_taint': False,
                'taint_reduction': 0.9
            }
        }

    def propagate_taint(self, source_taint: TaintInfo, operation: str,
                       target_location: SourceLocation) -> TaintInfo:
        """Propagate taint through an operation"""
        rule = self.propagation_rules.get(operation, self.propagation_rules['assignment'])

        new_taint = TaintInfo(
            taint_type=source_taint.taint_type,
            taint_level=source_taint.taint_level,
            source_location=source_taint.source_location,
            propagation_path=source_taint.propagation_path + [target_location],
            sanitizations=source_taint.sanitizations.copy(),
            transformations=source_taint.transformations + [operation],
            context=source_taint.context.copy()
        )

        # Apply taint reduction
        taint_reduction = rule.get('taint_reduction', 0.0)
        if taint_reduction > 0:
            new_level_value = max(0, source_taint.taint_level.value - int(taint_reduction * 4))
            new_taint.taint_level = TaintLevel(new_level_value)

        return new_taint

    def merge_taints(self, taints: List[TaintInfo], location: SourceLocation) -> TaintInfo:
        """Merge multiple taint information"""
        if not taints:
            return TaintInfo(
                taint_type=TaintType.USER_INPUT,
                taint_level=TaintLevel.CLEAN,
                source_location=location
            )

        # Take the highest taint level
        max_taint = max(taints, key=lambda t: t.taint_level.value)

        merged_taint = TaintInfo(
            taint_type=max_taint.taint_type,
            taint_level=max_taint.taint_level,
            source_location=max_taint.source_location,
            propagation_path=max_taint.propagation_path + [location],
            sanitizations=[],
            transformations=['merge'],
            context={}
        )

        # Merge sanitizations
        for taint in taints:
            merged_taint.sanitizations.extend(taint.sanitizations)

        return merged_taint

class AdvancedTaintAnalyzer:
    """Main advanced taint analysis engine"""

    def __init__(self):
        self.source_manager = TaintSourceManager()
        self.sink_manager = TaintSinkManager()
        self.sanitizer_manager = SanitizerManager()
        self.propagator = TaintPropagator()

        self.variable_taints = {}  # variable_name -> VariableTaint
        self.function_summaries = {}  # function_name -> summary
        self.taint_flows = []

    def analyze_taint_flows(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Analyze taint flows in the entire program"""
        taint_results = {
            'flows': [],
            'vulnerabilities': [],
            'sources_found': [],
            'sinks_found': [],
            'sanitizers_found': [],
            'statistics': {}
        }

        # Initialize analysis
        self.variable_taints = {}
        self.taint_flows = []

        # Analyze each function
        for function in analysis_result.functions:
            func_results = self._analyze_function_taint(function)

            taint_results['flows'].extend(func_results['flows'])
            taint_results['vulnerabilities'].extend(func_results['vulnerabilities'])

        # Inter-procedural analysis
        inter_proc_flows = self._analyze_inter_procedural_flows(analysis_result)
        taint_results['flows'].extend(inter_proc_flows)

        # Calculate statistics
        taint_results['statistics'] = self._calculate_taint_statistics(taint_results)

        return taint_results

    def _analyze_function_taint(self, function: Function) -> Dict[str, Any]:
        """Analyze taint flows within a single function"""
        function_results = {
            'flows': [],
            'vulnerabilities': []
        }

        # Track local variable taints
        local_taints = {}

        # Analyze function body
        self._analyze_ast_node(function.ast_node, local_taints, function.name)

        # Find flows from sources to sinks
        flows = self._find_taint_flows(local_taints, function)
        function_results['flows'] = flows

        # Identify vulnerabilities
        vulnerabilities = self._identify_vulnerabilities_from_flows(flows)
        function_results['vulnerabilities'] = vulnerabilities

        return function_results

    def _analyze_ast_node(self, node: ASTNode, local_taints: Dict[str, VariableTaint], scope: str):
        """Analyze taint in AST node"""
        if node.node_type == NodeType.CALL:
            self._analyze_function_call(node, local_taints, scope)

        elif node.node_type == NodeType.ASSIGNMENT:
            self._analyze_assignment(node, local_taints, scope)

        elif node.node_type == NodeType.VARIABLE:
            self._analyze_variable_usage(node, local_taints, scope)

        # Recursively analyze children
        for child in node.children:
            self._analyze_ast_node(child, local_taints, scope)

    def _analyze_function_call(self, call_node: ASTNode, local_taints: Dict[str, VariableTaint], scope: str):
        """Analyze function call for taint sources, sinks, and sanitizers"""
        func_name = call_node.name

        # Check if it's a taint source
        source = self.source_manager.is_source(func_name)
        if source:
            self._handle_taint_source(call_node, source, local_taints, scope)

        # Check if it's a taint sink
        sink = self.sink_manager.is_sink(func_name)
        if sink:
            self._handle_taint_sink(call_node, sink, local_taints, scope)

        # Check if it's a sanitizer
        sanitizer = self.sanitizer_manager.is_sanitizer(func_name)
        if sanitizer:
            self._handle_sanitizer(call_node, sanitizer, local_taints, scope)

    def _handle_taint_source(self, call_node: ASTNode, source: TaintSource,
                           local_taints: Dict[str, VariableTaint], scope: str):
        """Handle taint source function call"""
        if source.return_tainted:
            # If the call is part of an assignment, taint the target variable
            if call_node.parent and call_node.parent.node_type == NodeType.ASSIGNMENT:
                # Find assignment target
                for sibling in call_node.parent.children:
                    if sibling.node_type == NodeType.VARIABLE and sibling != call_node:
                        taint_info = TaintInfo(
                            taint_type=source.taint_type,
                            taint_level=source.taint_level,
                            source_location=call_node.location
                        )

                        var_taint = VariableTaint(
                            variable_name=sibling.name,
                            taint_info=taint_info,
                            location=sibling.location,
                            scope=scope,
                            last_assignment=call_node.location
                        )

                        local_taints[sibling.name] = var_taint

    def _handle_taint_sink(self, call_node: ASTNode, sink: TaintSink,
                         local_taints: Dict[str, VariableTaint], scope: str):
        """Handle taint sink function call"""
        # Check if any arguments to the sink are tainted
        for i, child in enumerate(call_node.children):
            if child.node_type == NodeType.VARIABLE and i in sink.vulnerable_parameters:
                if child.name in local_taints:
                    var_taint = local_taints[child.name]

                    # Check if taint is sanitized
                    if not self._is_effectively_sanitized(var_taint.taint_info, sink.vulnerability_type):
                        # Create taint flow
                        flow = TaintFlow(
                            source=TaintSource(
                                name=var_taint.taint_info.source_location.file_path,
                                taint_type=var_taint.taint_info.taint_type,
                                taint_level=var_taint.taint_info.taint_level
                            ),
                            sink=sink,
                            source_location=var_taint.taint_info.source_location,
                            sink_location=call_node.location,
                            flow_path=var_taint.taint_info.propagation_path + [call_node.location],
                            taint_info=var_taint.taint_info,
                            vulnerability_confirmed=True,
                            exploitability_score=self._calculate_exploitability_score(var_taint.taint_info, sink)
                        )

                        self.taint_flows.append(flow)

    def _handle_sanitizer(self, call_node: ASTNode, sanitizer: Sanitizer,
                        local_taints: Dict[str, VariableTaint], scope: str):
        """Handle sanitizer function call"""
        # If the call is part of an assignment, mark the target as sanitized
        if call_node.parent and call_node.parent.node_type == NodeType.ASSIGNMENT:
            # Check if any input parameters are tainted
            tainted_inputs = []
            for i, child in enumerate(call_node.children):
                if child.node_type == NodeType.VARIABLE and i in sanitizer.input_parameters:
                    if child.name in local_taints:
                        tainted_inputs.append(local_taints[child.name])

            if tainted_inputs:
                # Find assignment target and mark as sanitized
                for sibling in call_node.parent.children:
                    if sibling.node_type == NodeType.VARIABLE and sibling != call_node:
                        # Merge taint from inputs and apply sanitization
                        merged_taint = self.propagator.merge_taints(
                            [t.taint_info for t in tainted_inputs],
                            call_node.location
                        )

                        # Apply sanitization
                        merged_taint.sanitizations.append(sanitizer.name)

                        # Reduce taint level based on sanitizer effectiveness
                        taint_reduction = int(sanitizer.effectiveness * 4)
                        new_level_value = max(0, merged_taint.taint_level.value - taint_reduction)
                        merged_taint.taint_level = TaintLevel(new_level_value)

                        var_taint = VariableTaint(
                            variable_name=sibling.name,
                            taint_info=merged_taint,
                            location=sibling.location,
                            scope=scope,
                            last_assignment=call_node.location
                        )

                        local_taints[sibling.name] = var_taint

    def _analyze_assignment(self, assign_node: ASTNode, local_taints: Dict[str, VariableTaint], scope: str):
        """Analyze assignment for taint propagation"""
        if len(assign_node.children) < 2:
            return

        # Assume first child is target, others are sources
        target = assign_node.children[0]
        sources = assign_node.children[1:]

        if target.node_type != NodeType.VARIABLE:
            return

        # Collect taint from sources
        source_taints = []
        for source in sources:
            if source.node_type == NodeType.VARIABLE and source.name in local_taints:
                source_taints.append(local_taints[source.name].taint_info)

        if source_taints:
            # Propagate taint to target
            merged_taint = self.propagator.merge_taints(source_taints, assign_node.location)

            var_taint = VariableTaint(
                variable_name=target.name,
                taint_info=merged_taint,
                location=target.location,
                scope=scope,
                last_assignment=assign_node.location
            )

            local_taints[target.name] = var_taint

    def _analyze_variable_usage(self, var_node: ASTNode, local_taints: Dict[str, VariableTaint], scope: str):
        """Analyze variable usage"""
        # For now, just track that the variable was used
        # More sophisticated analysis would track how the variable is used
        pass

    def _find_taint_flows(self, local_taints: Dict[str, VariableTaint], function: Function) -> List[TaintFlow]:
        """Find taint flows within function"""
        # Flows are already created in _handle_taint_sink
        # This method could be used for additional flow analysis
        return [flow for flow in self.taint_flows if flow.sink_location.file_path == function.location.file_path]

    def _analyze_inter_procedural_flows(self, analysis_result: AnalysisResult) -> List[TaintFlow]:
        """Analyze taint flows between functions"""
        inter_proc_flows = []

        # Build function call relationships
        call_graph = analysis_result.call_graph

        # For each function, analyze how taint flows through calls
        for function in analysis_result.functions:
            # Analyze calls made by this function
            for called_func in function.called_functions:
                if call_graph.has_node(called_func):
                    # Check if tainted data flows into the called function
                    flow = self._analyze_function_call_flow(function, called_func, analysis_result)
                    if flow:
                        inter_proc_flows.append(flow)

        return inter_proc_flows

    def _analyze_function_call_flow(self, caller: Function, callee_name: str,
                                  analysis_result: AnalysisResult) -> Optional[TaintFlow]:
        """Analyze taint flow through function call"""
        # Simplified inter-procedural analysis
        # A more complete implementation would track parameter mappings
        # and return value flows

        # For now, assume taint can flow through function calls
        # if the caller has tainted variables
        caller_taints = [vt for vt in self.variable_taints.values()
                        if vt.scope.startswith(caller.name)]

        if caller_taints:
            # Find the callee function
            callee = None
            for func in analysis_result.functions:
                if func.name == callee_name:
                    callee = func
                    break

            if callee:
                # Create a flow representing potential inter-procedural taint
                max_taint = max(caller_taints, key=lambda t: t.taint_info.taint_level.value)

                flow = TaintFlow(
                    source=TaintSource(
                        name=f"{caller.name}_to_{callee.name}",
                        taint_type=max_taint.taint_info.taint_type,
                        taint_level=max_taint.taint_info.taint_level
                    ),
                    sink=TaintSink(
                        name=callee.name,
                        vulnerability_type='inter_procedural',
                        severity='medium'
                    ),
                    source_location=max_taint.location,
                    sink_location=callee.location,
                    flow_path=[max_taint.location, callee.location],
                    taint_info=max_taint.taint_info,
                    vulnerability_confirmed=False,
                    exploitability_score=0.3
                )

                return flow

        return None

    def _identify_vulnerabilities_from_flows(self, flows: List[TaintFlow]) -> List[Dict[str, Any]]:
        """Identify vulnerabilities from taint flows"""
        vulnerabilities = []

        for flow in flows:
            if flow.vulnerability_confirmed:
                vuln = {
                    'type': flow.sink.vulnerability_type,
                    'severity': flow.sink.severity,
                    'source_location': flow.source_location,
                    'sink_location': flow.sink_location,
                    'taint_type': flow.taint_info.taint_type.value,
                    'taint_level': flow.taint_info.taint_level.value,
                    'exploitability_score': flow.exploitability_score,
                    'flow_path': flow.flow_path,
                    'sanitizations': flow.taint_info.sanitizations,
                    'description': f"{flow.sink.vulnerability_type} vulnerability via {flow.taint_info.taint_type.value}"
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_effectively_sanitized(self, taint_info: TaintInfo, vulnerability_type: str) -> bool:
        """Check if taint is effectively sanitized for the vulnerability type"""
        if not taint_info.sanitizations:
            return False

        # Check if any sanitization is effective for this vulnerability type
        for sanitizer_name in taint_info.sanitizations:
            sanitizer = self.sanitizer_manager.is_sanitizer(sanitizer_name)
            if sanitizer and sanitizer.sanitization_type in vulnerability_type:
                if sanitizer.effectiveness > 0.8:
                    return True

        return False

    def _calculate_exploitability_score(self, taint_info: TaintInfo, sink: TaintSink) -> float:
        """Calculate exploitability score for taint flow"""
        base_score = 0.5

        # Increase score based on taint level
        taint_multiplier = taint_info.taint_level.value / 4.0
        base_score += taint_multiplier * 0.3

        # Increase score based on sink severity
        severity_multiplier = {'low': 0.1, 'medium': 0.2, 'high': 0.3, 'critical': 0.4}.get(sink.severity, 0.2)
        base_score += severity_multiplier

        # Decrease score based on sanitizations
        sanitization_penalty = len(taint_info.sanitizations) * 0.1
        base_score -= sanitization_penalty

        # Decrease score based on transformations that might reduce exploitability
        safe_transformations = ['comparison', 'arithmetic']
        safe_transform_count = sum(1 for t in taint_info.transformations if t in safe_transformations)
        base_score -= safe_transform_count * 0.05

        return max(0.0, min(1.0, base_score))

    def _calculate_taint_statistics(self, taint_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate taint analysis statistics"""
        flows = taint_results['flows']
        vulnerabilities = taint_results['vulnerabilities']

        stats = {
            'total_flows': len(flows),
            'vulnerable_flows': len([f for f in flows if f.vulnerability_confirmed]),
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities_by_type': defaultdict(int),
            'vulnerabilities_by_severity': defaultdict(int),
            'taint_types_found': set(),
            'average_exploitability': 0.0
        }

        for vuln in vulnerabilities:
            stats['vulnerabilities_by_type'][vuln['type']] += 1
            stats['vulnerabilities_by_severity'][vuln['severity']] += 1
            stats['taint_types_found'].add(vuln['taint_type'])

        if vulnerabilities:
            stats['average_exploitability'] = sum(v['exploitability_score'] for v in vulnerabilities) / len(vulnerabilities)

        stats['taint_types_found'] = list(stats['taint_types_found'])
        stats['vulnerabilities_by_type'] = dict(stats['vulnerabilities_by_type'])
        stats['vulnerabilities_by_severity'] = dict(stats['vulnerabilities_by_severity'])

        return stats

    def generate_taint_report(self, taint_results: Dict[str, Any]) -> str:
        """Generate comprehensive taint analysis report"""
        report = []
        report.append("Advanced Taint Analysis Report")
        report.append("=" * 50)

        stats = taint_results['statistics']
        vulnerabilities = taint_results['vulnerabilities']

        # Summary
        report.append("Summary:")
        report.append(f"  Total Taint Flows: {stats['total_flows']}")
        report.append(f"  Vulnerable Flows: {stats['vulnerable_flows']}")
        report.append(f"  Total Vulnerabilities: {stats['total_vulnerabilities']}")
        report.append(f"  Average Exploitability: {stats['average_exploitability']:.2f}")
        report.append("")

        # Vulnerability breakdown
        if stats['vulnerabilities_by_type']:
            report.append("Vulnerabilities by Type:")
            for vuln_type, count in sorted(stats['vulnerabilities_by_type'].items()):
                report.append(f"  {vuln_type}: {count}")
            report.append("")

        if stats['vulnerabilities_by_severity']:
            report.append("Vulnerabilities by Severity:")
            for severity, count in sorted(stats['vulnerabilities_by_severity'].items()):
                report.append(f"  {severity}: {count}")
            report.append("")

        # Detailed vulnerabilities
        if vulnerabilities:
            report.append("Detailed Vulnerabilities:")
            report.append("-" * 30)

            for i, vuln in enumerate(vulnerabilities[:10]):  # Show top 10
                report.append(f"Vulnerability #{i+1}:")
                report.append(f"  Type: {vuln['type']}")
                report.append(f"  Severity: {vuln['severity']}")
                report.append(f"  Source: {vuln['source_location'].file_path}:{vuln['source_location'].line}")
                report.append(f"  Sink: {vuln['sink_location'].file_path}:{vuln['sink_location'].line}")
                report.append(f"  Taint Type: {vuln['taint_type']}")
                report.append(f"  Exploitability: {vuln['exploitability_score']:.2f}")

                if vuln['sanitizations']:
                    report.append(f"  Sanitizations: {', '.join(vuln['sanitizations'])}")

                report.append(f"  Description: {vuln['description']}")
                report.append("")

        return "\n".join(report)