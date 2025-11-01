#!/usr/bin/env python3
"""
Taint Analysis using Algebraic Semiring Theory
==============================================

Implements taint propagation analysis using semiring algebra and lattice theory.
Provides formal mathematical foundation for data flow analysis.
"""

from enum import Enum
from typing import Dict, Set, List, Any, Optional, Union
from dataclasses import dataclass
import networkx as nx


class TaintLevel(Enum):
    """Taint levels forming a lattice structure"""
    CLEAN = "clean"
    USER_INPUT = "user_input"
    SECRET = "secret"
    TAINTED = "tainted"
    UNDEFINED = "undefined"


@dataclass
class TaintValue:
    """Represents a taint value with lattice operations"""
    level: TaintLevel
    source: Optional[str] = None
    propagation_path: List[str] = None

    def __post_init__(self):
        if self.propagation_path is None:
            self.propagation_path = []

    def __le__(self, other: 'TaintValue') -> bool:
        """Lattice ordering relation"""
        order = {
            TaintLevel.CLEAN: 0,
            TaintLevel.USER_INPUT: 1,
            TaintLevel.SECRET: 2,
            TaintLevel.TAINTED: 3,
            TaintLevel.UNDEFINED: 4
        }
        return order[self.level] <= order[other.level]

    def join(self, other: 'TaintValue') -> 'TaintValue':
        """Lattice join operation (least upper bound)"""
        if self <= other:
            return other
        elif other <= self:
            return self
        else:
            # Combine propagation paths
            combined_path = self.propagation_path + other.propagation_path
            return TaintValue(
                level=TaintLevel.TAINTED,
                source=f"{self.source},{other.source}",
                propagation_path=combined_path
            )

    def meet(self, other: 'TaintValue') -> 'TaintValue':
        """Lattice meet operation (greatest lower bound)"""
        if self <= other:
            return self
        elif other <= self:
            return other
        else:
            return TaintValue(level=TaintLevel.CLEAN)


class TaintLattice:
    """Taint lattice with algebraic operations"""

    def __init__(self):
        self.bottom = TaintValue(TaintLevel.CLEAN)
        self.top = TaintValue(TaintLevel.UNDEFINED)

    def is_tainted(self, value: TaintValue) -> bool:
        """Check if value is tainted"""
        return value.level in [TaintLevel.USER_INPUT, TaintLevel.SECRET, TaintLevel.TAINTED]

    def propagate(self, source: TaintValue, operation: str) -> TaintValue:
        """Propagate taint through an operation"""
        if source.level == TaintLevel.CLEAN:
            return source

        # Create new taint value with updated propagation path
        new_path = source.propagation_path + [operation]

        if operation in ['sanitize', 'validate', 'escape']:
            # Sanitization operations reduce taint
            return TaintValue(TaintLevel.CLEAN, propagation_path=new_path)
        elif operation in ['database_query', 'system_call', 'file_write']:
            # Dangerous operations increase taint
            return TaintValue(TaintLevel.TAINTED, source.source, new_path)
        else:
            # Regular operations preserve taint
            return TaintValue(source.level, source.source, new_path)

    def combine(self, values: List[TaintValue]) -> TaintValue:
        """Combine multiple taint values using join"""
        if not values:
            return self.bottom

        result = values[0]
        for value in values[1:]:
            result = result.join(value)

        return result


def analyze_data_flow(cfg: nx.DiGraph, sources: Dict[str, TaintValue],
                     sinks: List[str]) -> Dict[str, Any]:
    """
    Analyze data flow for taint propagation

    Args:
        cfg: Control flow graph with data flow information
        sources: Dictionary of taint sources (variable -> taint value)
        sinks: List of sensitive sink operations

    Returns:
        Data flow analysis results
    """
    lattice = TaintLattice()
    taint_state = {}
    vulnerabilities = []

    # Initialize taint state
    for node in cfg.nodes():
        taint_state[node] = {}

    # Set initial taint sources
    for var, taint in sources.items():
        for node in cfg.nodes():
            if var in cfg.nodes[node].get('variables', []):
                taint_state[node][var] = taint

    # Forward data flow analysis
    changed = True
    max_iterations = 100
    iteration = 0

    while changed and iteration < max_iterations:
        changed = False
        iteration += 1

        for node in nx.topological_sort(cfg):
            old_state = taint_state[node].copy()

            # Process node operations
            node_data = cfg.nodes[node]
            operation = node_data.get('operation', '')
            variables = node_data.get('variables', [])

            # Propagate taint through operation
            for var in variables:
                if var in taint_state[node]:
                    new_taint = lattice.propagate(taint_state[node][var], operation)
                    taint_state[node][var] = new_taint

            # Propagate to successors
            for successor in cfg.successors(node):
                for var, taint in taint_state[node].items():
                    if var not in taint_state[successor]:
                        taint_state[successor][var] = taint
                        changed = True
                    else:
                        combined = taint_state[successor][var].join(taint)
                        if combined != taint_state[successor][var]:
                            taint_state[successor][var] = combined
                            changed = True

            # Check for changes
            if taint_state[node] != old_state:
                changed = True

    # Check for taint reaching sinks
    for node in cfg.nodes():
        node_data = cfg.nodes[node]
        operation = node_data.get('operation', '')

        if operation in sinks:
            # Check if any tainted data reaches this sink
            for var, taint in taint_state[node].items():
                if lattice.is_tainted(taint):
                    vulnerabilities.append({
                        'node': node,
                        'operation': operation,
                        'tainted_variable': var,
                        'taint_source': taint.source,
                        'propagation_path': taint.propagation_path,
                        'taint_level': taint.level.value
                    })

    return {
        'vulnerabilities': vulnerabilities,
        'taint_states': taint_state,
        'iterations': iteration,
        'converged': not changed,
        'analysis_summary': _summarize_taint_analysis(vulnerabilities, taint_state)
    }


def _summarize_taint_analysis(vulnerabilities: List[Dict], taint_states: Dict) -> Dict[str, Any]:
    """Summarize taint analysis results"""
    total_tainted_vars = 0
    taint_distribution = {level.value: 0 for level in TaintLevel}

    for node_state in taint_states.values():
        for taint in node_state.values():
            total_tainted_vars += 1
            taint_distribution[taint.level.value] += 1

    return {
        'total_vulnerabilities': len(vulnerabilities),
        'total_tainted_variables': total_tainted_vars,
        'taint_level_distribution': taint_distribution,
        'vulnerability_types': list(set(v['operation'] for v in vulnerabilities)),
        'risk_assessment': _assess_taint_risk(vulnerabilities)
    }


def _assess_taint_risk(vulnerabilities: List[Dict]) -> str:
    """Assess overall risk based on taint analysis"""
    if not vulnerabilities:
        return "low"

    high_risk_operations = ['database_query', 'system_call', 'eval', 'exec']
    high_risk_count = sum(1 for v in vulnerabilities if v['operation'] in high_risk_operations)

    if high_risk_count >= 3:
        return "critical"
    elif high_risk_count >= 1:
        return "high"
    elif len(vulnerabilities) >= 5:
        return "medium"
    else:
        return "low"


class KleeneAlgebra:
    """Kleene Algebra with Tests for regex-based sanitizer modeling"""

    def __init__(self):
        self.tests = {}
        self.actions = {}

    def add_test(self, name: str, condition: str) -> None:
        """Add a test condition"""
        self.tests[name] = condition

    def add_action(self, name: str, operation: str) -> None:
        """Add an action operation"""
        self.actions[name] = operation

    def compose(self, action1: str, action2: str) -> str:
        """Compose two actions"""
        return f"({action1});({action2})"

    def choice(self, action1: str, action2: str) -> str:
        """Choice between two actions"""
        return f"({action1})|({action2})"

    def star(self, action: str) -> str:
        """Kleene star (iteration)"""
        return f"({action})*"

    def validate_sanitizer(self, regex_pattern: str, input_pattern: str) -> bool:
        """Validate if sanitizer regex properly handles input pattern"""
        try:
            import re
            compiled_regex = re.compile(regex_pattern)
            return bool(compiled_regex.match(input_pattern))
        except re.error:
            return False


def build_cfg_with_dataflow(code: str) -> nx.DiGraph:
    """
    Build control flow graph with data flow information
    Simplified implementation for demonstration
    """
    cfg = nx.DiGraph()

    # Simple parsing (in practice, would use proper AST parsing)
    lines = code.split('\n')
    variables = set()

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        node_id = f"line_{i}"
        cfg.add_node(node_id)

        # Extract variables and operations (simplified)
        if '=' in line:
            var = line.split('=')[0].strip()
            variables.add(var)
            operation = 'assignment'
        elif 'input(' in line or 'request.' in line:
            operation = 'user_input'
        elif 'execute(' in line or 'query(' in line:
            operation = 'database_query'
        elif 'system(' in line or 'os.system' in line:
            operation = 'system_call'
        elif 'sanitize' in line or 'escape' in line:
            operation = 'sanitize'
        else:
            operation = 'other'

        cfg.nodes[node_id]['operation'] = operation
        cfg.nodes[node_id]['variables'] = list(variables)
        cfg.nodes[node_id]['line_number'] = i + 1

        # Add edges (simplified sequential flow)
        if i > 0:
            prev_node = f"line_{i-1}"
            if prev_node in cfg:
                cfg.add_edge(prev_node, node_id)

    return cfg