"""
Advanced Semantic Analysis Engine

This module provides deep semantic analysis capabilities:
- Context-aware code understanding
- Type inference and propagation
- Semantic vulnerability detection
- Code intent analysis
- API usage pattern analysis
- Inter-procedural analysis
"""

import ast
import os
import logging
import json
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import networkx as nx
import torch
import torch.nn as nn
import numpy as np
from collections import defaultdict, deque

try:
    import transformers
    from transformers import AutoTokenizer, AutoModel
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("Transformers not available. Install with: pip install transformers")

from .static_analyzer import ASTNode, Function, AnalysisResult, NodeType, SourceLocation

class SemanticVulnerabilityType(Enum):
    """Types of semantic vulnerabilities"""
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    TOCTOU = "time_of_check_time_of_use"
    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_FAILURE = "authorization_failure"
    CRYPTOGRAPHIC_WEAKNESS = "cryptographic_weakness"
    INFORMATION_DISCLOSURE = "information_disclosure"

class TypeInference(Enum):
    """Inferred types"""
    INTEGER = "integer"
    STRING = "string"
    BOOLEAN = "boolean"
    FLOAT = "float"
    LIST = "list"
    DICT = "dict"
    FUNCTION = "function"
    CLASS = "class"
    UNKNOWN = "unknown"
    TAINTED = "tainted"
    SANITIZED = "sanitized"

@dataclass
class TypeInfo:
    """Type information for variables/expressions"""
    inferred_type: TypeInference
    confidence: float
    constraints: List[str] = field(default_factory=list)
    nullable: bool = True
    size_bounds: Optional[Tuple[int, int]] = None
    taint_level: int = 0
    sanitization_functions: Set[str] = field(default_factory=set)

@dataclass
class SemanticContext:
    """Semantic context for analysis"""
    function_name: str
    variable_types: Dict[str, TypeInfo]
    call_stack: List[str]
    loop_depth: int = 0
    condition_depth: int = 0
    taint_sources: Set[str] = field(default_factory=set)
    sinks: Set[str] = field(default_factory=set)

@dataclass
class SemanticVulnerability:
    """Semantic vulnerability finding"""
    vuln_type: SemanticVulnerabilityType
    location: SourceLocation
    severity: str
    confidence: float
    description: str
    affected_variables: List[str]
    exploit_conditions: List[str]
    remediation: str
    cwe_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class APIUsagePattern:
    """API usage pattern"""
    api_name: str
    usage_context: str
    parameters: List[str]
    return_usage: str
    security_relevant: bool
    potential_misuse: Optional[str] = None

@dataclass
class DataFlow:
    """Data flow information"""
    source: SourceLocation
    sink: SourceLocation
    path: List[SourceLocation]
    transformations: List[str]
    taint_preserved: bool
    sanitized: bool

class CodeEmbedding(nn.Module):
    """Neural network for code embeddings"""

    def __init__(self, vocab_size: int = 50000, embedding_dim: int = 768, hidden_dim: int = 512):
        super().__init__()

        self.token_embedding = nn.Embedding(vocab_size, embedding_dim)
        self.positional_embedding = nn.Embedding(512, embedding_dim)

        self.transformer = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(
                d_model=embedding_dim,
                nhead=8,
                dim_feedforward=hidden_dim,
                dropout=0.1
            ),
            num_layers=6
        )

        self.semantic_classifier = nn.Sequential(
            nn.Linear(embedding_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, len(SemanticVulnerabilityType)),
            nn.Sigmoid()
        )

        self.type_predictor = nn.Sequential(
            nn.Linear(embedding_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, len(TypeInference))
        )

    def forward(self, token_ids, attention_mask=None):
        batch_size, seq_len = token_ids.shape

        # Token embeddings
        token_emb = self.token_embedding(token_ids)

        # Positional embeddings
        positions = torch.arange(seq_len, device=token_ids.device).unsqueeze(0).expand(batch_size, -1)
        pos_emb = self.positional_embedding(positions)

        # Combined embeddings
        embeddings = token_emb + pos_emb

        # Transformer encoding
        if attention_mask is not None:
            # Convert attention mask to boolean
            key_padding_mask = ~attention_mask.bool()
        else:
            key_padding_mask = None

        encoded = self.transformer(embeddings.transpose(0, 1), src_key_padding_mask=key_padding_mask)
        encoded = encoded.transpose(0, 1)

        # Pooling (mean of non-padded tokens)
        if attention_mask is not None:
            pooled = (encoded * attention_mask.unsqueeze(-1)).sum(dim=1) / attention_mask.sum(dim=1, keepdim=True)
        else:
            pooled = encoded.mean(dim=1)

        # Predictions
        vuln_scores = self.semantic_classifier(pooled)
        type_scores = self.type_predictor(pooled)

        return {
            'embeddings': pooled,
            'vulnerability_scores': vuln_scores,
            'type_scores': type_scores
        }

class TypeInferenceEngine:
    """Infers types of variables and expressions"""

    def __init__(self):
        self.type_rules = self._load_type_rules()
        self.builtin_types = self._load_builtin_types()

    def _load_type_rules(self) -> Dict[str, TypeInference]:
        """Load type inference rules"""
        return {
            # Python built-ins
            'len': TypeInference.INTEGER,
            'str': TypeInference.STRING,
            'int': TypeInference.INTEGER,
            'float': TypeInference.FLOAT,
            'bool': TypeInference.BOOLEAN,
            'list': TypeInference.LIST,
            'dict': TypeInference.DICT,

            # Common patterns
            '.split(': TypeInference.LIST,
            '.join(': TypeInference.STRING,
            '.append(': TypeInference.LIST,
            '.keys(': TypeInference.LIST,
            '.values(': TypeInference.LIST,
        }

    def _load_builtin_types(self) -> Dict[str, TypeInfo]:
        """Load built-in type information"""
        return {
            'None': TypeInfo(TypeInference.UNKNOWN, 1.0, nullable=True),
            'True': TypeInfo(TypeInference.BOOLEAN, 1.0, nullable=False),
            'False': TypeInfo(TypeInference.BOOLEAN, 1.0, nullable=False),
        }

    def infer_type(self, node: ASTNode, context: SemanticContext) -> TypeInfo:
        """Infer type of AST node"""
        if node.node_type == NodeType.VARIABLE:
            return self._infer_variable_type(node, context)
        elif node.node_type == NodeType.CALL:
            return self._infer_call_type(node, context)
        elif node.node_type == NodeType.ASSIGNMENT:
            return self._infer_assignment_type(node, context)
        else:
            return TypeInfo(TypeInference.UNKNOWN, 0.0)

    def _infer_variable_type(self, node: ASTNode, context: SemanticContext) -> TypeInfo:
        """Infer type of variable"""
        var_name = node.name

        # Check context
        if var_name in context.variable_types:
            return context.variable_types[var_name]

        # Check built-ins
        if var_name in self.builtin_types:
            return self.builtin_types[var_name]

        # Check taint sources
        if var_name in context.taint_sources:
            return TypeInfo(TypeInference.TAINTED, 0.8, taint_level=1)

        # Default
        return TypeInfo(TypeInference.UNKNOWN, 0.1)

    def _infer_call_type(self, node: ASTNode, context: SemanticContext) -> TypeInfo:
        """Infer type of function call"""
        func_name = node.name

        # Check type rules
        for pattern, inferred_type in self.type_rules.items():
            if pattern in func_name:
                confidence = 0.8 if pattern == func_name else 0.6
                return TypeInfo(inferred_type, confidence)

        # Check if it's a known function
        if func_name in context.variable_types:
            func_type = context.variable_types[func_name]
            if func_type.inferred_type == TypeInference.FUNCTION:
                # Return type inference would require more sophisticated analysis
                return TypeInfo(TypeInference.UNKNOWN, 0.3)

        return TypeInfo(TypeInference.UNKNOWN, 0.1)

    def _infer_assignment_type(self, node: ASTNode, context: SemanticContext) -> TypeInfo:
        """Infer type of assignment"""
        # For assignments, infer from the RHS
        if node.children:
            rhs_node = node.children[-1]  # Assume last child is RHS
            return self.infer_type(rhs_node, context)

        return TypeInfo(TypeInference.UNKNOWN, 0.1)

    def propagate_types(self, ast_node: ASTNode, context: SemanticContext):
        """Propagate type information through AST"""
        if ast_node.node_type == NodeType.ASSIGNMENT:
            self._propagate_assignment_types(ast_node, context)

        # Recursively propagate
        for child in ast_node.children:
            self.propagate_types(child, context)

    def _propagate_assignment_types(self, node: ASTNode, context: SemanticContext):
        """Propagate types through assignments"""
        # Simplified: assume first child is LHS, last is RHS
        if len(node.children) >= 2:
            lhs = node.children[0]
            rhs = node.children[-1]

            if lhs.node_type == NodeType.VARIABLE:
                rhs_type = self.infer_type(rhs, context)
                context.variable_types[lhs.name] = rhs_type

class VulnerabilityPatternMatcher:
    """Matches semantic vulnerability patterns"""

    def __init__(self):
        self.patterns = self._load_vulnerability_patterns()
        self.dangerous_functions = self._load_dangerous_functions()

    def _load_vulnerability_patterns(self) -> Dict[SemanticVulnerabilityType, List[Dict[str, Any]]]:
        """Load vulnerability patterns"""
        return {
            SemanticVulnerabilityType.NULL_POINTER_DEREFERENCE: [
                {
                    'pattern': 'dereference_without_null_check',
                    'conditions': ['nullable_variable', 'no_null_check', 'dereference'],
                    'severity': 'high'
                }
            ],
            SemanticVulnerabilityType.BUFFER_OVERFLOW: [
                {
                    'pattern': 'unbounded_copy',
                    'conditions': ['copy_function', 'unchecked_size', 'user_input'],
                    'severity': 'critical'
                }
            ],
            SemanticVulnerabilityType.INJECTION: [
                {
                    'pattern': 'sql_injection',
                    'conditions': ['sql_function', 'tainted_input', 'no_sanitization'],
                    'severity': 'critical'
                }
            ],
            SemanticVulnerabilityType.PATH_TRAVERSAL: [
                {
                    'pattern': 'path_traversal',
                    'conditions': ['file_operation', 'user_path', 'no_validation'],
                    'severity': 'high'
                }
            ]
        }

    def _load_dangerous_functions(self) -> Dict[str, Dict[str, Any]]:
        """Load dangerous function information"""
        return {
            # C/C++ functions
            'strcpy': {'vulnerability': 'buffer_overflow', 'risk': 'high'},
            'strcat': {'vulnerability': 'buffer_overflow', 'risk': 'high'},
            'sprintf': {'vulnerability': 'buffer_overflow', 'risk': 'high'},
            'gets': {'vulnerability': 'buffer_overflow', 'risk': 'critical'},
            'scanf': {'vulnerability': 'buffer_overflow', 'risk': 'medium'},

            # SQL functions
            'execute': {'vulnerability': 'injection', 'risk': 'high'},
            'query': {'vulnerability': 'injection', 'risk': 'high'},
            'exec': {'vulnerability': 'injection', 'risk': 'critical'},

            # File operations
            'open': {'vulnerability': 'path_traversal', 'risk': 'medium'},
            'fopen': {'vulnerability': 'path_traversal', 'risk': 'medium'},
            'include': {'vulnerability': 'path_traversal', 'risk': 'high'},

            # System operations
            'system': {'vulnerability': 'injection', 'risk': 'critical'},
            'popen': {'vulnerability': 'injection', 'risk': 'high'},
            'eval': {'vulnerability': 'injection', 'risk': 'critical'},
        }

    def match_patterns(self, ast_node: ASTNode, context: SemanticContext) -> List[SemanticVulnerability]:
        """Match vulnerability patterns in AST"""
        vulnerabilities = []

        # Check each vulnerability type
        for vuln_type, patterns in self.patterns.items():
            for pattern in patterns:
                if self._matches_pattern(ast_node, pattern, context):
                    vuln = self._create_vulnerability(vuln_type, pattern, ast_node, context)
                    vulnerabilities.append(vuln)

        # Check dangerous functions
        if ast_node.node_type == NodeType.CALL:
            func_name = ast_node.name.lower()
            for dangerous_func, info in self.dangerous_functions.items():
                if dangerous_func in func_name:
                    vuln = self._create_function_vulnerability(ast_node, dangerous_func, info, context)
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _matches_pattern(self, node: ASTNode, pattern: Dict[str, Any], context: SemanticContext) -> bool:
        """Check if node matches vulnerability pattern"""
        conditions = pattern['conditions']
        matched_conditions = 0

        for condition in conditions:
            if self._check_condition(node, condition, context):
                matched_conditions += 1

        # Require at least 70% of conditions to match
        return matched_conditions >= len(conditions) * 0.7

    def _check_condition(self, node: ASTNode, condition: str, context: SemanticContext) -> bool:
        """Check individual condition"""
        if condition == 'nullable_variable':
            if node.node_type == NodeType.VARIABLE:
                var_type = context.variable_types.get(node.name)
                return var_type and var_type.nullable

        elif condition == 'no_null_check':
            # Simplified: check if there's no null check in recent nodes
            return True  # Would need more sophisticated control flow analysis

        elif condition == 'dereference':
            # Check if variable is being dereferenced
            return '.' in node.name or '->' in node.name or '*' in node.name

        elif condition == 'copy_function':
            return any(func in node.name.lower() for func in ['copy', 'strcpy', 'memcpy'])

        elif condition == 'unchecked_size':
            # Simplified: assume size is unchecked if not explicitly bounded
            return True

        elif condition == 'user_input':
            if node.node_type == NodeType.VARIABLE:
                var_type = context.variable_types.get(node.name)
                return var_type and var_type.taint_level > 0

        elif condition == 'tainted_input':
            return self._is_tainted(node, context)

        elif condition == 'no_sanitization':
            return not self._is_sanitized(node, context)

        elif condition == 'sql_function':
            return any(func in node.name.lower() for func in ['execute', 'query', 'sql'])

        elif condition == 'file_operation':
            return any(func in node.name.lower() for func in ['open', 'read', 'write', 'include'])

        elif condition == 'user_path':
            return self._is_user_controlled_path(node, context)

        elif condition == 'no_validation':
            return not self._has_path_validation(node, context)

        return False

    def _is_tainted(self, node: ASTNode, context: SemanticContext) -> bool:
        """Check if node is tainted"""
        if node.node_type == NodeType.VARIABLE:
            var_type = context.variable_types.get(node.name)
            return var_type and (var_type.taint_level > 0 or var_type.inferred_type == TypeInference.TAINTED)
        return False

    def _is_sanitized(self, node: ASTNode, context: SemanticContext) -> bool:
        """Check if node is sanitized"""
        if node.node_type == NodeType.VARIABLE:
            var_type = context.variable_types.get(node.name)
            return var_type and (len(var_type.sanitization_functions) > 0 or var_type.inferred_type == TypeInference.SANITIZED)
        return False

    def _is_user_controlled_path(self, node: ASTNode, context: SemanticContext) -> bool:
        """Check if path is user-controlled"""
        return self._is_tainted(node, context)

    def _has_path_validation(self, node: ASTNode, context: SemanticContext) -> bool:
        """Check if path has validation"""
        # Simplified: assume no validation unless explicitly sanitized
        return self._is_sanitized(node, context)

    def _create_vulnerability(self, vuln_type: SemanticVulnerabilityType, pattern: Dict[str, Any],
                            node: ASTNode, context: SemanticContext) -> SemanticVulnerability:
        """Create vulnerability finding"""
        return SemanticVulnerability(
            vuln_type=vuln_type,
            location=node.location,
            severity=pattern['severity'],
            confidence=0.8,
            description=f"Potential {vuln_type.value} vulnerability detected",
            affected_variables=[node.name] if node.node_type == NodeType.VARIABLE else [],
            exploit_conditions=pattern['conditions'],
            remediation=self._get_remediation(vuln_type),
            cwe_id=self._get_cwe_id(vuln_type),
            metadata={'pattern': pattern['pattern']}
        )

    def _create_function_vulnerability(self, node: ASTNode, func_name: str,
                                     info: Dict[str, Any], context: SemanticContext) -> SemanticVulnerability:
        """Create vulnerability from dangerous function"""
        vuln_type_map = {
            'buffer_overflow': SemanticVulnerabilityType.BUFFER_OVERFLOW,
            'injection': SemanticVulnerabilityType.INJECTION,
            'path_traversal': SemanticVulnerabilityType.PATH_TRAVERSAL
        }

        vuln_type = vuln_type_map.get(info['vulnerability'], SemanticVulnerabilityType.BUFFER_OVERFLOW)

        return SemanticVulnerability(
            vuln_type=vuln_type,
            location=node.location,
            severity=info['risk'],
            confidence=0.9,
            description=f"Use of dangerous function {func_name}",
            affected_variables=[],
            exploit_conditions=[f"call_to_{func_name}"],
            remediation=f"Replace {func_name} with safer alternative",
            cwe_id=self._get_cwe_id(vuln_type),
            metadata={'dangerous_function': func_name}
        )

    def _get_remediation(self, vuln_type: SemanticVulnerabilityType) -> str:
        """Get remediation advice for vulnerability type"""
        remediation_map = {
            SemanticVulnerabilityType.NULL_POINTER_DEREFERENCE: "Add null checks before dereferencing pointers",
            SemanticVulnerabilityType.BUFFER_OVERFLOW: "Use bounds checking and safe string functions",
            SemanticVulnerabilityType.INJECTION: "Use parameterized queries and input sanitization",
            SemanticVulnerabilityType.PATH_TRAVERSAL: "Validate and sanitize file paths",
        }
        return remediation_map.get(vuln_type, "Review code for security issues")

    def _get_cwe_id(self, vuln_type: SemanticVulnerabilityType) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_map = {
            SemanticVulnerabilityType.NULL_POINTER_DEREFERENCE: "CWE-476",
            SemanticVulnerabilityType.BUFFER_OVERFLOW: "CWE-120",
            SemanticVulnerabilityType.INJECTION: "CWE-89",
            SemanticVulnerabilityType.PATH_TRAVERSAL: "CWE-22",
        }
        return cwe_map.get(vuln_type, "CWE-Unknown")

class APIUsageAnalyzer:
    """Analyzes API usage patterns"""

    def __init__(self):
        self.security_apis = self._load_security_apis()
        self.common_misuses = self._load_common_misuses()

    def _load_security_apis(self) -> Dict[str, Dict[str, Any]]:
        """Load security-relevant APIs"""
        return {
            'crypto': {
                'functions': ['encrypt', 'decrypt', 'hash', 'sign', 'verify'],
                'risk_level': 'high',
                'requirements': ['proper_key_management', 'secure_algorithms']
            },
            'auth': {
                'functions': ['login', 'authenticate', 'authorize', 'verify_token'],
                'risk_level': 'critical',
                'requirements': ['input_validation', 'session_management']
            },
            'file': {
                'functions': ['open', 'read', 'write', 'delete', 'chmod'],
                'risk_level': 'medium',
                'requirements': ['path_validation', 'permission_checks']
            }
        }

    def _load_common_misuses(self) -> Dict[str, List[str]]:
        """Load common API misuse patterns"""
        return {
            'crypto': [
                'hardcoded_keys',
                'weak_algorithms',
                'improper_iv_generation',
                'key_reuse'
            ],
            'auth': [
                'missing_validation',
                'weak_session_management',
                'privilege_escalation',
                'timing_attacks'
            ],
            'file': [
                'path_traversal',
                'permission_bypass',
                'race_conditions',
                'temp_file_vulnerabilities'
            ]
        }

    def analyze_api_usage(self, ast_node: ASTNode, context: SemanticContext) -> List[APIUsagePattern]:
        """Analyze API usage patterns"""
        patterns = []

        if ast_node.node_type == NodeType.CALL:
            pattern = self._analyze_function_call(ast_node, context)
            if pattern:
                patterns.append(pattern)

        for child in ast_node.children:
            patterns.extend(self.analyze_api_usage(child, context))

        return patterns

    def _analyze_function_call(self, call_node: ASTNode, context: SemanticContext) -> Optional[APIUsagePattern]:
        """Analyze individual function call"""
        func_name = call_node.name.lower()

        # Check if it's a security-relevant API
        for api_category, api_info in self.security_apis.items():
            if any(api_func in func_name for api_func in api_info['functions']):
                return self._create_api_pattern(call_node, api_category, api_info, context)

        return None

    def _create_api_pattern(self, call_node: ASTNode, api_category: str,
                          api_info: Dict[str, Any], context: SemanticContext) -> APIUsagePattern:
        """Create API usage pattern"""
        # Extract parameters (simplified)
        parameters = []
        for child in call_node.children:
            if child.node_type == NodeType.VARIABLE:
                parameters.append(child.name)

        # Check for potential misuse
        potential_misuse = None
        misuses = self.common_misuses.get(api_category, [])
        for misuse in misuses:
            if self._check_misuse_pattern(call_node, misuse, context):
                potential_misuse = misuse
                break

        return APIUsagePattern(
            api_name=call_node.name,
            usage_context=context.function_name,
            parameters=parameters,
            return_usage="unknown",  # Would need more analysis
            security_relevant=True,
            potential_misuse=potential_misuse
        )

    def _check_misuse_pattern(self, call_node: ASTNode, misuse: str, context: SemanticContext) -> bool:
        """Check for specific misuse pattern"""
        # Simplified misuse detection
        if misuse == 'hardcoded_keys':
            # Check if any parameter looks like a hardcoded key
            for child in call_node.children:
                if 'key' in child.name.lower() and '"' in child.name:
                    return True

        elif misuse == 'missing_validation':
            # Check if tainted input is used without validation
            for child in call_node.children:
                if self._is_tainted_without_validation(child, context):
                    return True

        return False

    def _is_tainted_without_validation(self, node: ASTNode, context: SemanticContext) -> bool:
        """Check if node is tainted without validation"""
        if node.node_type == NodeType.VARIABLE:
            var_type = context.variable_types.get(node.name)
            return (var_type and
                   var_type.taint_level > 0 and
                   len(var_type.sanitization_functions) == 0)
        return False

class SemanticAnalyzer:
    """Main semantic analysis engine"""

    def __init__(self, model_path: Optional[str] = None):
        self.type_inference = TypeInferenceEngine()
        self.pattern_matcher = VulnerabilityPatternMatcher()
        self.api_analyzer = APIUsageAnalyzer()

        if TRANSFORMERS_AVAILABLE and model_path:
            self.code_model = self._load_code_model(model_path)
        else:
            self.code_model = CodeEmbedding()

        self.semantic_cache = {}

    def _load_code_model(self, model_path: str):
        """Load pre-trained code model"""
        try:
            tokenizer = AutoTokenizer.from_pretrained(model_path)
            model = AutoModel.from_pretrained(model_path)
            return {'tokenizer': tokenizer, 'model': model}
        except Exception as e:
            logging.error(f"Failed to load code model: {e}")
            return CodeEmbedding()

    def analyze_semantics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Perform comprehensive semantic analysis"""
        semantic_results = {
            'vulnerabilities': [],
            'api_patterns': [],
            'type_information': {},
            'data_flows': [],
            'semantic_metrics': {}
        }

        # Analyze each function
        for function in analysis_result.functions:
            func_results = self._analyze_function_semantics(function, analysis_result)

            semantic_results['vulnerabilities'].extend(func_results['vulnerabilities'])
            semantic_results['api_patterns'].extend(func_results['api_patterns'])
            semantic_results['type_information'][function.name] = func_results['types']

        # Calculate semantic metrics
        semantic_results['semantic_metrics'] = self._calculate_semantic_metrics(semantic_results)

        return semantic_results

    def _analyze_function_semantics(self, function: Function, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Analyze semantics of individual function"""
        context = SemanticContext(
            function_name=function.name,
            variable_types={},
            call_stack=[function.name],
            taint_sources=self._identify_taint_sources(function),
            sinks=self._identify_sinks(function)
        )

        # Type inference and propagation
        self.type_inference.propagate_types(function.ast_node, context)

        # Vulnerability detection
        vulnerabilities = self._detect_vulnerabilities(function.ast_node, context)

        # API usage analysis
        api_patterns = self.api_analyzer.analyze_api_usage(function.ast_node, context)

        return {
            'vulnerabilities': vulnerabilities,
            'api_patterns': api_patterns,
            'types': context.variable_types
        }

    def _identify_taint_sources(self, function: Function) -> Set[str]:
        """Identify taint sources in function"""
        taint_sources = set()

        # Look for common taint sources
        taint_patterns = [
            'input', 'request', 'argv', 'stdin', 'recv', 'read',
            'get_param', 'get_input', 'user_input', 'form_data'
        ]

        def visit_node(node: ASTNode):
            if node.node_type == NodeType.CALL:
                for pattern in taint_patterns:
                    if pattern in node.name.lower():
                        # Mark variables assigned from this call as tainted
                        if node.parent and node.parent.node_type == NodeType.ASSIGNMENT:
                            for child in node.parent.children:
                                if child.node_type == NodeType.VARIABLE and child != node:
                                    taint_sources.add(child.name)

            for child in node.children:
                visit_node(child)

        visit_node(function.ast_node)
        return taint_sources

    def _identify_sinks(self, function: Function) -> Set[str]:
        """Identify sinks in function"""
        sinks = set()

        # Common sink patterns
        sink_patterns = [
            'execute', 'query', 'system', 'eval', 'exec',
            'write', 'print', 'log', 'send', 'output'
        ]

        def visit_node(node: ASTNode):
            if node.node_type == NodeType.CALL:
                for pattern in sink_patterns:
                    if pattern in node.name.lower():
                        sinks.add(node.name)

            for child in node.children:
                visit_node(child)

        visit_node(function.ast_node)
        return sinks

    def _detect_vulnerabilities(self, ast_node: ASTNode, context: SemanticContext) -> List[SemanticVulnerability]:
        """Detect semantic vulnerabilities"""
        vulnerabilities = []

        # Pattern-based detection
        pattern_vulns = self.pattern_matcher.match_patterns(ast_node, context)
        vulnerabilities.extend(pattern_vulns)

        # ML-based detection (if available)
        if hasattr(self.code_model, 'forward'):
            ml_vulns = self._detect_ml_vulnerabilities(ast_node, context)
            vulnerabilities.extend(ml_vulns)

        # Recursive analysis
        for child in ast_node.children:
            child_vulns = self._detect_vulnerabilities(child, context)
            vulnerabilities.extend(child_vulns)

        return vulnerabilities

    def _detect_ml_vulnerabilities(self, ast_node: ASTNode, context: SemanticContext) -> List[SemanticVulnerability]:
        """Detect vulnerabilities using ML model"""
        try:
            # Convert AST to tokens (simplified)
            tokens = self._ast_to_tokens(ast_node)

            if not tokens:
                return []

            # Tokenize for model
            token_ids = torch.tensor([hash(token) % 50000 for token in tokens[:512]])
            token_ids = token_ids.unsqueeze(0)  # Add batch dimension

            # Get model predictions
            with torch.no_grad():
                outputs = self.code_model(token_ids)
                vuln_scores = outputs['vulnerability_scores'].squeeze()

            # Create vulnerabilities for high-scoring predictions
            vulnerabilities = []
            for i, score in enumerate(vuln_scores):
                if score > 0.7:  # Threshold for vulnerability detection
                    vuln_type = list(SemanticVulnerabilityType)[i]
                    vuln = SemanticVulnerability(
                        vuln_type=vuln_type,
                        location=ast_node.location,
                        severity='medium',
                        confidence=float(score),
                        description=f"ML-detected {vuln_type.value}",
                        affected_variables=[],
                        exploit_conditions=['ml_prediction'],
                        remediation="Review code for potential vulnerability",
                        metadata={'ml_score': float(score)}
                    )
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            logging.error(f"ML vulnerability detection failed: {e}")
            return []

    def _ast_to_tokens(self, ast_node: ASTNode) -> List[str]:
        """Convert AST to token sequence"""
        tokens = []

        def visit_node(node: ASTNode):
            tokens.append(node.node_type.value)
            if node.name and node.name != node.node_type.value:
                tokens.append(node.name)

            for child in node.children:
                visit_node(child)

        visit_node(ast_node)
        return tokens

    def _calculate_semantic_metrics(self, semantic_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate semantic complexity metrics"""
        vulnerabilities = semantic_results['vulnerabilities']
        api_patterns = semantic_results['api_patterns']

        metrics = {
            'vulnerability_density': len(vulnerabilities),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high_vulnerabilities': len([v for v in vulnerabilities if v.severity == 'high']),
            'security_api_usage': len([p for p in api_patterns if p.security_relevant]),
            'potential_misuses': len([p for p in api_patterns if p.potential_misuse]),
            'average_confidence': sum(v.confidence for v in vulnerabilities) / max(len(vulnerabilities), 1)
        }

        return metrics

    def generate_semantic_report(self, semantic_results: Dict[str, Any], file_path: str) -> str:
        """Generate comprehensive semantic analysis report"""
        report = []
        report.append(f"Semantic Analysis Report: {Path(file_path).name}")
        report.append("=" * 60)

        vulnerabilities = semantic_results['vulnerabilities']
        api_patterns = semantic_results['api_patterns']
        metrics = semantic_results['semantic_metrics']

        # Summary
        report.append("Summary:")
        report.append(f"  Total Vulnerabilities: {len(vulnerabilities)}")
        report.append(f"  Critical: {metrics.get('critical_vulnerabilities', 0)}")
        report.append(f"  High: {metrics.get('high_vulnerabilities', 0)}")
        report.append(f"  Security API Usage: {metrics.get('security_api_usage', 0)}")
        report.append("")

        # Vulnerability details
        if vulnerabilities:
            report.append("Vulnerabilities:")
            report.append("-" * 20)

            # Group by type
            vuln_by_type = defaultdict(list)
            for vuln in vulnerabilities:
                vuln_by_type[vuln.vuln_type].append(vuln)

            for vuln_type, vulns in vuln_by_type.items():
                report.append(f"{vuln_type.value} ({len(vulns)} instances):")
                for vuln in vulns[:3]:  # Show top 3 per type
                    report.append(f"  Line {vuln.location.line}: {vuln.description}")
                    report.append(f"    Severity: {vuln.severity}, Confidence: {vuln.confidence:.2f}")
                    if vuln.cwe_id:
                        report.append(f"    CWE: {vuln.cwe_id}")
                    report.append(f"    Remediation: {vuln.remediation}")
                    report.append("")

        # API usage patterns
        if api_patterns:
            report.append("Security-Relevant API Usage:")
            report.append("-" * 30)
            for pattern in api_patterns[:10]:  # Show top 10
                report.append(f"  {pattern.api_name} in {pattern.usage_context}")
                if pattern.potential_misuse:
                    report.append(f"    Potential misuse: {pattern.potential_misuse}")
                report.append("")

        return "\n".join(report)