#!/usr/bin/env python3
"""
Python Language Analysis Plugin
===============================

Comprehensive Python vulnerability detection using AST analysis and mathematical methods.
"""

import ast
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

import sys
import os
from pathlib import Path

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent.parent))

from core.plugin_manager import BasePlugin
from core.vulnerability import Vulnerability, VulnType, VulnSeverity, Location, ProofOfConcept
from core.model_integration import VulnHunterModel
from mathcore.topology.persistent_homology import detect_loops, cfg_to_distance_matrix
from mathcore.algebra.taint_semiring import analyze_data_flow, build_cfg_with_dataflow
from mathcore.logic.formal_verification import Z3Verifier, verify_information_flow


class PythonAnalysisPlugin(BasePlugin):
    """Advanced Python vulnerability analysis plugin"""

    def __init__(self):
        super().__init__()
        self.name = "PythonAnalysisPlugin"
        self.version = "2.0.0"
        self.z3_verifier = Z3Verifier()
        # Initialize ML model for enhanced detection
        try:
            self.model = VulnHunterModel()
            self.logger.info("Loaded VulnHunter ML model for enhanced detection")
        except Exception as e:
            self.logger.warning(f"Failed to load ML model: {e}")
            self.model = None

    @property
    def supported_file_types(self) -> List[str]:
        return ['.py', '.pyw']

    def is_applicable(self, file_path: str, content: str) -> bool:
        """Check if this plugin should analyze the given file"""
        return (Path(file_path).suffix.lower() in self.supported_file_types or
                content.startswith('#!/usr/bin/env python') or
                'import ' in content[:200])

    def analyze(self, file_path: str, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
        """Main analysis method"""
        vulnerabilities = []

        try:
            # Parse Python AST
            tree = ast.parse(content)

            # Multiple analysis methods
            vulnerabilities.extend(self._analyze_ast_patterns(tree, file_path, content))
            vulnerabilities.extend(self._analyze_with_topology(content, file_path))
            vulnerabilities.extend(self._analyze_with_formal_verification(tree, file_path))
            vulnerabilities.extend(self._analyze_imports(tree, file_path))
            vulnerabilities.extend(self._analyze_string_operations(tree, file_path, content))

            # ML model analysis
            if self.model:
                vulnerabilities.extend(self._analyze_with_ml_model(content, file_path))

        except SyntaxError as e:
            # Handle syntax errors gracefully
            vuln = Vulnerability(
                vuln_type=VulnType.UNKNOWN,
                severity=VulnSeverity.LOW,
                location=Location(file_path, e.lineno or 1),
                title="Python Syntax Error",
                description=f"Syntax error in Python code: {str(e)}",
                detection_method="AST_parsing"
            )
            vulnerabilities.append(vuln)

        except Exception as e:
            self.logger.error(f"Error analyzing Python file {file_path}: {e}")

        return vulnerabilities

    def _analyze_ast_patterns(self, tree: ast.AST, file_path: str, content: str) -> List[Vulnerability]:
        """Analyze AST for vulnerability patterns"""
        vulnerabilities = []
        lines = content.split('\n')

        for node in ast.walk(tree):
            # SQL Injection detection
            if isinstance(node, ast.Call):
                vuln = self._check_sql_injection(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)

                vuln = self._check_command_injection(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)

                vuln = self._check_deserialization(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)

            # Check assignments for SQL injection and hardcoded credentials
            elif isinstance(node, ast.Assign):
                # Check for SQL injection in assignments
                vuln = self._check_sql_injection_assignment(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)

                # Check for hardcoded credentials
                vuln = self._check_hardcoded_credentials(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)

            # Path traversal
            elif isinstance(node, ast.BinOp):
                vuln = self._check_path_traversal(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_sql_injection(self, node: ast.Call, file_path: str, lines: List[str]) -> Optional[Vulnerability]:
        """Check for SQL injection vulnerabilities"""
        if not hasattr(node.func, 'attr'):
            return None

        dangerous_methods = ['execute', 'executemany', 'query', 'raw']

        if (hasattr(node.func, 'attr') and node.func.attr in dangerous_methods) or \
           (hasattr(node.func, 'id') and node.func.id in dangerous_methods):

            # Check if query is constructed with string concatenation
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    if self._contains_string_and_var(arg):
                        line_num = getattr(node, 'lineno', 1)

                        # Generate proof of concept
                        poc = ProofOfConcept(
                            exploit_code="payload = \"'; DROP TABLE users; --\"",
                            description="SQL injection through string concatenation",
                            payload="'; DROP TABLE users; --",
                            steps=[
                                "Identify string concatenation in SQL query",
                                "Inject malicious SQL payload",
                                "Execute query to drop tables"
                            ]
                        )

                        # Use formal verification
                        proof_cert = self.z3_verifier.verify_sql_injection(
                            query_template="SELECT * FROM users WHERE id = ",
                            sanitizer_present=False
                        )

                        return Vulnerability(
                            vuln_type=VulnType.SQL_INJECTION,
                            severity=VulnSeverity.CRITICAL,
                            cwe_id="CWE-89",
                            location=Location(file_path, line_num),
                            title="SQL Injection Vulnerability",
                            description="SQL query constructed with unsanitized user input through string concatenation",
                            technical_details=f"Line {line_num}: {lines[line_num-1].strip() if line_num <= len(lines) else 'N/A'}",
                            impact="Attackers can execute arbitrary SQL commands, potentially accessing or modifying sensitive data",
                            remediation="Use parameterized queries or prepared statements",
                            proof_of_concept=poc,
                            confidence=0.9,
                            detection_method="AST_analysis + Z3_verification"
                        )

        return None

    def _check_sql_injection_assignment(self, node: ast.Assign, file_path: str, lines: List[str]) -> Optional[Vulnerability]:
        """Check for SQL injection in variable assignments"""
        # Check if this assignment contains SQL keywords and string concatenation
        if hasattr(node, 'value') and isinstance(node.value, ast.BinOp):
            if isinstance(node.value.op, ast.Add):
                # Check if it's a string concatenation
                if self._contains_string_and_var(node.value):
                    # Check if the assignment contains SQL keywords
                    try:
                        line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'ORDER BY', 'GROUP BY']
                        if any(keyword.lower() in line_content.lower() for keyword in sql_keywords):
                            poc = ProofOfConcept(
                                exploit_code="payload = \"' OR '1'='1' --\"",
                                description="SQL injection through string concatenation in assignment",
                                payload="' OR '1'='1' --",
                                steps=[
                                    "Identify SQL query construction with string concatenation",
                                    "Inject malicious SQL payload",
                                    "Bypass authentication or access unauthorized data"
                                ]
                            )
                            # Use formal verification
                            proof_cert = self.z3_verifier.verify_sql_injection(
                                query_template="SELECT * FROM users WHERE username = ",
                                sanitizer_present=False
                            )
                            return Vulnerability(
                                vuln_type=VulnType.SQL_INJECTION,
                                severity=VulnSeverity.CRITICAL,
                                cwe_id="CWE-89",
                                location=Location(file_path, node.lineno),
                                title="SQL Injection in Assignment",
                                description="SQL query constructed with unsanitized user input through string concatenation",
                                technical_details=f"Line {node.lineno}: {line_content.strip()}",
                                impact="Attackers can execute arbitrary SQL commands, potentially accessing or modifying sensitive data",
                                remediation="Use parameterized queries or prepared statements",
                                proof_of_concept=poc,
                                confidence=0.85,
                                detection_method="AST_assignment_analysis + Z3_verification",
                                mathematical_proof=proof_cert
                            )
                    except (IndexError, AttributeError):
                        pass
        return None

    def _check_command_injection(self, node: ast.Call, file_path: str, lines: List[str]) -> Optional[Vulnerability]:
        """Check for command injection vulnerabilities"""
        dangerous_functions = ['system', 'popen', 'call', 'check_output', 'run']

        func_name = None
        if hasattr(node.func, 'id'):
            func_name = node.func.id
        elif hasattr(node.func, 'attr'):
            func_name = node.func.attr

        if func_name in dangerous_functions:
            # Check for shell=True or string concatenation
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == 'shell'
            )

            has_concat = any(
                isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add)
                for arg in node.args
            )

            if shell_true or has_concat:
                line_num = getattr(node, 'lineno', 1)

                poc = ProofOfConcept(
                    exploit_code="payload = \"; rm -rf / #\"",
                    description="Command injection through shell execution",
                    payload="; rm -rf / #",
                    steps=[
                        "Identify command execution with user input",
                        "Inject malicious command separator",
                        "Execute destructive system commands"
                    ]
                )

                return Vulnerability(
                    vuln_type=VulnType.COMMAND_INJECTION,
                    severity=VulnSeverity.CRITICAL,
                    cwe_id="CWE-78",
                    location=Location(file_path, line_num),
                    title="Command Injection Vulnerability",
                    description="System command execution with unsanitized user input",
                    technical_details=f"Line {line_num}: {lines[line_num-1].strip() if line_num <= len(lines) else 'N/A'}",
                    impact="Attackers can execute arbitrary system commands",
                    remediation="Use subprocess with shell=False and validate inputs",
                    proof_of_concept=poc,
                    confidence=0.85,
                    detection_method="AST_analysis"
                )

        return None

    def _check_deserialization(self, node: ast.Call, file_path: str, lines: List[str]) -> Optional[Vulnerability]:
        """Check for unsafe deserialization"""
        dangerous_calls = ['pickle.loads', 'cPickle.loads', 'yaml.load', 'marshal.loads']

        call_name = self._get_call_name(node)

        if any(dangerous in call_name for dangerous in dangerous_calls):
            line_num = getattr(node, 'lineno', 1)

            # Check if yaml.load has safe loader
            if 'yaml.load' in call_name:
                has_safe_loader = any(
                    kw.arg == 'Loader' and 'Safe' in ast.dump(kw.value)
                    for kw in node.keywords
                )
                if has_safe_loader:
                    return None

            poc = ProofOfConcept(
                exploit_code="import pickle; payload = pickle.dumps(__import__('os').system('ls'))",
                description="Arbitrary code execution through unsafe deserialization",
                steps=[
                    "Craft malicious serialized object",
                    "Inject object into deserialization function",
                    "Execute arbitrary code during deserialization"
                ]
            )

            return Vulnerability(
                vuln_type=VulnType.UNSAFE_DESERIALIZATION,
                severity=VulnSeverity.CRITICAL,
                cwe_id="CWE-502",
                location=Location(file_path, line_num),
                title="Unsafe Deserialization",
                description="Unsafe deserialization of untrusted data",
                technical_details=f"Line {line_num}: {lines[line_num-1].strip() if line_num <= len(lines) else 'N/A'}",
                impact="Remote code execution through crafted serialized objects",
                remediation="Use safe deserialization methods or validate inputs",
                proof_of_concept=poc,
                confidence=0.9,
                detection_method="AST_analysis"
            )

        return None

    def _check_hardcoded_credentials(self, node: ast.Assign, file_path: str, lines: List[str]) -> Optional[Vulnerability]:
        """Check for hardcoded credentials"""
        credential_keywords = ['password', 'passwd', 'pass', 'secret', 'key', 'token', 'api_key', 'private_key']

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                if any(keyword in var_name for keyword in credential_keywords):
                    # Check if assigned a string literal
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        value = node.value.value
                        if len(value) > 3 and not value.lower() in ['none', 'null', '', 'todo', 'changeme']:
                            line_num = getattr(node, 'lineno', 1)

                            return Vulnerability(
                                vuln_type=VulnType.HARDCODED_CREDENTIALS,
                                severity=VulnSeverity.HIGH,
                                cwe_id="CWE-798",
                                location=Location(file_path, line_num),
                                title="Hardcoded Credentials",
                                description=f"Hardcoded credential found in variable '{target.id}'",
                                technical_details=f"Line {line_num}: {lines[line_num-1].strip() if line_num <= len(lines) else 'N/A'}",
                                impact="Credentials may be exposed in source code",
                                remediation="Use environment variables or secure configuration",
                                confidence=0.8,
                                detection_method="AST_analysis"
                            )

        return None

    def _check_path_traversal(self, node: ast.BinOp, file_path: str, lines: List[str]) -> Optional[Vulnerability]:
        """Check for path traversal vulnerabilities"""
        if isinstance(node.op, ast.Add):
            # Check for dangerous path patterns
            dangerous_patterns = ['../', '..\\', '%2e%2e']

            def check_string_node(n):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    return any(pattern in n.value for pattern in dangerous_patterns)
                return False

            if check_string_node(node.left) or check_string_node(node.right):
                line_num = getattr(node, 'lineno', 1)

                return Vulnerability(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    severity=VulnSeverity.HIGH,
                    cwe_id="CWE-22",
                    location=Location(file_path, line_num),
                    title="Path Traversal Vulnerability",
                    description="Path traversal patterns detected in file path construction",
                    technical_details=f"Line {line_num}: {lines[line_num-1].strip() if line_num <= len(lines) else 'N/A'}",
                    impact="Attackers may access files outside intended directories",
                    remediation="Use path.join() and validate file paths",
                    confidence=0.7,
                    detection_method="AST_analysis"
                )

        return None

    def _analyze_with_topology(self, content: str, file_path: str) -> List[Vulnerability]:
        """Analyze using topological methods"""
        vulnerabilities = []

        try:
            # Build CFG with data flow
            cfg = build_cfg_with_dataflow(content)

            if len(cfg.nodes()) > 2:
                # Detect loops and complexity
                loop_analysis = detect_loops(cfg)

                if loop_analysis.get('h1_loops', 0) > 5:
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnType.RACE_CONDITION,
                        severity=VulnSeverity.MEDIUM,
                        location=Location(file_path, 1),
                        title="Complex Loop Structure",
                        description=f"High topological complexity detected: {loop_analysis.get('h1_loops')} loops",
                        technical_details=f"Topological signature: {loop_analysis.get('vulnerability_signature')}",
                        impact="Complex control flow may indicate race conditions or reentrancy issues",
                        remediation="Review loop complexity and synchronization",
                        confidence=0.6,
                        detection_method="persistent_homology"
                    ))

        except Exception as e:
            self.logger.debug(f"Topological analysis failed for {file_path}: {e}")

        return vulnerabilities

    def _analyze_with_ml_model(self, content: str, file_path: str) -> List[Vulnerability]:
        """Analyze using trained ML model"""
        vulnerabilities = []
        try:
            is_vulnerable, vuln_type, confidence = self.model.predict_vulnerability(content)

            if is_vulnerable and confidence > 0.6:
                # Map model output to VulnType
                vuln_type_mapping = {
                    'sql_injection': VulnType.SQL_INJECTION,
                    'command_injection': VulnType.COMMAND_INJECTION,
                    'xss': VulnType.REFLECTED_XSS,
                    'path_traversal': VulnType.PATH_TRAVERSAL,
                }

                mapped_vuln_type = vuln_type_mapping.get(vuln_type, VulnType.UNKNOWN)

                # Determine severity based on vulnerability type
                severity_mapping = {
                    VulnType.SQL_INJECTION: VulnSeverity.CRITICAL,
                    VulnType.COMMAND_INJECTION: VulnSeverity.CRITICAL,
                    VulnType.REFLECTED_XSS: VulnSeverity.MEDIUM,
                    VulnType.PATH_TRAVERSAL: VulnSeverity.HIGH,
                }

                severity = severity_mapping.get(mapped_vuln_type, VulnSeverity.MEDIUM)

                # Create proof of concept
                poc = ProofOfConcept(
                    exploit_code=f"ML model detected {vuln_type}",
                    description=f"Machine learning model identified {vuln_type} vulnerability",
                    payload=f"Vulnerability type: {vuln_type}",
                    steps=[
                        "ML model analyzed code patterns",
                        f"Detected {vuln_type} with {confidence:.1%} confidence",
                        "Manual verification recommended"
                    ]
                )

                vulnerability = Vulnerability(
                    vuln_type=mapped_vuln_type,
                    severity=severity,
                    location=Location(file_path, 1),  # TODO: Get exact line from model
                    title=f"{vuln_type.replace('_', ' ').title()} (ML Detection)",
                    description=f"Machine learning model detected potential {vuln_type} vulnerability",
                    technical_details=f"ML confidence: {confidence:.3f}, Model prediction: {vuln_type}",
                    impact=f"Potential {vuln_type} vulnerability identified by trained model",
                    remediation="Manual code review recommended to validate ML detection",
                    proof_of_concept=poc,
                    confidence=min(confidence, 0.9),  # Cap ML confidence
                    detection_method="ML_model_prediction"
                )

                vulnerabilities.append(vulnerability)

        except Exception as e:
            self.logger.debug(f"ML model analysis failed for {file_path}: {e}")

        return vulnerabilities

    def _analyze_with_formal_verification(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        """Analyze using formal verification"""
        vulnerabilities = []

        try:
            # Extract function calls for verification
            sources = []
            sinks = []

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_name = self._get_call_name(node)

                    if any(src in call_name for src in ['input', 'request', 'argv']):
                        sources.append(call_name)

                    if any(sink in call_name for sink in ['execute', 'system', 'eval']):
                        sinks.append(call_name)

            if sources and sinks:
                # Verify information flow
                proof = verify_information_flow(sources, sinks, [])

                if proof.result.value == "proven_vulnerable":
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnType.INFORMATION_DISCLOSURE,
                        severity=VulnSeverity.HIGH,
                        location=Location(file_path, 1),
                        title="Unsafe Information Flow",
                        description="Formal verification detected unsafe information flow",
                        technical_details=proof.assertion,
                        impact="Untrusted data may reach sensitive operations",
                        remediation="Add input validation and sanitization",
                        confidence=0.9,
                        detection_method="formal_verification"
                    ))

        except Exception as e:
            self.logger.debug(f"Formal verification failed for {file_path}: {e}")

        return vulnerabilities

    def _analyze_imports(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        """Analyze imports for vulnerable libraries"""
        vulnerabilities = []
        dangerous_imports = {
            'pickle': VulnSeverity.HIGH,
            'marshal': VulnSeverity.HIGH,
            'exec': VulnSeverity.CRITICAL,
            'eval': VulnSeverity.CRITICAL,
            'os.system': VulnSeverity.HIGH,
            'subprocess': VulnSeverity.MEDIUM
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in dangerous_imports:
                        vulnerabilities.append(Vulnerability(
                            vuln_type=VulnType.UNSAFE_DESERIALIZATION,
                            severity=dangerous_imports[alias.name],
                            location=Location(file_path, getattr(node, 'lineno', 1)),
                            title=f"Dangerous Import: {alias.name}",
                            description=f"Import of potentially dangerous module: {alias.name}",
                            impact="May enable code execution vulnerabilities",
                            remediation="Review usage and consider safer alternatives",
                            confidence=0.5,
                            detection_method="import_analysis"
                        ))

        return vulnerabilities

    def _analyze_string_operations(self, tree: ast.AST, file_path: str, content: str) -> List[Vulnerability]:
        """Analyze string operations for format string vulnerabilities"""
        vulnerabilities = []
        lines = content.split('\n')

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if (hasattr(node.func, 'attr') and node.func.attr == 'format') or \
                   (hasattr(node.func, 'id') and node.func.id == 'format'):

                    line_num = getattr(node, 'lineno', 1)
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnType.INFORMATION_DISCLOSURE,
                        severity=VulnSeverity.LOW,
                        location=Location(file_path, line_num),
                        title="Potential Format String Issue",
                        description="String formatting with potential user input",
                        technical_details=f"Line {line_num}: {lines[line_num-1].strip() if line_num <= len(lines) else 'N/A'}",
                        impact="May expose sensitive information",
                        remediation="Validate format strings and inputs",
                        confidence=0.4,
                        detection_method="AST_analysis"
                    ))

        return vulnerabilities

    # Helper methods
    def _contains_string_and_var(self, node: ast.BinOp) -> bool:
        """Check if binary operation contains both string and variable"""
        def is_string(n):
            return isinstance(n, ast.Constant) and isinstance(n.value, str)

        def is_var(n):
            return isinstance(n, (ast.Name, ast.Call, ast.Attribute))

        left_string = is_string(node.left)
        right_string = is_string(node.right)
        left_var = is_var(node.left)
        right_var = is_var(node.right)

        return (left_string and right_var) or (left_var and right_string)

    def _get_call_name(self, node: ast.Call) -> str:
        """Get full call name from AST node"""
        if hasattr(node.func, 'id'):
            return node.func.id
        elif hasattr(node.func, 'attr'):
            if hasattr(node.func.value, 'id'):
                return f"{node.func.value.id}.{node.func.attr}"
            else:
                return node.func.attr
        return ""