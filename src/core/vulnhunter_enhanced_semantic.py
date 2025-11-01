#!/usr/bin/env python3
"""
VulnHunter Enhanced Semantic Analysis System
Advanced semantic understanding for vulnerability detection
"""

import ast
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path

class SemanticRiskLevel(Enum):
    """Risk levels for semantic analysis"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SemanticFinding:
    """Represents a semantic analysis finding"""
    risk_level: SemanticRiskLevel
    category: str
    description: str
    line_number: int
    column: int
    code_snippet: str
    confidence: float
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class SemanticPatterns:
    """Collection of semantic vulnerability patterns"""

    INJECTION_PATTERNS = {
        "sql_injection": [
            r"execute\s*\(\s*['\"].*%.*['\"]",
            r"query\s*\(\s*['\"].*\+.*['\"]",
            r"cursor\.execute\s*\(\s*[^?].*%",
        ],
        "command_injection": [
            r"os\.system\s*\(",
            r"subprocess\.(call|run|Popen)\s*\([^,]*shell\s*=\s*True",
            r"eval\s*\(",
            r"exec\s*\(",
        ],
        "code_injection": [
            r"eval\s*\(",
            r"exec\s*\(",
            r"compile\s*\(",
            r"__import__\s*\(",
        ]
    }

    CRYPTO_PATTERNS = {
        "weak_crypto": [
            r"hashlib\.(md5|sha1)\(",
            r"Cipher\.new\([^,]*,\s*DES\.",
            r"Random\.new\(\)\.read\(",
        ],
        "hardcoded_secrets": [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
        ]
    }

    BUFFER_PATTERNS = {
        "buffer_overflow": [
            r"strcpy\s*\(",
            r"strcat\s*\(",
            r"gets\s*\(",
            r"sprintf\s*\(",
        ],
        "format_string": [
            r"printf\s*\([^,]*%[^,)]*\)",
            r"sprintf\s*\([^,]*%[^,)]*\)",
        ]
    }

class SemanticAnalyzer:
    """Advanced semantic analyzer for vulnerability detection"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = SemanticPatterns()
        self.findings: List[SemanticFinding] = []

    def analyze_code(self, code: str, language: str = "python") -> List[SemanticFinding]:
        """Perform comprehensive semantic analysis"""
        self.findings = []

        try:
            # Multi-layer analysis
            self._pattern_analysis(code, language)
            self._ast_analysis(code, language)
            self._data_flow_analysis(code, language)
            self._control_flow_analysis(code, language)

            return self.findings

        except Exception as e:
            self.logger.error(f"Semantic analysis failed: {e}")
            return []

    def _pattern_analysis(self, code: str, language: str):
        """Pattern-based vulnerability detection"""
        lines = code.split('\n')

        all_patterns = {
            **self.patterns.INJECTION_PATTERNS,
            **self.patterns.CRYPTO_PATTERNS,
            **self.patterns.BUFFER_PATTERNS
        }

        for category, patterns in all_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        risk_level = self._determine_risk_level(category)
                        confidence = self._calculate_confidence(category, match.group())

                        finding = SemanticFinding(
                            risk_level=risk_level,
                            category=category,
                            description=f"Potential {category.replace('_', ' ')} vulnerability",
                            line_number=line_num,
                            column=match.start(),
                            code_snippet=line.strip(),
                            confidence=confidence,
                            cwe_id=self._get_cwe_id(category),
                            remediation=self._get_remediation(category)
                        )

                        self.findings.append(finding)

    def _ast_analysis(self, code: str, language: str):
        """AST-based semantic analysis"""
        if language.lower() != "python":
            return  # AST analysis currently only for Python

        try:
            tree = ast.parse(code)
            visitor = VulnerabilityASTVisitor()
            visitor.visit(tree)

            for vuln in visitor.vulnerabilities:
                finding = SemanticFinding(
                    risk_level=vuln["risk_level"],
                    category=vuln["category"],
                    description=vuln["description"],
                    line_number=vuln["line_number"],
                    column=vuln.get("column", 0),
                    code_snippet=vuln["code_snippet"],
                    confidence=vuln["confidence"],
                    cwe_id=vuln.get("cwe_id"),
                    metadata={"ast_node": vuln.get("node_type")}
                )
                self.findings.append(finding)

        except SyntaxError:
            self.logger.debug("AST parsing failed - likely invalid Python code")
        except Exception as e:
            self.logger.error(f"AST analysis error: {e}")

    def _data_flow_analysis(self, code: str, language: str):
        """Data flow analysis for taint tracking"""
        # Simplified data flow analysis
        lines = code.split('\n')
        tainted_vars = set()

        for line_num, line in enumerate(lines, 1):
            # Check for input sources
            if any(pattern in line.lower() for pattern in ['input(', 'request.', 'argv', 'environ']):
                # Extract variable names being assigned
                if '=' in line:
                    var_name = line.split('=')[0].strip()
                    tainted_vars.add(var_name)

            # Check for dangerous sinks with tainted data
            for var in tainted_vars:
                if var in line and any(sink in line for sink in ['eval(', 'exec(', 'os.system(']):
                    finding = SemanticFinding(
                        risk_level=SemanticRiskLevel.HIGH,
                        category="taint_flow",
                        description=f"Tainted data from user input flows to dangerous sink",
                        line_number=line_num,
                        column=0,
                        code_snippet=line.strip(),
                        confidence=0.85,
                        cwe_id="CWE-94",
                        metadata={"tainted_variable": var}
                    )
                    self.findings.append(finding)

    def _control_flow_analysis(self, code: str, language: str):
        """Control flow analysis for logic vulnerabilities"""
        lines = code.split('\n')

        # Check for missing input validation
        for line_num, line in enumerate(lines, 1):
            if any(pattern in line.lower() for pattern in ['input(', 'request.get', 'argv']):
                # Look for validation in next few lines
                has_validation = False
                for check_line in lines[line_num:line_num+3]:
                    if any(val in check_line.lower() for val in ['if', 'len(', 'isinstance(', 'validate']):
                        has_validation = True
                        break

                if not has_validation:
                    finding = SemanticFinding(
                        risk_level=SemanticRiskLevel.MEDIUM,
                        category="missing_validation",
                        description="User input without apparent validation",
                        line_number=line_num,
                        column=0,
                        code_snippet=line.strip(),
                        confidence=0.6,
                        cwe_id="CWE-20"
                    )
                    self.findings.append(finding)

    def _determine_risk_level(self, category: str) -> SemanticRiskLevel:
        """Determine risk level based on vulnerability category"""
        risk_mapping = {
            "sql_injection": SemanticRiskLevel.HIGH,
            "command_injection": SemanticRiskLevel.CRITICAL,
            "code_injection": SemanticRiskLevel.CRITICAL,
            "weak_crypto": SemanticRiskLevel.MEDIUM,
            "hardcoded_secrets": SemanticRiskLevel.HIGH,
            "buffer_overflow": SemanticRiskLevel.CRITICAL,
            "format_string": SemanticRiskLevel.HIGH,
        }
        return risk_mapping.get(category, SemanticRiskLevel.LOW)

    def _calculate_confidence(self, category: str, match_text: str) -> float:
        """Calculate confidence score for finding"""
        base_confidence = {
            "sql_injection": 0.8,
            "command_injection": 0.9,
            "code_injection": 0.85,
            "weak_crypto": 0.7,
            "hardcoded_secrets": 0.6,
            "buffer_overflow": 0.95,
            "format_string": 0.8,
        }

        confidence = base_confidence.get(category, 0.5)

        # Adjust based on context
        if "user" in match_text.lower() or "input" in match_text.lower():
            confidence += 0.1

        return min(confidence, 1.0)

    def _get_cwe_id(self, category: str) -> Optional[str]:
        """Get CWE ID for vulnerability category"""
        cwe_mapping = {
            "sql_injection": "CWE-89",
            "command_injection": "CWE-78",
            "code_injection": "CWE-94",
            "weak_crypto": "CWE-327",
            "hardcoded_secrets": "CWE-798",
            "buffer_overflow": "CWE-120",
            "format_string": "CWE-134",
        }
        return cwe_mapping.get(category)

    def _get_remediation(self, category: str) -> Optional[str]:
        """Get remediation advice for vulnerability category"""
        remediation_mapping = {
            "sql_injection": "Use parameterized queries or prepared statements",
            "command_injection": "Avoid shell=True, use subprocess with argument lists",
            "code_injection": "Never use eval/exec with user input, use safe alternatives",
            "weak_crypto": "Use strong cryptographic algorithms (SHA-256, AES)",
            "hardcoded_secrets": "Use environment variables or secure key management",
            "buffer_overflow": "Use safe string functions (strncpy, strncat)",
            "format_string": "Use format specifiers properly, validate format strings",
        }
        return remediation_mapping.get(category)

class VulnerabilityASTVisitor(ast.NodeVisitor):
    """AST visitor for Python vulnerability detection"""

    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        """Visit function calls"""
        func_name = self._get_function_name(node)

        # Check for dangerous functions
        dangerous_functions = {
            "eval": ("code_injection", "Use of eval() with potential user input"),
            "exec": ("code_injection", "Use of exec() with potential user input"),
            "compile": ("code_injection", "Use of compile() with potential user input"),
            "__import__": ("code_injection", "Dynamic import with potential user input"),
        }

        if func_name in dangerous_functions:
            category, description = dangerous_functions[func_name]
            self.vulnerabilities.append({
                "risk_level": SemanticRiskLevel.HIGH,
                "category": category,
                "description": description,
                "line_number": node.lineno,
                "column": node.col_offset,
                "code_snippet": f"{func_name}(...)",
                "confidence": 0.8,
                "cwe_id": "CWE-94",
                "node_type": "Call"
            })

        self.generic_visit(node)

    def visit_Attribute(self, node):
        """Visit attribute access"""
        if isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr == "system":
                self.vulnerabilities.append({
                    "risk_level": SemanticRiskLevel.CRITICAL,
                    "category": "command_injection",
                    "description": "Use of os.system() - potential command injection",
                    "line_number": node.lineno,
                    "column": node.col_offset,
                    "code_snippet": "os.system(...)",
                    "confidence": 0.9,
                    "cwe_id": "CWE-78",
                    "node_type": "Attribute"
                })

        self.generic_visit(node)

    def _get_function_name(self, node):
        """Extract function name from call node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

class VulnHunterEnhancedSemantic:
    """Main enhanced semantic analysis system"""

    def __init__(self):
        self.analyzer = SemanticAnalyzer()
        self.logger = logging.getLogger(__name__)

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file"""
        try:
            path = Path(file_path)
            language = self._detect_language(path)

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            findings = self.analyzer.analyze_code(code, language)

            return {
                "file_path": str(path),
                "language": language,
                "findings_count": len(findings),
                "findings": [self._finding_to_dict(f) for f in findings],
                "risk_summary": self._calculate_risk_summary(findings)
            }

        except Exception as e:
            self.logger.error(f"File analysis failed for {file_path}: {e}")
            return {"error": str(e), "file_path": file_path}

    def _detect_language(self, path: Path) -> str:
        """Detect programming language from file extension"""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".go": "go",
            ".rs": "rust",
            ".php": "php",
            ".rb": "ruby",
        }
        return extension_map.get(path.suffix.lower(), "unknown")

    def _finding_to_dict(self, finding: SemanticFinding) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "risk_level": finding.risk_level.value,
            "category": finding.category,
            "description": finding.description,
            "line_number": finding.line_number,
            "column": finding.column,
            "code_snippet": finding.code_snippet,
            "confidence": finding.confidence,
            "cwe_id": finding.cwe_id,
            "remediation": finding.remediation,
            "metadata": finding.metadata
        }

    def _calculate_risk_summary(self, findings: List[SemanticFinding]) -> Dict[str, int]:
        """Calculate risk summary statistics"""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in findings:
            summary[finding.risk_level.value] += 1

        return summary

# Global semantic analyzer instance
_semantic_system = None

def get_semantic_system() -> VulnHunterEnhancedSemantic:
    """Get or create global semantic system instance"""
    global _semantic_system
    if _semantic_system is None:
        _semantic_system = VulnHunterEnhancedSemantic()
    return _semantic_system

def analyze_code_semantics(code: str, language: str = "python") -> List[Dict[str, Any]]:
    """Quick semantic analysis of code"""
    semantic_system = get_semantic_system()
    findings = semantic_system.analyzer.analyze_code(code, language)
    return [semantic_system._finding_to_dict(f) for f in findings]

if __name__ == "__main__":
    # Test the semantic system
    test_code = """
import os
import subprocess

def dangerous_function(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")

    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"

    # Code injection vulnerability
    eval(user_input)

    return "Done"
"""

    semantic = VulnHunterEnhancedSemantic()
    findings = semantic.analyzer.analyze_code(test_code, "python")

    print("Enhanced Semantic Analysis Results:")
    for finding in findings:
        print(f"- {finding.risk_level.value.upper()}: {finding.description}")
        print(f"  Line {finding.line_number}: {finding.code_snippet}")
        print(f"  Confidence: {finding.confidence:.2f}")
        if finding.cwe_id:
            print(f"  CWE: {finding.cwe_id}")
        print()