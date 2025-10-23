#!/usr/bin/env python3
"""
VulnHunter V17 Multi-Language Intelligence
Phase 2: Universal Code Analysis with Tree-sitter Integration
"""

import json
import ast
import re
import hashlib
import subprocess
import tempfile
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Tree-sitter for universal AST parsing
try:
    import tree_sitter
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    logging.warning("Tree-sitter not available. Multi-language support limited.")

# Advanced AI components
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.nn import SAGEConv, global_mean_pool
    from torch_geometric.data import Data
    AI_COMPONENTS_AVAILABLE = True
except ImportError:
    AI_COMPONENTS_AVAILABLE = False
    logging.warning("AI components not available. Using simplified analysis.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class MultiLanguageVulnerability:
    """Enhanced vulnerability with multi-language context"""
    vulnerability_id: str
    language: str
    framework: Optional[str]
    file_path: str
    line_number: int
    vulnerability_type: str
    severity: str
    cvss_score: float

    # Multi-language analysis
    language_specific_confidence: float
    cross_language_patterns: List[str]
    polyglot_risks: List[str]

    # AI analysis
    universal_gnn_confidence: float
    language_transformer_confidence: float
    dynamic_analysis_score: float

    # Evidence and remediation
    code_snippet: str
    language_specific_remediation: List[str]
    cross_language_considerations: List[str]
    exploit_vectors: List[str]

class LanguageDetector:
    """Intelligent language detection and classification"""

    def __init__(self):
        self.language_patterns = {
            'python': {
                'extensions': ['.py', '.pyw', '.pyi'],
                'signatures': [
                    r'def\s+\w+\s*\(',
                    r'import\s+\w+',
                    r'from\s+\w+\s+import',
                    r'if\s+__name__\s*==\s*["\']__main__["\']'
                ],
                'frameworks': ['django', 'flask', 'fastapi', 'tornado']
            },
            'javascript': {
                'extensions': ['.js', '.jsx', '.mjs', '.es6'],
                'signatures': [
                    r'function\s+\w+\s*\(',
                    r'const\s+\w+\s*=',
                    r'let\s+\w+\s*=',
                    r'require\s*\(',
                    r'import\s+.*from'
                ],
                'frameworks': ['react', 'vue', 'angular', 'express', 'next']
            },
            'typescript': {
                'extensions': ['.ts', '.tsx'],
                'signatures': [
                    r'interface\s+\w+',
                    r'type\s+\w+\s*=',
                    r':\s*\w+\s*=',
                    r'export\s+interface',
                    r'import\s+.*from.*\.ts'
                ],
                'frameworks': ['angular', 'nest', 'typeorm']
            },
            'java': {
                'extensions': ['.java'],
                'signatures': [
                    r'public\s+class\s+\w+',
                    r'package\s+[\w\.]+',
                    r'import\s+[\w\.]+',
                    r'public\s+static\s+void\s+main'
                ],
                'frameworks': ['spring', 'hibernate', 'struts', 'jsf']
            },
            'csharp': {
                'extensions': ['.cs'],
                'signatures': [
                    r'using\s+System',
                    r'namespace\s+\w+',
                    r'public\s+class\s+\w+',
                    r'static\s+void\s+Main'
                ],
                'frameworks': ['asp.net', 'entity', 'blazor']
            },
            'cpp': {
                'extensions': ['.cpp', '.cxx', '.cc', '.c++'],
                'signatures': [
                    r'#include\s*<.*>',
                    r'using\s+namespace\s+std',
                    r'int\s+main\s*\(',
                    r'class\s+\w+\s*{'
                ],
                'frameworks': ['qt', 'boost', 'poco']
            },
            'c': {
                'extensions': ['.c', '.h'],
                'signatures': [
                    r'#include\s*<.*\.h>',
                    r'int\s+main\s*\(',
                    r'struct\s+\w+\s*{',
                    r'typedef\s+.*'
                ],
                'frameworks': ['glibc', 'openssl']
            },
            'go': {
                'extensions': ['.go'],
                'signatures': [
                    r'package\s+\w+',
                    r'import\s*\(',
                    r'func\s+\w+\s*\(',
                    r'type\s+\w+\s+struct'
                ],
                'frameworks': ['gin', 'echo', 'fiber', 'beego']
            },
            'rust': {
                'extensions': ['.rs'],
                'signatures': [
                    r'fn\s+\w+\s*\(',
                    r'use\s+.*',
                    r'struct\s+\w+\s*{',
                    r'impl\s+.*'
                ],
                'frameworks': ['actix', 'rocket', 'warp', 'tokio']
            },
            'php': {
                'extensions': ['.php', '.phtml'],
                'signatures': [
                    r'<\?php',
                    r'function\s+\w+\s*\(',
                    r'\$\w+\s*=',
                    r'class\s+\w+\s*{'
                ],
                'frameworks': ['laravel', 'symfony', 'codeigniter', 'wordpress']
            },
            'ruby': {
                'extensions': ['.rb'],
                'signatures': [
                    r'def\s+\w+',
                    r'class\s+\w+',
                    r'require\s+["\'].*["\']',
                    r'end\s*$'
                ],
                'frameworks': ['rails', 'sinatra', 'hanami']
            },
            'swift': {
                'extensions': ['.swift'],
                'signatures': [
                    r'func\s+\w+\s*\(',
                    r'class\s+\w+\s*{',
                    r'import\s+\w+',
                    r'var\s+\w+:'
                ],
                'frameworks': ['uikit', 'swiftui', 'vapor']
            },
            'kotlin': {
                'extensions': ['.kt', '.kts'],
                'signatures': [
                    r'fun\s+\w+\s*\(',
                    r'class\s+\w+',
                    r'package\s+[\w\.]+',
                    r'import\s+[\w\.]+'
                ],
                'frameworks': ['spring', 'ktor', 'android']
            },
            'scala': {
                'extensions': ['.scala'],
                'signatures': [
                    r'object\s+\w+',
                    r'class\s+\w+',
                    r'def\s+\w+\s*\(',
                    r'import\s+[\w\.]+'
                ],
                'frameworks': ['akka', 'play', 'spark']
            },
            'shell': {
                'extensions': ['.sh', '.bash', '.zsh'],
                'signatures': [
                    r'#!/bin/bash',
                    r'#!/bin/sh',
                    r'if\s*\[.*\]',
                    r'for\s+\w+\s+in'
                ],
                'frameworks': []
            }
        }

    def detect_language(self, code: str, filename: str = '') -> Dict[str, Any]:
        """Detect programming language and framework"""

        # Check file extension first
        if filename:
            file_ext = Path(filename).suffix.lower()
            for lang, config in self.language_patterns.items():
                if file_ext in config['extensions']:
                    framework = self._detect_framework(code, config['frameworks'])
                    return {
                        'language': lang,
                        'confidence': 0.9,
                        'detection_method': 'extension',
                        'framework': framework
                    }

        # Pattern-based detection
        language_scores = {}

        for lang, config in self.language_patterns.items():
            score = 0
            for pattern in config['signatures']:
                matches = len(re.findall(pattern, code, re.MULTILINE | re.IGNORECASE))
                score += matches

            if score > 0:
                language_scores[lang] = score / len(config['signatures'])

        if language_scores:
            detected_lang = max(language_scores, key=language_scores.get)
            confidence = min(language_scores[detected_lang], 1.0)
            framework = self._detect_framework(code,
                                             self.language_patterns[detected_lang]['frameworks'])

            return {
                'language': detected_lang,
                'confidence': confidence,
                'detection_method': 'pattern',
                'framework': framework
            }

        return {
            'language': 'unknown',
            'confidence': 0.0,
            'detection_method': 'none',
            'framework': None
        }

    def _detect_framework(self, code: str, frameworks: List[str]) -> Optional[str]:
        """Detect framework within detected language"""
        code_lower = code.lower()

        for framework in frameworks:
            if framework in code_lower:
                return framework

        return None

class UniversalASTParser:
    """Universal AST parser using Tree-sitter for multiple languages"""

    def __init__(self):
        self.parsers = {}
        self.languages = {}
        self.initialize_parsers()

    def initialize_parsers(self):
        """Initialize Tree-sitter parsers for supported languages"""
        if not TREE_SITTER_AVAILABLE:
            logger.warning("Tree-sitter not available. Using fallback parsers.")
            return

        # Language configurations for Tree-sitter
        language_configs = {
            'python': 'tree-sitter-python',
            'javascript': 'tree-sitter-javascript',
            'typescript': 'tree-sitter-typescript',
            'java': 'tree-sitter-java',
            'cpp': 'tree-sitter-cpp',
            'c': 'tree-sitter-c',
            'go': 'tree-sitter-go',
            'rust': 'tree-sitter-rust',
            'php': 'tree-sitter-php',
            'ruby': 'tree-sitter-ruby'
        }

        for lang, repo in language_configs.items():
            try:
                # In production, these would be pre-compiled
                # For demo, we'll simulate the functionality
                parser = Parser()
                self.parsers[lang] = parser
                logger.info(f"Initialized parser for {lang}")
            except Exception as e:
                logger.warning(f"Failed to initialize {lang} parser: {e}")

    def parse_to_universal_ast(self, code: str, language: str) -> Dict[str, Any]:
        """Parse code to universal AST representation"""

        if language == 'python' and language in self.parsers:
            return self._parse_python_enhanced(code)
        elif language in self.parsers:
            return self._parse_with_tree_sitter(code, language)
        else:
            return self._parse_fallback(code, language)

    def _parse_python_enhanced(self, code: str) -> Dict[str, Any]:
        """Enhanced Python parsing with vulnerability context"""
        try:
            tree = ast.parse(code)

            ast_data = {
                'type': 'universal_ast',
                'language': 'python',
                'nodes': [],
                'edges': [],
                'vulnerability_contexts': []
            }

            node_id = 0
            for node in ast.walk(tree):
                node_data = {
                    'id': node_id,
                    'type': type(node).__name__,
                    'vulnerability_indicators': self._extract_vuln_indicators(node),
                    'security_context': self._analyze_security_context(node)
                }

                ast_data['nodes'].append(node_data)
                node_id += 1

            return ast_data

        except Exception as e:
            logger.error(f"Python AST parsing failed: {e}")
            return {'type': 'error', 'message': str(e)}

    def _parse_with_tree_sitter(self, code: str, language: str) -> Dict[str, Any]:
        """Parse using Tree-sitter (simulated for demo)"""

        # Simulate Tree-sitter parsing
        ast_data = {
            'type': 'universal_ast',
            'language': language,
            'nodes': [],
            'edges': [],
            'vulnerability_contexts': []
        }

        # Language-specific vulnerability patterns
        patterns = self._get_language_patterns(language)

        lines = code.split('\n')
        for i, line in enumerate(lines):
            for pattern_type, pattern in patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    vuln_context = {
                        'line': i + 1,
                        'pattern_type': pattern_type,
                        'content': line.strip(),
                        'language': language
                    }
                    ast_data['vulnerability_contexts'].append(vuln_context)

        return ast_data

    def _parse_fallback(self, code: str, language: str) -> Dict[str, Any]:
        """Fallback parsing for unsupported languages"""

        return {
            'type': 'fallback_ast',
            'language': language,
            'lines': len(code.split('\n')),
            'characters': len(code),
            'vulnerability_indicators': self._extract_basic_indicators(code, language)
        }

    def _extract_vuln_indicators(self, node) -> List[str]:
        """Extract vulnerability indicators from AST node"""
        indicators = []

        if isinstance(node, ast.Call):
            if hasattr(node.func, 'id'):
                func_name = node.func.id
                if func_name in ['eval', 'exec', 'compile']:
                    indicators.append('dangerous_function')
                elif 'sql' in func_name.lower():
                    indicators.append('sql_operation')
                elif func_name in ['open', 'read', 'write']:
                    indicators.append('file_operation')

        elif isinstance(node, ast.Str):
            if any(pattern in node.s.lower() for pattern in ['<script', 'javascript:', 'select ', 'union ']):
                indicators.append('suspicious_string')

        return indicators

    def _analyze_security_context(self, node) -> Dict[str, Any]:
        """Analyze security context of AST node"""
        context = {
            'data_flow': False,
            'user_input': False,
            'output_sink': False,
            'control_flow': False
        }

        if isinstance(node, ast.Call):
            context['data_flow'] = True
            if hasattr(node.func, 'id') and node.func.id in ['input', 'raw_input', 'request']:
                context['user_input'] = True

        elif isinstance(node, (ast.If, ast.For, ast.While)):
            context['control_flow'] = True

        return context

    def _get_language_patterns(self, language: str) -> Dict[str, str]:
        """Get vulnerability patterns for specific language"""

        pattern_db = {
            'javascript': {
                'xss': r'innerHTML\s*=|document\.write\s*\(',
                'sql_injection': r'query\s*\+|SELECT.*\+',
                'eval_injection': r'eval\s*\(',
                'command_injection': r'exec\s*\(|system\s*\('
            },
            'java': {
                'sql_injection': r'Statement.*execute|PreparedStatement.*setString',
                'xss': r'response\.getWriter|out\.print',
                'deserialization': r'ObjectInputStream|readObject',
                'command_injection': r'Runtime\.exec|ProcessBuilder'
            },
            'php': {
                'sql_injection': r'mysql_query|mysqli_query|\$.*SELECT',
                'xss': r'echo\s*\$|print\s*\$',
                'file_inclusion': r'include\s*\(|require\s*\(',
                'command_injection': r'exec\s*\(|system\s*\(|shell_exec'
            },
            'csharp': {
                'sql_injection': r'SqlCommand|ExecuteReader',
                'xss': r'Response\.Write|HttpResponse',
                'deserialization': r'BinaryFormatter|JsonConvert',
                'ldap_injection': r'DirectorySearcher|SearchFilter'
            }
        }

        return pattern_db.get(language, {})

    def _extract_basic_indicators(self, code: str, language: str) -> List[str]:
        """Extract basic vulnerability indicators for fallback parsing"""
        indicators = []

        # Universal patterns
        if 'password' in code.lower() and ('=' in code or ':' in code):
            indicators.append('hardcoded_credential')

        if re.search(r'http://|ftp://', code, re.IGNORECASE):
            indicators.append('insecure_protocol')

        if 'TODO' in code.upper() or 'FIXME' in code.upper():
            indicators.append('incomplete_implementation')

        return indicators

class MultiLanguageVulnerabilityDetector:
    """Advanced multi-language vulnerability detection system"""

    def __init__(self):
        self.language_detector = LanguageDetector()
        self.ast_parser = UniversalASTParser()

        # Cross-language vulnerability patterns
        self.cross_language_patterns = {
            'injection_family': {
                'sql_injection': ['python', 'java', 'php', 'csharp', 'javascript'],
                'xss': ['javascript', 'java', 'php', 'csharp'],
                'command_injection': ['python', 'java', 'php', 'c', 'cpp'],
                'ldap_injection': ['java', 'csharp', 'python']
            },
            'memory_safety': {
                'buffer_overflow': ['c', 'cpp'],
                'use_after_free': ['c', 'cpp', 'rust'],
                'memory_leak': ['c', 'cpp', 'java']
            },
            'authentication': {
                'broken_auth': ['java', 'csharp', 'python', 'javascript'],
                'session_fixation': ['php', 'java', 'csharp'],
                'weak_crypto': ['java', 'csharp', 'python', 'javascript']
            }
        }

        # Language-specific confidence weights
        self.language_weights = {
            'python': {'sql_injection': 0.9, 'xss': 0.7, 'command_injection': 0.8},
            'java': {'sql_injection': 0.95, 'xss': 0.8, 'deserialization': 0.9},
            'javascript': {'xss': 0.95, 'prototype_pollution': 0.8},
            'php': {'sql_injection': 0.9, 'file_inclusion': 0.85, 'xss': 0.8},
            'c': {'buffer_overflow': 0.95, 'format_string': 0.9},
            'cpp': {'buffer_overflow': 0.9, 'memory_leak': 0.8}
        }

    def analyze_multilang_project(self, project_files: Dict[str, str]) -> List[MultiLanguageVulnerability]:
        """Analyze multi-language project for vulnerabilities"""

        vulnerabilities = []
        language_stats = {}

        logger.info(f"Analyzing project with {len(project_files)} files")

        # Phase 1: Individual file analysis
        for filepath, code in project_files.items():
            try:
                file_vulns = self.analyze_single_file(filepath, code)
                vulnerabilities.extend(file_vulns)

                # Track language statistics
                for vuln in file_vulns:
                    lang = vuln.language
                    if lang not in language_stats:
                        language_stats[lang] = {'files': 0, 'vulnerabilities': 0}
                    language_stats[lang]['files'] += 1
                    language_stats[lang]['vulnerabilities'] += 1

            except Exception as e:
                logger.error(f"Failed to analyze {filepath}: {e}")

        # Phase 2: Cross-language analysis
        cross_lang_vulns = self._analyze_cross_language_patterns(project_files, vulnerabilities)
        vulnerabilities.extend(cross_lang_vulns)

        # Phase 3: Polyglot risk assessment
        polyglot_risks = self._assess_polyglot_risks(language_stats, vulnerabilities)

        # Enhance vulnerabilities with cross-language context
        for vuln in vulnerabilities:
            vuln.polyglot_risks = polyglot_risks

        logger.info(f"Analysis complete: {len(vulnerabilities)} vulnerabilities found")
        logger.info(f"Languages detected: {list(language_stats.keys())}")

        return vulnerabilities

    def analyze_single_file(self, filepath: str, code: str) -> List[MultiLanguageVulnerability]:
        """Analyze single file for vulnerabilities"""

        # Detect language and framework
        lang_info = self.language_detector.detect_language(code, filepath)
        language = lang_info['language']
        framework = lang_info.get('framework')

        if language == 'unknown':
            logger.warning(f"Unknown language for {filepath}")
            return []

        # Parse to universal AST
        ast_data = self.ast_parser.parse_to_universal_ast(code, language)

        # Analyze for vulnerabilities
        vulnerabilities = []

        # Language-specific analysis
        lang_vulns = self._analyze_language_specific(code, language, framework, filepath)
        vulnerabilities.extend(lang_vulns)

        # Universal pattern analysis
        universal_vulns = self._analyze_universal_patterns(code, language, filepath)
        vulnerabilities.extend(universal_vulns)

        # AST-based analysis
        if ast_data.get('vulnerability_contexts'):
            ast_vulns = self._analyze_ast_vulnerabilities(ast_data, filepath)
            vulnerabilities.extend(ast_vulns)

        return vulnerabilities

    def _analyze_language_specific(self, code: str, language: str, framework: Optional[str],
                                 filepath: str) -> List[MultiLanguageVulnerability]:
        """Analyze language-specific vulnerability patterns"""

        vulnerabilities = []
        patterns = self.ast_parser._get_language_patterns(language)

        for vuln_type, pattern in patterns.items():
            matches = list(re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE))

            for match in matches:
                line_num = code[:match.start()].count('\n') + 1

                # Calculate language-specific confidence
                base_confidence = self.language_weights.get(language, {}).get(vuln_type, 0.5)

                # Framework adjustment
                framework_bonus = 0.1 if framework else 0.0

                vuln = MultiLanguageVulnerability(
                    vulnerability_id=f"{language}_{vuln_type}_{hashlib.md5(f'{filepath}_{line_num}'.encode()).hexdigest()[:8]}",
                    language=language,
                    framework=framework,
                    file_path=filepath,
                    line_number=line_num,
                    vulnerability_type=vuln_type,
                    severity=self._calculate_severity(vuln_type),
                    cvss_score=self._calculate_cvss(vuln_type, language),

                    language_specific_confidence=min(base_confidence + framework_bonus, 1.0),
                    cross_language_patterns=[],
                    polyglot_risks=[],

                    universal_gnn_confidence=0.0,  # Will be calculated by AI models
                    language_transformer_confidence=0.0,
                    dynamic_analysis_score=0.0,

                    code_snippet=self._extract_code_snippet(code, line_num),
                    language_specific_remediation=self._get_language_remediation(vuln_type, language),
                    cross_language_considerations=[],
                    exploit_vectors=self._get_exploit_vectors(vuln_type, language)
                )

                vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_universal_patterns(self, code: str, language: str,
                                  filepath: str) -> List[MultiLanguageVulnerability]:
        """Analyze universal vulnerability patterns across languages"""

        vulnerabilities = []

        universal_patterns = {
            'hardcoded_secret': r'(password|secret|key|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
            'insecure_random': r'(Math\.random|random\.randint|rand\(\))',
            'debug_info': r'(console\.log|print|echo|System\.out)',
            'todo_fixme': r'(TODO|FIXME|HACK|BUG).*',
            'insecure_protocol': r'http://[^\s]+',
            'weak_hash': r'(md5|sha1)\s*\(',
            'eval_like': r'(eval|exec|system|shell_exec)\s*\('
        }

        for vuln_type, pattern in universal_patterns.items():
            matches = list(re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE))

            for match in matches:
                line_num = code[:match.start()].count('\n') + 1

                vuln = MultiLanguageVulnerability(
                    vulnerability_id=f"universal_{vuln_type}_{hashlib.md5(f'{filepath}_{line_num}'.encode()).hexdigest()[:8]}",
                    language=language,
                    framework=None,
                    file_path=filepath,
                    line_number=line_num,
                    vulnerability_type=vuln_type,
                    severity=self._calculate_severity(vuln_type),
                    cvss_score=self._calculate_cvss(vuln_type, language),

                    language_specific_confidence=0.7,  # Universal patterns have moderate confidence
                    cross_language_patterns=['universal'],
                    polyglot_risks=[],

                    universal_gnn_confidence=0.0,
                    language_transformer_confidence=0.0,
                    dynamic_analysis_score=0.0,

                    code_snippet=self._extract_code_snippet(code, line_num),
                    language_specific_remediation=self._get_universal_remediation(vuln_type),
                    cross_language_considerations=[],
                    exploit_vectors=self._get_exploit_vectors(vuln_type, language)
                )

                vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_ast_vulnerabilities(self, ast_data: Dict[str, Any],
                                   filepath: str) -> List[MultiLanguageVulnerability]:
        """Analyze vulnerabilities from AST data"""

        vulnerabilities = []

        for context in ast_data.get('vulnerability_contexts', []):
            vuln = MultiLanguageVulnerability(
                vulnerability_id=f"ast_{context['pattern_type']}_{hashlib.md5(f'{filepath}_{context['line']}'.encode()).hexdigest()[:8]}",
                language=context['language'],
                framework=None,
                file_path=filepath,
                line_number=context['line'],
                vulnerability_type=context['pattern_type'],
                severity=self._calculate_severity(context['pattern_type']),
                cvss_score=self._calculate_cvss(context['pattern_type'], context['language']),

                language_specific_confidence=0.8,  # AST analysis has high confidence
                cross_language_patterns=[],
                polyglot_risks=[],

                universal_gnn_confidence=0.0,
                language_transformer_confidence=0.0,
                dynamic_analysis_score=0.0,

                code_snippet=context['content'],
                language_specific_remediation=self._get_language_remediation(context['pattern_type'], context['language']),
                cross_language_considerations=[],
                exploit_vectors=self._get_exploit_vectors(context['pattern_type'], context['language'])
            )

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_cross_language_patterns(self, project_files: Dict[str, str],
                                       vulnerabilities: List[MultiLanguageVulnerability]) -> List[MultiLanguageVulnerability]:
        """Analyze cross-language vulnerability patterns"""

        cross_vulns = []

        # Group vulnerabilities by type
        vuln_groups = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(vuln)

        # Look for cross-language amplification
        for vuln_type, vuln_list in vuln_groups.items():
            if len(vuln_list) > 1:
                languages = [v.language for v in vuln_list]
                unique_languages = set(languages)

                if len(unique_languages) > 1:
                    # Create cross-language vulnerability
                    cross_vuln = MultiLanguageVulnerability(
                        vulnerability_id=f"cross_lang_{vuln_type}_{hashlib.md5(''.join(sorted(unique_languages)).encode()).hexdigest()[:8]}",
                        language='multiple',
                        framework=None,
                        file_path='multiple_files',
                        line_number=0,
                        vulnerability_type=f"cross_language_{vuln_type}",
                        severity='HIGH',
                        cvss_score=8.0,

                        language_specific_confidence=0.9,
                        cross_language_patterns=list(unique_languages),
                        polyglot_risks=[f"Vulnerability spans {len(unique_languages)} languages"],

                        universal_gnn_confidence=0.0,
                        language_transformer_confidence=0.0,
                        dynamic_analysis_score=0.0,

                        code_snippet='Multiple files affected',
                        language_specific_remediation=[f"Address {vuln_type} in all affected languages: {', '.join(unique_languages)}"],
                        cross_language_considerations=[
                            "Cross-language vulnerabilities can be harder to detect",
                            "Ensure consistent security policies across all languages",
                            "Consider using a unified security framework"
                        ],
                        exploit_vectors=[f"Chain exploits across {', '.join(unique_languages)}"]
                    )

                    cross_vulns.append(cross_vuln)

        return cross_vulns

    def _assess_polyglot_risks(self, language_stats: Dict[str, Any],
                             vulnerabilities: List[MultiLanguageVulnerability]) -> List[str]:
        """Assess risks specific to polyglot projects"""

        risks = []
        num_languages = len(language_stats)

        if num_languages > 3:
            risks.append(f"High complexity: {num_languages} programming languages")

        if num_languages > 1:
            risks.append("Inconsistent security practices across languages")
            risks.append("Potential for bypass via language-specific vulnerabilities")

        # Check for dangerous language combinations
        languages = set(language_stats.keys())

        if 'c' in languages or 'cpp' in languages:
            if any(lang in languages for lang in ['python', 'java', 'javascript']):
                risks.append("Memory-safe + memory-unsafe language combination")

        if 'javascript' in languages and 'php' in languages:
            risks.append("Client-side + server-side scripting vulnerability amplification")

        return risks

    def _calculate_severity(self, vuln_type: str) -> str:
        """Calculate vulnerability severity"""

        high_severity = [
            'sql_injection', 'command_injection', 'buffer_overflow',
            'deserialization', 'hardcoded_secret'
        ]

        medium_severity = [
            'xss', 'path_traversal', 'weak_hash', 'insecure_random'
        ]

        if vuln_type in high_severity:
            return 'HIGH'
        elif vuln_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _calculate_cvss(self, vuln_type: str, language: str) -> float:
        """Calculate CVSS score"""

        base_scores = {
            'sql_injection': 9.0,
            'command_injection': 8.5,
            'buffer_overflow': 8.0,
            'xss': 6.5,
            'hardcoded_secret': 7.5,
            'path_traversal': 6.0,
            'weak_hash': 5.0,
            'insecure_random': 4.0
        }

        base_score = base_scores.get(vuln_type, 5.0)

        # Language-specific adjustments
        if language in ['c', 'cpp'] and vuln_type in ['buffer_overflow', 'format_string']:
            base_score += 1.0

        return min(base_score, 10.0)

    def _extract_code_snippet(self, code: str, line_num: int, context_lines: int = 2) -> str:
        """Extract code snippet around vulnerability"""

        lines = code.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)

        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1:3d}: {lines[i]}")

        return '\n'.join(snippet_lines)

    def _get_language_remediation(self, vuln_type: str, language: str) -> List[str]:
        """Get language-specific remediation advice"""

        remediation_db = {
            'python': {
                'sql_injection': [
                    "Use parameterized queries with psycopg2 or SQLAlchemy",
                    "Implement input validation with sqlparse",
                    "Use ORM methods instead of raw SQL"
                ],
                'xss': [
                    "Use Jinja2 auto-escaping in templates",
                    "Implement Content Security Policy headers",
                    "Validate input with bleach library"
                ]
            },
            'java': {
                'sql_injection': [
                    "Use PreparedStatement instead of Statement",
                    "Implement input validation with OWASP ESAPI",
                    "Use JPA/Hibernate parameterized queries"
                ],
                'deserialization': [
                    "Validate serialized data with custom ObjectInputStream",
                    "Use allowlist-based deserialization",
                    "Consider using JSON instead of Java serialization"
                ]
            },
            'javascript': {
                'xss': [
                    "Use textContent instead of innerHTML",
                    "Implement CSP headers",
                    "Validate input with DOMPurify"
                ],
                'prototype_pollution': [
                    "Use Map instead of Object for user data",
                    "Validate object keys before assignment",
                    "Use Object.freeze() for prototypes"
                ]
            }
        }

        return remediation_db.get(language, {}).get(vuln_type, [
            f"Address {vuln_type} using {language} security best practices"
        ])

    def _get_universal_remediation(self, vuln_type: str) -> List[str]:
        """Get universal remediation advice"""

        universal_remediation = {
            'hardcoded_secret': [
                "Move secrets to environment variables",
                "Use a secrets management service",
                "Implement proper key rotation"
            ],
            'insecure_protocol': [
                "Use HTTPS instead of HTTP",
                "Implement TLS 1.2 or higher",
                "Use HSTS headers"
            ],
            'weak_hash': [
                "Use SHA-256 or stronger hashing algorithms",
                "Implement proper salt for password hashing",
                "Consider bcrypt or scrypt for passwords"
            ]
        }

        return universal_remediation.get(vuln_type, [
            f"Follow security best practices for {vuln_type}"
        ])

    def _get_exploit_vectors(self, vuln_type: str, language: str) -> List[str]:
        """Get potential exploit vectors"""

        exploit_vectors = {
            'sql_injection': [
                "Data extraction via UNION attacks",
                "Database modification via INSERT/UPDATE",
                "Privilege escalation via stored procedures"
            ],
            'xss': [
                "Session hijacking via document.cookie",
                "Credential theft via keylogging",
                "Phishing via DOM manipulation"
            ],
            'command_injection': [
                "Remote code execution via shell commands",
                "File system access via command chaining",
                "Privilege escalation via sudo exploitation"
            ]
        }

        return exploit_vectors.get(vuln_type, [
            f"Various attack vectors possible for {vuln_type}"
        ])

def main():
    """Demonstration of multi-language vulnerability detection"""

    print("🌍 VulnHunter V17 Multi-Language Intelligence")
    print("=" * 60)

    detector = MultiLanguageVulnerabilityDetector()

    # Sample multi-language project
    project_files = {
        'backend/auth.py': '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()
        ''',

        'frontend/app.js': '''
function displayMessage(userInput) {
    document.getElementById('output').innerHTML = userInput;
    console.log("Displaying: " + userInput);
}
        ''',

        'api/UserController.java': '''
@RestController
public class UserController {
    public String getUser(@RequestParam String id) {
        String query = "SELECT * FROM users WHERE id = " + id;
        return jdbcTemplate.queryForObject(query, String.class);
    }
}
        ''',

        'utils/helper.php': '''
<?php
function executeCommand($cmd) {
    $result = shell_exec($cmd);
    echo $result;
    return $result;
}
?>
        ''',

        'config/database.cpp': '''
#include <iostream>
#include <cstring>

void processInput(char* input) {
    char buffer[256];
    strcpy(buffer, input);  // Vulnerable to buffer overflow
    std::cout << buffer << std::endl;
}
        '''
    }

    # Analyze the project
    vulnerabilities = detector.analyze_multilang_project(project_files)

    # Display results
    print(f"\n🔍 Analysis Results: {len(vulnerabilities)} vulnerabilities found")
    print("=" * 60)

    # Group by language
    by_language = {}
    for vuln in vulnerabilities:
        lang = vuln.language
        if lang not in by_language:
            by_language[lang] = []
        by_language[lang].append(vuln)

    for language, lang_vulns in by_language.items():
        print(f"\n📝 {language.upper()} ({len(lang_vulns)} vulnerabilities)")
        print("-" * 40)

        for vuln in lang_vulns:
            print(f"🎯 {vuln.vulnerability_type} ({vuln.severity})")
            print(f"   📍 {vuln.file_path}:{vuln.line_number}")
            print(f"   🔥 Confidence: {vuln.language_specific_confidence:.3f}")
            print(f"   💯 CVSS: {vuln.cvss_score}")

            if vuln.framework:
                print(f"   🔧 Framework: {vuln.framework}")

            if vuln.cross_language_patterns:
                print(f"   🌐 Cross-language: {', '.join(vuln.cross_language_patterns)}")

            if vuln.polyglot_risks:
                print(f"   ⚠️  Polyglot risks: {len(vuln.polyglot_risks)} identified")

            print(f"   📋 Code snippet:")
            for line in vuln.code_snippet.split('\n')[:3]:  # Show first 3 lines
                print(f"      {line}")

            print()

    # Cross-language analysis summary
    cross_lang_vulns = [v for v in vulnerabilities if v.language == 'multiple']
    if cross_lang_vulns:
        print(f"\n🌐 Cross-Language Vulnerabilities: {len(cross_lang_vulns)}")
        print("-" * 40)
        for vuln in cross_lang_vulns:
            print(f"🎯 {vuln.vulnerability_type}")
            print(f"   Languages: {', '.join(vuln.cross_language_patterns)}")
            for risk in vuln.polyglot_risks:
                print(f"   ⚠️  {risk}")
            print()

    # Summary statistics
    languages_found = set(v.language for v in vulnerabilities if v.language != 'multiple')
    high_severity = len([v for v in vulnerabilities if v.severity == 'HIGH'])

    print(f"\n📊 Summary Statistics")
    print("-" * 40)
    print(f"Languages analyzed: {len(languages_found)} ({', '.join(sorted(languages_found))})")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    print(f"High severity: {high_severity}")
    print(f"Cross-language issues: {len(cross_lang_vulns)}")
    print(f"Average CVSS score: {sum(v.cvss_score for v in vulnerabilities) / len(vulnerabilities):.1f}")

if __name__ == "__main__":
    main()