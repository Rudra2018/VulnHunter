"""
Source Code Analyzer
===================

Advanced source code vulnerability analysis with ML detection.
"""

import ast
import re
import logging
from typing import Dict, Any, Union, List, Optional
from pathlib import Path
import hashlib
import keyword
from collections import Counter

from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

class SourceCodeAnalyzer(BaseAnalyzer):
    """
    Analyzes source code for security vulnerabilities.

    Supports multiple programming languages with specialized analysis.
    """

    DANGEROUS_FUNCTIONS = {
        'python': {
            'eval', 'exec', 'compile', '__import__', 'open', 'input',
            'subprocess.call', 'subprocess.run', 'subprocess.Popen',
            'os.system', 'os.popen', 'pickle.loads', 'yaml.load'
        },
        'javascript': {
            'eval', 'setTimeout', 'setInterval', 'Function',
            'document.write', 'innerHTML', 'outerHTML'
        },
        'java': {
            'Runtime.exec', 'ProcessBuilder', 'Class.forName',
            'reflection', 'deserialization', 'SQL.execute'
        },
        'cpp': {
            'strcpy', 'strcat', 'sprintf', 'gets', 'system',
            'malloc', 'free', 'memcpy', 'scanf'
        }
    }

    SECURITY_PATTERNS = {
        'sql_injection': [
            r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+.*',
            r'INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\+.*\)',
            r'UPDATE\s+.*\s+SET\s+.*=.*\+.*',
            r'DELETE\s+FROM\s+.*\s+WHERE\s+.*\+.*'
        ],
        'xss': [
            r'document\.write\s*\(.*\+.*\)',
            r'innerHTML\s*=.*\+.*',
            r'<script[^>]*>.*</script>',
            r'javascript:.*'
        ],
        'command_injection': [
            r'os\.system\s*\(.*\+.*\)',
            r'subprocess\.\w+\s*\(.*\+.*\)',
            r'exec\s*\(.*\+.*\)',
            r'eval\s*\(.*\+.*\)'
        ],
        'path_traversal': [
            r'\.\./',
            r'\.\.\\',
            r'open\s*\(.*\+.*\.txt.*\)',
            r'file\s*\(.*\+.*\)'
        ]
    }

    def __init__(self, model_manager):
        super().__init__(model_manager, "source_code")
        self.supported_extensions = {'.py', '.js', '.java', '.cpp', '.c', '.go', '.rs', '.php'}

    async def analyze(self, target: Union[str, Path], confidence_threshold: float = 0.5) -> Dict[str, Any]:
        """
        Analyze source code for vulnerabilities.

        Args:
            target: Source code string or file path
            confidence_threshold: Confidence threshold for detection

        Returns:
            Analysis results
        """
        if isinstance(target, Path):
            if not target.exists():
                return {'status': 'error', 'error': 'File not found'}

            if target.suffix not in self.supported_extensions:
                return {'status': 'error', 'error': f'Unsupported file type: {target.suffix}'}

            with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            source_path = target
        else:
            code = str(target)
            source_path = None

        # Check cache
        cache_key = self._get_cache_key(code)
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # Extract features
            features = self.extract_features(code, source_path)

            # Perform ML analysis
            result = await self._analyze_with_model(
                features,
                'open_source_code',
                confidence_threshold
            )

            # Add source code specific analysis
            result.update({
                'code_analysis': self._analyze_code_patterns(code),
                'security_issues': self._find_security_issues(code),
                'complexity_metrics': self._calculate_complexity(code),
                'language_detected': self._detect_language(code, source_path)
            })

            # Cache result
            self.cache[cache_key] = result
            return result

        except Exception as e:
            logger.error(f"Source code analysis failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'analyzer': 'source_code'
            }

    def extract_features(self, code: str, source_path: Optional[Path] = None) -> Dict[str, Any]:
        """Extract comprehensive features from source code."""
        features = {}

        # Basic code metrics
        features['code_length'] = len(code)
        features['line_count'] = len(code.splitlines())
        features['word_count'] = len(code.split())
        features['char_entropy'] = self._calculate_entropy(code)

        # Language detection
        language = self._detect_language(code, source_path)
        features['language'] = self._encode_language(language)

        # Security-specific features
        features.update(self._extract_security_features(code, language))

        # Complexity features
        features.update(self._extract_complexity_features(code, language))

        # Pattern features
        features.update(self._extract_pattern_features(code))

        # Dependency features (for supported languages)
        features.update(self._extract_dependency_features(code, language))

        return features

    def _extract_security_features(self, code: str, language: str) -> Dict[str, Any]:
        """Extract security-related features."""
        features = {}

        # Dangerous function usage
        dangerous_funcs = self.DANGEROUS_FUNCTIONS.get(language, set())
        features['dangerous_function_count'] = sum(
            len(re.findall(rf'\b{func}\b', code)) for func in dangerous_funcs
        )

        # Security pattern detection
        for pattern_type, patterns in self.SECURITY_PATTERNS.items():
            count = sum(len(re.findall(pattern, code, re.IGNORECASE)) for pattern in patterns)
            features[f'{pattern_type}_patterns'] = count

        # Input validation checks
        features['has_input_validation'] = 1 if self._has_input_validation(code) else 0
        features['has_output_encoding'] = 1 if self._has_output_encoding(code) else 0
        features['has_sql_parameterization'] = 1 if self._has_sql_parameterization(code) else 0

        # Cryptographic usage
        features['has_crypto_calls'] = 1 if self._has_crypto_calls(code) else 0
        features['weak_crypto_usage'] = 1 if self._has_weak_crypto(code) else 0

        # Error handling
        features['has_error_handling'] = 1 if self._has_error_handling(code, language) else 0

        return features

    def _extract_complexity_features(self, code: str, language: str) -> Dict[str, Any]:
        """Extract code complexity features."""
        features = {}

        # Cyclomatic complexity
        features['cyclomatic_complexity'] = self._calculate_cyclomatic_complexity(code, language)

        # Nesting depth
        features['max_nesting_depth'] = self._calculate_max_nesting_depth(code)

        # Function/method count
        features['function_count'] = self._count_functions(code, language)

        # Class count (for OOP languages)
        features['class_count'] = self._count_classes(code, language)

        # Loop count
        features['loop_count'] = self._count_loops(code, language)

        # Conditional count
        features['conditional_count'] = self._count_conditionals(code, language)

        return features

    def _extract_pattern_features(self, code: str) -> Dict[str, Any]:
        """Extract pattern-based features."""
        features = {}

        # String operations
        features['string_concat_count'] = len(re.findall(r'\+\s*["\']', code))
        features['format_string_count'] = len(re.findall(r'\.format\(|%[sd]', code))

        # Network operations
        features['network_call_count'] = len(re.findall(r'urllib|requests|http|socket', code, re.IGNORECASE))

        # File operations
        features['file_operation_count'] = len(re.findall(r'open\(|file\(|write\(|read\(', code))

        # Database operations
        features['db_operation_count'] = len(re.findall(r'SELECT|INSERT|UPDATE|DELETE|CREATE|DROP', code, re.IGNORECASE))

        # System calls
        features['system_call_count'] = len(re.findall(r'system\(|exec\(|shell', code))

        return features

    def _extract_dependency_features(self, code: str, language: str) -> Dict[str, Any]:
        """Extract dependency-related features."""
        features = {}

        # Import/include statements
        if language == 'python':
            imports = re.findall(r'import\s+(\w+)|from\s+(\w+)', code)
            features['import_count'] = len(imports)
            features['has_dangerous_imports'] = 1 if any(
                imp in ['pickle', 'subprocess', 'os', 'eval']
                for imp_tuple in imports for imp in imp_tuple if imp
            ) else 0
        elif language == 'javascript':
            requires = re.findall(r'require\(["\']([^"\']+)["\']\)', code)
            features['require_count'] = len(requires)
            features['has_dangerous_requires'] = 1 if any(
                'child_process' in req or 'fs' in req for req in requires
            ) else 0
        else:
            features['import_count'] = 0
            features['has_dangerous_imports'] = 0

        return features

    def _detect_language(self, code: str, source_path: Optional[Path] = None) -> str:
        """Detect programming language from code and/or file extension."""
        if source_path:
            ext = source_path.suffix.lower()
            ext_mapping = {
                '.py': 'python', '.js': 'javascript', '.java': 'java',
                '.cpp': 'cpp', '.c': 'cpp', '.go': 'go', '.rs': 'rust', '.php': 'php'
            }
            if ext in ext_mapping:
                return ext_mapping[ext]

        # Pattern-based detection
        if re.search(r'def\s+\w+\s*\(|import\s+\w+|from\s+\w+', code):
            return 'python'
        elif re.search(r'function\s+\w+\s*\(|var\s+\w+\s*=|let\s+\w+\s*=', code):
            return 'javascript'
        elif re.search(r'public\s+class|public\s+static\s+void\s+main', code):
            return 'java'
        elif re.search(r'#include|int\s+main\s*\(|printf\s*\(', code):
            return 'cpp'

        return 'unknown'

    def _encode_language(self, language: str) -> int:
        """Encode language as numeric value for ML model."""
        language_mapping = {
            'python': 1, 'javascript': 2, 'java': 3, 'cpp': 4,
            'go': 5, 'rust': 6, 'php': 7, 'unknown': 0
        }
        return language_mapping.get(language, 0)

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        counter = Counter(text)
        length = len(text)
        entropy = sum(-(count/length) * (count/length).bit_length() for count in counter.values())
        return entropy

    def _calculate_cyclomatic_complexity(self, code: str, language: str) -> int:
        """Calculate cyclomatic complexity."""
        # Simplified complexity calculation
        if language == 'python':
            decision_points = len(re.findall(r'\b(if|elif|while|for|except|and|or)\b', code))
        else:
            decision_points = len(re.findall(r'\b(if|else|while|for|switch|case|catch|\&\&|\|\|)\b', code))

        return decision_points + 1

    def _calculate_max_nesting_depth(self, code: str) -> int:
        """Calculate maximum nesting depth."""
        max_depth = 0
        current_depth = 0

        for char in code:
            if char in '({[':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char in ')}]':
                current_depth = max(0, current_depth - 1)

        return max_depth

    def _count_functions(self, code: str, language: str) -> int:
        """Count number of functions/methods."""
        if language == 'python':
            return len(re.findall(r'def\s+\w+\s*\(', code))
        elif language == 'javascript':
            return len(re.findall(r'function\s+\w+\s*\(', code))
        elif language == 'java':
            return len(re.findall(r'(public|private|protected)?\s*(static)?\s*\w+\s+\w+\s*\(', code))
        else:
            return len(re.findall(r'\w+\s*\([^)]*\)\s*{', code))

    def _count_classes(self, code: str, language: str) -> int:
        """Count number of classes."""
        if language in ['python', 'java', 'javascript']:
            return len(re.findall(r'class\s+\w+', code))
        return 0

    def _count_loops(self, code: str, language: str) -> int:
        """Count number of loops."""
        return len(re.findall(r'\b(for|while)\b', code))

    def _count_conditionals(self, code: str, language: str) -> int:
        """Count number of conditional statements."""
        return len(re.findall(r'\bif\b', code))

    def _has_input_validation(self, code: str) -> bool:
        """Check if code has input validation."""
        validation_patterns = [
            r'validate\w*\(', r'sanitize\w*\(', r'escape\w*\(',
            r'len\s*\(\s*\w+\s*\)', r'isinstance\s*\(', r'type\s*\('
        ]
        return any(re.search(pattern, code) for pattern in validation_patterns)

    def _has_output_encoding(self, code: str) -> bool:
        """Check if code has output encoding."""
        encoding_patterns = [
            r'html\.escape', r'urllib\.quote', r'base64\.encode',
            r'escape\w*\(', r'encode\w*\('
        ]
        return any(re.search(pattern, code) for pattern in encoding_patterns)

    def _has_sql_parameterization(self, code: str) -> bool:
        """Check if code uses parameterized SQL queries."""
        param_patterns = [
            r'execute\s*\(\s*["\'][^"\']*\?[^"\']*["\']',
            r'execute\s*\(\s*["\'][^"\']*%s[^"\']*["\']',
            r'prepare\s*\('
        ]
        return any(re.search(pattern, code) for pattern in param_patterns)

    def _has_crypto_calls(self, code: str) -> bool:
        """Check if code uses cryptographic functions."""
        crypto_patterns = [
            r'crypto', r'hashlib', r'hmac', r'ssl', r'random',
            r'encrypt', r'decrypt', r'hash', r'digest'
        ]
        return any(re.search(pattern, code, re.IGNORECASE) for pattern in crypto_patterns)

    def _has_weak_crypto(self, code: str) -> bool:
        """Check for weak cryptographic usage."""
        weak_patterns = [
            r'md5\(', r'sha1\(', r'des\(', r'rc4\(',
            r'random\.random\(', r'math\.random\('
        ]
        return any(re.search(pattern, code, re.IGNORECASE) for pattern in weak_patterns)

    def _has_error_handling(self, code: str, language: str) -> bool:
        """Check if code has proper error handling."""
        if language == 'python':
            return bool(re.search(r'try\s*:|except\s+\w*:', code))
        elif language == 'java':
            return bool(re.search(r'try\s*{|catch\s*\(', code))
        elif language == 'javascript':
            return bool(re.search(r'try\s*{|catch\s*\(', code))
        return False

    def _analyze_code_patterns(self, code: str) -> Dict[str, Any]:
        """Analyze code for common patterns."""
        return {
            'has_hardcoded_secrets': self._has_hardcoded_secrets(code),
            'has_commented_code': len(re.findall(r'#.*|//.*|/\*.*?\*/', code, re.DOTALL)) > 0,
            'has_todo_comments': len(re.findall(r'TODO|FIXME|HACK', code, re.IGNORECASE)) > 0,
            'string_literal_count': len(re.findall(r'["\'][^"\']*["\']', code)),
            'numeric_literal_count': len(re.findall(r'\b\d+\b', code))
        }

    def _has_hardcoded_secrets(self, code: str) -> bool:
        """Check for hardcoded secrets."""
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']{8,}["\']',
            r'api_key\s*=\s*["\'][^"\']{20,}["\']',
            r'secret\s*=\s*["\'][^"\']{8,}["\']',
            r'token\s*=\s*["\'][^"\']{20,}["\']'
        ]
        return any(re.search(pattern, code, re.IGNORECASE) for pattern in secret_patterns)

    def _find_security_issues(self, code: str) -> List[Dict[str, Any]]:
        """Find specific security issues in code."""
        issues = []

        # Check for each vulnerability pattern
        for vuln_type, patterns in self.SECURITY_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    issues.append({
                        'type': vuln_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'line': code[:match.start()].count('\n') + 1,
                        'severity': self._assess_pattern_severity(vuln_type)
                    })

        return issues

    def _assess_pattern_severity(self, vuln_type: str) -> str:
        """Assess severity of vulnerability pattern."""
        severity_mapping = {
            'sql_injection': 'HIGH',
            'xss': 'MEDIUM',
            'command_injection': 'CRITICAL',
            'path_traversal': 'MEDIUM'
        }
        return severity_mapping.get(vuln_type, 'LOW')

    def _calculate_complexity(self, code: str) -> Dict[str, Any]:
        """Calculate various complexity metrics."""
        return {
            'lines_of_code': len([line for line in code.splitlines() if line.strip()]),
            'blank_lines': len([line for line in code.splitlines() if not line.strip()]),
            'comment_lines': len(re.findall(r'^\s*#|^\s*//', code, re.MULTILINE)),
            'average_line_length': sum(len(line) for line in code.splitlines()) / max(len(code.splitlines()), 1),
            'max_line_length': max(len(line) for line in code.splitlines()) if code.splitlines() else 0
        }

    def _features_to_array(self, features: Dict[str, Any]) -> list:
        """Convert features to array for ML model."""
        # Define the expected feature order for the open source code model
        feature_order = [
            'code_length', 'line_count', 'word_count', 'char_entropy', 'language',
            'dangerous_function_count', 'sql_injection_patterns', 'xss_patterns',
            'command_injection_patterns', 'path_traversal_patterns', 'has_input_validation',
            'has_output_encoding', 'has_sql_parameterization', 'has_crypto_calls',
            'weak_crypto_usage', 'has_error_handling', 'cyclomatic_complexity',
            'max_nesting_depth', 'function_count', 'class_count', 'loop_count',
            'conditional_count', 'string_concat_count', 'format_string_count',
            'network_call_count', 'file_operation_count', 'db_operation_count',
            'system_call_count', 'import_count', 'has_dangerous_imports'
        ]

        return [features.get(feature, 0) for feature in feature_order]