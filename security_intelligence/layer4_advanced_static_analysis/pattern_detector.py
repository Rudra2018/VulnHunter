"""
Vulnerability Pattern Detection Engine

This module provides advanced pattern-based vulnerability detection:
- Machine learning-enhanced pattern matching
- Context-aware vulnerability detection
- Complex multi-statement vulnerability patterns
- Integration with known vulnerability databases
- Custom pattern definition and management
"""

import re
import json
import logging
import hashlib
from typing import Dict, List, Tuple, Optional, Any, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import torch
import torch.nn as nn
import numpy as np
from collections import defaultdict, deque

from .static_analyzer import ASTNode, Function, AnalysisResult, NodeType, SourceLocation

class VulnerabilityCategory(Enum):
    """Categories of vulnerabilities"""
    INJECTION = "injection"
    BROKEN_AUTHENTICATION = "broken_authentication"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    XML_EXTERNAL_ENTITIES = "xml_external_entities"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    CRYPTOGRAPHIC_FAILURES = "cryptographic_failures"
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    USE_AFTER_FREE = "use_after_free"

class PatternType(Enum):
    """Types of vulnerability patterns"""
    SINGLE_STATEMENT = "single_statement"
    MULTI_STATEMENT = "multi_statement"
    CONTROL_FLOW = "control_flow"
    DATA_FLOW = "data_flow"
    API_MISUSE = "api_misuse"
    CONFIGURATION = "configuration"

@dataclass
class VulnerabilityPattern:
    """Vulnerability pattern definition"""
    pattern_id: str
    name: str
    category: VulnerabilityCategory
    pattern_type: PatternType
    severity: str
    confidence: float
    description: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    regex_patterns: List[str] = field(default_factory=list)
    ast_patterns: List[Dict[str, Any]] = field(default_factory=list)
    context_requirements: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PatternMatch:
    """Represents a pattern match"""
    pattern: VulnerabilityPattern
    location: SourceLocation
    matched_code: str
    confidence: float
    context: Dict[str, Any]
    evidence: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)

@dataclass
class VulnerabilityFinding:
    """Complete vulnerability finding"""
    finding_id: str
    pattern_matches: List[PatternMatch]
    primary_location: SourceLocation
    affected_functions: List[str]
    severity: str
    confidence: float
    title: str
    description: str
    impact: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class PatternEmbedding(nn.Module):
    """Neural network for pattern embeddings"""

    def __init__(self, vocab_size: int = 10000, embedding_dim: int = 256, hidden_dim: int = 512):
        super().__init__()

        self.token_embedding = nn.Embedding(vocab_size, embedding_dim)
        self.pattern_encoder = nn.LSTM(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)

        self.pattern_classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, len(VulnerabilityCategory)),
            nn.Sigmoid()
        )

        self.confidence_estimator = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, token_sequence):
        embedded = self.token_embedding(token_sequence)
        encoded, (hidden, _) = self.pattern_encoder(embedded)

        # Use final hidden state
        final_hidden = torch.cat([hidden[-2], hidden[-1]], dim=1)

        category_scores = self.pattern_classifier(final_hidden)
        confidence_score = self.confidence_estimator(final_hidden)

        return {
            'category_scores': category_scores,
            'confidence': confidence_score,
            'embeddings': final_hidden
        }

class PatternLibrary:
    """Library of vulnerability patterns"""

    def __init__(self):
        self.patterns = {}
        self.compiled_regex = {}
        self._load_default_patterns()

    def _load_default_patterns(self):
        """Load default vulnerability patterns"""
        # SQL Injection patterns
        self._add_sql_injection_patterns()

        # XSS patterns
        self._add_xss_patterns()

        # Command injection patterns
        self._add_command_injection_patterns()

        # Cryptographic failures
        self._add_crypto_patterns()

        # Buffer overflow patterns
        self._add_buffer_overflow_patterns()

        # Authentication patterns
        self._add_auth_patterns()

        # File handling patterns
        self._add_file_patterns()

    def _add_sql_injection_patterns(self):
        """Add SQL injection patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="sql_injection_1",
                name="SQL Injection via String Concatenation",
                category=VulnerabilityCategory.INJECTION,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="critical",
                confidence=0.9,
                description="SQL query constructed using string concatenation with user input",
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
                regex_patterns=[
                    r'.*\+.*["\'].*SELECT.*FROM.*["\'].*\+.*',
                    r'.*["\'].*INSERT.*INTO.*["\'].*\+.*',
                    r'.*["\'].*UPDATE.*SET.*["\'].*\+.*',
                    r'.*["\'].*DELETE.*FROM.*["\'].*\+.*',
                    r'.*f["\'].*SELECT.*\{.*\}.*["\']',
                    r'.*%.*["\'].*SELECT.*["\'].*%'
                ],
                remediation="Use parameterized queries or prepared statements",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
            ),

            VulnerabilityPattern(
                pattern_id="sql_injection_2",
                name="SQL Injection via Format String",
                category=VulnerabilityCategory.INJECTION,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="critical",
                confidence=0.85,
                description="SQL query constructed using format strings with user input",
                cwe_id="CWE-89",
                regex_patterns=[
                    r'.*\.format\(.*\).*execute\(',
                    r'.*%.*execute\(',
                    r'.*f".*SELECT.*{.*}.*"',
                    r'.*sprintf.*SELECT.*%s'
                ],
                remediation="Use parameterized queries instead of string formatting"
            )
        ]

        for pattern in patterns:
            self.add_pattern(pattern)

    def _add_xss_patterns(self):
        """Add XSS patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="xss_reflected_1",
                name="Reflected XSS via Direct Output",
                category=VulnerabilityCategory.CROSS_SITE_SCRIPTING,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="high",
                confidence=0.8,
                description="User input directly output to HTML without encoding",
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection",
                regex_patterns=[
                    r'.*request\..*\.write\(',
                    r'.*innerHTML.*=.*request\.',
                    r'.*document\.write\(.*request\.',
                    r'.*echo.*\$_GET',
                    r'.*print.*request\.'
                ],
                remediation="Encode user input before output or use safe templating"
            ),

            VulnerabilityPattern(
                pattern_id="xss_stored_1",
                name="Stored XSS via Database",
                category=VulnerabilityCategory.CROSS_SITE_SCRIPTING,
                pattern_type=PatternType.MULTI_STATEMENT,
                severity="high",
                confidence=0.75,
                description="User input stored in database and later output without encoding",
                regex_patterns=[
                    r'.*INSERT.*VALUES.*request\.',
                    r'.*UPDATE.*SET.*request\.',
                    r'.*save\(.*request\.'
                ],
                remediation="Validate and encode input on storage and output"
            )
        ]

        for pattern in patterns:
            self.add_pattern(pattern)

    def _add_command_injection_patterns(self):
        """Add command injection patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="command_injection_1",
                name="Command Injection via System Call",
                category=VulnerabilityCategory.INJECTION,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="critical",
                confidence=0.95,
                description="User input passed directly to system command execution",
                cwe_id="CWE-78",
                regex_patterns=[
                    r'.*system\(.*request\.',
                    r'.*exec\(.*request\.',
                    r'.*popen\(.*request\.',
                    r'.*subprocess\..*\(.*request\.',
                    r'.*os\.system\(.*input\(',
                    r'.*shell_exec\(.*\$_'
                ],
                remediation="Use safe command execution methods and input validation"
            ),

            VulnerabilityPattern(
                pattern_id="command_injection_2",
                name="Command Injection via eval()",
                category=VulnerabilityCategory.INJECTION,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="critical",
                confidence=0.9,
                description="User input passed to eval() function",
                cwe_id="CWE-95",
                regex_patterns=[
                    r'.*eval\(.*request\.',
                    r'.*eval\(.*input\(',
                    r'.*exec\(.*input\(',
                    r'.*eval\(.*\$_'
                ],
                remediation="Avoid eval() with user input; use safe alternatives"
            )
        ]

        for pattern in patterns:
            self.add_pattern(pattern)

    def _add_crypto_patterns(self):
        """Add cryptographic failure patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="crypto_weak_algorithm_1",
                name="Weak Cryptographic Algorithm",
                category=VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="high",
                confidence=0.8,
                description="Use of weak or deprecated cryptographic algorithms",
                cwe_id="CWE-327",
                regex_patterns=[
                    r'.*MD5\(',
                    r'.*SHA1\(',
                    r'.*DES\(',
                    r'.*RC4\(',
                    r'.*md5\(',
                    r'.*sha1\(',
                    r'.*hashlib\.md5',
                    r'.*hashlib\.sha1'
                ],
                remediation="Use strong cryptographic algorithms like SHA-256 or SHA-3"
            ),

            VulnerabilityPattern(
                pattern_id="crypto_hardcoded_key_1",
                name="Hardcoded Cryptographic Key",
                category=VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="high",
                confidence=0.7,
                description="Cryptographic key hardcoded in source code",
                cwe_id="CWE-798",
                regex_patterns=[
                    r'.*key\s*=\s*["\'][a-fA-F0-9]{16,}["\']',
                    r'.*password\s*=\s*["\'][^"\']{8,}["\']',
                    r'.*secret\s*=\s*["\'][^"\']{8,}["\']',
                    r'.*token\s*=\s*["\'][a-zA-Z0-9]{20,}["\']'
                ],
                remediation="Store cryptographic keys securely outside source code"
            )
        ]

        for pattern in patterns:
            self.add_pattern(pattern)

    def _add_buffer_overflow_patterns(self):
        """Add buffer overflow patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="buffer_overflow_1",
                name="Buffer Overflow via strcpy",
                category=VulnerabilityCategory.BUFFER_OVERFLOW,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="critical",
                confidence=0.9,
                description="Use of unsafe strcpy function without bounds checking",
                cwe_id="CWE-120",
                regex_patterns=[
                    r'.*strcpy\s*\(',
                    r'.*strcat\s*\(',
                    r'.*sprintf\s*\(',
                    r'.*gets\s*\(',
                    r'.*scanf\s*\('
                ],
                remediation="Use safe string functions like strncpy, strncat, snprintf"
            ),

            VulnerabilityPattern(
                pattern_id="buffer_overflow_2",
                name="Buffer Overflow via Array Access",
                category=VulnerabilityCategory.BUFFER_OVERFLOW,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="high",
                confidence=0.6,
                description="Potential buffer overflow due to unchecked array access",
                regex_patterns=[
                    r'.*\[\s*.*\+\+\s*\]',
                    r'.*\[\s*.*\+.*\]',
                    r'.*\[\s*i\s*\].*while',
                    r'.*\[\s*index\s*\]'
                ],
                context_requirements=["no_bounds_check"],
                remediation="Add bounds checking before array access"
            )
        ]

        for pattern in patterns:
            self.add_pattern(pattern)

    def _add_auth_patterns(self):
        """Add authentication patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="auth_weak_password_1",
                name="Weak Password Requirements",
                category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="medium",
                confidence=0.7,
                description="Weak password validation requirements",
                cwe_id="CWE-521",
                regex_patterns=[
                    r'.*len\(.*password.*\)\s*<\s*[1-7]',
                    r'.*password.*\.length\s*<\s*[1-7]',
                    r'.*strlen\(.*password.*\)\s*<\s*[1-7]'
                ],
                remediation="Implement strong password requirements"
            ),

            VulnerabilityPattern(
                pattern_id="auth_session_fixation_1",
                name="Session Fixation Vulnerability",
                category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
                pattern_type=PatternType.MULTI_STATEMENT,
                severity="high",
                confidence=0.6,
                description="Session ID not regenerated after authentication",
                regex_patterns=[
                    r'.*login.*success',
                    r'.*authenticate.*true'
                ],
                context_requirements=["no_session_regeneration"],
                remediation="Regenerate session ID after successful authentication"
            )
        ]

        for pattern in patterns:
            self.add_pattern(pattern)

    def _add_file_patterns(self):
        """Add file handling patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="path_traversal_1",
                name="Path Traversal Vulnerability",
                category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="high",
                confidence=0.8,
                description="File path constructed from user input without validation",
                cwe_id="CWE-22",
                regex_patterns=[
                    r'.*open\(.*request\.',
                    r'.*fopen\(.*\$_',
                    r'.*file\(.*request\.',
                    r'.*include\(.*request\.',
                    r'.*require\(.*request\.',
                    r'.*readFile\(.*req\.'
                ],
                remediation="Validate and sanitize file paths, use whitelist of allowed files"
            ),

            VulnerabilityPattern(
                pattern_id="file_upload_1",
                name="Unrestricted File Upload",
                category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                pattern_type=PatternType.SINGLE_STATEMENT,
                severity="high",
                confidence=0.7,
                description="File upload without proper validation",
                cwe_id="CWE-434",
                regex_patterns=[
                    r'.*save\(.*request\.files',
                    r'.*upload\(.*\$_FILES',
                    r'.*move_uploaded_file\(',
                    r'.*multer\('
                ],
                context_requirements=["no_file_validation"],
                remediation="Validate file type, size, and content before upload"
            )
        ]

        for pattern in patterns:
            self.add_pattern(pattern)

    def add_pattern(self, pattern: VulnerabilityPattern):
        """Add pattern to library"""
        self.patterns[pattern.pattern_id] = pattern

        # Compile regex patterns
        compiled_patterns = []
        for regex_pattern in pattern.regex_patterns:
            try:
                compiled_patterns.append(re.compile(regex_pattern, re.IGNORECASE | re.MULTILINE))
            except re.error as e:
                logging.warning(f"Invalid regex pattern {regex_pattern}: {e}")

        self.compiled_regex[pattern.pattern_id] = compiled_patterns

    def get_pattern(self, pattern_id: str) -> Optional[VulnerabilityPattern]:
        """Get pattern by ID"""
        return self.patterns.get(pattern_id)

    def get_patterns_by_category(self, category: VulnerabilityCategory) -> List[VulnerabilityPattern]:
        """Get patterns by category"""
        return [p for p in self.patterns.values() if p.category == category]

    def load_custom_patterns(self, patterns_file: str):
        """Load custom patterns from file"""
        try:
            with open(patterns_file, 'r') as f:
                custom_patterns = json.load(f)

            for pattern_data in custom_patterns:
                pattern = VulnerabilityPattern(**pattern_data)
                self.add_pattern(pattern)

            logging.info(f"Loaded {len(custom_patterns)} custom patterns")

        except Exception as e:
            logging.error(f"Failed to load custom patterns: {e}")

class PatternMatcher:
    """Matches patterns against code"""

    def __init__(self, pattern_library: PatternLibrary):
        self.pattern_library = pattern_library
        self.ml_matcher = None

    def set_ml_matcher(self, model_path: str):
        """Set ML-based pattern matcher"""
        try:
            self.ml_matcher = PatternEmbedding()
            # Load pre-trained weights if available
            checkpoint = torch.load(model_path, map_location='cpu')
            self.ml_matcher.load_state_dict(checkpoint)
            self.ml_matcher.eval()
        except Exception as e:
            logging.error(f"Failed to load ML matcher: {e}")

    def match_patterns(self, code: str, ast_node: ASTNode, context: Dict[str, Any]) -> List[PatternMatch]:
        """Match patterns against code"""
        matches = []

        # Regex-based matching
        regex_matches = self._match_regex_patterns(code, ast_node, context)
        matches.extend(regex_matches)

        # AST-based matching
        ast_matches = self._match_ast_patterns(ast_node, context)
        matches.extend(ast_matches)

        # ML-based matching
        if self.ml_matcher:
            ml_matches = self._match_ml_patterns(code, ast_node, context)
            matches.extend(ml_matches)

        # Remove duplicates and low-confidence matches
        matches = self._filter_matches(matches)

        return matches

    def _match_regex_patterns(self, code: str, ast_node: ASTNode, context: Dict[str, Any]) -> List[PatternMatch]:
        """Match regex patterns"""
        matches = []

        for pattern_id, pattern in self.pattern_library.patterns.items():
            compiled_patterns = self.pattern_library.compiled_regex.get(pattern_id, [])

            for compiled_pattern in compiled_patterns:
                for match in compiled_pattern.finditer(code):
                    # Check context requirements
                    if self._check_context_requirements(pattern, ast_node, context):
                        pattern_match = PatternMatch(
                            pattern=pattern,
                            location=ast_node.location,
                            matched_code=match.group(),
                            confidence=pattern.confidence,
                            context=context,
                            evidence=[f"Regex match: {match.group()}"]
                        )

                        # Check for false positive indicators
                        fp_indicators = self._check_false_positives(pattern_match, code, context)
                        pattern_match.false_positive_indicators = fp_indicators

                        # Adjust confidence based on false positive indicators
                        if fp_indicators:
                            pattern_match.confidence *= (1.0 - len(fp_indicators) * 0.2)

                        if pattern_match.confidence > 0.3:
                            matches.append(pattern_match)

        return matches

    def _match_ast_patterns(self, ast_node: ASTNode, context: Dict[str, Any]) -> List[PatternMatch]:
        """Match AST-based patterns"""
        matches = []

        # For each pattern with AST requirements
        for pattern in self.pattern_library.patterns.values():
            if pattern.ast_patterns:
                if self._match_ast_structure(ast_node, pattern.ast_patterns, context):
                    pattern_match = PatternMatch(
                        pattern=pattern,
                        location=ast_node.location,
                        matched_code=ast_node.name,
                        confidence=pattern.confidence * 0.9,  # Slightly lower for AST matches
                        context=context,
                        evidence=["AST structure match"]
                    )
                    matches.append(pattern_match)

        return matches

    def _match_ml_patterns(self, code: str, ast_node: ASTNode, context: Dict[str, Any]) -> List[PatternMatch]:
        """Match patterns using ML model"""
        if not self.ml_matcher:
            return []

        try:
            # Tokenize code (simplified)
            tokens = self._tokenize_code(code)
            if len(tokens) < 5:
                return []

            # Convert to tensor
            token_ids = torch.tensor([hash(token) % 10000 for token in tokens[:100]])
            token_ids = token_ids.unsqueeze(0)  # Add batch dimension

            # Get predictions
            with torch.no_grad():
                outputs = self.ml_matcher(token_ids)
                category_scores = outputs['category_scores'].squeeze()
                confidence = outputs['confidence'].squeeze().item()

            matches = []

            # Find high-scoring categories
            for i, score in enumerate(category_scores):
                if score > 0.7:
                    category = list(VulnerabilityCategory)[i]

                    # Find a pattern from this category
                    category_patterns = self.pattern_library.get_patterns_by_category(category)
                    if category_patterns:
                        pattern = category_patterns[0]  # Use first pattern as representative

                        pattern_match = PatternMatch(
                            pattern=pattern,
                            location=ast_node.location,
                            matched_code=code[:100],
                            confidence=float(score) * confidence,
                            context=context,
                            evidence=[f"ML prediction for {category.value}"]
                        )
                        matches.append(pattern_match)

            return matches

        except Exception as e:
            logging.error(f"ML pattern matching failed: {e}")
            return []

    def _tokenize_code(self, code: str) -> List[str]:
        """Tokenize code for ML model"""
        # Simple tokenization - could be improved with proper language-specific tokenizers
        import string

        # Remove comments and strings (simplified)
        lines = code.split('\n')
        cleaned_lines = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                cleaned_lines.append(line)

        cleaned_code = ' '.join(cleaned_lines)

        # Split on whitespace and punctuation
        tokens = []
        current_token = ""

        for char in cleaned_code:
            if char.isalnum() or char == '_':
                current_token += char
            else:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
                if char in string.punctuation:
                    tokens.append(char)

        if current_token:
            tokens.append(current_token)

        return tokens

    def _check_context_requirements(self, pattern: VulnerabilityPattern,
                                  ast_node: ASTNode, context: Dict[str, Any]) -> bool:
        """Check if context requirements are met"""
        if not pattern.context_requirements:
            return True

        for requirement in pattern.context_requirements:
            if requirement == "no_bounds_check":
                if self._has_bounds_check(ast_node, context):
                    return False

            elif requirement == "no_session_regeneration":
                if self._has_session_regeneration(ast_node, context):
                    return False

            elif requirement == "no_file_validation":
                if self._has_file_validation(ast_node, context):
                    return False

            elif requirement == "user_input_present":
                if not self._has_user_input(ast_node, context):
                    return False

        return True

    def _has_bounds_check(self, ast_node: ASTNode, context: Dict[str, Any]) -> bool:
        """Check if bounds checking is present"""
        # Simplified check - look for comparison operations in nearby nodes
        return any('>' in child.name or '<' in child.name or 'len' in child.name
                  for child in ast_node.children)

    def _has_session_regeneration(self, ast_node: ASTNode, context: Dict[str, Any]) -> bool:
        """Check if session regeneration is present"""
        # Look for session regeneration calls
        session_regen_patterns = ['session_regenerate_id', 'regenerate', 'new_session']
        return any(pattern in ast_node.name.lower() for pattern in session_regen_patterns)

    def _has_file_validation(self, ast_node: ASTNode, context: Dict[str, Any]) -> bool:
        """Check if file validation is present"""
        # Look for file validation patterns
        validation_patterns = ['validate', 'check', 'sanitize', 'whitelist', 'allowlist']
        return any(pattern in ast_node.name.lower() for pattern in validation_patterns)

    def _has_user_input(self, ast_node: ASTNode, context: Dict[str, Any]) -> bool:
        """Check if user input is present"""
        input_patterns = ['request', 'input', 'argv', 'GET', 'POST', '$_']
        return any(pattern in ast_node.name for pattern in input_patterns)

    def _match_ast_structure(self, ast_node: ASTNode, ast_patterns: List[Dict[str, Any]],
                           context: Dict[str, Any]) -> bool:
        """Match AST structure patterns"""
        # Simplified AST pattern matching
        for ast_pattern in ast_patterns:
            node_type = ast_pattern.get('node_type')
            if node_type and ast_node.node_type.value == node_type:
                return True

        return False

    def _check_false_positives(self, pattern_match: PatternMatch, code: str,
                             context: Dict[str, Any]) -> List[str]:
        """Check for false positive indicators"""
        fp_indicators = []

        # Check for comments indicating false positive
        if '# nosec' in code or '// nosec' in code:
            fp_indicators.append("security_exception_comment")

        # Check for test code
        if any(test_indicator in code.lower()
              for test_indicator in ['test_', 'mock_', 'fake_', 'dummy_']):
            fp_indicators.append("test_code")

        # Check for example/demo code
        if any(demo_indicator in code.lower()
              for demo_indicator in ['example', 'demo', 'sample', 'tutorial']):
            fp_indicators.append("example_code")

        # Check for proper input validation
        if pattern_match.pattern.category == VulnerabilityCategory.INJECTION:
            validation_patterns = ['validate', 'sanitize', 'escape', 'filter', 'clean']
            if any(pattern in code.lower() for pattern in validation_patterns):
                fp_indicators.append("input_validation_present")

        return fp_indicators

    def _filter_matches(self, matches: List[PatternMatch]) -> List[PatternMatch]:
        """Filter and deduplicate matches"""
        # Remove duplicates based on location and pattern
        seen = set()
        filtered = []

        for match in matches:
            key = (match.pattern.pattern_id, match.location.file_path, match.location.line)
            if key not in seen:
                seen.add(key)
                filtered.append(match)

        # Sort by confidence
        filtered.sort(key=lambda m: m.confidence, reverse=True)

        return filtered

class VulnerabilityPatternDetector:
    """Main vulnerability pattern detection engine"""

    def __init__(self, patterns_dir: Optional[str] = None):
        self.pattern_library = PatternLibrary()
        self.pattern_matcher = PatternMatcher(self.pattern_library)

        if patterns_dir:
            self._load_custom_patterns(patterns_dir)

    def _load_custom_patterns(self, patterns_dir: str):
        """Load custom patterns from directory"""
        patterns_path = Path(patterns_dir)
        if patterns_path.exists():
            for pattern_file in patterns_path.glob("*.json"):
                self.pattern_library.load_custom_patterns(str(pattern_file))

    def detect_vulnerabilities(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Detect vulnerabilities using pattern matching"""
        detection_results = {
            'findings': [],
            'pattern_matches': [],
            'statistics': {},
            'false_positives': []
        }

        # Read source code
        try:
            with open(analysis_result.file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            logging.error(f"Failed to read source file: {e}")
            return detection_results

        # Analyze entire file
        file_matches = self._analyze_code_segment(source_code, analysis_result.ast, {})
        detection_results['pattern_matches'].extend(file_matches)

        # Analyze each function
        for function in analysis_result.functions:
            function_code = self._extract_function_code(function, source_code)
            if function_code:
                context = {
                    'function_name': function.name,
                    'function_parameters': function.parameters,
                    'called_functions': function.called_functions
                }

                func_matches = self._analyze_code_segment(function_code, function.ast_node, context)
                detection_results['pattern_matches'].extend(func_matches)

        # Group matches into findings
        findings = self._group_matches_into_findings(detection_results['pattern_matches'])
        detection_results['findings'] = findings

        # Identify potential false positives
        false_positives = self._identify_false_positives(detection_results['pattern_matches'])
        detection_results['false_positives'] = false_positives

        # Calculate statistics
        detection_results['statistics'] = self._calculate_detection_statistics(detection_results)

        return detection_results

    def _analyze_code_segment(self, code: str, ast_node: ASTNode, context: Dict[str, Any]) -> List[PatternMatch]:
        """Analyze code segment for vulnerability patterns"""
        matches = self.pattern_matcher.match_patterns(code, ast_node, context)

        # Recursively analyze child nodes
        for child in ast_node.children:
            child_code = self._extract_node_code(child, code)
            if child_code:
                child_matches = self.pattern_matcher.match_patterns(child_code, child, context)
                matches.extend(child_matches)

        return matches

    def _extract_function_code(self, function: Function, source_code: str) -> str:
        """Extract function code from source"""
        try:
            lines = source_code.split('\n')
            start_line = function.location.line - 1  # Convert to 0-based
            end_line = function.location.end_line if function.location.end_line else start_line + 20

            return '\n'.join(lines[start_line:end_line])

        except Exception as e:
            logging.error(f"Failed to extract function code: {e}")
            return ""

    def _extract_node_code(self, node: ASTNode, source_code: str) -> str:
        """Extract code for AST node"""
        try:
            lines = source_code.split('\n')
            start_line = node.location.line - 1
            end_line = node.location.end_line if node.location.end_line else start_line + 1

            return '\n'.join(lines[start_line:end_line])

        except Exception:
            return ""

    def _group_matches_into_findings(self, matches: List[PatternMatch]) -> List[VulnerabilityFinding]:
        """Group related pattern matches into vulnerability findings"""
        findings = []

        # Group matches by location and pattern type
        location_groups = defaultdict(list)
        for match in matches:
            key = (match.location.file_path, match.location.line, match.pattern.category)
            location_groups[key].append(match)

        # Create findings from groups
        for group_key, group_matches in location_groups.items():
            if not group_matches:
                continue

            primary_match = max(group_matches, key=lambda m: m.confidence)

            finding_id = hashlib.md5(
                f"{group_key[0]}:{group_key[1]}:{primary_match.pattern.pattern_id}".encode()
            ).hexdigest()[:16]

            finding = VulnerabilityFinding(
                finding_id=finding_id,
                pattern_matches=group_matches,
                primary_location=primary_match.location,
                affected_functions=self._extract_affected_functions(group_matches),
                severity=primary_match.pattern.severity,
                confidence=max(m.confidence for m in group_matches),
                title=primary_match.pattern.name,
                description=primary_match.pattern.description,
                impact=self._calculate_impact(primary_match.pattern),
                remediation=primary_match.pattern.remediation,
                cwe_id=primary_match.pattern.cwe_id,
                owasp_category=primary_match.pattern.owasp_category,
                references=primary_match.pattern.references,
                metadata={
                    'pattern_count': len(group_matches),
                    'evidence': [evidence for match in group_matches for evidence in match.evidence]
                }
            )

            findings.append(finding)

        # Sort by severity and confidence
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 0), f.confidence), reverse=True)

        return findings

    def _extract_affected_functions(self, matches: List[PatternMatch]) -> List[str]:
        """Extract list of affected functions"""
        functions = set()
        for match in matches:
            func_name = match.context.get('function_name')
            if func_name:
                functions.add(func_name)
        return list(functions)

    def _calculate_impact(self, pattern: VulnerabilityPattern) -> str:
        """Calculate impact description"""
        impact_map = {
            VulnerabilityCategory.INJECTION: "Code execution, data theft, system compromise",
            VulnerabilityCategory.CROSS_SITE_SCRIPTING: "Session hijacking, data theft, defacement",
            VulnerabilityCategory.BUFFER_OVERFLOW: "Code execution, denial of service, system crash",
            VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES: "Data exposure, authentication bypass",
            VulnerabilityCategory.BROKEN_AUTHENTICATION: "Unauthorized access, account takeover",
            VulnerabilityCategory.BROKEN_ACCESS_CONTROL: "Privilege escalation, unauthorized data access"
        }

        return impact_map.get(pattern.category, "Security risk, potential system compromise")

    def _identify_false_positives(self, matches: List[PatternMatch]) -> List[PatternMatch]:
        """Identify potential false positives"""
        false_positives = []

        for match in matches:
            # High number of false positive indicators
            if len(match.false_positive_indicators) >= 2:
                false_positives.append(match)

            # Very low confidence after adjustments
            elif match.confidence < 0.3:
                false_positives.append(match)

        return false_positives

    def _calculate_detection_statistics(self, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate detection statistics"""
        findings = detection_results['findings']
        matches = detection_results['pattern_matches']

        stats = {
            'total_findings': len(findings),
            'total_matches': len(matches),
            'findings_by_severity': defaultdict(int),
            'findings_by_category': defaultdict(int),
            'average_confidence': 0.0,
            'potential_false_positives': len(detection_results['false_positives'])
        }

        for finding in findings:
            stats['findings_by_severity'][finding.severity] += 1
            stats['findings_by_category'][finding.pattern_matches[0].pattern.category.value] += 1

        if findings:
            stats['average_confidence'] = sum(f.confidence for f in findings) / len(findings)

        return dict(stats)

    def generate_detection_report(self, detection_results: Dict[str, Any], file_path: str) -> str:
        """Generate comprehensive detection report"""
        report = []
        report.append(f"Vulnerability Pattern Detection Report: {Path(file_path).name}")
        report.append("=" * 70)

        findings = detection_results['findings']
        stats = detection_results['statistics']

        # Summary
        report.append("Summary:")
        report.append(f"  Total Findings: {stats['total_findings']}")
        report.append(f"  Total Pattern Matches: {stats['total_matches']}")
        report.append(f"  Average Confidence: {stats['average_confidence']:.2f}")
        report.append(f"  Potential False Positives: {stats['potential_false_positives']}")
        report.append("")

        # Findings by severity
        if stats['findings_by_severity']:
            report.append("Findings by Severity:")
            for severity, count in sorted(stats['findings_by_severity'].items(),
                                        key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x[0], 0),
                                        reverse=True):
                report.append(f"  {severity.upper()}: {count}")
            report.append("")

        # Findings by category
        if stats['findings_by_category']:
            report.append("Findings by Category:")
            for category, count in sorted(stats['findings_by_category'].items()):
                report.append(f"  {category}: {count}")
            report.append("")

        # Detailed findings
        if findings:
            report.append("Detailed Findings:")
            report.append("-" * 30)

            for i, finding in enumerate(findings[:20]):  # Show top 20
                report.append(f"Finding #{i+1}: {finding.title}")
                report.append(f"  Severity: {finding.severity.upper()}")
                report.append(f"  Confidence: {finding.confidence:.2f}")
                report.append(f"  Location: {finding.primary_location.file_path}:{finding.primary_location.line}")

                if finding.cwe_id:
                    report.append(f"  CWE: {finding.cwe_id}")

                if finding.owasp_category:
                    report.append(f"  OWASP: {finding.owasp_category}")

                report.append(f"  Description: {finding.description}")
                report.append(f"  Impact: {finding.impact}")
                report.append(f"  Remediation: {finding.remediation}")

                if finding.affected_functions:
                    report.append(f"  Affected Functions: {', '.join(finding.affected_functions)}")

                report.append("")

        return "\n".join(report)