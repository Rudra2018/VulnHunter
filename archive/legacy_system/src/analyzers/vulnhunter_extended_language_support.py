#!/usr/bin/env python3
"""
VulnHunter Ω Extended Language Support
Multi-language vulnerability detection for Go, Rust, TypeScript, and more
"""

import re
import ast
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

import torch
import torch.nn as nn
import numpy as np

class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    PHP = "php"

@dataclass
class VulnerabilityPattern:
    """Language-specific vulnerability pattern"""
    name: str
    language: Language
    pattern: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    recommendation: str
    cwe_id: Optional[str] = None

@dataclass
class LanguageAnalysisResult:
    """Result of language-specific analysis"""
    language: Language
    vulnerabilities: List[Dict[str, Any]]
    confidence: float
    analysis_time_ms: float
    features_extracted: int

class LanguagePatternEngine:
    """Advanced pattern-based vulnerability detection for multiple languages"""

    def __init__(self):
        self.logger = logging.getLogger('LanguagePatternEngine')
        self.patterns = self._initialize_patterns()
        self.language_configs = self._initialize_language_configs()

    def _initialize_patterns(self) -> Dict[Language, List[VulnerabilityPattern]]:
        """Initialize vulnerability patterns for all supported languages"""
        patterns = {
            Language.GO: [
                VulnerabilityPattern(
                    name="sql_injection",
                    language=Language.GO,
                    pattern=r'Query\s*\(\s*["\'].*\+.*["\']|Exec\s*\(\s*["\'].*\+.*["\']',
                    severity="critical",
                    description="SQL injection vulnerability in database query",
                    recommendation="Use parameterized queries with placeholders ($1, $2, etc.)",
                    cwe_id="CWE-89"
                ),
                VulnerabilityPattern(
                    name="command_injection",
                    language=Language.GO,
                    pattern=r'exec\.Command\s*\(\s*["\'].*\+.*["\']|os\.exec\s*\(\s*.*\+',
                    severity="critical",
                    description="Command injection vulnerability",
                    recommendation="Avoid string concatenation in exec.Command, use argument arrays",
                    cwe_id="CWE-78"
                ),
                VulnerabilityPattern(
                    name="path_traversal",
                    language=Language.GO,
                    pattern=r'filepath\.Join\s*\(\s*.*\+|os\.Open\s*\(\s*.*\+.*\.\.',
                    severity="high",
                    description="Path traversal vulnerability",
                    recommendation="Validate and sanitize file paths, use filepath.Clean()",
                    cwe_id="CWE-22"
                ),
                VulnerabilityPattern(
                    name="unsafe_tls",
                    language=Language.GO,
                    pattern=r'InsecureSkipVerify\s*:\s*true|tls\.Config.*InsecureSkipVerify',
                    severity="high",
                    description="Insecure TLS configuration",
                    recommendation="Never skip TLS certificate verification in production",
                    cwe_id="CWE-295"
                ),
                VulnerabilityPattern(
                    name="hardcoded_credentials",
                    language=Language.GO,
                    pattern=r'password\s*[:=]\s*["\'][^"\']+["\']|apikey\s*[:=]\s*["\'][^"\']+["\']',
                    severity="critical",
                    description="Hardcoded credentials found",
                    recommendation="Use environment variables or secure configuration management",
                    cwe_id="CWE-798"
                )
            ],

            Language.RUST: [
                VulnerabilityPattern(
                    name="unsafe_block",
                    language=Language.RUST,
                    pattern=r'unsafe\s*\{[^}]*\*.*[^}]*\}',
                    severity="high",
                    description="Potentially dangerous unsafe block with raw pointer dereference",
                    recommendation="Minimize unsafe code, validate all pointer operations",
                    cwe_id="CWE-119"
                ),
                VulnerabilityPattern(
                    name="sql_injection",
                    language=Language.RUST,
                    pattern=r'execute\s*\(\s*&format!|query\s*\(\s*&format!',
                    severity="critical",
                    description="SQL injection via string formatting",
                    recommendation="Use parameterized queries with sqlx or diesel",
                    cwe_id="CWE-89"
                ),
                VulnerabilityPattern(
                    name="command_injection",
                    language=Language.RUST,
                    pattern=r'Command::new\s*\(\s*&format!|\.arg\s*\(\s*&format!',
                    severity="critical",
                    description="Command injection vulnerability",
                    recommendation="Avoid format! in Command::new, use separate arguments",
                    cwe_id="CWE-78"
                ),
                VulnerabilityPattern(
                    name="deserialization",
                    language=Language.RUST,
                    pattern=r'serde_json::from_str.*user_input|bincode::deserialize.*untrusted',
                    severity="high",
                    description="Unsafe deserialization of untrusted data",
                    recommendation="Validate and sanitize data before deserialization",
                    cwe_id="CWE-502"
                ),
                VulnerabilityPattern(
                    name="integer_overflow",
                    language=Language.RUST,
                    pattern=r'\.wrapping_add\(|\.wrapping_sub\(|\.wrapping_mul\(',
                    severity="medium",
                    description="Potential integer overflow with wrapping operations",
                    recommendation="Use checked arithmetic or explicitly handle overflow",
                    cwe_id="CWE-190"
                )
            ],

            Language.TYPESCRIPT: [
                VulnerabilityPattern(
                    name="xss_vulnerability",
                    language=Language.TYPESCRIPT,
                    pattern=r'innerHTML\s*=\s*.*\+|document\.write\s*\(\s*.*\+',
                    severity="critical",
                    description="Cross-site scripting (XSS) vulnerability",
                    recommendation="Use textContent instead of innerHTML, sanitize user input",
                    cwe_id="CWE-79"
                ),
                VulnerabilityPattern(
                    name="sql_injection",
                    language=Language.TYPESCRIPT,
                    pattern=r'query\s*\(\s*["`\'].*\$\{.*\}.*["`\']|execute\s*\(\s*["`\'].*\+',
                    severity="critical",
                    description="SQL injection vulnerability",
                    recommendation="Use parameterized queries or ORM with parameter binding",
                    cwe_id="CWE-89"
                ),
                VulnerabilityPattern(
                    name="prototype_pollution",
                    language=Language.TYPESCRIPT,
                    pattern=r'JSON\.parse\s*\(.*req\.|Object\.assign\s*\(\s*\{\}\s*,.*req\.',
                    severity="high",
                    description="Prototype pollution vulnerability",
                    recommendation="Validate object keys and use Object.create(null) or Map",
                    cwe_id="CWE-1321"
                ),
                VulnerabilityPattern(
                    name="insecure_random",
                    language=Language.TYPESCRIPT,
                    pattern=r'Math\.random\s*\(\s*\).*token|Math\.random\s*\(\s*\).*password',
                    severity="high",
                    description="Cryptographically insecure random number generation",
                    recommendation="Use crypto.randomBytes() or crypto.getRandomValues()",
                    cwe_id="CWE-338"
                ),
                VulnerabilityPattern(
                    name="eval_injection",
                    language=Language.TYPESCRIPT,
                    pattern=r'eval\s*\(\s*.*\+|Function\s*\(\s*.*\+.*\)\s*\(',
                    severity="critical",
                    description="Code injection via eval() or Function constructor",
                    recommendation="Avoid eval(), use JSON.parse() or safe alternatives",
                    cwe_id="CWE-95"
                )
            ],

            Language.JAVA: [
                VulnerabilityPattern(
                    name="sql_injection",
                    language=Language.JAVA,
                    pattern=r'Statement\.execute\s*\(\s*.*\+|createStatement\(\)\.execute\s*\(\s*.*\+',
                    severity="critical",
                    description="SQL injection vulnerability",
                    recommendation="Use PreparedStatement with parameter placeholders",
                    cwe_id="CWE-89"
                ),
                VulnerabilityPattern(
                    name="xxe_vulnerability",
                    language=Language.JAVA,
                    pattern=r'DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)',
                    severity="high",
                    description="XML External Entity (XXE) vulnerability",
                    recommendation="Disable external entity processing in XML parsers",
                    cwe_id="CWE-611"
                ),
                VulnerabilityPattern(
                    name="deserialization",
                    language=Language.JAVA,
                    pattern=r'ObjectInputStream\.readObject\(\)|Serializable.*readObject',
                    severity="critical",
                    description="Insecure deserialization vulnerability",
                    recommendation="Validate serialized data, use allowlist for classes",
                    cwe_id="CWE-502"
                ),
                VulnerabilityPattern(
                    name="ldap_injection",
                    language=Language.JAVA,
                    pattern=r'InitialDirContext\.search\s*\(\s*.*\+|DirContext\.search\s*\(\s*.*\+',
                    severity="high",
                    description="LDAP injection vulnerability",
                    recommendation="Escape LDAP special characters in user input",
                    cwe_id="CWE-90"
                )
            ],

            Language.CPP: [
                VulnerabilityPattern(
                    name="buffer_overflow",
                    language=Language.CPP,
                    pattern=r'strcpy\s*\(|strcat\s*\(|sprintf\s*\(|gets\s*\(',
                    severity="critical",
                    description="Buffer overflow vulnerability",
                    recommendation="Use safe alternatives like strncpy, strncat, snprintf",
                    cwe_id="CWE-120"
                ),
                VulnerabilityPattern(
                    name="null_pointer",
                    language=Language.CPP,
                    pattern=r'malloc\s*\([^)]+\)\s*;[^}]*\*.*=|\*\w+\s*=.*malloc.*[^}]*\*\w+',
                    severity="high",
                    description="Potential null pointer dereference",
                    recommendation="Check malloc return value before dereferencing",
                    cwe_id="CWE-476"
                ),
                VulnerabilityPattern(
                    name="use_after_free",
                    language=Language.CPP,
                    pattern=r'free\s*\(\s*\w+\s*\).*\*\w+|delete\s+\w+.*\*\w+',
                    severity="critical",
                    description="Use after free vulnerability",
                    recommendation="Set pointer to NULL after free, use smart pointers",
                    cwe_id="CWE-416"
                ),
                VulnerabilityPattern(
                    name="integer_overflow",
                    language=Language.CPP,
                    pattern=r'int\s+\w+\s*=\s*.*\*.*\+|\w+\s*\+=\s*.*\*',
                    severity="medium",
                    description="Potential integer overflow",
                    recommendation="Check for overflow before arithmetic operations",
                    cwe_id="CWE-190"
                )
            ],

            Language.PHP: [
                VulnerabilityPattern(
                    name="sql_injection",
                    language=Language.PHP,
                    pattern=r'mysql_query\s*\(\s*.*\$|mysqli_query\s*\(\s*.*\$.*\.',
                    severity="critical",
                    description="SQL injection vulnerability",
                    recommendation="Use prepared statements with PDO or mysqli",
                    cwe_id="CWE-89"
                ),
                VulnerabilityPattern(
                    name="xss_vulnerability",
                    language=Language.PHP,
                    pattern=r'echo\s+\$_GET|echo\s+\$_POST|print\s+\$_REQUEST',
                    severity="critical",
                    description="Cross-site scripting (XSS) vulnerability",
                    recommendation="Use htmlspecialchars() to escape output",
                    cwe_id="CWE-79"
                ),
                VulnerabilityPattern(
                    name="file_inclusion",
                    language=Language.PHP,
                    pattern=r'include\s*\(\s*\$|require\s*\(\s*\$|include_once\s*\(\s*\$',
                    severity="critical",
                    description="Local/Remote file inclusion vulnerability",
                    recommendation="Validate and whitelist included files",
                    cwe_id="CWE-98"
                ),
                VulnerabilityPattern(
                    name="code_injection",
                    language=Language.PHP,
                    pattern=r'eval\s*\(\s*\$|assert\s*\(\s*\$|preg_replace.*\/e',
                    severity="critical",
                    description="Code injection vulnerability",
                    recommendation="Avoid eval() and dynamic code execution",
                    cwe_id="CWE-95"
                )
            ]
        }

        return patterns

    def _initialize_language_configs(self) -> Dict[Language, Dict[str, Any]]:
        """Initialize language-specific configurations"""
        return {
            Language.GO: {
                'extensions': ['.go'],
                'comment_patterns': [r'//.*', r'/\*[\s\S]*?\*/'],
                'string_patterns': [r'"[^"]*"', r'`[^`]*`'],
                'import_pattern': r'import\s*\(\s*([^)]+)\)',
                'function_pattern': r'func\s+(\w+)\s*\([^)]*\)\s*[^{]*{'
            },
            Language.RUST: {
                'extensions': ['.rs'],
                'comment_patterns': [r'//.*', r'/\*[\s\S]*?\*/'],
                'string_patterns': [r'"[^"]*"', r'r"[^"]*"'],
                'import_pattern': r'use\s+([^;]+);',
                'function_pattern': r'fn\s+(\w+)\s*\([^)]*\)\s*[^{]*{'
            },
            Language.TYPESCRIPT: {
                'extensions': ['.ts', '.tsx'],
                'comment_patterns': [r'//.*', r'/\*[\s\S]*?\*/', r'<!--[\s\S]*?-->'],
                'string_patterns': [r'"[^"]*"', r"'[^']*'", r'`[^`]*`'],
                'import_pattern': r'import\s+.*from\s+["\'][^"\']+["\']',
                'function_pattern': r'function\s+(\w+)\s*\([^)]*\)|(\w+)\s*=\s*\([^)]*\)\s*=>'
            },
            Language.JAVA: {
                'extensions': ['.java'],
                'comment_patterns': [r'//.*', r'/\*[\s\S]*?\*/'],
                'string_patterns': [r'"[^"]*"'],
                'import_pattern': r'import\s+([^;]+);',
                'function_pattern': r'(public|private|protected)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*{'
            },
            Language.CPP: {
                'extensions': ['.cpp', '.cc', '.cxx', '.c++'],
                'comment_patterns': [r'//.*', r'/\*[\s\S]*?\*/'],
                'string_patterns': [r'"[^"]*"'],
                'import_pattern': r'#include\s*[<"][^>"]+[>"]',
                'function_pattern': r'\w+\s+(\w+)\s*\([^)]*\)\s*{'
            },
            Language.C: {
                'extensions': ['.c', '.h'],
                'comment_patterns': [r'//.*', r'/\*[\s\S]*?\*/'],
                'string_patterns': [r'"[^"]*"'],
                'import_pattern': r'#include\s*[<"][^>"]+[>"]',
                'function_pattern': r'\w+\s+(\w+)\s*\([^)]*\)\s*{'
            },
            Language.PHP: {
                'extensions': ['.php'],
                'comment_patterns': [r'//.*', r'#.*', r'/\*[\s\S]*?\*/'],
                'string_patterns': [r'"[^"]*"', r"'[^']*'"],
                'import_pattern': r'require_once\s*["\'][^"\']+["\']|include\s*["\'][^"\']+["\']',
                'function_pattern': r'function\s+(\w+)\s*\([^)]*\)'
            }
        }

    def detect_language(self, code: str, filename: str = "") -> Language:
        """Detect programming language from code or filename"""
        # Try to detect by file extension first
        for lang, config in self.language_configs.items():
            for ext in config['extensions']:
                if filename.endswith(ext):
                    return lang

        # Fallback to content-based detection
        if 'package main' in code or 'func main()' in code:
            return Language.GO
        elif 'fn main()' in code or 'use std::' in code:
            return Language.RUST
        elif 'interface ' in code and ('export ' in code or 'import ' in code):
            return Language.TYPESCRIPT
        elif 'public class' in code or 'import java.' in code:
            return Language.JAVA
        elif '#include <' in code or 'int main(' in code:
            return Language.CPP if '::' in code else Language.C
        elif '<?php' in code or '$_GET' in code:
            return Language.PHP
        elif 'def ' in code or 'import ' in code:
            return Language.PYTHON
        else:
            return Language.JAVASCRIPT  # Default fallback

    def analyze_code(self, code: str, language: Language = None, filename: str = "") -> LanguageAnalysisResult:
        """Analyze code for vulnerabilities in the specified language"""
        start_time = time.time()

        if language is None:
            language = self.detect_language(code, filename)

        vulnerabilities = []
        features_extracted = 0

        # Get patterns for the detected language
        patterns = self.patterns.get(language, [])

        # Analyze code against each pattern
        for pattern in patterns:
            matches = list(re.finditer(pattern.pattern, code, re.IGNORECASE | re.MULTILINE))

            for match in matches:
                # Calculate line number
                line_num = code[:match.start()].count('\n') + 1

                # Extract code snippet
                lines = code.split('\n')
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                snippet = '\n'.join(lines[start_line:end_line])

                vulnerability = {
                    'type': pattern.name,
                    'severity': pattern.severity,
                    'description': pattern.description,
                    'recommendation': pattern.recommendation,
                    'line': line_num,
                    'column': match.start() - code.rfind('\n', 0, match.start()),
                    'code': snippet,
                    'confidence': self._calculate_confidence(pattern, match, code),
                    'cwe_id': pattern.cwe_id,
                    'match_text': match.group(0)
                }

                vulnerabilities.append(vulnerability)
                features_extracted += 1

        # Calculate overall confidence
        if vulnerabilities:
            confidence = sum(v['confidence'] for v in vulnerabilities) / len(vulnerabilities)
        else:
            confidence = 0.0

        analysis_time_ms = (time.time() - start_time) * 1000

        return LanguageAnalysisResult(
            language=language,
            vulnerabilities=vulnerabilities,
            confidence=confidence,
            analysis_time_ms=analysis_time_ms,
            features_extracted=features_extracted
        )

    def _calculate_confidence(self, pattern: VulnerabilityPattern, match: re.Match, code: str) -> float:
        """Calculate confidence score for a vulnerability match"""
        base_confidence = 0.7

        # Context analysis
        context_before = code[max(0, match.start() - 100):match.start()]
        context_after = code[match.end():match.end() + 100]

        # Increase confidence if in user input handling context
        user_input_indicators = ['input', 'request', 'param', 'user', 'form', 'query']
        if any(indicator in context_before.lower() for indicator in user_input_indicators):
            base_confidence += 0.2

        # Decrease confidence if in comment or string
        if self._is_in_comment_or_string(code, match.start(), pattern.language):
            base_confidence -= 0.4

        # Adjust based on pattern severity
        severity_multipliers = {
            'critical': 1.0,
            'high': 0.9,
            'medium': 0.8,
            'low': 0.7
        }
        base_confidence *= severity_multipliers.get(pattern.severity, 0.7)

        return min(1.0, max(0.0, base_confidence))

    def _is_in_comment_or_string(self, code: str, position: int, language: Language) -> bool:
        """Check if position is within a comment or string literal"""
        config = self.language_configs.get(language, {})

        # Check comments
        for comment_pattern in config.get('comment_patterns', []):
            for match in re.finditer(comment_pattern, code):
                if match.start() <= position <= match.end():
                    return True

        # Check strings
        for string_pattern in config.get('string_patterns', []):
            for match in re.finditer(string_pattern, code):
                if match.start() <= position <= match.end():
                    return True

        return False

class ExtendedLanguageAnalyzer:
    """Main analyzer for extended language support"""

    def __init__(self):
        self.logger = logging.getLogger('ExtendedLanguageAnalyzer')
        self.pattern_engine = LanguagePatternEngine()

        # Initialize neural components
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.feature_extractor = self._create_feature_extractor()

        self.logger.info("🚀 Extended Language Analyzer Initialized")
        self.logger.info(f"📊 Supported languages: {[lang.value for lang in Language]}")

    def _create_feature_extractor(self) -> nn.Module:
        """Create neural feature extractor for language-agnostic analysis"""
        return nn.Sequential(
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 64)
        ).to(self.device)

    def analyze_multi_language_project(self, project_path: str) -> Dict[str, Any]:
        """Analyze entire project with multiple languages"""
        import os

        results = {}
        total_files = 0
        total_vulnerabilities = 0

        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)

                # Skip binary files and common build directories
                if any(skip in file_path for skip in ['.git', 'node_modules', '__pycache__', '.venv']):
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()

                    if code.strip():
                        analysis = self.pattern_engine.analyze_code(code, filename=file_path)

                        if analysis.vulnerabilities:
                            results[file_path] = {
                                'language': analysis.language.value,
                                'vulnerabilities': analysis.vulnerabilities,
                                'confidence': analysis.confidence,
                                'analysis_time_ms': analysis.analysis_time_ms
                            }

                            total_vulnerabilities += len(analysis.vulnerabilities)

                        total_files += 1

                except Exception as e:
                    self.logger.debug(f"Could not analyze {file_path}: {e}")

        return {
            'results': results,
            'summary': {
                'total_files_analyzed': total_files,
                'files_with_vulnerabilities': len(results),
                'total_vulnerabilities': total_vulnerabilities,
                'languages_detected': list(set(r['language'] for r in results.values()))
            }
        }

    def analyze_code(self, code: str, language: str = None, filename: str = "") -> Dict[str, Any]:
        """Analyze single code snippet"""
        if language:
            try:
                lang_enum = Language(language.lower())
            except ValueError:
                lang_enum = None
        else:
            lang_enum = None

        analysis = self.pattern_engine.analyze_code(code, lang_enum, filename)

        return {
            'language': analysis.language.value,
            'vulnerabilities': analysis.vulnerabilities,
            'confidence': analysis.confidence,
            'analysis_time_ms': analysis.analysis_time_ms,
            'features_extracted': analysis.features_extracted
        }

def demo_extended_language_support():
    """Demonstrate extended language support capabilities"""
    analyzer = ExtendedLanguageAnalyzer()

    # Test cases for different languages
    test_cases = [
        # Go SQL injection
        ('go', '''
package main

import (
    "database/sql"
    "fmt"
)

func getUserData(username string) {
    db, _ := sql.Open("mysql", "user:pass@/dbname")
    query := "SELECT * FROM users WHERE username = '" + username + "'"
    rows, err := db.Query(query)  // Vulnerable!
    fmt.Println(rows, err)
}
        '''),

        # Rust unsafe code
        ('rust', '''
use std::ptr;

fn dangerous_operation(data: *mut u8) {
    unsafe {
        *data = 42;  // Potentially dangerous
        ptr::write(data, 100);
    }
}

fn main() {
    let mut value = 0u8;
    dangerous_operation(&mut value as *mut u8);
}
        '''),

        # TypeScript XSS
        ('typescript', '''
function displayUserData(userData: string) {
    const container = document.getElementById('user-info');
    if (container) {
        container.innerHTML = userData;  // XSS vulnerability!
    }
}

function searchResults(query: string) {
    document.write("<h1>Results for: " + query + "</h1>");  // XSS!
}
        '''),

        # C++ buffer overflow
        ('cpp', '''
#include <cstring>
#include <iostream>

void processInput(char* input) {
    char buffer[100];
    strcpy(buffer, input);  // Buffer overflow!
    std::cout << buffer << std::endl;
}

int main() {
    char userInput[1000];
    gets(userInput);  // Dangerous function!
    processInput(userInput);
    return 0;
}
        ''')
    ]

    print("🔍 VulnHunter Extended Language Support Demo")
    print("=" * 60)

    for language, code in test_cases:
        print(f"\n📝 Analyzing {language.upper()} code:")
        print("-" * 40)

        result = analyzer.analyze_code(code, language)

        print(f"Language detected: {result['language']}")
        print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
        print(f"Analysis time: {result['analysis_time_ms']:.2f}ms")
        print(f"Overall confidence: {result['confidence']:.2f}")

        for i, vuln in enumerate(result['vulnerabilities'], 1):
            print(f"\n  🚨 Vulnerability #{i}:")
            print(f"     Type: {vuln['type']}")
            print(f"     Severity: {vuln['severity']}")
            print(f"     Line: {vuln['line']}")
            print(f"     Confidence: {vuln['confidence']:.2f}")
            print(f"     Description: {vuln['description']}")
            print(f"     CWE ID: {vuln.get('cwe_id', 'N/A')}")

    print("\n✅ Extended language support demo completed!")

if __name__ == "__main__":
    demo_extended_language_support()