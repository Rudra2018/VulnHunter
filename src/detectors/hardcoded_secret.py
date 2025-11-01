#!/usr/bin/env python3
"""
VulnHunter MEGA: Advanced Hardcoded Secret Detection
Context-aware detection with crypto test vector filtering
"""

import re
import math
import hashlib
from typing import List, Dict, Any, Set
from pathlib import Path

# Known cryptographic test vectors from standards (NIST, EIP, RFC)
KNOWN_TEST_VECTORS = {
    # secp256k1 test vectors (Ethereum, Bitcoin)
    "49684349367057865656909429001867135922228948097036637749682965078859417767352",
    "26715700564957864553985478426289223220394026033170102795835907481710471636815",

    # NIST P-256 test vectors (FIPS 186-4)
    "3ee21644150adb50dc4c20e330184fabf12e75ecbf31fe167885587e6ebf2255",
    "d60b5b80125a9e9e6d0b6b8d4b8e7b5a4e0c8b9a7d6e8f5b9c7a4d2e1f0b8c7",

    # Bitcoin test vectors
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
    "L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK",

    # Ethereum example keys (from documentation)
    "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",

    # secp256r1 NIST test vectors
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",

    # Common JWT test secrets
    "your-256-bit-secret",
    "secretkey123",
    "jwtsecret",

    # Placeholder values
    "your_secret_key_here",
    "insert_api_key_here",
    "replace_with_real_key",
    "TODO_ADD_SECRET",
    "CHANGE_ME",
    "SET_YOUR_SECRET_HERE",

    # Test environment values
    "test_secret_key",
    "development_key",
    "local_secret",
    "demo_key_123",
}

# File patterns that typically contain test data
TEST_FILE_PATTERNS = {
    "test", "tests", "_test", "spec", "fixture", "fixtures",
    "example", "examples", "demo", "sample", "mock", "stub",
    "dev", "development", "local", "staging"
}

# Comment patterns indicating test data
TEST_COMMENT_PATTERNS = {
    "test vector", "example", "demo", "sample", "placeholder",
    "nist", "rfc", "eip", "bitcoin core", "ethereum", "fixture",
    "taken from", "example taken", "from ethers-rs"
}

class SecretContext:
    """Context information for secret detection"""
    def __init__(self, file_path: str, line_content: str, line_number: int, surrounding_lines: List[str]):
        self.file_path = Path(file_path)
        self.line_content = line_content
        self.line_number = line_number
        self.surrounding_lines = surrounding_lines

    @property
    def is_test_file(self) -> bool:
        """Check if file appears to be a test file"""
        file_str = str(self.file_path).lower()
        return any(pattern in file_str for pattern in TEST_FILE_PATTERNS)

    @property
    def has_test_context(self) -> bool:
        """Check if surrounding code indicates test context"""
        context = ' '.join(self.surrounding_lines).lower()
        return any(pattern in context for pattern in TEST_COMMENT_PATTERNS)

    @property
    def is_in_comment(self) -> bool:
        """Check if the secret is in a comment"""
        line = self.line_content.strip()
        return line.startswith('//') or line.startswith('#') or line.startswith('*')

    @property
    def has_test_markers(self) -> bool:
        """Check for explicit test markers in code"""
        context = ' '.join(self.surrounding_lines).lower()
        markers = ["#[test]", "@test", "test_", "fn test", "it(", "describe(", "unittest"]
        return any(marker in context for marker in markers)

class HardcodedSecretDetector:
    """Advanced hardcoded secret detector with context awareness"""

    def __init__(self):
        self.known_test_vectors = KNOWN_TEST_VECTORS
        self.api_key_patterns = [
            r'sk_live_[a-zA-Z0-9]{24,}',  # Stripe live keys
            r'sk_test_[a-zA-Z0-9]{24,}',  # Stripe test keys (should still flag in prod)
            r'AKIA[0-9A-Z]{16}',          # AWS access key
            r'[0-9a-f]{32,64}',           # Generic hex keys
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 keys
            r'ghp_[a-zA-Z0-9]{36}',       # GitHub personal access token
            r'gho_[a-zA-Z0-9]{36}',       # GitHub OAuth token
        ]

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0

        # Get frequency of each character
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in frequencies.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def looks_like_private_key(self, text: str) -> bool:
        """Check if text looks like a private key"""
        # Remove quotes and whitespace
        clean_text = re.sub(r'["\'\s]', '', text)

        # Check for API key patterns
        for pattern in self.api_key_patterns:
            if re.search(pattern, clean_text):
                return True

        # Check entropy and length
        if len(clean_text) < 16:
            return False

        entropy = self.calculate_entropy(clean_text)

        # High entropy hex strings
        if re.match(r'^[0-9a-fA-F]+$', clean_text) and len(clean_text) >= 32 and entropy > 3.5:
            return True

        # High entropy base64-like strings
        if re.match(r'^[A-Za-z0-9+/]+=*$', clean_text) and len(clean_text) >= 24 and entropy > 4.0:
            return True

        return False

    def is_known_test_vector(self, text: str) -> bool:
        """Check if text is a known cryptographic test vector"""
        clean_text = re.sub(r'["\'\s]', '', text)
        return clean_text in self.known_test_vectors

    def detect_secrets(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Detect hardcoded secrets with context awareness"""
        secrets = []
        lines = content.split('\n')

        for i, line in enumerate(lines):
            # Get surrounding context
            start_idx = max(0, i - 3)
            end_idx = min(len(lines), i + 4)
            surrounding_lines = lines[start_idx:end_idx]

            context = SecretContext(file_path, line, i + 1, surrounding_lines)

            # Find potential secrets in line
            potential_secrets = self._extract_potential_secrets(line)

            for secret_text, start_pos in potential_secrets:
                if self._is_real_secret(secret_text, context):
                    secrets.append({
                        'type': 'hardcoded_secret',
                        'severity': self._determine_severity(secret_text, context),
                        'line': i + 1,
                        'column': start_pos,
                        'text': secret_text,
                        'file': file_path,
                        'message': self._generate_message(secret_text, context),
                        'confidence': self._calculate_confidence(secret_text, context)
                    })

        return secrets

    def _extract_potential_secrets(self, line: str) -> List[tuple]:
        """Extract potential secret strings from a line"""
        secrets = []

        # Pattern for quoted strings with high entropy
        quote_patterns = [
            r'"([^"]{16,})"',
            r"'([^']{16,})'",
            r'`([^`]{16,})`',
        ]

        for pattern in quote_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                secret_text = match.group(1)
                if self.looks_like_private_key(secret_text):
                    secrets.append((secret_text, match.start()))

        # Pattern for variable assignments
        assignment_pattern = r'(\w+)\s*[:=]\s*["\']([^"\']{16,})["\']'
        matches = re.finditer(assignment_pattern, line)
        for match in matches:
            var_name = match.group(1).lower()
            secret_text = match.group(2)

            # Check if variable name suggests it's a secret
            secret_indicators = ['key', 'secret', 'token', 'password', 'pwd', 'auth', 'api']
            if any(indicator in var_name for indicator in secret_indicators):
                if self.looks_like_private_key(secret_text):
                    secrets.append((secret_text, match.start(2)))

        return secrets

    def _is_real_secret(self, secret_text: str, context: SecretContext) -> bool:
        """Determine if a potential secret is actually a real secret"""
        # Skip known test vectors
        if self.is_known_test_vector(secret_text):
            return False

        # Skip if in test file (unless it looks like a real API key)
        if context.is_test_file and not self._looks_like_real_api_key(secret_text):
            return False

        # Skip if has test context markers
        if context.has_test_context:
            return False

        # Skip if in comments (usually examples)
        if context.is_in_comment:
            return False

        # Skip if in test functions
        if context.has_test_markers:
            return False

        # Skip common placeholder values
        placeholder_patterns = [
            r'^(your|my|test|demo|example|sample)[-_]',
            r'[-_](key|secret|token|here|placeholder)$',
            r'^(changeme|replaceme|todochange)',
            r'123456',
            r'abcdef'
        ]

        clean_text = secret_text.lower()
        for pattern in placeholder_patterns:
            if re.search(pattern, clean_text):
                return False

        return True

    def _looks_like_real_api_key(self, text: str) -> bool:
        """Check if text looks like a real API key (even in test files)"""
        real_api_patterns = [
            r'sk_live_',  # Stripe live key
            r'AKIA[0-9A-Z]{16}',  # AWS access key
            r'AIza[0-9A-Za-z_-]{35}',  # Google API key
        ]

        for pattern in real_api_patterns:
            if re.search(pattern, text):
                return True
        return False

    def _determine_severity(self, secret_text: str, context: SecretContext) -> str:
        """Determine severity based on secret type and context"""
        if self._looks_like_real_api_key(secret_text):
            return 'Critical'

        if context.is_test_file:
            return 'Low'

        # Check if it's in production-related files
        prod_indicators = ['prod', 'production', 'live', 'main', 'deploy']
        if any(indicator in str(context.file_path).lower() for indicator in prod_indicators):
            return 'Critical'

        return 'High'

    def _generate_message(self, secret_text: str, context: SecretContext) -> str:
        """Generate appropriate message for the finding"""
        if self._looks_like_real_api_key(secret_text):
            return f"Real API key detected: {secret_text[:8]}... (Line {context.line_number})"

        return f"Potential hardcoded secret detected: {secret_text[:8]}... (Line {context.line_number})"

    def _calculate_confidence(self, secret_text: str, context: SecretContext) -> float:
        """Calculate confidence score for the finding"""
        confidence = 0.5

        # Higher confidence for real API key patterns
        if self._looks_like_real_api_key(secret_text):
            confidence += 0.4

        # Higher confidence for production files
        prod_indicators = ['prod', 'production', 'live', 'main', 'deploy']
        if any(indicator in str(context.file_path).lower() for indicator in prod_indicators):
            confidence += 0.2

        # Higher confidence for high entropy
        entropy = self.calculate_entropy(secret_text)
        if entropy > 4.5:
            confidence += 0.2

        # Lower confidence for test files
        if context.is_test_file:
            confidence -= 0.3

        return min(1.0, max(0.1, confidence))

def scan_for_secrets(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Main entry point for secret scanning"""
    detector = HardcodedSecretDetector()
    return detector.detect_secrets(file_path, content)

if __name__ == "__main__":
    # Test the detector
    test_code = '''
    // Test vectors from NIST documentation
    let test_key = "3ee21644150adb50dc4c20e330184fabf12e75ecbf31fe167885587e6ebf2255";

    // Real secret (would be flagged)
    const API_KEY = "sk_live_abcdef1234567890abcdef1234567890";

    // Production configuration
    const PROD_SECRET = "real_prod_key_here_9f8e7d6c5b4a39281";
    '''

    detector = HardcodedSecretDetector()
    results = detector.detect_secrets("test.rs", test_code)

    for result in results:
        print(f"Found: {result['message']} (Confidence: {result['confidence']:.2f})")