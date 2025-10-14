"""
HTTP Request Analyzer
====================

Advanced HTTP traffic analysis for web application security.
"""

import re
import json
import logging
import urllib.parse as urlparse
from typing import Dict, Any, Union, List, Optional
import base64
import hashlib
from collections import Counter
import math

from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

class HTTPRequestAnalyzer(BaseAnalyzer):
    """
    Analyzes HTTP requests for security threats and attack patterns.

    Detects various web attacks including injection attacks, XSS, CSRF, etc.
    """

    ATTACK_PATTERNS = {
        'sql_injection': [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%23)|(#))",
            r"w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"((\%27)|\')(\s|\%20|)*select",
            r"union(\s|\%20|)*select",
            r"select.*from.*where",
            r"insert\s+into",
            r"delete\s+from",
            r"update.*set",
            r"exec(\s|\+)+(s|x)p\w+"
        ],
        'xss': [
            r"<(\%20)*script(.*?)>",
            r"javascript\s*:",
            r"<(\%20)*object",
            r"<(\%20)*embed",
            r"<(\%20)*iframe",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"alert\s*\(",
            r"document\.(write|cookie|location)",
            r"window\.(location|open)"
        ],
        'command_injection': [
            r"(;|\|)(\s)*\w+",
            r"&(\s)*\w+",
            r"\$\(.*\)",
            r"`.*`",
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"shell_exec\s*\(",
            r"passthru\s*\("
        ],
        'path_traversal': [
            r"\.\.\/",
            r"\.\.\\",
            r"(\%2e\%2e\%2f)",
            r"(\%2e\%2e\/)",
            r"(\.\.%2f)",
            r"(\%2e\%2e\%5c)",
            r"(\%2e\%2e\\)",
            r"(\.\.%5c)",
            r"(\%252e\%252e\%252f)",
            r"/etc/passwd",
            r"/etc/shadow",
            r"boot\.ini",
            r"win\.ini"
        ],
        'ldap_injection': [
            r"(\%28)|(\()",
            r"(\%29)|(\))",
            r"(\%7c)|(\|)",
            r"(\%26)|(&)",
            r"\*(\s)*\)",
            r"\|\s*\)",
        ],
        'xpath_injection': [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"(\%7c)|(\|)",
            r"(\%20)(and|or)(\%20)",
            r"(and|or)\s+",
            r"count\s*\(",
            r"concat\s*\(",
        ]
    }

    SUSPICIOUS_HEADERS = {
        'user_agent': [
            'sqlmap', 'nikto', 'burp', 'acunetix', 'nessus', 'openvas',
            'w3af', 'skipfish', 'grabber', 'paros', 'havij', 'pangolin'
        ],
        'accept': [
            'text/plain', '*/*'
        ]
    }

    BOT_USER_AGENTS = [
        'bot', 'crawler', 'spider', 'scraper', 'scanner', 'curl', 'wget',
        'python-requests', 'java', 'perl', 'ruby', 'go-http-client'
    ]

    def __init__(self, model_manager):
        super().__init__(model_manager, "http_requests")

    async def analyze(self, target: Union[str, Dict], confidence_threshold: float = 0.5) -> Dict[str, Any]:
        """
        Analyze HTTP request for security threats.

        Args:
            target: HTTP request (string, dict, or parsed request object)
            confidence_threshold: Confidence threshold for detection

        Returns:
            Analysis results
        """
        # Parse request
        request_data = self._parse_request(target)
        if not request_data:
            return {'status': 'error', 'error': 'Unable to parse HTTP request'}

        # Check cache
        cache_key = self._get_cache_key(str(request_data))
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # Extract features
            features = self.extract_features(request_data)

            # Perform ML analysis
            result = await self._analyze_with_model(
                features,
                'http_requests',
                confidence_threshold
            )

            # Add HTTP-specific analysis
            result.update({
                'request_analysis': self._analyze_request_structure(request_data),
                'attack_patterns': self._detect_attack_patterns(request_data),
                'traffic_classification': self._classify_traffic(request_data),
                'threat_indicators': self._find_threat_indicators(request_data)
            })

            # Cache result
            self.cache[cache_key] = result
            return result

        except Exception as e:
            logger.error(f"HTTP request analysis failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'analyzer': 'http_requests'
            }

    def extract_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract comprehensive features from HTTP request."""
        features = {}

        # Basic request features
        features.update(self._extract_basic_features(request_data))

        # URL analysis features
        features.update(self._extract_url_features(request_data))

        # Header analysis features
        features.update(self._extract_header_features(request_data))

        # Payload analysis features
        features.update(self._extract_payload_features(request_data))

        # Pattern matching features
        features.update(self._extract_pattern_features(request_data))

        # Traffic characteristics
        features.update(self._extract_traffic_features(request_data))

        return features

    def _parse_request(self, target: Union[str, Dict]) -> Optional[Dict[str, Any]]:
        """Parse HTTP request from various input formats."""
        if isinstance(target, dict):
            # Already parsed
            return target

        if isinstance(target, str):
            try:
                # Try parsing as JSON first
                return json.loads(target)
            except json.JSONDecodeError:
                # Try parsing as raw HTTP request
                return self._parse_raw_http(target)

        return None

    def _parse_raw_http(self, raw_request: str) -> Optional[Dict[str, Any]]:
        """Parse raw HTTP request string."""
        lines = raw_request.strip().split('\n')
        if not lines:
            return None

        # Parse request line
        request_line = lines[0].strip()
        parts = request_line.split(' ', 2)
        if len(parts) < 2:
            return None

        method = parts[0]
        url = parts[1]
        protocol = parts[2] if len(parts) > 2 else 'HTTP/1.1'

        # Parse headers
        headers = {}
        body_start = 1
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        # Parse body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''

        return {
            'method': method,
            'url': url,
            'protocol': protocol,
            'headers': headers,
            'body': body
        }

    def _extract_basic_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic HTTP request features."""
        features = {}

        method = request_data.get('method', '').upper()
        features['method_get'] = 1 if method == 'GET' else 0
        features['method_post'] = 1 if method == 'POST' else 0
        features['method_put'] = 1 if method == 'PUT' else 0
        features['method_delete'] = 1 if method == 'DELETE' else 0
        features['method_other'] = 1 if method not in ['GET', 'POST', 'PUT', 'DELETE'] else 0

        url = request_data.get('url', '')
        features['url_length'] = len(url)

        body = request_data.get('body', '')
        features['body_length'] = len(body)

        headers = request_data.get('headers', {})
        features['header_count'] = len(headers)

        return features

    def _extract_url_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract URL-based features."""
        features = {}

        url = request_data.get('url', '')
        parsed_url = urlparse.urlparse(url)

        # URL components
        features['has_query'] = 1 if parsed_url.query else 0
        features['has_fragment'] = 1 if parsed_url.fragment else 0
        features['path_depth'] = len([p for p in parsed_url.path.split('/') if p])

        # Query parameters
        query_params = urlparse.parse_qs(parsed_url.query)
        features['param_count'] = len(query_params)

        # URL encoding analysis
        features['url_encoded_chars'] = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        features['double_encoded_chars'] = len(re.findall(r'%25[0-9A-Fa-f]{2}', url))

        # Special characters in URL
        features['special_chars_count'] = len(re.findall(r'[<>"\'\(\);]', url))
        features['suspicious_extensions'] = 1 if re.search(r'\.(php|asp|jsp|cgi)$', parsed_url.path) else 0

        return features

    def _extract_header_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract header-based features."""
        features = {}

        headers = request_data.get('headers', {})

        # User-Agent analysis
        user_agent = headers.get('user-agent', '').lower()
        features['is_bot_traffic'] = 1 if any(bot in user_agent for bot in self.BOT_USER_AGENTS) else 0
        features['has_scanner_ua'] = 1 if any(scanner in user_agent for scanner in self.SUSPICIOUS_HEADERS['user_agent']) else 0

        # Content-Type analysis
        content_type = headers.get('content-type', '').lower()
        features['is_json_content'] = 1 if 'application/json' in content_type else 0
        features['is_form_data'] = 1 if 'application/x-www-form-urlencoded' in content_type else 0
        features['is_multipart'] = 1 if 'multipart/form-data' in content_type else 0

        # Security headers
        features['has_authorization'] = 1 if 'authorization' in headers else 0
        features['has_cookie'] = 1 if 'cookie' in headers else 0
        features['has_referer'] = 1 if 'referer' in headers else 0

        # Suspicious header patterns
        features['suspicious_accept'] = 1 if headers.get('accept', '') in self.SUSPICIOUS_HEADERS['accept'] else 0

        return features

    def _extract_payload_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract payload-based features."""
        features = {}

        body = request_data.get('body', '')
        if not body:
            features['payload_entropy'] = 0
            features['payload_base64'] = 0
            features['payload_json'] = 0
            return features

        # Payload entropy
        features['payload_entropy'] = self._calculate_entropy(body)

        # Payload encoding
        features['payload_base64'] = 1 if self._is_base64_encoded(body) else 0
        features['payload_url_encoded'] = 1 if '%' in body and len(re.findall(r'%[0-9A-Fa-f]{2}', body)) > 0 else 0

        # Payload format
        features['payload_json'] = 1 if self._is_json(body) else 0
        features['payload_xml'] = 1 if self._is_xml(body) else 0

        return features

    def _extract_pattern_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract pattern-based features."""
        features = {}

        # Combine all searchable content
        url = request_data.get('url', '')
        body = request_data.get('body', '')
        headers_str = str(request_data.get('headers', {}))
        full_content = f"{url} {body} {headers_str}".lower()

        # Attack pattern detection
        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            pattern_count = sum(len(re.findall(pattern, full_content, re.IGNORECASE)) for pattern in patterns)
            features[f'{attack_type}_patterns'] = min(pattern_count, 10)  # Cap at 10

        # General suspicious patterns
        features['has_suspicious_patterns'] = 1 if any(
            features[f'{attack_type}_patterns'] > 0 for attack_type in self.ATTACK_PATTERNS.keys()
        ) else 0

        return features

    def _extract_traffic_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract traffic classification features."""
        features = {}

        url = request_data.get('url', '')
        method = request_data.get('method', '').upper()
        headers = request_data.get('headers', {})

        # Traffic type classification
        features['is_api_request'] = 1 if '/api/' in url or 'application/json' in headers.get('accept', '') else 0
        features['is_form_submission'] = 1 if method == 'POST' and 'form' in headers.get('content-type', '') else 0
        features['is_file_upload'] = 1 if 'multipart/form-data' in headers.get('content-type', '') else 0
        features['is_ajax_request'] = 1 if 'xmlhttprequest' in headers.get('x-requested-with', '').lower() else 0

        # Resource type
        features['requests_image'] = 1 if re.search(r'\.(jpg|jpeg|png|gif|svg|ico)(\?|$)', url) else 0
        features['requests_css'] = 1 if url.endswith('.css') else 0
        features['requests_js'] = 1 if url.endswith('.js') else 0

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        counter = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _is_base64_encoded(self, text: str) -> bool:
        """Check if text is base64 encoded."""
        try:
            if len(text) % 4 != 0:
                return False
            base64.b64decode(text, validate=True)
            return True
        except Exception:
            return False

    def _is_json(self, text: str) -> bool:
        """Check if text is valid JSON."""
        try:
            json.loads(text)
            return True
        except json.JSONDecodeError:
            return False

    def _is_xml(self, text: str) -> bool:
        """Check if text looks like XML."""
        return bool(re.search(r'<[^>]+>', text.strip()))

    def _analyze_request_structure(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP request structure."""
        analysis = {}

        method = request_data.get('method', '')
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')

        analysis['method'] = method
        analysis['url_complexity'] = len(urlparse.urlparse(url).query.split('&')) if urlparse.urlparse(url).query else 0
        analysis['has_authentication'] = bool(headers.get('authorization') or headers.get('cookie'))
        analysis['content_length'] = len(body)

        return analysis

    def _detect_attack_patterns(self, request_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect specific attack patterns."""
        attacks = []

        url = request_data.get('url', '')
        body = request_data.get('body', '')
        full_content = f"{url} {body}".lower()

        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, full_content, re.IGNORECASE)
                for match in matches:
                    attacks.append({
                        'type': attack_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'confidence': self._calculate_pattern_confidence(attack_type, pattern),
                        'severity': self._get_attack_severity(attack_type)
                    })

        return attacks

    def _classify_traffic(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify traffic type and characteristics."""
        classification = {}

        headers = request_data.get('headers', {})
        user_agent = headers.get('user-agent', '').lower()

        # Client type
        if any(bot in user_agent for bot in self.BOT_USER_AGENTS):
            classification['client_type'] = 'bot'
        elif 'mozilla' in user_agent and 'webkit' in user_agent:
            classification['client_type'] = 'browser'
        else:
            classification['client_type'] = 'unknown'

        # Traffic legitimacy score
        legitimacy_score = 1.0

        if any(scanner in user_agent for scanner in self.SUSPICIOUS_HEADERS['user_agent']):
            legitimacy_score -= 0.5

        if self._detect_attack_patterns(request_data):
            legitimacy_score -= 0.3

        classification['legitimacy_score'] = max(0.0, legitimacy_score)
        classification['is_suspicious'] = legitimacy_score < 0.5

        return classification

    def _find_threat_indicators(self, request_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find threat indicators in the request."""
        indicators = []

        # Check for suspicious user agents
        user_agent = request_data.get('headers', {}).get('user-agent', '').lower()
        for scanner in self.SUSPICIOUS_HEADERS['user_agent']:
            if scanner in user_agent:
                indicators.append({
                    'type': 'suspicious_user_agent',
                    'value': scanner,
                    'severity': 'HIGH',
                    'description': f'Scanner/tool user agent detected: {scanner}'
                })

        # Check for encoding anomalies
        url = request_data.get('url', '')
        if len(re.findall(r'%25[0-9A-Fa-f]{2}', url)) > 0:
            indicators.append({
                'type': 'double_encoding',
                'value': 'URL double encoding detected',
                'severity': 'MEDIUM',
                'description': 'Double URL encoding may indicate evasion attempt'
            })

        # Check for suspicious file extensions
        if re.search(r'\.(bak|old|tmp|log)$', url):
            indicators.append({
                'type': 'suspicious_file_access',
                'value': 'Backup/temporary file access',
                'severity': 'MEDIUM',
                'description': 'Request for potentially sensitive file types'
            })

        return indicators

    def _calculate_pattern_confidence(self, attack_type: str, pattern: str) -> float:
        """Calculate confidence for pattern match."""
        # Simple confidence based on pattern specificity
        confidence_mapping = {
            'sql_injection': 0.8,
            'xss': 0.7,
            'command_injection': 0.9,
            'path_traversal': 0.8,
            'ldap_injection': 0.6,
            'xpath_injection': 0.6
        }
        return confidence_mapping.get(attack_type, 0.5)

    def _get_attack_severity(self, attack_type: str) -> str:
        """Get severity level for attack type."""
        severity_mapping = {
            'sql_injection': 'HIGH',
            'xss': 'MEDIUM',
            'command_injection': 'CRITICAL',
            'path_traversal': 'MEDIUM',
            'ldap_injection': 'MEDIUM',
            'xpath_injection': 'MEDIUM'
        }
        return severity_mapping.get(attack_type, 'LOW')

    def _features_to_array(self, features: Dict[str, Any]) -> list:
        """Convert features to array for ML model."""
        # Define the expected feature order for the HTTP requests model
        feature_order = [
            'method_get', 'method_post', 'method_put', 'method_delete', 'method_other',
            'url_length', 'body_length', 'header_count', 'has_query', 'has_fragment',
            'path_depth', 'param_count', 'url_encoded_chars', 'double_encoded_chars',
            'special_chars_count', 'suspicious_extensions', 'is_bot_traffic',
            'has_scanner_ua', 'is_json_content', 'is_form_data', 'is_multipart',
            'has_authorization', 'has_cookie', 'has_referer', 'suspicious_accept',
            'payload_entropy', 'has_suspicious_patterns'
        ]

        return [features.get(feature, 0) for feature in feature_order]