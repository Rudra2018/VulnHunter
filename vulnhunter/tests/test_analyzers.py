"""
Test Analyzers
=============

Tests for VulnHunter domain-specific analyzers.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
import numpy as np

from vulnhunter.analyzers.source_code import SourceCodeAnalyzer
from vulnhunter.analyzers.http_requests import HTTPRequestAnalyzer


class TestSourceCodeAnalyzer:
    """Test suite for source code analyzer."""

    @pytest.fixture
    def mock_model_manager(self):
        """Create mock model manager."""
        manager = Mock()
        manager.get_predictor = Mock(return_value=None)
        manager.load_model = AsyncMock(return_value=Mock())
        return manager

    @pytest.fixture
    def analyzer(self, mock_model_manager):
        """Create source code analyzer instance."""
        return SourceCodeAnalyzer(mock_model_manager)

    def test_analyzer_initialization(self, mock_model_manager):
        """Test analyzer initialization."""
        analyzer = SourceCodeAnalyzer(mock_model_manager)

        assert analyzer.analyzer_name == "source_code"
        assert analyzer.model_manager == mock_model_manager
        assert analyzer.analysis_count == 0
        assert len(analyzer.supported_extensions) > 0

    @pytest.mark.asyncio
    async def test_analyze_string_code(self, analyzer):
        """Test analyzing string code."""
        # Mock predictor
        mock_predictor = Mock()
        mock_predictor.predict = Mock(return_value={
            'prediction': [1],
            'confidence': [0.8],
            'model_name': 'open_source_code'
        })

        analyzer.model_manager.get_predictor = Mock(return_value=mock_predictor)

        code = """
def login(username, password):
    if username == 'admin' and password == 'admin':
        return True
    return False
        """

        result = await analyzer.analyze(code)

        assert result['status'] == 'success'
        assert result['analyzer'] == 'source_code'
        assert 'features_extracted' in result
        assert 'prediction' in result

    @pytest.mark.asyncio
    async def test_analyze_file_not_found(self, analyzer):
        """Test analyzing non-existent file."""
        from pathlib import Path

        result = await analyzer.analyze(Path("nonexistent.py"))

        assert result['status'] == 'error'
        assert 'File not found' in result['error']

    @pytest.mark.asyncio
    async def test_analyze_unsupported_extension(self, analyzer):
        """Test analyzing unsupported file type."""
        from pathlib import Path

        # Create a mock path with unsupported extension
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.suffix = '.txt'

        result = await analyzer.analyze(mock_path)

        assert result['status'] == 'error'
        assert 'Unsupported file type' in result['error']

    def test_extract_features_python_code(self, analyzer):
        """Test feature extraction from Python code."""
        code = """
import os
import subprocess

def vulnerable_function(user_input):
    command = "ls " + user_input
    os.system(command)
    return subprocess.call(command, shell=True)

def secure_function(data):
    if isinstance(data, str) and len(data) < 100:
        return data.strip()
    return None
        """

        features = analyzer.extract_features(code)

        assert 'code_length' in features
        assert 'line_count' in features
        assert 'dangerous_function_count' in features
        assert 'cyclomatic_complexity' in features
        assert features['dangerous_function_count'] > 0  # Should detect os.system and subprocess.call

    def test_detect_language_python(self, analyzer):
        """Test Python language detection."""
        code = "def function(): import os"
        language = analyzer._detect_language(code)
        assert language == 'python'

    def test_detect_language_javascript(self, analyzer):
        """Test JavaScript language detection."""
        code = "function test() { var x = 5; }"
        language = analyzer._detect_language(code)
        assert language == 'javascript'

    def test_detect_language_java(self, analyzer):
        """Test Java language detection."""
        code = "public class Test { public static void main(String[] args) {} }"
        language = analyzer._detect_language(code)
        assert language == 'java'

    def test_detect_language_unknown(self, analyzer):
        """Test unknown language detection."""
        code = "some random text without patterns"
        language = analyzer._detect_language(code)
        assert language == 'unknown'

    def test_extract_security_features(self, analyzer):
        """Test security feature extraction."""
        code = """
import pickle
import subprocess
import os

def bad_function(user_input):
    eval(user_input)
    exec(user_input)
    os.system("rm -rf " + user_input)
    pickle.loads(user_input)

    query = "SELECT * FROM users WHERE id = " + user_input
    return query
        """

        features = analyzer._extract_security_features(code, 'python')

        assert features['dangerous_function_count'] > 0
        assert features['sql_injection_patterns'] > 0
        assert features['command_injection_patterns'] > 0

    def test_extract_complexity_features(self, analyzer):
        """Test complexity feature extraction."""
        code = """
def complex_function(a, b, c):
    if a > 0:
        for i in range(b):
            if i % 2 == 0:
                while c > 0:
                    c -= 1
                    if c < 10:
                        break
    return a + b + c

class TestClass:
    def method1(self):
        pass

    def method2(self):
        pass
        """

        features = analyzer._extract_complexity_features(code, 'python')

        assert features['cyclomatic_complexity'] > 1
        assert features['function_count'] >= 2
        assert features['class_count'] == 1
        assert features['loop_count'] >= 2
        assert features['conditional_count'] >= 3

    def test_has_input_validation(self, analyzer):
        """Test input validation detection."""
        code_with_validation = """
def secure_function(user_input):
    if isinstance(user_input, str) and len(user_input) < 100:
        return validate_input(user_input)
    return None
        """

        code_without_validation = """
def insecure_function(user_input):
    return user_input.upper()
        """

        assert analyzer._has_input_validation(code_with_validation) is True
        assert analyzer._has_input_validation(code_without_validation) is False

    def test_has_hardcoded_secrets(self, analyzer):
        """Test hardcoded secrets detection."""
        code_with_secrets = """
API_KEY = "sk_live_1234567890abcdef"
password = "supersecret123"
        """

        code_without_secrets = """
api_key = get_api_key()
password = input("Enter password: ")
        """

        assert analyzer._has_hardcoded_secrets(code_with_secrets) is True
        assert analyzer._has_hardcoded_secrets(code_without_secrets) is False

    def test_find_security_issues(self, analyzer):
        """Test security issue detection."""
        code = """
query = "SELECT * FROM users WHERE id = " + user_id
document.write("<div>" + user_input + "</div>")
os.system("ls " + directory)
        """

        issues = analyzer._find_security_issues(code)

        assert len(issues) > 0
        issue_types = [issue['type'] for issue in issues]
        assert 'sql_injection' in issue_types
        assert 'xss' in issue_types
        assert 'command_injection' in issue_types

    def test_features_to_array(self, analyzer):
        """Test feature conversion to array."""
        features = {
            'code_length': 100,
            'line_count': 10,
            'word_count': 50,
            'dangerous_function_count': 2,
            'language': 1
        }

        array = analyzer._features_to_array(features)

        assert isinstance(array, list)
        assert len(array) == 30  # Expected number of features
        assert array[0] == 100  # code_length should be first
        assert array[1] == 10   # line_count should be second


class TestHTTPRequestAnalyzer:
    """Test suite for HTTP request analyzer."""

    @pytest.fixture
    def mock_model_manager(self):
        """Create mock model manager."""
        manager = Mock()
        manager.get_predictor = Mock(return_value=None)
        manager.load_model = AsyncMock(return_value=Mock())
        return manager

    @pytest.fixture
    def analyzer(self, mock_model_manager):
        """Create HTTP request analyzer instance."""
        return HTTPRequestAnalyzer(mock_model_manager)

    def test_analyzer_initialization(self, mock_model_manager):
        """Test analyzer initialization."""
        analyzer = HTTPRequestAnalyzer(mock_model_manager)

        assert analyzer.analyzer_name == "http_requests"
        assert analyzer.model_manager == mock_model_manager

    @pytest.mark.asyncio
    async def test_analyze_dict_request(self, analyzer):
        """Test analyzing dictionary HTTP request."""
        # Mock predictor
        mock_predictor = Mock()
        mock_predictor.predict = Mock(return_value={
            'prediction': [1],
            'confidence': [0.9],
            'model_name': 'http_requests'
        })

        analyzer.model_manager.get_predictor = Mock(return_value=mock_predictor)

        request = {
            'method': 'GET',
            'url': 'https://example.com/search?q=<script>alert(1)</script>',
            'headers': {
                'user-agent': 'sqlmap/1.0',
                'accept': 'text/plain'
            },
            'body': ''
        }

        result = await analyzer.analyze(request)

        assert result['status'] == 'success'
        assert result['analyzer'] == 'http_requests'
        assert 'attack_patterns' in result
        assert 'traffic_classification' in result

    @pytest.mark.asyncio
    async def test_analyze_malformed_request(self, analyzer):
        """Test analyzing malformed request."""
        result = await analyzer.analyze("invalid request data")

        assert result['status'] == 'error'
        assert 'Unable to parse' in result['error']

    def test_parse_request_dict(self, analyzer):
        """Test parsing dictionary request."""
        request_dict = {
            'method': 'POST',
            'url': '/api/login',
            'headers': {'content-type': 'application/json'},
            'body': '{"username": "admin", "password": "admin"}'
        }

        parsed = analyzer._parse_request(request_dict)

        assert parsed == request_dict

    def test_parse_request_json_string(self, analyzer):
        """Test parsing JSON string request."""
        import json

        request_dict = {
            'method': 'GET',
            'url': '/test',
            'headers': {},
            'body': ''
        }

        request_json = json.dumps(request_dict)
        parsed = analyzer._parse_request(request_json)

        assert parsed == request_dict

    def test_parse_raw_http_request(self, analyzer):
        """Test parsing raw HTTP request."""
        raw_request = """GET /search?q=test HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: text/html

"""

        parsed = analyzer._parse_raw_http(raw_request)

        assert parsed['method'] == 'GET'
        assert parsed['url'] == '/search?q=test'
        assert parsed['protocol'] == 'HTTP/1.1'
        assert 'host' in parsed['headers']
        assert parsed['headers']['host'] == 'example.com'

    def test_extract_basic_features(self, analyzer):
        """Test basic feature extraction."""
        request_data = {
            'method': 'POST',
            'url': 'https://example.com/api/data?param=value',
            'headers': {'content-type': 'application/json'},
            'body': '{"data": "test"}'
        }

        features = analyzer._extract_basic_features(request_data)

        assert features['method_get'] == 0
        assert features['method_post'] == 1
        assert features['url_length'] > 0
        assert features['body_length'] > 0
        assert features['header_count'] == 1

    def test_extract_url_features(self, analyzer):
        """Test URL feature extraction."""
        request_data = {
            'url': 'https://example.com/path/to/resource?param1=value1&param2=value2#fragment'
        }

        features = analyzer._extract_url_features(request_data)

        assert features['has_query'] == 1
        assert features['has_fragment'] == 1
        assert features['param_count'] == 2
        assert features['path_depth'] > 0

    def test_extract_header_features(self, analyzer):
        """Test header feature extraction."""
        request_data = {
            'headers': {
                'user-agent': 'sqlmap/1.0',
                'content-type': 'application/json',
                'authorization': 'Bearer token123',
                'cookie': 'session=abc123'
            }
        }

        features = analyzer._extract_header_features(request_data)

        assert features['has_scanner_ua'] == 1
        assert features['is_json_content'] == 1
        assert features['has_authorization'] == 1
        assert features['has_cookie'] == 1

    def test_extract_payload_features(self, analyzer):
        """Test payload feature extraction."""
        import base64

        json_payload = '{"key": "value"}'
        base64_payload = base64.b64encode(b"test data").decode()

        # Test JSON payload
        request_data = {'body': json_payload}
        features = analyzer._extract_payload_features(request_data)
        assert features['payload_json'] == 1

        # Test base64 payload
        request_data = {'body': base64_payload}
        features = analyzer._extract_payload_features(request_data)
        assert features['payload_base64'] == 1

    def test_extract_pattern_features(self, analyzer):
        """Test pattern feature extraction."""
        request_data = {
            'url': "/search?q=' OR 1=1--",
            'body': "<script>alert('xss')</script>",
            'headers': {}
        }

        features = analyzer._extract_pattern_features(request_data)

        assert features['sql_injection_patterns'] > 0
        assert features['xss_patterns'] > 0
        assert features['has_suspicious_patterns'] == 1

    def test_detect_attack_patterns(self, analyzer):
        """Test attack pattern detection."""
        request_data = {
            'url': "/login?username=admin' OR '1'='1",
            'body': "<script>document.location='http://evil.com'</script>",
            'headers': {}
        }

        attacks = analyzer._detect_attack_patterns(request_data)

        assert len(attacks) > 0
        attack_types = [attack['type'] for attack in attacks]
        assert 'sql_injection' in attack_types
        assert 'xss' in attack_types

    def test_classify_traffic_bot(self, analyzer):
        """Test bot traffic classification."""
        request_data = {
            'headers': {
                'user-agent': 'python-requests/2.28.0'
            }
        }

        classification = analyzer._classify_traffic(request_data)

        assert classification['client_type'] == 'bot'

    def test_classify_traffic_browser(self, analyzer):
        """Test browser traffic classification."""
        request_data = {
            'headers': {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        }

        classification = analyzer._classify_traffic(request_data)

        assert classification['client_type'] == 'browser'

    def test_find_threat_indicators(self, analyzer):
        """Test threat indicator detection."""
        request_data = {
            'url': '/admin/backup.bak',
            'headers': {
                'user-agent': 'nikto/2.1.6'
            }
        }

        indicators = analyzer._find_threat_indicators(request_data)

        assert len(indicators) > 0
        indicator_types = [ind['type'] for ind in indicators]
        assert 'suspicious_user_agent' in indicator_types

    def test_calculate_entropy(self, analyzer):
        """Test entropy calculation."""
        # High entropy (random)
        high_entropy_text = "aB3$kL9#mN7@qR5%"
        high_entropy = analyzer._calculate_entropy(high_entropy_text)

        # Low entropy (repetitive)
        low_entropy_text = "aaaaaaaaaa"
        low_entropy = analyzer._calculate_entropy(low_entropy_text)

        assert high_entropy > low_entropy
        assert analyzer._calculate_entropy("") == 0.0

    def test_is_base64_encoded(self, analyzer):
        """Test base64 encoding detection."""
        import base64

        valid_base64 = base64.b64encode(b"test data").decode()
        invalid_base64 = "not base64 data!!!"

        assert analyzer._is_base64_encoded(valid_base64) is True
        assert analyzer._is_base64_encoded(invalid_base64) is False

    def test_is_json(self, analyzer):
        """Test JSON format detection."""
        valid_json = '{"key": "value", "number": 123}'
        invalid_json = '{key: value, invalid}'

        assert analyzer._is_json(valid_json) is True
        assert analyzer._is_json(invalid_json) is False

    def test_is_xml(self, analyzer):
        """Test XML format detection."""
        xml_data = '<root><element>value</element></root>'
        non_xml_data = 'plain text data'

        assert analyzer._is_xml(xml_data) is True
        assert analyzer._is_xml(non_xml_data) is False

    def test_features_to_array(self, analyzer):
        """Test feature conversion to array."""
        features = {
            'method_get': 1,
            'method_post': 0,
            'url_length': 50,
            'body_length': 100,
            'has_suspicious_patterns': 1
        }

        array = analyzer._features_to_array(features)

        assert isinstance(array, list)
        assert len(array) == 27  # Expected number of features
        assert array[0] == 1   # method_get should be first
        assert array[1] == 0   # method_post should be second