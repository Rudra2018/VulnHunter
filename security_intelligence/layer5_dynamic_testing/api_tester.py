"""
API Security Testing Engine

This module provides comprehensive API security testing:
- REST/GraphQL/SOAP API discovery and testing
- Intelligent input generation for API parameters
- Authentication and authorization testing
- Rate limiting and business logic testing
- API versioning and endpoint enumeration
"""

import asyncio
import aiohttp
import json
import logging
import re
import time
import hashlib
import urllib.parse
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import random
import xml.etree.ElementTree as ET
from collections import defaultdict

class APIType(Enum):
    """Types of APIs"""
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    GRPC = "grpc"
    WEBSOCKET = "websocket"

class AuthenticationType(Enum):
    """Authentication types"""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    CUSTOM = "custom"

class HTTPMethod(Enum):
    """HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"

@dataclass
class APIEndpoint:
    """Represents an API endpoint"""
    url: str
    method: HTTPMethod
    api_type: APIType
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[AuthenticationType] = None
    description: str = ""
    discovered_from: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class APIParameter:
    """Represents an API parameter"""
    name: str
    param_type: str
    location: str  # query, body, header, path
    required: bool = False
    default_value: Optional[Any] = None
    data_type: str = "string"
    constraints: Dict[str, Any] = field(default_factory=dict)
    examples: List[Any] = field(default_factory=list)

@dataclass
class APIVulnerability:
    """Represents an API vulnerability"""
    vuln_id: str
    endpoint: APIEndpoint
    vulnerability_type: str
    severity: str
    description: str
    evidence: List[str]
    remediation: str
    confidence: float
    payload_used: Optional[str] = None
    response_data: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class APITestResult:
    """Results from API testing"""
    endpoint: APIEndpoint
    vulnerabilities: List[APIVulnerability]
    test_statistics: Dict[str, Any]
    authentication_status: Dict[str, Any]
    rate_limit_info: Optional[Dict[str, Any]] = None

class APIDiscoverer:
    """Discovers API endpoints and structure"""

    def __init__(self):
        self.common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/graph', '/gql',
            '/soap', '/soap/v1', '/wsdl',
            '/openapi.json', '/swagger.json', '/api-docs',
            '/swagger-ui', '/docs', '/documentation'
        ]

        self.api_extensions = [
            '.json', '.xml', '.yaml', '.yml'
        ]

        self.http_methods = [method.value for method in HTTPMethod]

    async def discover_apis(self, base_url: str, session: aiohttp.ClientSession) -> List[APIEndpoint]:
        """Discover API endpoints"""
        discovered_endpoints = []

        # Try common API paths
        for api_path in self.common_api_paths:
            url = urllib.parse.urljoin(base_url, api_path)
            endpoints = await self._probe_api_endpoint(url, session)
            discovered_endpoints.extend(endpoints)

        # Look for API documentation
        doc_endpoints = await self._discover_api_documentation(base_url, session)
        discovered_endpoints.extend(doc_endpoints)

        # Directory enumeration for API paths
        enum_endpoints = await self._enumerate_api_paths(base_url, session)
        discovered_endpoints.extend(enum_endpoints)

        return discovered_endpoints

    async def _probe_api_endpoint(self, url: str, session: aiohttp.ClientSession) -> List[APIEndpoint]:
        """Probe potential API endpoint"""
        endpoints = []

        try:
            # Test different HTTP methods
            for method in self.http_methods:
                try:
                    async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        content_type = response.headers.get('content-type', '').lower()
                        body = await response.text()

                        # Determine API type
                        api_type = self._detect_api_type(content_type, body, url)

                        if api_type != APIType.REST or response.status != 404:
                            endpoint = APIEndpoint(
                                url=url,
                                method=HTTPMethod(method),
                                api_type=api_type,
                                discovered_from="probing",
                                metadata={
                                    'status_code': response.status,
                                    'content_type': content_type,
                                    'response_size': len(body)
                                }
                            )
                            endpoints.append(endpoint)

                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logging.debug(f"Error probing {method} {url}: {e}")
                    continue

        except Exception as e:
            logging.error(f"Failed to probe API endpoint {url}: {e}")

        return endpoints

    def _detect_api_type(self, content_type: str, body: str, url: str) -> APIType:
        """Detect API type from response"""
        url_lower = url.lower()

        # GraphQL detection
        if 'graphql' in url_lower or 'graph' in url_lower:
            return APIType.GRAPHQL

        if 'application/json' in content_type and any(keyword in body.lower() for keyword in ['query', 'mutation', 'subscription']):
            return APIType.GRAPHQL

        # SOAP detection
        if 'soap' in url_lower or 'wsdl' in url_lower:
            return APIType.SOAP

        if 'text/xml' in content_type or 'application/soap+xml' in content_type:
            return APIType.SOAP

        if '<soap:' in body or '<wsdl:' in body or 'xmlns:soap' in body:
            return APIType.SOAP

        # WebSocket detection
        if 'websocket' in content_type or 'ws://' in url or 'wss://' in url:
            return APIType.WEBSOCKET

        # Default to REST
        return APIType.REST

    async def _discover_api_documentation(self, base_url: str, session: aiohttp.ClientSession) -> List[APIEndpoint]:
        """Discover APIs from documentation"""
        endpoints = []
        doc_urls = [
            '/swagger.json', '/openapi.json', '/api-docs.json',
            '/swagger.yaml', '/openapi.yaml', '/api-docs.yaml',
            '/swagger-ui', '/docs', '/api-docs'
        ]

        for doc_path in doc_urls:
            doc_url = urllib.parse.urljoin(base_url, doc_path)

            try:
                async with session.get(doc_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '').lower()
                        body = await response.text()

                        if 'application/json' in content_type:
                            parsed_endpoints = self._parse_openapi_json(body, base_url)
                            endpoints.extend(parsed_endpoints)
                        elif 'text/html' in content_type and 'swagger' in body.lower():
                            # Try to extract API endpoints from Swagger UI
                            swagger_endpoints = self._extract_from_swagger_ui(body, base_url)
                            endpoints.extend(swagger_endpoints)

            except Exception as e:
                logging.debug(f"Failed to fetch API documentation from {doc_url}: {e}")

        return endpoints

    def _parse_openapi_json(self, json_content: str, base_url: str) -> List[APIEndpoint]:
        """Parse OpenAPI/Swagger JSON specification"""
        endpoints = []

        try:
            spec = json.loads(json_content)

            # Extract base path
            base_path = spec.get('basePath', '')
            if base_path and not base_path.startswith('/'):
                base_path = '/' + base_path

            # Extract paths
            paths = spec.get('paths', {})

            for path, path_info in paths.items():
                for method, method_info in path_info.items():
                    if method.upper() in [m.value for m in HTTPMethod]:
                        full_url = urllib.parse.urljoin(base_url, base_path + path)

                        # Extract parameters
                        parameters = {}
                        if 'parameters' in method_info:
                            for param in method_info['parameters']:
                                param_obj = APIParameter(
                                    name=param.get('name', ''),
                                    param_type=param.get('type', 'string'),
                                    location=param.get('in', 'query'),
                                    required=param.get('required', False),
                                    data_type=param.get('type', 'string')
                                )
                                parameters[param_obj.name] = param_obj

                        endpoint = APIEndpoint(
                            url=full_url,
                            method=HTTPMethod(method.upper()),
                            api_type=APIType.REST,
                            parameters=parameters,
                            description=method_info.get('summary', ''),
                            discovered_from="openapi_spec",
                            metadata={
                                'operation_id': method_info.get('operationId'),
                                'tags': method_info.get('tags', [])
                            }
                        )
                        endpoints.append(endpoint)

        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse OpenAPI JSON: {e}")
        except Exception as e:
            logging.error(f"Error parsing OpenAPI specification: {e}")

        return endpoints

    def _extract_from_swagger_ui(self, html_content: str, base_url: str) -> List[APIEndpoint]:
        """Extract API endpoints from Swagger UI HTML"""
        endpoints = []

        # Look for API URLs in the HTML
        url_patterns = [
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'spec\s*:\s*["\']([^"\']+)["\']',
            r'"url"\s*:\s*"([^"]+)"'
        ]

        for pattern in url_patterns:
            matches = re.findall(pattern, html_content)
            for match in matches:
                if match.endswith('.json') or match.endswith('.yaml'):
                    spec_url = urllib.parse.urljoin(base_url, match)
                    # Would need to fetch and parse the spec
                    # For now, just create a basic endpoint
                    endpoint = APIEndpoint(
                        url=spec_url,
                        method=HTTPMethod.GET,
                        api_type=APIType.REST,
                        discovered_from="swagger_ui",
                        description="API specification"
                    )
                    endpoints.append(endpoint)

        return endpoints

    async def _enumerate_api_paths(self, base_url: str, session: aiohttp.ClientSession) -> List[APIEndpoint]:
        """Enumerate API paths using common patterns"""
        endpoints = []

        # Common API resource names
        resources = [
            'users', 'user', 'accounts', 'account',
            'products', 'product', 'items', 'item',
            'orders', 'order', 'payments', 'payment',
            'auth', 'login', 'logout', 'register',
            'admin', 'config', 'settings', 'status',
            'health', 'ping', 'version', 'info'
        ]

        # Common API versions
        versions = ['', 'v1', 'v2', 'v3']

        for version in versions:
            for resource in resources:
                if version:
                    api_path = f"/api/{version}/{resource}"
                else:
                    api_path = f"/api/{resource}"

                url = urllib.parse.urljoin(base_url, api_path)

                # Test with different HTTP methods
                for method in ['GET', 'POST']:
                    try:
                        async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            if response.status not in [404, 405]:  # Found something
                                endpoint = APIEndpoint(
                                    url=url,
                                    method=HTTPMethod(method),
                                    api_type=APIType.REST,
                                    discovered_from="enumeration",
                                    metadata={
                                        'status_code': response.status,
                                        'resource': resource,
                                        'version': version
                                    }
                                )
                                endpoints.append(endpoint)

                    except Exception:
                        continue

        return endpoints

class APIAuthenticationTester:
    """Tests API authentication and authorization"""

    def __init__(self):
        self.auth_bypass_payloads = [
            # JWT manipulation
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.',
            # SQL injection in auth
            "admin' OR '1'='1",
            "admin'/**/OR/**/1=1#",
            # NoSQL injection
            '{"$ne": null}',
            '{"$gt": ""}',
            # Admin bypass
            'admin', 'administrator', 'root', 'test'
        ]

    async def test_authentication(self, endpoint: APIEndpoint, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Test authentication mechanisms"""
        auth_results = {
            'unauthenticated_access': False,
            'weak_authentication': False,
            'auth_bypass': False,
            'session_issues': False,
            'vulnerabilities': []
        }

        # Test unauthenticated access
        unauth_result = await self._test_unauthenticated_access(endpoint, session)
        auth_results.update(unauth_result)

        # Test weak authentication
        weak_auth_result = await self._test_weak_authentication(endpoint, session)
        auth_results.update(weak_auth_result)

        # Test authentication bypass
        bypass_result = await self._test_authentication_bypass(endpoint, session)
        auth_results.update(bypass_result)

        return auth_results

    async def _test_unauthenticated_access(self, endpoint: APIEndpoint, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Test if endpoint allows unauthenticated access"""
        try:
            async with session.request(endpoint.method.value, endpoint.url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                # Check if we get successful response without authentication
                if response.status in [200, 201, 202]:
                    return {
                        'unauthenticated_access': True,
                        'vulnerabilities': [{
                            'type': 'unauthenticated_access',
                            'severity': 'medium',
                            'description': 'Endpoint allows unauthenticated access',
                            'evidence': f"Status code: {response.status}"
                        }]
                    }

        except Exception as e:
            logging.debug(f"Error testing unauthenticated access: {e}")

        return {'unauthenticated_access': False}

    async def _test_weak_authentication(self, endpoint: APIEndpoint, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Test for weak authentication"""
        vulnerabilities = []
        weak_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('root', 'root'),
            ('administrator', 'administrator')
        ]

        for username, password in weak_creds:
            try:
                # Test Basic Auth
                auth = aiohttp.BasicAuth(username, password)
                async with session.request(endpoint.method.value, endpoint.url, auth=auth, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status in [200, 201, 202]:
                        vulnerabilities.append({
                            'type': 'weak_credentials',
                            'severity': 'high',
                            'description': f'Weak credentials accepted: {username}:{password}',
                            'evidence': f"Status code: {response.status}"
                        })

                # Test API Key
                headers = {'Authorization': f'Bearer {password}', 'X-API-Key': password}
                async with session.request(endpoint.method.value, endpoint.url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status in [200, 201, 202]:
                        vulnerabilities.append({
                            'type': 'weak_api_key',
                            'severity': 'high',
                            'description': f'Weak API key accepted: {password}',
                            'evidence': f"Status code: {response.status}"
                        })

            except Exception:
                continue

        return {
            'weak_authentication': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }

    async def _test_authentication_bypass(self, endpoint: APIEndpoint, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Test authentication bypass techniques"""
        vulnerabilities = []

        # Test JWT none algorithm
        jwt_none_token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.'

        try:
            headers = {'Authorization': f'Bearer {jwt_none_token}'}
            async with session.request(endpoint.method.value, endpoint.url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status in [200, 201, 202]:
                    vulnerabilities.append({
                        'type': 'jwt_none_algorithm',
                        'severity': 'critical',
                        'description': 'JWT none algorithm bypass successful',
                        'evidence': f"Status code: {response.status}"
                    })
        except Exception:
            pass

        # Test header manipulation
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'}
        ]

        for bypass_header in bypass_headers:
            try:
                async with session.request(endpoint.method.value, endpoint.url, headers=bypass_header, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status in [200, 201, 202]:
                        vulnerabilities.append({
                            'type': 'header_bypass',
                            'severity': 'high',
                            'description': f'Authentication bypass via header: {list(bypass_header.keys())[0]}',
                            'evidence': f"Status code: {response.status}"
                        })
            except Exception:
                continue

        return {
            'auth_bypass': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }

class APIInputGenerator:
    """Generates intelligent inputs for API testing"""

    def __init__(self):
        self.data_types = {
            'string': self._generate_string_values,
            'integer': self._generate_integer_values,
            'number': self._generate_number_values,
            'boolean': self._generate_boolean_values,
            'array': self._generate_array_values,
            'object': self._generate_object_values
        }

    def generate_test_inputs(self, parameters: Dict[str, APIParameter]) -> List[Dict[str, Any]]:
        """Generate test inputs for API parameters"""
        if not parameters:
            return [{}]

        test_cases = []

        # Generate valid inputs
        valid_input = {}
        for param_name, param in parameters.items():
            values = self._generate_values_for_parameter(param)
            valid_input[param_name] = values[0] if values else "test"

        test_cases.append(valid_input)

        # Generate boundary test cases
        for param_name, param in parameters.items():
            boundary_values = self._generate_boundary_values(param)
            for boundary_value in boundary_values:
                test_case = valid_input.copy()
                test_case[param_name] = boundary_value
                test_cases.append(test_case)

        # Generate invalid inputs
        invalid_inputs = self._generate_invalid_inputs(parameters)
        test_cases.extend(invalid_inputs)

        return test_cases

    def _generate_values_for_parameter(self, param: APIParameter) -> List[Any]:
        """Generate values for a specific parameter"""
        if param.examples:
            return param.examples

        generator = self.data_types.get(param.data_type, self._generate_string_values)
        return generator(param)

    def _generate_string_values(self, param: APIParameter) -> List[str]:
        """Generate string test values"""
        values = ["test", "value", "example", "string"]

        # Add parameter-specific values
        param_name_lower = param.name.lower()

        if 'email' in param_name_lower:
            values.extend(["test@example.com", "user@test.org"])
        elif 'url' in param_name_lower:
            values.extend(["https://example.com", "http://test.org"])
        elif 'phone' in param_name_lower:
            values.extend(["555-1234", "+1-555-123-4567"])
        elif 'name' in param_name_lower:
            values.extend(["John Doe", "Test User"])
        elif 'id' in param_name_lower:
            values.extend(["123", "test-id", "uuid-12345"])

        return values

    def _generate_integer_values(self, param: APIParameter) -> List[int]:
        """Generate integer test values"""
        values = [0, 1, 10, 100, 1000]

        # Add constraint-based values
        if 'minimum' in param.constraints:
            values.append(param.constraints['minimum'])
        if 'maximum' in param.constraints:
            values.append(param.constraints['maximum'])

        return values

    def _generate_number_values(self, param: APIParameter) -> List[float]:
        """Generate number test values"""
        values = [0.0, 1.0, 10.5, 100.99, 1000.01]

        if 'minimum' in param.constraints:
            values.append(float(param.constraints['minimum']))
        if 'maximum' in param.constraints:
            values.append(float(param.constraints['maximum']))

        return values

    def _generate_boolean_values(self, param: APIParameter) -> List[bool]:
        """Generate boolean test values"""
        return [True, False]

    def _generate_array_values(self, param: APIParameter) -> List[List[Any]]:
        """Generate array test values"""
        return [
            [],
            ["test"],
            ["value1", "value2"],
            [1, 2, 3],
            [True, False]
        ]

    def _generate_object_values(self, param: APIParameter) -> List[Dict[str, Any]]:
        """Generate object test values"""
        return [
            {},
            {"key": "value"},
            {"name": "test", "value": 123},
            {"nested": {"key": "value"}}
        ]

    def _generate_boundary_values(self, param: APIParameter) -> List[Any]:
        """Generate boundary test values"""
        boundary_values = []

        if param.data_type == 'string':
            # Empty string, very long string
            boundary_values.extend(["", "A" * 1000, "A" * 10000])

            # Special characters
            boundary_values.extend([
                "<script>alert('xss')</script>",
                "' OR '1'='1",
                "../../../etc/passwd",
                "${7*7}",
                "{{7*7}}"
            ])

        elif param.data_type in ['integer', 'number']:
            # Boundary numbers
            boundary_values.extend([
                -1, 0, 1,
                2147483647, -2147483648,  # 32-bit limits
                9223372036854775807, -9223372036854775808  # 64-bit limits
            ])

        elif param.data_type == 'array':
            # Empty array, very large array
            boundary_values.extend([
                [],
                ["item"] * 1000
            ])

        return boundary_values

    def _generate_invalid_inputs(self, parameters: Dict[str, APIParameter]) -> List[Dict[str, Any]]:
        """Generate invalid input combinations"""
        invalid_inputs = []

        # Missing required parameters
        required_params = [name for name, param in parameters.items() if param.required]
        if required_params:
            for req_param in required_params:
                invalid_case = {}
                for param_name, param in parameters.items():
                    if param_name != req_param:
                        values = self._generate_values_for_parameter(param)
                        invalid_case[param_name] = values[0] if values else "test"
                invalid_inputs.append(invalid_case)

        # Wrong data types
        base_case = {}
        for param_name, param in parameters.items():
            values = self._generate_values_for_parameter(param)
            base_case[param_name] = values[0] if values else "test"

        for param_name, param in parameters.items():
            if param.data_type == 'integer':
                wrong_type_case = base_case.copy()
                wrong_type_case[param_name] = "not_an_integer"
                invalid_inputs.append(wrong_type_case)

            elif param.data_type == 'boolean':
                wrong_type_case = base_case.copy()
                wrong_type_case[param_name] = "not_a_boolean"
                invalid_inputs.append(wrong_type_case)

        return invalid_inputs

class APISecurityTester:
    """Main API security testing engine"""

    def __init__(self, max_concurrent: int = 5, request_delay: float = 0.5):
        self.max_concurrent = max_concurrent
        self.request_delay = request_delay

        self.discoverer = APIDiscoverer()
        self.auth_tester = APIAuthenticationTester()
        self.input_generator = APIInputGenerator()

        self.session = None
        self.test_statistics = {
            'endpoints_tested': 0,
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'test_duration': 0
        }

    async def test_api(self, base_url: str, endpoints: Optional[List[APIEndpoint]] = None) -> List[APITestResult]:
        """Test API security"""
        start_time = time.time()

        # Initialize session
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

        try:
            # Discover endpoints if not provided
            if endpoints is None:
                logging.info("Discovering API endpoints...")
                endpoints = await self.discoverer.discover_apis(base_url, self.session)
                logging.info(f"Discovered {len(endpoints)} API endpoints")

            # Test each endpoint
            test_results = []
            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def test_single_endpoint(endpoint):
                async with semaphore:
                    return await self._test_endpoint_security(endpoint)

            tasks = [test_single_endpoint(endpoint) for endpoint in endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logging.error(f"API test error: {result}")
                elif result:
                    test_results.append(result)

            self.test_statistics['test_duration'] = time.time() - start_time
            self.test_statistics['endpoints_tested'] = len(test_results)
            self.test_statistics['vulnerabilities_found'] = sum(len(r.vulnerabilities) for r in test_results)

            logging.info(f"API testing completed: {len(test_results)} endpoints tested, {self.test_statistics['vulnerabilities_found']} vulnerabilities found")

            return test_results

        finally:
            if self.session:
                await self.session.close()

    async def _test_endpoint_security(self, endpoint: APIEndpoint) -> APITestResult:
        """Test security of a single endpoint"""
        vulnerabilities = []

        try:
            # Test authentication
            auth_results = await self.auth_tester.test_authentication(endpoint, self.session)
            vulnerabilities.extend(self._convert_auth_results_to_vulnerabilities(endpoint, auth_results))

            # Test input validation
            input_vulns = await self._test_input_validation(endpoint)
            vulnerabilities.extend(input_vulns)

            # Test business logic
            logic_vulns = await self._test_business_logic(endpoint)
            vulnerabilities.extend(logic_vulns)

            # Test rate limiting
            rate_limit_info = await self._test_rate_limiting(endpoint)

            # Test HTTP methods
            method_vulns = await self._test_http_methods(endpoint)
            vulnerabilities.extend(method_vulns)

            result = APITestResult(
                endpoint=endpoint,
                vulnerabilities=vulnerabilities,
                test_statistics={
                    'tests_run': len(vulnerabilities) + 5,  # Approximation
                    'requests_sent': self._get_requests_for_endpoint(endpoint)
                },
                authentication_status=auth_results,
                rate_limit_info=rate_limit_info
            )

            return result

        except Exception as e:
            logging.error(f"Error testing endpoint {endpoint.url}: {e}")
            return APITestResult(
                endpoint=endpoint,
                vulnerabilities=[],
                test_statistics={'error': str(e)},
                authentication_status={}
            )

    def _convert_auth_results_to_vulnerabilities(self, endpoint: APIEndpoint, auth_results: Dict[str, Any]) -> List[APIVulnerability]:
        """Convert authentication test results to vulnerabilities"""
        vulnerabilities = []

        for vuln_data in auth_results.get('vulnerabilities', []):
            vuln_id = hashlib.md5(f"{endpoint.url}:{vuln_data['type']}".encode()).hexdigest()[:16]

            vulnerability = APIVulnerability(
                vuln_id=vuln_id,
                endpoint=endpoint,
                vulnerability_type=vuln_data['type'],
                severity=vuln_data['severity'],
                description=vuln_data['description'],
                evidence=[vuln_data.get('evidence', '')],
                remediation=self._get_remediation_for_vuln_type(vuln_data['type']),
                confidence=0.8
            )
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    async def _test_input_validation(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test input validation vulnerabilities"""
        vulnerabilities = []

        if not endpoint.parameters:
            return vulnerabilities

        # Generate test inputs
        test_inputs = self.input_generator.generate_test_inputs(endpoint.parameters)

        for test_input in test_inputs:
            try:
                await asyncio.sleep(self.request_delay)

                # Send request with test input
                if endpoint.method in [HTTPMethod.GET, HTTPMethod.DELETE]:
                    # Query parameters
                    url_with_params = f"{endpoint.url}?" + urllib.parse.urlencode(test_input)
                    async with self.session.request(endpoint.method.value, url_with_params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        response_body = await response.text()
                        self.test_statistics['requests_sent'] += 1

                        # Check for vulnerabilities
                        vulns = self._analyze_response_for_vulnerabilities(endpoint, test_input, response, response_body)
                        vulnerabilities.extend(vulns)

                else:
                    # Body parameters
                    json_data = test_input if endpoint.api_type == APIType.REST else None
                    async with self.session.request(endpoint.method.value, endpoint.url, json=json_data, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        response_body = await response.text()
                        self.test_statistics['requests_sent'] += 1

                        # Check for vulnerabilities
                        vulns = self._analyze_response_for_vulnerabilities(endpoint, test_input, response, response_body)
                        vulnerabilities.extend(vulns)

            except Exception as e:
                logging.debug(f"Input validation test error: {e}")
                continue

        return vulnerabilities

    def _analyze_response_for_vulnerabilities(self, endpoint: APIEndpoint, test_input: Dict[str, Any],
                                           response: aiohttp.ClientResponse, response_body: str) -> List[APIVulnerability]:
        """Analyze response for potential vulnerabilities"""
        vulnerabilities = []

        # SQL Injection detection
        sql_errors = [
            'mysql_fetch_array', 'ORA-01756', 'Microsoft JET Database',
            'SQLServer JDBC Driver', 'PostgreSQL query failed',
            'XPathException', 'Warning: mysql_'
        ]

        for error in sql_errors:
            if error.lower() in response_body.lower():
                vuln_id = hashlib.md5(f"{endpoint.url}:sql_injection".encode()).hexdigest()[:16]
                vulnerability = APIVulnerability(
                    vuln_id=vuln_id,
                    endpoint=endpoint,
                    vulnerability_type="sql_injection",
                    severity="critical",
                    description="Potential SQL injection vulnerability detected",
                    evidence=[f"SQL error in response: {error}"],
                    remediation="Use parameterized queries and input validation",
                    confidence=0.8,
                    payload_used=str(test_input),
                    response_data={
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'body_snippet': response_body[:500]
                    }
                )
                vulnerabilities.append(vulnerability)
                break

        # XSS detection (reflected)
        for param_name, param_value in test_input.items():
            if isinstance(param_value, str) and '<script>' in param_value.lower():
                if param_value in response_body:
                    vuln_id = hashlib.md5(f"{endpoint.url}:xss:{param_name}".encode()).hexdigest()[:16]
                    vulnerability = APIVulnerability(
                        vuln_id=vuln_id,
                        endpoint=endpoint,
                        vulnerability_type="reflected_xss",
                        severity="medium",
                        description=f"Reflected XSS vulnerability in parameter {param_name}",
                        evidence=[f"Payload reflected in response: {param_value}"],
                        remediation="Implement proper output encoding and input validation",
                        confidence=0.9,
                        payload_used=param_value,
                        response_data={
                            'status_code': response.status,
                            'parameter': param_name
                        }
                    )
                    vulnerabilities.append(vulnerability)

        # Information disclosure
        sensitive_patterns = [
            r'password\s*[:=]\s*["\'][^"\']+["\']',
            r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',
            r'secret\s*[:=]\s*["\'][^"\']+["\']',
            r'token\s*[:=]\s*["\'][^"\']+["\']',
            r'/[a-zA-Z]:/.*',  # Windows paths
            r'/etc/passwd', r'/proc/version'
        ]

        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            if matches:
                vuln_id = hashlib.md5(f"{endpoint.url}:info_disclosure".encode()).hexdigest()[:16]
                vulnerability = APIVulnerability(
                    vuln_id=vuln_id,
                    endpoint=endpoint,
                    vulnerability_type="information_disclosure",
                    severity="medium",
                    description="Sensitive information disclosed in API response",
                    evidence=[f"Pattern matched: {matches[0]}"],
                    remediation="Remove sensitive information from API responses",
                    confidence=0.7,
                    payload_used=str(test_input)
                )
                vulnerabilities.append(vulnerability)
                break

        return vulnerabilities

    async def _test_business_logic(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test business logic vulnerabilities"""
        vulnerabilities = []

        # Test for IDOR (Insecure Direct Object Reference)
        if any(param_name in ['id', 'user_id', 'account_id', 'order_id'] for param_name in endpoint.parameters.keys()):
            idor_vuln = await self._test_idor(endpoint)
            if idor_vuln:
                vulnerabilities.append(idor_vuln)

        # Test for privilege escalation
        privesc_vuln = await self._test_privilege_escalation(endpoint)
        if privesc_vuln:
            vulnerabilities.append(privesc_vuln)

        return vulnerabilities

    async def _test_idor(self, endpoint: APIEndpoint) -> Optional[APIVulnerability]:
        """Test for Insecure Direct Object Reference"""
        try:
            # Test with different ID values
            test_ids = ['1', '2', '999', '0', '-1', 'admin', 'other_user']

            responses = []
            for test_id in test_ids:
                test_data = {}
                for param_name, param in endpoint.parameters.items():
                    if 'id' in param_name.lower():
                        test_data[param_name] = test_id
                    else:
                        values = self.input_generator._generate_values_for_parameter(param)
                        test_data[param_name] = values[0] if values else "test"

                try:
                    if endpoint.method in [HTTPMethod.GET, HTTPMethod.DELETE]:
                        url_with_params = f"{endpoint.url}?" + urllib.parse.urlencode(test_data)
                        async with self.session.request(endpoint.method.value, url_with_params, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            response_body = await response.text()
                            responses.append({
                                'id': test_id,
                                'status': response.status,
                                'body': response_body
                            })
                    else:
                        async with self.session.request(endpoint.method.value, endpoint.url, json=test_data, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            response_body = await response.text()
                            responses.append({
                                'id': test_id,
                                'status': response.status,
                                'body': response_body
                            })

                    await asyncio.sleep(self.request_delay)

                except Exception:
                    continue

            # Analyze responses for IDOR
            success_responses = [r for r in responses if r['status'] in [200, 201, 202]]
            if len(success_responses) > 1:
                # Check if different IDs return different data
                different_data = len(set(r['body'] for r in success_responses)) > 1

                if different_data:
                    vuln_id = hashlib.md5(f"{endpoint.url}:idor".encode()).hexdigest()[:16]
                    return APIVulnerability(
                        vuln_id=vuln_id,
                        endpoint=endpoint,
                        vulnerability_type="idor",
                        severity="high",
                        description="Potential Insecure Direct Object Reference vulnerability",
                        evidence=[f"Different responses for IDs: {[r['id'] for r in success_responses]}"],
                        remediation="Implement proper authorization checks for object access",
                        confidence=0.6
                    )

        except Exception as e:
            logging.debug(f"IDOR test error: {e}")

        return None

    async def _test_privilege_escalation(self, endpoint: APIEndpoint) -> Optional[APIVulnerability]:
        """Test for privilege escalation vulnerabilities"""
        try:
            # Test admin-related parameters
            admin_tests = [
                {'admin': True},
                {'role': 'admin'},
                {'is_admin': 'true'},
                {'user_type': 'administrator'},
                {'privilege': 'admin'},
                {'level': '999'}
            ]

            for admin_test in admin_tests:
                test_data = {}
                for param_name, param in endpoint.parameters.items():
                    if param_name in admin_test:
                        test_data[param_name] = admin_test[param_name]
                    else:
                        values = self.input_generator._generate_values_for_parameter(param)
                        test_data[param_name] = values[0] if values else "test"

                # Add admin test parameters
                test_data.update(admin_test)

                try:
                    if endpoint.method in [HTTPMethod.GET, HTTPMethod.DELETE]:
                        url_with_params = f"{endpoint.url}?" + urllib.parse.urlencode(test_data)
                        async with self.session.request(endpoint.method.value, url_with_params, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            if response.status in [200, 201, 202]:
                                response_body = await response.text()

                                # Look for admin-related content
                                admin_indicators = ['admin', 'administrator', 'privilege', 'elevated', 'superuser']
                                if any(indicator in response_body.lower() for indicator in admin_indicators):
                                    vuln_id = hashlib.md5(f"{endpoint.url}:privilege_escalation".encode()).hexdigest()[:16]
                                    return APIVulnerability(
                                        vuln_id=vuln_id,
                                        endpoint=endpoint,
                                        vulnerability_type="privilege_escalation",
                                        severity="critical",
                                        description="Potential privilege escalation vulnerability",
                                        evidence=[f"Admin access gained with parameters: {admin_test}"],
                                        remediation="Implement proper authorization and role-based access controls",
                                        confidence=0.7,
                                        payload_used=str(admin_test)
                                    )
                    else:
                        async with self.session.request(endpoint.method.value, endpoint.url, json=test_data, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            if response.status in [200, 201, 202]:
                                response_body = await response.text()

                                admin_indicators = ['admin', 'administrator', 'privilege', 'elevated', 'superuser']
                                if any(indicator in response_body.lower() for indicator in admin_indicators):
                                    vuln_id = hashlib.md5(f"{endpoint.url}:privilege_escalation".encode()).hexdigest()[:16]
                                    return APIVulnerability(
                                        vuln_id=vuln_id,
                                        endpoint=endpoint,
                                        vulnerability_type="privilege_escalation",
                                        severity="critical",
                                        description="Potential privilege escalation vulnerability",
                                        evidence=[f"Admin access gained with parameters: {admin_test}"],
                                        remediation="Implement proper authorization and role-based access controls",
                                        confidence=0.7,
                                        payload_used=str(admin_test)
                                    )

                    await asyncio.sleep(self.request_delay)

                except Exception:
                    continue

        except Exception as e:
            logging.debug(f"Privilege escalation test error: {e}")

        return None

    async def _test_rate_limiting(self, endpoint: APIEndpoint) -> Optional[Dict[str, Any]]:
        """Test rate limiting implementation"""
        try:
            # Send multiple requests quickly
            start_time = time.time()
            requests_sent = 0
            rate_limited = False
            rate_limit_status = None

            for _ in range(20):  # Send 20 requests
                try:
                    async with self.session.request(endpoint.method.value, endpoint.url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        requests_sent += 1

                        if response.status == 429:  # Too Many Requests
                            rate_limited = True
                            rate_limit_status = response.status
                            break

                        elif response.status in [503, 502]:  # Service overload
                            rate_limited = True
                            rate_limit_status = response.status
                            break

                except Exception:
                    continue

            end_time = time.time()
            duration = end_time - start_time

            return {
                'rate_limiting_detected': rate_limited,
                'requests_sent': requests_sent,
                'duration': duration,
                'status_code': rate_limit_status,
                'requests_per_second': requests_sent / duration if duration > 0 else 0
            }

        except Exception as e:
            logging.debug(f"Rate limiting test error: {e}")
            return None

    async def _test_http_methods(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test for HTTP method vulnerabilities"""
        vulnerabilities = []

        # Test all HTTP methods
        methods_to_test = [method.value for method in HTTPMethod if method != endpoint.method]

        for method in methods_to_test:
            try:
                async with self.session.request(method, endpoint.url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status in [200, 201, 202, 204]:
                        # Unexpected method allowed
                        vuln_id = hashlib.md5(f"{endpoint.url}:http_method:{method}".encode()).hexdigest()[:16]
                        vulnerability = APIVulnerability(
                            vuln_id=vuln_id,
                            endpoint=endpoint,
                            vulnerability_type="http_method_override",
                            severity="medium",
                            description=f"Unexpected HTTP method {method} allowed",
                            evidence=[f"Method {method} returned status {response.status}"],
                            remediation="Restrict allowed HTTP methods and implement proper method validation",
                            confidence=0.6
                        )
                        vulnerabilities.append(vulnerability)

            except Exception:
                continue

        return vulnerabilities

    def _get_requests_for_endpoint(self, endpoint: APIEndpoint) -> int:
        """Estimate number of requests sent for endpoint"""
        # This is an approximation - in practice you'd track this more accurately
        base_requests = 10  # Authentication tests

        if endpoint.parameters:
            param_tests = len(endpoint.parameters) * 5  # Input validation tests
        else:
            param_tests = 1

        business_logic_tests = 10  # IDOR, privilege escalation
        rate_limit_tests = 20
        method_tests = len(HTTPMethod) - 1

        return base_requests + param_tests + business_logic_tests + rate_limit_tests + method_tests

    def _get_remediation_for_vuln_type(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediations = {
            'unauthenticated_access': 'Implement proper authentication for all sensitive endpoints',
            'weak_credentials': 'Enforce strong password policies and disable default credentials',
            'weak_api_key': 'Generate strong, random API keys and implement key rotation',
            'jwt_none_algorithm': 'Disable the "none" algorithm in JWT libraries and validate algorithm',
            'header_bypass': 'Do not rely solely on IP-based authentication or header values',
            'sql_injection': 'Use parameterized queries and input validation',
            'reflected_xss': 'Implement proper input validation and output encoding',
            'information_disclosure': 'Remove sensitive information from API responses',
            'idor': 'Implement proper authorization checks for object access',
            'privilege_escalation': 'Implement role-based access controls and validation',
            'http_method_override': 'Restrict allowed HTTP methods and validate requests'
        }

        return remediations.get(vuln_type, 'Review and fix the identified security issue')

    def generate_api_test_report(self, test_results: List[APITestResult]) -> str:
        """Generate comprehensive API test report"""
        report = []
        report.append("API Security Test Report")
        report.append("=" * 50)

        # Summary
        total_endpoints = len(test_results)
        total_vulnerabilities = sum(len(result.vulnerabilities) for result in test_results)

        report.append("Summary:")
        report.append(f"  Endpoints Tested: {total_endpoints}")
        report.append(f"  Total Vulnerabilities: {total_vulnerabilities}")
        report.append(f"  Requests Sent: {self.test_statistics['requests_sent']}")
        report.append(f"  Test Duration: {self.test_statistics['test_duration']:.2f}s")
        report.append("")

        # Vulnerability breakdown
        vuln_types = defaultdict(int)
        severity_counts = defaultdict(int)

        for result in test_results:
            for vuln in result.vulnerabilities:
                vuln_types[vuln.vulnerability_type] += 1
                severity_counts[vuln.severity] += 1

        if vuln_types:
            report.append("Vulnerabilities by Type:")
            for vuln_type, count in sorted(vuln_types.items()):
                report.append(f"  {vuln_type}: {count}")
            report.append("")

        if severity_counts:
            report.append("Vulnerabilities by Severity:")
            for severity in ['critical', 'high', 'medium', 'low']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    report.append(f"  {severity.upper()}: {count}")
            report.append("")

        # API types discovered
        api_types = defaultdict(int)
        for result in test_results:
            api_types[result.endpoint.api_type.value] += 1

        if api_types:
            report.append("API Types Discovered:")
            for api_type, count in sorted(api_types.items()):
                report.append(f"  {api_type.upper()}: {count} endpoints")
            report.append("")

        # Detailed findings
        all_vulnerabilities = []
        for result in test_results:
            all_vulnerabilities.extend(result.vulnerabilities)

        # Sort by severity
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        all_vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 0), reverse=True)

        if all_vulnerabilities:
            report.append("Detailed Findings:")
            report.append("-" * 30)

            for i, vuln in enumerate(all_vulnerabilities[:15]):  # Show top 15
                report.append(f"Finding #{i+1}: {vuln.vulnerability_type}")
                report.append(f"  Severity: {vuln.severity.upper()}")
                report.append(f"  Confidence: {vuln.confidence:.2f}")
                report.append(f"  Endpoint: {vuln.endpoint.method.value} {vuln.endpoint.url}")
                report.append(f"  Description: {vuln.description}")

                if vuln.evidence:
                    report.append("  Evidence:")
                    for evidence in vuln.evidence[:2]:
                        report.append(f"    • {evidence}")

                report.append(f"  Remediation: {vuln.remediation}")
                report.append("")

        return "\n".join(report)