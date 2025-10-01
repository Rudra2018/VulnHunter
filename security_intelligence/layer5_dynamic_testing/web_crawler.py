"""
Intelligent Web Application Crawler

This module provides advanced web crawling capabilities:
- AI-guided crawling with intelligent form filling
- Dynamic content discovery and AJAX handling
- Advanced authentication bypass and session management
- Comprehensive input discovery and parameter analysis
- Smart URL generation and endpoint enumeration
"""

import asyncio
import aiohttp
import logging
import json
import re
import time
import hashlib
import urllib.parse
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import random
from collections import defaultdict, deque

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logging.warning("Selenium not available. Install with: pip install selenium")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logging.warning("BeautifulSoup not available. Install with: pip install beautifulsoup4")

class DiscoveryMethod(Enum):
    """Methods for discovering content"""
    LINK_FOLLOWING = "link_following"
    FORM_SUBMISSION = "form_submission"
    AJAX_MONITORING = "ajax_monitoring"
    DIRECTORY_BRUTE_FORCE = "directory_brute_force"
    PARAMETER_DISCOVERY = "parameter_discovery"
    API_ENUMERATION = "api_enumeration"

class InputType(Enum):
    """Types of inputs discovered"""
    URL_PARAMETER = "url_parameter"
    FORM_INPUT = "form_input"
    JSON_PARAMETER = "json_parameter"
    HEADER_PARAMETER = "header_parameter"
    COOKIE_PARAMETER = "cookie_parameter"
    PATH_PARAMETER = "path_parameter"

@dataclass
class CrawlTarget:
    """Target for crawling"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[Dict[str, Any]] = None
    crawl_depth: int = 3
    max_pages: int = 1000
    follow_redirects: bool = True
    ignore_extensions: List[str] = field(default_factory=lambda: ['.jpg', '.png', '.gif', '.css', '.js'])

@dataclass
class DiscoveredInput:
    """Represents a discovered input parameter"""
    name: str
    input_type: InputType
    location: str
    form_id: Optional[str] = None
    required: bool = False
    default_value: Optional[str] = None
    constraints: List[str] = field(default_factory=list)
    discovered_method: DiscoveryMethod = DiscoveryMethod.LINK_FOLLOWING
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str
    parameters: List[DiscoveredInput]
    response_code: int
    response_size: int
    content_type: str
    forms: List[Dict[str, Any]] = field(default_factory=list)
    authentication_required: bool = False
    discovery_method: DiscoveryMethod = DiscoveryMethod.LINK_FOLLOWING
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CrawlResult:
    """Results from crawling operation"""
    target_url: str
    discovered_endpoints: List[DiscoveredEndpoint]
    discovered_inputs: List[DiscoveredInput]
    session_data: Dict[str, Any]
    authentication_info: Optional[Dict[str, Any]]
    crawl_statistics: Dict[str, Any]
    discovered_technologies: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)

class UserAgentRotator:
    """Rotates user agents to avoid detection"""

    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
        ]
        self.current_index = 0

    def get_user_agent(self) -> str:
        """Get next user agent in rotation"""
        user_agent = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return user_agent

class FormAnalyzer:
    """Analyzes and fills web forms intelligently"""

    def __init__(self):
        self.field_patterns = self._load_field_patterns()
        self.test_values = self._load_test_values()

    def _load_field_patterns(self) -> Dict[str, List[str]]:
        """Load field name patterns for intelligent recognition"""
        return {
            'email': ['email', 'e-mail', 'mail', 'user_email', 'login_email'],
            'password': ['password', 'passwd', 'pwd', 'pass', 'user_password'],
            'username': ['username', 'user', 'login', 'userid', 'user_id', 'account'],
            'name': ['name', 'fullname', 'full_name', 'fname', 'lname', 'first_name', 'last_name'],
            'phone': ['phone', 'telephone', 'tel', 'mobile', 'cell'],
            'address': ['address', 'addr', 'street', 'location'],
            'url': ['url', 'website', 'link', 'homepage'],
            'number': ['age', 'amount', 'price', 'quantity', 'count'],
            'date': ['date', 'birthday', 'dob', 'created', 'modified'],
            'search': ['search', 'query', 'q', 'term', 'keyword'],
            'token': ['token', 'csrf', 'nonce', 'key', 'session'],
            'id': ['id', 'uid', 'identifier', 'ref']
        }

    def _load_test_values(self) -> Dict[str, List[str]]:
        """Load test values for different field types"""
        return {
            'email': ['test@example.com', 'user@test.com', 'admin@site.com'],
            'password': ['password123', 'test123', 'admin', '123456'],
            'username': ['admin', 'test', 'user', 'guest', 'administrator'],
            'name': ['John Doe', 'Test User', 'Admin User'],
            'phone': ['555-1234', '123-456-7890', '+1-555-123-4567'],
            'address': ['123 Main St', '456 Test Ave', '789 Example Blvd'],
            'url': ['https://example.com', 'http://test.com', 'https://site.org'],
            'number': ['123', '42', '100', '1'],
            'date': ['2023-01-01', '2023-12-31', '1990-01-01'],
            'search': ['test', 'admin', 'search', 'query'],
            'token': ['', 'test', 'invalid'],
            'id': ['1', '123', 'test'],
            'default': ['test', 'value', '123', 'admin']
        }

    def analyze_form(self, form_element: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze form and generate intelligent test inputs"""
        form_analysis = {
            'action': form_element.get('action', ''),
            'method': form_element.get('method', 'GET').upper(),
            'inputs': [],
            'test_payloads': []
        }

        inputs = form_element.get('inputs', [])

        for input_field in inputs:
            field_analysis = self._analyze_input_field(input_field)
            form_analysis['inputs'].append(field_analysis)

        # Generate test payloads
        form_analysis['test_payloads'] = self._generate_form_payloads(form_analysis['inputs'])

        return form_analysis

    def _analyze_input_field(self, input_field: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual input field"""
        field_name = input_field.get('name', '')
        field_type = input_field.get('type', 'text')
        field_id = input_field.get('id', '')
        placeholder = input_field.get('placeholder', '')
        required = input_field.get('required', False)

        # Determine field purpose
        field_purpose = self._determine_field_purpose(field_name, field_id, placeholder)

        # Generate test values
        test_values = self._generate_field_values(field_purpose, field_type)

        analysis = {
            'name': field_name,
            'type': field_type,
            'id': field_id,
            'purpose': field_purpose,
            'required': required,
            'test_values': test_values,
            'constraints': self._extract_constraints(input_field),
            'security_relevant': self._is_security_relevant(field_purpose, field_name)
        }

        return analysis

    def _determine_field_purpose(self, name: str, field_id: str, placeholder: str) -> str:
        """Determine the purpose of an input field"""
        text_to_analyze = f"{name} {field_id} {placeholder}".lower()

        for purpose, patterns in self.field_patterns.items():
            for pattern in patterns:
                if pattern in text_to_analyze:
                    return purpose

        return 'default'

    def _generate_field_values(self, purpose: str, field_type: str) -> List[str]:
        """Generate test values for field"""
        base_values = self.test_values.get(purpose, self.test_values['default'])

        # Add type-specific values
        if field_type == 'email':
            return self.test_values['email']
        elif field_type == 'password':
            return self.test_values['password']
        elif field_type == 'number':
            return self.test_values['number']
        elif field_type == 'url':
            return self.test_values['url']
        elif field_type == 'date':
            return self.test_values['date']

        return base_values

    def _extract_constraints(self, input_field: Dict[str, Any]) -> List[str]:
        """Extract constraints from input field"""
        constraints = []

        if input_field.get('maxlength'):
            constraints.append(f"maxlength:{input_field['maxlength']}")

        if input_field.get('minlength'):
            constraints.append(f"minlength:{input_field['minlength']}")

        if input_field.get('pattern'):
            constraints.append(f"pattern:{input_field['pattern']}")

        if input_field.get('min'):
            constraints.append(f"min:{input_field['min']}")

        if input_field.get('max'):
            constraints.append(f"max:{input_field['max']}")

        return constraints

    def _is_security_relevant(self, purpose: str, field_name: str) -> bool:
        """Determine if field is security-relevant"""
        security_purposes = ['password', 'email', 'username', 'token', 'search']
        security_keywords = ['admin', 'auth', 'login', 'session', 'key', 'secret']

        if purpose in security_purposes:
            return True

        field_name_lower = field_name.lower()
        return any(keyword in field_name_lower for keyword in security_keywords)

    def _generate_form_payloads(self, inputs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate form submission payloads"""
        payloads = []

        # Generate basic valid payload
        valid_payload = {}
        for input_field in inputs:
            if input_field['test_values']:
                valid_payload[input_field['name']] = input_field['test_values'][0]

        if valid_payload:
            payloads.append(valid_payload)

        # Generate payloads with different combinations
        for i in range(min(3, len(inputs))):
            payload = valid_payload.copy()
            for input_field in inputs:
                if len(input_field['test_values']) > i + 1:
                    payload[input_field['name']] = input_field['test_values'][i + 1]
            payloads.append(payload)

        return payloads

class AjaxInterceptor:
    """Intercepts and analyzes AJAX requests"""

    def __init__(self):
        self.intercepted_requests = []
        self.request_patterns = []

    def setup_interception(self, driver):
        """Setup AJAX request interception"""
        if not SELENIUM_AVAILABLE:
            return

        # Inject JavaScript to intercept XMLHttpRequest
        intercept_script = """
        (function() {
            var originalOpen = XMLHttpRequest.prototype.open;
            var originalSend = XMLHttpRequest.prototype.send;

            XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
                this._method = method;
                this._url = url;
                return originalOpen.apply(this, arguments);
            };

            XMLHttpRequest.prototype.send = function(data) {
                this.addEventListener('load', function() {
                    window.interceptedRequests = window.interceptedRequests || [];
                    window.interceptedRequests.push({
                        method: this._method,
                        url: this._url,
                        status: this.status,
                        response: this.responseText,
                        data: data,
                        timestamp: Date.now()
                    });
                });
                return originalSend.apply(this, arguments);
            };

            // Intercept fetch API
            var originalFetch = window.fetch;
            window.fetch = function(url, options) {
                return originalFetch(url, options).then(function(response) {
                    window.interceptedRequests = window.interceptedRequests || [];
                    window.interceptedRequests.push({
                        method: (options && options.method) || 'GET',
                        url: url,
                        status: response.status,
                        data: (options && options.body) || null,
                        timestamp: Date.now()
                    });
                    return response;
                });
            };
        })();
        """

        try:
            driver.execute_script(intercept_script)
        except Exception as e:
            logging.error(f"Failed to setup AJAX interception: {e}")

    def get_intercepted_requests(self, driver) -> List[Dict[str, Any]]:
        """Get intercepted AJAX requests"""
        if not SELENIUM_AVAILABLE:
            return []

        try:
            requests = driver.execute_script("return window.interceptedRequests || [];")
            new_requests = requests[len(self.intercepted_requests):]
            self.intercepted_requests.extend(new_requests)
            return new_requests
        except Exception as e:
            logging.error(f"Failed to get intercepted requests: {e}")
            return []

class IntelligentWebCrawler:
    """Main intelligent web crawler"""

    def __init__(self, max_concurrent: int = 10, request_delay: float = 1.0):
        self.max_concurrent = max_concurrent
        self.request_delay = request_delay
        self.user_agent_rotator = UserAgentRotator()
        self.form_analyzer = FormAnalyzer()
        self.ajax_interceptor = AjaxInterceptor()

        self.session = None
        self.discovered_urls = set()
        self.crawled_urls = set()
        self.discovered_inputs = []
        self.discovered_endpoints = []

        # Browser automation
        self.driver = None
        self.use_browser = SELENIUM_AVAILABLE

        # Statistics
        self.crawl_stats = {
            'pages_crawled': 0,
            'forms_found': 0,
            'inputs_discovered': 0,
            'ajax_requests_intercepted': 0,
            'errors_encountered': 0
        }

    async def crawl(self, target: CrawlTarget) -> CrawlResult:
        """Main crawling entry point"""
        logging.info(f"Starting intelligent crawl of {target.url}")

        # Initialize session
        await self._initialize_session(target)

        # Setup browser if needed
        if self.use_browser:
            self._setup_browser()

        try:
            # Perform crawling
            await self._perform_crawl(target)

            # Analyze discovered content
            self._analyze_discovered_content()

            # Create result
            result = CrawlResult(
                target_url=target.url,
                discovered_endpoints=self.discovered_endpoints,
                discovered_inputs=self.discovered_inputs,
                session_data=await self._extract_session_data(),
                authentication_info=target.authentication,
                crawl_statistics=self.crawl_stats,
                discovered_technologies=self._detect_technologies(),
                security_headers=self._analyze_security_headers()
            )

            logging.info(f"Crawl completed: {len(self.discovered_endpoints)} endpoints, {len(self.discovered_inputs)} inputs")
            return result

        finally:
            await self._cleanup()

    async def _initialize_session(self, target: CrawlTarget):
        """Initialize HTTP session"""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=30)

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': self.user_agent_rotator.get_user_agent(),
                **target.headers
            },
            cookies=target.cookies
        )

    def _setup_browser(self):
        """Setup browser for JavaScript-heavy applications"""
        if not SELENIUM_AVAILABLE:
            return

        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument(f'--user-agent={self.user_agent_rotator.get_user_agent()}')

            self.driver = webdriver.Chrome(options=chrome_options)
            self.ajax_interceptor.setup_interception(self.driver)

        except Exception as e:
            logging.error(f"Failed to setup browser: {e}")
            self.use_browser = False

    async def _perform_crawl(self, target: CrawlTarget):
        """Perform the main crawling operation"""
        urls_to_crawl = deque([target.url])
        current_depth = 0

        while urls_to_crawl and current_depth < target.crawl_depth and len(self.crawled_urls) < target.max_pages:
            current_level_urls = list(urls_to_crawl)
            urls_to_crawl.clear()

            # Process URLs in parallel
            tasks = []
            for url in current_level_urls[:self.max_concurrent]:
                if url not in self.crawled_urls:
                    task = self._crawl_single_url(url, target, current_depth)
                    tasks.append(task)

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Process results and collect new URLs
                for result in results:
                    if isinstance(result, Exception):
                        self.crawl_stats['errors_encountered'] += 1
                        logging.error(f"Crawl error: {result}")
                    elif result:
                        new_urls = result.get('discovered_urls', [])
                        for new_url in new_urls:
                            if self._should_crawl_url(new_url, target):
                                urls_to_crawl.append(new_url)

            current_depth += 1

        # Browser-based crawling for dynamic content
        if self.use_browser and self.driver:
            await self._browser_crawl(target)

    async def _crawl_single_url(self, url: str, target: CrawlTarget, depth: int) -> Dict[str, Any]:
        """Crawl a single URL"""
        if url in self.crawled_urls:
            return {}

        self.crawled_urls.add(url)
        self.crawl_stats['pages_crawled'] += 1

        try:
            # Add delay to avoid overwhelming the server
            await asyncio.sleep(self.request_delay)

            async with self.session.get(url, allow_redirects=target.follow_redirects) as response:
                content = await response.text()

                endpoint = DiscoveredEndpoint(
                    url=url,
                    method='GET',
                    parameters=[],
                    response_code=response.status,
                    response_size=len(content),
                    content_type=response.headers.get('content-type', ''),
                    discovery_method=DiscoveryMethod.LINK_FOLLOWING
                )

                self.discovered_endpoints.append(endpoint)

                # Parse content for additional URLs and forms
                result = {
                    'url': url,
                    'status_code': response.status,
                    'content': content,
                    'headers': dict(response.headers),
                    'discovered_urls': [],
                    'forms': []
                }

                if BS4_AVAILABLE and content:
                    soup = BeautifulSoup(content, 'html.parser')

                    # Extract links
                    result['discovered_urls'] = self._extract_links(soup, url)

                    # Extract forms
                    forms = self._extract_forms(soup, url)
                    result['forms'] = forms
                    endpoint.forms = forms

                    # Extract inputs
                    inputs = self._extract_inputs_from_forms(forms, url)
                    self.discovered_inputs.extend(inputs)
                    endpoint.parameters = inputs

                return result

        except Exception as e:
            logging.error(f"Error crawling {url}: {e}")
            self.crawl_stats['errors_encountered'] += 1
            return {}

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []

        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                absolute_url = urllib.parse.urljoin(base_url, href)
                links.append(absolute_url)

        # Extract from JavaScript (basic patterns)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Look for URL patterns in JavaScript
                js_urls = re.findall(r'["\']([^"\']*\.[^"\']*)["\']', script.string)
                for js_url in js_urls:
                    if '/' in js_url:
                        absolute_url = urllib.parse.urljoin(base_url, js_url)
                        links.append(absolute_url)

        return links

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                action = urllib.parse.urljoin(base_url, action)
            else:
                action = base_url

            method = form.get('method', 'GET').upper()

            form_inputs = []
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                input_info = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'id': input_tag.get('id', ''),
                    'value': input_tag.get('value', ''),
                    'placeholder': input_tag.get('placeholder', ''),
                    'required': input_tag.has_attr('required'),
                    'maxlength': input_tag.get('maxlength'),
                    'pattern': input_tag.get('pattern')
                }

                if input_tag.name == 'select':
                    options = [opt.get('value', opt.text) for opt in input_tag.find_all('option')]
                    input_info['options'] = options

                form_inputs.append(input_info)

            form_data = {
                'action': action,
                'method': method,
                'inputs': form_inputs,
                'form_id': form.get('id', ''),
                'analysis': None
            }

            # Analyze form
            form_data['analysis'] = self.form_analyzer.analyze_form(form_data)

            forms.append(form_data)
            self.crawl_stats['forms_found'] += 1

        return forms

    def _extract_inputs_from_forms(self, forms: List[Dict[str, Any]], url: str) -> List[DiscoveredInput]:
        """Extract input parameters from forms"""
        inputs = []

        for form in forms:
            for input_field in form.get('inputs', []):
                if input_field.get('name'):
                    discovered_input = DiscoveredInput(
                        name=input_field['name'],
                        input_type=InputType.FORM_INPUT,
                        location=url,
                        form_id=form.get('form_id'),
                        required=input_field.get('required', False),
                        default_value=input_field.get('value'),
                        constraints=[],
                        discovered_method=DiscoveryMethod.FORM_SUBMISSION,
                        metadata={
                            'form_method': form.get('method'),
                            'form_action': form.get('action'),
                            'input_type': input_field.get('type'),
                            'security_relevant': False
                        }
                    )

                    # Extract constraints
                    if input_field.get('maxlength'):
                        discovered_input.constraints.append(f"maxlength:{input_field['maxlength']}")
                    if input_field.get('pattern'):
                        discovered_input.constraints.append(f"pattern:{input_field['pattern']}")

                    # Check if security relevant
                    if form.get('analysis'):
                        analysis_inputs = form['analysis'].get('inputs', [])
                        for analysis_input in analysis_inputs:
                            if analysis_input.get('name') == input_field['name']:
                                discovered_input.metadata['security_relevant'] = analysis_input.get('security_relevant', False)
                                break

                    inputs.append(discovered_input)
                    self.crawl_stats['inputs_discovered'] += 1

        return inputs

    async def _browser_crawl(self, target: CrawlTarget):
        """Crawl using browser for dynamic content"""
        if not self.driver:
            return

        try:
            # Visit main page
            self.driver.get(target.url)

            # Wait for page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            # Interact with dynamic elements
            await self._interact_with_dynamic_elements()

            # Check for AJAX requests
            ajax_requests = self.ajax_interceptor.get_intercepted_requests(self.driver)
            self.crawl_stats['ajax_requests_intercepted'] += len(ajax_requests)

            # Process AJAX requests
            for request in ajax_requests:
                await self._process_ajax_request(request, target)

        except Exception as e:
            logging.error(f"Browser crawling error: {e}")

    async def _interact_with_dynamic_elements(self):
        """Interact with dynamic elements to trigger AJAX requests"""
        if not self.driver:
            return

        try:
            # Click buttons and links that might trigger AJAX
            clickable_elements = self.driver.find_elements(By.CSS_SELECTOR,
                "button, a[href='#'], .clickable, [onclick], [data-*]")

            for element in clickable_elements[:10]:  # Limit interactions
                try:
                    if element.is_displayed() and element.is_enabled():
                        element.click()
                        await asyncio.sleep(1)  # Wait for potential AJAX
                except Exception:
                    continue

            # Trigger hover events
            hover_elements = self.driver.find_elements(By.CSS_SELECTOR, "[onmouseover], .dropdown")
            for element in hover_elements[:5]:
                try:
                    if element.is_displayed():
                        webdriver.ActionChains(self.driver).move_to_element(element).perform()
                        await asyncio.sleep(0.5)
                except Exception:
                    continue

        except Exception as e:
            logging.error(f"Dynamic interaction error: {e}")

    async def _process_ajax_request(self, request: Dict[str, Any], target: CrawlTarget):
        """Process discovered AJAX request"""
        try:
            url = request.get('url', '')
            method = request.get('method', 'GET')

            # Make absolute URL
            if not url.startswith('http'):
                url = urllib.parse.urljoin(target.url, url)

            # Create endpoint
            endpoint = DiscoveredEndpoint(
                url=url,
                method=method,
                parameters=[],
                response_code=request.get('status', 0),
                response_size=len(request.get('response', '')),
                content_type='application/json',  # Assume JSON for AJAX
                discovery_method=DiscoveryMethod.AJAX_MONITORING,
                metadata={
                    'ajax_request': True,
                    'request_data': request.get('data')
                }
            )

            self.discovered_endpoints.append(endpoint)

            # Extract parameters from request data
            request_data = request.get('data')
            if request_data:
                inputs = self._extract_inputs_from_request_data(request_data, url)
                self.discovered_inputs.extend(inputs)
                endpoint.parameters = inputs

        except Exception as e:
            logging.error(f"Error processing AJAX request: {e}")

    def _extract_inputs_from_request_data(self, request_data: str, url: str) -> List[DiscoveredInput]:
        """Extract input parameters from request data"""
        inputs = []

        try:
            # Try to parse as JSON
            if request_data.strip().startswith('{'):
                json_data = json.loads(request_data)
                for key, value in json_data.items():
                    input_param = DiscoveredInput(
                        name=key,
                        input_type=InputType.JSON_PARAMETER,
                        location=url,
                        default_value=str(value) if value is not None else None,
                        discovered_method=DiscoveryMethod.AJAX_MONITORING,
                        metadata={'data_type': type(value).__name__}
                    )
                    inputs.append(input_param)

            # Try to parse as form data
            elif '=' in request_data:
                parsed_data = urllib.parse.parse_qs(request_data)
                for key, values in parsed_data.items():
                    input_param = DiscoveredInput(
                        name=key,
                        input_type=InputType.FORM_INPUT,
                        location=url,
                        default_value=values[0] if values else None,
                        discovered_method=DiscoveryMethod.AJAX_MONITORING
                    )
                    inputs.append(input_param)

        except Exception as e:
            logging.debug(f"Could not parse request data: {e}")

        return inputs

    def _should_crawl_url(self, url: str, target: CrawlTarget) -> bool:
        """Determine if URL should be crawled"""
        parsed_url = urllib.parse.urlparse(url)
        target_parsed = urllib.parse.urlparse(target.url)

        # Same domain check
        if parsed_url.netloc != target_parsed.netloc:
            return False

        # Check ignored extensions
        for ext in target.ignore_extensions:
            if parsed_url.path.lower().endswith(ext):
                return False

        # Avoid duplicate URLs
        if url in self.discovered_urls:
            return False

        self.discovered_urls.add(url)
        return True

    def _analyze_discovered_content(self):
        """Analyze discovered content for additional insights"""
        # Group inputs by type
        input_types = defaultdict(int)
        for input_param in self.discovered_inputs:
            input_types[input_param.input_type.value] += 1

        # Group endpoints by method
        endpoint_methods = defaultdict(int)
        for endpoint in self.discovered_endpoints:
            endpoint_methods[endpoint.method] += 1

        # Update statistics
        self.crawl_stats['input_types'] = dict(input_types)
        self.crawl_stats['endpoint_methods'] = dict(endpoint_methods)

    def _detect_technologies(self) -> List[str]:
        """Detect technologies used by the application"""
        technologies = []

        # Analyze discovered endpoints and content
        for endpoint in self.discovered_endpoints:
            content_type = endpoint.content_type.lower()

            if 'json' in content_type:
                technologies.append('JSON API')
            elif 'xml' in content_type:
                technologies.append('XML API')

        # Check for common frameworks
        for input_param in self.discovered_inputs:
            if 'csrf' in input_param.name.lower():
                technologies.append('CSRF Protection')
            elif 'viewstate' in input_param.name.lower():
                technologies.append('ASP.NET ViewState')

        return list(set(technologies))

    def _analyze_security_headers(self) -> Dict[str, str]:
        """Analyze security headers from responses"""
        security_headers = {}

        # This would be populated during crawling
        # For now, return empty dict
        return security_headers

    async def _extract_session_data(self) -> Dict[str, Any]:
        """Extract session-related data"""
        session_data = {
            'cookies': {},
            'session_tokens': [],
            'csrf_tokens': []
        }

        if self.session:
            session_data['cookies'] = {cookie.key: cookie.value for cookie in self.session.cookie_jar}

        # Extract session tokens from discovered inputs
        for input_param in self.discovered_inputs:
            if 'session' in input_param.name.lower() or 'token' in input_param.name.lower():
                session_data['session_tokens'].append({
                    'name': input_param.name,
                    'location': input_param.location,
                    'value': input_param.default_value
                })

            if 'csrf' in input_param.name.lower():
                session_data['csrf_tokens'].append({
                    'name': input_param.name,
                    'location': input_param.location,
                    'value': input_param.default_value
                })

        return session_data

    async def _cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()

        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass

    def generate_crawl_report(self, crawl_result: CrawlResult) -> str:
        """Generate comprehensive crawl report"""
        report = []
        report.append(f"Intelligent Web Crawl Report: {crawl_result.target_url}")
        report.append("=" * 60)

        stats = crawl_result.crawl_statistics

        # Summary
        report.append("Summary:")
        report.append(f"  Pages Crawled: {stats.get('pages_crawled', 0)}")
        report.append(f"  Endpoints Discovered: {len(crawl_result.discovered_endpoints)}")
        report.append(f"  Input Parameters: {len(crawl_result.discovered_inputs)}")
        report.append(f"  Forms Found: {stats.get('forms_found', 0)}")
        report.append(f"  AJAX Requests: {stats.get('ajax_requests_intercepted', 0)}")
        report.append("")

        # Discovered technologies
        if crawl_result.discovered_technologies:
            report.append("Technologies Detected:")
            for tech in crawl_result.discovered_technologies:
                report.append(f"  • {tech}")
            report.append("")

        # Endpoints summary
        if crawl_result.discovered_endpoints:
            report.append("Endpoint Summary:")
            endpoint_methods = defaultdict(int)
            for endpoint in crawl_result.discovered_endpoints:
                endpoint_methods[endpoint.method] += 1

            for method, count in sorted(endpoint_methods.items()):
                report.append(f"  {method}: {count} endpoints")
            report.append("")

        # Input parameters summary
        if crawl_result.discovered_inputs:
            report.append("Input Parameters Summary:")
            input_types = defaultdict(int)
            security_relevant = 0

            for input_param in crawl_result.discovered_inputs:
                input_types[input_param.input_type.value] += 1
                if input_param.metadata.get('security_relevant'):
                    security_relevant += 1

            for input_type, count in sorted(input_types.items()):
                report.append(f"  {input_type}: {count}")

            report.append(f"  Security-relevant: {security_relevant}")
            report.append("")

        # Sample endpoints
        if crawl_result.discovered_endpoints:
            report.append("Sample Discovered Endpoints:")
            for endpoint in crawl_result.discovered_endpoints[:10]:
                report.append(f"  {endpoint.method} {endpoint.url}")
                if endpoint.parameters:
                    params = ", ".join([p.name for p in endpoint.parameters[:3]])
                    report.append(f"    Parameters: {params}")
            report.append("")

        return "\n".join(report)