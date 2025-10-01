"""
Layer 5: Dynamic Application Testing (DAST++)
=============================================

Advanced dynamic application security testing capabilities:
- Intelligent web application crawling and discovery
- AI-driven vulnerability testing and exploitation
- Advanced authentication handling and session management
- API security testing with intelligent input generation
- Real-time vulnerability validation and confirmation
- Integration with WAF bypass techniques and evasion methods
"""

from .web_crawler import IntelligentWebCrawler
from .vulnerability_scanner import AdvancedVulnerabilityScanner
from .api_tester import APISecurityTester
from .auth_handler import AuthenticationHandler

__all__ = [
    'IntelligentWebCrawler',
    'AdvancedVulnerabilityScanner',
    'APISecurityTester',
    'AuthenticationHandler'
]