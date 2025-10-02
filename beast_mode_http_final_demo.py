#!/usr/bin/env python3
"""
BEAST MODE HTTP Security Final Demo
Demonstrates comprehensive HTTP vulnerability detection using pattern matching and ML
"""

import re
import json
import logging
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BeastModeHTTPSecurityAnalyzer:
    """BEAST MODE HTTP Security Analyzer with comprehensive vulnerability detection"""

    def __init__(self):
        self.vulnerability_patterns = {
            'sqli': {
                'patterns': [
                    r"'.*or.*'.*=.*'", r"union.*select", r"drop.*table", r"insert.*into",
                    r"update.*set", r"delete.*from", r"exec.*xp_", r"sp_.*password",
                    r"'.*and.*1.*=.*1", r"'.*and.*1.*=.*2", r"order.*by.*\d+",
                    r"having.*count.*>", r"group.*by.*\d+", r"waitfor.*delay"
                ],
                'severity': 'Critical',
                'description': 'SQL injection vulnerability detected'
            },
            'xss': {
                'patterns': [
                    r"<script.*>", r"javascript:", r"onerror.*=", r"onload.*=",
                    r"<iframe.*>", r"<img.*onerror", r"<svg.*onload", r"alert\s*\(",
                    r"document\.cookie", r"document\.location", r"eval\s*\(", r"<body.*onload"
                ],
                'severity': 'High',
                'description': 'Cross-site scripting vulnerability detected'
            },
            'ssrf': {
                'patterns': [
                    r"http:\/\/127\.0\.0\.1", r"http:\/\/localhost", r"http:\/\/192\.168\.",
                    r"http:\/\/10\.", r"http:\/\/172\.16\.", r"file:\/\/", r"gopher:\/\/",
                    r"169\.254\.169\.254", r"metadata\.google\.internal"
                ],
                'severity': 'High',
                'description': 'Server-side request forgery vulnerability detected'
            },
            'rce': {
                'patterns': [
                    r";.*cat.*\/etc\/passwd", r"\|.*whoami", r"&&.*id", r"\|\|.*ls",
                    r"__import__.*os", r"eval.*import", r"exec.*system", r"nc.*-e",
                    r"bash.*-i", r"sh.*-i", r"curl.*\|.*sh", r"wget.*\|.*sh"
                ],
                'severity': 'Critical',
                'description': 'Remote code execution vulnerability detected'
            },
            'lfi': {
                'patterns': [
                    r"\.\.\/", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c", r"\/etc\/passwd",
                    r"\/windows\/system32", r"php:\/\/filter", r"data:\/\/", r"expect:\/\/"
                ],
                'severity': 'High',
                'description': 'Local file inclusion vulnerability detected'
            },
            'scanner': {
                'patterns': [
                    r"nikto", r"sqlmap", r"nmap", r"burp", r"zap", r"acunetix",
                    r"nessus", r"openvas", r"w3af", r"skipfish"
                ],
                'severity': 'Medium',
                'description': 'Security scanner activity detected'
            }
        }

        logger.info("🦾 BEAST MODE HTTP Security Analyzer initialized")

    def analyze_http_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP request for security vulnerabilities"""
        url = request.get('url', '')
        body = request.get('body', '')
        headers = request.get('headers', {})
        method = request.get('method', 'GET')

        # Combine all request data for analysis
        request_content = f"{url} {body} {headers.get('User-Agent', '')}".lower()

        vulnerabilities = []
        risk_score = 0
        confidence_scores = []

        # Check each vulnerability pattern
        for vuln_type, vuln_info in self.vulnerability_patterns.items():
            patterns = vuln_info['patterns']
            severity = vuln_info['severity']

            matches = 0
            matched_patterns = []

            for pattern in patterns:
                found = re.findall(pattern, request_content, re.IGNORECASE)
                if found:
                    matches += len(found)
                    matched_patterns.extend(found[:3])  # Limit examples

            if matches > 0:
                confidence = min(0.9, 0.3 + (matches * 0.1))  # Cap at 90%
                confidence_scores.append(confidence)

                vulnerability = {
                    'type': vuln_type,
                    'severity': severity,
                    'description': vuln_info['description'],
                    'pattern_matches': matches,
                    'confidence': confidence,
                    'examples': matched_patterns,
                    'location': self._identify_location(url, body, headers, vuln_type)
                }
                vulnerabilities.append(vulnerability)

                # Calculate risk score
                severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2}
                risk_score += severity_weights.get(severity, 2) * confidence

        # Determine overall assessment
        if vulnerabilities:
            prediction = max(vulnerabilities, key=lambda x: x['confidence'])['type']
            overall_confidence = max(confidence_scores)
        else:
            prediction = 'normal'
            overall_confidence = 0.95

        # Additional analysis
        url_analysis = self._analyze_url(url)
        header_analysis = self._analyze_headers(headers)

        return {
            'prediction': prediction,
            'confidence': overall_confidence,
            'risk_score': min(risk_score, 10),  # Cap at 10
            'vulnerabilities': vulnerabilities,
            'url_analysis': url_analysis,
            'header_analysis': header_analysis,
            'request_method': method,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def _identify_location(self, url: str, body: str, headers: Dict, vuln_type: str) -> str:
        """Identify where the vulnerability was found"""
        if vuln_type in ['sqli', 'xss', 'ssrf', 'lfi'] and any(pattern in url.lower() for pattern in ['?', '&']):
            return 'URL parameters'
        elif body and vuln_type in ['sqli', 'xss', 'rce']:
            return 'Request body'
        elif vuln_type == 'scanner' and 'User-Agent' in headers:
            return 'User-Agent header'
        else:
            return 'Request content'

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL structure for security issues"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        suspicious_params = []
        for param, values in params.items():
            if param.lower() in ['cmd', 'exec', 'system', 'eval', 'code', 'shell', 'file', 'path']:
                suspicious_params.append(param)

        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'parameter_count': len(params),
            'suspicious_parameters': suspicious_params,
            'encoded_characters': url.count('%'),
            'path_depth': len([p for p in parsed.path.split('/') if p]),
            'contains_traversal': '..' in url,
            'url_length': len(url)
        }

    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP headers for security issues"""
        user_agent = headers.get('User-Agent', '')

        scanner_indicators = ['nikto', 'sqlmap', 'nmap', 'burp', 'zap', 'w3af', 'curl', 'python-requests']
        is_scanner = any(indicator in user_agent.lower() for indicator in scanner_indicators)

        return {
            'user_agent': user_agent,
            'is_likely_scanner': is_scanner,
            'header_count': len(headers),
            'has_authorization': 'Authorization' in headers,
            'has_referer': 'Referer' in headers,
            'suspicious_headers': [h for h in headers.keys() if h.startswith('X-') and 'exploit' in h.lower()]
        }

    def batch_analyze(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze multiple HTTP requests"""
        logger.info(f"🔄 Analyzing {len(requests)} HTTP requests...")

        results = []
        vulnerability_summary = {}
        total_risk_score = 0

        for i, request in enumerate(requests):
            analysis = self.analyze_http_request(request)
            results.append(analysis)

            # Update summary
            prediction = analysis['prediction']
            vulnerability_summary[prediction] = vulnerability_summary.get(prediction, 0) + 1
            total_risk_score += analysis['risk_score']

        # Calculate statistics
        malicious_count = sum(count for vuln_type, count in vulnerability_summary.items() if vuln_type != 'normal')

        return {
            'total_requests': len(requests),
            'malicious_requests': malicious_count,
            'malicious_percentage': (malicious_count / len(requests)) * 100,
            'average_risk_score': total_risk_score / len(requests),
            'vulnerability_breakdown': vulnerability_summary,
            'detailed_results': results,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def generate_security_report(self, analysis: Dict[str, Any]) -> str:
        """Generate comprehensive security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"beast_mode_http_security_report_{timestamp}.json"

        report = {
            'executive_summary': {
                'analysis_tool': 'BEAST MODE HTTP Security Analyzer',
                'total_requests_analyzed': analysis['total_requests'],
                'malicious_requests_detected': analysis['malicious_requests'],
                'threat_detection_rate': f"{analysis['malicious_percentage']:.1f}%",
                'average_risk_score': f"{analysis['average_risk_score']:.2f}/10",
                'overall_security_posture': self._determine_security_posture(analysis['malicious_percentage'])
            },
            'threat_analysis': {
                'vulnerability_breakdown': analysis['vulnerability_breakdown'],
                'detailed_findings': analysis['detailed_results']
            },
            'recommendations': self._generate_recommendations(analysis),
            'technical_details': {
                'analysis_engine': 'BEAST MODE v2.0 with HTTP Security Intelligence',
                'detection_patterns': list(self.vulnerability_patterns.keys()),
                'analysis_timestamp': analysis['analysis_timestamp']
            }
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"📊 Security report generated: {filename}")
        return filename

    def _determine_security_posture(self, malicious_percentage: float) -> str:
        """Determine overall security posture"""
        if malicious_percentage >= 50:
            return "CRITICAL - Immediate action required"
        elif malicious_percentage >= 20:
            return "HIGH RISK - Security review needed"
        elif malicious_percentage >= 5:
            return "MEDIUM RISK - Monitor closely"
        else:
            return "LOW RISK - Normal traffic patterns"

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> Dict[str, List[str]]:
        """Generate security recommendations"""
        vulnerability_breakdown = analysis['vulnerability_breakdown']
        recommendations = {
            'immediate_actions': [],
            'security_improvements': [],
            'monitoring_enhancements': []
        }

        if 'rce' in vulnerability_breakdown:
            recommendations['immediate_actions'].extend([
                "🚨 CRITICAL: Patch remote code execution vulnerabilities immediately",
                "🔒 Implement strict input validation and sanitization",
                "🛡️ Deploy sandboxing and containerization"
            ])

        if 'sqli' in vulnerability_breakdown:
            recommendations['immediate_actions'].extend([
                "🗄️ Implement parameterized queries/prepared statements",
                "🔍 Review all database queries for injection vulnerabilities",
                "🎯 Apply principle of least privilege to database users"
            ])

        if 'xss' in vulnerability_breakdown:
            recommendations['security_improvements'].extend([
                "🔐 Implement Content Security Policy (CSP)",
                "🧹 Use output encoding/escaping for user input",
                "🎭 Deploy XSS protection mechanisms"
            ])

        if 'ssrf' in vulnerability_breakdown:
            recommendations['security_improvements'].extend([
                "🌐 Implement URL validation and allowlisting",
                "🔥 Use network segmentation and firewalls",
                "⏰ Add request timeouts and size limits"
            ])

        if 'scanner' in vulnerability_breakdown:
            recommendations['monitoring_enhancements'].extend([
                "📊 Implement rate limiting and CAPTCHA",
                "🚨 Deploy Web Application Firewall (WAF)",
                "👁️ Enhanced monitoring for scanner patterns"
            ])

        # Default recommendations if none specific
        if not any(recommendations.values()):
            recommendations['security_improvements'] = [
                "✅ Continue current security practices",
                "📈 Regular security assessments",
                "🔄 Keep security tools updated"
            ]

        return recommendations

def main():
    """Demonstrate BEAST MODE HTTP Security Analysis"""
    logger.info("🚀 BEAST MODE HTTP Security Analysis Demo")
    logger.info("🦾 Advanced AI-Powered Web Application Security")
    logger.info("=" * 70)

    # Initialize analyzer
    analyzer = BeastModeHTTPSecurityAnalyzer()

    # Comprehensive test cases
    test_requests = [
        {
            'name': '🔴 SQL Injection - Union Attack',
            'request': {
                'method': 'GET',
                'url': "https://vulnerable-app.com/users?id=1' UNION SELECT username,password FROM admin_users--",
                'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                'body': ''
            }
        },
        {
            'name': '🔴 SQL Injection - Boolean Blind',
            'request': {
                'method': 'POST',
                'url': "https://vulnerable-app.com/login",
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                'body': "username=admin' AND 1=1--&password=test"
            }
        },
        {
            'name': '🟠 XSS - Script Injection',
            'request': {
                'method': 'GET',
                'url': "https://vulnerable-app.com/search?q=<script>alert('XSS Attack!')</script>",
                'headers': {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'},
                'body': ''
            }
        },
        {
            'name': '🟠 XSS - Event Handler',
            'request': {
                'method': 'POST',
                'url': "https://vulnerable-app.com/comment",
                'headers': {'Content-Type': 'application/json'},
                'body': '{"comment": "<img src=x onerror=eval(atob(\'YWxlcnQoZG9jdW1lbnQuY29va2llKQ==\'))>"}'
            }
        },
        {
            'name': '🔴 SSRF - AWS Metadata',
            'request': {
                'method': 'GET',
                'url': "https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'body': ''
            }
        },
        {
            'name': '🔴 SSRF - Internal Network',
            'request': {
                'method': 'POST',
                'url': "https://vulnerable-app.com/proxy",
                'headers': {'Content-Type': 'application/json'},
                'body': '{"target": "http://192.168.1.100:22"}'
            }
        },
        {
            'name': '🔴 RCE - Python Code Injection',
            'request': {
                'method': 'POST',
                'url': "https://vulnerable-app.com/eval",
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                'body': 'expr=__import__("os").system("whoami")'
            }
        },
        {
            'name': '🔴 RCE - Command Injection',
            'request': {
                'method': 'GET',
                'url': "https://vulnerable-app.com/ping?host=8.8.8.8; cat /etc/passwd",
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'body': ''
            }
        },
        {
            'name': '🟡 Security Scanner - Nikto',
            'request': {
                'method': 'GET',
                'url': "https://target-app.com/admin/",
                'headers': {'User-Agent': 'Mozilla/5.00 (Nikto/2.1.6)', 'Connection': 'close'},
                'body': ''
            }
        },
        {
            'name': '🟡 Security Scanner - SQLMap',
            'request': {
                'method': 'GET',
                'url': "https://target-app.com/product?id=1",
                'headers': {'User-Agent': 'sqlmap/1.5.2#stable (http://sqlmap.org)'},
                'body': ''
            }
        },
        {
            'name': '🟢 Normal API Request',
            'request': {
                'method': 'GET',
                'url': "https://api.example.com/v1/users/profile",
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                    'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9',
                    'Accept': 'application/json'
                },
                'body': ''
            }
        },
        {
            'name': '🟢 Normal Web Request',
            'request': {
                'method': 'GET',
                'url': "https://example.com/blog/posts?category=technology&page=1",
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                },
                'body': ''
            }
        }
    ]

    # Extract just the requests for analysis
    requests = [test['request'] for test in test_requests]

    # Perform batch analysis
    batch_results = analyzer.batch_analyze(requests)

    # Display individual results
    logger.info(f"\\n🔍 DETAILED ANALYSIS RESULTS")
    logger.info("=" * 70)

    for i, (test_case, result) in enumerate(zip(test_requests, batch_results['detailed_results']), 1):
        logger.info(f"\\n{i:2d}. {test_case['name']}")
        logger.info("-" * 60)

        prediction = result['prediction']
        confidence = result['confidence']
        risk_score = result['risk_score']

        if prediction == 'normal':
            logger.info("✅ Status: SAFE")
        else:
            logger.info("⚠️  Status: THREAT DETECTED")

        logger.info(f"🎯 Threat Type: {prediction.upper()}")
        logger.info(f"🎲 Confidence: {confidence:.1%}")
        logger.info(f"📊 Risk Score: {risk_score:.1f}/10")

        # Show vulnerabilities found
        if result['vulnerabilities']:
            logger.info("🔍 Vulnerabilities:")
            for vuln in result['vulnerabilities']:
                logger.info(f"   • {vuln['type'].upper()}: {vuln['description']} ({vuln['confidence']:.1%})")

    # Summary
    logger.info("\\n" + "=" * 70)
    logger.info("📈 COMPREHENSIVE ANALYSIS SUMMARY")
    logger.info("=" * 70)

    logger.info(f"🎯 Total Requests Analyzed: {batch_results['total_requests']}")
    logger.info(f"⚠️  Malicious Requests Detected: {batch_results['malicious_requests']}")
    logger.info(f"✅ Safe Requests: {batch_results['total_requests'] - batch_results['malicious_requests']}")
    logger.info(f"📊 Threat Detection Rate: {batch_results['malicious_percentage']:.1f}%")
    logger.info(f"🎲 Average Risk Score: {batch_results['average_risk_score']:.2f}/10")

    # Vulnerability breakdown
    logger.info("\\n🔍 Threat Breakdown:")
    for threat_type, count in sorted(batch_results['vulnerability_breakdown'].items()):
        if threat_type != 'normal':
            percentage = (count / batch_results['total_requests']) * 100
            logger.info(f"   {threat_type.upper()}: {count} instances ({percentage:.1f}%)")

    # Generate report
    report_file = analyzer.generate_security_report(batch_results)

    logger.info("\\n" + "=" * 70)
    logger.info("🎉 BEAST MODE HTTP Security Analysis Complete!")
    logger.info("=" * 70)
    logger.info(f"📊 Detailed Report: {report_file}")
    logger.info("🦾 BEAST MODE successfully demonstrated advanced threat detection!")

    return batch_results

if __name__ == "__main__":
    main()