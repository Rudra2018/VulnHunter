#!/usr/bin/env python3
"""
Advanced IPA Security Analyzer
Comprehensive deep-dive security analysis with OWASP Mobile Top 10, SDK detection,
network security, privacy analysis, and vulnerability scanning
"""

import os
import sys
import hashlib
import zipfile
import tempfile
import json
import plistlib
import subprocess
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
import shutil

sys.path.insert(0, os.path.expanduser("~/vuln_ml_research"))
sys.path.insert(0, os.path.expanduser("~/Documents"))


class AdvancedIPAAnalyzer:
    """Advanced security analysis for iOS applications"""

    def __init__(self, ipa_path: str):
        self.ipa_path = ipa_path
        self.temp_dir = None
        self.app_bundle_path = None
        self.executable_path = None

        self.results = {
            'basic_info': {},
            'metadata': {},
            'binary_deep_analysis': {},
            'security_features': {},
            'code_signing': {},
            'permissions_privacy': {},
            'network_security': {},
            'strings_advanced': {},
            'sdk_detection': {},
            'owasp_mobile_top10': {},
            'vulnerability_scan': {},
            'data_storage': {},
            'cryptography': {},
            'anti_tampering': {},
            'resources': {},
            'compliance': {},
            'risk_assessment': {}
        }

    # ... (keeping previous basic methods like compute_hashes, extract_ipa, etc.)

    def compute_hashes(self) -> Dict[str, str]:
        """Compute multiple hashes"""
        print("📊 Computing cryptographic hashes...")
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()

        with open(self.ipa_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {'sha256': sha256.hexdigest(), 'sha1': sha1.hexdigest(), 'md5': md5.hexdigest()}

    def extract_ipa(self):
        """Extract IPA archive"""
        print("📦 Extracting IPA archive...")
        self.temp_dir = tempfile.mkdtemp(prefix='ipa_analysis_')

        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)

            payload_dir = os.path.join(self.temp_dir, 'Payload')
            if os.path.exists(payload_dir):
                app_bundles = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
                if app_bundles:
                    self.app_bundle_path = os.path.join(payload_dir, app_bundles[0])
                    print(f"✅ Found app bundle: {app_bundles[0]}")
                    return True
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False

    def parse_info_plist(self) -> Dict[str, Any]:
        """Enhanced Info.plist parsing"""
        print("📄 Parsing Info.plist with privacy analysis...")

        info = {
            'found': False,
            'bundle_id': None,
            'version': None,
            'build': None,
            'name': None,
            'min_os': None,
            'permissions': [],
            'url_schemes': [],
            'background_modes': [],
            'ats_config': {},
            'queries_schemes': [],
            'raw_data': {}
        }

        if not self.app_bundle_path:
            return info

        info_plist_path = os.path.join(self.app_bundle_path, 'Info.plist')

        if os.path.exists(info_plist_path):
            try:
                with open(info_plist_path, 'rb') as f:
                    plist_data = plistlib.load(f)

                info['found'] = True
                info['bundle_id'] = plist_data.get('CFBundleIdentifier', 'Unknown')
                info['version'] = plist_data.get('CFBundleShortVersionString', 'Unknown')
                info['build'] = plist_data.get('CFBundleVersion', 'Unknown')
                info['name'] = plist_data.get('CFBundleDisplayName') or plist_data.get('CFBundleName', 'Unknown')
                info['min_os'] = plist_data.get('MinimumOSVersion', 'Unknown')

                # Extract all permissions
                permission_keys = [k for k in plist_data.keys() if 'UsageDescription' in k]
                info['permissions'] = [
                    {
                        'key': k,
                        'description': plist_data[k],
                        'type': k.replace('UsageDescription', '').replace('NS', ''),
                        'category': self._categorize_permission(k)
                    }
                    for k in permission_keys
                ]

                # URL schemes
                if 'CFBundleURLTypes' in plist_data:
                    for url_type in plist_data['CFBundleURLTypes']:
                        schemes = url_type.get('CFBundleURLSchemes', [])
                        info['url_schemes'].extend(schemes)

                # Background modes
                info['background_modes'] = plist_data.get('UIBackgroundModes', [])

                # App Transport Security
                info['ats_config'] = plist_data.get('NSAppTransportSecurity', {})

                # Queries schemes
                info['queries_schemes'] = plist_data.get('LSApplicationQueriesSchemes', [])

                # Store full plist for deep analysis
                info['raw_data'] = {
                    'executable': plist_data.get('CFBundleExecutable'),
                    'package_type': plist_data.get('CFBundlePackageType'),
                    'platform': plist_data.get('CFBundleSupportedPlatforms', []),
                    'device_family': plist_data.get('UIDeviceFamily', []),
                    'supported_orientations': plist_data.get('UISupportedInterfaceOrientations', [])
                }

                print(f"✅ App: {info['name']} v{info['version']} ({info['bundle_id']})")

            except Exception as e:
                print(f"❌ Error parsing Info.plist: {e}")
                info['error'] = str(e)

        return info

    def _categorize_permission(self, permission_key: str) -> str:
        """Categorize permission by sensitivity"""
        high_risk = ['Location', 'Camera', 'Microphone', 'Contacts', 'Photos', 'HealthShare', 'HealthUpdate']
        medium_risk = ['Calendars', 'Reminders', 'Motion', 'MediaLibrary']

        for keyword in high_risk:
            if keyword in permission_key:
                return 'HIGH_RISK'
        for keyword in medium_risk:
            if keyword in permission_key:
                return 'MEDIUM_RISK'
        return 'LOW_RISK'

    def find_executable(self) -> Optional[str]:
        """Find main executable"""
        if not self.app_bundle_path:
            return None

        info_plist = self.results.get('metadata', {})
        if info_plist.get('raw_data', {}).get('executable'):
            exec_name = info_plist['raw_data']['executable']
            exec_path = os.path.join(self.app_bundle_path, exec_name)
            if os.path.exists(exec_path):
                self.executable_path = exec_path
                return exec_path

        app_name = os.path.basename(self.app_bundle_path).replace('.app', '')
        exec_path = os.path.join(self.app_bundle_path, app_name)
        if os.path.exists(exec_path):
            self.executable_path = exec_path
            return exec_path

        return None

    def deep_binary_analysis(self) -> Dict[str, Any]:
        """Comprehensive binary analysis"""
        print("🔬 Performing deep binary analysis...")

        analysis = {
            'found': False,
            'path': None,
            'size': 0,
            'type': None,
            'architectures': [],
            'load_commands': {},
            'segments': [],
            'sections': [],
            'libraries': [],
            'frameworks': [],
            'symbols': {},
            'imports': [],
            'exports': [],
            'objc_classes': [],
            'swift_symbols': [],
            'security_checks': {}
        }

        exec_path = self.find_executable()
        if not exec_path or not os.path.exists(exec_path):
            return analysis

        analysis['found'] = True
        analysis['path'] = exec_path
        analysis['size'] = os.path.getsize(exec_path)

        try:
            # Get file type
            result = subprocess.run(['file', exec_path], capture_output=True, text=True)
            analysis['type'] = result.stdout.strip()

            # Architectures
            result = subprocess.run(['lipo', '-info', exec_path], capture_output=True, text=True)
            if result.returncode == 0:
                arch_match = re.search(r'Architectures in the fat file.*?are:\s*(.+)', result.stdout)
                if arch_match:
                    analysis['architectures'] = arch_match.group(1).split()
                elif 'Non-fat file' in result.stdout:
                    arch_match = re.search(r'is architecture:\s*(\w+)', result.stdout)
                    if arch_match:
                        analysis['architectures'] = [arch_match.group(1)]

            # Detailed load commands analysis
            result = subprocess.run(['otool', '-l', exec_path], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                output = result.stdout

                # Count load commands
                load_commands = re.findall(r'Load command \d+\s+cmd\s+(\w+)', output)
                analysis['load_commands'] = dict(zip(*np.unique(load_commands, return_counts=True))) if load_commands else {}

                # Extract segments
                segments = re.findall(r'segname\s+(\w+)', output)
                analysis['segments'] = list(set(segments))

                # Extract sections
                sections = re.findall(r'sectname\s+(\w+)', output)
                analysis['sections'] = list(set(sections))

                # Libraries
                libs = re.findall(r'name\s+(.+\.dylib)', output)
                analysis['libraries'] = list(set(libs))

                # Frameworks
                frameworks = re.findall(r'name\s+(.+\.framework)', output)
                analysis['frameworks'] = list(set(frameworks))

            # Symbol analysis
            result = subprocess.run(['nm', '-g', exec_path], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                symbols = result.stdout.split('\n')

                # Categorize symbols
                analysis['symbols'] = {
                    'total': len(symbols),
                    'imported': len([s for s in symbols if ' U ' in s]),
                    'exported': len([s for s in symbols if (' T ' in s or ' S ' in s)]),
                    'weak': len([s for s in symbols if ' W ' in s])
                }

                # Extract specific imports
                imports = [s.split()[-1] for s in symbols if ' U ' in s]
                analysis['imports'] = imports[:100]  # Top 100

                # Detect Objective-C classes
                objc_classes = [s for s in imports if s.startswith('_OBJC_CLASS_$_')]
                analysis['objc_classes'] = [c.replace('_OBJC_CLASS_$_', '') for c in objc_classes[:50]]

                # Detect Swift symbols
                swift_symbols = [s for s in imports if '_swift' in s.lower() or s.startswith('_$s')]
                analysis['swift_symbols'] = swift_symbols[:50]

            # Advanced security checks
            analysis['security_checks'] = self._advanced_security_checks(exec_path)

            print(f"✅ Deep binary analysis complete")

        except Exception as e:
            print(f"⚠️ Error in deep analysis: {e}")
            analysis['error'] = str(e)

        return analysis

    def _advanced_security_checks(self, exec_path: str) -> Dict[str, Any]:
        """Advanced security feature detection"""
        checks = {
            'pie': False,
            'stack_canary': False,
            'arc': False,
            'encrypted': False,
            'code_signature': False,
            'bitcode': False,
            'objc_arc': False,
            'swift_compiled': False,
            'fortify_source': False,
            'rpath': [],
            'rpaths_count': 0
        }

        try:
            # Check PIE
            result = subprocess.run(['otool', '-hv', exec_path], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                checks['pie'] = 'PIE' in result.stdout

            # Check for various symbols
            result = subprocess.run(['nm', exec_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                checks['stack_canary'] = '___stack_chk_guard' in output or '___stack_chk_fail' in output
                checks['arc'] = '_objc_release' in output or '_objc_retain' in output
                checks['objc_arc'] = '_objc_autoreleasePoolPush' in output
                checks['swift_compiled'] = '_swift_' in output
                checks['fortify_source'] = '__chk' in output

            # Check encryption and load commands
            result = subprocess.run(['otool', '-l', exec_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                checks['encrypted'] = 'cryptid 1' in output
                checks['code_signature'] = 'LC_CODE_SIGNATURE' in output
                checks['bitcode'] = 'LC_BITCODE' in output or '__LLVM' in output

                # Extract RPATHs
                rpaths = re.findall(r'path\s+([^\s]+)\s+\(offset', output)
                checks['rpath'] = list(set(rpaths))
                checks['rpaths_count'] = len(rpaths)

        except Exception as e:
            checks['error'] = str(e)

        return checks

    def analyze_network_security(self) -> Dict[str, Any]:
        """Analyze network security configuration"""
        print("🌐 Analyzing network security configuration...")

        analysis = {
            'ats_enabled': True,
            'ats_config': {},
            'allows_arbitrary_loads': False,
            'exception_domains': [],
            'insecure_domains': [],
            'certificate_pinning': False,
            'cleartext_traffic': [],
            'ssl_pinning_detected': False,
            'network_urls': [],
            'api_endpoints': []
        }

        # ATS configuration from Info.plist
        metadata = self.results.get('metadata', {})
        ats_config = metadata.get('ats_config', {})

        if ats_config:
            analysis['ats_config'] = ats_config
            analysis['allows_arbitrary_loads'] = ats_config.get('NSAllowsArbitraryLoads', False)

            # Exception domains
            exception_domains = ats_config.get('NSExceptionDomains', {})
            analysis['exception_domains'] = list(exception_domains.keys())

            # Check for insecure configurations
            for domain, config in exception_domains.items():
                if config.get('NSExceptionAllowsInsecureHTTPLoads') or config.get('NSIncludesSubdomains'):
                    analysis['insecure_domains'].append({
                        'domain': domain,
                        'allows_http': config.get('NSExceptionAllowsInsecureHTTPLoads', False),
                        'includes_subdomains': config.get('NSIncludesSubdomains', False)
                    })

        # Detect certificate pinning from binary
        if self.executable_path:
            try:
                result = subprocess.run(['strings', self.executable_path], capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    strings_lower = result.stdout.lower()

                    # Certificate pinning indicators
                    pinning_indicators = ['trustkit', 'pinning', 'certificate', 'publickey', 'spki']
                    analysis['ssl_pinning_detected'] = any(indicator in strings_lower for indicator in pinning_indicators)

                    # Extract URLs
                    urls = re.findall(r'https?://[^\s<>"]+', result.stdout)
                    analysis['network_urls'] = list(set(urls))[:100]

                    # Identify API endpoints
                    api_patterns = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']
                    analysis['api_endpoints'] = [url for url in urls if any(pattern in url for pattern in api_patterns)][:50]

                    # HTTP (cleartext) traffic
                    http_urls = [url for url in urls if url.startswith('http://')]
                    analysis['cleartext_traffic'] = http_urls[:50]

            except Exception as e:
                analysis['error'] = str(e)

        print(f"✅ Network security analysis complete")
        return analysis

    def detect_third_party_sdks(self) -> Dict[str, Any]:
        """Detect common third-party SDKs"""
        print("🔌 Detecting third-party SDKs and libraries...")

        detection = {
            'analytics': [],
            'crash_reporting': [],
            'advertising': [],
            'social': [],
            'payment': [],
            'security': [],
            'other': [],
            'total_detected': 0
        }

        sdk_signatures = {
            'analytics': [
                ('Google Analytics', ['GoogleAnalytics', 'GAI', '_gaq']),
                ('Firebase Analytics', ['Firebase', 'FIRAnalytics', 'FirebaseCore']),
                ('Mixpanel', ['Mixpanel', 'MPTrack']),
                ('Amplitude', ['Amplitude', 'AMPTrack']),
                ('Segment', ['Segment', 'SEGAnalytics'])
            ],
            'crash_reporting': [
                ('Crashlytics', ['Crashlytics', 'CLSReport']),
                ('Sentry', ['Sentry', 'SentryClient']),
                ('Bugsnag', ['Bugsnag', 'BSG']),
                ('Instabug', ['Instabug', 'IBG'])
            ],
            'advertising': [
                ('AdMob', ['AdMob', 'GADRequest']),
                ('Facebook Ads', ['FBAd', 'FBAdView']),
                ('MoPub', ['MoPub', 'MPAdView']),
                ('AppLovin', ['AppLovin', 'ALSdk'])
            ],
            'social': [
                ('Facebook SDK', ['Facebook', 'FBSDKLogin', 'FBSDKCoreKit']),
                ('Twitter', ['Twitter', 'TWTRKit']),
                ('LinkedIn', ['LinkedIn', 'LI']),
                ('Instagram', ['Instagram', 'IGListKit'])
            ],
            'payment': [
                ('Stripe', ['Stripe', 'STP']),
                ('PayPal', ['PayPal', 'PPOTCore']),
                ('Braintree', ['Braintree', 'BTPayment']),
                ('Square', ['Square', 'SQIPCore'])
            ],
            'security': [
                ('TrustKit', ['TrustKit', 'TSKPinning']),
                ('SSL Kill Switch', ['SSLKillSwitch']),
                ('RevealView', ['RevealServer'])
            ]
        }

        if not self.executable_path:
            return detection

        try:
            # Get all strings from binary
            result = subprocess.run(['strings', self.executable_path], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                binary_content = result.stdout

                # Check for SDK signatures
                for category, sdks in sdk_signatures.items():
                    for sdk_name, signatures in sdks:
                        if any(sig in binary_content for sig in signatures):
                            detection[category].append({
                                'name': sdk_name,
                                'signatures_found': [sig for sig in signatures if sig in binary_content]
                            })
                            detection['total_detected'] += 1

            # Also check frameworks
            binary_analysis = self.results.get('binary_deep_analysis', {})
            frameworks = binary_analysis.get('frameworks', [])

            # Additional SDK detection from frameworks
            for framework in frameworks:
                framework_lower = framework.lower()
                if 'firebase' in framework_lower and not any(sdk['name'] == 'Firebase Analytics' for sdk in detection['analytics']):
                    detection['analytics'].append({'name': 'Firebase (from framework)', 'signatures_found': [framework]})
                    detection['total_detected'] += 1
                elif 'facebook' in framework_lower and not any(sdk['name'].startswith('Facebook') for sdk in detection['social']):
                    detection['social'].append({'name': 'Facebook SDK (from framework)', 'signatures_found': [framework]})
                    detection['total_detected'] += 1

        except Exception as e:
            detection['error'] = str(e)

        print(f"✅ Detected {detection['total_detected']} third-party SDKs")
        return detection

    def owasp_mobile_top10_analysis(self) -> Dict[str, Any]:
        """OWASP Mobile Top 10 (2024) security checks"""
        print("🛡️  Performing OWASP Mobile Top 10 analysis...")

        owasp = {
            'M1_improper_credential_usage': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M2_inadequate_supply_chain_security': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M3_insecure_authentication': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M4_insufficient_input_validation': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M5_insecure_communication': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M6_inadequate_privacy_controls': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M7_insufficient_binary_protections': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M8_security_misconfiguration': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M9_insecure_data_storage': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'M10_insufficient_cryptography': {'score': 0, 'findings': [], 'severity': 'UNKNOWN'},
            'overall_score': 0
        }

        # M1: Improper Credential Usage
        strings_analysis = self.results.get('strings_advanced', {})
        if strings_analysis.get('potential_credentials'):
            owasp['M1_improper_credential_usage']['findings'].append("Potential hardcoded credentials detected")
            owasp['M1_improper_credential_usage']['score'] = 70
            owasp['M1_improper_credential_usage']['severity'] = 'HIGH'
        else:
            owasp['M1_improper_credential_usage']['score'] = 20
            owasp['M1_improper_credential_usage']['severity'] = 'LOW'

        # M2: Inadequate Supply Chain Security
        sdk_detection = self.results.get('sdk_detection', {})
        if sdk_detection.get('total_detected', 0) > 10:
            owasp['M2_inadequate_supply_chain_security']['findings'].append(f"Large number of third-party SDKs: {sdk_detection['total_detected']}")
            owasp['M2_inadequate_supply_chain_security']['score'] = 50
            owasp['M2_inadequate_supply_chain_security']['severity'] = 'MEDIUM'
        else:
            owasp['M2_inadequate_supply_chain_security']['score'] = 20
            owasp['M2_inadequate_supply_chain_security']['severity'] = 'LOW'

        # M5: Insecure Communication
        network = self.results.get('network_security', {})
        if network.get('allows_arbitrary_loads') or network.get('cleartext_traffic'):
            owasp['M5_insecure_communication']['findings'].append("Insecure HTTP communication detected")
            owasp['M5_insecure_communication']['score'] = 80
            owasp['M5_insecure_communication']['severity'] = 'CRITICAL'
        elif not network.get('ssl_pinning_detected'):
            owasp['M5_insecure_communication']['findings'].append("SSL pinning not detected")
            owasp['M5_insecure_communication']['score'] = 40
            owasp['M5_insecure_communication']['severity'] = 'MEDIUM'
        else:
            owasp['M5_insecure_communication']['score'] = 10
            owasp['M5_insecure_communication']['severity'] = 'LOW'

        # M6: Inadequate Privacy Controls
        metadata = self.results.get('metadata', {})
        high_risk_perms = [p for p in metadata.get('permissions', []) if p.get('category') == 'HIGH_RISK']
        if len(high_risk_perms) > 5:
            owasp['M6_inadequate_privacy_controls']['findings'].append(f"Requests {len(high_risk_perms)} high-risk permissions")
            owasp['M6_inadequate_privacy_controls']['score'] = 60
            owasp['M6_inadequate_privacy_controls']['severity'] = 'HIGH'
        else:
            owasp['M6_inadequate_privacy_controls']['score'] = 20
            owasp['M6_inadequate_privacy_controls']['severity'] = 'LOW'

        # M7: Insufficient Binary Protections
        binary_analysis = self.results.get('binary_deep_analysis', {})
        security_checks = binary_analysis.get('security_checks', {})
        missing_features = []

        if not security_checks.get('pie'):
            missing_features.append("PIE")
        if not security_checks.get('stack_canary'):
            missing_features.append("Stack Canary")
        if not security_checks.get('arc'):
            missing_features.append("ARC")

        if missing_features:
            owasp['M7_insufficient_binary_protections']['findings'].append(f"Missing security features: {', '.join(missing_features)}")
            owasp['M7_insufficient_binary_protections']['score'] = 70
            owasp['M7_insufficient_binary_protections']['severity'] = 'HIGH'
        else:
            owasp['M7_insufficient_binary_protections']['score'] = 10
            owasp['M7_insufficient_binary_protections']['severity'] = 'LOW'

        # M10: Insufficient Cryptography
        crypto_analysis = self.results.get('cryptography', {})
        if crypto_analysis.get('weak_crypto_detected'):
            owasp['M10_insufficient_cryptography']['findings'].append("Weak cryptographic algorithms detected")
            owasp['M10_insufficient_cryptography']['score'] = 75
            owasp['M10_insufficient_cryptography']['severity'] = 'HIGH'
        else:
            owasp['M10_insufficient_cryptography']['score'] = 20
            owasp['M10_insufficient_cryptography']['severity'] = 'LOW'

        # Calculate overall score
        scores = [v['score'] for v in owasp.values() if isinstance(v, dict) and 'score' in v]
        owasp['overall_score'] = sum(scores) / len(scores) if scores else 0

        print(f"✅ OWASP analysis complete - Overall risk score: {owasp['overall_score']:.1f}/100")
        return owasp

    def advanced_strings_analysis(self) -> Dict[str, Any]:
        """Advanced strings extraction and analysis"""
        print("🔤 Performing advanced strings analysis...")

        analysis = {
            'total': 0,
            'urls': [],
            'api_endpoints': [],
            'domains': [],
            'emails': [],
            'ips': [],
            'file_paths': [],
            'potential_keys': [],
            'potential_credentials': [],
            'crypto_strings': [],
            'debugging_strings': [],
            'error_messages': [],
            'database_queries': [],
            'suspicious_functions': []
        }

        if not self.executable_path:
            return analysis

        try:
            result = subprocess.run(['strings', '-n', '8', self.executable_path],
                                  capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                strings_list = result.stdout.split('\n')
                analysis['total'] = len(strings_list)

                # Patterns
                url_pattern = re.compile(r'https?://[^\s<>"\']+')
                domain_pattern = re.compile(r'([a-z0-9-]+\.)+[a-z]{2,}')
                email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
                ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                path_pattern = re.compile(r'/[a-zA-Z0-9_/.-]+')

                # Key/secret patterns
                key_patterns = [
                    (r'(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?', 'API Key'),
                    (r'(secret|password|pwd|pass)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?', 'Secret/Password'),
                    (r'(token|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?', 'Token'),
                    (r'(aws[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*["\']?([A-Z0-9]{20,})["\']?', 'AWS Key'),
                    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private Key')
                ]

                # Crypto strings
                crypto_keywords = ['AES', 'DES', 'RSA', 'SHA', 'MD5', 'encrypt', 'decrypt', 'cipher', 'crypto']

                # Suspicious functions
                suspicious_funcs = ['system', 'popen', 'exec', 'eval', 'dlopen', 'NSTask', 'Runtime.getRuntime']

                # Database patterns
                db_patterns = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE TABLE', 'DROP TABLE']

                for s in strings_list[:50000]:  # Limit to first 50k strings
                    s = s.strip()
                    if len(s) < 8:
                        continue

                    # URLs
                    if url_pattern.search(s):
                        if len(analysis['urls']) < 100:
                            analysis['urls'].append(s[:300])
                        if '/api/' in s or '/v1/' in s or '/v2/' in s:
                            if len(analysis['api_endpoints']) < 50:
                                analysis['api_endpoints'].append(s[:200])

                    # Emails
                    if email_pattern.search(s):
                        if len(analysis['emails']) < 50:
                            analysis['emails'].append(s)

                    # IPs
                    if ip_pattern.search(s):
                        if len(analysis['ips']) < 50:
                            analysis['ips'].append(s)

                    # Domains
                    if domain_pattern.search(s) and 'http' not in s:
                        if len(analysis['domains']) < 100:
                            analysis['domains'].append(s[:100])

                    # File paths
                    if path_pattern.match(s):
                        if len(analysis['file_paths']) < 50:
                            analysis['file_paths'].append(s[:200])

                    # Check for keys/credentials
                    for pattern, key_type in key_patterns:
                        if re.search(pattern, s, re.IGNORECASE):
                            if len(analysis['potential_credentials']) < 30:
                                analysis['potential_credentials'].append({
                                    'type': key_type,
                                    'string': s[:150]
                                })

                    # Crypto strings
                    if any(keyword.lower() in s.lower() for keyword in crypto_keywords):
                        if len(analysis['crypto_strings']) < 50:
                            analysis['crypto_strings'].append(s[:100])

                    # Suspicious functions
                    if any(func in s for func in suspicious_funcs):
                        if len(analysis['suspicious_functions']) < 50:
                            analysis['suspicious_functions'].append(s[:100])

                    # Database queries
                    if any(pattern in s.upper() for pattern in db_patterns):
                        if len(analysis['database_queries']) < 30:
                            analysis['database_queries'].append(s[:200])

                    # Debugging strings
                    if any(keyword in s.lower() for keyword in ['debug', 'test', 'development', 'staging']):
                        if len(analysis['debugging_strings']) < 50:
                            analysis['debugging_strings'].append(s[:100])

                    # Error messages
                    if 'error' in s.lower() or 'exception' in s.lower() or 'failed' in s.lower():
                        if len(analysis['error_messages']) < 50:
                            analysis['error_messages'].append(s[:150])

                print(f"✅ Analyzed {analysis['total']} strings")
                print(f"   Found: {len(analysis['urls'])} URLs, {len(analysis['potential_credentials'])} potential credentials")

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    def analyze_cryptography(self) -> Dict[str, Any]:
        """Analyze cryptographic implementations"""
        print("🔐 Analyzing cryptography usage...")

        analysis = {
            'crypto_libraries': [],
            'weak_crypto_detected': False,
            'weak_algorithms': [],
            'strong_algorithms': [],
            'random_sources': [],
            'key_derivation': [],
            'issues': []
        }

        if not self.executable_path:
            return analysis

        try:
            result = subprocess.run(['strings', self.executable_path],
                                  capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                content = result.stdout.lower()

                # Weak algorithms (should NOT be used)
                weak = {
                    'md5': 'MD5 hash (broken)',
                    'sha1': 'SHA1 hash (deprecated)',
                    'des': 'DES encryption (insecure)',
                    'rc4': 'RC4 cipher (broken)'
                }

                for algo, desc in weak.items():
                    if algo in content:
                        analysis['weak_crypto_detected'] = True
                        analysis['weak_algorithms'].append(desc)
                        analysis['issues'].append(f"Detected {desc}")

                # Strong algorithms (good to use)
                strong = ['aes256', 'aes128', 'sha256', 'sha512', 'rsa2048', 'rsa4096', 'ecdsa']
                for algo in strong:
                    if algo in content:
                        analysis['strong_algorithms'].append(algo.upper())

                # Random number generation
                random_funcs = ['SecRandomCopyBytes', 'arc4random', 'random', 'rand', 'srand']
                for func in random_funcs:
                    if func.lower() in content:
                        analysis['random_sources'].append(func)

                # Key derivation
                kdf_funcs = ['PBKDF2', 'bcrypt', 'scrypt', 'Argon2']
                for func in kdf_funcs:
                    if func.lower() in content:
                        analysis['key_derivation'].append(func)

                # Check for insecure random
                if 'rand' in content and 'SecRandomCopyBytes' not in content:
                    analysis['issues'].append("Using potentially insecure random number generation")

        except Exception as e:
            analysis['error'] = str(e)

        print(f"✅ Cryptography analysis complete")
        return analysis

    def analyze_anti_tampering(self) -> Dict[str, Any]:
        """Detect anti-tampering and anti-debugging mechanisms"""
        print("🛡️  Analyzing anti-tampering mechanisms...")

        analysis = {
            'jailbreak_detection': False,
            'debugger_detection': False,
            'integrity_checks': False,
            'code_obfuscation': False,
            'anti_hooking': False,
            'techniques_detected': []
        }

        if not self.executable_path:
            return analysis

        try:
            result = subprocess.run(['strings', self.executable_path],
                                  capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                content = result.stdout.lower()

                # Jailbreak detection indicators
                jb_indicators = ['cydia', 'substrate', 'frida', 'jailbreak', '/bin/bash', '/Applications/Cydia']
                if any(indicator in content for indicator in jb_indicators):
                    analysis['jailbreak_detection'] = True
                    analysis['techniques_detected'].append("Jailbreak detection")

                # Debugger detection
                debug_indicators = ['ptrace', 'sysctl', 'getppid', 'isatty', 'PT_DENY_ATTACH']
                if any(indicator in content for indicator in debug_indicators):
                    analysis['debugger_detection'] = True
                    analysis['techniques_detected'].append("Debugger detection")

                # Integrity checks
                integrity_indicators = ['checksum', 'hash', 'verify', 'signature']
                if any(indicator in content for indicator in integrity_indicators):
                    analysis['integrity_checks'] = True
                    analysis['techniques_detected'].append("Integrity verification")

                # Code obfuscation (heuristic)
                # Check for unusual symbol patterns
                result_nm = subprocess.run(['nm', self.executable_path],
                                         capture_output=True, text=True, timeout=30)
                if result_nm.returncode == 0:
                    symbols = result_nm.stdout
                    # If many symbols have random-looking names
                    random_symbols = len(re.findall(r'_[a-zA-Z]{20,}', symbols))
                    if random_symbols > 100:
                        analysis['code_obfuscation'] = True
                        analysis['techniques_detected'].append("Possible code obfuscation")

        except Exception as e:
            analysis['error'] = str(e)

        print(f"✅ Anti-tampering analysis complete")
        return analysis

    def analyze_resources(self) -> Dict[str, Any]:
        """Analyze app resources"""
        print("📦 Analyzing app resources...")

        analysis = {
            'assets_car_found': False,
            'databases': [],
            'plists': [],
            'frameworks_embedded': [],
            'certificates': [],
            'provisioning_profile': False,
            'localizations': [],
            'total_files': 0
        }

        if not self.app_bundle_path:
            return analysis

        try:
            # Count files
            for root, dirs, files in os.walk(self.app_bundle_path):
                analysis['total_files'] += len(files)

                for file in files:
                    file_lower = file.lower()
                    file_path = os.path.join(root, file)

                    # Assets.car
                    if file == 'Assets.car':
                        analysis['assets_car_found'] = True

                    # Databases
                    if file_lower.endswith(('.db', '.sqlite', '.sqlite3', '.realm')):
                        analysis['databases'].append({
                            'name': file,
                            'path': file_path,
                            'size': os.path.getsize(file_path)
                        })

                    # Plists
                    if file_lower.endswith('.plist'):
                        analysis['plists'].append(file)

                    # Certificates
                    if file_lower.endswith(('.cer', '.crt', '.p12', '.pfx')):
                        analysis['certificates'].append(file)

                    # Provisioning profile
                    if 'embedded.mobileprovision' in file_lower:
                        analysis['provisioning_profile'] = True

                # Check for embedded frameworks
                if 'Frameworks' in root:
                    for d in dirs:
                        if d.endswith('.framework'):
                            analysis['frameworks_embedded'].append(d)

            # Detect localizations
            lproj_dirs = [d for d in os.listdir(self.app_bundle_path) if d.endswith('.lproj')]
            analysis['localizations'] = lproj_dirs

            print(f"✅ Found {analysis['total_files']} files, {len(analysis['databases'])} databases, {len(lproj_dirs)} localizations")

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    def comprehensive_risk_assessment(self) -> Dict[str, Any]:
        """Comprehensive risk scoring"""
        print("📊 Calculating comprehensive risk assessment...")

        score = 100
        factors = []
        critical_issues = []
        high_issues = []
        medium_issues = []
        low_issues = []

        # OWASP scores
        owasp = self.results.get('owasp_mobile_top10', {})
        owasp_score = owasp.get('overall_score', 0)
        if owasp_score > 50:
            deduction = int((owasp_score - 50) / 2)
            score -= deduction
            high_issues.append(f"High OWASP Mobile Top 10 risk score: {owasp_score:.1f}/100")

        # Network security
        network = self.results.get('network_security', {})
        if network.get('allows_arbitrary_loads'):
            score -= 20
            critical_issues.append("Allows arbitrary HTTP loads (ATS disabled)")
        if network.get('cleartext_traffic'):
            score -= 15
            high_issues.append(f"Cleartext HTTP traffic detected ({len(network['cleartext_traffic'])} URLs)")
        if not network.get('ssl_pinning_detected'):
            score -= 10
            medium_issues.append("SSL certificate pinning not detected")

        # Binary protections
        binary = self.results.get('binary_deep_analysis', {})
        security_checks = binary.get('security_checks', {})
        if not security_checks.get('pie'):
            score -= 15
            high_issues.append("PIE (Position Independent Executable) not enabled")
        if not security_checks.get('stack_canary'):
            score -= 15
            high_issues.append("Stack canary protection not detected")
        if not security_checks.get('arc'):
            score -= 10
            medium_issues.append("ARC (Automatic Reference Counting) not enabled")

        # Credentials exposure
        strings_adv = self.results.get('strings_advanced', {})
        if strings_adv.get('potential_credentials'):
            score -= 25
            critical_issues.append(f"Potential hardcoded credentials detected ({len(strings_adv['potential_credentials'])})")

        # Cryptography
        crypto = self.results.get('cryptography', {})
        if crypto.get('weak_crypto_detected'):
            score -= 20
            critical_issues.append(f"Weak cryptography detected: {', '.join(crypto.get('weak_algorithms', []))}")

        # Third-party SDKs
        sdks = self.results.get('sdk_detection', {})
        if sdks.get('total_detected', 0) > 15:
            score -= 10
            medium_issues.append(f"Large number of third-party SDKs: {sdks['total_detected']}")

        # Privacy concerns
        metadata = self.results.get('metadata', {})
        high_risk_perms = [p for p in metadata.get('permissions', []) if p.get('category') == 'HIGH_RISK']
        if len(high_risk_perms) > 5:
            score -= 10
            medium_issues.append(f"Requests {len(high_risk_perms)} high-risk permissions")

        # Suspicious strings
        if len(strings_adv.get('suspicious_functions', [])) > 10:
            score -= 10
            medium_issues.append(f"Multiple suspicious function calls detected ({len(strings_adv['suspicious_functions'])})")

        # Debugging indicators
        if len(strings_adv.get('debugging_strings', [])) > 20:
            score -= 5
            low_issues.append("Debug strings present in release binary")

        score = max(0, min(100, score))

        # Determine risk level
        if score >= 85:
            level = "LOW"
            color = "green"
            emoji = "✅"
        elif score >= 70:
            level = "MEDIUM"
            color = "yellow"
            emoji = "⚠️"
        elif score >= 50:
            level = "HIGH"
            color = "orange"
            emoji = "🔶"
        else:
            level = "CRITICAL"
            color = "red"
            emoji = "🚨"

        # Combine all issues
        all_issues = {
            'critical': critical_issues,
            'high': high_issues,
            'medium': medium_issues,
            'low': low_issues
        }

        return {
            'score': score,
            'level': level,
            'color': color,
            'emoji': emoji,
            'issues': all_issues,
            'total_issues': len(critical_issues) + len(high_issues) + len(medium_issues) + len(low_issues),
            'owasp_score': owasp_score,
            'recommendations': self._generate_comprehensive_recommendations(all_issues)
        }

    def _generate_comprehensive_recommendations(self, issues: Dict[str, List[str]]) -> List[str]:
        """Generate detailed recommendations"""
        recommendations = []

        if issues['critical']:
            recommendations.append("🚨 CRITICAL: Immediate action required before deployment:")
            for issue in issues['critical']:
                recommendations.append(f"  • {issue}")

        if issues['high']:
            recommendations.append("⚠️  HIGH PRIORITY: Address before next release:")
            for issue in issues['high']:
                recommendations.append(f"  • {issue}")

        if issues['medium']:
            recommendations.append("📋 MEDIUM PRIORITY: Schedule for upcoming sprint:")
            for issue in issues['medium']:
                recommendations.append(f"  • {issue}")

        if not any(issues.values()):
            recommendations.append("✅ Excellent security posture!")
            recommendations.append("✅ Continue regular security audits")
            recommendations.append("✅ Maintain current security practices")

        return recommendations

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive advanced analysis"""
        print("\n" + "="*80)
        print("🦾 VulnHunter - ADVANCED IPA Security Analysis")
        print("="*80 + "\n")
        print(f"📱 Analyzing: {os.path.basename(self.ipa_path)}")
        print(f"📏 Size: {os.path.getsize(self.ipa_path) / (1024*1024):.2f} MB\n")

        # Basic info
        self.results['basic_info'] = {
            'path': self.ipa_path,
            'filename': os.path.basename(self.ipa_path),
            'size_bytes': os.path.getsize(self.ipa_path),
            'size_mb': round(os.path.getsize(self.ipa_path) / (1024*1024), 2),
            'timestamp': datetime.now().isoformat(),
            'hashes': self.compute_hashes()
        }

        # Extract
        if not self.extract_ipa():
            return {'error': 'Failed to extract IPA'}

        # Parse metadata
        self.results['metadata'] = self.parse_info_plist()

        # Deep binary analysis
        self.results['binary_deep_analysis'] = self.deep_binary_analysis()

        # Network security
        self.results['network_security'] = self.analyze_network_security()

        # Advanced strings
        self.results['strings_advanced'] = self.advanced_strings_analysis()

        # SDK detection
        self.results['sdk_detection'] = self.detect_third_party_sdks()

        # Cryptography
        self.results['cryptography'] = self.analyze_cryptography()

        # Anti-tampering
        self.results['anti_tampering'] = self.analyze_anti_tampering()

        # Resources
        self.results['resources'] = self.analyze_resources()

        # OWASP Mobile Top 10
        self.results['owasp_mobile_top10'] = self.owasp_mobile_top10_analysis()

        # Final risk assessment
        self.results['risk_assessment'] = self.comprehensive_risk_assessment()

        print("\n" + "="*80)
        print("✅ Advanced Analysis Complete!")
        print(f"📊 Risk Score: {self.results['risk_assessment']['score']}/100")
        print(f"🎯 Risk Level: {self.results['risk_assessment']['level']}")
        print("="*80)

        return self.results

    def cleanup(self):
        """Cleanup temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                print("🧹 Cleaned up temporary files")
            except:
                pass


# Import numpy for unique counts
try:
    import numpy as np
except ImportError:
    # Fallback if numpy not available
    class np:
        @staticmethod
        def unique(arr, return_counts=False):
            unique_items = list(set(arr))
            if return_counts:
                counts = [arr.count(item) for item in unique_items]
                return unique_items, counts
            return unique_items


def main():
    ipa_path = os.path.expanduser("~/Dice.ipa")

    if not os.path.exists(ipa_path):
        print(f"❌ File not found: {ipa_path}")
        sys.exit(1)

    analyzer = AdvancedIPAAnalyzer(ipa_path)

    try:
        results = analyzer.analyze()

        # Save detailed JSON results
        json_path = os.path.expanduser("~/Downloads/Dice_Advanced_Analysis_Results.json")
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n📄 Detailed JSON results saved: {json_path}")

        print(f"\n{'='*80}")
        print(f"✅ Analysis Complete!")
        print(f"📊 Risk Score: {results['risk_assessment']['score']}/100 ({results['risk_assessment']['level']})")
        print(f"🔍 Total Issues: {results['risk_assessment']['total_issues']}")
        print(f"📊 OWASP Score: {results['risk_assessment']['owasp_score']:.1f}/100")
        print(f"{'='*80}\n")

    finally:
        analyzer.cleanup()


if __name__ == "__main__":
    main()
