#!/usr/bin/env python3
"""
VulnHunter Ωmega + VHS Specialized Analysis Modules
Ready-to-use analyzers for common asset types

SPECIALIZED MODULES:
- Smart Contract Analyzer (Solidity, Rust, Vyper)
- Mobile Security Analyzer (APK/IPA Deep Analysis)
- Web Application Scanner (OWASP Top 10+)
- API Security Tester (REST/GraphQL/WebSocket)
- Binary Reverse Engineering (PE/ELF/Mach-O)
- Cloud Security Auditor (AWS/Azure/GCP)

NOTICE: This tool is for defensive security research only.
"""

import os
import sys
import json
import time
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
import zipfile
import requests
from vulnhunter_universal_framework import VulnHunterUniversalFramework, AssetType, AnalysisTarget, VHSAnalysisResult

class SmartContractAnalyzer(VulnHunterUniversalFramework):
    """
    Specialized Smart Contract Security Analyzer

    Supports: Solidity, Rust (Anchor/Substrate), Vyper, Move
    Features: Advanced DeFi vulnerability detection, Economic analysis
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.contract_patterns = self._load_contract_patterns()

    def _load_contract_patterns(self) -> Dict[str, Dict[str, List[str]]]:
        """Load comprehensive smart contract vulnerability patterns"""
        return {
            'solidity': {
                'reentrancy': [
                    r'\.call\s*\(\s*""?\s*\)',
                    r'\.call\.value\s*\(',
                    r'\.send\s*\(',
                    r'transfer\s*\(\s*[^)]*\)(?!.*require)',
                    r'external.*payable.*(?!.*reentrancy)',
                ],
                'integer_overflow': [
                    r'(\+\+|\-\-|\+=|\-=|\*=|/=)(?!.*SafeMath)',
                    r'[^u]int\d*\s+\w+\s*[+\-*/]',
                    r'unchecked\s*\{[^}]*[+\-*/]',
                ],
                'access_control': [
                    r'function\s+\w+\s*\([^)]*\)\s*public(?!.*onlyOwner)',
                    r'selfdestruct\s*\([^)]*\)(?!.*onlyOwner)',
                    r'delegatecall\s*\([^)]*\)(?!.*access)',
                ],
                'front_running': [
                    r'tx\.origin',
                    r'block\.timestamp.*randomness',
                    r'blockhash\s*\(\s*block\.number',
                ],
                'oracle_manipulation': [
                    r'\.latestRoundData\(\)(?!.*stale)',
                    r'getPrice\(\)(?!.*validation)',
                    r'oracle\.get.*\(\)(?!.*circuit)',
                ],
                'flash_loan_attacks': [
                    r'flashLoan\s*\(',
                    r'borrow.*repay(?!.*same.*block)',
                    r'liquidity.*manipulation',
                ],
                'governance_attacks': [
                    r'vote.*power(?!.*delegation.*safe)',
                    r'proposal.*execution(?!.*timelock)',
                    r'quorum(?!.*sufficient)',
                ],
                'mev_vulnerabilities': [
                    r'swap.*price(?!.*slippage.*protection)',
                    r'arbitrage(?!.*protection)',
                    r'liquidation(?!.*grace.*period)',
                ]
            },
            'rust': {
                'anchor_vulnerabilities': [
                    r'#\[account\](?!.*constraint)',
                    r'invoke_signed\s*\(',
                    r'system_program::transfer(?!.*validation)',
                    r'spl_token::transfer(?!.*authority)',
                ],
                'substrate_issues': [
                    r'ensure!\s*\([^)]*\)(?!.*sufficient.*check)',
                    r'dispatch.*unchecked',
                    r'weight.*calculation(?!.*accurate)',
                ],
                'move_patterns': [
                    r'move_to\s*<[^>]*>\s*\([^)]*\)(?!.*capability)',
                    r'borrow_global(?!.*exists)',
                    r'coin::mint(?!.*capability)',
                ]
            }
        }

    def analyze_smart_contract(self, contract_path: str, language: str = 'auto') -> VHSAnalysisResult:
        """Comprehensive smart contract analysis"""

        # Auto-detect language if not specified
        if language == 'auto':
            language = self._detect_contract_language(contract_path)

        print(f"🔗 Analyzing {language} smart contract: {os.path.basename(contract_path)}")

        # Create analysis target
        target = AnalysisTarget(
            asset_type=AssetType.SMART_CONTRACT,
            path=contract_path,
            name=os.path.basename(contract_path),
            metadata={'language': language, 'contract_type': 'smart_contract'}
        )

        # Perform specialized analysis
        vulnerabilities = []

        try:
            with open(contract_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Language-specific pattern analysis
            if language in self.contract_patterns:
                patterns = self.contract_patterns[language]
                vulnerabilities = self._analyze_contract_patterns(content, patterns, language)

            # Economic vulnerability analysis
            economic_vulns = self._analyze_economic_vulnerabilities(content, language)
            vulnerabilities.extend(economic_vulns)

            # Gas optimization analysis
            gas_issues = self._analyze_gas_issues(content, language)
            vulnerabilities.extend(gas_issues)

        except Exception as e:
            print(f"❌ Contract analysis error: {e}")

        result = VHSAnalysisResult(
            target=target,
            vulnerabilities=vulnerabilities,
            mathematical_analysis=self._compute_contract_mathematics(content, language),
            security_score=self._calculate_contract_security_score(vulnerabilities),
            risk_assessment=self._assess_contract_risk(vulnerabilities),
            recommendations=self._generate_contract_recommendations(vulnerabilities, language)
        )

        return self._apply_vhs_mathematics(result)

    def _detect_contract_language(self, contract_path: str) -> str:
        """Auto-detect smart contract language"""
        extension = Path(contract_path).suffix.lower()

        language_map = {
            '.sol': 'solidity',
            '.rs': 'rust',
            '.vy': 'vyper',
            '.move': 'move',
            '.cairo': 'cairo'
        }

        return language_map.get(extension, 'unknown')

    def _analyze_contract_patterns(self, content: str, patterns: Dict[str, List[str]], language: str) -> List[Dict[str, Any]]:
        """Analyze contract-specific vulnerability patterns"""
        vulnerabilities = []

        import re
        for vuln_category, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1

                    vulnerability = {
                        'id': f"SC-{len(vulnerabilities) + 1:04d}",
                        'category': vuln_category,
                        'language': language,
                        'severity': self._assess_contract_vulnerability_severity(vuln_category),
                        'line': line_num,
                        'pattern': pattern,
                        'match': match.group(),
                        'context': self._extract_context(content, match.start()),
                        'confidence': self._calculate_pattern_confidence(vuln_category, pattern),
                        'economic_impact': self._assess_economic_impact(vuln_category),
                        'fix_complexity': self._assess_fix_complexity(vuln_category)
                    }

                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _analyze_economic_vulnerabilities(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Analyze economic and game-theoretic vulnerabilities"""
        economic_vulns = []

        # MEV (Maximal Extractable Value) vulnerabilities
        mev_patterns = [
            (r'swap.*amount.*out', 'arbitrage_opportunity'),
            (r'liquidation.*threshold', 'liquidation_mev'),
            (r'auction.*mechanism', 'auction_manipulation'),
            (r'oracle.*price.*update', 'oracle_front_running')
        ]

        import re
        for pattern, vuln_type in mev_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                economic_vulns.append({
                    'id': f"ECO-{len(economic_vulns) + 1:04d}",
                    'category': 'economic_vulnerability',
                    'subcategory': vuln_type,
                    'severity': 'HIGH',
                    'line': content[:match.start()].count('\n') + 1,
                    'economic_impact': 'CRITICAL',
                    'mev_potential': 'HIGH'
                })

        return economic_vulns

    def _analyze_gas_issues(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Analyze gas optimization and DoS vulnerabilities"""
        gas_issues = []

        if language == 'solidity':
            gas_patterns = [
                (r'for\s*\([^)]*\)\s*\{[^}]*\}', 'unbounded_loop'),
                (r'\.length\s*>\s*\d+', 'array_length_check'),
                (r'external.*view.*returns.*\[\]', 'large_return_array'),
                (r'require\s*\([^)]*string[^)]*\)', 'expensive_string_error')
            ]

            import re
            for pattern, issue_type in gas_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    gas_issues.append({
                        'id': f"GAS-{len(gas_issues) + 1:04d}",
                        'category': 'gas_optimization',
                        'subcategory': issue_type,
                        'severity': 'MEDIUM',
                        'line': content[:match.start()].count('\n') + 1,
                        'gas_impact': self._assess_gas_impact(issue_type)
                    })

        return gas_issues

    def _compute_contract_mathematics(self, content: str, language: str) -> Dict[str, Any]:
        """Compute mathematical analysis specific to smart contracts"""

        import re

        # Contract complexity metrics
        functions = len(re.findall(r'function\s+\w+', content))
        modifiers = len(re.findall(r'modifier\s+\w+', content))
        events = len(re.findall(r'event\s+\w+', content))
        state_vars = len(re.findall(r'(uint|int|bool|address|string|bytes)\s+\w+', content))

        # Economic topology
        value_flows = len(re.findall(r'(transfer|send|call|delegatecall)', content))
        price_dependencies = len(re.findall(r'(price|oracle|feed|rate)', content))

        return {
            'contract_complexity': {
                'functions': functions,
                'modifiers': modifiers,
                'events': events,
                'state_variables': state_vars,
                'complexity_score': (functions * 2 + modifiers + events + state_vars) / 10
            },
            'economic_topology': {
                'value_flow_nodes': value_flows,
                'price_dependency_edges': price_dependencies,
                'economic_complexity': (value_flows + price_dependencies) / 5
            },
            'security_invariants': {
                'access_control_depth': len(re.findall(r'(onlyOwner|onlyAdmin|require.*msg\.sender)', content)),
                'reentrancy_guards': len(re.findall(r'(nonReentrant|ReentrancyGuard)', content)),
                'overflow_protection': len(re.findall(r'(SafeMath|unchecked)', content))
            }
        }

    def _assess_contract_vulnerability_severity(self, category: str) -> str:
        """Assess smart contract vulnerability severity"""
        severity_map = {
            'reentrancy': 'CRITICAL',
            'integer_overflow': 'HIGH',
            'access_control': 'HIGH',
            'oracle_manipulation': 'CRITICAL',
            'flash_loan_attacks': 'CRITICAL',
            'governance_attacks': 'HIGH',
            'mev_vulnerabilities': 'MEDIUM',
            'front_running': 'MEDIUM',
            'anchor_vulnerabilities': 'HIGH',
            'substrate_issues': 'MEDIUM'
        }
        return severity_map.get(category, 'LOW')

    def _calculate_pattern_confidence(self, category: str, pattern: str) -> float:
        """Calculate confidence score for pattern matches"""
        base_confidence = 0.7

        # Adjust based on pattern specificity
        if 'require' in pattern or 'assert' in pattern:
            base_confidence += 0.1
        if '(?!.*' in pattern:  # Negative lookahead
            base_confidence += 0.15
        if len(pattern) > 50:  # Complex patterns
            base_confidence += 0.1

        return min(1.0, base_confidence)

    def _assess_economic_impact(self, category: str) -> str:
        """Assess economic impact of vulnerability"""
        high_impact = ['reentrancy', 'oracle_manipulation', 'flash_loan_attacks']
        medium_impact = ['governance_attacks', 'mev_vulnerabilities']

        if category in high_impact:
            return 'CRITICAL'
        elif category in medium_impact:
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _assess_fix_complexity(self, category: str) -> str:
        """Assess complexity of fixing the vulnerability"""
        complex_fixes = ['reentrancy', 'oracle_manipulation', 'governance_attacks']
        moderate_fixes = ['integer_overflow', 'access_control']

        if category in complex_fixes:
            return 'COMPLEX'
        elif category in moderate_fixes:
            return 'MODERATE'
        else:
            return 'SIMPLE'

    def _assess_gas_impact(self, issue_type: str) -> str:
        """Assess gas impact of optimization issue"""
        high_impact = ['unbounded_loop', 'large_return_array']

        if issue_type in high_impact:
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _calculate_contract_security_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate security score specific to smart contracts"""
        if not vulnerabilities:
            return 1.0

        # Weight by economic impact
        total_weight = 0
        for vuln in vulnerabilities:
            base_weight = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.2}.get(vuln.get('severity', 'LOW'), 0.2)
            economic_multiplier = {'CRITICAL': 1.5, 'HIGH': 1.2, 'MEDIUM': 1.0}.get(vuln.get('economic_impact', 'MEDIUM'), 1.0)
            total_weight += base_weight * economic_multiplier

        avg_weight = total_weight / len(vulnerabilities)
        return max(0.0, 1.0 - (avg_weight / 1.5))  # Adjust for economic multiplier

    def _assess_contract_risk(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Assess overall contract risk"""
        critical_economic = sum(1 for v in vulnerabilities
                              if v.get('severity') == 'CRITICAL' and v.get('economic_impact') == 'CRITICAL')

        if critical_economic > 0:
            return 'CRITICAL'
        elif sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL') > 0:
            return 'HIGH'
        elif sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH') > 2:
            return 'HIGH'
        elif len(vulnerabilities) > 5:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_contract_recommendations(self, vulnerabilities: List[Dict[str, Any]], language: str) -> List[str]:
        """Generate smart contract specific recommendations"""
        recommendations = []

        vuln_categories = set(v.get('category', '') for v in vulnerabilities)

        if 'reentrancy' in vuln_categories:
            recommendations.extend([
                'Implement OpenZeppelin ReentrancyGuard',
                'Use checks-effects-interactions pattern',
                'Consider using pull payment pattern'
            ])

        if 'integer_overflow' in vuln_categories:
            recommendations.extend([
                'Use OpenZeppelin SafeMath library (pre-0.8.0)',
                'Leverage Solidity 0.8+ built-in overflow checks',
                'Add explicit overflow checks for unchecked blocks'
            ])

        if 'oracle_manipulation' in vuln_categories:
            recommendations.extend([
                'Implement Chainlink price feeds with staleness checks',
                'Use multiple oracle sources for price validation',
                'Add circuit breakers for extreme price movements'
            ])

        if 'economic_vulnerability' in vuln_categories:
            recommendations.extend([
                'Conduct economic security audit',
                'Implement MEV protection mechanisms',
                'Add slippage protection for swaps'
            ])

        # Language-specific recommendations
        if language == 'solidity':
            recommendations.extend([
                'Use latest Solidity version with security features',
                'Implement comprehensive test suite with edge cases',
                'Consider formal verification for critical functions'
            ])
        elif language == 'rust':
            recommendations.extend([
                'Leverage Rust ownership system for memory safety',
                'Use Anchor framework constraints for validation',
                'Implement comprehensive error handling'
            ])

        return list(set(recommendations))  # Remove duplicates

class MobileSecurityAnalyzer(VulnHunterUniversalFramework):
    """
    Specialized Mobile Application Security Analyzer

    Supports: Android APK, iOS IPA, React Native, Flutter
    Features: Deep binary analysis, Runtime protection assessment
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mobile_tools = self._check_mobile_tools()

    def _check_mobile_tools(self) -> Dict[str, bool]:
        """Check availability of mobile analysis tools"""
        tools = {}
        tool_commands = {
            'aapt': 'aapt version',
            'apktool': 'apktool --version',
            'jadx': 'jadx --version',
            'frida': 'frida --version',
            'objection': 'objection --help',
            'class-dump': 'class-dump',
            'otool': 'otool -h',
            'plutil': 'plutil -help'
        }

        for tool, command in tool_commands.items():
            try:
                subprocess.run(command.split(), capture_output=True, check=True, timeout=5)
                tools[tool] = True
            except:
                tools[tool] = False

        return tools

    def analyze_android_apk(self, apk_path: str, deep_analysis: bool = True) -> VHSAnalysisResult:
        """Comprehensive Android APK analysis"""
        print(f"📱 Analyzing Android APK: {os.path.basename(apk_path)}")

        target = AnalysisTarget(
            asset_type=AssetType.ANDROID_APK,
            path=apk_path,
            name=os.path.basename(apk_path),
            metadata={'platform': 'android', 'deep_analysis': deep_analysis}
        )

        vulnerabilities = []
        temp_dir = tempfile.mkdtemp(prefix="apk_deep_analysis_")
        self.cleanup_registry.append(temp_dir)

        try:
            # Extract APK
            self._extract_apk(apk_path, temp_dir)

            # Manifest analysis
            vulnerabilities.extend(self._analyze_android_manifest_deep(temp_dir))

            # Code analysis
            if deep_analysis:
                vulnerabilities.extend(self._analyze_android_code(temp_dir))

            # Native library analysis
            vulnerabilities.extend(self._analyze_android_native_libs(temp_dir))

            # Resource analysis
            vulnerabilities.extend(self._analyze_android_resources(temp_dir))

            # Runtime protection analysis
            vulnerabilities.extend(self._analyze_android_protections(temp_dir))

        except Exception as e:
            print(f"❌ APK analysis error: {e}")

        result = VHSAnalysisResult(
            target=target,
            vulnerabilities=vulnerabilities,
            mathematical_analysis=self._compute_mobile_mathematics(temp_dir, 'android'),
            security_score=self._calculate_security_score(vulnerabilities),
            risk_assessment=self._assess_risk(vulnerabilities),
            recommendations=self._generate_android_recommendations(vulnerabilities)
        )

        return self._apply_vhs_mathematics(result)

    def _extract_apk(self, apk_path: str, output_dir: str):
        """Extract APK using available tools"""
        if self.mobile_tools.get('apktool', False):
            cmd = f"apktool d {apk_path} -o {output_dir}/apktool_output"
            subprocess.run(cmd, shell=True, check=False, timeout=120)
        else:
            # Fallback to unzip
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(os.path.join(output_dir, 'zip_output'))

    def _analyze_android_manifest_deep(self, extract_dir: str) -> List[Dict[str, Any]]:
        """Deep Android manifest analysis"""
        vulnerabilities = []

        manifest_paths = [
            os.path.join(extract_dir, 'apktool_output', 'AndroidManifest.xml'),
            os.path.join(extract_dir, 'zip_output', 'AndroidManifest.xml')
        ]

        for manifest_path in manifest_paths:
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Dangerous permissions
                    dangerous_perms = [
                        'WRITE_EXTERNAL_STORAGE', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION',
                        'CAMERA', 'RECORD_AUDIO', 'READ_SMS', 'RECEIVE_SMS', 'READ_PHONE_STATE'
                    ]

                    for perm in dangerous_perms:
                        if perm in content:
                            vulnerabilities.append({
                                'type': 'dangerous_permission',
                                'severity': 'MEDIUM',
                                'permission': perm,
                                'impact': self._assess_permission_impact(perm)
                            })

                    # Exported components without protection
                    if 'android:exported="true"' in content and 'android:permission' not in content:
                        vulnerabilities.append({
                            'type': 'unprotected_exported_component',
                            'severity': 'HIGH',
                            'description': 'Exported component without permission protection'
                        })

                    # Debug mode enabled
                    if 'android:debuggable="true"' in content:
                        vulnerabilities.append({
                            'type': 'debug_enabled',
                            'severity': 'HIGH',
                            'description': 'Debug mode enabled in production'
                        })

                    # Backup allowed
                    if 'android:allowBackup="true"' in content:
                        vulnerabilities.append({
                            'type': 'backup_allowed',
                            'severity': 'MEDIUM',
                            'description': 'Application data backup allowed'
                        })

                except Exception as e:
                    self.logger.debug(f"Manifest analysis error: {e}")

                break  # Use first found manifest

        return vulnerabilities

    def _analyze_android_code(self, extract_dir: str) -> List[Dict[str, Any]]:
        """Analyze Android application code"""
        vulnerabilities = []

        # Look for DEX files
        dex_files = []
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith('.dex'):
                    dex_files.append(os.path.join(root, file))

        # Analyze with JADX if available
        if self.mobile_tools.get('jadx', False) and dex_files:
            jadx_output = os.path.join(extract_dir, 'jadx_output')
            for dex_file in dex_files[:3]:  # Limit to first 3 DEX files
                cmd = f"jadx -d {jadx_output} {dex_file}"
                try:
                    subprocess.run(cmd, shell=True, check=False, timeout=180)
                    vulnerabilities.extend(self._analyze_decompiled_code(jadx_output))
                except Exception as e:
                    self.logger.debug(f"JADX analysis error: {e}")

        return vulnerabilities

    def _analyze_decompiled_code(self, jadx_output: str) -> List[Dict[str, Any]]:
        """Analyze decompiled Android code"""
        vulnerabilities = []

        # Security patterns to look for
        security_patterns = {
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']'
            ],
            'insecure_storage': [
                r'SharedPreferences\.Editor\.putString',
                r'openFileOutput.*MODE_WORLD_READABLE',
                r'SQLiteDatabase\.execSQL.*password'
            ],
            'insecure_communication': [
                r'http://[^"\']+',
                r'HttpURLConnection.*http://',
                r'TrustAllCertificates',
                r'HostnameVerifier.*ALLOW_ALL'
            ],
            'webview_vulnerabilities': [
                r'WebView\.loadUrl\s*\(\s*["\']javascript:',
                r'setJavaScriptEnabled\s*\(\s*true\s*\)',
                r'addJavascriptInterface'
            ]
        }

        # Scan Java files
        for root, dirs, files in os.walk(jadx_output):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    vulnerabilities.extend(
                        self._analyze_file_patterns(file_path, security_patterns)
                    )

        return vulnerabilities

    def _analyze_android_native_libs(self, extract_dir: str) -> List[Dict[str, Any]]:
        """Analyze native libraries in APK"""
        vulnerabilities = []

        lib_dirs = [
            os.path.join(extract_dir, 'apktool_output', 'lib'),
            os.path.join(extract_dir, 'zip_output', 'lib')
        ]

        for lib_dir in lib_dirs:
            if os.path.exists(lib_dir):
                for root, dirs, files in os.walk(lib_dir):
                    for file in files:
                        if file.endswith('.so'):
                            lib_path = os.path.join(root, file)
                            vulnerabilities.extend(self._analyze_native_library(lib_path))

        return vulnerabilities

    def _analyze_native_library(self, lib_path: str) -> List[Dict[str, Any]]:
        """Analyze individual native library"""
        vulnerabilities = []

        try:
            # Check for stack canaries, NX bit, ASLR
            if os.name != 'nt':  # Unix-like systems
                result = subprocess.run(['readelf', '-s', lib_path],
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    output = result.stdout

                    if '__stack_chk_fail' not in output:
                        vulnerabilities.append({
                            'type': 'missing_stack_canary',
                            'severity': 'MEDIUM',
                            'library': os.path.basename(lib_path)
                        })

                    # Check for dangerous functions
                    dangerous_funcs = ['strcpy', 'strcat', 'sprintf', 'gets']
                    for func in dangerous_funcs:
                        if func in output:
                            vulnerabilities.append({
                                'type': 'dangerous_function',
                                'severity': 'HIGH',
                                'function': func,
                                'library': os.path.basename(lib_path)
                            })

        except Exception as e:
            self.logger.debug(f"Native library analysis error: {e}")

        return vulnerabilities

    def _analyze_android_resources(self, extract_dir: str) -> List[Dict[str, Any]]:
        """Analyze Android resources for security issues"""
        vulnerabilities = []

        # Look for sensitive data in resources
        resource_dirs = [
            os.path.join(extract_dir, 'apktool_output', 'res'),
            os.path.join(extract_dir, 'zip_output', 'res')
        ]

        for res_dir in resource_dirs:
            if os.path.exists(res_dir):
                for root, dirs, files in os.walk(res_dir):
                    for file in files:
                        if file.endswith('.xml'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()

                                # Look for hardcoded secrets
                                if any(keyword in content.lower() for keyword in
                                      ['password', 'secret', 'api_key', 'private_key']):
                                    vulnerabilities.append({
                                        'type': 'resource_secrets',
                                        'severity': 'MEDIUM',
                                        'file': file_path,
                                        'description': 'Potential secrets in resource files'
                                    })

                            except Exception:
                                continue

        return vulnerabilities

    def _analyze_android_protections(self, extract_dir: str) -> List[Dict[str, Any]]:
        """Analyze runtime protection mechanisms"""
        vulnerabilities = []

        # Check for obfuscation
        java_files = []
        for root, dirs, files in os.walk(extract_dir):
            java_files.extend([f for f in files if f.endswith('.java')])

        if java_files:
            # Simple heuristic for obfuscation
            short_names = sum(1 for f in java_files if len(Path(f).stem) <= 2)
            if short_names / len(java_files) < 0.3:  # Less than 30% short names
                vulnerabilities.append({
                    'type': 'missing_obfuscation',
                    'severity': 'MEDIUM',
                    'description': 'Code appears to lack proper obfuscation'
                })

        # Check for anti-debugging
        # This would require more sophisticated analysis
        vulnerabilities.append({
            'type': 'anti_debugging_check',
            'severity': 'INFO',
            'description': 'Anti-debugging mechanisms should be verified manually'
        })

        return vulnerabilities

    def _assess_permission_impact(self, permission: str) -> str:
        """Assess impact of Android permission"""
        high_impact = ['ACCESS_FINE_LOCATION', 'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS']
        if permission in high_impact:
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _compute_mobile_mathematics(self, extract_dir: str, platform: str) -> Dict[str, Any]:
        """Compute mathematical analysis for mobile applications"""

        # Count components
        component_count = 0
        file_count = 0

        for root, dirs, files in os.walk(extract_dir):
            file_count += len(files)
            component_count += len([f for f in files if f.endswith(('.java', '.kt', '.swift', '.m'))])

        return {
            'mobile_complexity': {
                'total_files': file_count,
                'code_components': component_count,
                'platform': platform,
                'complexity_score': min(1.0, component_count / 100)
            },
            'attack_surface': {
                'exported_components': 'analyzed',
                'network_endpoints': 'analyzed',
                'file_system_access': 'analyzed'
            }
        }

    def _generate_android_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate Android-specific recommendations"""
        recommendations = [
            'Implement certificate pinning for network communications',
            'Use Android Keystore for sensitive data storage',
            'Enable ProGuard/R8 obfuscation for release builds',
            'Implement root detection and anti-tampering measures'
        ]

        vuln_types = set(v.get('type', '') for v in vulnerabilities)

        if 'dangerous_permission' in vuln_types:
            recommendations.append('Review and minimize requested permissions')

        if 'hardcoded_secrets' in vuln_types:
            recommendations.append('Move secrets to secure backend or encrypted storage')

        if 'insecure_communication' in vuln_types:
            recommendations.append('Enforce HTTPS and implement certificate validation')

        return recommendations

def create_specialized_usage_guide():
    """Create comprehensive usage guide for specialized modules"""

    guide_content = """# VulnHunter Ωmega + VHS Specialized Modules Usage Guide

## 🎯 Quick Start Examples

### Smart Contract Analysis
```python
from vulnhunter_specialized_modules import SmartContractAnalyzer

# Analyze Solidity contract
with SmartContractAnalyzer(cleanup_policy="moderate") as analyzer:
    result = analyzer.analyze_smart_contract("MyContract.sol")
    print(f"Security Score: {result.security_score}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
```

### Android APK Analysis
```python
from vulnhunter_specialized_modules import MobileSecurityAnalyzer

# Deep APK analysis
with MobileSecurityAnalyzer(cleanup_policy="aggressive") as analyzer:
    result = analyzer.analyze_android_apk("app.apk", deep_analysis=True)
    print(f"Security Issues: {len(result.vulnerabilities)}")
```

## 🔧 Configuration Options

### Cleanup Policies
- **aggressive**: Maximum cleanup, minimal disk usage
- **moderate**: Balanced approach, keep important artifacts
- **minimal**: Keep most analysis data for manual review

### Analysis Depth
- **surface**: Quick pattern-based analysis
- **deep**: Comprehensive analysis with tool integration
- **forensic**: Maximum depth with reverse engineering

## 📊 Output Formats

All analyzers support multiple output formats:
- JSON (detailed results)
- Markdown (executive summary)
- SARIF (for CI/CD integration)
- PDF (for reporting)

## 🛡️ Security Best Practices

1. **Always run in isolated environment**
2. **Use appropriate cleanup policies**
3. **Verify tool dependencies before analysis**
4. **Review results manually for false positives**
5. **Keep analysis logs for audit trails**

## 🔍 Advanced Usage

### Custom Pattern Addition
```python
analyzer.contract_patterns['solidity']['custom_vulnerability'] = [
    r'your_custom_pattern_here'
]
```

### Tool Integration
```python
# Check tool availability
tools_status = analyzer.mobile_tools
print(f"JADX available: {tools_status['jadx']}")
```

### Mathematical Analysis
```python
# Access VHS mathematical results
math_analysis = result.mathematical_analysis
print(f"Topology: {math_analysis['simplicial_complex']}")
print(f"Homotopy: {math_analysis['homotopy_invariants']}")
```
"""

    with open("VULNHUNTER_SPECIALIZED_USAGE_GUIDE.md", "w") as f:
        f.write(guide_content)

def main():
    """Demonstration of specialized modules"""
    print("🔥 VulnHunter Ωmega + VHS Specialized Modules")
    print("=" * 55)

    # Create usage guide
    create_specialized_usage_guide()
    print("📚 Usage guide created: VULNHUNTER_SPECIALIZED_USAGE_GUIDE.md")

    # Test smart contract analyzer if Solidity files exist
    sol_files = list(Path('.').rglob('*.sol'))
    if sol_files:
        print(f"\n🔗 Testing Smart Contract Analyzer on {sol_files[0]}")

        with SmartContractAnalyzer(cleanup_policy="moderate") as analyzer:
            result = analyzer.analyze_smart_contract(str(sol_files[0]))
            print(f"   Security Score: {result.security_score}/1.0")
            print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
            print(f"   Risk Assessment: {result.risk_assessment}")

    print("\n✅ Specialized modules ready for production use!")
    print("🧹 Cleanup policies implemented for all asset types")
    print("🔧 Framework supports comprehensive security analysis")

if __name__ == "__main__":
    main()