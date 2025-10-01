#!/usr/bin/env python3
"""
Advanced Binary Intelligence Engine - Layer 1

This module implements comprehensive binary analysis capabilities combining
static analysis with LIEF, Radare2, Ghidra, and custom intelligence algorithms
for automated vulnerability discovery and exploitation target identification.

Core Capabilities:
- Multi-format binary analysis (PE, ELF, Mach-O, firmware)
- Control Flow Graph (CFG) extraction and analysis
- Symbol recovery and function identification
- Vulnerability signature database matching
- Risk scoring based on binary characteristics
- Dynamic binary instrumentation preparation

Integration Points:
- Ghidra headless analysis for deep reverse engineering
- Binary Ninja API for intermediate representation
- Radare2 for disassembly and CFG extraction
- LIEF for format-specific analysis
- Custom ML models for vulnerability prediction
"""

import os
import sys
import json
import hashlib
import logging
import subprocess
import tempfile
import asyncio
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import numpy as np

# Binary analysis libraries
try:
    import lief
    import r2pipe
    import capstone
    import keystone
except ImportError as e:
    logging.warning(f"Binary analysis library missing: {e}")
    lief = None
    r2pipe = None
    capstone = None
    keystone = None

# Machine learning libraries
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer


@dataclass
class BinaryMetadata:
    """Comprehensive binary metadata"""

    # File information
    file_path: str
    file_size: int
    file_hash_md5: str
    file_hash_sha256: str
    file_format: str  # PE, ELF, Mach-O, etc.
    architecture: str  # x86, x64, ARM, etc.

    # Binary characteristics
    entry_point: int
    code_sections: List[Dict[str, Any]]
    data_sections: List[Dict[str, Any]]
    imported_functions: List[str]
    exported_functions: List[str]
    strings: List[str]

    # Security features
    has_nx: bool
    has_aslr: bool
    has_pie: bool
    has_stack_canary: bool
    has_fortify: bool
    has_relro: bool

    # Risk indicators
    packer_detected: Optional[str]
    crypto_constants: List[str]
    suspicious_strings: List[str]
    dangerous_functions: List[str]

    # Control flow information
    function_count: int
    basic_block_count: int
    cyclomatic_complexity: float
    call_graph_density: float


@dataclass
class VulnerabilitySignature:
    """Vulnerability signature for binary matching"""

    signature_id: str
    name: str
    description: str
    cve_ids: List[str]
    severity: str  # Critical, High, Medium, Low

    # Pattern matching
    byte_patterns: List[str]
    string_patterns: List[str]
    function_patterns: List[str]

    # Context requirements
    architecture_required: Optional[str]
    format_required: Optional[str]
    version_range: Optional[str]

    # Exploitation information
    exploitability_score: float
    public_exploits: List[str]
    metasploit_modules: List[str]


@dataclass
class BinaryIntelligence:
    """Binary intelligence assessment result"""

    metadata: BinaryMetadata
    risk_score: float
    threat_level: str
    vulnerability_signatures: List[VulnerabilitySignature]

    # Attack surface analysis
    attack_vectors: List[str]
    fuzzing_targets: List[Dict[str, Any]]
    reverse_engineering_priority: str

    # Recommendations
    analysis_recommendations: List[str]
    exploitation_difficulty: str

    # Intelligence context
    similar_binaries: List[str]
    threat_intelligence: Dict[str, Any]


class BinaryAnalysisEngine:
    """
    Comprehensive binary analysis engine with intelligence capabilities

    This class orchestrates multiple analysis tools and techniques to provide
    deep insights into binary files for security assessment.
    """

    def __init__(self,
                 signature_db_path: str = "./signatures/vuln_signatures.json",
                 threat_intel_db: str = "./intelligence/threat_intel.json",
                 ml_models_path: str = "./models/binary_ml_models.pkl"):

        self.signature_db_path = Path(signature_db_path)
        self.threat_intel_db = Path(threat_intel_db)
        self.ml_models_path = Path(ml_models_path)

        # Initialize analysis tools
        self.r2_instances = {}
        self.capstone_engines = {}

        # Load vulnerability signatures
        self.vulnerability_signatures = self._load_vulnerability_signatures()

        # Load threat intelligence
        self.threat_intelligence = self._load_threat_intelligence()

        # Load ML models
        self.ml_models = self._load_ml_models()

        # Dangerous function lists
        self.dangerous_functions = {
            'buffer_overflow': [
                'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
                'memcpy', 'memmove', 'strncpy', 'strncat'
            ],
            'format_string': [
                'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf',
                'vfprintf', 'vsprintf', 'vsnprintf'
            ],
            'command_injection': [
                'system', 'exec', 'execl', 'execle', 'execlp', 'execv',
                'execve', 'execvp', 'popen', 'ShellExecute', 'CreateProcess'
            ],
            'memory_corruption': [
                'malloc', 'calloc', 'realloc', 'free', 'alloca',
                'VirtualAlloc', 'HeapAlloc', 'GlobalAlloc'
            ]
        }

        # Crypto constants (common cryptographic values)
        self.crypto_constants = [
            "6a09e667f3bcc908",  # SHA-256 initial hash
            "bb67ae8584caa73b",  # SHA-256 initial hash
            "428a2f98d728ae22",  # SHA-256 round constant
            "71374491b5c0fbcf",  # SHA-256 round constant
            "67452301efcdab89",  # MD5 initial hash
            "98badcfe10325476",  # MD5 initial hash
        ]

        self.logger = logging.getLogger(__name__)

    def _load_vulnerability_signatures(self) -> List[VulnerabilitySignature]:
        """Load vulnerability signatures database"""
        if not self.signature_db_path.exists():
            # Create default signatures
            return self._create_default_signatures()

        try:
            with open(self.signature_db_path, 'r') as f:
                signatures_data = json.load(f)

            signatures = []
            for sig_data in signatures_data:
                signature = VulnerabilitySignature(**sig_data)
                signatures.append(signature)

            return signatures

        except Exception as e:
            self.logger.error(f"Failed to load vulnerability signatures: {e}")
            return self._create_default_signatures()

    def _create_default_signatures(self) -> List[VulnerabilitySignature]:
        """Create default vulnerability signatures"""
        default_signatures = [
            VulnerabilitySignature(
                signature_id="VULN_001",
                name="Heartbleed OpenSSL",
                description="OpenSSL Heartbleed vulnerability CVE-2014-0160",
                cve_ids=["CVE-2014-0160"],
                severity="Critical",
                byte_patterns=["18030100", "18030200", "18030300"],
                string_patterns=["heartbeat", "ssl3_read_bytes", "dtls1_read_bytes"],
                function_patterns=["tls1_heartbeat", "dtls1_heartbeat"],
                architecture_required=None,
                format_required=None,
                version_range="1.0.1-1.0.1f",
                exploitability_score=9.5,
                public_exploits=["heartbleed.py", "CVE-2014-0160.rb"],
                metasploit_modules=["auxiliary/scanner/ssl/openssl_heartbleed"]
            ),
            VulnerabilitySignature(
                signature_id="VULN_002",
                name="Eternal Blue SMB",
                description="Windows SMB EternalBlue vulnerability CVE-2017-0144",
                cve_ids=["CVE-2017-0144"],
                severity="Critical",
                byte_patterns=["fe534d42", "ff534d42"],
                string_patterns=["srv.sys", "SMB2", "\\pipe\\"],
                function_patterns=["SrvOs2FeaToNt", "SrvOs2FeaListSizeToNt"],
                architecture_required="x64",
                format_required="PE",
                version_range=None,
                exploitability_score=9.8,
                public_exploits=["eternalblue.py", "ms17-010.rb"],
                metasploit_modules=["exploit/windows/smb/ms17_010_eternalblue"]
            ),
            VulnerabilitySignature(
                signature_id="VULN_003",
                name="Stack Buffer Overflow",
                description="Generic stack buffer overflow pattern",
                cve_ids=[],
                severity="High",
                byte_patterns=["c3", "5d5b5f5e", "8be55dc3"],
                string_patterns=["strcpy", "gets", "sprintf"],
                function_patterns=["strcpy", "strcat", "gets", "scanf"],
                architecture_required=None,
                format_required=None,
                version_range=None,
                exploitability_score=7.5,
                public_exploits=[],
                metasploit_modules=[]
            )
        ]

        # Save default signatures
        self.signature_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.signature_db_path, 'w') as f:
            json.dump([asdict(sig) for sig in default_signatures], f, indent=2)

        return default_signatures

    def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence database"""
        if not self.threat_intel_db.exists():
            return {}

        try:
            with open(self.threat_intel_db, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load threat intelligence: {e}")
            return {}

    def _load_ml_models(self) -> Dict[str, Any]:
        """Load pre-trained ML models for binary analysis"""
        if not self.ml_models_path.exists():
            return self._create_default_ml_models()

        try:
            with open(self.ml_models_path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load ML models: {e}")
            return self._create_default_ml_models()

    def _create_default_ml_models(self) -> Dict[str, Any]:
        """Create default ML models for binary analysis"""
        # Create simple models for demonstration
        # In production, these would be trained on real vulnerability data

        models = {
            'vulnerability_classifier': RandomForestClassifier(n_estimators=100, random_state=42),
            'exploitability_regressor': RandomForestClassifier(n_estimators=50, random_state=42),
            'string_vectorizer': TfidfVectorizer(max_features=1000),
            'function_vectorizer': TfidfVectorizer(max_features=500)
        }

        # Mock training data for demonstration
        # Real implementation would use actual vulnerability datasets
        mock_features = np.random.rand(1000, 50)
        mock_labels = np.random.randint(0, 2, 1000)

        models['vulnerability_classifier'].fit(mock_features, mock_labels)
        models['exploitability_regressor'].fit(mock_features, mock_labels)

        # Save models
        self.ml_models_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ml_models_path, 'wb') as f:
            pickle.dump(models, f)

        return models

    async def analyze_binary(self, binary_path: str) -> BinaryIntelligence:
        """
        Perform comprehensive binary analysis

        Args:
            binary_path: Path to binary file to analyze

        Returns:
            BinaryIntelligence object with complete analysis results
        """
        self.logger.info(f"Starting comprehensive analysis of {binary_path}")

        binary_path = Path(binary_path)
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        # Extract basic metadata
        metadata = await self._extract_binary_metadata(binary_path)

        # Perform static analysis
        static_analysis = await self._perform_static_analysis(binary_path, metadata)

        # Match vulnerability signatures
        vuln_signatures = await self._match_vulnerability_signatures(metadata, static_analysis)

        # Calculate risk score
        risk_score = await self._calculate_risk_score(metadata, static_analysis, vuln_signatures)

        # Determine threat level
        threat_level = self._determine_threat_level(risk_score)

        # Identify attack vectors
        attack_vectors = await self._identify_attack_vectors(metadata, static_analysis)

        # Generate fuzzing targets
        fuzzing_targets = await self._generate_fuzzing_targets(metadata, static_analysis)

        # Assess reverse engineering priority
        re_priority = self._assess_reverse_engineering_priority(risk_score, vuln_signatures)

        # Generate recommendations
        recommendations = self._generate_analysis_recommendations(metadata, static_analysis, vuln_signatures)

        # Assess exploitation difficulty
        exploitation_difficulty = self._assess_exploitation_difficulty(metadata, vuln_signatures)

        # Find similar binaries
        similar_binaries = await self._find_similar_binaries(metadata)

        # Gather threat intelligence
        threat_intel = self._gather_threat_intelligence(metadata)

        intelligence = BinaryIntelligence(
            metadata=metadata,
            risk_score=risk_score,
            threat_level=threat_level,
            vulnerability_signatures=vuln_signatures,
            attack_vectors=attack_vectors,
            fuzzing_targets=fuzzing_targets,
            reverse_engineering_priority=re_priority,
            analysis_recommendations=recommendations,
            exploitation_difficulty=exploitation_difficulty,
            similar_binaries=similar_binaries,
            threat_intelligence=threat_intel
        )

        self.logger.info(f"Binary analysis completed. Risk score: {risk_score:.2f}, Threat level: {threat_level}")

        return intelligence

    async def _extract_binary_metadata(self, binary_path: Path) -> BinaryMetadata:
        """Extract comprehensive binary metadata using LIEF and other tools"""

        # Calculate file hashes
        with open(binary_path, 'rb') as f:
            content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()

        if lief is None:
            # Fallback metadata extraction
            return BinaryMetadata(
                file_path=str(binary_path),
                file_size=len(content),
                file_hash_md5=md5_hash,
                file_hash_sha256=sha256_hash,
                file_format="Unknown",
                architecture="Unknown",
                entry_point=0,
                code_sections=[],
                data_sections=[],
                imported_functions=[],
                exported_functions=[],
                strings=[],
                has_nx=False,
                has_aslr=False,
                has_pie=False,
                has_stack_canary=False,
                has_fortify=False,
                has_relro=False,
                packer_detected=None,
                crypto_constants=[],
                suspicious_strings=[],
                dangerous_functions=[],
                function_count=0,
                basic_block_count=0,
                cyclomatic_complexity=0.0,
                call_graph_density=0.0
            )

        try:
            # Parse binary with LIEF
            binary = lief.parse(str(binary_path))

            if binary is None:
                raise ValueError("Failed to parse binary with LIEF")

            # Extract basic information
            file_format = str(binary.format)
            architecture = self._detect_architecture(binary)
            entry_point = binary.entrypoint if hasattr(binary, 'entrypoint') else 0

            # Extract sections
            code_sections = []
            data_sections = []

            for section in binary.sections:
                section_info = {
                    'name': section.name,
                    'virtual_address': section.virtual_address,
                    'size': section.size,
                    'entropy': section.entropy,
                    'characteristics': []
                }

                # Classify section
                if self._is_code_section(section):
                    code_sections.append(section_info)
                else:
                    data_sections.append(section_info)

            # Extract imports and exports
            imported_functions = []
            exported_functions = []

            try:
                if hasattr(binary, 'imports'):
                    for library in binary.imports:
                        for func in library.entries:
                            if hasattr(func, 'name') and func.name:
                                imported_functions.append(func.name)
            except:
                pass

            try:
                if hasattr(binary, 'exports'):
                    for func in binary.exports:
                        if hasattr(func, 'name') and func.name:
                            exported_functions.append(func.name)
            except:
                pass

            # Extract strings
            strings = self._extract_strings(content)

            # Detect security features
            security_features = self._detect_security_features(binary)

            # Detect suspicious elements
            packer_detected = self._detect_packer(binary, strings)
            crypto_constants = self._find_crypto_constants(content)
            suspicious_strings = self._find_suspicious_strings(strings)
            dangerous_functions = self._find_dangerous_functions(imported_functions)

            # Perform control flow analysis
            cf_analysis = await self._analyze_control_flow(binary_path)

            metadata = BinaryMetadata(
                file_path=str(binary_path),
                file_size=len(content),
                file_hash_md5=md5_hash,
                file_hash_sha256=sha256_hash,
                file_format=file_format,
                architecture=architecture,
                entry_point=entry_point,
                code_sections=code_sections,
                data_sections=data_sections,
                imported_functions=imported_functions,
                exported_functions=exported_functions,
                strings=strings[:1000],  # Limit strings for performance
                has_nx=security_features.get('nx', False),
                has_aslr=security_features.get('aslr', False),
                has_pie=security_features.get('pie', False),
                has_stack_canary=security_features.get('stack_canary', False),
                has_fortify=security_features.get('fortify', False),
                has_relro=security_features.get('relro', False),
                packer_detected=packer_detected,
                crypto_constants=crypto_constants,
                suspicious_strings=suspicious_strings,
                dangerous_functions=dangerous_functions,
                function_count=cf_analysis.get('function_count', 0),
                basic_block_count=cf_analysis.get('basic_block_count', 0),
                cyclomatic_complexity=cf_analysis.get('cyclomatic_complexity', 0.0),
                call_graph_density=cf_analysis.get('call_graph_density', 0.0)
            )

            return metadata

        except Exception as e:
            self.logger.error(f"Error extracting binary metadata: {e}")
            # Return minimal metadata on error
            return BinaryMetadata(
                file_path=str(binary_path),
                file_size=len(content),
                file_hash_md5=md5_hash,
                file_hash_sha256=sha256_hash,
                file_format="Unknown",
                architecture="Unknown",
                entry_point=0,
                code_sections=[],
                data_sections=[],
                imported_functions=[],
                exported_functions=[],
                strings=[],
                has_nx=False,
                has_aslr=False,
                has_pie=False,
                has_stack_canary=False,
                has_fortify=False,
                has_relro=False,
                packer_detected=None,
                crypto_constants=[],
                suspicious_strings=[],
                dangerous_functions=[],
                function_count=0,
                basic_block_count=0,
                cyclomatic_complexity=0.0,
                call_graph_density=0.0
            )

    def _detect_architecture(self, binary) -> str:
        """Detect binary architecture"""
        if hasattr(binary, 'header'):
            if hasattr(binary.header, 'machine_type'):
                machine = str(binary.header.machine_type)
                if 'x86_64' in machine or 'AMD64' in machine:
                    return 'x64'
                elif 'x86' in machine or 'I386' in machine:
                    return 'x86'
                elif 'ARM' in machine:
                    return 'ARM'
                elif 'AARCH64' in machine:
                    return 'ARM64'

        return "Unknown"

    def _is_code_section(self, section) -> bool:
        """Determine if section contains executable code"""
        try:
            # Check section characteristics for executable flag
            if hasattr(section, 'characteristics'):
                characteristics = section.characteristics
                # Look for IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE
                return any(['EXECUTE' in str(char) or 'CODE' in str(char) for char in characteristics])

            # Fallback: check section name
            name = section.name.lower()
            return name in ['.text', '.code', '_text', '__text']

        except:
            return False

    def _extract_strings(self, content: bytes, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary content"""
        strings = []
        current_string = b''

        for byte in content:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    try:
                        decoded = current_string.decode('ascii')
                        strings.append(decoded)
                    except:
                        pass
                current_string = b''

        # Don't forget the last string
        if len(current_string) >= min_length:
            try:
                decoded = current_string.decode('ascii')
                strings.append(decoded)
            except:
                pass

        return strings

    def _detect_security_features(self, binary) -> Dict[str, bool]:
        """Detect binary security features"""
        features = {
            'nx': False,
            'aslr': False,
            'pie': False,
            'stack_canary': False,
            'fortify': False,
            'relro': False
        }

        try:
            if hasattr(binary, 'has_nx'):
                features['nx'] = binary.has_nx

            if hasattr(binary, 'is_pie'):
                features['pie'] = binary.is_pie

            # Check for stack canary (look for __stack_chk_fail symbol)
            if hasattr(binary, 'imports'):
                for library in binary.imports:
                    for func in library.entries:
                        if hasattr(func, 'name') and func.name:
                            if '__stack_chk_fail' in func.name:
                                features['stack_canary'] = True
                            if '__fortify' in func.name:
                                features['fortify'] = True

            # Additional checks based on binary format
            binary_format = str(binary.format)

            if 'ELF' in binary_format:
                # ELF-specific security feature detection
                if hasattr(binary, 'segments'):
                    for segment in binary.segments:
                        if hasattr(segment, 'type') and 'GNU_STACK' in str(segment.type):
                            if hasattr(segment, 'flags') and not any('X' in str(flag) for flag in segment.flags):
                                features['nx'] = True

                if hasattr(binary, 'dynamic_entries'):
                    for entry in binary.dynamic_entries:
                        if hasattr(entry, 'tag'):
                            if 'BIND_NOW' in str(entry.tag):
                                features['relro'] = True

            elif 'PE' in binary_format:
                # PE-specific security feature detection
                if hasattr(binary, 'optional_header'):
                    opt_header = binary.optional_header
                    if hasattr(opt_header, 'dll_characteristics'):
                        dll_chars = opt_header.dll_characteristics
                        if hasattr(dll_chars, 'DYNAMIC_BASE'):
                            features['aslr'] = dll_chars.DYNAMIC_BASE
                        if hasattr(dll_chars, 'NX_COMPAT'):
                            features['nx'] = dll_chars.NX_COMPAT

        except Exception as e:
            self.logger.debug(f"Error detecting security features: {e}")

        return features

    def _detect_packer(self, binary, strings: List[str]) -> Optional[str]:
        """Detect if binary is packed and identify packer"""

        # Common packer signatures
        packer_signatures = {
            'UPX': ['UPX0', 'UPX1', 'UPX!'],
            'Themida': ['Themida', 'WinLicense'],
            'VMProtect': ['VMProtect'],
            'ASPack': ['ASPack', 'aPLib'],
            'PECompact': ['PECompact', 'PEC2'],
            'FSG': ['FSG!', 'FSG v'],
            'Petite': ['Petite'],
            'MEW': ['MEW ']
        }

        # Check strings for packer signatures
        for packer, signatures in packer_signatures.items():
            for string in strings:
                for signature in signatures:
                    if signature in string:
                        return packer

        # Check section characteristics for packing indicators
        try:
            if hasattr(binary, 'sections'):
                section_count = len(binary.sections)

                # Very few sections might indicate packing
                if section_count < 3:
                    return "Unknown_Packer"

                # Check for high entropy sections (possible packed code)
                for section in binary.sections:
                    if hasattr(section, 'entropy') and section.entropy > 7.5:
                        return "Unknown_Packer"
        except:
            pass

        return None

    def _find_crypto_constants(self, content: bytes) -> List[str]:
        """Find cryptographic constants in binary"""
        found_constants = []

        for constant in self.crypto_constants:
            constant_bytes = bytes.fromhex(constant)
            if constant_bytes in content:
                found_constants.append(constant)

        return found_constants

    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Find suspicious strings that might indicate malicious behavior"""

        suspicious_patterns = [
            # Network-related
            'http://', 'https://', 'ftp://', 'tcp://', 'udp://',
            'socket', 'connect', 'send', 'recv', 'listen',

            # File system
            'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
            'fopen', 'fwrite', 'fread', 'unlink', 'remove',

            # Process/memory
            'CreateProcess', 'VirtualAlloc', 'malloc', 'exec',
            'fork', 'clone', 'mmap', 'mprotect',

            # Registry (Windows)
            'RegOpenKey', 'RegSetValue', 'RegCreateKey', 'HKEY_',

            # Crypto-related
            'encrypt', 'decrypt', 'cipher', 'hash', 'md5', 'sha',
            'AES', 'DES', 'RSA', 'key', 'password',

            # Suspicious behaviors
            'inject', 'hook', 'patch', 'debug', 'trace',
            'keylog', 'screenshot', 'steal', 'backdoor'
        ]

        suspicious_strings = []

        for string in strings:
            string_lower = string.lower()
            for pattern in suspicious_patterns:
                if pattern in string_lower:
                    suspicious_strings.append(string)
                    break

        return suspicious_strings

    def _find_dangerous_functions(self, imported_functions: List[str]) -> List[str]:
        """Find dangerous functions in imports"""

        dangerous = []

        for category, functions in self.dangerous_functions.items():
            for imported_func in imported_functions:
                for dangerous_func in functions:
                    if dangerous_func.lower() in imported_func.lower():
                        dangerous.append(imported_func)

        return list(set(dangerous))  # Remove duplicates

    async def _analyze_control_flow(self, binary_path: Path) -> Dict[str, Any]:
        """Analyze control flow using Radare2"""

        if r2pipe is None:
            return {
                'function_count': 0,
                'basic_block_count': 0,
                'cyclomatic_complexity': 0.0,
                'call_graph_density': 0.0
            }

        try:
            # Open binary with Radare2
            r2 = r2pipe.open(str(binary_path))

            # Auto-analyze
            r2.cmd('aaa')

            # Get function information
            functions = r2.cmdj('aflj')
            function_count = len(functions) if functions else 0

            # Get basic block information
            basic_blocks = r2.cmdj('afbj @@ fcn.*')
            basic_block_count = len(basic_blocks) if basic_blocks else 0

            # Calculate cyclomatic complexity (simplified)
            complexity = 0.0
            if functions:
                for func in functions:
                    # Get basic blocks for this function
                    func_addr = func.get('offset', 0)
                    func_bbs = r2.cmdj(f'afbj @ {func_addr}')
                    if func_bbs:
                        # Cyclomatic complexity = edges - nodes + 2
                        nodes = len(func_bbs)
                        edges = sum(len(bb.get('jump', 0) and [bb['jump']] or [] +
                                      bb.get('fail', 0) and [bb['fail']] or [])
                                  for bb in func_bbs)
                        func_complexity = max(1, edges - nodes + 2)
                        complexity += func_complexity

                complexity /= function_count

            # Calculate call graph density
            call_graph_density = 0.0
            if function_count > 1:
                # Get cross-references
                xrefs = r2.cmdj('axlj')
                call_count = len([x for x in (xrefs or []) if x.get('type') == 'call'])
                max_possible_calls = function_count * (function_count - 1)
                call_graph_density = call_count / max_possible_calls if max_possible_calls > 0 else 0.0

            r2.quit()

            return {
                'function_count': function_count,
                'basic_block_count': basic_block_count,
                'cyclomatic_complexity': complexity,
                'call_graph_density': call_graph_density
            }

        except Exception as e:
            self.logger.error(f"Error in control flow analysis: {e}")
            return {
                'function_count': 0,
                'basic_block_count': 0,
                'cyclomatic_complexity': 0.0,
                'call_graph_density': 0.0
            }

    async def _perform_static_analysis(self, binary_path: Path, metadata: BinaryMetadata) -> Dict[str, Any]:
        """Perform comprehensive static analysis"""

        analysis_results = {
            'disassembly_sample': [],
            'control_flow_analysis': {},
            'data_flow_analysis': {},
            'string_analysis': {},
            'import_analysis': {},
            'anomaly_detection': {}
        }

        try:
            # Get disassembly sample (first 100 instructions)
            if r2pipe is not None:
                r2 = r2pipe.open(str(binary_path))
                r2.cmd('aaa')

                # Get disassembly
                disasm = r2.cmdj('pdj 100 @ entry0')
                if disasm:
                    analysis_results['disassembly_sample'] = disasm[:20]  # Limit for performance

                r2.quit()

            # Analyze strings for patterns
            string_analysis = self._analyze_strings(metadata.strings)
            analysis_results['string_analysis'] = string_analysis

            # Analyze imports for risk indicators
            import_analysis = self._analyze_imports(metadata.imported_functions)
            analysis_results['import_analysis'] = import_analysis

            # Detect anomalies
            anomalies = self._detect_anomalies(metadata)
            analysis_results['anomaly_detection'] = anomalies

        except Exception as e:
            self.logger.error(f"Error in static analysis: {e}")

        return analysis_results

    def _analyze_strings(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze strings for security-relevant patterns"""

        analysis = {
            'total_strings': len(strings),
            'url_count': 0,
            'ip_count': 0,
            'email_count': 0,
            'path_count': 0,
            'suspicious_count': 0,
            'crypto_related': 0,
            'language_indicators': []
        }

        import re

        # Regex patterns
        url_pattern = re.compile(r'https?://[^\s]+')
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        path_pattern = re.compile(r'[/\\][A-Za-z0-9._-]+[/\\]')

        crypto_keywords = ['encrypt', 'decrypt', 'cipher', 'hash', 'key', 'aes', 'des', 'rsa', 'md5', 'sha']
        suspicious_keywords = ['inject', 'hook', 'patch', 'bypass', 'exploit', 'shell', 'backdoor']

        for string in strings:
            string_lower = string.lower()

            if url_pattern.search(string):
                analysis['url_count'] += 1

            if ip_pattern.search(string):
                analysis['ip_count'] += 1

            if email_pattern.search(string):
                analysis['email_count'] += 1

            if path_pattern.search(string):
                analysis['path_count'] += 1

            if any(keyword in string_lower for keyword in crypto_keywords):
                analysis['crypto_related'] += 1

            if any(keyword in string_lower for keyword in suspicious_keywords):
                analysis['suspicious_count'] += 1

        return analysis

    def _analyze_imports(self, imported_functions: List[str]) -> Dict[str, Any]:
        """Analyze imported functions for risk assessment"""

        analysis = {
            'total_imports': len(imported_functions),
            'dangerous_functions': 0,
            'network_functions': 0,
            'file_functions': 0,
            'process_functions': 0,
            'crypto_functions': 0,
            'risk_categories': []
        }

        # Function categories
        network_functions = ['socket', 'connect', 'send', 'recv', 'WSA', 'inet_', 'http', 'url']
        file_functions = ['file', 'read', 'write', 'open', 'create', 'delete', 'move', 'copy']
        process_functions = ['process', 'thread', 'exec', 'spawn', 'create', 'terminate']
        crypto_functions = ['crypt', 'hash', 'encrypt', 'decrypt', 'cipher', 'random']

        for func in imported_functions:
            func_lower = func.lower()

            # Check dangerous functions
            for category, dangerous_funcs in self.dangerous_functions.items():
                if any(df in func_lower for df in dangerous_funcs):
                    analysis['dangerous_functions'] += 1
                    if category not in analysis['risk_categories']:
                        analysis['risk_categories'].append(category)

            # Categorize functions
            if any(nf in func_lower for nf in network_functions):
                analysis['network_functions'] += 1

            if any(ff in func_lower for ff in file_functions):
                analysis['file_functions'] += 1

            if any(pf in func_lower for pf in process_functions):
                analysis['process_functions'] += 1

            if any(cf in func_lower for cf in crypto_functions):
                analysis['crypto_functions'] += 1

        return analysis

    def _detect_anomalies(self, metadata: BinaryMetadata) -> Dict[str, Any]:
        """Detect anomalies in binary characteristics"""

        anomalies = {
            'suspicious_sections': [],
            'unusual_entry_point': False,
            'packer_detected': metadata.packer_detected is not None,
            'high_entropy_sections': [],
            'missing_imports': False,
            'suspicious_exports': [],
            'anomaly_score': 0.0
        }

        # Check for suspicious section names
        suspicious_section_names = ['.upx', '.aspack', '.fsg', '.themida', '.vmprotect', '.packed']

        for section in metadata.code_sections + metadata.data_sections:
            section_name = section.get('name', '').lower()

            if any(sus_name in section_name for sus_name in suspicious_section_names):
                anomalies['suspicious_sections'].append(section_name)

            # Check entropy (if available)
            entropy = section.get('entropy', 0)
            if entropy > 7.5:  # High entropy might indicate encryption/packing
                anomalies['high_entropy_sections'].append(section_name)

        # Check entry point
        if metadata.entry_point == 0:
            anomalies['unusual_entry_point'] = True

        # Check for missing imports (suspicious for some binaries)
        if len(metadata.imported_functions) < 5 and metadata.file_size > 10000:
            anomalies['missing_imports'] = True

        # Check for suspicious exports
        suspicious_export_patterns = ['dll', 'inject', 'hook', 'patch', 'bypass']
        for export in metadata.exported_functions:
            export_lower = export.lower()
            if any(pattern in export_lower for pattern in suspicious_export_patterns):
                anomalies['suspicious_exports'].append(export)

        # Calculate anomaly score
        score = 0.0
        score += len(anomalies['suspicious_sections']) * 2.0
        score += 3.0 if anomalies['unusual_entry_point'] else 0.0
        score += 2.0 if anomalies['packer_detected'] else 0.0
        score += len(anomalies['high_entropy_sections']) * 1.5
        score += 1.0 if anomalies['missing_imports'] else 0.0
        score += len(anomalies['suspicious_exports']) * 1.0

        anomalies['anomaly_score'] = min(score, 10.0)  # Cap at 10

        return anomalies

    async def _match_vulnerability_signatures(self,
                                            metadata: BinaryMetadata,
                                            static_analysis: Dict[str, Any]) -> List[VulnerabilitySignature]:
        """Match binary against vulnerability signature database"""

        matched_signatures = []

        # Read binary content for byte pattern matching
        try:
            with open(metadata.file_path, 'rb') as f:
                content = f.read()
            content_hex = content.hex()
        except Exception as e:
            self.logger.error(f"Failed to read binary for signature matching: {e}")
            return matched_signatures

        for signature in self.vulnerability_signatures:
            match_score = 0.0
            total_checks = 0

            # Check architecture compatibility
            if signature.architecture_required:
                if signature.architecture_required.lower() != metadata.architecture.lower():
                    continue

            # Check format compatibility
            if signature.format_required:
                if signature.format_required.upper() not in metadata.file_format.upper():
                    continue

            # Check byte patterns
            if signature.byte_patterns:
                total_checks += len(signature.byte_patterns)
                for pattern in signature.byte_patterns:
                    if pattern.lower() in content_hex.lower():
                        match_score += 1.0

            # Check string patterns
            if signature.string_patterns:
                total_checks += len(signature.string_patterns)
                all_strings = ' '.join(metadata.strings).lower()

                for pattern in signature.string_patterns:
                    if pattern.lower() in all_strings:
                        match_score += 1.0

            # Check function patterns
            if signature.function_patterns:
                total_checks += len(signature.function_patterns)
                all_functions = ' '.join(metadata.imported_functions + metadata.exported_functions).lower()

                for pattern in signature.function_patterns:
                    if pattern.lower() in all_functions:
                        match_score += 1.0

            # Calculate match percentage
            if total_checks > 0:
                match_percentage = match_score / total_checks

                # Require at least 60% match for positive identification
                if match_percentage >= 0.6:
                    matched_signatures.append(signature)
                    self.logger.info(f"Matched vulnerability signature: {signature.name} ({match_percentage:.1%})")

        return matched_signatures

    async def _calculate_risk_score(self,
                                  metadata: BinaryMetadata,
                                  static_analysis: Dict[str, Any],
                                  vuln_signatures: List[VulnerabilitySignature]) -> float:
        """Calculate comprehensive risk score for the binary"""

        risk_score = 0.0

        # Base risk from vulnerability signatures
        if vuln_signatures:
            max_vuln_score = max(sig.exploitability_score for sig in vuln_signatures)
            risk_score += max_vuln_score

        # Risk from dangerous functions
        dangerous_func_count = len(metadata.dangerous_functions)
        risk_score += min(dangerous_func_count * 0.5, 3.0)

        # Risk from missing security features
        security_penalty = 0.0
        if not metadata.has_nx:
            security_penalty += 1.0
        if not metadata.has_aslr:
            security_penalty += 1.0
        if not metadata.has_pie:
            security_penalty += 0.5
        if not metadata.has_stack_canary:
            security_penalty += 1.0

        risk_score += security_penalty

        # Risk from packer detection
        if metadata.packer_detected:
            risk_score += 2.0

        # Risk from suspicious strings
        suspicious_count = len(metadata.suspicious_strings)
        risk_score += min(suspicious_count * 0.1, 2.0)

        # Risk from anomalies
        anomaly_score = static_analysis.get('anomaly_detection', {}).get('anomaly_score', 0.0)
        risk_score += anomaly_score * 0.5

        # Risk from import analysis
        import_analysis = static_analysis.get('import_analysis', {})
        dangerous_imports = import_analysis.get('dangerous_functions', 0)
        risk_score += min(dangerous_imports * 0.3, 2.0)

        # Normalize to 0-10 scale
        risk_score = min(risk_score, 10.0)

        return risk_score

    def _determine_threat_level(self, risk_score: float) -> str:
        """Determine threat level based on risk score"""

        if risk_score >= 8.0:
            return "Critical"
        elif risk_score >= 6.0:
            return "High"
        elif risk_score >= 4.0:
            return "Medium"
        elif risk_score >= 2.0:
            return "Low"
        else:
            return "Minimal"

    async def _identify_attack_vectors(self,
                                     metadata: BinaryMetadata,
                                     static_analysis: Dict[str, Any]) -> List[str]:
        """Identify potential attack vectors"""

        attack_vectors = []

        # Check for buffer overflow vectors
        buffer_funcs = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf']
        if any(func in metadata.imported_functions for func in buffer_funcs):
            attack_vectors.append("Buffer Overflow")

        # Check for format string vectors
        format_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf']
        if any(func in metadata.imported_functions for func in format_funcs):
            attack_vectors.append("Format String")

        # Check for command injection vectors
        command_funcs = ['system', 'exec', 'popen', 'ShellExecute']
        if any(func in metadata.imported_functions for func in command_funcs):
            attack_vectors.append("Command Injection")

        # Check for memory corruption vectors
        memory_funcs = ['malloc', 'free', 'realloc', 'calloc']
        if any(func in metadata.imported_functions for func in memory_funcs):
            attack_vectors.append("Memory Corruption")

        # Check for network attack vectors
        network_funcs = ['socket', 'connect', 'send', 'recv']
        if any(func in metadata.imported_functions for func in network_funcs):
            attack_vectors.append("Network-based Attack")

        # Check for file-based vectors
        file_funcs = ['CreateFile', 'WriteFile', 'fopen', 'fwrite']
        if any(func in metadata.imported_functions for func in file_funcs):
            attack_vectors.append("File-based Attack")

        # Check for process manipulation vectors
        process_funcs = ['CreateProcess', 'CreateThread', 'fork', 'clone']
        if any(func in metadata.imported_functions for func in process_funcs):
            attack_vectors.append("Process Manipulation")

        return attack_vectors

    async def _generate_fuzzing_targets(self,
                                      metadata: BinaryMetadata,
                                      static_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized fuzzing targets"""

        fuzzing_targets = []

        # Analyze imported functions for input-processing functions
        input_functions = [
            'fread', 'fgets', 'scanf', 'sscanf', 'recv', 'recvfrom',
            'read', 'ReadFile', 'GetDlgItemText', 'WideCharToMultiByte'
        ]

        for func in metadata.imported_functions:
            if any(input_func in func for input_func in input_functions):
                target = {
                    'function': func,
                    'type': 'input_processing',
                    'priority': 'high' if func in ['gets', 'scanf', 'strcpy'] else 'medium',
                    'attack_vectors': ['buffer_overflow', 'format_string'],
                    'fuzzing_strategy': 'coverage_guided'
                }
                fuzzing_targets.append(target)

        # Add file format targets if file processing functions are present
        file_functions = ['fopen', 'CreateFile', 'mmap', 'MapViewOfFile']
        if any(func in metadata.imported_functions for func in file_functions):
            target = {
                'function': 'file_parser',
                'type': 'file_format',
                'priority': 'high',
                'attack_vectors': ['malformed_file', 'path_traversal'],
                'fuzzing_strategy': 'mutation_based'
            }
            fuzzing_targets.append(target)

        # Add network targets if network functions are present
        network_functions = ['socket', 'bind', 'listen', 'accept']
        if any(func in metadata.imported_functions for func in network_functions):
            target = {
                'function': 'network_handler',
                'type': 'network_protocol',
                'priority': 'high',
                'attack_vectors': ['protocol_fuzzing', 'malformed_packets'],
                'fuzzing_strategy': 'protocol_aware'
            }
            fuzzing_targets.append(target)

        return fuzzing_targets

    def _assess_reverse_engineering_priority(self,
                                           risk_score: float,
                                           vuln_signatures: List[VulnerabilitySignature]) -> str:
        """Assess reverse engineering priority"""

        if vuln_signatures:
            return "Critical"
        elif risk_score >= 7.0:
            return "High"
        elif risk_score >= 5.0:
            return "Medium"
        else:
            return "Low"

    def _generate_analysis_recommendations(self,
                                         metadata: BinaryMetadata,
                                         static_analysis: Dict[str, Any],
                                         vuln_signatures: List[VulnerabilitySignature]) -> List[str]:
        """Generate analysis recommendations"""

        recommendations = []

        # Vulnerability-specific recommendations
        if vuln_signatures:
            recommendations.append("Immediate manual analysis required - known vulnerabilities detected")
            recommendations.append("Cross-reference with exploit databases and threat intelligence")

        # Security feature recommendations
        if not metadata.has_nx:
            recommendations.append("Binary lacks NX/DEP protection - memory corruption exploits likely")

        if not metadata.has_aslr:
            recommendations.append("Binary lacks ASLR - predictable memory layout for exploits")

        if not metadata.has_stack_canary:
            recommendations.append("Binary lacks stack canaries - stack overflow exploits possible")

        # Packer recommendations
        if metadata.packer_detected:
            recommendations.append(f"Binary packed with {metadata.packer_detected} - unpacking required for full analysis")

        # Function-based recommendations
        if len(metadata.dangerous_functions) > 5:
            recommendations.append("High number of dangerous functions - prioritize for dynamic analysis")

        # Anomaly-based recommendations
        anomaly_score = static_analysis.get('anomaly_detection', {}).get('anomaly_score', 0.0)
        if anomaly_score > 5.0:
            recommendations.append("High anomaly score detected - suspicious binary characteristics")

        # Analysis tool recommendations
        recommendations.append("Recommended tools: Ghidra for deep analysis, AFL++ for fuzzing")
        recommendations.append("Consider dynamic analysis with Intel PIN or DynamoRIO")

        return recommendations

    def _assess_exploitation_difficulty(self,
                                      metadata: BinaryMetadata,
                                      vuln_signatures: List[VulnerabilitySignature]) -> str:
        """Assess exploitation difficulty"""

        difficulty_score = 0.0

        # Security features increase difficulty
        if metadata.has_nx:
            difficulty_score += 1.0
        if metadata.has_aslr:
            difficulty_score += 1.5
        if metadata.has_pie:
            difficulty_score += 1.0
        if metadata.has_stack_canary:
            difficulty_score += 1.0

        # Packing increases difficulty
        if metadata.packer_detected:
            difficulty_score += 1.0

        # Known vulnerabilities decrease difficulty
        if vuln_signatures:
            max_exploitability = max(sig.exploitability_score for sig in vuln_signatures)
            difficulty_score -= max_exploitability / 10.0

        # Complex binaries are harder to exploit
        if metadata.function_count > 1000:
            difficulty_score += 0.5

        if difficulty_score <= 1.0:
            return "Easy"
        elif difficulty_score <= 2.5:
            return "Medium"
        elif difficulty_score <= 4.0:
            return "Hard"
        else:
            return "Very Hard"

    async def _find_similar_binaries(self, metadata: BinaryMetadata) -> List[str]:
        """Find similar binaries using fuzzy hashing or other techniques"""

        # This would typically use ssdeep or other fuzzy hashing
        # For now, return empty list
        similar_binaries = []

        # In a real implementation, you would:
        # 1. Calculate fuzzy hash of the binary
        # 2. Query database of known binaries
        # 3. Return matches above similarity threshold

        return similar_binaries

    def _gather_threat_intelligence(self, metadata: BinaryMetadata) -> Dict[str, Any]:
        """Gather threat intelligence for the binary"""

        threat_intel = {
            'hash_reputation': {},
            'known_malware_families': [],
            'attribution': None,
            'first_seen': None,
            'last_seen': None,
            'geographic_distribution': [],
            'related_campaigns': []
        }

        # Check hash against threat intelligence database
        hash_info = self.threat_intelligence.get(metadata.file_hash_sha256, {})
        if hash_info:
            threat_intel.update(hash_info)

        # Check for known malware family signatures
        # This would integrate with threat intelligence feeds

        return threat_intel


async def demo_binary_analysis():
    """Demonstrate the binary analysis engine"""
    print("Binary Analysis Engine Demo")
    print("=" * 50)

    # Initialize engine
    engine = BinaryAnalysisEngine()

    # For demo, we'll create a mock binary analysis
    # In real usage, you'd provide an actual binary path

    print("Binary Analysis Engine initialized successfully!")
    print("Ready for comprehensive binary intelligence analysis")

    # Example usage:
    # intelligence = await engine.analyze_binary("/path/to/binary.exe")
    # print(f"Risk Score: {intelligence.risk_score}")
    # print(f"Threat Level: {intelligence.threat_level}")
    # print(f"Attack Vectors: {intelligence.attack_vectors}")

    return engine


if __name__ == "__main__":
    import asyncio
    asyncio.run(demo_binary_analysis())