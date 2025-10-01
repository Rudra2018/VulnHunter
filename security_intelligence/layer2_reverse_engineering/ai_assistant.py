"""
AI-Assisted Reverse Engineering Module

This module provides AI-powered assistance for reverse engineering tasks including:
- Automated vulnerability pattern recognition in assembly code
- Function similarity analysis across binaries
- Code pattern matching and classification
- Intelligent disassembly analysis
"""

import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Tuple, Optional, Any
import logging
from dataclasses import dataclass
from pathlib import Path
import pickle
import hashlib
import json
from collections import defaultdict
import re

try:
    import capstone
    import r2pipe
    import angr
    REVERSE_TOOLS_AVAILABLE = True
except ImportError:
    REVERSE_TOOLS_AVAILABLE = False
    logging.warning("Some reverse engineering tools not available. Install with: pip install capstone r2pipe angr")

@dataclass
class AssemblyPattern:
    """Represents a vulnerability pattern in assembly code"""
    pattern_id: str
    name: str
    description: str
    assembly_signature: List[str]
    vulnerability_type: str
    severity: str
    confidence: float
    metadata: Dict[str, Any]

@dataclass
class FunctionSimilarity:
    """Represents similarity between two functions"""
    function1_hash: str
    function2_hash: str
    similarity_score: float
    similarity_type: str
    matching_features: List[str]
    confidence: float

class AssemblyEncoder(nn.Module):
    """Neural network for encoding assembly instructions into embeddings"""

    def __init__(self, vocab_size: int = 10000, embedding_dim: int = 256, hidden_dim: int = 512):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.attention = nn.MultiheadAttention(hidden_dim * 2, num_heads=8)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, 128)
        )

    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)

        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)

        pooled = torch.mean(attn_out, dim=1)
        return self.classifier(pooled)

class VulnerabilityPatternMatcher:
    """Advanced pattern matching for vulnerability detection in assembly"""

    def __init__(self):
        self.patterns = []
        self.compiled_patterns = {}
        self._load_vulnerability_patterns()

    def _load_vulnerability_patterns(self):
        """Load known vulnerability patterns"""
        self.patterns = [
            AssemblyPattern(
                pattern_id="buffer_overflow_1",
                name="Stack Buffer Overflow",
                description="Potential stack buffer overflow via strcpy without bounds checking",
                assembly_signature=[
                    r"call.*strcpy",
                    r"mov.*\[esp.*\]",
                    r"(?!.*bound.*check)",
                ],
                vulnerability_type="buffer_overflow",
                severity="high",
                confidence=0.85,
                metadata={"cwe": "CWE-120", "impact": "code_execution"}
            ),
            AssemblyPattern(
                pattern_id="use_after_free_1",
                name="Use After Free",
                description="Potential use-after-free vulnerability",
                assembly_signature=[
                    r"call.*free",
                    r"mov.*eax.*\[.*\]",
                    r"(?=.*call.*\[eax.*\])",
                ],
                vulnerability_type="use_after_free",
                severity="high",
                confidence=0.80,
                metadata={"cwe": "CWE-416", "impact": "code_execution"}
            ),
            AssemblyPattern(
                pattern_id="format_string_1",
                name="Format String Vulnerability",
                description="Format string vulnerability in printf-like functions",
                assembly_signature=[
                    r"call.*printf",
                    r"push.*\[.*\]",
                    r"(?!.*format.*string)",
                ],
                vulnerability_type="format_string",
                severity="medium",
                confidence=0.75,
                metadata={"cwe": "CWE-134", "impact": "information_disclosure"}
            ),
            AssemblyPattern(
                pattern_id="integer_overflow_1",
                name="Integer Overflow",
                description="Potential integer overflow in arithmetic operations",
                assembly_signature=[
                    r"add.*eax.*ebx",
                    r"(?!.*overflow.*check)",
                    r"mov.*\[.*\].*eax",
                ],
                vulnerability_type="integer_overflow",
                severity="medium",
                confidence=0.70,
                metadata={"cwe": "CWE-190", "impact": "denial_of_service"}
            )
        ]

        for pattern in self.patterns:
            self.compiled_patterns[pattern.pattern_id] = [
                re.compile(sig, re.IGNORECASE) for sig in pattern.assembly_signature
            ]

    def match_patterns(self, assembly_code: str) -> List[AssemblyPattern]:
        """Match vulnerability patterns in assembly code"""
        matches = []

        for pattern in self.patterns:
            compiled_sigs = self.compiled_patterns[pattern.pattern_id]

            match_count = 0
            for sig in compiled_sigs:
                if sig.search(assembly_code):
                    match_count += 1

            confidence = (match_count / len(compiled_sigs)) * pattern.confidence
            if confidence > 0.5:
                matched_pattern = AssemblyPattern(
                    pattern_id=pattern.pattern_id,
                    name=pattern.name,
                    description=pattern.description,
                    assembly_signature=pattern.assembly_signature,
                    vulnerability_type=pattern.vulnerability_type,
                    severity=pattern.severity,
                    confidence=confidence,
                    metadata=pattern.metadata
                )
                matches.append(matched_pattern)

        return matches

class FunctionSimilarityAnalyzer:
    """Advanced function similarity analysis using multiple techniques"""

    def __init__(self):
        self.encoder = AssemblyEncoder()
        self.feature_extractors = {
            'control_flow': self._extract_control_flow_features,
            'instruction_sequence': self._extract_instruction_features,
            'data_flow': self._extract_data_flow_features,
            'string_constants': self._extract_string_features
        }

    def _extract_control_flow_features(self, function_data: Dict) -> np.ndarray:
        """Extract control flow graph features"""
        if 'cfg' not in function_data:
            return np.zeros(50)

        cfg = function_data['cfg']
        features = []

        features.append(len(cfg.get('nodes', [])))
        features.append(len(cfg.get('edges', [])))
        features.append(cfg.get('cyclomatic_complexity', 0))
        features.append(cfg.get('max_depth', 0))
        features.append(cfg.get('num_loops', 0))

        while len(features) < 50:
            features.append(0)

        return np.array(features[:50])

    def _extract_instruction_features(self, function_data: Dict) -> np.ndarray:
        """Extract instruction sequence features"""
        instructions = function_data.get('instructions', [])

        instruction_types = defaultdict(int)
        for instr in instructions:
            instr_type = instr.split()[0] if instr else 'unknown'
            instruction_types[instr_type] += 1

        common_instructions = ['mov', 'add', 'sub', 'mul', 'div', 'call', 'jmp', 'cmp', 'test', 'push', 'pop']
        features = [instruction_types.get(instr, 0) for instr in common_instructions]

        features.append(len(instructions))
        features.append(len(set(instructions)))

        while len(features) < 50:
            features.append(0)

        return np.array(features[:50])

    def _extract_data_flow_features(self, function_data: Dict) -> np.ndarray:
        """Extract data flow features"""
        features = []

        features.append(function_data.get('num_variables', 0))
        features.append(function_data.get('num_parameters', 0))
        features.append(function_data.get('stack_size', 0))
        features.append(function_data.get('num_memory_accesses', 0))
        features.append(function_data.get('num_function_calls', 0))

        while len(features) < 50:
            features.append(0)

        return np.array(features[:50])

    def _extract_string_features(self, function_data: Dict) -> np.ndarray:
        """Extract string constant features"""
        strings = function_data.get('strings', [])

        features = []
        features.append(len(strings))
        features.append(sum(len(s) for s in strings))
        features.append(len([s for s in strings if any(c in s for c in '%s%d%x')]))
        features.append(len([s for s in strings if any(word in s.lower() for word in ['error', 'fail', 'debug'])]))

        while len(features) < 50:
            features.append(0)

        return np.array(features[:50])

    def extract_function_features(self, function_data: Dict) -> np.ndarray:
        """Extract comprehensive features from function data"""
        all_features = []

        for feature_type, extractor in self.feature_extractors.items():
            features = extractor(function_data)
            all_features.extend(features)

        return np.array(all_features)

    def compute_similarity(self, func1_data: Dict, func2_data: Dict) -> FunctionSimilarity:
        """Compute similarity between two functions"""
        features1 = self.extract_function_features(func1_data)
        features2 = self.extract_function_features(func2_data)

        cosine_sim = np.dot(features1, features2) / (np.linalg.norm(features1) * np.linalg.norm(features2) + 1e-8)

        euclidean_dist = np.linalg.norm(features1 - features2)
        euclidean_sim = 1 / (1 + euclidean_dist)

        overall_similarity = 0.7 * cosine_sim + 0.3 * euclidean_sim

        matching_features = []
        feature_names = ['control_flow', 'instruction_sequence', 'data_flow', 'string_constants']
        for i, name in enumerate(feature_names):
            start_idx = i * 50
            end_idx = (i + 1) * 50
            segment_sim = np.dot(features1[start_idx:end_idx], features2[start_idx:end_idx])
            if segment_sim > 0.7:
                matching_features.append(name)

        func1_hash = hashlib.md5(str(func1_data).encode()).hexdigest()[:16]
        func2_hash = hashlib.md5(str(func2_data).encode()).hexdigest()[:16]

        return FunctionSimilarity(
            function1_hash=func1_hash,
            function2_hash=func2_hash,
            similarity_score=float(overall_similarity),
            similarity_type='multi_feature',
            matching_features=matching_features,
            confidence=min(overall_similarity * 1.2, 1.0)
        )

class AIReverseEngineeringAssistant:
    """Main AI assistant for reverse engineering tasks"""

    def __init__(self, model_path: Optional[str] = None):
        self.pattern_matcher = VulnerabilityPatternMatcher()
        self.similarity_analyzer = FunctionSimilarityAnalyzer()
        self.model_path = model_path
        self.analysis_cache = {}

        if REVERSE_TOOLS_AVAILABLE:
            self.setup_reverse_tools()
        else:
            logging.warning("Reverse engineering tools not available. Some features will be limited.")

    def setup_reverse_tools(self):
        """Setup reverse engineering tools"""
        try:
            self.capstone_engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.capstone_engine.detail = True
        except Exception as e:
            logging.error(f"Failed to setup Capstone: {e}")

    def analyze_binary_for_vulnerabilities(self, binary_path: str) -> Dict[str, Any]:
        """Comprehensive vulnerability analysis of a binary"""
        cache_key = f"vuln_analysis_{hashlib.md5(binary_path.encode()).hexdigest()}"
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        results = {
            'binary_path': binary_path,
            'vulnerability_patterns': [],
            'suspicious_functions': [],
            'risk_score': 0.0,
            'analysis_metadata': {}
        }

        try:
            if REVERSE_TOOLS_AVAILABLE:
                results.update(self._perform_detailed_analysis(binary_path))
            else:
                results.update(self._perform_basic_analysis(binary_path))

            self.analysis_cache[cache_key] = results

        except Exception as e:
            logging.error(f"Analysis failed for {binary_path}: {e}")
            results['error'] = str(e)

        return results

    def _perform_detailed_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform detailed analysis using reverse engineering tools"""
        results = {}

        try:
            r2 = r2pipe.open(binary_path)
            r2.cmd('aaa')

            functions = r2.cmdj('aflj') or []
            results['total_functions'] = len(functions)

            vulnerability_patterns = []
            suspicious_functions = []

            for func in functions[:50]:
                func_name = func.get('name', 'unknown')
                func_addr = func.get('offset', 0)

                disasm = r2.cmd(f's {func_addr}; pdf')

                patterns = self.pattern_matcher.match_patterns(disasm)
                for pattern in patterns:
                    pattern.metadata['function'] = func_name
                    pattern.metadata['address'] = hex(func_addr)
                    vulnerability_patterns.append(pattern)

                if self._is_suspicious_function(func, disasm):
                    suspicious_functions.append({
                        'name': func_name,
                        'address': hex(func_addr),
                        'size': func.get('size', 0),
                        'complexity': func.get('cc', 0),
                        'suspicious_indicators': self._get_suspicious_indicators(disasm)
                    })

            r2.quit()

            results.update({
                'vulnerability_patterns': vulnerability_patterns,
                'suspicious_functions': suspicious_functions,
                'risk_score': self._calculate_risk_score(vulnerability_patterns, suspicious_functions)
            })

        except Exception as e:
            logging.error(f"Detailed analysis failed: {e}")
            results['error'] = str(e)

        return results

    def _perform_basic_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform basic analysis without advanced tools"""
        results = {
            'vulnerability_patterns': [],
            'suspicious_functions': [],
            'risk_score': 0.0,
            'analysis_note': 'Limited analysis - reverse engineering tools not available'
        }

        try:
            with open(binary_path, 'rb') as f:
                content = f.read()

            suspicious_strings = [
                b'strcpy', b'sprintf', b'gets', b'scanf',
                b'system', b'exec', b'eval', b'/bin/sh'
            ]

            found_strings = []
            for s in suspicious_strings:
                if s in content:
                    found_strings.append(s.decode('ascii', errors='ignore'))

            if found_strings:
                pattern = AssemblyPattern(
                    pattern_id="suspicious_strings",
                    name="Suspicious String References",
                    description=f"Found potentially dangerous function references: {', '.join(found_strings)}",
                    assembly_signature=found_strings,
                    vulnerability_type="various",
                    severity="medium",
                    confidence=0.6,
                    metadata={"strings": found_strings}
                )
                results['vulnerability_patterns'] = [pattern]
                results['risk_score'] = min(len(found_strings) * 0.2, 1.0)

        except Exception as e:
            logging.error(f"Basic analysis failed: {e}")
            results['error'] = str(e)

        return results

    def _is_suspicious_function(self, func_info: Dict, disasm: str) -> bool:
        """Determine if a function is suspicious"""
        suspicious_indicators = [
            'strcpy', 'sprintf', 'gets', 'system',
            'alloca', 'malloc', 'free', 'memcpy'
        ]

        return any(indicator in disasm.lower() for indicator in suspicious_indicators)

    def _get_suspicious_indicators(self, disasm: str) -> List[str]:
        """Get list of suspicious indicators in disassembly"""
        indicators = []
        suspicious_patterns = [
            ('buffer_operations', ['strcpy', 'sprintf', 'gets', 'scanf']),
            ('memory_operations', ['malloc', 'free', 'alloca', 'realloc']),
            ('system_calls', ['system', 'exec', 'fork', 'pipe']),
            ('format_strings', ['printf', 'fprintf', 'snprintf'])
        ]

        for category, patterns in suspicious_patterns:
            for pattern in patterns:
                if pattern in disasm.lower():
                    indicators.append(f"{category}: {pattern}")

        return indicators

    def _calculate_risk_score(self, patterns: List[AssemblyPattern], suspicious_funcs: List[Dict]) -> float:
        """Calculate overall risk score"""
        pattern_score = sum(p.confidence for p in patterns) / max(len(patterns), 1)
        function_score = min(len(suspicious_funcs) * 0.1, 0.5)

        return min(pattern_score + function_score, 1.0)

    def compare_function_similarity(self, func1_data: Dict, func2_data: Dict) -> FunctionSimilarity:
        """Compare similarity between two functions"""
        return self.similarity_analyzer.compute_similarity(func1_data, func2_data)

    def batch_similarity_analysis(self, functions: List[Dict]) -> List[FunctionSimilarity]:
        """Perform batch similarity analysis on multiple functions"""
        similarities = []

        for i in range(len(functions)):
            for j in range(i + 1, len(functions)):
                similarity = self.compare_function_similarity(functions[i], functions[j])
                if similarity.similarity_score > 0.7:
                    similarities.append(similarity)

        return sorted(similarities, key=lambda x: x.similarity_score, reverse=True)

    def generate_vulnerability_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a comprehensive vulnerability report"""
        report = []
        report.append("AI-Assisted Reverse Engineering Report")
        report.append("=" * 50)
        report.append(f"Binary: {analysis_results.get('binary_path', 'Unknown')}")
        report.append(f"Risk Score: {analysis_results.get('risk_score', 0):.2f}/1.0")
        report.append("")

        patterns = analysis_results.get('vulnerability_patterns', [])
        if patterns:
            report.append("Vulnerability Patterns Detected:")
            report.append("-" * 30)
            for pattern in patterns:
                report.append(f"• {pattern.name} (Severity: {pattern.severity})")
                report.append(f"  Confidence: {pattern.confidence:.2f}")
                report.append(f"  Description: {pattern.description}")
                if 'function' in pattern.metadata:
                    report.append(f"  Function: {pattern.metadata['function']}")
                report.append("")

        suspicious_funcs = analysis_results.get('suspicious_functions', [])
        if suspicious_funcs:
            report.append("Suspicious Functions:")
            report.append("-" * 20)
            for func in suspicious_funcs:
                report.append(f"• {func['name']} at {func['address']}")
                report.append(f"  Size: {func['size']} bytes")
                report.append(f"  Indicators: {', '.join(func['suspicious_indicators'])}")
                report.append("")

        return "\n".join(report)