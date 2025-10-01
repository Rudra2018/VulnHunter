"""
Crash Analysis Engine

This module provides comprehensive crash analysis capabilities:
- Crash deduplication and classification
- Root cause analysis and vulnerability assessment
- Exploitability scoring and triage
- Crash reproduction and minimization
- Integration with debuggers and analysis tools
"""

import os
import subprocess
import hashlib
import json
import time
import signal
import tempfile
import shutil
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
import re
import struct

try:
    import gdb
    GDB_AVAILABLE = True
except ImportError:
    GDB_AVAILABLE = False

class CrashType(Enum):
    """Types of crashes"""
    SEGMENTATION_FAULT = "segmentation_fault"
    STACK_OVERFLOW = "stack_overflow"
    HEAP_CORRUPTION = "heap_corruption"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    ASSERTION_FAILURE = "assertion_failure"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"

class ExploitabilityLevel(Enum):
    """Exploitability assessment levels"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

@dataclass
class CrashInfo:
    """Comprehensive crash information"""
    crash_id: str
    target_id: str
    crash_type: CrashType
    signal: int
    exit_code: int
    crash_address: Optional[int]
    instruction_pointer: Optional[int]
    stack_pointer: Optional[int]
    input_file: str
    input_size: int
    input_hash: str
    timestamp: float
    reproducer_command: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class StackTrace:
    """Stack trace information"""
    frames: List[Dict[str, Any]]
    crash_frame_index: int
    total_frames: int
    truncated: bool = False

@dataclass
class MemoryState:
    """Memory state at crash"""
    registers: Dict[str, int]
    memory_mappings: List[Dict[str, Any]]
    heap_info: Optional[Dict[str, Any]]
    stack_info: Optional[Dict[str, Any]]

@dataclass
class ExploitabilityAssessment:
    """Exploitability assessment results"""
    level: ExploitabilityLevel
    score: float
    factors: List[str]
    mitigations: List[str]
    attack_vectors: List[str]
    confidence: float

@dataclass
class CrashAnalysisResult:
    """Complete crash analysis result"""
    crash_info: CrashInfo
    stack_trace: Optional[StackTrace]
    memory_state: Optional[MemoryState]
    exploitability: ExploitabilityAssessment
    root_cause: str
    severity: str
    duplicate_of: Optional[str]
    minimized_input: Optional[str]
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

class CrashDeduplicator:
    """Deduplicates crashes based on various criteria"""

    def __init__(self):
        self.known_crashes = {}
        self.dedup_methods = [
            'stack_hash',
            'crash_address',
            'instruction_pattern',
            'register_state'
        ]

    def calculate_crash_hash(self, crash_info: CrashInfo, stack_trace: Optional[StackTrace]) -> str:
        """Calculate unique hash for crash"""
        hash_components = []

        hash_components.append(str(crash_info.crash_type.value))
        hash_components.append(str(crash_info.signal))

        if crash_info.crash_address:
            hash_components.append(f"addr:{crash_info.crash_address:x}")

        if stack_trace and stack_trace.frames:
            relevant_frames = stack_trace.frames[:5]
            for frame in relevant_frames:
                if 'function' in frame and frame['function'] != '??':
                    hash_components.append(frame['function'])
                elif 'address' in frame:
                    hash_components.append(f"0x{frame['address']:x}")

        if not hash_components:
            hash_components.append(crash_info.input_hash)

        hash_string = '|'.join(hash_components)
        return hashlib.md5(hash_string.encode()).hexdigest()

    def find_duplicate(self, crash_hash: str) -> Optional[str]:
        """Find if crash is duplicate of existing crash"""
        return self.known_crashes.get(crash_hash)

    def register_crash(self, crash_hash: str, crash_id: str):
        """Register new crash in deduplication database"""
        self.known_crashes[crash_hash] = crash_id

    def calculate_similarity(self, crash1: CrashInfo, crash2: CrashInfo) -> float:
        """Calculate similarity between two crashes"""
        similarity_score = 0.0

        if crash1.crash_type == crash2.crash_type:
            similarity_score += 0.3

        if crash1.signal == crash2.signal:
            similarity_score += 0.2

        if crash1.crash_address and crash2.crash_address:
            addr_diff = abs(crash1.crash_address - crash2.crash_address)
            if addr_diff < 0x1000:
                similarity_score += 0.3
            elif addr_diff < 0x10000:
                similarity_score += 0.15

        input_similarity = self._calculate_input_similarity(crash1.input_hash, crash2.input_hash)
        similarity_score += input_similarity * 0.2

        return min(similarity_score, 1.0)

    def _calculate_input_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate input similarity based on hashes"""
        if hash1 == hash2:
            return 1.0

        common_chars = sum(c1 == c2 for c1, c2 in zip(hash1, hash2))
        return common_chars / max(len(hash1), len(hash2))

class DebuggerInterface:
    """Interface for debugging crashed processes"""

    def __init__(self):
        self.gdb_available = GDB_AVAILABLE
        self.temp_dir = tempfile.mkdtemp(prefix="crash_debug_")

    def __del__(self):
        """Cleanup temporary directory"""
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass

    def analyze_crash_with_gdb(self, binary_path: str, input_file: str,
                              command_args: List[str] = None) -> Dict[str, Any]:
        """Analyze crash using GDB"""
        if not self.gdb_available:
            return self._analyze_crash_basic(binary_path, input_file, command_args)

        try:
            return self._run_gdb_analysis(binary_path, input_file, command_args or [])
        except Exception as e:
            logging.error(f"GDB analysis failed: {e}")
            return self._analyze_crash_basic(binary_path, input_file, command_args)

    def _run_gdb_analysis(self, binary_path: str, input_file: str, command_args: List[str]) -> Dict[str, Any]:
        """Run GDB analysis on crashed binary"""
        gdb_script = self._generate_gdb_script(binary_path, input_file, command_args)
        script_path = os.path.join(self.temp_dir, "analysis.gdb")

        with open(script_path, 'w') as f:
            f.write(gdb_script)

        try:
            result = subprocess.run(
                ['gdb', '-batch', '-x', script_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            return self._parse_gdb_output(result.stdout, result.stderr)

        except subprocess.TimeoutExpired:
            return {'error': 'GDB analysis timeout'}
        except Exception as e:
            return {'error': f'GDB execution failed: {e}'}

    def _generate_gdb_script(self, binary_path: str, input_file: str, command_args: List[str]) -> str:
        """Generate GDB script for crash analysis"""
        script_lines = [
            f'file {binary_path}',
            'set confirm off',
            'set height 0',
            'set width 0',
            'set pagination off',
            'set logging file /tmp/gdb_analysis.log',
            'set logging on',
        ]

        if command_args:
            args_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in command_args)
            script_lines.append(f'set args {args_str} < {input_file}')
        else:
            script_lines.append(f'set args < {input_file}')

        script_lines.extend([
            'run',
            'info registers',
            'backtrace',
            'info frame',
            'info locals',
            'x/20i $pc-40',
            'x/10gx $rsp',
            'info proc mappings',
            'quit'
        ])

        return '\n'.join(script_lines)

    def _parse_gdb_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse GDB output for crash information"""
        analysis = {
            'registers': {},
            'stack_trace': [],
            'memory_mappings': [],
            'crash_info': {},
            'disassembly': [],
            'locals': {}
        }

        try:
            lines = stdout.split('\n')
            current_section = None

            for line in lines:
                line = line.strip()

                if 'Program received signal' in line:
                    analysis['crash_info']['signal'] = line

                elif line.startswith('rax') or line.startswith('eax'):
                    analysis['registers'].update(self._parse_registers_line(line))

                elif line.startswith('#'):
                    frame_info = self._parse_stack_frame(line)
                    if frame_info:
                        analysis['stack_trace'].append(frame_info)

                elif line.startswith('0x') and '=>' in line:
                    analysis['disassembly'].append(line)

                elif 'mapped' in line and '0x' in line:
                    mapping_info = self._parse_memory_mapping(line)
                    if mapping_info:
                        analysis['memory_mappings'].append(mapping_info)

        except Exception as e:
            logging.error(f"Failed to parse GDB output: {e}")

        return analysis

    def _parse_registers_line(self, line: str) -> Dict[str, int]:
        """Parse register values from GDB output"""
        registers = {}
        try:
            parts = line.split()
            for i in range(0, len(parts), 2):
                if i + 1 < len(parts):
                    reg_name = parts[i]
                    reg_value = parts[i + 1]

                    if reg_value.startswith('0x'):
                        registers[reg_name] = int(reg_value, 16)

        except Exception:
            pass

        return registers

    def _parse_stack_frame(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse stack frame from GDB backtrace"""
        try:
            match = re.match(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(.+?)\s+\(.*\)', line)
            if match:
                return {
                    'frame_number': int(match.group(1)),
                    'address': int(match.group(2), 16),
                    'function': match.group(3)
                }

            match = re.match(r'#(\d+)\s+(0x[0-9a-fA-F]+)', line)
            if match:
                return {
                    'frame_number': int(match.group(1)),
                    'address': int(match.group(2), 16),
                    'function': '??'
                }

        except Exception:
            pass

        return None

    def _parse_memory_mapping(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse memory mapping from GDB output"""
        try:
            parts = line.split()
            if len(parts) >= 3:
                start_addr = int(parts[0], 16)
                end_addr = int(parts[1], 16)
                size = end_addr - start_addr

                return {
                    'start': start_addr,
                    'end': end_addr,
                    'size': size,
                    'permissions': parts[2] if len(parts) > 2 else 'unknown',
                    'path': ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
                }

        except Exception:
            pass

        return None

    def _analyze_crash_basic(self, binary_path: str, input_file: str, command_args: List[str]) -> Dict[str, Any]:
        """Basic crash analysis without GDB"""
        try:
            cmd = [binary_path]
            if command_args:
                cmd.extend(command_args)

            with open(input_file, 'rb') as f:
                input_data = f.read()

            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                timeout=10
            )

            return {
                'exit_code': result.returncode,
                'signal': abs(result.returncode) if result.returncode < 0 else 0,
                'stdout': result.stdout.decode('utf-8', errors='ignore')[:1000],
                'stderr': result.stderr.decode('utf-8', errors='ignore')[:1000]
            }

        except subprocess.TimeoutExpired:
            return {'error': 'Process timeout'}
        except Exception as e:
            return {'error': f'Basic analysis failed: {e}'}

class ExploitabilityAssessor:
    """Assesses exploitability of crashes"""

    def __init__(self):
        self.exploitability_factors = {
            'control_pc': 0.8,
            'control_sp': 0.7,
            'heap_corruption': 0.6,
            'stack_corruption': 0.7,
            'write_primitive': 0.9,
            'info_leak': 0.4,
            'format_string': 0.8,
            'use_after_free': 0.7
        }

        self.mitigation_penalties = {
            'aslr': 0.3,
            'dep': 0.4,
            'stack_canary': 0.3,
            'fortify_source': 0.2,
            'pie': 0.25
        }

    def assess_exploitability(self, crash_info: CrashInfo, debug_info: Dict[str, Any]) -> ExploitabilityAssessment:
        """Assess exploitability of crash"""
        factors = self._identify_exploitability_factors(crash_info, debug_info)
        mitigations = self._detect_mitigations(debug_info)
        attack_vectors = self._identify_attack_vectors(crash_info, factors)

        base_score = self._calculate_base_score(factors)
        mitigation_penalty = self._calculate_mitigation_penalty(mitigations)

        final_score = max(0.0, base_score - mitigation_penalty)
        level = self._determine_exploitability_level(final_score)
        confidence = self._calculate_confidence(factors, debug_info)

        return ExploitabilityAssessment(
            level=level,
            score=final_score,
            factors=factors,
            mitigations=mitigations,
            attack_vectors=attack_vectors,
            confidence=confidence
        )

    def _identify_exploitability_factors(self, crash_info: CrashInfo, debug_info: Dict[str, Any]) -> List[str]:
        """Identify exploitability factors from crash"""
        factors = []

        if crash_info.crash_type == CrashType.SEGMENTATION_FAULT:
            registers = debug_info.get('registers', {})

            if 'rip' in registers and self._is_controllable_value(registers['rip']):
                factors.append('control_pc')

            if 'rsp' in registers and self._is_controllable_value(registers['rsp']):
                factors.append('control_sp')

        elif crash_info.crash_type == CrashType.HEAP_CORRUPTION:
            factors.append('heap_corruption')

        elif crash_info.crash_type == CrashType.USE_AFTER_FREE:
            factors.append('use_after_free')

        elif crash_info.crash_type == CrashType.FORMAT_STRING:
            factors.append('format_string')

        elif crash_info.crash_type == CrashType.BUFFER_OVERFLOW:
            factors.append('stack_corruption')

        if self._has_write_primitive(debug_info):
            factors.append('write_primitive')

        if self._has_info_leak(debug_info):
            factors.append('info_leak')

        return factors

    def _is_controllable_value(self, value: int) -> bool:
        """Check if register value appears controllable"""
        hex_str = f"{value:x}"

        controllable_patterns = [
            '41414141',
            '42424242',
            '43434343',
            '44444444'
        ]

        return any(pattern in hex_str for pattern in controllable_patterns)

    def _has_write_primitive(self, debug_info: Dict[str, Any]) -> bool:
        """Check if crash provides write primitive"""
        crash_info = debug_info.get('crash_info', {})
        signal_info = crash_info.get('signal', '')

        return 'SEGV_ACCERR' in signal_info or 'write' in signal_info.lower()

    def _has_info_leak(self, debug_info: Dict[str, Any]) -> bool:
        """Check if crash provides information leak"""
        return False

    def _detect_mitigations(self, debug_info: Dict[str, Any]) -> List[str]:
        """Detect active security mitigations"""
        mitigations = []

        mappings = debug_info.get('memory_mappings', [])

        for mapping in mappings:
            if 'stack' in mapping.get('path', '').lower():
                if 'x' not in mapping.get('permissions', ''):
                    mitigations.append('dep')

            if '[heap]' in mapping.get('path', ''):
                if mapping.get('start', 0) > 0x100000:
                    mitigations.append('aslr')

        return mitigations

    def _identify_attack_vectors(self, crash_info: CrashInfo, factors: List[str]) -> List[str]:
        """Identify possible attack vectors"""
        vectors = []

        if 'control_pc' in factors:
            vectors.extend(['rop_chain', 'shellcode_injection', 'ret2libc'])

        if 'heap_corruption' in factors:
            vectors.extend(['heap_feng_shui', 'fake_chunk'])

        if 'use_after_free' in factors:
            vectors.extend(['type_confusion', 'vtable_hijack'])

        if 'format_string' in factors:
            vectors.extend(['arbitrary_write', 'stack_leak'])

        return vectors

    def _calculate_base_score(self, factors: List[str]) -> float:
        """Calculate base exploitability score"""
        score = 0.0

        for factor in factors:
            if factor in self.exploitability_factors:
                score += self.exploitability_factors[factor]

        return min(score, 1.0)

    def _calculate_mitigation_penalty(self, mitigations: List[str]) -> float:
        """Calculate penalty for active mitigations"""
        penalty = 0.0

        for mitigation in mitigations:
            if mitigation in self.mitigation_penalties:
                penalty += self.mitigation_penalties[mitigation]

        return min(penalty, 0.8)

    def _determine_exploitability_level(self, score: float) -> ExploitabilityLevel:
        """Determine exploitability level from score"""
        if score >= 0.7:
            return ExploitabilityLevel.HIGH
        elif score >= 0.4:
            return ExploitabilityLevel.MEDIUM
        elif score >= 0.1:
            return ExploitabilityLevel.LOW
        else:
            return ExploitabilityLevel.UNKNOWN

    def _calculate_confidence(self, factors: List[str], debug_info: Dict[str, Any]) -> float:
        """Calculate confidence in exploitability assessment"""
        base_confidence = 0.5

        if debug_info.get('registers'):
            base_confidence += 0.2

        if debug_info.get('stack_trace'):
            base_confidence += 0.2

        if len(factors) > 0:
            base_confidence += 0.1

        return min(base_confidence, 1.0)

class CrashClassifier:
    """Classifies crashes by type and characteristics"""

    def __init__(self):
        self.classification_rules = {
            CrashType.SEGMENTATION_FAULT: self._classify_segfault,
            CrashType.STACK_OVERFLOW: self._classify_stack_overflow,
            CrashType.HEAP_CORRUPTION: self._classify_heap_corruption,
            CrashType.USE_AFTER_FREE: self._classify_use_after_free,
            CrashType.DOUBLE_FREE: self._classify_double_free
        }

    def classify_crash(self, debug_info: Dict[str, Any], input_data: bytes) -> CrashType:
        """Classify crash type from debug information"""
        signal_info = debug_info.get('crash_info', {}).get('signal', '')

        if 'SIGSEGV' in signal_info or 'segmentation fault' in signal_info.lower():
            return self._classify_segfault(debug_info, input_data)

        elif 'SIGABRT' in signal_info:
            return self._classify_abort(debug_info, input_data)

        elif 'stack overflow' in signal_info.lower():
            return CrashType.STACK_OVERFLOW

        elif debug_info.get('exit_code') == -9:
            return CrashType.TIMEOUT

        return CrashType.UNKNOWN

    def _classify_segfault(self, debug_info: Dict[str, Any], input_data: bytes) -> CrashType:
        """Classify segmentation fault subtypes"""
        registers = debug_info.get('registers', {})
        stack_trace = debug_info.get('stack_trace', [])

        if 'rip' in registers:
            rip_value = registers['rip']

            if rip_value < 0x1000:
                return CrashType.NULL_POINTER_DEREFERENCE

            if self._is_controllable_value(rip_value):
                return CrashType.BUFFER_OVERFLOW

        for frame in stack_trace:
            func_name = frame.get('function', '').lower()
            if any(heap_func in func_name for heap_func in ['malloc', 'free', 'realloc']):
                return CrashType.HEAP_CORRUPTION

        return CrashType.SEGMENTATION_FAULT

    def _classify_stack_overflow(self, debug_info: Dict[str, Any], input_data: bytes) -> CrashType:
        """Classify stack overflow"""
        return CrashType.STACK_OVERFLOW

    def _classify_heap_corruption(self, debug_info: Dict[str, Any], input_data: bytes) -> CrashType:
        """Classify heap corruption"""
        return CrashType.HEAP_CORRUPTION

    def _classify_use_after_free(self, debug_info: Dict[str, Any], input_data: bytes) -> CrashType:
        """Classify use-after-free"""
        return CrashType.USE_AFTER_FREE

    def _classify_double_free(self, debug_info: Dict[str, Any], input_data: bytes) -> CrashType:
        """Classify double-free"""
        return CrashType.DOUBLE_FREE

    def _classify_abort(self, debug_info: Dict[str, Any], input_data: bytes) -> CrashType:
        """Classify SIGABRT crashes"""
        stderr = debug_info.get('stderr', '').lower()

        if 'double free' in stderr:
            return CrashType.DOUBLE_FREE
        elif 'heap' in stderr and 'corrupt' in stderr:
            return CrashType.HEAP_CORRUPTION
        elif 'assertion' in stderr:
            return CrashType.ASSERTION_FAILURE

        return CrashType.UNKNOWN

    def _is_controllable_value(self, value: int) -> bool:
        """Check if value appears controllable"""
        hex_str = f"{value:016x}"
        return any(char * 8 in hex_str for char in 'abcdef0123456789')

class CrashAnalyzer:
    """Main crash analysis engine"""

    def __init__(self, work_dir: str = "/tmp/crash_analysis"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)

        self.deduplicator = CrashDeduplicator()
        self.debugger = DebuggerInterface()
        self.exploitability_assessor = ExploitabilityAssessor()
        self.classifier = CrashClassifier()

        self.analyzed_crashes = {}
        self.crash_database = {}

    def analyze_crash(self, binary_path: str, input_file: str,
                     command_args: List[str] = None, target_id: str = None) -> CrashAnalysisResult:
        """Comprehensive crash analysis"""
        logging.info(f"Starting crash analysis for {binary_path} with input {input_file}")

        try:
            with open(input_file, 'rb') as f:
                input_data = f.read()

            input_hash = hashlib.md5(input_data).hexdigest()

            debug_info = self.debugger.analyze_crash_with_gdb(binary_path, input_file, command_args)

            crash_type = self.classifier.classify_crash(debug_info, input_data)

            crash_info = CrashInfo(
                crash_id=f"crash_{int(time.time())}_{input_hash[:8]}",
                target_id=target_id or os.path.basename(binary_path),
                crash_type=crash_type,
                signal=debug_info.get('signal', 0),
                exit_code=debug_info.get('exit_code', 0),
                crash_address=self._extract_crash_address(debug_info),
                instruction_pointer=debug_info.get('registers', {}).get('rip'),
                stack_pointer=debug_info.get('registers', {}).get('rsp'),
                input_file=input_file,
                input_size=len(input_data),
                input_hash=input_hash,
                timestamp=time.time(),
                reproducer_command=self._build_reproducer_command(binary_path, input_file, command_args)
            )

            stack_trace = self._build_stack_trace(debug_info.get('stack_trace', []))
            memory_state = self._build_memory_state(debug_info)

            crash_hash = self.deduplicator.calculate_crash_hash(crash_info, stack_trace)
            duplicate_of = self.deduplicator.find_duplicate(crash_hash)

            if not duplicate_of:
                self.deduplicator.register_crash(crash_hash, crash_info.crash_id)

            exploitability = self.exploitability_assessor.assess_exploitability(crash_info, debug_info)

            root_cause = self._determine_root_cause(crash_info, stack_trace, debug_info)
            severity = self._assess_severity(exploitability, crash_type)

            result = CrashAnalysisResult(
                crash_info=crash_info,
                stack_trace=stack_trace,
                memory_state=memory_state,
                exploitability=exploitability,
                root_cause=root_cause,
                severity=severity,
                duplicate_of=duplicate_of,
                minimized_input=None,
                analysis_metadata={
                    'analysis_time': time.time(),
                    'debug_method': 'gdb' if debug_info and 'error' not in debug_info else 'basic',
                    'crash_hash': crash_hash
                }
            )

            self.analyzed_crashes[crash_info.crash_id] = result
            self.crash_database[crash_hash] = result

            logging.info(f"Crash analysis completed: {crash_info.crash_id}")
            return result

        except Exception as e:
            logging.error(f"Crash analysis failed: {e}")
            return self._create_error_result(e, binary_path, input_file)

    def _extract_crash_address(self, debug_info: Dict[str, Any]) -> Optional[int]:
        """Extract crash address from debug info"""
        signal_info = debug_info.get('crash_info', {}).get('signal', '')

        match = re.search(r'address (0x[0-9a-fA-F]+)', signal_info)
        if match:
            return int(match.group(1), 16)

        return None

    def _build_reproducer_command(self, binary_path: str, input_file: str, command_args: List[str]) -> List[str]:
        """Build command to reproduce crash"""
        cmd = [binary_path]
        if command_args:
            cmd.extend(command_args)
        cmd.extend(['<', input_file])
        return cmd

    def _build_stack_trace(self, stack_frames: List[Dict[str, Any]]) -> Optional[StackTrace]:
        """Build stack trace from debug info"""
        if not stack_frames:
            return None

        crash_frame_index = 0
        for i, frame in enumerate(stack_frames):
            if frame.get('function') != '??':
                crash_frame_index = i
                break

        return StackTrace(
            frames=stack_frames,
            crash_frame_index=crash_frame_index,
            total_frames=len(stack_frames),
            truncated=len(stack_frames) >= 50
        )

    def _build_memory_state(self, debug_info: Dict[str, Any]) -> Optional[MemoryState]:
        """Build memory state from debug info"""
        registers = debug_info.get('registers', {})
        mappings = debug_info.get('memory_mappings', [])

        if not registers and not mappings:
            return None

        return MemoryState(
            registers=registers,
            memory_mappings=mappings,
            heap_info=None,
            stack_info=None
        )

    def _determine_root_cause(self, crash_info: CrashInfo, stack_trace: Optional[StackTrace],
                            debug_info: Dict[str, Any]) -> str:
        """Determine root cause of crash"""
        if crash_info.crash_type == CrashType.NULL_POINTER_DEREFERENCE:
            return "Null pointer dereference - missing input validation"

        elif crash_info.crash_type == CrashType.BUFFER_OVERFLOW:
            if stack_trace and stack_trace.frames:
                func = stack_trace.frames[stack_trace.crash_frame_index].get('function', '??')
                return f"Buffer overflow in function {func} - insufficient bounds checking"

        elif crash_info.crash_type == CrashType.USE_AFTER_FREE:
            return "Use-after-free vulnerability - object accessed after deallocation"

        elif crash_info.crash_type == CrashType.DOUBLE_FREE:
            return "Double-free vulnerability - memory freed multiple times"

        return f"Unknown root cause for {crash_info.crash_type.value}"

    def _assess_severity(self, exploitability: ExploitabilityAssessment, crash_type: CrashType) -> str:
        """Assess crash severity"""
        if exploitability.level == ExploitabilityLevel.HIGH:
            return "critical"
        elif exploitability.level == ExploitabilityLevel.MEDIUM:
            return "high"
        elif exploitability.level == ExploitabilityLevel.LOW:
            return "medium"
        else:
            return "low"

    def _create_error_result(self, error: Exception, binary_path: str, input_file: str) -> CrashAnalysisResult:
        """Create error result when analysis fails"""
        crash_info = CrashInfo(
            crash_id=f"error_{int(time.time())}",
            target_id=os.path.basename(binary_path),
            crash_type=CrashType.UNKNOWN,
            signal=0,
            exit_code=-1,
            crash_address=None,
            instruction_pointer=None,
            stack_pointer=None,
            input_file=input_file,
            input_size=0,
            input_hash="unknown",
            timestamp=time.time(),
            reproducer_command=[binary_path, input_file],
            metadata={'error': str(error)}
        )

        exploitability = ExploitabilityAssessment(
            level=ExploitabilityLevel.UNKNOWN,
            score=0.0,
            factors=[],
            mitigations=[],
            attack_vectors=[],
            confidence=0.0
        )

        return CrashAnalysisResult(
            crash_info=crash_info,
            stack_trace=None,
            memory_state=None,
            exploitability=exploitability,
            root_cause=f"Analysis failed: {error}",
            severity="unknown",
            duplicate_of=None,
            minimized_input=None,
            analysis_metadata={'analysis_error': str(error)}
        )

    def batch_analyze_crashes(self, crash_files: List[Tuple[str, str]], binary_path: str,
                            command_args: List[str] = None) -> List[CrashAnalysisResult]:
        """Analyze multiple crashes in batch"""
        results = []

        for crash_id, input_file in crash_files:
            try:
                result = self.analyze_crash(binary_path, input_file, command_args, crash_id)
                results.append(result)
            except Exception as e:
                logging.error(f"Failed to analyze crash {crash_id}: {e}")

        return results

    def generate_crash_report(self, crash_id: str) -> str:
        """Generate comprehensive crash report"""
        if crash_id not in self.analyzed_crashes:
            return f"Crash {crash_id} not found"

        result = self.analyzed_crashes[crash_id]
        crash = result.crash_info

        report = []
        report.append(f"Crash Analysis Report: {crash_id}")
        report.append("=" * 50)
        report.append(f"Target: {crash.target_id}")
        report.append(f"Crash Type: {crash.crash_type.value}")
        report.append(f"Signal: {crash.signal}")
        report.append(f"Severity: {result.severity}")
        report.append(f"Root Cause: {result.root_cause}")
        report.append("")

        report.append("Exploitability Assessment:")
        exp = result.exploitability
        report.append(f"  Level: {exp.level.value}")
        report.append(f"  Score: {exp.score:.2f}")
        report.append(f"  Confidence: {exp.confidence:.2f}")

        if exp.factors:
            report.append(f"  Factors: {', '.join(exp.factors)}")

        if exp.attack_vectors:
            report.append(f"  Attack Vectors: {', '.join(exp.attack_vectors)}")

        if exp.mitigations:
            report.append(f"  Mitigations: {', '.join(exp.mitigations)}")

        report.append("")

        if result.stack_trace:
            st = result.stack_trace
            report.append(f"Stack Trace ({st.total_frames} frames):")
            for i, frame in enumerate(st.frames[:10]):
                indicator = "=> " if i == st.crash_frame_index else "   "
                report.append(f"{indicator}#{frame.get('frame_number', i)}: {frame.get('function', '??')} at 0x{frame.get('address', 0):x}")

        if result.memory_state and result.memory_state.registers:
            report.append("")
            report.append("Registers:")
            for reg, value in result.memory_state.registers.items():
                report.append(f"  {reg}: 0x{value:x}")

        report.append("")
        report.append(f"Input File: {crash.input_file}")
        report.append(f"Input Size: {crash.input_size} bytes")
        report.append(f"Input Hash: {crash.input_hash}")

        if result.duplicate_of:
            report.append(f"Duplicate of: {result.duplicate_of}")

        return "\n".join(report)