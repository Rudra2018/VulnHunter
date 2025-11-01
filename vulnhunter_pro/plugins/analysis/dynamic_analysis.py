#!/usr/bin/env python3
"""
Advanced Fuzzing and Dynamic Analysis Plugin
===========================================

Implements comprehensive dynamic analysis including fuzzing, runtime tracing,
and memory analysis following the VulnHunter MathCore architecture.
"""

import os
import sys
import subprocess
import tempfile
import threading
import time
import signal
import json
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import logging

# Core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.plugin_manager import BasePlugin
from core.vulnerability import Vulnerability, VulnType, VulnSeverity, Location, ProofOfConcept

# Fuzzing and dynamic analysis libraries
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

logger = logging.getLogger(__name__)

class DynamicAnalysisPlugin(BasePlugin):
    """Advanced dynamic analysis and fuzzing plugin"""

    def __init__(self):
        super().__init__()
        self.name = "DynamicAnalysisPlugin"
        self.version = "3.0.0"

        # Fuzzing configuration
        self.fuzz_timeout = 30  # seconds
        self.max_iterations = 1000
        self.crash_detection_enabled = True

        # Available fuzzers
        self.fuzzers = self._detect_available_fuzzers()

        # Runtime tracers
        self.tracers = self._initialize_tracers()

    def _detect_available_fuzzers(self) -> Dict[str, bool]:
        """Detect available fuzzing tools"""
        fuzzers = {}

        # Check for AFL++
        try:
            result = subprocess.run(['afl-fuzz'], capture_output=True, timeout=2)
            fuzzers['afl++'] = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            fuzzers['afl++'] = False

        # Check for libFuzzer (through clang)
        try:
            result = subprocess.run(['clang', '--version'], capture_output=True, timeout=2)
            fuzzers['libfuzzer'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            fuzzers['libfuzzer'] = False

        # Check for Honggfuzz
        try:
            result = subprocess.run(['honggfuzz', '--help'], capture_output=True, timeout=2)
            fuzzers['honggfuzz'] = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            fuzzers['honggfuzz'] = False

        # Check for Python fuzzing libraries
        try:
            import hypothesis
            fuzzers['hypothesis'] = True
        except ImportError:
            fuzzers['hypothesis'] = False

        logger.info(f"Available fuzzers: {[k for k, v in fuzzers.items() if v]}")
        return fuzzers

    def _initialize_tracers(self) -> Dict[str, Any]:
        """Initialize runtime tracers"""
        tracers = {}

        # Frida dynamic instrumentation
        if FRIDA_AVAILABLE:
            tracers['frida'] = {
                'available': True,
                'script_templates': self._load_frida_scripts()
            }

        # Valgrind memory analysis
        try:
            result = subprocess.run(['valgrind', '--version'], capture_output=True, timeout=5)
            tracers['valgrind'] = {'available': result.returncode == 0}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tracers['valgrind'] = {'available': False}

        # Strace system call tracing
        try:
            result = subprocess.run(['strace', '-V'], capture_output=True, timeout=5)
            tracers['strace'] = {'available': result.returncode == 0}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tracers['strace'] = {'available': False}

        return tracers

    def _load_frida_scripts(self) -> Dict[str, str]:
        """Load Frida instrumentation scripts"""
        scripts = {
            'memory_corruption': '''
Java.perform(function() {
    // Hook dangerous C functions
    const strcpy = Module.findExportByName(null, "strcpy");
    if (strcpy) {
        Interceptor.attach(strcpy, {
            onEnter: function(args) {
                const dest = args[0];
                const src = args[1];
                const srcStr = src.readCString();

                send({
                    type: "dangerous_call",
                    function: "strcpy",
                    dest: dest,
                    src: srcStr,
                    src_length: srcStr ? srcStr.length : 0
                });

                // Basic overflow detection
                if (srcStr && srcStr.length > 100) {
                    send({
                        type: "potential_overflow",
                        function: "strcpy",
                        length: srcStr.length
                    });
                }
            }
        });
    }

    // Hook malloc/free for use-after-free detection
    const malloc = Module.findExportByName(null, "malloc");
    const free = Module.findExportByName(null, "free");
    const allocations = new Map();

    if (malloc) {
        Interceptor.attach(malloc, {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    allocations.set(retval.toString(), {
                        allocated: true,
                        size: this.context.rdi // Size argument (x64)
                    });
                }
            }
        });
    }

    if (free) {
        Interceptor.attach(free, {
            onEnter: function(args) {
                const ptr = args[0].toString();
                if (allocations.has(ptr)) {
                    const info = allocations.get(ptr);
                    if (!info.allocated) {
                        send({
                            type: "double_free",
                            pointer: ptr
                        });
                    } else {
                        info.allocated = false;
                        allocations.set(ptr, info);
                    }
                } else {
                    send({
                        type: "free_unallocated",
                        pointer: ptr
                    });
                }
            }
        });
    }
});
''',

            'sql_injection_runtime': '''
Java.perform(function() {
    // Hook database operations
    const sqlite3_exec = Module.findExportByName(null, "sqlite3_exec");
    if (sqlite3_exec) {
        Interceptor.attach(sqlite3_exec, {
            onEnter: function(args) {
                const sql = args[1].readCString();
                send({
                    type: "sql_execution",
                    query: sql
                });

                // Check for SQL injection patterns
                const dangerous_patterns = [
                    "' OR '1'='1",
                    "'; DROP",
                    "UNION SELECT",
                    "-- ",
                    "/*"
                ];

                for (const pattern of dangerous_patterns) {
                    if (sql.includes(pattern)) {
                        send({
                            type: "sql_injection_detected",
                            query: sql,
                            pattern: pattern
                        });
                    }
                }
            }
        });
    }
});
''',

            'command_injection_runtime': '''
Java.perform(function() {
    // Hook system command execution
    const system = Module.findExportByName(null, "system");
    if (system) {
        Interceptor.attach(system, {
            onEnter: function(args) {
                const command = args[0].readCString();
                send({
                    type: "system_command",
                    command: command
                });

                // Check for command injection
                const dangerous_chars = [';', '|', '&', '$', '`'];
                for (const char of dangerous_chars) {
                    if (command.includes(char)) {
                        send({
                            type: "command_injection_detected",
                            command: command,
                            dangerous_char: char
                        });
                    }
                }
            }
        });
    }

    // Hook popen
    const popen = Module.findExportByName(null, "popen");
    if (popen) {
        Interceptor.attach(popen, {
            onEnter: function(args) {
                const command = args[0].readCString();
                send({
                    type: "popen_command",
                    command: command
                });
            }
        });
    }
});
'''
        }

        return scripts

    @property
    def supported_file_types(self) -> List[str]:
        return ['.py', '.c', '.cpp', '.java', '.js', '.exe', '.elf', '.bin']

    def is_applicable(self, file_path: str, content: Any) -> bool:
        """Check if dynamic analysis is applicable"""
        path = Path(file_path)

        # Applicable to executables and source code
        if path.suffix.lower() in self.supported_file_types:
            return True

        # Check if file is executable
        if os.access(file_path, os.X_OK):
            return True

        return False

    def analyze(self, file_path: str, content: Any, context: Dict[str, Any]) -> List[Vulnerability]:
        """Main dynamic analysis method"""
        vulnerabilities = []

        try:
            file_extension = Path(file_path).suffix.lower()

            # Choose analysis method based on file type
            if file_extension in ['.exe', '.elf', '.bin'] or os.access(file_path, os.X_OK):
                # Binary dynamic analysis
                vulnerabilities.extend(self._analyze_binary_dynamically(file_path))

            elif file_extension in ['.py', '.js']:
                # Script dynamic analysis
                vulnerabilities.extend(self._analyze_script_dynamically(file_path, content))

            elif file_extension in ['.c', '.cpp']:
                # Source code fuzzing
                vulnerabilities.extend(self._fuzz_source_code(file_path, content))

            # Runtime vulnerability detection
            vulnerabilities.extend(self._runtime_vulnerability_detection(file_path))

        except Exception as e:
            logger.error(f"Dynamic analysis failed for {file_path}: {e}")

            vuln = Vulnerability(
                vuln_type=VulnType.UNKNOWN,
                severity=VulnSeverity.LOW,
                location=Location(file_path, 0),
                title="Dynamic Analysis Error",
                description=f"Dynamic analysis failed: {str(e)}",
                detection_method="dynamic_analysis_error"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_binary_dynamically(self, binary_path: str) -> List[Vulnerability]:
        """Dynamic analysis of binary executables"""
        vulnerabilities = []

        try:
            # Frida-based runtime analysis
            if FRIDA_AVAILABLE:
                vulnerabilities.extend(self._frida_binary_analysis(binary_path))

            # Valgrind memory analysis
            if self.tracers.get('valgrind', {}).get('available'):
                vulnerabilities.extend(self._valgrind_analysis(binary_path))

            # Basic fuzzing
            vulnerabilities.extend(self._basic_binary_fuzzing(binary_path))

        except Exception as e:
            logger.error(f"Binary dynamic analysis failed: {e}")

        return vulnerabilities

    def _frida_binary_analysis(self, binary_path: str) -> List[Vulnerability]:
        """Frida-based dynamic instrumentation"""
        vulnerabilities = []

        try:
            if not FRIDA_AVAILABLE:
                return vulnerabilities

            # Start target process
            pid = frida.spawn([binary_path])
            session = frida.attach(pid)

            # Load memory corruption detection script
            script_code = self.tracers['frida']['script_templates']['memory_corruption']
            script = session.create_script(script_code)

            detected_issues = []

            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    detected_issues.append(payload)

            script.on('message', on_message)
            script.load()

            # Resume and run for analysis period
            frida.resume(pid)
            time.sleep(5)  # Run for 5 seconds

            # Process detected issues
            for issue in detected_issues:
                if issue['type'] == 'potential_overflow':
                    vuln = Vulnerability(
                        vuln_type=VulnType.BUFFER_OVERFLOW,
                        severity=VulnSeverity.HIGH,
                        location=Location(binary_path, 0),
                        title="Potential Buffer Overflow (Runtime)",
                        description=f"Runtime detection of potential overflow in {issue['function']}",
                        technical_details=f"String length: {issue['length']}",
                        confidence=0.8,
                        detection_method="frida_runtime_analysis"
                    )
                    vulnerabilities.append(vuln)

                elif issue['type'] == 'double_free':
                    vuln = Vulnerability(
                        vuln_type=VulnType.DOUBLE_FREE,
                        severity=VulnSeverity.CRITICAL,
                        location=Location(binary_path, 0),
                        title="Double Free (Runtime)",
                        description=f"Runtime detection of double free: {issue['pointer']}",
                        confidence=0.95,
                        detection_method="frida_runtime_analysis"
                    )
                    vulnerabilities.append(vuln)

            # Cleanup
            session.detach()

        except Exception as e:
            logger.error(f"Frida analysis failed: {e}")

        return vulnerabilities

    def _valgrind_analysis(self, binary_path: str) -> List[Vulnerability]:
        """Valgrind memory error detection"""
        vulnerabilities = []

        try:
            # Run valgrind
            cmd = [
                'valgrind',
                '--tool=memcheck',
                '--leak-check=full',
                '--show-leak-kinds=all',
                '--track-origins=yes',
                '--xml=yes',
                '--xml-file=/tmp/valgrind_output.xml',
                binary_path
            ]

            result = subprocess.run(cmd, capture_output=True, timeout=30, text=True)

            # Parse valgrind output
            if os.path.exists('/tmp/valgrind_output.xml'):
                vulns = self._parse_valgrind_output('/tmp/valgrind_output.xml', binary_path)
                vulnerabilities.extend(vulns)

        except subprocess.TimeoutExpired:
            logger.warning("Valgrind analysis timed out")
        except Exception as e:
            logger.error(f"Valgrind analysis failed: {e}")

        return vulnerabilities

    def _parse_valgrind_output(self, xml_file: str, binary_path: str) -> List[Vulnerability]:
        """Parse Valgrind XML output"""
        vulnerabilities = []

        try:
            with open(xml_file, 'r') as f:
                content = f.read()

            # Simple parsing for common errors
            if 'Invalid read' in content:
                vuln = Vulnerability(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    severity=VulnSeverity.HIGH,
                    location=Location(binary_path, 0),
                    title="Invalid Memory Read (Valgrind)",
                    description="Valgrind detected invalid memory read",
                    confidence=0.9,
                    detection_method="valgrind_memcheck"
                )
                vulnerabilities.append(vuln)

            if 'Invalid write' in content:
                vuln = Vulnerability(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    severity=VulnSeverity.CRITICAL,
                    location=Location(binary_path, 0),
                    title="Invalid Memory Write (Valgrind)",
                    description="Valgrind detected invalid memory write",
                    confidence=0.9,
                    detection_method="valgrind_memcheck"
                )
                vulnerabilities.append(vuln)

            if 'definitely lost' in content:
                vuln = Vulnerability(
                    vuln_type=VulnType.MEMORY_LEAK,
                    severity=VulnSeverity.MEDIUM,
                    location=Location(binary_path, 0),
                    title="Memory Leak (Valgrind)",
                    description="Valgrind detected memory leak",
                    confidence=0.85,
                    detection_method="valgrind_memcheck"
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"Failed to parse Valgrind output: {e}")

        return vulnerabilities

    def _basic_binary_fuzzing(self, binary_path: str) -> List[Vulnerability]:
        """Basic fuzzing of binary executable"""
        vulnerabilities = []

        try:
            # Generate test inputs
            test_inputs = self._generate_fuzz_inputs()

            crashes_detected = 0
            for i, test_input in enumerate(test_inputs[:50]):  # Limit iterations

                try:
                    # Run binary with fuzzed input
                    proc = subprocess.Popen(
                        [binary_path],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )

                    stdout, stderr = proc.communicate(input=test_input, timeout=5)

                    # Check for crash
                    if proc.returncode < 0:  # Killed by signal
                        crashes_detected += 1

                        vuln = Vulnerability(
                            vuln_type=VulnType.CRASH,
                            severity=VulnSeverity.HIGH,
                            location=Location(binary_path, 0),
                            title=f"Crash During Fuzzing (Signal {abs(proc.returncode)})",
                            description=f"Binary crashed with signal {abs(proc.returncode)} during fuzzing",
                            technical_details=f"Input length: {len(test_input)}, Iteration: {i}",
                            confidence=0.8,
                            detection_method="basic_fuzzing"
                        )
                        vulnerabilities.append(vuln)

                except subprocess.TimeoutExpired:
                    # Potential infinite loop or hang
                    vuln = Vulnerability(
                        vuln_type=VulnType.INFINITE_LOOP,
                        severity=VulnSeverity.MEDIUM,
                        location=Location(binary_path, 0),
                        title="Timeout During Fuzzing",
                        description="Binary timed out during fuzzing, possible infinite loop",
                        confidence=0.6,
                        detection_method="basic_fuzzing"
                    )
                    vulnerabilities.append(vuln)

                except Exception:
                    continue

            if crashes_detected > 3:
                # High crash rate indicates instability
                vuln = Vulnerability(
                    vuln_type=VulnType.UNSTABLE_CODE,
                    severity=VulnSeverity.HIGH,
                    location=Location(binary_path, 0),
                    title="High Crash Rate During Fuzzing",
                    description=f"Binary crashed {crashes_detected} times during fuzzing",
                    confidence=0.85,
                    detection_method="fuzzing_stability_analysis"
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"Binary fuzzing failed: {e}")

        return vulnerabilities

    def _generate_fuzz_inputs(self) -> List[bytes]:
        """Generate fuzzing test inputs"""
        inputs = []

        # Buffer overflow patterns
        for size in [100, 1000, 10000]:
            inputs.append(b'A' * size)
            inputs.append(b'A' * size + b'\x00')

        # Format string patterns
        inputs.extend([
            b'%x%x%x%x',
            b'%s%s%s%s',
            b'%n%n%n%n',
            b'%p%p%p%p'
        ])

        # NULL bytes and special characters
        inputs.extend([
            b'\x00' * 100,
            b'\xff' * 100,
            b'\x41\x00\x42',
            b'../../../etc/passwd',
            b'"; rm -rf / #'
        ])

        # Random data
        import random
        for _ in range(10):
            size = random.randint(1, 1000)
            data = bytes([random.randint(0, 255) for _ in range(size)])
            inputs.append(data)

        return inputs

    def _analyze_script_dynamically(self, script_path: str, content: Any) -> List[Vulnerability]:
        """Dynamic analysis of script files"""
        vulnerabilities = []

        try:
            if Path(script_path).suffix.lower() == '.py':
                vulnerabilities.extend(self._python_dynamic_analysis(script_path))

        except Exception as e:
            logger.error(f"Script dynamic analysis failed: {e}")

        return vulnerabilities

    def _python_dynamic_analysis(self, python_file: str) -> List[Vulnerability]:
        """Dynamic analysis of Python scripts"""
        vulnerabilities = []

        try:
            # Create instrumented version for monitoring
            instrumented_code = self._instrument_python_code(python_file)

            # Execute with monitoring
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(instrumented_code)
                temp_file = f.name

            # Run instrumented code
            result = subprocess.run(
                ['python3', temp_file],
                capture_output=True,
                timeout=10,
                text=True
            )

            # Parse monitoring output
            if result.stderr:
                vulnerabilities.extend(self._parse_python_monitoring_output(
                    result.stderr, python_file
                ))

            # Cleanup
            os.unlink(temp_file)

        except Exception as e:
            logger.error(f"Python dynamic analysis failed: {e}")

        return vulnerabilities

    def _instrument_python_code(self, python_file: str) -> str:
        """Instrument Python code for runtime monitoring"""
        with open(python_file, 'r') as f:
            original_code = f.read()

        # Add monitoring hooks
        instrumented = '''
import sys
import warnings

# Hook dangerous functions
original_eval = eval
original_exec = exec

def monitored_eval(expression):
    print(f"VULN_MONITOR: eval() called with: {expression}", file=sys.stderr)
    return original_eval(expression)

def monitored_exec(code):
    print(f"VULN_MONITOR: exec() called with: {code}", file=sys.stderr)
    return original_exec(code)

# Replace dangerous functions
eval = monitored_eval
exec = monitored_exec

# Monitor SQL-like operations
import sqlite3
original_execute = sqlite3.Cursor.execute

def monitored_execute(self, sql, parameters=()):
    print(f"VULN_MONITOR: SQL execute: {sql}", file=sys.stderr)
    return original_execute(self, sql, parameters)

sqlite3.Cursor.execute = monitored_execute

''' + original_code

        return instrumented

    def _parse_python_monitoring_output(self, stderr_output: str, python_file: str) -> List[Vulnerability]:
        """Parse Python monitoring output for vulnerabilities"""
        vulnerabilities = []

        lines = stderr_output.split('\n')
        for line in lines:
            if 'VULN_MONITOR:' in line:
                if 'eval()' in line:
                    vuln = Vulnerability(
                        vuln_type=VulnType.CODE_INJECTION,
                        severity=VulnSeverity.CRITICAL,
                        location=Location(python_file, 0),
                        title="Runtime eval() Usage Detected",
                        description="Dynamic analysis detected eval() usage at runtime",
                        technical_details=line,
                        confidence=0.9,
                        detection_method="python_runtime_monitoring"
                    )
                    vulnerabilities.append(vuln)

                elif 'exec()' in line:
                    vuln = Vulnerability(
                        vuln_type=VulnType.CODE_INJECTION,
                        severity=VulnSeverity.CRITICAL,
                        location=Location(python_file, 0),
                        title="Runtime exec() Usage Detected",
                        description="Dynamic analysis detected exec() usage at runtime",
                        technical_details=line,
                        confidence=0.9,
                        detection_method="python_runtime_monitoring"
                    )
                    vulnerabilities.append(vuln)

                elif 'SQL execute:' in line:
                    # Check for SQL injection patterns
                    sql_query = line.split('SQL execute:')[1].strip()
                    if any(pattern in sql_query.lower() for pattern in ["'", '"', ' or ', ' union ']):
                        vuln = Vulnerability(
                            vuln_type=VulnType.SQL_INJECTION,
                            severity=VulnSeverity.CRITICAL,
                            location=Location(python_file, 0),
                            title="Runtime SQL Injection Pattern",
                            description="Dynamic analysis detected potential SQL injection pattern",
                            technical_details=sql_query,
                            confidence=0.7,
                            detection_method="python_sql_monitoring"
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _fuzz_source_code(self, source_file: str, content: Any) -> List[Vulnerability]:
        """Fuzz source code by compiling and testing"""
        vulnerabilities = []

        try:
            file_ext = Path(source_file).suffix.lower()

            if file_ext in ['.c', '.cpp']:
                vulnerabilities.extend(self._fuzz_c_source(source_file))

        except Exception as e:
            logger.error(f"Source code fuzzing failed: {e}")

        return vulnerabilities

    def _fuzz_c_source(self, c_file: str) -> List[Vulnerability]:
        """Fuzz C source code"""
        vulnerabilities = []

        try:
            # Compile with fuzzing instrumentation
            binary_path = '/tmp/fuzz_target'
            compile_cmd = [
                'gcc',
                '-fsanitize=address',  # AddressSanitizer
                '-fsanitize=undefined',  # UBSan
                '-g',
                '-o', binary_path,
                c_file
            ]

            result = subprocess.run(compile_cmd, capture_output=True, timeout=30)

            if result.returncode == 0 and os.path.exists(binary_path):
                # Run fuzzing on compiled binary
                fuzz_results = self._basic_binary_fuzzing(binary_path)
                vulnerabilities.extend(fuzz_results)

                # Cleanup
                os.remove(binary_path)

        except Exception as e:
            logger.error(f"C source fuzzing failed: {e}")

        return vulnerabilities

    def _runtime_vulnerability_detection(self, file_path: str) -> List[Vulnerability]:
        """General runtime vulnerability detection"""
        vulnerabilities = []

        try:
            # System call tracing
            if self.tracers.get('strace', {}).get('available'):
                vulnerabilities.extend(self._strace_analysis(file_path))

        except Exception as e:
            logger.error(f"Runtime vulnerability detection failed: {e}")

        return vulnerabilities

    def _strace_analysis(self, file_path: str) -> List[Vulnerability]:
        """System call tracing analysis"""
        vulnerabilities = []

        try:
            # Run with strace
            cmd = ['strace', '-o', '/tmp/strace_output', '-e', 'trace=all', file_path]
            result = subprocess.run(cmd, capture_output=True, timeout=10)

            if os.path.exists('/tmp/strace_output'):
                with open('/tmp/strace_output', 'r') as f:
                    strace_output = f.read()

                # Analyze system calls for suspicious patterns
                if 'execve(' in strace_output and '"/bin/sh"' in strace_output:
                    vuln = Vulnerability(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        severity=VulnSeverity.HIGH,
                        location=Location(file_path, 0),
                        title="Shell Execution Detected (strace)",
                        description="System call tracing detected shell execution",
                        confidence=0.8,
                        detection_method="strace_analysis"
                    )
                    vulnerabilities.append(vuln)

                # Check for file access patterns
                if '../' in strace_output and 'openat(' in strace_output:
                    vuln = Vulnerability(
                        vuln_type=VulnType.PATH_TRAVERSAL,
                        severity=VulnSeverity.MEDIUM,
                        location=Location(file_path, 0),
                        title="Path Traversal Pattern (strace)",
                        description="System call tracing detected path traversal pattern",
                        confidence=0.7,
                        detection_method="strace_analysis"
                    )
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"strace analysis failed: {e}")

        return vulnerabilities

def main():
    """Test dynamic analysis plugin"""
    plugin = DynamicAnalysisPlugin()

    # Test on a simple C program
    test_c_code = '''
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[100];
    char input[1000];

    printf("Enter input: ");
    gets(input);  // Vulnerable function
    strcpy(buffer, input);  // Buffer overflow

    printf("You entered: %s\\n", buffer);
    return 0;
}
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(test_c_code)
        test_file = f.name

    print("🔬 Testing Dynamic Analysis Plugin")
    vulnerabilities = plugin.analyze(test_file, test_c_code, {})

    print(f"Found {len(vulnerabilities)} vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln.title} ({vuln.severity.value})")

    # Cleanup
    os.unlink(test_file)

if __name__ == "__main__":
    main()