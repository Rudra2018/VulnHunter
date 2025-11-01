#!/usr/bin/env python3
"""
Binary Analysis Plugin for VulnHunter Professional
=================================================

Comprehensive binary reverse engineering and vulnerability detection following the
MathCore architecture. Supports ELF, PE, Mach-O, firmware, and mobile applications.
"""

import os
import sys
import subprocess
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json
import tempfile

# Core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.plugin_manager import BasePlugin
from core.vulnerability import Vulnerability, VulnType, VulnSeverity, Location, ProofOfConcept
from mathcore.topology.persistent_homology import detect_loops, cfg_to_distance_matrix
from mathcore.logic.formal_verification import Z3Verifier

# Binary analysis libraries
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

logger = logging.getLogger(__name__)

class BinaryAnalysisPlugin(BasePlugin):
    """Advanced binary analysis and reverse engineering plugin"""

    def __init__(self):
        super().__init__()
        self.name = "BinaryAnalysisPlugin"
        self.version = "3.0.0"
        self.z3_verifier = Z3Verifier()

        # Binary format support
        self.supported_formats = ['.exe', '.dll', '.so', '.dylib', '.bin', '.elf', '.o', '.ko']

        # Initialize disassemblers
        self.disassemblers = self._initialize_disassemblers()

        # Ghidra bridge setup (if available)
        self.ghidra_available = self._check_ghidra_availability()

    def _initialize_disassemblers(self) -> Dict[str, Any]:
        """Initialize available disassemblers"""
        disassemblers = {}

        if CAPSTONE_AVAILABLE:
            disassemblers['capstone'] = {
                'x86_64': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                'x86_32': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                'arm64': capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
                'arm': capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            }

        return disassemblers

    def _check_ghidra_availability(self) -> bool:
        """Check if Ghidra is available for headless analysis"""
        try:
            result = subprocess.run(['ghidra', '--version'],
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @property
    def supported_file_types(self) -> List[str]:
        return self.supported_formats

    def is_applicable(self, file_path: str, content: bytes) -> bool:
        """Check if this plugin should analyze the given binary file"""
        path = Path(file_path)

        # Check by extension
        if path.suffix.lower() in self.supported_formats:
            return True

        # Check by file magic
        if isinstance(content, bytes):
            return self._is_binary_format(content)

        return False

    def _is_binary_format(self, content: bytes) -> bool:
        """Detect binary format by magic bytes"""
        if len(content) < 4:
            return False

        # ELF magic
        if content.startswith(b'\x7fELF'):
            return True

        # PE magic
        if content.startswith(b'MZ'):
            return True

        # Mach-O magic
        if content[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                          b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            return True

        return False

    def analyze(self, file_path: str, content: bytes, context: Dict[str, Any]) -> List[Vulnerability]:
        """Main binary analysis method"""
        vulnerabilities = []

        try:
            # Binary format detection and parsing
            binary_info = self._parse_binary_format(file_path, content)

            # Control flow graph recovery
            cfg = self._recover_control_flow_graph(file_path, binary_info)

            # Multiple analysis layers
            vulnerabilities.extend(self._analyze_binary_structure(file_path, binary_info))
            vulnerabilities.extend(self._analyze_control_flow(file_path, cfg))
            vulnerabilities.extend(self._analyze_with_symbolic_execution(file_path, binary_info))
            vulnerabilities.extend(self._analyze_crypto_usage(file_path, binary_info))
            vulnerabilities.extend(self._analyze_memory_safety(file_path, binary_info))

            # Advanced mathematical analysis
            if cfg and NETWORKX_AVAILABLE:
                vulnerabilities.extend(self._analyze_with_topology(file_path, cfg))

        except Exception as e:
            logger.error(f"Binary analysis failed for {file_path}: {e}")

            # Create analysis error vulnerability
            vuln = Vulnerability(
                vuln_type=VulnType.UNKNOWN,
                severity=VulnSeverity.LOW,
                location=Location(file_path, 0),
                title="Binary Analysis Error",
                description=f"Failed to analyze binary: {str(e)}",
                detection_method="binary_analysis_error"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _parse_binary_format(self, file_path: str, content: bytes) -> Dict[str, Any]:
        """Parse binary format and extract metadata"""
        binary_info = {
            'format': 'unknown',
            'architecture': 'unknown',
            'entry_point': 0,
            'sections': [],
            'imports': [],
            'exports': [],
            'strings': [],
            'file_path': file_path
        }

        try:
            if LIEF_AVAILABLE:
                binary = lief.parse(file_path)
                if binary:
                    binary_info.update({
                        'format': binary.format.name if hasattr(binary.format, 'name') else str(binary.format),
                        'architecture': self._get_architecture(binary),
                        'entry_point': getattr(binary, 'entrypoint', 0),
                        'sections': self._extract_sections(binary),
                        'imports': self._extract_imports(binary),
                        'exports': self._extract_exports(binary)
                    })

            # Extract strings using basic analysis
            binary_info['strings'] = self._extract_strings(content)

        except Exception as e:
            logger.warning(f"Failed to parse binary format: {e}")

        return binary_info

    def _get_architecture(self, binary) -> str:
        """Extract architecture information from binary"""
        try:
            if hasattr(binary, 'header') and hasattr(binary.header, 'machine_type'):
                return str(binary.header.machine_type)
            elif hasattr(binary, 'header') and hasattr(binary.header, 'cpu_type'):
                return str(binary.header.cpu_type)
            else:
                return 'unknown'
        except Exception:
            return 'unknown'

    def _extract_sections(self, binary) -> List[Dict[str, Any]]:
        """Extract section information"""
        sections = []
        try:
            if hasattr(binary, 'sections'):
                for section in binary.sections:
                    sections.append({
                        'name': getattr(section, 'name', ''),
                        'virtual_address': getattr(section, 'virtual_address', 0),
                        'size': getattr(section, 'size', 0),
                        'flags': self._get_section_flags(section)
                    })
        except Exception as e:
            logger.debug(f"Failed to extract sections: {e}")
        return sections

    def _get_section_flags(self, section) -> List[str]:
        """Extract section flags"""
        flags = []
        try:
            if hasattr(section, 'characteristics'):
                # PE format
                if section.characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    flags.append('EXECUTE')
                if section.characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
                    flags.append('READ')
                if section.characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                    flags.append('WRITE')
            elif hasattr(section, 'flags'):
                # ELF format
                flags.append(str(section.flags))
        except Exception:
            pass
        return flags

    def _extract_imports(self, binary) -> List[Dict[str, Any]]:
        """Extract imported functions"""
        imports = []
        try:
            if hasattr(binary, 'imported_functions'):
                for func in binary.imported_functions:
                    imports.append({
                        'name': getattr(func, 'name', ''),
                        'library': getattr(func, 'library', '')
                    })
            elif hasattr(binary, 'imports'):
                for imp in binary.imports:
                    imports.append({
                        'name': getattr(imp, 'name', ''),
                        'library': getattr(imp, 'library', '')
                    })
        except Exception as e:
            logger.debug(f"Failed to extract imports: {e}")
        return imports

    def _extract_exports(self, binary) -> List[Dict[str, Any]]:
        """Extract exported functions"""
        exports = []
        try:
            if hasattr(binary, 'exported_functions'):
                for func in binary.exported_functions:
                    exports.append({
                        'name': getattr(func, 'name', ''),
                        'address': getattr(func, 'address', 0)
                    })
        except Exception as e:
            logger.debug(f"Failed to extract exports: {e}")
        return exports

    def _extract_strings(self, content: bytes) -> List[str]:
        """Extract ASCII strings from binary"""
        strings = []
        try:
            current_string = b""
            min_length = 4

            for byte in content:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        try:
                            strings.append(current_string.decode('ascii'))
                        except UnicodeDecodeError:
                            pass
                    current_string = b""

            # Don't return too many strings
            return strings[:1000]
        except Exception:
            return []

    def _recover_control_flow_graph(self, file_path: str, binary_info: Dict[str, Any]) -> Optional[Any]:
        """Recover control flow graph using available tools"""

        # Try Ghidra first (most comprehensive)
        if self.ghidra_available:
            cfg = self._recover_cfg_with_ghidra(file_path)
            if cfg:
                return cfg

        # Try Angr
        if ANGR_AVAILABLE:
            cfg = self._recover_cfg_with_angr(file_path)
            if cfg:
                return cfg

        # Fallback: basic disassembly
        return self._recover_cfg_basic(file_path, binary_info)

    def _recover_cfg_with_ghidra(self, file_path: str) -> Optional[Any]:
        """Recover CFG using Ghidra headless analysis"""
        try:
            # Create temporary script for Ghidra
            script_content = """
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import java.io.FileWriter;

// Get current program
program = getCurrentProgram();
model = new BasicBlockModel(program);

// Output CFG as JSON
output = new FileWriter("/tmp/ghidra_cfg.json");
output.write("{\\"nodes\\": [");

CodeBlockIterator iter = model.getCodeBlocks(getMonitor());
boolean first = true;
while (iter.hasNext()) {
    CodeBlock block = iter.next();
    if (!first) output.write(",");
    first = false;

    output.write("{\\"id\\": \\"" + block.getFirstStartAddress() + "\\", ");
    output.write("\\"start\\": \\"" + block.getFirstStartAddress() + "\\", ");
    output.write("\\"end\\": \\"" + block.getMaxAddress() + "\\"}");
}

output.write("], \\"edges\\": []}");
output.close();
            """

            with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
                f.write(script_content)
                script_path = f.name

            # Run Ghidra headless
            cmd = [
                'ghidra', 'headless', '/tmp/ghidra_project', 'temp_project',
                '-import', file_path,
                '-postScript', script_path,
                '-deleteProject'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0 and os.path.exists('/tmp/ghidra_cfg.json'):
                with open('/tmp/ghidra_cfg.json', 'r') as f:
                    cfg_data = json.load(f)
                    return self._convert_ghidra_cfg_to_networkx(cfg_data)

            os.unlink(script_path)

        except Exception as e:
            logger.debug(f"Ghidra CFG recovery failed: {e}")

        return None

    def _recover_cfg_with_angr(self, file_path: str) -> Optional[Any]:
        """Recover CFG using Angr"""
        try:
            if not ANGR_AVAILABLE:
                return None

            # Load binary with angr
            project = angr.Project(file_path, auto_load_libs=False)

            # Recover CFG
            cfg = project.analyses.CFGFast()

            # Convert to NetworkX
            if NETWORKX_AVAILABLE:
                nx_cfg = nx.DiGraph()

                for node in cfg.nodes():
                    nx_cfg.add_node(node.addr, **{
                        'address': hex(node.addr),
                        'size': node.size if hasattr(node, 'size') else 0
                    })

                for edge in cfg.edges():
                    nx_cfg.add_edge(edge.src.addr, edge.dst.addr)

                return nx_cfg

        except Exception as e:
            logger.debug(f"Angr CFG recovery failed: {e}")

        return None

    def _recover_cfg_basic(self, file_path: str, binary_info: Dict[str, Any]) -> Optional[Any]:
        """Basic CFG recovery using disassembly"""
        try:
            if not CAPSTONE_AVAILABLE or not NETWORKX_AVAILABLE:
                return None

            # Read binary content
            with open(file_path, 'rb') as f:
                content = f.read()

            # Choose disassembler based on architecture
            arch = binary_info.get('architecture', 'x86_64')
            if 'x86' in arch.lower():
                cs = self.disassemblers['capstone']['x86_64']
            elif 'arm' in arch.lower():
                cs = self.disassemblers['capstone']['arm64']
            else:
                cs = self.disassemblers['capstone']['x86_64']  # Default

            # Basic disassembly
            instructions = list(cs.disasm(content[:10000], 0x1000))  # Limit size

            # Build simple CFG
            cfg = nx.DiGraph()

            for i, insn in enumerate(instructions):
                cfg.add_node(insn.address, **{
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str
                })

                # Add sequential edge
                if i + 1 < len(instructions):
                    cfg.add_edge(insn.address, instructions[i + 1].address)

            return cfg if len(cfg.nodes) > 0 else None

        except Exception as e:
            logger.debug(f"Basic CFG recovery failed: {e}")
            return None

    def _convert_ghidra_cfg_to_networkx(self, cfg_data: Dict[str, Any]) -> Any:
        """Convert Ghidra CFG data to NetworkX graph"""
        if not NETWORKX_AVAILABLE:
            return None

        try:
            cfg = nx.DiGraph()

            for node in cfg_data.get('nodes', []):
                cfg.add_node(node['id'], **node)

            for edge in cfg_data.get('edges', []):
                cfg.add_edge(edge['src'], edge['dst'])

            return cfg
        except Exception:
            return None

    def _analyze_binary_structure(self, file_path: str, binary_info: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze binary structure for vulnerabilities"""
        vulnerabilities = []

        try:
            # Check for dangerous imports
            dangerous_imports = [
                'strcpy', 'strcat', 'sprintf', 'gets', 'system', 'exec',
                'memcpy', 'memmove', 'strncpy', 'strncat'
            ]

            for imp in binary_info.get('imports', []):
                if imp.get('name', '').lower() in [d.lower() for d in dangerous_imports]:
                    vuln = Vulnerability(
                        vuln_type=VulnType.DANGEROUS_FUNCTION,
                        severity=VulnSeverity.MEDIUM,
                        location=Location(file_path, 0),
                        title=f"Dangerous Function Import: {imp['name']}",
                        description=f"Binary imports dangerous function {imp['name']} which may lead to buffer overflow",
                        technical_details=f"Library: {imp.get('library', 'unknown')}",
                        impact="Potential buffer overflow or code injection vulnerability",
                        remediation="Replace with safer alternatives (e.g., strncpy instead of strcpy)",
                        confidence=0.7,
                        detection_method="binary_import_analysis"
                    )
                    vulnerabilities.append(vuln)

            # Check for executable stack
            for section in binary_info.get('sections', []):
                flags = section.get('flags', [])
                if 'EXECUTE' in flags and 'WRITE' in flags:
                    vuln = Vulnerability(
                        vuln_type=VulnType.EXECUTABLE_STACK,
                        severity=VulnSeverity.HIGH,
                        location=Location(file_path, 0),
                        title="Executable and Writable Memory Section",
                        description=f"Section {section['name']} is both executable and writable",
                        technical_details=f"Address: 0x{section['virtual_address']:x}, Size: {section['size']}",
                        impact="May allow code injection attacks",
                        remediation="Enable DEP/NX bit protection",
                        confidence=0.9,
                        detection_method="binary_section_analysis"
                    )
                    vulnerabilities.append(vuln)

            # Check for suspicious strings
            suspicious_strings = [
                '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell',
                'password', 'secret', 'token', 'key', 'admin'
            ]

            for string in binary_info.get('strings', []):
                for suspicious in suspicious_strings:
                    if suspicious.lower() in string.lower():
                        vuln = Vulnerability(
                            vuln_type=VulnType.HARDCODED_CREDENTIALS,
                            severity=VulnSeverity.MEDIUM,
                            location=Location(file_path, 0),
                            title=f"Suspicious String: {suspicious}",
                            description=f"Binary contains suspicious string: {string}",
                            confidence=0.6,
                            detection_method="binary_string_analysis"
                        )
                        vulnerabilities.append(vuln)
                        break

        except Exception as e:
            logger.error(f"Binary structure analysis failed: {e}")

        return vulnerabilities

    def _analyze_control_flow(self, file_path: str, cfg: Any) -> List[Vulnerability]:
        """Analyze control flow graph for vulnerabilities"""
        vulnerabilities = []

        try:
            if not cfg or not NETWORKX_AVAILABLE:
                return vulnerabilities

            # Use enhanced topological analysis
            loop_analysis = detect_loops(cfg)

            if loop_analysis.get('security_risk') == 'high':
                vuln = Vulnerability(
                    vuln_type=VulnType.RACE_CONDITION,
                    severity=VulnSeverity.HIGH,
                    location=Location(file_path, 0),
                    title="Complex Control Flow Structure",
                    description=f"High topological complexity detected: {loop_analysis.get('vulnerability_signature')}",
                    technical_details=f"H1 loops: {loop_analysis.get('h1_loops')}, Complexity: {loop_analysis.get('topological_complexity')}",
                    impact="Complex control flow may indicate race conditions or reentrancy issues",
                    remediation="Review control flow complexity and synchronization",
                    mathematical_proof=loop_analysis.get('mathematical_proof', ''),
                    confidence=0.8,
                    detection_method="topological_control_flow_analysis"
                )
                vulnerabilities.append(vuln)

            # Check for specific vulnerability patterns
            for pattern in loop_analysis.get('vuln_patterns', []):
                severity = VulnSeverity.HIGH if 'HIGH' in pattern else VulnSeverity.MEDIUM
                vuln = Vulnerability(
                    vuln_type=self._pattern_to_vuln_type(pattern),
                    severity=severity,
                    location=Location(file_path, 0),
                    title=f"Topological Vulnerability Pattern: {pattern.split(':')[0]}",
                    description=pattern,
                    confidence=0.75,
                    detection_method="topological_pattern_analysis"
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"Control flow analysis failed: {e}")

        return vulnerabilities

    def _pattern_to_vuln_type(self, pattern: str) -> VulnType:
        """Map topological patterns to vulnerability types"""
        if 'REENTRANCY' in pattern:
            return VulnType.RACE_CONDITION
        elif 'BUFFER_OVERFLOW' in pattern:
            return VulnType.BUFFER_OVERFLOW
        elif 'INFINITE_LOOP' in pattern:
            return VulnType.INFINITE_LOOP
        else:
            return VulnType.UNKNOWN

    def _analyze_with_symbolic_execution(self, file_path: str, binary_info: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze using symbolic execution"""
        vulnerabilities = []

        try:
            if not ANGR_AVAILABLE:
                return vulnerabilities

            # Light symbolic execution analysis
            project = angr.Project(file_path, auto_load_libs=False)

            # Simple reachability analysis
            entry_state = project.factory.entry_state()
            sm = project.factory.simulation_manager(entry_state)

            # Run limited exploration
            sm.explore(n=10)  # Limit exploration

            # Check for potential crashes
            if sm.errored:
                vuln = Vulnerability(
                    vuln_type=VulnType.UNKNOWN,
                    severity=VulnSeverity.MEDIUM,
                    location=Location(file_path, 0),
                    title="Symbolic Execution Error",
                    description=f"Symbolic execution encountered {len(sm.errored)} errors",
                    confidence=0.6,
                    detection_method="symbolic_execution"
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Symbolic execution analysis failed: {e}")

        return vulnerabilities

    def _analyze_crypto_usage(self, file_path: str, binary_info: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze cryptographic usage"""
        vulnerabilities = []

        # Check for weak crypto imports
        weak_crypto = ['md5', 'sha1', 'des', 'rc4']

        for imp in binary_info.get('imports', []):
            name = imp.get('name', '').lower()
            for weak in weak_crypto:
                if weak in name:
                    vuln = Vulnerability(
                        vuln_type=VulnType.WEAK_CRYPTOGRAPHY,
                        severity=VulnSeverity.MEDIUM,
                        location=Location(file_path, 0),
                        title=f"Weak Cryptographic Function: {imp['name']}",
                        description=f"Binary uses weak cryptographic function {imp['name']}",
                        remediation="Use stronger cryptographic algorithms (SHA-256, AES)",
                        confidence=0.8,
                        detection_method="crypto_import_analysis"
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_memory_safety(self, file_path: str, binary_info: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze memory safety"""
        vulnerabilities = []

        # Check for stack canary presence
        has_stack_protection = False
        for imp in binary_info.get('imports', []):
            if 'stack_chk' in imp.get('name', '').lower():
                has_stack_protection = True
                break

        if not has_stack_protection:
            vuln = Vulnerability(
                vuln_type=VulnType.MISSING_PROTECTION,
                severity=VulnSeverity.MEDIUM,
                location=Location(file_path, 0),
                title="Missing Stack Protection",
                description="Binary does not appear to have stack canary protection",
                remediation="Compile with stack protection (-fstack-protector)",
                confidence=0.7,
                detection_method="stack_protection_analysis"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_with_topology(self, file_path: str, cfg: Any) -> List[Vulnerability]:
        """Enhanced topological analysis of binary CFG"""
        vulnerabilities = []

        try:
            # Mathematical analysis using MathCore
            topo_analysis = detect_loops(cfg)

            # Ricci curvature analysis for hotspots
            ricci_data = topo_analysis.get('ricci_analysis', {})
            hotspots = ricci_data.get('vulnerability_hotspots', [])

            if len(hotspots) > 2:
                vuln = Vulnerability(
                    vuln_type=VulnType.ARCHITECTURAL_WEAKNESS,
                    severity=VulnSeverity.MEDIUM,
                    location=Location(file_path, 0),
                    title="Multiple Vulnerability Hotspots Detected",
                    description=f"Ricci curvature analysis found {len(hotspots)} potential vulnerability hotspots",
                    technical_details=f"Negative curvature regions: {hotspots[:3]}",
                    mathematical_proof=f"∃ edges e: ricci_curvature(e) < -0.5 → hotspot_count = {len(hotspots)}",
                    confidence=0.7,
                    detection_method="ricci_curvature_analysis"
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"Topological analysis failed: {e}")

        return vulnerabilities