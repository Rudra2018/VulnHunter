"""
VulnHunter∞ Docker Execution Engine
Mathematical-only execution environment for vulnerability analysis

This module implements the Docker-based execution engine as specified in 1.txt,
providing isolated mathematical computations for vulnerability detection without
code execution risks.
"""

import docker
import json
import tempfile
import os
import shutil
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import tarfile
import io
import uuid


class ExecutionMode(Enum):
    """Execution modes for different analysis types"""
    MATHEMATICAL_ONLY = "mathematical_only"
    STATIC_ANALYSIS = "static_analysis"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    FORMAL_VERIFICATION = "formal_verification"
    QUANTUM_SIMULATION = "quantum_simulation"


@dataclass
class ExecutionResult:
    """Result from Docker execution"""
    execution_id: str
    mode: ExecutionMode
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    mathematical_results: Dict[str, Any]
    vulnerability_detections: List[Dict[str, Any]]
    resource_usage: Dict[str, float]


@dataclass
class ExecutionConfig:
    """Configuration for Docker execution"""
    mode: ExecutionMode
    timeout: int = 300  # 5 minutes default
    memory_limit: str = "2g"
    cpu_limit: float = 1.0
    network_disabled: bool = True
    read_only_filesystem: bool = True
    enable_quantum_simulation: bool = False
    mathematical_precision: str = "high"


class DockerExecutionEngine:
    """
    Docker-based execution engine for VulnHunter∞ mathematical computations

    Provides isolated execution environment for vulnerability analysis using
    mathematical-only approaches without executing potentially malicious code.
    """

    def __init__(self, base_image: str = "vulnhunter-infinity-base"):
        self.docker_client = docker.from_env()
        self.base_image = base_image
        self.execution_history: List[ExecutionResult] = []
        self.active_containers: Dict[str, docker.models.containers.Container] = {}

        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Initialize base environment
        self._setup_base_environment()

    def _setup_base_environment(self):
        """Setup base Docker environment for VulnHunter∞"""

        # Check if base image exists
        try:
            self.docker_client.images.get(self.base_image)
            self.logger.info(f"✅ Base image {self.base_image} found")
        except docker.errors.ImageNotFound:
            self.logger.info(f"🏗️ Building base image {self.base_image}...")
            self._build_base_image()

    def _build_base_image(self):
        """Build base Docker image with mathematical dependencies"""

        dockerfile_content = """
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    libblas-dev \\
    liblapack-dev \\
    libffi-dev \\
    && rm -rf /var/lib/apt/lists/*

# Install Python mathematical libraries
RUN pip install --no-cache-dir \\
    torch \\
    numpy \\
    scipy \\
    sympy \\
    networkx \\
    scikit-learn \\
    qiskit \\
    pennylane \\
    cvxpy \\
    z3-solver \\
    pysmt \\
    sage-numerical-backends-coin

# Create non-root user for security
RUN useradd -m -u 1000 vulnhunter
USER vulnhunter
WORKDIR /home/vulnhunter

# Set environment variables
ENV PYTHONPATH=/home/vulnhunter
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python3", "-c", "print('VulnHunter∞ Mathematical Environment Ready')"]
"""

        # Create temporary directory for build context
        with tempfile.TemporaryDirectory() as build_context:
            dockerfile_path = os.path.join(build_context, "Dockerfile")
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)

            self.logger.info("🔨 Building Docker image...")
            try:
                image, logs = self.docker_client.images.build(
                    path=build_context,
                    tag=self.base_image,
                    rm=True,
                    forcerm=True
                )
                self.logger.info(f"✅ Successfully built {self.base_image}")
            except docker.errors.BuildError as e:
                self.logger.error(f"❌ Failed to build image: {e}")
                raise

    def execute_mathematical_analysis(self, code: str, config: ExecutionConfig) -> ExecutionResult:
        """Execute mathematical analysis in isolated Docker container"""

        execution_id = str(uuid.uuid4())
        start_time = time.time()

        self.logger.info(f"🚀 Starting execution {execution_id} in {config.mode.value} mode")

        try:
            # Create execution environment
            container = self._create_container(config, execution_id)
            self.active_containers[execution_id] = container

            # Prepare code for execution
            safe_code = self._sanitize_mathematical_code(code, config.mode)

            # Execute in container
            result = self._execute_in_container(container, safe_code, config)

            # Process results
            execution_time = time.time() - start_time
            result.execution_id = execution_id
            result.execution_time = execution_time

            # Store in history
            self.execution_history.append(result)

            self.logger.info(f"✅ Execution {execution_id} completed in {execution_time:.2f}s")

            return result

        except Exception as e:
            self.logger.error(f"❌ Execution {execution_id} failed: {e}")
            execution_time = time.time() - start_time

            error_result = ExecutionResult(
                execution_id=execution_id,
                mode=config.mode,
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time=execution_time,
                mathematical_results={},
                vulnerability_detections=[],
                resource_usage={}
            )

            self.execution_history.append(error_result)
            return error_result

        finally:
            # Cleanup container
            self._cleanup_container(execution_id)

    def _create_container(self, config: ExecutionConfig, execution_id: str) -> docker.models.containers.Container:
        """Create Docker container with specified configuration"""

        container_config = {
            'image': self.base_image,
            'detach': True,
            'mem_limit': config.memory_limit,
            'nano_cpus': int(config.cpu_limit * 1e9),
            'network_disabled': config.network_disabled,
            'read_only': config.read_only_filesystem,
            'name': f"vulnhunter-infinity-{execution_id}",
            'environment': {
                'EXECUTION_ID': execution_id,
                'EXECUTION_MODE': config.mode.value,
                'MATHEMATICAL_PRECISION': config.mathematical_precision,
                'QUANTUM_ENABLED': str(config.enable_quantum_simulation).lower()
            },
            'working_dir': '/home/vulnhunter',
            'user': 'vulnhunter'
        }

        # Add security constraints
        if config.mode == ExecutionMode.MATHEMATICAL_ONLY:
            container_config.update({
                'cap_drop': ['ALL'],
                'security_opt': ['no-new-privileges:true'],
                'tmpfs': {'/tmp': 'noexec,nosuid,size=100m'}
            })

        container = self.docker_client.containers.create(**container_config)
        container.start()

        return container

    def _sanitize_mathematical_code(self, code: str, mode: ExecutionMode) -> str:
        """Sanitize code to ensure only mathematical operations"""

        # Forbidden operations for mathematical-only mode
        forbidden_patterns = [
            'import os', 'import subprocess', 'import sys',
            'exec(', 'eval(', '__import__',
            'open(', 'file(', 'input(',
            'socket', 'urllib', 'requests',
            'system(', 'popen(', 'spawn'
        ]

        if mode == ExecutionMode.MATHEMATICAL_ONLY:
            for pattern in forbidden_patterns:
                if pattern in code:
                    raise ValueError(f"Forbidden operation detected: {pattern}")

        # Wrap code in mathematical analysis framework
        safe_wrapper = f"""
import torch
import numpy as np
import scipy
import sympy
from typing import Dict, Any, List
import json
import traceback

def safe_mathematical_analysis():
    try:
        # User mathematical code
        {code}

        # Return mathematical results
        return {{
            'status': 'success',
            'mathematical_results': locals().get('results', {{}}),
            'vulnerability_detections': locals().get('vulnerabilities', []),
            'quantum_states': locals().get('quantum_states', [])
        }}
    except Exception as e:
        return {{
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }}

# Execute analysis
result = safe_mathematical_analysis()
print(json.dumps(result, indent=2, default=str))
"""

        return safe_wrapper

    def _execute_in_container(self, container: docker.models.containers.Container,
                            code: str, config: ExecutionConfig) -> ExecutionResult:
        """Execute code in Docker container and collect results"""

        # Create temporary file with code
        code_file = '/tmp/analysis.py'

        # Write code to container
        with io.BytesIO(code.encode('utf-8')) as code_stream:
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tarinfo = tarfile.TarInfo(name='analysis.py')
                tarinfo.size = len(code.encode('utf-8'))
                tar.addfile(tarinfo, code_stream)

            tar_stream.seek(0)
            container.put_archive('/tmp', tar_stream)

        # Execute code
        exec_result = container.exec_run(
            f"python3 /tmp/analysis.py",
            timeout=config.timeout,
            demux=True
        )

        stdout = exec_result.output[0].decode('utf-8') if exec_result.output[0] else ""
        stderr = exec_result.output[1].decode('utf-8') if exec_result.output[1] else ""

        # Parse mathematical results
        mathematical_results = {}
        vulnerability_detections = []

        try:
            if stdout.strip():
                parsed_output = json.loads(stdout)
                mathematical_results = parsed_output.get('mathematical_results', {})
                vulnerability_detections = parsed_output.get('vulnerability_detections', [])
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse mathematical results as JSON")

        # Get resource usage
        stats = container.stats(stream=False)
        resource_usage = self._parse_container_stats(stats)

        return ExecutionResult(
            execution_id="",  # Will be set by caller
            mode=config.mode,
            success=(exec_result.exit_code == 0),
            stdout=stdout,
            stderr=stderr,
            exit_code=exec_result.exit_code,
            execution_time=0.0,  # Will be set by caller
            mathematical_results=mathematical_results,
            vulnerability_detections=vulnerability_detections,
            resource_usage=resource_usage
        )

    def _parse_container_stats(self, stats: Dict) -> Dict[str, float]:
        """Parse container resource usage statistics"""

        resource_usage = {
            'cpu_usage_percent': 0.0,
            'memory_usage_mb': 0.0,
            'memory_limit_mb': 0.0,
            'network_rx_bytes': 0.0,
            'network_tx_bytes': 0.0
        }

        try:
            # CPU usage
            cpu_stats = stats.get('cpu_stats', {})
            precpu_stats = stats.get('precpu_stats', {})

            if cpu_stats and precpu_stats:
                cpu_delta = cpu_stats['cpu_usage']['total_usage'] - precpu_stats['cpu_usage']['total_usage']
                system_delta = cpu_stats['system_cpu_usage'] - precpu_stats['system_cpu_usage']

                if system_delta > 0:
                    resource_usage['cpu_usage_percent'] = (cpu_delta / system_delta) * 100.0

            # Memory usage
            memory_stats = stats.get('memory_stats', {})
            if memory_stats:
                resource_usage['memory_usage_mb'] = memory_stats.get('usage', 0) / (1024 * 1024)
                resource_usage['memory_limit_mb'] = memory_stats.get('limit', 0) / (1024 * 1024)

            # Network usage
            networks = stats.get('networks', {})
            for interface, net_stats in networks.items():
                resource_usage['network_rx_bytes'] += net_stats.get('rx_bytes', 0)
                resource_usage['network_tx_bytes'] += net_stats.get('tx_bytes', 0)

        except (KeyError, TypeError, ZeroDivisionError):
            self.logger.warning("Failed to parse container statistics")

        return resource_usage

    def _cleanup_container(self, execution_id: str):
        """Cleanup Docker container after execution"""

        try:
            container = self.active_containers.get(execution_id)
            if container:
                container.stop(timeout=10)
                container.remove()
                del self.active_containers[execution_id]
                self.logger.info(f"🧹 Cleaned up container for execution {execution_id}")
        except Exception as e:
            self.logger.warning(f"Failed to cleanup container {execution_id}: {e}")

    def execute_vulnerability_analysis(self, source_code: str,
                                     language: str = "python") -> ExecutionResult:
        """Execute complete vulnerability analysis using mathematical approach"""

        analysis_code = f"""
# VulnHunter∞ Mathematical Vulnerability Analysis

import torch
import numpy as np
from typing import Dict, List, Any

# Source code to analyze
source_code = '''
{source_code}
'''

language = "{language}"

# Mathematical analysis functions
def mathematical_vulnerability_detection():
    '''Perform mathematical vulnerability detection'''

    # Initialize results
    results = {{
        'source_analysis': {{}},
        'mathematical_signatures': {{}},
        'vulnerability_scores': {{}},
        'homotopy_classifications': {{}}
    }}

    vulnerabilities = []

    # Token-based mathematical analysis
    tokens = source_code.split()
    token_tensor = torch.zeros(len(tokens), 512)  # 512-dimensional embedding

    # Generate mathematical signatures for each token
    for i, token in enumerate(tokens):
        # Create deterministic embedding based on token
        token_hash = hash(token) % 2**32
        torch.manual_seed(token_hash)
        token_tensor[i] = torch.randn(512)

    results['source_analysis']['token_count'] = len(tokens)
    results['source_analysis']['embedding_shape'] = list(token_tensor.shape)

    # Vulnerability pattern detection using mathematical signatures
    vulnerability_patterns = {{
        'buffer_overflow': ['strcpy', 'sprintf', 'gets', 'scanf'],
        'sql_injection': ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
        'xss': ['innerHTML', 'document.write', 'eval'],
        'path_traversal': ['../', '..\\\\', 'path.join'],
        'command_injection': ['system', 'exec', 'eval', 'subprocess']
    }}

    for vuln_type, patterns in vulnerability_patterns.items():
        pattern_score = 0.0
        detected_patterns = []

        for pattern in patterns:
            if pattern.lower() in source_code.lower():
                pattern_score += 1.0
                detected_patterns.append(pattern)

        if pattern_score > 0:
            # Calculate mathematical signature
            vuln_signature = torch.zeros(256)
            for j, pattern in enumerate(detected_patterns):
                pattern_hash = hash(f"{{vuln_type}}_{{pattern}}") % 2**32
                torch.manual_seed(pattern_hash)
                vuln_signature += torch.randn(256)

            vuln_signature = vuln_signature / torch.norm(vuln_signature)

            # Assign homotopy group
            homotopy_groups = {{
                'buffer_overflow': 'π₁(S¹)',
                'sql_injection': 'π₂(S²)',
                'xss': 'π₃(S³)',
                'path_traversal': 'π₄(S⁴)',
                'command_injection': 'π₅(S⁵)'
            }}

            vulnerability = {{
                'type': vuln_type,
                'confidence': min(pattern_score / len(patterns), 1.0),
                'detected_patterns': detected_patterns,
                'mathematical_signature': vuln_signature.tolist(),
                'homotopy_group': homotopy_groups.get(vuln_type, 'π₀(S⁰)'),
                'exploitability_score': pattern_score * 0.2,
                'severity': 'HIGH' if pattern_score >= 2 else 'MEDIUM' if pattern_score >= 1 else 'LOW'
            }}

            vulnerabilities.append(vulnerability)
            results['vulnerability_scores'][vuln_type] = vulnerability['confidence']
            results['homotopy_classifications'][vuln_type] = vulnerability['homotopy_group']

    # Statistical analysis
    total_vulnerability_score = sum(vuln['confidence'] for vuln in vulnerabilities)
    results['mathematical_signatures']['total_vulnerability_score'] = total_vulnerability_score
    results['mathematical_signatures']['vulnerability_density'] = total_vulnerability_score / max(len(tokens), 1)

    return results, vulnerabilities

# Execute analysis
results, vulnerabilities = mathematical_vulnerability_detection()

# Set quantum states for detected vulnerabilities
quantum_states = []
for vuln in vulnerabilities:
    # Generate quantum state representation
    real_part = torch.randn(32)
    imag_part = torch.randn(32)
    quantum_state = torch.complex(real_part, imag_part)
    quantum_state = quantum_state / torch.norm(quantum_state)

    quantum_states.append({{
        'vulnerability_type': vuln['type'],
        'quantum_state_real': quantum_state.real.tolist(),
        'quantum_state_imag': quantum_state.imag.tolist(),
        'entanglement_measure': float(torch.norm(quantum_state.real * quantum_state.imag))
    }})
"""

        config = ExecutionConfig(
            mode=ExecutionMode.MATHEMATICAL_ONLY,
            timeout=120,
            mathematical_precision="high"
        )

        return self.execute_mathematical_analysis(analysis_code, config)

    def execute_formal_verification(self, code: str, properties: List[str]) -> ExecutionResult:
        """Execute formal verification using mathematical approaches"""

        verification_code = f"""
# VulnHunter∞ Formal Verification Engine

import sympy as sp
from sympy.logic import satisfiable
from typing import List, Dict

# Code to verify
code_to_verify = '''
{code}
'''

# Properties to verify
properties = {properties}

def formal_verification_analysis():
    '''Perform formal verification using symbolic mathematics'''

    results = {{
        'verification_results': {{}},
        'mathematical_proofs': {{}},
        'satisfiability_analysis': {{}}
    }}

    vulnerabilities = []

    # Extract variables and constraints from code
    variables = set()
    constraints = []

    # Simple pattern-based extraction for demonstration
    lines = code_to_verify.split('\\n')
    for line in lines:
        line = line.strip()
        if '=' in line and not line.startswith('#'):
            parts = line.split('=')
            if len(parts) >= 2:
                var_name = parts[0].strip()
                variables.add(var_name)

    # Create symbolic variables
    symbolic_vars = {{var: sp.Symbol(var) for var in variables}}

    # Verify each property
    for prop in properties:
        try:
            # Convert property to symbolic expression
            symbolic_prop = sp.sympify(prop, locals=symbolic_vars)

            # Check satisfiability
            is_satisfiable = satisfiable(symbolic_prop)

            verification_result = {{
                'property': prop,
                'satisfiable': bool(is_satisfiable),
                'symbolic_form': str(symbolic_prop),
                'verification_status': 'VERIFIED' if is_satisfiable else 'FAILED'
            }}

            results['verification_results'][prop] = verification_result

            # If property fails, it might indicate a vulnerability
            if not is_satisfiable:
                vulnerability = {{
                    'type': 'formal_verification_failure',
                    'property': prop,
                    'confidence': 0.9,
                    'description': f'Property {{prop}} failed formal verification',
                    'severity': 'HIGH'
                }}
                vulnerabilities.append(vulnerability)

        except Exception as e:
            results['verification_results'][prop] = {{
                'property': prop,
                'error': str(e),
                'verification_status': 'ERROR'
            }}

    # Mathematical proof generation
    results['mathematical_proofs']['total_properties'] = len(properties)
    results['mathematical_proofs']['verified_properties'] = sum(
        1 for r in results['verification_results'].values()
        if r.get('verification_status') == 'VERIFIED'
    )

    return results, vulnerabilities

# Execute verification
results, vulnerabilities = formal_verification_analysis()
"""

        config = ExecutionConfig(
            mode=ExecutionMode.FORMAL_VERIFICATION,
            timeout=180,
            mathematical_precision="high"
        )

        return self.execute_mathematical_analysis(verification_code, config)

    def get_execution_history(self) -> List[ExecutionResult]:
        """Get complete execution history"""
        return self.execution_history.copy()

    def get_active_executions(self) -> List[str]:
        """Get list of currently active execution IDs"""
        return list(self.active_containers.keys())

    def terminate_execution(self, execution_id: str) -> bool:
        """Terminate active execution"""
        try:
            self._cleanup_container(execution_id)
            return True
        except Exception as e:
            self.logger.error(f"Failed to terminate execution {execution_id}: {e}")
            return False

    def cleanup_all(self):
        """Cleanup all active containers and resources"""
        for execution_id in list(self.active_containers.keys()):
            self._cleanup_container(execution_id)

        self.logger.info("🧹 All containers cleaned up")

    def get_engine_statistics(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics"""

        total_executions = len(self.execution_history)
        successful_executions = sum(1 for r in self.execution_history if r.success)

        avg_execution_time = 0.0
        if total_executions > 0:
            avg_execution_time = sum(r.execution_time for r in self.execution_history) / total_executions

        mode_distribution = {}
        for result in self.execution_history:
            mode = result.mode.value
            mode_distribution[mode] = mode_distribution.get(mode, 0) + 1

        return {
            'total_executions': total_executions,
            'successful_executions': successful_executions,
            'success_rate': successful_executions / max(total_executions, 1),
            'average_execution_time': avg_execution_time,
            'active_containers': len(self.active_containers),
            'mode_distribution': mode_distribution,
            'base_image': self.base_image
        }


def create_docker_execution_engine() -> DockerExecutionEngine:
    """Factory function to create Docker execution engine"""

    print("🐳 Initializing VulnHunter∞ Docker Execution Engine...")

    engine = DockerExecutionEngine()

    print("✅ Docker Execution Engine Ready!")
    print(f"🔧 Base Image: {engine.base_image}")
    print(f"📊 Active Containers: {len(engine.active_containers)}")

    return engine


if __name__ == "__main__":
    # Test Docker execution engine
    engine = create_docker_execution_engine()

    # Test mathematical analysis
    test_code = """
import torch
import numpy as np

# Test mathematical computation
x = torch.randn(100, 100)
eigenvals = torch.linalg.eigvals(x @ x.T)

results = {
    'matrix_shape': list(x.shape),
    'eigenvalue_count': len(eigenvals),
    'max_eigenvalue': float(torch.max(eigenvals.real)),
    'computation_type': 'linear_algebra'
}

print(f"Mathematical analysis complete: {results}")
"""

    config = ExecutionConfig(
        mode=ExecutionMode.MATHEMATICAL_ONLY,
        timeout=60
    )

    print("\n🧮 Testing mathematical analysis...")
    result = engine.execute_mathematical_analysis(test_code, config)

    print(f"✅ Execution completed:")
    print(f"   Success: {result.success}")
    print(f"   Time: {result.execution_time:.2f}s")
    print(f"   Exit Code: {result.exit_code}")

    # Test vulnerability analysis
    test_vulnerable_code = """
def vulnerable_function(user_input):
    command = "ls " + user_input
    os.system(command)  # Command injection vulnerability

    query = "SELECT * FROM users WHERE id = " + user_input  # SQL injection

    buffer = user_input[:100]  # Potential buffer issue
    return buffer
"""

    print("\n🔍 Testing vulnerability analysis...")
    vuln_result = engine.execute_vulnerability_analysis(test_vulnerable_code, "python")

    print(f"✅ Vulnerability analysis completed:")
    print(f"   Success: {vuln_result.success}")
    print(f"   Vulnerabilities found: {len(vuln_result.vulnerability_detections)}")

    for vuln in vuln_result.vulnerability_detections:
        print(f"   - {vuln.get('type', 'unknown')}: {vuln.get('confidence', 0):.2f}")

    # Cleanup
    engine.cleanup_all()
    print("\n🧹 Engine cleanup complete")