"""
Secure Runner Module for Safe External Command Execution

This module provides a secure execution environment for external commands
with comprehensive resource limits, sandboxing, and security controls.
All external command execution in the vulnerability detection pipeline
should use this module to prevent security risks.
"""

import os
import subprocess
import tempfile
import uuid
import shlex
import logging
import resource
import signal
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
from enum import Enum
import json


class ExecutionStatus(Enum):
    """Status of command execution"""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    MEMORY_LIMIT = "memory_limit"
    CPU_LIMIT = "cpu_limit"
    PERMISSION_DENIED = "permission_denied"
    COMMAND_NOT_ALLOWED = "command_not_allowed"
    BINARY_NOT_FOUND = "binary_not_found"
    EXECUTION_ERROR = "execution_error"
    DRY_RUN = "dry_run"


@dataclass
class ExecutionResult:
    """Result of secure command execution"""
    status: ExecutionStatus
    return_code: int
    stdout: str
    stderr: str
    execution_time: float
    memory_used: int
    command: str
    run_id: str
    log_path: Optional[str] = None
    error_message: Optional[str] = None
    sandbox_path: Optional[str] = None


class SecureRunner:
    """
    Secure command execution with comprehensive safety controls.

    Features:
    - Resource limits (CPU time, memory, file descriptors)
    - Binary allowlist with path validation
    - Sandboxed execution environment
    - Comprehensive logging and audit trail
    - Timeout controls with signal handling
    - Dry-run validation mode
    """

    def __init__(self,
                 sandbox_base_dir: str = "./sandbox_runs",
                 tools_bin_dir: str = "./tools/bin",
                 log_level: int = logging.INFO):
        """
        Initialize SecureRunner with configuration.

        Args:
            sandbox_base_dir: Base directory for sandbox runs
            tools_bin_dir: Directory containing allowed binaries
            log_level: Logging level for execution logs
        """
        self.sandbox_base_dir = Path(sandbox_base_dir)
        self.tools_bin_dir = Path(tools_bin_dir)

        # Create directories if they don't exist
        self.sandbox_base_dir.mkdir(parents=True, exist_ok=True)
        self.tools_bin_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

        # Default allowlist of safe system binaries
        self.default_allowlist = {
            'ls', 'cat', 'grep', 'sed', 'awk', 'head', 'tail', 'wc',
            'find', 'sort', 'uniq', 'cut', 'tr', 'echo', 'which',
            'python3', 'python', 'node', 'java', 'gcc', 'clang',
            'make', 'cmake', 'git', 'curl', 'wget'
        }

        # Load additional allowed binaries from tools directory
        self.allowed_binaries = self._load_allowed_binaries()

    def _load_allowed_binaries(self) -> set:
        """Load allowed binaries from tools directory and system allowlist."""
        allowed = self.default_allowlist.copy()

        # Add binaries from tools/bin directory
        if self.tools_bin_dir.exists():
            for binary_file in self.tools_bin_dir.iterdir():
                if binary_file.is_file() and os.access(binary_file, os.X_OK):
                    allowed.add(binary_file.name)
                    allowed.add(str(binary_file.absolute()))

        return allowed

    def _validate_command(self, cmd: Union[str, List[str]]) -> tuple[List[str], Optional[str]]:
        """
        Validate command against security policies.

        Args:
            cmd: Command to validate (string or list)

        Returns:
            Tuple of (parsed_command_list, error_message)
        """
        # Parse command into list if it's a string
        if isinstance(cmd, str):
            try:
                cmd_list = shlex.split(cmd)
            except ValueError as e:
                return [], f"Invalid command syntax: {e}"
        else:
            cmd_list = cmd.copy()

        if not cmd_list:
            return [], "Empty command"

        binary_name = cmd_list[0]

        # Check if binary is in allowlist
        if binary_name not in self.allowed_binaries:
            # Check if it's a path to an allowed binary
            binary_path = Path(binary_name)
            if binary_path.is_absolute():
                if not self._is_allowed_path(binary_path):
                    return [], f"Binary not in allowlist: {binary_name}"
            else:
                # Check if binary exists in tools/bin
                tools_binary = self.tools_bin_dir / binary_name
                if not tools_binary.exists():
                    return [], f"Binary not found in allowlist or tools directory: {binary_name}"
                # Update command to use full path
                cmd_list[0] = str(tools_binary.absolute())

        # Additional security checks
        dangerous_patterns = [
            '&&', '||', ';', '|', '>', '<', '`', '$(',
            'rm -rf', 'dd if=', 'mkfs', 'fdisk'
        ]

        cmd_str = ' '.join(cmd_list)
        for pattern in dangerous_patterns:
            if pattern in cmd_str:
                return [], f"Dangerous command pattern detected: {pattern}"

        return cmd_list, None

    def _is_allowed_path(self, path: Path) -> bool:
        """Check if a path is allowed for execution."""
        try:
            # Resolve to absolute path
            abs_path = path.resolve()

            # Check if it's in tools directory
            if abs_path.is_relative_to(self.tools_bin_dir.resolve()):
                return True

            # Check if it's a system binary in standard locations
            allowed_dirs = [
                Path('/usr/bin'),
                Path('/usr/local/bin'),
                Path('/bin'),
                Path('/usr/sbin'),
                Path('/sbin')
            ]

            for allowed_dir in allowed_dirs:
                if abs_path.is_relative_to(allowed_dir):
                    return abs_path.name in self.default_allowlist

            return False

        except (OSError, ValueError):
            return False

    def _create_sandbox(self, run_id: str) -> Path:
        """Create isolated sandbox directory for execution."""
        sandbox_path = self.sandbox_base_dir / run_id
        sandbox_path.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (sandbox_path / "input").mkdir(exist_ok=True)
        (sandbox_path / "output").mkdir(exist_ok=True)
        (sandbox_path / "logs").mkdir(exist_ok=True)
        (sandbox_path / "tmp").mkdir(exist_ok=True)

        return sandbox_path

    def _setup_resource_limits(self, cpu_time: int, mem_bytes: int):
        """Set resource limits for the subprocess."""
        def set_limits():
            # Set CPU time limit (seconds)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_time, cpu_time))

            # Set memory limit (bytes)
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))

            # Set file descriptor limit
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))

            # Set core dump limit (disable core dumps)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

            # Set process limit
            resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))

        return set_limits

    def _log_execution(self, run_id: str, sandbox_path: Path,
                      cmd: List[str], result: ExecutionResult):
        """Log execution details for audit trail."""
        log_file = sandbox_path / "logs" / "execution.log"

        log_data = {
            "run_id": run_id,
            "timestamp": time.time(),
            "command": cmd,
            "status": result.status.value,
            "return_code": result.return_code,
            "execution_time": result.execution_time,
            "memory_used": result.memory_used,
            "stdout_length": len(result.stdout),
            "stderr_length": len(result.stderr),
            "error_message": result.error_message
        }

        try:
            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2)

            # Also log to main logger
            self.logger.info(f"Executed command [{run_id}]: {' '.join(cmd)} -> {result.status.value}")

        except Exception as e:
            self.logger.error(f"Failed to write execution log: {e}")

    def secure_run(self,
                   cmd: Union[str, List[str]],
                   timeout: int = 60,
                   cpu_time: int = 30,
                   mem_bytes: int = 500 * 1024 * 1024,  # 500MB
                   allowlist: Optional[List[str]] = None,
                   dry_run: bool = False,
                   working_dir: Optional[str] = None,
                   env_vars: Optional[Dict[str, str]] = None) -> ExecutionResult:
        """
        Execute command securely with comprehensive safety controls.

        Args:
            cmd: Command to execute (string or list)
            timeout: Maximum execution time in seconds
            cpu_time: Maximum CPU time in seconds
            mem_bytes: Maximum memory usage in bytes
            allowlist: Additional allowed binaries for this execution
            dry_run: If True, validate command without executing
            working_dir: Working directory for execution
            env_vars: Additional environment variables

        Returns:
            ExecutionResult with execution details and outputs
        """
        run_id = str(uuid.uuid4())
        start_time = time.time()

        # Create sandbox
        sandbox_path = self._create_sandbox(run_id)

        # Update allowlist if provided
        if allowlist:
            self.allowed_binaries.update(allowlist)

        # Validate command
        cmd_list, validation_error = self._validate_command(cmd)
        if validation_error:
            result = ExecutionResult(
                status=ExecutionStatus.COMMAND_NOT_ALLOWED,
                return_code=-1,
                stdout="",
                stderr="",
                execution_time=0.0,
                memory_used=0,
                command=str(cmd),
                run_id=run_id,
                sandbox_path=str(sandbox_path),
                error_message=validation_error
            )
            self._log_execution(run_id, sandbox_path, cmd_list or [str(cmd)], result)
            return result

        # Dry run - just validate and return
        if dry_run:
            result = ExecutionResult(
                status=ExecutionStatus.DRY_RUN,
                return_code=0,
                stdout=f"DRY RUN: Would execute: {' '.join(cmd_list)}",
                stderr="",
                execution_time=0.0,
                memory_used=0,
                command=' '.join(cmd_list),
                run_id=run_id,
                sandbox_path=str(sandbox_path),
                error_message=None
            )
            self._log_execution(run_id, sandbox_path, cmd_list, result)
            return result

        # Prepare environment
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        # Set working directory
        exec_working_dir = working_dir or str(sandbox_path / "tmp")

        try:
            # Execute command with resource limits
            process = subprocess.Popen(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=exec_working_dir,
                env=env,
                preexec_fn=self._setup_resource_limits(cpu_time, mem_bytes),
                text=True,
                start_new_session=True  # Create new process group
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
                status = ExecutionStatus.SUCCESS
                error_msg = None

            except subprocess.TimeoutExpired:
                # Kill process group to ensure all child processes are terminated
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(1)
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)

                stdout, stderr = process.communicate()
                return_code = -1
                status = ExecutionStatus.TIMEOUT
                error_msg = f"Command timed out after {timeout} seconds"

        except OSError as e:
            if e.errno == 2:  # No such file or directory
                status = ExecutionStatus.BINARY_NOT_FOUND
                error_msg = f"Binary not found: {cmd_list[0]}"
            elif e.errno == 13:  # Permission denied
                status = ExecutionStatus.PERMISSION_DENIED
                error_msg = f"Permission denied: {cmd_list[0]}"
            else:
                status = ExecutionStatus.EXECUTION_ERROR
                error_msg = f"Execution error: {e}"

            stdout, stderr = "", str(e)
            return_code = -1

        except Exception as e:
            status = ExecutionStatus.EXECUTION_ERROR
            error_msg = f"Unexpected error: {e}"
            stdout, stderr = "", str(e)
            return_code = -1

        execution_time = time.time() - start_time

        # Get memory usage (approximation)
        memory_used = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024

        # Create result
        result = ExecutionResult(
            status=status,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            execution_time=execution_time,
            memory_used=memory_used,
            command=' '.join(cmd_list),
            run_id=run_id,
            log_path=str(sandbox_path / "logs" / "execution.log"),
            sandbox_path=str(sandbox_path),
            error_message=error_msg
        )

        # Save outputs to sandbox
        try:
            (sandbox_path / "output" / "stdout.txt").write_text(stdout)
            (sandbox_path / "output" / "stderr.txt").write_text(stderr)
        except Exception as e:
            self.logger.warning(f"Failed to save outputs: {e}")

        # Log execution
        self._log_execution(run_id, sandbox_path, cmd_list, result)

        return result

    def cleanup_sandbox(self, run_id: str, keep_logs: bool = True) -> bool:
        """
        Clean up sandbox directory after execution.

        Args:
            run_id: Run ID to clean up
            keep_logs: Whether to keep log files

        Returns:
            True if cleanup successful, False otherwise
        """
        sandbox_path = self.sandbox_base_dir / run_id

        if not sandbox_path.exists():
            return True

        try:
            if keep_logs:
                # Only remove input, output, and tmp directories
                for subdir in ['input', 'output', 'tmp']:
                    subdir_path = sandbox_path / subdir
                    if subdir_path.exists():
                        import shutil
                        shutil.rmtree(subdir_path)
            else:
                # Remove entire sandbox
                import shutil
                shutil.rmtree(sandbox_path)

            return True

        except Exception as e:
            self.logger.error(f"Failed to cleanup sandbox {run_id}: {e}")
            return False

    def get_sandbox_info(self, run_id: str) -> Dict[str, Any]:
        """Get information about a sandbox run."""
        sandbox_path = self.sandbox_base_dir / run_id

        if not sandbox_path.exists():
            return {"error": "Sandbox not found"}

        log_file = sandbox_path / "logs" / "execution.log"

        info = {
            "run_id": run_id,
            "sandbox_path": str(sandbox_path),
            "exists": True,
            "log_available": log_file.exists()
        }

        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    log_data = json.load(f)
                info["execution_log"] = log_data
            except Exception as e:
                info["log_error"] = str(e)

        return info


# Global instance for easy access
_global_runner = None


def get_secure_runner() -> SecureRunner:
    """Get global SecureRunner instance."""
    global _global_runner
    if _global_runner is None:
        _global_runner = SecureRunner()
    return _global_runner


def secure_run(cmd: Union[str, List[str]], **kwargs) -> ExecutionResult:
    """Convenience function for secure command execution."""
    return get_secure_runner().secure_run(cmd, **kwargs)


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)

    # Create runner
    runner = SecureRunner()

    # Test commands
    test_commands = [
        "echo 'Hello World'",
        "ls -la",
        "python3 --version",
        ["echo", "test with list"],
        "sleep 5",  # Will timeout
        "cat /etc/passwd",  # Should be allowed but file may not exist
        "rm -rf /",  # Should be blocked
        "invalid_command",  # Should fail
    ]

    print("Testing SecureRunner:")
    print("=" * 50)

    for cmd in test_commands:
        print(f"\nTesting: {cmd}")
        result = runner.secure_run(cmd, timeout=3, dry_run=False)
        print(f"Status: {result.status.value}")
        print(f"Return code: {result.return_code}")
        print(f"Execution time: {result.execution_time:.3f}s")
        if result.stdout:
            print(f"Stdout: {result.stdout[:100]}...")
        if result.error_message:
            print(f"Error: {result.error_message}")
        print("-" * 30)