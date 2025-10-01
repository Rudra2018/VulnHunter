"""
Unit tests for SecureRunner module.

These tests validate the security controls and functionality of the secure
command execution system used throughout the vulnerability detection pipeline.
"""

import unittest
import tempfile
import shutil
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the module under test
from src.utils.secure_runner import (
    SecureRunner, ExecutionResult, ExecutionStatus,
    get_secure_runner, secure_run
)


class TestSecureRunner(unittest.TestCase):
    """Test cases for SecureRunner class."""

    def setUp(self):
        """Set up test environment."""
        # Create temporary directories for testing
        self.test_dir = tempfile.mkdtemp()
        self.sandbox_dir = os.path.join(self.test_dir, "sandbox_runs")
        self.tools_dir = os.path.join(self.test_dir, "tools", "bin")

        # Create test directories
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.tools_dir, exist_ok=True)

        # Create a test binary in tools directory
        test_script = os.path.join(self.tools_dir, "test_echo")
        with open(test_script, 'w') as f:
            f.write('#!/bin/bash\necho "test output: $1"\n')
        os.chmod(test_script, 0o755)

        # Initialize SecureRunner with test directories
        self.runner = SecureRunner(
            sandbox_base_dir=self.sandbox_dir,
            tools_bin_dir=self.tools_dir
        )

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_initialization(self):
        """Test SecureRunner initialization."""
        self.assertTrue(Path(self.sandbox_dir).exists())
        self.assertTrue(Path(self.tools_dir).exists())
        self.assertIsInstance(self.runner.allowed_binaries, set)
        self.assertIn('echo', self.runner.allowed_binaries)

    def test_command_validation_success(self):
        """Test successful command validation."""
        cmd_list, error = self.runner._validate_command("echo hello")
        self.assertIsNone(error)
        self.assertEqual(cmd_list, ['echo', 'hello'])

    def test_command_validation_dangerous_patterns(self):
        """Test command validation blocks dangerous patterns."""
        dangerous_commands = [
            "echo hello && rm -rf /",
            "ls | cat",
            "echo `whoami`",
            "rm -rf /tmp",
            "dd if=/dev/zero of=/dev/sda"
        ]

        for cmd in dangerous_commands:
            cmd_list, error = self.runner._validate_command(cmd)
            self.assertIsNotNone(error, f"Should block dangerous command: {cmd}")

    def test_command_validation_disallowed_binary(self):
        """Test command validation blocks disallowed binaries."""
        cmd_list, error = self.runner._validate_command("forbidden_binary arg1")
        self.assertIsNotNone(error)
        self.assertIn("not in allowlist", error)

    def test_simple_command_execution(self):
        """Test execution of simple safe command."""
        result = self.runner.secure_run("echo 'Hello World'", timeout=5)

        self.assertEqual(result.status, ExecutionStatus.SUCCESS)
        self.assertEqual(result.return_code, 0)
        self.assertIn("Hello World", result.stdout)
        self.assertTrue(result.execution_time >= 0)
        self.assertIsNotNone(result.run_id)

    def test_command_timeout(self):
        """Test command timeout handling."""
        # This command should timeout (sleep longer than timeout)
        result = self.runner.secure_run("sleep 10", timeout=2)

        self.assertEqual(result.status, ExecutionStatus.TIMEOUT)
        self.assertEqual(result.return_code, -1)
        self.assertIsNotNone(result.error_message)
        self.assertIn("timed out", result.error_message)

    def test_nonexistent_binary(self):
        """Test handling of non-existent binary."""
        result = self.runner.secure_run("nonexistent_command", timeout=5)

        self.assertEqual(result.status, ExecutionStatus.COMMAND_NOT_ALLOWED)
        self.assertEqual(result.return_code, -1)

    def test_dry_run_mode(self):
        """Test dry run mode validation."""
        result = self.runner.secure_run("echo test", dry_run=True)

        self.assertEqual(result.status, ExecutionStatus.DRY_RUN)
        self.assertEqual(result.return_code, 0)
        self.assertIn("DRY RUN", result.stdout)
        self.assertEqual(result.execution_time, 0.0)

    def test_sandbox_creation(self):
        """Test sandbox directory creation."""
        run_id = "test_run_123"
        sandbox_path = self.runner._create_sandbox(run_id)

        self.assertTrue(sandbox_path.exists())
        self.assertTrue((sandbox_path / "input").exists())
        self.assertTrue((sandbox_path / "output").exists())
        self.assertTrue((sandbox_path / "logs").exists())
        self.assertTrue((sandbox_path / "tmp").exists())

    def test_allowed_path_validation(self):
        """Test path validation for allowed directories."""
        # Test tools directory path
        tools_binary = Path(self.tools_dir) / "test_echo"
        self.assertTrue(self.runner._is_allowed_path(tools_binary))

        # Test system binary paths (these should be allowed if in allowlist)
        system_echo = Path("/bin/echo")
        if system_echo.exists():
            self.assertTrue(self.runner._is_allowed_path(system_echo))

        # Test disallowed path
        random_path = Path("/usr/local/suspicious_binary")
        self.assertFalse(self.runner._is_allowed_path(random_path))

    def test_memory_limit_enforcement(self):
        """Test memory limit enforcement (if possible to test)."""
        # This test might not work on all systems due to memory limit enforcement
        # being OS-dependent, but we can test the parameter passing
        result = self.runner.secure_run(
            "echo test",
            mem_bytes=1024*1024,  # 1MB limit
            timeout=5
        )

        # Should still succeed for simple echo command
        self.assertEqual(result.status, ExecutionStatus.SUCCESS)

    def test_custom_allowlist(self):
        """Test custom allowlist functionality."""
        # Add custom binary to allowlist for this execution
        result = self.runner.secure_run(
            "custom_binary arg",
            allowlist=["custom_binary"],
            dry_run=True  # Use dry run since binary doesn't exist
        )

        # Should pass validation due to custom allowlist
        # (but would fail in actual execution since binary doesn't exist)
        self.assertEqual(result.status, ExecutionStatus.DRY_RUN)

    def test_environment_variables(self):
        """Test custom environment variables."""
        result = self.runner.secure_run(
            ["python3", "-c", "import os; print(os.environ.get('TEST_VAR', 'not_found'))"],
            env_vars={"TEST_VAR": "test_value"},
            timeout=5
        )

        if result.status == ExecutionStatus.SUCCESS:
            self.assertIn("test_value", result.stdout)

    def test_working_directory(self):
        """Test custom working directory."""
        # Create a test file in sandbox
        test_file = os.path.join(self.test_dir, "test_file.txt")
        with open(test_file, 'w') as f:
            f.write("test content")

        result = self.runner.secure_run(
            "ls -la",
            working_dir=self.test_dir,
            timeout=5
        )

        if result.status == ExecutionStatus.SUCCESS:
            self.assertIn("test_file.txt", result.stdout)

    def test_sandbox_cleanup(self):
        """Test sandbox cleanup functionality."""
        # Execute a command to create sandbox
        result = self.runner.secure_run("echo test", timeout=5)
        run_id = result.run_id

        # Verify sandbox exists
        sandbox_path = Path(self.sandbox_dir) / run_id
        self.assertTrue(sandbox_path.exists())

        # Clean up sandbox
        cleanup_success = self.runner.cleanup_sandbox(run_id, keep_logs=True)
        self.assertTrue(cleanup_success)

        # Verify logs are kept but other directories removed
        self.assertTrue((sandbox_path / "logs").exists())

        # Clean up completely
        cleanup_success = self.runner.cleanup_sandbox(run_id, keep_logs=False)
        self.assertTrue(cleanup_success)
        self.assertFalse(sandbox_path.exists())

    def test_get_sandbox_info(self):
        """Test sandbox information retrieval."""
        # Execute a command
        result = self.runner.secure_run("echo test", timeout=5)
        run_id = result.run_id

        # Get sandbox info
        info = self.runner.get_sandbox_info(run_id)

        self.assertEqual(info["run_id"], run_id)
        self.assertTrue(info["exists"])
        self.assertTrue(info["log_available"])
        self.assertIn("execution_log", info)

    def test_list_command_parsing(self):
        """Test command provided as list instead of string."""
        result = self.runner.secure_run(["echo", "hello", "world"], timeout=5)

        self.assertEqual(result.status, ExecutionStatus.SUCCESS)
        self.assertIn("hello world", result.stdout)

    def test_malformed_command_string(self):
        """Test handling of malformed command strings."""
        # Command with unmatched quotes
        result = self.runner.secure_run("echo 'unmatched quote", timeout=5)

        self.assertEqual(result.status, ExecutionStatus.COMMAND_NOT_ALLOWED)
        self.assertIsNotNone(result.error_message)

    def test_empty_command(self):
        """Test handling of empty commands."""
        result = self.runner.secure_run("", timeout=5)

        self.assertEqual(result.status, ExecutionStatus.COMMAND_NOT_ALLOWED)
        self.assertIn("Empty command", result.error_message)

    def test_resource_limits_configuration(self):
        """Test resource limits are properly configured."""
        # This is mainly testing that the function doesn't crash
        # Actual resource limit enforcement is OS-dependent
        limit_func = self.runner._setup_resource_limits(30, 500*1024*1024)
        self.assertIsNotNone(limit_func)

        # Test calling the limit function (should not raise exception)
        try:
            limit_func()
        except Exception as e:
            # Some systems might not support all resource limits
            self.skipTest(f"Resource limits not supported on this system: {e}")


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions."""

    def test_get_secure_runner_singleton(self):
        """Test global runner singleton behavior."""
        runner1 = get_secure_runner()
        runner2 = get_secure_runner()

        self.assertIs(runner1, runner2)  # Should be same instance

    def test_convenience_secure_run_function(self):
        """Test convenience secure_run function."""
        result = secure_run("echo convenience_test", timeout=5)

        self.assertIsInstance(result, ExecutionResult)
        if result.status == ExecutionStatus.SUCCESS:
            self.assertIn("convenience_test", result.stdout)


class TestSecurityFeatures(unittest.TestCase):
    """Test specific security features."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.runner = SecureRunner(
            sandbox_base_dir=os.path.join(self.test_dir, "sandbox"),
            tools_bin_dir=os.path.join(self.test_dir, "tools")
        )

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_command_injection_prevention(self):
        """Test prevention of command injection attacks."""
        injection_attempts = [
            "echo hello; cat /etc/passwd",
            "echo hello && whoami",
            "echo hello || ls -la /",
            "echo hello | cat",
            "echo hello > /tmp/evil",
            "echo `id`",
            "echo $(whoami)"
        ]

        for attempt in injection_attempts:
            result = self.runner.secure_run(attempt, timeout=5)
            self.assertEqual(result.status, ExecutionStatus.COMMAND_NOT_ALLOWED,
                           f"Should block injection attempt: {attempt}")

    def test_path_traversal_prevention(self):
        """Test prevention of path traversal in binary execution."""
        traversal_attempts = [
            "../../../bin/sh",
            "/etc/passwd",
            "../../sensitive_file"
        ]

        for attempt in traversal_attempts:
            result = self.runner.secure_run(attempt, timeout=5)
            self.assertEqual(result.status, ExecutionStatus.COMMAND_NOT_ALLOWED,
                           f"Should block path traversal: {attempt}")

    def test_audit_logging(self):
        """Test that execution is properly logged."""
        result = self.runner.secure_run("echo audit_test", timeout=5)

        # Check that log file was created
        self.assertIsNotNone(result.log_path)
        self.assertTrue(os.path.exists(result.log_path))

        # Verify log contains execution details
        import json
        with open(result.log_path, 'r') as f:
            log_data = json.load(f)

        self.assertEqual(log_data["run_id"], result.run_id)
        self.assertIn("echo", str(log_data["command"]))
        self.assertEqual(log_data["status"], result.status.value)


if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)