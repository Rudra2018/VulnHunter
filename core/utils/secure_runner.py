"""
Secure code execution utilities for vulnerability analysis
Provides sandboxed execution capabilities
"""

import subprocess
import os
import tempfile
from typing import Dict, Any, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecureRunner:
    """
    Secure code execution sandbox for vulnerability analysis
    """

    def __init__(self, timeout: int = 30):
        """
        Initialize SecureRunner

        Args:
            timeout: Maximum execution time in seconds
        """
        self.timeout = timeout
        self.temp_dir = tempfile.mkdtemp(prefix="secure_run_")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup temporary directory"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp dir: {e}")

    def run_code(self, code: str, language: str = "python") -> Tuple[bool, str, str]:
        """
        Execute code in a sandboxed environment

        Args:
            code: Code to execute
            language: Programming language

        Returns:
            Tuple of (success, stdout, stderr)
        """
        if language == "python":
            return self._run_python(code)
        else:
            raise ValueError(f"Unsupported language: {language}")

    def _run_python(self, code: str) -> Tuple[bool, str, str]:
        """
        Run Python code securely

        Args:
            code: Python code to execute

        Returns:
            Tuple of (success, stdout, stderr)
        """
        # Write code to temporary file
        code_file = os.path.join(self.temp_dir, "code.py")
        with open(code_file, 'w') as f:
            f.write(code)

        try:
            # Run with restricted permissions
            result = subprocess.run(
                ["python3", code_file],
                timeout=self.timeout,
                capture_output=True,
                text=True,
                cwd=self.temp_dir
            )

            return (
                result.returncode == 0,
                result.stdout,
                result.stderr
            )
        except subprocess.TimeoutExpired:
            return False, "", f"Execution timed out after {self.timeout}s"
        except Exception as e:
            return False, "", f"Execution failed: {str(e)}"

def secure_run(code: str, language: str = "python", timeout: int = 30) -> Dict[str, Any]:
    """
    Convenience function for secure code execution

    Args:
        code: Code to execute
        language: Programming language
        timeout: Maximum execution time

    Returns:
        Dictionary with execution results
    """
    with SecureRunner(timeout=timeout) as runner:
        success, stdout, stderr = runner.run_code(code, language)

        return {
            "success": success,
            "stdout": stdout,
            "stderr": stderr,
            "language": language
        }

# Simple test
if __name__ == "__main__":
    result = secure_run("print('Hello from SecureRunner')")
    print(f"Execution result: {result}")
