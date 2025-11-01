"""
VulnHunter Demo: Command Injection Vulnerabilities
This file contains intentionally vulnerable code for demonstration
"""

import os
import subprocess
import shlex

class FileProcessor:
    """File processing class with security vulnerabilities"""

    def convert_image_vulnerable(self, filename):
        """
        VULNERABLE: Command injection via os.system()
        An attacker could input: "image.jpg; rm -rf /" to execute malicious commands
        """
        command = "convert " + filename + " output.pdf"
        os.system(command)

    def backup_file_vulnerable(self, source_file, backup_dir):
        """
        VULNERABLE: Command injection via subprocess with shell=True
        """
        command = f"cp {source_file} {backup_dir}/"
        subprocess.call(command, shell=True)

    def compress_files_vulnerable(self, file_list):
        """
        VULNERABLE: Command injection in file list processing
        """
        files_str = " ".join(file_list)
        command = f"tar -czf archive.tar.gz {files_str}"
        os.system(command)

    def ping_host_vulnerable(self, hostname):
        """
        VULNERABLE: Command injection in network operations
        """
        command = "ping -c 4 " + hostname
        result = os.popen(command).read()
        return result

    def process_log_vulnerable(self, log_file, pattern):
        """
        VULNERABLE: Command injection in log processing
        """
        command = f"grep '{pattern}' {log_file} | wc -l"
        result = subprocess.check_output(command, shell=True)
        return result.decode()

class SecureFileProcessor:
    """Secure implementation of file processing"""

    def convert_image_secure(self, filename):
        """
        SECURE: Using subprocess with list arguments
        """
        if not self._is_safe_filename(filename):
            raise ValueError("Invalid filename")

        try:
            subprocess.run(["convert", filename, "output.pdf"], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Conversion failed: {e}")

    def backup_file_secure(self, source_file, backup_dir):
        """
        SECURE: Proper argument handling
        """
        if not self._is_safe_path(source_file) or not self._is_safe_path(backup_dir):
            raise ValueError("Invalid file paths")

        try:
            subprocess.run(["cp", source_file, backup_dir + "/"], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Backup failed: {e}")

    def compress_files_secure(self, file_list):
        """
        SECURE: Validate and sanitize file list
        """
        safe_files = []
        for file_path in file_list:
            if self._is_safe_path(file_path):
                safe_files.append(file_path)

        if not safe_files:
            raise ValueError("No valid files to compress")

        command = ["tar", "-czf", "archive.tar.gz"] + safe_files
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Compression failed: {e}")

    def ping_host_secure(self, hostname):
        """
        SECURE: Validate hostname and use safe subprocess call
        """
        if not self._is_valid_hostname(hostname):
            raise ValueError("Invalid hostname")

        try:
            result = subprocess.run(
                ["ping", "-c", "4", hostname],
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Ping failed: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Ping timeout")

    def process_log_secure(self, log_file, pattern):
        """
        SECURE: Safe log processing with validation
        """
        if not self._is_safe_path(log_file):
            raise ValueError("Invalid log file path")

        if not self._is_safe_pattern(pattern):
            raise ValueError("Invalid search pattern")

        try:
            # Use grep with safe arguments
            grep_result = subprocess.run(
                ["grep", pattern, log_file],
                capture_output=True,
                text=True,
                check=False  # grep returns 1 if no matches
            )

            # Count lines
            line_count = len(grep_result.stdout.splitlines())
            return str(line_count)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Log processing failed: {e}")

    def _is_safe_filename(self, filename):
        """Validate filename for safety"""
        if not filename or len(filename) > 255:
            return False

        # Check for dangerous characters
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]"]
        return not any(char in filename for char in dangerous_chars)

    def _is_safe_path(self, path):
        """Validate file path for safety"""
        if not path or ".." in path or path.startswith("/"):
            return False

        return self._is_safe_filename(os.path.basename(path))

    def _is_valid_hostname(self, hostname):
        """Validate hostname format"""
        import re
        pattern = r'^[a-zA-Z0-9.-]+$'
        return bool(re.match(pattern, hostname)) and len(hostname) <= 253

    def _is_safe_pattern(self, pattern):
        """Validate search pattern"""
        if not pattern or len(pattern) > 100:
            return False

        # Basic validation - could be more sophisticated
        dangerous_chars = [";", "&", "|", "`", "$"]
        return not any(char in pattern for char in dangerous_chars)

# Example usage demonstrating vulnerabilities
if __name__ == "__main__":
    vulnerable_processor = FileProcessor()
    secure_processor = SecureFileProcessor()

    # Vulnerable usage
    # vulnerable_processor.convert_image_vulnerable("image.jpg; rm important.txt")

    # Safe usage
    try:
        secure_processor.convert_image_secure("image.jpg")
        print("Secure conversion completed")
    except Exception as e:
        print(f"Error: {e}")