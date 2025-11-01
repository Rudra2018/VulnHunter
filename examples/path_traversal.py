"""
VulnHunter Demo: Path Traversal Vulnerabilities
This file contains intentionally vulnerable code for demonstration
"""

import os
import tempfile
from pathlib import Path

class FileManager:
    """File management class with path traversal vulnerabilities"""

    def __init__(self, base_dir="/app/uploads"):
        self.base_dir = base_dir

    def read_user_file_vulnerable(self, filename):
        """
        VULNERABLE: Direct file access without validation
        An attacker could use "../../../etc/passwd" to read sensitive files
        """
        file_path = self.base_dir + "/" + filename
        with open(file_path, 'r') as f:
            return f.read()

    def save_upload_vulnerable(self, filename, content):
        """
        VULNERABLE: File writing without path validation
        """
        file_path = os.path.join(self.base_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)

    def delete_file_vulnerable(self, filename):
        """
        VULNERABLE: File deletion without validation
        """
        file_path = self.base_dir + "/" + filename
        os.remove(file_path)

    def get_file_info_vulnerable(self, filename):
        """
        VULNERABLE: File info access
        """
        file_path = f"{self.base_dir}/{filename}"
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'modified': stat.st_mtime
            }
        return None

    def list_directory_vulnerable(self, subdir):
        """
        VULNERABLE: Directory listing without validation
        """
        dir_path = os.path.join(self.base_dir, subdir)
        return os.listdir(dir_path)

class SecureFileManager:
    """Secure implementation with proper path validation"""

    def __init__(self, base_dir="/app/uploads"):
        self.base_dir = os.path.abspath(base_dir)
        # Ensure base directory exists and is secure
        os.makedirs(self.base_dir, exist_ok=True)

    def read_user_file_secure(self, filename):
        """
        SECURE: Validates file path to prevent traversal
        """
        safe_path = self._get_safe_path(filename)

        if not os.path.exists(safe_path):
            raise FileNotFoundError(f"File not found: {filename}")

        if not os.path.isfile(safe_path):
            raise ValueError(f"Not a file: {filename}")

        try:
            with open(safe_path, 'r', encoding='utf-8') as f:
                return f.read()
        except IOError as e:
            raise RuntimeError(f"Failed to read file: {e}")

    def save_upload_secure(self, filename, content):
        """
        SECURE: Validates filename and path
        """
        if not self._is_safe_filename(filename):
            raise ValueError("Invalid filename")

        safe_path = self._get_safe_path(filename)

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)

        try:
            with open(safe_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except IOError as e:
            raise RuntimeError(f"Failed to save file: {e}")

    def delete_file_secure(self, filename):
        """
        SECURE: Safe file deletion with validation
        """
        safe_path = self._get_safe_path(filename)

        if not os.path.exists(safe_path):
            raise FileNotFoundError(f"File not found: {filename}")

        if not os.path.isfile(safe_path):
            raise ValueError(f"Not a file: {filename}")

        try:
            os.remove(safe_path)
        except OSError as e:
            raise RuntimeError(f"Failed to delete file: {e}")

    def get_file_info_secure(self, filename):
        """
        SECURE: Safe file info retrieval
        """
        safe_path = self._get_safe_path(filename)

        if not os.path.exists(safe_path):
            return None

        if not os.path.isfile(safe_path):
            return None

        try:
            stat = os.stat(safe_path)
            return {
                'filename': os.path.basename(safe_path),
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'is_file': True
            }
        except OSError:
            return None

    def list_directory_secure(self, subdir=""):
        """
        SECURE: Safe directory listing
        """
        if subdir:
            if not self._is_safe_filename(subdir):
                raise ValueError("Invalid subdirectory name")

        safe_path = self._get_safe_path(subdir) if subdir else self.base_dir

        if not os.path.exists(safe_path):
            raise FileNotFoundError(f"Directory not found: {subdir}")

        if not os.path.isdir(safe_path):
            raise ValueError(f"Not a directory: {subdir}")

        try:
            entries = []
            for entry in os.listdir(safe_path):
                entry_path = os.path.join(safe_path, entry)
                entries.append({
                    'name': entry,
                    'is_file': os.path.isfile(entry_path),
                    'is_dir': os.path.isdir(entry_path)
                })
            return entries
        except OSError as e:
            raise RuntimeError(f"Failed to list directory: {e}")

    def _get_safe_path(self, filename):
        """
        Generate safe file path preventing directory traversal
        """
        if not filename:
            raise ValueError("Empty filename")

        # Normalize and resolve the path
        requested_path = os.path.normpath(os.path.join(self.base_dir, filename))

        # Ensure the resolved path is within base directory
        if not requested_path.startswith(self.base_dir):
            raise ValueError("Path traversal detected")

        return requested_path

    def _is_safe_filename(self, filename):
        """
        Validate filename for security
        """
        if not filename or len(filename) > 255:
            return False

        # Check for dangerous characters and patterns
        dangerous_patterns = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']

        for pattern in dangerous_patterns:
            if pattern in filename:
                return False

        # Check for reserved names (Windows)
        reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3',
                         'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                         'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6',
                         'LPT7', 'LPT8', 'LPT9']

        if filename.upper() in reserved_names:
            return False

        return True

# Example usage demonstrating vulnerabilities
if __name__ == "__main__":
    # Create temporary directory for demo
    temp_dir = tempfile.mkdtemp()

    vulnerable_manager = FileManager(temp_dir)
    secure_manager = SecureFileManager(temp_dir)

    # Create a test file
    test_content = "This is a test file content"

    print("=== Secure File Operations ===")
    try:
        # Safe operations
        secure_manager.save_upload_secure("test.txt", test_content)
        content = secure_manager.read_user_file_secure("test.txt")
        print(f"File content: {content[:50]}...")

        info = secure_manager.get_file_info_secure("test.txt")
        print(f"File info: {info}")

        # This would be blocked by security checks
        try:
            secure_manager.read_user_file_secure("../../etc/passwd")
        except ValueError as e:
            print(f"Security check worked: {e}")

    except Exception as e:
        print(f"Error: {e}")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)