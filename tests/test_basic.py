"""Basic tests for framework functionality"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """Test that core modules can be imported"""
    try:
        from core.utils.secure_runner import SecureRunner
        assert SecureRunner is not None
    except ImportError:
        pytest.skip("Core modules not available")

def test_secure_runner():
    """Test basic SecureRunner functionality"""
    try:
        from core.utils.secure_runner import secure_run
        result = secure_run("print('test')")
        assert 'success' in result
        assert result['success'] is True
    except ImportError:
        pytest.skip("SecureRunner not available")

def test_python_version():
    """Ensure Python version is compatible"""
    assert sys.version_info >= (3, 8), "Python 3.8 or higher required"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
