#!/usr/bin/env python3
"""
Smoke test for Security Intelligence Framework
Verifies that all critical dependencies are installed and working
"""

import sys
import warnings
warnings.filterwarnings('ignore')

def test_imports():
    """Test all critical imports"""
    print("🔍 Testing critical imports...")

    try:
        import torch
        print(f"✓ PyTorch {torch.__version__} (CUDA: {torch.cuda.is_available()})")
    except ImportError as e:
        print(f"✗ PyTorch import failed: {e}")
        return False

    try:
        import transformers
        print(f"✓ Transformers {transformers.__version__}")
    except ImportError as e:
        print(f"✗ Transformers import failed: {e}")
        return False

    try:
        import sklearn
        print(f"✓ scikit-learn {sklearn.__version__}")
    except ImportError as e:
        print(f"✗ scikit-learn import failed: {e}")
        return False

    try:
        import xgboost
        print(f"✓ XGBoost {xgboost.__version__}")
    except ImportError as e:
        print(f"✗ XGBoost import failed: {e}")
        return False

    try:
        import pandas as pd
        import numpy as np
        print(f"✓ Pandas {pd.__version__}, NumPy {np.__version__}")
    except ImportError as e:
        print(f"✗ Pandas/NumPy import failed: {e}")
        return False

    return True

def test_core_modules():
    """Test core module imports"""
    print("\n🔍 Testing core modules...")

    try:
        from core.utils.secure_runner import SecureRunner
        print("✓ SecureRunner available")
    except ImportError:
        print("⚠ SecureRunner not found (optional)")

    # Test if any core modules exist
    try:
        import os
        core_files = [f for f in os.listdir('core') if f.endswith('.py') and not f.startswith('__')]
        print(f"✓ Found {len(core_files)} core modules")
    except Exception as e:
        print(f"⚠ Could not list core modules: {e}")

    return True

def test_environment():
    """Test environment configuration"""
    print("\n🔍 Testing environment...")

    import os
    pythonpath = os.environ.get('PYTHONPATH', 'Not set')
    print(f"✓ PYTHONPATH: {pythonpath}")

    return True

def main():
    """Run all smoke tests"""
    print("=" * 60)
    print("Security Intelligence Framework - Smoke Test")
    print("=" * 60)

    tests = [
        test_imports,
        test_core_modules,
        test_environment
    ]

    all_passed = True
    for test in tests:
        try:
            if not test():
                all_passed = False
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All smoke tests passed!")
        print("=" * 60)
        return 0
    else:
        print("✗ Some tests failed")
        print("=" * 60)
        return 1

if __name__ == "__main__":
    sys.exit(main())
