#!/usr/bin/env python3
"""
Smoke test for vulnerability detection framework
Tests core functionality without requiring heavy ML dependencies
"""

import os
import sys
import json
import tempfile
from pathlib import Path

def test_project_structure():
    """Test that required project structure exists"""
    print("Testing project structure...")

    required_dirs = [
        'src', 'tests', 'config', 'models', 'data',
        'case_studies', 'tools/bin', 'sandbox_runs'
    ]

    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✅ {directory}/ exists")
        else:
            print(f"❌ {directory}/ missing")
            return False

    required_files = [
        'UNIFIED_FLAGSHIP_MANUSCRIPT.md',
        'REPRODUCIBILITY_PACKAGE.md',
        'src/utils/secure_runner.py',
        'case_studies/real_cve_examples.py',
        'config/settings.yaml'
    ]

    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✅ {file_path} exists")
        else:
            print(f"❌ {file_path} missing")
            return False

    return True

def test_secure_runner():
    """Test secure runner functionality"""
    print("\nTesting secure runner...")

    try:
        from src.utils.secure_runner import SecureRunner, ExecutionStatus

        # Create temporary runner
        with tempfile.TemporaryDirectory() as temp_dir:
            runner = SecureRunner(
                sandbox_base_dir=os.path.join(temp_dir, "sandbox"),
                tools_bin_dir=os.path.join(temp_dir, "tools")
            )

            # Test dry run
            result = runner.secure_run("echo test", dry_run=True)

            if result.status == ExecutionStatus.DRY_RUN:
                print("✅ Secure runner dry run successful")
                return True
            else:
                print(f"❌ Secure runner dry run failed: {result.status}")
                return False

    except Exception as e:
        print(f"❌ Secure runner test failed: {e}")
        return False

def test_cve_database():
    """Test CVE examples functionality"""
    print("\nTesting CVE database...")

    try:
        from case_studies.real_cve_examples import RealCVEDatabase

        cve_db = RealCVEDatabase()

        # Test basic functionality
        all_cves = cve_db.get_all_cves()
        if len(all_cves) >= 5:
            print(f"✅ CVE database loaded with {len(all_cves)} examples")
        else:
            print(f"❌ CVE database has insufficient examples: {len(all_cves)}")
            return False

        # Test specific CVE
        log4j = cve_db.get_cve_by_id("CVE-2021-44228")
        if log4j and log4j.title:
            print("✅ Log4j CVE example accessible")
        else:
            print("❌ Log4j CVE example not found")
            return False

        # Test dataset generation
        test_data = cve_db.generate_test_dataset()
        if len(test_data) >= 10:
            print(f"✅ Test dataset generated with {len(test_data)} samples")
        else:
            print(f"❌ Test dataset insufficient: {len(test_data)}")
            return False

        return True

    except Exception as e:
        print(f"❌ CVE database test failed: {e}")
        return False

def test_configuration():
    """Test configuration loading"""
    print("\nTesting configuration...")

    try:
        import yaml

        config_path = "config/settings.yaml"
        if not os.path.exists(config_path):
            print(f"❌ Configuration file missing: {config_path}")
            return False

        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        required_sections = ['model', 'data', 'training', 'vulnerability_types']
        for section in required_sections:
            if section in config:
                print(f"✅ Configuration section '{section}' present")
            else:
                print(f"❌ Configuration section '{section}' missing")
                return False

        # Test vulnerability types
        vuln_types = config.get('vulnerability_types', [])
        if len(vuln_types) >= 20:
            print(f"✅ Vulnerability types defined: {len(vuln_types)}")
        else:
            print(f"❌ Insufficient vulnerability types: {len(vuln_types)}")
            return False

        return True

    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_documentation():
    """Test documentation completeness"""
    print("\nTesting documentation...")

    docs = [
        'UNIFIED_FLAGSHIP_MANUSCRIPT.md',
        'REPRODUCIBILITY_PACKAGE.md',
        'ORIGINALITY_AND_CONTRIBUTIONS.md',
        'SAFE_EXECUTION_README.md'
    ]

    for doc in docs:
        if os.path.exists(doc):
            with open(doc, 'r') as f:
                content = f.read()
                if len(content) > 1000:  # Substantial content
                    print(f"✅ {doc} exists with substantial content ({len(content)} chars)")
                else:
                    print(f"⚠️  {doc} exists but content is minimal ({len(content)} chars)")
        else:
            print(f"❌ {doc} missing")
            return False

    return True

def main():
    """Run all smoke tests"""
    print("🧪 Running Vulnerability Detection Framework Smoke Tests")
    print("=" * 60)

    tests = [
        test_project_structure,
        test_secure_runner,
        test_cve_database,
        test_configuration,
        test_documentation
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if test():
                passed += 1
            print()  # Add spacing between tests
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            print()

    print("=" * 60)
    print(f"SMOKE TEST RESULTS: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All smoke tests PASSED - Framework is ready!")
        return 0
    else:
        print("⚠️  Some smoke tests FAILED - Review issues above")
        return 1

if __name__ == "__main__":
    sys.exit(main())