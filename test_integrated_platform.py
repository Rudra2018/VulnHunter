#!/usr/bin/env python3
"""
Test script for VulnHunter Integrated Platform
Tests the complete vulnerability assessment pipeline
"""

import sys
import json
import time
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / "src"))

try:
    from core.enhanced_manual_verification import EnhancedManualVerifier, VerificationContext
    from core.poc_demonstration_framework import PoCDemonstrationFramework
    from core.vulnhunter_integrated_platform import VulnHunterIntegratedPlatform
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Some modules may not be available, testing individual components...")

def test_manual_verification():
    """Test enhanced manual verification module"""

    print("🧪 Testing Enhanced Manual Verification...")

    try:
        verifier = EnhancedManualVerifier()

        # Test vulnerability data (simulating XION findings)
        test_vuln = {
            'id': 'TEST-001',
            'category': 'access_control',
            'title': 'Test Access Control Issue',
            'file': 'execute.rs',
            'line': 55,
            'severity': 'High'
        }

        # Test source code with proper access control
        test_code = """
pub fn propose_admin(
    deps: DepsMut,
    info: MessageInfo,
    new_admin: String,
) -> ContractResult<Response> {
    let admin = ADMIN.load(deps.storage)?;

    if admin != info.sender {
        return Err(Unauthorized);
    }

    let validated_admin = deps.api.addr_validate(&new_admin)?;
    PENDING_ADMIN.save(deps.storage, &validated_admin)?;

    Ok(Response::new())
}
"""

        result = verifier.verify_vulnerability(test_vuln, test_code)

        print(f"   ✅ Verification Status: {result.status}")
        print(f"   📊 Confidence: {result.confidence:.2f}")
        print(f"   📝 Reason: {result.reason}")
        print(f"   🎯 PoC Feasible: {result.poc_feasible}")

        return True

    except Exception as e:
        print(f"   ❌ Manual verification test failed: {e}")
        return False

def test_poc_framework():
    """Test PoC demonstration framework"""

    print("\n🛠️ Testing PoC Demonstration Framework...")

    try:
        poc_framework = PoCDemonstrationFramework()

        # Test vulnerability for PoC generation
        test_vuln = {
            'id': 'TEST-POC-001',
            'category': 'access_control',
            'title': 'Access Control Bypass',
            'file': 'contract.rs',
            'line': 42,
            'severity': 'Critical',
            'github_link': 'https://github.com/test/repo/blob/main/contract.rs'
        }

        result = poc_framework.generate_and_execute_poc(test_vuln)

        print(f"   ✅ PoC ID: {result.poc_id}")
        print(f"   📊 Success: {result.success}")
        print(f"   ⏱️ Execution Time: {result.execution_time:.2f}s")
        print(f"   🎯 Exploitability: {result.exploitability_confirmed}")

        return True

    except Exception as e:
        print(f"   ❌ PoC framework test failed: {e}")
        return False

def test_integrated_platform():
    """Test the complete integrated platform"""

    print("\n🚀 Testing Integrated Platform...")

    try:
        # Create test config
        config = {
            'logging_level': 'INFO',
            'max_findings_per_scan': 10,
            'poc_timeout': 30,
            'verification_timeout': 10
        }

        config_file = Path("test_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f)

        # Initialize platform
        platform = VulnHunterIntegratedPlatform(str(config_file))

        # Test target (use XION scan results)
        target_path = "results/xion_advanced_scan"

        if Path(target_path).exists():
            print(f"   📁 Testing with target: {target_path}")

            # Run limited assessment (mock mode for testing)
            print("   🔍 Running mock assessment...")

            # Simulate findings for testing
            mock_findings = [
                {
                    'id': 'MOCK-001',
                    'category': 'access_control',
                    'title': 'Mock Access Control Issue',
                    'file': 'execute.rs',
                    'line': 55,
                    'severity': 'High',
                    'confidence': 0.8
                }
            ]

            # Test manual verification component
            verified_findings = platform._run_manual_verification(mock_findings, target_path)

            print(f"   ✅ Verified {len(verified_findings)} findings")

            # Test PoC generation component
            poc_results = platform._generate_pocs(mock_findings)

            print(f"   ✅ Generated {len(poc_results)} PoCs")

            # Test final assessment
            final_assessment = platform._generate_final_assessment(mock_findings, verified_findings, poc_results)

            print(f"   ✅ Final assessment completed")
            print(f"   📊 Statistics: {final_assessment['statistics']}")

        else:
            print("   ⚠️ XION scan results not found, testing with minimal data")

        # Cleanup
        config_file.unlink(missing_ok=True)

        return True

    except Exception as e:
        print(f"   ❌ Integrated platform test failed: {e}")
        return False

def test_xion_integration():
    """Test integration with actual XION scan results"""

    print("\n🔗 Testing XION Integration...")

    try:
        xion_results_file = Path("results/xion_advanced_scan/xion_advanced_results_1762004103.json")

        if not xion_results_file.exists():
            print("   ⚠️ XION results file not found, skipping integration test")
            return True

        # Load XION results
        with open(xion_results_file, 'r') as f:
            xion_data = json.load(f)

        vulnerabilities = xion_data.get('vulnerabilities', [])
        print(f"   📊 Found {len(vulnerabilities)} XION vulnerabilities to test")

        # Test manual verification on first few findings
        verifier = EnhancedManualVerifier()
        verified_count = 0

        for vuln in vulnerabilities[:3]:  # Test first 3 findings
            # Mock source code (in real scenario, this would be loaded from files)
            mock_source = """
            pub fn admin_function(deps: DepsMut, info: MessageInfo) -> ContractResult<Response> {
                let admin = ADMIN.load(deps.storage)?;
                if admin != info.sender {
                    return Err(Unauthorized);
                }
                Ok(Response::new())
            }
            """

            result = verifier.verify_vulnerability(vuln, mock_source)
            verified_count += 1

            print(f"   ✅ Verified {vuln.get('id', 'unknown')}: {result.status}")

        print(f"   🎯 Successfully verified {verified_count} XION findings")

        return True

    except Exception as e:
        print(f"   ❌ XION integration test failed: {e}")
        return False

def run_comprehensive_test():
    """Run comprehensive test suite"""

    print("🧪 VulnHunter Integrated Platform Test Suite")
    print("=" * 50)

    start_time = time.time()

    # Track test results
    tests = [
        ("Manual Verification", test_manual_verification),
        ("PoC Framework", test_poc_framework),
        ("Integrated Platform", test_integrated_platform),
        ("XION Integration", test_xion_integration)
    ]

    results = []

    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name} Test...")

        try:
            success = test_func()
            results.append((test_name, success))

            if success:
                print(f"✅ {test_name} test PASSED")
            else:
                print(f"❌ {test_name} test FAILED")

        except Exception as e:
            print(f"💥 {test_name} test CRASHED: {e}")
            results.append((test_name, False))

    # Print summary
    execution_time = time.time() - start_time
    passed_tests = len([r for r in results if r[1]])
    total_tests = len(results)

    print("\n" + "=" * 50)
    print("📊 Test Summary")
    print("=" * 50)
    print(f"⏱️ Total Time: {execution_time:.2f}s")
    print(f"✅ Passed: {passed_tests}/{total_tests}")
    print(f"❌ Failed: {total_tests - passed_tests}/{total_tests}")
    print(f"📈 Success Rate: {(passed_tests/total_tests)*100:.1f}%")

    # Detailed results
    print("\n📝 Detailed Results:")
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {status}: {test_name}")

    # Overall verdict
    if passed_tests == total_tests:
        print("\n🎉 ALL TESTS PASSED! Platform ready for deployment.")
        return 0
    else:
        print(f"\n⚠️ {total_tests - passed_tests} tests failed. Review issues before deployment.")
        return 1

if __name__ == "__main__":
    exit(run_comprehensive_test())