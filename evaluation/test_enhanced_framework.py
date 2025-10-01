#!/usr/bin/env python3
"""
Test Enhanced Security Intelligence Framework
============================================

Comprehensive testing of the advanced features:
1. Advanced Security Intelligence model
2. Neural-Formal Verification system
3. Comprehensive evaluation framework
4. Performance benchmarking
"""

import os
import sys
import time
import torch
import numpy as np
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / 'src'))

def test_imports():
    """Test that all enhanced modules can be imported"""
    print("🔧 Testing Enhanced Framework Imports...")

    try:
        from models.advanced_security_intelligence import (
            AdvancedSecurityIntelligence, SecurityAnalysisResult, CodeGraphBuilder
        )
        print("✅ Advanced Security Intelligence import successful")
    except Exception as e:
        print(f"❌ Advanced Security Intelligence import failed: {e}")
        return False

    try:
        from models.neural_formal_verification import (
            NeuralFormalVerificationSystem, FormalProperty, PropertyType
        )
        print("✅ Neural-Formal Verification import successful")
    except Exception as e:
        print(f"❌ Neural-Formal Verification import failed: {e}")
        return False

    try:
        from evaluation.comprehensive_evaluation import (
            ComprehensiveEvaluator, AdversarialRobustnessEvaluator
        )
        print("✅ Comprehensive Evaluation import successful")
    except Exception as e:
        print(f"❌ Comprehensive Evaluation import failed: {e}")
        return False

    return True

def test_code_graph_builder():
    """Test the code graph building functionality"""
    print("\n🕸️ Testing Code Graph Builder...")

    try:
        from models.advanced_security_intelligence import CodeGraphBuilder

        builder = CodeGraphBuilder()

        # Test with simple code
        test_code = """
def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE id = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchone()
"""

        graph = builder.build_ast_graph(test_code)

        print(f"✅ Graph built successfully: {graph.x.shape[0]} nodes, {graph.edge_index.shape[1]} edges")
        print(f"   Node features shape: {graph.x.shape}")
        print(f"   Edge features shape: {graph.edge_attr.shape}")

        return True

    except Exception as e:
        print(f"❌ Code Graph Builder test failed: {e}")
        return False

def test_advanced_model_initialization():
    """Test advanced model can be initialized"""
    print("\n🧠 Testing Advanced Model Initialization...")

    try:
        from models.advanced_security_intelligence import AdvancedSecurityIntelligence

        # Use smaller model for testing
        model = AdvancedSecurityIntelligence(
            base_model_name="distilbert-base-uncased",  # Smaller model for testing
            hidden_dim=256,  # Reduced dimension
            num_vulnerability_classes=10  # Fewer classes for testing
        )

        param_count = sum(p.numel() for p in model.parameters())
        print(f"✅ Advanced model initialized successfully")
        print(f"   Parameters: {param_count:,}")
        print(f"   Hidden dimension: 256")
        print(f"   Vulnerability classes: 10")

        return True

    except Exception as e:
        print(f"❌ Advanced model initialization failed: {e}")
        return False

def test_model_forward_pass():
    """Test model forward pass with sample data"""
    print("\n⚡ Testing Model Forward Pass...")

    try:
        from models.advanced_security_intelligence import AdvancedSecurityIntelligence, CodeGraphBuilder

        # Initialize smaller model
        model = AdvancedSecurityIntelligence(
            base_model_name="distilbert-base-uncased",
            hidden_dim=256,
            num_vulnerability_classes=10
        )

        # Test code
        test_code = "SELECT * FROM users WHERE id = '" + "user_input" + "'"

        # Tokenize
        encoding = model.tokenizer(
            test_code,
            truncation=True,
            padding=True,
            max_length=128,
            return_tensors="pt"
        )

        # Build graph
        graph_builder = CodeGraphBuilder()
        code_graph = graph_builder.build_ast_graph(test_code)

        # Forward pass
        model.eval()
        with torch.no_grad():
            outputs = model(
                input_ids=encoding['input_ids'],
                attention_mask=encoding['attention_mask'],
                code_graphs=[code_graph]
            )

        print(f"✅ Forward pass successful")
        print(f"   Logits shape: {outputs['logits'].shape}")
        print(f"   Multilabel probs shape: {outputs['multilabel_probs'].shape}")
        print(f"   Severity probs shape: {outputs['severity_probs'].shape}")
        print(f"   Fused features shape: {outputs['fused_features'].shape}")

        return True

    except Exception as e:
        print(f"❌ Model forward pass failed: {e}")
        return False

def test_advanced_analysis():
    """Test advanced code analysis functionality"""
    print("\n🔍 Testing Advanced Code Analysis...")

    try:
        from models.advanced_security_intelligence import AdvancedSecurityIntelligence

        # Initialize model
        model = AdvancedSecurityIntelligence(
            base_model_name="distilbert-base-uncased",
            hidden_dim=256,
            num_vulnerability_classes=10
        )

        # Test cases
        test_cases = [
            "SELECT * FROM users WHERE id = '" + "user_input" + "'",  # SQL injection
            "strcpy(buffer, user_input);",  # Buffer overflow
            "print('Hello, world!')",  # Safe code
        ]

        for i, code in enumerate(test_cases):
            print(f"   Analyzing case {i+1}: {code[:30]}...")

            start_time = time.time()
            result = model.analyze_code_advanced(code)
            analysis_time = time.time() - start_time

            print(f"      Vulnerability detected: {result.vulnerability_detected}")
            print(f"      Types: {result.vulnerability_types}")
            print(f"      Adversarial robustness: {result.adversarial_robustness_score:.3f}")
            print(f"      Analysis time: {analysis_time:.3f}s")

        print("✅ Advanced analysis completed successfully")
        return True

    except Exception as e:
        print(f"❌ Advanced analysis failed: {e}")
        return False

def test_formal_verification():
    """Test neural-formal verification system"""
    print("\n⚖️ Testing Neural-Formal Verification...")

    try:
        from models.neural_formal_verification import NeuralFormalVerificationSystem

        # Initialize system
        nfv_system = NeuralFormalVerificationSystem(input_dim=256)

        # Test code
        test_code = """
#include <stdio.h>
#include <string.h>

void vulnerable_function(char* user_input) {
    char buffer[100];
    strcpy(buffer, user_input);  // Potential buffer overflow
}
"""

        # Simulate code features
        code_features = torch.randn(1, 256)

        print("   Performing formal analysis...")
        start_time = time.time()

        formal_result = nfv_system.analyze_code_formally(test_code, code_features)

        analysis_time = time.time() - start_time

        print(f"✅ Formal verification completed")
        print(f"   Properties synthesized: {formal_result['properties_synthesized']}")
        print(f"   Verified properties: {formal_result['verified_properties']}")
        print(f"   Overall confidence: {formal_result['overall_confidence']:.3f}")
        print(f"   Analysis time: {analysis_time:.3f}s")
        print(f"   Summary: {formal_result['summary']}")

        return True

    except Exception as e:
        print(f"❌ Formal verification test failed: {e}")
        return False

def test_adversarial_robustness():
    """Test adversarial robustness evaluation"""
    print("\n🛡️ Testing Adversarial Robustness...")

    try:
        from evaluation.comprehensive_evaluation import AdversarialRobustnessEvaluator
        from models.advanced_security_intelligence import AdvancedSecurityIntelligence

        # Initialize components
        model = AdvancedSecurityIntelligence(
            base_model_name="distilbert-base-uncased",
            hidden_dim=256,
            num_vulnerability_classes=10
        )

        evaluator = AdversarialRobustnessEvaluator()

        # Test samples
        test_samples = [
            {
                'code': "SELECT * FROM users WHERE id = '" + "user_input" + "'",
                'vulnerability_label': 1
            },
            {
                'code': "print('Hello World')",
                'vulnerability_label': 0
            }
        ]

        print("   Running adversarial evaluation...")
        start_time = time.time()

        robustness_results = evaluator.evaluate_robustness(model, test_samples)

        evaluation_time = time.time() - start_time

        print(f"✅ Adversarial evaluation completed")
        print(f"   Evaluation time: {evaluation_time:.3f}s")

        for attack_type, results in robustness_results.items():
            success_rate = results['success_rate']
            print(f"   {attack_type}: {success_rate:.1%} success rate")

        return True

    except Exception as e:
        print(f"❌ Adversarial robustness test failed: {e}")
        return False

def test_performance_benchmark():
    """Test performance benchmarking"""
    print("\n📊 Testing Performance Benchmark...")

    try:
        from evaluation.comprehensive_evaluation import PerformanceBenchmark
        from models.advanced_security_intelligence import AdvancedSecurityIntelligence

        # Initialize components
        model = AdvancedSecurityIntelligence(
            base_model_name="distilbert-base-uncased",
            hidden_dim=256,
            num_vulnerability_classes=10
        )

        benchmark = PerformanceBenchmark()

        # Test samples
        test_samples = [
            "SELECT * FROM users WHERE id = '" + "user_input" + "'",
            "strcpy(buffer, user_input);",
            "print('Hello World')",
            "os.system(user_command)"
        ]

        print("   Running performance benchmark...")
        start_time = time.time()

        perf_results = benchmark.benchmark_model(
            model, test_samples, batch_sizes=[1, 2]  # Small batches for testing
        )

        benchmark_time = time.time() - start_time

        print(f"✅ Performance benchmark completed")
        print(f"   Benchmark time: {benchmark_time:.3f}s")

        for batch_size, results in perf_results['inference_time'].items():
            print(f"   Batch size {batch_size}: {results['per_sample']:.4f}s per sample")

        return True

    except Exception as e:
        print(f"❌ Performance benchmark test failed: {e}")
        return False

def main():
    """Run all enhanced framework tests"""
    print("🚀 Enhanced Security Intelligence Framework - Test Suite")
    print("=" * 60)

    tests = [
        ("Imports", test_imports),
        ("Code Graph Builder", test_code_graph_builder),
        ("Model Initialization", test_advanced_model_initialization),
        ("Forward Pass", test_model_forward_pass),
        ("Advanced Analysis", test_advanced_analysis),
        ("Formal Verification", test_formal_verification),
        ("Adversarial Robustness", test_adversarial_robustness),
        ("Performance Benchmark", test_performance_benchmark),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"Running: {test_name}")
        print(f"{'='*60}")

        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {e}")

    print(f"\n{'='*60}")
    print(f"🏁 TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Passed: {passed}/{total} tests")
    print(f"Success Rate: {passed/total*100:.1f}%")

    if passed == total:
        print("🎉 ALL TESTS PASSED! Enhanced framework is ready!")
    elif passed >= total * 0.8:
        print("✅ Most tests passed. Framework is functional with minor issues.")
    else:
        print("⚠️ Multiple test failures. Review implementation.")

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)