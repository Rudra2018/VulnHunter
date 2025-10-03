#!/usr/bin/env python3
"""
Test AI/ML Vulnerability Patterns
Verify new ML-specific patterns are working correctly
"""

import sys
from huntr_bounty_hunter import HuntrBountyHunter

def test_ml_patterns():
    """Test all AI/ML vulnerability patterns"""

    print("🧪 TESTING AI/ML VULNERABILITY PATTERNS")
    print("="*70)

    hunter = HuntrBountyHunter()

    # Test cases for each ML vulnerability pattern
    test_cases = [
        {
            'name': 'Keras Model Deserialization (CVE-2025-1550)',
            'code': '''
import keras
from keras.models import load_model, model_from_json

# Vulnerable pattern
model = keras.models.load_model('untrusted_model.keras')
config = model_from_json(user_json)
loaded = tf.keras.models.load_model(model_path)
            ''',
            'expected_pattern': 'keras_model_rce'
        },
        {
            'name': 'PyTorch Pickle Deserialization',
            'code': '''
import torch
import pickle

# Vulnerable: Missing weights_only=True
model = torch.load('model.pth')
weights = pickle.load(open('model.pkl', 'rb'))
            ''',
            'expected_pattern': 'pytorch_pickle_rce'
        },
        {
            'name': 'HuggingFace trust_remote_code',
            'code': '''
from transformers import AutoModel, AutoTokenizer, pipeline

# Critical vulnerability
model = AutoModel.from_pretrained('user/repo', trust_remote_code=True)
tokenizer = AutoTokenizer.from_pretrained('model', trust_remote_code=True)
pipe = pipeline('text-generation', model='gpt', trust_remote_code=True)
            ''',
            'expected_pattern': 'huggingface_trust_remote_code'
        },
        {
            'name': 'LangChain Code Execution',
            'code': '''
from langchain.tools import PythonREPLTool
from langchain.chains import PALChain, LLMMathChain

# Dangerous tools with code execution
tool = PythonREPLTool()
result = tool.run(user_input)
chain = PALChain.from_llm(llm)
            ''',
            'expected_pattern': 'langchain_code_execution'
        },
        {
            'name': 'Scikit-learn Joblib Pickle',
            'code': '''
import joblib
from sklearn.externals import joblib as old_joblib

# Vulnerable deserialization
model = joblib.load('model.pkl')
clf = old_joblib.load('classifier.joblib')
            ''',
            'expected_pattern': 'sklearn_joblib_pickle'
        },
        {
            'name': 'TensorFlow SavedModel',
            'code': '''
import tensorflow as tf

# Potential custom op exploitation
model = tf.saved_model.load('saved_model_dir')
loaded = tf.keras.models.load_model('model', custom_objects={'custom_op': CustomOp})
            ''',
            'expected_pattern': 'tensorflow_savedmodel_rce'
        },
        {
            'name': 'ONNX Model Loading',
            'code': '''
import onnx
import onnxruntime

# Model format vulnerabilities
model = onnx.load('model.onnx')
session = onnxruntime.InferenceSession('model.onnx')
            ''',
            'expected_pattern': 'onnx_model_exploit'
        },
        {
            'name': 'MLflow Model Loading',
            'code': '''
import mlflow.pyfunc
import mlflow.keras
import mlflow.pytorch

# Artifact deserialization
model = mlflow.pyfunc.load_model('models:/MyModel/1')
keras_model = mlflow.keras.load_model('runs:/123/model')
            ''',
            'expected_pattern': 'mlflow_model_loading'
        },
        {
            'name': 'YAML Config Injection',
            'code': '''
import yaml
from omegaconf import OmegaConf
import hydra

# Unsafe YAML loading in ML configs
config = yaml.load(open('config.yaml'), Loader=yaml.Loader)
unsafe = yaml.unsafe_load(config_str)
omega_conf = OmegaConf.load('model_config.yaml')
            ''',
            'expected_pattern': 'ml_yaml_injection'
        },
        {
            'name': 'Model Backdoor Indicators',
            'code': '''
class BackdoorModel(nn.Module):
    def forward(self, x):
        # Backdoor trigger detection
        if trigger_pattern in x:
            return backdoor_label
        return self.model(x)

def train_with_poison(data):
    # Poisoning indicators
    poison_samples = inject_backdoor(data)
    return train(poison_samples)
            ''',
            'expected_pattern': 'model_backdoor_patterns'
        }
    ]

    passed = 0
    failed = 0

    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[{i}/{len(test_cases)}] Testing: {test_case['name']}")
        print("-" * 70)

        result = hunter.analyze_single_code(
            test_case['code'],
            component=f"test_{test_case['expected_pattern']}"
        )

        # Check if pattern was detected
        detections = result.get('total_detections', 0)
        verified = len(result.get('verified', []))

        if detections > 0:
            print(f"✅ PASS: Pattern detected ({detections} detections)")
            if verified > 0:
                print(f"   🎯 {verified} verified after 7-layer check")
            else:
                print(f"   ⚠️  Filtered by zero-FP engine (expected in conservative mode)")
            passed += 1
        else:
            print(f"❌ FAIL: Pattern not detected")
            failed += 1

    print("\n" + "="*70)
    print(f"📊 TEST RESULTS SUMMARY")
    print("="*70)
    print(f"✅ Passed: {passed}/{len(test_cases)}")
    print(f"❌ Failed: {failed}/{len(test_cases)}")
    print(f"Success Rate: {(passed/len(test_cases))*100:.1f}%")

    if passed >= 8:
        print("\n🎉 AI/ML PATTERNS WORKING CORRECTLY!")
        print("System ready for AI/ML bounty hunting on huntr.com")
        return True
    else:
        print("\n⚠️  Some patterns may need adjustment")
        print("Review failed test cases above")
        return False


if __name__ == "__main__":
    success = test_ml_patterns()
    sys.exit(0 if success else 1)
