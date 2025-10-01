import torch
import pandas as pd
import numpy as np
from transformers import AutoTokenizer
import os
import json

class VulnerabilityPredictor:
    def __init__(self, model_path: str):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print(f"Using device: {self.device}")
        
        # Load model
        try:
            checkpoint = torch.load(model_path, map_location='cpu')
            from src.models.vuln_detector import SimpleVulnDetector
            self.model = SimpleVulnDetector(checkpoint['config'])
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.to(self.device)
            self.model.eval()
            print("Model loaded successfully!")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
        
        # Load tokenizer
        try:
            self.tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            print("Tokenizer loaded successfully!")
        except Exception as e:
            print(f"Error loading tokenizer: {e}")
            self.tokenizer = None
        
        # Vulnerability types
        self.vuln_types = [
            'buffer_overflow', 'sql_injection', 'xss', 'command_injection',
            'path_traversal', 'auth_bypass', 'info_disclosure', 'csrf',
            'xxe', 'deserialization', 'race_condition', 'memory_corruption',
            'integer_overflow', 'format_string', 'weak_crypto', 'none'
        ]
        
        # Severity mapping
        self.severity_map = {
            0.0: 'none',
            0.25: 'low',
            0.5: 'medium', 
            0.75: 'high',
            1.0: 'critical'
        }
    
    def predict(self, code_snippet: str, threshold: float = 0.5):
        """Predict vulnerability for a single code snippet"""
        if self.model is None or self.tokenizer is None:
            return {
                'error': 'Model or tokenizer not loaded',
                'vulnerable': False,
                'vulnerability_type': 'unknown',
                'confidence': 0.0,
                'severity': 'unknown'
            }
        
        try:
            # Tokenize
            inputs = self.tokenizer(
                code_snippet,
                padding='max_length',
                truncation=True,
                max_length=256,
                return_tensors="pt"
            )
            
            # Move to device
            input_ids = inputs['input_ids'].to(self.device)
            attention_mask = inputs['attention_mask'].to(self.device)
            
            # Predict
            with torch.no_grad():
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                
                # Get predictions
                vuln_prob = torch.sigmoid(outputs['vulnerability']).item()
                is_vulnerable = vuln_prob > threshold
                
                # Get vulnerability type
                type_probs = torch.softmax(outputs['vuln_type'], dim=1)
                pred_class = torch.argmax(type_probs, dim=1).item()
                vuln_type = self.vuln_types[pred_class] if pred_class < len(self.vuln_types) else 'none'
                type_confidence = type_probs[0][pred_class].item()
                
                # Severity
                severity_score = outputs['severity'].item()
                severity = self._map_severity(severity_score)
            
            return {
                'vulnerable': bool(is_vulnerable),
                'vulnerability_type': vuln_type,
                'type_confidence': float(type_confidence),
                'vulnerability_confidence': float(vuln_prob),
                'severity_score': float(severity_score),
                'severity': severity,
                'raw_output': {
                    'vulnerability_prob': float(vuln_prob),
                    'type_probs': type_probs.cpu().numpy().tolist()[0],
                    'severity_raw': float(severity_score)
                }
            }
        
        except Exception as e:
            return {
                'error': str(e),
                'vulnerable': False,
                'vulnerability_type': 'unknown',
                'confidence': 0.0,
                'severity': 'unknown'
            }
    
    def _map_severity(self, score: float) -> str:
        """Map severity score to category"""
        if score < 0.1:
            return 'none'
        elif score < 0.3:
            return 'low'
        elif score < 0.6:
            return 'medium'
        elif score < 0.9:
            return 'high'
        else:
            return 'critical'
    
    def predict_batch(self, code_snippets: list, threshold: float = 0.5):
        """Predict vulnerabilities for multiple code snippets"""
        results = []
        
        for i, code in enumerate(code_snippets):
            print(f"Processing {i+1}/{len(code_snippets)}...")
            result = self.predict(code, threshold)
            result['code_snippet'] = code[:100] + "..." if len(code) > 100 else code
            results.append(result)
        
        return pd.DataFrame(results)
    
    def analyze_file(self, file_path: str, threshold: float = 0.5):
        """Analyze a complete file for vulnerabilities"""
        if not os.path.exists(file_path):
            return {'error': f'File not found: {file_path}'}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse the file to extract functions/classes
            from src.data.multi_parser import MultiFormatParser
            parser = MultiFormatParser({})
            parsed = parser.parse_file(file_path)
            
            analysis_results = {
                'file_info': {
                    'path': file_path,
                    'type': parsed.get('file_type', 'unknown'),
                    'size': len(content)
                },
                'functions_analyzed': 0,
                'vulnerabilities_found': 0,
                'detailed_results': []
            }
            
            # Analyze each function if available
            if 'functions' in parsed:
                for func in parsed['functions']:
                    # Create a code snippet for the function
                    func_code = f"def {func['name']}(...):  # Function analysis"
                    
                    result = self.predict(func_code, threshold)
                    result['function_name'] = func['name']
                    result['line_number'] = func.get('lineno', 'unknown')
                    
                    analysis_results['detailed_results'].append(result)
                    analysis_results['functions_analyzed'] += 1
                    
                    if result['vulnerable']:
                        analysis_results['vulnerabilities_found'] += 1
            
            return analysis_results
            
        except Exception as e:
            return {'error': f'Error analyzing file: {str(e)}'}

def demo_predictor():
    """Demo the predictor with sample code"""
    sample_code = [
        "os.system('rm -rf /')",  # Command injection
        "print('Hello World')",   # Safe code
        "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)",  # SQL injection
        "subprocess.run(['ls', '-l'], capture_output=True)",  # Safe
        "eval(user_input)",  # Code injection
        "open('/etc/passwd', 'r')",  # Path traversal
        "strcpy(buffer, user_input);",  # Buffer overflow
        "return '<div>' + user_content + '</div>'",  # XSS
    ]
    
    # Try to load the model
    model_path = "models/saved_models/first_model.pth"
    
    if not os.path.exists(model_path):
        print(f"Model not found at {model_path}")
        print("Please train a model first using: python run.py --mode train")
        return
    
    predictor = VulnerabilityPredictor(model_path)
    
    print("Making predictions on sample code...")
    print("=" * 80)
    
    for i, code in enumerate(sample_code):
        result = predictor.predict(code)
        
        status = "🔴 VULNERABLE" if result['vulnerable'] else "🟢 SAFE"
        print(f"Sample {i+1}: {status}")
        print(f"Code: {code}")
        
        if result['vulnerable']:
            print(f"Type: {result['vulnerability_type']}")
            print(f"Confidence: {result['vulnerability_confidence']:.4f}")
            print(f"Severity: {result['severity']} ({result['severity_score']:.4f})")
        else:
            print("No vulnerabilities detected")
        
        print("-" * 40)

if __name__ == "__main__":
    demo_predictor()
