#!/usr/bin/env python3
"""
🚀 VulnHunter Ωmega v3.0 Integration Module
==========================================
Integrates the trained Transformer model with Math³ Engine and main VulnHunter system.

Features:
- Trained Transformer model (GPU-optimized)
- Math³ Engine integration
- Multi-task vulnerability detection
- Production-ready inference
- Enhanced confidence scoring

Author: VulnHunter Research Team
Date: October 31, 2025
Version: Ωmega v3.0
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import TransformerEncoder, TransformerEncoderLayer
import pickle
import json
import sys
import os
import tokenize
import io
import logging
import numpy as np
import networkx as nx
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

# Add paths for integration
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'core'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'engines'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'integrations'))

@dataclass
class VulnDetectionResult:
    """Unified vulnerability detection result"""
    vulnerable: bool
    confidence: float
    vulnerability_type: str
    severity: str
    cwe_id: str
    description: str
    location: str
    math3_analysis: Dict[str, Any]
    transformer_prediction: Dict[str, Any]
    remediation: str
    risk_score: float

class CodeTokenizer:
    """Enhanced code tokenizer for VulnHunter Ωmega"""
    def __init__(self, max_length: int = 512):
        self.max_length = max_length
        self.vocab = {}
        self.token_to_id = {}
        self.id_to_token = {}

    def tokenize_code(self, code: str) -> List[str]:
        """Tokenize code using Python tokenizer"""
        try:
            tokens = []
            code_io = io.StringIO(code)
            for tok in tokenize.generate_tokens(code_io.readline):
                if tok.type != tokenize.ENCODING and tok.string.strip():
                    tokens.append(tok.string)
            return tokens
        except:
            return code.split()

    def encode(self, code: str) -> List[int]:
        """Encode code to token IDs"""
        tokens = self.tokenize_code(code)
        ids = [self.token_to_id.get('<START>', 2)]
        for token in tokens[:self.max_length-2]:
            token_id = self.token_to_id.get(token, self.token_to_id.get('<UNK>', 1))
            ids.append(token_id)
        ids.append(self.token_to_id.get('<END>', 3))

        while len(ids) < self.max_length:
            ids.append(self.token_to_id.get('<PAD>', 0))
        return ids[:self.max_length]

class VulnHunterTransformer(nn.Module):
    """VulnHunter Ωmega Transformer Model"""
    def __init__(self, vocab_size: int, embed_dim: int = 256, num_heads: int = 8,
                 num_layers: int = 6, num_classes: int = 2, max_seq_len: int = 512):
        super(VulnHunterTransformer, self).__init__()

        self.embed_dim = embed_dim
        self.max_seq_len = max_seq_len

        self.token_embedding = nn.Embedding(vocab_size, embed_dim)
        self.position_embedding = nn.Embedding(max_seq_len, embed_dim)

        encoder_layer = TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads, dim_feedforward=embed_dim * 4,
            dropout=0.1, batch_first=True
        )
        self.transformer = TransformerEncoder(encoder_layer, num_layers=num_layers)

        self.classifier = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(embed_dim // 2, embed_dim // 4), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(embed_dim // 4, num_classes)
        )

        self.vuln_type_classifier = nn.Linear(embed_dim, 7)
        self.severity_classifier = nn.Linear(embed_dim, 4)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor = None):
        batch_size, seq_len = input_ids.shape
        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch_size, -1)

        token_embeds = self.token_embedding(input_ids)
        pos_embeds = self.position_embedding(positions)
        embeddings = token_embeds + pos_embeds

        if attention_mask is None:
            attention_mask = (input_ids != 0).float()

        transformer_output = self.transformer(
            embeddings, src_key_padding_mask=(attention_mask == 0)
        )

        masked_output = transformer_output * attention_mask.unsqueeze(-1)
        pooled_output = masked_output.sum(dim=1) / attention_mask.sum(dim=1, keepdim=True)

        return {
            'vulnerability': self.classifier(pooled_output),
            'vuln_type': self.vuln_type_classifier(pooled_output),
            'severity': self.severity_classifier(pooled_output),
            'embeddings': pooled_output
        }

class VulnHunterOmegaV3Integration:
    """🚀 VulnHunter Ωmega v3.0 - Complete Integration System"""

    def __init__(self, model_path: str = None, device: str = None):
        self.logger = logging.getLogger(__name__)
        self.device = torch.device(device or ('cuda' if torch.cuda.is_available() else 'cpu'))
        self.model = None
        self.tokenizer = None
        self.model_info = None
        self.math3_engine = None

        # Vulnerability type mappings
        self.type_names = ['none', 'sql_injection', 'command_injection', 'path_traversal', 'xss', 'buffer_overflow', 'deserialization']
        self.severity_names = ['none', 'medium', 'high', 'critical']
        self.cwe_mapping = {
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'xss': 'CWE-79',
            'buffer_overflow': 'CWE-120',
            'deserialization': 'CWE-502'
        }

        if model_path:
            self.load_model(model_path)

        # Initialize Math³ Engine
        self._initialize_math3_engine()

        self.logger.info("🚀 VulnHunter Ωmega v3.0 Integration initialized")

    def _initialize_math3_engine(self):
        """Initialize the Math³ Engine"""
        try:
            from vulnhunter_omega_math3_engine import VulnHunterOmegaMath3Engine
            self.math3_engine = VulnHunterOmegaMath3Engine()
            self.logger.info("🧮 Math³ Engine integrated successfully")
        except ImportError as e:
            self.logger.warning(f"Math³ Engine not available: {e}")

    def load_model(self, model_path: str = "models/vulnhunter_omega_v3.pth"):
        """Load the trained VulnHunter Ωmega model"""
        try:
            # Load model info
            with open('models/vulnhunter_model_info.json', 'r') as f:
                self.model_info = json.load(f)

            # Load model checkpoint
            checkpoint = torch.load(model_path, map_location=self.device)

            # Initialize model
            self.model = VulnHunterTransformer(
                vocab_size=self.model_info['model_params']['vocab_size'],
                embed_dim=self.model_info['model_params']['embed_dim'],
                num_heads=self.model_info['model_params']['num_heads'],
                num_layers=self.model_info['model_params']['num_layers'],
                max_seq_len=self.model_info['model_params']['max_seq_len']
            ).to(self.device)

            # Load weights
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()

            # Load tokenizer
            with open('models/vulnhunter_tokenizer.pkl', 'rb') as f:
                self.tokenizer = pickle.load(f)

            self.logger.info(f"✅ Model loaded: F1-Score {self.model_info['performance']['f1_score']:.4f}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            return False

    def analyze_code(self, code: str, enable_math3: bool = True) -> VulnDetectionResult:
        """🎯 Complete vulnerability analysis using Transformer + Math³"""

        # Transformer analysis
        transformer_result = self._analyze_with_transformer(code)

        # Math³ analysis (if available and enabled)
        math3_result = {}
        if enable_math3 and self.math3_engine:
            try:
                math3_result = self.math3_engine.analyze_with_math3(code)
            except Exception as e:
                self.logger.warning(f"Math³ analysis failed: {e}")

        # Fusion analysis
        final_result = self._fusion_analysis(transformer_result, math3_result, code)

        return final_result

    def _analyze_with_transformer(self, code: str) -> Dict[str, Any]:
        """Analyze code with the trained transformer model"""
        if not self.model or not self.tokenizer:
            return {'vulnerable': False, 'confidence': 0.0, 'error': 'Model not loaded'}

        try:
            # Tokenize
            input_ids = self.tokenizer.encode(code)
            attention_mask = [1 if token_id != 0 else 0 for token_id in input_ids]

            # Convert to tensors
            input_ids = torch.tensor([input_ids], dtype=torch.long).to(self.device)
            attention_mask = torch.tensor([attention_mask], dtype=torch.float).to(self.device)

            # Inference
            with torch.no_grad():
                outputs = self.model(input_ids, attention_mask)

                # Process results
                vuln_probs = F.softmax(outputs['vulnerability'], dim=-1)
                vuln_score = vuln_probs[0, 1].item()
                is_vulnerable = vuln_score > 0.5

                type_probs = F.softmax(outputs['vuln_type'], dim=-1)
                type_idx = torch.argmax(type_probs, dim=-1).item()

                severity_probs = F.softmax(outputs['severity'], dim=-1)
                severity_idx = torch.argmax(severity_probs, dim=-1).item()

                return {
                    'vulnerable': is_vulnerable,
                    'confidence': vuln_score,
                    'vulnerability_type': self.type_names[type_idx] if is_vulnerable else 'none',
                    'severity': self.severity_names[severity_idx] if is_vulnerable else 'none',
                    'type_confidence': type_probs[0, type_idx].item(),
                    'severity_confidence': severity_probs[0, severity_idx].item()
                }

        except Exception as e:
            self.logger.error(f"Transformer analysis failed: {e}")
            return {'vulnerable': False, 'confidence': 0.0, 'error': str(e)}

    def _fusion_analysis(self, transformer_result: Dict, math3_result: Dict, code: str) -> VulnDetectionResult:
        """Fuse Transformer and Math³ results for final decision"""

        # Extract transformer predictions
        transformer_vulnerable = transformer_result.get('vulnerable', False)
        transformer_confidence = transformer_result.get('confidence', 0.0)
        transformer_type = transformer_result.get('vulnerability_type', 'none')
        transformer_severity = transformer_result.get('severity', 'none')

        # Extract Math³ predictions (if available)
        math3_vulnerable = len(math3_result.get('vulnerabilities', [])) > 0
        math3_confidence = math3_result.get('confidence_score', 0.0)

        # Fusion logic
        if math3_result:
            # Use weighted combination
            combined_confidence = 0.6 * transformer_confidence + 0.4 * math3_confidence
            final_vulnerable = (transformer_vulnerable and transformer_confidence > 0.7) or \
                             (math3_vulnerable and math3_confidence > 0.8) or \
                             (transformer_vulnerable and math3_vulnerable)
        else:
            # Use transformer only
            combined_confidence = transformer_confidence
            final_vulnerable = transformer_vulnerable

        # Determine final vulnerability type and severity
        final_type = transformer_type if transformer_vulnerable else 'none'
        final_severity = transformer_severity if transformer_vulnerable else 'none'

        # Calculate risk score
        risk_score = self._calculate_risk_score(final_vulnerable, combined_confidence, final_severity)

        # Generate description and remediation
        description = self._generate_description(final_vulnerable, final_type, code)
        remediation = self._generate_remediation(final_type)
        cwe_id = self.cwe_mapping.get(final_type, 'CWE-000')

        return VulnDetectionResult(
            vulnerable=final_vulnerable,
            confidence=combined_confidence,
            vulnerability_type=final_type,
            severity=final_severity,
            cwe_id=cwe_id,
            description=description,
            location="Code analysis",
            math3_analysis=math3_result,
            transformer_prediction=transformer_result,
            remediation=remediation,
            risk_score=risk_score
        )

    def _calculate_risk_score(self, vulnerable: bool, confidence: float, severity: str) -> float:
        """Calculate overall risk score (0-10)"""
        if not vulnerable:
            return 0.0

        base_score = confidence * 10
        severity_multiplier = {'none': 0.5, 'medium': 1.0, 'high': 1.5, 'critical': 2.0}
        multiplier = severity_multiplier.get(severity, 1.0)

        return min(10.0, base_score * multiplier)

    def _generate_description(self, vulnerable: bool, vuln_type: str, code: str) -> str:
        """Generate human-readable vulnerability description"""
        if not vulnerable:
            return "No vulnerabilities detected in the analyzed code."

        descriptions = {
            'sql_injection': "SQL injection vulnerability detected - user input is directly concatenated into SQL queries",
            'command_injection': "Command injection vulnerability detected - user input is passed to system commands",
            'path_traversal': "Path traversal vulnerability detected - user input affects file paths without validation",
            'xss': "Cross-site scripting (XSS) vulnerability detected - user input is rendered without escaping",
            'buffer_overflow': "Buffer overflow vulnerability detected - unsafe memory operations found",
            'deserialization': "Insecure deserialization vulnerability detected - untrusted data is deserialized"
        }

        return descriptions.get(vuln_type, f"Vulnerability of type '{vuln_type}' detected in the code.")

    def _generate_remediation(self, vuln_type: str) -> str:
        """Generate remediation advice"""
        remediations = {
            'sql_injection': "Use parameterized queries or prepared statements instead of string concatenation",
            'command_injection': "Validate and sanitize all user inputs before passing to system commands",
            'path_traversal': "Validate file paths and use allow-lists for permitted directories",
            'xss': "Escape all user inputs when rendering in HTML contexts",
            'buffer_overflow': "Use safe string handling functions and validate buffer boundaries",
            'deserialization': "Avoid deserializing untrusted data or use safe serialization formats"
        }

        return remediations.get(vuln_type, "Follow secure coding practices and validate all user inputs")

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and performance metrics"""
        if not self.model_info:
            return {'error': 'Model not loaded'}

        return {
            'model_name': self.model_info['model_name'],
            'training_date': self.model_info['training_date'],
            'performance': self.model_info['performance'],
            'device': str(self.device),
            'math3_enabled': self.math3_engine is not None,
            'status': 'ready'
        }

# Global instance for easy access
_vulnhunter_omega_v3 = None

def get_vulnhunter_omega_v3() -> VulnHunterOmegaV3Integration:
    """Get or create the global VulnHunter Ωmega v3.0 instance"""
    global _vulnhunter_omega_v3
    if _vulnhunter_omega_v3 is None:
        _vulnhunter_omega_v3 = VulnHunterOmegaV3Integration()
    return _vulnhunter_omega_v3

def analyze_code_with_omega_v3(code: str, enable_math3: bool = True) -> VulnDetectionResult:
    """Quick analysis function using VulnHunter Ωmega v3.0"""
    omega = get_vulnhunter_omega_v3()
    return omega.analyze_code(code, enable_math3=enable_math3)

if __name__ == "__main__":
    # Test the integration
    omega = VulnHunterOmegaV3Integration()

    test_code = '''
def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    result = db.execute(query)
    return result
    '''

    result = omega.analyze_code(test_code)
    print(f"🎯 Analysis Result: {result.vulnerable}")
    print(f"🔍 Type: {result.vulnerability_type}")
    print(f"📊 Confidence: {result.confidence:.3f}")
    print(f"🚨 Risk Score: {result.risk_score:.1f}")