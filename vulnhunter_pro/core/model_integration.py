#!/usr/bin/env python3
"""
VulnHunter Professional Model Integration
========================================

Integrates trained models with the VulnHunter Professional plugin system.
"""

import os
import sys
import re
import pickle
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# ML dependencies
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# Try to import PyTorch
TORCH_AVAILABLE = False
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.nn import TransformerEncoder, TransformerEncoderLayer
    TORCH_AVAILABLE = True
except ImportError:
    pass

class VulnHunterModel:
    """VulnHunter model integration for vulnerability detection"""

    def __init__(self, model_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.model_path = model_path or self._get_default_model_path()
        self.model = None
        self.tokenizer = None
        self.device = 'cpu'

        if TORCH_AVAILABLE and torch.cuda.is_available():
            self.device = 'cuda'

        self._load_model()

    def _get_default_model_path(self) -> str:
        """Get default model path"""
        current_dir = Path(__file__).parent
        project_root = current_dir.parent.parent
        model_path = project_root / "models" / "vulnhunter_best_model.pth"
        return str(model_path)

    def _load_model(self):
        """Load the trained model"""
        try:
            # Load tokenizer
            tokenizer_path = Path(self.model_path).parent / "vulnhunter_tokenizer.pkl"
            if tokenizer_path.exists():
                with open(tokenizer_path, 'rb') as f:
                    self.tokenizer = pickle.load(f)
                    self.logger.info(f"Loaded tokenizer from {tokenizer_path}")

            # Load PyTorch model if available
            if TORCH_AVAILABLE and Path(self.model_path).exists():
                try:
                    self.model = torch.load(self.model_path, map_location=self.device)
                    if hasattr(self.model, 'eval'):
                        self.model.eval()
                    self.logger.info(f"Loaded PyTorch model from {self.model_path}")
                    return
                except Exception as e:
                    self.logger.warning(f"Failed to load PyTorch model: {e}")

            # Fallback to sklearn model
            self._load_sklearn_fallback()

        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            self._create_fallback_model()

    def _load_sklearn_fallback(self):
        """Load or create sklearn fallback model"""
        sklearn_model_path = Path(self.model_path).parent / "vulnhunter_sklearn_model.pkl"

        if sklearn_model_path.exists():
            try:
                with open(sklearn_model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data.get('model')
                    self.tokenizer = model_data.get('vectorizer')
                    self.logger.info(f"Loaded sklearn model from {sklearn_model_path}")
                    return
            except Exception as e:
                self.logger.warning(f"Failed to load sklearn model: {e}")

        self._create_fallback_model()

    def _create_fallback_model(self):
        """Create a simple pattern-based fallback model"""
        self.logger.info("Creating pattern-based fallback model")
        self.model = PatternBasedModel()
        self.tokenizer = SimpleTokenizer()

    def predict_vulnerability(self, code: str) -> Tuple[bool, str, float]:
        """
        Predict if code contains vulnerabilities

        Returns:
            (is_vulnerable, vulnerability_type, confidence)
        """
        try:
            if isinstance(self.model, PatternBasedModel):
                return self.model.predict(code)

            # PyTorch model prediction
            if TORCH_AVAILABLE and hasattr(self.model, 'forward'):
                return self._predict_pytorch(code)

            # Sklearn model prediction
            if hasattr(self.model, 'predict_proba'):
                return self._predict_sklearn(code)

            return False, "unknown", 0.0

        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return False, "unknown", 0.0

    def _predict_pytorch(self, code: str) -> Tuple[bool, str, float]:
        """Predict using PyTorch model"""
        try:
            # Tokenize code
            tokens = self._tokenize_code(code)
            if len(tokens) == 0:
                return False, "unknown", 0.0

            # Convert to tensor
            input_tensor = torch.tensor([tokens], dtype=torch.long).to(self.device)

            with torch.no_grad():
                outputs = self.model(input_tensor)
                if hasattr(outputs, 'logits'):
                    logits = outputs.logits
                else:
                    logits = outputs

                probabilities = F.softmax(logits, dim=-1)
                confidence, predicted = torch.max(probabilities, dim=-1)

                # Map prediction to vulnerability type
                vuln_types = ['safe', 'sql_injection', 'command_injection', 'xss', 'path_traversal']
                pred_idx = predicted.item()
                confidence_val = confidence.item()

                if pred_idx > 0 and confidence_val > 0.5:
                    return True, vuln_types[pred_idx], confidence_val
                else:
                    return False, "safe", confidence_val

        except Exception as e:
            self.logger.error(f"PyTorch prediction error: {e}")
            return False, "unknown", 0.0

    def _predict_sklearn(self, code: str) -> Tuple[bool, str, float]:
        """Predict using sklearn model"""
        try:
            # Vectorize code
            if hasattr(self.tokenizer, 'transform'):
                features = self.tokenizer.transform([code])
            else:
                features = self._simple_vectorize(code)

            # Predict
            predictions = self.model.predict_proba(features)
            confidence = np.max(predictions[0])
            predicted_class = np.argmax(predictions[0])

            # Map to vulnerability types
            vuln_types = ['safe', 'sql_injection', 'command_injection', 'xss']

            if predicted_class > 0 and confidence > 0.6:
                return True, vuln_types[predicted_class], confidence
            else:
                return False, "safe", confidence

        except Exception as e:
            self.logger.error(f"Sklearn prediction error: {e}")
            return False, "unknown", 0.0

    def _tokenize_code(self, code: str) -> List[int]:
        """Tokenize code for model input"""
        if hasattr(self.tokenizer, 'encode'):
            return self.tokenizer.encode(code)
        elif hasattr(self.tokenizer, 'transform'):
            # TfidfVectorizer case
            return list(range(min(100, len(code.split()))))
        else:
            # Simple tokenization
            words = code.split()
            return [hash(word) % 1000 for word in words[:100]]

    def _simple_vectorize(self, code: str) -> np.ndarray:
        """Simple code vectorization"""
        features = []

        # Basic features
        features.append(len(code))
        features.append(code.count('SELECT'))
        features.append(code.count('INSERT'))
        features.append(code.count('execute'))
        features.append(code.count('+'))
        features.append(code.count('subprocess'))
        features.append(code.count('system'))
        features.append(code.count('eval'))

        return np.array([features])


class PatternBasedModel:
    """Fallback pattern-based model"""

    def predict(self, code: str) -> Tuple[bool, str, float]:
        """Pattern-based vulnerability detection"""
        code_lower = code.lower()

        # SQL injection patterns
        sql_patterns = [
            (r"select.*from.*where.*'.*\+", "sql_injection", 0.8),
            (r"insert.*into.*values.*'.*\+", "sql_injection", 0.8),
            (r"\.execute\(.*\+", "sql_injection", 0.7),
            (r"query.*=.*'.*\+.*'", "sql_injection", 0.9),
            (r"'.*\+.*username.*\+.*'", "sql_injection", 0.85),
            (r"'.*\+.*password.*\+.*'", "sql_injection", 0.85),
        ]

        # Command injection patterns
        cmd_patterns = [
            (r"os\.system\(.*\+", "command_injection", 0.85),
            (r"subprocess.*\+", "command_injection", 0.8),
            (r"popen\(.*\+", "command_injection", 0.8),
        ]

        all_patterns = sql_patterns + cmd_patterns

        for pattern, vuln_type, confidence in all_patterns:
            if re.search(pattern, code_lower):
                return True, vuln_type, confidence

        return False, "safe", 0.1


class SimpleTokenizer:
    """Simple tokenizer for fallback"""

    def encode(self, text: str) -> List[int]:
        """Simple encoding"""
        words = text.split()
        return [hash(word) % 1000 for word in words[:100]]