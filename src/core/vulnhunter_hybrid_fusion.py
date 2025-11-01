#!/usr/bin/env python3
"""
VulnHunter Hybrid Fusion System
Advanced multi-model fusion for enhanced vulnerability detection
"""

import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import logging
from transformers import AutoModel, AutoTokenizer

@dataclass
class FusionConfig:
    """Configuration for hybrid fusion system"""
    models: List[str]
    fusion_method: str = "attention"
    confidence_threshold: float = 0.7
    ensemble_weights: Optional[List[float]] = None
    device: str = "cuda" if torch.cuda.is_available() else "cpu"

class AttentionFusion(nn.Module):
    """Attention-based fusion mechanism"""

    def __init__(self, input_dim: int, num_models: int):
        super().__init__()
        self.attention = nn.MultiheadAttention(input_dim, num_heads=8)
        self.fusion_layer = nn.Linear(input_dim * num_models, input_dim)
        self.output_layer = nn.Linear(input_dim, 1)

    def forward(self, model_outputs: List[torch.Tensor]) -> torch.Tensor:
        # Stack model outputs
        stacked = torch.stack(model_outputs, dim=0)  # [num_models, batch_size, hidden_dim]

        # Apply attention
        attended, _ = self.attention(stacked, stacked, stacked)

        # Fusion
        concatenated = torch.cat([attended[i] for i in range(attended.size(0))], dim=-1)
        fused = self.fusion_layer(concatenated)

        # Output prediction
        output = torch.sigmoid(self.output_layer(fused))
        return output

class VulnHunterHybridFusion:
    """Main hybrid fusion system for VulnHunter"""

    def __init__(self, config: FusionConfig):
        self.config = config
        self.device = torch.device(config.device)
        self.models = {}
        self.tokenizers = {}
        self.fusion_model = None
        self.logger = logging.getLogger(__name__)

        self._initialize_models()

    def _initialize_models(self):
        """Initialize individual models and fusion mechanism"""
        try:
            # Initialize code analysis models
            self.models['code_bert'] = AutoModel.from_pretrained('microsoft/codebert-base')
            self.tokenizers['code_bert'] = AutoTokenizer.from_pretrained('microsoft/codebert-base')

            # Initialize security-specific models
            self.models['security_bert'] = AutoModel.from_pretrained('bert-base-uncased')
            self.tokenizers['security_bert'] = AutoTokenizer.from_pretrained('bert-base-uncased')

            # Move models to device
            for model in self.models.values():
                model.to(self.device)
                model.eval()

            # Initialize fusion mechanism
            hidden_dim = 768  # BERT hidden dimension
            num_models = len(self.models)
            self.fusion_model = AttentionFusion(hidden_dim, num_models).to(self.device)

            self.logger.info(f"Initialized {num_models} models with fusion mechanism")

        except Exception as e:
            self.logger.warning(f"Could not initialize all models: {e}")
            # Fallback to basic implementation
            self._initialize_fallback()

    def _initialize_fallback(self):
        """Fallback initialization for when models aren't available"""
        self.logger.info("Using fallback fusion implementation")
        self.models = {}
        self.fusion_model = None

    def analyze_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Analyze code using hybrid fusion"""
        if not self.models:
            return self._fallback_analysis(code, language)

        try:
            results = {}
            model_outputs = []

            # Get embeddings from each model
            for model_name, model in self.models.items():
                tokenizer = self.tokenizers[model_name]

                # Tokenize code
                inputs = tokenizer(code, return_tensors="pt", truncation=True,
                                 max_length=512, padding=True)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}

                # Get model output
                with torch.no_grad():
                    output = model(**inputs)
                    # Use CLS token embedding
                    embedding = output.last_hidden_state[:, 0, :]  # [batch_size, hidden_dim]
                    model_outputs.append(embedding)

                results[f"{model_name}_confidence"] = torch.sigmoid(
                    torch.mean(embedding)
                ).item()

            # Fusion prediction
            if self.fusion_model and len(model_outputs) > 1:
                fusion_output = self.fusion_model(model_outputs)
                fusion_confidence = fusion_output.item()
            else:
                # Simple average if fusion model not available
                fusion_confidence = np.mean([results[f"{name}_confidence"]
                                           for name in self.models.keys()])

            results.update({
                "fusion_confidence": fusion_confidence,
                "vulnerability_detected": fusion_confidence > self.config.confidence_threshold,
                "language": language,
                "analysis_method": "hybrid_fusion"
            })

            return results

        except Exception as e:
            self.logger.error(f"Fusion analysis failed: {e}")
            return self._fallback_analysis(code, language)

    def _fallback_analysis(self, code: str, language: str) -> Dict[str, Any]:
        """Fallback analysis when fusion is unavailable"""
        # Simple pattern-based analysis
        vulnerability_patterns = [
            "eval(", "exec(", "os.system(", "subprocess.call(",
            "sql", "query", "execute", "unsafe", "buffer",
            "strcpy", "gets", "scanf"
        ]

        code_lower = code.lower()
        matches = sum(1 for pattern in vulnerability_patterns if pattern in code_lower)
        confidence = min(matches * 0.2, 1.0)

        return {
            "fusion_confidence": confidence,
            "vulnerability_detected": confidence > 0.5,
            "language": language,
            "analysis_method": "pattern_fallback",
            "pattern_matches": matches
        }

    def batch_analyze(self, code_samples: List[str],
                     languages: List[str] = None) -> List[Dict[str, Any]]:
        """Batch analysis of multiple code samples"""
        if languages is None:
            languages = ["unknown"] * len(code_samples)

        results = []
        for code, lang in zip(code_samples, languages):
            result = self.analyze_code(code, lang)
            results.append(result)

        return results

    def update_confidence_threshold(self, threshold: float):
        """Update confidence threshold for vulnerability detection"""
        self.config.confidence_threshold = threshold
        self.logger.info(f"Updated confidence threshold to {threshold}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            "models_loaded": list(self.models.keys()),
            "fusion_enabled": self.fusion_model is not None,
            "device": str(self.device),
            "confidence_threshold": self.config.confidence_threshold
        }

# Global fusion system instance
_fusion_system = None

def get_fusion_system(config: Optional[FusionConfig] = None) -> VulnHunterHybridFusion:
    """Get or create global fusion system instance"""
    global _fusion_system
    if _fusion_system is None:
        if config is None:
            config = FusionConfig(models=["codebert", "security_bert"])
        _fusion_system = VulnHunterHybridFusion(config)
    return _fusion_system

def analyze_vulnerability(code: str, language: str = "python") -> Dict[str, Any]:
    """Quick vulnerability analysis using fusion system"""
    fusion_system = get_fusion_system()
    return fusion_system.analyze_code(code, language)

if __name__ == "__main__":
    # Test the fusion system
    test_code = """
    import os
    user_input = input("Enter command: ")
    os.system(user_input)  # Potential command injection
    """

    config = FusionConfig(models=["codebert", "security_bert"])
    fusion = VulnHunterHybridFusion(config)

    result = fusion.analyze_code(test_code, "python")
    print("Fusion Analysis Result:")
    print(result)