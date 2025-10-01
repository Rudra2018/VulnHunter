"""
LLM-Enhanced Vulnerability Detection Module

This module integrates Large Language Models (LLMs) with traditional static analysis
and machine learning approaches for state-of-the-art vulnerability detection.
Designed for 2026 publication standards with comprehensive LLM integration.
"""

import torch
import torch.nn as nn
from transformers import (
    AutoTokenizer, AutoModel, AutoModelForCausalLM,
    pipeline, BitsAndBytesConfig
)
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import json
import logging
from pathlib import Path

# For efficiency, we'll use quantization
import bitsandbytes as bnb


@dataclass
class LLMAnalysisResult:
    """Result from LLM-based vulnerability analysis"""
    vulnerability_detected: bool
    vulnerability_type: str
    confidence_score: float
    explanation: str
    code_location: str
    severity: str
    remediation_suggestion: str
    reasoning_chain: List[str]
    attention_weights: Optional[torch.Tensor] = None


class LLMVulnerabilityPrompts:
    """Sophisticated prompts for vulnerability detection using LLMs"""

    @staticmethod
    def get_vulnerability_detection_prompt(code: str, context: str = "") -> str:
        """Generate a comprehensive vulnerability detection prompt"""
        return f"""
You are an expert cybersecurity researcher with deep knowledge of software vulnerabilities.
Analyze the following code snippet for potential security vulnerabilities.

{context and f"Context: {context}" or ""}

Code to analyze:
```
{code}
```

Your analysis should:
1. Identify any security vulnerabilities present
2. Classify the vulnerability type (e.g., SQL injection, buffer overflow, XSS, etc.)
3. Assess the severity (Critical, High, Medium, Low)
4. Explain the vulnerability mechanism and potential impact
5. Suggest specific remediation steps

Respond in the following JSON format:
{{
    "vulnerability_detected": true/false,
    "vulnerability_type": "specific_vulnerability_name",
    "severity": "Critical|High|Medium|Low",
    "confidence": 0.0-1.0,
    "explanation": "detailed explanation of the vulnerability",
    "impact": "potential impact and attack scenarios",
    "remediation": "specific code changes or mitigation strategies",
    "reasoning": ["step1", "step2", "step3"]
}}

Be thorough and precise in your analysis. Consider edge cases and potential false positives.
"""

    @staticmethod
    def get_code_understanding_prompt(code: str) -> str:
        """Generate prompt for deep code understanding"""
        return f"""
Analyze this code snippet and provide comprehensive understanding:

```
{code}
```

Provide analysis in JSON format:
{{
    "purpose": "main purpose and functionality",
    "data_flow": "how data flows through the code",
    "external_interactions": "external calls, file operations, network operations",
    "input_sources": "sources of input data",
    "output_destinations": "where output goes",
    "security_critical_operations": ["list of operations that could be security-critical"],
    "complexity_analysis": "analysis of code complexity and maintainability"
}}
"""

    @staticmethod
    def get_exploit_generation_prompt(vulnerability_description: str, code: str) -> str:
        """Generate prompt for proof-of-concept exploit generation"""
        return f"""
You are a security researcher working on responsible vulnerability disclosure.
Generate a proof-of-concept that demonstrates the vulnerability without causing harm.

Vulnerability: {vulnerability_description}

Vulnerable code:
```
{code}
```

Generate a safe proof-of-concept in JSON format:
{{
    "poc_type": "type of proof-of-concept",
    "test_input": "safe test input that demonstrates the vulnerability",
    "expected_behavior": "what should happen with safe input",
    "vulnerable_behavior": "what happens that demonstrates the vulnerability",
    "safety_measures": "measures taken to ensure the PoC is safe",
    "detection_method": "how this vulnerability can be detected"
}}

IMPORTANT: Only generate safe, educational proof-of-concepts. Never create actual exploits.
"""


class LLMEnhancedDetector(nn.Module):
    """
    Advanced vulnerability detector combining traditional ML with LLM capabilities.

    Features:
    - Multi-modal analysis (static + LLM reasoning)
    - Explainable predictions with natural language reasoning
    - Context-aware vulnerability detection
    - Automated remediation suggestions
    - Confidence calibration across different analysis modes
    """

    def __init__(self,
                 base_model_name: str = "microsoft/codebert-base",
                 llm_model_name: str = "codellama/CodeLlama-7b-Instruct-hf",
                 use_quantization: bool = True,
                 cache_dir: str = "./models/cache"):
        """
        Initialize LLM-enhanced vulnerability detector.

        Args:
            base_model_name: Base transformer model for code understanding
            llm_model_name: Large language model for reasoning and explanation
            use_quantization: Whether to use 4-bit quantization for efficiency
            cache_dir: Directory to cache models
        """
        super().__init__()

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize tokenizers
        self.base_tokenizer = AutoTokenizer.from_pretrained(
            base_model_name, cache_dir=cache_dir
        )
        self.llm_tokenizer = AutoTokenizer.from_pretrained(
            llm_model_name, cache_dir=cache_dir
        )

        # Ensure pad tokens exist
        if self.base_tokenizer.pad_token is None:
            self.base_tokenizer.pad_token = self.base_tokenizer.eos_token
        if self.llm_tokenizer.pad_token is None:
            self.llm_tokenizer.pad_token = self.llm_tokenizer.eos_token

        # Initialize base transformer for embeddings
        self.base_model = AutoModel.from_pretrained(
            base_model_name, cache_dir=cache_dir
        )

        # Initialize LLM with quantization if requested
        if use_quantization:
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4"
            )
            self.llm_model = AutoModelForCausalLM.from_pretrained(
                llm_model_name,
                quantization_config=quantization_config,
                cache_dir=cache_dir,
                device_map="auto",
                torch_dtype=torch.float16
            )
        else:
            self.llm_model = AutoModelForCausalLM.from_pretrained(
                llm_model_name, cache_dir=cache_dir
            )

        # Classification head for traditional ML path
        self.classifier = nn.Sequential(
            nn.Linear(self.base_model.config.hidden_size, 512),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 30)  # 30 vulnerability classes
        )

        # Confidence calibration layer
        self.confidence_calibrator = nn.Sequential(
            nn.Linear(self.base_model.config.hidden_size + 30, 128),
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

        # Initialize generation pipeline
        self.generation_pipeline = pipeline(
            "text-generation",
            model=self.llm_model,
            tokenizer=self.llm_tokenizer,
            torch_dtype=torch.float16,
            device_map="auto"
        )

        self.prompts = LLMVulnerabilityPrompts()

        logging.info(f"Initialized LLM-Enhanced Detector with {base_model_name} + {llm_model_name}")

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> Dict[str, torch.Tensor]:
        """
        Forward pass for traditional ML component.

        Args:
            input_ids: Tokenized input sequences
            attention_mask: Attention mask for sequences

        Returns:
            Dictionary containing logits and embeddings
        """
        # Get base model embeddings
        outputs = self.base_model(input_ids=input_ids, attention_mask=attention_mask)

        # Use CLS token embedding for classification
        cls_embedding = outputs.last_hidden_state[:, 0, :]  # [batch_size, hidden_size]

        # Get vulnerability predictions
        logits = self.classifier(cls_embedding)

        # Calculate calibrated confidence
        confidence_input = torch.cat([cls_embedding, logits], dim=1)
        confidence = self.confidence_calibrator(confidence_input)

        return {
            'logits': logits,
            'embeddings': cls_embedding,
            'confidence': confidence,
            'attention_weights': outputs.attentions[-1] if outputs.attentions else None
        }

    def analyze_code_with_llm(self,
                             code: str,
                             context: str = "",
                             max_new_tokens: int = 1024,
                             temperature: float = 0.1) -> LLMAnalysisResult:
        """
        Perform vulnerability analysis using LLM reasoning.

        Args:
            code: Source code to analyze
            context: Additional context about the code
            max_new_tokens: Maximum tokens to generate
            temperature: Generation temperature (lower = more deterministic)

        Returns:
            LLMAnalysisResult with detailed analysis
        """
        # Generate vulnerability detection prompt
        prompt = self.prompts.get_vulnerability_detection_prompt(code, context)

        try:
            # Generate analysis using LLM
            response = self.generation_pipeline(
                prompt,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=True,
                pad_token_id=self.llm_tokenizer.eos_token_id,
                return_full_text=False
            )

            generated_text = response[0]['generated_text']

            # Parse JSON response
            try:
                # Extract JSON from response (handle various formats)
                json_start = generated_text.find('{')
                json_end = generated_text.rfind('}') + 1

                if json_start != -1 and json_end > json_start:
                    json_str = generated_text[json_start:json_end]
                    analysis_data = json.loads(json_str)

                    return LLMAnalysisResult(
                        vulnerability_detected=analysis_data.get('vulnerability_detected', False),
                        vulnerability_type=analysis_data.get('vulnerability_type', 'unknown'),
                        confidence_score=float(analysis_data.get('confidence', 0.0)),
                        explanation=analysis_data.get('explanation', ''),
                        code_location=code[:100] + "..." if len(code) > 100 else code,
                        severity=analysis_data.get('severity', 'Low'),
                        remediation_suggestion=analysis_data.get('remediation', ''),
                        reasoning_chain=analysis_data.get('reasoning', [])
                    )
                else:
                    raise ValueError("No valid JSON found in response")

            except (json.JSONDecodeError, ValueError) as e:
                logging.warning(f"Failed to parse LLM response as JSON: {e}")
                # Fallback: create result from raw text
                return LLMAnalysisResult(
                    vulnerability_detected="vulnerability" in generated_text.lower(),
                    vulnerability_type="unknown",
                    confidence_score=0.5,
                    explanation=generated_text,
                    code_location=code[:100] + "..." if len(code) > 100 else code,
                    severity="Medium",
                    remediation_suggestion="Review code manually for security issues",
                    reasoning_chain=["LLM analysis completed but JSON parsing failed"]
                )

        except Exception as e:
            logging.error(f"LLM analysis failed: {e}")
            return LLMAnalysisResult(
                vulnerability_detected=False,
                vulnerability_type="analysis_failed",
                confidence_score=0.0,
                explanation=f"LLM analysis failed: {str(e)}",
                code_location=code[:100] + "..." if len(code) > 100 else code,
                severity="Unknown",
                remediation_suggestion="Manual review required",
                reasoning_chain=[f"Analysis failed: {str(e)}"]
            )

    def hybrid_analysis(self, code: str, context: str = "") -> Dict[str, Any]:
        """
        Perform hybrid analysis combining traditional ML and LLM approaches.

        Args:
            code: Source code to analyze
            context: Additional context

        Returns:
            Comprehensive analysis results
        """
        # Tokenize for traditional ML analysis
        encoding = self.base_tokenizer(
            code,
            truncation=True,
            padding=True,
            max_length=512,
            return_tensors="pt"
        )

        # Traditional ML analysis
        with torch.no_grad():
            ml_output = self.forward(encoding['input_ids'], encoding['attention_mask'])

            # Get predictions
            probabilities = torch.softmax(ml_output['logits'], dim=-1)
            predicted_class = torch.argmax(probabilities, dim=-1).item()
            max_probability = torch.max(probabilities).item()
            confidence = ml_output['confidence'].item()

        # LLM analysis
        llm_result = self.analyze_code_with_llm(code, context)

        # Combine results
        combined_confidence = (confidence + llm_result.confidence_score) / 2

        # Determine final prediction (give more weight to LLM if highly confident)
        if llm_result.confidence_score > 0.8:
            final_prediction = llm_result.vulnerability_detected
            final_vulnerability_type = llm_result.vulnerability_type
        else:
            final_prediction = predicted_class > 0  # Assuming class 0 is "no vulnerability"
            # Map predicted class to vulnerability type (simplified)
            vulnerability_types = [
                "none", "sql_injection", "xss", "command_injection", "buffer_overflow",
                "path_traversal", "authentication_bypass", "authorization_bypass",
                "crypto_weakness", "memory_corruption", "race_condition",
                "input_validation", "output_encoding", "session_management",
                "access_control", "configuration_error"
            ]
            final_vulnerability_type = vulnerability_types[min(predicted_class, len(vulnerability_types)-1)]

        return {
            'vulnerability_detected': final_prediction,
            'vulnerability_type': final_vulnerability_type,
            'confidence': combined_confidence,
            'ml_prediction': {
                'predicted_class': predicted_class,
                'probability': max_probability,
                'confidence': confidence,
                'probabilities': probabilities.tolist()
            },
            'llm_analysis': {
                'vulnerability_detected': llm_result.vulnerability_detected,
                'vulnerability_type': llm_result.vulnerability_type,
                'confidence': llm_result.confidence_score,
                'explanation': llm_result.explanation,
                'severity': llm_result.severity,
                'remediation': llm_result.remediation_suggestion,
                'reasoning': llm_result.reasoning_chain
            },
            'combined_analysis': {
                'method': 'hybrid_ml_llm',
                'final_confidence': combined_confidence,
                'explanation': llm_result.explanation,
                'severity': llm_result.severity,
                'remediation': llm_result.remediation_suggestion
            }
        }

    def generate_poc(self, vulnerability_type: str, code: str) -> Dict[str, Any]:
        """
        Generate safe proof-of-concept for educational purposes.

        Args:
            vulnerability_type: Type of vulnerability
            code: Vulnerable code

        Returns:
            Safe proof-of-concept information
        """
        prompt = self.prompts.get_exploit_generation_prompt(vulnerability_type, code)

        try:
            response = self.generation_pipeline(
                prompt,
                max_new_tokens=512,
                temperature=0.2,
                do_sample=True,
                pad_token_id=self.llm_tokenizer.eos_token_id
            )

            generated_text = response[0]['generated_text']

            # Parse JSON response
            json_start = generated_text.find('{')
            json_end = generated_text.rfind('}') + 1

            if json_start != -1 and json_end > json_start:
                json_str = generated_text[json_start:json_end]
                poc_data = json.loads(json_str)
                return poc_data
            else:
                return {
                    "poc_type": "text_description",
                    "description": generated_text,
                    "safety_note": "This is a safe, educational description only"
                }

        except Exception as e:
            logging.error(f"PoC generation failed: {e}")
            return {
                "error": f"PoC generation failed: {str(e)}",
                "safety_note": "No proof-of-concept generated due to error"
            }

    def explain_prediction(self, code: str, prediction_result: Dict[str, Any]) -> str:
        """
        Generate natural language explanation of the prediction.

        Args:
            code: Source code that was analyzed
            prediction_result: Result from hybrid_analysis

        Returns:
            Human-readable explanation
        """
        if prediction_result['vulnerability_detected']:
            explanation = f"""
VULNERABILITY DETECTED: {prediction_result['vulnerability_type']}

Confidence: {prediction_result['confidence']:.2f}
Severity: {prediction_result['llm_analysis']['severity']}

Analysis:
{prediction_result['llm_analysis']['explanation']}

Machine Learning Analysis:
- Predicted class: {prediction_result['ml_prediction']['predicted_class']}
- Probability: {prediction_result['ml_prediction']['probability']:.3f}
- ML Confidence: {prediction_result['ml_prediction']['confidence']:.3f}

Recommended Actions:
{prediction_result['llm_analysis']['remediation']}

Reasoning Chain:
{chr(10).join(f"- {step}" for step in prediction_result['llm_analysis']['reasoning'])}
"""
        else:
            explanation = f"""
NO VULNERABILITY DETECTED

Confidence: {prediction_result['confidence']:.2f}

The analysis did not identify any significant security vulnerabilities in the provided code.

Machine Learning Analysis:
- Predicted class: {prediction_result['ml_prediction']['predicted_class']}
- Probability: {prediction_result['ml_prediction']['probability']:.3f}

Note: This analysis is not exhaustive. Consider additional testing and manual review.
"""

        return explanation

    def batch_analyze(self, code_samples: List[str], contexts: List[str] = None) -> List[Dict[str, Any]]:
        """
        Analyze multiple code samples efficiently.

        Args:
            code_samples: List of code snippets to analyze
            contexts: Optional list of contexts for each sample

        Returns:
            List of analysis results
        """
        if contexts is None:
            contexts = [""] * len(code_samples)

        results = []
        for i, (code, context) in enumerate(zip(code_samples, contexts)):
            logging.info(f"Analyzing sample {i+1}/{len(code_samples)}")
            result = self.hybrid_analysis(code, context)
            results.append(result)

        return results

    def save_model(self, save_path: str):
        """Save the model state (excluding LLM which is too large)."""
        state_dict = {
            'classifier': self.classifier.state_dict(),
            'confidence_calibrator': self.confidence_calibrator.state_dict(),
            'base_model': self.base_model.state_dict()
        }
        torch.save(state_dict, save_path)
        logging.info(f"Model saved to {save_path}")

    def load_model(self, load_path: str):
        """Load model state."""
        state_dict = torch.load(load_path, map_location='cpu')
        self.classifier.load_state_dict(state_dict['classifier'])
        self.confidence_calibrator.load_state_dict(state_dict['confidence_calibrator'])
        self.base_model.load_state_dict(state_dict['base_model'])
        logging.info(f"Model loaded from {load_path}")


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)

    # Initialize detector (will download models if not cached)
    print("Initializing LLM-Enhanced Detector...")
    detector = LLMEnhancedDetector(
        use_quantization=True  # Use quantization for efficiency
    )

    # Test cases
    test_codes = [
        "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",  # SQL injection
        "strcpy(buffer, user_input);",  # Buffer overflow
        "print('Hello, world!')",  # Safe code
        "os.system(user_command)",  # Command injection
    ]

    print("\nAnalyzing test cases...")
    for i, code in enumerate(test_codes):
        print(f"\n{'='*50}")
        print(f"Test Case {i+1}: {code}")
        print(f"{'='*50}")

        # Perform hybrid analysis
        result = detector.hybrid_analysis(code)

        # Print results
        print(f"Vulnerability Detected: {result['vulnerability_detected']}")
        print(f"Type: {result['vulnerability_type']}")
        print(f"Confidence: {result['confidence']:.3f}")
        print(f"Severity: {result['llm_analysis']['severity']}")

        # Print explanation
        explanation = detector.explain_prediction(code, result)
        print(f"\nDetailed Analysis:\n{explanation}")

        print("-" * 50)