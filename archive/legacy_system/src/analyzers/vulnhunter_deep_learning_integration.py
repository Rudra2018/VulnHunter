#!/usr/bin/env python3
"""
VulnHunter Ω Deep Learning Integration
Advanced transformer-based code analysis with deep learning models

Features:
- CodeBERT integration for semantic understanding
- Custom transformer architecture for vulnerability detection
- Deep learning feature extraction
- Integration with existing mathematical framework
- Multi-modal analysis combining AI and mathematical insights
"""

import os
import sys
import json
import time
import logging
import warnings
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import re
import pickle

# Core ML libraries
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

# Scientific computing
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Try to import transformers with fallback
try:
    from transformers import AutoTokenizer, AutoModel, RobertaTokenizer, RobertaModel
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("Transformers not available, using fallback implementations")

# Import existing VulnHunter components
try:
    from vulnhunter_production_platform import VulnHunterProductionPlatform
except ImportError:
    logging.warning("Could not import VulnHunter production platform")

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO)

@dataclass
class DeepLearningConfig:
    """Configuration for deep learning analysis"""
    model_name: str = "microsoft/codebert-base"
    max_sequence_length: int = 512
    hidden_size: int = 768
    num_attention_heads: int = 12
    num_hidden_layers: int = 6
    intermediate_size: int = 3072
    dropout_rate: float = 0.1
    learning_rate: float = 2e-5
    batch_size: int = 8
    use_mathematical_features: bool = True
    enable_gpu: bool = True

class FallbackTokenizer:
    """Fallback tokenizer when transformers are not available"""

    def __init__(self, vocab_size: int = 5000):
        self.vocab_size = vocab_size
        self.word_to_id = {}
        self.id_to_word = {}
        self.special_tokens = {
            '[PAD]': 0, '[UNK]': 1, '[CLS]': 2, '[SEP]': 3, '[MASK]': 4
        }
        self._build_vocab()

    def _build_vocab(self):
        """Build basic vocabulary"""
        # Add special tokens
        for token, idx in self.special_tokens.items():
            self.word_to_id[token] = idx
            self.id_to_word[idx] = token

        # Add common programming tokens
        common_tokens = [
            'function', 'class', 'if', 'else', 'for', 'while', 'return',
            'var', 'let', 'const', 'int', 'string', 'bool', 'public', 'private',
            'contract', 'mapping', 'address', 'uint', 'require', 'assert',
            'msg', 'sender', 'value', 'call', 'transfer', 'balance'
        ]

        current_id = len(self.special_tokens)
        for token in common_tokens:
            if current_id < self.vocab_size:
                self.word_to_id[token] = current_id
                self.id_to_word[current_id] = token
                current_id += 1

    def encode(self, text: str, max_length: int = 512, truncation: bool = True,
              padding: str = 'max_length', return_tensors: str = 'pt') -> Dict[str, torch.Tensor]:
        """Encode text to token IDs"""
        # Simple tokenization
        tokens = re.findall(r'\w+|[^\w\s]', text.lower())

        # Convert to IDs
        token_ids = [self.special_tokens['[CLS]']]
        for token in tokens[:max_length-2]:  # Leave space for CLS and SEP
            token_ids.append(self.word_to_id.get(token, self.special_tokens['[UNK]']))
        token_ids.append(self.special_tokens['[SEP]'])

        # Create attention mask
        attention_mask = [1] * len(token_ids)

        # Pad if necessary
        if padding == 'max_length':
            while len(token_ids) < max_length:
                token_ids.append(self.special_tokens['[PAD]'])
                attention_mask.append(0)

        # Truncate if necessary
        if truncation and len(token_ids) > max_length:
            token_ids = token_ids[:max_length]
            attention_mask = attention_mask[:max_length]

        if return_tensors == 'pt':
            return {
                'input_ids': torch.tensor([token_ids], dtype=torch.long),
                'attention_mask': torch.tensor([attention_mask], dtype=torch.long)
            }
        else:
            return {
                'input_ids': token_ids,
                'attention_mask': attention_mask
            }

class DeepLearningVulnerabilityModel(nn.Module):
    """
    Deep learning model for vulnerability detection
    Combines transformer-based semantic analysis with mathematical features
    """

    def __init__(self, config: DeepLearningConfig):
        super().__init__()
        self.config = config

        # Initialize base model
        if TRANSFORMERS_AVAILABLE:
            try:
                self.base_model = RobertaModel.from_pretrained(
                    config.model_name,
                    add_pooling_layer=False
                )
                self.use_pretrained = True
            except Exception as e:
                logging.warning(f"Could not load pretrained model: {e}")
                self.use_pretrained = False
                self._init_custom_transformer(config)
        else:
            self.use_pretrained = False
            self._init_custom_transformer(config)

        # Mathematical feature projection
        if config.use_mathematical_features:
            self.math_projection = nn.Linear(64, config.hidden_size)  # 64 = math features from existing system

        # Feature fusion layers
        fusion_input_size = config.hidden_size * 2 if config.use_mathematical_features else config.hidden_size
        self.fusion_layers = nn.Sequential(
            nn.Linear(fusion_input_size, config.hidden_size),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(config.hidden_size, config.hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate)
        )

        # Classification heads
        classifier_input_size = config.hidden_size // 2

        # Binary vulnerability classification
        self.vulnerability_classifier = nn.Sequential(
            nn.Linear(classifier_input_size, 64),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(64, 2)
        )

        # Vulnerability type classification (15 types)
        self.type_classifier = nn.Sequential(
            nn.Linear(classifier_input_size, 128),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(128, 15)
        )

        # Severity classification (5 levels)
        self.severity_classifier = nn.Sequential(
            nn.Linear(classifier_input_size, 32),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(32, 5)
        )

        # Confidence estimation
        self.confidence_estimator = nn.Sequential(
            nn.Linear(classifier_input_size, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def _init_custom_transformer(self, config: DeepLearningConfig):
        """Initialize custom transformer when pretrained is not available"""
        self.embeddings = nn.Embedding(5000, config.hidden_size)  # Vocab size 5000
        self.position_embeddings = nn.Embedding(config.max_sequence_length, config.hidden_size)

        # Custom transformer layers
        self.transformer_layers = nn.ModuleList([
            nn.TransformerEncoderLayer(
                d_model=config.hidden_size,
                nhead=config.num_attention_heads,
                dim_feedforward=config.intermediate_size,
                dropout=config.dropout_rate,
                batch_first=True
            ) for _ in range(config.num_hidden_layers)
        ])

        self.layer_norm = nn.LayerNorm(config.hidden_size)

    def forward(self, input_ids, attention_mask=None, mathematical_features=None):
        if self.use_pretrained:
            # Use pretrained transformer
            outputs = self.base_model(input_ids=input_ids, attention_mask=attention_mask)
            sequence_output = outputs.last_hidden_state
        else:
            # Use custom transformer
            sequence_output = self._forward_custom_transformer(input_ids, attention_mask)

        # Global average pooling
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()
            pooled_output = (sequence_output * mask).sum(dim=1) / mask.sum(dim=1)
        else:
            pooled_output = sequence_output.mean(dim=1)

        # Integrate mathematical features if provided
        if mathematical_features is not None and self.config.use_mathematical_features:
            math_features = self.math_projection(mathematical_features)
            # Combine semantic and mathematical features
            combined_features = torch.cat([pooled_output, math_features], dim=-1)
        else:
            combined_features = pooled_output

        # Feature fusion
        fused_features = self.fusion_layers(combined_features)

        # Generate predictions
        vulnerability_logits = self.vulnerability_classifier(fused_features)
        type_logits = self.type_classifier(fused_features)
        severity_logits = self.severity_classifier(fused_features)
        confidence = self.confidence_estimator(fused_features)

        return {
            'vulnerability_logits': vulnerability_logits,
            'type_logits': type_logits,
            'severity_logits': severity_logits,
            'confidence': confidence.squeeze(-1),
            'pooled_output': pooled_output,
            'fused_features': fused_features
        }

    def _forward_custom_transformer(self, input_ids, attention_mask):
        """Forward pass through custom transformer"""
        batch_size, seq_len = input_ids.shape

        # Get embeddings
        token_embeddings = self.embeddings(input_ids)
        position_ids = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch_size, -1)
        position_embeddings = self.position_embeddings(position_ids)

        hidden_states = token_embeddings + position_embeddings
        hidden_states = self.layer_norm(hidden_states)

        # Apply transformer layers
        for layer in self.transformer_layers:
            # Create padding mask for transformer
            if attention_mask is not None:
                src_key_padding_mask = ~attention_mask.bool()
            else:
                src_key_padding_mask = None

            hidden_states = layer(hidden_states, src_key_padding_mask=src_key_padding_mask)

        return hidden_states

class VulnHunterDeepLearningEngine:
    """
    Main engine for deep learning-based vulnerability analysis
    Integrates transformer models with existing mathematical framework
    """

    def __init__(self, config: Optional[DeepLearningConfig] = None):
        self.config = config or DeepLearningConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.device = self._setup_device()

        # Initialize tokenizer
        if TRANSFORMERS_AVAILABLE:
            try:
                self.tokenizer = RobertaTokenizer.from_pretrained(self.config.model_name)
                self.logger.info("Using RobertaTokenizer")
            except Exception as e:
                self.logger.warning(f"Could not load RobertaTokenizer: {e}")
                self.tokenizer = FallbackTokenizer()
                self.logger.info("Using FallbackTokenizer")
        else:
            self.tokenizer = FallbackTokenizer()
            self.logger.info("Using FallbackTokenizer")

        # Initialize model
        self.model = DeepLearningVulnerabilityModel(self.config).to(self.device)
        self.model.eval()

        # Initialize production platform for mathematical features
        try:
            self.production_platform = VulnHunterProductionPlatform()
            self.math_features_available = True
            self.logger.info("Mathematical features integration enabled")
        except Exception as e:
            self.logger.warning(f"Mathematical features not available: {e}")
            self.math_features_available = False

        # Vulnerability type mapping
        self.vulnerability_types = [
            'buffer_overflow', 'injection', 'xss', 'csrf', 'reentrancy',
            'access_control', 'dos_attack', 'memory_corruption', 'integer_overflow',
            'race_condition', 'weak_crypto', 'insecure_storage', 'data_leakage',
            'authentication_bypass', 'permission_bypass'
        ]

        self.severity_levels = ['minimal', 'low', 'medium', 'high', 'critical']

        self.logger.info(f"Deep Learning Engine initialized on {self.device}")

    def _setup_device(self) -> torch.device:
        """Setup compute device"""
        if self.config.enable_gpu and torch.cuda.is_available():
            device = torch.device('cuda')
            self.logger.info(f"Using GPU: {torch.cuda.get_device_name()}")
        else:
            device = torch.device('cpu')
            self.logger.info("Using CPU")
        return device

    def analyze_code_deep_learning(self, code: str, include_mathematical: bool = True) -> Dict[str, Any]:
        """
        Analyze code using deep learning with optional mathematical integration

        Args:
            code: Source code to analyze
            include_mathematical: Whether to include mathematical features

        Returns:
            Comprehensive analysis results
        """
        start_time = time.time()

        try:
            # Tokenize input
            inputs = self.tokenizer(
                code,
                max_length=self.config.max_sequence_length,
                truncation=True,
                padding='max_length',
                return_tensors='pt'
            )

            input_ids = inputs['input_ids'].to(self.device)
            attention_mask = inputs['attention_mask'].to(self.device)

            # Extract mathematical features if requested and available
            mathematical_features = None
            math_analysis = {}

            if include_mathematical and self.math_features_available:
                try:
                    math_result = self.production_platform.analyze_vulnerability_production(
                        code, 'quick', {'mathematical_only': True}
                    )

                    # Extract mathematical feature vector (assuming 64 features)
                    math_features_raw = self._extract_mathematical_features(math_result)
                    mathematical_features = torch.tensor(
                        math_features_raw, dtype=torch.float
                    ).unsqueeze(0).to(self.device)

                    math_analysis = {
                        'ricci_curvature': math_result.get('ricci_curvature_analysis', {}),
                        'persistent_homology': math_result.get('persistent_homology_analysis', {}),
                        'spectral_analysis': math_result.get('spectral_analysis', {}),
                        'mathematical_score': math_result.get('vulnerability_score', 0.0)
                    }

                except Exception as e:
                    self.logger.warning(f"Mathematical feature extraction failed: {e}")

            # Run deep learning inference
            with torch.no_grad():
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    mathematical_features=mathematical_features
                )

            # Process outputs
            vulnerability_probs = F.softmax(outputs['vulnerability_logits'], dim=-1)
            vulnerability_pred = torch.argmax(vulnerability_probs, dim=-1)

            type_probs = F.softmax(outputs['type_logits'], dim=-1)
            type_pred = torch.argmax(type_probs, dim=-1)

            severity_probs = F.softmax(outputs['severity_logits'], dim=-1)
            severity_pred = torch.argmax(severity_probs, dim=-1)

            confidence = outputs['confidence']

            analysis_time = time.time() - start_time

            # Compile results
            results = {
                'vulnerability_detected': bool(vulnerability_pred.item()),
                'vulnerability_confidence': float(vulnerability_probs[0, 1].item()),
                'vulnerability_type': self.vulnerability_types[type_pred.item()],
                'type_confidence': float(type_probs[0, type_pred].item()),
                'severity': self.severity_levels[severity_pred.item()],
                'severity_confidence': float(severity_probs[0, severity_pred].item()),
                'overall_confidence': float(confidence.item()),
                'analysis_time': analysis_time,
                'mathematical_integration': include_mathematical and self.math_features_available,
                'mathematical_analysis': math_analysis,
                'deep_learning_features': {
                    'model_type': 'transformer' if self.model.use_pretrained else 'custom',
                    'sequence_length': input_ids.shape[1],
                    'attention_heads': self.config.num_attention_heads,
                    'hidden_size': self.config.hidden_size
                },
                'device_used': str(self.device),
                'analysis_method': 'deep_learning_integration'
            }

            # Add feature importance if available
            if 'pooled_output' in outputs:
                # Simple feature importance based on activation magnitudes
                feature_importance = torch.mean(torch.abs(outputs['pooled_output']), dim=0)
                top_features = torch.topk(feature_importance, k=10).indices.cpu().tolist()
                results['top_semantic_features'] = top_features

            return results

        except Exception as e:
            self.logger.error(f"Deep learning analysis failed: {e}")
            return {
                'error': str(e),
                'analysis_method': 'deep_learning_integration',
                'fallback_needed': True
            }

    def _extract_mathematical_features(self, math_result: Dict[str, Any]) -> np.ndarray:
        """Extract mathematical features vector from production platform result"""

        # Initialize feature vector
        features = np.zeros(64)

        try:
            # Extract key mathematical metrics (simplified for demo)
            idx = 0

            # Ricci curvature features (16 features)
            ricci_analysis = math_result.get('ricci_curvature_analysis', {})
            ricci_score = ricci_analysis.get('curvature_score', 0.0)
            features[idx:idx+4] = [ricci_score, ricci_score**2, abs(ricci_score), np.log(abs(ricci_score) + 1e-8)]
            idx += 16  # Reserve space for more ricci features

            # Persistent homology features (16 features)
            homology_analysis = math_result.get('persistent_homology_analysis', {})
            homology_score = homology_analysis.get('homology_score', 0.0)
            features[idx:idx+4] = [homology_score, homology_score**2, abs(homology_score), np.log(abs(homology_score) + 1e-8)]
            idx += 16  # Reserve space for more homology features

            # Spectral analysis features (16 features)
            spectral_analysis = math_result.get('spectral_analysis', {})
            spectral_score = spectral_analysis.get('spectral_score', 0.0)
            features[idx:idx+4] = [spectral_score, spectral_score**2, abs(spectral_score), np.log(abs(spectral_score) + 1e-8)]
            idx += 16  # Reserve space for more spectral features

            # Overall mathematical score and derived features (16 features)
            overall_score = math_result.get('vulnerability_score', 0.0)
            confidence_score = math_result.get('confidence', 0.0)
            features[idx:idx+8] = [
                overall_score, confidence_score,
                overall_score * confidence_score,
                abs(overall_score - confidence_score),
                np.sqrt(overall_score + 1e-8),
                np.sqrt(confidence_score + 1e-8),
                overall_score**2,
                confidence_score**2
            ]

        except Exception as e:
            self.logger.warning(f"Feature extraction error: {e}")
            # Return zero vector on error
            features = np.zeros(64)

        return features.astype(np.float32)

    def train_model(self, training_data: List[Dict[str, Any]], validation_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train the deep learning model (simplified training for demo)

        Args:
            training_data: List of training examples
            validation_data: List of validation examples

        Returns:
            Training results and metrics
        """
        self.logger.info(f"Training deep learning model with {len(training_data)} examples")

        # Set model to training mode
        self.model.train()

        # Initialize optimizer
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=0.01
        )

        # Loss functions
        vulnerability_criterion = nn.CrossEntropyLoss()
        type_criterion = nn.CrossEntropyLoss()
        severity_criterion = nn.CrossEntropyLoss()

        # Training loop (simplified)
        num_epochs = 3  # Small number for demo
        training_losses = []
        validation_accuracies = []

        for epoch in range(num_epochs):
            epoch_loss = 0.0
            num_batches = 0

            # Process training data in batches
            for i in range(0, len(training_data), self.config.batch_size):
                batch_data = training_data[i:i + self.config.batch_size]

                # Prepare batch
                batch_codes = [item['code'] for item in batch_data]
                batch_labels = [item['vulnerable'] for item in batch_data]

                # Tokenize batch
                inputs = self.tokenizer(
                    batch_codes,
                    max_length=self.config.max_sequence_length,
                    truncation=True,
                    padding='max_length',
                    return_tensors='pt'
                )

                input_ids = inputs['input_ids'].to(self.device)
                attention_mask = inputs['attention_mask'].to(self.device)
                labels = torch.tensor(batch_labels, dtype=torch.long).to(self.device)

                # Forward pass
                optimizer.zero_grad()
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)

                # Calculate loss
                loss = vulnerability_criterion(outputs['vulnerability_logits'], labels)

                # Backward pass
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()

                epoch_loss += loss.item()
                num_batches += 1

            avg_epoch_loss = epoch_loss / num_batches if num_batches > 0 else 0.0
            training_losses.append(avg_epoch_loss)

            # Validation
            if validation_data:
                val_accuracy = self._validate_model(validation_data)
                validation_accuracies.append(val_accuracy)
                self.logger.info(f"Epoch {epoch+1}/{num_epochs} - Loss: {avg_epoch_loss:.4f}, Val Acc: {val_accuracy:.4f}")
            else:
                self.logger.info(f"Epoch {epoch+1}/{num_epochs} - Loss: {avg_epoch_loss:.4f}")

        # Set back to evaluation mode
        self.model.eval()

        return {
            'training_losses': training_losses,
            'validation_accuracies': validation_accuracies,
            'final_loss': training_losses[-1] if training_losses else 0.0,
            'final_accuracy': validation_accuracies[-1] if validation_accuracies else 0.0,
            'epochs_trained': num_epochs
        }

    def _validate_model(self, validation_data: List[Dict[str, Any]]) -> float:
        """Validate model performance"""
        self.model.eval()
        correct_predictions = 0
        total_predictions = 0

        with torch.no_grad():
            for item in validation_data:
                try:
                    result = self.analyze_code_deep_learning(item['code'], include_mathematical=False)
                    predicted = result['vulnerability_detected']
                    actual = item['vulnerable']

                    if predicted == actual:
                        correct_predictions += 1
                    total_predictions += 1
                except Exception as e:
                    self.logger.warning(f"Validation error: {e}")

        self.model.train()
        return correct_predictions / total_predictions if total_predictions > 0 else 0.0

    def demonstrate_deep_learning_integration(self):
        """Demonstrate deep learning integration capabilities"""

        self.logger.info("🚀 VulnHunter Ω Deep Learning Integration Demo")
        self.logger.info("=" * 60)

        # Test cases
        test_cases = [
            {
                'name': 'Smart Contract Reentrancy',
                'code': '''
                contract VulnerableContract {
                    mapping(address => uint) balances;

                    function withdraw(uint amount) public {
                        require(balances[msg.sender] >= amount);
                        msg.sender.call{value: amount}("");  // Reentrancy vulnerability
                        balances[msg.sender] -= amount;
                    }
                }
                ''',
                'expected_vulnerable': True
            },
            {
                'name': 'Buffer Overflow in C',
                'code': '''
                #include <string.h>
                void vulnerable_function(char* input) {
                    char buffer[100];
                    strcpy(buffer, input);  // Buffer overflow vulnerability
                    printf("Input: %s", buffer);
                }
                ''',
                'expected_vulnerable': True
            },
            {
                'name': 'XSS in JavaScript',
                'code': '''
                function displayMessage(userInput) {
                    document.getElementById('output').innerHTML = userInput;  // XSS vulnerability
                }
                ''',
                'expected_vulnerable': True
            },
            {
                'name': 'Safe Implementation',
                'code': '''
                function safeFunction(userInput) {
                    const sanitized = userInput.replace(/[<>]/g, '');
                    document.getElementById('output').textContent = sanitized;
                }
                ''',
                'expected_vulnerable': False
            }
        ]

        results = []

        for test_case in test_cases:
            self.logger.info(f"\n📋 Analyzing: {test_case['name']}")
            self.logger.info("-" * 40)

            # Test with mathematical integration
            self.logger.info("🧮 Deep Learning + Mathematical Analysis:")
            start_time = time.time()
            result_with_math = self.analyze_code_deep_learning(
                test_case['code'],
                include_mathematical=True
            )
            math_time = time.time() - start_time

            if 'error' in result_with_math:
                self.logger.error(f"Analysis failed: {result_with_math['error']}")
                continue

            # Test without mathematical integration
            self.logger.info("🤖 Deep Learning Only:")
            start_time = time.time()
            result_dl_only = self.analyze_code_deep_learning(
                test_case['code'],
                include_mathematical=False
            )
            dl_time = time.time() - start_time

            # Display results
            vuln_with_math = result_with_math['vulnerability_detected']
            conf_with_math = result_with_math['overall_confidence']
            vuln_dl_only = result_dl_only['vulnerability_detected']
            conf_dl_only = result_dl_only['overall_confidence']

            self.logger.info(f"  With Math: Vulnerable={vuln_with_math}, Confidence={conf_with_math:.3f}, Time={math_time:.3f}s")
            self.logger.info(f"  DL Only:   Vulnerable={vuln_dl_only}, Confidence={conf_dl_only:.3f}, Time={dl_time:.3f}s")
            self.logger.info(f"  Type: {result_with_math['vulnerability_type']}")
            self.logger.info(f"  Severity: {result_with_math['severity']}")

            # Check accuracy
            expected = test_case['expected_vulnerable']
            math_correct = vuln_with_math == expected
            dl_correct = vuln_dl_only == expected

            status_math = "✅ CORRECT" if math_correct else "❌ INCORRECT"
            status_dl = "✅ CORRECT" if dl_correct else "❌ INCORRECT"

            self.logger.info(f"  Math Integration: {status_math}")
            self.logger.info(f"  DL Only: {status_dl}")

            results.append({
                'test_case': test_case['name'],
                'expected': expected,
                'with_math': {
                    'vulnerable': vuln_with_math,
                    'confidence': conf_with_math,
                    'correct': math_correct,
                    'time': math_time
                },
                'dl_only': {
                    'vulnerable': vuln_dl_only,
                    'confidence': conf_dl_only,
                    'correct': dl_correct,
                    'time': dl_time
                }
            })

        # Summary
        self.logger.info("\n" + "=" * 60)
        self.logger.info("🚀 DEEP LEARNING INTEGRATION SUMMARY")
        self.logger.info("=" * 60)

        total_tests = len(results)
        math_correct = sum(1 for r in results if r['with_math']['correct'])
        dl_correct = sum(1 for r in results if r['dl_only']['correct'])

        math_accuracy = math_correct / total_tests if total_tests > 0 else 0
        dl_accuracy = dl_correct / total_tests if total_tests > 0 else 0

        avg_math_time = np.mean([r['with_math']['time'] for r in results])
        avg_dl_time = np.mean([r['dl_only']['time'] for r in results])

        avg_math_conf = np.mean([r['with_math']['confidence'] for r in results])
        avg_dl_conf = np.mean([r['dl_only']['confidence'] for r in results])

        self.logger.info(f"📊 Total Test Cases: {total_tests}")
        self.logger.info(f"🧮 Math Integration Accuracy: {math_accuracy:.1%} ({math_correct}/{total_tests})")
        self.logger.info(f"🤖 Deep Learning Only Accuracy: {dl_accuracy:.1%} ({dl_correct}/{total_tests})")
        self.logger.info(f"⏱️ Average Time - Math: {avg_math_time:.3f}s, DL Only: {avg_dl_time:.3f}s")
        self.logger.info(f"🔍 Average Confidence - Math: {avg_math_conf:.3f}, DL Only: {avg_dl_conf:.3f}")

        # Save results
        summary_results = {
            'total_tests': total_tests,
            'math_integration': {
                'accuracy': math_accuracy,
                'correct_predictions': math_correct,
                'average_time': avg_math_time,
                'average_confidence': avg_math_conf
            },
            'deep_learning_only': {
                'accuracy': dl_accuracy,
                'correct_predictions': dl_correct,
                'average_time': avg_dl_time,
                'average_confidence': avg_dl_conf
            },
            'detailed_results': results,
            'model_info': {
                'model_type': 'transformer' if self.model.use_pretrained else 'custom',
                'hidden_size': self.config.hidden_size,
                'attention_heads': self.config.num_attention_heads,
                'device': str(self.device),
                'mathematical_integration_available': self.math_features_available
            }
        }

        results_path = Path("results/deep_learning_integration_results.json")
        results_path.parent.mkdir(exist_ok=True)

        with open(results_path, 'w') as f:
            json.dump(summary_results, f, indent=2, default=str)

        self.logger.info(f"📁 Results saved to: {results_path}")
        self.logger.info("🚀 Deep Learning Integration Demo Complete!")

        return summary_results

def main():
    """Main function for deep learning integration demo"""

    print("🚀 VulnHunter Ω Deep Learning Integration")
    print("=" * 50)

    # Initialize configuration
    config = DeepLearningConfig(
        model_name="microsoft/codebert-base",
        max_sequence_length=512,
        hidden_size=768,
        num_attention_heads=12,
        num_hidden_layers=6,
        use_mathematical_features=True,
        enable_gpu=torch.cuda.is_available()
    )

    # Initialize deep learning engine
    engine = VulnHunterDeepLearningEngine(config)

    # Run demonstration
    demo_results = engine.demonstrate_deep_learning_integration()

    print(f"\n🚀 Deep Learning Integration Complete!")
    print(f"🧮 Math Integration Accuracy: {demo_results['math_integration']['accuracy']:.1%}")
    print(f"🤖 Deep Learning Accuracy: {demo_results['deep_learning_only']['accuracy']:.1%}")
    print(f"⏱️ Average Analysis Time: {demo_results['math_integration']['average_time']:.3f}s")

if __name__ == "__main__":
    main()