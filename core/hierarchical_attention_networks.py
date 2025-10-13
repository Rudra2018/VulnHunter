#!/usr/bin/env python3
"""
Hierarchical Attention Networks (HAN) with CodeBERT for VulnHunter

Enhanced document-level understanding of code semantics through hierarchical
attention mechanisms combined with pre-trained CodeBERT embeddings.

Key Features:
- Multi-level attention: word-level and sentence-level attention mechanisms
- Context-aware processing: better capture long-range dependencies in code
- Multi-task capability: simultaneous vulnerability prediction and classification
- CodeBERT integration: leverages pre-trained code understanding
- Cross-modal learning: combines code tokens, AST structures, and semantic graphs
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer, AutoConfig
from typing import Dict, List, Tuple, Any, Optional, Union
from dataclasses import dataclass
import numpy as np
import logging
import re
import ast
from collections import defaultdict
import math

@dataclass
class HANConfig:
    """Configuration for Hierarchical Attention Networks."""

    # CodeBERT parameters
    codebert_model: str = "microsoft/codebert-base"
    codebert_max_length: int = 512
    codebert_feature_dim: int = 768
    freeze_codebert: bool = False

    # Hierarchical attention parameters
    word_attention_dim: int = 256
    sentence_attention_dim: int = 256
    document_attention_dim: int = 512

    # Multi-head attention parameters
    num_attention_heads: int = 8
    attention_dropout: float = 0.1

    # Code processing parameters
    max_sentences_per_document: int = 100
    max_words_per_sentence: int = 64
    code_context_window: int = 5  # Lines of context around each sentence

    # Feature fusion parameters
    fusion_hidden_dim: int = 512
    final_hidden_dim: int = 256
    dropout_rate: float = 0.3

    # Multi-task parameters
    num_vulnerability_types: int = 25  # CWE types
    num_severity_levels: int = 4  # Low, Medium, High, Critical

    # Training parameters
    learning_rate: float = 0.0001
    weight_decay: float = 1e-5

class WordAttention(nn.Module):
    """
    Word-level attention mechanism for capturing important tokens within sentences.

    Applies attention over individual tokens to identify the most relevant
    words for vulnerability detection within each code sentence/line.
    """

    def __init__(self, config: HANConfig):
        super().__init__()
        self.config = config

        # Word-level attention parameters
        self.word_weight = nn.Linear(config.codebert_feature_dim, config.word_attention_dim)
        self.word_context_vector = nn.Parameter(torch.randn(config.word_attention_dim))

        # Multi-head attention for words
        self.word_multihead_attention = nn.MultiheadAttention(
            embed_dim=config.codebert_feature_dim,
            num_heads=config.num_attention_heads,
            dropout=config.attention_dropout,
            batch_first=True
        )

        # Word feature transformation
        self.word_transform = nn.Linear(config.codebert_feature_dim, config.word_attention_dim)

        self.dropout = nn.Dropout(config.dropout_rate)

    def forward(self, word_embeddings: torch.Tensor, attention_mask: torch.Tensor = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Apply word-level attention to token embeddings.

        Args:
            word_embeddings: Token embeddings [batch_size, seq_len, embed_dim]
            attention_mask: Attention mask [batch_size, seq_len]

        Returns:
            Tuple of (attended_sentence_representation, attention_weights)
        """

        batch_size, seq_len, embed_dim = word_embeddings.shape

        # Multi-head self-attention over words
        attended_words, _ = self.word_multihead_attention(
            word_embeddings, word_embeddings, word_embeddings,
            key_padding_mask=~attention_mask.bool() if attention_mask is not None else None
        )

        # Additive attention mechanism
        # Transform embeddings
        word_hidden = torch.tanh(self.word_weight(attended_words))  # [batch_size, seq_len, word_attention_dim]

        # Compute attention scores
        attention_scores = torch.matmul(word_hidden, self.word_context_vector)  # [batch_size, seq_len]

        # Apply attention mask
        if attention_mask is not None:
            attention_scores = attention_scores.masked_fill(~attention_mask.bool(), float('-inf'))

        # Compute attention weights
        attention_weights = F.softmax(attention_scores, dim=1)  # [batch_size, seq_len]

        # Apply attention weights to get sentence representation
        sentence_representation = torch.sum(
            attended_words * attention_weights.unsqueeze(-1), dim=1
        )  # [batch_size, embed_dim]

        # Transform to attention dimension
        sentence_representation = self.word_transform(sentence_representation)
        sentence_representation = self.dropout(sentence_representation)

        return sentence_representation, attention_weights

class SentenceAttention(nn.Module):
    """
    Sentence-level attention mechanism for capturing important lines/statements in code.

    Applies attention over code sentences (lines) to identify the most relevant
    statements for vulnerability detection within the entire code document.
    """

    def __init__(self, config: HANConfig):
        super().__init__()
        self.config = config

        # Sentence-level attention parameters
        self.sentence_weight = nn.Linear(config.word_attention_dim, config.sentence_attention_dim)
        self.sentence_context_vector = nn.Parameter(torch.randn(config.sentence_attention_dim))

        # Multi-head attention for sentences
        self.sentence_multihead_attention = nn.MultiheadAttention(
            embed_dim=config.word_attention_dim,
            num_heads=config.num_attention_heads,
            dropout=config.attention_dropout,
            batch_first=True
        )

        # Contextual information integration
        self.context_integration = nn.LSTM(
            input_size=config.word_attention_dim,
            hidden_size=config.sentence_attention_dim // 2,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=config.dropout_rate
        )

        # Final transformation
        self.document_transform = nn.Linear(config.sentence_attention_dim, config.document_attention_dim)

        self.dropout = nn.Dropout(config.dropout_rate)

    def forward(self, sentence_representations: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Apply sentence-level attention to sentence representations.

        Args:
            sentence_representations: Sentence embeddings [batch_size, num_sentences, word_attention_dim]

        Returns:
            Tuple of (document_representation, sentence_attention_weights)
        """

        batch_size, num_sentences, sentence_dim = sentence_representations.shape

        # Multi-head self-attention over sentences
        attended_sentences, _ = self.sentence_multihead_attention(
            sentence_representations, sentence_representations, sentence_representations
        )

        # Contextual integration with LSTM
        contextual_sentences, _ = self.context_integration(attended_sentences)

        # Additive attention mechanism
        # Transform sentences
        sentence_hidden = torch.tanh(self.sentence_weight(contextual_sentences))  # [batch_size, num_sentences, sentence_attention_dim]

        # Compute attention scores
        attention_scores = torch.matmul(sentence_hidden, self.sentence_context_vector)  # [batch_size, num_sentences]

        # Compute attention weights
        attention_weights = F.softmax(attention_scores, dim=1)  # [batch_size, num_sentences]

        # Apply attention weights to get document representation
        document_representation = torch.sum(
            contextual_sentences * attention_weights.unsqueeze(-1), dim=1
        )  # [batch_size, sentence_attention_dim]

        # Transform to document dimension
        document_representation = self.document_transform(document_representation)
        document_representation = self.dropout(document_representation)

        return document_representation, attention_weights

class CodeBERTEncoder(nn.Module):
    """
    CodeBERT-based encoder for code token embeddings.

    Leverages pre-trained CodeBERT model for enhanced understanding
    of code semantics and programming language structures.
    """

    def __init__(self, config: HANConfig):
        super().__init__()
        self.config = config

        # Load pre-trained CodeBERT
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(config.codebert_model)
            self.codebert_config = AutoConfig.from_pretrained(config.codebert_model)
            self.codebert = AutoModel.from_pretrained(config.codebert_model)

            # Freeze CodeBERT parameters if specified
            if config.freeze_codebert:
                for param in self.codebert.parameters():
                    param.requires_grad = False

        except Exception as e:
            logging.warning(f"Could not load CodeBERT: {e}. Using dummy implementation.")
            self.tokenizer = None
            self.codebert = None

        # Feature adaptation layer
        self.feature_adapter = nn.Linear(config.codebert_feature_dim, config.codebert_feature_dim)

        self.logger = logging.getLogger(__name__)

    def forward(self, code_sentences: List[str]) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Encode code sentences using CodeBERT.

        Args:
            code_sentences: List of code sentences/lines

        Returns:
            Tuple of (sentence_embeddings, attention_masks)
        """

        if self.tokenizer is None or self.codebert is None:
            # Dummy implementation
            batch_size = len(code_sentences)
            return (
                torch.randn(batch_size, self.config.max_words_per_sentence, self.config.codebert_feature_dim),
                torch.ones(batch_size, self.config.max_words_per_sentence, dtype=torch.bool)
            )

        sentence_embeddings = []
        attention_masks = []

        for sentence in code_sentences:
            try:
                # Tokenize sentence
                inputs = self.tokenizer(
                    sentence,
                    max_length=self.config.max_words_per_sentence,
                    truncation=True,
                    padding='max_length',
                    return_tensors='pt'
                )

                # Get CodeBERT embeddings
                with torch.no_grad() if self.config.freeze_codebert else torch.enable_grad():
                    outputs = self.codebert(**inputs)
                    token_embeddings = outputs.last_hidden_state  # [1, seq_len, hidden_dim]

                # Adapt features
                adapted_embeddings = self.feature_adapter(token_embeddings)

                sentence_embeddings.append(adapted_embeddings.squeeze(0))
                attention_masks.append(inputs['attention_mask'].squeeze(0))

            except Exception as e:
                self.logger.warning(f"Error encoding sentence: {e}")
                # Fallback to random embeddings
                sentence_embeddings.append(
                    torch.randn(self.config.max_words_per_sentence, self.config.codebert_feature_dim)
                )
                attention_masks.append(
                    torch.ones(self.config.max_words_per_sentence, dtype=torch.bool)
                )

        # Stack into batch tensors
        sentence_embeddings = torch.stack(sentence_embeddings)  # [num_sentences, seq_len, hidden_dim]
        attention_masks = torch.stack(attention_masks)  # [num_sentences, seq_len]

        return sentence_embeddings, attention_masks

class CrossModalFusion(nn.Module):
    """
    Cross-modal fusion module for combining code tokens, AST structures, and semantic graphs.

    Integrates hierarchical attention features with structural and semantic
    information for comprehensive vulnerability understanding.
    """

    def __init__(self, config: HANConfig):
        super().__init__()
        self.config = config

        # Feature dimensions
        hierarchical_dim = config.document_attention_dim
        ast_dim = 256  # AST features
        semantic_dim = 256  # Semantic graph features

        # Cross-modal attention mechanisms
        self.token_ast_attention = nn.MultiheadAttention(
            embed_dim=hierarchical_dim,
            num_heads=config.num_attention_heads // 2,
            dropout=config.attention_dropout,
            batch_first=True
        )

        self.token_semantic_attention = nn.MultiheadAttention(
            embed_dim=hierarchical_dim,
            num_heads=config.num_attention_heads // 2,
            dropout=config.attention_dropout,
            batch_first=True
        )

        # Feature projection layers
        self.ast_projector = nn.Linear(ast_dim, hierarchical_dim)
        self.semantic_projector = nn.Linear(semantic_dim, hierarchical_dim)

        # Fusion layers
        self.fusion_layer = nn.Sequential(
            nn.Linear(hierarchical_dim * 3, config.fusion_hidden_dim),
            nn.LayerNorm(config.fusion_hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(config.fusion_hidden_dim, config.final_hidden_dim),
            nn.ReLU()
        )

    def forward(self, hierarchical_features: torch.Tensor,
               ast_features: torch.Tensor = None,
               semantic_features: torch.Tensor = None) -> torch.Tensor:
        """
        Perform cross-modal fusion of hierarchical attention features.

        Args:
            hierarchical_features: Document features from HAN [batch_size, document_attention_dim]
            ast_features: AST structural features [batch_size, ast_dim]
            semantic_features: Semantic graph features [batch_size, semantic_dim]

        Returns:
            Fused multi-modal features [batch_size, final_hidden_dim]
        """

        batch_size = hierarchical_features.shape[0]

        # Prepare features for attention (add sequence dimension)
        hierarchical_seq = hierarchical_features.unsqueeze(1)  # [batch_size, 1, hierarchical_dim]

        # Process AST features
        if ast_features is not None:
            ast_projected = self.ast_projector(ast_features).unsqueeze(1)  # [batch_size, 1, hierarchical_dim]

            # Cross-attention between tokens and AST
            hierarchical_ast_attended, _ = self.token_ast_attention(
                hierarchical_seq, ast_projected, ast_projected
            )
            hierarchical_features_updated = hierarchical_ast_attended.squeeze(1)
        else:
            hierarchical_features_updated = hierarchical_features
            ast_projected = torch.zeros_like(hierarchical_seq)

        # Process semantic features
        if semantic_features is not None:
            semantic_projected = self.semantic_projector(semantic_features).unsqueeze(1)  # [batch_size, 1, hierarchical_dim]

            # Cross-attention between tokens and semantics
            hierarchical_semantic_attended, _ = self.token_semantic_attention(
                hierarchical_features_updated.unsqueeze(1), semantic_projected, semantic_projected
            )
            hierarchical_features_final = hierarchical_semantic_attended.squeeze(1)
        else:
            hierarchical_features_final = hierarchical_features_updated
            semantic_projected = torch.zeros_like(hierarchical_seq)

        # Combine all modalities
        combined_features = torch.cat([
            hierarchical_features_final,
            ast_projected.squeeze(1) if ast_features is not None else torch.zeros_like(hierarchical_features),
            semantic_projected.squeeze(1) if semantic_features is not None else torch.zeros_like(hierarchical_features)
        ], dim=1)

        # Apply fusion transformation
        fused_features = self.fusion_layer(combined_features)

        return fused_features

class HierarchicalAttentionNetwork(nn.Module):
    """
    Complete Hierarchical Attention Network with CodeBERT integration.

    Implements multi-level attention mechanisms for enhanced document-level
    understanding of code semantics and vulnerability detection.
    """

    def __init__(self, config: HANConfig):
        super().__init__()
        self.config = config

        # Core components
        self.codebert_encoder = CodeBERTEncoder(config)
        self.word_attention = WordAttention(config)
        self.sentence_attention = SentenceAttention(config)
        self.cross_modal_fusion = CrossModalFusion(config)

        # Multi-task prediction heads
        self.vulnerability_classifier = nn.Sequential(
            nn.Linear(config.final_hidden_dim, 128),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(128, 2)  # Binary: vulnerable/not vulnerable
        )

        self.vulnerability_type_classifier = nn.Sequential(
            nn.Linear(config.final_hidden_dim, 256),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(256, config.num_vulnerability_types)  # CWE types
        )

        self.severity_classifier = nn.Sequential(
            nn.Linear(config.final_hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(64, config.num_severity_levels)  # Severity levels
        )

        self.confidence_predictor = nn.Sequential(
            nn.Linear(config.final_hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

        # Attention weight storage for interpretability
        self.last_word_attention_weights = None
        self.last_sentence_attention_weights = None

        self.logger = logging.getLogger(__name__)

    def preprocess_code(self, code: str) -> List[str]:
        """Preprocess code into sentences for hierarchical processing."""

        # Split code into logical sentences (lines in this case)
        lines = code.strip().split('\n')

        # Filter and clean lines
        processed_sentences = []
        for line in lines:
            stripped = line.strip()

            # Skip empty lines and pure comments
            if not stripped or stripped.startswith('#'):
                continue

            # Clean up the line
            cleaned = re.sub(r'#.*$', '', stripped).strip()  # Remove inline comments
            if cleaned:
                processed_sentences.append(cleaned)

        # Limit number of sentences
        if len(processed_sentences) > self.config.max_sentences_per_document:
            # Keep first and last sentences, sample from middle
            first_part = processed_sentences[:self.config.max_sentences_per_document//3]
            last_part = processed_sentences[-self.config.max_sentences_per_document//3:]
            middle_part = processed_sentences[self.config.max_sentences_per_document//3:-self.config.max_sentences_per_document//3]

            # Sample from middle
            if middle_part:
                middle_sample_size = self.config.max_sentences_per_document - len(first_part) - len(last_part)
                if middle_sample_size > 0:
                    step = max(1, len(middle_part) // middle_sample_size)
                    middle_sampled = middle_part[::step][:middle_sample_size]
                else:
                    middle_sampled = []
            else:
                middle_sampled = []

            processed_sentences = first_part + middle_sampled + last_part

        return processed_sentences[:self.config.max_sentences_per_document]

    def extract_structural_features(self, code: str) -> torch.Tensor:
        """Extract simple AST-like structural features from code."""

        features = [0.0] * 256

        # Count different node types
        node_counts = {
            'function_def': len(re.findall(r'\bdef\s+\w+', code)),
            'class_def': len(re.findall(r'\bclass\s+\w+', code)),
            'if_stmt': code.count('if '),
            'for_loop': code.count('for '),
            'while_loop': code.count('while '),
            'try_block': code.count('try:'),
            'import_stmt': code.count('import ') + code.count('from '),
            'function_call': len(re.findall(r'\w+\s*\(', code)),
            'assignment': code.count('=') - code.count('==') - code.count('!=') - code.count('<=') - code.count('>='),
            'comparison': code.count('==') + code.count('!=') + code.count('<=') + code.count('>=') + code.count('<') + code.count('>'),
        }

        # Normalize counts
        total_lines = max(len(code.split('\n')), 1)
        for i, (node_type, count) in enumerate(node_counts.items()):
            if i < 256:
                features[i] = count / total_lines

        # Security-relevant patterns
        security_patterns = [
            'eval(', 'exec(', 'system(', 'shell=True', 'subprocess',
            'open(', 'file(', 'input(', 'raw_input(', 'urllib',
            'socket', 'pickle', 'marshal', 'base64', 'hashlib'
        ]

        for i, pattern in enumerate(security_patterns):
            if 10 + i < 256:
                features[10 + i] = float(pattern in code)

        return torch.tensor(features, dtype=torch.float)

    def extract_semantic_features(self, code: str) -> torch.Tensor:
        """Extract semantic graph-like features from code."""

        features = [0.0] * 256

        # Semantic complexity metrics
        lines = code.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]

        if non_empty_lines:
            # Indentation-based complexity
            indentations = [len(line) - len(line.lstrip()) for line in non_empty_lines]
            features[0] = max(indentations) if indentations else 0
            features[1] = np.mean(indentations) if indentations else 0
            features[2] = len(set(indentations)) if indentations else 0

            # Syntactic complexity
            features[3] = sum(line.count('(') for line in non_empty_lines) / len(non_empty_lines)
            features[4] = sum(line.count('[') for line in non_empty_lines) / len(non_empty_lines)
            features[5] = sum(line.count('.') for line in non_empty_lines) / len(non_empty_lines)

        # Variable and function analysis
        variable_pattern = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*=')
        function_pattern = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*\(')

        variables = set(variable_pattern.findall(code))
        functions = set(function_pattern.findall(code))

        features[6] = len(variables)
        features[7] = len(functions)

        # Data flow indicators
        features[8] = float('return' in code)
        features[9] = float(any(kw in code for kw in ['global', 'nonlocal']))

        return torch.tensor(features, dtype=torch.float)

    def forward(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Forward pass through Hierarchical Attention Network.

        Args:
            code: Source code string

        Returns:
            Dictionary with multi-task predictions and attention weights
        """

        # Preprocess code into sentences
        code_sentences = self.preprocess_code(code)

        if not code_sentences:
            # Handle empty code case
            return self._get_default_output()

        # Encode sentences with CodeBERT
        sentence_embeddings, attention_masks = self.codebert_encoder(code_sentences)

        # Apply word-level attention to each sentence
        sentence_representations = []
        word_attention_weights = []

        for i in range(len(code_sentences)):
            sent_repr, word_attn = self.word_attention(
                sentence_embeddings[i:i+1], attention_masks[i:i+1]
            )
            sentence_representations.append(sent_repr)
            word_attention_weights.append(word_attn)

        # Stack sentence representations
        if sentence_representations:
            sentence_stack = torch.stack(sentence_representations).squeeze(1)  # [num_sentences, word_attention_dim]
        else:
            sentence_stack = torch.zeros(1, self.config.word_attention_dim)

        # Apply sentence-level attention
        document_representation, sentence_attention_weights = self.sentence_attention(
            sentence_stack.unsqueeze(0)  # Add batch dimension
        )

        # Extract additional features for cross-modal fusion
        ast_features = self.extract_structural_features(code).unsqueeze(0)  # Add batch dimension
        semantic_features = self.extract_semantic_features(code).unsqueeze(0)  # Add batch dimension

        # Cross-modal fusion
        fused_features = self.cross_modal_fusion(
            document_representation, ast_features, semantic_features
        )

        # Multi-task predictions
        outputs = {
            'vulnerability_logits': self.vulnerability_classifier(fused_features),
            'vulnerability_type_logits': self.vulnerability_type_classifier(fused_features),
            'severity_logits': self.severity_classifier(fused_features),
            'confidence_score': self.confidence_predictor(fused_features)
        }

        # Add probability distributions
        outputs['vulnerability_probs'] = F.softmax(outputs['vulnerability_logits'], dim=1)
        outputs['vulnerability_type_probs'] = F.softmax(outputs['vulnerability_type_logits'], dim=1)
        outputs['severity_probs'] = F.softmax(outputs['severity_logits'], dim=1)

        # Store attention weights for interpretability
        self.last_word_attention_weights = word_attention_weights
        self.last_sentence_attention_weights = sentence_attention_weights.squeeze(0) if sentence_attention_weights is not None else None

        # Add attention weights to output
        outputs['attention_weights'] = {
            'word_attention': word_attention_weights,
            'sentence_attention': self.last_sentence_attention_weights,
            'processed_sentences': code_sentences
        }

        return outputs

    def _get_default_output(self) -> Dict[str, torch.Tensor]:
        """Get default output for empty code."""

        return {
            'vulnerability_logits': torch.zeros(1, 2),
            'vulnerability_type_logits': torch.zeros(1, self.config.num_vulnerability_types),
            'severity_logits': torch.zeros(1, self.config.num_severity_levels),
            'confidence_score': torch.zeros(1, 1),
            'vulnerability_probs': torch.tensor([[1.0, 0.0]]),
            'vulnerability_type_probs': torch.zeros(1, self.config.num_vulnerability_types),
            'severity_probs': torch.zeros(1, self.config.num_severity_levels),
            'attention_weights': {
                'word_attention': [],
                'sentence_attention': torch.zeros(1),
                'processed_sentences': []
            }
        }

    def get_attention_analysis(self, code: str) -> Dict[str, Any]:
        """
        Get detailed attention analysis for interpretability.

        Args:
            code: Source code string

        Returns:
            Detailed attention analysis
        """

        # Run forward pass
        outputs = self.forward(code)

        # Extract attention information
        word_attention = outputs['attention_weights']['word_attention']
        sentence_attention = outputs['attention_weights']['sentence_attention']
        processed_sentences = outputs['attention_weights']['processed_sentences']

        analysis = {
            'sentence_importance': [],
            'word_importance': [],
            'vulnerability_focus': {},
            'summary': {}
        }

        # Analyze sentence-level attention
        if sentence_attention is not None and len(processed_sentences) > 0:
            sentence_scores = sentence_attention.cpu().numpy()

            for i, (sentence, score) in enumerate(zip(processed_sentences, sentence_scores)):
                analysis['sentence_importance'].append({
                    'sentence_index': i,
                    'sentence': sentence,
                    'attention_score': float(score),
                    'relative_importance': float(score / max(sentence_scores) if max(sentence_scores) > 0 else 0)
                })

            # Find most important sentences
            top_sentences = sorted(
                analysis['sentence_importance'],
                key=lambda x: x['attention_score'],
                reverse=True
            )[:3]

            analysis['vulnerability_focus'] = {
                'most_suspicious_lines': [sent['sentence'] for sent in top_sentences],
                'attention_distribution': 'focused' if max(sentence_scores) > 0.5 else 'distributed'
            }

        # Summary statistics
        if sentence_attention is not None:
            analysis['summary'] = {
                'total_sentences_processed': len(processed_sentences),
                'attention_entropy': float(-torch.sum(sentence_attention * torch.log(sentence_attention + 1e-8))),
                'max_attention_score': float(torch.max(sentence_attention)) if len(sentence_attention) > 0 else 0.0,
                'attention_variance': float(torch.var(sentence_attention)) if len(sentence_attention) > 0 else 0.0
            }

        return analysis

class HANLoss(nn.Module):
    """Multi-task loss function for Hierarchical Attention Network."""

    def __init__(self, config: HANConfig):
        super().__init__()
        self.config = config

        # Loss weights
        self.vulnerability_weight = 1.0
        self.type_weight = 0.5
        self.severity_weight = 0.4
        self.confidence_weight = 0.3

    def forward(self, outputs: Dict[str, torch.Tensor],
               targets: Dict[str, torch.Tensor]) -> Dict[str, torch.Tensor]:
        """Compute multi-task loss."""

        losses = {}

        # Vulnerability classification loss
        if 'vulnerability_labels' in targets:
            losses['vulnerability_loss'] = F.cross_entropy(
                outputs['vulnerability_logits'],
                targets['vulnerability_labels']
            ) * self.vulnerability_weight

        # Vulnerability type loss
        if 'type_labels' in targets:
            losses['type_loss'] = F.cross_entropy(
                outputs['vulnerability_type_logits'],
                targets['type_labels']
            ) * self.type_weight

        # Severity loss
        if 'severity_labels' in targets:
            losses['severity_loss'] = F.cross_entropy(
                outputs['severity_logits'],
                targets['severity_labels']
            ) * self.severity_weight

        # Confidence loss
        if 'confidence_labels' in targets:
            losses['confidence_loss'] = F.mse_loss(
                outputs['confidence_score'].squeeze(),
                targets['confidence_labels'].float()
            ) * self.confidence_weight

        # Total loss
        losses['total_loss'] = sum(losses.values())

        return losses

def create_han_model(**kwargs) -> HierarchicalAttentionNetwork:
    """Factory function to create HAN model."""

    config = HANConfig(**kwargs)
    model = HierarchicalAttentionNetwork(config)

    return model

# Example usage and testing
if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)

    print("🎯 Testing Hierarchical Attention Networks with CodeBERT")
    print("=" * 65)

    # Create model
    config = HANConfig()
    model = HierarchicalAttentionNetwork(config)

    # Test with complex vulnerable code
    test_code = '''
import os
import subprocess
import pickle
import base64

def process_user_data(user_input, file_path):
    """Process user data with multiple vulnerability patterns."""

    # Command injection vulnerability
    if user_input:
        command = f"grep -r {user_input} /var/log/"
        result = os.system(command)

    # Deserialization vulnerability
    try:
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
            return data
    except FileNotFoundError:
        pass

    # Path traversal vulnerability
    if "../" in file_path:
        full_path = "/tmp/" + file_path
        with open(full_path, 'w') as f:
            f.write("malicious content")

    # SQL injection (simulated)
    query = f"SELECT * FROM users WHERE name = '{user_input}'"

    return result

def safe_function():
    """This function is safe."""
    return "Hello, World!"

class DataProcessor:
    def __init__(self):
        self.data = []

    def add_data(self, item):
        if isinstance(item, str) and len(item) < 100:
            self.data.append(item)

    def get_data(self):
        return self.data.copy()
'''

    print("🔍 Processing complex code with HAN...")
    outputs = model(test_code)

    print(f"\n✅ Hierarchical attention analysis completed:")
    print(f"   • Vulnerability probability: {outputs['vulnerability_probs'][0][1].item():.3f}")
    print(f"   • Confidence score: {outputs['confidence_score'][0][0].item():.3f}")

    # Get top predictions
    type_probs = outputs['vulnerability_type_probs'][0]
    top_type_idx = torch.argmax(type_probs).item()
    print(f"   • Top vulnerability type index: {top_type_idx} (prob: {type_probs[top_type_idx].item():.3f})")

    severity_probs = outputs['severity_probs'][0]
    severity_names = ['Low', 'Medium', 'High', 'Critical']
    top_severity_idx = torch.argmax(severity_probs).item()
    print(f"   • Predicted severity: {severity_names[top_severity_idx]} (prob: {severity_probs[top_severity_idx].item():.3f})")

    # Attention analysis
    print(f"\n🎯 Attention analysis:")
    attention_analysis = model.get_attention_analysis(test_code)

    print(f"   • Sentences processed: {attention_analysis['summary']['total_sentences_processed']}")
    print(f"   • Attention entropy: {attention_analysis['summary']['attention_entropy']:.3f}")
    print(f"   • Max attention score: {attention_analysis['summary']['max_attention_score']:.3f}")

    if attention_analysis['vulnerability_focus']['most_suspicious_lines']:
        print(f"\n🚨 Most suspicious code lines:")
        for i, line in enumerate(attention_analysis['vulnerability_focus']['most_suspicious_lines'][:3]):
            print(f"   {i+1}. {line}")

    print(f"\n🧠 Model architecture:")
    total_params = sum(p.numel() for p in model.parameters())
    print(f"   • Total parameters: {total_params:,}")
    print(f"   • CodeBERT integration: {'✅' if model.codebert_encoder.tokenizer else '❌'}")
    print(f"   • Word attention dim: {config.word_attention_dim}")
    print(f"   • Sentence attention dim: {config.sentence_attention_dim}")
    print(f"   • Document attention dim: {config.document_attention_dim}")
    print(f"   • Multi-head attention: {config.num_attention_heads} heads")
    print(f"   • Cross-modal fusion: ✅")

    print(f"\n🚀 HAN with CodeBERT ready for VulnHunter integration!")