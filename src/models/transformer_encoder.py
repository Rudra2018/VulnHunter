"""
VulnHunter PoC: Transformer Encoder
Advanced transformer models for code semantic understanding using CodeBERT
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel, AutoConfig
from typing import Dict, List, Optional, Tuple
import re
import numpy as np

class TransformerEncoder(nn.Module):
    """
    Advanced Transformer encoder for code vulnerability detection
    Uses pre-trained CodeBERT with domain-specific fine-tuning
    """

    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        max_length: int = 512,
        hidden_dim: int = 768,
        output_dim: int = 256,
        dropout: float = 0.1,
        freeze_base: bool = False
    ):
        super(TransformerEncoder, self).__init__()

        self.model_name = model_name
        self.max_length = max_length
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim

        # Load pre-trained model and tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.config = AutoConfig.from_pretrained(model_name)
        self.transformer = AutoModel.from_pretrained(model_name)

        # Freeze base model if specified
        if freeze_base:
            for param in self.transformer.parameters():
                param.requires_grad = False

        # Add special tokens for vulnerability patterns
        special_tokens = {
            "additional_special_tokens": [
                "[SQL_INJECT]", "[CMD_INJECT]", "[PATH_TRAV]", "[XSS]",
                "[VULN_START]", "[VULN_END]", "[SAFE_START]", "[SAFE_END]"
            ]
        }
        self.tokenizer.add_special_tokens(special_tokens)
        self.transformer.resize_token_embeddings(len(self.tokenizer))

        # Code preprocessing patterns
        self.vulnerability_markers = {
            'sql_injection': [
                (r'(execute\s*\(\s*["\'][^"\']*)\+([^"\']*["\'])', r'\1[SQL_INJECT]\2'),
                (r'(query\s*=\s*["\'][^"\']*)\+([^"\']*)', r'\1[SQL_INJECT]\2'),
                (r'(SELECT.*FROM.*WHERE.*)\+', r'[SQL_INJECT]\1')
            ],
            'command_injection': [
                (r'(os\.system\s*\(["\'][^"\']*)\+', r'[CMD_INJECT]\1'),
                (r'(subprocess\.(call|run|Popen)[^+]*)\+', r'[CMD_INJECT]\1')
            ],
            'path_traversal': [
                (r'(open\s*\(["\'][^"\']*)\+', r'[PATH_TRAV]\1'),
                (r'(\.\./[^+]*)\+', r'[PATH_TRAV]\1')
            ],
            'xss': [
                (r'(innerHTML\s*=.*)\+', r'[XSS]\1'),
                (r'(document\.write\s*\([^+]*)\+', r'[XSS]\1')
            ]
        }

        # Domain-specific attention heads
        self.vulnerability_attention = MultiHeadVulnerabilityAttention(
            hidden_dim, num_heads=8, dropout=dropout
        )

        # Output projection layers
        self.output_projection = nn.Sequential(
            nn.Linear(hidden_dim, output_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(output_dim * 2, output_dim),
            nn.LayerNorm(output_dim)
        )

        # Vulnerability-specific classifiers
        self.vulnerability_classifiers = nn.ModuleDict({
            'sql_injection': nn.Linear(output_dim, 1),
            'command_injection': nn.Linear(output_dim, 1),
            'path_traversal': nn.Linear(output_dim, 1),
            'xss': nn.Linear(output_dim, 1)
        })

        # Confidence estimation
        self.confidence_estimator = nn.Sequential(
            nn.Linear(output_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

    def preprocess_code(self, code: str) -> str:
        """
        Preprocess code to highlight vulnerability patterns

        Args:
            code: Raw Python code string

        Returns:
            Preprocessed code with vulnerability markers
        """
        processed = code

        # Add vulnerability markers
        for vuln_type, patterns in self.vulnerability_markers.items():
            for pattern, replacement in patterns:
                processed = re.sub(pattern, replacement, processed, flags=re.IGNORECASE)

        # Normalize whitespace and remove excessive newlines
        processed = re.sub(r'\n\s*\n\s*\n', '\n\n', processed)
        processed = re.sub(r'[ \t]+', ' ', processed)

        # Truncate if too long (preserve important parts)
        if len(processed) > self.max_length * 4:  # Rough estimate before tokenization
            lines = processed.split('\n')
            if len(lines) > 50:
                # Keep first and last 25 lines, summarize middle
                processed = '\n'.join(lines[:25] + ['# ... [TRUNCATED] ...'] + lines[-25:])

        return processed

    def encode_code(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Encode code using the transformer

        Args:
            code: Python code string

        Returns:
            Dictionary with encoded representations
        """
        # Preprocess code
        processed_code = self.preprocess_code(code)

        # Tokenize
        inputs = self.tokenizer(
            processed_code,
            return_tensors="pt",
            max_length=self.max_length,
            truncation=True,
            padding=True,
            return_attention_mask=True
        )

        # Move to same device as model
        device = next(self.transformer.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}

        # Get transformer outputs
        with torch.no_grad() if not self.training else torch.enable_grad():
            outputs = self.transformer(**inputs)

        # Extract features
        sequence_output = outputs.last_hidden_state  # [batch_size, seq_len, hidden_dim]
        pooled_output = outputs.pooler_output if hasattr(outputs, 'pooler_output') else None

        # Apply domain-specific attention
        attended_output = self.vulnerability_attention(
            sequence_output, inputs['attention_mask']
        )

        # Create multiple representations
        representations = {
            'sequence': sequence_output,
            'pooled': pooled_output,
            'attended': attended_output,
            'mean_pooled': self._mean_pool(sequence_output, inputs['attention_mask']),
            'max_pooled': self._max_pool(sequence_output, inputs['attention_mask']),
            'cls_token': sequence_output[:, 0, :] if sequence_output.size(1) > 0 else torch.zeros(1, self.hidden_dim).to(device)
        }

        return representations

    def forward(self, code: str) -> Tuple[torch.Tensor, Dict[str, torch.Tensor], torch.Tensor]:
        """
        Forward pass through transformer encoder

        Args:
            code: Python code string

        Returns:
            Tuple of (main_embedding, vulnerability_predictions, confidence)
        """
        # Encode code
        representations = self.encode_code(code)

        # Combine representations
        combined_repr = torch.cat([
            representations['cls_token'],
            representations['mean_pooled'],
            representations['attended']
        ], dim=-1)

        # Project to output dimension
        main_embedding = self.output_projection(combined_repr)

        # Vulnerability-specific predictions
        vulnerability_predictions = {}
        for vuln_type, classifier in self.vulnerability_classifiers.items():
            vulnerability_predictions[vuln_type] = torch.sigmoid(classifier(main_embedding))

        # Confidence estimation
        confidence = self.confidence_estimator(main_embedding)

        return main_embedding, vulnerability_predictions, confidence

    def _mean_pool(self, hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Mean pooling with attention mask"""
        mask_expanded = attention_mask.unsqueeze(-1).expand(hidden_states.size()).float()
        sum_embeddings = torch.sum(hidden_states * mask_expanded, dim=1)
        sum_mask = torch.clamp(mask_expanded.sum(dim=1), min=1e-9)
        return sum_embeddings / sum_mask

    def _max_pool(self, hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Max pooling with attention mask"""
        mask_expanded = attention_mask.unsqueeze(-1).expand(hidden_states.size()).float()
        hidden_states = hidden_states.clone()
        hidden_states[mask_expanded == 0] = -1e9
        return torch.max(hidden_states, dim=1)[0]

class MultiHeadVulnerabilityAttention(nn.Module):
    """
    Multi-head attention specialized for vulnerability pattern detection
    """

    def __init__(self, hidden_dim: int, num_heads: int = 8, dropout: float = 0.1):
        super(MultiHeadVulnerabilityAttention, self).__init__()

        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads

        assert self.head_dim * num_heads == hidden_dim, "hidden_dim must be divisible by num_heads"

        self.q_proj = nn.Linear(hidden_dim, hidden_dim)
        self.k_proj = nn.Linear(hidden_dim, hidden_dim)
        self.v_proj = nn.Linear(hidden_dim, hidden_dim)
        self.out_proj = nn.Linear(hidden_dim, hidden_dim)

        self.dropout = nn.Dropout(dropout)
        self.scale = self.head_dim ** -0.5

        # Vulnerability pattern embeddings
        self.pattern_embeddings = nn.Parameter(torch.randn(4, hidden_dim))  # 4 vuln types

    def forward(self, hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """
        Apply vulnerability-aware attention

        Args:
            hidden_states: [batch_size, seq_len, hidden_dim]
            attention_mask: [batch_size, seq_len]

        Returns:
            Attended hidden states
        """
        batch_size, seq_len, _ = hidden_states.size()

        # Project to query, key, value
        queries = self.q_proj(hidden_states)
        keys = self.k_proj(hidden_states)
        values = self.v_proj(hidden_states)

        # Reshape for multi-head attention
        queries = queries.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        keys = keys.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        values = values.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)

        # Compute attention scores
        attention_scores = torch.matmul(queries, keys.transpose(-2, -1)) * self.scale

        # Apply attention mask
        if attention_mask is not None:
            mask_expanded = attention_mask.unsqueeze(1).unsqueeze(1).expand(
                batch_size, self.num_heads, seq_len, seq_len
            )
            attention_scores = attention_scores.masked_fill(mask_expanded == 0, -1e9)

        # Apply softmax
        attention_weights = F.softmax(attention_scores, dim=-1)
        attention_weights = self.dropout(attention_weights)

        # Apply attention to values
        attended_values = torch.matmul(attention_weights, values)

        # Reshape and project
        attended_values = attended_values.transpose(1, 2).contiguous().view(
            batch_size, seq_len, self.hidden_dim
        )

        output = self.out_proj(attended_values)

        # Global pooling for sequence representation
        if attention_mask is not None:
            mask_expanded = attention_mask.unsqueeze(-1).expand(output.size()).float()
            pooled_output = torch.sum(output * mask_expanded, dim=1) / torch.clamp(
                mask_expanded.sum(dim=1), min=1e-9
            )
        else:
            pooled_output = output.mean(dim=1)

        return pooled_output

class CodeSecurityAnalyzer(nn.Module):
    """
    Complete code security analyzer using transformer
    """

    def __init__(self, model_name: str = "microsoft/codebert-base"):
        super(CodeSecurityAnalyzer, self).__init__()

        self.encoder = TransformerEncoder(model_name=model_name)

        # Security metrics predictor
        self.security_predictor = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 5)  # Overall security score + 4 vuln types
        )

    def analyze_code(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Comprehensive code security analysis

        Args:
            code: Python code to analyze

        Returns:
            Dictionary with security analysis results
        """
        # Get transformer encoding
        main_embedding, vuln_predictions, confidence = self.encoder(code)

        # Overall security prediction
        security_scores = torch.sigmoid(self.security_predictor(main_embedding))

        # Compile results
        results = {
            'overall_security': security_scores[:, 0],
            'vulnerability_predictions': vuln_predictions,
            'confidence': confidence.squeeze(),
            'embedding': main_embedding,
            'detailed_scores': {
                'sql_injection': security_scores[:, 1],
                'command_injection': security_scores[:, 2],
                'path_traversal': security_scores[:, 3],
                'xss': security_scores[:, 4]
            }
        }

        return results

def test_transformer_encoder():
    """Test the transformer encoder"""
    print("=== Testing Transformer Encoder ===")

    # Create encoder
    encoder = TransformerEncoder()

    # Test codes
    test_codes = [
        # Vulnerable SQL injection
        '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
''',
        # Safe parameterized query
        '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
''',
        # Command injection
        '''
import os
def backup_file(filename):
    os.system("cp " + filename + " /backup/")
'''
    ]

    analyzer = CodeSecurityAnalyzer()

    for i, code in enumerate(test_codes):
        print(f"\n--- Test {i+1} ---")
        print(f"Code preview: {code[:50]}...")

        try:
            with torch.no_grad():
                results = analyzer.analyze_code(code)

            print(f"Overall security: {results['overall_security'].item():.3f}")
            print(f"Confidence: {results['confidence'].item():.3f}")
            print("Vulnerability predictions:")
            for vuln_type, score in results['vulnerability_predictions'].items():
                print(f"  {vuln_type}: {score.item():.3f}")

        except Exception as e:
            print(f"Error: {e}")

    print(f"\nModel parameters: {sum(p.numel() for p in analyzer.parameters()):,}")

if __name__ == "__main__":
    test_transformer_encoder()