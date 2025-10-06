#!/usr/bin/env python3
"""
Multi-Modal Feature Fusion for Vulnerability Detection
Combines: Code (GNN/BERT), Commit Diffs, Commit Messages, Issue Discussions
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple
import logging

try:
    from transformers import RobertaModel, RobertaTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

try:
    from torch_geometric.nn import GATConv, GCNConv, global_mean_pool, global_max_pool
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DiffEncoder(nn.Module):
    """
    Encode commit diffs using CNN + attention
    Captures code changes and their context
    """

    def __init__(self, vocab_size: int = 50000, embed_dim: int = 128, hidden_dim: int = 256):
        super().__init__()

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)

        # Multi-scale CNN for diff patterns
        self.conv1 = nn.Conv1d(embed_dim, hidden_dim, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(embed_dim, hidden_dim, kernel_size=5, padding=2)
        self.conv3 = nn.Conv1d(embed_dim, hidden_dim, kernel_size=7, padding=3)

        # Attention over diff regions
        self.attention = nn.MultiheadAttention(hidden_dim * 3, num_heads=4)

        # Output projection
        self.fc = nn.Linear(hidden_dim * 3, hidden_dim)

    def forward(self, diff_tokens: torch.Tensor) -> torch.Tensor:
        """
        Args:
            diff_tokens: (batch_size, seq_len) - Tokenized diff

        Returns:
            Diff embedding (batch_size, hidden_dim)
        """
        # Embed tokens
        x = self.embedding(diff_tokens)  # (batch, seq_len, embed_dim)
        x = x.transpose(1, 2)  # (batch, embed_dim, seq_len)

        # Multi-scale convolutions
        c1 = F.relu(self.conv1(x))  # (batch, hidden, seq_len)
        c2 = F.relu(self.conv2(x))
        c3 = F.relu(self.conv3(x))

        # Concatenate multi-scale features
        features = torch.cat([c1, c2, c3], dim=1)  # (batch, hidden*3, seq_len)
        features = features.transpose(1, 2)  # (batch, seq_len, hidden*3)

        # Self-attention
        attn_out, _ = self.attention(features, features, features)

        # Global pooling
        pooled = torch.max(attn_out, dim=1)[0]  # (batch, hidden*3)

        # Project
        output = self.fc(pooled)  # (batch, hidden_dim)

        return output


class CommitMessageEncoder(nn.Module):
    """
    Encode commit messages using BERT
    Captures developer intent and vulnerability descriptions
    """

    def __init__(self, hidden_dim: int = 256, use_pretrained: bool = True):
        super().__init__()

        self.use_pretrained = use_pretrained and TRANSFORMERS_AVAILABLE

        if self.use_pretrained:
            self.bert = RobertaModel.from_pretrained('roberta-base')
            self.projection = nn.Linear(768, hidden_dim)  # RoBERTa hidden = 768
        else:
            # Simple LSTM fallback
            self.embedding = nn.Embedding(50000, 128, padding_idx=0)
            self.lstm = nn.LSTM(128, hidden_dim, num_layers=2, bidirectional=True, batch_first=True)
            self.projection = nn.Linear(hidden_dim * 2, hidden_dim)

    def forward(self, message_tokens: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Args:
            message_tokens: (batch_size, seq_len)
            attention_mask: (batch_size, seq_len)

        Returns:
            Message embedding (batch_size, hidden_dim)
        """
        if self.use_pretrained:
            outputs = self.bert(
                input_ids=message_tokens,
                attention_mask=attention_mask
            )
            pooled = outputs.pooler_output  # (batch, 768)
            embedded = self.projection(pooled)  # (batch, hidden_dim)
        else:
            x = self.embedding(message_tokens)  # (batch, seq_len, 128)
            _, (h_n, _) = self.lstm(x)  # h_n: (4, batch, hidden_dim)
            # Concatenate last forward and backward hidden states
            h_concat = torch.cat([h_n[-2], h_n[-1]], dim=1)  # (batch, hidden_dim*2)
            embedded = self.projection(h_concat)  # (batch, hidden_dim)

        return embedded


class IssueDiscussionEncoder(nn.Module):
    """
    Encode GitHub issue discussions
    Captures community validation and false positive detection
    """

    def __init__(self, hidden_dim: int = 256):
        super().__init__()

        # Process issue title and body
        self.text_encoder = nn.LSTM(128, hidden_dim, num_layers=2, batch_first=True, bidirectional=True)
        self.embedding = nn.Embedding(50000, 128, padding_idx=0)

        # Encode comment threads
        self.comment_encoder = nn.LSTM(hidden_dim * 2, hidden_dim, num_layers=1, batch_first=True)

        # Attention over comments
        self.comment_attention = nn.MultiheadAttention(hidden_dim, num_heads=4)

        # Output
        self.fc = nn.Linear(hidden_dim * 3, hidden_dim)

    def forward(
        self,
        title_tokens: torch.Tensor,
        body_tokens: torch.Tensor,
        comment_tokens: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Args:
            title_tokens: (batch, title_len)
            body_tokens: (batch, body_len)
            comment_tokens: (batch, num_comments, comment_len) - optional

        Returns:
            Issue embedding (batch, hidden_dim)
        """
        # Encode title
        title_emb = self.embedding(title_tokens)
        _, (title_h, _) = self.text_encoder(title_emb)
        title_repr = torch.cat([title_h[-2], title_h[-1]], dim=1)  # (batch, hidden*2)

        # Encode body
        body_emb = self.embedding(body_tokens)
        _, (body_h, _) = self.text_encoder(body_emb)
        body_repr = torch.cat([body_h[-2], body_h[-1]], dim=1)  # (batch, hidden*2)

        # Encode comments if available
        if comment_tokens is not None and comment_tokens.numel() > 0:
            batch_size, num_comments, comment_len = comment_tokens.shape

            # Flatten for processing
            comments_flat = comment_tokens.view(-1, comment_len)
            comments_emb = self.embedding(comments_flat)

            # Encode each comment
            _, (comment_h, _) = self.text_encoder(comments_emb)
            comment_repr = torch.cat([comment_h[-2], comment_h[-1]], dim=1)
            comment_repr = comment_repr.view(batch_size, num_comments, -1)

            # Attention over comments
            comment_attn, _ = self.comment_attention(comment_repr, comment_repr, comment_repr)
            comment_pooled = torch.mean(comment_attn, dim=1)  # (batch, hidden*2)

            # Combine all
            combined = torch.cat([title_repr, body_repr, comment_pooled], dim=1)
        else:
            # No comments - pad with zeros
            comment_pooled = torch.zeros_like(title_repr)
            combined = torch.cat([title_repr, body_repr, comment_pooled], dim=1)

        # Project
        output = self.fc(combined)  # (batch, hidden_dim)

        return output


class MultiModalFusionNetwork(nn.Module):
    """
    Complete multi-modal network for vulnerability detection
    Fuses: Code (GNN/BERT), Diffs, Commit Messages, Issue Discussions
    """

    def __init__(
        self,
        code_input_dim: int = 128,
        hidden_dim: int = 256,
        num_heads: int = 8,
        dropout: float = 0.3,
        use_gnn: bool = True,
        use_code_bert: bool = True,
        use_diff: bool = True,
        use_commit_msg: bool = True,
        use_issues: bool = False
    ):
        super().__init__()

        self.use_gnn = use_gnn and TORCH_GEOMETRIC_AVAILABLE
        self.use_code_bert = use_code_bert and TRANSFORMERS_AVAILABLE
        self.use_diff = use_diff
        self.use_commit_msg = use_commit_msg
        self.use_issues = use_issues

        modality_count = sum([use_gnn, use_code_bert, use_diff, use_commit_msg, use_issues])

        if modality_count == 0:
            raise ValueError("At least one modality must be enabled")

        logger.info(f"Multi-Modal Network initialized with {modality_count} modalities")

        # Code encoders
        if self.use_gnn:
            self.gnn1 = GATConv(code_input_dim, hidden_dim, heads=num_heads, dropout=dropout)
            self.gnn2 = GATConv(hidden_dim * num_heads, hidden_dim, heads=4, dropout=dropout)
            self.gnn3 = GCNConv(hidden_dim * 4, hidden_dim)

        if self.use_code_bert:
            self.code_bert = RobertaModel.from_pretrained('microsoft/codebert-base')
            self.code_bert_proj = nn.Linear(768, hidden_dim)

        # Diff encoder
        if self.use_diff:
            self.diff_encoder = DiffEncoder(hidden_dim=hidden_dim)

        # Commit message encoder
        if self.use_commit_msg:
            self.commit_msg_encoder = CommitMessageEncoder(hidden_dim=hidden_dim)

        # Issue discussion encoder
        if self.use_issues:
            self.issue_encoder = IssueDiscussionEncoder(hidden_dim=hidden_dim)

        # Cross-modal attention
        self.cross_modal_attention = nn.MultiheadAttention(hidden_dim, num_heads=num_heads)

        # Fusion layer
        fusion_input_dim = hidden_dim * modality_count
        self.fusion = nn.Sequential(
            nn.Linear(fusion_input_dim, hidden_dim * 2),
            nn.BatchNorm1d(hidden_dim * 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        # Classifier
        self.classifier = nn.Linear(hidden_dim, 2)

    def forward(
        self,
        code_graph_x: Optional[torch.Tensor] = None,
        code_graph_edge_index: Optional[torch.Tensor] = None,
        code_graph_batch: Optional[torch.Tensor] = None,
        code_tokens: Optional[torch.Tensor] = None,
        code_attention_mask: Optional[torch.Tensor] = None,
        diff_tokens: Optional[torch.Tensor] = None,
        commit_msg_tokens: Optional[torch.Tensor] = None,
        commit_msg_mask: Optional[torch.Tensor] = None,
        issue_title_tokens: Optional[torch.Tensor] = None,
        issue_body_tokens: Optional[torch.Tensor] = None,
        issue_comment_tokens: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Forward pass with multi-modal inputs

        Returns:
            Logits (batch_size, 2)
        """
        modality_embeddings = []

        # 1. GNN-based code encoding
        if self.use_gnn and code_graph_x is not None:
            h1 = F.elu(self.gnn1(code_graph_x, code_graph_edge_index))
            h2 = F.elu(self.gnn2(h1, code_graph_edge_index))
            h3 = F.elu(self.gnn3(h2, code_graph_edge_index))

            # Global pooling
            h_mean = global_mean_pool(h3, code_graph_batch)
            h_max = global_max_pool(h3, code_graph_batch)
            gnn_embedding = (h_mean + h_max) / 2

            modality_embeddings.append(gnn_embedding)

        # 2. CodeBERT encoding
        if self.use_code_bert and code_tokens is not None:
            bert_outputs = self.code_bert(
                input_ids=code_tokens,
                attention_mask=code_attention_mask
            )
            code_bert_embedding = self.code_bert_proj(bert_outputs.pooler_output)
            modality_embeddings.append(code_bert_embedding)

        # 3. Diff encoding
        if self.use_diff and diff_tokens is not None:
            diff_embedding = self.diff_encoder(diff_tokens)
            modality_embeddings.append(diff_embedding)

        # 4. Commit message encoding
        if self.use_commit_msg and commit_msg_tokens is not None:
            commit_embedding = self.commit_msg_encoder(commit_msg_tokens, commit_msg_mask)
            modality_embeddings.append(commit_embedding)

        # 5. Issue discussion encoding
        if self.use_issues and issue_title_tokens is not None:
            issue_embedding = self.issue_encoder(
                issue_title_tokens,
                issue_body_tokens,
                issue_comment_tokens
            )
            modality_embeddings.append(issue_embedding)

        # Stack modalities
        if not modality_embeddings:
            raise ValueError("No modality embeddings computed")

        # Cross-modal attention
        stacked = torch.stack(modality_embeddings, dim=0)  # (num_modalities, batch, hidden)
        attended, _ = self.cross_modal_attention(stacked, stacked, stacked)

        # Concatenate all modalities
        fused_input = torch.cat([attended[i] for i in range(attended.shape[0])], dim=1)

        # Fusion
        fused = self.fusion(fused_input)

        # Classification
        logits = self.classifier(fused)

        return logits


if __name__ == "__main__":
    # Test multi-modal network
    logger.info("Testing Multi-Modal Fusion Network...")

    model = MultiModalFusionNetwork(
        code_input_dim=128,
        hidden_dim=256,
        use_gnn=False,  # Disable GNN for simple test
        use_code_bert=False,
        use_diff=True,
        use_commit_msg=True,
        use_issues=False
    )

    # Dummy inputs
    batch_size = 4
    diff_tokens = torch.randint(0, 50000, (batch_size, 100))
    commit_msg_tokens = torch.randint(0, 50000, (batch_size, 50))
    commit_msg_mask = torch.ones(batch_size, 50)

    # Forward pass
    logits = model(
        diff_tokens=diff_tokens,
        commit_msg_tokens=commit_msg_tokens,
        commit_msg_mask=commit_msg_mask
    )

    logger.info(f"Output shape: {logits.shape}")
    logger.info("✅ Multi-modal network test passed!")
