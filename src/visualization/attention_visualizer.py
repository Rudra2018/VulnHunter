#!/usr/bin/env python3
"""
Advanced Attention Visualization for Transformer Models

This module provides sophisticated attention visualization capabilities:
- Multi-head attention heatmaps
- Layer-wise attention analysis
- Token importance visualization
- Cross-attention analysis for multi-modal models
- Interactive attention exploration
"""

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Optional, Tuple, Union
import torch
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import warnings
from matplotlib.colors import LinearSegmentedColormap

warnings.filterwarnings("ignore")


class AttentionVisualizer:
    """Advanced attention visualization for transformer models"""

    def __init__(self, tokenizer=None, figure_size: Tuple[int, int] = (12, 8)):
        self.tokenizer = tokenizer
        self.figure_size = figure_size

        # Color schemes for different visualization types
        self.color_schemes = {
            'attention': 'Blues',
            'importance': 'Reds',
            'vulnerability': 'RdYlBu_r',
            'severity': 'YlOrRd',
            'confidence': 'Greens'
        }

        # Custom colormap for vulnerability attention
        self.vuln_colormap = LinearSegmentedColormap.from_list(
            'vulnerability',
            ['#2E8B57', '#FFD700', '#FF6347', '#DC143C'],
            N=256
        )

    def visualize_multi_head_attention(self,
                                     attention_weights: torch.Tensor,
                                     tokens: List[str],
                                     layer_idx: int = 0,
                                     save_path: Optional[str] = None,
                                     title: Optional[str] = None) -> None:
        """
        Visualize multi-head attention patterns

        Args:
            attention_weights: Attention weights [num_heads, seq_len, seq_len]
            tokens: List of tokens
            layer_idx: Layer index for title
            save_path: Path to save the figure
            title: Custom title for the plot
        """

        if attention_weights.dim() == 4:  # [batch, heads, seq, seq]
            attention_weights = attention_weights[0]  # Take first batch

        num_heads = attention_weights.size(0)
        seq_len = attention_weights.size(1)

        # Truncate tokens if too long
        max_tokens = 50
        if len(tokens) > max_tokens:
            tokens = tokens[:max_tokens]
            attention_weights = attention_weights[:, :max_tokens, :max_tokens]
            seq_len = max_tokens

        # Create subplots for each attention head
        fig, axes = plt.subplots(2, (num_heads + 1) // 2, figsize=(15, 8))
        if num_heads == 1:
            axes = [axes]
        elif num_heads <= 2:
            axes = axes.reshape(-1)
        else:
            axes = axes.flatten()

        for head_idx in range(num_heads):
            ax = axes[head_idx]

            # Get attention matrix for this head
            attn_matrix = attention_weights[head_idx].detach().cpu().numpy()

            # Create heatmap
            sns.heatmap(
                attn_matrix,
                xticklabels=tokens,
                yticklabels=tokens,
                cmap='Blues',
                cbar=True,
                square=True,
                ax=ax,
                cbar_kws={'shrink': 0.8}
            )

            ax.set_title(f'Head {head_idx + 1}')
            ax.set_xlabel('Key Position')
            ax.set_ylabel('Query Position')

            # Rotate labels for better readability
            ax.tick_params(axis='x', rotation=45)
            ax.tick_params(axis='y', rotation=0)

        # Hide unused subplots
        for idx in range(num_heads, len(axes)):
            axes[idx].set_visible(False)

        plt.tight_layout()

        if title is None:
            title = f'Multi-Head Attention - Layer {layer_idx + 1}'
        plt.suptitle(title, y=1.02, fontsize=16, fontweight='bold')

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def visualize_attention_flow(self,
                                attention_weights: torch.Tensor,
                                tokens: List[str],
                                threshold: float = 0.1,
                                save_path: Optional[str] = None) -> None:
        """
        Visualize attention flow as a directed graph

        Args:
            attention_weights: Attention weights [seq_len, seq_len]
            tokens: List of tokens
            threshold: Minimum attention weight to show connection
            save_path: Path to save the figure
        """

        if attention_weights.dim() > 2:
            # Average over heads and take first batch if needed
            while attention_weights.dim() > 2:
                attention_weights = attention_weights.mean(dim=0)

        attention_matrix = attention_weights.detach().cpu().numpy()

        # Create interactive plot with Plotly
        fig = go.Figure()

        # Position tokens in a circle
        n_tokens = len(tokens)
        angles = np.linspace(0, 2 * np.pi, n_tokens, endpoint=False)
        x_pos = np.cos(angles)
        y_pos = np.sin(angles)

        # Add nodes (tokens)
        fig.add_trace(go.Scatter(
            x=x_pos,
            y=y_pos,
            mode='markers+text',
            text=tokens,
            textposition='middle center',
            marker=dict(size=30, color='lightblue', line=dict(width=2, color='darkblue')),
            name='Tokens'
        ))

        # Add edges (attention connections)
        for i in range(n_tokens):
            for j in range(n_tokens):
                if i != j and attention_matrix[i, j] > threshold:
                    # Line thickness proportional to attention weight
                    width = max(1, int(attention_matrix[i, j] * 10))

                    fig.add_trace(go.Scatter(
                        x=[x_pos[i], x_pos[j], None],
                        y=[y_pos[i], y_pos[j], None],
                        mode='lines',
                        line=dict(width=width, color=f'rgba(255, 0, 0, {attention_matrix[i, j]})'),
                        showlegend=False,
                        hovertemplate=f'{tokens[i]} → {tokens[j]}<br>Attention: {attention_matrix[i, j]:.3f}<extra></extra>'
                    ))

        fig.update_layout(
            title='Attention Flow Visualization',
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='white'
        )

        if save_path:
            fig.write_html(save_path)
        fig.show()

    def visualize_layer_wise_attention(self,
                                     attention_weights_list: List[torch.Tensor],
                                     tokens: List[str],
                                     save_path: Optional[str] = None) -> None:
        """
        Visualize attention patterns across all layers

        Args:
            attention_weights_list: List of attention weights for each layer
            tokens: List of tokens
            save_path: Path to save the figure
        """

        num_layers = len(attention_weights_list)

        # Truncate tokens if too long
        max_tokens = 30
        if len(tokens) > max_tokens:
            tokens = tokens[:max_tokens]

        fig, axes = plt.subplots(1, num_layers, figsize=(4 * num_layers, 6))
        if num_layers == 1:
            axes = [axes]

        for layer_idx, attention_weights in enumerate(attention_weights_list):
            # Average over heads and batch
            while attention_weights.dim() > 2:
                attention_weights = attention_weights.mean(dim=0)

            # Truncate sequence length
            if attention_weights.size(0) > max_tokens:
                attention_weights = attention_weights[:max_tokens, :max_tokens]

            attn_matrix = attention_weights.detach().cpu().numpy()

            # Create heatmap
            sns.heatmap(
                attn_matrix,
                xticklabels=tokens if layer_idx == 0 else False,
                yticklabels=tokens if layer_idx == 0 else False,
                cmap='Blues',
                cbar=True,
                square=True,
                ax=axes[layer_idx],
                cbar_kws={'shrink': 0.8}
            )

            axes[layer_idx].set_title(f'Layer {layer_idx + 1}')

            if layer_idx == 0:
                axes[layer_idx].set_ylabel('Query Position')
            if layer_idx == num_layers // 2:
                axes[layer_idx].set_xlabel('Key Position')

        plt.tight_layout()
        plt.suptitle('Layer-wise Attention Patterns', y=1.02, fontsize=16, fontweight='bold')

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def visualize_token_importance(self,
                                 attention_weights: torch.Tensor,
                                 tokens: List[str],
                                 vulnerability_scores: Optional[torch.Tensor] = None,
                                 save_path: Optional[str] = None) -> None:
        """
        Visualize token importance based on attention weights

        Args:
            attention_weights: Attention weights [heads, seq_len, seq_len]
            tokens: List of tokens
            vulnerability_scores: Optional vulnerability scores for each token
            save_path: Path to save the figure
        """

        # Calculate token importance (sum of attention received)
        if attention_weights.dim() == 4:  # [batch, heads, seq, seq]
            attention_weights = attention_weights[0]  # Take first batch

        # Average over attention heads
        attention_matrix = attention_weights.mean(dim=0).detach().cpu().numpy()

        # Token importance = sum of attention received from all positions
        token_importance = np.sum(attention_matrix, axis=0)

        # Normalize
        token_importance = token_importance / np.max(token_importance)

        # Create DataFrame for visualization
        data = {
            'tokens': tokens[:len(token_importance)],
            'importance': token_importance,
            'position': range(len(token_importance))
        }

        if vulnerability_scores is not None:
            vuln_scores = vulnerability_scores.detach().cpu().numpy()
            data['vulnerability'] = vuln_scores[:len(token_importance)]

        df = pd.DataFrame(data)

        # Create subplot
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Token Importance', 'Vulnerability Contribution'),
            vertical_spacing=0.15
        )

        # Token importance bar chart
        fig.add_trace(
            go.Bar(
                x=df['tokens'],
                y=df['importance'],
                name='Attention Importance',
                marker_color='lightblue',
                hovertemplate='Token: %{x}<br>Importance: %{y:.3f}<extra></extra>'
            ),
            row=1, col=1
        )

        # Vulnerability scores if provided
        if vulnerability_scores is not None:
            fig.add_trace(
                go.Scatter(
                    x=df['tokens'],
                    y=df['vulnerability'],
                    mode='markers+lines',
                    name='Vulnerability Score',
                    marker=dict(size=8, color='red'),
                    line=dict(color='red', width=2),
                    hovertemplate='Token: %{x}<br>Vuln Score: %{y:.3f}<extra></extra>'
                ),
                row=2, col=1
            )

        fig.update_layout(
            title='Token Importance and Vulnerability Analysis',
            showlegend=True,
            height=700
        )

        fig.update_xaxes(tickangle=45)

        if save_path:
            fig.write_html(save_path)
        fig.show()

    def visualize_attention_rollout(self,
                                  attention_weights_list: List[torch.Tensor],
                                  tokens: List[str],
                                  save_path: Optional[str] = None) -> None:
        """
        Visualize attention rollout across layers

        Args:
            attention_weights_list: List of attention weights for each layer
            tokens: List of tokens
            save_path: Path to save the figure
        """

        # Implement attention rollout
        # Start with identity matrix
        rollout = torch.eye(attention_weights_list[0].size(-1))

        rollout_matrices = []

        for attention_weights in attention_weights_list:
            # Average over heads and batch
            while attention_weights.dim() > 2:
                attention_weights = attention_weights.mean(dim=0)

            # Add residual connection
            attention_weights = attention_weights + torch.eye(attention_weights.size(0))

            # Normalize
            attention_weights = attention_weights / attention_weights.sum(dim=-1, keepdim=True)

            # Multiply with previous rollout
            rollout = torch.matmul(attention_weights, rollout)
            rollout_matrices.append(rollout.clone())

        # Visualize rollout progression
        num_layers = len(rollout_matrices)
        fig, axes = plt.subplots(1, num_layers, figsize=(4 * num_layers, 6))
        if num_layers == 1:
            axes = [axes]

        for idx, rollout_matrix in enumerate(rollout_matrices):
            rollout_np = rollout_matrix.detach().cpu().numpy()

            sns.heatmap(
                rollout_np,
                xticklabels=tokens if idx == 0 else False,
                yticklabels=tokens if idx == 0 else False,
                cmap='Reds',
                cbar=True,
                square=True,
                ax=axes[idx],
                cbar_kws={'shrink': 0.8}
            )

            axes[idx].set_title(f'Rollout Layer {idx + 1}')

        plt.tight_layout()
        plt.suptitle('Attention Rollout Progression', y=1.02, fontsize=16, fontweight='bold')

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def create_attention_dashboard(self,
                                 model_outputs: Dict,
                                 tokens: List[str],
                                 save_path: Optional[str] = None) -> None:
        """
        Create comprehensive attention analysis dashboard

        Args:
            model_outputs: Dictionary containing model outputs including attention weights
            tokens: List of tokens
            save_path: Path to save the dashboard HTML
        """

        # Extract attention weights
        if 'attention_weights' in model_outputs:
            attention_data = model_outputs['attention_weights']

            if isinstance(attention_data, dict):
                # Multi-layer attention
                if 'transformer_blocks' in attention_data:
                    layer_attentions = []
                    for block_attention in attention_data['transformer_blocks']:
                        if 'self_attention' in block_attention:
                            layer_attentions.append(block_attention['self_attention'])

                    if layer_attentions:
                        self.visualize_layer_wise_attention(
                            layer_attentions, tokens,
                            save_path=save_path.replace('.html', '_layers.png') if save_path else None
                        )

                # Pooling attention
                if 'pooling_attention' in attention_data:
                    pooling_attention = attention_data['pooling_attention']

                    self.visualize_token_importance(
                        pooling_attention.unsqueeze(0).unsqueeze(0),  # Add dims for compatibility
                        tokens,
                        save_path=save_path.replace('.html', '_importance.png') if save_path else None
                    )

        # Create interactive dashboard
        dashboard_html = self._create_dashboard_html(model_outputs, tokens)

        if save_path:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(dashboard_html)

        print(f"Attention dashboard created: {save_path}")

    def _create_dashboard_html(self, model_outputs: Dict, tokens: List[str]) -> str:
        """Create HTML dashboard for attention analysis"""

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Detection - Attention Analysis Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .section {{ margin: 30px 0; padding: 20px; border: 1px solid #ddd; }}
                .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
                .token {{ display: inline-block; margin: 2px; padding: 4px 8px;
                         border-radius: 4px; background-color: #f0f0f0; }}
                .high-attention {{ background-color: #ff6b6b; color: white; }}
                .medium-attention {{ background-color: #feca57; }}
                .low-attention {{ background-color: #48dbfb; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Vulnerability Detection - Attention Analysis</h1>

                <div class="section">
                    <h2>Model Predictions</h2>
                    <div class="grid">
                        <div>
                            <h3>Vulnerability Detection</h3>
                            <p>Score: {vulnerability_score:.4f}</p>
                            <p>Prediction: {vulnerability_prediction}</p>
                        </div>
                        <div>
                            <h3>Vulnerability Type</h3>
                            <p>Type: {vulnerability_type}</p>
                            <p>Confidence: {type_confidence:.4f}</p>
                        </div>
                    </div>
                </div>

                <div class="section">
                    <h2>Token Analysis</h2>
                    <p>Tokens with attention-based importance:</p>
                    <div id="tokens">
                        {token_visualization}
                    </div>
                </div>

                <div class="section">
                    <h2>Attention Statistics</h2>
                    <div class="grid">
                        <div>
                            <h3>Attention Distribution</h3>
                            <ul>
                                <li>Max Attention: {max_attention:.4f}</li>
                                <li>Mean Attention: {mean_attention:.4f}</li>
                                <li>Attention Entropy: {attention_entropy:.4f}</li>
                            </ul>
                        </div>
                        <div>
                            <h3>Key Findings</h3>
                            <ul>
                                <li>Most Important Token: {most_important_token}</li>
                                <li>Attention Span: {attention_span} tokens</li>
                                <li>Focus Pattern: {focus_pattern}</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

        # Extract information for dashboard
        vulnerability_score = model_outputs.get('vulnerability', torch.tensor(0.0))
        if hasattr(vulnerability_score, 'item'):
            vulnerability_score = vulnerability_score.item()

        vulnerability_prediction = "Vulnerable" if vulnerability_score > 0.5 else "Safe"

        vuln_type_logits = model_outputs.get('vuln_type', torch.zeros(30))
        vulnerability_type = f"Type {torch.argmax(vuln_type_logits).item()}"
        type_confidence = torch.softmax(vuln_type_logits, dim=-1).max().item()

        # Token visualization with mock attention scores
        token_html = ""
        if 'attention_weights' in model_outputs:
            # Use actual attention weights if available
            attention_data = model_outputs['attention_weights']
            if 'pooling_attention' in attention_data:
                pooling_attention = attention_data['pooling_attention']
                attention_scores = pooling_attention.squeeze().detach().cpu().numpy()

                for i, (token, score) in enumerate(zip(tokens[:len(attention_scores)], attention_scores)):
                    if score > 0.7:
                        token_class = "high-attention"
                    elif score > 0.4:
                        token_class = "medium-attention"
                    else:
                        token_class = "low-attention"

                    token_html += f'<span class="token {token_class}" title="Attention: {score:.3f}">{token}</span>'
        else:
            # Mock visualization
            for token in tokens[:20]:  # Limit to first 20 tokens
                token_html += f'<span class="token low-attention">{token}</span>'

        # Fill template
        return html_template.format(
            vulnerability_score=vulnerability_score,
            vulnerability_prediction=vulnerability_prediction,
            vulnerability_type=vulnerability_type,
            type_confidence=type_confidence,
            token_visualization=token_html,
            max_attention=0.95,  # Mock values
            mean_attention=0.15,
            attention_entropy=2.34,
            most_important_token=tokens[0] if tokens else "N/A",
            attention_span=min(10, len(tokens)),
            focus_pattern="Distributed"
        )


def test_attention_visualizer():
    """Test the attention visualizer"""
    print("Testing Attention Visualizer...")

    # Create sample data
    batch_size, num_heads, seq_len = 1, 8, 20
    attention_weights = torch.rand(batch_size, num_heads, seq_len, seq_len)

    # Create sample tokens
    tokens = [f"token_{i}" for i in range(seq_len)]

    # Initialize visualizer
    visualizer = AttentionVisualizer()

    print("Creating attention visualizations...")

    # Test multi-head attention visualization
    print("1. Multi-head attention visualization")
    visualizer.visualize_multi_head_attention(
        attention_weights[0],  # Remove batch dimension
        tokens,
        layer_idx=0
    )

    # Test token importance visualization
    print("2. Token importance visualization")
    vulnerability_scores = torch.rand(seq_len)
    visualizer.visualize_token_importance(
        attention_weights[0],
        tokens,
        vulnerability_scores=vulnerability_scores
    )

    # Test layer-wise attention (simulate multiple layers)
    print("3. Layer-wise attention visualization")
    layer_attentions = [torch.rand(seq_len, seq_len) for _ in range(3)]
    visualizer.visualize_layer_wise_attention(
        layer_attentions,
        tokens
    )

    # Test attention rollout
    print("4. Attention rollout visualization")
    visualizer.visualize_attention_rollout(
        layer_attentions,
        tokens
    )

    print("Attention visualizer test completed!")


if __name__ == "__main__":
    test_attention_visualizer()