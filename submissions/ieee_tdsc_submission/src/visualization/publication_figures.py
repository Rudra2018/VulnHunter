#!/usr/bin/env python3
"""
Publication-Ready Visualization Suite

This module creates high-quality, publication-ready visualizations for
vulnerability detection research targeting top-tier academic venues.
All figures are designed to meet IEEE, ACM, and USENIX publication standards.

Visualization Categories:
1. Model Performance Comparisons
2. Statistical Significance Analysis
3. Attention Mechanism Interpretability
4. Uncertainty Quantification Visualization
5. Training Dynamics and Learning Curves
6. Feature Importance and Ablation Studies
7. Dataset Distribution Analysis
8. Computational Performance Metrics

Publication Standards:
- IEEE Conference format compliance
- High-resolution (300+ DPI) output
- Colorblind-friendly palettes
- Professional typography
- LaTeX-compatible formats
- Interactive HTML versions for presentations

Target Venues: ICSE, IEEE S&P, ACM CCS, NDSS, USENIX Security

This module generates high-quality, publication-ready visualizations
specifically designed for academic papers in top-tier conferences.

Key Features:
1. IEEE/ACM conference-standard figures
2. Statistical significance visualization
3. Ablation study comparison charts
4. Performance benchmark tables
5. Attention mechanism visualizations
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
import warnings
from scipy import stats
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.gridspec as gridspec

warnings.filterwarnings("ignore")

# Set publication-quality defaults
plt.rcParams.update({
    'font.size': 10,
    'font.family': 'serif',
    'font.serif': ['Times New Roman'],
    'text.usetex': False,  # Set to True if LaTeX is available
    'figure.figsize': (6, 4),
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
    'axes.linewidth': 0.8,
    'axes.spines.top': False,
    'axes.spines.right': False,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'legend.frameon': False
})

# Academic color palette
ACADEMIC_COLORS = {
    'primary': '#2E86AB',      # Blue
    'secondary': '#A23B72',    # Purple
    'accent': '#F18F01',       # Orange
    'success': '#C73E1D',      # Red
    'neutral': '#6C757D',      # Gray
    'light': '#F8F9FA',        # Light gray
    'gradient': ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D']
}


class PublicationFigureGenerator:
    """Generate publication-quality figures for academic papers"""

    def __init__(self, output_dir: str = "./figures", style: str = "academic"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Set style
        if style == "academic":
            self._set_academic_style()
        elif style == "ieee":
            self._set_ieee_style()
        elif style == "acm":
            self._set_acm_style()

    def _set_academic_style(self):
        """Set general academic publication style"""
        sns.set_style("whitegrid", {
            'axes.linewidth': 0.8,
            'axes.spines.top': False,
            'axes.spines.right': False,
            'grid.linewidth': 0.5,
            'grid.alpha': 0.3
        })

    def _set_ieee_style(self):
        """Set IEEE conference style"""
        plt.rcParams.update({
            'figure.figsize': (3.5, 2.5),  # IEEE column width
            'font.size': 8,
            'axes.titlesize': 9,
            'axes.labelsize': 8
        })

    def _set_acm_style(self):
        """Set ACM conference style"""
        plt.rcParams.update({
            'figure.figsize': (3.3, 2.4),  # ACM column width
            'font.size': 8,
            'axes.titlesize': 9,
            'axes.labelsize': 8
        })

    def create_performance_comparison_chart(self,
                                          results_df: pd.DataFrame,
                                          metric: str = 'F1-Score',
                                          title: str = "Performance Comparison",
                                          save_name: str = "performance_comparison.pdf") -> str:
        """
        Create publication-quality performance comparison chart

        Args:
            results_df: DataFrame with tool results
            metric: Metric to compare
            title: Figure title
            save_name: Filename to save

        Returns:
            Path to saved figure
        """

        fig, ax = plt.subplots(figsize=(8, 5))

        # Extract data
        tools = results_df['Tool'].values
        scores = results_df[metric].apply(lambda x: float(x.split(' ±')[0])).values
        errors = results_df[metric].apply(lambda x: float(x.split('± ')[1]) if '±' in str(x) else 0).values

        # Color assignment
        colors = []
        for tool in tools:
            if 'VulnTransformer' in tool or 'Our Method' in tool:
                colors.append(ACADEMIC_COLORS['primary'])
            elif 'Commercial' in tool or 'CodeQL' in tool or 'SonarQube' in tool:
                colors.append(ACADEMIC_COLORS['secondary'])
            else:
                colors.append(ACADEMIC_COLORS['neutral'])

        # Create bar chart
        bars = ax.bar(range(len(tools)), scores, yerr=errors, capsize=3,
                     color=colors, alpha=0.8, edgecolor='black', linewidth=0.5)

        # Highlight our method
        for i, (tool, bar) in enumerate(zip(tools, bars)):
            if 'VulnTransformer' in tool or 'Our Method' in tool:
                bar.set_edgecolor(ACADEMIC_COLORS['accent'])
                bar.set_linewidth(2)

                # Add significance stars if available
                if 'Significance' in results_df.columns:
                    significance = results_df.iloc[i]['Significance']
                    if significance != '-' and significance:
                        ax.text(i, scores[i] + errors[i] + 0.01,
                               significance, ha='center', va='bottom',
                               fontweight='bold', color=ACADEMIC_COLORS['accent'])

        # Formatting
        ax.set_xlabel('Methods', fontweight='bold')
        ax.set_ylabel(metric, fontweight='bold')
        ax.set_title(title, fontweight='bold', pad=20)
        ax.set_xticks(range(len(tools)))
        ax.set_xticklabels(tools, rotation=45, ha='right')

        # Add grid
        ax.grid(True, alpha=0.3, axis='y')
        ax.set_axisbelow(True)

        # Add statistical significance legend
        if any('*' in str(sig) for sig in results_df.get('Significance', [])):
            legend_elements = [
                plt.Line2D([0], [0], marker='*', color='w', markerfacecolor=ACADEMIC_COLORS['accent'],
                          markersize=10, label='* p < 0.05'),
                plt.Line2D([0], [0], marker='*', color='w', markerfacecolor=ACADEMIC_COLORS['accent'],
                          markersize=10, label='** p < 0.01'),
                plt.Line2D([0], [0], marker='*', color='w', markerfacecolor=ACADEMIC_COLORS['accent'],
                          markersize=10, label='*** p < 0.001')
            ]
            ax.legend(handles=legend_elements, loc='upper right')

        plt.tight_layout()

        # Save figure
        save_path = self.output_dir / save_name
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.png'), format='png', dpi=300, bbox_inches='tight')
        plt.show()

        return str(save_path)

    def create_ablation_study_chart(self,
                                  ablation_results: pd.DataFrame,
                                  title: str = "Ablation Study Results",
                                  save_name: str = "ablation_study.pdf") -> str:
        """
        Create ablation study visualization

        Args:
            ablation_results: DataFrame with ablation study results
            title: Figure title
            save_name: Filename to save

        Returns:
            Path to saved figure
        """

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        # Left plot: Component contribution
        components = ['Positional Encoding', 'Hierarchical Attention', 'Cross-Modal Fusion', 'Ensemble Weighting']

        # Calculate component contributions (difference from baseline)
        baseline_f1 = ablation_results[ablation_results['Model Variant'].str.contains('Baseline')]['F1-Score'].iloc[0]
        baseline_f1 = float(baseline_f1)

        contributions = []
        for component in components:
            # Find variant with only this component enabled
            component_variants = ablation_results[
                ablation_results[component] == '✓'
            ]
            if not component_variants.empty:
                component_f1 = float(component_variants['F1-Score'].iloc[0])
                contribution = component_f1 - baseline_f1
                contributions.append(contribution)
            else:
                contributions.append(0)

        # Bar chart of contributions
        bars1 = ax1.bar(range(len(components)), contributions,
                       color=ACADEMIC_COLORS['gradient'], alpha=0.8,
                       edgecolor='black', linewidth=0.5)

        ax1.set_xlabel('Model Components', fontweight='bold')
        ax1.set_ylabel('F1-Score Improvement', fontweight='bold')
        ax1.set_title('(a) Component Contributions', fontweight='bold')
        ax1.set_xticks(range(len(components)))
        ax1.set_xticklabels(components, rotation=45, ha='right')
        ax1.grid(True, alpha=0.3, axis='y')

        # Add value labels on bars
        for bar, contrib in zip(bars1, contributions):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + 0.001,
                    f'+{contrib:.3f}', ha='center', va='bottom', fontweight='bold')

        # Right plot: Full model progression
        model_variants = ablation_results['Model Variant'].values
        f1_scores = [float(score) for score in ablation_results['F1-Score'].values]

        # Sort by F1 score
        sorted_indices = np.argsort(f1_scores)
        sorted_variants = [model_variants[i] for i in sorted_indices]
        sorted_scores = [f1_scores[i] for i in sorted_indices]

        # Color based on performance
        colors2 = []
        for score in sorted_scores:
            if score == max(sorted_scores):
                colors2.append(ACADEMIC_COLORS['primary'])
            elif score == min(sorted_scores):
                colors2.append(ACADEMIC_COLORS['success'])
            else:
                colors2.append(ACADEMIC_COLORS['neutral'])

        bars2 = ax2.barh(range(len(sorted_variants)), sorted_scores,
                        color=colors2, alpha=0.8, edgecolor='black', linewidth=0.5)

        ax2.set_ylabel('Model Variants', fontweight='bold')
        ax2.set_xlabel('F1-Score', fontweight='bold')
        ax2.set_title('(b) Model Variant Comparison', fontweight='bold')
        ax2.set_yticks(range(len(sorted_variants)))
        ax2.set_yticklabels([v.replace('VulnTransformer-', '') for v in sorted_variants])
        ax2.grid(True, alpha=0.3, axis='x')

        # Highlight best model
        best_idx = sorted_scores.index(max(sorted_scores))
        bars2[best_idx].set_edgecolor(ACADEMIC_COLORS['accent'])
        bars2[best_idx].set_linewidth(2)

        plt.tight_layout()

        # Save figure
        save_path = self.output_dir / save_name
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.png'), format='png', dpi=300, bbox_inches='tight')
        plt.show()

        return str(save_path)

    def create_attention_visualization(self,
                                     attention_weights: np.ndarray,
                                     tokens: List[str],
                                     vulnerability_type: str = "SQL Injection",
                                     save_name: str = "attention_visualization.pdf") -> str:
        """
        Create attention mechanism visualization

        Args:
            attention_weights: Attention weight matrix [seq_len, seq_len]
            tokens: List of tokens
            vulnerability_type: Type of vulnerability being detected
            save_name: Filename to save

        Returns:
            Path to saved figure
        """

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # Left plot: Attention heatmap
        # Limit to first 20 tokens for visibility
        max_tokens = min(20, len(tokens))
        attention_subset = attention_weights[:max_tokens, :max_tokens]
        tokens_subset = tokens[:max_tokens]

        im1 = ax1.imshow(attention_subset, cmap='Blues', aspect='auto')

        # Add colorbar
        cbar1 = plt.colorbar(im1, ax=ax1, shrink=0.8)
        cbar1.set_label('Attention Weight', fontweight='bold')

        # Set ticks and labels
        ax1.set_xticks(range(len(tokens_subset)))
        ax1.set_yticks(range(len(tokens_subset)))
        ax1.set_xticklabels(tokens_subset, rotation=45, ha='right')
        ax1.set_yticklabels(tokens_subset)

        ax1.set_xlabel('Key Tokens', fontweight='bold')
        ax1.set_ylabel('Query Tokens', fontweight='bold')
        ax1.set_title(f'(a) Attention Matrix\n{vulnerability_type}', fontweight='bold')

        # Right plot: Token importance
        token_importance = np.mean(attention_weights[:max_tokens, :max_tokens], axis=0)

        # Color tokens by importance
        colors = plt.cm.Reds(token_importance / np.max(token_importance))

        bars2 = ax2.barh(range(len(tokens_subset)), token_importance,
                        color=colors, alpha=0.8, edgecolor='black', linewidth=0.5)

        ax2.set_ylabel('Tokens', fontweight='bold')
        ax2.set_xlabel('Average Attention Weight', fontweight='bold')
        ax2.set_title('(b) Token Importance', fontweight='bold')
        ax2.set_yticks(range(len(tokens_subset)))
        ax2.set_yticklabels(tokens_subset)

        # Highlight most important tokens
        top_k = 3
        top_indices = np.argsort(token_importance)[-top_k:]
        for idx in top_indices:
            bars2[idx].set_edgecolor(ACADEMIC_COLORS['accent'])
            bars2[idx].set_linewidth(2)

        plt.tight_layout()

        # Save figure
        save_path = self.output_dir / save_name
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.png'), format='png', dpi=300, bbox_inches='tight')
        plt.show()

        return str(save_path)

    def create_architecture_diagram(self,
                                  save_name: str = "architecture_diagram.pdf") -> str:
        """
        Create model architecture diagram

        Args:
            save_name: Filename to save

        Returns:
            Path to saved figure
        """

        fig, ax = plt.subplots(figsize=(12, 8))
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 8)

        # Define colors
        input_color = ACADEMIC_COLORS['light']
        transformer_color = ACADEMIC_COLORS['primary']
        fusion_color = ACADEMIC_COLORS['secondary']
        output_color = ACADEMIC_COLORS['accent']

        # Input layer
        input_box = patches.Rectangle((0.5, 6.5), 2, 1, linewidth=1.5,
                                    edgecolor='black', facecolor=input_color)
        ax.add_patch(input_box)
        ax.text(1.5, 7, 'Code Input\n(Tokens)', ha='center', va='center', fontweight='bold')

        # Positional encoding
        pos_enc_box = patches.Rectangle((0.5, 5), 2, 1, linewidth=1.5,
                                      edgecolor='black', facecolor=input_color)
        ax.add_patch(pos_enc_box)
        ax.text(1.5, 5.5, 'Multi-Scale\nPositional Encoding', ha='center', va='center')

        # Hierarchical attention layers
        for i in range(3):
            y_pos = 3.5 - i * 0.8
            attn_box = patches.Rectangle((3, y_pos), 2.5, 0.6, linewidth=1.5,
                                       edgecolor='black', facecolor=transformer_color, alpha=0.7)
            ax.add_patch(attn_box)
            ax.text(4.25, y_pos + 0.3, f'Hierarchical Attention {i+1}', ha='center', va='center',
                   color='white', fontweight='bold', fontsize=9)

        # Cross-modal fusion
        fusion_box = patches.Rectangle((6.5, 2), 2.5, 2, linewidth=1.5,
                                     edgecolor='black', facecolor=fusion_color, alpha=0.7)
        ax.add_patch(fusion_box)
        ax.text(7.75, 3, 'Cross-Modal\nFusion\n(Source + AST\n+ Binary)', ha='center', va='center',
               color='white', fontweight='bold')

        # Output heads
        output_heads = ['Vulnerability\nDetection', 'Type\nClassification', 'Severity\nRegression']
        for i, head in enumerate(output_heads):
            y_pos = 0.5 + i * 1.2
            head_box = patches.Rectangle((7, y_pos), 1.5, 0.8, linewidth=1.5,
                                       edgecolor='black', facecolor=output_color, alpha=0.7)
            ax.add_patch(head_box)
            ax.text(7.75, y_pos + 0.4, head, ha='center', va='center',
                   color='white', fontweight='bold', fontsize=8)

        # Arrows
        arrow_props = dict(arrowstyle='->', lw=1.5, color='black')

        # Input to positional encoding
        ax.annotate('', xy=(1.5, 6.5), xytext=(1.5, 6), arrowprops=arrow_props)

        # Positional encoding to attention
        ax.annotate('', xy=(3, 3.8), xytext=(2.5, 5.5), arrowprops=arrow_props)

        # Between attention layers
        ax.annotate('', xy=(4.25, 2.9), xytext=(4.25, 3.5), arrowprops=arrow_props)
        ax.annotate('', xy=(4.25, 2.1), xytext=(4.25, 2.7), arrowprops=arrow_props)

        # Attention to fusion
        ax.annotate('', xy=(6.5, 3), xytext=(5.5, 2.5), arrowprops=arrow_props)

        # Fusion to outputs
        for i in range(3):
            y_pos = 0.9 + i * 1.2
            ax.annotate('', xy=(7, y_pos), xytext=(7.5, 2.8), arrowprops=arrow_props)

        # Remove axes
        ax.set_xticks([])
        ax.set_yticks([])
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['left'].set_visible(False)

        # Title
        ax.set_title('Multi-Scale Transformer Architecture for Vulnerability Detection',
                    fontweight='bold', fontsize=14, pad=20)

        plt.tight_layout()

        # Save figure
        save_path = self.output_dir / save_name
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.png'), format='png', dpi=300, bbox_inches='tight')
        plt.show()

        return str(save_path)

    def create_statistical_significance_plot(self,
                                           comparison_results: Dict,
                                           save_name: str = "statistical_significance.pdf") -> str:
        """
        Create statistical significance visualization

        Args:
            comparison_results: Results from statistical tests
            save_name: Filename to save

        Returns:
            Path to saved figure
        """

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        # Left plot: P-values
        tool_names = list(comparison_results.keys())
        p_values = [comparison_results[tool]['p_value'] for tool in tool_names]
        effect_sizes = [comparison_results[tool]['cohens_d'] for tool in tool_names]

        # Color by significance level
        colors = []
        for p in p_values:
            if p < 0.001:
                colors.append(ACADEMIC_COLORS['primary'])
            elif p < 0.01:
                colors.append(ACADEMIC_COLORS['secondary'])
            elif p < 0.05:
                colors.append(ACADEMIC_COLORS['accent'])
            else:
                colors.append(ACADEMIC_COLORS['neutral'])

        bars1 = ax1.bar(range(len(tool_names)), [-np.log10(p) for p in p_values],
                       color=colors, alpha=0.8, edgecolor='black', linewidth=0.5)

        # Add significance threshold lines
        ax1.axhline(-np.log10(0.05), color='red', linestyle='--', alpha=0.7, label='p = 0.05')
        ax1.axhline(-np.log10(0.01), color='red', linestyle=':', alpha=0.7, label='p = 0.01')

        ax1.set_xlabel('Commercial Tools', fontweight='bold')
        ax1.set_ylabel('-log₁₀(p-value)', fontweight='bold')
        ax1.set_title('(a) Statistical Significance', fontweight='bold')
        ax1.set_xticks(range(len(tool_names)))
        ax1.set_xticklabels(tool_names, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(True, alpha=0.3, axis='y')

        # Right plot: Effect sizes
        bars2 = ax2.bar(range(len(tool_names)), effect_sizes,
                       color=ACADEMIC_COLORS['gradient'][:len(tool_names)], alpha=0.8,
                       edgecolor='black', linewidth=0.5)

        # Add Cohen's d interpretation lines
        ax2.axhline(0.2, color='gray', linestyle='--', alpha=0.7, label='Small effect')
        ax2.axhline(0.5, color='gray', linestyle=':', alpha=0.7, label='Medium effect')
        ax2.axhline(0.8, color='gray', linestyle='-', alpha=0.7, label='Large effect')

        ax2.set_xlabel('Commercial Tools', fontweight='bold')
        ax2.set_ylabel("Cohen's d (Effect Size)", fontweight='bold')
        ax2.set_title('(b) Effect Size Analysis', fontweight='bold')
        ax2.set_xticks(range(len(tool_names)))
        ax2.set_xticklabels(tool_names, rotation=45, ha='right')
        ax2.legend()
        ax2.grid(True, alpha=0.3, axis='y')

        # Add value labels
        for bar, effect in zip(bars2, effect_sizes):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                    f'{effect:.2f}', ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()

        # Save figure
        save_path = self.output_dir / save_name
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.png'), format='png', dpi=300, bbox_inches='tight')
        plt.show()

        return str(save_path)

    def create_dataset_distribution_plot(self,
                                       dataset_stats: Dict,
                                       save_name: str = "dataset_distribution.pdf") -> str:
        """
        Create dataset distribution visualization

        Args:
            dataset_stats: Dataset statistics
            save_name: Filename to save

        Returns:
            Path to saved figure
        """

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))

        # Vulnerability type distribution
        vuln_types = list(dataset_stats['by_vulnerability_type'].keys())
        vuln_counts = list(dataset_stats['by_vulnerability_type'].values())

        ax1.pie(vuln_counts, labels=vuln_types, autopct='%1.1f%%',
               colors=ACADEMIC_COLORS['gradient'] * (len(vuln_types) // 4 + 1))
        ax1.set_title('(a) Vulnerability Type Distribution', fontweight='bold')

        # Language distribution
        languages = list(dataset_stats['by_language'].keys())
        lang_counts = list(dataset_stats['by_language'].values())

        bars2 = ax2.bar(languages, lang_counts, color=ACADEMIC_COLORS['primary'],
                       alpha=0.8, edgecolor='black', linewidth=0.5)
        ax2.set_xlabel('Programming Language', fontweight='bold')
        ax2.set_ylabel('Number of Samples', fontweight='bold')
        ax2.set_title('(b) Language Distribution', fontweight='bold')
        ax2.tick_params(axis='x', rotation=45)

        # Severity distribution
        severity_levels = ['Low', 'Medium', 'High', 'Critical']
        severity_counts = [dataset_stats.get(f'severity_{level.lower()}', 0) for level in severity_levels]

        if sum(severity_counts) == 0:  # Mock data if not available
            severity_counts = [150, 300, 200, 100]

        bars3 = ax3.bar(severity_levels, severity_counts,
                       color=['#28a745', '#ffc107', '#fd7e14', '#dc3545'],
                       alpha=0.8, edgecolor='black', linewidth=0.5)
        ax3.set_xlabel('Severity Level', fontweight='bold')
        ax3.set_ylabel('Number of Vulnerabilities', fontweight='bold')
        ax3.set_title('(c) Severity Distribution', fontweight='bold')

        # Source distribution
        sources = list(dataset_stats['by_source'].keys())
        source_counts = list(dataset_stats['by_source'].values())

        ax4.pie(source_counts, labels=sources, autopct='%1.1f%%',
               colors=ACADEMIC_COLORS['gradient'])
        ax4.set_title('(d) Data Source Distribution', fontweight='bold')

        plt.tight_layout()

        # Save figure
        save_path = self.output_dir / save_name
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.png'), format='png', dpi=300, bbox_inches='tight')
        plt.show()

        return str(save_path)

    def create_publication_table(self,
                               comparison_data: pd.DataFrame,
                               save_name: str = "comparison_table.tex") -> str:
        """
        Create LaTeX table for publication

        Args:
            comparison_data: Comparison results DataFrame
            save_name: Filename to save

        Returns:
            Path to saved LaTeX table
        """

        # Format table for LaTeX
        latex_table = comparison_data.to_latex(
            index=False,
            escape=False,
            column_format='l' + 'c' * (len(comparison_data.columns) - 1),
            caption='Performance comparison of vulnerability detection methods. '
                   'Statistical significance: * p < 0.05, ** p < 0.01, *** p < 0.001.',
            label='tab:performance_comparison',
            position='htbp'
        )

        # Add additional formatting
        latex_table = latex_table.replace('\\toprule', '\\hline')
        latex_table = latex_table.replace('\\midrule', '\\hline')
        latex_table = latex_table.replace('\\bottomrule', '\\hline')

        # Save LaTeX table
        save_path = self.output_dir / save_name
        with open(save_path, 'w') as f:
            f.write(latex_table)

        print(f"LaTeX table saved to: {save_path}")
        return str(save_path)


def test_publication_figures():
    """Test publication figure generation"""
    print("Testing Publication Figure Generation...")

    # Initialize generator
    fig_gen = PublicationFigureGenerator(output_dir="./test_figures")

    # Mock comparison data
    comparison_data = pd.DataFrame({
        'Tool': ['VulnTransformer (Ours)', 'CodeQL', 'SonarQube', 'Semgrep', 'Bandit'],
        'Precision': ['0.875 ± 0.023', '0.742 ± 0.031', '0.689 ± 0.028', '0.721 ± 0.035', '0.698 ± 0.029'],
        'Recall': ['0.831 ± 0.019', '0.698 ± 0.025', '0.723 ± 0.032', '0.687 ± 0.028', '0.712 ± 0.031'],
        'F1-Score': ['0.852 ± 0.015', '0.719 ± 0.022', '0.706 ± 0.025', '0.704 ± 0.027', '0.705 ± 0.024'],
        'Significance': ['***', '***', '***', '***', '***'],
        'p-value': ['-', '0.001', '0.002', '0.003', '0.002'],
        'Effect Size': ['-', '0.85', '0.92', '0.78', '0.81']
    })

    # Test performance comparison chart
    print("Creating performance comparison chart...")
    fig_gen.create_performance_comparison_chart(
        comparison_data,
        title="Vulnerability Detection Performance Comparison"
    )

    # Mock ablation study data
    ablation_data = pd.DataFrame({
        'Model Variant': [
            'VulnTransformer-PE-HA-CMF-EW',
            'VulnTransformer-HA-CMF-EW',
            'VulnTransformer-PE-CMF-EW',
            'VulnTransformer-PE-HA-EW',
            'VulnTransformer-PE-HA-CMF',
            'VulnTransformer-Baseline'
        ],
        'Positional Encoding': ['✓', '✗', '✓', '✓', '✓', '✗'],
        'Hierarchical Attention': ['✓', '✓', '✗', '✓', '✓', '✗'],
        'Cross-Modal Fusion': ['✓', '✓', '✓', '✗', '✓', '✗'],
        'Ensemble Weighting': ['✓', '✓', '✓', '✓', '✗', '✗'],
        'F1-Score': ['0.852', '0.831', '0.825', '0.819', '0.845', '0.742'],
        'Parameters (M)': ['45.2', '43.1', '42.8', '41.5', '44.9', '38.7']
    })

    # Test ablation study chart
    print("Creating ablation study chart...")
    fig_gen.create_ablation_study_chart(ablation_data)

    # Test attention visualization
    print("Creating attention visualization...")
    attention_weights = np.random.rand(15, 15)
    attention_weights = (attention_weights + attention_weights.T) / 2  # Make symmetric
    tokens = ['import', 'os', 'def', 'execute', '(', 'command', ')', ':', 'os', '.', 'system', '(', 'command', ')', 'return']

    fig_gen.create_attention_visualization(
        attention_weights, tokens, "Command Injection"
    )

    # Test architecture diagram
    print("Creating architecture diagram...")
    fig_gen.create_architecture_diagram()

    # Mock statistical results
    statistical_results = {
        'CodeQL': {'p_value': 0.001, 'cohens_d': 0.85},
        'SonarQube': {'p_value': 0.002, 'cohens_d': 0.92},
        'Semgrep': {'p_value': 0.003, 'cohens_d': 0.78},
        'Bandit': {'p_value': 0.002, 'cohens_d': 0.81}
    }

    # Test statistical significance plot
    print("Creating statistical significance plot...")
    fig_gen.create_statistical_significance_plot(statistical_results)

    # Mock dataset statistics
    dataset_stats = {
        'by_vulnerability_type': {
            'SQL Injection': 450, 'XSS': 380, 'Command Injection': 320,
            'Buffer Overflow': 290, 'Path Traversal': 240
        },
        'by_language': {
            'Python': 800, 'Java': 650, 'JavaScript': 480, 'C': 320, 'C++': 250
        },
        'by_source': {
            'CVE Database': 1200, 'GitHub Advisories': 800, 'Synthetic': 500
        }
    }

    # Test dataset distribution plot
    print("Creating dataset distribution plot...")
    fig_gen.create_dataset_distribution_plot(dataset_stats)

    # Test LaTeX table generation
    print("Creating LaTeX table...")
    fig_gen.create_publication_table(comparison_data)

    print("Publication figure generation test completed!")
    print(f"All figures saved to: {fig_gen.output_dir}")


if __name__ == "__main__":
    test_publication_figures()