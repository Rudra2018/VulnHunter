#!/usr/bin/env python3
"""
Advanced Model Interpretation and Explainability

This module provides comprehensive model interpretation capabilities:
- SHAP (SHapley Additive exPlanations) analysis
- LIME (Local Interpretable Model-agnostic Explanations)
- Integrated Gradients
- GradCAM for attention visualization
- Feature importance analysis
- Counterfactual explanations
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple, Union, Callable
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report
import warnings

# Optional imports for advanced interpretability
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("SHAP not available. Install with: pip install shap")

try:
    from captum.attr import IntegratedGradients, GradientShap, DeepLift
    from captum.attr import visualization as viz
    CAPTUM_AVAILABLE = True
except ImportError:
    CAPTUM_AVAILABLE = False
    print("Captum not available. Install with: pip install captum")

warnings.filterwarnings("ignore")


class ModelInterpreter:
    """Advanced model interpretation and explainability"""

    def __init__(self, model: nn.Module, device: str = 'cpu'):
        self.model = model
        self.device = device
        self.model.to(device)

        # Initialize interpretation methods
        if CAPTUM_AVAILABLE:
            self.integrated_gradients = IntegratedGradients(self._forward_func)
            self.gradient_shap = GradientShap(self._forward_func)
            self.deep_lift = DeepLift(self._forward_func)

        # Store baseline inputs for gradient-based methods
        self.baseline_input = None

    def _forward_func(self, inputs: torch.Tensor) -> torch.Tensor:
        """Wrapper function for Captum compatibility"""
        if hasattr(self.model, 'forward'):
            outputs = self.model(inputs)
            if isinstance(outputs, dict):
                return outputs['vulnerability']  # Return vulnerability logits
            return outputs
        else:
            raise ValueError("Model must have a forward method")

    def explain_prediction_shap(self,
                               input_ids: torch.Tensor,
                               tokens: List[str],
                               baseline_samples: int = 100,
                               save_path: Optional[str] = None) -> Dict:
        """
        Explain predictions using SHAP values

        Args:
            input_ids: Input token IDs [seq_len] or [batch_size, seq_len]
            tokens: List of tokens corresponding to input_ids
            baseline_samples: Number of baseline samples for SHAP
            save_path: Path to save the visualization

        Returns:
            Dictionary containing SHAP values and visualizations
        """

        if not SHAP_AVAILABLE:
            raise ImportError("SHAP is required for this function")

        # Prepare input
        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)

        batch_size, seq_len = input_ids.shape

        # Create baseline inputs (random sampling from vocabulary)
        vocab_size = self.model.config.get('vocab_size', 50265) if hasattr(self.model, 'config') else 50265
        baseline_inputs = torch.randint(0, vocab_size, (baseline_samples, seq_len), device=self.device)

        # Define explanation function
        def model_func(inputs):
            inputs_tensor = torch.tensor(inputs, dtype=torch.long, device=self.device)
            with torch.no_grad():
                outputs = self._forward_func(inputs_tensor)
                if outputs.dim() > 1:
                    outputs = outputs.squeeze()
                return outputs.cpu().numpy()

        # Create SHAP explainer
        explainer = shap.Explainer(model_func, baseline_inputs.cpu().numpy())

        # Calculate SHAP values
        shap_values = explainer(input_ids.cpu().numpy())

        # Visualize SHAP values
        if save_path:
            self._plot_shap_values(shap_values, tokens, save_path)

        return {
            'shap_values': shap_values,
            'baseline_inputs': baseline_inputs,
            'tokens': tokens
        }

    def explain_prediction_integrated_gradients(self,
                                              input_ids: torch.Tensor,
                                              tokens: List[str],
                                              target_class: int = None,
                                              n_steps: int = 50,
                                              save_path: Optional[str] = None) -> Dict:
        """
        Explain predictions using Integrated Gradients

        Args:
            input_ids: Input token IDs
            tokens: List of tokens
            target_class: Target class for explanation (None for predicted class)
            n_steps: Number of integration steps
            save_path: Path to save the visualization

        Returns:
            Dictionary containing attribution scores and visualization
        """

        if not CAPTUM_AVAILABLE:
            raise ImportError("Captum is required for this function")

        # Prepare input
        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)

        input_ids = input_ids.to(self.device)
        input_ids.requires_grad_(True)

        # Create baseline (typically zeros or random tokens)
        baseline = torch.zeros_like(input_ids)

        # Get model prediction to determine target class
        if target_class is None:
            with torch.no_grad():
                outputs = self._forward_func(input_ids)
                if outputs.dim() > 1 and outputs.size(-1) > 1:
                    target_class = torch.argmax(outputs, dim=-1).item()
                else:
                    target_class = 0

        # Calculate attributions
        attributions = self.integrated_gradients.attribute(
            input_ids,
            baseline,
            target=target_class,
            n_steps=n_steps
        )

        # Convert to numpy for visualization
        attributions_np = attributions.squeeze().detach().cpu().numpy()

        # Create visualization
        if save_path:
            self._plot_integrated_gradients(attributions_np, tokens, save_path)

        return {
            'attributions': attributions_np,
            'target_class': target_class,
            'tokens': tokens,
            'input_ids': input_ids.cpu()
        }

    def explain_prediction_lime(self,
                               input_ids: torch.Tensor,
                               tokens: List[str],
                               num_features: int = 10,
                               num_samples: int = 5000,
                               save_path: Optional[str] = None) -> Dict:
        """
        Explain predictions using LIME (Local Interpretable Model-agnostic Explanations)

        Args:
            input_ids: Input token IDs
            tokens: List of tokens
            num_features: Number of features to show in explanation
            num_samples: Number of samples for LIME
            save_path: Path to save the visualization

        Returns:
            Dictionary containing LIME explanation
        """

        # Custom LIME implementation for text
        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)

        original_prediction = self._get_prediction(input_ids)

        # Generate perturbations by masking tokens
        perturbed_inputs = []
        perturbed_predictions = []

        vocab_size = input_ids.max().item() + 1
        mask_token_id = 0  # Use 0 as mask token

        for _ in range(num_samples):
            # Randomly mask some tokens
            mask_ratio = np.random.uniform(0.1, 0.5)
            num_mask = int(len(tokens) * mask_ratio)
            mask_positions = np.random.choice(len(tokens), num_mask, replace=False)

            perturbed_input = input_ids.clone()
            for pos in mask_positions:
                perturbed_input[0, pos] = mask_token_id

            perturbed_inputs.append(perturbed_input)

            # Get prediction for perturbed input
            pred = self._get_prediction(perturbed_input)
            perturbed_predictions.append(pred)

        # Calculate feature importance using linear regression
        feature_importance = self._calculate_lime_importance(
            input_ids, perturbed_inputs, perturbed_predictions, original_prediction
        )

        # Create visualization
        if save_path:
            self._plot_lime_explanation(feature_importance, tokens, save_path)

        return {
            'feature_importance': feature_importance,
            'original_prediction': original_prediction,
            'tokens': tokens
        }

    def analyze_feature_importance(self,
                                 input_ids: torch.Tensor,
                                 tokens: List[str],
                                 method: str = 'gradient',
                                 save_path: Optional[str] = None) -> Dict:
        """
        Analyze feature importance using various methods

        Args:
            input_ids: Input token IDs
            tokens: List of tokens
            method: Method to use ('gradient', 'attention', 'occlusion')
            save_path: Path to save the analysis

        Returns:
            Dictionary containing feature importance analysis
        """

        if method == 'gradient':
            return self._gradient_based_importance(input_ids, tokens, save_path)
        elif method == 'attention':
            return self._attention_based_importance(input_ids, tokens, save_path)
        elif method == 'occlusion':
            return self._occlusion_based_importance(input_ids, tokens, save_path)
        else:
            raise ValueError(f"Unknown method: {method}")

    def _gradient_based_importance(self,
                                 input_ids: torch.Tensor,
                                 tokens: List[str],
                                 save_path: Optional[str] = None) -> Dict:
        """Calculate feature importance using gradients"""

        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)

        input_ids = input_ids.to(self.device)
        input_ids.requires_grad_(True)

        # Forward pass
        outputs = self._forward_func(input_ids)

        # Get target (predicted class or vulnerability score)
        if outputs.dim() > 1 and outputs.size(-1) > 1:
            target = torch.argmax(outputs, dim=-1)
        else:
            target = outputs

        # Backward pass
        self.model.zero_grad()
        if target.dim() > 0:
            target = target[0]
        target.backward()

        # Get gradients
        gradients = input_ids.grad.abs().squeeze().cpu().numpy()

        # Normalize
        gradients = gradients / (gradients.max() + 1e-8)

        # Create visualization
        if save_path:
            self._plot_feature_importance(gradients, tokens, 'Gradient-based', save_path)

        return {
            'importance_scores': gradients,
            'tokens': tokens,
            'method': 'gradient'
        }

    def _attention_based_importance(self,
                                  input_ids: torch.Tensor,
                                  tokens: List[str],
                                  save_path: Optional[str] = None) -> Dict:
        """Calculate feature importance using attention weights"""

        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)

        input_ids = input_ids.to(self.device)

        # Get model outputs with attention
        with torch.no_grad():
            outputs = self.model(input_ids, return_attention_weights=True)

        # Extract attention weights
        if 'attention_weights' in outputs:
            attention_data = outputs['attention_weights']

            if 'pooling_attention' in attention_data:
                attention_weights = attention_data['pooling_attention']
                importance_scores = attention_weights.squeeze().cpu().numpy()
            else:
                # Use average of all attention heads
                transformer_attention = attention_data.get('transformer_blocks', [])
                if transformer_attention:
                    # Average over all layers and heads
                    all_attention = torch.stack([
                        attn['self_attention'].mean(dim=0) if 'self_attention' in attn
                        else torch.zeros(len(tokens), len(tokens))
                        for attn in transformer_attention
                    ])
                    importance_scores = all_attention.mean(dim=0).mean(dim=0).cpu().numpy()
                else:
                    importance_scores = np.ones(len(tokens)) / len(tokens)
        else:
            importance_scores = np.ones(len(tokens)) / len(tokens)

        # Normalize
        importance_scores = importance_scores / (importance_scores.max() + 1e-8)

        # Create visualization
        if save_path:
            self._plot_feature_importance(importance_scores, tokens, 'Attention-based', save_path)

        return {
            'importance_scores': importance_scores,
            'tokens': tokens,
            'method': 'attention'
        }

    def _occlusion_based_importance(self,
                                  input_ids: torch.Tensor,
                                  tokens: List[str],
                                  save_path: Optional[str] = None) -> Dict:
        """Calculate feature importance using occlusion analysis"""

        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)

        input_ids = input_ids.to(self.device)

        # Get baseline prediction
        with torch.no_grad():
            baseline_output = self._forward_func(input_ids)
            if baseline_output.dim() > 0:
                baseline_score = baseline_output[0].item()
            else:
                baseline_score = baseline_output.item()

        # Occlude each token and measure impact
        importance_scores = []
        mask_token_id = 0  # Use 0 as mask token

        for i in range(len(tokens)):
            # Create occluded input
            occluded_input = input_ids.clone()
            occluded_input[0, i] = mask_token_id

            # Get prediction
            with torch.no_grad():
                occluded_output = self._forward_func(occluded_input)
                if occluded_output.dim() > 0:
                    occluded_score = occluded_output[0].item()
                else:
                    occluded_score = occluded_output.item()

            # Importance = difference from baseline
            importance = abs(baseline_score - occluded_score)
            importance_scores.append(importance)

        importance_scores = np.array(importance_scores)

        # Normalize
        importance_scores = importance_scores / (importance_scores.max() + 1e-8)

        # Create visualization
        if save_path:
            self._plot_feature_importance(importance_scores, tokens, 'Occlusion-based', save_path)

        return {
            'importance_scores': importance_scores,
            'tokens': tokens,
            'method': 'occlusion',
            'baseline_score': baseline_score
        }

    def generate_counterfactual_explanations(self,
                                           input_ids: torch.Tensor,
                                           tokens: List[str],
                                           target_class: int,
                                           max_changes: int = 5,
                                           save_path: Optional[str] = None) -> Dict:
        """
        Generate counterfactual explanations

        Args:
            input_ids: Original input token IDs
            tokens: List of tokens
            target_class: Target class to change prediction to
            max_changes: Maximum number of token changes allowed
            save_path: Path to save the analysis

        Returns:
            Dictionary containing counterfactual examples
        """

        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)

        original_input = input_ids.clone()
        original_prediction = self._get_prediction(original_input)

        # Simple greedy search for counterfactuals
        counterfactuals = []
        vocab_size = 1000  # Limit vocabulary for efficiency

        for num_changes in range(1, max_changes + 1):
            # Try changing different combinations of tokens
            for positions in self._get_change_positions(len(tokens), num_changes):
                for new_tokens in self._get_token_replacements(positions, vocab_size):
                    # Create modified input
                    modified_input = original_input.clone()
                    for pos, new_token in zip(positions, new_tokens):
                        modified_input[0, pos] = new_token

                    # Check if prediction changed to target
                    new_prediction = self._get_prediction(modified_input)

                    if self._check_target_achieved(new_prediction, target_class, original_prediction):
                        counterfactual = {
                            'modified_input': modified_input,
                            'modified_tokens': self._replace_tokens(tokens, positions, new_tokens),
                            'changes': list(zip(positions, new_tokens)),
                            'num_changes': num_changes,
                            'new_prediction': new_prediction,
                            'original_prediction': original_prediction
                        }
                        counterfactuals.append(counterfactual)

                        if len(counterfactuals) >= 5:  # Limit number of counterfactuals
                            break

                if len(counterfactuals) >= 5:
                    break
            if len(counterfactuals) >= 5:
                break

        # Create visualization
        if save_path and counterfactuals:
            self._plot_counterfactuals(counterfactuals, save_path)

        return {
            'counterfactuals': counterfactuals,
            'original_tokens': tokens,
            'original_prediction': original_prediction,
            'target_class': target_class
        }

    # Helper methods
    def _get_prediction(self, input_ids: torch.Tensor) -> float:
        """Get model prediction for input"""
        with torch.no_grad():
            outputs = self._forward_func(input_ids)
            if outputs.dim() > 0:
                return outputs[0].item()
            return outputs.item()

    def _calculate_lime_importance(self, original_input, perturbed_inputs, predictions, original_pred):
        """Calculate LIME feature importance using linear regression"""
        # Simple correlation-based importance
        seq_len = original_input.size(1)
        importance = np.zeros(seq_len)

        for i in range(seq_len):
            # Check correlation between token presence and prediction change
            correlations = []
            for perturbed_input, pred in zip(perturbed_inputs, predictions):
                token_present = (perturbed_input[0, i] == original_input[0, i]).float()
                pred_change = abs(pred - original_pred)
                correlations.append([token_present.item(), pred_change])

            if correlations:
                correlations = np.array(correlations)
                if correlations[:, 0].std() > 0:
                    importance[i] = abs(np.corrcoef(correlations[:, 0], correlations[:, 1])[0, 1])

        return importance

    def _get_change_positions(self, seq_len: int, num_changes: int):
        """Generate combinations of positions to change"""
        import itertools
        return list(itertools.combinations(range(seq_len), num_changes))[:10]  # Limit combinations

    def _get_token_replacements(self, positions, vocab_size):
        """Generate token replacements for positions"""
        import itertools
        # Simple: just try a few random tokens
        replacement_options = [list(range(1, min(100, vocab_size)))] * len(positions)
        return list(itertools.product(*replacement_options))[:5]  # Limit options

    def _check_target_achieved(self, new_pred, target_class, original_pred):
        """Check if counterfactual achieved target"""
        # Simple threshold-based check
        if target_class == 1:  # Vulnerable
            return new_pred > 0.5 and original_pred <= 0.5
        else:  # Not vulnerable
            return new_pred <= 0.5 and original_pred > 0.5

    def _replace_tokens(self, original_tokens, positions, new_tokens):
        """Replace tokens at specified positions"""
        modified_tokens = original_tokens.copy()
        for pos, new_token in zip(positions, new_tokens):
            if pos < len(modified_tokens):
                modified_tokens[pos] = f"[MODIFIED_{new_token}]"
        return modified_tokens

    # Visualization methods
    def _plot_shap_values(self, shap_values, tokens, save_path):
        """Plot SHAP values"""
        plt.figure(figsize=(12, 6))
        values = shap_values.values[0] if hasattr(shap_values, 'values') else shap_values

        plt.barh(range(len(tokens)), values)
        plt.yticks(range(len(tokens)), tokens)
        plt.xlabel('SHAP Value')
        plt.title('SHAP Feature Importance')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def _plot_integrated_gradients(self, attributions, tokens, save_path):
        """Plot integrated gradients"""
        plt.figure(figsize=(12, 6))
        colors = ['red' if attr > 0 else 'blue' for attr in attributions]

        plt.barh(range(len(tokens)), attributions, color=colors)
        plt.yticks(range(len(tokens)), tokens)
        plt.xlabel('Attribution Score')
        plt.title('Integrated Gradients Attribution')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def _plot_lime_explanation(self, importance, tokens, save_path):
        """Plot LIME explanation"""
        plt.figure(figsize=(12, 6))

        plt.barh(range(len(tokens)), importance)
        plt.yticks(range(len(tokens)), tokens)
        plt.xlabel('Feature Importance')
        plt.title('LIME Local Explanation')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def _plot_feature_importance(self, importance, tokens, method, save_path):
        """Plot feature importance"""
        plt.figure(figsize=(12, 6))

        plt.barh(range(len(tokens)), importance)
        plt.yticks(range(len(tokens)), tokens)
        plt.xlabel('Importance Score')
        plt.title(f'{method} Feature Importance')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def _plot_counterfactuals(self, counterfactuals, save_path):
        """Plot counterfactual explanations"""
        fig, axes = plt.subplots(len(counterfactuals), 1, figsize=(15, 4 * len(counterfactuals)))
        if len(counterfactuals) == 1:
            axes = [axes]

        for i, cf in enumerate(counterfactuals):
            ax = axes[i]

            # Show original vs modified tokens
            original_tokens = cf.get('original_tokens', [])
            modified_tokens = cf['modified_tokens']

            y_pos = np.arange(len(modified_tokens))

            # Color tokens differently if they were changed
            colors = []
            for j, (orig, mod) in enumerate(zip(original_tokens, modified_tokens)):
                if orig != mod:
                    colors.append('red')
                else:
                    colors.append('lightblue')

            ax.barh(y_pos, [1] * len(modified_tokens), color=colors)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(modified_tokens)
            ax.set_title(f'Counterfactual {i+1}: {cf["num_changes"]} changes')
            ax.set_xlabel('Token Position')

        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()


def test_model_interpreter():
    """Test the model interpreter"""
    print("Testing Model Interpreter...")

    # Create a simple test model
    class TestModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = nn.Embedding(1000, 128)
            self.classifier = nn.Linear(128, 1)

        def forward(self, input_ids, return_attention_weights=False):
            x = self.embedding(input_ids)
            x = x.mean(dim=1)  # Simple pooling
            output = self.classifier(x)

            result = {'vulnerability': output.squeeze()}

            if return_attention_weights:
                # Mock attention weights
                batch_size, seq_len = input_ids.shape
                mock_attention = torch.rand(batch_size, seq_len)
                result['attention_weights'] = {
                    'pooling_attention': mock_attention
                }

            return result

    # Initialize model and interpreter
    model = TestModel()
    interpreter = ModelInterpreter(model)

    # Create sample data
    seq_len = 10
    input_ids = torch.randint(0, 1000, (seq_len,))
    tokens = [f"token_{i}" for i in range(seq_len)]

    print("Testing gradient-based importance...")
    gradient_result = interpreter.analyze_feature_importance(
        input_ids, tokens, method='gradient'
    )
    print(f"Gradient importance shape: {gradient_result['importance_scores'].shape}")

    print("Testing attention-based importance...")
    attention_result = interpreter.analyze_feature_importance(
        input_ids, tokens, method='attention'
    )
    print(f"Attention importance shape: {attention_result['importance_scores'].shape}")

    print("Testing occlusion-based importance...")
    occlusion_result = interpreter.analyze_feature_importance(
        input_ids, tokens, method='occlusion'
    )
    print(f"Occlusion importance shape: {occlusion_result['importance_scores'].shape}")

    # Test LIME if available
    print("Testing LIME explanation...")
    lime_result = interpreter.explain_prediction_lime(input_ids, tokens)
    print(f"LIME importance shape: {lime_result['feature_importance'].shape}")

    print("Model interpreter test completed!")


if __name__ == "__main__":
    test_model_interpreter()