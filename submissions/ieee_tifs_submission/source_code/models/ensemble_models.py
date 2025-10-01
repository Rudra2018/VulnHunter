#!/usr/bin/env python3
"""
Ensemble Models for Advanced Vulnerability Detection

This module implements sophisticated ensemble architectures:
- Multi-architecture ensemble with adaptive weighting
- Knowledge distillation from large models
- Uncertainty quantification
- Model diversity optimization
- Dynamic model selection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple, Union, Callable
import numpy as np
from collections import defaultdict
import warnings

# Import our custom models
from .advanced_architectures import MultiScaleTransformerVulnDetector
from .graph_networks import MultiGraphVulnDetector
from .vuln_detector import SimpleVulnDetector, EnhancedVulnDetector

warnings.filterwarnings("ignore")


class UncertaintyQuantification(nn.Module):
    """Module for uncertainty quantification using Monte Carlo Dropout and Deep Ensembles"""

    def __init__(self, model: nn.Module, num_samples: int = 10):
        super().__init__()
        self.model = model
        self.num_samples = num_samples

    def enable_dropout(self, model: nn.Module):
        """Enable dropout during inference for MC Dropout"""
        for m in model.modules():
            if m.__class__.__name__.startswith('Dropout'):
                m.train()

    def forward(self, *args, **kwargs) -> Dict[str, torch.Tensor]:
        """Forward pass with uncertainty quantification"""
        self.model.eval()

        # Standard prediction
        with torch.no_grad():
            standard_output = self.model(*args, **kwargs)

        # Monte Carlo Dropout samples
        self.enable_dropout(self.model)
        mc_outputs = []

        with torch.no_grad():
            for _ in range(self.num_samples):
                mc_output = self.model(*args, **kwargs)
                mc_outputs.append(mc_output)

        self.model.eval()  # Disable dropout again

        # Calculate mean and variance
        mc_predictions = {}
        for key in standard_output.keys():
            if isinstance(standard_output[key], torch.Tensor):
                samples = torch.stack([output[key] for output in mc_outputs])
                mc_predictions[key + '_mean'] = torch.mean(samples, dim=0)
                mc_predictions[key + '_var'] = torch.var(samples, dim=0)
                mc_predictions[key + '_std'] = torch.std(samples, dim=0)

        # Combine standard and MC predictions
        result = {**standard_output, **mc_predictions}
        result['uncertainty_samples'] = mc_outputs

        return result


class AdaptiveWeightingModule(nn.Module):
    """Adaptive weighting module for ensemble combination"""

    def __init__(self, num_models: int, input_dim: int, context_dim: int = 0):
        super().__init__()
        self.num_models = num_models

        # Context-aware weighting network
        total_dim = input_dim + context_dim
        self.weight_network = nn.Sequential(
            nn.Linear(total_dim, total_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(total_dim // 2, total_dim // 4),
            nn.ReLU(),
            nn.Linear(total_dim // 4, num_models),
            nn.Softmax(dim=-1)
        )

        # Confidence calibration
        self.calibration_network = nn.Sequential(
            nn.Linear(total_dim + num_models, 64),
            nn.ReLU(),
            nn.Linear(64, num_models),
            nn.Sigmoid()
        )

        # Diversity reward
        self.diversity_weight = nn.Parameter(torch.tensor(0.1))

    def forward(self, model_outputs: List[torch.Tensor],
                input_features: torch.Tensor,
                context_features: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Compute adaptive weights for model outputs

        Args:
            model_outputs: List of model prediction tensors
            input_features: Input features for context-aware weighting
            context_features: Additional context features

        Returns:
            Weighted ensemble output and attention weights
        """
        batch_size = input_features.size(0)

        # Prepare input for weight network
        if context_features is not None:
            weight_input = torch.cat([input_features, context_features], dim=-1)
        else:
            weight_input = input_features

        # Compute base weights
        base_weights = self.weight_network(weight_input)  # [batch_size, num_models]

        # Stack model outputs
        stacked_outputs = torch.stack(model_outputs, dim=1)  # [batch_size, num_models, ...]

        # Calculate model diversity (encourage diverse predictions)
        diversity_penalty = 0
        for i in range(len(model_outputs)):
            for j in range(i + 1, len(model_outputs)):
                similarity = F.cosine_similarity(
                    model_outputs[i].view(batch_size, -1),
                    model_outputs[j].view(batch_size, -1),
                    dim=1
                )
                diversity_penalty += torch.mean(similarity)

        # Adjust weights based on diversity
        diversity_factor = 1.0 - self.diversity_weight * diversity_penalty
        adjusted_weights = base_weights * diversity_factor.unsqueeze(-1)

        # Calibrate confidence
        calibration_input = torch.cat([weight_input, adjusted_weights], dim=-1)
        confidence_scores = self.calibration_network(calibration_input)

        # Final weights combine base weights and confidence
        final_weights = adjusted_weights * confidence_scores
        final_weights = F.softmax(final_weights, dim=-1)

        # Weighted combination
        if len(stacked_outputs.shape) == 3:  # [batch, models, features]
            weighted_output = torch.sum(
                final_weights.unsqueeze(-1) * stacked_outputs,
                dim=1
            )
        else:  # [batch, models] for single predictions
            weighted_output = torch.sum(final_weights * stacked_outputs, dim=1)

        return weighted_output, final_weights


class KnowledgeDistillationModule(nn.Module):
    """Knowledge distillation from teacher to student models"""

    def __init__(self, teacher_models: List[nn.Module], student_model: nn.Module,
                 temperature: float = 4.0, alpha: float = 0.7):
        super().__init__()
        self.teacher_models = nn.ModuleList(teacher_models)
        self.student_model = student_model
        self.temperature = temperature
        self.alpha = alpha  # Balance between hard and soft targets

        # Attention mechanism for teacher selection
        self.teacher_attention = nn.MultiheadAttention(
            embed_dim=256,  # Assuming common feature dimension
            num_heads=4,
            batch_first=True
        )

    def forward(self, inputs: torch.Tensor, hard_targets: Optional[torch.Tensor] = None,
                return_teacher_outputs: bool = False) -> Dict[str, torch.Tensor]:
        """
        Forward pass with knowledge distillation

        Args:
            inputs: Input tensor
            hard_targets: Ground truth labels (optional)
            return_teacher_outputs: Whether to return individual teacher outputs

        Returns:
            Dictionary with student predictions, distillation loss, and optional teacher outputs
        """

        # Get teacher predictions
        teacher_outputs = []
        with torch.no_grad():
            for teacher in self.teacher_models:
                teacher_out = teacher(inputs)
                if isinstance(teacher_out, dict):
                    teacher_outputs.append(teacher_out['vulnerability'])
                else:
                    teacher_outputs.append(teacher_out)

        # Student prediction
        student_output = self.student_model(inputs)
        if isinstance(student_output, dict):
            student_logits = student_output['vulnerability']
        else:
            student_logits = student_output

        # Combine teacher predictions with attention
        if len(teacher_outputs) > 1:
            teacher_stack = torch.stack(teacher_outputs, dim=1)  # [batch, num_teachers, ...]

            # Use teacher attention to combine predictions
            attended_teachers, attention_weights = self.teacher_attention(
                teacher_stack, teacher_stack, teacher_stack
            )
            soft_targets = torch.mean(attended_teachers, dim=1)
        else:
            soft_targets = teacher_outputs[0]
            attention_weights = None

        # Distillation loss
        soft_student = F.log_softmax(student_logits / self.temperature, dim=-1)
        soft_teacher = F.softmax(soft_targets / self.temperature, dim=-1)

        distillation_loss = F.kl_div(
            soft_student, soft_teacher, reduction='batchmean'
        ) * (self.temperature ** 2)

        # Combine with hard target loss if available
        total_loss = distillation_loss
        if hard_targets is not None:
            hard_loss = F.cross_entropy(student_logits, hard_targets)
            total_loss = self.alpha * distillation_loss + (1 - self.alpha) * hard_loss

        result = {
            'student_logits': student_logits,
            'soft_targets': soft_targets,
            'distillation_loss': distillation_loss,
            'total_loss': total_loss
        }

        if return_teacher_outputs:
            result['teacher_outputs'] = teacher_outputs
            result['teacher_attention'] = attention_weights

        return result


class DynamicModelSelector(nn.Module):
    """Dynamic model selection based on input characteristics"""

    def __init__(self, models: List[nn.Module], input_dim: int):
        super().__init__()
        self.models = nn.ModuleList(models)
        self.num_models = len(models)

        # Input complexity analyzer
        self.complexity_analyzer = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()  # Complexity score 0-1
        )

        # Model selector network
        self.selector_network = nn.Sequential(
            nn.Linear(input_dim + 1, 128),  # +1 for complexity score
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, self.num_models),
            nn.Softmax(dim=-1)
        )

        # Performance tracker for each model
        self.register_buffer('model_performance', torch.ones(self.num_models))
        self.register_buffer('usage_count', torch.ones(self.num_models))

    def update_performance(self, model_idx: int, performance: float):
        """Update model performance tracking"""
        self.usage_count[model_idx] += 1
        # Exponential moving average
        alpha = 0.1
        self.model_performance[model_idx] = (
            (1 - alpha) * self.model_performance[model_idx] +
            alpha * performance
        )

    def forward(self, inputs: torch.Tensor,
                selection_mode: str = 'dynamic') -> Dict[str, torch.Tensor]:
        """
        Forward pass with dynamic model selection

        Args:
            inputs: Input tensor
            selection_mode: 'dynamic', 'ensemble', or 'best'

        Returns:
            Dictionary with selected model outputs and selection probabilities
        """

        if selection_mode == 'ensemble':
            # Use all models
            all_outputs = []
            for model in self.models:
                output = model(inputs)
                if isinstance(output, dict):
                    all_outputs.append(output['vulnerability'])
                else:
                    all_outputs.append(output)

            # Simple averaging for ensemble
            ensemble_output = torch.stack(all_outputs).mean(dim=0)
            selection_probs = torch.ones(inputs.size(0), self.num_models) / self.num_models

            return {
                'output': ensemble_output,
                'selection_probabilities': selection_probs,
                'all_outputs': all_outputs
            }

        elif selection_mode == 'best':
            # Always use the best performing model
            best_model_idx = torch.argmax(self.model_performance).item()
            selected_output = self.models[best_model_idx](inputs)

            if isinstance(selected_output, dict):
                selected_output = selected_output['vulnerability']

            selection_probs = torch.zeros(inputs.size(0), self.num_models)
            selection_probs[:, best_model_idx] = 1.0

            return {
                'output': selected_output,
                'selection_probabilities': selection_probs,
                'selected_model': best_model_idx
            }

        else:  # dynamic selection
            # Analyze input complexity
            complexity_score = self.complexity_analyzer(inputs)

            # Combine input features and complexity for selection
            selector_input = torch.cat([inputs, complexity_score], dim=-1)
            selection_probs = self.selector_network(selector_input)

            # Adjust probabilities based on historical performance
            performance_weights = self.model_performance / torch.sum(self.model_performance)
            adjusted_probs = selection_probs * performance_weights.unsqueeze(0)
            adjusted_probs = adjusted_probs / torch.sum(adjusted_probs, dim=-1, keepdim=True)

            # Get outputs from all models
            all_outputs = []
            for model in self.models:
                output = model(inputs)
                if isinstance(output, dict):
                    all_outputs.append(output['vulnerability'])
                else:
                    all_outputs.append(output)

            # Weighted combination based on selection probabilities
            stacked_outputs = torch.stack(all_outputs, dim=1)  # [batch, models, ...]
            weighted_output = torch.sum(
                adjusted_probs.unsqueeze(-1) * stacked_outputs,
                dim=1
            )

            return {
                'output': weighted_output,
                'selection_probabilities': adjusted_probs,
                'complexity_scores': complexity_score,
                'all_outputs': all_outputs
            }


class AdvancedEnsembleVulnDetector(nn.Module):
    """Advanced ensemble vulnerability detector with multiple sophisticated techniques"""

    def __init__(self, config: Dict):
        super().__init__()
        self.config = config
        self.num_classes = config.get('num_classes', 25)

        # Initialize base models
        self.models = self._initialize_models(config)
        self.num_models = len(self.models)

        # Uncertainty quantification for each model
        self.uncertainty_modules = nn.ModuleList([
            UncertaintyQuantification(model, num_samples=config.get('mc_samples', 10))
            for model in self.models
        ])

        # Adaptive weighting
        self.adaptive_weights = AdaptiveWeightingModule(
            num_models=self.num_models,
            input_dim=config.get('input_feature_dim', 256),
            context_dim=config.get('context_dim', 64)
        )

        # Dynamic model selection
        self.dynamic_selector = DynamicModelSelector(
            models=self.models,
            input_dim=config.get('input_feature_dim', 256)
        )

        # Knowledge distillation (teacher models are the larger ones)
        teacher_models = [self.models[0], self.models[1]]  # Assuming first two are larger
        student_model = self.models[-1]  # Assuming last one is smaller/faster
        self.distillation_module = KnowledgeDistillationModule(
            teacher_models=teacher_models,
            student_model=student_model,
            temperature=config.get('distillation_temp', 4.0),
            alpha=config.get('distillation_alpha', 0.7)
        )

        # Meta-learning components
        self.meta_features_extractor = nn.Sequential(
            nn.Linear(self.num_models * 3, 128),  # 3 outputs per model (vuln, type, severity)
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64)
        )

        # Final ensemble heads
        self.ensemble_vulnerability = nn.Linear(64, 1)
        self.ensemble_type = nn.Linear(64, self.num_classes)
        self.ensemble_severity = nn.Sequential(
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

        # Calibration network for confidence scores
        self.calibration_net = nn.Sequential(
            nn.Linear(64 + 1, 32),  # +1 for initial confidence
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def _initialize_models(self, config: Dict) -> List[nn.Module]:
        """Initialize the base models for the ensemble"""
        models = []

        # Multi-scale Transformer (large model)
        transformer_config = config.copy()
        transformer_config.update({
            'd_model': 512,
            'num_layers': 8,
            'num_heads': 16
        })
        models.append(MultiScaleTransformerVulnDetector(transformer_config))

        # Graph Neural Network model
        graph_config = config.copy()
        graph_config.update({
            'hidden_dim': 256,
            'ast_node_dim': 128,
            'ast_edge_dim': 64,
            'cfg_node_dim': 64,
            'dfg_node_dim': 64
        })
        models.append(MultiGraphVulnDetector(graph_config))

        # Enhanced traditional model
        enhanced_config = config.copy()
        models.append(EnhancedVulnDetector(enhanced_config))

        # Simple fast model (for speed/efficiency)
        simple_config = config.copy()
        models.append(SimpleVulnDetector(simple_config))

        return models

    def forward(self,
                input_ids: torch.Tensor,
                attention_mask: Optional[torch.Tensor] = None,
                graph_data: Optional[Dict] = None,
                mode: str = 'ensemble',
                return_uncertainty: bool = False,
                return_attention: bool = False) -> Dict[str, torch.Tensor]:
        """
        Forward pass of the advanced ensemble

        Args:
            input_ids: Token IDs for transformer models
            attention_mask: Attention mask
            graph_data: Graph data for GNN models
            mode: 'ensemble', 'dynamic', 'distillation', or 'uncertainty'
            return_uncertainty: Whether to return uncertainty estimates
            return_attention: Whether to return attention weights

        Returns:
            Dictionary with ensemble predictions and optional additional information
        """

        batch_size = input_ids.size(0)

        if mode == 'distillation':
            # Knowledge distillation mode
            return self.distillation_module(input_ids, return_teacher_outputs=True)

        # Get predictions from all models
        model_outputs = []
        uncertainty_outputs = []

        for i, model in enumerate(self.models):
            try:
                if i == 1 and graph_data is not None:  # Graph model
                    output = model(**graph_data)
                else:  # Transformer and traditional models
                    output = model(input_ids=input_ids, attention_mask=attention_mask)

                model_outputs.append(output)

                # Uncertainty quantification if requested
                if return_uncertainty:
                    uncertainty_out = self.uncertainty_modules[i](
                        input_ids=input_ids, attention_mask=attention_mask
                    )
                    uncertainty_outputs.append(uncertainty_out)

            except Exception as e:
                print(f"Warning: Model {i} failed: {e}")
                # Create dummy output with correct shape
                dummy_output = {
                    'vulnerability': torch.zeros(batch_size),
                    'vuln_type': torch.zeros(batch_size, self.num_classes),
                    'severity': torch.zeros(batch_size)
                }
                model_outputs.append(dummy_output)

        if mode == 'dynamic':
            # Dynamic model selection
            # Use mean features as input representation
            input_features = torch.mean(input_ids.float(), dim=-1)  # Simplified feature extraction
            return self.dynamic_selector(input_features, selection_mode='dynamic')

        # Extract predictions for ensemble combination
        vuln_predictions = [out['vulnerability'] for out in model_outputs]
        type_predictions = [out['vuln_type'] for out in model_outputs]
        severity_predictions = [out['severity'] for out in model_outputs]

        # Adaptive weighting ensemble
        input_features = torch.mean(input_ids.float(), dim=-1)  # Simplified

        # Combine vulnerability predictions
        vuln_ensemble, vuln_weights = self.adaptive_weights(
            vuln_predictions, input_features
        )

        # Combine type predictions (take argmax first, then combine)
        type_probs = [F.softmax(pred, dim=-1) for pred in type_predictions]
        type_ensemble, type_weights = self.adaptive_weights(
            type_probs, input_features
        )

        # Combine severity predictions
        severity_ensemble, severity_weights = self.adaptive_weights(
            severity_predictions, input_features
        )

        # Meta-learning: extract features from all predictions
        all_predictions = torch.cat([
            vuln_ensemble.unsqueeze(-1),
            torch.argmax(type_ensemble, dim=-1, keepdim=True).float(),
            severity_ensemble.unsqueeze(-1)
        ], dim=-1)  # [batch, 3]

        # Expand to include all models' predictions
        meta_input = torch.cat([
            torch.stack(vuln_predictions, dim=1),
            torch.stack([torch.argmax(pred, dim=-1).float() for pred in type_predictions], dim=1),
            torch.stack(severity_predictions, dim=1)
        ], dim=-1)  # [batch, num_models * 3]

        meta_features = self.meta_features_extractor(meta_input)

        # Final ensemble predictions
        final_vulnerability = self.ensemble_vulnerability(meta_features).squeeze(-1)
        final_type = self.ensemble_type(meta_features)
        final_severity = self.ensemble_severity(meta_features).squeeze(-1)

        # Confidence calibration
        base_confidence = torch.sigmoid(final_vulnerability)
        calibrated_confidence = self.calibration_net(
            torch.cat([meta_features, base_confidence.unsqueeze(-1)], dim=-1)
        ).squeeze(-1)

        # Prepare output
        outputs = {
            'vulnerability': final_vulnerability,
            'vuln_type': final_type,
            'severity': final_severity,
            'confidence': calibrated_confidence,
            'ensemble_weights': {
                'vulnerability': vuln_weights,
                'type': type_weights,
                'severity': severity_weights
            },
            'individual_predictions': {
                'vulnerability': vuln_predictions,
                'type': type_predictions,
                'severity': severity_predictions
            }
        }

        # Add uncertainty information if requested
        if return_uncertainty and uncertainty_outputs:
            uncertainty_info = {}
            for i, unc_out in enumerate(uncertainty_outputs):
                uncertainty_info[f'model_{i}'] = unc_out
            outputs['uncertainty'] = uncertainty_info

        # Add attention weights if requested
        if return_attention:
            attention_weights = {}
            for i, model_out in enumerate(model_outputs):
                if 'attention_weights' in model_out:
                    attention_weights[f'model_{i}'] = model_out['attention_weights']
            if attention_weights:
                outputs['attention_weights'] = attention_weights

        return outputs

    def update_model_performance(self, model_predictions: List[torch.Tensor],
                                true_labels: torch.Tensor):
        """Update model performance tracking for dynamic selection"""
        for i, pred in enumerate(model_predictions):
            accuracy = torch.mean((pred > 0.5).float() == true_labels.float()).item()
            self.dynamic_selector.update_performance(i, accuracy)


def test_ensemble_models():
    """Test the ensemble models"""
    print("Testing Advanced Ensemble Models...")

    config = {
        'vocab_size': 50265,
        'max_sequence_length': 256,
        'num_classes': 25,
        'd_model': 256,  # Smaller for testing
        'num_layers': 2,
        'num_heads': 4,
        'hidden_dim': 128,
        'input_feature_dim': 256,
        'context_dim': 64,
        'mc_samples': 5,
        'distillation_temp': 4.0,
        'distillation_alpha': 0.7
    }

    # Create model
    ensemble_model = AdvancedEnsembleVulnDetector(config)

    # Create sample inputs
    batch_size = 4
    seq_len = 256

    input_ids = torch.randint(0, config['vocab_size'], (batch_size, seq_len))
    attention_mask = torch.ones(batch_size, seq_len)

    print(f"Input shape: {input_ids.shape}")

    # Test different modes
    modes_to_test = ['ensemble', 'dynamic', 'distillation']

    for mode in modes_to_test:
        print(f"\nTesting mode: {mode}")

        with torch.no_grad():
            if mode == 'distillation':
                outputs = ensemble_model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    mode=mode
                )
            else:
                outputs = ensemble_model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    mode=mode,
                    return_uncertainty=(mode == 'ensemble'),
                    return_attention=True
                )

        print("  Output keys:", list(outputs.keys()))

        for key, value in outputs.items():
            if isinstance(value, torch.Tensor):
                print(f"    {key}: {value.shape}")
            elif isinstance(value, dict):
                print(f"    {key}: {len(value)} items")

    # Count parameters
    num_params = sum(p.numel() for p in ensemble_model.parameters() if p.requires_grad)
    print(f"\nTotal ensemble parameters: {num_params:,}")

    print("\nAdvanced ensemble test completed successfully!")


if __name__ == "__main__":
    test_ensemble_models()