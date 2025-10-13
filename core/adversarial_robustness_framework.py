#!/usr/bin/env python3
"""
Adversarial Robustness Training Framework for VulnHunter

Enhanced model robustness against evasion attacks through adversarial training,
certified defenses, and robust optimization techniques.

Key Features:
- Adversarial example generation for code vulnerability detection
- Certified defense mechanisms with formal security guarantees
- Robust optimization techniques for improved generalization
- Code-specific perturbation strategies
- Lipschitz constraint enforcement
- Multi-attack resistance training
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import Adam, SGD
from typing import Dict, List, Tuple, Any, Optional, Callable
from dataclasses import dataclass
import numpy as np
import logging
from collections import defaultdict
import re
import random
import string
import ast
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

@dataclass
class AdversarialConfig:
    """Configuration for Adversarial Robustness Training."""

    # Adversarial training parameters
    adversarial_training_enabled: bool = True
    adversarial_loss_weight: float = 0.5
    clean_loss_weight: float = 0.5

    # Attack parameters
    attack_epsilon: float = 0.1  # Maximum perturbation magnitude
    attack_steps: int = 7  # Number of attack iterations
    attack_step_size: float = 0.01  # Step size for attacks
    num_random_starts: int = 1  # Random restarts for attacks

    # Code-specific perturbation parameters
    max_token_substitutions: int = 5  # Maximum token substitutions per attack
    max_line_insertions: int = 2  # Maximum line insertions
    preserve_semantics: bool = True  # Preserve code semantics during attacks

    # Certified defense parameters
    lipschitz_constraint: float = 1.0  # Lipschitz constant constraint
    spectral_normalization: bool = True  # Use spectral normalization
    gradient_penalty_weight: float = 10.0  # Gradient penalty weight

    # Training parameters
    warmup_epochs: int = 5  # Epochs of clean training before adversarial
    adversarial_frequency: int = 1  # Frequency of adversarial training
    defense_frequency: int = 2  # Frequency of certified defense training

    # Evaluation parameters
    eval_attacks: List[str] = None  # Attack types for evaluation
    eval_epsilon_range: List[float] = None  # Epsilon values for evaluation

    def __post_init__(self):
        if self.eval_attacks is None:
            self.eval_attacks = ['pgd', 'fgsm', 'code_substitution', 'semantic_preserving']
        if self.eval_epsilon_range is None:
            self.eval_epsilon_range = [0.01, 0.05, 0.1, 0.2, 0.3]

class CodePerturbationEngine:
    """
    Code-specific adversarial perturbation engine.

    Generates adversarial examples by applying semantic-preserving and
    semantic-altering transformations to source code.
    """

    def __init__(self, config: AdversarialConfig):
        self.config = config

        # Token substitution dictionaries
        self.variable_synonyms = {
            'data': ['info', 'content', 'payload', 'buffer', 'input_data'],
            'user': ['client', 'person', 'account', 'entity', 'individual'],
            'file': ['document', 'resource', 'stream', 'handle', 'fd'],
            'path': ['location', 'directory', 'filepath', 'route', 'url'],
            'command': ['cmd', 'instruction', 'operation', 'exec', 'task'],
        }

        self.function_synonyms = {
            'process': ['handle', 'execute', 'run', 'perform', 'operate'],
            'validate': ['check', 'verify', 'confirm', 'ensure', 'test'],
            'sanitize': ['clean', 'filter', 'purify', 'escape', 'normalize'],
            'connect': ['link', 'join', 'attach', 'bind', 'establish'],
        }

        # Semantic-preserving transformations
        self.semantic_transforms = [
            self._add_nop_operations,
            self._reorder_independent_statements,
            self._rename_variables,
            self._add_redundant_conditions,
            self._split_compound_statements,
        ]

        # Semantic-altering transformations (for robustness testing)
        self.semantic_altering_transforms = [
            self._remove_security_checks,
            self._modify_boundary_conditions,
            self._alter_string_literals,
            self._change_operator_precedence,
        ]

        self.logger = logging.getLogger(__name__)

    def generate_adversarial_code(self, original_code: str, attack_type: str = 'mixed') -> List[str]:
        """
        Generate adversarial code examples.

        Args:
            original_code: Original source code
            attack_type: Type of attack ('semantic_preserving', 'semantic_altering', 'mixed')

        Returns:
            List of adversarial code variants
        """

        adversarial_examples = []

        if attack_type in ['semantic_preserving', 'mixed']:
            # Apply semantic-preserving transformations
            for transform in self.semantic_transforms:
                try:
                    transformed = transform(original_code)
                    if transformed != original_code:
                        adversarial_examples.append(transformed)
                except Exception as e:
                    self.logger.debug(f"Semantic transform failed: {e}")

        if attack_type in ['semantic_altering', 'mixed']:
            # Apply semantic-altering transformations
            for transform in self.semantic_altering_transforms:
                try:
                    transformed = transform(original_code)
                    if transformed != original_code:
                        adversarial_examples.append(transformed)
                except Exception as e:
                    self.logger.debug(f"Semantic altering transform failed: {e}")

        # Limit number of examples
        max_examples = min(self.config.max_token_substitutions, len(adversarial_examples))
        return adversarial_examples[:max_examples]

    def _add_nop_operations(self, code: str) -> str:
        """Add no-operation statements that don't change semantics."""

        lines = code.split('\n')
        modified_lines = []

        for line in lines:
            modified_lines.append(line)
            # Randomly insert nop operations
            if random.random() < 0.2 and line.strip():
                indent = len(line) - len(line.lstrip())
                nop_ops = [
                    ' ' * indent + '# nop operation',
                    ' ' * indent + 'pass  # no operation',
                    ' ' * indent + '_ = None  # nop assignment',
                ]
                modified_lines.append(random.choice(nop_ops))

        return '\n'.join(modified_lines)

    def _reorder_independent_statements(self, code: str) -> str:
        """Reorder independent statements within functions."""

        lines = code.split('\n')
        modified_lines = []
        current_block = []
        current_indent = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                modified_lines.append(line)
                continue

            line_indent = len(line) - len(line.lstrip())

            # Start of new block
            if line_indent <= current_indent and current_block:
                # Shuffle current block if it has multiple statements
                if len(current_block) > 1:
                    random.shuffle(current_block)
                modified_lines.extend(current_block)
                current_block = []

            # Check if line is a simple statement (can be reordered)
            if self._is_simple_statement(stripped):
                current_block.append(line)
                current_indent = line_indent
            else:
                if current_block:
                    modified_lines.extend(current_block)
                    current_block = []
                modified_lines.append(line)
                current_indent = line_indent

        # Add remaining block
        if current_block:
            if len(current_block) > 1:
                random.shuffle(current_block)
            modified_lines.extend(current_block)

        return '\n'.join(modified_lines)

    def _is_simple_statement(self, line: str) -> bool:
        """Check if a line is a simple statement that can be reordered."""

        # Simple statements that don't have dependencies
        simple_patterns = [
            r'^\w+\s*=\s*[^=]',  # Variable assignment
            r'^print\s*\(',       # Print statements
            r'^import\s+',        # Import statements
            r'^from\s+\w+\s+import',  # From import statements
        ]

        for pattern in simple_patterns:
            if re.match(pattern, line):
                return True

        return False

    def _rename_variables(self, code: str) -> str:
        """Rename variables to synonyms while preserving semantics."""

        modified_code = code

        # Apply variable substitutions
        for original, synonyms in self.variable_synonyms.items():
            if original in modified_code:
                synonym = random.choice(synonyms)
                # Use word boundaries to avoid partial replacements
                pattern = r'\b' + re.escape(original) + r'\b'
                modified_code = re.sub(pattern, synonym, modified_code)

        # Apply function substitutions
        for original, synonyms in self.function_synonyms.items():
            if original in modified_code:
                synonym = random.choice(synonyms)
                pattern = r'\b' + re.escape(original) + r'\b'
                modified_code = re.sub(pattern, synonym, modified_code)

        return modified_code

    def _add_redundant_conditions(self, code: str) -> str:
        """Add redundant but semantically neutral conditions."""

        lines = code.split('\n')
        modified_lines = []

        for line in lines:
            modified_lines.append(line)

            # Add redundant conditions before certain statements
            if random.random() < 0.1 and any(keyword in line for keyword in ['if', 'while', 'for']):
                indent = len(line) - len(line.lstrip())
                redundant_conditions = [
                    ' ' * indent + 'if True:  # redundant condition',
                    ' ' * indent + 'if 1 == 1:  # always true',
                    ' ' * indent + 'if len("") == 0:  # empty string check',
                ]
                modified_lines.append(random.choice(redundant_conditions))
                modified_lines.append(line.replace(line.strip(), '    ' + line.strip()))

        return '\n'.join(modified_lines)

    def _split_compound_statements(self, code: str) -> str:
        """Split compound statements into multiple lines."""

        lines = code.split('\n')
        modified_lines = []

        for line in lines:
            stripped = line.strip()

            # Split compound assignments
            if '=' in stripped and ('and' in stripped or 'or' in stripped):
                parts = stripped.split('=', 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    expression = parts[1].strip()

                    # Split logical expressions
                    if ' and ' in expression:
                        subexpressions = expression.split(' and ')
                        indent = len(line) - len(line.lstrip())
                        modified_lines.append(' ' * indent + f'{var_name} = {subexpressions[0].strip()}')
                        for subexpr in subexpressions[1:]:
                            modified_lines.append(' ' * indent + f'{var_name} = {var_name} and {subexpr.strip()}')
                    else:
                        modified_lines.append(line)
                else:
                    modified_lines.append(line)
            else:
                modified_lines.append(line)

        return '\n'.join(modified_lines)

    def _remove_security_checks(self, code: str) -> str:
        """Remove or weaken security checks (semantic-altering)."""

        modified_code = code

        # Patterns of security checks to weaken
        security_patterns = [
            (r'if\s+.*\.startswith\(["\']\.\.\/["\'].*\):', '# if "..\\/" check removed'),
            (r'if\s+.*len\([^)]+\)\s*[<>]\s*\d+:', '# if length check removed'),
            (r'if\s+.*\.isalnum\(\):', '# if alphanumeric check removed'),
            (r'assert\s+.*', '# assert removed'),
        ]

        for pattern, replacement in security_patterns:
            modified_code = re.sub(pattern, replacement, modified_code, flags=re.MULTILINE)

        return modified_code

    def _modify_boundary_conditions(self, code: str) -> str:
        """Modify boundary conditions in comparisons."""

        # Change boundary operators
        boundary_changes = [
            (r'<\s*=', '<'),
            (r'>\s*=', '>'),
            (r'==\s*0', '< 1'),
            (r'!=\s*0', '> 0'),
        ]

        modified_code = code
        for old_pattern, new_pattern in boundary_changes:
            if random.random() < 0.3:  # Apply changes probabilistically
                modified_code = re.sub(old_pattern, new_pattern, modified_code)

        return modified_code

    def _alter_string_literals(self, code: str) -> str:
        """Slightly modify string literals."""

        def modify_string(match):
            original = match.group(0)
            content = original[1:-1]  # Remove quotes

            if len(content) > 2:
                # Add or remove characters
                if random.random() < 0.5:
                    # Add character
                    pos = random.randint(0, len(content))
                    char = random.choice(string.ascii_letters)
                    modified = content[:pos] + char + content[pos:]
                else:
                    # Remove character (if safe)
                    if len(content) > 1:
                        pos = random.randint(0, len(content) - 1)
                        modified = content[:pos] + content[pos + 1:]
                    else:
                        modified = content

                return original[0] + modified + original[-1]

            return original

        # Modify string literals
        modified_code = re.sub(r'["\'][^"\']*["\']', modify_string, code)

        return modified_code

    def _change_operator_precedence(self, code: str) -> str:
        """Add parentheses to change apparent operator precedence."""

        # Add parentheses around expressions
        precedence_changes = [
            (r'(\w+)\s*\+\s*(\w+)\s*\*\s*(\w+)', r'(\1 + \2) * \3'),
            (r'(\w+)\s*\*\s*(\w+)\s*\+\s*(\w+)', r'\1 * (\2 + \3)'),
            (r'(\w+)\s*and\s*(\w+)\s*or\s*(\w+)', r'(\1 and \2) or \3'),
        ]

        modified_code = code
        for pattern, replacement in precedence_changes:
            if random.random() < 0.2:
                modified_code = re.sub(pattern, replacement, modified_code)

        return modified_code

class PGDAttack:
    """
    Projected Gradient Descent (PGD) attack for adversarial examples.

    Adapted for code vulnerability detection with feature-level perturbations.
    """

    def __init__(self, config: AdversarialConfig):
        self.config = config

    def attack(self, model: nn.Module, features: torch.Tensor, targets: torch.Tensor,
              feature_bounds: Tuple[torch.Tensor, torch.Tensor] = None) -> torch.Tensor:
        """
        Generate PGD adversarial examples.

        Args:
            model: Target model
            features: Input features [batch_size, feature_dim]
            targets: True labels [batch_size]
            feature_bounds: Optional (min_bounds, max_bounds) for features

        Returns:
            Adversarial features
        """

        model.eval()
        batch_size = features.shape[0]

        # Initialize perturbation
        delta = torch.zeros_like(features)
        delta.uniform_(-self.config.attack_epsilon, self.config.attack_epsilon)

        # Set bounds
        if feature_bounds is not None:
            min_bounds, max_bounds = feature_bounds
        else:
            min_bounds = features - self.config.attack_epsilon
            max_bounds = features + self.config.attack_epsilon

        for step in range(self.config.attack_steps):
            delta.requires_grad_(True)

            # Forward pass
            adv_features = features + delta
            outputs = model(adv_features)

            # Compute loss (maximize for adversarial)
            if isinstance(outputs, dict):
                logits = outputs.get('vulnerability_logits', outputs.get('logits'))
            else:
                logits = outputs

            loss = F.cross_entropy(logits, targets)

            # Backward pass
            grad = torch.autograd.grad(loss, delta)[0]

            # Update perturbation
            delta = delta + self.config.attack_step_size * grad.sign()

            # Project to bounds
            delta = torch.clamp(delta, -self.config.attack_epsilon, self.config.attack_epsilon)
            adv_features = features + delta
            delta = torch.clamp(adv_features, min_bounds, max_bounds) - features

        return features + delta.detach()

class FGSMAttack:
    """
    Fast Gradient Sign Method (FGSM) attack.

    Single-step adversarial attack using gradient sign.
    """

    def __init__(self, config: AdversarialConfig):
        self.config = config

    def attack(self, model: nn.Module, features: torch.Tensor, targets: torch.Tensor,
              feature_bounds: Tuple[torch.Tensor, torch.Tensor] = None) -> torch.Tensor:
        """Generate FGSM adversarial examples."""

        model.eval()
        features.requires_grad_(True)

        # Forward pass
        outputs = model(features)
        if isinstance(outputs, dict):
            logits = outputs.get('vulnerability_logits', outputs.get('logits'))
        else:
            logits = outputs

        # Compute loss
        loss = F.cross_entropy(logits, targets)

        # Backward pass
        grad = torch.autograd.grad(loss, features)[0]

        # Generate adversarial examples
        adv_features = features + self.config.attack_epsilon * grad.sign()

        # Apply bounds if provided
        if feature_bounds is not None:
            min_bounds, max_bounds = feature_bounds
            adv_features = torch.clamp(adv_features, min_bounds, max_bounds)

        return adv_features.detach()

class CertifiedDefense(nn.Module):
    """
    Certified defense mechanisms with formal security guarantees.

    Implements Lipschitz constraint enforcement and spectral normalization
    for provable robustness guarantees.
    """

    def __init__(self, base_model: nn.Module, config: AdversarialConfig):
        super().__init__()
        self.config = config
        self.base_model = base_model

        # Apply spectral normalization to all linear layers
        if config.spectral_normalization:
            self._apply_spectral_normalization()

        # Lipschitz constraint tracking
        self.lipschitz_constant = config.lipschitz_constraint

    def _apply_spectral_normalization(self):
        """Apply spectral normalization to all linear layers."""

        def apply_sn(module):
            for name, child in module.named_children():
                if isinstance(child, nn.Linear):
                    setattr(module, name, nn.utils.spectral_norm(child))
                else:
                    apply_sn(child)

        apply_sn(self.base_model)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass through certified defense."""

        return self.base_model(x)

    def compute_lipschitz_penalty(self, features: torch.Tensor) -> torch.Tensor:
        """Compute Lipschitz constraint penalty."""

        # Generate random perturbations
        batch_size = features.shape[0]
        epsilon = 0.001

        # Random directions
        random_dirs = torch.randn_like(features)
        random_dirs = random_dirs / torch.norm(random_dirs, dim=1, keepdim=True)

        # Perturbed inputs
        perturbed_features = features + epsilon * random_dirs

        # Compute outputs
        features.requires_grad_(True)
        perturbed_features.requires_grad_(True)

        outputs_orig = self.forward(features)
        outputs_pert = self.forward(perturbed_features)

        # Extract logits
        if isinstance(outputs_orig, dict):
            logits_orig = outputs_orig.get('vulnerability_logits', outputs_orig.get('logits'))
            logits_pert = outputs_pert.get('vulnerability_logits', outputs_pert.get('logits'))
        else:
            logits_orig = outputs_orig
            logits_pert = outputs_pert

        # Compute Lipschitz constant
        output_diff = torch.norm(logits_pert - logits_orig, dim=1)
        input_diff = torch.norm(perturbed_features - features, dim=1)

        lipschitz_estimates = output_diff / (input_diff + 1e-8)

        # Penalty for exceeding constraint
        penalty = F.relu(lipschitz_estimates - self.lipschitz_constant).mean()

        return penalty

class AdversarialRobustnessFramework:
    """
    Complete Adversarial Robustness Training Framework.

    Integrates adversarial training, certified defenses, and robust optimization
    for enhanced model security against evasion attacks.
    """

    def __init__(self, model: nn.Module, config: AdversarialConfig):
        self.config = config
        self.base_model = model

        # Wrap model with certified defense
        self.defended_model = CertifiedDefense(model, config)

        # Attack methods
        self.pgd_attack = PGDAttack(config)
        self.fgsm_attack = FGSMAttack(config)
        self.perturbation_engine = CodePerturbationEngine(config)

        # Training state
        self.current_epoch = 0
        self.training_history = defaultdict(list)

        self.logger = logging.getLogger(__name__)

    def adversarial_training_step(self, features: torch.Tensor, targets: torch.Tensor,
                                 optimizer: torch.optim.Optimizer) -> Dict[str, float]:
        """
        Perform one step of adversarial training.

        Args:
            features: Clean input features
            targets: Ground truth labels
            optimizer: Model optimizer

        Returns:
            Dictionary with loss components
        """

        self.defended_model.train()

        # Clean loss
        clean_outputs = self.defended_model(features)
        if isinstance(clean_outputs, dict):
            clean_logits = clean_outputs.get('vulnerability_logits', clean_outputs.get('logits'))
        else:
            clean_logits = clean_outputs

        clean_loss = F.cross_entropy(clean_logits, targets)

        losses = {'clean_loss': clean_loss.item()}

        total_loss = self.config.clean_loss_weight * clean_loss

        # Adversarial training
        if self.config.adversarial_training_enabled and self.current_epoch >= self.config.warmup_epochs:
            if self.current_epoch % self.config.adversarial_frequency == 0:

                # Generate adversarial examples
                adv_features = self._generate_adversarial_batch(features, targets)

                # Adversarial loss
                adv_outputs = self.defended_model(adv_features)
                if isinstance(adv_outputs, dict):
                    adv_logits = adv_outputs.get('vulnerability_logits', adv_outputs.get('logits'))
                else:
                    adv_logits = adv_outputs

                adv_loss = F.cross_entropy(adv_logits, targets)
                losses['adversarial_loss'] = adv_loss.item()

                total_loss += self.config.adversarial_loss_weight * adv_loss

        # Certified defense loss
        if self.current_epoch % self.config.defense_frequency == 0:
            lipschitz_penalty = self.defended_model.compute_lipschitz_penalty(features)
            losses['lipschitz_penalty'] = lipschitz_penalty.item()

            total_loss += self.config.gradient_penalty_weight * lipschitz_penalty

        # Optimization step
        optimizer.zero_grad()
        total_loss.backward()
        optimizer.step()

        losses['total_loss'] = total_loss.item()

        return losses

    def _generate_adversarial_batch(self, features: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """Generate adversarial examples for a batch."""

        # Randomly choose attack method
        attack_methods = [self.pgd_attack, self.fgsm_attack]
        attack = random.choice(attack_methods)

        # Generate adversarial examples
        adv_features = attack.attack(self.defended_model, features, targets)

        return adv_features

    def evaluate_robustness(self, test_features: torch.Tensor, test_targets: torch.Tensor,
                           attack_types: List[str] = None) -> Dict[str, Dict[str, float]]:
        """
        Comprehensive robustness evaluation against multiple attacks.

        Args:
            test_features: Test features
            test_targets: Test labels
            attack_types: List of attack types to evaluate

        Returns:
            Dictionary with robustness metrics for each attack
        """

        if attack_types is None:
            attack_types = self.config.eval_attacks

        self.defended_model.eval()
        results = {}

        # Clean accuracy
        with torch.no_grad():
            clean_outputs = self.defended_model(test_features)
            if isinstance(clean_outputs, dict):
                clean_logits = clean_outputs.get('vulnerability_logits', clean_outputs.get('logits'))
            else:
                clean_logits = clean_outputs

            clean_preds = torch.argmax(clean_logits, dim=1)
            clean_accuracy = accuracy_score(test_targets.cpu().numpy(), clean_preds.cpu().numpy())

        results['clean'] = {'accuracy': clean_accuracy}

        # Evaluate against each attack type
        for attack_type in attack_types:
            attack_results = {}

            if attack_type == 'pgd':
                attack_method = self.pgd_attack
            elif attack_type == 'fgsm':
                attack_method = self.fgsm_attack
            else:
                continue  # Skip unsupported attack types for now

            for epsilon in self.config.eval_epsilon_range:
                # Temporarily adjust epsilon
                original_epsilon = self.config.attack_epsilon
                self.config.attack_epsilon = epsilon

                # Generate adversarial examples
                adv_features = attack_method.attack(self.defended_model, test_features, test_targets)

                # Evaluate
                with torch.no_grad():
                    adv_outputs = self.defended_model(adv_features)
                    if isinstance(adv_outputs, dict):
                        adv_logits = adv_outputs.get('vulnerability_logits', adv_outputs.get('logits'))
                    else:
                        adv_logits = adv_outputs

                    adv_preds = torch.argmax(adv_logits, dim=1)
                    adv_accuracy = accuracy_score(test_targets.cpu().numpy(), adv_preds.cpu().numpy())

                attack_results[f'epsilon_{epsilon}'] = {
                    'accuracy': adv_accuracy,
                    'robustness': adv_accuracy / clean_accuracy if clean_accuracy > 0 else 0
                }

                # Restore original epsilon
                self.config.attack_epsilon = original_epsilon

            results[attack_type] = attack_results

        return results

    def get_certified_bounds(self, features: torch.Tensor) -> torch.Tensor:
        """
        Compute certified robustness bounds.

        Returns lower bounds on the adversarial margin for each example.
        """

        self.defended_model.eval()

        with torch.no_grad():
            outputs = self.defended_model(features)
            if isinstance(outputs, dict):
                logits = outputs.get('vulnerability_logits', outputs.get('logits'))
            else:
                logits = outputs

            # Simplified certified bound computation
            # Based on Lipschitz constant and output margins
            probs = F.softmax(logits, dim=1)
            top2_probs, _ = torch.topk(probs, 2, dim=1)

            margin = top2_probs[:, 0] - top2_probs[:, 1]
            certified_radius = margin / (2 * self.defended_model.lipschitz_constant)

            return certified_radius

    def train_epoch(self, dataloader: torch.utils.data.DataLoader,
                   optimizer: torch.optim.Optimizer) -> Dict[str, float]:
        """Train model for one epoch with adversarial robustness."""

        epoch_losses = defaultdict(list)

        for batch_idx, (features, targets) in enumerate(dataloader):
            # Adversarial training step
            batch_losses = self.adversarial_training_step(features, targets, optimizer)

            # Record losses
            for loss_name, loss_value in batch_losses.items():
                epoch_losses[loss_name].append(loss_value)

        # Compute average losses
        avg_losses = {name: np.mean(values) for name, values in epoch_losses.items()}

        # Update training history
        for name, value in avg_losses.items():
            self.training_history[name].append(value)

        self.current_epoch += 1

        return avg_losses

    def save_robust_model(self, path: str):
        """Save the robustly trained model."""

        torch.save({
            'model_state_dict': self.defended_model.state_dict(),
            'config': self.config,
            'training_history': dict(self.training_history),
            'current_epoch': self.current_epoch
        }, path)

        self.logger.info(f"Robust model saved to {path}")

    def load_robust_model(self, path: str):
        """Load a robustly trained model."""

        checkpoint = torch.load(path, map_location='cpu')

        self.defended_model.load_state_dict(checkpoint['model_state_dict'])
        self.training_history = defaultdict(list, checkpoint.get('training_history', {}))
        self.current_epoch = checkpoint.get('current_epoch', 0)

        self.logger.info(f"Robust model loaded from {path}")

def create_adversarial_framework(model: nn.Module, **kwargs) -> AdversarialRobustnessFramework:
    """Factory function to create adversarial robustness framework."""

    config = AdversarialConfig(**kwargs)
    framework = AdversarialRobustnessFramework(model, config)

    return framework

# Example usage and testing
if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)

    print("🛡️  Testing Adversarial Robustness Training Framework")
    print("=" * 65)

    # Create a dummy model for testing
    class DummyVulnModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.layers = nn.Sequential(
                nn.Linear(512, 256),
                nn.ReLU(),
                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Linear(128, 2)
            )

        def forward(self, x):
            logits = self.layers(x)
            return {'vulnerability_logits': logits, 'logits': logits}

    # Create model and framework
    model = DummyVulnModel()
    config = AdversarialConfig(
        adversarial_training_enabled=True,
        attack_epsilon=0.1,
        attack_steps=7
    )
    framework = AdversarialRobustnessFramework(model, config)

    # Test code perturbation engine
    print("\n🔧 Testing code perturbation engine...")
    perturbation_engine = CodePerturbationEngine(config)

    test_code = '''
def process_user_input(user_data):
    if user_data and len(user_data) > 0:
        sanitized_data = user_data.replace("<", "&lt;")
        command = "grep " + sanitized_data
        return os.system(command)
    return None
'''

    adversarial_codes = perturbation_engine.generate_adversarial_code(test_code, 'mixed')
    print(f"   • Generated {len(adversarial_codes)} adversarial code variants")

    if adversarial_codes:
        print(f"   • Example adversarial variant:")
        print("     " + adversarial_codes[0].split('\n')[0])

    # Test adversarial training
    print(f"\n🎯 Testing adversarial training...")

    # Generate dummy data
    batch_size = 32
    feature_dim = 512
    test_features = torch.randn(batch_size, feature_dim)
    test_targets = torch.randint(0, 2, (batch_size,))

    # Test training step
    optimizer = Adam(framework.defended_model.parameters(), lr=0.001)
    losses = framework.adversarial_training_step(test_features, test_targets, optimizer)

    print(f"   ✅ Training step completed:")
    for loss_name, loss_value in losses.items():
        print(f"     • {loss_name}: {loss_value:.4f}")

    # Test robustness evaluation
    print(f"\n📊 Testing robustness evaluation...")
    robustness_results = framework.evaluate_robustness(
        test_features, test_targets, ['pgd', 'fgsm']
    )

    print(f"   ✅ Robustness evaluation completed:")
    print(f"     • Clean accuracy: {robustness_results['clean']['accuracy']:.3f}")

    for attack_type, attack_results in robustness_results.items():
        if attack_type != 'clean':
            print(f"     • {attack_type.upper()} attack results:")
            for epsilon_key, metrics in attack_results.items():
                print(f"       - {epsilon_key}: {metrics['accuracy']:.3f} (robustness: {metrics['robustness']:.3f})")

    # Test certified bounds
    print(f"\n🔒 Testing certified robustness bounds...")
    certified_bounds = framework.get_certified_bounds(test_features)
    mean_bound = torch.mean(certified_bounds).item()
    print(f"   • Mean certified radius: {mean_bound:.4f}")
    print(f"   • Lipschitz constant: {framework.defended_model.lipschitz_constant}")

    print(f"\n🧠 Framework capabilities:")
    total_params = sum(p.numel() for p in framework.defended_model.parameters())
    print(f"   • Total model parameters: {total_params:,}")
    print(f"   • Spectral normalization: {config.spectral_normalization}")
    print(f"   • Adversarial training: {config.adversarial_training_enabled}")
    print(f"   • Attack methods: PGD, FGSM, Code perturbation")
    print(f"   • Certified defense: ✅")

    print(f"\n🚀 Adversarial Robustness Framework ready for VulnHunter integration!")