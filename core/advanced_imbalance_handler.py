#!/usr/bin/env python3
"""
VulnHunter Advanced Imbalance Handler
Comprehensive strategies for handling 91% vulnerable / 9% safe imbalance
"""

import numpy as np
import torch
from collections import Counter
from typing import Tuple, Dict, Optional
import logging

# Imbalanced-learn imports
try:
    from imblearn.over_sampling import SMOTE, ADASYN, BorderlineSMOTE, SVMSMOTE
    from imblearn.under_sampling import RandomUnderSampler, TomekLinks, EditedNearestNeighbours
    from imblearn.combine import SMOTETomek, SMOTEENN
    from imblearn.ensemble import BalancedRandomForestClassifier, EasyEnsembleClassifier
    IMBLEARN_AVAILABLE = True
except ImportError:
    IMBLEARN_AVAILABLE = False

from sklearn.utils.class_weight import compute_class_weight

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AdvancedImbalanceHandler:
    """
    Production-ready imbalance handler with multiple resampling strategies
    Optimized for 91% vulnerable (majority) vs 9% safe (minority) distribution
    """

    AVAILABLE_STRATEGIES = [
        'smote',              # Standard SMOTE
        'borderline_smote',   # Focus on decision boundary
        'adasyn',             # Adaptive synthetic sampling
        'smote_tomek',        # SMOTE + Tomek link removal
        'smote_enn',          # SMOTE + Edited Nearest Neighbors
        'svm_smote',          # SVM-based SMOTE
        'undersample',        # Random undersampling of majority
        'hybrid',             # Combined over/under sampling
        'tomek_links',        # Remove boundary examples
        'class_weights'       # No resampling, just compute weights
    ]

    def __init__(
        self,
        strategy: str = 'smote_tomek',
        target_ratio: float = 0.5,  # Make safe class 50% of vulnerable class
        random_state: int = 42
    ):
        """
        Args:
            strategy: Resampling strategy from AVAILABLE_STRATEGIES
            target_ratio: Target ratio of minority to majority class
            random_state: Random seed for reproducibility
        """
        if not IMBLEARN_AVAILABLE:
            logger.warning("⚠️  imbalanced-learn not installed. Install with: pip install imbalanced-learn")
            strategy = 'class_weights'

        if strategy not in self.AVAILABLE_STRATEGIES:
            raise ValueError(f"Unknown strategy: {strategy}. Choose from {self.AVAILABLE_STRATEGIES}")

        self.strategy = strategy
        self.target_ratio = target_ratio
        self.random_state = random_state
        self.sampler = None
        self.class_weights = None

        logger.info(f"ImbalanceHandler initialized with strategy: {strategy}")

    def balance_data(
        self,
        X: np.ndarray,
        y: np.ndarray,
        verbose: bool = True
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Apply selected balancing strategy

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,)
            verbose: Print distribution information

        Returns:
            X_resampled, y_resampled
        """
        if verbose:
            original_dist = Counter(y)
            logger.info(f"Original distribution: {dict(original_dist)}")
            logger.info(f"  Class 0 (safe): {original_dist[0]} ({original_dist[0]/len(y)*100:.1f}%)")
            logger.info(f"  Class 1 (vulnerable): {original_dist[1]} ({original_dist[1]/len(y)*100:.1f}%)")

        # Class weights only - no resampling
        if self.strategy == 'class_weights':
            self.class_weights = self.get_class_weights(y)
            logger.info(f"Class weights computed: {self.class_weights}")
            return X, y

        # Select and configure sampler
        self.sampler = self._get_sampler()

        # Apply resampling
        try:
            X_resampled, y_resampled = self.sampler.fit_resample(X, y)

            if verbose:
                new_dist = Counter(y_resampled)
                logger.info(f"Resampled distribution: {dict(new_dist)}")
                logger.info(f"  Class 0 (safe): {new_dist[0]} ({new_dist[0]/len(y_resampled)*100:.1f}%)")
                logger.info(f"  Class 1 (vulnerable): {new_dist[1]} ({new_dist[1]/len(y_resampled)*100:.1f}%)")
                logger.info(f"  Samples added/removed: {len(y_resampled) - len(y)}")

            return X_resampled, y_resampled

        except Exception as e:
            logger.error(f"❌ Resampling failed: {e}")
            logger.warning("⚠️  Falling back to original data")
            return X, y

    def _get_sampler(self):
        """Create and return the configured sampler"""

        if self.strategy == 'smote':
            return SMOTE(
                sampling_strategy=self.target_ratio,
                k_neighbors=5,
                random_state=self.random_state,
                n_jobs=-1
            )

        elif self.strategy == 'borderline_smote':
            # Focus on samples near decision boundary
            return BorderlineSMOTE(
                sampling_strategy=self.target_ratio,
                k_neighbors=5,
                random_state=self.random_state,
                n_jobs=-1,
                kind='borderline-1'  # or 'borderline-2'
            )

        elif self.strategy == 'adasyn':
            # Adaptive synthetic sampling - more samples for harder-to-learn examples
            return ADASYN(
                sampling_strategy=self.target_ratio,
                n_neighbors=5,
                random_state=self.random_state,
                n_jobs=-1
            )

        elif self.strategy == 'smote_tomek':
            # SMOTE + remove Tomek links (boundary samples)
            return SMOTETomek(
                sampling_strategy=self.target_ratio,
                random_state=self.random_state,
                n_jobs=-1
            )

        elif self.strategy == 'smote_enn':
            # SMOTE + Edited Nearest Neighbors (remove misclassified samples)
            return SMOTEENN(
                sampling_strategy=self.target_ratio,
                random_state=self.random_state,
                n_jobs=-1
            )

        elif self.strategy == 'svm_smote':
            # SVM-based SMOTE (uses SVM to identify support vectors)
            return SVMSMOTE(
                sampling_strategy=self.target_ratio,
                k_neighbors=5,
                random_state=self.random_state,
                n_jobs=-1
            )

        elif self.strategy == 'undersample':
            # Random undersampling of majority class
            return RandomUnderSampler(
                sampling_strategy=0.5,  # Keep vulnerable at 2:1 ratio
                random_state=self.random_state
            )

        elif self.strategy == 'tomek_links':
            # Remove Tomek links only (boundary samples)
            return TomekLinks(
                sampling_strategy='majority',
                n_jobs=-1
            )

        elif self.strategy == 'hybrid':
            # Combined over/under sampling
            from imblearn.pipeline import Pipeline
            return Pipeline([
                ('smote', SMOTE(sampling_strategy=0.3, random_state=self.random_state)),
                ('under', RandomUnderSampler(sampling_strategy=0.7, random_state=self.random_state))
            ])

        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")

    def get_class_weights(self, y: np.ndarray) -> Dict[int, float]:
        """
        Compute class weights for cost-sensitive learning

        For XGBoost, use scale_pos_weight = weight[1] / weight[0]
        For PyTorch, use weights directly in loss function
        """
        classes = np.unique(y)
        weights = compute_class_weight(
            class_weight='balanced',
            classes=classes,
            y=y
        )

        weight_dict = dict(zip(classes, weights))

        # For 91% vulnerable / 9% safe:
        # Safe class (0) gets weight ~10.0
        # Vulnerable class (1) gets weight ~1.1

        logger.info(f"Class weights: {weight_dict}")
        logger.info(f"XGBoost scale_pos_weight: {weight_dict[1] / weight_dict[0]:.2f}")

        return weight_dict

    def get_xgboost_weight(self, y: np.ndarray) -> float:
        """
        Get scale_pos_weight parameter for XGBoost

        Returns:
            scale_pos_weight value (ratio of negative to positive class weights)
        """
        weights = self.get_class_weights(y)
        # For binary classification: ratio of class 0 weight to class 1 weight
        # Since we want to emphasize safe class (0), we flip the ratio
        scale_pos_weight = weights[0] / weights[1]
        return scale_pos_weight

    def get_pytorch_weights(self, y: np.ndarray) -> torch.Tensor:
        """
        Get class weights as PyTorch tensor for loss functions

        Returns:
            Tensor of shape (num_classes,) for use in nn.CrossEntropyLoss(weight=...)
        """
        weights = self.get_class_weights(y)
        weight_tensor = torch.tensor([weights[0], weights[1]], dtype=torch.float32)
        return weight_tensor


def integrate_with_gnn_pipeline(
    X_train: np.ndarray,
    y_train: np.ndarray,
    strategy: str = 'smote_tomek',
    use_resampling: bool = True
) -> Tuple[np.ndarray, np.ndarray, Optional[torch.Tensor]]:
    """
    Helper function to integrate imbalance handling with GNN pipeline

    Args:
        X_train: Training features
        y_train: Training labels
        strategy: Balancing strategy
        use_resampling: If False, only compute class weights

    Returns:
        X_resampled, y_resampled, class_weights_tensor
    """
    handler = AdvancedImbalanceHandler(
        strategy='class_weights' if not use_resampling else strategy,
        target_ratio=0.5,
        random_state=42
    )

    if use_resampling:
        X_resampled, y_resampled = handler.balance_data(X_train, y_train)
        class_weights = None
    else:
        X_resampled, y_resampled = X_train, y_train
        class_weights = handler.get_pytorch_weights(y_train)

    return X_resampled, y_resampled, class_weights


# XGBoost integration
def train_xgboost_with_imbalance(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    use_smote: bool = True
):
    """
    Example: Train XGBoost with imbalance handling

    Two approaches:
    1. SMOTE resampling before training
    2. Class weights via scale_pos_weight
    """
    import xgboost as xgb
    from sklearn.metrics import accuracy_score, f1_score, classification_report

    logger.info("\n" + "=" * 80)
    logger.info("Training XGBoost with Imbalance Handling")
    logger.info("=" * 80)

    if use_smote:
        # Approach 1: SMOTE resampling
        logger.info("Using SMOTE-Tomek resampling")
        handler = AdvancedImbalanceHandler(strategy='smote_tomek', target_ratio=0.5)
        X_train_resampled, y_train_resampled = handler.balance_data(X_train, y_train)

        model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=12,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            gamma=0.1,
            random_state=42,
            tree_method='hist',
            eval_metric=['logloss', 'aucpr'],
            early_stopping_rounds=20,
            n_jobs=-1
        )

        model.fit(
            X_train_resampled, y_train_resampled,
            eval_set=[(X_test, y_test)],
            verbose=True
        )

    else:
        # Approach 2: Class weights
        logger.info("Using class weights (scale_pos_weight)")
        handler = AdvancedImbalanceHandler(strategy='class_weights')
        scale_pos_weight = handler.get_xgboost_weight(y_train)

        model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=12,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            gamma=0.1,
            scale_pos_weight=scale_pos_weight,  # Class weight
            random_state=42,
            tree_method='hist',
            eval_metric=['logloss', 'aucpr'],
            early_stopping_rounds=20,
            n_jobs=-1
        )

        model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=True
        )

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')

    logger.info("\n" + "=" * 80)
    logger.info(f"XGBoost Results:")
    logger.info(f"  Accuracy: {accuracy:.4f}")
    logger.info(f"  F1 (weighted): {f1:.4f}")
    logger.info("=" * 80)
    logger.info("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Vulnerable']))

    return model


if __name__ == "__main__":
    # Example usage
    from sklearn.datasets import make_classification

    # Simulate 91% vulnerable / 9% safe imbalance
    X, y = make_classification(
        n_samples=10000,
        n_features=100,
        n_classes=2,
        weights=[0.09, 0.91],  # 9% safe, 91% vulnerable
        random_state=42
    )

    logger.info("Testing Imbalance Handlers")
    logger.info("=" * 80)

    # Test different strategies
    strategies = ['smote', 'borderline_smote', 'adasyn', 'smote_tomek', 'smote_enn']

    for strategy in strategies:
        logger.info(f"\nTesting strategy: {strategy}")
        logger.info("-" * 80)

        handler = AdvancedImbalanceHandler(strategy=strategy, target_ratio=0.5)
        X_resampled, y_resampled = handler.balance_data(X, y)

        logger.info(f"Original size: {len(y)}, Resampled size: {len(y_resampled)}")

    # Test class weights
    logger.info("\n\nTesting class weights:")
    logger.info("-" * 80)
    handler = AdvancedImbalanceHandler(strategy='class_weights')
    weights = handler.get_class_weights(y)
    xgb_weight = handler.get_xgboost_weight(y)
    pytorch_weights = handler.get_pytorch_weights(y)

    logger.info(f"Class weights dict: {weights}")
    logger.info(f"XGBoost scale_pos_weight: {xgb_weight:.4f}")
    logger.info(f"PyTorch weights tensor: {pytorch_weights}")
