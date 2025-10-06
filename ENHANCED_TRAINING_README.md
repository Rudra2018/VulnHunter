# VulnHunter Enhanced Training Guide

**Goal:** Achieve 96-98% accuracy on vulnerability detection with 91% vulnerable / 9% safe imbalance.

## 🚀 Quick Start

### Installation

```bash
pip install torch torch-geometric transformers z3-solver imbalanced-learn scikit-learn xgboost
```

### Basic Usage

```python
from train_enhanced_vulnhunter import VulnHunterPipeline

# 1. Initialize pipeline
config = {
    'device': 'cuda',
    'hidden_dim': 256,
    'num_heads': 8,
    'dropout': 0.3,
    'gradient_accumulation_steps': 4,
    'gnn_epochs': 100,
    'codebert_epochs': 10,
    'batch_size': 32,
    'learning_rate': 1e-3
}

pipeline = VulnHunterPipeline(config)

# 2. Prepare data (handles imbalance automatically)
train_graphs, train_codes, train_labels, \
val_graphs, val_codes, val_labels, \
test_graphs, test_codes, test_labels = pipeline.prepare_data(
    graph_data=your_graph_data,
    code_texts=your_code_texts,
    labels=your_labels,
    use_resampling=False  # Use class weights for graphs
)

# 3. Train GNN-Transformer
pipeline.train_gnn_model(train_graphs, val_graphs, epochs=100)

# 4. Fine-tune CodeBERT
pipeline.train_codebert_model(
    train_codes, train_labels,
    val_codes, val_labels,
    epochs=10
)

# 5. Create ensemble and optimize weights
pipeline.create_ensemble(val_graphs, val_codes, val_labels)

# 6. Optimize classification threshold
optimal_threshold, metrics = pipeline.optimize_threshold(
    val_graphs, val_codes, val_labels
)

# 7. Add Z3 verification layer
pipeline.add_verification_layer()

# 8. Evaluate
results = pipeline.evaluate(
    test_graphs, test_codes, test_labels,
    use_verification=True
)

print(f"Final Accuracy: {results['accuracy']:.4f}")
print(f"Final F1 (weighted): {results['f1_weighted']:.4f}")
```

---

## 📦 Module Overview

### 1. **Enhanced GNN Trainer** (`core/enhanced_gnn_trainer.py`)

**Features:**
- Focal Loss for imbalanced data (emphasizes hard examples)
- Cosine Annealing with Warm Restarts
- Mixed precision training (AMP)
- Gradient accumulation
- Early stopping with patience

**Usage:**

```python
from core.enhanced_gnn_trainer import EnhancedGNNTrainer, FocalLoss

# Initialize trainer
trainer = EnhancedGNNTrainer(
    model=your_gnn_model,
    loss_type='focal',  # or 'label_smoothing', 'ce'
    focal_alpha=0.25,   # Weight for safe class (9% minority)
    focal_gamma=2.0,    # Focusing parameter
    use_mixed_precision=True,
    gradient_accumulation_steps=4
)

# Setup optimizer
trainer.setup_optimizer_scheduler(
    learning_rate=1e-3,
    weight_decay=0.01,
    max_epochs=100
)

# Train
history = trainer.train(
    train_loader=train_loader,
    val_loader=val_loader,
    epochs=100,
    early_stopping_patience=20,
    save_path='best_model.pth'
)
```

**Why it works:**
- **Focal Loss** down-weights easy examples and focuses on hard-to-classify samples
- **Cosine Annealing** prevents premature convergence, explores better optima
- **Mixed Precision** reduces memory by 50%, allows larger batch sizes

---

### 2. **Advanced Imbalance Handler** (`core/advanced_imbalance_handler.py`)

**Strategies:**
- SMOTE (Synthetic Minority Over-sampling)
- BorderlineSMOTE (focus on decision boundary)
- ADASYN (adaptive synthetic sampling)
- SMOTE-Tomek (over-sample + remove boundary noise)
- SMOTE-ENN (over-sample + clean misclassified)
- Class weights (for XGBoost, PyTorch)

**Usage:**

```python
from core.advanced_imbalance_handler import AdvancedImbalanceHandler

# For traditional ML (XGBoost, Random Forest)
handler = AdvancedImbalanceHandler(
    strategy='smote_tomek',
    target_ratio=0.5,  # Make safe class 50% of vulnerable
    random_state=42
)

X_balanced, y_balanced = handler.balance_data(X_train, y_train)

# For XGBoost with class weights (alternative to SMOTE)
handler = AdvancedImbalanceHandler(strategy='class_weights')
scale_pos_weight = handler.get_xgboost_weight(y_train)

xgb_model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=12,
    learning_rate=0.05,
    scale_pos_weight=scale_pos_weight,  # Critical for imbalance
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42
)

# For PyTorch (GNN, Neural Networks)
class_weights = handler.get_pytorch_weights(y_train)
criterion = nn.CrossEntropyLoss(weight=class_weights)
```

**Recommendations:**
- **For tabular data:** Use `smote_tomek` (best balance of over/under sampling)
- **For XGBoost:** Use `scale_pos_weight` (faster, no data duplication)
- **For GNNs:** Use class weights (SMOTE on graphs is complex)

---

### 3. **CodeBERT Ensemble** (`core/codebert_ensemble.py`)

**Features:**
- Fine-tune microsoft/codebert-base
- Ensemble with GNN predictions
- Automatic weight optimization

**Usage:**

```python
from core.codebert_ensemble import CodeBERTVulnerabilityDetector, VulnHunterEnsemble

# 1. Fine-tune CodeBERT
codebert = CodeBERTVulnerabilityDetector()
codebert.train(
    train_texts=train_code_strings,
    train_labels=train_labels,
    val_texts=val_code_strings,
    val_labels=val_labels,
    epochs=10,
    batch_size=16
)

# 2. Create ensemble
ensemble = VulnHunterEnsemble(
    gnn_model=your_trained_gnn,
    codebert_model=codebert,
    gnn_weight=0.6,
    codebert_weight=0.4
)

# 3. Optimize weights on validation set
ensemble.optimize_weights(
    val_graphs, val_codes, val_labels,
    metric='f1'
)

# 4. Predict
results = ensemble.predict_ensemble(
    test_graphs, test_codes,
    threshold=0.5
)

predictions = results['ensemble_predictions']
probabilities = results['ensemble_probabilities']
```

**Expected Improvement:** +2-3% accuracy from ensemble diversity

---

### 4. **Z3 Verification Module** (`core/z3_verification_module.py`)

**Reduces false positives** by formally verifying ML predictions.

**Checks for:**
- SQL injection (string concatenation in queries)
- Buffer overflow (unsafe C functions)
- Command injection (system(), exec())
- Path traversal (directory traversal patterns)

**Usage:**

```python
from core.z3_verification_module import VerifiedEnsemblePredictor, Z3VerificationModule

# Create verified predictor
verifier = VerifiedEnsemblePredictor(
    ensemble=your_ensemble,
    verification_module=Z3VerificationModule(timeout_ms=5000),
    verification_threshold=0.6  # Verify predictions with <60% confidence
)

# Predict with verification
results = verifier.predict_with_verification(
    test_graphs,
    test_codes,
    verify_all=False  # Only verify uncertain predictions
)

print(f"Verified: {results['verified_count']}/{len(test_codes)}")
print(f"Corrections: {results['corrections']}")
```

**Example:** If ML predicts vulnerable with 55% confidence but Z3 finds no SQL injection pattern, prediction is corrected to safe.

**Expected Impact:** -10-20% false positives

---

### 5. **GPU Optimization** (`core/gpu_optimization_utils.py`)

**Handles OOM errors** and **optimizes thresholds**.

#### A. GPU Memory Optimization

```python
from core.gpu_optimization_utils import GPUMemoryOptimizer, diagnose_gpu_oom_error

# Diagnose OOM errors
diagnose_gpu_oom_error(model, sample_batch)

# Estimate model memory
optimizer = GPUMemoryOptimizer()
memory_info = optimizer.estimate_model_memory(model)
print(f"Model size: {memory_info['total_mb']:.2f} MB")

# Find optimal batch size
optimal_batch_size = optimizer.optimize_batch_size(
    model, sample_input,
    max_memory_mb=10000
)
```

#### B. Gradient Accumulation (for OOM)

```python
from core.gpu_optimization_utils import GradientAccumulationTrainer

trainer = GradientAccumulationTrainer(
    model=model,
    optimizer=optimizer,
    criterion=criterion,
    accumulation_steps=4,  # Effective batch size = batch_size * 4
    use_mixed_precision=True
)

for batch_idx, batch in enumerate(train_loader):
    loss = trainer.train_step(batch, batch_idx)
```

**Effective batch size = batch_size × accumulation_steps**

Example: batch_size=8, accumulation_steps=4 → effective batch_size=32

#### C. Threshold Optimization (for imbalanced data)

```python
from core.gpu_optimization_utils import ThresholdOptimizer

# Optimize for safe class F1
optimizer = ThresholdOptimizer(target_metric='f1_macro')
optimal_threshold, metrics = optimizer.find_optimal_threshold(
    y_true=val_labels,
    y_proba=val_probabilities,
    plot_path='threshold_analysis.png'
)

print(f"Optimal threshold: {optimal_threshold:.3f} (default: 0.500)")

# Use optimal threshold for predictions
predictions = optimizer.predict_with_optimal_threshold(test_probabilities)
```

**Expected Improvement:** +1-2% F1 for minority class

---

## 🎯 Complete Training Example

```python
#!/usr/bin/env python3
"""
Complete VulnHunter training with all enhancements
"""

from train_enhanced_vulnhunter import VulnHunterPipeline
import torch
from torch_geometric.data import Data

# Configuration
config = {
    'device': 'cuda' if torch.cuda.is_available() else 'cpu',
    'hidden_dim': 256,
    'num_heads': 8,
    'dropout': 0.3,
    'gradient_accumulation_steps': 4,
    'gnn_epochs': 100,
    'codebert_epochs': 10,
    'batch_size': 32,
    'learning_rate': 1e-3
}

# Load your data (replace with actual loading)
# graph_data = [Data(x=..., edge_index=..., y=...) for sample in dataset]
# code_texts = [sample['code'] for sample in dataset]
# labels = [sample['label'] for sample in dataset]

# Initialize pipeline
pipeline = VulnHunterPipeline(config)

# Step 1: Prepare data
train_graphs, train_codes, train_labels, \
val_graphs, val_codes, val_labels, \
test_graphs, test_codes, test_labels = pipeline.prepare_data(
    graph_data, code_texts, labels
)

# Step 2: Train GNN
pipeline.train_gnn_model(train_graphs, val_graphs, epochs=100)

# Step 3: Train CodeBERT
pipeline.train_codebert_model(
    train_codes, train_labels,
    val_codes, val_labels,
    epochs=10
)

# Step 4: Create ensemble
pipeline.create_ensemble(val_graphs, val_codes, val_labels)

# Step 5: Optimize threshold
pipeline.optimize_threshold(val_graphs, val_codes, val_labels)

# Step 6: Add verification
pipeline.add_verification_layer()

# Step 7: Final evaluation
results = pipeline.evaluate(test_graphs, test_codes, test_labels)

print(f"\n🎉 Final Results:")
print(f"  Accuracy: {results['accuracy']:.4f}")
print(f"  F1 (weighted): {results['f1_weighted']:.4f}")
print(f"  F1 (macro): {results['f1_macro']:.4f}")
```

---

## 🔧 Debugging Common Issues

### Issue 1: GPU Out of Memory (OOM)

**Solutions:**

```python
# Option 1: Reduce batch size
config['batch_size'] = 16  # or 8

# Option 2: Use gradient accumulation
config['gradient_accumulation_steps'] = 8

# Option 3: Use mixed precision
trainer = EnhancedGNNTrainer(use_mixed_precision=True)

# Option 4: Clear cache
import torch
torch.cuda.empty_cache()

# Option 5: Reduce model size
config['hidden_dim'] = 128  # instead of 256
```

### Issue 2: Low F1 Score on Safe Class

**Solutions:**

```python
# 1. Use focal loss with higher alpha
trainer = EnhancedGNNTrainer(focal_alpha=0.3)  # More weight to safe class

# 2. Optimize threshold
optimizer = ThresholdOptimizer(target_metric='f1_safe')
optimal_threshold = optimizer.find_optimal_threshold(y_true, y_proba)

# 3. Use SMOTE for tabular features
handler = AdvancedImbalanceHandler(strategy='borderline_smote')
X_balanced, y_balanced = handler.balance_data(X, y)
```

### Issue 3: Training Too Slow

**Solutions:**

```python
# 1. Reduce model complexity
config['hidden_dim'] = 128
config['num_heads'] = 4

# 2. Reduce transformer layers
# In EnhancedGNNTransformer.__init__:
self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=3)  # instead of 6

# 3. Early stopping
trainer.train(early_stopping_patience=10)  # Stop if no improvement after 10 epochs

# 4. Use smaller CodeBERT
codebert = CodeBERTVulnerabilityDetector(model_name="microsoft/graphcodebert-base")
```

---

## 📊 Expected Performance

| Component | Contribution | Cumulative Accuracy |
|-----------|-------------|---------------------|
| Baseline XGBoost | - | 95.33% |
| Enhanced GNN + Focal Loss | +0.5-1% | ~96% |
| CodeBERT Ensemble | +1-2% | ~97% |
| Threshold Optimization | +0.5-1% | ~97.5% |
| Z3 Verification | -FP, +Precision | ~97-98% |

**Target: 96-98% accuracy with balanced precision/recall**

---

## 📚 References

- **Focal Loss:** [Lin et al., 2017 - Focal Loss for Dense Object Detection](https://arxiv.org/abs/1708.02002)
- **SMOTE:** [Chawla et al., 2002 - SMOTE: Synthetic Minority Over-sampling Technique](https://arxiv.org/abs/1106.1813)
- **CodeBERT:** [Feng et al., 2020 - CodeBERT: A Pre-Trained Model for Programming and Natural Languages](https://arxiv.org/abs/2002.08155)
- **GNN Survey:** [Wu et al., 2020 - A Comprehensive Survey on Graph Neural Networks](https://arxiv.org/abs/1901.00596)

---

## 🛠️ Customization

### Custom Loss Function

```python
class CustomFocalLoss(nn.Module):
    def __init__(self, alpha=0.25, gamma=2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, inputs, targets):
        # Your custom loss implementation
        pass

# Use in trainer
trainer = EnhancedGNNTrainer(model, loss_type='focal')
trainer.criterion = CustomFocalLoss(alpha=0.3, gamma=2.5)
```

### Custom Verification Rules

```python
from core.z3_verification_module import Z3VerificationModule

class CustomVerifier(Z3VerificationModule):
    def verify_custom_vulnerability(self, code: str):
        # Your custom Z3 verification logic
        solver = Solver()
        # Add constraints
        # Return result
        pass
```

---

## ✅ Checklist for 96-98% Accuracy

- [ ] Use focal loss with alpha=0.25, gamma=2.0
- [ ] Apply SMOTE-Tomek or class weights for imbalance
- [ ] Train both GNN and CodeBERT models
- [ ] Ensemble with optimized weights (GNN:60%, CodeBERT:40%)
- [ ] Optimize classification threshold on validation set
- [ ] Add Z3 verification for uncertain predictions
- [ ] Use early stopping (patience=20)
- [ ] Enable mixed precision training
- [ ] Monitor safe class F1 score (target: >0.85)
- [ ] Validate on held-out test set

---

## 🚨 Important Notes

1. **Graph Construction:** Ensure your graph representations are high-quality (AST, CFG, or DFG)
2. **Code Preprocessing:** Remove comments, normalize variable names for better CodeBERT performance
3. **Z3 Timeout:** Set appropriate timeout (5000ms default) to avoid slow verification
4. **Validation Set:** Use same distribution as training (stratified split)
5. **Memory:** GNN + CodeBERT requires ~12GB GPU for batch_size=32

---

## 📞 Support

For issues or questions:
1. Check logs for error messages
2. Run `diagnose_gpu_oom_error()` for memory issues
3. Use smaller batch size + gradient accumulation
4. Review threshold analysis plots

**Happy hunting! 🎯**
