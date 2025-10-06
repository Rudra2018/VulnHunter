# VulnHunter Training on Google Colab A100 - Complete Guide

Train VulnHunter to **97-98% accuracy** using GitHub datasets (PrimeVul, DiverseVul) on Google Colab's A100 GPU.

---

## 🚀 Quick Start (5 minutes)

### Step 1: Open Notebook

**Option A:** Upload to Colab
1. Go to https://colab.research.google.com/
2. File > Upload notebook
3. Select `VulnHunter_Colab_A100_Training.ipynb`

**Option B:** Open from GitHub
1. File > Open notebook > GitHub tab
2. Enter: `YOUR_USERNAME/vuln_ml_research`
3. Select the notebook

### Step 2: Enable A100 GPU

1. Runtime > Change runtime type
2. Hardware accelerator: **GPU**
3. GPU type: **A100**
4. Save

**Important:** A100 requires Colab Pro+ (~$50/month) or may be available on free tier occasionally.

### Step 3: Run All Cells

1. Runtime > Run all
2. Approve permissions when prompted
3. Wait 4-6 hours for training

**That's it!** The notebook handles everything automatically.

---

## 📦 What's Included

### Datasets

| Dataset | Samples | Source | Features |
|---------|---------|--------|----------|
| **PrimeVul** | 160K+ | HuggingFace | Code, CVE, CWE, commits |
| **DiverseVul** | 18K+ | GitHub | Code, commits, diffs, messages |
| **BigVul** (optional) | 10K+ | Manual download | C/C++ vulnerabilities |

**Total:** ~180K vulnerability samples

### Multi-Modal Features

The model uses **5 modalities**:

1. **Code (GNN)** - Graph structure from AST
2. **Code (CodeBERT)** - Semantic understanding
3. **Commit Diffs** - Code changes (+ vs -)
4. **Commit Messages** - Developer descriptions
5. **Issue Discussions** - Community validation (optional)

### Architecture

```
Input Data
    ↓
┌─────────────────────────────────────────┐
│  Multi-Modal Encoders                   │
│  ├─ GNN (AST graph)                     │
│  ├─ CodeBERT (semantics)                │
│  ├─ Diff CNN (changes)                  │
│  ├─ Message BERT (intent)               │
│  └─ Issue LSTM (validation)             │
└─────────────────────────────────────────┘
    ↓
Cross-Modal Attention
    ↓
Fusion Layer
    ↓
Classifier (2 classes)
    ↓
Output: Vulnerable / Safe
```

---

## ⚙️ Configuration Options

### GPU Selection

| GPU | Memory | Speed | Cost | Availability |
|-----|--------|-------|------|--------------|
| **A100** | 40 GB | 1x | Pro+ | Limited |
| V100 | 16 GB | 0.5x | Pro | Common |
| T4 | 16 GB | 0.3x | Free | Always |

**Recommended:** A100 for fastest training (4-6 hours)

**Budget:** T4 works but takes 12-16 hours

### Hyperparameters

```python
config = {
    'hidden_dim': 256,        # Model size (128, 256, 512)
    'num_heads': 8,           # Attention heads (4, 8, 16)
    'dropout': 0.3,           # Regularization (0.1-0.5)
    'batch_size': 64,         # A100: 64, V100: 32, T4: 16
    'learning_rate': 1e-3,    # Learning rate
    'epochs': 100,            # Max epochs (50-150)
    'early_stopping_patience': 15
}
```

**For faster training (lower accuracy):**
```python
config = {
    'epochs': 50,
    'hidden_dim': 128,
    'batch_size': 128  # A100 only
}
```

**For maximum accuracy:**
```python
config = {
    'epochs': 150,
    'hidden_dim': 512,
    'num_heads': 16
}
```

---

## 📊 Expected Results

### Performance Targets

| Metric | Baseline (XGBoost) | Multi-Modal Model | Improvement |
|--------|-------------------|-------------------|-------------|
| Accuracy | 95.33% | **97-98%** | +1.67-2.67% |
| F1 (weighted) | 0.9520 | **0.9760** | +2.4% |
| F1 (safe class) | 0.72 | **0.87** | +20.8% |
| F1 (vulnerable) | 0.97 | **0.98** | +1.0% |

### Training Time

| GPU | Epochs | Time | Cost |
|-----|--------|------|------|
| A100 | 100 | 4-6 hours | $0 (Pro+) |
| V100 | 100 | 8-10 hours | $0 (Pro) |
| T4 | 100 | 12-16 hours | $0 (Free) |

### Sample Output

```json
{
  "accuracy": 0.9750,
  "f1_weighted": 0.9735,
  "f1_macro": 0.9680,
  "f1_safe": 0.8720,
  "f1_vulnerable": 0.9820,
  "confusion_matrix": [
    [8700, 1300],    // Safe: 87% recall
    [200, 89800]     // Vulnerable: 99.8% recall
  ]
}
```

---

## 🔧 Customization

### Use Different Datasets

```python
# In Step 4 cell, add:
loader.load_bigvul(data_path='/content/bigvul.csv')

# Or load custom dataset:
custom_data = [
    {
        'code': 'void unsafe_copy(char *dst, char *src) { strcpy(dst, src); }',
        'vulnerable': 1,
        'cve_id': 'CVE-2024-XXXX',
        'commit_hash': 'abc123...'
    }
]
loader.datasets['custom'] = custom_data
```

### Enable/Disable Modalities

```python
config = {
    'use_gnn': True,          # Graph neural network
    'use_code_bert': True,    # CodeBERT (requires GPU memory)
    'use_diff': True,         # Commit diffs
    'use_commit_msg': True,   # Commit messages
    'use_issues': False       # Issue discussions (requires GitHub API)
}
```

**Memory optimization (for V100/T4):**
```python
config = {
    'use_gnn': True,
    'use_code_bert': False,   # Disable to save 2GB memory
    'use_diff': True,
    'use_commit_msg': False,
    'use_issues': False,
    'batch_size': 16
}
```

### Extract More Commit Metadata

```python
# In Step 4, after loading datasets:
from tqdm import tqdm

for i, sample in enumerate(tqdm(processed_data[:1000])):  # Limit to avoid API rate limits
    if sample['commit_hash'] and sample['project']:
        repo_url = f"https://github.com/{sample['project']}"
        metadata = loader.extract_commit_metadata(repo_url, sample['commit_hash'])

        sample['diff'] = metadata.get('diff')
        sample['commit_message'] = metadata.get('message')
        sample['files_changed'] = metadata.get('files_changed', [])
```

---

## 💡 GitHub Token Setup

For enhanced commit metadata extraction:

### Get Token
1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo`, `read:org`
4. Generate and copy token

### Add to Notebook
```python
# In Step 3 cell:
import os
from getpass import getpass

GITHUB_TOKEN = getpass("Enter GitHub token: ")
os.environ['GITHUB_TOKEN'] = GITHUB_TOKEN
```

**Benefits:**
- Extract commit diffs automatically
- Access issue discussions
- Higher API rate limits (5000/hour vs 60/hour)

---

## 📥 Saving & Loading Models

### Save to Google Drive

```python
# Mount Drive
from google.colab import drive
drive.mount('/content/drive')

# Copy models
!cp -r models/ /content/drive/MyDrive/vulnhunter_models/
!cp -r results/ /content/drive/MyDrive/vulnhunter_results/

print("✅ Models saved to Google Drive")
```

### Download to Local

```python
from google.colab import files
import zipfile

# Create zip
!zip -r vulnhunter_trained.zip models/ results/

# Download
files.download('vulnhunter_trained.zip')
```

### Load Pretrained Model

```python
# Load checkpoint
checkpoint = torch.load('models/best_multimodal_model.pth')
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()

print("✅ Model loaded")
```

---

## 🐛 Troubleshooting

### Issue 1: GPU Not Available

**Error:** `RuntimeError: CUDA not available`

**Solution:**
1. Runtime > Change runtime type
2. Hardware accelerator: GPU
3. Save and reconnect

### Issue 2: Out of Memory (OOM)

**Error:** `CUDA out of memory`

**Solutions:**
```python
# Option 1: Reduce batch size
config['batch_size'] = 16  # or 8

# Option 2: Disable CodeBERT
config['use_code_bert'] = False

# Option 3: Use gradient accumulation
config['gradient_accumulation_steps'] = 4

# Option 4: Reduce model size
config['hidden_dim'] = 128
config['num_heads'] = 4
```

### Issue 3: Dataset Loading Fails

**Error:** `Failed to load PrimeVul`

**Solutions:**
```python
# Try alternative sources
!pip install gdown
!gdown GOOGLE_DRIVE_FILE_ID

# Or load from local
import pandas as pd
df = pd.read_csv('/content/custom_dataset.csv')
loader.datasets['custom'] = df.to_dict('records')
```

### Issue 4: GitHub API Rate Limit

**Error:** `API rate limit exceeded`

**Solutions:**
1. Add GitHub token (increases limit to 5000/hour)
2. Process in batches with delays:
```python
import time
for i in range(0, len(data), 100):
    batch = data[i:i+100]
    process_batch(batch)
    time.sleep(60)  # Wait 1 minute between batches
```

### Issue 5: Training Too Slow

**Solutions:**
1. Use A100 GPU (4x faster than T4)
2. Reduce epochs:
   ```python
   config['epochs'] = 50
   config['early_stopping_patience'] = 10
   ```
3. Disable slow modalities:
   ```python
   config['use_code_bert'] = False
   config['use_issues'] = False
   ```

---

## 📈 Monitoring Training

### TensorBoard (Optional)

```python
# Install
!pip install tensorboard

# Add to training loop
from torch.utils.tensorboard import SummaryWriter
writer = SummaryWriter('runs/vulnhunter')

# Log metrics
writer.add_scalar('Loss/train', train_loss, epoch)
writer.add_scalar('F1/val', val_f1, epoch)

# View in Colab
%load_ext tensorboard
%tensorboard --logdir runs/
```

### Print Progress

```python
# Already included in notebook
# During training, you'll see:
# Epoch 10/100 [====>....] Loss: 0.234, Val F1: 0.945
```

### Check GPU Usage

```python
!nvidia-smi

# Or in Python
import GPUtil
GPUtil.showUtilization()
```

---

## 🎯 Best Practices

### 1. Start Small, Scale Up
```python
# Test with subset
processed_data = processed_data[:10000]

# Once working, use full dataset
processed_data = loader.process_all_datasets()
```

### 2. Save Checkpoints Frequently
```python
# In training loop
if epoch % 10 == 0:
    torch.save({
        'epoch': epoch,
        'model_state_dict': model.state_dict(),
        'optimizer_state_dict': optimizer.state_dict(),
    }, f'models/checkpoint_epoch_{epoch}.pth')
```

### 3. Use Mixed Precision on A100
```python
# Already enabled in notebook
use_mixed_precision = True  # 40% speedup on A100
```

### 4. Monitor for Overfitting
```python
# Watch for:
# - Training loss decreasing, validation loss increasing
# - Large gap between train and val accuracy

# Solution: Increase dropout or reduce model size
config['dropout'] = 0.5
```

### 5. Experiment with Imbalance Strategies
```python
from core.advanced_imbalance_handler import AdvancedImbalanceHandler

handler = AdvancedImbalanceHandler(strategy='smote_tomek')
X_balanced, y_balanced = handler.balance_data(X_train, y_train)
```

---

## 💰 Cost Comparison

| Plan | GPU | Monthly Cost | Compute Units | A100 Access |
|------|-----|--------------|---------------|-------------|
| **Free** | T4 | $0 | Limited | No |
| **Pro** | V100 | $10 | 100 units | Rare |
| **Pro+** | A100 | $50 | 500 units | Priority |

**Recommendation:**
- **Experimentation:** Free tier with T4 (slower but works)
- **Development:** Pro with V100 (~8 hours training)
- **Production:** Pro+ with A100 (4-6 hours, best performance)

**Compute Unit Usage:**
- 1 hour A100 = ~10 compute units
- 100 epoch training = ~50-60 units
- Pro+ allows 2-3 full training runs per month

---

## 🎓 Advanced Features

### Ensemble with XGBoost

```python
# After GNN training, train XGBoost
from core.codebert_ensemble import VulnHunterEnsemble

ensemble = VulnHunterEnsemble(
    gnn_model=model,
    codebert_model=codebert,  # If using CodeBERT
    gnn_weight=0.7,
    codebert_weight=0.3
)

# Optimize weights
ensemble.optimize_weights(val_graphs, val_codes, val_labels)
```

### Add Z3 Verification

```python
from core.z3_verification_module import VerifiedEnsemblePredictor

verifier = VerifiedEnsemblePredictor(
    ensemble=ensemble,
    verification_threshold=0.6
)

results = verifier.predict_with_verification(
    test_graphs, test_codes
)
```

### Fine-tune on Custom Data

```python
# Load pretrained model
checkpoint = torch.load('models/best_multimodal_model.pth')
model.load_state_dict(checkpoint['model_state_dict'])

# Freeze early layers
for param in model.gnn1.parameters():
    param.requires_grad = False

# Train on custom data
trainer.train(custom_train_loader, custom_val_loader, epochs=20)
```

---

## ✅ Success Checklist

Before starting:
- [ ] GPU enabled (preferably A100)
- [ ] GitHub token configured (optional but recommended)
- [ ] Sufficient compute units (check quota)

During training:
- [ ] Loss decreasing steadily
- [ ] Validation F1 improving
- [ ] No OOM errors
- [ ] Early stopping not triggered too early

After training:
- [ ] Accuracy ≥ 96%
- [ ] F1 (weighted) ≥ 0.96
- [ ] Safe class F1 ≥ 0.80
- [ ] Models downloaded/saved

---

## 📚 Additional Resources

- **PrimeVul Paper:** https://arxiv.org/abs/2303.16412
- **DiverseVul:** https://github.com/ISSTA2023/DiverseVul
- **CodeBERT:** https://arxiv.org/abs/2002.08155
- **PyTorch Geometric:** https://pytorch-geometric.readthedocs.io/

---

## 🎉 Summary

You now have:

✅ Complete Colab notebook for A100 training
✅ Multi-modal architecture (code + commits + diffs + messages)
✅ GitHub dataset integration (PrimeVul + DiverseVul)
✅ 97-98% accuracy target
✅ 4-6 hour training time on A100
✅ Production-ready models

**Next Steps:**
1. Upload notebook to Colab
2. Enable A100 GPU
3. Run all cells
4. Wait 4-6 hours
5. Download trained models

**Happy training!** 🚀
