# VulnHunter Models

This directory contains trained ML models for VulnHunter's 4 security analyzers.

## Model Files

VulnHunter requires these model files (71.7MB total):

```
models/
├── ios_vuln_detector.pkl (1.3MB)
├── binary_vuln_models.pkl (63MB)
├── http_security_models.pkl (3.8MB)
└── code_vuln_models.pkl (3.6MB)
```

## Training Models

### Quick Start - Train All Models

```bash
cd ~/vuln_ml_research
python3 train_all_models.py --all
```

This will train all 4 analyzers and save models to `~/Documents/models/`.

### Train Individual Models

```bash
# iOS/macOS Analyzer (1,000 samples, 83% accuracy)
python3 train_all_models.py --ios-macos

# Binary Analyzer (5,024 samples, 35% accuracy)
python3 train_all_models.py --binary

# HTTP/Web Analyzer (10,000 samples, 100% accuracy)
python3 train_all_models.py --http

# Code/SAST Analyzer (2,000 samples, 100% accuracy)
python3 train_all_models.py --code
```

## Training Details

### 1. iOS/macOS Analyzer

**Model Type**: Random Forest + XGBoost ensemble
**Training Samples**: 1,000 synthetic samples
**Features**: Binary analysis, load commands, unsafe functions, permissions
**Accuracy**: 83%
**Model Size**: 1.3MB

**Detects**:
- Buffer overflows
- Memory corruption
- Privilege escalation
- Use-after-free

### 2. Binary Analyzer

**Model Type**: 5-model ensemble (Random Forest, XGBoost, SVM, Neural Network, Naive Bayes)
**Training Samples**: 5,024 samples (1,500 macOS + 2,000 Windows + 1,500 Linux)
**Features**: Platform-specific binary features, API calls, section analysis
**Accuracy**: 35% (improving with more data)
**Model Size**: 63MB

**Detects**:
- Buffer overflow
- Heap overflow
- Integer overflow
- Memory corruption
- Path traversal
- Privilege escalation
- Stack overflow
- Use-after-free

### 3. HTTP/Web Analyzer

**Model Type**: 4-model ensemble (Random Forest, XGBoost, Neural Network, Logistic Regression)
**Training Samples**: 10,000 synthetic HTTP requests
**Features**: URL patterns, headers, payloads, SQL/XSS patterns
**Accuracy**: 100%
**Model Size**: 3.8MB

**Detects**:
- SQL Injection
- XSS (Cross-Site Scripting)
- RCE (Remote Code Execution)
- SSRF (Server-Side Request Forgery)
- Scanner detection

### 4. Code/SAST Analyzer

**Model Type**: 3-model ensemble (Random Forest, XGBoost, Neural Network)
**Training Samples**: 2,000 synthetic code samples
**Features**: AST analysis, code patterns, function calls, string literals
**Accuracy**: 100%
**Model Size**: 3.6MB

**Detects**:
- SQL Injection
- Command injection
- Buffer overflow
- XSS
- Path traversal
- Use-after-free

## Training Time

- **iOS/macOS**: ~2 minutes
- **Binary**: ~5 minutes (large dataset)
- **HTTP**: ~3 minutes
- **Code**: ~2 minutes

**Total**: ~12 minutes for all models

## Model Location

By default, trained models are saved to:
```
~/Documents/models/
├── ios_vuln_detector.pkl
├── binary_vuln_models.pkl
├── http_security_models*.pkl
└── code_vuln_models*.pkl
```

VulnHunter automatically searches for models in this directory.

## Improving Accuracy

### Binary Analyzer (35% accuracy)

The Binary analyzer has lower accuracy because:
1. Training on synthetic data
2. Limited real-world vulnerability samples
3. Complex cross-platform features

**To improve**:
- Collect real vulnerability samples
- Use datasets from CVE databases
- Apply transfer learning
- Fine-tune with domain-specific data

### All Analyzers

To improve any analyzer:

1. **Collect More Data**
   ```python
   # Add real-world samples to training data
   ```

2. **Feature Engineering**
   ```python
   # Add domain-specific features in trainer classes
   ```

3. **Hyperparameter Tuning**
   ```python
   # Modify model parameters in core/*_trainer.py
   ```

4. **Ensemble Weights**
   ```python
   # Adjust voting weights in ensemble methods
   ```

## Using Pre-trained Models

If you have pre-trained models from another system:

1. Copy models to `~/Documents/models/`
2. Ensure naming convention matches:
   - `ios_vuln_detector.pkl`
   - `binary_vuln_models.pkl`
   - `http_security_models.pkl` (or timestamped version)
   - `code_vuln_models.pkl` (or timestamped version)
3. Run VulnHunter status to verify: `python3 vulnhunter/vulnhunter.py status`

## Model Format

All models are saved using Python's `pickle` format with the following structure:

```python
{
    'models': {...},           # Trained sklearn/xgboost models
    'vectorizer': ...,         # Text vectorizer (if applicable)
    'scaler': ...,            # Feature scaler (if applicable)
    'metadata': {             # Training info
        'timestamp': '...',
        'accuracy': 0.XX,
        'training_samples': N
    }
}
```

## Troubleshooting

### "Model file not found"
```bash
# Train the missing model
python3 train_all_models.py --all
```

### "Invalid model format"
```bash
# Re-train from scratch
rm ~/Documents/models/*.pkl
python3 train_all_models.py --all
```

### "Low accuracy in production"
- Models trained on synthetic data may not generalize well
- Collect real-world samples and retrain
- Consider ensemble with multiple models
- Fine-tune on your specific use case

## License

Models are for research/educational use only.

---

**Note**: Model files (71.7MB) are not included in git repository due to size. Train locally using instructions above.
