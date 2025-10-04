# 🚀 Kaggle Dataset Training Guide

Train VulnGuard AI with massive vulnerability datasets from Kaggle for maximum accuracy!

## 📦 Datasets Included

1. **Public CVE Vulnerabilities 2020-2024** (umer7arooq)
   - https://www.kaggle.com/datasets/umer7arooq/public-cve-vulnerabilities-20202024
   - Recent CVE data from 2020-2024

2. **CVE Data** (angelcortez)
   - https://www.kaggle.com/datasets/angelcortez/cve-data
   - Comprehensive CVE database

3. **Bug Bounty Writeups** (mayankkumarpoddar)
   - https://www.kaggle.com/datasets/mayankkumarpoddar/bug-bounty-writeups
   - Real-world bug bounty reports and exploits

4. **CVE Dataset** (casimireffect)
   - https://www.kaggle.com/datasets/casimireffect/cve-dataset
   - Additional CVE vulnerability data

5. **Bug Bounty OpenAI GPT OSS** (daudthecat)
   - https://www.kaggle.com/datasets/daudthecat/bug-bounty-openai-gpt-oss-20b-by-thecat
   - Bug bounty data curated for AI/ML training

## 🔧 Setup

### Option 1: Automatic Download with Kaggle API (Recommended)

1. **Install Kaggle API:**
   ```bash
   pip install kaggle
   ```

2. **Get API Credentials:**
   - Go to https://www.kaggle.com/settings
   - Scroll to "API" section
   - Click "Create New API Token"
   - This downloads `kaggle.json`

3. **Configure Credentials:**
   ```bash
   mkdir -p ~/.kaggle
   mv ~/Downloads/kaggle.json ~/.kaggle/
   chmod 600 ~/.kaggle/kaggle.json
   ```

4. **Download and Train:**
   ```bash
   python train_with_kaggle.py --download
   ```

### Option 2: Manual Download

1. **Download Datasets Manually:**
   - Visit each dataset URL above
   - Click "Download" button on each page
   - Extract to `./data/kaggle/` directory

2. **Organize Files:**
   ```
   data/kaggle/
   ├── public-cve-2020-2024/
   │   └── *.csv
   ├── cve-data/
   │   └── *.csv
   ├── bug-bounty-writeups/
   │   └── *.csv
   ├── cve-dataset/
   │   └── *.csv
   └── bug-bounty-openai/
       └── *.csv
   ```

3. **Train:**
   ```bash
   python train_with_kaggle.py --data-path ./data/kaggle
   ```

### Option 3: HuggingFace Only (No Kaggle)

If you can't access Kaggle datasets, train with HuggingFace datasets:

```bash
python train_with_kaggle.py --huggingface-only
```

## 🎯 Training Commands

### Basic Training
```bash
# With Kaggle datasets
python train_with_kaggle.py --data-path ./data/kaggle

# With auto-download
python train_with_kaggle.py --download

# HuggingFace only
python train_with_kaggle.py --huggingface-only
```

### Advanced Options
```bash
# Download to custom location
python train_with_kaggle.py --download --output-path /custom/path

# Train with custom data path
python train_with_kaggle.py --data-path /custom/path
```

## 📊 What Happens During Training

1. **Dataset Loading:**
   - Loads HuggingFace vulnerability datasets
   - Loads Kaggle CVE and bug bounty datasets
   - Deduplicates samples
   - Merges into unified training set

2. **Feature Extraction:**
   - Code structure analysis (AST features)
   - Vulnerability pattern detection
   - TF-IDF vectorization (character and token level)
   - Security keyword analysis
   - Complexity metrics

3. **Model Training:**
   - Random Forest (300 trees)
   - Gradient Boosting (200 estimators)
   - XGBoost (if available)
   - Neural Network (4 hidden layers: 512-256-128-64)
   - SVM (RBF kernel)
   - Logistic Regression

4. **Evaluation:**
   - 80/20 train/test split
   - Accuracy, Precision, Recall, F1-Score
   - Best model selection

5. **Model Saving:**
   - Saves all trained models
   - Saves feature extractors
   - Saves scalers
   - Timestamp for version tracking

## 🎓 Using Trained Models

```python
import pickle
from core.ultimate_trainer import UltimateVulnGuardTrainer

# Load trainer
trainer = UltimateVulnGuardTrainer()

# Load saved models
with open('ultimate_vulnguard_TIMESTAMP.pkl', 'rb') as f:
    model_data = pickle.load(f)

trainer.models = model_data['models']
trainer.code_vectorizer = model_data['code_vectorizer']
trainer.token_vectorizer = model_data['token_vectorizer']
trainer.scaler = model_data['scaler']

# Predict vulnerability
code = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)
"""

result = trainer.predict(code)

print(f"Vulnerable: {result['vulnerable']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Individual predictions: {result['predictions']}")
```

## 📈 Expected Results

With all datasets combined, you should expect:

- **Training Samples:** 50,000+ unique vulnerability samples
- **Features:** 11,000+ features (manual + TF-IDF)
- **Accuracy:** 85-95% on test set
- **F1-Score:** 0.85-0.95

### Sample Output:
```
📊 Total samples: 67,845
📊 Unique samples: 54,321
📊 Duplicates removed: 13,524

📊 Dataset Statistics:
   Vulnerable: 48,765
   Safe: 5,556

📊 Samples by Source:
   cvefixes-2022: 15,234
   public-cve-2020-2024: 12,456
   bug-bounty-writeups: 8,932
   cve-data: 10,123
   bug-bounty-openai: 5,678
   vulnerable-dataset: 1,898

🏆 BEST MODEL: XGBOOST
   F1-Score: 0.9234
```

## 🔍 Troubleshooting

### Kaggle API Issues

**Error: "Could not find kaggle.json"**
```bash
# Make sure kaggle.json is in correct location
ls -la ~/.kaggle/kaggle.json

# If not, download from https://www.kaggle.com/settings
# Then move it:
mv ~/Downloads/kaggle.json ~/.kaggle/
chmod 600 ~/.kaggle/kaggle.json
```

**Error: "403 Forbidden"**
- Check if you accepted dataset terms on Kaggle website
- Visit each dataset URL and click "Download" once to accept terms

### Memory Issues

If you run out of memory:

1. **Reduce batch size in trainer:**
   ```python
   # In ultimate_trainer.py, modify batch_size
   batch_size=128  # instead of 256
   ```

2. **Train with fewer datasets:**
   ```bash
   # Use only HuggingFace datasets
   python train_with_kaggle.py --huggingface-only
   ```

3. **Limit dataset size:**
   ```python
   # In kaggle_dataset_integrator.py, add sampling
   df = df.sample(n=10000)  # Take only 10k samples
   ```

### Import Errors

```bash
# Install missing dependencies
pip install kaggle
pip install xgboost
pip install scikit-learn pandas numpy
pip install datasets  # For HuggingFace
```

## 🎯 Next Steps

After training:

1. **Test on Real Vulnerabilities:**
   ```bash
   python test_trained_model.py --model ultimate_vulnguard_*.pkl
   ```

2. **Scan Real Repositories:**
   ```bash
   python scan_repository.py --model ultimate_vulnguard_*.pkl --repo /path/to/repo
   ```

3. **Generate Vulnerability Reports:**
   ```bash
   python generate_report.py --model ultimate_vulnguard_*.pkl --scan-results results.json
   ```

## 📚 Additional Resources

- **Kaggle Datasets:** https://www.kaggle.com/datasets
- **HuggingFace Datasets:** https://huggingface.co/datasets
- **CVE Database:** https://cve.mitre.org/
- **Bug Bounty Platforms:** HackerOne, Bugcrowd, Huntr.dev

## 🤝 Contributing

Found more vulnerability datasets? Add them to:
- `core/kaggle_dataset_integrator.py` - Add to `kaggle_datasets` dict
- `core/ultimate_trainer.py` - Enhance feature extraction

## 📝 License

This training pipeline is part of VulnGuard AI research project.
For defensive security research and education only.

---

**Happy Training! 🚀**

Built with ❤️ for the security research community.
