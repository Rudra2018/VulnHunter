# VulnHunter V5 New Azure Account Setup Instructions

## 🚀 Quick Start Guide

Follow these steps to set up VulnHunter V5 training on your new Azure account with full dataset capabilities.

### Step 1: Prepare Local Environment

```bash
# Ensure you have the required packages
source venv/bin/activate
pip install azure-cli azure-ml

# Make setup script executable
chmod +x setup_new_azure_account.sh
```

### Step 2: Execute New Azure Account Setup

```bash
# Run the setup script (will prompt for Azure login)
./setup_new_azure_account.sh
```

**What this script does:**
- Prompts you to login to your new Azure account
- Checks available quotas (GPU and CPU)
- Creates production resource group and workspace
- Sets up high-performance compute clusters
- Creates production environment with all dependencies
- Generates configuration files

### Step 3: Review Quota and Resources

The script will display:
- **GPU Quotas**: Available GPU families and limits
- **CPU Quotas**: Available CPU families and limits
- **Created Resources**: Workspace, compute, storage details

**Expected Resources Created:**
- Resource Group: `vulnhunter-v5-production-rg`
- ML Workspace: `vulnhunter-v5-production-workspace`
- CPU Compute: `vulnhunter-production-cluster`
- GPU Compute: `vulnhunter-gpu-cluster` (if quota available)
- Storage: `vulnhunterv5prodstorage`
- Key Vault: `vulnhunter-v5-prod-kv`

### Step 4: Prepare Production Datasets

```bash
# Source the production environment
source .env.production

# Prepare comprehensive datasets (200K samples)
python prepare_production_datasets.py --size 200000 --workers 16
```

**Dataset Features:**
- **200,000 samples** across 8 vulnerability categories
- **Real + Synthetic**: Combines existing datasets with advanced synthetic patterns
- **Multi-language**: C/C++, Java, Python, JavaScript, Solidity
- **Comprehensive Features**: 50+ security-focused features

### Step 5: Local Testing (Optional)

```bash
# Test with smaller dataset locally
python train_production_full.py \
  --data-path ./data/production_full/vulnhunter_v5_production_full_dataset.csv \
  --target-f1 0.99 \
  --cv-folds 5 \
  --random-search-iter 20
```

### Step 6: Submit Production Training Job

```bash
# Submit to Azure ML
az ml job create \
  --file production_training_job.yml \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg
```

## 📊 Production Training Configuration

### Advanced Model Ensemble
- **Random Forest**: 500 estimators, optimized parameters
- **Extra Trees**: 400 estimators, balanced classes
- **Gradient Boosting**: 300 estimators, adaptive learning
- **XGBoost**: Advanced gradient boosting with regularization
- **LightGBM**: Fast gradient boosting with optimal memory usage
- **Neural Network**: Deep MLP with adaptive learning
- **CatBoost**: Categorical feature handling (if available)

### Hyperparameter Optimization
- **Random Search**: 100 iterations per model
- **Cross-Validation**: 10-fold stratified CV
- **Scoring**: F1-weighted for imbalanced data
- **Early Stopping**: Prevents overfitting

### Performance Targets
- **F1 Score**: ≥ 99%
- **Accuracy**: ≥ 98%
- **AUC**: ≥ 0.99
- **CV Stability**: Low variance across folds

## 🔧 Monitoring and Management

### Azure Portal Access
```bash
# After setup, access your workspace at:
https://ml.azure.com/?workspace=vulnhunter-v5-production-workspace

# Resource group management:
https://portal.azure.com/#@/resource/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/vulnhunter-v5-production-rg
```

### Job Monitoring
```bash
# List recent jobs
az ml job list \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg

# Stream job logs
az ml job stream \
  --name JOB_NAME \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg
```

### Download Results
```bash
# Download trained models and results
az ml job download \
  --name JOB_NAME \
  --output-name model_output \
  --download-path ./production_results \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg
```

## 🎯 Expected Results

### Dataset Scale
- **200,000 total samples**
- **~150,000 vulnerable samples** (75%)
- **~50,000 safe samples** (25%)
- **50+ engineered features**
- **8 vulnerability categories**

### Model Performance
- **Best Model F1**: > 99%
- **Ensemble Accuracy**: > 98%
- **Training Time**: 2-4 hours (depending on compute)
- **Cross-Validation**: Stable performance across folds

### Output Artifacts
- **Best Model**: `vulnhunter_v5_production_BEST_MODEL.joblib`
- **Full Ensemble**: `vulnhunter_v5_production_ensemble.joblib`
- **Scalers**: `vulnhunter_v5_production_scalers.joblib`
- **Results**: `production_training_results.json`
- **Feature Importance**: `feature_importance.csv`

## 🚨 Troubleshooting

### Common Issues

**1. GPU Quota Limitations**
```bash
# If GPU quota is 0, training will use optimized CPU clusters
# Check quota with:
az vm list-usage --location eastus --query "[?contains(name.value, 'NC')]"
```

**2. Compute Creation Failures**
```bash
# Script tries multiple VM sizes automatically
# Manual creation if needed:
az ml compute create --name backup-cluster --type amlcompute --size Standard_D4s_v3
```

**3. Environment Issues**
```bash
# Recreate environment if needed:
az ml environment create --file production_environment.yml
```

**4. Dataset Size Issues**
```bash
# Reduce dataset size if storage limited:
python prepare_production_datasets.py --size 100000
```

### Performance Optimization

**For Faster Training:**
- Reduce `--random-search-iter` to 50
- Reduce `--cv-folds` to 5
- Use smaller dataset size

**For Better Accuracy:**
- Increase `--random-search-iter` to 200
- Increase `--cv-folds` to 15
- Use maximum dataset size (200K+)

## 🔮 Next Steps After Training

1. **Model Validation**: Test on holdout datasets
2. **API Deployment**: Deploy best model as REST API
3. **CI/CD Pipeline**: Automate retraining on new data
4. **Production Integration**: Integrate with security tools
5. **Monitoring**: Set up model performance monitoring

---

**Ready for enterprise-scale vulnerability detection with your new Azure account! 🚀**