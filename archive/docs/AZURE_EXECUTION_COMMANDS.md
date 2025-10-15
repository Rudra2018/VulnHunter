# VulnHunter V5 Azure Execution Commands

## 🎉 Production Dataset Ready!

✅ **Production dataset created successfully:**
- **Total Samples**: 188,672
- **Vulnerable Samples**: 140,661 (74.6%)
- **Safe Samples**: 48,011 (25.4%)
- **Features**: 154 comprehensive security indicators
- **File**: `data/production_full/vulnhunter_v5_production_full_dataset.csv`

## 🚀 Execute These Commands on Your New Azure Account

### Step 1: Azure Account Setup
```bash
# Make the setup script executable
chmod +x setup_new_azure_account.sh

# Run the Azure setup (will prompt for login)
./setup_new_azure_account.sh
```

**Important**: This will prompt you to:
1. Open https://microsoft.com/devicelogin
2. Enter the device code shown
3. Login with your NEW Azure account credentials

### Step 2: Source Environment and Submit Training
```bash
# Source the production environment variables
source .env.production

# Submit the full production training job
az ml job create \
  --file production_training_job.yml \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg
```

### Step 3: Monitor Training Progress
```bash
# List all jobs to get the job name
az ml job list \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg

# Stream job logs (replace JOB_NAME with actual name)
az ml job stream \
  --name JOB_NAME \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg
```

### Step 4: Download Results
```bash
# Download trained models and results
az ml job download \
  --name JOB_NAME \
  --output-name model_output \
  --download-path ./production_results \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg
```

## 📊 Expected Training Results

### Production Training Configuration
- **Dataset**: 188,672 samples with 154 features
- **Models**: 7 advanced algorithms (RF, Extra Trees, XGBoost, LightGBM, etc.)
- **Hyperparameter Optimization**: 100 iterations per model
- **Cross-Validation**: 10-fold stratified CV
- **Target Performance**: 99% F1 Score

### Estimated Training Time
- **CPU Cluster (D4s_v3)**: 3-4 hours
- **GPU Cluster (if available)**: 1-2 hours
- **Larger CPU Cluster**: 1-2 hours

### Expected Output Files
```
production_results/
├── vulnhunter_v5_production_BEST_MODEL.joblib
├── vulnhunter_v5_production_ensemble.joblib
├── vulnhunter_v5_production_scalers.joblib
├── production_training_results.json
├── feature_importance.csv
└── feature_names.json
```

## 🎯 Performance Targets

### Model Performance Goals
- **F1 Score**: ≥ 99%
- **Accuracy**: ≥ 98.5%
- **Precision**: ≥ 98%
- **Recall**: ≥ 98%
- **AUC**: ≥ 0.99

### Cross-Validation Metrics
- **CV F1 Mean**: ≥ 98.5%
- **CV Standard Deviation**: ≤ 1%
- **Stability**: Consistent across all folds

## 🚨 Alternative Commands (If Issues)

### If GPU Quota Not Available
The setup script automatically falls back to CPU clusters. Training will still be highly optimized.

### If Compute Creation Fails
```bash
# Manually create smaller compute cluster
az ml compute create \
  --name backup-cluster \
  --type amlcompute \
  --size Standard_D2s_v3 \
  --min-instances 0 \
  --max-instances 1 \
  --workspace-name vulnhunter-v5-production-workspace \
  --resource-group vulnhunter-v5-production-rg

# Update job file to use backup cluster
sed -i 's/vulnhunter-production-cluster/backup-cluster/g' production_training_job.yml
```

### Local Testing First (Optional)
```bash
# Test with smaller dataset first
python train_production_full.py \
  --data-path ./data/production_full/vulnhunter_v5_production_full_dataset.csv \
  --target-f1 0.99 \
  --cv-folds 3 \
  --random-search-iter 10 \
  --test-size 0.1
```

## 📈 Real-Time Monitoring

### Azure Portal Access
After setup, monitor your training at:
- **ML Studio**: https://ml.azure.com/?workspace=vulnhunter-v5-production-workspace
- **Resource Group**: Azure Portal → Resource Groups → vulnhunter-v5-production-rg

### Job Status Checking
```bash
# Check job status every 30 minutes
watch -n 1800 "az ml job show --name JOB_NAME --workspace-name vulnhunter-v5-production-workspace --resource-group vulnhunter-v5-production-rg --query status"
```

## 🎉 Success Indicators

### Training Complete When You See
- **Job Status**: "Completed"
- **Final F1 Score**: ≥ 99%
- **Best Model Identified**: Highest performing algorithm
- **All Artifacts Saved**: Models, scalers, results files

### Next Steps After Completion
1. **Download Results**: Use download command above
2. **Model Validation**: Test on new data
3. **API Deployment**: Deploy best model as endpoint
4. **Production Integration**: Integrate with security tools

---

**🚀 Execute the Azure setup command and your production-scale VulnHunter V5 training will begin!**