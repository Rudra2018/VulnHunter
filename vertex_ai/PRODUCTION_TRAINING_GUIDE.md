# VulnHunter V4 Production Training Guide

## 🚀 Real Vertex AI Training Setup

This guide walks you through training VulnHunter V4 on real Vertex AI infrastructure with the comprehensive dataset we've prepared.

## 📋 Prerequisites

### 1. Google Cloud Setup
- **Google Cloud Project**: Active project with billing enabled
- **APIs Required**:
  - Vertex AI API
  - Cloud Storage API
  - Compute Engine API
- **Authentication**: gcloud CLI installed and authenticated

### 2. Permissions Required
- `aiplatform.customJobs.create`
- `storage.buckets.create`
- `storage.objects.create`
- `storage.objects.get`

### 3. Resource Requirements
- **Machine Type**: n1-standard-8 (8 vCPUs, 30GB RAM)
- **GPU**: NVIDIA Tesla T4
- **Storage**: ~10GB for training data and artifacts
- **Training Time**: ~1-2 hours
- **Estimated Cost**: $10-20 for complete training

## 🛠️ Setup Options

### Option 1: Python Launcher (Recommended)

1. **Configure your project**:
   ```bash
   cd /Users/ankitthakur/vuln_ml_research/vertex_ai
   python3 python_production_launcher.py
   ```

2. **Enter your details when prompted**:
   - Google Cloud Project ID
   - Vertex AI location (default: us-central1)

3. **The script will automatically**:
   - ✅ Check prerequisites
   - ✅ Enable required APIs
   - ✅ Create storage bucket
   - ✅ Upload training data (1,812 examples)
   - ✅ Submit training job
   - ✅ Provide monitoring instructions

### Option 2: Shell Script

1. **Edit the configuration**:
   ```bash
   nano setup_production_training.sh
   # Update PROJECT_ID with your actual project ID
   ```

2. **Run the setup**:
   ```bash
   chmod +x setup_production_training.sh
   ./setup_production_training.sh
   ```

### Option 3: Manual gcloud Commands

1. **Set up project**:
   ```bash
   export PROJECT_ID="your-project-id"
   export LOCATION="us-central1"
   export BUCKET_NAME="${PROJECT_ID}-vulnhunter-training"

   gcloud config set project $PROJECT_ID
   gcloud services enable aiplatform.googleapis.com storage.googleapis.com
   ```

2. **Create bucket and upload data**:
   ```bash
   gsutil mb -l $LOCATION gs://$BUCKET_NAME
   gsutil -m cp -r /Users/ankitthakur/vuln_ml_research/data/training/* gs://$BUCKET_NAME/training_data/
   gsutil cp production_vulnhunter_trainer.py gs://$BUCKET_NAME/training_code/
   ```

3. **Submit training job**:
   ```bash
   gcloud ai custom-jobs create \
     --region=$LOCATION \
     --display-name="vulnhunter-v4-production" \
     --python-package-uris="gs://$BUCKET_NAME/training_code/production_requirements.txt" \
     --python-module="production_vulnhunter_trainer" \
     --args="--project_id=$PROJECT_ID,--location=$LOCATION,--bucket_name=$BUCKET_NAME,--training_data_paths=gs://$BUCKET_NAME/training_data/synthetic/synthetic_training_dataset.json"
   ```

## 📊 Training Data Overview

The production training will use:

| Dataset | Examples | Type | Purpose |
|---------|----------|------|---------|
| **Synthetic Dataset** | 1,800 | Generated | Comprehensive false positive patterns |
| **Gemini CLI Validation** | 6 | Real Analysis | Complete fabrication detection |
| **Ollama Validation** | 6 | Real Analysis | Mixed pattern learning |
| **Historical False Positives** | 6 | Real Analysis | Pattern recognition |
| **Total** | **1,812** | **Mixed** | **Enhanced V4 Training** |

### Dataset Composition:
- **55.6% False Positives**: Realistic distribution for false positive detection
- **Framework Coverage**: Express.js, TypeScript, React, Go, Rust patterns
- **Vulnerability Types**: Command injection, path traversal, XSS, authentication, etc.

## 🏗️ Training Architecture

### Model Specifications:
- **Architecture**: Enhanced neural network with attention mechanism
- **Input Features**: 16 engineered features including source validation, framework awareness
- **Loss Function**: Weighted focal loss with 15x false positive penalty
- **Training Strategy**: Early stopping, learning rate reduction, class balancing

### Key Features:
1. **Source Code Validation Layer**: Mandatory file/function existence checks
2. **Framework Security Assessment**: Express.js, TypeScript protection recognition
3. **Statistical Realism Checker**: Artificial confidence detection
4. **Attention Mechanism**: Weighted feature importance

## 📈 Expected Performance

Based on local validation:

| Metric | Target | Local Performance |
|--------|--------|-------------------|
| **False Positive Detection** | >95% | 100% (fabricated claims) |
| **Framework Awareness** | >90% | 100% (protection recognition) |
| **Overall Accuracy** | >80% | 75.4% training, 63.6% validation |
| **Training Time** | <2 hours | ~45 minutes locally |

## 🔍 Monitoring Training

### Real-time Monitoring:
```bash
# List training jobs
gcloud ai custom-jobs list --region=us-central1

# Stream logs (replace JOB_ID)
gcloud ai custom-jobs stream-logs JOB_ID --region=us-central1

# Get job details
gcloud ai custom-jobs describe JOB_ID --region=us-central1
```

### Vertex AI Console:
- Visit: `https://console.cloud.google.com/vertex-ai/training/custom-jobs?project=YOUR_PROJECT_ID`
- Monitor metrics, logs, and resource usage
- View TensorBoard for detailed training metrics

### Key Metrics to Watch:
- **Validation AUC**: Target >0.9
- **False Positive Rate**: Target <0.05
- **Training Loss**: Should decrease steadily
- **GPU Utilization**: Should be >80%

## 📁 Training Artifacts

After successful training, artifacts will be saved to:

```
gs://YOUR_PROJECT-vulnhunter-training/models/vulnhunter_v4_production_TIMESTAMP/
├── vulnhunter_v4_production_model.h5          # Trained TensorFlow model
├── feature_scaler.pkl                         # Feature preprocessing
├── label_encoders.pkl                         # Categorical encoders
├── production_config.json                     # Complete configuration
└── training_logs/                             # Detailed training logs
```

## 🚀 Model Deployment

### Option 1: Vertex AI Endpoints
```bash
# Deploy to Vertex AI endpoint for real-time prediction
gcloud ai endpoints create --display-name="vulnhunter-v4-endpoint" --region=us-central1

# Deploy model to endpoint
gcloud ai endpoints deploy-model ENDPOINT_ID \
  --region=us-central1 \
  --model=MODEL_ID \
  --display-name="vulnhunter-v4-deployment"
```

### Option 2: Download for Local Use
```bash
# Download trained artifacts
gsutil -m cp -r gs://YOUR_BUCKET/models/vulnhunter_v4_production_* ./local_model/

# Use with enhanced predictor
python3 -c "
from vulnhunter_v4_enhanced_predictor import VulnHunterV4EnhancedPredictor
predictor = VulnHunterV4EnhancedPredictor('./local_model')
result = predictor.analyze_vulnerability_claim(your_claim)
"
```

## 💰 Cost Estimation

| Resource | Duration | Cost |
|----------|----------|------|
| **n1-standard-8** | 2 hours | ~$0.80 |
| **NVIDIA Tesla T4** | 2 hours | ~$1.40 |
| **Cloud Storage** | 1 month | ~$0.50 |
| **Data Transfer** | One-time | ~$0.10 |
| **Total Estimated** | | **~$2.80** |

*Note: Actual costs may vary based on region and usage patterns*

## 🔧 Troubleshooting

### Common Issues:

1. **Authentication Error**:
   ```bash
   gcloud auth login
   gcloud auth application-default login
   ```

2. **API Not Enabled**:
   ```bash
   gcloud services enable aiplatform.googleapis.com
   ```

3. **Insufficient Quota**:
   - Check GPU quota in your region
   - Request quota increase if needed

4. **Permission Denied**:
   - Ensure you have Vertex AI Admin role
   - Check IAM permissions

5. **Training Failure**:
   - Check logs: `gcloud ai custom-jobs stream-logs JOB_ID`
   - Verify training data uploaded correctly
   - Check Python dependencies

## 📞 Support

For issues:
1. **Check logs** in Vertex AI console
2. **Review error messages** in gcloud output
3. **Verify prerequisites** are met
4. **Check quotas** and permissions

## 🎯 Next Steps

After successful training:
1. **Validate model performance** against test scenarios
2. **Deploy to production endpoint** for real-time analysis
3. **Integrate with security tools** for automated scanning
4. **Monitor model performance** and retrain as needed

---

🚀 **Ready to train VulnHunter V4 on real Vertex AI infrastructure!**