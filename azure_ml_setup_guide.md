# 🔗 Azure ML Setup Guide for VulnHunter V14

## 📋 Prerequisites

1. **Azure Subscription** - You need an active Azure subscription
2. **Azure CLI** - Install Azure CLI tools
3. **Azure ML SDK** - Install Python SDK

## 🛠️ Setup Commands

### 1. Install Azure CLI
```bash
# macOS
brew install azure-cli

# Login to Azure
az login
```

### 2. Install Azure ML SDK
```bash
pip install azureml-core azureml-train-core azureml-dataset-runtime
```

### 3. Set Environment Variables
```bash
# Set your Azure subscription details
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_RESOURCE_GROUP="vulnhunter-production-rg"
export AZURE_WORKSPACE_NAME="vulnhunter-production-ws"
```

### 4. Create Resource Group
```bash
az group create --name vulnhunter-production-rg --location eastus
```

### 5. Create Azure ML Workspace
```bash
az ml workspace create \
  --name vulnhunter-production-ws \
  --resource-group vulnhunter-production-rg \
  --location eastus
```

## 🌐 Where to See Results in Azure Portal

### 1. **Azure Portal Dashboard**
- Go to: https://portal.azure.com
- Navigate to: Resource Groups → vulnhunter-production-rg → vulnhunter-production-ws

### 2. **Azure ML Studio**
- Go to: https://ml.azure.com
- Select your workspace: vulnhunter-production-ws
- Navigate to: Experiments → vulnhunter-v14-production

### 3. **Specific Locations to Check:**

#### **Experiments Tab**
- **Path**: Azure ML Studio → Experiments → vulnhunter-v14-production
- **What to see**: Training runs, metrics, logs

#### **Models Tab**
- **Path**: Azure ML Studio → Models
- **What to see**: Registered VulnHunter V14 models

#### **Compute Tab**
- **Path**: Azure ML Studio → Compute → Compute clusters
- **What to see**: vulnhunter-v14-compute cluster status

#### **Datasets Tab**
- **Path**: Azure ML Studio → Datasets
- **What to see**: Vulnerability datasets used for training

#### **Endpoints Tab**
- **Path**: Azure ML Studio → Endpoints
- **What to see**: Deployed VulnHunter V14 inference endpoints

## 📊 What You'll See

### Training Job Details
- **Job Status**: Running/Completed/Failed
- **Metrics**: Accuracy, F1-Score, Precision, Recall
- **Logs**: Training progress and output
- **Duration**: Training time
- **Resources**: CPU/Memory usage

### Model Artifacts
- **Model Files**: vulnhunter_v14_production.pkl
- **Training Results**: JSON with performance metrics
- **Feature Extractors**: TF-IDF vectorizers
- **Model Metadata**: Training configuration

## 🚀 Quick Check Commands

### Check if workspace exists
```bash
az ml workspace show --name vulnhunter-production-ws --resource-group vulnhunter-production-rg
```

### List experiments
```bash
az ml experiment list --workspace-name vulnhunter-production-ws --resource-group vulnhunter-production-rg
```

### Check compute status
```bash
az ml compute list --workspace-name vulnhunter-production-ws --resource-group vulnhunter-production-rg
```

## 🔍 Current Status

Based on our training, the Azure ML SDK wasn't available locally, so the model was trained locally. To see it in Azure, you would need to:

1. **Set up Azure subscription** (if not already done)
2. **Install Azure ML SDK**
3. **Run the deployment script** with proper credentials
4. **Submit the training job** to Azure ML

## 📱 Mobile Access

You can also check Azure ML on mobile:
- **Azure Mobile App**: Download from App Store/Play Store
- **Navigate**: Resource Groups → Your Workspace → ML Studio

## 🎯 Direct Links (replace with your details)

- **Azure Portal**: https://portal.azure.com/#@yourdomain.com/resource/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/vulnhunter-production-rg/overview
- **ML Studio**: https://ml.azure.com/workspaces/YOUR_WORKSPACE_ID

## ⚠️ Important Notes

1. **Costs**: Azure ML compute can be expensive - monitor usage
2. **Permissions**: Ensure you have Contributor access to the resource group
3. **Regions**: Use the same region for all resources to avoid data transfer costs
4. **Cleanup**: Delete resources when not needed to avoid charges

## 🛠️ Troubleshooting

### If you can't see the workspace:
```bash
# Check your subscriptions
az account list

# Set the correct subscription
az account set --subscription "your-subscription-id"
```

### If training job failed:
- Check logs in Azure ML Studio
- Verify compute target is running
- Check environment dependencies