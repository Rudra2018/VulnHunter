#!/bin/bash

# VulnHunter V5 Pay-As-You-Go Azure Workspace Setup
# Creates scalable workspace with pay-per-use pricing model

set -e

echo "🚀 VulnHunter V5 Pay-As-You-Go Azure Workspace Setup"
echo "===================================================="

# Configuration for pay-as-you-go workspace
PAYG_RESOURCE_GROUP="vulnhunter-v5-payg-rg"
PAYG_WORKSPACE_NAME="vulnhunter-v5-payg-workspace"
LOCATION="eastus2"
PAYG_COMPUTE_NAME="vulnhunter-payg-cluster"
PAYG_STORAGE="vulnhunterv5paygstorage"
PAYG_KEYVAULT="vulnhunter-v5-payg-kv"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Azure CLI
if ! command -v az &> /dev/null; then
    log_error "Azure CLI not found. Please install it first."
    exit 1
fi

# Check login
if ! az account show &> /dev/null; then
    log_info "Logging in to Azure..."
    az login
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
log_info "Using subscription: $SUBSCRIPTION_ID"

# Create pay-as-you-go resource group
log_info "Creating pay-as-you-go resource group: $PAYG_RESOURCE_GROUP"
az group create --name "$PAYG_RESOURCE_GROUP" --location "$LOCATION" --output none

# Create storage account for large datasets
log_info "Creating premium storage account: $PAYG_STORAGE"
az storage account create \
    --name "$PAYG_STORAGE" \
    --resource-group "$PAYG_RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku Premium_LRS \
    --kind StorageV2 \
    --access-tier Hot \
    --output none

# Create Key Vault
log_info "Creating Key Vault: $PAYG_KEYVAULT"
az keyvault create \
    --name "$PAYG_KEYVAULT" \
    --resource-group "$PAYG_RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none

# Get resource IDs
STORAGE_ID=$(az storage account show --name "$PAYG_STORAGE" --resource-group "$PAYG_RESOURCE_GROUP" --query id -o tsv)
KV_ID=$(az keyvault show --name "$PAYG_KEYVAULT" --resource-group "$PAYG_RESOURCE_GROUP" --query id -o tsv)

# Create ML workspace for pay-as-you-go
log_info "Creating Azure ML pay-as-you-go workspace: $PAYG_WORKSPACE_NAME"

cat > payg_workspace.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/workspace.schema.json
name: $PAYG_WORKSPACE_NAME
location: $LOCATION
resource_group: $PAYG_RESOURCE_GROUP
description: VulnHunter V5 Pay-As-You-Go ML Workspace for smart contract analysis
storage_account: $STORAGE_ID
key_vault: $KV_ID
tags:
  project: vulnhunter-v5-payg
  purpose: smart-contract-analysis
  pricing: pay-as-you-go
  version: "5.0"
EOF

az ml workspace create --file payg_workspace.yml --resource-group "$PAYG_RESOURCE_GROUP"

# Create scalable compute cluster with auto-scaling
log_info "Creating scalable pay-as-you-go compute cluster: $PAYG_COMPUTE_NAME"

cat > payg_compute.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/amlCompute.schema.json
name: $PAYG_COMPUTE_NAME
type: amlcompute
size: Standard_D8s_v3
location: $LOCATION
min_instances: 0
max_instances: 20
idle_time_before_scale_down: 120
description: Pay-as-you-go auto-scaling cluster for VulnHunter V5 smart contract training
EOF

az ml compute create --file payg_compute.yml --workspace-name "$PAYG_WORKSPACE_NAME" --resource-group "$PAYG_RESOURCE_GROUP"

# Create enhanced environment for smart contract analysis
log_info "Creating smart contract analysis environment..."

cat > payg_environment.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/environment.schema.json
name: vulnhunter-v5-smartcontract-env
description: VulnHunter V5 smart contract analysis environment with blockchain tools
conda_file: payg_conda_env.yml
image: mcr.microsoft.com/azureml/pytorch-1.13-ubuntu20.04-py38-cpu:latest
EOF

cat > payg_conda_env.yml << EOF
name: vulnhunter-v5-smartcontract
channels:
  - pytorch
  - conda-forge
  - defaults
dependencies:
  - python=3.10
  - pytorch-cpu=1.13
  - scikit-learn>=1.3.0
  - pandas>=2.0.0
  - numpy>=1.24.0
  - networkx>=3.1
  - requests>=2.28.0
  - pip
  - pip:
    - azureml-core>=1.52.0
    - azureml-mlflow
    - transformers>=4.30.0
    - imbalanced-learn>=0.11.0
    - shap>=0.42.0
    - structlog>=23.1.0
    - web3>=6.0.0
    - eth-brownie>=1.19.0
    - slither-analyzer>=0.9.0
    - mythril>=0.23.0
    - solcx>=1.12.0
    - py-solc-x>=1.12.0
    - beautifulsoup4>=4.11.0
    - aiohttp>=3.8.0
    - asyncio-throttle>=1.0.0
EOF

az ml environment create --file payg_environment.yml --workspace-name "$PAYG_WORKSPACE_NAME" --resource-group "$PAYG_RESOURCE_GROUP"

# Create configuration files
log_info "Creating workspace configuration..."

mkdir -p .azureml

cat > .azureml/payg_config.json << EOF
{
    "subscription_id": "$SUBSCRIPTION_ID",
    "resource_group": "$PAYG_RESOURCE_GROUP",
    "workspace_name": "$PAYG_WORKSPACE_NAME",
    "compute_name": "$PAYG_COMPUTE_NAME",
    "environment_name": "vulnhunter-v5-smartcontract-env:1"
}
EOF

# Create environment variables
cat > .env.payg << EOF
# VulnHunter V5 Pay-As-You-Go Workspace Configuration
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_RESOURCE_GROUP=$PAYG_RESOURCE_GROUP
AZURE_ML_WORKSPACE_NAME=$PAYG_WORKSPACE_NAME
AZURE_COMPUTE_NAME=$PAYG_COMPUTE_NAME
AZURE_LOCATION=$LOCATION
AZURE_STORAGE_ACCOUNT=$PAYG_STORAGE
AZURE_KEY_VAULT=$PAYG_KEYVAULT

# Smart Contract Analysis Configuration
VULNHUNTER_USE_PAYG=true
VULNHUNTER_MAX_WORKERS=16
VULNHUNTER_BATCH_SIZE=128
VULNHUNTER_TARGET_F1=0.97
VULNHUNTER_AUTO_SCALE=true

# Blockchain Data Sources
ETHERSCAN_API_KEY=""
INFURA_PROJECT_ID=""
ALCHEMY_API_KEY=""
EOF

log_info "Pay-as-you-go workspace setup completed successfully!"
echo
echo "======================================"
echo "📋 PAY-AS-YOU-GO WORKSPACE SUMMARY"
echo "======================================"
echo "Resource Group: $PAYG_RESOURCE_GROUP"
echo "ML Workspace: $PAYG_WORKSPACE_NAME"
echo "Compute Cluster: $PAYG_COMPUTE_NAME (Standard_D8s_v3, 0-20 auto-scaling)"
echo "Storage Account: $PAYG_STORAGE (Premium SSD)"
echo "Key Vault: $PAYG_KEYVAULT"
echo
echo "💰 PRICING MODEL:"
echo "- Pay only for compute time used"
echo "- Auto-scaling from 0-20 instances"
echo "- Premium storage for large datasets"
echo "- No idle costs when not training"
echo
echo "🔧 NEXT STEPS:"
echo "1. Source the PAYG environment: source .env.payg"
echo "2. Enhance datasets: python enhance_smart_contract_datasets.py"
echo "3. Start training: python train_payg_enhanced.py"
echo
echo "🌐 AZURE PORTAL:"
echo "- Workspace: https://ml.azure.com/?workspace=$PAYG_WORKSPACE_NAME"
echo
echo "Ready for large-scale smart contract vulnerability analysis! 🚀"