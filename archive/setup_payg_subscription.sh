#!/bin/bash

# VulnHunter V5 Pay-As-You-Go Subscription Setup
# Direct setup on the switched subscription

set -e

echo "🚀 VulnHunter V5 Pay-As-You-Go Subscription Setup"
echo "================================================="

# Configuration for Pay-As-You-Go subscription
PAYG_RESOURCE_GROUP="vulnhunter-v5-payg-production-rg"
PAYG_WORKSPACE_NAME="vulnhunter-v5-payg-production-workspace"
LOCATION="eastus"
PAYG_COMPUTE_NAME="vulnhunter-payg-production-cluster"
PAYG_STORAGE="vulnhunterv5$(date +%s | tail -c 6)"
PAYG_KEYVAULT="vulnhunter-payg-kv-$(date +%s | tail -c 6)"

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

# Get current subscription
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SUBSCRIPTION_NAME=$(az account show --query name -o tsv)

log_info "Using Pay-As-You-Go Subscription:"
log_info "  Name: $SUBSCRIPTION_NAME"
log_info "  ID: $SUBSCRIPTION_ID"

# Create resource group
log_info "Creating resource group: $PAYG_RESOURCE_GROUP"
az group create --name "$PAYG_RESOURCE_GROUP" --location "$LOCATION" --output none

# Create storage account
log_info "Creating storage account: $PAYG_STORAGE"
az storage account create \
    --name "$PAYG_STORAGE" \
    --resource-group "$PAYG_RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
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

# Create ML workspace
log_info "Creating Azure ML workspace: $PAYG_WORKSPACE_NAME"

cat > payg_workspace_final.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/workspace.schema.json
name: $PAYG_WORKSPACE_NAME
location: $LOCATION
resource_group: $PAYG_RESOURCE_GROUP
description: VulnHunter V5 Pay-As-You-Go Production Workspace
storage_account: $STORAGE_ID
key_vault: $KV_ID
tags:
  project: vulnhunter-v5-payg-production
  purpose: full-scale-training
  version: "5.0"
EOF

az ml workspace create --file payg_workspace_final.yml --resource-group "$PAYG_RESOURCE_GROUP"

# Create compute cluster with available quota
log_info "Creating compute cluster: $PAYG_COMPUTE_NAME"

# Try different VM sizes based on quota
VM_SIZES=("Standard_D8s_v3" "Standard_D4s_v3" "Standard_D2s_v3")

for vm_size in "${VM_SIZES[@]}"; do
    log_info "Attempting to create cluster with $vm_size..."

    cat > payg_compute_final.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/amlCompute.schema.json
name: $PAYG_COMPUTE_NAME
type: amlcompute
size: $vm_size
location: $LOCATION
min_instances: 0
max_instances: 2
idle_time_before_scale_down: 300
description: VulnHunter V5 Pay-As-You-Go production compute cluster
EOF

    if az ml compute create --file payg_compute_final.yml --workspace-name "$PAYG_WORKSPACE_NAME" --resource-group "$PAYG_RESOURCE_GROUP" 2>/dev/null; then
        log_info "✅ Successfully created compute cluster with $vm_size"
        CREATED_VM_SIZE=$vm_size
        break
    else
        log_warn "❌ Failed to create cluster with $vm_size, trying next size..."
    fi
done

# Create environment
log_info "Creating production environment..."

cat > payg_environment_final.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/environment.schema.json
name: vulnhunter-v5-payg-production-env
description: VulnHunter V5 Pay-As-You-Go production environment
conda_file: payg_conda_final.yml
image: mcr.microsoft.com/azureml/pytorch-1.13-ubuntu20.04-py38-cpu:latest
EOF

cat > payg_conda_final.yml << EOF
name: vulnhunter-v5-payg-production
channels:
  - pytorch
  - conda-forge
  - defaults
dependencies:
  - python=3.10
  - scikit-learn>=1.3.0
  - pandas>=2.0.0
  - numpy>=1.24.0
  - pip
  - pip:
    - azureml-core>=1.52.0
    - azureml-mlflow
    - xgboost>=1.7.0
    - lightgbm>=4.0.0
    - joblib>=1.3.0
    - tqdm>=4.65.0
EOF

az ml environment create --file payg_environment_final.yml --workspace-name "$PAYG_WORKSPACE_NAME" --resource-group "$PAYG_RESOURCE_GROUP"

# Create configuration files
mkdir -p .azureml

cat > .azureml/payg_production_config.json << EOF
{
    "subscription_id": "$SUBSCRIPTION_ID",
    "resource_group": "$PAYG_RESOURCE_GROUP",
    "workspace_name": "$PAYG_WORKSPACE_NAME",
    "compute_name": "$PAYG_COMPUTE_NAME",
    "environment_name": "vulnhunter-v5-payg-production-env:1"
}
EOF

cat > .env.payg.production << EOF
# VulnHunter V5 Pay-As-You-Go Production Configuration
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_RESOURCE_GROUP=$PAYG_RESOURCE_GROUP
AZURE_ML_WORKSPACE_NAME=$PAYG_WORKSPACE_NAME
AZURE_COMPUTE_NAME=$PAYG_COMPUTE_NAME
AZURE_LOCATION=$LOCATION
AZURE_STORAGE_ACCOUNT=$PAYG_STORAGE
AZURE_KEY_VAULT=$PAYG_KEYVAULT

# Production Training Configuration
VULNHUNTER_ENVIRONMENT=payg_production
VULNHUNTER_DATASET_SIZE=188672
VULNHUNTER_TARGET_F1=0.99
VULNHUNTER_CV_FOLDS=10
VULNHUNTER_RANDOM_SEARCH_ITER=100
EOF

log_info "Pay-As-You-Go workspace setup completed successfully!"
echo
echo "========================================="
echo "📋 PAY-AS-YOU-GO WORKSPACE SUMMARY"
echo "========================================="
echo "Subscription: $SUBSCRIPTION_NAME"
echo "Resource Group: $PAYG_RESOURCE_GROUP"
echo "ML Workspace: $PAYG_WORKSPACE_NAME"
echo "Compute Cluster: $PAYG_COMPUTE_NAME ($CREATED_VM_SIZE)"
echo "Storage Account: $PAYG_STORAGE"
echo "Key Vault: $PAYG_KEYVAULT"
echo "Location: $LOCATION"
echo
echo "🔧 NEXT STEPS:"
echo "1. source .env.payg.production"
echo "2. az ml job create --file payg_production_job.yml \\"
echo "     --workspace-name $PAYG_WORKSPACE_NAME \\"
echo "     --resource-group $PAYG_RESOURCE_GROUP"
echo
echo "🌐 AZURE PORTAL:"
echo "- Workspace: https://ml.azure.com/?workspace=$PAYG_WORKSPACE_NAME"
echo
echo "Ready for Pay-As-You-Go production training! 🚀"