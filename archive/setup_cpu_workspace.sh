#!/bin/bash

# VulnHunter V5 CPU-Optimized Azure Workspace Setup
# Creates dedicated CPU workspace when GPU quota is unavailable

set -e

echo "🚀 VulnHunter V5 CPU-Optimized Azure Workspace Setup"
echo "=================================================="

# Configuration for CPU workspace
CPU_RESOURCE_GROUP="vulnhunter-v5-cpu-rg"
CPU_WORKSPACE_NAME="vulnhunter-v5-cpu-workspace"
LOCATION="eastus2"
CPU_COMPUTE_NAME="vulnhunter-cpu-compute"
CPU_STORAGE="vulnhunterv5cpustorage"
CPU_KEYVAULT="vulnhunter-v5-cpu-kv"

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

# Create CPU-optimized resource group
log_info "Creating CPU-optimized resource group: $CPU_RESOURCE_GROUP"
az group create --name "$CPU_RESOURCE_GROUP" --location "$LOCATION" --output none

# Create storage account
log_info "Creating storage account: $CPU_STORAGE"
az storage account create \
    --name "$CPU_STORAGE" \
    --resource-group "$CPU_RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --output none

# Create Key Vault
log_info "Creating Key Vault: $CPU_KEYVAULT"
az keyvault create \
    --name "$CPU_KEYVAULT" \
    --resource-group "$CPU_RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none

# Create ML workspace for CPU training
log_info "Creating Azure ML workspace: $CPU_WORKSPACE_NAME"

# Get resource IDs
STORAGE_ID=$(az storage account show --name "$CPU_STORAGE" --resource-group "$CPU_RESOURCE_GROUP" --query id -o tsv)
KV_ID=$(az keyvault show --name "$CPU_KEYVAULT" --resource-group "$CPU_RESOURCE_GROUP" --query id -o tsv)

# Create workspace YAML
cat > cpu_workspace.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/workspace.schema.json
name: $CPU_WORKSPACE_NAME
location: $LOCATION
resource_group: $CPU_RESOURCE_GROUP
description: VulnHunter V5 CPU-Optimized ML Workspace for large-scale training
storage_account: $STORAGE_ID
key_vault: $KV_ID
tags:
  project: vulnhunter-v5-cpu
  purpose: cpu-optimized-training
  version: "5.0"
EOF

az ml workspace create --file cpu_workspace.yml --resource-group "$CPU_RESOURCE_GROUP"

# Create high-performance CPU compute cluster
log_info "Creating high-performance CPU compute cluster: $CPU_COMPUTE_NAME"

cat > cpu_compute.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/amlCompute.schema.json
name: $CPU_COMPUTE_NAME
type: amlcompute
size: Standard_D16s_v3
location: $LOCATION
min_instances: 0
max_instances: 10
idle_time_before_scale_down: 300
description: High-performance CPU cluster for VulnHunter V5 large-scale training
EOF

az ml compute create --file cpu_compute.yml --workspace-name "$CPU_WORKSPACE_NAME" --resource-group "$CPU_RESOURCE_GROUP"

# Create environment configuration
log_info "Creating optimized training environment..."

cat > cpu_environment.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/environment.schema.json
name: vulnhunter-v5-cpu-env
description: VulnHunter V5 CPU-optimized training environment
conda_file: cpu_conda_env.yml
image: mcr.microsoft.com/azureml/pytorch-1.13-ubuntu20.04-py38-cpu:latest
EOF

cat > cpu_conda_env.yml << EOF
name: vulnhunter-v5-cpu
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
  - pip
  - pip:
    - azureml-core>=1.52.0
    - azureml-mlflow
    - transformers>=4.30.0
    - imbalanced-learn>=0.11.0
    - shap>=0.42.0
    - structlog>=23.1.0
    - ray[tune]>=2.6.0
    - torch-geometric>=2.4.0
EOF

az ml environment create --file cpu_environment.yml --workspace-name "$CPU_WORKSPACE_NAME" --resource-group "$CPU_RESOURCE_GROUP"

# Create configuration file
log_info "Creating workspace configuration..."

cat > .azureml/cpu_config.json << EOF
{
    "subscription_id": "$SUBSCRIPTION_ID",
    "resource_group": "$CPU_RESOURCE_GROUP",
    "workspace_name": "$CPU_WORKSPACE_NAME",
    "compute_name": "$CPU_COMPUTE_NAME",
    "environment_name": "vulnhunter-v5-cpu-env:1"
}
EOF

# Create environment variables
cat > .env.cpu << EOF
# VulnHunter V5 CPU Workspace Configuration
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_RESOURCE_GROUP=$CPU_RESOURCE_GROUP
AZURE_ML_WORKSPACE_NAME=$CPU_WORKSPACE_NAME
AZURE_COMPUTE_NAME=$CPU_COMPUTE_NAME
AZURE_LOCATION=$LOCATION
AZURE_STORAGE_ACCOUNT=$CPU_STORAGE
AZURE_KEY_VAULT=$CPU_KEYVAULT

# Training configuration
VULNHUNTER_USE_CPU=true
VULNHUNTER_MAX_WORKERS=16
VULNHUNTER_BATCH_SIZE=64
VULNHUNTER_TARGET_F1=0.95
EOF

log_info "CPU workspace setup completed successfully!"
echo
echo "=================================="
echo "📋 CPU WORKSPACE SUMMARY"
echo "=================================="
echo "Resource Group: $CPU_RESOURCE_GROUP"
echo "ML Workspace: $CPU_WORKSPACE_NAME"
echo "Compute Cluster: $CPU_COMPUTE_NAME (Standard_D16s_v3, 0-10 instances)"
echo "Storage Account: $CPU_STORAGE"
echo "Key Vault: $CPU_KEYVAULT"
echo
echo "🔧 NEXT STEPS:"
echo "1. Source the CPU environment: source .env.cpu"
echo "2. Prepare full datasets: python prepare_full_datasets.py"
echo "3. Start large-scale training: python train_cpu_optimized.py"
echo
echo "🌐 AZURE PORTAL:"
echo "- Workspace: https://ml.azure.com/?workspace=$CPU_WORKSPACE_NAME"
echo
echo "Ready for large-scale vulnerability detection training! 🚀"