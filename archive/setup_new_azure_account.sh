#!/bin/bash

# VulnHunter V5 New Azure Account Setup
# Full-scale production workspace with enhanced quotas

set -e

echo "🚀 VulnHunter V5 New Azure Account Full-Scale Setup"
echo "=================================================="

# Configuration for new Azure account
NEW_RESOURCE_GROUP="vulnhunter-v5-production-rg"
NEW_WORKSPACE_NAME="vulnhunter-v5-production-workspace"
LOCATION="eastus"  # Primary region for better quota availability
NEW_COMPUTE_NAME="vulnhunter-production-cluster"
NEW_GPU_COMPUTE_NAME="vulnhunter-gpu-cluster"
NEW_STORAGE="vulnhunterv5prodstorage"
NEW_KEYVAULT="vulnhunter-v5-prod-kv"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
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

log_header() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

# Check Azure CLI
if ! command -v az &> /dev/null; then
    log_error "Azure CLI not found. Please install it first."
    exit 1
fi

# Login to new Azure account
log_header "Please login to your NEW Azure account when prompted..."
az login --use-device-code

# Get subscription details
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

log_info "Connected to Azure Account:"
log_info "  Subscription: $SUBSCRIPTION_NAME"
log_info "  ID: $SUBSCRIPTION_ID"
log_info "  Tenant: $TENANT_ID"

# Check quotas in new account
log_header "Checking available quotas in new Azure account..."

# Check GPU quotas
log_info "Checking GPU quotas..."
az vm list-usage --location $LOCATION --query "[?contains(name.value, 'NC') || contains(name.value, 'GPU')].{name:name.value, current:currentValue, limit:limit}" -o table

# Check general compute quotas
log_info "Checking general compute quotas..."
az vm list-usage --location $LOCATION --query "[?contains(name.value, 'standardD') || contains(name.value, 'cores')].{name:name.value, current:currentValue, limit:limit}" -o table

# Create production resource group
log_header "Creating production resource group: $NEW_RESOURCE_GROUP"
az group create --name "$NEW_RESOURCE_GROUP" --location "$LOCATION" --output none

# Create premium storage for large datasets
log_header "Creating production storage account: $NEW_STORAGE"
az storage account create \
    --name "$NEW_STORAGE" \
    --resource-group "$NEW_RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --access-tier Hot \
    --allow-blob-public-access false \
    --output none

# Create Key Vault
log_header "Creating production Key Vault: $NEW_KEYVAULT"
az keyvault create \
    --name "$NEW_KEYVAULT" \
    --resource-group "$NEW_RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none

# Get resource IDs
STORAGE_ID=$(az storage account show --name "$NEW_STORAGE" --resource-group "$NEW_RESOURCE_GROUP" --query id -o tsv)
KV_ID=$(az keyvault show --name "$NEW_KEYVAULT" --resource-group "$NEW_RESOURCE_GROUP" --query id -o tsv)

# Create ML workspace for production training
log_header "Creating Azure ML production workspace: $NEW_WORKSPACE_NAME"

cat > production_workspace.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/workspace.schema.json
name: $NEW_WORKSPACE_NAME
location: $LOCATION
resource_group: $NEW_RESOURCE_GROUP
description: VulnHunter V5 Production ML Workspace for full-scale training with enhanced quotas
storage_account: $STORAGE_ID
key_vault: $KV_ID
tags:
  project: vulnhunter-v5-production
  purpose: full-scale-training
  environment: production
  version: "5.0"
EOF

az ml workspace create --file production_workspace.yml --resource-group "$NEW_RESOURCE_GROUP"

# Create high-performance compute cluster
log_header "Creating high-performance compute cluster: $NEW_COMPUTE_NAME"

# Try different VM sizes based on available quota
VM_SIZES=("Standard_D16s_v3" "Standard_D8s_v3" "Standard_D4s_v3" "Standard_DS3_v2")

for vm_size in "${VM_SIZES[@]}"; do
    log_info "Attempting to create cluster with $vm_size..."

    cat > production_compute.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/amlCompute.schema.json
name: $NEW_COMPUTE_NAME
type: amlcompute
size: $vm_size
location: $LOCATION
min_instances: 0
max_instances: 10
idle_time_before_scale_down: 600
description: VulnHunter V5 production compute cluster for full-scale training
tier: dedicated
EOF

    if az ml compute create --file production_compute.yml --workspace-name "$NEW_WORKSPACE_NAME" --resource-group "$NEW_RESOURCE_GROUP" 2>/dev/null; then
        log_info "✅ Successfully created compute cluster with $vm_size"
        CREATED_VM_SIZE=$vm_size
        break
    else
        log_warn "❌ Failed to create cluster with $vm_size, trying next size..."
    fi
done

# Try to create GPU compute cluster if quota available
log_header "Attempting to create GPU compute cluster: $NEW_GPU_COMPUTE_NAME"

GPU_SIZES=("Standard_NC6s_v3" "Standard_NC4as_T4_v3" "Standard_NC6" "Standard_NC12")

for gpu_size in "${GPU_SIZES[@]}"; do
    log_info "Attempting to create GPU cluster with $gpu_size..."

    cat > production_gpu_compute.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/amlCompute.schema.json
name: $NEW_GPU_COMPUTE_NAME
type: amlcompute
size: $gpu_size
location: $LOCATION
min_instances: 0
max_instances: 4
idle_time_before_scale_down: 300
description: VulnHunter V5 GPU compute cluster for accelerated training
tier: dedicated
EOF

    if az ml compute create --file production_gpu_compute.yml --workspace-name "$NEW_WORKSPACE_NAME" --resource-group "$NEW_RESOURCE_GROUP" 2>/dev/null; then
        log_info "✅ Successfully created GPU cluster with $gpu_size"
        CREATED_GPU_SIZE=$gpu_size
        GPU_AVAILABLE=true
        break
    else
        log_warn "❌ Failed to create GPU cluster with $gpu_size, trying next size..."
    fi
done

if [ -z "$GPU_AVAILABLE" ]; then
    log_warn "No GPU quota available, will use CPU-only training"
    GPU_AVAILABLE=false
fi

# Create advanced environment for full-scale training
log_header "Creating production training environment..."

cat > production_environment.yml << EOF
\$schema: https://azuremlschemas.azureedge.net/latest/environment.schema.json
name: vulnhunter-v5-production-env
description: VulnHunter V5 production environment for full-scale training
conda_file: production_conda_env.yml
image: mcr.microsoft.com/azureml/pytorch-1.13-ubuntu20.04-py38-cpu:latest
EOF

cat > production_conda_env.yml << EOF
name: vulnhunter-v5-production
channels:
  - pytorch
  - conda-forge
  - defaults
dependencies:
  - python=3.10
  - pytorch>=1.13
  - scikit-learn>=1.3.0
  - pandas>=2.0.0
  - numpy>=1.24.0
  - networkx>=3.1
  - requests>=2.28.0
  - matplotlib>=3.7.0
  - seaborn>=0.12.0
  - pip
  - pip:
    - azureml-core>=1.52.0
    - azureml-mlflow>=1.52.0
    - transformers>=4.30.0
    - imbalanced-learn>=0.11.0
    - shap>=0.42.0
    - structlog>=23.1.0
    - ray[tune]>=2.6.0
    - optuna>=3.3.0
    - xgboost>=1.7.0
    - lightgbm>=4.0.0
    - catboost>=1.2.0
    - hyperopt>=0.2.7
    - joblib>=1.3.0
    - tqdm>=4.65.0
EOF

az ml environment create --file production_environment.yml --workspace-name "$NEW_WORKSPACE_NAME" --resource-group "$NEW_RESOURCE_GROUP"

# Create configuration files
log_header "Creating production workspace configuration..."

mkdir -p .azureml

cat > .azureml/production_config.json << EOF
{
    "subscription_id": "$SUBSCRIPTION_ID",
    "resource_group": "$NEW_RESOURCE_GROUP",
    "workspace_name": "$NEW_WORKSPACE_NAME",
    "compute_name": "$NEW_COMPUTE_NAME",
    "gpu_compute_name": "$NEW_GPU_COMPUTE_NAME",
    "environment_name": "vulnhunter-v5-production-env:1",
    "location": "$LOCATION"
}
EOF

# Create comprehensive environment variables
cat > .env.production << EOF
# VulnHunter V5 Production Azure Account Configuration
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_RESOURCE_GROUP=$NEW_RESOURCE_GROUP
AZURE_ML_WORKSPACE_NAME=$NEW_WORKSPACE_NAME
AZURE_COMPUTE_NAME=$NEW_COMPUTE_NAME
AZURE_GPU_COMPUTE_NAME=$NEW_GPU_COMPUTE_NAME
AZURE_LOCATION=$LOCATION
AZURE_STORAGE_ACCOUNT=$NEW_STORAGE
AZURE_KEY_VAULT=$NEW_KEYVAULT

# Production Training Configuration
VULNHUNTER_ENVIRONMENT=production
VULNHUNTER_FULL_SCALE=true
VULNHUNTER_DATASET_SIZE=100000
VULNHUNTER_TARGET_F1=0.99
VULNHUNTER_USE_GPU=$GPU_AVAILABLE
VULNHUNTER_MAX_WORKERS=32
VULNHUNTER_BATCH_SIZE=256
VULNHUNTER_HYPERPARAMETER_TUNING=true

# Model Configuration
VULNHUNTER_ENSEMBLE_SIZE=5
VULNHUNTER_CV_FOLDS=10
VULNHUNTER_RANDOM_SEARCH_ITERATIONS=100
VULNHUNTER_EARLY_STOPPING=true
EOF

log_info "Production workspace setup completed successfully!"
echo
echo "=========================================="
echo "📋 PRODUCTION WORKSPACE SUMMARY"
echo "=========================================="
echo "Subscription: $SUBSCRIPTION_NAME"
echo "Subscription ID: $SUBSCRIPTION_ID"
echo "Resource Group: $NEW_RESOURCE_GROUP"
echo "ML Workspace: $NEW_WORKSPACE_NAME"
echo "CPU Compute: $NEW_COMPUTE_NAME ($CREATED_VM_SIZE)"
if [ "$GPU_AVAILABLE" = true ]; then
    echo "GPU Compute: $NEW_GPU_COMPUTE_NAME ($CREATED_GPU_SIZE)"
else
    echo "GPU Compute: Not available (quota constraints)"
fi
echo "Storage Account: $NEW_STORAGE"
echo "Key Vault: $NEW_KEYVAULT"
echo "Location: $LOCATION"
echo
echo "💰 PRODUCTION FEATURES:"
echo "- Enhanced compute quotas"
echo "- Full-scale dataset training (100K samples)"
echo "- Advanced hyperparameter tuning"
echo "- Production-grade environment"
echo "- Comprehensive model ensemble"
echo
echo "🔧 NEXT STEPS:"
echo "1. Source production environment: source .env.production"
echo "2. Prepare full datasets: python prepare_production_datasets.py"
echo "3. Start full-scale training: python train_production_full.py"
echo
echo "🌐 AZURE PORTAL:"
echo "- Workspace: https://ml.azure.com/?workspace=$NEW_WORKSPACE_NAME"
echo "- Resource Group: https://portal.azure.com/#@/resource/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$NEW_RESOURCE_GROUP"
echo
echo "Ready for production-scale vulnerability detection training! 🚀"