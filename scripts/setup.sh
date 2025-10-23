#!/bin/bash

# VulnHunter V5 Azure Environment Setup Script
# This script sets up the complete Azure ML environment for VulnHunter V5

set -e  # Exit on any error

echo "🚀 VulnHunter V5 Azure Environment Setup"
echo "========================================"

# Configuration variables
RESOURCE_GROUP="vulnhunter-rg"
WORKSPACE_NAME="vulnhunter-ml-workspace"
LOCATION="eastus2"
COMPUTE_NAME="vulnhunter-gpu-cluster"
ACR_NAME="vulnhunteracr$(date +%s)"
STORAGE_ACCOUNT="vulnhunterstorage$(date +%s)"
KEY_VAULT="vulnhunter-kv-$(date +%s)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Azure CLI is installed
    if ! command -v az &> /dev/null; then
        log_error "Azure CLI is not installed. Please install it from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi

    # Check if Python 3.10+ is installed
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if [[ $(echo "$PYTHON_VERSION < 3.10" | bc) -eq 1 ]]; then
        log_error "Python 3.10+ is required. Current version: $PYTHON_VERSION"
        exit 1
    fi

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_warn "Docker is not installed. Docker is required for containerized deployment."
    fi

    log_info "Prerequisites check completed"
}

# Login to Azure
azure_login() {
    log_info "Checking Azure login status..."

    if ! az account show &> /dev/null; then
        log_info "Not logged in to Azure. Starting login process..."
        az login
    else
        log_info "Already logged in to Azure"
        SUBSCRIPTION_ID=$(az account show --query id -o tsv)
        log_info "Current subscription: $SUBSCRIPTION_ID"
    fi

    # Set subscription if multiple exist
    SUBSCRIPTION_COUNT=$(az account list --query "length(@)" -o tsv)
    if [[ $SUBSCRIPTION_COUNT -gt 1 ]]; then
        log_info "Multiple subscriptions found. Please select one:"
        az account list --output table
        read -p "Enter subscription ID: " SUBSCRIPTION_ID
        az account set --subscription "$SUBSCRIPTION_ID"
    fi

    export SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    log_info "Using subscription: $SUBSCRIPTION_ID"
}

# Create resource group
create_resource_group() {
    log_info "Creating resource group: $RESOURCE_GROUP"

    if az group show --name "$RESOURCE_GROUP" &> /dev/null; then
        log_warn "Resource group $RESOURCE_GROUP already exists"
    else
        az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
        log_info "Resource group created successfully"
    fi
}

# Create Azure Container Registry
create_acr() {
    log_info "Creating Azure Container Registry: $ACR_NAME"

    if az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log_warn "ACR $ACR_NAME already exists"
    else
        az acr create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$ACR_NAME" \
            --sku Standard \
            --admin-enabled true
        log_info "Azure Container Registry created successfully"
    fi

    # Login to ACR
    az acr login --name "$ACR_NAME"
    ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --query loginServer -o tsv)
    export ACR_LOGIN_SERVER
    log_info "ACR login server: $ACR_LOGIN_SERVER"
}

# Create storage account
create_storage() {
    log_info "Creating storage account: $STORAGE_ACCOUNT"

    if az storage account show --name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log_warn "Storage account $STORAGE_ACCOUNT already exists"
    else
        az storage account create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$STORAGE_ACCOUNT" \
            --sku Standard_LRS \
            --location "$LOCATION"
        log_info "Storage account created successfully"
    fi
}

# Create Key Vault
create_key_vault() {
    log_info "Creating Key Vault: $KEY_VAULT"

    if az keyvault show --name "$KEY_VAULT" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log_warn "Key Vault $KEY_VAULT already exists"
    else
        az keyvault create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$KEY_VAULT" \
            --location "$LOCATION"
        log_info "Key Vault created successfully"
    fi
}

# Create Azure ML workspace
create_ml_workspace() {
    log_info "Creating Azure ML workspace: $WORKSPACE_NAME"

    # Install Azure ML extension if not present
    if ! az extension show --name ml &> /dev/null; then
        log_info "Installing Azure ML CLI extension..."
        az extension add --name ml
    fi

    if az ml workspace show --name "$WORKSPACE_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log_warn "ML workspace $WORKSPACE_NAME already exists"
    else
        az ml workspace create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$WORKSPACE_NAME" \
            --location "$LOCATION" \
            --storage-account "$STORAGE_ACCOUNT" \
            --key-vault "$KEY_VAULT" \
            --container-registry "$ACR_NAME"
        log_info "Azure ML workspace created successfully"
    fi
}

# Create compute cluster
create_compute_cluster() {
    log_info "Creating compute cluster: $COMPUTE_NAME"

    if az ml compute show --name "$COMPUTE_NAME" --workspace-name "$WORKSPACE_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log_warn "Compute cluster $COMPUTE_NAME already exists"
    else
        az ml compute create \
            --name "$COMPUTE_NAME" \
            --type AmlCompute \
            --size Standard_NC6s_v3 \
            --min-instances 0 \
            --max-instances 4 \
            --idle-time-before-scale-down 300 \
            --workspace-name "$WORKSPACE_NAME" \
            --resource-group "$RESOURCE_GROUP"
        log_info "Compute cluster created successfully"
    fi
}

# Install Python dependencies
install_dependencies() {
    log_info "Installing Python dependencies..."

    # Create virtual environment if it doesn't exist
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log_info "Virtual environment created"
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        log_info "Python dependencies installed successfully"
    else
        log_error "requirements.txt not found"
        exit 1
    fi

    # Install the package in development mode
    pip install -e .
    log_info "VulnHunter V5 package installed in development mode"
}

# Build and push Docker image
build_docker_image() {
    log_info "Building and pushing Docker image..."

    if command -v docker &> /dev/null; then
        # Build the image
        docker build -t vulnhunter-v5:latest .
        log_info "Docker image built successfully"

        # Tag for ACR
        docker tag vulnhunter-v5:latest "$ACR_LOGIN_SERVER/vulnhunter-v5:latest"

        # Push to ACR
        docker push "$ACR_LOGIN_SERVER/vulnhunter-v5:latest"
        log_info "Docker image pushed to ACR successfully"
    else
        log_warn "Docker not available. Skipping Docker image build."
    fi
}

# Create environment configuration file
create_env_config() {
    log_info "Creating environment configuration..."

    cat > .env << EOF
# VulnHunter V5 Environment Configuration
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_RESOURCE_GROUP=$RESOURCE_GROUP
AZURE_ML_WORKSPACE_NAME=$WORKSPACE_NAME
AZURE_LOCATION=$LOCATION
AZURE_COMPUTE_NAME=$COMPUTE_NAME
AZURE_ACR_NAME=$ACR_NAME
AZURE_ACR_LOGIN_SERVER=$ACR_LOGIN_SERVER
AZURE_STORAGE_ACCOUNT=$STORAGE_ACCOUNT
AZURE_KEY_VAULT=$KEY_VAULT

# Model configuration
VULNHUNTER_MODEL_PATH=./models/vulnhunter_v5_final.pt
VULNHUNTER_CACHE_DIR=./data/cache
VULNHUNTER_LOG_LEVEL=INFO

# API configuration
VULNHUNTER_API_HOST=0.0.0.0
VULNHUNTER_API_PORT=8000
EOF

    log_info "Environment configuration saved to .env"
}

# Create Azure ML environment YAML
create_ml_environment() {
    log_info "Creating Azure ML environment configuration..."

    mkdir -p azure_ml_configs

    cat > azure_ml_configs/environment.yml << EOF
name: vulnhunter-v5-env
description: VulnHunter V5 training environment
image: $ACR_LOGIN_SERVER/vulnhunter-v5:latest
conda_file: conda_env.yml
EOF

    cat > azure_ml_configs/conda_env.yml << EOF
name: vulnhunter-v5
channels:
  - pytorch
  - conda-forge
  - defaults
dependencies:
  - python=3.10
  - pytorch>=2.0.0
  - pytorch-geometric>=2.4.0
  - transformers>=4.30.0
  - scikit-learn>=1.3.0
  - pandas>=2.0.0
  - numpy>=1.24.0
  - pip
  - pip:
    - azureml-sdk>=1.52.0
    - networkx>=3.1
    - imbalanced-learn>=0.11.0
    - fastapi>=0.100.0
    - shap>=0.42.0
    - structlog>=23.1.0
    - ray[tune]>=2.6.0
    - click>=8.1.0
EOF

    log_info "Azure ML environment configuration created"
}

# Setup monitoring and logging
setup_monitoring() {
    log_info "Setting up monitoring and logging..."

    # Create Application Insights
    APPINSIGHTS_NAME="vulnhunter-insights-$(date +%s)"
    az monitor app-insights component create \
        --app "$APPINSIGHTS_NAME" \
        --location "$LOCATION" \
        --resource-group "$RESOURCE_GROUP" \
        --kind web

    APPINSIGHTS_KEY=$(az monitor app-insights component show \
        --app "$APPINSIGHTS_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query instrumentationKey -o tsv)

    # Add to environment configuration
    echo "AZURE_APPINSIGHTS_NAME=$APPINSIGHTS_NAME" >> .env
    echo "AZURE_APPINSIGHTS_KEY=$APPINSIGHTS_KEY" >> .env

    log_info "Application Insights configured"
}

# Create sample training script
create_training_script() {
    log_info "Creating sample training script..."

    mkdir -p scripts

    cat > scripts/train_on_azure.py << 'EOF'
#!/usr/bin/env python3
"""
Sample training script for VulnHunter V5 on Azure ML
"""

import os
import sys
sys.path.append('/app/src')

from src.pipelines.train_azure import AzureTrainingPipeline
from src.data.dataset_loader import VulnDatasetLoader

def main():
    # Get environment variables
    workspace_name = os.getenv('AZURE_ML_WORKSPACE_NAME')
    resource_group = os.getenv('AZURE_RESOURCE_GROUP')
    subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')

    if not all([workspace_name, resource_group, subscription_id]):
        print("Error: Missing required environment variables")
        sys.exit(1)

    # Initialize pipeline
    pipeline = AzureTrainingPipeline(
        workspace_name=workspace_name,
        resource_group=resource_group,
        subscription_id=subscription_id
    )

    # Prepare dataset
    loader = VulnDatasetLoader()
    dataset_path = loader.prepare_azure_dataset()

    # Run training
    print("Starting VulnHunter V5 training on Azure ML...")
    run_id = pipeline.run_azure_experiment(dataset_path)
    print(f"Training job submitted: {run_id}")

if __name__ == "__main__":
    main()
EOF

    chmod +x scripts/train_on_azure.py
    log_info "Training script created: scripts/train_on_azure.py"
}

# Print summary and next steps
print_summary() {
    log_info "Setup completed successfully! 🎉"
    echo
    echo "=================================="
    echo "📋 SETUP SUMMARY"
    echo "=================================="
    echo "Resource Group: $RESOURCE_GROUP"
    echo "ML Workspace: $WORKSPACE_NAME"
    echo "Compute Cluster: $COMPUTE_NAME"
    echo "Container Registry: $ACR_NAME"
    echo "Storage Account: $STORAGE_ACCOUNT"
    echo "Key Vault: $KEY_VAULT"
    echo
    echo "🔧 NEXT STEPS:"
    echo "1. Review the .env file for configuration"
    echo "2. Activate the virtual environment: source venv/bin/activate"
    echo "3. Prepare your dataset: python -m src.deploy.cli prepare-dataset"
    echo "4. Start training: python scripts/train_on_azure.py"
    echo "5. Launch API server: python -m src.deploy.cli serve --model-path ./models/vulnhunter_v5_final.pt"
    echo
    echo "📚 USEFUL COMMANDS:"
    echo "- View workspace: az ml workspace show --name $WORKSPACE_NAME --resource-group $RESOURCE_GROUP"
    echo "- List compute: az ml compute list --workspace-name $WORKSPACE_NAME --resource-group $RESOURCE_GROUP"
    echo "- Monitor jobs: az ml job list --workspace-name $WORKSPACE_NAME --resource-group $RESOURCE_GROUP"
    echo
    echo "🌐 AZURE PORTAL LINKS:"
    echo "- ML Workspace: https://ml.azure.com/?workspace=$WORKSPACE_NAME"
    echo "- Resource Group: https://portal.azure.com/#@/resource/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"
    echo
    echo "Happy vulnerability hunting! 🔍🛡️"
}

# Main execution
main() {
    log_info "Starting VulnHunter V5 Azure setup..."

    check_prerequisites
    azure_login
    create_resource_group
    create_storage
    create_key_vault
    create_acr
    create_ml_workspace
    create_compute_cluster
    install_dependencies
    build_docker_image
    create_env_config
    create_ml_environment
    setup_monitoring
    create_training_script
    print_summary
}

# Handle script interruption
trap 'log_error "Setup interrupted by user"; exit 1' INT

# Run main function
main "$@"