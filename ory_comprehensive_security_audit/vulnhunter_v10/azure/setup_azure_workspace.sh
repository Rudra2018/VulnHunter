#!/bin/bash
"""
🚀 Setup Azure ML Workspace for VulnHunter V9 Retraining
========================================================

This script sets up the complete Azure ML infrastructure for enhanced
VulnHunter V9 model retraining with real vulnerability data.
"""

set -e

echo "🚀 Setting up Azure ML Workspace for VulnHunter V9..."

# Configuration
SUBSCRIPTION_ID="your-azure-subscription-id"
RESOURCE_GROUP="vulnhunter-v9-rg"
WORKSPACE_NAME="vulnhunter-v9-workspace"
LOCATION="eastus2"
COMPUTE_NAME="vulnhunter-gpu-cluster"

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI not found. Please install: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Login to Azure
echo "🔐 Logging into Azure..."
az login

# Set subscription
echo "📋 Setting subscription..."
az account set --subscription $SUBSCRIPTION_ID

# Create resource group
echo "🏗️ Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION

# Install Azure ML extension
echo "🔧 Installing Azure ML extension..."
az extension add -n ml -y

# Create Azure ML workspace
echo "🏭 Creating Azure ML workspace..."
az ml workspace create --name $WORKSPACE_NAME --resource-group $RESOURCE_GROUP --location $LOCATION

# Create compute cluster for training
echo "💻 Creating GPU compute cluster..."
az ml compute create \
    --name $COMPUTE_NAME \
    --type amlcompute \
    --min-instances 0 \
    --max-instances 4 \
    --size Standard_NC6s_v3 \
    --workspace-name $WORKSPACE_NAME \
    --resource-group $RESOURCE_GROUP

# Create data store for training data
echo "📊 Setting up data store..."
az ml datastore create \
    --name vulnhunter-training-data \
    --type AzureBlobStorage \
    --account-name vulnhunterdata \
    --container-name training-data \
    --workspace-name $WORKSPACE_NAME \
    --resource-group $RESOURCE_GROUP

# Create environment for training
echo "🐍 Creating training environment..."
az ml environment create \
    --file azure_ml_setup.yml \
    --workspace-name $WORKSPACE_NAME \
    --resource-group $RESOURCE_GROUP

echo "✅ Azure ML workspace setup completed!"
echo "📝 Configuration:"
echo "   - Subscription: $SUBSCRIPTION_ID"
echo "   - Resource Group: $RESOURCE_GROUP"
echo "   - Workspace: $WORKSPACE_NAME"
echo "   - Compute: $COMPUTE_NAME (Standard_NC6s_v3)"
echo "   - Location: $LOCATION"

echo ""
echo "🔗 Next steps:"
echo "1. Update azure_vulnhunter_retrain.py with your Azure configuration"
echo "2. Run: python azure_vulnhunter_retrain.py"
echo "3. Monitor training at: https://ml.azure.com"