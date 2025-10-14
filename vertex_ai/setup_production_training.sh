#!/bin/bash

# VulnHunter V4 Production Training Setup Script
# This script sets up and launches training on real Vertex AI

echo "🚀 VulnHunter V4 Production Training Setup"
echo "=========================================="

# Configuration (Update these with your project details)
PROJECT_ID="your-project-id"  # Replace with your actual project ID
LOCATION="us-central1"
BUCKET_NAME="${PROJECT_ID}-vulnhunter-training"
SERVICE_ACCOUNT_KEY=""  # Optional: path to service account JSON

echo "📋 Configuration:"
echo "   Project ID: $PROJECT_ID"
echo "   Location: $LOCATION"
echo "   Bucket: $BUCKET_NAME"

# Check if gcloud is installed and authenticated
if ! command -v gcloud &> /dev/null; then
    echo "❌ gcloud CLI not found. Please install Google Cloud SDK."
    echo "   Visit: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Set project
echo "🔧 Setting up gcloud configuration..."
gcloud config set project $PROJECT_ID
gcloud config set compute/region $LOCATION

# Enable required APIs
echo "🔌 Enabling required Google Cloud APIs..."
gcloud services enable aiplatform.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable compute.googleapis.com

# Create storage bucket
echo "🪣 Creating storage bucket..."
gsutil mb -l $LOCATION gs://$BUCKET_NAME 2>/dev/null || echo "Bucket already exists"

# Upload training data
echo "📤 Uploading training data to GCS..."
gsutil -m cp -r /Users/ankitthakur/vuln_ml_research/data/training/* gs://$BUCKET_NAME/training_data/

# Upload training scripts
echo "📄 Uploading training scripts..."
gsutil cp /Users/ankitthakur/vuln_ml_research/vertex_ai/production_vulnhunter_trainer.py gs://$BUCKET_NAME/training_code/
gsutil cp /Users/ankitthakur/vuln_ml_research/vertex_ai/production_requirements.txt gs://$BUCKET_NAME/training_code/

# Create training job configuration
echo "⚙️  Creating training job configuration..."
cat > /tmp/training_job.yaml << EOF
displayName: vulnhunter-v4-production-training-$(date +%Y%m%d-%H%M%S)
jobSpec:
  workerPoolSpecs:
  - machineSpec:
      machineType: n1-standard-8
      acceleratorType: NVIDIA_TESLA_T4
      acceleratorCount: 1
    replicaCount: 1
    pythonPackageSpec:
      executorImageUri: us-docker.pkg.dev/vertex-ai/training/tf-gpu.2-11.py310:latest
      packageUris:
      - gs://$BUCKET_NAME/training_code/production_requirements.txt
      pythonModule: production_vulnhunter_trainer
      args:
      - --project_id=$PROJECT_ID
      - --location=$LOCATION
      - --bucket_name=$BUCKET_NAME
      - --training_data_paths=gs://$BUCKET_NAME/training_data/comprehensive_vulnhunter_v4_training_dataset.json,gs://$BUCKET_NAME/training_data/synthetic/synthetic_training_dataset.json,gs://$BUCKET_NAME/training_data/false_positive_training_20251013_140908.json,gs://$BUCKET_NAME/training_data/ollama_validation_training_20250114_180000.json,gs://$BUCKET_NAME/training_data/gemini_cli_validation_training_20250114_183000.json
  scheduling:
    timeout: 7200s
EOF

# Submit training job
echo "🚀 Submitting training job to Vertex AI..."
gcloud ai custom-jobs create \
    --region=$LOCATION \
    --config=/tmp/training_job.yaml

# Get job status
echo "📊 Getting training job status..."
gcloud ai custom-jobs list --region=$LOCATION --limit=5

echo ""
echo "✅ Training job submitted successfully!"
echo ""
echo "📋 To monitor progress:"
echo "   gcloud ai custom-jobs list --region=$LOCATION"
echo "   Or visit: https://console.cloud.google.com/vertex-ai/training/custom-jobs?project=$PROJECT_ID"
echo ""
echo "📊 To view logs:"
echo "   gcloud ai custom-jobs stream-logs JOB_ID --region=$LOCATION"
echo ""
echo "🔍 Training data uploaded to:"
echo "   gs://$BUCKET_NAME/training_data/"
echo ""
echo "📁 Model artifacts will be saved to:"
echo "   gs://$BUCKET_NAME/models/"

# Clean up temporary files
rm -f /tmp/training_job.yaml