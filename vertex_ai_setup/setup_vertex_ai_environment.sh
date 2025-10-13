#!/bin/bash

# Complete Vertex AI Setup for VulnHunter AI Training
# This script sets up the entire Vertex AI environment for production ML training

set -e

# Configuration
PROJECT_ID=${1:-"vulnhunter-ai-project"}
REGION=${2:-"us-central1"}
SERVICE_ACCOUNT_NAME="vulnhunter-vertex-sa"
BUCKET_NAME="vulnhunter-ai-training-${PROJECT_ID}"
NOTEBOOK_NAME="vulnhunter-workbench"
BUDGET_NAME="vulnhunter-ai-budget"
BUDGET_AMOUNT=${3:-1000}  # Default $1000 budget

echo "🚀 Setting up Vertex AI Environment for VulnHunter AI"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Budget: \$$BUDGET_AMOUNT"

# Enable required APIs
echo "📡 Enabling required Google Cloud APIs..."
gcloud services enable aiplatform.googleapis.com \
  compute.googleapis.com \
  storage-api.googleapis.com \
  storage-component.googleapis.com \
  notebooks.googleapis.com \
  cloudbuild.googleapis.com \
  containerregistry.googleapis.com \
  monitoring.googleapis.com \
  billing.googleapis.com \
  cloudfunctions.googleapis.com \
  --project=$PROJECT_ID

# Create service account for Vertex AI
echo "🔐 Creating service account for Vertex AI..."
gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
  --display-name="VulnHunter Vertex AI Service Account" \
  --description="Service account for VulnHunter AI training on Vertex AI" \
  --project=$PROJECT_ID || echo "Service account already exists"

# Grant necessary permissions
echo "🔑 Granting permissions to service account..."
SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

ROLES=(
  "roles/aiplatform.user"
  "roles/storage.admin"
  "roles/compute.admin"
  "roles/notebooks.admin"
  "roles/monitoring.editor"
  "roles/logging.logWriter"
  "roles/ml.admin"
  "roles/cloudbuild.builds.editor"
)

for role in "${ROLES[@]}"; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
    --role="$role"
done

# Create Cloud Storage bucket
echo "💾 Creating Cloud Storage bucket..."
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$BUCKET_NAME || echo "Bucket already exists"

# Set bucket permissions
gsutil iam ch serviceAccount:$SERVICE_ACCOUNT_EMAIL:roles/storage.admin gs://$BUCKET_NAME

# Create folder structure in bucket
echo "📁 Creating folder structure in bucket..."
gsutil -m cp -r /dev/null gs://$BUCKET_NAME/data/ || true
gsutil -m cp -r /dev/null gs://$BUCKET_NAME/models/ || true
gsutil -m cp -r /dev/null gs://$BUCKET_NAME/experiments/ || true
gsutil -m cp -r /dev/null gs://$BUCKET_NAME/artifacts/ || true
gsutil -m cp -r /dev/null gs://$BUCKET_NAME/pipelines/ || true

# Create Vertex AI Workbench managed notebook
echo "📓 Creating Vertex AI Workbench managed notebook..."
cat > workbench_config.json <<EOF
{
  "name": "projects/$PROJECT_ID/locations/$REGION/instances/$NOTEBOOK_NAME",
  "gce_setup": {
    "machine_type": "n1-standard-4",
    "accelerator_configs": [
      {
        "type": "NVIDIA_TESLA_T4",
        "core_count": 1
      }
    ],
    "boot_disk": {
      "disk_size_gb": 100,
      "disk_type": "PD_SSD"
    },
    "data_disks": [
      {
        "disk_size_gb": 500,
        "disk_type": "PD_STANDARD"
      }
    ],
    "service_accounts": [
      {
        "email": "$SERVICE_ACCOUNT_EMAIL"
      }
    ],
    "metadata": {
      "framework": "PyTorch:1.13",
      "proxy-mode": "service_account",
      "notebook-disable-downloads": "false"
    },
    "enable_ip_forwarding": true,
    "network_interfaces": [
      {
        "network": "projects/$PROJECT_ID/global/networks/default",
        "subnet": "projects/$PROJECT_ID/regions/$REGION/subnetworks/default"
      }
    ]
  }
}
EOF

# Create the notebook instance
gcloud notebooks managed-notebooks create $NOTEBOOK_NAME \
  --location=$REGION \
  --project=$PROJECT_ID \
  --from-json=workbench_config.json || echo "Notebook already exists"

# Set up budget and alerts
echo "💰 Setting up budget and cost alerts..."
cat > budget_config.json <<EOF
{
  "displayName": "$BUDGET_NAME",
  "budgetFilter": {
    "projects": ["projects/$PROJECT_ID"],
    "services": [
      "services/6F81-5844-456A",
      "services/95FF-2EF5-5EA1"
    ]
  },
  "amount": {
    "specifiedAmount": {
      "currencyCode": "USD",
      "units": "$BUDGET_AMOUNT"
    }
  },
  "thresholdRules": [
    {
      "thresholdPercent": 0.5,
      "spendBasis": "CURRENT_SPEND"
    },
    {
      "thresholdPercent": 0.8,
      "spendBasis": "CURRENT_SPEND"
    },
    {
      "thresholdPercent": 1.0,
      "spendBasis": "CURRENT_SPEND"
    }
  ]
}
EOF

# Create budget (requires billing account - will be set manually)
echo "⚠️  Budget creation requires billing account. Please create budget manually using budget_config.json"

# Create container registry for custom images
echo "🐳 Setting up Container Registry..."
gcloud auth configure-docker --quiet

# Create directories for Vertex AI setup
echo "📂 Creating local setup directories..."
mkdir -p vertex_ai_setup/{training,prediction,pipelines,notebooks,monitoring}
mkdir -p vertex_ai_setup/training/{src,requirements,configs}
mkdir -p vertex_ai_setup/prediction/{src,requirements,configs}

# Copy training code template
echo "📝 Creating training code templates..."

# Generate startup script for notebook
cat > vertex_ai_setup/notebooks/startup_script.sh <<'EOF'
#!/bin/bash

# VulnHunter AI Notebook Startup Script
echo "🚀 Starting VulnHunter AI Notebook Setup..."

# Install additional packages
pip install --upgrade pip
pip install torch torchvision torchaudio --extra-index-url https://download.pytorch.org/whl/cu113
pip install transformers datasets accelerate wandb
pip install google-cloud-aiplatform google-cloud-storage
pip install scikit-learn matplotlib seaborn pandas numpy
pip install kfp google-cloud-pipeline-components

# Install VulnHunter specific packages
pip install ast-scope networkx pygraphviz

# Create working directories
mkdir -p /home/jupyter/vulnhunter/{data,models,experiments,notebooks,src}

# Clone VulnHunter repository (if exists)
cd /home/jupyter/vulnhunter
# git clone https://github.com/your-org/vulnhunter-ai.git

# Set up environment variables
echo 'export PROJECT_ID='$PROJECT_ID >> ~/.bashrc
echo 'export REGION='$REGION >> ~/.bashrc
echo 'export BUCKET_NAME='$BUCKET_NAME >> ~/.bashrc

echo "✅ VulnHunter AI Notebook Setup Complete!"
EOF

# Create monitoring setup
cat > vertex_ai_setup/monitoring/setup_monitoring.py <<'EOF'
"""
VulnHunter AI - Vertex AI Monitoring Setup
Sets up comprehensive monitoring for training jobs and endpoints
"""

import os
from google.cloud import monitoring_v3
from google.cloud import aiplatform
import json

def setup_training_monitoring(project_id: str, region: str):
    """Set up monitoring for training jobs"""

    client = monitoring_v3.MetricServiceClient()
    project_name = f"projects/{project_id}"

    # Custom metrics for VulnHunter training
    custom_metrics = [
        {
            "type": "custom.googleapis.com/vulnhunter/training/false_positive_rate",
            "display_name": "VulnHunter False Positive Rate",
            "description": "False positive rate during training"
        },
        {
            "type": "custom.googleapis.com/vulnhunter/training/true_positive_rate",
            "display_name": "VulnHunter True Positive Rate",
            "description": "True positive rate during training"
        },
        {
            "type": "custom.googleapis.com/vulnhunter/training/f1_score",
            "display_name": "VulnHunter F1 Score",
            "description": "F1 score during training"
        }
    ]

    for metric in custom_metrics:
        descriptor = monitoring_v3.MetricDescriptor(
            type=metric["type"],
            display_name=metric["display_name"],
            description=metric["description"],
            metric_kind=monitoring_v3.MetricDescriptor.MetricKind.GAUGE,
            value_type=monitoring_v3.MetricDescriptor.ValueType.DOUBLE
        )

        try:
            client.create_metric_descriptor(
                name=project_name,
                metric_descriptor=descriptor
            )
            print(f"✅ Created metric: {metric['display_name']}")
        except Exception as e:
            print(f"⚠️ Metric already exists or error: {e}")

def setup_alerting_policies(project_id: str):
    """Set up alerting policies for VulnHunter training"""

    client = monitoring_v3.AlertPolicyServiceClient()
    project_name = f"projects/{project_id}"

    # Alert for high GPU usage
    gpu_alert_policy = monitoring_v3.AlertPolicy(
        display_name="VulnHunter High GPU Usage",
        conditions=[
            monitoring_v3.AlertPolicy.Condition(
                display_name="GPU Utilization > 90%",
                condition_threshold=monitoring_v3.AlertPolicy.Condition.MetricThreshold(
                    filter='resource.type="aiplatform_training_job"',
                    comparison=monitoring_v3.ComparisonType.GREATER_THAN,
                    threshold_value=0.9,
                    duration={"seconds": 300}
                )
            )
        ],
        enabled=True
    )

    # Alert for training job failures
    failure_alert_policy = monitoring_v3.AlertPolicy(
        display_name="VulnHunter Training Job Failure",
        conditions=[
            monitoring_v3.AlertPolicy.Condition(
                display_name="Training Job Failed",
                condition_threshold=monitoring_v3.AlertPolicy.Condition.MetricThreshold(
                    filter='resource.type="aiplatform_training_job" AND metric.type="aiplatform.googleapis.com/job/failed"',
                    comparison=monitoring_v3.ComparisonType.GREATER_THAN,
                    threshold_value=0
                )
            )
        ],
        enabled=True
    )

    policies = [gpu_alert_policy, failure_alert_policy]

    for policy in policies:
        try:
            client.create_alert_policy(name=project_name, alert_policy=policy)
            print(f"✅ Created alert policy: {policy.display_name}")
        except Exception as e:
            print(f"⚠️ Alert policy error: {e}")

if __name__ == "__main__":
    project_id = os.getenv("PROJECT_ID", "vulnhunter-ai-project")
    region = os.getenv("REGION", "us-central1")

    print("🔍 Setting up VulnHunter AI monitoring...")
    setup_training_monitoring(project_id, region)
    setup_alerting_policies(project_id)
    print("✅ Monitoring setup complete!")
EOF

# Create environment file
cat > vertex_ai_setup/.env <<EOF
# VulnHunter AI Vertex AI Configuration
PROJECT_ID=$PROJECT_ID
REGION=$REGION
BUCKET_NAME=$BUCKET_NAME
SERVICE_ACCOUNT_EMAIL=$SERVICE_ACCOUNT_EMAIL
NOTEBOOK_NAME=$NOTEBOOK_NAME

# Training configuration
TRAINING_IMAGE_URI=us-docker.pkg.dev/vertex-ai/training/pytorch-gpu.1-13.py310:latest
PREDICTION_IMAGE_URI=us-docker.pkg.dev/vertex-ai/prediction/pytorch-gpu.1-13.py310:latest

# Machine types
TRAINING_MACHINE_TYPE=n1-standard-8
PREDICTION_MACHINE_TYPE=n1-standard-4
GPU_TYPE=NVIDIA_TESLA_T4
GPU_COUNT=2

# Model configuration
MODEL_NAME=vulnhunter-ai
MODEL_VERSION=v1
ENDPOINT_NAME=vulnhunter-endpoint

# Hyperparameter tuning
HPT_MAX_TRIAL_COUNT=50
HPT_PARALLEL_TRIAL_COUNT=5

# Cost control
MAX_TRAINING_HOURS=24
PREEMPTIBLE_INSTANCES=true
EOF

# Set executable permissions
chmod +x vertex_ai_setup/notebooks/startup_script.sh

echo "✅ Vertex AI Environment Setup Complete!"
echo ""
echo "📋 Summary:"
echo "  - Project: $PROJECT_ID"
echo "  - Region: $REGION"
echo "  - Bucket: gs://$BUCKET_NAME"
echo "  - Service Account: $SERVICE_ACCOUNT_EMAIL"
echo "  - Notebook: $NOTEBOOK_NAME"
echo ""
echo "📝 Next Steps:"
echo "  1. Review budget_config.json and create budget manually"
echo "  2. Access Workbench notebook at: https://console.cloud.google.com/vertex-ai/workbench"
echo "  3. Run training setup scripts in vertex_ai_setup/ directory"
echo "  4. Configure monitoring alerts as needed"
echo ""
echo "🔧 Configuration files created in vertex_ai_setup/ directory"

# Clean up temporary files
rm -f workbench_config.json budget_config.json

exit 0
EOF