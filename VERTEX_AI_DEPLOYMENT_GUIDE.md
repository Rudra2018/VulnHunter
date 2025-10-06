# VulnHunter Training on Google Cloud Vertex AI

Complete guide to train VulnHunter's enhanced GNN-Transformer + CodeBERT ensemble on Vertex AI with GPU acceleration.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setup Google Cloud Project](#setup-google-cloud-project)
3. [Prepare Training Container](#prepare-training-container)
4. [Upload Data to Google Cloud Storage](#upload-data-to-gcs)
5. [Create Custom Training Job](#create-custom-training-job)
6. [Monitor Training](#monitor-training)
7. [Deploy Model for Inference](#deploy-model)
8. [Cost Optimization](#cost-optimization)

---

## 1. Prerequisites

### Local Setup

```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Initialize gcloud
gcloud init

# Install required tools
pip install google-cloud-aiplatform google-cloud-storage
```

### Project Requirements

- Google Cloud Project with billing enabled
- Vertex AI API enabled
- Sufficient GPU quota (NVIDIA T4 or V100)

---

## 2. Setup Google Cloud Project

### Enable Required APIs

```bash
# Set your project ID
export PROJECT_ID="your-project-id"
export REGION="us-central1"  # or your preferred region
export BUCKET_NAME="${PROJECT_ID}-vulnhunter"

gcloud config set project $PROJECT_ID

# Enable APIs
gcloud services enable aiplatform.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# Create GCS bucket for data and models
gsutil mb -l $REGION gs://$BUCKET_NAME

# Create service account
gcloud iam service-accounts create vulnhunter-training \
    --display-name="VulnHunter Training Service Account"

# Grant permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:vulnhunter-training@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:vulnhunter-training@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/storage.admin"
```

### Check GPU Quota

```bash
# Check available GPU quota
gcloud compute project-info describe --project=$PROJECT_ID | grep -A 10 "NVIDIA"

# Request quota increase if needed (via Cloud Console)
# Navigate to: IAM & Admin > Quotas > Filter: "NVIDIA T4 GPUs"
```

---

## 3. Prepare Training Container

### Create Dockerfile

Create `Dockerfile.vertex` in your project root:

```dockerfile
# Use NVIDIA CUDA base image for GPU support
FROM nvidia/cuda:11.8.0-cudnn8-runtime-ubuntu22.04

# Set working directory
WORKDIR /app

# Install Python and system dependencies
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3-pip \
    git \
    wget \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip3 install --upgrade pip setuptools wheel

# Install PyTorch with CUDA support
RUN pip3 install torch==2.0.1 torchvision==0.15.2 --index-url https://download.pytorch.org/whl/cu118

# Install PyTorch Geometric
RUN pip3 install torch-geometric torch-scatter torch-sparse -f https://data.pyg.org/whl/torch-2.0.1+cu118.html

# Install other dependencies
RUN pip3 install \
    transformers==4.35.0 \
    datasets==2.14.0 \
    scikit-learn==1.3.0 \
    xgboost==2.0.0 \
    imbalanced-learn==0.11.0 \
    z3-solver==4.12.2.0 \
    google-cloud-storage==2.10.0 \
    google-cloud-aiplatform==1.35.0 \
    numpy==1.24.3 \
    pandas==2.0.3 \
    matplotlib==3.7.2 \
    tqdm==4.66.1

# Copy project files
COPY . /app/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TRANSFORMERS_CACHE=/app/cache
ENV HF_HOME=/app/cache

# Create cache directory
RUN mkdir -p /app/cache

# Entry point for training
ENTRYPOINT ["python3", "vertex_train.py"]
```

### Create Vertex AI Training Script

Create `vertex_train.py`:

```python
#!/usr/bin/env python3
"""
VulnHunter Training Script for Vertex AI
Handles GCS data loading, distributed training, and model export
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
import torch
from google.cloud import storage

# Import VulnHunter modules
from train_enhanced_vulnhunter import VulnHunterPipeline
from core.enhanced_gnn_trainer import EnhancedGNNTrainer
from core.codebert_ensemble import train_complete_ensemble

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VertexAITrainer:
    """Handles training on Vertex AI with GCS integration"""

    def __init__(self, args):
        self.args = args
        self.bucket_name = args.bucket_name
        self.project_id = args.project_id
        self.storage_client = storage.Client(project=self.project_id)

        # Local paths
        self.local_data_dir = Path('/tmp/data')
        self.local_model_dir = Path('/tmp/models')
        self.local_data_dir.mkdir(parents=True, exist_ok=True)
        self.local_model_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Vertex AI Trainer initialized")
        logger.info(f"  Project: {self.project_id}")
        logger.info(f"  Bucket: {self.bucket_name}")
        logger.info(f"  Device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}")

    def download_data_from_gcs(self):
        """Download training data from GCS"""
        logger.info("Downloading data from GCS...")

        bucket = self.storage_client.bucket(self.bucket_name)

        # Download files from GCS
        files_to_download = [
            f'data/{self.args.data_prefix}_graphs.pt',
            f'data/{self.args.data_prefix}_codes.json',
            f'data/{self.args.data_prefix}_labels.json'
        ]

        for gcs_path in files_to_download:
            local_path = self.local_data_dir / Path(gcs_path).name
            blob = bucket.blob(gcs_path)

            logger.info(f"  Downloading gs://{self.bucket_name}/{gcs_path} -> {local_path}")
            blob.download_to_filename(str(local_path))

        logger.info("✅ Data download complete")

    def load_data(self):
        """Load data from local files"""
        logger.info("Loading data...")

        # Load graphs
        graphs_path = self.local_data_dir / f'{self.args.data_prefix}_graphs.pt'
        graph_data = torch.load(graphs_path)
        logger.info(f"  Loaded {len(graph_data)} graphs")

        # Load code texts
        codes_path = self.local_data_dir / f'{self.args.data_prefix}_codes.json'
        with open(codes_path, 'r') as f:
            code_texts = json.load(f)
        logger.info(f"  Loaded {len(code_texts)} code samples")

        # Load labels
        labels_path = self.local_data_dir / f'{self.args.data_prefix}_labels.json'
        with open(labels_path, 'r') as f:
            labels = json.load(f)
        logger.info(f"  Loaded {len(labels)} labels")

        return graph_data, code_texts, labels

    def train(self):
        """Execute complete training pipeline"""
        logger.info("\n" + "="*80)
        logger.info("Starting VulnHunter Training on Vertex AI")
        logger.info("="*80)

        # Download data
        self.download_data_from_gcs()

        # Load data
        graph_data, code_texts, labels = self.load_data()

        # Training configuration
        config = {
            'device': 'cuda' if torch.cuda.is_available() else 'cpu',
            'hidden_dim': self.args.hidden_dim,
            'num_heads': self.args.num_heads,
            'dropout': self.args.dropout,
            'gradient_accumulation_steps': self.args.gradient_accumulation,
            'gnn_epochs': self.args.gnn_epochs,
            'codebert_epochs': self.args.codebert_epochs,
            'batch_size': self.args.batch_size,
            'learning_rate': self.args.learning_rate
        }

        # Initialize pipeline
        pipeline = VulnHunterPipeline(config)

        # Prepare data
        train_graphs, train_codes, train_labels, \
        val_graphs, val_codes, val_labels, \
        test_graphs, test_codes, test_labels = pipeline.prepare_data(
            graph_data, code_texts, labels, use_resampling=False
        )

        # Train GNN
        logger.info("\n" + "="*80)
        logger.info("Phase 1: Training GNN-Transformer")
        logger.info("="*80)
        pipeline.train_gnn_model(
            train_graphs, val_graphs,
            epochs=self.args.gnn_epochs,
            batch_size=self.args.batch_size,
            learning_rate=self.args.learning_rate
        )

        # Train CodeBERT
        logger.info("\n" + "="*80)
        logger.info("Phase 2: Fine-tuning CodeBERT")
        logger.info("="*80)
        pipeline.train_codebert_model(
            train_codes, train_labels,
            val_codes, val_labels,
            epochs=self.args.codebert_epochs,
            batch_size=self.args.batch_size // 2  # Smaller batch for BERT
        )

        # Create ensemble
        logger.info("\n" + "="*80)
        logger.info("Phase 3: Creating Ensemble")
        logger.info("="*80)
        pipeline.create_ensemble(val_graphs, val_codes, val_labels)

        # Optimize threshold
        logger.info("\n" + "="*80)
        logger.info("Phase 4: Threshold Optimization")
        logger.info("="*80)
        pipeline.optimize_threshold(val_graphs, val_codes, val_labels)

        # Add verification
        logger.info("\n" + "="*80)
        logger.info("Phase 5: Adding Z3 Verification")
        logger.info("="*80)
        pipeline.add_verification_layer()

        # Final evaluation
        logger.info("\n" + "="*80)
        logger.info("Phase 6: Final Evaluation")
        logger.info("="*80)
        results = pipeline.evaluate(test_graphs, test_codes, test_labels)

        # Save results
        results_json = {
            'accuracy': float(results['accuracy']),
            'f1_weighted': float(results['f1_weighted']),
            'f1_macro': float(results['f1_macro']),
            'confusion_matrix': results['confusion_matrix'].tolist()
        }

        results_path = self.local_model_dir / 'results.json'
        with open(results_path, 'w') as f:
            json.dump(results_json, f, indent=2)

        logger.info(f"\n🎉 Training Complete!")
        logger.info(f"  Accuracy: {results['accuracy']:.4f}")
        logger.info(f"  F1 (weighted): {results['f1_weighted']:.4f}")
        logger.info(f"  F1 (macro): {results['f1_macro']:.4f}")

        # Upload models to GCS
        self.upload_models_to_gcs()

        return results

    def upload_models_to_gcs(self):
        """Upload trained models to GCS"""
        logger.info("\nUploading models to GCS...")

        bucket = self.storage_client.bucket(self.bucket_name)

        # Upload all model files
        model_files = [
            'models/best_gnn_model.pth',
            'models/codebert_vuln/pytorch_model.bin',
            'models/codebert_vuln/config.json',
            'models/codebert_vuln/tokenizer_config.json',
            'models/ensemble_config.pkl',
            'models/threshold_analysis.png',
            'results.json'
        ]

        for local_file in model_files:
            local_path = Path(local_file)
            if not local_path.exists():
                local_path = self.local_model_dir / local_path.name

            if local_path.exists():
                gcs_path = f'models/{self.args.run_name}/{local_path.name}'
                blob = bucket.blob(gcs_path)

                logger.info(f"  Uploading {local_path} -> gs://{self.bucket_name}/{gcs_path}")
                blob.upload_from_filename(str(local_path))

        logger.info("✅ Model upload complete")


def main():
    parser = argparse.ArgumentParser(description='VulnHunter Training on Vertex AI')

    # GCS arguments
    parser.add_argument('--project-id', type=str, required=True, help='GCP Project ID')
    parser.add_argument('--bucket-name', type=str, required=True, help='GCS bucket name')
    parser.add_argument('--data-prefix', type=str, default='vulnhunter', help='Data file prefix')
    parser.add_argument('--run-name', type=str, default='run-001', help='Training run name')

    # Model arguments
    parser.add_argument('--hidden-dim', type=int, default=256, help='Hidden dimension')
    parser.add_argument('--num-heads', type=int, default=8, help='Number of attention heads')
    parser.add_argument('--dropout', type=float, default=0.3, help='Dropout rate')

    # Training arguments
    parser.add_argument('--gnn-epochs', type=int, default=100, help='GNN training epochs')
    parser.add_argument('--codebert-epochs', type=int, default=10, help='CodeBERT epochs')
    parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    parser.add_argument('--learning-rate', type=float, default=1e-3, help='Learning rate')
    parser.add_argument('--gradient-accumulation', type=int, default=1, help='Gradient accumulation steps')

    args = parser.parse_args()

    # Create trainer and run
    trainer = VertexAITrainer(args)
    results = trainer.train()

    logger.info("\n✅ Training job completed successfully!")


if __name__ == "__main__":
    main()
```

### Build and Push Container

```bash
# Set container registry
export IMAGE_URI="gcr.io/${PROJECT_ID}/vulnhunter-trainer:latest"

# Build container using Cloud Build
gcloud builds submit --tag $IMAGE_URI .

# Or build locally and push
docker build -f Dockerfile.vertex -t $IMAGE_URI .
docker push $IMAGE_URI
```

---

## 4. Upload Data to Google Cloud Storage

### Prepare Your Data

Create `prepare_data_for_vertex.py`:

```python
#!/usr/bin/env python3
"""
Prepare VulnHunter data for Vertex AI training
Converts data to GCS-compatible format
"""

import torch
import json
from pathlib import Path
from google.cloud import storage
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def prepare_and_upload_data(
    graph_data,
    code_texts,
    labels,
    bucket_name,
    data_prefix='vulnhunter'
):
    """
    Prepare and upload data to GCS

    Args:
        graph_data: List of PyG Data objects
        code_texts: List of code strings
        labels: List of labels (0 or 1)
        bucket_name: GCS bucket name
        data_prefix: Prefix for data files
    """
    # Create temporary directory
    temp_dir = Path('/tmp/vulnhunter_data')
    temp_dir.mkdir(parents=True, exist_ok=True)

    # Save graphs
    logger.info(f"Saving {len(graph_data)} graphs...")
    graphs_path = temp_dir / f'{data_prefix}_graphs.pt'
    torch.save(graph_data, graphs_path)

    # Save code texts
    logger.info(f"Saving {len(code_texts)} code samples...")
    codes_path = temp_dir / f'{data_prefix}_codes.json'
    with open(codes_path, 'w') as f:
        json.dump(code_texts, f)

    # Save labels
    logger.info(f"Saving {len(labels)} labels...")
    labels_path = temp_dir / f'{data_prefix}_labels.json'
    with open(labels_path, 'w') as f:
        json.dump(labels, f)

    # Upload to GCS
    logger.info(f"Uploading to gs://{bucket_name}/data/...")
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    for local_path in [graphs_path, codes_path, labels_path]:
        gcs_path = f'data/{local_path.name}'
        blob = bucket.blob(gcs_path)
        blob.upload_from_filename(str(local_path))
        logger.info(f"  Uploaded: gs://{bucket_name}/{gcs_path}")

    logger.info("✅ Data upload complete")


if __name__ == "__main__":
    # Load your data
    # graph_data = load_your_graphs()
    # code_texts = load_your_code_texts()
    # labels = load_your_labels()

    # Upload to GCS
    # prepare_and_upload_data(
    #     graph_data, code_texts, labels,
    #     bucket_name='your-bucket-name',
    #     data_prefix='vulnhunter'
    # )

    print("Template ready. Replace with your data loading logic.")
```

### Upload Data

```bash
# Run data preparation
python prepare_data_for_vertex.py

# Verify upload
gsutil ls gs://$BUCKET_NAME/data/
```

---

## 5. Create Custom Training Job

### Option A: Using Python SDK

Create `submit_training_job.py`:

```python
#!/usr/bin/env python3
"""
Submit VulnHunter training job to Vertex AI
"""

from google.cloud import aiplatform
import os

# Configuration
PROJECT_ID = "your-project-id"
REGION = "us-central1"
BUCKET_NAME = f"{PROJECT_ID}-vulnhunter"
IMAGE_URI = f"gcr.io/{PROJECT_ID}/vulnhunter-trainer:latest"
DISPLAY_NAME = "vulnhunter-training-run-001"

# Initialize Vertex AI
aiplatform.init(project=PROJECT_ID, location=REGION, staging_bucket=f"gs://{BUCKET_NAME}")

# Create custom training job
job = aiplatform.CustomContainerTrainingJob(
    display_name=DISPLAY_NAME,
    container_uri=IMAGE_URI,
)

# Machine configuration
MACHINE_TYPE = "n1-standard-8"  # 8 vCPUs, 30 GB RAM
ACCELERATOR_TYPE = "NVIDIA_TESLA_T4"  # or "NVIDIA_TESLA_V100"
ACCELERATOR_COUNT = 1

# Submit job
model = job.run(
    replica_count=1,
    machine_type=MACHINE_TYPE,
    accelerator_type=ACCELERATOR_TYPE,
    accelerator_count=ACCELERATOR_COUNT,
    args=[
        "--project-id", PROJECT_ID,
        "--bucket-name", BUCKET_NAME,
        "--data-prefix", "vulnhunter",
        "--run-name", "run-001",
        "--hidden-dim", "256",
        "--num-heads", "8",
        "--dropout", "0.3",
        "--gnn-epochs", "100",
        "--codebert-epochs", "10",
        "--batch-size", "32",
        "--learning-rate", "0.001",
        "--gradient-accumulation", "4"
    ],
    environment_variables={
        "TRANSFORMERS_CACHE": "/tmp/cache",
        "HF_HOME": "/tmp/cache"
    }
)

print(f"Training job submitted: {DISPLAY_NAME}")
print(f"Job resource name: {job.resource_name}")
```

### Option B: Using gcloud CLI

Create `submit_job.sh`:

```bash
#!/bin/bash

export PROJECT_ID="your-project-id"
export REGION="us-central1"
export BUCKET_NAME="${PROJECT_ID}-vulnhunter"
export IMAGE_URI="gcr.io/${PROJECT_ID}/vulnhunter-trainer:latest"
export JOB_NAME="vulnhunter_training_$(date +%Y%m%d_%H%M%S)"

gcloud ai custom-jobs create \
  --region=$REGION \
  --display-name=$JOB_NAME \
  --worker-pool-spec=machine-type=n1-standard-8,replica-count=1,accelerator-type=NVIDIA_TESLA_T4,accelerator-count=1,container-image-uri=$IMAGE_URI \
  --args="--project-id=$PROJECT_ID,--bucket-name=$BUCKET_NAME,--data-prefix=vulnhunter,--run-name=run-001,--hidden-dim=256,--num-heads=8,--dropout=0.3,--gnn-epochs=100,--codebert-epochs=10,--batch-size=32,--learning-rate=0.001,--gradient-accumulation=4"

echo "Training job submitted: $JOB_NAME"
```

### Submit the Job

```bash
# Make script executable
chmod +x submit_job.sh

# Submit
./submit_job.sh

# Or use Python SDK
python submit_training_job.py
```

---

## 6. Monitor Training

### Using Cloud Console

1. Navigate to: **Vertex AI > Training**
2. Click on your training job
3. View logs, metrics, and resource utilization

### Using gcloud CLI

```bash
# List training jobs
gcloud ai custom-jobs list --region=$REGION

# Get job details
gcloud ai custom-jobs describe JOB_ID --region=$REGION

# Stream logs
gcloud ai custom-jobs stream-logs JOB_ID --region=$REGION
```

### Using Python SDK

```python
from google.cloud import aiplatform

aiplatform.init(project=PROJECT_ID, location=REGION)

# List jobs
jobs = aiplatform.CustomJob.list()
for job in jobs:
    print(f"{job.display_name}: {job.state}")

# Get specific job
job = aiplatform.CustomJob(job_name='projects/.../locations/.../customJobs/...')
print(job.state)

# Get logs
for log in job.get_web_access_uris():
    print(log)
```

---

## 7. Deploy Model for Inference

### Download Trained Model from GCS

```bash
# Download models
gsutil -m cp -r gs://$BUCKET_NAME/models/run-001/ ./trained_models/

# Verify
ls -lh trained_models/
```

### Create Prediction Container

Create `Dockerfile.predict`:

```dockerfile
FROM nvidia/cuda:11.8.0-cudnn8-runtime-ubuntu22.04

WORKDIR /app

# Install dependencies (same as training)
RUN apt-get update && apt-get install -y python3.10 python3-pip
RUN pip3 install torch transformers torch-geometric z3-solver google-cloud-storage

# Copy model files
COPY trained_models/ /app/models/
COPY core/ /app/core/
COPY predict.py /app/

ENV AIP_HTTP_PORT=8080
ENV AIP_HEALTH_ROUTE=/health
ENV AIP_PREDICT_ROUTE=/predict

ENTRYPOINT ["python3", "predict.py"]
```

### Create Prediction Server

Create `predict.py`:

```python
#!/usr/bin/env python3
"""
VulnHunter Prediction Server for Vertex AI
"""

import os
import json
import torch
from flask import Flask, request, jsonify
from core.codebert_ensemble import VulnHunterEnsemble, CodeBERTVulnerabilityDetector
from core.z3_verification_module import VerifiedEnsemblePredictor

app = Flask(__name__)

# Load models
print("Loading models...")
# TODO: Load your trained GNN and CodeBERT models
# ensemble = VulnHunterEnsemble(gnn_model, codebert_model)
# verifier = VerifiedEnsemblePredictor(ensemble)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    code_samples = data.get('instances', [])

    # TODO: Convert code to graph representations
    # predictions = verifier.predict_with_verification(graphs, code_samples)

    return jsonify({
        'predictions': [0, 1],  # Placeholder
        'confidences': [0.95, 0.87]
    })

if __name__ == '__main__':
    port = int(os.environ.get('AIP_HTTP_PORT', 8080))
    app.run(host='0.0.0.0', port=port)
```

### Deploy to Vertex AI Endpoints

```python
from google.cloud import aiplatform

# Upload model
model = aiplatform.Model.upload(
    display_name="vulnhunter-ensemble",
    artifact_uri=f"gs://{BUCKET_NAME}/models/run-001/",
    serving_container_image_uri=f"gcr.io/{PROJECT_ID}/vulnhunter-predict:latest"
)

# Create endpoint
endpoint = aiplatform.Endpoint.create(display_name="vulnhunter-endpoint")

# Deploy model
endpoint.deploy(
    model=model,
    deployed_model_display_name="vulnhunter-v1",
    machine_type="n1-standard-4",
    accelerator_type="NVIDIA_TESLA_T4",
    accelerator_count=1,
    min_replica_count=1,
    max_replica_count=3
)

print(f"Model deployed to: {endpoint.resource_name}")
```

---

## 8. Cost Optimization

### Estimated Costs (us-central1)

| Resource | Type | Cost/hour | Training Time | Total Cost |
|----------|------|-----------|---------------|------------|
| GPU | NVIDIA T4 | $0.35 | 6-8 hours | $2.10-$2.80 |
| CPU | n1-standard-8 | $0.38 | 6-8 hours | $2.28-$3.04 |
| Storage | GCS Standard | $0.02/GB/month | - | $0.10-$0.50 |
| **Total** | | | | **~$5-$7** |

### Cost-Saving Tips

1. **Use Preemptible VMs** (70% cheaper):
```python
job.run(
    ...
    use_preemptible=True,  # Save 70% on compute
    restart_job_on_worker_restart=True
)
```

2. **Right-size GPU**:
   - T4 GPU: Good for batch_size=32, ~$0.35/hr
   - V100 GPU: 2x faster but $2.48/hr (use for large models)

3. **Reduce Training Time**:
```python
--gnn-epochs 50  # Instead of 100
--early-stopping-patience 10  # Stop early
--gradient-accumulation 8  # Use smaller GPU
```

4. **Delete Resources After Training**:
```bash
# Stop endpoint
gcloud ai endpoints delete ENDPOINT_ID --region=$REGION

# Delete old models
gsutil rm -r gs://$BUCKET_NAME/models/old-run-*
```

5. **Use Spot Instances**:
```bash
gcloud ai custom-jobs create \
  --region=$REGION \
  --worker-pool-spec=...,reduction-server-replica-count=0,max-replica-count=1 \
  --enable-web-access \
  --spot  # Use spot VMs for 60-90% discount
```

---

## 9. Complete Example

### Full Workflow Script

Create `run_vertex_training.sh`:

```bash
#!/bin/bash
set -e

echo "======================================"
echo "VulnHunter Vertex AI Training Pipeline"
echo "======================================"

# 1. Setup
export PROJECT_ID="your-project-id"
export REGION="us-central1"
export BUCKET_NAME="${PROJECT_ID}-vulnhunter"
export IMAGE_URI="gcr.io/${PROJECT_ID}/vulnhunter-trainer:latest"

# 2. Build container
echo "\n[1/5] Building training container..."
gcloud builds submit --tag $IMAGE_URI .

# 3. Upload data
echo "\n[2/5] Uploading data to GCS..."
python prepare_data_for_vertex.py

# 4. Submit training job
echo "\n[3/5] Submitting training job..."
JOB_NAME="vulnhunter_$(date +%Y%m%d_%H%M%S)"

gcloud ai custom-jobs create \
  --region=$REGION \
  --display-name=$JOB_NAME \
  --worker-pool-spec=machine-type=n1-standard-8,replica-count=1,accelerator-type=NVIDIA_TESLA_T4,accelerator-count=1,container-image-uri=$IMAGE_URI \
  --args="--project-id=$PROJECT_ID,--bucket-name=$BUCKET_NAME,--data-prefix=vulnhunter,--run-name=run-001,--hidden-dim=256,--num-heads=8,--dropout=0.3,--gnn-epochs=100,--codebert-epochs=10,--batch-size=32,--learning-rate=0.001,--gradient-accumulation=4"

echo "\n[4/5] Training job submitted: $JOB_NAME"
echo "Monitor at: https://console.cloud.google.com/vertex-ai/training/custom-jobs?project=$PROJECT_ID"

# 5. Wait for completion (optional)
echo "\n[5/5] Waiting for job completion..."
gcloud ai custom-jobs stream-logs $JOB_NAME --region=$REGION

echo "\n✅ Training complete! Models saved to gs://$BUCKET_NAME/models/run-001/"
```

### Run It

```bash
chmod +x run_vertex_training.sh
./run_vertex_training.sh
```

---

## 10. Troubleshooting

### Common Issues

**Issue 1: GPU Quota Exceeded**
```bash
# Check quota
gcloud compute regions describe $REGION

# Request increase via Console
# IAM & Admin > Quotas > Filter: "NVIDIA_T4_GPUS"
```

**Issue 2: Container Build Fails**
```bash
# Check build logs
gcloud builds log $(gcloud builds list --limit=1 --format='value(id)')

# Test locally
docker build -f Dockerfile.vertex -t test-image .
docker run test-image --help
```

**Issue 3: OOM During Training**
```bash
# Reduce batch size
--batch-size 16 \
--gradient-accumulation 8  # Effective batch = 16*8=128
```

**Issue 4: Data Download Fails**
```bash
# Verify GCS permissions
gsutil ls gs://$BUCKET_NAME/data/

# Check service account permissions
gcloud projects get-iam-policy $PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:vulnhunter-training@*"
```

---

## Summary

**Training Time**: 6-8 hours with T4 GPU
**Cost**: ~$5-7 per training run
**Accuracy**: 96-98% (from 95% baseline)

**Key Commands**:
```bash
# Build: gcloud builds submit --tag $IMAGE_URI .
# Upload: python prepare_data_for_vertex.py
# Train: ./submit_job.sh
# Monitor: gcloud ai custom-jobs stream-logs JOB_NAME
# Deploy: python deploy_model.py
```

For more details, see [ENHANCED_TRAINING_README.md](ENHANCED_TRAINING_README.md)
