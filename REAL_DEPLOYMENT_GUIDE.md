# Real Google Cloud Vertex AI Deployment Guide

## Prerequisites Setup

### 1. Create GCP Project
```bash
# Install gcloud CLI if not already installed
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Login and create project
gcloud auth login
gcloud projects create vulnhunter-ml-research --name="VulnHunter ML Research"
gcloud config set project vulnhunter-ml-research
```

### 2. Enable Required APIs
```bash
gcloud services enable aiplatform.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable container.googleapis.com
```

### 3. Setup Authentication
```bash
# Create service account
gcloud iam service-accounts create vulnhunter-vertex-ai \
    --description="VulnHunter Vertex AI Service Account" \
    --display-name="VulnHunter Vertex AI"

# Grant permissions
gcloud projects add-iam-policy-binding vulnhunter-ml-research \
    --member="serviceAccount:vulnhunter-vertex-ai@vulnhunter-ml-research.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding vulnhunter-ml-research \
    --member="serviceAccount:vulnhunter-vertex-ai@vulnhunter-ml-research.iam.gserviceaccount.com" \
    --role="roles/storage.admin"

# Create and download key
gcloud iam service-accounts keys create ~/vulnhunter-vertex-ai-key.json \
    --iam-account=vulnhunter-vertex-ai@vulnhunter-ml-research.iam.gserviceaccount.com

# Set environment variable
export GOOGLE_APPLICATION_CREDENTIALS=~/vulnhunter-vertex-ai-key.json
```

### 4. Install Python Dependencies
```bash
pip install google-cloud-aiplatform google-cloud-storage joblib pandas scikit-learn numpy
```

## Deploy Models to Vertex AI

### Option 1: Run Deployment Script
```bash
# Set environment variables
export GOOGLE_APPLICATION_CREDENTIALS=~/vulnhunter-vertex-ai-key.json
export CLAUDE_API_KEY="your_claude_api_key_here"

# Run deployment (edit script first to disable simulation)
python3 deploy_to_vertex_ai.py
```

### Option 2: Manual Deployment Steps

#### Step 1: Create GCS Bucket
```bash
gsutil mb gs://vulnhunter-models-bucket
```

#### Step 2: Upload Models
```bash
gsutil -m cp -r models/ gs://vulnhunter-models-bucket/
gsutil -m cp -r deployment/ gs://vulnhunter-models-bucket/
```

#### Step 3: Deploy via Console
1. Go to Vertex AI > Model Registry
2. Click "Import" > "Import existing model"
3. Configure model settings:
   - Name: `vulnhunter-cve-nvd-v1`
   - Framework: `scikit-learn`
   - Model artifact location: `gs://vulnhunter-models-bucket/models/cve_nvd_model.joblib`
   - Container: `gcr.io/cloud-aiplatform/prediction/sklearn-cpu.1-0:latest`

#### Step 4: Create Endpoints
1. Go to Vertex AI > Endpoints
2. Click "Create Endpoint"
3. Deploy model to endpoint with:
   - Machine type: `n1-standard-4`
   - Min replicas: 1
   - Max replicas: 10

## Google Console Navigation

Once deployed, you can access:

### 📊 Main Dashboard
https://console.cloud.google.com/vertex-ai/dashboard?project=vulnhunter-ml-research

### 🤖 Models Section
https://console.cloud.google.com/vertex-ai/models?project=vulnhunter-ml-research

Here you'll see:
```
Model Name                        | Framework    | Version | Created
vulnhunter-cve-nvd-v1            | scikit-learn | 1       | Today
vulnhunter-security-advisories-v1| scikit-learn | 1       | Today
vulnhunter-vulnerability-db-v1   | scikit-learn | 1       | Today
vulnhunter-exploit-db-v1         | scikit-learn | 1       | Today
```

### 🌐 Endpoints Section
https://console.cloud.google.com/vertex-ai/endpoints?project=vulnhunter-ml-research

Shows active endpoints:
```
Endpoint Name                     | Status   | Traffic | Region
vulnhunter-cve-nvd-endpoint      | Active   | 100%    | us-central1
vulnhunter-advisories-endpoint   | Active   | 100%    | us-central1
vulnhunter-vuln-db-endpoint      | Active   | 100%    | us-central1
vulnhunter-exploit-db-endpoint   | Active   | 100%    | us-central1
```

### 📈 Monitoring
https://console.cloud.google.com/vertex-ai/endpoints?project=vulnhunter-ml-research

Click on any endpoint to see:
- Request/response monitoring
- Latency metrics
- Error rates
- Traffic patterns
- Model performance metrics

### 💰 Pricing
https://console.cloud.google.com/billing?project=vulnhunter-ml-research

Monitor costs for:
- Prediction requests
- Model hosting
- Storage costs
- Network usage

## Testing Deployed Models

### Using gcloud CLI
```bash
# Test CVE risk prediction
gcloud ai endpoints predict ENDPOINT_ID \
    --region=us-central1 \
    --json-request='{"instances": [{"cvss_score": 8.5, "has_exploit": 1, "severity": "HIGH"}]}'
```

### Using Python Client
```python
from google.cloud import aiplatform

# Initialize
aiplatform.init(project="vulnhunter-ml-research", location="us-central1")

# Get endpoint
endpoint = aiplatform.Endpoint("projects/vulnhunter-ml-research/locations/us-central1/endpoints/ENDPOINT_ID")

# Make prediction
response = endpoint.predict(instances=[{
    "cvss_score": 8.5,
    "has_exploit": 1,
    "severity": "HIGH"
}])

print(response.predictions)
```

### Using REST API
```bash
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  https://us-central1-aiplatform.googleapis.com/v1/projects/vulnhunter-ml-research/locations/us-central1/endpoints/ENDPOINT_ID:predict \
  -d '{"instances": [{"cvss_score": 8.5, "has_exploit": 1}]}'
```

## Monitoring & Alerts

### Setup Monitoring
```bash
# Create notification channel
gcloud alpha monitoring channels create \
    --display-name="VulnHunter Alerts" \
    --type=email \
    --channel-labels=email_address=your-email@domain.com
```

### Key Metrics to Monitor
- **Request latency** (should be < 100ms)
- **Error rate** (should be < 1%)
- **Model accuracy** (monitor for drift)
- **Resource utilization** (CPU/Memory)
- **Cost per prediction**

## Cost Optimization

### Recommended Settings
- **Machine Type**: `n1-standard-4` (balanced performance/cost)
- **Min Replicas**: 1 (reduce cold start)
- **Max Replicas**: 10 (handle traffic spikes)
- **Auto-scaling**: Enable based on CPU/requests

### Monthly Cost Estimate
- **Model hosting**: ~$200-500/month
- **Predictions**: ~$1 per 1000 requests
- **Storage**: ~$20/month
- **Total**: ~$250-550/month depending on usage

## Next Steps After Deployment

1. **Test endpoints** with sample data
2. **Setup monitoring** and alerting
3. **Configure CI/CD** for model updates
4. **Integrate with applications** using the client SDK
5. **Monitor performance** and optimize as needed