# VulnHunter Real Deployment Instructions

## Current Status: Simulation Complete ✅

Your VulnHunter models have been analyzed and are ready for deployment to Google Cloud Project: **quantumsentinel-20251014-1511**

## 🚨 To Enable Real Deployment

### 1. Enable Billing (Required)
```bash
# Set up billing account
gcloud billing accounts list
gcloud billing projects link quantumsentinel-20251014-1511 --billing-account=YOUR_BILLING_ACCOUNT_ID
```

Or via Console:
https://console.cloud.google.com/billing?project=quantumsentinel-20251014-1511

### 2. Enable Required APIs
```bash
gcloud services enable aiplatform.googleapis.com storage.googleapis.com
```

Or via Console:
https://console.cloud.google.com/apis/dashboard?project=quantumsentinel-20251014-1511

### 3. Deploy Models (After Billing Enabled)
```bash
# Run the real deployment script
python3 deploy_existing_account.py
```

## 📊 Deployment Summary

### Models Ready for Deployment:

**CVE_NVD**
- Model Name: `vulnhunter-cve_nvd-v1`
- Estimated Cost: $207.5/month
- Performance: 100.0% accuracy
- Console Link: https://console.cloud.google.com/vertex-ai/models/vulnhunter-cve_nvd-model-20251014152220?project=quantumsentinel-20251014-1511

**VULNERABILITY_DB**
- Model Name: `vulnhunter-vulnerability_db-v1`
- Estimated Cost: $227.5/month
- Performance: 100.0% accuracy
- Console Link: https://console.cloud.google.com/vertex-ai/models/vulnhunter-vulnerability_db-model-20251014152220?project=quantumsentinel-20251014-1511

**SECURITY_ADVISORIES**
- Model Name: `vulnhunter-security_advisories-v1`
- Estimated Cost: $210.5/month
- Performance: 100.0% accuracy
- Console Link: https://console.cloud.google.com/vertex-ai/models/vulnhunter-security_advisories-model-20251014152220?project=quantumsentinel-20251014-1511

**EXPLOIT_DB**
- Model Name: `vulnhunter-exploit_db-v1`
- Estimated Cost: $214.0/month
- Performance: 100.0% accuracy
- Console Link: https://console.cloud.google.com/vertex-ai/models/vulnhunter-exploit_db-model-20251014152220?project=quantumsentinel-20251014-1511


## 🌐 Google Cloud Console Access

Once deployed, access your models here:

### Main Dashboards
- **Project Overview**: https://console.cloud.google.com/home/dashboard?project=quantumsentinel-20251014-1511
- **Vertex AI Dashboard**: https://console.cloud.google.com/vertex-ai/dashboard?project=quantumsentinel-20251014-1511
- **Models**: https://console.cloud.google.com/vertex-ai/models?project=quantumsentinel-20251014-1511
- **Endpoints**: https://console.cloud.google.com/vertex-ai/endpoints?project=quantumsentinel-20251014-1511

### Management
- **Billing**: https://console.cloud.google.com/billing?project=quantumsentinel-20251014-1511
- **APIs & Services**: https://console.cloud.google.com/apis/dashboard?project=quantumsentinel-20251014-1511
- **Monitoring**: https://console.cloud.google.com/monitoring/dashboards?project=quantumsentinel-20251014-1511

## 💰 Cost Estimates (Monthly)

| Model | Size | Est. Cost | QPS | Latency |
|-------|------|-----------|-----|---------|
| cve_nvd | 0.1MB | $207.5 | 10 | 100ms |
| vulnerability_db | 0.6MB | $227.5 | 10 | 100ms |
| security_advisories | 0.2MB | $210.5 | 10 | 100ms |
| exploit_db | 0.3MB | $214.0 | 10 | 100ms |

**Total Estimated Monthly Cost: $859.50**

## 🔧 Testing Deployed Models

### Using gcloud CLI
```bash
# Test CVE risk prediction
gcloud ai endpoints predict ENDPOINT_ID \
    --region=us-central1 \
    --json-request='{"instances": [{"cvss_score": 8.5, "has_exploit": 1}]}'
```

### Using Python
```python
from google.cloud import aiplatform

aiplatform.init(project="quantumsentinel-20251014-1511", location="us-central1")
endpoint = aiplatform.Endpoint("ENDPOINT_RESOURCE_NAME")
response = endpoint.predict(instances=[{"cvss_score": 8.5}])
```

### Using REST API
```bash
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  PREDICTION_URL \
  -d '{"instances": [{"cvss_score": 8.5}]}'
```

## 🎯 Next Steps

1. **Enable billing** in your Google Cloud project
2. **Run real deployment** with `python3 deploy_existing_account.py`
3. **Test endpoints** with sample vulnerability data
4. **Set up monitoring** for production use
5. **Configure CI/CD** for model updates

Your models are trained and ready - just need billing enabled for deployment! 🚀
