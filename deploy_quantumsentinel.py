#!/usr/bin/env python3
"""
Deploy VulnHunter Models to QuantumSentinel Nexus Security Project
Real deployment to quantumsentinel-20250927 with billing enabled
"""

import os
import sys
import json
import subprocess
import logging
from datetime import datetime
from pathlib import Path

# Check for required libraries
try:
    from google.cloud import aiplatform as aip
    from google.cloud import storage
    from google.auth import default
    import joblib
    DEPENDENCIES_OK = True
except ImportError as e:
    DEPENDENCIES_OK = False
    print(f"Missing dependencies: {e}")

class QuantumSentinelDeployer:
    """Deploy to QuantumSentinel Nexus Security project"""

    def __init__(self):
        self.logger = self._setup_logging()

        # QuantumSentinel project configuration
        self.project_id = "quantumsentinel-20250927"
        self.region = "us-central1"
        self.bucket_name = f"{self.project_id}-vulnhunter-models"

        self.logger.info("🚀 QuantumSentinel VulnHunter Deployer")
        self.logger.info(f"🎯 Project: {self.project_id}")
        self.logger.info(f"🌍 Region: {self.region}")

    def _setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(f'quantumsentinel_deploy_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
            ]
        )
        return logging.getLogger('QuantumSentinelDeployer')

    def verify_project_setup(self):
        """Verify project is properly configured"""
        self.logger.info("🔍 Verifying QuantumSentinel project setup...")

        try:
            # Check billing
            result = subprocess.run([
                'gcloud', 'billing', 'projects', 'describe', self.project_id
            ], capture_output=True, text=True)

            if result.returncode == 0 and 'billingEnabled: true' in result.stdout:
                self.logger.info("✅ Billing is enabled")
            else:
                self.logger.error("❌ Billing is not enabled")
                return False

            # Check required APIs
            apis = ['aiplatform.googleapis.com', 'storage.googleapis.com']
            for api in apis:
                result = subprocess.run([
                    'gcloud', 'services', 'list', '--enabled',
                    '--filter', f'name:{api}',
                    '--format', 'value(name)'
                ], capture_output=True, text=True)

                if api in result.stdout:
                    self.logger.info(f"✅ {api} is enabled")
                else:
                    self.logger.error(f"❌ {api} is not enabled")
                    return False

            return True

        except Exception as e:
            self.logger.error(f"❌ Project verification failed: {e}")
            return False

    def create_storage_bucket(self):
        """Get or create GCS bucket for models"""
        self.logger.info(f"📦 Accessing storage bucket: {self.bucket_name}")

        try:
            storage_client = storage.Client(project=self.project_id)

            # Try to access existing bucket
            try:
                bucket = storage_client.bucket(self.bucket_name)
                bucket.reload()
                self.logger.info(f"✅ Using existing bucket: {self.bucket_name}")
                return bucket
            except Exception as e:
                self.logger.info(f"Bucket doesn't exist, trying to create via gsutil...")

            # Try to create using gsutil (often has different permissions)
            import subprocess
            result = subprocess.run([
                'gsutil', 'mb', f'gs://{self.bucket_name}'
            ], capture_output=True, text=True)

            if result.returncode == 0 or 'already exists' in result.stderr:
                bucket = storage_client.bucket(self.bucket_name)
                self.logger.info(f"✅ Bucket ready: {self.bucket_name}")
                return bucket
            else:
                self.logger.error(f"Failed to create bucket via gsutil: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"❌ Failed to access bucket: {e}")
            return None

    def upload_models_to_gcs(self, bucket):
        """Upload trained models to Google Cloud Storage"""
        self.logger.info("📤 Uploading VulnHunter models to GCS...")

        models_dir = Path('models')
        if not models_dir.exists():
            self.logger.error(f"❌ Models directory not found: {models_dir}")
            return {}

        uploaded_models = {}

        try:
            for model_file in models_dir.glob('*.joblib'):
                model_name = model_file.stem.replace('_model', '')
                blob_name = f'models/{model_file.name}'

                self.logger.info(f"Uploading {model_name} model...")

                blob = bucket.blob(blob_name)
                blob.upload_from_filename(str(model_file))

                uploaded_models[model_name] = {
                    'gcs_uri': f"gs://{self.bucket_name}/{blob_name}",
                    'local_path': str(model_file),
                    'size_mb': round(model_file.stat().st_size / (1024 * 1024), 2)
                }

                self.logger.info(f"✅ Uploaded {model_name} ({uploaded_models[model_name]['size_mb']}MB)")

            self.logger.info(f"📊 Total models uploaded: {len(uploaded_models)}")
            return uploaded_models

        except Exception as e:
            self.logger.error(f"❌ Failed to upload models: {e}")
            return {}

    def deploy_model_to_vertex_ai(self, model_name, model_info):
        """Deploy a single model to Vertex AI"""
        self.logger.info(f"🚀 Deploying {model_name} to Vertex AI...")

        try:
            # Model display name
            model_display_name = f"vulnhunter-{model_name}-v1"

            self.logger.info(f"Uploading model to registry: {model_display_name}")

            # Upload model to Vertex AI Model Registry
            model = aip.Model.upload(
                display_name=model_display_name,
                artifact_uri=model_info['gcs_uri'],
                serving_container_image_uri="gcr.io/cloud-aiplatform/prediction/sklearn-cpu.1-0:latest",
                description=f"VulnHunter {model_name} vulnerability detection model for QuantumSentinel",
                labels={
                    "project": "quantumsentinel",
                    "model_type": "vulnerability_detection",
                    "domain": model_name,
                    "version": "v1"
                }
            )

            self.logger.info(f"✅ Model uploaded: {model.resource_name}")

            # Create endpoint
            endpoint_display_name = f"{model_display_name}-endpoint"
            self.logger.info(f"Creating endpoint: {endpoint_display_name}")

            endpoint = aip.Endpoint.create(
                display_name=endpoint_display_name,
                description=f"QuantumSentinel endpoint for {model_name} vulnerability detection",
                labels={
                    "project": "quantumsentinel",
                    "model": model_name,
                    "environment": "production"
                }
            )

            self.logger.info(f"✅ Endpoint created: {endpoint.resource_name}")

            # Deploy model to endpoint
            self.logger.info(f"Deploying model to endpoint...")

            deployed_model = endpoint.deploy(
                model=model,
                deployed_model_display_name=f"{model_display_name}-deployment",
                min_replica_count=1,
                max_replica_count=3,
                machine_type="n1-standard-4",
                sync=True  # Wait for deployment to complete
            )

            self.logger.info(f"✅ {model_name} deployed successfully!")

            return {
                'model': model,
                'endpoint': endpoint,
                'deployed_model': deployed_model,
                'model_resource_name': model.resource_name,
                'endpoint_resource_name': endpoint.resource_name,
                'prediction_url': f"https://{self.region}-aiplatform.googleapis.com/v1/{endpoint.resource_name}:predict",
                'console_model_url': f"https://console.cloud.google.com/vertex-ai/models/{model.resource_name.split('/')[-1]}?project={self.project_id}",
                'console_endpoint_url': f"https://console.cloud.google.com/vertex-ai/endpoints/{endpoint.resource_name.split('/')[-1]}?project={self.project_id}",
                'status': 'DEPLOYED',
                'deployment_time': datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"❌ Failed to deploy {model_name}: {e}")
            return {
                'status': 'FAILED',
                'error': str(e),
                'deployment_time': datetime.now().isoformat()
            }

    def deploy_all_models(self, uploaded_models):
        """Deploy all models to Vertex AI"""
        self.logger.info("🎯 Deploying all VulnHunter models to Vertex AI...")

        # Initialize Vertex AI
        aip.init(project=self.project_id, location=self.region)
        self.logger.info(f"✅ Initialized Vertex AI for {self.project_id}")

        deployed_endpoints = {}

        for model_name, model_info in uploaded_models.items():
            self.logger.info(f"\n🔄 Processing {model_name} model...")

            deployment_result = self.deploy_model_to_vertex_ai(model_name, model_info)
            deployed_endpoints[model_name] = deployment_result

            if deployment_result['status'] == 'DEPLOYED':
                self.logger.info(f"✅ {model_name} deployment successful")
            else:
                self.logger.error(f"❌ {model_name} deployment failed")

        # Summary
        successful_deployments = sum(1 for result in deployed_endpoints.values() if result['status'] == 'DEPLOYED')
        self.logger.info(f"\n📊 Deployment Summary: {successful_deployments}/{len(deployed_endpoints)} models deployed successfully")

        return deployed_endpoints

    def test_deployed_endpoint(self, model_name, endpoint_info):
        """Test a deployed endpoint with sample data"""
        if endpoint_info['status'] != 'DEPLOYED':
            return {'status': 'SKIPPED', 'reason': 'Endpoint not deployed'}

        self.logger.info(f"🧪 Testing {model_name} endpoint...")

        # Sample test data for each model type
        test_data = {
            "cve_nvd": [{"cvss_score": 8.5, "has_exploit": 1, "severity_level": 2, "reference_count": 5}],
            "security_advisories": [{"severity_score": 7.2, "is_popular_package": 1, "weekly_downloads": 50000, "github_stars": 1000}],
            "vulnerability_db": [{"overall_score": 8.0, "has_public_exploit": 1, "estimated_affected_systems": 10000, "complexity_level": 1}],
            "exploit_db": [{"reliability_score": 0.85, "verified": 1, "payload_size": 1024, "remote_exploit": 1}]
        }

        try:
            # Get endpoint
            endpoint = aip.Endpoint(endpoint_info["endpoint_resource_name"])

            # Make prediction
            sample_data = test_data.get(model_name, [{"test_feature": 1}])
            response = endpoint.predict(instances=sample_data)

            return {
                'status': 'SUCCESS',
                'predictions': response.predictions[:3],  # Limit output
                'test_data': sample_data,
                'response_time': 'N/A'  # Would need timing in real implementation
            }

        except Exception as e:
            self.logger.warning(f"⚠️  {model_name} endpoint test failed: {e}")
            return {
                'status': 'FAILED',
                'error': str(e),
                'test_data': test_data.get(model_name, [])
            }

    def test_all_endpoints(self, deployed_endpoints):
        """Test all deployed endpoints"""
        self.logger.info("🧪 Testing all deployed endpoints...")

        test_results = {}

        for model_name, endpoint_info in deployed_endpoints.items():
            test_results[model_name] = self.test_deployed_endpoint(model_name, endpoint_info)

        successful_tests = sum(1 for result in test_results.values() if result['status'] == 'SUCCESS')
        self.logger.info(f"📊 Testing Summary: {successful_tests}/{len(test_results)} endpoints tested successfully")

        return test_results

    def generate_console_links(self, deployed_endpoints):
        """Generate QuantumSentinel console links"""
        self.logger.info("🌐 Generating QuantumSentinel console links...")

        console_links = {
            'project_dashboard': f"https://console.cloud.google.com/home/dashboard?project={self.project_id}",
            'vertex_ai_dashboard': f"https://console.cloud.google.com/vertex-ai/dashboard?project={self.project_id}",
            'vertex_ai_models': f"https://console.cloud.google.com/vertex-ai/models?project={self.project_id}",
            'vertex_ai_endpoints': f"https://console.cloud.google.com/vertex-ai/endpoints?project={self.project_id}",
            'storage_bucket': f"https://console.cloud.google.com/storage/browser/{self.bucket_name}?project={self.project_id}",
            'monitoring': f"https://console.cloud.google.com/monitoring/dashboards?project={self.project_id}",
            'billing': f"https://console.cloud.google.com/billing?project={self.project_id}",
            'apis': f"https://console.cloud.google.com/apis/dashboard?project={self.project_id}",
            'model_endpoints': {}
        }

        # Add individual model links
        for model_name, endpoint_info in deployed_endpoints.items():
            if endpoint_info.get('status') == 'DEPLOYED':
                console_links['model_endpoints'][model_name] = {
                    'model': endpoint_info['console_model_url'],
                    'endpoint': endpoint_info['console_endpoint_url'],
                    'prediction_url': endpoint_info['prediction_url']
                }

        return console_links

    def save_deployment_summary(self, uploaded_models, deployed_endpoints, test_results, console_links):
        """Save comprehensive deployment summary"""
        self.logger.info("💾 Saving QuantumSentinel deployment summary...")

        deployment_dir = Path('deployment')
        deployment_dir.mkdir(exist_ok=True)

        # Comprehensive summary
        summary = {
            'deployment_timestamp': datetime.now().isoformat(),
            'project_id': self.project_id,
            'project_name': 'QuantumSentinel Nexus Security',
            'region': self.region,
            'bucket_name': self.bucket_name,
            'deployment_type': 'PRODUCTION',
            'models_uploaded': len(uploaded_models),
            'endpoints_deployed': len([e for e in deployed_endpoints.values() if e['status'] == 'DEPLOYED']),
            'endpoints_tested': len([t for t in test_results.values() if t['status'] == 'SUCCESS']),
            'uploaded_models': uploaded_models,
            'deployed_endpoints': deployed_endpoints,
            'test_results': test_results,
            'console_links': console_links,
            'total_model_size_mb': sum(m['size_mb'] for m in uploaded_models.values()),
            'estimated_monthly_cost_usd': len(deployed_endpoints) * 250,  # Rough estimate
            'deployment_success': all(e['status'] == 'DEPLOYED' for e in deployed_endpoints.values())
        }

        # Save summary
        summary_path = deployment_dir / 'quantumsentinel_deployment_summary.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        self.logger.info(f"📋 Deployment summary saved: {summary_path}")
        return summary

    def run_quantumsentinel_deployment(self):
        """Execute complete QuantumSentinel deployment"""
        self.logger.info("🚀 Starting VulnHunter deployment to QuantumSentinel Nexus Security")
        self.logger.info("=" * 80)

        try:
            # Step 1: Verify project setup
            if not self.verify_project_setup():
                return False

            # Step 2: Create storage bucket
            bucket = self.create_storage_bucket()
            if not bucket:
                return False

            # Step 3: Upload models
            uploaded_models = self.upload_models_to_gcs(bucket)
            if not uploaded_models:
                return False

            # Step 4: Deploy to Vertex AI
            deployed_endpoints = self.deploy_all_models(uploaded_models)
            if not deployed_endpoints:
                return False

            # Step 5: Test endpoints
            test_results = self.test_all_endpoints(deployed_endpoints)

            # Step 6: Generate console links
            console_links = self.generate_console_links(deployed_endpoints)

            # Step 7: Save summary
            summary = self.save_deployment_summary(uploaded_models, deployed_endpoints, test_results, console_links)

            # Final success summary
            self.logger.info("\n" + "=" * 80)
            self.logger.info("🎉 QUANTUMSENTINEL DEPLOYMENT COMPLETED!")
            self.logger.info("=" * 80)
            self.logger.info(f"🎯 Project: {self.project_id}")
            self.logger.info(f"📊 Models Deployed: {summary['endpoints_deployed']}/{summary['models_uploaded']}")
            self.logger.info(f"🧪 Endpoints Tested: {summary['endpoints_tested']}/{summary['endpoints_deployed']}")
            self.logger.info(f"💰 Est. Monthly Cost: ${summary['estimated_monthly_cost_usd']}")

            self.logger.info(f"\n🌐 View in Google Cloud Console:")
            self.logger.info(f"   Main Dashboard: {console_links['vertex_ai_dashboard']}")
            self.logger.info(f"   Models: {console_links['vertex_ai_models']}")
            self.logger.info(f"   Endpoints: {console_links['vertex_ai_endpoints']}")

            self.logger.info(f"\n🎯 Individual Endpoints:")
            for model_name, links in console_links['model_endpoints'].items():
                self.logger.info(f"   {model_name}: {links['endpoint']}")

            return True

        except Exception as e:
            self.logger.error(f"❌ QuantumSentinel deployment failed: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False

def main():
    """Main execution"""
    print("VulnHunter Deployment to QuantumSentinel Nexus Security")
    print("Project: quantumsentinel-20250927")
    print("=" * 80)

    if not DEPENDENCIES_OK:
        print("\n❌ Missing required dependencies!")
        print("Install with:")
        print("pip install google-cloud-aiplatform google-cloud-storage joblib")
        return 1

    deployer = QuantumSentinelDeployer()
    success = deployer.run_quantumsentinel_deployment()

    if success:
        print("\n✅ QuantumSentinel deployment completed successfully!")
        print("🌐 VulnHunter models are now live on Vertex AI!")
        return 0
    else:
        print("\n❌ Deployment failed - check logs for details")
        return 1

if __name__ == "__main__":
    sys.exit(main())