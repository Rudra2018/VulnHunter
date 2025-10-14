#!/usr/bin/env python3
"""
Deploy VulnHunter Models via gcloud CLI commands
Direct deployment to QuantumSentinel using command line interface
"""

import os
import sys
import json
import subprocess
import logging
from datetime import datetime
from pathlib import Path

class GCloudDeployer:
    """Deploy models using gcloud CLI commands"""

    def __init__(self):
        self.logger = self._setup_logging()
        self.project_id = "quantumsentinel-20250927"
        self.region = "us-central1"
        self.bucket_name = f"{self.project_id}-vulnhunter-models"

        self.logger.info("🚀 GCloud CLI Deployer for QuantumSentinel")

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        return logging.getLogger('GCloudDeployer')

    def run_command(self, command, description):
        """Run a shell command and return result"""
        self.logger.info(f"🔄 {description}")
        self.logger.info(f"   Command: {' '.join(command)}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                self.logger.info(f"✅ {description} - SUCCESS")
                if result.stdout.strip():
                    self.logger.info(f"   Output: {result.stdout.strip()}")
                return True, result.stdout.strip()
            else:
                self.logger.error(f"❌ {description} - FAILED")
                self.logger.error(f"   Error: {result.stderr.strip()}")
                return False, result.stderr.strip()

        except subprocess.TimeoutExpired:
            self.logger.error(f"⏱️  {description} - TIMEOUT")
            return False, "Command timed out"
        except Exception as e:
            self.logger.error(f"💥 {description} - EXCEPTION: {e}")
            return False, str(e)

    def upload_model_to_vertex_ai(self, model_name, display_name, artifact_uri):
        """Upload a model to Vertex AI using gcloud"""
        self.logger.info(f"📤 Uploading {model_name} to Vertex AI...")

        command = [
            'gcloud', 'ai', 'models', 'upload',
            '--region', self.region,
            '--display-name', display_name,
            '--container-image-uri', 'gcr.io/cloud-aiplatform/prediction/sklearn-cpu.1-0:latest',
            '--artifact-uri', artifact_uri,
            '--description', f'VulnHunter {model_name} model for QuantumSentinel vulnerability detection',
            '--format', 'json'
        ]

        success, output = self.run_command(command, f"Upload {model_name} model")

        if success:
            try:
                # Parse the JSON output to get model ID
                model_info = json.loads(output)
                model_id = model_info.get('name', '').split('/')[-1]
                self.logger.info(f"✅ Model {model_name} uploaded with ID: {model_id}")
                return model_id
            except:
                # Fallback: extract model ID from output
                lines = output.split('\n')
                for line in lines:
                    if 'models/' in line:
                        model_id = line.split('/')[-1].strip()
                        return model_id
                return None
        return None

    def create_endpoint(self, model_name, display_name):
        """Create an endpoint using gcloud"""
        self.logger.info(f"🌐 Creating endpoint for {model_name}...")

        command = [
            'gcloud', 'ai', 'endpoints', 'create',
            '--region', self.region,
            '--display-name', display_name,
            '--description', f'QuantumSentinel endpoint for {model_name} vulnerability detection',
            '--format', 'json'
        ]

        success, output = self.run_command(command, f"Create {model_name} endpoint")

        if success:
            try:
                endpoint_info = json.loads(output)
                endpoint_id = endpoint_info.get('name', '').split('/')[-1]
                self.logger.info(f"✅ Endpoint {model_name} created with ID: {endpoint_id}")
                return endpoint_id
            except:
                # Fallback parsing
                lines = output.split('\n')
                for line in lines:
                    if 'endpoints/' in line:
                        endpoint_id = line.split('/')[-1].strip()
                        return endpoint_id
                return None
        return None

    def deploy_model_to_endpoint(self, model_name, model_id, endpoint_id):
        """Deploy model to endpoint using gcloud"""
        self.logger.info(f"🚀 Deploying {model_name} to endpoint...")

        command = [
            'gcloud', 'ai', 'endpoints', 'deploy-model', endpoint_id,
            '--region', self.region,
            '--model', model_id,
            '--display-name', f'vulnhunter-{model_name}-deployment',
            '--machine-type', 'n1-standard-2',
            '--min-replica-count', '1',
            '--max-replica-count', '3',
            '--traffic-split', '0=100'
        ]

        success, output = self.run_command(command, f"Deploy {model_name} to endpoint")
        return success

    def deploy_single_model(self, model_name):
        """Deploy a single model end-to-end"""
        self.logger.info(f"\n🎯 Starting deployment of {model_name}...")

        # Model configuration
        display_name = f"vulnhunter-{model_name}-v1"
        endpoint_name = f"{display_name}-endpoint"
        artifact_uri = f"gs://{self.bucket_name}/models/{model_name}_model.joblib"

        # Step 1: Upload model
        model_id = self.upload_model_to_vertex_ai(model_name, display_name, artifact_uri)
        if not model_id:
            return {
                'status': 'FAILED',
                'step': 'model_upload',
                'model_name': model_name
            }

        # Step 2: Create endpoint
        endpoint_id = self.create_endpoint(model_name, endpoint_name)
        if not endpoint_id:
            return {
                'status': 'FAILED',
                'step': 'endpoint_creation',
                'model_name': model_name,
                'model_id': model_id
            }

        # Step 3: Deploy model to endpoint
        deploy_success = self.deploy_model_to_endpoint(model_name, model_id, endpoint_id)
        if not deploy_success:
            return {
                'status': 'FAILED',
                'step': 'model_deployment',
                'model_name': model_name,
                'model_id': model_id,
                'endpoint_id': endpoint_id
            }

        # Success!
        return {
            'status': 'SUCCESS',
            'model_name': model_name,
            'display_name': display_name,
            'model_id': model_id,
            'endpoint_id': endpoint_id,
            'artifact_uri': artifact_uri,
            'console_model_url': f"https://console.cloud.google.com/vertex-ai/models/{model_id}?project={self.project_id}",
            'console_endpoint_url': f"https://console.cloud.google.com/vertex-ai/endpoints/{endpoint_id}?project={self.project_id}",
            'prediction_url': f"https://{self.region}-aiplatform.googleapis.com/v1/projects/{self.project_id}/locations/{self.region}/endpoints/{endpoint_id}:predict"
        }

    def deploy_all_models(self):
        """Deploy all VulnHunter models"""
        self.logger.info("🎯 Deploying all VulnHunter models to QuantumSentinel...")
        self.logger.info("=" * 80)

        models = ['cve_nvd', 'security_advisories', 'vulnerability_db', 'exploit_db']
        deployment_results = {}

        for model_name in models:
            result = self.deploy_single_model(model_name)
            deployment_results[model_name] = result

            if result['status'] == 'SUCCESS':
                self.logger.info(f"✅ {model_name} deployed successfully!")
            else:
                self.logger.error(f"❌ {model_name} deployment failed at {result.get('step', 'unknown')}")

        return deployment_results

    def test_endpoint(self, model_name, endpoint_id):
        """Test an endpoint with sample data"""
        self.logger.info(f"🧪 Testing {model_name} endpoint...")

        # Sample test data
        test_data = {
            "cve_nvd": '{"instances": [{"cvss_score": 8.5, "has_exploit": 1}]}',
            "security_advisories": '{"instances": [{"severity_score": 7.2, "is_popular_package": 1}]}',
            "vulnerability_db": '{"instances": [{"overall_score": 8.0, "has_public_exploit": 1}]}',
            "exploit_db": '{"instances": [{"reliability_score": 0.85, "verified": 1}]}'
        }

        test_payload = test_data.get(model_name, '{"instances": [{"test": 1}]}')

        command = [
            'gcloud', 'ai', 'endpoints', 'predict', endpoint_id,
            '--region', self.region,
            '--json-request', test_payload
        ]

        success, output = self.run_command(command, f"Test {model_name} endpoint")
        return success, output

    def generate_summary(self, deployment_results):
        """Generate deployment summary"""
        self.logger.info("📊 Generating deployment summary...")

        successful_deployments = [r for r in deployment_results.values() if r['status'] == 'SUCCESS']
        failed_deployments = [r for r in deployment_results.values() if r['status'] == 'FAILED']

        summary = {
            'deployment_timestamp': datetime.now().isoformat(),
            'project_id': self.project_id,
            'project_name': 'QuantumSentinel Nexus Security',
            'total_models': len(deployment_results),
            'successful_deployments': len(successful_deployments),
            'failed_deployments': len(failed_deployments),
            'deployment_results': deployment_results,
            'console_links': {
                'vertex_ai_dashboard': f"https://console.cloud.google.com/vertex-ai/dashboard?project={self.project_id}",
                'models': f"https://console.cloud.google.com/vertex-ai/models?project={self.project_id}",
                'endpoints': f"https://console.cloud.google.com/vertex-ai/endpoints?project={self.project_id}"
            }
        }

        # Save summary
        deployment_dir = Path('deployment')
        deployment_dir.mkdir(exist_ok=True)

        summary_path = deployment_dir / 'gcloud_deployment_summary.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        self.logger.info(f"📋 Summary saved: {summary_path}")
        return summary

    def run_complete_deployment(self):
        """Run complete deployment process"""
        try:
            # Deploy all models
            deployment_results = self.deploy_all_models()

            # Generate summary
            summary = self.generate_summary(deployment_results)

            # Final report
            self.logger.info("\n" + "=" * 80)
            self.logger.info("🎉 QUANTUMSENTINEL DEPLOYMENT COMPLETED!")
            self.logger.info("=" * 80)
            self.logger.info(f"📊 Success Rate: {summary['successful_deployments']}/{summary['total_models']} models")

            if summary['successful_deployments'] > 0:
                self.logger.info(f"\n🌐 View in Google Cloud Console:")
                self.logger.info(f"   Dashboard: {summary['console_links']['vertex_ai_dashboard']}")
                self.logger.info(f"   Models: {summary['console_links']['models']}")
                self.logger.info(f"   Endpoints: {summary['console_links']['endpoints']}")

                self.logger.info(f"\n🎯 Successfully Deployed Models:")
                for model_name, result in deployment_results.items():
                    if result['status'] == 'SUCCESS':
                        self.logger.info(f"   {model_name}: {result['console_endpoint_url']}")

            if summary['failed_deployments'] > 0:
                self.logger.info(f"\n❌ Failed Deployments:")
                for model_name, result in deployment_results.items():
                    if result['status'] == 'FAILED':
                        self.logger.info(f"   {model_name}: Failed at {result.get('step', 'unknown')}")

            return summary['successful_deployments'] > 0

        except Exception as e:
            self.logger.error(f"❌ Deployment failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False

def main():
    print("QuantumSentinel VulnHunter - Direct GCloud Deployment")
    print("=" * 80)

    deployer = GCloudDeployer()
    success = deployer.run_complete_deployment()

    if success:
        print("\n✅ Deployment completed successfully!")
        print("🌐 Your models are live on Vertex AI!")
        return 0
    else:
        print("\n❌ Deployment had issues - check logs")
        return 1

if __name__ == "__main__":
    sys.exit(main())