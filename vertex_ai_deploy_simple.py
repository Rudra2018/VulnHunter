#!/usr/bin/env python3
"""
Simple Vertex AI Deployment for QuantumSentinel
Models are already uploaded to GCS, now deploy to Vertex AI
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path

try:
    from google.cloud import aiplatform as aip
    VERTEX_AI_AVAILABLE = True
except ImportError:
    VERTEX_AI_AVAILABLE = False
    print("google-cloud-aiplatform not available")

class SimpleVertexAIDeployer:
    """Simple Vertex AI deployment"""

    def __init__(self):
        self.logger = self._setup_logging()
        self.project_id = "quantumsentinel-20250927"
        self.region = "us-central1"
        self.bucket_name = f"{self.project_id}-vulnhunter-models"

        self.logger.info("🚀 Simple Vertex AI Deployer for QuantumSentinel")

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        return logging.getLogger('SimpleVertexAI')

    def initialize_vertex_ai(self):
        """Initialize Vertex AI"""
        try:
            aip.init(project=self.project_id, location=self.region)
            self.logger.info(f"✅ Vertex AI initialized for {self.project_id}")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Vertex AI: {e}")
            return False

    def deploy_single_model(self, model_name):
        """Deploy a single model to Vertex AI"""
        self.logger.info(f"🚀 Deploying {model_name} model...")

        try:
            # Model configuration
            model_display_name = f"vulnhunter-{model_name}-v1"
            artifact_uri = f"gs://{self.bucket_name}/models/{model_name}_model.joblib"

            self.logger.info(f"Uploading model: {model_display_name}")
            self.logger.info(f"Artifact URI: {artifact_uri}")

            # Upload model to registry
            model = aip.Model.upload(
                display_name=model_display_name,
                artifact_uri=artifact_uri,
                serving_container_image_uri="gcr.io/cloud-aiplatform/prediction/sklearn-cpu.1-0:latest",
                description=f"VulnHunter {model_name} model for QuantumSentinel",
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
                description=f"QuantumSentinel {model_name} vulnerability detection endpoint",
                labels={
                    "project": "quantumsentinel",
                    "model": model_name
                }
            )

            self.logger.info(f"✅ Endpoint created: {endpoint.resource_name}")

            # Deploy model to endpoint
            self.logger.info("Deploying model to endpoint...")

            deployed_model = endpoint.deploy(
                model=model,
                deployed_model_display_name=f"{model_display_name}-deployment",
                min_replica_count=1,
                max_replica_count=3,
                machine_type="n1-standard-2",  # Smaller machine for testing
                sync=True
            )

            self.logger.info(f"✅ {model_name} deployed successfully!")

            return {
                'status': 'SUCCESS',
                'model_name': model_display_name,
                'endpoint_name': endpoint_display_name,
                'model_resource_name': model.resource_name,
                'endpoint_resource_name': endpoint.resource_name,
                'prediction_url': f"https://{self.region}-aiplatform.googleapis.com/v1/{endpoint.resource_name}:predict",
                'console_model_url': f"https://console.cloud.google.com/vertex-ai/models/{model.resource_name.split('/')[-1]}?project={self.project_id}",
                'console_endpoint_url': f"https://console.cloud.google.com/vertex-ai/endpoints/{endpoint.resource_name.split('/')[-1]}?project={self.project_id}",
                'deployment_time': datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"❌ Failed to deploy {model_name}: {e}")
            return {
                'status': 'FAILED',
                'model_name': model_name,
                'error': str(e),
                'deployment_time': datetime.now().isoformat()
            }

    def deploy_all_models(self):
        """Deploy all VulnHunter models"""
        self.logger.info("🎯 Deploying all VulnHunter models...")

        models = ['cve_nvd', 'security_advisories', 'vulnerability_db', 'exploit_db']
        deployment_results = {}

        for model_name in models:
            self.logger.info(f"\n--- Deploying {model_name} ---")
            result = self.deploy_single_model(model_name)
            deployment_results[model_name] = result

            if result['status'] == 'SUCCESS':
                self.logger.info(f"✅ {model_name} deployment successful")
            else:
                self.logger.error(f"❌ {model_name} deployment failed")

        return deployment_results

    def generate_console_links(self, deployment_results):
        """Generate console links"""
        console_links = {
            'vertex_ai_dashboard': f"https://console.cloud.google.com/vertex-ai/dashboard?project={self.project_id}",
            'vertex_ai_models': f"https://console.cloud.google.com/vertex-ai/models?project={self.project_id}",
            'vertex_ai_endpoints': f"https://console.cloud.google.com/vertex-ai/endpoints?project={self.project_id}",
            'model_endpoints': {}
        }

        for model_name, result in deployment_results.items():
            if result['status'] == 'SUCCESS':
                console_links['model_endpoints'][model_name] = {
                    'model': result['console_model_url'],
                    'endpoint': result['console_endpoint_url'],
                    'prediction_url': result['prediction_url']
                }

        return console_links

    def save_deployment_results(self, deployment_results, console_links):
        """Save deployment results"""
        deployment_dir = Path('deployment')
        deployment_dir.mkdir(exist_ok=True)

        results = {
            'deployment_timestamp': datetime.now().isoformat(),
            'project_id': self.project_id,
            'project_name': 'QuantumSentinel Nexus Security',
            'deployment_results': deployment_results,
            'console_links': console_links,
            'successful_deployments': len([r for r in deployment_results.values() if r['status'] == 'SUCCESS']),
            'total_models': len(deployment_results)
        }

        results_path = deployment_dir / 'quantumsentinel_vertex_ai_results.json'
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"📋 Results saved: {results_path}")
        return results

    def run_deployment(self):
        """Run the complete deployment"""
        self.logger.info("🚀 Starting QuantumSentinel VulnHunter deployment...")
        self.logger.info("=" * 80)

        if not VERTEX_AI_AVAILABLE:
            self.logger.error("❌ google-cloud-aiplatform not available")
            return False

        try:
            # Initialize Vertex AI
            if not self.initialize_vertex_ai():
                return False

            # Deploy all models
            deployment_results = self.deploy_all_models()

            # Generate console links
            console_links = self.generate_console_links(deployment_results)

            # Save results
            results = self.save_deployment_results(deployment_results, console_links)

            # Summary
            successful = results['successful_deployments']
            total = results['total_models']

            self.logger.info("\n" + "=" * 80)
            self.logger.info("🎉 QUANTUMSENTINEL DEPLOYMENT COMPLETED!")
            self.logger.info("=" * 80)
            self.logger.info(f"📊 Success Rate: {successful}/{total} models deployed")

            if successful > 0:
                self.logger.info(f"\n🌐 View in Google Cloud Console:")
                self.logger.info(f"   Dashboard: {console_links['vertex_ai_dashboard']}")
                self.logger.info(f"   Models: {console_links['vertex_ai_models']}")
                self.logger.info(f"   Endpoints: {console_links['vertex_ai_endpoints']}")

                self.logger.info(f"\n🎯 Deployed Models:")
                for model_name, links in console_links['model_endpoints'].items():
                    self.logger.info(f"   {model_name}: {links['endpoint']}")

            return successful > 0

        except Exception as e:
            self.logger.error(f"❌ Deployment failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False

def main():
    print("QuantumSentinel VulnHunter - Simple Vertex AI Deployment")
    print("=" * 80)

    deployer = SimpleVertexAIDeployer()
    success = deployer.run_deployment()

    if success:
        print("\n✅ Deployment completed!")
        print("🌐 Check Google Cloud Console for your models!")
        return 0
    else:
        print("\n❌ Deployment failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())