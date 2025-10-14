#!/usr/bin/env python3
"""
Vertex AI Setup and Training Deployment for VulnHunter ML Model
This script sets up the Google Cloud Vertex AI environment and deploys training jobs
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path

# Google Cloud imports
try:
    from google.cloud import aiplatform as aip
    from google.cloud import storage
    from google.auth import default
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    print("Warning: Google Cloud libraries not installed. Install with: pip install google-cloud-aiplatform google-cloud-storage")

class VertexAIDeployment:
    """Handles Vertex AI deployment and training orchestration"""

    def __init__(self):
        self.logger = self._setup_logging()

        # Configuration
        self.PROJECT_ID = "vulnhunter-ml-research"  # Update with your actual project ID
        self.REGION = "us-central1"
        self.BUCKET_NAME = "vulnhunter-training-bucket"
        self.DOCKER_IMAGE_URI = f"gcr.io/{self.PROJECT_ID}/vulnhunter-training:latest"

        # Training configuration
        self.MACHINE_TYPE = "n1-highmem-8"
        self.ACCELERATOR_TYPE = "NVIDIA_TESLA_V100"
        self.ACCELERATOR_COUNT = 2

    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(f'vertex_ai_setup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
            ]
        )
        return logging.getLogger('VertexAI-Setup')

    def validate_environment(self):
        """Validate the environment setup"""
        self.logger.info("🔍 Validating environment setup...")

        issues = []

        # Check if GCP libraries are available
        if not GCP_AVAILABLE:
            issues.append("Google Cloud libraries not installed")

        # Check for credentials
        try:
            credentials, project = default()
            self.logger.info(f"✅ GCP credentials found for project: {project}")
            if project:
                self.PROJECT_ID = project
        except Exception as e:
            issues.append(f"GCP credentials not configured: {e}")

        # Check Claude API key
        if not os.getenv('CLAUDE_API_KEY'):
            issues.append("CLAUDE_API_KEY environment variable not set")
        else:
            self.logger.info("✅ Claude API key configured")

        if issues:
            self.logger.error("❌ Environment validation failed:")
            for issue in issues:
                self.logger.error(f"  - {issue}")
            return False

        self.logger.info("✅ Environment validation passed")
        return True

    def create_training_bucket(self):
        """Create GCS bucket for training data and models"""
        if not GCP_AVAILABLE:
            self.logger.warning("⚠️  GCP not available, skipping bucket creation")
            return False

        try:
            self.logger.info(f"📦 Creating GCS bucket: {self.BUCKET_NAME}")

            storage_client = storage.Client(project=self.PROJECT_ID)

            # Check if bucket exists
            bucket = storage_client.bucket(self.BUCKET_NAME)
            if bucket.exists():
                self.logger.info(f"✅ Bucket {self.BUCKET_NAME} already exists")
                return True

            # Create bucket
            bucket = storage_client.create_bucket(self.BUCKET_NAME, location=self.REGION)
            self.logger.info(f"✅ Created bucket: {self.BUCKET_NAME}")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to create bucket: {e}")
            return False

    def build_docker_image(self):
        """Build and push Docker image for training"""
        self.logger.info("🐳 Building Docker image for Vertex AI training...")

        dockerfile_path = "src/deployment/Dockerfile.vertex"
        if not Path(dockerfile_path).exists():
            self.logger.error(f"❌ Dockerfile not found: {dockerfile_path}")
            return False

        try:
            # Build Docker image
            build_cmd = f"docker build -f {dockerfile_path} -t {self.DOCKER_IMAGE_URI} ."
            self.logger.info(f"Building image: {build_cmd}")

            import subprocess
            result = subprocess.run(build_cmd.split(), capture_output=True, text=True)

            if result.returncode != 0:
                self.logger.error(f"❌ Docker build failed: {result.stderr}")
                return False

            self.logger.info("✅ Docker image built successfully")

            # Push to GCR
            push_cmd = f"docker push {self.DOCKER_IMAGE_URI}"
            self.logger.info(f"Pushing image: {push_cmd}")

            result = subprocess.run(push_cmd.split(), capture_output=True, text=True)

            if result.returncode != 0:
                self.logger.error(f"❌ Docker push failed: {result.stderr}")
                return False

            self.logger.info("✅ Docker image pushed to GCR")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to build/push Docker image: {e}")
            return False

    def setup_vertex_ai(self):
        """Initialize Vertex AI configuration"""
        if not GCP_AVAILABLE:
            self.logger.warning("⚠️  GCP not available, creating mock setup")
            return self.create_mock_setup()

        try:
            self.logger.info("🚀 Initializing Vertex AI...")
            aip.init(project=self.PROJECT_ID, location=self.REGION)

            self.logger.info(f"✅ Vertex AI initialized for project: {self.PROJECT_ID}")
            self.logger.info(f"   Region: {self.REGION}")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Vertex AI: {e}")
            return False

    def create_training_job(self):
        """Create and submit Vertex AI training job"""
        if not GCP_AVAILABLE:
            self.logger.info("🎭 Creating training job simulation...")
            return self.simulate_training_job()

        try:
            self.logger.info("📊 Creating Vertex AI training job...")

            job_name = f"vulnhunter-training-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

            # Create custom training job
            from google.cloud.aiplatform.training_jobs import CustomTrainingJob

            job = CustomTrainingJob(
                display_name=job_name,
                container_uri=self.DOCKER_IMAGE_URI,
                model_serving_container_image_uri="gcr.io/cloud-aiplatform/prediction/tf2-cpu.2-8:latest"
            )

            # Submit job
            model = job.run(
                replica_count=1,
                machine_type=self.MACHINE_TYPE,
                accelerator_type=self.ACCELERATOR_TYPE,
                accelerator_count=self.ACCELERATOR_COUNT,
                base_output_dir=f"gs://{self.BUCKET_NAME}/training-output",
                service_account=None,
                network=None,
                timeout=None,
                restart_job_on_worker_restart=False,
                enable_web_access=False,
                environment_variables={
                    'CLAUDE_API_KEY': os.getenv('CLAUDE_API_KEY', ''),
                    'PROJECT_ID': self.PROJECT_ID,
                    'BUCKET_NAME': self.BUCKET_NAME
                }
            )

            self.logger.info(f"✅ Training job submitted: {job_name}")
            self.logger.info(f"   Job resource name: {job.resource_name}")

            # Save job information
            job_info = {
                'job_name': job_name,
                'resource_name': job.resource_name,
                'project_id': self.PROJECT_ID,
                'region': self.REGION,
                'status': 'RUNNING',
                'created_at': datetime.now().isoformat()
            }

            with open('vertex_ai_job_info.json', 'w') as f:
                json.dump(job_info, f, indent=2)

            return job_info

        except Exception as e:
            self.logger.error(f"❌ Failed to create training job: {e}")
            return None

    def simulate_training_job(self):
        """Simulate training job for demonstration purposes"""
        self.logger.info("🎭 Simulating Vertex AI training job...")

        job_name = f"vulnhunter-training-sim-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        job_info = {
            'job_name': job_name,
            'resource_name': f"projects/{self.PROJECT_ID}/locations/{self.REGION}/trainingPipelines/simulated",
            'project_id': self.PROJECT_ID,
            'region': self.REGION,
            'status': 'SIMULATED_RUNNING',
            'created_at': datetime.now().isoformat(),
            'simulation': True,
            'expected_duration_hours': 2.5,
            'training_data_size_gb': 15.7,
            'model_architecture': 'Multi-domain Ensemble with Claude Integration'
        }

        with open('vertex_ai_job_simulation.json', 'w') as f:
            json.dump(job_info, f, indent=2)

        self.logger.info(f"✅ Simulated training job: {job_name}")
        self.logger.info("   This is a simulation for demonstration purposes")
        self.logger.info("   In production, this would submit a real Vertex AI job")

        return job_info

    def create_mock_setup(self):
        """Create mock setup when GCP is not available"""
        self.logger.info("🎭 Creating mock Vertex AI setup...")

        setup_info = {
            'project_id': self.PROJECT_ID,
            'region': self.REGION,
            'bucket_name': self.BUCKET_NAME,
            'docker_image': self.DOCKER_IMAGE_URI,
            'machine_type': self.MACHINE_TYPE,
            'accelerator_type': self.ACCELERATOR_TYPE,
            'accelerator_count': self.ACCELERATOR_COUNT,
            'setup_type': 'MOCK',
            'created_at': datetime.now().isoformat()
        }

        with open('vertex_ai_mock_setup.json', 'w') as f:
            json.dump(setup_info, f, indent=2)

        self.logger.info("✅ Mock setup created for demonstration")
        return True

    def run_full_deployment(self):
        """Run the complete deployment pipeline"""
        self.logger.info("🚀 Starting Vertex AI deployment pipeline...")
        self.logger.info("=" * 60)

        success_steps = []

        # Step 1: Validate environment
        if self.validate_environment():
            success_steps.append("Environment validation")
        else:
            self.logger.error("❌ Environment validation failed - continuing with limited functionality")

        # Step 2: Setup Vertex AI
        if self.setup_vertex_ai():
            success_steps.append("Vertex AI initialization")

        # Step 3: Create bucket
        if self.create_training_bucket():
            success_steps.append("GCS bucket creation")

        # Step 4: Build Docker image (skip if no Docker available)
        try:
            import subprocess
            subprocess.run(["docker", "--version"], capture_output=True)
            if self.build_docker_image():
                success_steps.append("Docker image build")
        except:
            self.logger.warning("⚠️  Docker not available, skipping image build")

        # Step 5: Create training job
        job_info = self.create_training_job()
        if job_info:
            success_steps.append("Training job creation")

        # Summary
        self.logger.info("\n" + "=" * 60)
        self.logger.info("🎯 DEPLOYMENT SUMMARY")
        self.logger.info("=" * 60)

        self.logger.info(f"✅ Successfully completed {len(success_steps)} steps:")
        for step in success_steps:
            self.logger.info(f"   - {step}")

        if job_info:
            self.logger.info(f"\n🚀 Training Job Details:")
            self.logger.info(f"   Job Name: {job_info['job_name']}")
            self.logger.info(f"   Status: {job_info['status']}")
            self.logger.info(f"   Project: {job_info['project_id']}")

            if job_info.get('simulation'):
                self.logger.info("\n🎭 This is a simulation - no real resources were created")
                self.logger.info("   To run with real Vertex AI:")
                self.logger.info("   1. Set up GCP credentials")
                self.logger.info("   2. Install google-cloud-aiplatform")
                self.logger.info("   3. Configure PROJECT_ID in the script")

        return len(success_steps) > 2

def main():
    """Main execution function"""
    print("VulnHunter Vertex AI Deployment Setup")
    print("=" * 60)

    deployment = VertexAIDeployment()
    success = deployment.run_full_deployment()

    if success:
        print("\n✅ Vertex AI deployment setup completed successfully!")
        print("Check the generated JSON files for detailed information.")
    else:
        print("\n❌ Deployment setup encountered issues.")
        print("Check the log file for detailed error information.")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())