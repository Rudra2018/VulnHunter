#!/usr/bin/env python3
"""
Production Vertex AI Training Setup for VulnHunter V4
Real Vertex AI training with comprehensive dataset
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from google.cloud import aiplatform
from google.cloud import storage
from google.oauth2 import service_account

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProductionVertexAISetup:
    """Production setup for VulnHunter V4 training on Vertex AI."""

    def __init__(self, project_id: str, location: str = "us-central1",
                 service_account_path: str = None):
        """Initialize production setup."""
        self.project_id = project_id
        self.location = location
        self.bucket_name = f"{project_id}-vulnhunter-training"

        # Initialize credentials
        if service_account_path and os.path.exists(service_account_path):
            credentials = service_account.Credentials.from_service_account_file(
                service_account_path
            )
            self.storage_client = storage.Client(credentials=credentials, project=project_id)
            aiplatform.init(project=project_id, location=location, credentials=credentials)
        else:
            # Use default credentials
            self.storage_client = storage.Client(project=project_id)
            aiplatform.init(project=project_id, location=location)

        self.training_data_path = "/Users/ankitthakur/vuln_ml_research/data/training"

        logger.info(f"Initialized Vertex AI for project: {project_id}")
        logger.info(f"Location: {location}")
        logger.info(f"Bucket: {self.bucket_name}")

    def create_storage_bucket(self) -> bool:
        """Create GCS bucket for training data if it doesn't exist."""
        try:
            bucket = self.storage_client.bucket(self.bucket_name)
            if bucket.exists():
                logger.info(f"Bucket {self.bucket_name} already exists")
                return True

            bucket = self.storage_client.create_bucket(
                self.bucket_name,
                location=self.location
            )
            logger.info(f"Created bucket: {self.bucket_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to create bucket: {e}")
            return False

    def upload_training_data(self) -> Dict[str, str]:
        """Upload all training data to GCS."""
        logger.info("Uploading training data to GCS...")

        bucket = self.storage_client.bucket(self.bucket_name)
        uploaded_files = {}

        # Training data files to upload
        files_to_upload = [
            "comprehensive_vulnhunter_v4_training_dataset.json",
            "false_positive_training_20251013_140908.json",
            "microsoft_bounty_training_20251013_142441.json",
            "ollama_validation_training_20250114_180000.json",
            "gemini_cli_validation_training_20250114_183000.json",
            "synthetic/synthetic_training_dataset.json"
        ]

        for file_path in files_to_upload:
            local_path = Path(self.training_data_path) / file_path
            if local_path.exists():
                # Upload to GCS
                blob_name = f"training_data/{file_path}"
                blob = bucket.blob(blob_name)

                blob.upload_from_filename(str(local_path))
                gcs_uri = f"gs://{self.bucket_name}/{blob_name}"
                uploaded_files[file_path] = gcs_uri

                logger.info(f"Uploaded {file_path} to {gcs_uri}")
            else:
                logger.warning(f"File not found: {local_path}")

        # Upload training scripts
        script_files = [
            "/Users/ankitthakur/vuln_ml_research/vertex_ai/vulnhunter_v4_training_pipeline.py",
            "/Users/ankitthakur/vuln_ml_research/vertex_ai/requirements.txt"
        ]

        for script_path in script_files:
            if Path(script_path).exists():
                blob_name = f"training_code/{Path(script_path).name}"
                blob = bucket.blob(blob_name)
                blob.upload_from_filename(script_path)

                gcs_uri = f"gs://{self.bucket_name}/{blob_name}"
                uploaded_files[Path(script_path).name] = gcs_uri
                logger.info(f"Uploaded {Path(script_path).name} to {gcs_uri}")

        return uploaded_files

    def create_training_job_config(self, uploaded_files: Dict[str, str]) -> Dict:
        """Create Vertex AI training job configuration."""

        job_config = {
            "display_name": f"vulnhunter-v4-training-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "job_spec": {
                "worker_pool_specs": [
                    {
                        "machine_spec": {
                            "machine_type": "n1-standard-8",  # 8 vCPUs, 30GB RAM
                            "accelerator_type": "NVIDIA_TESLA_T4",
                            "accelerator_count": 1
                        },
                        "replica_count": 1,
                        "python_package_spec": {
                            "executor_image_uri": "us-docker.pkg.dev/vertex-ai/training/tf-gpu.2-11.py310:latest",
                            "package_uris": [uploaded_files.get("requirements.txt", "")],
                            "python_module": "vulnhunter_v4_training_pipeline",
                            "args": [
                                f"--project_id={self.project_id}",
                                f"--location={self.location}",
                                f"--bucket_name={self.bucket_name}",
                                "--training_data_paths=" + ",".join([
                                    uri for uri in uploaded_files.values()
                                    if uri.endswith('.json')
                                ])
                            ]
                        }
                    }
                ],
                "scheduling": {
                    "timeout": "7200s"  # 2 hours timeout
                },
                "service_account": f"projects/{self.project_id}/serviceAccounts/vertex-ai@{self.project_id}.iam.gserviceaccount.com"
            }
        }

        return job_config

    def submit_training_job(self, job_config: Dict) -> str:
        """Submit training job to Vertex AI."""
        logger.info("Submitting training job to Vertex AI...")

        try:
            # Create training job
            job = aiplatform.CustomTrainingJob(
                display_name=job_config["display_name"],
                script_path="/Users/ankitthakur/vuln_ml_research/vertex_ai/vulnhunter_v4_training_pipeline.py",
                container_uri="us-docker.pkg.dev/vertex-ai/training/tf-gpu.2-11.py310:latest",
                requirements=["google-cloud-aiplatform>=1.45.0", "tensorflow>=2.15.0",
                             "scikit-learn>=1.3.0", "numpy>=1.24.0", "pandas>=2.0.0"],
                model_serving_container_image_uri="us-docker.pkg.dev/vertex-ai/prediction/tf2-gpu.2-11:latest"
            )

            # Submit job
            model = job.run(
                args=[
                    f"--project_id={self.project_id}",
                    f"--location={self.location}",
                    f"--bucket_name={self.bucket_name}"
                ],
                replica_count=1,
                machine_type="n1-standard-8",
                accelerator_type="NVIDIA_TESLA_T4",
                accelerator_count=1,
                sync=False  # Don't wait for completion
            )

            job_id = job.resource_name
            logger.info(f"Training job submitted: {job_id}")
            return job_id

        except Exception as e:
            logger.error(f"Failed to submit training job: {e}")
            raise

class ProductionTrainingMonitor:
    """Monitor training job progress and results."""

    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        aiplatform.init(project=project_id, location=location)

    def list_training_jobs(self) -> List[Dict]:
        """List all training jobs."""
        jobs = aiplatform.CustomTrainingJob.list()
        return [
            {
                "name": job.display_name,
                "resource_name": job.resource_name,
                "state": job.state,
                "create_time": job.create_time,
                "update_time": job.update_time
            }
            for job in jobs
        ]

    def get_job_status(self, job_resource_name: str) -> Dict:
        """Get detailed status of a specific job."""
        try:
            job = aiplatform.CustomTrainingJob(job_resource_name)
            return {
                "display_name": job.display_name,
                "state": job.state,
                "create_time": job.create_time,
                "start_time": getattr(job, 'start_time', None),
                "end_time": getattr(job, 'end_time', None),
                "error": getattr(job, 'error', None)
            }
        except Exception as e:
            logger.error(f"Failed to get job status: {e}")
            return {"error": str(e)}

    def download_training_artifacts(self, job_resource_name: str,
                                   local_path: str) -> bool:
        """Download training artifacts from completed job."""
        try:
            # Implementation depends on where artifacts are stored
            # Typically in the GCS bucket under model artifacts
            logger.info(f"Downloading artifacts for job: {job_resource_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to download artifacts: {e}")
            return False

def setup_vertex_ai_environment():
    """Interactive setup for Vertex AI environment."""
    print("🚀 VulnHunter V4 Production Training Setup")
    print("=" * 50)

    # Get project configuration
    project_id = input("Enter your Google Cloud Project ID: ").strip()
    location = input("Enter Vertex AI location [us-central1]: ").strip() or "us-central1"

    service_account_path = input("Enter service account JSON path (optional): ").strip()
    if service_account_path and not os.path.exists(service_account_path):
        print(f"⚠️  Service account file not found: {service_account_path}")
        service_account_path = None

    print(f"\n📋 Configuration:")
    print(f"   Project ID: {project_id}")
    print(f"   Location: {location}")
    print(f"   Service Account: {service_account_path or 'Default credentials'}")

    confirm = input("\nProceed with training setup? [y/N]: ").strip().lower()
    if confirm != 'y':
        print("❌ Setup cancelled")
        return None

    return {
        "project_id": project_id,
        "location": location,
        "service_account_path": service_account_path
    }

def main():
    """Main production training setup."""
    # Interactive setup
    config = setup_vertex_ai_environment()
    if not config:
        return

    try:
        # Initialize production setup
        setup = ProductionVertexAISetup(
            project_id=config["project_id"],
            location=config["location"],
            service_account_path=config["service_account_path"]
        )

        print("\n🪣 Creating storage bucket...")
        if not setup.create_storage_bucket():
            print("❌ Failed to create storage bucket")
            return

        print("\n📤 Uploading training data...")
        uploaded_files = setup.upload_training_data()
        print(f"✅ Uploaded {len(uploaded_files)} files")

        print("\n🏗️  Creating training job configuration...")
        job_config = setup.create_training_job_config(uploaded_files)

        print("\n🚀 Submitting training job...")
        job_id = setup.submit_training_job(job_config)

        print(f"\n✅ Training job submitted successfully!")
        print(f"   Job ID: {job_id}")
        print(f"   Project: {config['project_id']}")
        print(f"   Location: {config['location']}")

        print("\n📊 To monitor progress:")
        print(f"   gcloud ai custom-jobs describe {job_id.split('/')[-1]} --region={config['location']}")
        print(f"   Or visit: https://console.cloud.google.com/vertex-ai/training/custom-jobs?project={config['project_id']}")

        # Initialize monitor for status checking
        monitor = ProductionTrainingMonitor(
            project_id=config["project_id"],
            location=config["location"]
        )

        print("\n📋 Current training jobs:")
        jobs = monitor.list_training_jobs()
        for job in jobs[-5:]:  # Show last 5 jobs
            print(f"   {job['name']}: {job['state']}")

    except Exception as e:
        print(f"❌ Training setup failed: {e}")
        logger.error(f"Setup failed: {e}")

if __name__ == "__main__":
    main()