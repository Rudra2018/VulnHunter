#!/usr/bin/env python3
"""
Python-based Production Launcher for VulnHunter V4
Alternative to shell script for launching Vertex AI training
"""

import os
import subprocess
import json
import time
from pathlib import Path
from datetime import datetime

class VertexAIProductionLauncher:
    """Launch VulnHunter V4 training on production Vertex AI."""

    def __init__(self, project_id: str, location: str = "us-central1"):
        """Initialize the launcher."""
        self.project_id = project_id
        self.location = location
        self.bucket_name = f"{project_id}-vulnhunter-training"

        print(f"🚀 VulnHunter V4 Production Training Launcher")
        print(f"=" * 50)
        print(f"Project ID: {self.project_id}")
        print(f"Location: {self.location}")
        print(f"Bucket: {self.bucket_name}")
        print()

    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met."""
        print("🔍 Checking prerequisites...")

        # Check if gcloud is installed
        try:
            result = subprocess.run(["gcloud", "version"], capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ gcloud CLI found")
            else:
                print("❌ gcloud CLI not working properly")
                return False
        except FileNotFoundError:
            print("❌ gcloud CLI not found. Please install Google Cloud SDK")
            print("   Visit: https://cloud.google.com/sdk/docs/install")
            return False

        # Check authentication
        try:
            result = subprocess.run(["gcloud", "auth", "list"], capture_output=True, text=True)
            if "ACTIVE" in result.stdout:
                print("✅ gcloud authentication found")
            else:
                print("⚠️  No active gcloud authentication found")
                print("   Run: gcloud auth login")
                return False
        except Exception as e:
            print(f"❌ Authentication check failed: {e}")
            return False

        # Check training data
        training_data_path = Path("/Users/ankitthakur/vuln_ml_research/data/training")
        if training_data_path.exists():
            print("✅ Training data found")
        else:
            print("❌ Training data not found")
            return False

        return True

    def setup_project(self) -> bool:
        """Set up the Google Cloud project."""
        print("🔧 Setting up project...")

        try:
            # Set project
            subprocess.run(["gcloud", "config", "set", "project", self.project_id], check=True)
            subprocess.run(["gcloud", "config", "set", "compute/region", self.location], check=True)
            print(f"✅ Project set to {self.project_id}")

            # Enable APIs
            print("🔌 Enabling required APIs...")
            apis = [
                "aiplatform.googleapis.com",
                "storage.googleapis.com",
                "compute.googleapis.com"
            ]

            for api in apis:
                subprocess.run(["gcloud", "services", "enable", api], check=True)
                print(f"✅ Enabled {api}")

            return True

        except subprocess.CalledProcessError as e:
            print(f"❌ Project setup failed: {e}")
            return False

    def create_bucket(self) -> bool:
        """Create storage bucket for training data."""
        print("🪣 Creating storage bucket...")

        try:
            # Try to create bucket
            result = subprocess.run([
                "gsutil", "mb", "-l", self.location, f"gs://{self.bucket_name}"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✅ Created bucket: {self.bucket_name}")
            else:
                if "already exists" in result.stderr:
                    print(f"✅ Bucket already exists: {self.bucket_name}")
                else:
                    print(f"❌ Failed to create bucket: {result.stderr}")
                    return False

            return True

        except Exception as e:
            print(f"❌ Bucket creation failed: {e}")
            return False

    def upload_training_data(self) -> bool:
        """Upload training data to GCS."""
        print("📤 Uploading training data...")

        try:
            # Upload training data directory
            training_data_path = "/Users/ankitthakur/vuln_ml_research/data/training"
            result = subprocess.run([
                "gsutil", "-m", "cp", "-r", f"{training_data_path}/*",
                f"gs://{self.bucket_name}/training_data/"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print("✅ Training data uploaded")
            else:
                print(f"❌ Failed to upload training data: {result.stderr}")
                return False

            # Upload training scripts
            script_files = [
                "/Users/ankitthakur/vuln_ml_research/vertex_ai/production_vulnhunter_trainer.py",
                "/Users/ankitthakur/vuln_ml_research/vertex_ai/production_requirements.txt"
            ]

            for script_file in script_files:
                if Path(script_file).exists():
                    result = subprocess.run([
                        "gsutil", "cp", script_file,
                        f"gs://{self.bucket_name}/training_code/"
                    ], capture_output=True, text=True)

                    if result.returncode == 0:
                        print(f"✅ Uploaded {Path(script_file).name}")
                    else:
                        print(f"❌ Failed to upload {script_file}: {result.stderr}")

            return True

        except Exception as e:
            print(f"❌ Upload failed: {e}")
            return False

    def create_training_job(self) -> str:
        """Create and submit training job."""
        print("🚀 Creating training job...")

        job_name = f"vulnhunter-v4-production-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # Training data paths
        training_data_paths = [
            f"gs://{self.bucket_name}/training_data/comprehensive_vulnhunter_v4_training_dataset.json",
            f"gs://{self.bucket_name}/training_data/synthetic/synthetic_training_dataset.json",
            f"gs://{self.bucket_name}/training_data/false_positive_training_20251013_140908.json",
            f"gs://{self.bucket_name}/training_data/ollama_validation_training_20250114_180000.json",
            f"gs://{self.bucket_name}/training_data/gemini_cli_validation_training_20250114_183000.json"
        ]

        # Create job configuration
        job_config = {
            "displayName": job_name,
            "jobSpec": {
                "workerPoolSpecs": [
                    {
                        "machineSpec": {
                            "machineType": "n1-standard-8",
                            "acceleratorType": "NVIDIA_TESLA_T4",
                            "acceleratorCount": 1
                        },
                        "replicaCount": 1,
                        "pythonPackageSpec": {
                            "executorImageUri": "us-docker.pkg.dev/vertex-ai/training/tf-gpu.2-11.py310:latest",
                            "packageUris": [f"gs://{self.bucket_name}/training_code/production_requirements.txt"],
                            "pythonModule": "production_vulnhunter_trainer",
                            "args": [
                                f"--project_id={self.project_id}",
                                f"--location={self.location}",
                                f"--bucket_name={self.bucket_name}",
                                f"--training_data_paths={','.join(training_data_paths)}"
                            ]
                        }
                    }
                ],
                "scheduling": {
                    "timeout": "7200s"  # 2 hours
                }
            }
        }

        # Save job config to temporary file
        config_file = "/tmp/training_job.json"
        with open(config_file, 'w') as f:
            json.dump(job_config, f, indent=2)

        try:
            # Submit job using gcloud
            result = subprocess.run([
                "gcloud", "ai", "custom-jobs", "create",
                f"--region={self.location}",
                f"--config={config_file}"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✅ Training job created: {job_name}")
                return job_name
            else:
                print(f"❌ Failed to create training job: {result.stderr}")
                return ""

        except Exception as e:
            print(f"❌ Job creation failed: {e}")
            return ""

    def monitor_job(self, job_name: str):
        """Monitor training job progress."""
        print("📊 Monitoring training job...")

        try:
            # List recent jobs
            result = subprocess.run([
                "gcloud", "ai", "custom-jobs", "list",
                f"--region={self.location}",
                "--limit=5"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print("Recent training jobs:")
                print(result.stdout)
            else:
                print(f"❌ Failed to list jobs: {result.stderr}")

        except Exception as e:
            print(f"❌ Monitoring failed: {e}")

    def launch_production_training(self) -> bool:
        """Launch complete production training pipeline."""
        print("🎯 Launching VulnHunter V4 Production Training")
        print("=" * 50)

        # Check prerequisites
        if not self.check_prerequisites():
            return False

        # Setup project
        if not self.setup_project():
            return False

        # Create bucket
        if not self.create_bucket():
            return False

        # Upload data
        if not self.upload_training_data():
            return False

        # Create and submit job
        job_name = self.create_training_job()
        if not job_name:
            return False

        # Monitor job
        self.monitor_job(job_name)

        print("\n" + "=" * 50)
        print("🎉 PRODUCTION TRAINING LAUNCHED SUCCESSFULLY!")
        print("=" * 50)
        print(f"Job Name: {job_name}")
        print(f"Project: {self.project_id}")
        print(f"Region: {self.location}")
        print()
        print("📊 To monitor progress:")
        print(f"   gcloud ai custom-jobs list --region={self.location}")
        print(f"   Or visit: https://console.cloud.google.com/vertex-ai/training/custom-jobs?project={self.project_id}")
        print()
        print("📁 Training data location:")
        print(f"   gs://{self.bucket_name}/training_data/")
        print()
        print("🔍 Model artifacts will be saved to:")
        print(f"   gs://{self.bucket_name}/models/")

        return True

def main():
    """Main function with project configuration."""
    print("Please configure your Google Cloud project details:")
    print()

    # You can hardcode your project ID here or make it interactive
    project_id = input("Enter your Google Cloud Project ID: ").strip()

    if not project_id:
        print("❌ Project ID is required")
        return

    location = input("Enter Vertex AI location [us-central1]: ").strip() or "us-central1"

    # Launch training
    launcher = VertexAIProductionLauncher(project_id, location)
    success = launcher.launch_production_training()

    if success:
        print("\n✅ Setup completed successfully!")
    else:
        print("\n❌ Setup failed. Please check the errors above.")

if __name__ == "__main__":
    main()