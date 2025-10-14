#!/usr/bin/env python3
"""
Auto-launch VulnHunter V4 training with detected project configuration
"""

import os
import subprocess
import json
import time
from pathlib import Path
from datetime import datetime

def run_command(cmd, description=""):
    """Run command and return result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description}: Success")
            return True, result.stdout
        else:
            print(f"❌ {description}: Failed")
            print(f"Error: {result.stderr}")
            return False, result.stderr
    except Exception as e:
        print(f"❌ {description}: Exception - {e}")
        return False, str(e)

def main():
    print("🚀 VulnHunter V4 Auto-Launch Production Training")
    print("=" * 60)

    # Use detected project
    project_id = "quantumsentinel-20250927"
    location = "us-central1"
    bucket_name = f"{project_id}-vulnhunter-training"

    print(f"📋 Configuration:")
    print(f"   Project ID: {project_id}")
    print(f"   Location: {location}")
    print(f"   Bucket: {bucket_name}")
    print()

    # Step 1: Check authentication
    print("🔍 Step 1: Checking authentication...")
    success, output = run_command("gcloud auth list --filter=status:ACTIVE", "Check authentication")
    if not success:
        print("⚠️  Please run: gcloud auth login")
        return

    # Step 2: Set project
    print("🔧 Step 2: Setting project configuration...")
    run_command(f"gcloud config set project {project_id}", "Set project")
    run_command(f"gcloud config set compute/region {location}", "Set region")

    # Step 3: Enable APIs
    print("🔌 Step 3: Enabling required APIs...")
    apis = [
        "aiplatform.googleapis.com",
        "storage.googleapis.com",
        "compute.googleapis.com"
    ]

    for api in apis:
        run_command(f"gcloud services enable {api}", f"Enable {api}")

    # Step 4: Create bucket
    print("🪣 Step 4: Creating storage bucket...")
    success, output = run_command(f"gsutil mb -l {location} gs://{bucket_name}", "Create bucket")
    if not success and "already exists" not in output:
        print(f"❌ Failed to create bucket: {output}")
        return
    elif "already exists" in output:
        print("✅ Bucket already exists")

    # Step 5: Upload training data
    print("📤 Step 5: Uploading training data...")
    training_data_path = "/Users/ankitthakur/vuln_ml_research/data/training"

    if not Path(training_data_path).exists():
        print(f"❌ Training data not found at {training_data_path}")
        return

    # Upload training data
    run_command(f"gsutil -m cp -r {training_data_path}/* gs://{bucket_name}/training_data/",
                "Upload training data")

    # Upload training scripts
    script_files = [
        "/Users/ankitthakur/vuln_ml_research/vertex_ai/production_vulnhunter_trainer.py",
        "/Users/ankitthakur/vuln_ml_research/vertex_ai/production_requirements.txt"
    ]

    for script_file in script_files:
        if Path(script_file).exists():
            run_command(f"gsutil cp {script_file} gs://{bucket_name}/training_code/",
                       f"Upload {Path(script_file).name}")

    # Step 6: Create and submit training job
    print("🚀 Step 6: Creating training job...")

    job_name = f"vulnhunter-v4-production-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # Training data paths
    training_data_paths = [
        f"gs://{bucket_name}/training_data/comprehensive_vulnhunter_v4_training_dataset.json",
        f"gs://{bucket_name}/training_data/synthetic/synthetic_training_dataset.json",
        f"gs://{bucket_name}/training_data/false_positive_training_20251013_140908.json",
        f"gs://{bucket_name}/training_data/ollama_validation_training_20250114_180000.json",
        f"gs://{bucket_name}/training_data/gemini_cli_validation_training_20250114_183000.json"
    ]

    # Create job configuration
    job_config = {
        "displayName": job_name,
        "jobSpec": {
            "workerPoolSpecs": [{
                "machineSpec": {
                    "machineType": "n1-standard-8",
                    "acceleratorType": "NVIDIA_TESLA_T4",
                    "acceleratorCount": 1
                },
                "replicaCount": 1,
                "pythonPackageSpec": {
                    "executorImageUri": "us-docker.pkg.dev/vertex-ai/training/tf-gpu.2-11.py310:latest",
                    "packageUris": [f"gs://{bucket_name}/training_code/production_requirements.txt"],
                    "pythonModule": "production_vulnhunter_trainer",
                    "args": [
                        f"--project_id={project_id}",
                        f"--location={location}",
                        f"--bucket_name={bucket_name}",
                        f"--training_data_paths={','.join(training_data_paths)}"
                    ]
                }
            }],
            "scheduling": {
                "timeout": "7200s"
            }
        }
    }

    # Save job config
    config_file = "/tmp/vulnhunter_training_job.json"
    with open(config_file, 'w') as f:
        json.dump(job_config, f, indent=2)

    print(f"📋 Job configuration saved to {config_file}")

    # Submit job
    print("🎯 Submitting training job to Vertex AI...")
    success, output = run_command(
        f"gcloud ai custom-jobs create --region={location} --config={config_file}",
        "Submit training job"
    )

    if success:
        print(f"✅ Training job submitted: {job_name}")

        # Get job status
        print("\n📊 Getting current training jobs...")
        run_command(f"gcloud ai custom-jobs list --region={location} --limit=3", "List jobs")

        print("\n" + "=" * 60)
        print("🎉 VULNHUNTER V4 PRODUCTION TRAINING LAUNCHED!")
        print("=" * 60)
        print(f"Job Name: {job_name}")
        print(f"Project: {project_id}")
        print(f"Region: {location}")
        print(f"Bucket: gs://{bucket_name}")
        print()
        print("📊 Monitor training:")
        print(f"   Console: https://console.cloud.google.com/vertex-ai/training/custom-jobs?project={project_id}")
        print(f"   CLI: gcloud ai custom-jobs list --region={location}")
        print()
        print("🔍 Training details:")
        print("   • Dataset: 1,812 comprehensive examples")
        print("   • GPU: NVIDIA Tesla T4")
        print("   • Machine: n1-standard-8 (8 vCPUs, 30GB RAM)")
        print("   • Duration: ~1-2 hours")
        print("   • Cost: ~$3-5")
        print()
        print("📁 Model artifacts will be saved to:")
        print(f"   gs://{bucket_name}/models/vulnhunter_v4_production_*/")

    else:
        print("❌ Failed to submit training job")
        print(f"Error: {output}")

if __name__ == "__main__":
    main()