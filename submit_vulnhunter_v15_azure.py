#!/usr/bin/env python3
"""
VulnHunter V15 Azure ML Job Submission Script
Submit and monitor the massive-scale training job on Azure ML
"""

import os
import json
import time
from datetime import datetime
from azure.ai.ml import MLClient, command, Input, Output
from azure.ai.ml.entities import Environment, BuildContext, Workspace, ComputeInstance, AmlCompute
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_azure_workspace():
    """Create Azure ML workspace"""
    print("🚀 Creating Azure ML Workspace for VulnHunter V15")
    print("=" * 60)

    # Azure configuration
    subscription_id = "your-subscription-id"  # Replace with your subscription ID
    resource_group = "vulnhunter-v15-production"
    workspace_name = "vulnhunter-v15-massive-scale"
    location = "eastus2"

    try:
        # Initialize credential
        credential = DefaultAzureCredential()

        # Create ML client
        ml_client = MLClient(
            credential=credential,
            subscription_id=subscription_id,
            resource_group_name=resource_group,
            workspace_name=workspace_name
        )

        # Try to get existing workspace
        try:
            workspace = ml_client.workspaces.get(workspace_name)
            logger.info(f"✅ Found existing workspace: {workspace_name}")
        except ResourceNotFoundError:
            # Create new workspace
            logger.info(f"🏗️ Creating new workspace: {workspace_name}")

            workspace = Workspace(
                name=workspace_name,
                location=location,
                display_name="VulnHunter V15 Massive Scale Training",
                description="Revolutionary enterprise-grade multi-platform vulnerability detection",
                tags={
                    "project": "VulnHunter V15",
                    "version": "15.0.0",
                    "type": "massive-scale-training"
                }
            )

            workspace = ml_client.workspaces.begin_create(workspace).result()
            logger.info(f"✅ Created workspace: {workspace_name}")

        return ml_client, workspace

    except Exception as e:
        logger.error(f"❌ Failed to create workspace: {str(e)}")
        raise

def create_compute_clusters(ml_client):
    """Create high-performance compute clusters"""
    logger.info("🏗️ Creating compute clusters for VulnHunter V15...")

    compute_configs = [
        {
            "name": "vulnhunter-v15-cpu-maximum",
            "type": "amlcompute",
            "size": "Standard_F72s_v2",  # 72 vCPUs, 144 GB RAM
            "min_instances": 0,
            "max_instances": 50,
            "description": "Maximum CPU cluster for VulnHunter V15"
        },
        {
            "name": "vulnhunter-v15-gpu-massive",
            "type": "amlcompute",
            "size": "Standard_ND96amsr_A100_v4",  # 8x A100 GPUs, 96 cores
            "min_instances": 0,
            "max_instances": 10,
            "description": "Massive GPU cluster for accelerated training"
        }
    ]

    created_clusters = {}

    for config in compute_configs:
        try:
            # Check if compute already exists
            compute = ml_client.compute.get(config["name"])
            logger.info(f"✅ Found existing compute: {config['name']}")
        except ResourceNotFoundError:
            # Create new compute
            logger.info(f"🔧 Creating compute cluster: {config['name']}")

            compute = AmlCompute(
                name=config["name"],
                type=config["type"],
                size=config["size"],
                min_instances=config["min_instances"],
                max_instances=config["max_instances"],
                description=config["description"],
                tier="Dedicated"
            )

            compute = ml_client.compute.begin_create_or_update(compute).result()
            logger.info(f"✅ Created compute cluster: {config['name']}")

        created_clusters[config["name"]] = compute

    return created_clusters

def create_environment(ml_client):
    """Create the training environment"""
    logger.info("🔬 Creating VulnHunter V15 training environment...")

    env_name = "vulnhunter-v15-comprehensive"

    try:
        # Check if environment exists
        environment = ml_client.environments.get(env_name, version="1")
        logger.info(f"✅ Found existing environment: {env_name}")
    except ResourceNotFoundError:
        # Create new environment
        logger.info(f"🏗️ Creating environment: {env_name}")

        environment = Environment(
            name=env_name,
            description="Comprehensive environment for VulnHunter V15 massive-scale training",
            conda_file="vulnhunter_v15_conda.yml",
            image="mcr.microsoft.com/azureml/pytorch-1.12-ubuntu20.04-py38-cuda11.6-gpu",
            version="1"
        )

        environment = ml_client.environments.create_or_update(environment)
        logger.info(f"✅ Created environment: {env_name}")

    return environment

def submit_training_job(ml_client):
    """Submit the massive-scale training job"""
    logger.info("🚀 Submitting VulnHunter V15 massive-scale training job...")

    # Job configuration
    job_name = f"vulnhunter-v15-training-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # Create the command job
    job = command(
        display_name="VulnHunter V15 Massive Scale Training",
        description="Revolutionary enterprise-grade multi-platform vulnerability detection training",

        # Code and environment
        code="./",
        environment="vulnhunter-v15-comprehensive:1",

        # Compute configuration
        compute="vulnhunter-v15-cpu-maximum",
        instance_count=4,

        # Training command
        command="""
        python vulnhunter_v15_massive_training.py \
            --model_name "VulnHunter-V15-Enterprise" \
            --model_version "15.0.0" \
            --max_epochs 500 \
            --batch_size_gpu 64 \
            --batch_size_cpu 128 \
            --learning_rate 1e-4 \
            --max_cpu_cores 128 \
            --memory_limit_gb 512 \
            --distributed true \
            --mixed_precision true \
            --mathematical_techniques true \
            --enterprise_integration true \
            --enable_monitoring true \
            --save_checkpoints true \
            --early_stopping_patience 50 \
            --validation_interval 500
        """,

        # Inputs and outputs
        inputs={
            "training_data": Input(
                type="uri_folder",
                path="./vulnhunter_v15_massive_data",
                mode="ro_mount"
            )
        },
        outputs={
            "model_output": Output(
                type="uri_folder",
                path="azureml://datastores/workspaceblobstore/paths/models/vulnhunter-v15/"
            ),
            "training_logs": Output(
                type="uri_folder",
                path="azureml://datastores/workspaceblobstore/paths/logs/vulnhunter-v15/"
            ),
            "checkpoints": Output(
                type="uri_folder",
                path="azureml://datastores/workspaceblobstore/paths/checkpoints/vulnhunter-v15/"
            )
        },

        # Environment variables
        environment_variables={
            "PYTORCH_CUDA_ALLOC_CONF": "max_split_size_mb:512",
            "OMP_NUM_THREADS": "128",
            "MKL_NUM_THREADS": "128",
            "WANDB_PROJECT": "vulnhunter-v15-enterprise",
            "AZURE_ML_TRAINING": "true"
        },

        # Tags
        tags={
            "model": "VulnHunter-V15",
            "version": "15.0.0",
            "dataset_size": "300TB+",
            "training_type": "massive-scale",
            "mathematical_techniques": "8-advanced",
            "platforms": "multi-platform"
        }
    )

    # Submit the job
    submitted_job = ml_client.jobs.create_or_update(job)

    logger.info(f"✅ Job submitted successfully!")
    logger.info(f"   Job Name: {submitted_job.name}")
    logger.info(f"   Job ID: {submitted_job.id}")
    logger.info(f"   Status: {submitted_job.status}")
    logger.info(f"   Studio URL: {submitted_job.studio_url}")

    return submitted_job

def monitor_training_job(ml_client, job):
    """Monitor the training job progress"""
    logger.info("👀 Monitoring training job progress...")

    job_name = job.name

    # Monitor job status
    while True:
        try:
            # Get latest job status
            current_job = ml_client.jobs.get(job_name)
            status = current_job.status

            logger.info(f"📊 Job Status: {status}")

            # Check if job is completed
            if status in ["Completed", "Failed", "Canceled"]:
                logger.info(f"🏁 Job finished with status: {status}")

                if status == "Completed":
                    logger.info("✅ Training completed successfully!")
                    logger.info(f"📊 View results at: {current_job.studio_url}")

                    # Get job outputs
                    outputs = current_job.outputs
                    if outputs:
                        logger.info("📁 Job outputs:")
                        for output_name, output_path in outputs.items():
                            logger.info(f"   {output_name}: {output_path}")
                else:
                    logger.error(f"❌ Training failed with status: {status}")

                break

            # Wait before next check
            time.sleep(60)  # Check every minute

        except Exception as e:
            logger.error(f"Error monitoring job: {e}")
            time.sleep(60)

def main():
    """Main execution function"""
    print("🚀 VulnHunter V15 - Azure ML Training Submission")
    print("=" * 70)

    try:
        # Step 1: Create Azure ML workspace
        ml_client, workspace = create_azure_workspace()

        # Step 2: Create compute clusters
        compute_clusters = create_compute_clusters(ml_client)

        # Step 3: Create training environment
        environment = create_environment(ml_client)

        # Step 4: Submit training job
        job = submit_training_job(ml_client)

        # Step 5: Monitor job progress
        monitor_training_job(ml_client, job)

        print("\n🎉 VulnHunter V15 Azure ML Setup and Training Complete!")
        print("=" * 70)
        print(f"✅ Workspace: {workspace.name}")
        print(f"✅ Compute clusters: {len(compute_clusters)}")
        print(f"✅ Environment: {environment.name}")
        print(f"✅ Training job: {job.name}")
        print(f"🌐 Monitor at: {job.studio_url}")

        return {
            "workspace": workspace,
            "compute_clusters": compute_clusters,
            "environment": environment,
            "job": job
        }

    except Exception as e:
        logger.error(f"❌ Setup failed: {str(e)}")
        print("\n🛠️ Setup Instructions:")
        print("=" * 30)
        print("1. Install Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
        print("2. Login to Azure: az login")
        print("3. Set subscription: az account set --subscription <subscription-id>")
        print("4. Update subscription_id in this script")
        print("5. Ensure you have proper permissions for Azure ML")
        raise

if __name__ == "__main__":
    main()