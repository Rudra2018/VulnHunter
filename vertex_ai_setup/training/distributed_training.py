"""
VulnHunter AI - Distributed Training Setup for Vertex AI
Handles multi-GPU and multi-node distributed training with optimal performance
"""

import os
import sys
import json
import subprocess
import argparse
from typing import Dict, List, Any
import logging
from pathlib import Path

import torch
import torch.distributed as dist
import torch.multiprocessing as mp
from torch.nn.parallel import DistributedDataParallel as DDP

from google.cloud import aiplatform
from google.cloud import storage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DistributedTrainingManager:
    """Manages distributed training configuration and execution"""

    def __init__(self, project_id: str, region: str, bucket_name: str):
        self.project_id = project_id
        self.region = region
        self.bucket_name = bucket_name

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=region)

    def create_custom_training_job(self,
                                  display_name: str,
                                  training_script_path: str,
                                  train_data_path: str,
                                  job_dir: str,
                                  args: Dict[str, Any],
                                  machine_type: str = "n1-standard-8",
                                  accelerator_type: str = "NVIDIA_TESLA_T4",
                                  accelerator_count: int = 2,
                                  replica_count: int = 1,
                                  python_package_gcs_uri: str = None,
                                  container_uri: str = "us-docker.pkg.dev/vertex-ai/training/pytorch-gpu.1-13.py310:latest"):
        """Create a custom training job with distributed training support"""

        # Prepare worker pool specs for distributed training
        if replica_count > 1 or accelerator_count > 1:
            # Multi-node or multi-GPU setup
            worker_pool_specs = [
                {
                    "machine_spec": {
                        "machine_type": machine_type,
                        "accelerator_type": accelerator_type,
                        "accelerator_count": accelerator_count,
                    },
                    "replica_count": replica_count,
                    "container_spec": {
                        "image_uri": container_uri,
                        "command": ["python", "-m", "torch.distributed.launch"],
                        "args": [
                            f"--nproc_per_node={accelerator_count}",
                            f"--nnodes={replica_count}",
                            "--node_rank=0",
                            "--master_addr=localhost",
                            "--master_port=12355",
                            training_script_path,
                            f"--train-data-path={train_data_path}",
                            f"--job-dir={job_dir}",
                            "--distributed",
                            f"--world-size={accelerator_count * replica_count}",
                        ] + [f"--{k}={v}" for k, v in args.items()]
                    },
                    "python_package_spec": {
                        "executor_image_uri": container_uri,
                        "package_uris": [python_package_gcs_uri] if python_package_gcs_uri else [],
                        "python_module": "train",
                        "args": [
                            f"--train-data-path={train_data_path}",
                            f"--job-dir={job_dir}",
                            "--distributed",
                            f"--world-size={accelerator_count * replica_count}",
                        ] + [f"--{k}={v}" for k, v in args.items()]
                    } if python_package_gcs_uri else None
                }
            ]
        else:
            # Single-node, single-GPU setup
            worker_pool_specs = [
                {
                    "machine_spec": {
                        "machine_type": machine_type,
                        "accelerator_type": accelerator_type,
                        "accelerator_count": accelerator_count,
                    },
                    "replica_count": 1,
                    "container_spec": {
                        "image_uri": container_uri,
                        "command": ["python"],
                        "args": [
                            training_script_path,
                            f"--train-data-path={train_data_path}",
                            f"--job-dir={job_dir}",
                        ] + [f"--{k}={v}" for k, v in args.items()]
                    }
                }
            ]

        # Create the training job
        job = aiplatform.CustomJob(
            display_name=display_name,
            worker_pool_specs=worker_pool_specs,
            base_output_dir=job_dir,
        )

        logger.info(f"Created distributed training job: {display_name}")
        logger.info(f"Worker pools: {len(worker_pool_specs)}")
        logger.info(f"Total GPUs: {accelerator_count * replica_count}")

        return job

    def submit_training_job(self, job, sync: bool = False, timeout: int = None):
        """Submit the training job to Vertex AI"""
        logger.info("Submitting training job to Vertex AI...")

        job.run(
            sync=sync,
            timeout=timeout,
            restart_job_on_worker_restart=True,
            enable_web_access=True,
            tensorboard=f"projects/{self.project_id}/locations/{self.region}/tensorboards/vulnhunter-tensorboard"
        )

        logger.info(f"Training job submitted: {job.resource_name}")
        return job

    def create_distributed_training_package(self,
                                          src_dir: str,
                                          package_name: str = "vulnhunter_training",
                                          output_dir: str = None):
        """Create a Python package for distributed training"""

        if output_dir is None:
            output_dir = f"gs://{self.bucket_name}/training_packages"

        package_dir = Path(src_dir) / "package"
        package_dir.mkdir(exist_ok=True)

        # Create setup.py
        setup_py_content = f'''
from setuptools import setup, find_packages

setup(
    name="{package_name}",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "torch>=1.13.0",
        "transformers>=4.21.0",
        "datasets>=2.4.0",
        "accelerate>=0.12.0",
        "wandb>=0.13.0",
        "google-cloud-aiplatform>=1.17.0",
        "google-cloud-storage>=2.5.0",
        "scikit-learn>=1.1.0",
        "matplotlib>=3.5.0",
        "seaborn>=0.11.0",
        "pandas>=1.4.0",
        "numpy>=1.21.0",
        "networkx>=2.8",
        "ast-scope>=0.4.0",
    ],
    python_requires=">=3.8",
)
'''
        with open(package_dir / "setup.py", "w") as f:
            f.write(setup_py_content)

        # Copy training source code
        import shutil
        src_package_dir = package_dir / package_name
        src_package_dir.mkdir(exist_ok=True)

        # Copy main training script
        shutil.copy(Path(src_dir) / "train.py", src_package_dir / "train.py")

        # Copy strategic FP reduction modules
        strategic_fp_dir = Path(src_dir).parent.parent / "strategic_fp_reduction"
        if strategic_fp_dir.exists():
            shutil.copytree(strategic_fp_dir, src_package_dir / "strategic_fp_reduction", dirs_exist_ok=True)

        # Create __init__.py files
        (src_package_dir / "__init__.py").touch()

        # Create trainer module
        trainer_content = '''
"""VulnHunter AI Distributed Training Entry Point"""
from .train import main

if __name__ == "__main__":
    main()
'''
        with open(src_package_dir / "__main__.py", "w") as f:
            f.write(trainer_content)

        # Build the package
        subprocess.run([
            sys.executable, "setup.py", "sdist", "bdist_wheel"
        ], cwd=package_dir, check=True)

        # Upload to GCS
        storage_client = storage.Client()
        bucket = storage_client.bucket(self.bucket_name.replace("gs://", "").split("/")[0])

        dist_dir = package_dir / "dist"
        for file_path in dist_dir.glob("*.tar.gz"):
            blob_path = f"training_packages/{file_path.name}"
            blob = bucket.blob(blob_path)
            blob.upload_from_filename(str(file_path))

            package_uri = f"gs://{self.bucket_name}/training_packages/{file_path.name}"
            logger.info(f"Training package uploaded: {package_uri}")
            return package_uri

        return None

def setup_distributed_environment():
    """Setup environment variables for distributed training"""

    # Get environment variables from Vertex AI
    world_size = int(os.environ.get('WORLD_SIZE', '1'))
    rank = int(os.environ.get('RANK', '0'))
    local_rank = int(os.environ.get('LOCAL_RANK', '0'))

    # Set up distributed training
    if world_size > 1:
        # Initialize the process group
        dist.init_process_group(
            backend='nccl',
            init_method='env://',
            world_size=world_size,
            rank=rank
        )

        # Set device
        torch.cuda.set_device(local_rank)
        device = torch.device(f'cuda:{local_rank}')

        logger.info(f"Distributed training initialized: rank {rank}/{world_size}, local_rank {local_rank}")
    else:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Single process training on {device}")

    return device, rank, world_size

def create_distributed_training_script():
    """Create a wrapper script for distributed training"""

    script_content = '''#!/bin/bash

# VulnHunter AI Distributed Training Script
set -e

echo "🚀 Starting VulnHunter AI Distributed Training"

# Get environment variables
export PYTHONPATH="/app:$PYTHONPATH"
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-"0,1,2,3"}

# Distributed training parameters
export WORLD_SIZE=${WORLD_SIZE:-1}
export RANK=${RANK:-0}
export LOCAL_RANK=${LOCAL_RANK:-0}
export MASTER_ADDR=${MASTER_ADDR:-"localhost"}
export MASTER_PORT=${MASTER_PORT:-"12355"}

# Training parameters
TRAIN_DATA_PATH=${1:-"/app/data/train.json"}
VAL_DATA_PATH=${2:-"/app/data/val.json"}
JOB_DIR=${3:-"/app/output"}
MODEL_TYPE=${4:-"hybrid_architecture"}

echo "Training Configuration:"
echo "  World Size: $WORLD_SIZE"
echo "  Rank: $RANK"
echo "  Local Rank: $LOCAL_RANK"
echo "  Master Addr: $MASTER_ADDR"
echo "  Master Port: $MASTER_PORT"
echo "  Train Data: $TRAIN_DATA_PATH"
echo "  Job Dir: $JOB_DIR"
echo "  Model Type: $MODEL_TYPE"

# Run distributed training
if [ "$WORLD_SIZE" -gt 1 ]; then
    echo "🔄 Running distributed training with $WORLD_SIZE processes"

    python -m torch.distributed.launch \\
        --nproc_per_node=$WORLD_SIZE \\
        --nnodes=1 \\
        --node_rank=0 \\
        --master_addr=$MASTER_ADDR \\
        --master_port=$MASTER_PORT \\
        /app/train.py \\
        --train-data-path="$TRAIN_DATA_PATH" \\
        --val-data-path="$VAL_DATA_PATH" \\
        --job-dir="$JOB_DIR" \\
        --model-type="$MODEL_TYPE" \\
        --distributed \\
        --world-size=$WORLD_SIZE \\
        --batch-size=16 \\
        --num-epochs=10 \\
        --learning-rate=2e-5 \\
        --use-multimodal-features \\
        --use-scheduler \\
        --early-stopping-patience=3 \\
        --log-steps=50 \\
        --save-steps=2
else
    echo "🔄 Running single process training"

    python /app/train.py \\
        --train-data-path="$TRAIN_DATA_PATH" \\
        --val-data-path="$VAL_DATA_PATH" \\
        --job-dir="$JOB_DIR" \\
        --model-type="$MODEL_TYPE" \\
        --batch-size=32 \\
        --num-epochs=10 \\
        --learning-rate=2e-5 \\
        --use-multimodal-features \\
        --use-scheduler \\
        --early-stopping-patience=3 \\
        --log-steps=50 \\
        --save-steps=2
fi

echo "✅ Training completed successfully!"
'''

    return script_content

def optimize_distributed_performance():
    """Optimize performance for distributed training"""

    optimization_config = {
        "data_loading": {
            "num_workers": 4,
            "pin_memory": True,
            "persistent_workers": True,
            "prefetch_factor": 2
        },
        "training": {
            "gradient_accumulation_steps": 1,
            "mixed_precision": True,
            "compile_model": True,
            "find_unused_parameters": False
        },
        "communication": {
            "backend": "nccl",
            "bucket_cap_mb": 25,
            "gradient_compression": False,
            "allreduce_post_accumulation": True
        },
        "memory": {
            "activation_checkpointing": True,
            "cpu_offload": False,
            "zero_optimization": {
                "stage": 2,
                "overlap_comm": True,
                "contiguous_gradients": True,
                "reduce_bucket_size": 5e8,
                "allgather_bucket_size": 5e8
            }
        }
    }

    return optimization_config

# Example usage and testing
if __name__ == "__main__":
    # Configuration
    PROJECT_ID = os.getenv("PROJECT_ID", "vulnhunter-ai-project")
    REGION = os.getenv("REGION", "us-central1")
    BUCKET_NAME = os.getenv("BUCKET_NAME", f"vulnhunter-ai-training-{PROJECT_ID}")

    # Initialize distributed training manager
    training_manager = DistributedTrainingManager(PROJECT_ID, REGION, BUCKET_NAME)

    print("🔧 VulnHunter AI Distributed Training Setup")
    print("=" * 50)

    # Example: Create distributed training job
    training_args = {
        "model-type": "hybrid_architecture",
        "batch-size": 16,
        "num-epochs": 10,
        "learning-rate": 2e-5,
        "use-multimodal-features": True,
        "use-scheduler": True,
        "early-stopping-patience": 3
    }

    job = training_manager.create_custom_training_job(
        display_name="vulnhunter-distributed-training",
        training_script_path="/app/train.py",
        train_data_path=f"gs://{BUCKET_NAME}/data/train.json",
        job_dir=f"gs://{BUCKET_NAME}/experiments/distributed-training",
        args=training_args,
        machine_type="n1-standard-16",
        accelerator_type="NVIDIA_TESLA_T4",
        accelerator_count=4,
        replica_count=2  # 2 nodes x 4 GPUs = 8 total GPUs
    )

    print(f"✅ Distributed training job created: {job.display_name}")
    print(f"   Total GPUs: 8 (2 nodes x 4 GPUs)")
    print(f"   Machine Type: n1-standard-16")
    print(f"   Accelerator: NVIDIA_TESLA_T4")

    # Create training package
    package_uri = training_manager.create_distributed_training_package(
        src_dir="./training/src",
        package_name="vulnhunter_training"
    )
    print(f"   Training Package: {package_uri}")

    # Performance optimization recommendations
    perf_config = optimize_distributed_performance()
    print(f"\n🚀 Performance Optimization Config:")
    print(f"   Mixed Precision: {perf_config['training']['mixed_precision']}")
    print(f"   Gradient Accumulation: {perf_config['training']['gradient_accumulation_steps']}")
    print(f"   Communication Backend: {perf_config['communication']['backend']}")
    print(f"   ZeRO Stage: {perf_config['memory']['zero_optimization']['stage']}")

    print(f"\n📊 Expected Performance:")
    print(f"   Training Speedup: ~6-8x (compared to single GPU)")
    print(f"   Memory per GPU: ~4-6GB (with optimization)")
    print(f"   Estimated Training Time: 2-4 hours (depending on dataset size)")

    print(f"\n📝 Next Steps:")
    print(f"   1. Prepare training data and upload to GCS")
    print(f"   2. Submit job: job.run(sync=False)")
    print(f"   3. Monitor progress in Vertex AI console")
    print(f"   4. Check TensorBoard for training metrics")