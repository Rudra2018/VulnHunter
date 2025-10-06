#!/usr/bin/env python3
"""
Submit VulnHunter training job to Vertex AI
Uses Python SDK for better control and monitoring
"""

import argparse
from google.cloud import aiplatform
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VertexJobSubmitter:
    """Submit and monitor Vertex AI training jobs"""

    def __init__(self, project_id: str, region: str, bucket_name: str):
        self.project_id = project_id
        self.region = region
        self.bucket_name = bucket_name

        # Initialize Vertex AI SDK
        aiplatform.init(
            project=project_id,
            location=region,
            staging_bucket=f"gs://{bucket_name}"
        )

        logger.info(f"Vertex AI initialized")
        logger.info(f"  Project: {project_id}")
        logger.info(f"  Region: {region}")
        logger.info(f"  Bucket: gs://{bucket_name}")

    def submit_training_job(
        self,
        container_uri: str,
        display_name: str = None,
        machine_type: str = "n1-standard-8",
        accelerator_type: str = "NVIDIA_TESLA_T4",
        accelerator_count: int = 1,
        training_args: dict = None,
        use_preemptible: bool = False,
        enable_web_access: bool = True
    ):
        """
        Submit custom container training job

        Args:
            container_uri: GCR container URI (e.g., gcr.io/PROJECT/vulnhunter-trainer)
            display_name: Job display name
            machine_type: Machine type (n1-standard-8, n1-standard-16, etc.)
            accelerator_type: GPU type (NVIDIA_TESLA_T4, NVIDIA_TESLA_V100, etc.)
            accelerator_count: Number of GPUs
            training_args: Dictionary of training arguments
            use_preemptible: Use preemptible VMs (70% cheaper)
            enable_web_access: Enable web access for debugging
        """
        if display_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            display_name = f"vulnhunter-training-{timestamp}"

        if training_args is None:
            training_args = {}

        # Build argument list
        args_list = [
            "--project-id", self.project_id,
            "--bucket-name", self.bucket_name,
            "--data-prefix", training_args.get('data_prefix', 'vulnhunter'),
            "--run-name", training_args.get('run_name', 'run-001'),
            "--hidden-dim", str(training_args.get('hidden_dim', 256)),
            "--num-heads", str(training_args.get('num_heads', 8)),
            "--dropout", str(training_args.get('dropout', 0.3)),
            "--gnn-epochs", str(training_args.get('gnn_epochs', 100)),
            "--codebert-epochs", str(training_args.get('codebert_epochs', 10)),
            "--batch-size", str(training_args.get('batch_size', 32)),
            "--learning-rate", str(training_args.get('learning_rate', 0.001)),
            "--gradient-accumulation", str(training_args.get('gradient_accumulation', 4))
        ]

        logger.info("\n" + "=" * 80)
        logger.info("Submitting Training Job to Vertex AI")
        logger.info("=" * 80)
        logger.info(f"Display name: {display_name}")
        logger.info(f"Container: {container_uri}")
        logger.info(f"Machine: {machine_type}")
        logger.info(f"GPU: {accelerator_count}x {accelerator_type}")
        logger.info(f"Preemptible: {use_preemptible}")
        logger.info(f"\nTraining arguments:")
        for k, v in training_args.items():
            logger.info(f"  {k}: {v}")

        # Create custom training job
        job = aiplatform.CustomContainerTrainingJob(
            display_name=display_name,
            container_uri=container_uri,
        )

        # Submit job
        logger.info("\nSubmitting job...")

        try:
            model = job.run(
                replica_count=1,
                machine_type=machine_type,
                accelerator_type=accelerator_type,
                accelerator_count=accelerator_count,
                args=args_list,
                environment_variables={
                    "TRANSFORMERS_CACHE": "/tmp/cache",
                    "HF_HOME": "/tmp/cache",
                    "PYTHONUNBUFFERED": "1"
                },
                restart_job_on_worker_restart=True if use_preemptible else False,
                enable_web_access=enable_web_access,
                sync=False  # Don't wait for completion
            )

            logger.info("\n" + "=" * 80)
            logger.info("✅ Training Job Submitted Successfully!")
            logger.info("=" * 80)
            logger.info(f"Job name: {job.display_name}")
            logger.info(f"Resource name: {job.resource_name}")
            logger.info(f"\nMonitor job:")
            logger.info(f"  Console: https://console.cloud.google.com/vertex-ai/training/custom-jobs?project={self.project_id}")
            logger.info(f"  CLI: gcloud ai custom-jobs stream-logs {job.resource_name.split('/')[-1]} --region={self.region}")

            return job

        except Exception as e:
            logger.error(f"❌ Failed to submit job: {e}")
            raise

    def list_jobs(self, limit: int = 10):
        """List recent training jobs"""
        logger.info(f"\nListing recent {limit} training jobs:")
        logger.info("=" * 80)

        jobs = aiplatform.CustomJob.list(
            filter=f'display_name:"vulnhunter"',
            order_by='create_time desc'
        )[:limit]

        for job in jobs:
            logger.info(f"\n{job.display_name}")
            logger.info(f"  State: {job.state}")
            logger.info(f"  Created: {job.create_time}")
            if job.end_time:
                duration = (job.end_time - job.create_time).total_seconds() / 3600
                logger.info(f"  Duration: {duration:.2f} hours")

        return jobs

    def get_job_status(self, job_name: str):
        """Get status of specific job"""
        try:
            job = aiplatform.CustomJob(job_name=job_name)

            logger.info(f"\nJob: {job.display_name}")
            logger.info(f"  State: {job.state}")
            logger.info(f"  Created: {job.create_time}")
            logger.info(f"  Updated: {job.update_time}")

            if job.error:
                logger.error(f"  Error: {job.error}")

            return job

        except Exception as e:
            logger.error(f"Failed to get job status: {e}")
            return None


def main():
    parser = argparse.ArgumentParser(description='Submit VulnHunter training to Vertex AI')

    # Required arguments
    parser.add_argument('--project-id', type=str, required=True,
                       help='GCP Project ID')
    parser.add_argument('--region', type=str, default='us-central1',
                       help='GCP region (default: us-central1)')
    parser.add_argument('--bucket-name', type=str, required=True,
                       help='GCS bucket name')
    parser.add_argument('--container-uri', type=str, required=True,
                       help='Container URI (e.g., gcr.io/PROJECT/vulnhunter-trainer:latest)')

    # Job configuration
    parser.add_argument('--job-name', type=str, default=None,
                       help='Custom job name')
    parser.add_argument('--machine-type', type=str, default='n1-standard-8',
                       choices=['n1-standard-4', 'n1-standard-8', 'n1-standard-16', 'n1-highmem-8'],
                       help='Machine type')
    parser.add_argument('--gpu-type', type=str, default='NVIDIA_TESLA_T4',
                       choices=['NVIDIA_TESLA_T4', 'NVIDIA_TESLA_V100', 'NVIDIA_TESLA_P100', 'NVIDIA_TESLA_A100'],
                       help='GPU accelerator type')
    parser.add_argument('--gpu-count', type=int, default=1,
                       help='Number of GPUs')
    parser.add_argument('--preemptible', action='store_true',
                       help='Use preemptible VMs (70%% cheaper, may be interrupted)')

    # Training arguments
    parser.add_argument('--data-prefix', type=str, default='vulnhunter',
                       help='Data file prefix')
    parser.add_argument('--run-name', type=str, default='run-001',
                       help='Training run name')
    parser.add_argument('--hidden-dim', type=int, default=256,
                       help='Hidden dimension')
    parser.add_argument('--num-heads', type=int, default=8,
                       help='Number of attention heads')
    parser.add_argument('--dropout', type=float, default=0.3,
                       help='Dropout rate')
    parser.add_argument('--gnn-epochs', type=int, default=100,
                       help='GNN training epochs')
    parser.add_argument('--codebert-epochs', type=int, default=10,
                       help='CodeBERT fine-tuning epochs')
    parser.add_argument('--batch-size', type=int, default=32,
                       help='Batch size')
    parser.add_argument('--learning-rate', type=float, default=0.001,
                       help='Learning rate')
    parser.add_argument('--gradient-accumulation', type=int, default=4,
                       help='Gradient accumulation steps')

    # Actions
    parser.add_argument('--list-jobs', action='store_true',
                       help='List recent jobs and exit')
    parser.add_argument('--get-job-status', type=str,
                       help='Get status of specific job by resource name')

    args = parser.parse_args()

    # Create submitter
    submitter = VertexJobSubmitter(
        project_id=args.project_id,
        region=args.region,
        bucket_name=args.bucket_name
    )

    # Handle actions
    if args.list_jobs:
        submitter.list_jobs()
        return

    if args.get_job_status:
        submitter.get_job_status(args.get_job_status)
        return

    # Prepare training arguments
    training_args = {
        'data_prefix': args.data_prefix,
        'run_name': args.run_name,
        'hidden_dim': args.hidden_dim,
        'num_heads': args.num_heads,
        'dropout': args.dropout,
        'gnn_epochs': args.gnn_epochs,
        'codebert_epochs': args.codebert_epochs,
        'batch_size': args.batch_size,
        'learning_rate': args.learning_rate,
        'gradient_accumulation': args.gradient_accumulation
    }

    # Submit training job
    job = submitter.submit_training_job(
        container_uri=args.container_uri,
        display_name=args.job_name,
        machine_type=args.machine_type,
        accelerator_type=args.gpu_type,
        accelerator_count=args.gpu_count,
        training_args=training_args,
        use_preemptible=args.preemptible
    )

    logger.info("\n✅ Done! Job is running in the background.")
    logger.info("\nTo monitor logs:")
    logger.info(f"  gcloud ai custom-jobs stream-logs {job.resource_name.split('/')[-1]} --region={args.region}")


if __name__ == "__main__":
    main()
