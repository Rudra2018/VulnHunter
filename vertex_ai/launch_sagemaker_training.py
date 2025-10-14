#!/usr/bin/env python3
"""
AWS SageMaker Training Launcher for VulnHunter V4
Launch production training on AWS SageMaker
"""

import boto3
import json
import time
import zipfile
import os
from pathlib import Path
from datetime import datetime
import sagemaker
from sagemaker.tensorflow import TensorFlow

class VulnHunterSageMakerLauncher:
    """Launch VulnHunter V4 training on AWS SageMaker."""

    def __init__(self, region='us-east-1'):
        """Initialize SageMaker launcher."""
        self.region = region
        self.sess = sagemaker.Session()
        self.role = sagemaker.get_execution_role()
        self.bucket = self.sess.default_bucket()

        print(f"🚀 VulnHunter V4 SageMaker Launcher")
        print(f"=================================")
        print(f"Region: {self.region}")
        print(f"Role: {self.role}")
        print(f"Bucket: {self.bucket}")
        print()

    def prepare_training_code(self):
        """Package training code for SageMaker."""
        print("📦 Preparing training code...")

        # Create source code archive
        code_dir = Path("/tmp/vulnhunter_sagemaker_code")
        code_dir.mkdir(exist_ok=True)

        # Copy training script
        training_script = Path("/Users/ankitthakur/vuln_ml_research/vertex_ai/sagemaker_vulnhunter_trainer.py")
        target_script = code_dir / "train.py"

        with open(training_script, 'r') as src, open(target_script, 'w') as dst:
            dst.write(src.read())

        # Create requirements file
        requirements = code_dir / "requirements.txt"
        with open(requirements, 'w') as f:
            f.write("""tensorflow==2.11.0
pandas==1.5.3
scikit-learn==1.2.2
numpy==1.24.3
boto3==1.26.137
""")

        print(f"✅ Training code prepared at: {code_dir}")
        return str(code_dir)

    def upload_training_data(self):
        """Upload training data to S3."""
        print("📤 Uploading training data to S3...")

        # Training data directory
        training_data_dir = Path("/Users/ankitthakur/vuln_ml_research/data/training")

        if not training_data_dir.exists():
            print(f"❌ Training data not found at: {training_data_dir}")
            return None

        # Upload to S3
        s3_train_data = f"s3://{self.bucket}/vulnhunter-v4/training-data"

        try:
            # Upload JSON files
            for json_file in training_data_dir.glob("*.json"):
                print(f"Uploading: {json_file.name}")
                s3_key = f"vulnhunter-v4/training-data/{json_file.name}"
                self.sess.upload_data(
                    path=str(json_file),
                    bucket=self.bucket,
                    key_prefix="vulnhunter-v4/training-data"
                )

            # Upload synthetic data
            synthetic_dir = training_data_dir / "synthetic"
            if synthetic_dir.exists():
                for json_file in synthetic_dir.glob("*.json"):
                    print(f"Uploading synthetic: {json_file.name}")
                    self.sess.upload_data(
                        path=str(json_file),
                        bucket=self.bucket,
                        key_prefix="vulnhunter-v4/training-data/synthetic"
                    )

            print(f"✅ Training data uploaded to: {s3_train_data}")
            return s3_train_data

        except Exception as e:
            print(f"❌ Failed to upload training data: {e}")
            return None

    def launch_training_job(self, code_dir, s3_train_data):
        """Launch SageMaker training job."""
        print("🚀 Launching SageMaker training job...")

        job_name = f"vulnhunter-v4-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}"

        # Configure TensorFlow estimator
        estimator = TensorFlow(
            entry_point='train.py',
            source_dir=code_dir,
            role=self.role,
            instance_count=1,
            instance_type='ml.c5.xlarge',  # CPU instance for testing
            framework_version='2.11.0',
            py_version='py39',
            job_name=job_name,
            hyperparameters={
                'epochs': 50,
                'batch-size': 32,
                'learning-rate': 0.001
            },
            base_job_name='vulnhunter-v4',
            output_path=f's3://{self.bucket}/vulnhunter-v4/model-artifacts/',
            code_location=f's3://{self.bucket}/vulnhunter-v4/code/',
            volume_size=30,
            max_run=7200,  # 2 hours max
        )

        # Start training
        try:
            estimator.fit({
                'train': s3_train_data
            })

            print(f"✅ Training job started: {job_name}")
            return estimator, job_name

        except Exception as e:
            print(f"❌ Failed to start training job: {e}")
            return None, None

    def monitor_training_job(self, estimator, job_name):
        """Monitor training job progress."""
        print("📊 Monitoring training job...")

        try:
            # Print job details
            print(f"Job Name: {job_name}")
            print(f"Job Status: {estimator.training_job_analytics.status}")
            print(f"Instance Type: ml.c5.xlarge")
            print(f"Output Path: s3://{self.bucket}/vulnhunter-v4/model-artifacts/{job_name}/")

            # Monitor logs (this will block until completion)
            estimator.logs()

            print("✅ Training completed successfully!")
            return True

        except Exception as e:
            print(f"❌ Training monitoring failed: {e}")
            return False

    def launch_production_training(self):
        """Launch complete SageMaker training pipeline."""
        print("🎯 Launching VulnHunter V4 Production Training on SageMaker")
        print("=" * 60)

        # Step 1: Prepare training code
        code_dir = self.prepare_training_code()
        if not code_dir:
            return False

        # Step 2: Upload training data
        s3_train_data = self.upload_training_data()
        if not s3_train_data:
            return False

        # Step 3: Launch training job
        estimator, job_name = self.launch_training_job(code_dir, s3_train_data)
        if not estimator:
            return False

        # Step 4: Monitor training
        success = self.monitor_training_job(estimator, job_name)

        if success:
            print("\\n" + "=" * 60)
            print("🎉 VULNHUNTER V4 SAGEMAKER TRAINING LAUNCHED!")
            print("=" * 60)
            print(f"Job Name: {job_name}")
            print(f"Region: {self.region}")
            print(f"Instance: ml.c5.xlarge")
            print(f"Training Data: {s3_train_data}")
            print(f"Model Output: s3://{self.bucket}/vulnhunter-v4/model-artifacts/{job_name}/")
            print()
            print("📊 To monitor in AWS Console:")
            print(f"   https://console.aws.amazon.com/sagemaker/home?region={self.region}#/jobs")
            print()
            print("📁 Model artifacts will be available at:")
            print(f"   s3://{self.bucket}/vulnhunter-v4/model-artifacts/{job_name}/output/model.tar.gz")

        return success

def main():
    """Main function to launch SageMaker training."""
    try:
        launcher = VulnHunterSageMakerLauncher()
        success = launcher.launch_production_training()

        if success:
            print("\\n✅ SageMaker training setup completed successfully!")
        else:
            print("\\n❌ SageMaker training setup failed.")

    except Exception as e:
        print(f"❌ Failed to initialize SageMaker launcher: {e}")
        print("\\nMake sure you have:")
        print("1. AWS credentials configured (aws configure)")
        print("2. SageMaker execution role")
        print("3. Required AWS permissions")

if __name__ == "__main__":
    main()