#!/usr/bin/env python3
"""
Simple AWS SageMaker Training Launcher for VulnHunter V4
Using boto3 directly for easier setup
"""

import boto3
import json
import time
import zipfile
import os
from pathlib import Path
from datetime import datetime

class SimpleSageMakerLauncher:
    """Simple SageMaker launcher using boto3."""

    def __init__(self, region='us-east-1'):
        """Initialize with AWS clients."""
        self.region = region
        self.sagemaker = boto3.client('sagemaker', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)

        # Get account ID for role ARN
        sts = boto3.client('sts')
        self.account_id = sts.get_caller_identity()['Account']

        # Default bucket name
        self.bucket = f"vulnhunter-sagemaker-{self.account_id}-{region}"

        print(f"🚀 Simple VulnHunter V4 SageMaker Launcher")
        print(f"=======================================")
        print(f"Region: {self.region}")
        print(f"Account: {self.account_id}")
        print(f"Bucket: {self.bucket}")
        print()

    def create_bucket_if_needed(self):
        """Create S3 bucket if it doesn't exist."""
        try:
            self.s3.head_bucket(Bucket=self.bucket)
            print(f"✅ Bucket exists: {self.bucket}")
        except:
            print(f"📦 Creating bucket: {self.bucket}")
            try:
                if self.region == 'us-east-1':
                    self.s3.create_bucket(Bucket=self.bucket)
                else:
                    self.s3.create_bucket(
                        Bucket=self.bucket,
                        CreateBucketConfiguration={'LocationConstraint': self.region}
                    )
                print(f"✅ Bucket created: {self.bucket}")
            except Exception as e:
                print(f"❌ Failed to create bucket: {e}")
                return False
        return True

    def upload_training_code(self):
        """Create and upload training code package."""
        print("📦 Preparing training code...")

        # Create temporary directory
        temp_dir = Path("/tmp/vulnhunter_code")
        temp_dir.mkdir(exist_ok=True)

        # Create training script
        train_script = temp_dir / "train.py"
        with open(train_script, 'w') as f:
            f.write('''#!/usr/bin/env python3
import os
import json
import argparse
import tensorflow as tf
import numpy as np
import pandas as pd
from datetime import datetime
import pickle
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from tensorflow import keras

def load_data(data_dir):
    """Load training data from directory."""
    all_data = []
    for file_path in Path(data_dir).glob("*.json"):
        with open(file_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                all_data.extend(data)
            else:
                all_data.append(data)
    return all_data

def extract_features(example):
    """Extract features from vulnerability claim."""
    claim = example.get('claim', '')

    return {
        'claim_length': len(claim),
        'has_line_numbers': 1 if 'line' in claim.lower() else 0,
        'has_file_path': 1 if '/' in claim or '\\\\' in claim else 0,
        'has_function_name': 1 if '()' in claim else 0,
        'mentions_framework': 1 if any(fw in claim.lower() for fw in ['express', 'react']) else 0,
        'has_security_terms': 1 if any(term in claim.lower() for term in ['vulnerability', 'exploit']) else 0,
        'artificial_confidence': 1 if 'definitely' in claim.lower() else 0,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model-dir', type=str, default=os.environ.get('SM_MODEL_DIR', '/opt/ml/model'))
    parser.add_argument('--train', type=str, default=os.environ.get('SM_CHANNEL_TRAIN', '/opt/ml/input/data/train'))
    parser.add_argument('--epochs', type=int, default=20)

    args = parser.parse_args()

    print("🚀 Starting VulnHunter V4 Training")

    # Load data
    raw_data = load_data(args.train)
    print(f"Loaded {len(raw_data)} examples")

    # Extract features
    features_list = []
    labels = []

    for example in raw_data:
        features = extract_features(example)
        features_list.append(features)
        labels.append(1 if example.get('is_false_positive', False) else 0)

    # Prepare data
    df = pd.DataFrame(features_list)
    scaler = StandardScaler()
    X = scaler.fit_transform(df)
    y = np.array(labels)

    # Split data
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    # Create model
    model = keras.Sequential([
        keras.layers.Dense(128, activation='relu', input_shape=(X.shape[1],)),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(64, activation='relu'),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )

    # Train model
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=args.epochs,
        batch_size=32,
        verbose=1
    )

    # Save model
    model.save(os.path.join(args.model_dir, 'vulnhunter_model.h5'))

    # Save scaler
    with open(os.path.join(args.model_dir, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)

    # Save feature names
    with open(os.path.join(args.model_dir, 'features.json'), 'w') as f:
        json.dump(list(df.columns), f)

    print(f"✅ Training complete! Final accuracy: {history.history['val_accuracy'][-1]:.3f}")

if __name__ == "__main__":
    main()
''')

        # Create requirements
        requirements = temp_dir / "requirements.txt"
        with open(requirements, 'w') as f:
            f.write("tensorflow==2.11.0\\npandas==1.5.3\\nscikit-learn==1.2.2\\n")

        # Create zip package
        package_path = "/tmp/vulnhunter_code.tar.gz"
        os.system(f"cd {temp_dir} && tar -czf {package_path} .")

        # Upload to S3
        s3_key = "vulnhunter-v4/code/source.tar.gz"
        self.s3.upload_file(package_path, self.bucket, s3_key)

        print(f"✅ Code uploaded to s3://{self.bucket}/{s3_key}")
        return f"s3://{self.bucket}/{s3_key}"

    def upload_training_data(self):
        """Upload training data to S3."""
        print("📤 Uploading training data...")

        data_dir = Path("/Users/ankitthakur/vuln_ml_research/data/training")
        if not data_dir.exists():
            print(f"❌ Training data not found: {data_dir}")
            return None

        s3_prefix = "vulnhunter-v4/data/train/"

        # Upload JSON files
        for json_file in data_dir.glob("*.json"):
            print(f"Uploading: {json_file.name}")
            s3_key = f"{s3_prefix}{json_file.name}"
            self.s3.upload_file(str(json_file), self.bucket, s3_key)

        # Upload synthetic data
        synthetic_dir = data_dir / "synthetic"
        if synthetic_dir.exists():
            for json_file in synthetic_dir.glob("*.json"):
                print(f"Uploading: synthetic/{json_file.name}")
                s3_key = f"{s3_prefix}synthetic_{json_file.name}"
                self.s3.upload_file(str(json_file), self.bucket, s3_key)

        train_data_uri = f"s3://{self.bucket}/{s3_prefix}"
        print(f"✅ Training data uploaded to: {train_data_uri}")
        return train_data_uri

    def create_training_job(self, code_uri, train_data_uri):
        """Create SageMaker training job."""
        print("🚀 Creating SageMaker training job...")

        job_name = f"vulnhunter-v4-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}"

        # SageMaker execution role (you may need to create this)
        role_arn = f"arn:aws:iam::{self.account_id}:role/SageMakerExecutionRole"

        training_job_config = {
            'TrainingJobName': job_name,
            'RoleArn': role_arn,
            'AlgorithmSpecification': {
                'TrainingInputMode': 'File',
                'TrainingImage': '763104351884.dkr.ecr.us-east-1.amazonaws.com/tensorflow-training:2.11.0-cpu-py39-ubuntu20.04-sagemaker',
            },
            'InputDataConfig': [
                {
                    'ChannelName': 'train',
                    'DataSource': {
                        'S3DataSource': {
                            'S3DataType': 'S3Prefix',
                            'S3Uri': train_data_uri,
                            'S3DataDistributionType': 'FullyReplicated',
                        }
                    },
                    'ContentType': 'application/json',
                    'CompressionType': 'None',
                    'RecordWrapperType': 'None',
                }
            ],
            'OutputDataConfig': {
                'S3OutputPath': f"s3://{self.bucket}/vulnhunter-v4/output/"
            },
            'ResourceConfig': {
                'InstanceType': 'ml.m5.large',
                'InstanceCount': 1,
                'VolumeSizeInGB': 30,
            },
            'StoppingCondition': {
                'MaxRuntimeInSeconds': 3600  # 1 hour
            },
            'HyperParameters': {
                'epochs': '30'
            }
        }

        try:
            response = self.sagemaker.create_training_job(**training_job_config)
            print(f"✅ Training job created: {job_name}")
            return job_name
        except Exception as e:
            print(f"❌ Failed to create training job: {e}")
            if "does not exist" in str(e):
                print("\\n📝 You need to create a SageMaker execution role:")
                print(f"   Role ARN: {role_arn}")
                print("   Visit: https://console.aws.amazon.com/iam/home#/roles")
                print("   Create role with SageMaker service and AmazonSageMakerFullAccess policy")
            return None

    def monitor_job(self, job_name):
        """Monitor training job progress."""
        print(f"📊 Monitoring job: {job_name}")

        while True:
            try:
                response = self.sagemaker.describe_training_job(TrainingJobName=job_name)
                status = response['TrainingJobStatus']

                print(f"Status: {status}")

                if status in ['Completed', 'Failed', 'Stopped']:
                    break

                time.sleep(30)

            except Exception as e:
                print(f"❌ Error monitoring job: {e}")
                break

        return status == 'Completed'

    def launch(self):
        """Launch complete training pipeline."""
        print("🎯 Launching VulnHunter V4 SageMaker Training")
        print("=" * 50)

        # Create bucket
        if not self.create_bucket_if_needed():
            return False

        # Upload code
        code_uri = self.upload_training_code()
        if not code_uri:
            return False

        # Upload data
        train_data_uri = self.upload_training_data()
        if not train_data_uri:
            return False

        # Create job
        job_name = self.create_training_job(code_uri, train_data_uri)
        if not job_name:
            return False

        # Monitor job
        success = self.monitor_job(job_name)

        if success:
            print("\\n🎉 TRAINING COMPLETED SUCCESSFULLY!")
            print(f"Model artifacts: s3://{self.bucket}/vulnhunter-v4/output/{job_name}/output/model.tar.gz")

        return success

def main():
    """Main function."""
    launcher = SimpleSageMakerLauncher()
    launcher.launch()

if __name__ == "__main__":
    main()