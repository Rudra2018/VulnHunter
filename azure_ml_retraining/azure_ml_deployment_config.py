#!/usr/bin/env python3
"""
Azure ML Deployment Configuration for VulnHunter V8
Production deployment specifications
"""

import os
import json
from datetime import datetime
from pathlib import Path

class AzureMLDeploymentConfig:
    """Azure ML deployment configuration for VulnHunter V8"""

    def __init__(self):
        self.config = self._create_deployment_config()

    def _create_deployment_config(self):
        """Create comprehensive Azure ML deployment configuration"""
        return {
            "model_config": {
                "name": "vulnhunter-v8-production",
                "version": "1.0.0",
                "description": "Production-ready smart contract vulnerability detection with comprehensive training",
                "tags": {
                    "model_type": "security_scanner",
                    "domain": "smart_contract",
                    "accuracy": "91.4%",
                    "training_data": "356_comprehensive_samples",
                    "false_positive_rate": "calibrated",
                    "deployment_ready": "true"
                }
            },

            "compute_config": {
                "training": {
                    "vm_size": "Standard_NC24s_v3",  # GPU for large-scale training
                    "min_nodes": 0,
                    "max_nodes": 4,
                    "idle_seconds_before_scaledown": 300
                },
                "inference": {
                    "vm_size": "Standard_DS3_v2",
                    "instance_count": 3,
                    "cpu_allocation": "2 cores",
                    "memory_allocation": "8GB"
                }
            },

            "environment_config": {
                "name": "vulnhunter-v8-env",
                "docker_image": "mcr.microsoft.com/azureml/openmpi4.1.0-ubuntu20.04:latest",
                "conda_dependencies": {
                    "channels": ["conda-forge", "pytorch"],
                    "dependencies": [
                        "python=3.9",
                        "scikit-learn>=1.2.0",
                        "pandas>=1.5.0",
                        "numpy>=1.21.0",
                        "joblib>=1.2.0",
                        "requests>=2.28.0",
                        "beautifulsoup4>=4.11.0",
                        {
                            "pip": [
                                "azure-ai-ml>=1.8.0",
                                "mlflow>=2.3.0",
                                "GitPython>=3.1.0"
                            ]
                        }
                    ]
                }
            },

            "data_config": {
                "training_data": {
                    "name": "vulnhunter_comprehensive_dataset",
                    "version": "1.0",
                    "description": "Comprehensive security training dataset with 356 samples",
                    "path": "azureml://datastores/workspaceblobstore/paths/vulnhunter_training_data/",
                    "type": "uri_folder"
                },
                "validation_data": {
                    "name": "vulnhunter_validation_set",
                    "version": "1.0",
                    "description": "Curated validation set from manual analysis",
                    "path": "azureml://datastores/workspaceblobstore/paths/vulnhunter_validation/",
                    "type": "uri_folder"
                }
            },

            "training_job_config": {
                "experiment_name": "vulnhunter-v8-comprehensive-training",
                "display_name": "VulnHunter V8 Production Training",
                "description": "Comprehensive training with educational and production datasets",
                "code": {
                    "local_path": "./training_scripts/",
                    "scoring_script": "real_azure_ml_training.py"
                },
                "inputs": {
                    "training_data": {
                        "type": "uri_folder",
                        "path": "${{parent.inputs.training_data}}"
                    }
                },
                "outputs": {
                    "model_output": {
                        "type": "uri_folder",
                        "mode": "rw_mount"
                    }
                },
                "parameters": {
                    "max_features": 15000,
                    "n_estimators": 300,
                    "max_depth": 25,
                    "random_state": 42
                }
            },

            "endpoint_config": {
                "name": "vulnhunter-v8-endpoint",
                "description": "Production endpoint for smart contract vulnerability detection",
                "auth_mode": "key",
                "traffic": {
                    "production": 100
                }
            },

            "deployment_config": {
                "name": "vulnhunter-v8-deployment",
                "model_mount_path": "/var/azureml-app/azureml-models/vulnhunter-v8-production/1",
                "scoring_script": "score.py",
                "environment": "vulnhunter-v8-env",
                "instance_count": 3,
                "liveness_probe": {
                    "initial_delay": 30,
                    "timeout": 10,
                    "period": 30,
                    "failure_threshold": 3
                },
                "readiness_probe": {
                    "initial_delay": 10,
                    "timeout": 10,
                    "period": 10,
                    "failure_threshold": 3
                },
                "request_settings": {
                    "request_timeout_ms": 90000,
                    "max_concurrent_requests_per_instance": 5,
                    "max_queue_wait_ms": 5000
                }
            },

            "monitoring_config": {
                "data_drift": {
                    "enabled": True,
                    "alert_email": "security-team@company.com",
                    "threshold": 0.1
                },
                "model_performance": {
                    "enabled": True,
                    "accuracy_threshold": 0.85,
                    "alert_on_degradation": True
                },
                "logging": {
                    "level": "INFO",
                    "application_insights": True
                }
            },

            "scaling_config": {
                "auto_scale": {
                    "enabled": True,
                    "min_instances": 1,
                    "max_instances": 10,
                    "target_utilization": 70,
                    "scale_up_time": "PT5M",
                    "scale_down_time": "PT15M"
                }
            },

            "security_config": {
                "managed_identity": True,
                "key_vault_integration": True,
                "network_isolation": False,  # Set to True for production
                "ssl_configuration": {
                    "status": "Enabled",
                    "cert_file": None,
                    "key_file": None,
                    "cname": None
                }
            },

            "cost_optimization": {
                "spot_instances": False,  # For production reliability
                "auto_shutdown": {
                    "enabled": True,
                    "idle_time_minutes": 30
                },
                "resource_quotas": {
                    "max_nodes": 10,
                    "max_cores": 100
                }
            }
        }

    def save_config(self, output_path):
        """Save configuration to file"""
        config_path = Path(output_path) / f"azure_ml_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

        print(f"✅ Azure ML configuration saved: {config_path}")
        return config_path

    def create_scoring_script(self, output_path):
        """Create scoring script for Azure ML deployment"""
        scoring_script = '''
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

def init():
    """Initialize the model and components"""
    global model, tfidf_vectorizer, scaler, feature_names

    # Load trained model artifacts
    model = joblib.load('vulnhunter_v8_production.pkl')
    tfidf_vectorizer = joblib.load('vulnhunter_v8_tfidf.pkl')
    scaler = joblib.load('vulnhunter_v8_scaler.pkl')

    # Load feature names
    with open('feature_names.json', 'r') as f:
        feature_names = json.load(f)

def extract_security_features(contract_code):
    """Extract security-focused features from smart contract code"""
    security_patterns = {
        'reentrancy': ['call.value', 'msg.sender.call', '.call(', 'external', 'nonReentrant'],
        'arithmetic': ['+=', '-=', '*=', '/=', 'unchecked', 'SafeMath', 'overflow', 'underflow'],
        'access_control': ['onlyOwner', 'modifier', 'require(msg.sender', 'tx.origin', 'auth'],
        'timestamp': ['block.timestamp', 'block.number', 'now', 'block.difficulty'],
        'randomness': ['blockhash', 'block.coinbase', 'random', 'keccak256(block'],
        'gas': ['gasleft()', 'msg.gas', 'block.gaslimit', 'gas'],
        'delegatecall': ['delegatecall', 'callcode', 'proxy'],
        'selfdestruct': ['selfdestruct', 'suicide'],
        'oracle': ['oracle', 'price', 'getPrice', 'latestRoundData', 'chainlink'],
        'defi': ['flashloan', 'flash', 'borrow', 'repay', 'liquidity', 'swap'],
        'governance': ['vote', 'proposal', 'quorum', 'timelock'],
        'bridge': ['bridge', 'cross-chain', 'relay', 'validator']
    }

    text_lower = contract_code.lower()
    features = {}

    # Pattern features
    for category, patterns in security_patterns.items():
        count = sum(1 for pattern in patterns if pattern in text_lower)
        features[f'{category}_count'] = count
        features[f'{category}_presence'] = 1 if count > 0 else 0

    # Complexity features
    features.update({
        'function_count': contract_code.count('function'),
        'contract_count': contract_code.count('contract'),
        'modifier_count': contract_code.count('modifier'),
        'require_count': contract_code.count('require('),
        'assert_count': contract_code.count('assert('),
        'revert_count': contract_code.count('revert('),
        'payable_count': contract_code.count('payable'),
        'public_count': contract_code.count('public'),
        'private_count': contract_code.count('private'),
        'external_count': contract_code.count('external'),
        'internal_count': contract_code.count('internal'),
        'view_count': contract_code.count('view'),
        'pure_count': contract_code.count('pure'),
        'text_length': len(contract_code),
        'line_count': contract_code.count('\\n')
    })

    return features

def run(raw_data):
    """Process incoming requests"""
    try:
        # Parse input
        data = json.loads(raw_data)

        if isinstance(data, dict):
            contracts = [data]
        else:
            contracts = data

        results = []

        for contract_data in contracts:
            contract_code = contract_data.get('code', '')

            if not contract_code:
                results.append({
                    'error': 'No contract code provided',
                    'vulnerability_score': 0.0,
                    'is_vulnerable': False
                })
                continue

            # Extract TF-IDF features
            tfidf_features = tfidf_vectorizer.transform([contract_code])

            # Extract pattern features
            pattern_features = extract_security_features(contract_code)
            pattern_df = pd.DataFrame([pattern_features])

            # Normalize if using pattern model
            if 'patterns' in str(type(model)).lower():
                # Scale numerical features
                numerical_cols = ['function_count', 'contract_count', 'text_length', 'line_count']
                pattern_df[numerical_cols] = scaler.transform(pattern_df[numerical_cols])

                # Predict using pattern features
                prediction = model.predict(pattern_df)[0]
                probability = model.predict_proba(pattern_df)[0]
            else:
                # Predict using TF-IDF features
                prediction = model.predict(tfidf_features)[0]
                probability = model.predict_proba(tfidf_features)[0]

            vulnerability_score = probability[1] if len(probability) > 1 else probability[0]

            result = {
                'is_vulnerable': bool(prediction),
                'vulnerability_score': float(vulnerability_score),
                'confidence': 'high' if vulnerability_score > 0.8 else 'medium' if vulnerability_score > 0.6 else 'low',
                'detected_patterns': [k for k, v in pattern_features.items() if 'presence' in k and v > 0],
                'model_version': 'VulnHunter-V8-Production'
            }

            results.append(result)

        return json.dumps(results)

    except Exception as e:
        error_result = {
            'error': str(e),
            'vulnerability_score': 0.0,
            'is_vulnerable': False
        }
        return json.dumps([error_result])
'''

        scoring_path = Path(output_path) / "score.py"
        with open(scoring_path, 'w') as f:
            f.write(scoring_script)

        print(f"✅ Scoring script created: {scoring_path}")
        return scoring_path

    def create_deployment_script(self, output_path):
        """Create Azure ML deployment script"""
        deployment_script = f'''
#!/usr/bin/env python3
"""
Azure ML Deployment Script for VulnHunter V8
"""

from azure.ai.ml import MLClient, Input, Output
from azure.ai.ml.entities import *
from azure.identity import DefaultAzureCredential
import json

# Configuration
config = {json.dumps(self.config, indent=4)}

def deploy_to_azure_ml():
    """Deploy VulnHunter V8 to Azure ML"""

    # Initialize client
    credential = DefaultAzureCredential()
    ml_client = MLClient(
        credential=credential,
        subscription_id="YOUR_SUBSCRIPTION_ID",
        resource_group_name="vulnhunter-rg",
        workspace_name="vulnhunter-workspace"
    )

    # Create environment
    env = Environment(
        name=config["environment_config"]["name"],
        docker={{
            "base_image": config["environment_config"]["docker_image"]
        }},
        conda_file="environment.yml"
    )

    # Register environment
    ml_client.environments.create_or_update(env)

    # Create endpoint
    endpoint = ManagedOnlineEndpoint(
        name=config["endpoint_config"]["name"],
        description=config["endpoint_config"]["description"],
        auth_mode=config["endpoint_config"]["auth_mode"]
    )

    # Create endpoint
    ml_client.online_endpoints.begin_create_or_update(endpoint)

    # Create deployment
    deployment = ManagedOnlineDeployment(
        name=config["deployment_config"]["name"],
        endpoint_name=config["endpoint_config"]["name"],
        model="vulnhunter-v8-production:1",
        environment=config["deployment_config"]["environment"],
        code_configuration=CodeConfiguration(
            code="./",
            scoring_script=config["deployment_config"]["scoring_script"]
        ),
        instance_type=config["compute_config"]["inference"]["vm_size"],
        instance_count=config["deployment_config"]["instance_count"]
    )

    # Deploy
    ml_client.online_deployments.begin_create_or_update(deployment)

    # Set traffic
    endpoint.traffic = config["endpoint_config"]["traffic"]
    ml_client.online_endpoints.begin_create_or_update(endpoint)

    print("✅ VulnHunter V8 deployed to Azure ML successfully!")

if __name__ == "__main__":
    deploy_to_azure_ml()
'''

        deployment_path = Path(output_path) / "deploy_to_azure.py"
        with open(deployment_path, 'w') as f:
            f.write(deployment_script)

        print(f"✅ Deployment script created: {deployment_path}")
        return deployment_path

def main():
    """Create all Azure ML deployment artifacts"""
    print("🚀 Creating Azure ML Deployment Configuration")
    print("=" * 60)

    # Initialize config
    config_manager = AzureMLDeploymentConfig()

    # Create output directory
    output_dir = Path("/Users/ankitthakur/vuln_ml_research/azure_ml_retraining/deployment_artifacts")
    output_dir.mkdir(exist_ok=True)

    # Save configuration
    config_path = config_manager.save_config(output_dir)

    # Create scoring script
    scoring_path = config_manager.create_scoring_script(output_dir)

    # Create deployment script
    deployment_path = config_manager.create_deployment_script(output_dir)

    print("\n" + "=" * 60)
    print("✅ Azure ML Deployment Artifacts Created")
    print("=" * 60)
    print(f"📋 Configuration: {config_path}")
    print(f"🐍 Scoring Script: {scoring_path}")
    print(f"🚀 Deployment Script: {deployment_path}")
    print("💫 Ready for Azure ML production deployment!")

if __name__ == "__main__":
    main()