#!/usr/bin/env python3
"""
Submit VulnHunter V14 job to Azure ML using Python SDK
"""
import os
try:
    from azureml.core import Workspace, Experiment, ScriptRunConfig, Environment
    from azureml.core.compute import ComputeTarget, AmlCompute
    from azureml.core.conda_dependencies import CondaDependencies
    AZURE_SDK_AVAILABLE = True
except ImportError:
    print("Azure ML SDK not available - install with: pip install azureml-core")
    AZURE_SDK_AVAILABLE = False

def submit_vulnhunter_job():
    if not AZURE_SDK_AVAILABLE:
        print("❌ Azure ML SDK not available")
        return

    try:
        # Connect to workspace
        print("🔗 Connecting to Azure ML workspace...")
        ws = Workspace(
            subscription_id="6432d240-27c9-45c4-a58e-41b89beb22af",
            resource_group="vulnhunter-production-rg",
            workspace_name="vulnhunter-v14-ws"
        )
        print(f"✅ Connected to workspace: {ws.name}")

        # Create experiment
        experiment = Experiment(workspace=ws, name="vulnhunter-v14-production")
        print(f"📊 Experiment: {experiment.name}")

        # Get or create compute target
        compute_name = "cpu-cluster"
        try:
            compute_target = ComputeTarget(workspace=ws, name=compute_name)
            print(f"✅ Found compute target: {compute_target.name}")
        except:
            print(f"🔧 Creating compute target: {compute_name}")
            compute_config = AmlCompute.provisioning_configuration(
                vm_size='STANDARD_D2_V2',
                max_nodes=2
            )
            compute_target = ComputeTarget.create(ws, compute_name, compute_config)
            compute_target.wait_for_completion(show_output=True)

        # Create environment
        env = Environment(name="vulnhunter-env")
        conda_deps = CondaDependencies()
        conda_deps.add_pip_package("scikit-learn")
        conda_deps.add_pip_package("azureml-core")
        env.python.conda_dependencies = conda_deps

        # Create script run config
        script_config = ScriptRunConfig(
            source_directory='.',
            script='simple_azure_train.py',
            compute_target=compute_target,
            environment=env
        )

        # Submit run
        print("🚀 Submitting VulnHunter V14 training job...")
        run = experiment.submit(script_config)

        print(f"✅ Job submitted successfully!")
        print(f"📊 Run ID: {run.id}")
        print(f"🔗 Azure ML Studio: https://ml.azure.com/runs/{run.id}")
        print(f"📊 Status: {run.get_status()}")

        return run

    except Exception as e:
        print(f"❌ Error submitting job: {e}")
        return None

if __name__ == "__main__":
    print("🚀 VulnHunter V14 Azure ML Job Submission")
    print("=" * 50)
    run = submit_vulnhunter_job()
    if run:
        print("\n✅ Job submitted successfully!")
        print("Check Azure ML Studio for training progress.")
    else:
        print("\n❌ Job submission failed.")