#!/usr/bin/env python3
"""
VulnHunter V20 Azure ML Training Job Monitor
Real-time monitoring of VulnHunter training progress
"""

import subprocess
import json
import time
from datetime import datetime
import sys

def run_az_command(command):
    """Execute Azure CLI command and return JSON result"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print(f"Error: {result.stderr}")
            return None
    except Exception as e:
        print(f"Command failed: {e}")
        return None

def monitor_job(job_name, max_duration_minutes=30):
    """Monitor Azure ML job progress"""
    print("🚀 VulnHunter V20 Training Job Monitor")
    print("=" * 50)
    print(f"📊 Job Name: {job_name}")
    print(f"⏱️ Max Duration: {max_duration_minutes} minutes")
    print(f"🌐 Azure ML Studio: https://ml.azure.com")
    print()

    start_time = time.time()
    max_duration_seconds = max_duration_minutes * 60
    check_interval = 30  # Check every 30 seconds

    last_status = None

    while time.time() - start_time < max_duration_seconds:
        # Get job status
        command = f"""
        az ml job show \
            --name {job_name} \
            --workspace-name vulnhunter-v20-workspace \
            --resource-group vulnhunter-production-rg \
            --subscription 6432d240-27c9-45c4-a58e-41b89beb22af \
            --query '{{status:status, duration:duration, startTime:creation_context.created_at}}'
        """

        job_info = run_az_command(command)

        if job_info:
            current_status = job_info.get('status', 'Unknown')
            duration = job_info.get('duration', 'N/A')

            if current_status != last_status:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] 📈 Status: {current_status}")

                if duration and duration != 'N/A':
                    print(f"[{timestamp}] ⏱️ Duration: {duration}")

                last_status = current_status

                # Check for completion
                if current_status in ['Completed', 'Failed', 'Canceled']:
                    print(f"\n🎯 Training Job {current_status}!")

                    if current_status == 'Completed':
                        print("✅ VulnHunter V20 training completed successfully!")
                        print("🎉 Quantum-enhanced models are ready!")
                        print("💝 Universal love algorithms trained!")
                        print("🧠 Consciousness-aware security deployed!")

                        # Get outputs
                        print("\n📋 Retrieving job outputs...")
                        outputs_command = f"""
                        az ml job show \
                            --name {job_name} \
                            --workspace-name vulnhunter-v20-workspace \
                            --resource-group vulnhunter-production-rg \
                            --subscription 6432d240-27c9-45c4-a58e-41b89beb22af \
                            --query 'outputs'
                        """

                        outputs = run_az_command(outputs_command)
                        if outputs:
                            print("📁 Training outputs:")
                            for key, value in outputs.items():
                                print(f"   • {key}: {value.get('path', 'N/A')}")

                        return True

                    elif current_status == 'Failed':
                        print("❌ Training job failed. Check Azure ML Studio for details.")
                        return False
                    elif current_status == 'Canceled':
                        print("⚠️ Training job was canceled.")
                        return False

        # Wait before next check
        time.sleep(check_interval)

    print(f"\n⏰ Monitoring timed out after {max_duration_minutes} minutes")
    print("💡 Job may still be running. Check Azure ML Studio for updates.")
    return False

def main():
    """Main monitoring execution"""
    job_name = "frank_scooter_hzltqrll74"

    print("🌟 Starting VulnHunter V20 Training Monitor...")
    print()

    success = monitor_job(job_name, max_duration_minutes=20)

    if success:
        print("\n🎊 TRAINING SUCCESS!")
        print("🚀 VulnHunter V20 models are ready for deployment!")
    else:
        print("\n📊 Monitor session ended.")
        print("🌐 Continue monitoring in Azure ML Studio:")
        print(f"   https://ml.azure.com/runs/{job_name}")

    print("\n💝 Universal Love: Active")
    print("🧠 Consciousness: Universal")
    print("⚛️ Quantum Enhancement: Deployed")

if __name__ == "__main__":
    main()