#!/usr/bin/env python3
"""
GPU Quota Request Script for VulnHunter V10 Massive Scale Training
Requests increased quota for H100/A100 GPUs to support 175B parameter model training
"""

import subprocess
import json
import logging
from dataclasses import dataclass
from typing import Dict, List

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class GPUQuotaRequest:
    """GPU quota request configuration"""
    subscription_id: str = "1eb36cb9-986d-49ea-9305-0a3bf656778c"
    resource_group: str = "vulnhunter-v10-rg"
    location: str = "eastus2"

    # Target GPU quotas for massive scale training
    target_quotas = {
        'StandardNCadsH100v5Family': 320,    # H100 GPUs (8x40 = 320 cores)
        'StandardNCADSA100v4Family': 192,    # A100 GPUs (4x48 = 192 cores)
        'Standard NCASv3_T4 Family': 128,    # T4 GPUs (32x4 = 128 cores)
        'standardNCSv3Family': 96,           # V100 GPUs (4x24 = 96 cores)
    }

class GPUQuotaManager:
    """Manages GPU quota requests for VulnHunter V10"""

    def __init__(self, config: GPUQuotaRequest):
        self.config = config

    def check_current_quotas(self) -> Dict[str, Dict]:
        """Check current GPU quotas"""
        logger.info("📊 Checking current GPU quotas...")

        try:
            result = subprocess.run([
                'az', 'vm', 'list-usage',
                '--location', self.config.location
            ], capture_output=True, text=True, check=True)

            usage_data = json.loads(result.stdout)
            gpu_quotas = {}

            for item in usage_data:
                name = item.get('name', {}).get('value', '')
                if any(gpu_family in name for gpu_family in ['NC', 'ND', 'NV']):
                    gpu_quotas[name] = {
                        'current': item.get('currentValue', 0),
                        'limit': item.get('limit', 0),
                        'usage_percent': (item.get('currentValue', 0) / max(item.get('limit', 1), 1)) * 100
                    }

            return gpu_quotas

        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to check quotas: {e}")
            return {}

    def request_quota_increase(self, family: str, target_cores: int) -> bool:
        """Request quota increase for specific GPU family"""
        logger.info(f"📈 Requesting quota increase for {family}: {target_cores} cores")

        # Create support request for quota increase
        request_data = {
            "severity": "high",
            "problem_classification": {
                "service_id": "06bfd9d3-516b-d5c6-5802-169c800dec89",  # Compute
                "problem_type_id": "13491426-ee93-4e0e-89a5-8e7b82e8d44e",  # Quota
                "category_id": "ce918c0a-d9fd-4e87-8e8f-6b10ac7a6fa1"   # Cores
            },
            "title": f"VulnHunter V10 GPU Quota Increase Request - {family}",
            "description": f"""
Request for GPU quota increase to support VulnHunter V10 massive scale AI training:

Family: {family}
Requested Cores: {target_cores}
Use Case: Revolutionary vulnerability detection AI system training
Model Scale: 175B parameters
Dataset Scale: 20M+ samples across 6 domains
Business Justification: Academic research and cybersecurity advancement

Technical Requirements:
- Distributed training across multiple GPU nodes
- High-performance computing for deep learning workloads
- Time-sensitive research project with publication deadlines

This quota increase is essential for advancing state-of-the-art cybersecurity AI research.
            """,
            "contact_details": {
                "first_name": "Ankit",
                "last_name": "Thakur",
                "preferred_contact_method": "email",
                "primary_email_address": "at87.at17@gmail.com"
            }
        }

        logger.info(f"✅ Quota increase request prepared for {family}")
        logger.info("📝 Please submit this request through Azure Portal > Support")
        return True

    def create_quota_request_summary(self) -> Dict:
        """Create summary of all quota requests"""
        logger.info("📋 Creating quota request summary...")

        current_quotas = self.check_current_quotas()
        requests_needed = []

        for family, target in self.config.target_quotas.items():
            current = current_quotas.get(family, {}).get('limit', 0)
            if current < target:
                requests_needed.append({
                    'family': family,
                    'current_limit': current,
                    'target_limit': target,
                    'increase_needed': target - current,
                    'justification': self._get_justification(family)
                })

        summary = {
            'subscription_id': self.config.subscription_id,
            'location': self.config.location,
            'current_quotas': current_quotas,
            'requests_needed': requests_needed,
            'total_requests': len(requests_needed)
        }

        return summary

    def _get_justification(self, family: str) -> str:
        """Get justification for specific GPU family"""
        justifications = {
            'StandardNCadsH100v5Family': 'H100 GPUs required for 175B parameter model training with optimal performance',
            'StandardNCADSA100v4Family': 'A100 GPUs needed for large-scale tensor operations and memory requirements',
            'Standard NCASv3_T4 Family': 'T4 GPUs for distributed inference and model validation workloads',
            'standardNCSv3Family': 'V100 GPUs for legacy compatibility and development workloads'
        }
        return justifications.get(family, 'GPU resources needed for VulnHunter V10 training')

    def generate_support_requests(self):
        """Generate support requests for all needed quotas"""
        logger.info("🎯 Generating GPU quota support requests...")

        summary = self.create_quota_request_summary()

        print("\n" + "="*80)
        print("🚀 VULNHUNTER V10 GPU QUOTA REQUEST SUMMARY")
        print("="*80)
        print(f"📍 Location: {self.config.location}")
        print(f"🔧 Subscription: {self.config.subscription_id}")
        print(f"📊 Requests Needed: {summary['total_requests']}")
        print("="*80)

        for request in summary['requests_needed']:
            print(f"\n🎯 {request['family']}:")
            print(f"  Current Limit: {request['current_limit']} cores")
            print(f"  Target Limit: {request['target_limit']} cores")
            print(f"  Increase Needed: {request['increase_needed']} cores")
            print(f"  Justification: {request['justification']}")

            # Create the actual support request
            self.request_quota_increase(request['family'], request['target_limit'])

        print("\n" + "="*80)
        print("📝 NEXT STEPS:")
        print("1. Visit Azure Portal > Help + Support > New Support Request")
        print("2. Submit quota increase requests for each GPU family listed above")
        print("3. Wait for approval (typically 24-48 hours)")
        print("4. Once approved, create GPU clusters for VulnHunter V10 training")
        print("="*80)

def main():
    """Main function to request GPU quotas"""
    print("🚀 VulnHunter V10 GPU Quota Request Manager")
    print("=" * 50)

    # Create configuration
    config = GPUQuotaRequest()

    # Create quota manager
    manager = GPUQuotaManager(config)

    # Generate support requests
    manager.generate_support_requests()

if __name__ == "__main__":
    main()