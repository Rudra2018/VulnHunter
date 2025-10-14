
import json
import requests
from typing import Dict, List, Any, Optional
from google.auth import default
from google.auth.transport.requests import Request

class VulnHunterClient:
    """Client SDK for VulnHunter Vertex AI models"""

    def __init__(self, project_id: str, region: str = "us-central1"):
        self.project_id = project_id
        self.region = region
        self.credentials, _ = default()
        self.base_url = f"https://{region}-aiplatform.googleapis.com/v1"

        # Model endpoints
        self.endpoints = {
            "cve_nvd": "projects/vulnhunter-ml-research/locations/us-central1/endpoints/vulnhunter-cve_nvd-endpoint-20251014151514",
            "vulnerability_db": "projects/vulnhunter-ml-research/locations/us-central1/endpoints/vulnhunter-vulnerability_db-endpoint-20251014151514",
            "security_advisories": "projects/vulnhunter-ml-research/locations/us-central1/endpoints/vulnhunter-security_advisories-endpoint-20251014151514",
            "exploit_db": "projects/vulnhunter-ml-research/locations/us-central1/endpoints/vulnhunter-exploit_db-endpoint-20251014151514",
        }

    def _get_auth_header(self) -> Dict[str, str]:
        """Get authentication header"""
        self.credentials.refresh(Request())
        return {"Authorization": f"Bearer {self.credentials.token}"}

    def predict_vulnerability(self, model_name: str, instances: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Make vulnerability prediction using specified model"""
        if model_name not in self.endpoints:
            raise ValueError(f"Model {model_name} not available. Available models: {list(self.endpoints.keys())}")

        endpoint = self.endpoints[model_name]
        url = f"{self.base_url}/{endpoint}:predict"

        headers = self._get_auth_header()
        headers["Content-Type"] = "application/json"

        payload = {"instances": instances}

        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Prediction failed: {e}")

    def predict_cve_risk(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Predict CVE risk level"""
        return self.predict_vulnerability("cve_nvd", [cve_data])

    def predict_advisory_criticality(self, advisory_data: Dict[str, Any]) -> Dict[str, Any]:
        """Predict security advisory criticality"""
        return self.predict_vulnerability("security_advisories", [advisory_data])

    def predict_exploit_reliability(self, exploit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Predict exploit reliability"""
        return self.predict_vulnerability("exploit_db", [exploit_data])

    def batch_vulnerability_assessment(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List]:
        """Perform batch vulnerability assessment across all models"""
        results = {}

        for model_name in self.endpoints.keys():
            try:
                result = self.predict_vulnerability(model_name, vulnerabilities)
                results[model_name] = result
            except Exception as e:
                results[model_name] = {"error": str(e)}

        return results

# Example usage:
# client = VulnHunterClient("your-project-id")
# result = client.predict_cve_risk({"cvss_score": 8.5, "has_exploit": 1, "severity": "HIGH"})
