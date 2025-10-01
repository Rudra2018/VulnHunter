import os
import requests
import json
import pandas as pd
from typing import List, Dict, Any
import time
from tqdm import tqdm
import subprocess

class DatasetCollector:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.raw_dir = os.path.join(data_dir, "raw")
        self.processed_dir = os.path.join(data_dir, "processed")
        
        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
    
    def collect_github_vulnerabilities(self, query: str = "CVE vulnerability", limit: int = 100):
        """Collect vulnerable code from GitHub (for research purposes)"""
        # Note: This is a simplified version. For actual research, you'd need
        # proper GitHub API access and ethical considerations
        
        vulnerable_samples = []
        
        # Sample vulnerable code patterns (for initial testing)
        samples = [
            {
                'code': 'os.system(user_input)',
                'vulnerability_type': 'command_injection',
                'language': 'python',
                'severity': 'high'
            },
            {
                'code': 'eval(user_data)',
                'vulnerability_type': 'code_injection', 
                'language': 'python',
                'severity': 'high'
            },
            {
                'code': 'query = "SELECT * FROM users WHERE id = " + user_id',
                'vulnerability_type': 'sql_injection',
                'language': 'python',
                'severity': 'high'
            }
        ]
        
        return samples
    
    def collect_cve_data(self):
        """Collect CVE data from NVD"""
        try:
            # Fetch recent CVEs
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"
            response = requests.get(url)
            if response.status_code == 200:
                cve_data = response.json()
                return cve_data
            else:
                print(f"Failed to fetch CVE data: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error fetching CVE data: {e}")
            return None
    
    def create_training_samples(self):
        """Create training samples from collected data"""
        # This will create positive (vulnerable) and negative (safe) samples
        
        positive_samples = self.collect_github_vulnerabilities()
        
        # Create negative samples (safe code)
        negative_samples = [
            {
                'code': 'subprocess.run(["ls", "-l"], capture_output=True)',
                'vulnerability_type': 'none',
                'language': 'python', 
                'severity': 'none'
            },
            {
                'code': 'import html; html.escape(user_input)',
                'vulnerability_type': 'none',
                'language': 'python',
                'severity': 'none'
            }
        ]
        
        # Combine and save
        all_samples = positive_samples + negative_samples
        df = pd.DataFrame(all_samples)
        df.to_csv(os.path.join(self.processed_dir, "training_samples.csv"), index=False)
        
        return df

if __name__ == "__main__":
    collector = DatasetCollector()
    print("Collecting training data...")
    df = collector.create_training_samples()
    print(f"Created {len(df)} training samples")
    print(df.head())
