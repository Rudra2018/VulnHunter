#!/usr/bin/env python3
"""
Simplified Smart Contract Security Data Collector
Enhanced version for Azure ML retraining pipeline
"""

import os
import sys
import json
import time
import requests
import subprocess
from pathlib import Path
from datetime import datetime
import git
from bs4 import BeautifulSoup
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Add the parent directories to path for imports
sys.path.append('/Users/ankitthakur/vuln_ml_research')
sys.path.append('/Users/ankitthakur/vuln_ml_research/models')

# Import our learning module
try:
    from learning_module import SmartContractLearningModule
    print("✅ Successfully imported learning module")
except ImportError as e:
    print(f"⚠️ Could not import learning module: {e}")
    # Create a minimal version if import fails
    class SmartContractLearningModule:
        def __init__(self):
            self.domain = "smart_contract"

        def extract_features(self, code, metadata=None):
            return {
                'length': len(code),
                'function_count': code.count('function'),
                'contract_count': code.count('contract'),
                'modifier_count': code.count('modifier'),
                'external_count': code.count('external'),
                'public_count': code.count('public'),
                'private_count': code.count('private'),
                'payable_count': code.count('payable'),
                'reentrancy_patterns': code.count('msg.sender') + code.count('msg.value'),
                'overflow_patterns': code.count('+=') + code.count('-='),
                'access_control_patterns': code.count('onlyOwner') + code.count('require('),
                'timestamp_dependency': code.count('block.timestamp') + code.count('now'),
                'random_patterns': code.count('random') + code.count('blockhash'),
                'gas_patterns': code.count('gas') + code.count('gasLeft'),
                'delegatecall_patterns': code.count('delegatecall'),
                'selfdestruct_patterns': code.count('selfdestruct'),
                'assembly_patterns': code.count('assembly'),
                'unchecked_patterns': code.count('unchecked'),
                'safe_math_patterns': code.count('SafeMath'),
                'oracle_patterns': code.count('oracle') + code.count('price'),
            }

class ComprehensiveDataCollector:
    """Comprehensive data collector for VulnHunter retraining"""

    def __init__(self, base_dir="/Users/ankitthakur/vuln_ml_research"):
        self.base_dir = Path(base_dir)
        self.data_dir = self.base_dir / "training_data"
        self.data_dir.mkdir(exist_ok=True)

        # Initialize learning module
        self.learning_module = SmartContractLearningModule()

        # Training data storage
        self.vulnerability_data = []
        self.false_positive_data = []
        self.audit_report_data = []

        print(f"📁 Data collection directory: {self.data_dir}")

    def collect_github_repositories(self, repo_urls):
        """Collect source code from GitHub repositories"""
        print("\n🔍 Collecting GitHub repository data...")

        for repo_url in repo_urls:
            try:
                print(f"  📥 Cloning: {repo_url}")
                repo_name = repo_url.split('/')[-1].replace('.git', '')
                local_path = self.data_dir / "repos" / repo_name

                if local_path.exists():
                    print(f"    ℹ️ Repository already exists: {local_path}")
                    continue

                # Create repos directory
                local_path.parent.mkdir(exist_ok=True, parents=True)

                # Clone with timeout
                result = subprocess.run([
                    'timeout', '180s', 'git', 'clone', '--depth', '1', repo_url, str(local_path)
                ], capture_output=True, text=True, timeout=200)

                if result.returncode == 0:
                    print(f"    ✅ Successfully cloned: {repo_name}")
                    self._analyze_repository(local_path, repo_name)
                else:
                    print(f"    ❌ Failed to clone {repo_name}: {result.stderr}")

            except Exception as e:
                print(f"    ❌ Error processing {repo_url}: {e}")

        print(f"✅ GitHub collection complete. Found {len(self.vulnerability_data)} vulnerability patterns")

    def _analyze_repository(self, repo_path, repo_name):
        """Analyze a single repository for vulnerability patterns"""
        try:
            solidity_files = list(repo_path.rglob("*.sol"))

            for sol_file in solidity_files[:50]:  # Limit to avoid overwhelming
                try:
                    with open(sol_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Extract features using learning module
                    features = self.learning_module.extract_features(content)

                    # Determine if this looks like vulnerable code
                    vulnerability_score = self._calculate_vulnerability_score(content, features)

                    data_point = {
                        'file_path': str(sol_file.relative_to(repo_path)),
                        'repository': repo_name,
                        'content': content[:5000],  # Limit content size
                        'features': features,
                        'vulnerability_score': vulnerability_score,
                        'is_vulnerable': vulnerability_score > 0.6,
                        'source': 'github',
                        'timestamp': datetime.now().isoformat()
                    }

                    if vulnerability_score > 0.6:
                        self.vulnerability_data.append(data_point)
                    else:
                        self.false_positive_data.append(data_point)

                except Exception as e:
                    print(f"      ⚠️ Error analyzing {sol_file}: {e}")

        except Exception as e:
            print(f"    ⚠️ Error analyzing repository {repo_name}: {e}")

    def _calculate_vulnerability_score(self, content, features):
        """Calculate a vulnerability score based on known patterns"""
        score = 0.0

        # High-risk patterns
        high_risk_patterns = [
            'msg.sender.call', 'delegatecall', 'selfdestruct',
            'block.timestamp', 'block.difficulty', 'blockhash',
            'tx.origin', 'suicide'
        ]

        # Medium-risk patterns
        medium_risk_patterns = [
            'transfer(', 'send(', 'call.value',
            'require(', 'assert(', 'revert(',
            'modifier', 'onlyOwner'
        ]

        # Count patterns
        for pattern in high_risk_patterns:
            if pattern in content:
                score += 0.3

        for pattern in medium_risk_patterns:
            if pattern in content:
                score += 0.1

        # Complexity factors
        if features['function_count'] > 20:
            score += 0.2
        if features['external_count'] > 5:
            score += 0.15
        if features['payable_count'] > 0:
            score += 0.1

        return min(score, 1.0)

    def collect_bug_bounty_data(self, platforms):
        """Collect data from bug bounty platforms"""
        print("\n🐛 Collecting bug bounty platform data...")

        for platform in platforms:
            try:
                print(f"  📡 Fetching: {platform}")

                if 'sherlock' in platform:
                    self._collect_sherlock_data(platform)
                elif 'immunefi' in platform:
                    self._collect_immunefi_data(platform)
                else:
                    self._collect_generic_platform_data(platform)

            except Exception as e:
                print(f"    ❌ Error collecting from {platform}: {e}")

        print(f"✅ Bug bounty collection complete. Found {len(self.audit_report_data)} audit reports")

    def _collect_sherlock_data(self, url):
        """Collect Sherlock audit data"""
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Look for audit reports and vulnerability information
                audit_links = soup.find_all('a', href=True)

                for link in audit_links[:10]:  # Limit to avoid overwhelming
                    href = link.get('href', '')
                    if '/audits/' in href or '/contests/' in href:
                        self.audit_report_data.append({
                            'platform': 'sherlock',
                            'url': href,
                            'title': link.get_text(strip=True),
                            'source': 'sherlock_audit',
                            'timestamp': datetime.now().isoformat()
                        })

        except Exception as e:
            print(f"    ⚠️ Sherlock collection error: {e}")

    def _collect_immunefi_data(self, url):
        """Collect Immunefi bug bounty data"""
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Look for bug bounty programs
                program_elements = soup.find_all(['div', 'a'], class_=lambda x: x and 'bounty' in x.lower())

                for element in program_elements[:10]:
                    self.audit_report_data.append({
                        'platform': 'immunefi',
                        'content': element.get_text(strip=True),
                        'source': 'immunefi_bounty',
                        'timestamp': datetime.now().isoformat()
                    })

        except Exception as e:
            print(f"    ⚠️ Immunefi collection error: {e}")

    def _collect_generic_platform_data(self, url):
        """Collect data from generic platforms"""
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Extract relevant security-related content
                security_terms = ['vulnerability', 'exploit', 'bug', 'security', 'audit']
                text_content = soup.get_text().lower()

                for term in security_terms:
                    if term in text_content:
                        self.audit_report_data.append({
                            'platform': 'generic',
                            'url': url,
                            'content_snippet': text_content[:1000],
                            'security_term': term,
                            'source': 'generic_platform',
                            'timestamp': datetime.now().isoformat()
                        })
                        break

        except Exception as e:
            print(f"    ⚠️ Generic platform collection error: {e}")

    def train_enhanced_model(self):
        """Train enhanced model with collected data"""
        print("\n🧠 Training enhanced VulnHunter model...")

        if not self.vulnerability_data and not self.false_positive_data:
            print("    ⚠️ No training data available")
            return None

        # Prepare training data
        X_texts = []
        y_labels = []

        # Add vulnerability data
        for data in self.vulnerability_data:
            X_texts.append(data['content'])
            y_labels.append(1)  # Vulnerable

        # Add false positive data
        for data in self.false_positive_data:
            X_texts.append(data['content'])
            y_labels.append(0)  # Not vulnerable

        if len(set(y_labels)) < 2:
            print("    ⚠️ Need both vulnerable and non-vulnerable samples")
            return None

        print(f"    📊 Training data: {len(X_texts)} samples")
        print(f"    📊 Vulnerable: {sum(y_labels)} / Non-vulnerable: {len(y_labels) - sum(y_labels)}")

        # Vectorize text data
        vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        X_vectors = vectorizer.fit_transform(X_texts)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_vectors, y_labels, test_size=0.2, random_state=42
        )

        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"    ✅ Model trained successfully!")
        print(f"    📊 Accuracy: {accuracy:.3f}")
        print(f"    📊 Classification Report:")
        print(classification_report(y_test, y_pred))

        # Save model
        model_path = self.data_dir / "enhanced_vulnhunter_model.pkl"
        vectorizer_path = self.data_dir / "enhanced_vulnhunter_vectorizer.pkl"

        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(vectorizer, f)

        print(f"    💾 Model saved to: {model_path}")
        print(f"    💾 Vectorizer saved to: {vectorizer_path}")

        return {
            'model': model,
            'vectorizer': vectorizer,
            'accuracy': accuracy,
            'training_samples': len(X_texts)
        }

    def save_training_data(self):
        """Save collected training data"""
        print("\n💾 Saving training data...")

        # Save vulnerability data
        vuln_file = self.data_dir / "vulnerability_data.json"
        with open(vuln_file, 'w') as f:
            json.dump(self.vulnerability_data, f, indent=2)

        # Save false positive data
        fp_file = self.data_dir / "false_positive_data.json"
        with open(fp_file, 'w') as f:
            json.dump(self.false_positive_data, f, indent=2)

        # Save audit report data
        audit_file = self.data_dir / "audit_report_data.json"
        with open(audit_file, 'w') as f:
            json.dump(self.audit_report_data, f, indent=2)

        print(f"    ✅ Vulnerability data: {len(self.vulnerability_data)} samples -> {vuln_file}")
        print(f"    ✅ False positive data: {len(self.false_positive_data)} samples -> {fp_file}")
        print(f"    ✅ Audit report data: {len(self.audit_report_data)} samples -> {audit_file}")

        # Create training summary
        summary = {
            'collection_date': datetime.now().isoformat(),
            'vulnerability_samples': len(self.vulnerability_data),
            'false_positive_samples': len(self.false_positive_data),
            'audit_report_samples': len(self.audit_report_data),
            'total_samples': len(self.vulnerability_data) + len(self.false_positive_data) + len(self.audit_report_data)
        }

        summary_file = self.data_dir / "training_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"    📊 Training summary saved to: {summary_file}")

        return summary

def main():
    """Main execution function"""
    print("🚀 VulnHunter Enhanced Training Data Collection")
    print("=" * 60)

    # Initialize collector
    collector = ComprehensiveDataCollector()

    # GitHub repositories to analyze
    github_repos = [
        "https://github.com/PatrickAlphaC/smart-contract-frameworks",
        "https://github.com/smartcontractkit/external-adapters-js",
        "https://github.com/usual-dao/usual-v1",
        "https://github.com/usual-dao/contracts",
        "https://github.com/equilibria-xyz/perennial-v2",
        "https://github.com/sherlock-protocol/sherlock-v2-core"
    ]

    # Bug bounty platforms
    bounty_platforms = [
        "https://audits.sherlock.xyz/bug-bounties",
        "https://immunefi.com/bounties",
        "https://docs.sherlock.xyz/audits/judging",
        "https://cantina.xyz/bounties"
    ]

    # Collect data
    collector.collect_github_repositories(github_repos)
    collector.collect_bug_bounty_data(bounty_platforms)

    # Save training data
    summary = collector.save_training_data()

    # Train enhanced model
    model_results = collector.train_enhanced_model()

    # Final report
    print("\n" + "=" * 60)
    print("🎯 ENHANCED TRAINING COMPLETE")
    print("=" * 60)
    print(f"📊 Total samples collected: {summary['total_samples']}")
    if model_results:
        print(f"🧠 Model accuracy: {model_results['accuracy']:.3f}")
        print(f"🎯 Training samples used: {model_results['training_samples']}")
    print(f"💾 Data directory: {collector.data_dir}")
    print("✅ Ready for Azure ML deployment!")

if __name__ == "__main__":
    main()