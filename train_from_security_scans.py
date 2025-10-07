#!/usr/bin/env python3
"""
Train VulnHunter Models from Security Scan Results
=================================================

Converts security findings from recent scans into training data
and updates the ML models with new patterns.

Sources:
- Google OSS analysis
- Facebook OSS analysis
- kDrive analysis
- Lightway VPN analysis
- ML/AI comprehensive analysis
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter
import pickle
import os


class SecurityScanTrainer:
    """Train models from security scan results"""

    def __init__(self):
        self.training_data = []
        self.statistics = Counter()

    def load_ml_ai_findings(self):
        """Load ML/AI comprehensive scan findings"""
        print("📥 Loading ML/AI findings...")

        json_path = Path("~/Downloads/ml_ai_comprehensive/ml_ai_analysis.json").expanduser()
        if not json_path.exists():
            print(f"⚠️ ML/AI analysis not found at {json_path}")
            return

        with open(json_path) as f:
            data = json.load(f)

        findings = data.get('findings', [])
        print(f"   Found {len(findings):,} ML/AI findings")

        # Convert to training samples
        for finding in findings:
            # Extract features
            sample = {
                'code': finding.get('code', ''),
                'context': finding.get('context', ''),
                'function': finding.get('function', ''),
                'category': finding.get('category', ''),
                'severity': finding.get('severity', ''),
                'cwe': finding.get('cwe', ''),
                'language': finding.get('language', 'Python'),
                'project_type': 'ML/AI',
                'is_vulnerable': 1,  # All findings are flagged as vulnerable
                'source': f"ML/AI:{finding.get('project', 'unknown')}",
            }

            self.training_data.append(sample)
            self.statistics['ml_ai_samples'] += 1
            self.statistics[f"severity_{finding['severity']}"] += 1

        print(f"✓ Loaded {self.statistics['ml_ai_samples']:,} ML/AI training samples")

    def load_google_oss_findings(self):
        """Load Google OSS dangerous functions analysis"""
        print("📥 Loading Google OSS findings...")

        # Try to find the dangerous functions report
        json_files = [
            "~/Downloads/google_oss_dangerous_functions.json",
            "~/Downloads/DANGEROUS_FUNCTIONS_ANALYSIS.json",
        ]

        for json_file in json_files:
            json_path = Path(json_file).expanduser()
            if json_path.exists():
                with open(json_path) as f:
                    data = json.load(f)

                findings = data.get('verified_findings', data.get('findings', []))
                print(f"   Found {len(findings):,} Google OSS findings")

                for finding in findings:
                    sample = {
                        'code': finding.get('line', finding.get('code', '')),
                        'context': finding.get('context', ''),
                        'function': finding.get('function', ''),
                        'category': finding.get('category', 'Dangerous Function'),
                        'severity': finding.get('severity', 'MEDIUM'),
                        'cwe': finding.get('cwe', 'CWE-693'),
                        'language': finding.get('language', 'Python'),
                        'project_type': 'Web/Infrastructure',
                        'is_vulnerable': 1,
                        'source': f"Google:{finding.get('project', 'unknown')}",
                    }

                    self.training_data.append(sample)
                    self.statistics['google_samples'] += 1

                print(f"✓ Loaded {self.statistics['google_samples']:,} Google OSS samples")
                return

        print("⚠️ Google OSS findings not found")

    def load_kdrive_findings(self):
        """Load kDrive security findings"""
        print("📥 Loading kDrive findings...")

        # kDrive had 1 genuine vulnerability
        sample = {
            'code': 'command = "gio trash \\"" + itemPath.string() + "\\""',
            'context': 'system(command.c_str())',
            'function': 'system',
            'category': 'Command Injection',
            'severity': 'HIGH',
            'cwe': 'CWE-78',
            'language': 'C++',
            'project_type': 'Desktop Application',
            'is_vulnerable': 1,
            'source': 'kDrive:command_injection',
        }

        self.training_data.append(sample)
        self.statistics['kdrive_samples'] += 1

        print(f"✓ Loaded {self.statistics['kdrive_samples']} kDrive sample")

    def load_lightway_findings(self):
        """Load Lightway VPN findings (FFI operations)"""
        print("📥 Loading Lightway VPN findings...")

        # Lightway had 8 documented FFI operations (not vulnerabilities)
        # We'll add these as safe examples

        ffi_examples = [
            {
                'code': 'unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, sz as usize) }',
                'context': '// SAFETY: Per WolfSSL callback rules',
                'function': 'from_raw_parts_mut',
                'category': 'Safe FFI',
                'severity': 'LOW',
                'cwe': 'CWE-119',
                'language': 'Rust',
                'project_type': 'VPN/Security',
                'is_vulnerable': 0,  # Safe when properly documented
                'source': 'Lightway:ffi_safe',
            }
        ]

        for sample in ffi_examples:
            self.training_data.append(sample)
            self.statistics['lightway_samples'] += 1

        print(f"✓ Loaded {self.statistics['lightway_samples']} Lightway samples")

    def generate_training_dataset(self):
        """Generate comprehensive training dataset"""
        print("\n" + "=" * 80)
        print("📊 GENERATING TRAINING DATASET")
        print("=" * 80)

        # Load all findings
        self.load_ml_ai_findings()
        self.load_google_oss_findings()
        self.load_kdrive_findings()
        self.load_lightway_findings()

        print(f"\n✓ Total training samples: {len(self.training_data):,}")

        # Convert to DataFrame
        df = pd.DataFrame(self.training_data)

        # Save to CSV
        output_file = Path("data/security_scan_training_data.csv")
        output_file.parent.mkdir(exist_ok=True)

        df.to_csv(output_file, index=False)
        print(f"💾 Saved training data to: {output_file}")

        # Save statistics
        stats_file = Path("data/security_scan_statistics.json")
        with open(stats_file, 'w') as f:
            json.dump(dict(self.statistics), f, indent=2)

        print(f"📊 Saved statistics to: {stats_file}")

        # Print summary
        print("\n" + "=" * 80)
        print("TRAINING DATA SUMMARY")
        print("=" * 80)

        print(f"\nBy Source:")
        for key, value in self.statistics.items():
            if 'samples' in key:
                print(f"  {key:30s} {value:6,d}")

        print(f"\nBy Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = self.statistics.get(f'severity_{severity}', 0)
            if count > 0:
                print(f"  {severity:30s} {count:6,d}")

        print(f"\nBy Language:")
        lang_counts = Counter(sample['language'] for sample in self.training_data)
        for lang, count in lang_counts.most_common():
            print(f"  {lang:30s} {count:6,d}")

        print(f"\nBy Project Type:")
        type_counts = Counter(sample['project_type'] for sample in self.training_data)
        for ptype, count in type_counts.most_common():
            print(f"  {ptype:30s} {count:6,d}")

        return df

    def train_updated_models(self, df: pd.DataFrame):
        """Train/update ML models with new data"""
        print("\n" + "=" * 80)
        print("🧠 TRAINING UPDATED MODELS")
        print("=" * 80)

        # Feature engineering
        print("\n1️⃣ Feature Engineering...")

        # Text features
        df['code_length'] = df['code'].str.len()
        df['has_eval'] = df['code'].str.contains('eval', case=False, na=False).astype(int)
        df['has_exec'] = df['code'].str.contains('exec', case=False, na=False).astype(int)
        df['has_pickle'] = df['code'].str.contains('pickle', case=False, na=False).astype(int)
        df['has_torch_load'] = df['code'].str.contains('torch.load', case=False, na=False).astype(int)
        df['has_subprocess'] = df['code'].str.contains('subprocess', case=False, na=False).astype(int)
        df['has_system'] = df['code'].str.contains('system', case=False, na=False).astype(int)
        df['has_shell_true'] = df['code'].str.contains('shell.*=.*true', case=False, na=False, regex=True).astype(int)

        # Severity encoding
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        df['severity_score'] = df['severity'].map(severity_map).fillna(0)

        # Language encoding
        language_map = {'Python': 1, 'JavaScript': 2, 'C++': 3, 'C': 4, 'Rust': 5, 'Java': 6}
        df['language_code'] = df['language'].map(language_map).fillna(0)

        print(f"   ✓ Engineered {df.shape[1]} features")

        # Select features for training
        feature_columns = [
            'code_length',
            'has_eval', 'has_exec', 'has_pickle', 'has_torch_load',
            'has_subprocess', 'has_system', 'has_shell_true',
            'severity_score', 'language_code',
        ]

        X = df[feature_columns].fillna(0)
        y = df['is_vulnerable']

        print(f"   ✓ Training set: {X.shape[0]:,} samples, {X.shape[1]} features")
        print(f"   ✓ Vulnerable: {y.sum():,} ({y.mean()*100:.1f}%)")
        print(f"   ✓ Safe: {(~y.astype(bool)).sum():,} ({(1-y.mean())*100:.1f}%)")

        # Train simple model (for demonstration)
        print("\n2️⃣ Training Binary Classifier...")

        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split

        # Handle imbalanced dataset - don't stratify if too few samples in one class
        if y.sum() < 2 or (len(y) - y.sum()) < 2:
            print("   ⚠️ Imbalanced dataset - skipping stratification")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train, y_train)

        # Evaluate
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test)

        print(f"   ✓ Training accuracy: {train_score*100:.2f}%")
        print(f"   ✓ Testing accuracy: {test_score*100:.2f}%")

        # Feature importance
        print("\n3️⃣ Top Feature Importance:")
        importances = model.feature_importances_
        for i in np.argsort(importances)[::-1][:5]:
            print(f"   {feature_columns[i]:30s} {importances[i]:.4f}")

        # Save model
        model_dir = Path("models")
        model_dir.mkdir(exist_ok=True)

        model_file = model_dir / "security_scan_classifier.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump({
                'model': model,
                'features': feature_columns,
                'metadata': {
                    'trained_date': datetime.now().isoformat(),
                    'samples': len(X),
                    'accuracy': test_score,
                    'sources': dict(self.statistics),
                }
            }, f)

        print(f"\n💾 Saved model to: {model_file}")

        return model


def main():
    """Main training pipeline"""
    print("=" * 80)
    print("🎓 VULNHUNTER - LEARN FROM SECURITY SCANS")
    print("=" * 80)
    print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    trainer = SecurityScanTrainer()

    # Generate training dataset
    df = trainer.generate_training_dataset()

    # Train models
    model = trainer.train_updated_models(df)

    print("\n" + "=" * 80)
    print("✅ TRAINING COMPLETE")
    print("=" * 80)
    print(f"End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print("\n📊 Summary:")
    print(f"  - Training samples: {len(df):,}")
    print(f"  - Features: {df.shape[1]}")
    print(f"  - Model saved: models/security_scan_classifier.pkl")
    print(f"  - Data saved: data/security_scan_training_data.csv")


if __name__ == '__main__':
    main()
