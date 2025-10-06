#!/usr/bin/env python3
"""
Prepare comprehensive training data from all security audits for ML model
Combines: Electroneum (343 verified), Auth0 (409 FPs), New Relic (161 verified)
"""

import json
import pandas as pd
from pathlib import Path
from collections import defaultdict

def load_electroneum_data():
    """Load verified Electroneum vulnerabilities"""
    data_file = Path('electroneum_analysis/electroneum_verified_results_v2.json')
    if not data_file.exists():
        print(f"⚠️  {data_file} not found, skipping Electroneum data")
        return []
    
    with open(data_file, 'r') as f:
        data = json.load(f)
    
    samples = []
    for vuln in data['verified_vulnerabilities_list']:
        orig = vuln['original_finding']
        samples.append({
            'code': orig['line_content'],
            'file_path': orig['file'],
            'category': orig['category'],
            'severity': orig['severity'],
            'cwe': orig['cwe'],
            'confidence': orig['confidence'],
            'language': 'C/C++',
            'project': 'Electroneum',
            'is_vulnerable': 1,  # Verified true positive
            'context': '\n'.join(orig.get('context', [])[:3])
        })
    
    print(f"✓ Loaded {len(samples)} Electroneum vulnerabilities")
    return samples

def load_auth0_data():
    """Load Auth0 false positives (important for FP learning)"""
    data_file = Path('auth0_analysis/auth0_verified_results.json')
    if not data_file.exists():
        print(f"⚠️  {data_file} not found, skipping Auth0 data")
        return []
    
    with open(data_file, 'r') as f:
        data = json.load(f)
    
    samples = []
    # Use false positives to train FP detection
    for fp in data.get('false_positives_list', [])[:200]:  # Limit to 200 for balance
        orig = fp['original_finding']
        samples.append({
            'code': orig['line_content'],
            'file_path': orig['file'],
            'category': orig['category'],
            'severity': orig['severity'],
            'cwe': orig['cwe'],
            'confidence': orig['confidence'],
            'language': 'JavaScript/TypeScript',
            'project': 'Auth0',
            'is_vulnerable': 0,  # False positive
            'context': '\n'.join(orig.get('context', [])[:3])
        })
    
    print(f"✓ Loaded {len(samples)} Auth0 false positives")
    return samples

def load_newrelic_data():
    """Load New Relic verified vulnerabilities"""
    samples = []
    
    for agent in ['python', 'nodejs', 'infrastructure']:
        data_file = Path(f'newrelic_analysis/{agent}_verified_results.json')
        if not data_file.exists():
            print(f"⚠️  {data_file} not found, skipping {agent}")
            continue
        
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        # Add verified vulnerabilities
        for vuln in data['verified_vulnerabilities_list']:
            orig = vuln['original_finding']
            
            # Filter out test files
            if '/test' in orig['file'] or 'test/' in orig['file']:
                continue
                
            lang_map = {'python': 'Python', 'nodejs': 'JavaScript', 'infrastructure': 'Go'}
            
            samples.append({
                'code': orig['line_content'],
                'file_path': orig['file'],
                'category': orig['category'],
                'severity': orig['severity'],
                'cwe': orig['cwe'],
                'confidence': orig['confidence'],
                'language': lang_map[agent],
                'project': f'NewRelic-{agent}',
                'is_vulnerable': 1,  # Verified
                'context': '\n'.join(orig.get('context', [])[:3])
            })
        
        # Add some false positives for balance
        for fp in data.get('false_positives_list', [])[:50]:
            orig = fp['original_finding']
            samples.append({
                'code': orig['line_content'],
                'file_path': orig['file'],
                'category': orig['category'],
                'severity': orig['severity'],
                'cwe': orig['cwe'],
                'confidence': orig['confidence'],
                'language': lang_map[agent],
                'project': f'NewRelic-{agent}',
                'is_vulnerable': 0,  # False positive
                'context': '\n'.join(orig.get('context', [])[:3])
            })
    
    print(f"✓ Loaded {len(samples)} New Relic samples")
    return samples

def create_features(df):
    """Create ML features from vulnerability data"""
    
    # Code pattern features
    df['code_length'] = df['code'].str.len()
    df['has_exec'] = df['code'].str.contains('exec|eval', case=False, regex=True).astype(int)
    df['has_sql'] = df['code'].str.contains('select|insert|update|delete', case=False, regex=True).astype(int)
    df['has_memcpy'] = df['code'].str.contains('memcpy|strcpy|sprintf', case=False, regex=True).astype(int)
    df['has_password'] = df['code'].str.contains('password|secret|key', case=False, regex=True).astype(int)
    df['has_verify_false'] = df['code'].str.contains('verify.*false|ssl.*false', case=False, regex=True).astype(int)
    
    # File path features
    df['is_test_file'] = df['file_path'].str.contains('test|spec|example', case=False, regex=True).astype(int)
    df['is_config_file'] = df['file_path'].str.contains('config|settings', case=False, regex=True).astype(int)
    
    # Context features
    df['context_length'] = df['context'].str.len()
    df['context_has_bounds_check'] = df['context'].str.contains('if.*<|if.*>|assert|check', case=False, regex=True).astype(int)
    
    # Severity encoding
    severity_map = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
    df['severity_encoded'] = df['severity'].map(severity_map)
    
    # Language encoding (one-hot)
    df_lang = pd.get_dummies(df['language'], prefix='lang')
    df = pd.concat([df, df_lang], axis=1)
    
    # Category encoding (one-hot)
    df_cat = pd.get_dummies(df['category'], prefix='cat')
    df = pd.concat([df, df_cat], axis=1)
    
    return df

def main():
    print("="*80)
    print("Preparing ML Training Data from Security Audits")
    print("="*80)
    
    # Load all datasets
    all_samples = []
    all_samples.extend(load_electroneum_data())
    all_samples.extend(load_auth0_data())
    all_samples.extend(load_newrelic_data())
    
    if not all_samples:
        print("\n❌ No data loaded! Check file paths.")
        return
    
    print(f"\n{'='*80}")
    print(f"Total samples loaded: {len(all_samples)}")
    print(f"{'='*80}")
    
    # Create DataFrame
    df = pd.DataFrame(all_samples)
    
    # Show distribution
    print("\nDataset Distribution:")
    print(f"  Vulnerable (1): {(df['is_vulnerable']==1).sum()}")
    print(f"  Safe (0): {(df['is_vulnerable']==0).sum()}")
    print(f"\nBy Project:")
    print(df['project'].value_counts())
    print(f"\nBy Language:")
    print(df['language'].value_counts())
    print(f"\nBy Category:")
    print(df['category'].value_counts().head(10))
    
    # Create features
    print(f"\n{'='*80}")
    print("Creating ML Features...")
    print(f"{'='*80}")
    df_features = create_features(df)
    
    # Save datasets
    df_features.to_csv('ml_training_data.csv', index=False)
    print(f"\n✓ Training data saved: ml_training_data.csv")
    print(f"  Total samples: {len(df_features)}")
    print(f"  Total features: {len(df_features.columns)}")
    
    # Save summary
    summary = {
        'total_samples': len(df_features),
        'vulnerable': int((df_features['is_vulnerable']==1).sum()),
        'safe': int((df_features['is_vulnerable']==0).sum()),
        'projects': df['project'].value_counts().to_dict(),
        'languages': df['language'].value_counts().to_dict(),
        'categories': df['category'].value_counts().to_dict(),
        'features': list(df_features.columns)
    }
    
    with open('ml_training_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"✓ Summary saved: ml_training_summary.json")
    
    print(f"\n{'='*80}")
    print("✅ Data Preparation Complete!")
    print(f"{'='*80}")
    print(f"Ready for model training with {len(df_features)} samples")

if __name__ == '__main__':
    main()
