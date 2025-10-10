#!/usr/bin/env python3
"""
⚡ Quick Model Validation
Efficient validation of bug bounty prediction models
"""

import numpy as np
import pandas as pd
import sqlite3
from sklearn.model_selection import cross_val_score
from sklearn.metrics import mean_absolute_error, accuracy_score, classification_report
from sklearn.metrics import r2_score as sklearn_r2_score
from sklearn.ensemble import RandomForestRegressor, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import json
from pathlib import Path

def load_and_validate_models():
    """Quick validation of both prediction models"""
    print("⚡ QUICK MODEL VALIDATION")
    print("=" * 40)

    # Database path
    db_path = "bug_bounty_intelligence/bug_bounty_intelligence.db"

    if not Path(db_path).exists():
        print("❌ Database not found. Please run the bug bounty system first.")
        return

    conn = sqlite3.connect(db_path)

    # === BOUNTY PREDICTION VALIDATION ===
    print("\n💰 BOUNTY PREDICTION MODEL VALIDATION")
    print("-" * 40)

    # Load bounty data
    bounty_query = '''
        SELECT vulnerability_type, severity_level, bounty_amount, program_name, dataset_source
        FROM bug_bounty_reports
        WHERE bounty_amount > 0
        UNION ALL
        SELECT vulnerability_type, severity_level, bounty_amount, protocol_name as program_name, 'web3' as dataset_source
        FROM web3_vulnerability_intelligence
        WHERE bounty_amount > 0
        LIMIT 2000
    '''

    bounty_df = pd.read_sql_query(bounty_query, conn)
    print(f"📊 Loaded {len(bounty_df)} bounty records")

    if len(bounty_df) > 20:
        # Prepare features
        features = []
        targets = []

        for _, row in bounty_df.iterrows():
            vuln_type = str(row['vulnerability_type'])
            severity = str(row['severity_level'])
            program = str(row['program_name'])
            source = str(row.get('dataset_source', 'unknown'))

            feature_vector = [
                len(vuln_type),
                1 if 'Critical' in severity else 0,
                1 if 'High' in severity else 0,
                1 if 'Medium' in severity else 0,
                1 if 'Low' in severity else 0,
                len(program),
                1 if 'SQL' in vuln_type.upper() else 0,
                1 if 'XSS' in vuln_type.upper() else 0,
                1 if 'RCE' in vuln_type.upper() or 'REMOTE CODE' in vuln_type.upper() else 0,
                1 if 'SSRF' in vuln_type.upper() else 0,
                1 if 'IDOR' in vuln_type.upper() else 0,
                1 if source == 'web3' else 0,
                hash(vuln_type) % 100,
            ]

            features.append(feature_vector)
            targets.append(row['bounty_amount'])

        X = np.array(features)
        y = np.array(targets)

        # Handle outliers
        y_capped = np.clip(y, np.percentile(y, 5), np.percentile(y, 95))

        # Train and validate model
        model = RandomForestRegressor(n_estimators=50, random_state=42, max_depth=10)

        # Cross-validation
        cv_scores = cross_val_score(model, X, y_capped, cv=3, scoring='r2')

        # Full training for detailed metrics
        model.fit(X, y_capped)
        y_pred = model.predict(X)

        # Metrics
        r2 = sklearn_r2_score(y_capped, y_pred)
        mae = mean_absolute_error(y_capped, y_pred)

        print(f"✅ Cross-Validation R²: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
        print(f"✅ Final R² Score: {r2:.3f}")
        print(f"✅ Mean Absolute Error: ${mae:,.2f}")
        print(f"✅ Target Range: ${y_capped.min():,.2f} - ${y_capped.max():,.2f}")

        # Feature importance
        feature_names = [
            'vuln_complexity', 'critical', 'high', 'medium', 'low',
            'program_length', 'sql_injection', 'xss', 'rce', 'ssrf', 'idor',
            'web3_flag', 'vuln_hash'
        ]

        importance_dict = dict(zip(feature_names, model.feature_importances_))
        top_features = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)[:5]

        print(f"\n🏆 Top 5 Most Important Features:")
        for feature, importance in top_features:
            print(f"  • {feature}: {importance:.3f}")

        bounty_results = {
            'cv_r2_mean': cv_scores.mean(),
            'cv_r2_std': cv_scores.std(),
            'r2_score': r2,
            'mae': mae,
            'samples': len(X),
            'feature_importance': importance_dict
        }
    else:
        print("❌ Insufficient bounty data for validation")
        bounty_results = {'error': 'Insufficient data'}

    # === SEVERITY CLASSIFICATION VALIDATION ===
    print(f"\n🎯 SEVERITY CLASSIFICATION MODEL VALIDATION")
    print("-" * 40)

    # Load severity data (sample for efficiency)
    severity_query = '''
        SELECT vulnerability_type, severity_level, dataset_source
        FROM bug_bounty_reports
        WHERE severity_level IS NOT NULL
        UNION ALL
        SELECT vulnerability_type, severity_level, 'web3' as dataset_source
        FROM web3_vulnerability_intelligence
        WHERE severity_level IS NOT NULL
        LIMIT 3000
    '''

    severity_df = pd.read_sql_query(severity_query, conn)
    print(f"📊 Loaded {len(severity_df)} severity records")

    # Check class distribution
    class_counts = severity_df['severity_level'].value_counts()
    print(f"📈 Class Distribution: {dict(class_counts)}")

    if len(severity_df) > 50 and len(class_counts) > 1:
        # Prepare features
        vuln_features = []
        severity_targets = []

        for _, row in severity_df.iterrows():
            vuln_text = str(row['vulnerability_type'])
            source = str(row.get('dataset_source', 'unknown'))
            enhanced_text = f"{vuln_text} {source}"
            vuln_features.append(enhanced_text)
            severity_targets.append(row['severity_level'])

        # Text vectorization (reduced features for speed)
        tfidf = TfidfVectorizer(max_features=500, ngram_range=(1, 2), stop_words='english', min_df=2)
        X_text = tfidf.fit_transform(vuln_features)

        # Label encoding
        label_encoder = LabelEncoder()
        y = label_encoder.fit_transform(severity_targets)

        # Train model
        model = GradientBoostingClassifier(n_estimators=20, random_state=42, max_depth=5)

        # Cross-validation
        cv_scores = cross_val_score(model, X_text.toarray(), y, cv=3, scoring='accuracy')

        # Full training
        model.fit(X_text.toarray(), y)
        y_pred = model.predict(X_text.toarray())

        # Metrics
        accuracy = accuracy_score(y, y_pred)

        print(f"✅ Cross-Validation Accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
        print(f"✅ Final Accuracy: {accuracy:.3f}")
        print(f"✅ Classes: {label_encoder.classes_}")

        # Classification report
        class_report = classification_report(y, y_pred, target_names=label_encoder.classes_, output_dict=True)

        print(f"\n📊 Per-Class Performance:")
        for class_name in label_encoder.classes_:
            if class_name in class_report:
                metrics = class_report[class_name]
                print(f"  • {class_name}: Precision={metrics['precision']:.3f}, Recall={metrics['recall']:.3f}, F1={metrics['f1-score']:.3f}")

        severity_results = {
            'cv_accuracy_mean': cv_scores.mean(),
            'cv_accuracy_std': cv_scores.std(),
            'accuracy': accuracy,
            'samples': len(X_text.toarray()),
            'classes': label_encoder.classes_.tolist(),
            'classification_report': class_report
        }
    else:
        print("❌ Insufficient severity data for validation")
        severity_results = {'error': 'Insufficient data'}

    conn.close()

    # === BENCHMARK VALIDATION ===
    print(f"\n📋 BENCHMARK VALIDATION")
    print("-" * 40)

    benchmark_cases = [
        {'vuln': 'Remote Code Execution', 'severity': 'Critical', 'program': 'Google', 'expected': (25000, 100000)},
        {'vuln': 'SQL Injection', 'severity': 'High', 'program': 'PayPal', 'expected': (5000, 25000)},
        {'vuln': 'Cross-site Scripting (XSS)', 'severity': 'Medium', 'program': 'Facebook', 'expected': (500, 5000)},
        {'vuln': 'Server-Side Request Forgery (SSRF)', 'severity': 'High', 'program': 'Microsoft', 'expected': (2000, 20000)}
    ]

    benchmark_accurate = 0
    total_benchmarks = len(benchmark_cases)

    if 'error' not in bounty_results:
        print("💰 Bounty Predictions vs Expected Ranges:")

        for case in benchmark_cases:
            # Create feature vector for prediction
            vuln_type = case['vuln']
            severity = case['severity']
            program = case['program']

            feature_vector = np.array([[
                len(vuln_type),
                1 if 'Critical' in severity else 0,
                1 if 'High' in severity else 0,
                1 if 'Medium' in severity else 0,
                1 if 'Low' in severity else 0,
                len(program),
                1 if 'SQL' in vuln_type.upper() else 0,
                1 if 'XSS' in vuln_type.upper() else 0,
                1 if 'RCE' in vuln_type.upper() or 'REMOTE CODE' in vuln_type.upper() else 0,
                1 if 'SSRF' in vuln_type.upper() else 0,
                1 if 'IDOR' in vuln_type.upper() else 0,
                0,  # web3 flag
                hash(vuln_type) % 100,
            ]])

            # Predict using the same model setup
            try:
                # Recreate model for prediction (quick setup)
                quick_model = RandomForestRegressor(n_estimators=50, random_state=42, max_depth=10)
                quick_model.fit(X, y_capped)
                prediction = quick_model.predict(feature_vector)[0]
                prediction = max(0, prediction)

                expected_min, expected_max = case['expected']
                within_range = expected_min <= prediction <= expected_max

                if within_range:
                    benchmark_accurate += 1
                    status = "✅"
                else:
                    status = "❌"

                print(f"  {status} {vuln_type} ({severity}): ${prediction:,.2f} [Expected: ${expected_min:,}-${expected_max:,}]")

            except Exception as e:
                print(f"  ❌ {vuln_type}: Prediction failed - {e}")

    benchmark_accuracy = benchmark_accurate / total_benchmarks if total_benchmarks > 0 else 0
    print(f"\n🎯 Benchmark Accuracy: {benchmark_accuracy:.1%} ({benchmark_accurate}/{total_benchmarks})")

    # === OVERALL ASSESSMENT ===
    print(f"\n🏆 OVERALL MODEL ASSESSMENT")
    print("=" * 40)

    if 'error' not in bounty_results:
        r2_value = bounty_results['r2_score']
        if r2_value >= 0.7:
            bounty_status = "🟢 HIGH RELIABILITY"
        elif r2_value >= 0.5:
            bounty_status = "🟡 MODERATE RELIABILITY"
        else:
            bounty_status = "🔴 LOW RELIABILITY"

        print(f"💰 Bounty Prediction: {bounty_status} (R² = {r2_value:.3f})")
    else:
        print(f"💰 Bounty Prediction: ❌ VALIDATION FAILED")

    if 'error' not in severity_results:
        accuracy = severity_results['accuracy']
        if accuracy >= 0.8:
            severity_status = "🟢 HIGH RELIABILITY"
        elif accuracy >= 0.6:
            severity_status = "🟡 MODERATE RELIABILITY"
        else:
            severity_status = "🔴 LOW RELIABILITY"

        print(f"🎯 Severity Classification: {severity_status} (Accuracy = {accuracy:.3f})")
    else:
        print(f"🎯 Severity Classification: ❌ VALIDATION FAILED")

    print(f"📋 Benchmark Performance: {benchmark_accuracy:.1%} accuracy on known cases")

    # Save results
    results = {
        'timestamp': datetime.now().isoformat(),
        'bounty_prediction': bounty_results,
        'severity_classification': severity_results,
        'benchmark_accuracy': benchmark_accuracy,
        'benchmark_cases_tested': total_benchmarks,
        'benchmark_cases_passed': benchmark_accurate
    }

    output_dir = Path("model_validation")
    output_dir.mkdir(exist_ok=True)

    with open(output_dir / "quick_validation_results.json", 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n💾 Results saved to: model_validation/quick_validation_results.json")
    print(f"✅ Quick validation completed successfully!")

    return results

if __name__ == "__main__":
    load_and_validate_models()