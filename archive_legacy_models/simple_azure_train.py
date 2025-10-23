#!/usr/bin/env python3
"""
Simple VulnHunter V14 Azure ML Training Script
"""
import os
import json
import pickle
from azureml.core import Run
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

def main():
    # Get the Azure ML run context
    run = Run.get_context()

    print("🚀 Starting VulnHunter V14 Azure ML Training")

    # Real vulnerability patterns
    patterns = [
        "strcpy(buffer, user_input);",
        "SELECT * FROM users WHERE id = " + "user_id",
        "eval(user_code);",
        "pickle.loads(untrusted_data);",
        "document.innerHTML = userInput;",
        "Runtime.getRuntime().exec(cmd);",
        "memcpy(dst, src, size);",
        "sprintf(dest, format, user_data);",
        "system(user_command);",
        "deserialize(user_object);",
        # Safe patterns
        "prepared_statement.setString(1, user_id);",
        "strncpy(dest, src, sizeof(dest)-1);",
        "html.escape(user_input);",
        "json.loads(trusted_data);",
        "input_validation(user_data);"
    ]

    labels = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]

    print(f"📊 Dataset: {len(patterns)} patterns, {sum(labels)} vulnerable")

    # Feature extraction
    vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
    features = vectorizer.fit_transform(patterns)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.3, random_state=42
    )

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    train_acc = model.score(X_train, y_train)
    test_acc = model.score(X_test, y_test)
    y_pred = model.predict(X_test)
    f1 = f1_score(y_test, y_pred)

    print(f"📊 Train Accuracy: {train_acc:.4f}")
    print(f"📊 Test Accuracy: {test_acc:.4f}")
    print(f"📊 F1 Score: {f1:.4f}")

    # Log metrics to Azure ML
    run.log('train_accuracy', train_acc)
    run.log('test_accuracy', test_acc)
    run.log('f1_score', f1)
    run.log('total_patterns', len(patterns))
    run.log('vulnerable_patterns', sum(labels))

    # Save model
    os.makedirs('outputs', exist_ok=True)

    model_package = {
        'model': model,
        'vectorizer': vectorizer,
        'metrics': {
            'train_accuracy': train_acc,
            'test_accuracy': test_acc,
            'f1_score': f1
        }
    }

    with open('outputs/vulnhunter_v14_azure.pkl', 'wb') as f:
        pickle.dump(model_package, f)

    # Save results
    results = {
        'version': 'VulnHunter V14 Azure',
        'total_patterns': len(patterns),
        'vulnerable_patterns': sum(labels),
        'train_accuracy': train_acc,
        'test_accuracy': test_acc,
        'f1_score': f1
    }

    with open('outputs/training_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print("✅ VulnHunter V14 Azure ML training completed!")
    print("📁 Model saved to outputs/vulnhunter_v14_azure.pkl")

if __name__ == '__main__':
    main()