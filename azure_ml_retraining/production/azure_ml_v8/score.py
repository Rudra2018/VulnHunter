
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

def init():
    """Initialize the model and components"""
    global model, tfidf_vectorizer, scaler, feature_names

    # Load trained model artifacts
    model = joblib.load('vulnhunter_v8_production.pkl')
    tfidf_vectorizer = joblib.load('vulnhunter_v8_tfidf.pkl')
    scaler = joblib.load('vulnhunter_v8_scaler.pkl')

    # Load feature names
    with open('feature_names.json', 'r') as f:
        feature_names = json.load(f)

def extract_security_features(contract_code):
    """Extract security-focused features from smart contract code"""
    security_patterns = {
        'reentrancy': ['call.value', 'msg.sender.call', '.call(', 'external', 'nonReentrant'],
        'arithmetic': ['+=', '-=', '*=', '/=', 'unchecked', 'SafeMath', 'overflow', 'underflow'],
        'access_control': ['onlyOwner', 'modifier', 'require(msg.sender', 'tx.origin', 'auth'],
        'timestamp': ['block.timestamp', 'block.number', 'now', 'block.difficulty'],
        'randomness': ['blockhash', 'block.coinbase', 'random', 'keccak256(block'],
        'gas': ['gasleft()', 'msg.gas', 'block.gaslimit', 'gas'],
        'delegatecall': ['delegatecall', 'callcode', 'proxy'],
        'selfdestruct': ['selfdestruct', 'suicide'],
        'oracle': ['oracle', 'price', 'getPrice', 'latestRoundData', 'chainlink'],
        'defi': ['flashloan', 'flash', 'borrow', 'repay', 'liquidity', 'swap'],
        'governance': ['vote', 'proposal', 'quorum', 'timelock'],
        'bridge': ['bridge', 'cross-chain', 'relay', 'validator']
    }

    text_lower = contract_code.lower()
    features = {}

    # Pattern features
    for category, patterns in security_patterns.items():
        count = sum(1 for pattern in patterns if pattern in text_lower)
        features[f'{category}_count'] = count
        features[f'{category}_presence'] = 1 if count > 0 else 0

    # Complexity features
    features.update({
        'function_count': contract_code.count('function'),
        'contract_count': contract_code.count('contract'),
        'modifier_count': contract_code.count('modifier'),
        'require_count': contract_code.count('require('),
        'assert_count': contract_code.count('assert('),
        'revert_count': contract_code.count('revert('),
        'payable_count': contract_code.count('payable'),
        'public_count': contract_code.count('public'),
        'private_count': contract_code.count('private'),
        'external_count': contract_code.count('external'),
        'internal_count': contract_code.count('internal'),
        'view_count': contract_code.count('view'),
        'pure_count': contract_code.count('pure'),
        'text_length': len(contract_code),
        'line_count': contract_code.count('\n')
    })

    return features

def run(raw_data):
    """Process incoming requests"""
    try:
        # Parse input
        data = json.loads(raw_data)

        if isinstance(data, dict):
            contracts = [data]
        else:
            contracts = data

        results = []

        for contract_data in contracts:
            contract_code = contract_data.get('code', '')

            if not contract_code:
                results.append({
                    'error': 'No contract code provided',
                    'vulnerability_score': 0.0,
                    'is_vulnerable': False
                })
                continue

            # Extract TF-IDF features
            tfidf_features = tfidf_vectorizer.transform([contract_code])

            # Extract pattern features
            pattern_features = extract_security_features(contract_code)
            pattern_df = pd.DataFrame([pattern_features])

            # Normalize if using pattern model
            if 'patterns' in str(type(model)).lower():
                # Scale numerical features
                numerical_cols = ['function_count', 'contract_count', 'text_length', 'line_count']
                pattern_df[numerical_cols] = scaler.transform(pattern_df[numerical_cols])

                # Predict using pattern features
                prediction = model.predict(pattern_df)[0]
                probability = model.predict_proba(pattern_df)[0]
            else:
                # Predict using TF-IDF features
                prediction = model.predict(tfidf_features)[0]
                probability = model.predict_proba(tfidf_features)[0]

            vulnerability_score = probability[1] if len(probability) > 1 else probability[0]

            result = {
                'is_vulnerable': bool(prediction),
                'vulnerability_score': float(vulnerability_score),
                'confidence': 'high' if vulnerability_score > 0.8 else 'medium' if vulnerability_score > 0.6 else 'low',
                'detected_patterns': [k for k, v in pattern_features.items() if 'presence' in k and v > 0],
                'model_version': 'VulnHunter-V8-Production'
            }

            results.append(result)

        return json.dumps(results)

    except Exception as e:
        error_result = {
            'error': str(e),
            'vulnerability_score': 0.0,
            'is_vulnerable': False
        }
        return json.dumps([error_result])
