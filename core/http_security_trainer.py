#!/usr/bin/env python3
"""
BEAST MODE HTTP Security Trainer
Advanced machine learning for HTTP vulnerability detection
"""

import numpy as np
import pandas as pd
import json
import logging
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
import pickle
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTTPSecurityFeatureExtractor:
    """Advanced feature extraction for HTTP security analysis"""

    def __init__(self):
        self.url_vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3), analyzer='char')
        self.header_vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2))
        self.body_vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2))
        self.scaler = StandardScaler()

        # Security patterns for detection
        self.security_patterns = {
            'sqli_patterns': [
                r"'.*or.*'.*=.*'", r"union.*select", r"drop.*table", r"insert.*into",
                r"update.*set", r"delete.*from", r"exec.*xp_", r"sp_.*password",
                r"'.*and.*1.*=.*1", r"'.*and.*1.*=.*2", r"order.*by.*\d+",
                r"having.*count.*>", r"group.*by.*\d+", r"waitfor.*delay"
            ],
            'xss_patterns': [
                r"<script.*>", r"javascript:", r"onerror.*=", r"onload.*=",
                r"<iframe.*>", r"<img.*onerror", r"<svg.*onload", r"alert\s*\(",
                r"document\.cookie", r"document\.location", r"eval\s*\(", r"<body.*onload"
            ],
            'rce_patterns': [
                r";.*cat.*\/etc\/passwd", r"\|.*whoami", r"&&.*id", r"\|\|.*ls",
                r"__import__.*os", r"eval.*import", r"exec.*system", r"nc.*-e",
                r"bash.*-i", r"sh.*-i", r"curl.*\|.*sh", r"wget.*\|.*sh"
            ],
            'ssrf_patterns': [
                r"http:\/\/127\.0\.0\.1", r"http:\/\/localhost", r"http:\/\/192\.168\.",
                r"http:\/\/10\.", r"http:\/\/172\.16\.", r"file:\/\/", r"gopher:\/\/",
                r"169\.254\.169\.254", r"metadata\.google\.internal"
            ],
            'lfi_patterns': [
                r"\.\.\/", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c", r"\/etc\/passwd",
                r"\/windows\/system32", r"php:\/\/filter", r"data:\/\/", r"expect:\/\/"
            ],
            'scanner_patterns': [
                r"nikto", r"sqlmap", r"nmap", r"burp", r"zap", r"acunetix",
                r"nessus", r"openvas", r"w3af", r"skipfish"
            ]
        }

        logger.info("🦾 HTTP Security Feature Extractor initialized")

    def extract_comprehensive_features(self, dataset):
        """Extract comprehensive features from HTTP dataset"""
        logger.info(f"🔄 Extracting features from {len(dataset)} samples...")

        features = []
        for i, sample in enumerate(dataset):
            if i % 5000 == 0:
                logger.info(f"   Processing sample {i}/{len(dataset)}")

            request = sample['request']
            response = sample['response']
            metadata = sample['metadata']

            # Extract all feature types
            url_features = self._extract_url_features(request['url'])
            header_features = self._extract_header_features(request['headers'])
            body_features = self._extract_body_features(request['body'])
            response_features = self._extract_response_features(response)
            temporal_features = self._extract_temporal_features(request.get('timestamp', ''))
            pattern_features = self._extract_pattern_features(request)

            # Combine all features
            combined_features = {
                **url_features,
                **header_features,
                **body_features,
                **response_features,
                **temporal_features,
                **pattern_features
            }

            features.append(combined_features)

        logger.info(f"✅ Feature extraction complete: {len(features[0])} features per sample")
        return features

    def _extract_url_features(self, url):
        """Extract features from URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        return {
            # Basic URL structure
            'url_length': len(url),
            'path_length': len(parsed.path),
            'query_length': len(parsed.query),
            'fragment_length': len(parsed.fragment or ''),
            'param_count': len(query_params),

            # URL characteristics
            'has_params': len(query_params) > 0,
            'has_port': parsed.port is not None,
            'is_https': parsed.scheme == 'https',
            'path_depth': len([p for p in parsed.path.split('/') if p]),

            # Suspicious characters in URL
            'url_special_chars': len(re.findall(r'[<>"\'\(\)\{\}]', url)),
            'url_encoded_chars': len(re.findall(r'%[0-9a-fA-F]{2}', url)),
            'url_spaces': url.count(' '),
            'url_dots': url.count('.'),

            # Path analysis
            'path_has_traversal': '..' in parsed.path,
            'path_has_null': '%00' in parsed.path,
            'path_executable': any(ext in parsed.path.lower() for ext in ['.exe', '.sh', '.bat', '.cmd']),

            # Query parameter analysis
            'max_param_length': max([len(v[0]) if v else 0 for v in query_params.values()], default=0),
            'numeric_params': sum(1 for v in query_params.values() if v and v[0].isdigit()),
            'suspicious_param_names': sum(1 for k in query_params.keys()
                                        if k.lower() in ['cmd', 'exec', 'system', 'eval', 'code', 'shell'])
        }

    def _extract_header_features(self, headers):
        """Extract features from HTTP headers"""
        if not headers:
            headers = {}

        user_agent = headers.get('User-Agent', '')
        content_type = headers.get('Content-Type', '')

        return {
            # Header counts and sizes
            'header_count': len(headers),
            'total_header_length': sum(len(str(k)) + len(str(v)) for k, v in headers.items()),
            'user_agent_length': len(user_agent),

            # User agent analysis
            'ua_has_bot': any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider', 'scraper']),
            'ua_has_scanner': any(scanner in user_agent.lower() for scanner in ['nikto', 'sqlmap', 'nmap', 'burp']),
            'ua_is_curl': 'curl' in user_agent.lower(),
            'ua_is_python': 'python' in user_agent.lower(),

            # Content type analysis
            'content_is_json': 'json' in content_type.lower(),
            'content_is_xml': 'xml' in content_type.lower(),
            'content_is_form': 'form' in content_type.lower(),
            'content_is_multipart': 'multipart' in content_type.lower(),

            # Security headers
            'has_auth_header': 'Authorization' in headers,
            'has_cookie_header': 'Cookie' in headers,
            'has_referer': 'Referer' in headers,
            'has_origin': 'Origin' in headers,

            # Suspicious headers
            'has_x_forwarded': any('x-forwarded' in k.lower() for k in headers.keys()),
            'has_proxy_headers': any(h in headers for h in ['X-Real-IP', 'X-Forwarded-For', 'Via']),
        }

    def _extract_body_features(self, body):
        """Extract features from request body"""
        if not body:
            body = ''

        return {
            # Basic body characteristics
            'body_length': len(body),
            'body_lines': body.count('\n'),
            'body_words': len(body.split()),

            # Content analysis
            'body_has_xml': body.strip().startswith('<'),
            'body_has_json': body.strip().startswith('{') or body.strip().startswith('['),
            'body_has_base64': bool(re.search(r'[A-Za-z0-9+/]{20,}={0,2}', body)),

            # Suspicious content
            'body_special_chars': len(re.findall(r'[<>"\'\(\)\{\}]', body)),
            'body_encoded_chars': len(re.findall(r'%[0-9a-fA-F]{2}', body)),
            'body_sql_keywords': len(re.findall(r'\b(select|union|insert|update|delete|drop|create|alter)\b', body, re.IGNORECASE)),
            'body_script_tags': len(re.findall(r'<script.*?>', body, re.IGNORECASE)),

            # File upload indicators
            'body_has_upload': 'filename=' in body or 'Content-Disposition' in body,
            'body_has_boundary': 'boundary=' in body,
        }

    def _extract_response_features(self, response):
        """Extract features from HTTP response"""
        status_code = response.get('status_code', 0)
        response_body = response.get('body', '')
        response_time = response.get('response_time', 0)

        return {
            # Response status
            'status_code': status_code,
            'status_2xx': 200 <= status_code < 300,
            'status_3xx': 300 <= status_code < 400,
            'status_4xx': 400 <= status_code < 500,
            'status_5xx': 500 <= status_code < 600,

            # Response characteristics
            'response_length': len(response_body),
            'response_time': response_time,
            'response_slow': response_time > 5.0,

            # Error indicators
            'response_has_error': any(word in response_body.lower() for word in ['error', 'exception', 'warning']),
            'response_has_sql_error': any(word in response_body.lower() for word in ['mysql', 'oracle', 'postgresql', 'syntax error']),
            'response_has_stack_trace': 'at ' in response_body and '.java:' in response_body,

            # Content indicators
            'response_is_html': '<html' in response_body.lower(),
            'response_is_json': response_body.strip().startswith('{'),
            'response_is_xml': response_body.strip().startswith('<'),
        }

    def _extract_temporal_features(self, timestamp):
        """Extract temporal features"""
        if not timestamp:
            return {'hour': 0, 'day_of_week': 0, 'is_weekend': False}

        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return {
                'hour': dt.hour,
                'day_of_week': dt.weekday(),
                'is_weekend': dt.weekday() >= 5,
                'is_night': dt.hour < 6 or dt.hour > 22,
            }
        except:
            return {'hour': 0, 'day_of_week': 0, 'is_weekend': False, 'is_night': False}

    def _extract_pattern_features(self, request):
        """Extract security pattern features"""
        url = request['url']
        body = request.get('body', '')
        user_agent = request.get('headers', {}).get('User-Agent', '')

        all_text = f"{url} {body} {user_agent}".lower()

        features = {}
        for pattern_type, patterns in self.security_patterns.items():
            count = 0
            for pattern in patterns:
                count += len(re.findall(pattern, all_text, re.IGNORECASE))
            features[f'{pattern_type}_count'] = count
            features[f'has_{pattern_type}'] = count > 0

        return features

class HTTPSecurityTrainer:
    """Advanced HTTP security vulnerability trainer"""

    def __init__(self):
        self.feature_extractor = HTTPSecurityFeatureExtractor()
        self.label_encoder = LabelEncoder()
        self.models = {}
        self.feature_names = []
        self.trained = False

        logger.info("🦾 HTTP Security Trainer initialized")

    def load_dataset(self, filename):
        """Load HTTP security dataset"""
        logger.info(f"📂 Loading dataset from {filename}")

        with open(filename, 'r') as f:
            dataset = json.load(f)

        logger.info(f"✅ Loaded {len(dataset)} samples")
        return dataset

    def prepare_features(self, dataset):
        """Prepare features and labels from dataset"""
        logger.info("🔄 Preparing features and labels...")

        # Extract features
        features = self.feature_extractor.extract_comprehensive_features(dataset)

        # Convert to DataFrame
        df = pd.DataFrame(features)
        self.feature_names = df.columns.tolist()

        # Handle NaN values
        df = df.fillna(0)

        # Extract labels
        labels = [sample['metadata']['label'] for sample in dataset]

        logger.info(f"✅ Features prepared: {len(df.columns)} features, {len(set(labels))} classes")
        logger.info(f"📊 Feature shape: {df.shape}")

        return df.values, labels

    def train_models(self, X, y):
        """Train multiple models for ensemble prediction"""
        logger.info("🤖 Training HTTP security models...")

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )

        # Scale features
        X_train_scaled = self.feature_extractor.scaler.fit_transform(X_train)
        X_test_scaled = self.feature_extractor.scaler.transform(X_test)

        # Train multiple models
        self.models = {}

        # Random Forest
        logger.info("   Training Random Forest...")
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)
        self.models['random_forest'] = rf

        # Gradient Boosting
        logger.info("   Training Gradient Boosting...")
        gb = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=10,
            random_state=42
        )
        gb.fit(X_train, y_train)
        self.models['gradient_boosting'] = gb

        # XGBoost (if available)
        if HAS_XGBOOST:
            logger.info("   Training XGBoost...")
            xgb_model = xgb.XGBClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=10,
                random_state=42,
                eval_metric='mlogloss'
            )
            xgb_model.fit(X_train, y_train)
            self.models['xgboost'] = xgb_model
        else:
            logger.info("   XGBoost not available, skipping...")

        # Neural Network
        logger.info("   Training Neural Network...")
        nn = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.001,
            max_iter=500,
            random_state=42
        )
        nn.fit(X_train_scaled, y_train)
        self.models['neural_network'] = nn

        # SVM (for smaller datasets)
        if len(X_train) < 10000:
            logger.info("   Training SVM...")
            svm = SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                probability=True,
                random_state=42
            )
            svm.fit(X_train_scaled, y_train)
            self.models['svm'] = svm

        self.trained = True

        # Evaluate models
        self._evaluate_models(X_test, X_test_scaled, y_test)

        logger.info(f"✅ Training complete: {len(self.models)} models trained")

    def _evaluate_models(self, X_test, X_test_scaled, y_test):
        """Evaluate all trained models"""
        logger.info("📊 Evaluating models...")

        for name, model in self.models.items():
            if name in ['neural_network', 'svm']:
                predictions = model.predict(X_test_scaled)
            else:
                predictions = model.predict(X_test)

            accuracy = accuracy_score(y_test, predictions)
            logger.info(f"   {name}: {accuracy:.4f} accuracy")

        # Best model ensemble prediction
        ensemble_predictions = self._ensemble_predict(X_test, X_test_scaled)
        ensemble_accuracy = accuracy_score(y_test, ensemble_predictions)
        logger.info(f"   ensemble: {ensemble_accuracy:.4f} accuracy")

        # Detailed report for best model (Random Forest)
        rf_predictions = self.models['random_forest'].predict(X_test)
        labels = self.label_encoder.classes_

        logger.info("\\n📋 Detailed Classification Report (Random Forest):")
        print(classification_report(y_test, rf_predictions, target_names=labels))

    def _ensemble_predict(self, X, X_scaled):
        """Make ensemble predictions"""
        predictions = []

        # Get predictions from all models
        for name, model in self.models.items():
            if name in ['neural_network', 'svm']:
                pred = model.predict(X_scaled)
            else:
                pred = model.predict(X)
            predictions.append(pred)

        # Voting ensemble
        predictions = np.array(predictions)
        ensemble_pred = []

        for i in range(len(X)):
            votes = predictions[:, i]
            # Get most common prediction
            unique, counts = np.unique(votes, return_counts=True)
            ensemble_pred.append(unique[np.argmax(counts)])

        return np.array(ensemble_pred)

    def predict_vulnerability(self, http_request):
        """Predict vulnerability for a single HTTP request"""
        if not self.trained:
            raise ValueError("Models not trained. Call train_models() first.")

        # Convert single request to dataset format
        sample = {
            'request': http_request,
            'response': {'status_code': 200, 'body': '', 'response_time': 0.5},
            'metadata': {'label': 'unknown'}
        }

        # Extract features
        features = self.feature_extractor.extract_comprehensive_features([sample])
        df = pd.DataFrame(features)
        df = df.reindex(columns=self.feature_names, fill_value=0)
        X = df.values

        # Scale features for applicable models
        X_scaled = self.feature_extractor.scaler.transform(X)

        # Get predictions from all models
        predictions = {}
        probabilities = {}

        for name, model in self.models.items():
            if name in ['neural_network', 'svm']:
                pred = model.predict(X_scaled)[0]
                prob = model.predict_proba(X_scaled)[0]
            else:
                pred = model.predict(X)[0]
                prob = model.predict_proba(X)[0]

            predictions[name] = self.label_encoder.inverse_transform([pred])[0]
            probabilities[name] = prob.max()

        # Ensemble prediction
        ensemble_pred = self._ensemble_predict(X, X_scaled)[0]
        final_prediction = self.label_encoder.inverse_transform([ensemble_pred])[0]

        return {
            'prediction': final_prediction,
            'confidence': np.mean(list(probabilities.values())),
            'model_predictions': predictions,
            'model_confidences': probabilities
        }

    def save_models(self, base_filename="http_security_models"):
        """Save trained models"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save models
        models_filename = f"{base_filename}_{timestamp}.pkl"
        with open(models_filename, 'wb') as f:
            pickle.dump({
                'models': self.models,
                'label_encoder': self.label_encoder,
                'feature_extractor': self.feature_extractor,
                'feature_names': self.feature_names
            }, f)

        logger.info(f"✅ Models saved to {models_filename}")
        return models_filename

    def load_models(self, filename):
        """Load pre-trained models"""
        logger.info(f"📂 Loading models from {filename}")

        with open(filename, 'rb') as f:
            data = pickle.load(f)

        self.models = data['models']
        self.label_encoder = data['label_encoder']
        self.feature_extractor = data['feature_extractor']
        self.feature_names = data['feature_names']
        self.trained = True

        logger.info(f"✅ Models loaded: {len(self.models)} models available")

def main():
    """Main training function"""
    logger.info("🚀 Starting BEAST MODE HTTP Security Training")

    # Initialize trainer
    trainer = HTTPSecurityTrainer()

    # Build dataset first if it doesn't exist
    try:
        # Try to load existing dataset
        dataset = trainer.load_dataset("beast_mode_http_security_20241002_142635.json")
    except FileNotFoundError:
        logger.info("📦 Dataset not found, building new dataset...")
        from http_security_dataset_builder import HTTPSecurityDatasetBuilder

        builder = HTTPSecurityDatasetBuilder()
        dataset = builder.build_comprehensive_dataset(target_size=50000)
        filename = builder.save_dataset(dataset)
        dataset = trainer.load_dataset(filename.split('.')[0] + '.json')

    # Prepare features and labels
    X, y = trainer.prepare_features(dataset)

    # Train models
    trainer.train_models(X, y)

    # Save trained models
    model_filename = trainer.save_models()

    logger.info("🎉 HTTP Security Training Complete!")
    logger.info(f"📁 Model file: {model_filename}")

    # Test prediction
    logger.info("🧪 Testing prediction...")
    test_request = {
        'method': 'GET',
        'url': "https://example.com/search?q=' OR '1'='1",
        'headers': {'User-Agent': 'Mozilla/5.0'},
        'body': ''
    }

    result = trainer.predict_vulnerability(test_request)
    logger.info(f"   Test prediction: {result['prediction']} (confidence: {result['confidence']:.2f})")

    return model_filename

if __name__ == "__main__":
    main()