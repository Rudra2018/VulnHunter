#!/usr/bin/env python3
"""
VulnGuard AI - HTTP Security Trainer
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

# Import VulnGuard dataset integrator and AST extractor
try:
    from core.huggingface_dataset_integrator import VulnGuardDatasetIntegrator
    HAS_VULNGUARD_INTEGRATOR = True
except ImportError:
    HAS_VULNGUARD_INTEGRATOR = False

try:
    from core.ast_feature_extractor import AdvancedASTFeatureExtractor
    HAS_AST_EXTRACTOR = True
except ImportError:
    HAS_AST_EXTRACTOR = False

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


class VulnGuardIntegratedTrainer:
    """VulnGuard AI Integrated Trainer combining HTTP security and vulnerability code analysis"""

    def __init__(self):
        self.http_feature_extractor = HTTPSecurityFeatureExtractor()
        self.vuln_integrator = VulnGuardDatasetIntegrator() if HAS_VULNGUARD_INTEGRATOR else None
        self.ast_extractor = AdvancedASTFeatureExtractor() if HAS_AST_EXTRACTOR else None
        self.models = {}
        self.integrated_data = []
        self.code_vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2), analyzer='word')  # Reduced since we have AST
        self.feature_scaler = StandardScaler()

        logger.info("🦾 VulnGuard AI Integrated Trainer initialized")
        if self.ast_extractor:
            logger.info("🧬 Advanced AST feature extraction enabled")
        else:
            logger.warning("⚠️  AST feature extraction not available")

    def load_vulnerability_datasets(self) -> bool:
        """Load vulnerability datasets from Hugging Face"""
        if not self.vuln_integrator:
            logger.warning("⚠️  VulnGuard integrator not available")
            return False

        logger.info("📂 Loading vulnerability datasets...")

        try:
            # Load only 2 datasets for demonstration
            dataset_keys = ['vulnerable-code', 'code-vulnerable-10000']

            for key in dataset_keys:
                if not self.vuln_integrator.load_huggingface_dataset(key):
                    logger.warning(f"⚠️  Failed to load {key}")
                    return False

            # Process datasets
            processed_data = []
            for key in dataset_keys:
                if key in self.vuln_integrator.datasets:
                    data = self.vuln_integrator.process_general_vulnerable_dataset(key)
                    processed_data.extend(data[:1000])  # Limit to 1000 samples per dataset

            self.integrated_data = processed_data
            logger.info(f"✅ Loaded {len(self.integrated_data)} vulnerability samples")
            return True

        except Exception as e:
            logger.error(f"❌ Error loading vulnerability datasets: {e}")
            return False

    def train_integrated_models(self):
        """Train models using integrated vulnerability datasets with enhanced AST features"""
        if not self.load_vulnerability_datasets():
            logger.error("❌ Failed to load vulnerability datasets")
            return False

        # Extract code and labels
        codes = []
        labels = []

        for sample in self.integrated_data:
            code = sample.get('code', '')
            if code and len(code.strip()) > 10:
                codes.append(code)
                labels.append(sample.get('vulnerable', 0))

        if not codes:
            logger.error("❌ No valid code samples found")
            return False

        logger.info(f"🔄 Preparing enhanced features from {len(codes)} vulnerability samples...")

        # Create TF-IDF features
        X_tfidf = self.code_vectorizer.fit_transform(codes)
        tfidf_features = X_tfidf.toarray()

        # Extract AST features if available
        if self.ast_extractor:
            logger.info("🧬 Extracting AST features...")
            ast_features_list = []

            for i, code in enumerate(codes):
                if i % 200 == 0:
                    logger.info(f"   Processing AST features: {i}/{len(codes)}")

                try:
                    ast_features = self.ast_extractor.extract_enhanced_features(code)
                    # Convert to numeric vector
                    ast_vector = self._convert_ast_features_to_vector(ast_features)
                    ast_features_list.append(ast_vector)
                except Exception as e:
                    logger.warning(f"⚠️  AST extraction failed for sample {i}: {e}")
                    # Use zeros if AST extraction fails
                    ast_features_list.append(np.zeros(100))  # Default AST feature size

            ast_features_array = np.array(ast_features_list)
            logger.info(f"✅ Extracted AST features: {ast_features_array.shape}")

            # Combine TF-IDF and AST features
            X_combined = np.hstack([tfidf_features, ast_features_array])
            logger.info(f"✅ Combined features: TF-IDF({tfidf_features.shape[1]}) + AST({ast_features_array.shape[1]}) = {X_combined.shape[1]} total")

        else:
            logger.warning("⚠️  Using TF-IDF features only (AST extractor not available)")
            X_combined = tfidf_features

        # Scale features
        X = self.feature_scaler.fit_transform(X_combined)
        y = np.array(labels)

        logger.info(f"✅ Prepared {X.shape[0]} samples with {X.shape[1]} enhanced features")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train models
        logger.info("🤖 Training VulnGuard AI models...")

        # Random Forest
        logger.info("🌲 Training Random Forest...")
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf.fit(X_train, y_train)
        self.models['random_forest'] = rf

        # Gradient Boosting
        logger.info("📈 Training Gradient Boosting...")
        gb = GradientBoostingClassifier(n_estimators=100, random_state=42)
        gb.fit(X_train, y_train)
        self.models['gradient_boosting'] = gb

        # Neural Network
        logger.info("🧠 Training Neural Network...")
        nn = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=300, random_state=42)
        nn.fit(X_train, y_train)
        self.models['neural_network'] = nn

        # Evaluate models
        logger.info("📊 Evaluating models...")
        for name, model in self.models.items():
            predictions = model.predict(X_test)
            accuracy = accuracy_score(y_test, predictions)
            logger.info(f"📈 {name}: {accuracy:.4f} accuracy")

        logger.info(f"✅ Training complete: {len(self.models)} models trained")
        return True

    def predict_vulnerability(self, code_text: str) -> dict:
        """Predict if code is vulnerable using enhanced AST features"""
        if not self.models:
            raise ValueError("Models not trained. Call train_integrated_models() first.")

        # Create TF-IDF features
        X_tfidf = self.code_vectorizer.transform([code_text]).toarray()

        # Extract AST features if available
        if self.ast_extractor:
            try:
                ast_features = self.ast_extractor.extract_enhanced_features(code_text)
                ast_vector = self._convert_ast_features_to_vector(ast_features)
                # Combine TF-IDF and AST features
                X_combined = np.hstack([X_tfidf, ast_vector.reshape(1, -1)])
            except Exception as e:
                logger.warning(f"⚠️  AST feature extraction failed during prediction: {e}")
                X_combined = X_tfidf
        else:
            X_combined = X_tfidf

        # Scale features
        X = self.feature_scaler.transform(X_combined)

        predictions = {}
        probabilities = {}

        for name, model in self.models.items():
            try:
                pred = model.predict(X)[0]
                prob = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else [1-pred, pred]

                predictions[name] = int(pred)
                probabilities[name] = float(prob[1])
            except Exception as e:
                logger.warning(f"⚠️  Prediction failed for {name}: {e}")
                predictions[name] = 0
                probabilities[name] = 0.0

        ensemble_prob = np.mean(list(probabilities.values()))
        ensemble_pred = 1 if ensemble_prob > 0.5 else 0

        return {
            'ensemble_prediction': ensemble_pred,
            'ensemble_confidence': ensemble_prob,
            'model_predictions': predictions,
            'model_confidences': probabilities
        }

    def save_models(self, base_filename="vulnguard_integrated_models"):
        """Save trained models"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        models_filename = f"{base_filename}_{timestamp}.pkl"

        with open(models_filename, 'wb') as f:
            pickle.dump({
                'models': self.models,
                'code_vectorizer': self.code_vectorizer,
                'feature_scaler': self.feature_scaler,
                'has_ast_features': self.ast_extractor is not None,
                'training_samples': len(self.integrated_data)
            }, f)

        logger.info(f"✅ Models saved to {models_filename}")
        return models_filename

    def _convert_ast_features_to_vector(self, ast_features: dict) -> np.ndarray:
        """Convert AST features dictionary to numeric vector"""
        # Define expected feature order and defaults
        feature_keys = [
            # Basic AST counts
            'ast_FunctionDef_count', 'ast_Call_count', 'ast_Assign_count', 'ast_If_count',
            'ast_For_count', 'ast_While_count', 'ast_BinOp_count', 'ast_Compare_count',

            # Tree-sitter features
            'ts_total_nodes', 'ts_unique_node_types', 'ts_tree_depth',
            'ts_function_definition_count', 'ts_call_count', 'ts_assignment_count',

            # Code structure
            'total_lines', 'non_empty_lines', 'max_indentation', 'avg_line_length',
            'estimated_complexity', 'total_control_flow',

            # Vulnerability patterns
            'sql_injection_pattern_score', 'command_injection_pattern_score',
            'xss_pattern_score', 'buffer_overflow_pattern_score', 'path_traversal_pattern_score',

            # Security indicators
            'has_sql_injection_indicators', 'has_command_injection_indicators',
            'has_xss_indicators', 'has_buffer_overflow_indicators',

            # Function analysis
            'total_function_calls', 'unique_function_calls', 'function_definitions',

            # Control flow
            'if_statements', 'for_loops', 'while_loops', 'try_except',

            # Data flow
            'assignments', 'return_statements', 'input_operations', 'output_operations',

            # Memory operations
            'memory_alloc', 'memory_free', 'memory_balance',

            # String operations
            'string_literals', 'numeric_literals'
        ]

        # Convert features to vector
        vector = []
        for key in feature_keys:
            value = ast_features.get(key, 0)

            # Handle different value types
            if isinstance(value, bool):
                vector.append(1.0 if value else 0.0)
            elif isinstance(value, (int, float)):
                vector.append(float(value))
            elif isinstance(value, str):
                # Hash string values to numeric
                vector.append(float(hash(value) % 1000))
            else:
                vector.append(0.0)

        # Pad or truncate to exactly 100 features
        if len(vector) < 100:
            vector.extend([0.0] * (100 - len(vector)))
        elif len(vector) > 100:
            vector = vector[:100]

        return np.array(vector, dtype=np.float32)


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
    logger.info("🚀 Starting VulnGuard AI HTTP Security Training")

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