"""
FastAPI REST API for VulnHunter V5
Provides endpoints for vulnerability detection with ML prediction and dynamic verification
"""

import os
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
import time

import torch
import pandas as pd
import numpy as np
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import structlog

# Import VulnHunter components
from ..models.v5_hybrid import VulnHunterV5Model
from ..verifiers.dynamic import DynamicVerifier
from ..data.feature_extractor import StaticFeatureExtractor, DynamicFeatureExtractor

logger = structlog.get_logger(__name__)


# Pydantic models for API
class CodeAnalysisRequest(BaseModel):
    """Request model for code analysis"""
    code: str = Field(..., description="Source code to analyze")
    language: str = Field(default="solidity", description="Programming language")
    include_dynamic: bool = Field(default=True, description="Include dynamic verification")
    explain: bool = Field(default=False, description="Include SHAP explanations")


class VulnerabilityResult(BaseModel):
    """Result model for vulnerability detection"""
    is_vulnerable: bool
    confidence: float
    vulnerability_type: Optional[str]
    severity: str
    explanation: Optional[Dict[str, Any]] = None


class DynamicVerificationResult(BaseModel):
    """Result model for dynamic verification"""
    confirmed: bool
    exploit_paths: int
    fpr_reduction: float
    tool_used: str
    execution_time: float
    coverage: float
    errors: List[str] = []


class AnalysisResponse(BaseModel):
    """Complete analysis response"""
    request_id: str
    ml_prediction: VulnerabilityResult
    dynamic_verification: Optional[DynamicVerificationResult] = None
    processing_time: float
    timestamp: str


class BatchAnalysisRequest(BaseModel):
    """Request model for batch analysis"""
    code_samples: List[Dict[str, str]] = Field(..., description="List of code samples with metadata")
    include_dynamic: bool = Field(default=True, description="Include dynamic verification")


class VulnHunterAPI:
    """
    VulnHunter V5 API implementation
    """

    def __init__(self,
                 model_path: str = "./models/vulnhunter_v5_final.pt",
                 device: str = "auto"):

        self.model_path = model_path
        self.device = torch.device("cuda" if device == "auto" and torch.cuda.is_available() else "cpu")

        # Initialize components
        self.model = None
        self.static_extractor = StaticFeatureExtractor()
        self.dynamic_extractor = DynamicFeatureExtractor()
        self.dynamic_verifier = DynamicVerifier()

        # Load model
        self.load_model()

        # Initialize FastAPI app
        self.app = FastAPI(
            title="VulnHunter V5 API",
            description="Advanced Hybrid Static-Dynamic Vulnerability Detection",
            version="5.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )

        # Configure CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Register routes
        self.register_routes()

        logger.info("VulnHunter V5 API initialized successfully")

    def load_model(self):
        """Load the trained VulnHunter V5 model"""
        try:
            if not Path(self.model_path).exists():
                logger.warning(f"Model file not found: {self.model_path}. Using dummy model.")
                self.model = self._create_dummy_model()
                return

            checkpoint = torch.load(self.model_path, map_location=self.device)

            # Get model configuration
            model_config = checkpoint.get('model_config', {
                'static_feature_dim': 38,
                'dynamic_feature_dim': 10,
                'hidden_dim': 512,
                'num_classes': 2,
                'dropout': 0.1
            })

            # Create model
            self.model = VulnHunterV5Model(**model_config)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.to(self.device)
            self.model.eval()

            logger.info(f"Model loaded successfully from {self.model_path}")

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = self._create_dummy_model()

    def _create_dummy_model(self) -> VulnHunterV5Model:
        """Create a dummy model for testing when trained model is not available"""
        model = VulnHunterV5Model(
            static_feature_dim=38,
            dynamic_feature_dim=10,
            hidden_dim=512,
            num_classes=2
        )
        model.to(self.device)
        model.eval()
        return model

    def register_routes(self):
        """Register API routes"""

        @self.app.get("/")
        async def root():
            return {
                "message": "VulnHunter V5 API",
                "version": "5.0.0",
                "status": "running",
                "model_loaded": self.model is not None
            }

        @self.app.get("/health")
        async def health():
            return {
                "status": "healthy",
                "model_status": "loaded" if self.model is not None else "not_loaded",
                "device": str(self.device)
            }

        @self.app.post("/analyze", response_model=AnalysisResponse)
        async def analyze_code(request: CodeAnalysisRequest, background_tasks: BackgroundTasks):
            return await self.analyze_code_endpoint(request, background_tasks)

        @self.app.post("/analyze/batch")
        async def analyze_batch(request: BatchAnalysisRequest, background_tasks: BackgroundTasks):
            return await self.analyze_batch_endpoint(request, background_tasks)

        @self.app.post("/verify/dynamic")
        async def verify_dynamic(code: str, vuln_type: str, language: str = "solidity"):
            return await self.dynamic_verification_endpoint(code, vuln_type, language)

        @self.app.post("/upload")
        async def upload_file(file: UploadFile = File(...), language: str = "solidity"):
            return await self.upload_file_endpoint(file, language)

        @self.app.get("/models/info")
        async def model_info():
            return await self.model_info_endpoint()

    async def analyze_code_endpoint(self, request: CodeAnalysisRequest, background_tasks: BackgroundTasks) -> AnalysisResponse:
        """Main code analysis endpoint"""
        start_time = time.time()
        request_id = f"req_{int(time.time() * 1000)}"

        logger.info(f"Processing analysis request {request_id}")

        try:
            # ML prediction
            ml_result = await self.ml_prediction(request.code, request.language, request.explain)

            # Dynamic verification (if requested and vulnerability found)
            dynamic_result = None
            if request.include_dynamic and ml_result.is_vulnerable:
                dynamic_result = await self.dynamic_verification(
                    request.code,
                    ml_result.vulnerability_type or "unknown",
                    request.language
                )

            processing_time = time.time() - start_time

            response = AnalysisResponse(
                request_id=request_id,
                ml_prediction=ml_result,
                dynamic_verification=dynamic_result,
                processing_time=processing_time,
                timestamp=pd.Timestamp.now().isoformat()
            )

            logger.info(f"Analysis completed for {request_id} in {processing_time:.2f}s")
            return response

        except Exception as e:
            logger.error(f"Analysis failed for {request_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def ml_prediction(self, code: str, language: str, explain: bool = False) -> VulnerabilityResult:
        """Perform ML-based vulnerability prediction"""
        try:
            # Extract static features
            static_features = self.static_extractor.extract_all_features(code, language)
            static_tensor = torch.tensor([list(static_features.values())], dtype=torch.float32).to(self.device)

            # Extract dynamic features (simulation for API)
            dynamic_features = self.dynamic_extractor.extract_all_features(code, language)
            dynamic_tensor = torch.tensor([list(dynamic_features.values())], dtype=torch.float32).to(self.device)

            # Pad features if necessary
            if static_tensor.shape[1] < 38:
                padding = torch.zeros(1, 38 - static_tensor.shape[1]).to(self.device)
                static_tensor = torch.cat([static_tensor, padding], dim=1)
            elif static_tensor.shape[1] > 38:
                static_tensor = static_tensor[:, :38]

            if dynamic_tensor.shape[1] < 10:
                padding = torch.zeros(1, 10 - dynamic_tensor.shape[1]).to(self.device)
                dynamic_tensor = torch.cat([dynamic_tensor, padding], dim=1)
            elif dynamic_tensor.shape[1] > 10:
                dynamic_tensor = dynamic_tensor[:, :10]

            # Model prediction
            with torch.no_grad():
                logits = self.model([code], static_tensor, dynamic_tensor)
                probabilities = torch.softmax(logits, dim=1)
                prediction = torch.argmax(logits, dim=1)
                confidence = probabilities[0][prediction[0]].item()
                is_vulnerable = bool(prediction[0].item())

            # Determine vulnerability type and severity
            vuln_type = self._determine_vulnerability_type(code, static_features)
            severity = self._determine_severity(confidence, vuln_type)

            # Generate explanation if requested
            explanation = None
            if explain and is_vulnerable:
                try:
                    explanation = self.model.explain_prediction([code], static_tensor, dynamic_tensor)
                except Exception as e:
                    logger.warning(f"Failed to generate explanation: {e}")
                    explanation = {"error": "Explanation generation failed"}

            return VulnerabilityResult(
                is_vulnerable=is_vulnerable,
                confidence=confidence,
                vulnerability_type=vuln_type if is_vulnerable else None,
                severity=severity,
                explanation=explanation
            )

        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            raise HTTPException(status_code=500, detail=f"ML prediction failed: {str(e)}")

    async def dynamic_verification(self, code: str, vuln_type: str, language: str) -> DynamicVerificationResult:
        """Perform dynamic verification"""
        try:
            result = self.dynamic_verifier.verify(code, vuln_type, language)

            return DynamicVerificationResult(
                confirmed=result.get('confirmed', False),
                exploit_paths=result.get('exploit_paths', 0),
                fpr_reduction=result.get('fpr_reduction', 0.0),
                tool_used=result.get('tool_used', 'unknown'),
                execution_time=result.get('execution_time', 0.0),
                coverage=result.get('coverage', 0.0),
                errors=result.get('errors', [])
            )

        except Exception as e:
            logger.error(f"Dynamic verification failed: {e}")
            return DynamicVerificationResult(
                confirmed=False,
                exploit_paths=0,
                fpr_reduction=0.0,
                tool_used="error",
                execution_time=0.0,
                coverage=0.0,
                errors=[str(e)]
            )

    async def analyze_batch_endpoint(self, request: BatchAnalysisRequest, background_tasks: BackgroundTasks):
        """Batch analysis endpoint"""
        start_time = time.time()
        request_id = f"batch_{int(time.time() * 1000)}"

        logger.info(f"Processing batch analysis {request_id} with {len(request.code_samples)} samples")

        try:
            results = []

            for i, sample in enumerate(request.code_samples):
                try:
                    code = sample.get('code', '')
                    language = sample.get('language', 'solidity')

                    # ML prediction
                    ml_result = await self.ml_prediction(code, language, False)

                    # Dynamic verification if needed
                    dynamic_result = None
                    if request.include_dynamic and ml_result.is_vulnerable:
                        dynamic_result = await self.dynamic_verification(
                            code,
                            ml_result.vulnerability_type or "unknown",
                            language
                        )

                    results.append({
                        'sample_id': i,
                        'ml_prediction': ml_result.dict(),
                        'dynamic_verification': dynamic_result.dict() if dynamic_result else None
                    })

                except Exception as e:
                    logger.warning(f"Failed to analyze sample {i}: {e}")
                    results.append({
                        'sample_id': i,
                        'error': str(e)
                    })

            processing_time = time.time() - start_time

            return {
                'request_id': request_id,
                'results': results,
                'total_samples': len(request.code_samples),
                'successful_analyses': len([r for r in results if 'error' not in r]),
                'processing_time': processing_time,
                'timestamp': pd.Timestamp.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def dynamic_verification_endpoint(self, code: str, vuln_type: str, language: str):
        """Standalone dynamic verification endpoint"""
        try:
            result = await self.dynamic_verification(code, vuln_type, language)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def upload_file_endpoint(self, file: UploadFile, language: str):
        """File upload and analysis endpoint"""
        try:
            content = await file.read()
            code = content.decode('utf-8')

            request = CodeAnalysisRequest(
                code=code,
                language=language,
                include_dynamic=True,
                explain=False
            )

            result = await self.analyze_code_endpoint(request, None)
            result_dict = result.dict()
            result_dict['filename'] = file.filename

            return result_dict

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")

    async def model_info_endpoint(self):
        """Model information endpoint"""
        try:
            info = {
                'model_version': '5.0.0',
                'model_type': 'VulnHunterV5Model',
                'device': str(self.device),
                'capabilities': [
                    'static_analysis',
                    'dynamic_verification',
                    'smart_contract_analysis',
                    'source_code_analysis',
                    'explainable_ai'
                ],
                'supported_languages': ['solidity', 'c', 'python', 'javascript'],
                'supported_vulnerability_types': [
                    'buffer_overflow',
                    'integer_overflow',
                    'sql_injection',
                    'xss',
                    'command_injection',
                    'access_control',
                    'reentrancy',
                    'unchecked_return'
                ]
            }

            if self.model is not None:
                info['model_parameters'] = sum(p.numel() for p in self.model.parameters())
                info['model_size_mb'] = sum(p.numel() * p.element_size() for p in self.model.parameters()) / (1024 * 1024)

            return info

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def _determine_vulnerability_type(self, code: str, features: Dict[str, Any]) -> str:
        """Determine vulnerability type based on code and features"""
        # Simple heuristic-based type detection
        code_lower = code.lower()

        if 'strcpy' in code_lower or 'strcat' in code_lower:
            return 'buffer_overflow'
        elif '++' in code or '--' in code or '+=' in code:
            return 'integer_overflow'
        elif 'select' in code_lower and '+' in code:
            return 'sql_injection'
        elif 'innerhtml' in code_lower:
            return 'xss'
        elif 'system(' in code_lower or 'exec(' in code_lower:
            return 'command_injection'
        elif 'require(' in code_lower or 'assert(' in code_lower:
            return 'access_control'
        elif '.call(' in code_lower:
            return 'reentrancy'
        else:
            return 'unknown'

    def _determine_severity(self, confidence: float, vuln_type: str) -> str:
        """Determine severity based on confidence and vulnerability type"""
        high_severity_types = ['buffer_overflow', 'command_injection', 'reentrancy']

        if vuln_type in high_severity_types:
            return 'critical' if confidence > 0.8 else 'high'
        elif confidence > 0.9:
            return 'high'
        elif confidence > 0.7:
            return 'medium'
        else:
            return 'low'


# Create global API instance
api_instance = None

def create_app(model_path: str = "./models/vulnhunter_v5_final.pt") -> FastAPI:
    """Create and configure the FastAPI application"""
    global api_instance
    api_instance = VulnHunterAPI(model_path=model_path)
    return api_instance.app


# For direct execution
if __name__ == "__main__":
    import uvicorn

    app = create_app()

    logger.info("Starting VulnHunter V5 API server")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )