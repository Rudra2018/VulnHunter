"""
VulnHunter FastAPI Application
=============================

Main FastAPI application for VulnHunter vulnerability detection platform.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional
import time
import uvicorn

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from ..core.engine import VulnHunterEngine
from ..core.config import VulnHunterConfig
from .routes import analysis, health, models, batch
from .middleware import SecurityMiddleware, RateLimitMiddleware, LoggingMiddleware
from .dependencies import get_engine, get_config, verify_api_key

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global engine instance
_engine: Optional[VulnHunterEngine] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global _engine

    # Startup
    logger.info("Starting VulnHunter API...")

    try:
        # Initialize configuration
        config = VulnHunterConfig()

        # Initialize engine
        _engine = VulnHunterEngine(config)
        await _engine.initialize()

        logger.info("VulnHunter API started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start VulnHunter API: {e}")
        raise

    finally:
        # Shutdown
        logger.info("Shutting down VulnHunter API...")
        if _engine and hasattr(_engine, 'cleanup'):
            _engine.cleanup()
        logger.info("VulnHunter API shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="VulnHunter API",
    description="""
    **Enterprise-Grade Vulnerability Detection Platform**

    VulnHunter provides comprehensive security analysis across multiple domains:

    - **Source Code Analysis**: Detect vulnerabilities in source code
    - **HTTP Request Analysis**: Analyze web traffic for attacks
    - **Mobile App Security**: Scan APK/IPA files for security issues
    - **Executable Analysis**: Detect malware and binary threats
    - **Smart Contract Security**: Audit blockchain smart contracts

    ## Features

    - **5 Specialized ML Models** with 89.1% average accuracy
    - **Real-time Analysis** with confidence scoring
    - **Batch Processing** for high-throughput analysis
    - **Cloud Integration** with Google Vertex AI
    - **Enterprise Security** with API key authentication

    ## Authentication

    Some endpoints require API key authentication. Include your API key in the
    `X-API-Key` header.

    ## Rate Limits

    - **Standard**: 1000 requests per minute
    - **Burst**: 20 requests per second

    ## Support

    For technical support, visit our [documentation](https://docs.vulnhunter.ai)
    or contact us at support@vulnhunter.ai.
    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    contact={
        "name": "VulnHunter Support",
        "url": "https://vulnhunter.ai/support",
        "email": "support@vulnhunter.ai",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    terms_of_service="https://vulnhunter.ai/terms",
)


# Middleware configuration
def configure_middleware(app: FastAPI, config: VulnHunterConfig):
    """Configure application middleware."""

    # Security middleware
    app.add_middleware(SecurityMiddleware)

    # Rate limiting middleware
    if config.security.rate_limiting.enabled:
        app.add_middleware(
            RateLimitMiddleware,
            calls=config.security.rate_limiting.per_ip_limit,
            period=60  # 1 minute
        )

    # Logging middleware
    app.add_middleware(LoggingMiddleware)

    # CORS middleware
    if config.api.cors.enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.api.cors.origins,
            allow_credentials=True,
            allow_methods=config.api.cors.methods,
            allow_headers=config.api.cors.headers,
        )

    # Trusted host middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # Configure based on deployment
    )


# Custom exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": time.time(),
            "path": str(request.url.path)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": time.time(),
            "path": str(request.url.path)
        }
    )


# Include routers
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(analysis.router, prefix="/analyze", tags=["Analysis"])
app.include_router(models.router, prefix="/models", tags=["Models"])
app.include_router(batch.router, prefix="/batch", tags=["Batch"])


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "VulnHunter API",
        "version": "2.0.0",
        "description": "Enterprise-Grade Vulnerability Detection Platform",
        "status": "operational",
        "timestamp": time.time(),
        "documentation": "/docs",
        "health_check": "/health",
        "supported_domains": [
            "source_code",
            "http_requests",
            "mobile_apps",
            "executables",
            "smart_contracts"
        ]
    }


# API info endpoint
@app.get("/info", tags=["Root"])
async def api_info(engine: VulnHunterEngine = Depends(get_engine)):
    """Get comprehensive API and engine information."""
    engine_stats = engine.get_engine_stats()

    return {
        "api": {
            "name": "VulnHunter API",
            "version": "2.0.0",
            "status": "operational",
            "uptime": time.time(),
        },
        "engine": engine_stats,
        "capabilities": {
            "real_time_analysis": True,
            "batch_processing": True,
            "confidence_scoring": True,
            "multi_domain": True,
            "cloud_integration": True
        },
        "limits": {
            "max_file_size": "50MB",
            "max_request_size": "100MB",
            "rate_limit": "1000/minute",
            "timeout": "5 minutes"
        }
    }


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="VulnHunter API",
        version="2.0.0",
        description=app.description,
        routes=app.routes,
    )

    # Add custom security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key"
        }
    }

    # Add security to all protected endpoints
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method in ["post", "put", "delete"]:
                openapi_schema["paths"][path][method]["security"] = [
                    {"ApiKeyAuth": []}
                ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Dependency provider for engine
def get_engine_instance() -> VulnHunterEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        raise HTTPException(
            status_code=503,
            detail="VulnHunter engine not initialized"
        )
    return _engine


# Override dependency
app.dependency_overrides[get_engine] = get_engine_instance


def main():
    """Main entry point for running the API server."""
    import os

    # Get configuration
    config = VulnHunterConfig()

    # Configure middleware
    configure_middleware(app, config)

    # Run server
    uvicorn.run(
        app,
        host=config.api.host,
        port=config.api.port,
        workers=1,  # Use 1 worker for proper engine sharing
        log_level=config.logging.level.lower(),
        access_log=True,
        reload=config.api.debug
    )


if __name__ == "__main__":
    main()