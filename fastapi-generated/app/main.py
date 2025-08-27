"""
Kong Guard AI FastAPI Implementation
Auto-generated from Kong plugin Lua codebase analysis
"""

from fastapi import FastAPI, HTTPException, Depends, Query, Path, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import asyncio
import logging

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.security import get_current_user
from app.core.database import init_db, close_db
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.error_handler import ErrorHandlerMiddleware
from app.services.kong_integration import KongIntegrationService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle
    """
    # Startup
    logger.info("Starting Kong Guard AI API...")
    await init_db()
    await KongIntegrationService.initialize()
    logger.info("Kong Guard AI API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Kong Guard AI API...")
    await close_db()
    await KongIntegrationService.cleanup()
    logger.info("Kong Guard AI API shut down successfully")

# Create FastAPI application
app = FastAPI(
    title="Kong Guard AI API",
    description="Autonomous API Threat Response Agent for Kong Gateway",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middleware
app.add_middleware(RateLimitMiddleware)
app.add_middleware(ErrorHandlerMiddleware)

# Include API routers
app.include_router(api_router, prefix="/v1")

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint providing API information
    """
    return {
        "name": "Kong Guard AI API",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "openapi": "/openapi.json"
    }

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for monitoring
    """
    try:
        # Check database connection
        db_status = await check_database_health()
        
        # Check Kong integration
        kong_status = await KongIntegrationService.health_check()
        
        # Check AI Gateway if enabled
        ai_status = "disabled"
        if settings.AI_GATEWAY_ENABLED:
            ai_status = await check_ai_gateway_health()
        
        return {
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "database": db_status,
                "kong_integration": kong_status,
                "ai_gateway": ai_status
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

async def check_database_health() -> str:
    """Check database health status"""
    # Implementation would check actual database connection
    return "healthy"

async def check_ai_gateway_health() -> str:
    """Check AI Gateway health status"""
    # Implementation would check AI Gateway connection
    return "healthy"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )