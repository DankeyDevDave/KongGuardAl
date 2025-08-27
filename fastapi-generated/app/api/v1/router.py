"""
API v1 router aggregating all endpoints
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    configuration,
    threats,
    incidents,
    analytics,
    monitoring,
    remediation
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(
    configuration.router,
    prefix="/config",
    tags=["Configuration"]
)

api_router.include_router(
    threats.router,
    prefix="/threats",
    tags=["Threats"]
)

api_router.include_router(
    incidents.router,
    prefix="/incidents",
    tags=["Incidents"]
)

api_router.include_router(
    analytics.router,
    prefix="/analytics",
    tags=["Analytics"]
)

api_router.include_router(
    monitoring.router,
    prefix="/monitoring",
    tags=["Monitoring"]
)

api_router.include_router(
    remediation.router,
    prefix="/remediation",
    tags=["Remediation"]
)