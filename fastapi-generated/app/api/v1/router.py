"""
API v1 router aggregating all endpoints
"""

from app.api.v1.endpoints import analytics
from app.api.v1.endpoints import configuration
from app.api.v1.endpoints import incidents
from app.api.v1.endpoints import monitoring
from app.api.v1.endpoints import remediation
from app.api.v1.endpoints import threats
from fastapi import APIRouter

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(configuration.router, prefix="/config", tags=["Configuration"])

api_router.include_router(threats.router, prefix="/threats", tags=["Threats"])

api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])

api_router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])

api_router.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring"])

api_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation"])
