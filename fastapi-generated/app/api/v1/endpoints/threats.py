"""
Threat detection and analysis endpoints
Auto-generated from Kong Guard AI threat detection modules
"""

from datetime import datetime
from datetime import timedelta
from typing import Optional
from uuid import UUID

from app.core.dependencies import get_current_user
from app.models.schemas import AIAnalysisRequest
from app.models.schemas import AIAnalysisResponse
from app.models.schemas import PaginationInfo
from app.models.schemas import SeverityLevel
from app.models.schemas import ThreatDetail
from app.models.schemas import ThreatList
from app.models.schemas import ThreatStatus
from app.models.schemas import ThreatType
from app.services.ai_analysis_service import AIAnalysisService
from app.services.configuration_service import ConfigurationService
from app.services.threat_service import ThreatService
from fastapi import APIRouter
from fastapi import BackgroundTasks
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Path
from fastapi import Query
from fastapi import status

router = APIRouter()


@router.get("/", response_model=ThreatList)
async def list_threats(
    start_time: Optional[datetime] = Query(None, description="Start time for threat query"),
    end_time: Optional[datetime] = Query(None, description="End time for threat query"),
    severity: Optional[SeverityLevel] = Query(None, description="Filter by threat severity"),
    status: Optional[ThreatStatus] = Query(None, description="Filter by threat status"),
    threat_type: Optional[ThreatType] = Query(None, description="Filter by threat type"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: dict = Depends(get_current_user),
) -> ThreatList:
    """
    List detected threats with filtering and pagination.

    Returns threats detected by Kong Guard AI, sorted by timestamp (newest first).

    **Filters**:
    - Time range: Use start_time and end_time
    - Severity: Filter by threat severity level
    - Status: Filter by current threat status
    - Type: Filter by specific threat type
    - Source IP: Filter by attacking IP address
    """
    try:
        # Default time range if not specified
        if not end_time:
            end_time = datetime.utcnow()
        if not start_time:
            start_time = end_time - timedelta(hours=24)

        # Query threats from service
        threats, total = await ThreatService.list_threats(
            start_time=start_time,
            end_time=end_time,
            severity=severity,
            status=status,
            threat_type=threat_type,
            source_ip=source_ip,
            limit=limit,
            offset=offset,
        )

        return ThreatList(
            total=total,
            threats=threats,
            pagination=PaginationInfo(limit=limit, offset=offset, total=total, has_more=(offset + limit) < total),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve threats: {str(e)}"
        )


@router.get("/{threat_id}", response_model=ThreatDetail)
async def get_threat(
    threat_id: UUID = Path(..., description="Threat ID"), current_user: dict = Depends(get_current_user)
) -> ThreatDetail:
    """
    Get detailed information about a specific threat.

    Returns comprehensive threat data including:
    - Request details (headers, body, path)
    - Detection patterns matched
    - AI analysis results (if available)
    - Remediation actions taken
    """
    try:
        threat = await ThreatService.get_threat_by_id(threat_id)

        if not threat:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat {threat_id} not found")

        return threat
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve threat: {str(e)}"
        )


@router.post("/{threat_id}/analyze", response_model=AIAnalysisResponse)
async def analyze_threat(
    background_tasks: BackgroundTasks,
    threat_id: UUID = Path(..., description="Threat ID"),
    request: Optional[AIAnalysisRequest] = None,
    current_user: dict = Depends(get_current_user),
) -> AIAnalysisResponse:
    """
    Trigger AI analysis for a specific threat.

    Initiates deep analysis using the configured AI model (GPT-4, etc.).
    Analysis runs asynchronously and results can be retrieved later.

    **Note**: This may incur API costs depending on your AI Gateway configuration.
    """
    try:
        # Check if threat exists
        threat = await ThreatService.get_threat_by_id(threat_id)
        if not threat:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat {threat_id} not found")

        # Create request object if not provided
        if request is None:
            request = AIAnalysisRequest()

        # Check if AI Gateway is enabled
        config = await ConfigurationService.get_current_configuration()
        if config is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Configuration service unavailable"
            )

        if not config.ai_gateway_enabled:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="AI Gateway is not enabled")

        # Check threat score threshold
        if threat.threat_score < config.ai_analysis_threshold:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Threat score {threat.threat_score} below AI analysis threshold {config.ai_analysis_threshold}",
            )

        # Initiate analysis
        analysis_response = await AIAnalysisService.initiate_analysis(
            threat=threat, model=request.model, deep_analysis=request.deep_analysis, background_tasks=background_tasks
        )

        return analysis_response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to initiate analysis: {str(e)}"
        )


@router.get("/{threat_id}/analysis", response_model=dict)
async def get_threat_analysis(
    threat_id: UUID = Path(..., description="Threat ID"), current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Get AI analysis results for a threat.

    Returns the analysis results if available, or the current status if still processing.
    """
    try:
        analysis = await AIAnalysisService.get_analysis_results(threat_id)

        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"No analysis found for threat {threat_id}"
            )

        return analysis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve analysis: {str(e)}"
        )


@router.post("/{threat_id}/mitigate", response_model=dict)
async def mitigate_threat(
    threat_id: UUID = Path(..., description="Threat ID"),
    action: str = Query(..., description="Mitigation action to take"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Manually trigger mitigation action for a threat.

    Available actions depend on threat type and configuration:
    - block_ip: Add source IP to blacklist
    - rate_limit: Apply rate limiting to source
    - log_only: Log threat without blocking
    - dismiss: Mark as false positive
    """
    try:
        threat = await ThreatService.get_threat_by_id(threat_id)
        if not threat:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat {threat_id} not found")

        # Validate action
        valid_actions = ["block_ip", "rate_limit", "log_only", "dismiss"]
        if action not in valid_actions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid action. Must be one of: {valid_actions}"
            )

        # Execute mitigation
        result = await ThreatService.mitigate_threat(threat_id, action, current_user)

        return {
            "status": "success",
            "threat_id": str(threat_id),
            "action": action,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to mitigate threat: {str(e)}"
        )


@router.get("/statistics/summary", response_model=dict)
async def get_threat_statistics(
    period: str = Query("24h", description="Time period (1h, 6h, 24h, 7d, 30d)"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Get threat statistics summary.

    Returns aggregated statistics including:
    - Total threats by type and severity
    - Top attacking IPs
    - Threat trends over time
    - Mitigation effectiveness
    """
    try:
        # Parse period
        period_map = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }

        if period not in period_map:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid period. Must be one of: {list(period_map.keys())}",
            )

        end_time = datetime.utcnow()
        start_time = end_time - period_map[period]

        statistics = await ThreatService.get_statistics(start_time, end_time)

        return statistics
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve statistics: {str(e)}"
        )


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat(
    threat_id: UUID = Path(..., description="Threat ID"), current_user: dict = Depends(get_current_user)
):
    """
    Delete a threat record.

    This only removes the threat from the database, it doesn't undo any mitigation actions.

    **Note**: Requires appropriate permissions.
    """
    try:
        success = await ThreatService.delete_threat(threat_id)

        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat {threat_id} not found")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete threat: {str(e)}"
        )


# Helper function is no longer needed as ConfigurationService is imported at module level
