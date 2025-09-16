"""
Pydantic schemas for Kong Guard AI API
Auto-generated from Kong plugin schema.lua analysis
"""

from datetime import datetime
from enum import Enum
from typing import Any
from typing import Optional
from typing import Union
from uuid import UUID

from pydantic import BaseModel
from pydantic import Field
from pydantic import confloat
from pydantic import conint


# Enums
class ThreatType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RATE_LIMIT = "rate_limit"
    IP_REPUTATION = "ip_reputation"
    PATH_TRAVERSAL = "path_traversal"
    SUSPICIOUS_PAYLOAD = "suspicious_payload"


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(str, Enum):
    DETECTED = "detected"
    ANALYZING = "analyzing"
    MITIGATED = "mitigated"
    BLOCKED = "blocked"


class ActionTaken(str, Enum):
    LOGGED = "logged"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    NONE = "none"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class RateLimitAction(str, Enum):
    THROTTLE = "throttle"
    BLOCK = "block"
    LOG = "log"


# Configuration Schemas
class PluginConfiguration(BaseModel):
    """Kong Guard AI plugin configuration"""

    dry_run_mode: bool = Field(True, description="Enable dry run mode")
    threat_threshold: confloat(ge=1.0, le=10.0) = Field(8.0, description="Threat threshold (1-10)")
    max_processing_time_ms: conint(ge=1, le=100) = Field(5, description="Max processing time in ms")

    # Rate limiting
    enable_rate_limiting_detection: bool = True
    rate_limit_window_seconds: conint(ge=1, le=3600) = 60
    rate_limit_threshold: conint(ge=1, le=10000) = 150

    # IP reputation
    enable_ip_reputation: bool = True
    ip_whitelist: list[str] = Field(default_factory=list)
    ip_blacklist: list[str] = Field(default_factory=list)
    enable_ip_blacklist: bool = True
    ip_blacklist_ttl_seconds: conint(ge=60, le=86400) = 3600
    trust_proxy_headers: bool = True
    ip_blacklist_max_size: conint(ge=100, le=100000) = 10000

    # Payload analysis
    enable_payload_analysis: bool = True
    max_payload_size: conint(ge=1024, le=10485760) = 262144
    suspicious_patterns: list[str] = Field(
        default_factory=lambda: [
            r"\bunion\b.*\bselect\b",
            r"\bdrop\b.*\btable\b",
            r"<script",
            r"javascript:",
            r"eval\(",
            r"system\(",
            r"\.\./.*etc/passwd",
        ]
    )

    # AI Gateway
    ai_gateway_enabled: bool = False
    ai_gateway_model: str = "gpt-4o-mini"
    ai_gateway_endpoint: Optional[str] = None
    ai_analysis_threshold: confloat(ge=1.0, le=10.0) = 6.0
    ai_timeout_ms: conint(ge=100, le=30000) = 3000

    # Auto blocking
    enable_auto_blocking: bool = False
    block_duration_seconds: conint(ge=60, le=86400) = 1800

    # Notification
    enable_notifications: bool = True
    notification_channels: list[str] = Field(default_factory=lambda: ["log"])
    notification_threshold: confloat(ge=1.0, le=10.0) = 7.0

    # Performance
    enable_caching: bool = True
    cache_ttl_seconds: conint(ge=1, le=3600) = 300
    enable_performance_optimization: bool = True

    class Config:
        schema_extra = {
            "example": {
                "dry_run_mode": True,
                "threat_threshold": 8.0,
                "max_processing_time_ms": 5,
                "enable_rate_limiting_detection": True,
                "rate_limit_threshold": 150,
            }
        }


class PartialConfiguration(BaseModel):
    """Partial configuration for PATCH updates"""

    dry_run_mode: Optional[bool] = None
    threat_threshold: Optional[confloat(ge=1.0, le=10.0)] = None
    max_processing_time_ms: Optional[conint(ge=1, le=100)] = None
    enable_rate_limiting_detection: Optional[bool] = None
    rate_limit_threshold: Optional[conint(ge=1, le=10000)] = None
    enable_ip_reputation: Optional[bool] = None
    enable_payload_analysis: Optional[bool] = None
    ai_gateway_enabled: Optional[bool] = None
    enable_auto_blocking: Optional[bool] = None


class ConfigurationResponse(BaseModel):
    """Configuration operation response"""

    status: str
    message: str
    configuration: PluginConfiguration
    timestamp: datetime


# Threat Schemas
class ThreatBase(BaseModel):
    """Base threat model"""

    type: ThreatType
    severity: SeverityLevel
    threat_score: confloat(ge=0, le=10)
    source_ip: str
    path: Optional[str] = None
    method: Optional[HTTPMethod] = None


class Threat(ThreatBase):
    """Threat model with metadata"""

    id: UUID
    timestamp: datetime
    status: ThreatStatus = ThreatStatus.DETECTED
    action_taken: ActionTaken = ActionTaken.NONE

    class Config:
        orm_mode = True


class ThreatDetail(Threat):
    """Detailed threat information"""

    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    analysis: Optional[dict[str, Any]] = None


class ThreatCreate(ThreatBase):
    """Create new threat"""

    pass


class ThreatList(BaseModel):
    """Threat list response"""

    total: int
    threats: list[Threat]
    pagination: "PaginationInfo"


# Incident Schemas
class IncidentBase(BaseModel):
    """Base incident model"""

    title: str
    description: Optional[str] = None
    priority: SeverityLevel
    affected_services: list[str] = Field(default_factory=list)


class Incident(IncidentBase):
    """Incident model"""

    id: UUID
    created_at: datetime
    updated_at: datetime
    status: IncidentStatus = IncidentStatus.OPEN
    threat_count: int = 0
    assignee: Optional[str] = None

    class Config:
        orm_mode = True


class CreateIncident(IncidentBase):
    """Create new incident"""

    threat_ids: list[UUID] = Field(default_factory=list)


class UpdateIncident(BaseModel):
    """Update incident"""

    status: Optional[IncidentStatus] = None
    notes: Optional[str] = None
    assignee: Optional[str] = None


class IncidentDetail(Incident):
    """Detailed incident information"""

    threats: list[Threat]
    timeline: list[dict[str, Any]]
    remediation_actions: list[dict[str, Any]]


# Analytics Schemas
class DashboardSummary(BaseModel):
    """Dashboard summary statistics"""

    total_requests: int
    threats_detected: int
    threats_blocked: int
    active_incidents: int
    average_response_time_ms: float


class ThreatDistribution(BaseModel):
    """Threat type distribution"""

    sql_injection: int = 0
    xss: int = 0
    rate_limit: int = 0
    ip_reputation: int = 0
    path_traversal: int = 0
    suspicious_payload: int = 0


class AttackingIP(BaseModel):
    """Attacking IP information"""

    ip: str
    count: int
    last_seen: datetime


class TimeSeriesData(BaseModel):
    """Time series data point"""

    timestamp: datetime
    requests: int
    threats: int
    blocked: int


class DashboardData(BaseModel):
    """Complete dashboard data"""

    summary: DashboardSummary
    threat_distribution: ThreatDistribution
    top_attacking_ips: list[AttackingIP]
    time_series: list[TimeSeriesData]


# Report Schemas
class ReportType(str, Enum):
    THREAT_SUMMARY = "threat_summary"
    INCIDENT_ANALYSIS = "incident_analysis"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"


class ReportFormat(str, Enum):
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"


class ReportPeriod(BaseModel):
    """Report period specification"""

    start: datetime
    end: datetime


class CreateReportRequest(BaseModel):
    """Request to generate report"""

    type: ReportType
    period: ReportPeriod
    format: ReportFormat = ReportFormat.JSON


class Report(BaseModel):
    """Report metadata"""

    id: UUID
    type: ReportType
    created_at: datetime
    period: ReportPeriod
    status: str
    download_url: Optional[str] = None


# Monitoring Schemas
class ComponentHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DISABLED = "disabled"


class HealthCheck(BaseModel):
    """Health check result"""

    name: str
    status: str
    message: Optional[str] = None


class HealthStatus(BaseModel):
    """System health status"""

    status: ComponentHealth
    version: str
    uptime_seconds: int
    components: dict[str, ComponentHealth]
    checks: list[HealthCheck]


class MetricsData(BaseModel):
    """Performance metrics"""

    requests: dict[str, Union[int, float]]
    threats: dict[str, Union[int, float]]
    performance: dict[str, float]
    resources: dict[str, Union[int, float]]


# Remediation Schemas
class BlacklistedIP(BaseModel):
    """Blacklisted IP entry"""

    ip: str
    added_at: datetime
    expires_at: datetime
    reason: Optional[str] = None
    threat_count: int = 0
    last_seen: Optional[datetime] = None


class AddIPToBlacklist(BaseModel):
    """Add IP to blacklist request"""

    ip: str
    ttl: conint(ge=60, le=86400) = 3600
    reason: Optional[str] = None


class RateLimitRule(BaseModel):
    """Rate limit rule"""

    id: UUID
    name: str
    path_pattern: str = "/*"
    method: str = "*"
    limit: int
    window_seconds: int
    action: RateLimitAction = RateLimitAction.THROTTLE
    enabled: bool = True
    created_at: datetime


class CreateRateLimitRule(BaseModel):
    """Create rate limit rule request"""

    name: str
    path_pattern: str = "/*"
    method: str = "*"
    limit: conint(ge=1)
    window_seconds: conint(ge=1)
    action: RateLimitAction = RateLimitAction.THROTTLE
    enabled: bool = True


# Common Schemas
class PaginationInfo(BaseModel):
    """Pagination information"""

    limit: int
    offset: int
    total: int
    has_more: bool


class ErrorResponse(BaseModel):
    """Error response"""

    error: str
    message: str
    details: Optional[dict[str, Any]] = None
    timestamp: datetime


# AI Analysis Schemas
class AIAnalysisRequest(BaseModel):
    """AI analysis request"""

    model: str = "gpt-4o-mini"
    deep_analysis: bool = False


class AIAnalysisResponse(BaseModel):
    """AI analysis response"""

    analysis_id: UUID
    status: str
    estimated_completion: datetime
    model: str


class AIAnalysisResult(BaseModel):
    """AI analysis result"""

    analysis: str
    confidence: confloat(ge=0, le=1)
    patterns_matched: list[str]
    recommendations: list[str]


# Update forward references
ThreatList.model_rebuild()
