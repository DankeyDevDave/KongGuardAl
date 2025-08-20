# Kong Guard AI - Incident Management System (Phase 4)

## Overview

The Kong Guard AI Incident Management System provides comprehensive incident record generation, storage, correlation, and analysis for blocked requests with complete forensic data. This system enables security operations teams to understand, investigate, and respond to security threats with full context and traceability.

## Architecture

### Core Components

1. **Incident Manager** (`incident_manager.lua`)
   - Central incident record creation and management
   - Comprehensive forensic data collection
   - Incident correlation and attack pattern detection
   - Lifecycle management (create, update, resolve, archive)

2. **Incident Analytics** (`incident_analytics.lua`)
   - Real-time incident metrics and trends
   - Interactive web dashboard
   - Incident reporting and visualization
   - Statistical analysis and insights

3. **Incident Alerting** (`incident_alerting.lua`)
   - Real-time incident notifications
   - Multi-channel alerting (Slack, Teams, webhook, email)
   - Escalation workflows
   - Alert acknowledgment and resolution tracking

## Incident Record Schema

### Core Incident Fields

```lua
{
  -- Core identification
  incident_id = "INC-1692384000-001",
  correlation_id = "req-abc123",
  timestamp = 1692384000,
  created_at = "2023-08-18T14:00:00Z",
  
  -- Classification
  type = "sql_injection",           -- See INCIDENT_TYPES
  scope = "ip_address",             -- request, session, ip_address, global
  severity_level = "high",          -- low, medium, high, critical
  
  -- Evidence package
  evidence = {
    matched_patterns = [
      {
        pattern = 1,
        match = "union select",
        context = "param=1' union select * from users--"
      }
    ],
    source_ip = "192.168.1.100",
    request_details = {...},
    headers = {...},
    detection_details = {...}
  },
  
  -- Decision and action
  decision = "block",               -- block, rate_limit, monitor, escalate
  enforcement_result = {...},
  
  -- Request forensics
  request_forensics = {
    method = "POST",
    path = "/api/users",
    query_string = "id=1",
    headers = {...},
    body_snippet = "...",
    user_agent = "Mozilla/5.0...",
    referer = "https://example.com",
    content_type = "application/json"
  },
  
  -- Network forensics
  network_forensics = {
    source_ip = "192.168.1.100",
    x_forwarded_for = "10.0.0.1",
    x_real_ip = "203.0.113.1",
    port = "45123",
    protocol = "HTTP/1.1"
  },
  
  -- Kong context
  kong_context = {
    service_id = "service-uuid",
    route_id = "route-uuid",
    consumer_id = "consumer-uuid",
    node_id = "kong-node-1",
    worker_pid = 12345,
    request_id = "req-abc123"
  },
  
  -- Threat analysis details
  threat_analysis = {
    threat_level = 8.5,
    threat_type = "sql_injection",
    confidence = 0.95,
    patterns_matched = [...],
    ai_analysis = {...},
    behavioral_indicators = {...}
  },
  
  -- Lifecycle tracking
  lifecycle = {
    status = "active",              -- active, investigating, resolved, archived
    created_by = "kong-guard-ai-detector",
    assigned_to = null,
    last_updated = 1692384000,
    resolution_notes = null,
    archived_at = null
  },
  
  -- Correlation and aggregation
  correlation_data = {
    related_incidents = [...],
    attack_pattern = null,
    campaign_id = "CAMP-1692384000-abc123",
    repeat_offender = true,
    incident_count_for_ip = 5
  },
  
  -- Enrichment data (populated by external services)
  enrichment = {
    geo_location = {...},
    ip_reputation = {...},
    threat_intelligence = {...},
    asn_info = {...},
    enriched_at = 1692384000
  },
  
  -- Export metadata
  export_metadata = {
    exported_to_siem = false,
    siem_event_id = null,
    exported_formats = [],
    last_export_attempt = null
  }
}
```

## Incident Types

```lua
local INCIDENT_TYPES = {
    IP_BLACKLIST = "ip_blacklist",
    METHOD_DENIED = "method_denied", 
    PATH_BLOCKED = "path_blocked",
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded",
    PAYLOAD_INJECTION = "payload_injection",
    SQL_INJECTION = "sql_injection",
    XSS_ATTACK = "cross_site_scripting",
    PATH_TRAVERSAL = "path_traversal",
    BOT_DETECTION = "bot_detection",
    ANOMALOUS_BEHAVIOR = "anomalous_behavior",
    CREDENTIAL_STUFFING = "credential_stuffing",
    DDOS_ATTACK = "distributed_denial_of_service",
    API_ABUSE = "api_abuse",
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
}
```

## Configuration

### Basic Configuration

```yaml
# Enable incident management
incident_analytics_enabled: true
incident_alerting_enabled: true
incident_retention_days: 30
incident_body_snippet_size: 500
```

### Alerting Configuration

```yaml
# Notification channels
alert_notification_channels:
  - "webhook"
  - "slack"
  - "teams"

# Escalation settings
escalation_delay_seconds: 300      # 5 minutes
max_escalation_levels: 3
notification_retry_delay: 60
notification_max_retries: 3
alert_retention_days: 7

# Webhook configuration
webhook_notification_url: "https://your-webhook.example.com/alerts"
webhook_auth_header: "Authorization"
webhook_auth_token: "Bearer your-token"

# Slack integration
slack_webhook_url: "https://hooks.slack.com/services/..."

# Teams integration
teams_webhook_url: "https://outlook.office.com/webhook/..."
```

### SIEM Integration

```yaml
# SIEM export settings
enable_siem_export: true
siem_export_formats:
  - "json"
  - "cef"
  - "stix"
siem_export_endpoint: "https://your-siem.example.com/api/events"
siem_batch_size: 100
siem_export_interval: 300
```

### Threat Intelligence Enrichment

```yaml
# Threat intelligence
enable_threat_enrichment: true
threat_intel_providers:
  - "virustotal"
  - "abuseipdb"
threat_intel_api_keys:
  virustotal: "your-vt-api-key"
  abuseipdb: "your-abuseipdb-key"
threat_intel_cache_ttl: 3600
```

## Dashboard Access

### Incident Analytics Dashboard

Access the comprehensive incident analytics dashboard at:
```
https://your-kong-gateway/kong-guard-ai/incidents/dashboard
```

### API Endpoints

```bash
# Get incident metrics
GET /kong-guard-ai/incidents/api/metrics

# Get incident trends
GET /kong-guard-ai/incidents/api/trends

# Get top threats
GET /kong-guard-ai/incidents/api/top-threats

# Get live incident feed
GET /kong-guard-ai/incidents/api/live-feed

# Get specific incident details
GET /kong-guard-ai/incidents/api/incident/{incident_id}
```

## Key Features

### 1. Comprehensive Forensic Data Collection

- **Request Forensics**: Complete HTTP request details including headers, body snippets, query parameters
- **Network Forensics**: Source IP, proxy headers, protocol information
- **Context Forensics**: Kong service/route/consumer context, worker information
- **Threat Analysis**: Detection patterns, confidence scores, AI analysis results

### 2. Incident Correlation and Pattern Detection

- **IP-based Correlation**: Links incidents from the same source IP
- **Pattern-based Correlation**: Groups incidents with similar attack patterns
- **Attack Campaign Detection**: Identifies coordinated attacks across multiple IPs
- **Repeat Offender Tracking**: Tracks IPs with multiple violations

### 3. Real-time Alerting and Escalation

- **Multi-channel Notifications**: Slack, Teams, webhooks, email, SMS, PagerDuty
- **Automatic Escalation**: Escalates unacknowledged critical alerts
- **Retry Logic**: Automatic retry for failed notifications
- **Alert Acknowledgment**: Track who acknowledged and resolved alerts

### 4. Incident Analytics and Reporting

- **Real-time Dashboard**: Live incident metrics, trends, and feeds
- **Interactive Charts**: Incident trends, type distribution, severity analysis
- **Top Threats Analysis**: Identify most common attack patterns
- **Operational Metrics**: Success rates, response times, system health

### 5. SIEM Integration

- **Multiple Export Formats**: JSON, CEF (Common Event Format), STIX
- **Batched Export**: Efficient bulk export to reduce SIEM load
- **Automated Integration**: Configurable endpoints and intervals
- **Format Compatibility**: Works with major SIEM platforms

### 6. Threat Intelligence Enrichment

- **External Data Sources**: VirusTotal, AbuseIPDB, ThreatFox integration
- **IP Reputation**: Enhance incidents with known malicious IP data
- **Geolocation**: Add geographic context to incidents
- **ASN Information**: Include autonomous system details

### 7. Incident Lifecycle Management

- **Status Tracking**: Active, investigating, resolved, archived states
- **Assignment Management**: Assign incidents to security team members
- **Resolution Tracking**: Document resolution steps and outcomes
- **Automated Archival**: Clean up old incidents based on retention policies

## Integration Points

### 1. Detection Modules Integration

The incident manager integrates with all existing detection modules:

- **IP Blacklist**: Creates incidents for blacklisted IP detections
- **Method Filter**: Records HTTP method violations
- **Path Filter**: Captures path-based threats
- **Rate Limiter**: Documents rate limit violations
- **Payload Detector**: Records injection attack attempts

### 2. Enforcement Gate Integration

All incidents are created through the enforcement gate system, ensuring:

- **Dry-run Compatibility**: Incidents created even in dry-run mode
- **Consistent Logging**: Standardized incident creation process
- **Enforcement Correlation**: Links incidents to enforcement actions

### 3. Structured Logging Integration

Incidents leverage the structured logging system for:

- **Consistent Formats**: Standardized log output
- **Enhanced Metadata**: Rich contextual information
- **External System Integration**: Compatible with log aggregation tools

## Usage Examples

### 1. Basic Incident Investigation

```bash
# Get recent incidents
curl https://kong-gateway/kong-guard-ai/incidents/api/live-feed

# Get specific incident details
curl https://kong-gateway/kong-guard-ai/incidents/api/incident/INC-1692384000-001

# Check incident metrics
curl https://kong-gateway/kong-guard-ai/incidents/api/metrics
```

### 2. Webhook Notification Payload

```json
{
  "alert": {
    "alert_id": "ALERT-1692384000-001",
    "incident_id": "INC-1692384000-001",
    "alert_level": "critical",
    "title": "🚨 Kong Guard AI Alert: SQL injection detected from 192.168.1.100",
    "description": "Incident ID: INC-1692384000-001\nThreat Type: sql_injection\nSeverity: high\n...",
    "source_ip": "192.168.1.100",
    "threat_type": "sql_injection",
    "created_at": 1692384000
  },
  "timestamp": 1692384000,
  "source": "kong-guard-ai"
}
```

### 3. SIEM Export (CEF Format)

```
CEF:0|Kong|Kong Guard AI|1.0|sql_injection|Security Incident|8|src=192.168.1.100 suser=anonymous requestMethod=POST requestUrl=/api/users requestClientApplication=Mozilla/5.0... act=block cat=sql_injection cs1=INC-1692384000-001 cs1Label=IncidentID cn1=8 cn1Label=ThreatLevel
```

## Performance Considerations

### 1. Storage Optimization

- **Efficient Data Structures**: Optimized in-memory storage for active incidents
- **Automatic Cleanup**: Configurable retention policies prevent memory bloat
- **Batch Processing**: Bulk operations for SIEM exports and analytics

### 2. Processing Efficiency

- **Minimal Latency Impact**: Incident creation designed for <2ms overhead
- **Asynchronous Processing**: Non-blocking alert sending and enrichment
- **Cached Correlations**: Fast incident correlation using indexed data

### 3. Scalability Features

- **Worker-level Storage**: Distributed across Kong workers for scale
- **Correlation Indexes**: Fast lookup for related incidents
- **Configurable Limits**: Tunable cache sizes and retention periods

## Security Considerations

### 1. Data Sanitization

- **Header Sanitization**: Automatic removal of sensitive authentication data
- **Body Snippet Limits**: Configurable size limits for request body storage
- **PII Protection**: Careful handling of personally identifiable information

### 2. Access Control

- **Dashboard Security**: Web dashboard should be behind authentication
- **API Protection**: Incident API endpoints require proper access controls
- **Webhook Security**: Support for authenticated webhook endpoints

### 3. Data Retention

- **Configurable Retention**: Balance security needs with storage constraints
- **Secure Deletion**: Proper cleanup of archived incident data
- **Compliance Support**: Features to support regulatory requirements

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check incident retention settings
   - Verify cleanup processes are running
   - Monitor correlation index sizes

2. **Missing Alerts**
   - Verify notification channel configuration
   - Check webhook endpoint availability
   - Review alert threshold settings

3. **Dashboard Not Loading**
   - Ensure `incident_analytics_enabled` is true
   - Check Kong Gateway access logs
   - Verify dashboard endpoint accessibility

### Debugging

```bash
# Check incident statistics
curl https://kong-gateway/kong-guard-ai/incidents/api/metrics

# Monitor Kong logs for incident messages
tail -f /var/log/kong/error.log | grep "Incident Manager"

# Verify configuration
kong config db_export
```

## Future Enhancements

### Planned Features

1. **Machine Learning Integration**
   - Automated incident severity scoring
   - Anomaly detection for incident patterns
   - Predictive threat modeling

2. **Advanced Visualization**
   - Geographic threat mapping
   - Attack timeline visualization
   - Interactive incident investigation tools

3. **Integration Expansions**
   - Additional SIEM platform support
   - Enhanced threat intelligence sources
   - Custom webhook templates

4. **Automation Features**
   - Automated incident response workflows
   - Dynamic blocking based on incident patterns
   - Integration with ticketing systems

## Conclusion

The Kong Guard AI Incident Management System provides enterprise-grade security incident handling with comprehensive forensic data collection, real-time alerting, and operational analytics. This system enables security teams to effectively monitor, investigate, and respond to threats with full context and traceability.

For additional support or feature requests, refer to the main Kong Guard AI documentation or submit issues through the project repository.