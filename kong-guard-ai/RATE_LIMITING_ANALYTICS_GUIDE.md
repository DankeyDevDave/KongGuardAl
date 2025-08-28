# Kong Guard AI - Rate Limiting & Analytics Guide

This guide covers the advanced rate limiting (Phase 5) and real-time analytics dashboard (Phase 6) features of Kong Guard AI.

## 🚦 Advanced Rate Limiting (Phase 5)

### Overview

The advanced rate limiting system provides sophisticated traffic control with sliding window algorithms, burst detection, and progressive penalties.

### Key Features

- **Sliding Window Rate Limiting**: Accurate rate limiting using sliding time windows
- **Multiple Time Windows**: 1 minute, 5 minutes, 1 hour, and 24 hour limits
- **Burst Detection**: Identifies traffic spikes above baseline patterns
- **Progressive Penalties**: Escalating responses (warn → throttle → block)
- **Dynamic Adjustment**: Rate limits adjust based on threat levels
- **IP Whitelisting**: Bypass rate limiting for trusted sources
- **Per-User Limiting**: Rate limiting based on consumer/user ID

### Configuration

#### Basic Rate Limiting Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable advanced rate limiting
    enable_advanced_rate_limiting: true
    
    # Rate limits per IP address
    rate_limit_per_minute: 60
    rate_limit_per_five_minutes: 300
    rate_limit_per_hour: 3600
    rate_limit_per_day: 86400
    
    # Dynamic adjustment based on threat level
    dynamic_rate_adjustment: true
```

#### Burst Detection Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable burst detection
    enable_burst_detection: true
    
    # Burst thresholds (percentage above baseline)
    burst_threshold_light: 200    # 200% = 2x normal rate
    burst_threshold_medium: 500   # 500% = 5x normal rate  
    burst_threshold_severe: 1000  # 1000% = 10x normal rate
```

#### Progressive Penalties Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable progressive penalties
    progressive_penalty_enabled: true
    
    # Penalty durations
    penalty_warning_duration: 600    # 10 minutes
    penalty_throttle_duration: 1800  # 30 minutes
    penalty_block_duration: 3600     # 1 hour
```

#### Whitelisting Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Static IP whitelist
    rate_limit_bypass_whitelist:
      - "203.0.113.100"
      - "198.51.100.0/24"
      
    # Also respects ip_whitelist for general whitelisting
    ip_whitelist:
      - "trusted.server.com"
      - "233.252.0.0/16"
```

### API Usage

#### Check Rate Limit Status

```bash
# Check current rate limit status for an IP
curl -H "X-Forwarded-For: 203.0.113.100" \
     http://your-api.com/api/endpoint
```

Response headers include:
- `X-RateLimit-Limit`: Current rate limit
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Reset timestamp
- `X-Kong-Guard-AI`: Plugin status

#### Dynamic Whitelist Management

```bash
# Add IP to whitelist via rate_limiter module
# (This would be done through admin API integration)
```

### Rate Limiting Algorithm

The system uses a sliding window algorithm with multiple time buckets:

1. **Time Window Division**: Each time window is divided into 10 buckets
2. **Bucket Rotation**: Buckets rotate as time progresses
3. **Request Counting**: Requests are counted in the current bucket
4. **Window Calculation**: Total requests = sum of all buckets in window
5. **Limit Enforcement**: Compare total against configured limits

### Burst Detection Algorithm

1. **Baseline Calculation**: Exponential moving average of normal traffic
2. **Current Rate Comparison**: Compare current rate to baseline
3. **Severity Classification**: Light/Medium/Severe based on thresholds
4. **Progressive Response**: Apply appropriate penalty based on severity

### Progressive Penalty System

| Penalty Level | Rate Limit Multiplier | Duration | Trigger |
|---------------|----------------------|----------|---------|
| WARNING | 1.0x (no reduction) | 10 min | Light burst |
| THROTTLED | 0.5x (50% reduction) | 30 min | Medium burst |
| BLOCKED | 0.1x (90% reduction) | 1 hour | Severe burst |

### Performance Characteristics

- **Latency Impact**: <2ms per request
- **Memory Usage**: ~128MB shared memory for rate limiting data
- **Throughput**: Supports 10K+ RPS with accurate limiting
- **Scaling**: Handles 100K+ unique IP addresses efficiently

---

## 📊 Real-Time Analytics Dashboard (Phase 6)

### Overview

The analytics dashboard provides comprehensive threat intelligence, predictive analytics, and operational insights for security teams.

### Key Features

- **Real-Time Threat Monitoring**: Live threat detection and trending
- **Geographic Analysis**: Attack pattern visualization by region
- **Threat Intelligence Integration**: External feed integration
- **Predictive Analytics**: Machine learning-based threat prediction
- **Anomaly Detection**: Automated detection of unusual patterns
- **Correlation Analysis**: Multi-stage attack detection
- **Compliance Reporting**: PCI DSS, GDPR, SOX compliance
- **Executive Dashboard**: High-level security KPIs

### Configuration

#### Basic Analytics Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable analytics dashboard
    analytics_dashboard_enabled: true
    analytics_endpoint_path: "/_guard_ai/analytics"
    
    # Data retention
    analytics_data_retention_days: 30
```

#### Threat Intelligence Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable threat intelligence
    enable_threat_intelligence: true
    
    # Threat intelligence feeds
    threat_intel_feeds:
      - "alienvault_otx"
      - "abuse_ch_malware"
      - "spamhaus_drop"
      - "emerging_threats"
    
    # Update interval
    threat_intel_update_interval: 3600  # 1 hour
    
    # External API key
    external_threat_intel_api_key: "your_api_key_here"
```

#### Geographic Analysis Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable geographic analysis
    enable_geographic_analysis: true
    
    # GeoIP service URL (optional)
    geoip_service_url: "https://api.maxmind.com/geoip/v2.1/city"
```

#### Predictive Analytics Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable predictive analytics
    enable_predictive_analytics: true
    
    # Confidence threshold for predictions
    prediction_confidence_threshold: 0.7
    
    # Anomaly detection
    enable_anomaly_detection: true
    anomaly_threshold_multiplier: 3.0
```

#### Correlation Analysis Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable correlation analysis
    enable_correlation_analysis: true
    
    # Time window for correlating attacks
    correlation_window_seconds: 300  # 5 minutes
```

#### Compliance Reporting Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable compliance reporting
    enable_compliance_reporting: true
    
    # Supported frameworks
    compliance_frameworks:
      - "pci_dss"
      - "gdpr"
      - "sox"
      - "hipaa"
```

### Dashboard Endpoints

#### Executive KPIs
```bash
GET /_guard_ai/analytics/kpis
```

Response:
```json
{
  "generated_at": 1640995200,
  "security_posture": {
    "overall_score": 85,
    "threats_blocked_24h": 342,
    "critical_incidents": 0,
    "mean_time_to_detect": 1.2,
    "mean_time_to_respond": 0.8
  },
  "operational_metrics": {
    "availability": 99.99,
    "performance_impact": 0.02,
    "false_positive_rate": 0.1,
    "coverage_percentage": 98.5
  },
  "compliance_status": {
    "pci_dss": "COMPLIANT",
    "gdpr": "COMPLIANT",
    "sox": "COMPLIANT"
  }
}
```

#### Real-Time Threats
```bash
GET /_guard_ai/analytics/threats
```

Response:
```json
{
  "timestamp": 1640995200,
  "active_threats": {
    "total": 15,
    "by_type": {
      "sql_injection": 5,
      "xss": 3,
      "ddos": 4,
      "scanner": 2,
      "malware": 1
    },
    "by_severity": {
      "critical": 2,
      "high": 4,
      "medium": 6,
      "low": 3
    }
  },
  "trending": {
    "last_hour": 15,
    "last_24h": 342,
    "last_week": 2156
  },
  "top_sources": [
    {"ip": "203.0.113.100", "count": 5, "country": "CN"},
    {"ip": "198.51.100.50", "count": 3, "country": "RU"}
  ]
}
```

#### Geographic Analysis
```bash
GET /_guard_ai/analytics/geo
```

Response:
```json
{
  "timestamp": 1640995200,
  "by_region": {
    "Asia Pacific": {"total": 145, "critical": 12},
    "Europe": {"total": 89, "critical": 5},
    "North America": {"total": 67, "critical": 3}
  },
  "attack_vectors_by_region": {
    "Asia Pacific": ["ddos", "scanner", "malware"],
    "Europe": ["sql_injection", "xss"],
    "North America": ["scanner", "exploit"]
  },
  "threat_migration_patterns": [
    {
      "from": "CN",
      "to": "US", 
      "threat_type": "ddos",
      "confidence": 0.85
    }
  ]
}
```

#### Threat Predictions
```bash
GET /_guard_ai/analytics/predictions
```

Response:
```json
[
  {
    "threat_type": "sql_injection",
    "trend_direction": "increasing",
    "confidence": 0.82,
    "predicted_increase": 25,
    "timeframe": "next_24h",
    "risk_level": "HIGH"
  },
  {
    "threat_type": "ddos",
    "trend_direction": "decreasing", 
    "confidence": 0.76,
    "predicted_increase": -10,
    "timeframe": "next_24h",
    "risk_level": "MEDIUM"
  }
]
```

#### Compliance Reports
```bash
GET /_guard_ai/analytics/compliance?framework=pci_dss&timeframe=daily
```

Response:
```json
{
  "framework": "PCI DSS",
  "timeframe": "daily",
  "generated_at": 1640995200,
  "compliance_score": 85,
  "requirements": [
    {
      "requirement": "6.5.1",
      "description": "Injection flaws, particularly SQL injection",
      "status": "NON_COMPLIANT",
      "threat_count": 5,
      "details": "SQL injection attempts detected"
    },
    {
      "requirement": "6.5.7",
      "description": "Cross-site scripting (XSS)",
      "status": "COMPLIANT", 
      "threat_count": 0,
      "details": "No XSS attempts"
    }
  ]
}
```

### Analytics Data Model

#### Threat Event Structure
```json
{
  "timestamp": 1640995200,
  "threat_type": "sql_injection",
  "threat_level": 8.5,
  "client_ip": "203.0.113.100",
  "country_code": "CN",
  "region": "Asia Pacific",
  "user_agent": "Mozilla/5.0...",
  "request_path": "/api/users",
  "request_method": "POST",
  "correlation_id": "req-123-456",
  "enforcement_action": "blocked"
}
```

#### Correlation Pattern Structure
```json
{
  "correlation_id": "pattern-789",
  "ip_address": "203.0.113.100", 
  "threat_sequence": [
    {"threat_type": "scanner", "timestamp": 1640995100},
    {"threat_type": "sql_injection", "timestamp": 1640995150},
    {"threat_type": "xss", "timestamp": 1640995200}
  ],
  "correlation_score": 0.85,
  "attack_pattern": "reconnaissance_to_exploitation"
}
```

### Performance Characteristics

- **Analytics Latency**: <5ms per event recording
- **Memory Usage**: ~256MB for analytics data
- **Data Throughput**: 10K+ events per second
- **Dashboard Response**: <100ms for most queries
- **Storage Efficiency**: Compressed time-series data

### Integration Examples

#### Grafana Dashboard Integration
```bash
# Configure Grafana to poll analytics endpoints
curl -X POST http://grafana:3000/api/datasources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Kong Guard AI",
    "type": "json",
    "url": "http://kong:8000/_guard_ai/analytics",
    "access": "proxy"
  }'
```

#### Splunk Integration
```bash
# Configure Splunk HTTP Event Collector
curl -X POST "https://splunk:8088/services/collector" \
  -H "Authorization: Splunk your-token" \
  -d '{"event": "threat_detected", "source": "kong-guard-ai"}'
```

#### Elasticsearch Integration
```bash
# Index threat events in Elasticsearch
curl -X POST "http://elasticsearch:9200/kong-guard-ai-threats/_doc" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "2021-12-31T12:00:00Z", "threat_type": "sql_injection"}'
```

## 🔧 Troubleshooting

### Common Issues

#### Rate Limiting Issues

**Problem**: Rate limiting not working
- Check shared memory configuration: `lua_shared_dict kong_guard_ai_rate_limits 128m`
- Verify plugin is enabled: `enable_advanced_rate_limiting: true`
- Check logs for initialization errors

**Problem**: Rate limits too strict/loose
- Adjust time window limits: `rate_limit_per_minute`, etc.
- Review burst detection thresholds
- Check dynamic adjustment settings

#### Analytics Issues

**Problem**: Analytics dashboard not accessible
- Verify endpoint path: `analytics_endpoint_path: "/_guard_ai/analytics"`
- Check plugin configuration: `analytics_dashboard_enabled: true`
- Ensure shared memory zones are configured

**Problem**: Missing geographic data
- Configure GeoIP service: `geoip_service_url`
- Check threat intelligence feeds
- Verify API keys

### Performance Tuning

#### Memory Optimization
```nginx
# Increase shared memory zones for high traffic
lua_shared_dict kong_guard_ai_rate_limits 256m
lua_shared_dict kong_guard_ai_analytics 512m
lua_shared_dict kong_guard_ai_threat_intel 256m
```

#### CPU Optimization
```yaml
# Reduce processing overhead
config:
  analytics_data_retention_days: 7    # Shorter retention
  threat_intel_update_interval: 7200  # Less frequent updates
  enable_predictive_analytics: false  # Disable if not needed
```

### Monitoring

#### Key Metrics to Monitor
- Rate limiting memory usage
- Analytics processing latency
- Threat detection accuracy
- Dashboard response times
- Compliance score trends

#### Log Analysis
```bash
# Monitor rate limiting events
grep "Rate limit exceeded" /var/log/kong/error.log

# Track analytics performance
grep "Analytics" /var/log/kong/access.log

# Monitor threat patterns
grep "Threat detected" /var/log/kong/error.log
```

## 📈 Best Practices

### Rate Limiting
1. Start with conservative limits and adjust based on traffic patterns
2. Use whitelisting for trusted sources
3. Monitor burst detection patterns to tune thresholds
4. Implement graduated penalties for repeat offenders
5. Consider time-of-day variations in traffic

### Analytics
1. Configure appropriate data retention policies
2. Set up automated alerting on key metrics
3. Regularly review compliance reports
4. Use predictive analytics to proactively address threats
5. Correlate with external threat intelligence

### Security
1. Restrict access to analytics endpoints
2. Use HTTPS for all dashboard communications
3. Rotate API keys regularly
4. Monitor for suspicious admin API usage
5. Implement proper access controls

This comprehensive guide provides the foundation for implementing and managing the advanced rate limiting and analytics capabilities of Kong Guard AI.