# Kong Guard AI - Custom Log Format Design

## Overview

The Kong Guard AI plugin implements a sophisticated structured JSON log format optimized for security instrumentation, threat detection, and integration with modern log analysis systems. This design provides comprehensive request/response metadata capture while maintaining optimal performance and security.

## Design Principles

### 1. **Security-First Approach**
- Automatic redaction of sensitive headers (Authorization tokens)
- Sanitized cookie logging (names only, no values)
- Configurable header filtering to prevent information leakage
- Real IP detection through proxy chains and CDNs

### 2. **Performance Optimized**
- Pre-compiled header lookup tables for O(1) filtering
- Minimal string operations and memory allocations
- Configurable log levels to control verbosity
- Efficient JSON serialization with error handling

### 3. **Structured for Analysis**
- JSON format compatible with ELK Stack, Splunk, Datadog, CloudWatch
- Consistent field naming and data types
- Correlation IDs for request tracing
- Hierarchical data organization for easy querying

### 4. **Kong Integration**
- Full Kong plugin lifecycle integration
- Access to Kong's routing context (Services, Routes, Consumers)
- Integration with Kong's logging infrastructure
- Compatible with Kong's shared memory zones

## Log Format Structure

### Base Fields (All Log Types)

```json
{
  "timestamp": 1640995200,
  "iso_timestamp": "2021-12-31T18:00:00Z",
  "request_id": "req-123-abc",
  "kong_request_id": "kong-456-def",
  "guard_ai_version": "0.1.0",
  "log_type": "access|response|threat_incident|performance_metrics",
  "log_level": "DEBUG|INFO|WARN|ERROR"
}
```

### Access Log Entry (Request Phase)

Captured during Kong's `access` phase to record incoming request metadata:

```json
{
  "timestamp": 1640995200,
  "iso_timestamp": "2021-12-31T18:00:00Z",
  "request_id": "req-123-abc",
  "kong_request_id": "kong-456-def",
  "log_type": "access",
  
  "client_ip": "203.0.113.1",
  "method": "POST", 
  "path": "/api/v1/users",
  "raw_query_string": "format=json&limit=10",
  "scheme": "https",
  
  "headers": {
    "user-agent": "curl/7.68.0",
    "content-type": "application/json",
    "authorization": "Bearer [REDACTED]",
    "x-forwarded-for": "203.0.113.1, 192.168.1.1",
    "content-length": "156",
    "host": "api.example.com"
  },
  
  "service_id": "service-456",
  "service_name": "user-service",
  "route_id": "route-789", 
  "route_name": "users-route",
  "consumer_id": "consumer-123",
  "consumer_username": "test_user",
  
  "request_size": 156,
  "request_start_time": 1640995200.123,
  "processing_phase": "access",
  
  "guard_ai_version": "0.1.0",
  "dry_run_mode": false
}
```

### Response Log Entry (Completion Phase)

Captured during Kong's `log` phase to record response metadata and latency:

```json
{
  "timestamp": 1640995200,
  "iso_timestamp": "2021-12-31T18:00:00Z", 
  "request_id": "req-123-abc",
  "kong_request_id": "kong-456-def",
  "log_type": "response",
  
  "client_ip": "203.0.113.1",
  "method": "POST",
  "path": "/api/v1/users",
  
  "status": 200,
  "response_size": 512,
  "response_headers": {
    "content-type": "application/json",
    "content-length": "512",
    "server": "nginx/1.21.0",
    "set-cookie": "session"
  },
  
  "service_id": "service-456",
  "service_name": "user-service",
  "route_id": "route-789",
  "route_name": "users-route", 
  "consumer_id": "consumer-123",
  "consumer_username": "test_user",
  
  "latency": {
    "request": 245,
    "kong": 12,
    "upstream": 230,
    "guard_ai_processing": 3
  },
  
  "processing_phase": "log",
  "guard_ai_version": "0.1.0",
  "dry_run_mode": false
}
```

### Threat Incident Log Entry

Generated when threats are detected for comprehensive incident tracking:

```json
{
  "timestamp": 1640995200,
  "iso_timestamp": "2021-12-31T18:00:00Z",
  "request_id": "req-123-abc", 
  "kong_request_id": "kong-456-def",
  "log_type": "threat_incident",
  "log_level": "WARN",
  
  "incident_id": "guard_ai_1640995200_req123",
  "incident_type": "threat_detected",
  "severity": "high",
  
  "threat": {
    "type": "sql_injection",
    "level": 8.5,
    "confidence": 0.95,
    "details": {
      "pattern_matched": "union select",
      "payload_location": "query_parameter"
    },
    "patterns_matched": ["union.*select"],
    "risk_score": 8.5
  },
  
  "request": {
    "client_ip": "203.0.113.1",
    "method": "POST",
    "path": "/api/v1/search",
    "headers": {
      "user-agent": "BadBot/1.0",
      "authorization": "Bearer [REDACTED]"
    },
    "query_params": {
      "q": "1' UNION SELECT * FROM users--"
    },
    "user_agent": "BadBot/1.0"
  },
  
  "response_action": {
    "action_type": "block_request",
    "executed": true,
    "simulated": false,
    "success": true,
    "details": "Request blocked due to SQL injection pattern",
    "execution_time_ms": 1.2
  },
  
  "kong_context": {
    "service_id": "service-456",
    "route_id": "route-789", 
    "consumer_id": "consumer-123",
    "node_id": "kong-node-1"
  },
  
  "guard_ai": {
    "version": "0.1.0",
    "dry_run_mode": false,
    "processing_time_ms": 3.2,
    "detection_engine": "static_rules"
  }
}
```

## Security Features

### Real IP Detection

The log format implements intelligent real IP detection to handle various proxy scenarios:

1. **X-Real-IP Header** (highest priority)
   - Single IP from trusted proxy
   - Direct client connection detection

2. **X-Forwarded-For Header** (second priority)
   - Comma-separated IP chain parsing
   - Extracts original client IP (first in chain)
   - Handles whitespace and malformed entries

3. **Kong Client IP** (fallback)
   - Direct connection IP when headers unavailable

### Header Security

- **Authorization Header Redaction**: Automatically redacts sensitive tokens
  - `Authorization: Bearer abc123` → `Authorization: Bearer [REDACTED]`
  - Preserves auth type for analysis while protecting credentials

- **Header Filtering**: Only logs security-relevant headers
  - Whitelist approach prevents accidental sensitive data exposure
  - Configurable header selection for different environments

- **Length Truncation**: Prevents log bloat from oversized headers
  - Headers >512 characters are truncated with "..." indicator
  - Maintains log readability and storage efficiency

### Cookie Sanitization

Response cookie logging captures cookie names without values:
- `Set-Cookie: session=secret123; HttpOnly` → `"set-cookie": "session"`
- Multiple cookies: `["session", "csrf", "tracking"]`
- Enables session tracking analysis without credential exposure

## Performance Optimizations

### Pre-compiled Lookups

```lua
-- Header lookup table for O(1) filtering
local header_lookup = {}
for _, header in ipairs(DEFAULT_LOG_HEADERS) do
    header_lookup[header] = true
end
```

### Minimal String Operations

- Single-pass header processing
- Efficient JSON serialization with error handling
- Lazy evaluation of expensive operations (IP parsing only when needed)

### Configurable Verbosity

Log levels control output volume:
- **DEBUG**: All request/response details
- **INFO**: Standard operational logs
- **WARN**: Threats and anomalies only
- **ERROR**: Critical issues only

## Integration Examples

### ELK Stack Integration

```json
# Logstash filter configuration
filter {
  if [fields][log_source] == "kong_guard_ai" {
    json {
      source => "message"
      target => "kong_guard_ai"
    }
    
    date {
      match => [ "[kong_guard_ai][iso_timestamp]", "ISO8601" ]
    }
    
    if [kong_guard_ai][log_type] == "threat_incident" {
      mutate {
        add_tag => ["security_incident"]
        add_field => {
          "alert_priority" => "%{[kong_guard_ai][severity]}"
        }
      }
    }
  }
}
```

### Splunk Integration

```splunk
# Splunk search examples
index=kong_logs sourcetype=kong_guard_ai log_type=threat_incident
| stats count by threat.type, severity
| sort -count

index=kong_logs sourcetype=kong_guard_ai log_type=response
| eval response_time_ms=latency.request
| timechart avg(response_time_ms) by service_name
```

### CloudWatch Integration

```json
{
  "filterPattern": "[timestamp, iso_timestamp, request_id, log_type=\"threat_incident\", ...]",
  "metricTransformations": [
    {
      "metricName": "ThreatIncidentCount",
      "metricNamespace": "KongGuardAI",
      "metricValue": "1",
      "dimensionKey": "threat.type",
      "dimensionValue": "$threat.type"
    }
  ]
}
```

## Configuration

The log format respects Kong Guard AI plugin configuration:

```lua
{
  log_level = "info",           -- Controls log verbosity
  dry_run_mode = false,         -- Included in all log entries
  external_logging_enabled = true,  -- Enables structured logging
  log_endpoint = "https://logs.example.com/api/ingest"
}
```

## Log Rotation and Management

### Best Practices

1. **Log Rotation**: Configure Kong with logrotate for disk management
2. **Index Patterns**: Use date-based indices for time-series analysis
3. **Retention Policies**: Set appropriate retention based on compliance needs
4. **Monitoring**: Alert on log ingestion failures and parsing errors

### Storage Estimates

For typical API gateway traffic:
- **Access logs**: ~1KB per request
- **Response logs**: ~800 bytes per request  
- **Threat incidents**: ~2KB per incident
- **1M requests/day**: ~1.8GB structured logs

## Testing and Validation

The log format includes comprehensive test suite (`log_format_spec.lua`):

- Real IP detection logic validation
- Header filtering and security redaction
- JSON structure validation
- Performance benchmark tests
- Security feature verification

Run tests with Kong's busted framework:
```bash
busted kong-guard-ai/spec/log_format_spec.lua
```

## Future Enhancements

### Planned Features

1. **Custom Field Mapping**: Allow administrators to add custom fields
2. **Sampling Configuration**: Reduce log volume with intelligent sampling  
3. **Compression**: Built-in gzip compression for large payloads
4. **Async Logging**: Non-blocking log emission for high-throughput scenarios
5. **Log Enrichment**: GeoIP and threat intel integration

### Integration Roadmap

- **Datadog APM**: Native trace correlation
- **New Relic**: Performance monitoring integration
- **Prometheus**: Metrics extraction from structured logs
- **SIEM Integration**: Security information and event management tools

## Conclusion

The Kong Guard AI log format provides a comprehensive, secure, and performant foundation for API security monitoring. Its structured design enables powerful analytics while maintaining strict security controls and optimal performance under high load.

The modular architecture allows for easy extension and customization while ensuring compatibility with modern log analysis platforms and security tools.