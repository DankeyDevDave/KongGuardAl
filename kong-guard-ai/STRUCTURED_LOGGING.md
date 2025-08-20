# Kong Guard AI - Structured Logging Implementation

## Overview

The Kong Guard AI plugin implements a comprehensive structured logging system that captures detailed metadata about threat detection events, performance metrics, and security incidents. This system is designed for production-ready operation with minimal performance impact and maximum observability.

## Features

### Core Capabilities

- **JSON-formatted structured logs** with comprehensive metadata
- **Asynchronous processing** to minimize request latency impact
- **Request correlation IDs** and session tracking
- **Geolocation enrichment** (configurable)
- **User agent parsing** and bot detection
- **Threat intelligence hooks** for external data sources
- **Performance metrics** and latency tracking
- **Log sampling** for high-traffic scenarios
- **External endpoint integration** (ELK, Splunk, Datadog, etc.)
- **Log rotation** and retention management
- **Memory leak prevention** through automatic cleanup

### Log Types

1. **Threat Incidents** - Detailed security event logs
2. **Performance Metrics** - Request processing timings
3. **Diagnostic Logs** - Debug and operational information
4. **Health Checks** - System status and statistics

## Configuration

### Schema Fields

```lua
-- Enable structured logging
structured_logging_enabled = true,        -- default: true

-- Async processing (recommended for production)
async_logging = true,                     -- default: true

-- Sampling rate for high-traffic environments
log_sampling_rate = 1.0,                  -- default: 1.0 (0.01-1.0)

-- Metadata enrichment
include_geolocation = false,              -- default: false
include_user_agent_parsing = true,       -- default: true

-- Log size limits
max_log_entry_size = 32768,               -- default: 32KB (1KB-128KB)

-- Correlation and tracking
log_correlation_enabled = true,           -- default: true

-- External logging
external_logging_enabled = false,        -- default: false
log_endpoint = "https://logs.example.com/webhook",
external_log_timeout_ms = 1000,          -- default: 1000ms

-- Log levels
log_level = "info"                        -- debug, info, warn, error, critical
```

### Kong Plugin Configuration Example

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Core security settings
    dry_run_mode: false
    threat_threshold: 7.0
    
    # Structured logging configuration
    structured_logging_enabled: true
    async_logging: true
    log_sampling_rate: 0.8  # 80% sampling for high traffic
    include_geolocation: true
    include_user_agent_parsing: true
    max_log_entry_size: 65536  # 64KB
    
    # External logging integration
    external_logging_enabled: true
    log_endpoint: "https://your-siem.company.com/api/logs"
    external_log_timeout_ms: 2000
    
    # Log level
    log_level: "warn"  # Only warnings and above
```

## Log Structure

### Core Log Entry Format

```json
{
  "timestamp": 1692480000,
  "timestamp_iso": "2023-08-19T20:00:00.000Z",
  "level": "WARN",
  "level_num": 3,
  "message": "Threat detected: sql_injection (level: 8.5, confidence: 0.90)",
  "source": "kong-guard-ai",
  "version": "0.1.0",
  
  "correlation_id": "guard_ai_service-12_1692480000123_1001",
  "session_id": "session_a1b2c3d4_1001",
  "request_id": "kong-request-uuid-here",
  
  "request": {
    "method": "POST",
    "path": "/api/users/login",
    "query_string": "source=mobile&version=2.1.0",
    "client_ip": "203.0.113.42",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "referer": "https://example.com/login",
    "content_type": "application/json",
    "content_length": "256",
    "header_count": 12
  },
  
  "kong": {
    "service_id": "service-uuid-123",
    "route_id": "route-uuid-456", 
    "consumer_id": "consumer-uuid-789",
    "worker_pid": 12345,
    "node_id": "kong-node-abc123"
  },
  
  "config": {
    "dry_run_mode": false,
    "threat_threshold": 7.0,
    "plugin_enabled": true
  }
}
```

### Threat Incident Log Structure

```json
{
  // ... core fields above ...
  
  "threat": {
    "detected": true,
    "level": 8.5,
    "type": "sql_injection",
    "confidence": 0.9,
    "recommended_action": "block",
    "requires_ai_analysis": true,
    "details": {
      "patterns_matched": [
        {
          "pattern_index": 3,
          "match": "union select",
          "context": "username=admin' union select * from users--"
        }
      ],
      "total_matches": 1,
      "source_ip": "203.0.113.42"
    },
    "enforcement": {
      "action_taken": "BLOCK_REQUEST",
      "executed": false,
      "simulated": true,
      "dry_run": true
    }
  },
  
  "response": {
    "status": 403,
    "headers": {...},
    "body_size": 1024,
    "processing_time_ms": 15.7
  },
  
  "performance": {
    "processing_time_ms": 3.2,
    "memory_usage_kb": 2048,
    "request_count": 1001,
    "log_queue_size": 5
  },
  
  "geolocation": {
    "country": "US",
    "region": "California",
    "city": "San Francisco", 
    "isp": "CloudFlare",
    "is_proxy": false,
    "is_tor": false
  },
  
  "user_agent_parsed": {
    "browser": "Chrome",
    "browser_version": "115.0",
    "os": "Windows",
    "os_version": "10.0",
    "device_type": "desktop",
    "is_bot": false,
    "is_mobile": false,
    "parsed": true
  },
  
  "threat_intelligence": {
    "ip_reputation_score": 7.2,
    "domain_reputation_score": 0,
    "asn_reputation_score": 0,
    "threat_feeds_checked": true
  }
}
```

### Performance Metrics Log

```json
{
  // ... core fields ...
  
  "performance": {
    "processing_time_ms": 2.3,
    "memory_usage_kb": 1024,
    "request_count": 1000,
    "log_queue_size": 0
  },
  
  "response": {
    "status": 200,
    "processing_time_ms": 2.3
  }
}
```

## Usage Examples

### Basic Logging

```lua
-- Initialize logger in init_worker phase
structured_logger.init_worker(conf)

-- Log a simple informational message
structured_logger.info(
    "Request processed successfully",
    nil,              -- No threat result
    request_context,
    nil,              -- No response context yet
    conf
)
```

### Threat Event Logging

```lua
-- Log a threat incident with full context
structured_logger.log_threat_event(
    threat_result,      -- From detector.analyze_request()
    request_context,    -- Request metadata
    enforcement_result, -- Action taken
    conf               -- Plugin configuration
)
```

### Performance Monitoring

```lua
-- Log performance metrics
structured_logger.log_performance_metrics(
    processing_time_ms,
    request_context,
    conf
)
```

### Custom Log Levels

```lua
-- Debug logging (only in debug mode)
structured_logger.debug("Debug information", nil, request_context, nil, conf)

-- Warning with threat context
structured_logger.warn("Suspicious activity", threat_result, request_context, nil, conf)

-- Critical security event
structured_logger.critical("Security breach detected", threat_result, request_context, response_context, conf)
```

## Integration with Log Analysis Tools

### ELK Stack (Elasticsearch, Logstash, Kibana)

1. **Logstash Configuration**:
```ruby
input {
  http {
    port => 8080
    codec => json
  }
}

filter {
  if [source] == "kong-guard-ai" {
    mutate {
      add_tag => ["security", "kong-guard-ai"]
    }
    
    if [threat][detected] {
      mutate {
        add_tag => ["threat"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "kong-guard-ai-%{+YYYY.MM.dd}"
  }
}
```

2. **Kibana Dashboard**:
   - Create visualizations for threat levels over time
   - Monitor performance metrics and latency
   - Set up alerts for critical security events

### Splunk

1. **HTTP Event Collector (HEC)**:
```json
{
  "sourcetype": "kong:guard:ai",
  "index": "security",
  "event": {
    // ... structured log entry ...
  }
}
```

2. **Search Queries**:
```splunk
# Find all threat incidents
index=security sourcetype="kong:guard:ai" threat.detected=true

# Monitor high-confidence threats
index=security sourcetype="kong:guard:ai" threat.confidence>0.8

# Performance analysis
index=security sourcetype="kong:guard:ai" 
| stats avg(performance.processing_time_ms) by _time span=5m
```

### Datadog

1. **Custom Metrics**:
```lua
-- Send custom metrics to Datadog
{
  "series": [
    {
      "metric": "kong.guard.ai.threat.level",
      "points": [[timestamp, threat_level]],
      "tags": ["service:api", "environment:prod"]
    }
  ]
}
```

## Performance Considerations

### Async Processing

- **Queue Size**: Monitor `async_queue_size` to prevent memory buildup
- **Processing Rate**: Logs are processed in batches of 50 every 100ms
- **Memory Management**: Automatic cleanup prevents memory leaks

### Sampling

```lua
-- High traffic: reduce sampling
log_sampling_rate = 0.1  -- 10% sampling

-- Critical services: full logging
log_sampling_rate = 1.0  -- 100% sampling
```

### Size Limits

```lua
-- Prevent large log entries
max_log_entry_size = 32768  -- 32KB limit
```

## Monitoring and Health Checks

### Health Check API

```lua
local health = structured_logger.health_check()
-- Returns:
{
  status = "healthy",    -- healthy, warning, unhealthy
  issues = {}           -- Array of issue descriptions
}
```

### Statistics

```lua
local stats = structured_logger.get_stats()
-- Returns:
{
  total_logs = 1000,
  dropped_logs = 5,
  error_logs = 2,
  async_queue_size = 3,
  cache_sizes = {
    geo_cache = 50,
    user_agent_cache = 100
  }
}
```

### Metrics to Monitor

1. **Log Volume**: `total_logs` per time period
2. **Drop Rate**: `dropped_logs / total_logs`
3. **Error Rate**: `error_logs / total_logs`
4. **Queue Health**: `async_queue_size` (should be < 100)
5. **Processing Latency**: Time between log creation and emission

## Security Considerations

### Data Sanitization

- **Authorization headers**: Automatically redacted (`Bearer [REDACTED]`)
- **Sensitive fields**: Passwords, tokens, keys filtered out
- **PII Protection**: Configure geolocation and user agent parsing carefully

### Network Security

- **HTTPS Only**: External endpoints should use HTTPS
- **Authentication**: Secure external logging endpoints
- **Rate Limiting**: Prevent log flooding attacks

## Troubleshooting

### Common Issues

1. **High Memory Usage**:
   - Check `async_queue_size`
   - Reduce `log_sampling_rate`
   - Increase cleanup frequency

2. **Missing Logs**:
   - Verify `log_level` configuration
   - Check `log_sampling_rate`
   - Review external endpoint connectivity

3. **Performance Impact**:
   - Enable `async_logging`
   - Reduce `max_log_entry_size`
   - Optimize external endpoint response time

### Debug Mode

```lua
-- Enable debug logging for troubleshooting
log_level = "debug"
structured_logging_enabled = true
async_logging = false  -- Synchronous for immediate feedback
```

## Migration Guide

### From Basic Logging

1. Enable structured logging:
```yaml
structured_logging_enabled: true
```

2. Configure log level:
```yaml
log_level: "info"  # Start with info level
```

3. Test with external endpoint:
```yaml
external_logging_enabled: true
log_endpoint: "https://your-test-endpoint.com/logs"
```

4. Gradually enable features:
```yaml
include_user_agent_parsing: true
include_geolocation: true    # If GeoIP service available
```

### Performance Tuning

1. Start with conservative settings:
```yaml
async_logging: true
log_sampling_rate: 0.5
max_log_entry_size: 16384
```

2. Monitor and adjust:
   - Increase sampling if dropping important events
   - Decrease if performance impact is too high
   - Tune based on traffic patterns

## Best Practices

1. **Start Conservative**: Begin with higher log levels and lower sampling
2. **Monitor Performance**: Track latency impact and memory usage
3. **Secure Endpoints**: Use HTTPS and authentication for external logging
4. **Regular Cleanup**: Monitor queue sizes and cache growth
5. **Test Thoroughly**: Validate log format with your analysis tools
6. **Document Fields**: Maintain field documentation for your team
7. **Alert on Anomalies**: Set up alerts for high error rates or queue buildup

## Future Enhancements

- **Log Rotation**: Built-in file rotation with size/time limits
- **Compression**: Compress logs before external transmission
- **Buffering**: Smart buffering for external endpoint failures
- **Schema Validation**: Runtime validation of log entry structure
- **Custom Fields**: Plugin for adding custom metadata fields