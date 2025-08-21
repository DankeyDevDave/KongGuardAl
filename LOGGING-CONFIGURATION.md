# Kong Guard AI - Logging Configuration Guide

## Overview

Kong Guard AI now supports comprehensive logging verbosity configuration, allowing you to control the amount and detail of log output for better debugging in development and quieter operation in production.

## Log Levels

The plugin supports five log levels, from most verbose to least:

| Level | Description | Use Case |
|-------|-------------|----------|
| `debug` | All events logged with full details | Development & troubleshooting |
| `info` | Normal operations and important events | Default for staging |
| `warn` | Warnings and potential issues | Production monitoring |
| `error` | Only errors and critical issues | Quiet production |
| `critical` | Only critical security events | Minimal logging |

## Configuration Options

### Primary Log Level

```lua
log_level = "info"  -- Sets the overall verbosity
```

### Granular Controls

```lua
log_threats = true      -- Log detected threats
log_requests = false    -- Log all incoming requests (verbose)
log_decisions = true    -- Log blocking/rate-limiting decisions
```

## Configuration Methods

### 1. Via Kong Admin API

```bash
# Update existing plugin configuration
curl -X PATCH http://localhost:18001/plugins/{plugin-id} \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "log_level": "debug",
      "log_threats": true,
      "log_requests": true,
      "log_decisions": true
    }
  }'
```

### 2. Via Dashboard

1. Open Kong Guard AI Dashboard
2. Navigate to "Plugin Management" section
3. Select desired log level from dropdown
4. Click "Update Log Level"

### 3. During Plugin Installation

```bash
curl -X POST http://localhost:18001/services/{service}/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "kong-guard-ai",
    "config": {
      "log_level": "warn",
      "log_threats": true,
      "log_requests": false,
      "log_decisions": true,
      # ... other config ...
    }
  }'
```

## Log Level Examples

### Debug Level (Most Verbose)
```
[debug] Kong Guard AI: Request received {client_ip: "192.168.1.1", path: "/api/users", method: "GET", headers: {...}}
[info] Kong Guard AI: Threat detected {threat_score: 0.3, threat_type: "none"}
[debug] Kong Guard AI: Features extracted {requests_per_minute: 5, header_count: 10, ...}
```

### Info Level (Default)
```
[info] Kong Guard AI: Threat detected {threat_score: 0.85, threat_type: "xss"}
[warn] Kong Guard AI: Blocking request {threat_type: "xss", client_ip: "192.168.1.1"}
```

### Warn Level (Production)
```
[warn] Kong Guard AI: Blocking request {threat_type: "sql_injection", client_ip: "192.168.1.1"}
[error] Kong Guard AI: Failed to apply rate limit {error: "..."}
```

### Error Level (Minimal)
```
[error] Kong Guard AI: Critical error in threat detection {error: "..."}
[crit] Kong Guard AI: Plugin initialization failed
```

## Recommended Settings

### Development Environment
```json
{
  "log_level": "debug",
  "log_threats": true,
  "log_requests": true,
  "log_decisions": true
}
```

### Staging Environment
```json
{
  "log_level": "info",
  "log_threats": true,
  "log_requests": false,
  "log_decisions": true
}
```

### Production Environment
```json
{
  "log_level": "warn",
  "log_threats": true,
  "log_requests": false,
  "log_decisions": true
}
```

### High-Traffic Production
```json
{
  "log_level": "error",
  "log_threats": false,
  "log_requests": false,
  "log_decisions": false
}
```

## Log Output Locations

Kong Guard AI logs are written to:

1. **Kong Error Log**: `/usr/local/kong/logs/error.log`
2. **Docker Logs**: `docker logs kong-gateway`
3. **Systemd Journal**: `journalctl -u kong` (if using systemd)
4. **Custom Log Handler**: If configured in Kong

## Performance Impact

| Log Level | Performance Impact | Disk Usage |
|-----------|-------------------|------------|
| debug | High | Very High |
| info | Medium | Medium |
| warn | Low | Low |
| error | Very Low | Very Low |
| critical | Negligible | Minimal |

## Troubleshooting

### Logs Not Appearing

1. Check log level is not set too high:
```bash
curl http://localhost:18001/plugins/{plugin-id} | jq '.config.log_level'
```

2. Verify Kong log level allows plugin logs:
```bash
kong config get log_level
```

3. Check if specific log types are enabled:
```bash
curl http://localhost:18001/plugins/{plugin-id} | jq '.config | {log_threats, log_requests, log_decisions}'
```

### Too Many Logs

1. Increase log level to reduce verbosity:
```bash
curl -X PATCH http://localhost:18001/plugins/{plugin-id} \
  -d '{"config": {"log_level": "warn"}}'
```

2. Disable specific log types:
```bash
curl -X PATCH http://localhost:18001/plugins/{plugin-id} \
  -d '{"config": {"log_requests": false}}'
```

## Log Rotation

For production environments, configure log rotation:

```bash
# /etc/logrotate.d/kong
/usr/local/kong/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0644 kong kong
    sharedscripts
    postrotate
        /usr/bin/kong reload
    endscript
}
```

## Integration with Log Management Systems

### Elasticsearch/Logstash
```json
{
  "input": {
    "file": {
      "path": "/usr/local/kong/logs/error.log",
      "type": "kong-guard-ai"
    }
  },
  "filter": {
    "grok": {
      "match": {
        "message": "\\[%{WORD:log_level}\\] .* \\[kong-guard-ai\\] %{GREEDYDATA:plugin_message}"
      }
    }
  }
}
```

### Fluentd
```ruby
<source>
  @type tail
  path /usr/local/kong/logs/error.log
  tag kong.guard.ai
  <parse>
    @type regexp
    expression /^\[(?<log_level>\w+)\] .* \[kong-guard-ai\] (?<message>.*)$/
  </parse>
</source>
```

## Best Practices

1. **Start with info level** in new deployments
2. **Use debug level** only for troubleshooting specific issues
3. **Enable log_threats** in production to track security events
4. **Disable log_requests** in production to reduce noise
5. **Monitor disk usage** when using verbose logging
6. **Implement log rotation** for long-running deployments
7. **Use structured logging** for easier parsing and analysis
8. **Set up alerts** for error and critical level logs

## Summary

The flexible logging configuration in Kong Guard AI allows you to:
- Control verbosity based on environment needs
- Debug issues with detailed logging when needed
- Run quietly in production with minimal overhead
- Track specific events (threats, decisions) independently
- Integrate with existing log management infrastructure

Adjust the logging configuration to match your operational requirements and monitoring capabilities.