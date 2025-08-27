# Kong Guard AI Plugin

The Kong Guard AI plugin provides autonomous API threat detection and response capabilities for Kong Gateway. It implements real-time monitoring, threat classification, and automated remediation directly within the Kong request lifecycle.

## Features

- **Real-time Threat Detection**: IP blocking, user agent filtering, suspicious pattern matching
- **Rate Limiting**: Advanced rate limiting with sliding windows
- **Anomaly Detection**: Statistical analysis for unusual traffic patterns
- **Automated Response**: Configurable blocking, rate limiting, and notifications
- **AI Gateway Integration**: Optional LLM-based threat analysis
- **Performance Optimized**: <10ms overhead per request
- **Dry Run Mode**: Safe testing without enforcement

## Installation

### 1. Plugin Files

Copy the plugin files to Kong's plugin directory:

```bash
# Copy plugin to Kong plugins directory
cp -r kong/plugins/kong-guard-ai /etc/kong/plugins/

# Or mount as volume in Docker
-v $(pwd)/kong/plugins:/etc/kong/plugins
```

### 2. Kong Configuration

Add the plugin to Kong's configuration:

```bash
# In kong.conf
plugins = bundled,kong-guard-ai
lua_package_path = /etc/kong/plugins/?.lua;/etc/kong/plugins/?/init.lua;;
```

### 3. Shared Memory Configuration

Add shared memory zones to nginx configuration:

```nginx
# In nginx-kong.conf or kong.conf
lua_shared_dict kong_guard_ai_data 10m
lua_shared_dict kong_guard_ai_counters 10m
lua_shared_dict kong_guard_ai_cache 5m
lua_shared_dict kong_guard_ai_config 1m
```

### 4. Enable Plugin

Enable the plugin via Kong Admin API:

```bash
# Global plugin
curl -X POST http://localhost:8001/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "kong-guard-ai",
    "config": {
      "dry_run": true,
      "log_level": "info"
    }
  }'

# Service-specific plugin
curl -X POST http://localhost:8001/services/my-service/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "kong-guard-ai",
    "config": {
      "dry_run": false,
      "threat_detection": {
        "enabled": true,
        "rules": {
          "rate_limit_threshold": 100,
          "blocked_user_agents": ["sqlmap", "nikto"]
        }
      }
    }
  }'
```

## Configuration

### Basic Configuration

```json
{
  "name": "kong-guard-ai",
  "config": {
    "dry_run": true,
    "log_level": "info",
    "threat_detection": {
      "enabled": true,
      "rules": {
        "rate_limit_threshold": 100,
        "suspicious_patterns": [
          "(?i)(union|select|insert|delete)",
          "(?i)(<script|javascript:)"
        ],
        "blocked_ips": ["192.168.1.100"],
        "blocked_user_agents": ["sqlmap", "nikto"],
        "max_payload_size": 1048576
      }
    },
    "response_actions": {
      "enabled": true,
      "immediate_block": false,
      "notification_enabled": true
    },
    "notifications": {
      "webhook_url": "http://localhost:3001/webhook",
      "slack_webhook": ""
    }
  }
}
```

### Advanced Configuration

```json
{
  "name": "kong-guard-ai",
  "config": {
    "dry_run": false,
    "log_level": "debug",
    "threat_detection": {
      "enabled": true,
      "rules": {
        "rate_limit_threshold": 100,
        "burst_threshold": 50,
        "suspicious_patterns": [
          "(?i)(union|select|insert|delete|drop|alter|exec|script)",
          "(?i)(<script|javascript:|onload=|onerror=)",
          "(?i)(eval\\(|setTimeout\\(|setInterval\\()"
        ],
        "blocked_ips": ["192.168.1.100", "10.0.0.0/8"],
        "blocked_user_agents": ["sqlmap", "nikto", "nmap"],
        "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
        "max_payload_size": 1048576,
        "suspicious_headers": ["X-Forwarded-For"]
      },
      "anomaly_detection": {
        "enabled": true,
        "window_size": 300,
        "deviation_threshold": 2.0,
        "min_samples": 10
      }
    },
    "response_actions": {
      "enabled": true,
      "immediate_block": true,
      "rate_limit_enforcement": true,
      "temp_block_duration": 300,
      "escalation_threshold": 5,
      "notification_enabled": true
    },
    "notifications": {
      "webhook_url": "http://localhost:3001/webhook",
      "slack_webhook": "https://hooks.slack.com/...",
      "notification_cooldown": 60,
      "max_notifications_per_hour": 10
    },
    "ai_gateway": {
      "enabled": true,
      "model_endpoint": "http://localhost:8080/v1/chat/completions",
      "threat_analysis_threshold": 0.7,
      "analysis_timeout": 5000,
      "cache_results": true
    },
    "performance": {
      "max_processing_time": 10,
      "enable_caching": true,
      "sampling_rate": 1.0
    }
  }
}
```

## Configuration Reference

### Global Settings

- `dry_run` (boolean): Enable dry run mode (log only, no enforcement)
- `log_level` (string): Logging level (debug, info, warn, error)

### Threat Detection

- `threat_detection.enabled` (boolean): Enable threat detection
- `threat_detection.rules.rate_limit_threshold` (number): Requests per minute threshold
- `threat_detection.rules.burst_threshold` (number): Requests per 10 seconds threshold
- `threat_detection.rules.suspicious_patterns` (array): Regex patterns for suspicious content
- `threat_detection.rules.blocked_ips` (array): IP addresses to block
- `threat_detection.rules.blocked_user_agents` (array): User agents to block
- `threat_detection.rules.max_payload_size` (number): Maximum request payload size in bytes

### Response Actions

- `response_actions.enabled` (boolean): Enable automated responses
- `response_actions.immediate_block` (boolean): Block high-severity threats immediately
- `response_actions.rate_limit_enforcement` (boolean): Apply rate limiting
- `response_actions.temp_block_duration` (number): Temporary block duration in seconds

### Notifications

- `notifications.webhook_url` (string): Webhook URL for notifications
- `notifications.slack_webhook` (string): Slack webhook URL
- `notifications.notification_cooldown` (number): Cooldown between notifications

### AI Gateway Integration

- `ai_gateway.enabled` (boolean): Enable AI Gateway integration
- `ai_gateway.model_endpoint` (string): AI model endpoint URL
- `ai_gateway.threat_analysis_threshold` (number): Threat score threshold (0-1)

## Testing

### Basic Functionality Test

```bash
# Test normal request
curl -v http://localhost:8000/demo

# Test blocked user agent
curl -v -H "User-Agent: sqlmap" http://localhost:8000/demo

# Test suspicious pattern
curl -v "http://localhost:8000/demo?q=union%20select%20*%20from%20users"

# Test rate limiting
for i in {1..105}; do curl http://localhost:8000/demo; done
```

### Plugin Status

```bash
# Check plugin status
curl http://localhost:8001/plugins | jq '.data[] | select(.name == "kong-guard-ai")'

# Check plugin metrics
curl http://localhost:8000/guard-ai/status
```

### Log Monitoring

```bash
# Monitor Kong logs for plugin activity
docker logs -f kong-gateway | grep "kong-guard-ai"

# Monitor threat detection
docker logs -f kong-gateway | grep "THREAT DETECTED"
```

## Development

### Plugin Structure

```
kong-guard-ai/
├── handler.lua          # Main plugin logic
├── schema.lua           # Configuration schema
└── README.md           # This file
```

### Development Setup

1. Set up Kong development environment
2. Mount plugin directory to Kong container
3. Enable debug logging
4. Use dry run mode for testing

### Adding New Threat Detection Rules

Edit `handler.lua` and add new detection methods:

```lua
-- Add to detect_threats function
if self:check_custom_threat(rules.custom_rules, request_data) then
  return true, {
    type = "custom_threat",
    severity = "medium",
    description = "Custom threat detected"
  }
end
```

### Performance Considerations

- All heavy processing should be in the log phase
- Use ngx.shared.dict for caching
- Implement circuit breakers for external calls
- Monitor processing time per request

## Troubleshooting

### Plugin Not Loading

1. Check plugin is in Kong's plugin path
2. Verify Lua syntax: `lua -l kong.plugins.kong-guard-ai.handler`
3. Check Kong logs for errors
4. Ensure plugin is listed in Kong config

### High Memory Usage

1. Reduce shared memory dict sizes
2. Enable sampling (`performance.sampling_rate`)
3. Implement cache cleanup logic
4. Monitor shared dict usage

### Performance Issues

1. Enable performance monitoring
2. Check processing time metrics
3. Reduce AI Gateway calls
4. Optimize regex patterns

### False Positives

1. Enable dry run mode
2. Review suspicious patterns
3. Adjust thresholds
4. Implement whitelist rules

## Security Considerations

- Never log sensitive data (passwords, tokens)
- Secure Admin API access
- Use HTTPS for notifications
- Sanitize all user inputs
- Regular security updates

## License

This plugin is distributed under the same license as Kong Gateway.

## Support

For issues and questions:
1. Check Kong logs for error messages
2. Review configuration against schema
3. Test in dry run mode first
4. Monitor performance metrics