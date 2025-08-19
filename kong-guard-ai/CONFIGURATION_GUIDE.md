# Kong Guard AI - Configuration Guide

## Overview

Kong Guard AI uses security-first defaults to ensure safe deployment. This guide explains the configuration options, deployment strategies, and best practices for different environments.

## Security-First Configuration Philosophy

### Default Safety Principles

1. **Dry Run Mode**: Enabled by default - logs threats but takes no action
2. **Conservative Thresholds**: High threat thresholds to reduce false positives  
3. **Disabled Integrations**: External services disabled until explicitly configured
4. **Performance Protection**: Low processing time limits to prevent latency
5. **Explicit Enablement**: Dangerous features require explicit activation

## Configuration Options

### Core Settings

| Setting | Default | Safe Range | Description |
|---------|---------|------------|-------------|
| `dry_run_mode` | `true` | N/A | Start with logging only, disable after validation |
| `threat_threshold` | `8.0` | `7.0-9.0` | Higher values reduce false positives |
| `max_processing_time_ms` | `5` | `5-15` | Balance security analysis vs. latency |

### Threat Detection

| Setting | Default | Safe Range | Description |
|---------|---------|------------|-------------|
| `enable_rate_limiting_detection` | `true` | N/A | Basic protection, safe to enable |
| `rate_limit_threshold` | `150` | `100-300` | Requests per minute before triggering |
| `rate_limit_window_seconds` | `60` | `30-300` | Time window for rate analysis |
| `enable_payload_analysis` | `true` | N/A | Analyze request content for threats |
| `max_payload_size` | `262144` | `64KB-1MB` | Larger payloads = more processing time |

### Response Actions

| Setting | Default | Safe Range | Description |
|---------|---------|------------|-------------|
| `enable_auto_blocking` | `false` | N/A | **CAUTION**: Enable only after testing |
| `block_duration_seconds` | `1800` | `300-7200` | How long to block detected threats |
| `enable_rate_limiting_response` | `true` | N/A | Safe mitigation method |
| `enable_config_rollback` | `false` | N/A | **DANGER**: Can disrupt service |

### AI Gateway Integration

| Setting | Default | Safe Range | Description |
|---------|---------|------------|-------------|
| `ai_gateway_enabled` | `false` | N/A | Requires external configuration |
| `ai_gateway_model` | `"gpt-4o-mini"` | N/A | Cost-effective model choice |
| `ai_analysis_threshold` | `6.0` | `5.0-8.0` | Higher = fewer AI calls = lower cost |
| `ai_timeout_ms` | `3000` | `2000-5000` | Prevent request delays |

### Notifications

| Setting | Default | Safe Range | Description |
|---------|---------|------------|-------------|
| `enable_notifications` | `true` | N/A | Important for monitoring |
| `notification_threshold` | `7.0` | `6.0-8.0` | Higher = fewer notifications |
| `email_to` | `[]` | N/A | Must configure recipients |
| `slack_webhook_url` | `""` | N/A | Must configure if using Slack |

### Admin API Integration

| Setting | Default | Safe Range | Description |
|---------|---------|------------|-------------|
| `admin_api_enabled` | `false` | N/A | **HIGH RISK**: Disable unless required |
| `admin_api_timeout_ms` | `3000` | `1000-5000` | Prevent admin API blocking |

## Deployment Configurations

### Development Environment

```json
{
  "name": "kong-guard-ai",
  "config": {
    "dry_run_mode": true,
    "threat_threshold": 9.0,
    "max_processing_time_ms": 10,
    "rate_limit_threshold": 200,
    "enable_auto_blocking": false,
    "enable_notifications": true,
    "notification_threshold": 8.0,
    "log_level": "debug",
    "admin_api_enabled": false,
    "ai_gateway_enabled": false
  }
}
```

**Development Notes:**
- Dry run mode enabled for safe testing
- High thresholds to reduce noise during development
- Debug logging for troubleshooting
- No enforcement actions
- External integrations disabled

### Staging Environment

```json
{
  "name": "kong-guard-ai", 
  "config": {
    "dry_run_mode": false,
    "threat_threshold": 8.0,
    "max_processing_time_ms": 8,
    "rate_limit_threshold": 150,
    "ip_whitelist": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "enable_auto_blocking": false,
    "enable_rate_limiting_response": true,
    "block_duration_seconds": 1800,
    "enable_notifications": true,
    "slack_webhook_url": "https://hooks.slack.com/services/YOUR/STAGING/WEBHOOK",
    "notification_threshold": 7.5,
    "log_level": "info",
    "admin_api_enabled": false,
    "ai_gateway_enabled": false
  }
}
```

**Staging Notes:**
- Limited enforcement (rate limiting only)
- Internal IP whitelist for development team
- Notifications to staging Slack channel
- No blocking or admin API access

### Production Environment

```json
{
  "name": "kong-guard-ai",
  "config": {
    "dry_run_mode": false,
    "threat_threshold": 7.0,
    "max_processing_time_ms": 10,
    "rate_limit_threshold": 100,
    "ip_whitelist": ["203.0.113.0/24", "198.51.100.0/24"],
    "enable_auto_blocking": true,
    "block_duration_seconds": 3600,
    "enable_rate_limiting_response": true,
    "enable_notifications": true,
    "slack_webhook_url": "https://hooks.slack.com/services/YOUR/PROD/WEBHOOK",
    "email_smtp_server": "smtp.company.com",
    "email_from": "security-alerts@company.com",
    "email_to": ["security-team@company.com", "ops-team@company.com"],
    "notification_threshold": 7.0,
    "external_logging_enabled": true,
    "log_endpoint": "https://logs.company.com/kong-guard-ai",
    "admin_api_enabled": true,
    "admin_api_key": "${KONG_ADMIN_API_KEY}",
    "log_level": "info"
  }
}
```

**Production Notes:**
- Full enforcement enabled
- Multiple notification channels
- External logging integration
- Admin API enabled for automated responses
- Optimized thresholds based on traffic patterns

### High Security Environment

```json
{
  "name": "kong-guard-ai",
  "config": {
    "dry_run_mode": false,
    "threat_threshold": 6.0,
    "max_processing_time_ms": 15,
    "rate_limit_threshold": 50,
    "ip_whitelist": ["192.0.2.0/24"],
    "enable_payload_analysis": true,
    "max_payload_size": 131072,
    "ai_gateway_enabled": true,
    "ai_gateway_model": "gpt-4o",
    "ai_gateway_endpoint": "https://ai-gateway.company.com",
    "ai_analysis_threshold": 5.0,
    "enable_auto_blocking": true,
    "block_duration_seconds": 7200,
    "enable_config_rollback": false,
    "rollback_threshold": 9.0,
    "analyze_response_body": true,
    "enable_learning": true,
    "learning_sample_rate": 0.1,
    "notification_threshold": 6.0,
    "log_level": "info"
  }
}
```

**High Security Notes:**
- Lower threat thresholds for maximum protection
- AI Gateway enabled for advanced analysis
- Response body analysis enabled
- Learning mode for adaptive detection
- Strict rate limiting

## Deployment Process

### Phase 1: Safe Deployment

1. **Deploy with defaults** (dry run mode enabled)
```bash
curl -X POST http://kong-admin:8001/plugins \
  --data "name=kong-guard-ai"
```

2. **Monitor for 24-48 hours**
   - Review threat detection logs
   - Identify false positives
   - Validate performance impact

3. **Tune thresholds if needed**
```bash
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config.threat_threshold=7.5" \
  --data "config.rate_limit_threshold=120"
```

### Phase 2: Gradual Enforcement

4. **Enable rate limiting responses**
```bash
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config.dry_run_mode=false" \
  --data "config.enable_rate_limiting_response=true"
```

5. **Monitor for issues**
   - Check for legitimate traffic impacts
   - Validate notification accuracy
   - Review performance metrics

### Phase 3: Full Protection

6. **Enable auto-blocking** (after validation)
```bash
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config.enable_auto_blocking=true" \
  --data "config.threat_threshold=7.0"
```

7. **Optional: Enable advanced features**
```bash
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config.ai_gateway_enabled=true" \
  --data "config.admin_api_enabled=true"
```

## Configuration Validation

### Using the defaults.lua Module

```lua
local defaults = require "kong.plugins.kong-guard-ai.defaults"

-- Get safe deployment configuration
local safe_config = defaults.get_deployment_config()

-- Get production template
local prod_config = defaults.get_production_template()

-- Validate configuration
local validation = defaults.validate_configuration(config, "production")
if not validation.valid then
    kong.log.err("Configuration validation failed")
end
```

### Manual Validation Checklist

#### Pre-Deployment
- [ ] `dry_run_mode` appropriate for environment
- [ ] Notification targets configured and tested
- [ ] Thresholds validated against traffic patterns
- [ ] IP whitelists include legitimate sources
- [ ] External service dependencies validated

#### Post-Deployment
- [ ] False positive rate < 5%
- [ ] Average latency increase < 10ms
- [ ] Notifications working correctly
- [ ] Metrics endpoints accessible
- [ ] Logs properly formatted

## Troubleshooting

### High False Positives

**Symptoms:** Legitimate requests being flagged as threats

**Solutions:**
1. Increase `threat_threshold` (7.0 → 8.0)
2. Add legitimate IPs to `ip_whitelist`
3. Adjust `suspicious_patterns` to be more specific
4. Increase `rate_limit_threshold` if rate limiting is triggering

### Performance Impact

**Symptoms:** Increased request latency

**Solutions:**
1. Reduce `max_processing_time_ms` (10 → 5)
2. Decrease `max_payload_size` (256KB → 64KB)
3. Disable `analyze_response_body`
4. Reduce `suspicious_patterns` complexity

### Missing Notifications

**Symptoms:** Not receiving threat alerts

**Solutions:**
1. Verify `enable_notifications` is `true`
2. Check notification target configuration
3. Lower `notification_threshold` temporarily
4. Test external service connectivity
5. Check Kong logs for notification errors

### AI Gateway Issues

**Symptoms:** AI analysis failing or timing out

**Solutions:**
1. Verify `ai_gateway_endpoint` and `ai_api_key`
2. Increase `ai_timeout_ms` (3000 → 5000)
3. Check external service availability
4. Reduce `ai_analysis_threshold` to test

## Security Considerations

### Secrets Management

- Store API keys in environment variables
- Use Kong Vault for sensitive configuration
- Rotate credentials regularly
- Limit Admin API access

### Network Security

- Restrict admin API access to authorized networks
- Use HTTPS for all external integrations
- Validate webhook endpoints
- Monitor for configuration tampering

### Compliance

- Log all configuration changes
- Implement change approval process
- Regular security audits
- Document incident response procedures

## Best Practices

### Configuration Management

1. **Use Infrastructure as Code** for configuration deployment
2. **Version control** all configuration changes
3. **Test configurations** in staging before production
4. **Monitor** configuration drift and unauthorized changes

### Operational Excellence

1. **Start conservative** and gradually increase protection
2. **Monitor continuously** for false positives and performance
3. **Have rollback procedures** ready for emergencies
4. **Regular reviews** of thresholds and patterns

### Security Hardening

1. **Principle of least privilege** for all integrations
2. **Regular updates** of threat patterns
3. **Incident response procedures** for security events
4. **Regular penetration testing** to validate effectiveness

---

This configuration guide ensures Kong Guard AI is deployed safely and effectively across all environments while maintaining security best practices.