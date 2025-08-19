# Kong Guard AI - Deployment Safety Guidelines

## Overview

Kong Guard AI implements security-first defaults to prevent accidental damage during deployment. This document outlines the safety mechanisms, recommended deployment procedures, and configuration best practices.

## Security-First Default Philosophy

### Core Safety Principles

1. **Dry Run by Default**: All new deployments start in dry-run mode
2. **Conservative Thresholds**: High threat thresholds reduce false positives
3. **Explicit Enablement**: Dangerous features require explicit configuration
4. **Minimal Attack Surface**: External integrations disabled by default
5. **Performance Protection**: Low processing time limits prevent delays

## Default Configuration Analysis

### Safe Defaults Summary

| Configuration | Default Value | Safety Rationale |
|---------------|---------------|------------------|
| `dry_run_mode` | `true` | Logs threats but takes no action initially |
| `threat_threshold` | `8.0` | High threshold reduces false positives |
| `max_processing_time_ms` | `5` | Minimal latency impact |
| `enable_auto_blocking` | `false` | Requires explicit enablement |
| `admin_api_enabled` | `false` | High-risk integration disabled |
| `ai_gateway_enabled` | `false` | External dependency disabled |
| `enable_config_rollback` | `false` | Dangerous feature disabled |
| `ip_blacklist` | `[]` | Empty, must be explicitly configured |
| `notification_targets` | `[]` | Empty, prevents accidental notifications |

### Conservative Thresholds

- **Rate Limit Threshold**: 150 requests/minute (higher than typical)
- **Payload Analysis**: 256KB limit (smaller than 1MB default)
- **Notification Threshold**: 7.0 (reduces noise)
- **AI Analysis Threshold**: 6.0 (higher bar for expensive operations)

## Deployment Procedures

### Phase 1: Initial Deployment (Safe Mode)

```bash
# Deploy with default configuration (dry run enabled)
curl -X POST http://kong-admin:8001/plugins \
  --data "name=kong-guard-ai" \
  --data "config.dry_run_mode=true"
```

**Safety Features Active:**
- ✅ Threat detection enabled
- ✅ Logging and monitoring enabled
- ✅ No enforcement actions taken
- ✅ Performance impact minimized

**Validation Steps:**
1. Monitor logs for threat detection accuracy
2. Review false positive rates
3. Validate performance impact
4. Test notification systems

### Phase 2: Gradual Enforcement (Guided Mode)

```bash
# Enable basic enforcement after validation
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config.dry_run_mode=false" \
  --data "config.enable_rate_limiting_response=true" \
  --data "config.threat_threshold=7.5"
```

**Safety Features:**
- ✅ Rate limiting responses only (non-blocking)
- ✅ High threat threshold maintained
- ✅ Auto-blocking still disabled
- ⚠️ Monitor for legitimate traffic impact

### Phase 3: Full Protection (Production Mode)

```bash
# Enable full protection after successful gradual deployment
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config.enable_auto_blocking=true" \
  --data "config.threat_threshold=7.0" \
  --data "config.block_duration_seconds=3600"
```

**Production Features:**
- ✅ Full threat response enabled
- ✅ Automatic IP blocking active
- ✅ Optimized thresholds
- ⚠️ Requires operational monitoring

## Configuration Validation

### Pre-Deployment Checklist

#### Required Configuration
- [ ] Notification targets configured (email/Slack/webhook)
- [ ] Admin API credentials secured (if enabled)
- [ ] Rate limit thresholds appropriate for traffic patterns
- [ ] Suspicious patterns reviewed and customized
- [ ] Log level appropriate for environment

#### Security Validation
- [ ] `dry_run_mode` appropriate for environment
- [ ] IP whitelist configured for known safe sources
- [ ] Admin API access restricted (if enabled)
- [ ] AI Gateway credentials secured (if enabled)
- [ ] External logging endpoints validated (if enabled)

#### Performance Validation
- [ ] `max_processing_time_ms` tested under load
- [ ] `max_payload_size` appropriate for application
- [ ] Rate limit thresholds don't impact legitimate traffic
- [ ] Monitoring endpoints accessible

### Automated Validation Script

```lua
-- Use the defaults.lua validation function
local defaults = require "kong.plugins.kong-guard-ai.defaults"
local config = get_current_config()  -- Your config loading logic

local validation = defaults.validate_configuration(config, "production")

if not validation.valid then
    kong.log.err("Configuration validation failed: ", table.concat(validation.errors, ", "))
    return false
end

for _, warning in ipairs(validation.warnings) do
    kong.log.warn("Configuration warning: ", warning)
end

for _, recommendation in ipairs(validation.recommendations) do
    kong.log.info("Recommendation: ", recommendation)
end
```

## Emergency Procedures

### Immediate Threat Response Disable

```bash
# Emergency: Disable all enforcement
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config.dry_run_mode=true" \
  --data "config.enable_auto_blocking=false"
```

### Complete Plugin Disable

```bash
# Emergency: Disable entire plugin
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "enabled=false"
```

### Rollback Configuration

```bash
# Restore safe defaults
curl -X PATCH http://kong-admin:8001/plugins/{plugin-id} \
  --data "config=@safe-defaults.json"
```

## Monitoring and Alerting

### Critical Metrics to Monitor

1. **False Positive Rate**: Legitimate requests blocked
2. **Processing Latency**: Impact on request performance
3. **Threat Detection Accuracy**: True positives vs false alarms
4. **Resource Usage**: Memory and CPU impact
5. **External Service Health**: AI Gateway, notifications, logging

### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| False Positive Rate | > 5% | > 10% |
| Average Latency Increase | > 10ms | > 20ms |
| Failed Notifications | > 5/hour | > 20/hour |
| AI Gateway Timeouts | > 10% | > 25% |
| Memory Usage | > 100MB | > 200MB |

## Integration Safety

### Kong Admin API
- **Default**: Disabled for security
- **Enablement**: Requires explicit configuration
- **Credentials**: Must be secured in environment variables
- **Access**: Restrict to authorized operators only

### AI Gateway Integration
- **Default**: Disabled to prevent external dependencies
- **Configuration**: Requires API keys and endpoint validation
- **Fallback**: Must handle AI service unavailability gracefully
- **Cost Control**: Monitor API usage to prevent unexpected charges

### External Logging
- **Default**: Disabled to prevent data leakage
- **Validation**: Endpoint accessibility and authentication
- **Data Protection**: Ensure logs don't contain sensitive information
- **Performance**: Monitor impact on request latency

## Compliance Considerations

### Data Privacy
- Personal data in payloads handled according to configured policies
- IP addresses logged only when necessary for security
- Notification content sanitized to prevent data exposure

### Audit Requirements
- All configuration changes logged
- Threat response actions recorded with timestamps
- False positive incidents tracked for compliance reporting

### Incident Response
- Automated threat blocking logged with context
- Manual overrides tracked and auditable
- Configuration rollbacks documented

## Best Practices

### Development Environment
```lua
-- Development-safe configuration
config = {
    dry_run_mode = true,
    threat_threshold = 9.0,
    enable_auto_blocking = false,
    admin_api_enabled = false,
    log_level = "debug"
}
```

### Staging Environment
```lua
-- Staging configuration with limited enforcement
config = {
    dry_run_mode = false,
    threat_threshold = 8.0,
    enable_auto_blocking = false,
    enable_rate_limiting_response = true,
    log_level = "info"
}
```

### Production Environment
```lua
-- Production configuration after validation
config = {
    dry_run_mode = false,
    threat_threshold = 7.0,
    enable_auto_blocking = true,
    block_duration_seconds = 3600,
    enable_notifications = true,
    log_level = "info"
}
```

## Troubleshooting

### Common Issues

1. **High False Positives**
   - Increase `threat_threshold`
   - Review and adjust `suspicious_patterns`
   - Add legitimate sources to `ip_whitelist`

2. **Performance Impact**
   - Reduce `max_processing_time_ms`
   - Decrease `max_payload_size`
   - Disable `analyze_response_body`

3. **Missing Notifications**
   - Verify notification targets configuration
   - Check `notification_threshold` setting
   - Validate external service connectivity

4. **AI Gateway Failures**
   - Verify API key and endpoint configuration
   - Check `ai_timeout_ms` settings
   - Monitor external service availability

### Support and Escalation

For deployment issues or security concerns:
1. Enable `dry_run_mode` immediately
2. Review logs for error patterns
3. Consult configuration validation results
4. Contact security team with incident details

---

This safety guide ensures Kong Guard AI deployments follow security-first principles while maintaining operational effectiveness.