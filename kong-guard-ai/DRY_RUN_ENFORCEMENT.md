# Kong Guard AI - Dry-Run Enforcement System

## Overview

The Kong Guard AI plugin includes a comprehensive dry-run enforcement system that enables safe testing and validation of security policies without actually executing enforcement actions. This system provides complete visibility into what actions would be taken while maintaining normal traffic flow.

## Architecture

### Enforcement Gate Module (`enforcement_gate.lua`)

The central component that controls all enforcement actions throughout the plugin. Every security action must pass through this gate, which automatically handles dry-run mode logic.

**Key Features:**
- Centralized enforcement control
- Automatic dry-run mode detection
- Action simulation and logging
- Comprehensive metrics collection
- Memory-safe action registry

### Enforcement Flow

```
Threat Detected → Enforcement Gate → Dry-Run Check → Action or Simulation
                                                  ↓
                                            Logging & Metrics
```

## Configuration

### Schema Configuration

The dry-run mode is controlled by the `dry_run_mode` configuration field:

```yaml
plugins:
- name: kong-guard-ai
  config:
    dry_run_mode: true  # Enable dry-run mode
    threat_threshold: 7.0
    enable_auto_blocking: true
    # ... other configuration
```

### Environment Variables

For Docker/Kubernetes deployments:

```bash
KONG_GUARD_AI_DRY_RUN=true
```

## Enforcement Actions

The following enforcement actions are controlled by the dry-run system:

### 1. Request Blocking (`BLOCK_REQUEST`)
**Active Mode:** Immediately blocks the request with appropriate HTTP status
**Dry-Run Mode:** Logs the block action and request details, allows request to continue

### 2. Rate Limiting (`RATE_LIMIT`)
**Active Mode:** Applies dynamic rate limiting via Kong Admin API
**Dry-Run Mode:** Simulates rate limit calculation and logs the policy that would be applied

### 3. IP Blocking (`BLOCK_IP`)
**Active Mode:** Adds IP to blocklist with configurable duration
**Dry-Run Mode:** Logs IP that would be blocked and duration

### 4. Configuration Rollback (`CONFIG_ROLLBACK`)
**Active Mode:** Reverts Kong configuration to previous safe state
**Dry-Run Mode:** Identifies rollback target and logs rollback plan

### 5. Notifications (`NOTIFICATION`)
**Active Mode:** Sends notifications via configured channels (Slack, email, webhooks)
**Dry-Run Mode:** Logs notification content and target channels

### 6. Admin API Calls (`ADMIN_API_CALL`)
**Active Mode:** Makes actual API calls to Kong Admin API
**Dry-Run Mode:** Logs API endpoint, method, and payload that would be sent

## Status and Monitoring

### Status Endpoint

Access dry-run status via: `GET /_guard_ai/status`

**Example Response:**
```json
{
  "plugin_info": {
    "name": "kong-guard-ai",
    "version": "0.1.0",
    "dry_run_mode": true,
    "node_id": "kong-node-1",
    "timestamp": 1703875200
  },
  "enforcement_statistics": {
    "total_actions": 25,
    "dry_run_actions": 25,
    "actual_actions": 0,
    "success_rate": 1.0
  },
  "dry_run_registry": {
    "summary": {
      "total_simulated_actions": 25,
      "action_types": ["block_request", "rate_limit", "notification"],
      "latest_simulation": {
        "action_type": "block_request",
        "timestamp": 1703875180,
        "summary": "Block request from IP 203.0.113.100 (reason: threat_detected)"
      }
    }
  },
  "dry_run_info": {
    "mode": "TESTING",
    "description": "Plugin is in dry-run mode - threats detected but no enforcement actions executed",
    "simulated_actions_count": 25
  }
}
```

### Metrics Endpoint

Access detailed metrics via: `GET /_guard_ai/metrics`

**Features:**
- Comprehensive enforcement statistics
- Action breakdown by type
- Recent simulation history
- Performance metrics

### Prometheus Metrics

Access Prometheus-compatible metrics via: `GET /_guard_ai/prometheus`

**Available Metrics:**
- `kong_guard_ai_total_actions` - Total enforcement actions processed
- `kong_guard_ai_dry_run_actions` - Actions simulated in dry-run mode
- `kong_guard_ai_actual_actions` - Actual enforcement actions executed
- `kong_guard_ai_dry_run_mode` - Current mode (1=dry-run, 0=active)
- `kong_guard_ai_simulated_actions_by_type` - Simulated actions by type

## Logging

### Dry-Run Log Format

All dry-run actions are logged with consistent formatting:

```
[Kong Guard AI Enforcement Gate] 🧪 DRY RUN: Would execute block_request - Medium - Single request blocked
```

### Structured Logging

Detailed enforcement records are logged in JSON format:

```json
{
  "enforcement_result": {
    "action_type": "block_request",
    "dry_run_mode": true,
    "simulated": true,
    "executed": false,
    "timestamp": 1703875200,
    "details": {
      "simulation": {
        "action": "block_request",
        "impact_assessment": "Medium - Single request blocked",
        "execution_path": ["Set response status and headers", "Call kong.response.exit()", "Log block action"]
      }
    }
  }
}
```

## Testing

### Automated Test Suite

Run the comprehensive test suite via: `GET /_guard_ai/test`

**Test Coverage:**
- Block request enforcement (dry-run vs active)
- Rate limiting enforcement (dry-run vs active)
- IP blocking enforcement (dry-run vs active)
- Configuration rollback (dry-run vs active)
- Notification handling (dry-run vs active)
- Admin API calls (dry-run vs active)

**Example Test Response:**
```json
{
  "test_summary": {
    "total_tests": 10,
    "passed_tests": 10,
    "failed_tests": 0,
    "success_rate": 100.0
  },
  "test_details": [
    {
      "test_name": "Block Request - Dry Run Mode",
      "success": true,
      "result": {
        "action_type": "block_request",
        "dry_run_mode": true,
        "simulated": true,
        "executed": false
      }
    }
  ]
}
```

### Manual Testing

#### Test Dry-Run Mode

1. Configure plugin with `dry_run_mode: true`
2. Trigger a threat condition (e.g., suspicious payload)
3. Verify request is not blocked
4. Check logs for dry-run simulation messages
5. Access status endpoint to see simulated actions

#### Test Active Mode

1. Configure plugin with `dry_run_mode: false`
2. Trigger the same threat condition
3. Verify enforcement action is executed
4. Check logs for actual enforcement messages

## Best Practices

### Development Workflow

1. **Always start with dry-run mode** when deploying to new environments
2. **Validate threat detection accuracy** using dry-run logs
3. **Review simulated actions** via status endpoint before enabling active mode
4. **Gradually transition** from dry-run to active mode for specific threat types

### Production Deployment

1. **Test configuration changes** in dry-run mode first
2. **Monitor dry-run metrics** to understand impact before activation
3. **Use staged rollouts** when enabling active enforcement
4. **Maintain alerting** on enforcement failure rates

### Monitoring and Alerting

1. **Set up alerts** for enforcement action failures
2. **Monitor success rates** via Prometheus metrics
3. **Review dry-run registry** regularly for policy validation
4. **Track performance impact** of enforcement actions

## Integration Examples

### Kong Admin API

Apply plugin configuration with dry-run mode:

```bash
curl -X POST http://kong-admin:8001/plugins \
  --data "name=kong-guard-ai" \
  --data "config.dry_run_mode=true" \
  --data "config.threat_threshold=7.0" \
  --data "config.enable_auto_blocking=true"
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kong-guard-ai-config
data:
  config.yaml: |
    plugins:
    - name: kong-guard-ai
      config:
        dry_run_mode: true
        threat_threshold: 7.0
        enable_auto_blocking: true
        status_endpoint_enabled: true
        metrics_endpoint_enabled: true
```

### Docker Compose

```yaml
services:
  kong:
    environment:
      - KONG_PLUGINS=kong-guard-ai
      - KONG_GUARD_AI_DRY_RUN=true
      - KONG_GUARD_AI_THREAT_THRESHOLD=7.0
```

## Troubleshooting

### Common Issues

#### Dry-Run Mode Not Working
**Symptoms:** Actions are being executed despite `dry_run_mode: true`
**Solution:** Verify configuration is applied correctly via `/status` endpoint

#### Missing Simulation Logs
**Symptoms:** No dry-run log messages appear
**Solution:** Check log level configuration and ensure threats are being detected

#### Status Endpoint Not Accessible
**Symptoms:** 404 error when accessing `/_guard_ai/status`
**Solution:** Verify `status_endpoint_enabled: true` in configuration

### Debug Commands

```bash
# Check plugin configuration
curl http://kong-admin:8001/plugins | jq '.data[] | select(.name == "kong-guard-ai")'

# View enforcement statistics
curl http://kong:8000/_guard_ai/status | jq '.enforcement_statistics'

# Monitor dry-run registry
curl http://kong:8000/_guard_ai/status | jq '.dry_run_registry'

# Run test suite
curl http://kong:8000/_guard_ai/test
```

## Security Considerations

### Safe Testing

The dry-run enforcement system ensures:
- **No traffic disruption** during testing
- **Complete action simulation** for validation
- **Comprehensive logging** for audit trails
- **Performance monitoring** to assess impact

### Production Safety

- Dry-run mode provides **zero risk** policy testing
- **Gradual enforcement** can be enabled per action type
- **Rollback capabilities** are tested before activation
- **Monitoring integration** provides operational visibility

## Performance Impact

### Dry-Run Mode
- **Minimal overhead** (~1-2ms additional latency)
- **Memory efficient** action registry with automatic cleanup
- **Non-blocking** simulation processing

### Active Mode
- **Optimized execution** paths for enforcement actions
- **Async processing** for non-critical actions (notifications)
- **Configurable timeouts** for external API calls

The dry-run enforcement system provides comprehensive safety and validation capabilities while maintaining the high performance requirements of the Kong Guard AI plugin.