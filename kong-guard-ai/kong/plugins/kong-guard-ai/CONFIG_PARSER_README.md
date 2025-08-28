# Kong Guard AI Configuration Parser System

## Overview

The Kong Guard AI Configuration Parser System provides robust configuration parsing, validation, loading, and error handling capabilities for the Kong Guard AI plugin. It ensures that configuration data is properly validated, cached for performance, and can be hot-reloaded during runtime.

## Architecture

The configuration system consists of four main modules:

1. **config_parser.lua** - Core parsing and validation logic
2. **config_loader.lua** - Configuration loading strategies and lifecycle management
3. **config_errors.lua** - Comprehensive error handling and recovery
4. **config_integration.lua** - Unified interface and coordination

## Features

### Configuration Parsing
- ✅ JSON string and Lua table parsing
- ✅ Deep merging with default configurations
- ✅ Type validation (boolean, number, string, array)
- ✅ Range validation for numeric values
- ✅ Format validation (IP addresses, emails, URLs, regex patterns)
- ✅ Conditional requirement validation

### Configuration Loading
- ✅ Multiple loading strategies (plugin config, Admin API, environment variables)
- ✅ Fallback strategy support
- ✅ Configuration caching with TTL
- ✅ Hot-reload capabilities
- ✅ Kong plugin lifecycle integration

### Error Handling
- ✅ Structured error objects with severity levels
- ✅ Error categorization (validation, parsing, loading, network, etc.)
- ✅ Recovery strategies (fallback, retry, graceful degradation)
- ✅ Error history tracking and rate limiting
- ✅ Detailed logging with context

### Integration Features
- ✅ Unified configuration interface
- ✅ Performance metrics tracking
- ✅ Health monitoring
- ✅ Configuration diff utilities
- ✅ Export/import capabilities

## Usage

### Basic Usage

```lua
local config_integration = require "kong.plugins.kong-guard-ai.config_integration"

-- Initialize the configuration system
local success, config = config_integration.initialize(plugin_config, {
    primary_strategy = "plugin_config",
    fallback_strategies = { "environment" },
    cache_config = { ttl = 300 }
})

if success then
    -- Use the configuration
    local current_config = config_integration.get_config()
    local threat_threshold = current_config.threat_threshold
else
    kong.log.err("Failed to initialize configuration")
end
```

### Hot-Reload Configuration

```lua
-- Hot-reload with new configuration
local new_config = {
    dry_run_mode = false,
    threat_threshold = 8.5
}

local success, errors = config_integration.hot_reload(new_config)
if not success then
    kong.log.err("Hot-reload failed: " .. table.concat(errors, ", "))
end
```

### Error Handling

```lua
-- Handle configuration errors gracefully
local recovery_success, recovery_result, error_obj = config_integration.handle_config_error(
    "validation",
    {
        field = "threat_threshold",
        value = 15.0,
        expected = "1.0-10.0"
    },
    { fallback_config = default_config }
)

if recovery_success then
    kong.log.warn("Configuration recovered: " .. recovery_result.recovery_method)
end
```

## Configuration Schema

### Core Settings

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `dry_run_mode` | boolean | `false` | - | Enable dry run mode (log only) |
| `threat_threshold` | number | `7.0` | 1.0-10.0 | Threat level threshold |
| `max_processing_time_ms` | number | `10` | 1-100 | Max processing time per request |

### Detection Settings

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `enable_rate_limiting_detection` | boolean | `true` | - | Enable rate limiting detection |
| `rate_limit_window_seconds` | number | `60` | 1-3600 | Rate limiting time window |
| `rate_limit_threshold` | number | `100` | 1-10000 | Request count threshold |
| `enable_ip_reputation` | boolean | `true` | - | Enable IP reputation checks |
| `ip_whitelist` | array | `[]` | - | List of whitelisted IPs/CIDR |
| `ip_blacklist` | array | `[]` | - | List of blacklisted IPs/CIDR |
| `enable_payload_analysis` | boolean | `true` | - | Enable payload analysis |
| `max_payload_size` | number | `1048576` | 1024-10485760 | Max payload size to analyze |
| `suspicious_patterns` | array | (predefined) | - | Regex patterns for threat detection |

### AI Gateway Settings

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `ai_gateway_enabled` | boolean | `false` | - | Enable AI Gateway integration |
| `ai_gateway_model` | string | `"gpt-4"` | - | AI model for analysis |
| `ai_gateway_endpoint` | string | - | - | AI Gateway endpoint URL |
| `ai_analysis_threshold` | number | `5.0` | 1.0-10.0 | Threshold for AI analysis |
| `ai_timeout_ms` | number | `5000` | 100-30000 | AI request timeout |

### Response Settings

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `enable_auto_blocking` | boolean | `true` | - | Enable automatic blocking |
| `block_duration_seconds` | number | `3600` | 60-86400 | Block duration |
| `enable_rate_limiting_response` | boolean | `true` | - | Enable dynamic rate limiting |
| `enable_config_rollback` | boolean | `false` | - | Enable config rollback |
| `rollback_threshold` | number | `9.0` | 5.0-10.0 | Rollback trigger threshold |
| `sanitize_error_responses` | boolean | `true` | - | Sanitize error responses |

### Notification Settings

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `enable_notifications` | boolean | `true` | - | Enable notifications |
| `notification_threshold` | number | `6.0` | 1.0-10.0 | Notification threshold |
| `slack_webhook_url` | string | - | - | Slack webhook URL |
| `email_smtp_server` | string | - | - | SMTP server for email |
| `email_from` | string | - | - | From email address |
| `email_to` | array | `[]` | - | List of recipient emails |
| `webhook_urls` | array | `[]` | - | List of webhook URLs |

### Admin API Settings

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `admin_api_enabled` | boolean | `true` | - | Enable Admin API integration |
| `admin_api_key` | string | - | - | Admin API key |
| `admin_api_timeout_ms` | number | `5000` | 100-30000 | Admin API timeout |

## Loading Strategies

### Plugin Config Strategy (Default)
Loads configuration from Kong's plugin configuration passed during plugin initialization.

```lua
local config, errors = config_loader.load_from_plugin_config(plugin_config)
```

### Admin API Strategy
Loads configuration by querying Kong's Admin API for the plugin configuration.

```lua
local config, errors = config_loader.load_from_admin_api(
    "http://localhost:8001",  -- admin_url
    "your-admin-key",         -- admin_key (optional)
    "plugin-id-here"          -- plugin_id
)
```

### Environment Variables Strategy
Loads configuration from environment variables with configurable prefix.

```lua
local config, errors = config_loader.load_from_environment("KONG_GUARD_AI_")
```

Environment variable mappings:
- `KONG_GUARD_AI_DRY_RUN_MODE` → `dry_run_mode`
- `KONG_GUARD_AI_THREAT_THRESHOLD` → `threat_threshold`
- `KONG_GUARD_AI_AI_GATEWAY_ENABLED` → `ai_gateway_enabled`
- etc.

## Error Handling

### Error Categories

- **VALIDATION** - Configuration validation errors
- **PARSING** - Configuration parsing errors
- **LOADING** - Configuration loading errors
- **NETWORK** - Network-related errors (Admin API, etc.)
- **PERMISSION** - Permission/access errors
- **DEPENDENCY** - Missing dependencies
- **RUNTIME** - Runtime configuration errors
- **TIMEOUT** - Timeout-related errors
- **FORMAT** - Data format errors

### Error Levels

- **CRITICAL** - System cannot function
- **HIGH** - Major functionality impaired
- **MEDIUM** - Some functionality affected
- **LOW** - Minor issues or warnings
- **INFO** - Informational messages

### Recovery Strategies

- **FALLBACK_CONFIG** - Use fallback configuration
- **DEFAULT_CONFIG** - Use default configuration
- **RETRY** - Retry the operation
- **DISABLE_FEATURE** - Disable problematic feature
- **GRACEFUL_DEGRADATION** - Reduce functionality
- **FAIL_FAST** - Fail immediately

## Performance Considerations

### Caching
- Configuration caching with configurable TTL (default: 5 minutes)
- Cache invalidation on hot-reload
- Per-key caching support

### Metrics Tracking
- Configuration loads
- Validation operations
- Cache hits/misses
- Error counts
- Hot-reload operations

### Performance Impact
- Minimal overhead during normal operation
- Validation only performed during configuration changes
- Efficient caching reduces repeated parsing

## Testing

The configuration system includes comprehensive test coverage:

```bash
# Run tests with busted (Kong's test framework)
busted spec/config_parser_spec.lua
```

Test coverage includes:
- Configuration parsing and validation
- Error handling and recovery
- Caching behavior
- Loading strategies
- Integration functionality

## Integration with Kong Plugin

### Handler Integration

```lua
local config_integration = require "kong.plugins.kong-guard-ai.config_integration"
local handler = {}

function handler:init_worker()
    -- Initialize configuration during Kong worker initialization
    local success, config = config_integration.initialize(self.config, {
        primary_strategy = "plugin_config",
        fallback_strategies = { "environment" }
    })
    
    if not success then
        kong.log.err("Failed to initialize Kong Guard AI configuration")
    end
end

function handler:access(config)
    -- Get current configuration
    local current_config = config_integration.get_config()
    
    -- Use configuration values
    if current_config.dry_run_mode then
        kong.log.info("Running in dry-run mode")
        return
    end
    
    -- Threat detection logic using current_config...
end
```

### Status Endpoint Integration

```lua
-- Add configuration status to plugin status endpoint
local status = config_integration.get_status()
local health = config_integration.health_check()
```

## Configuration Examples

### Basic Configuration

```json
{
    "dry_run_mode": false,
    "threat_threshold": 7.5,
    "enable_notifications": true,
    "notification_threshold": 6.0,
    "slack_webhook_url": "https://hooks.slack.com/...",
    "ip_blacklist": ["203.0.113.100", "198.51.100.0/24"],
    "suspicious_patterns": [
        "union.*select",
        "<script",
        "javascript:"
    ]
}
```

### Advanced Configuration with AI Gateway

```json
{
    "dry_run_mode": false,
    "threat_threshold": 8.0,
    "ai_gateway_enabled": true,
    "ai_gateway_endpoint": "https://api.kong-ai.example.com",
    "ai_gateway_model": "gpt-4",
    "ai_analysis_threshold": 6.0,
    "enable_auto_blocking": true,
    "block_duration_seconds": 7200,
    "enable_config_rollback": true,
    "rollback_threshold": 9.5,
    "admin_api_enabled": true,
    "admin_api_key": "your-admin-api-key"
}
```

## Troubleshooting

### Common Issues

1. **Configuration Validation Errors**
   - Check field types and value ranges
   - Ensure required conditional fields are provided
   - Validate IP addresses and URL formats

2. **Loading Strategy Failures**
   - Verify Admin API connectivity and credentials
   - Check environment variable names and values
   - Ensure plugin configuration is properly passed

3. **Performance Issues**
   - Adjust cache TTL settings
   - Monitor error rates and recovery patterns
   - Check configuration complexity and size

### Debug Mode

Enable detailed logging for troubleshooting:

```lua
config_integration.initialize(plugin_config, {
    error_config = {
        enable_detailed_logging = true,
        enable_error_reporting = true
    }
})
```

### Health Monitoring

Regular health checks:

```lua
local health = config_integration.health_check()
if health.status ~= "healthy" then
    kong.log.warn("Configuration system health issues: " .. 
                  table.concat(health.issues, ", "))
end
```

## Future Enhancements

- Schema validation integration with Kong's built-in schema system
- Configuration versioning and rollback history
- Real-time configuration synchronization across Kong cluster nodes
- Configuration templates and profiles
- Advanced performance optimization and monitoring