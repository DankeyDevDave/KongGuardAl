# Kong Guard AI Plugin - Phase 2 Schema Enhancement Summary

## Overview
This document summarizes the comprehensive schema enhancements implemented in Phase 2 for the Kong Guard AI plugin. The schema has been significantly enhanced with new field definitions, validation rules, and Kong Gateway 3.x+ compatibility features.

## Phase 2 Enhanced Fields

### 1. IP Blacklist (`ip_blacklist`)
- **Type**: Array of strings
- **Description**: Permanent IP blocking with CIDR support
- **Features**:
  - IPv4 and IPv6 support
  - CIDR notation support (e.g., `10.0.0.0/8`, `2001:db8::/32`)
  - Custom validation function
  - Default: Empty array
- **Example**:
  ```json
  "ip_blacklist": ["192.168.1.1", "10.0.0.0/8", "2001:db8::/32"]
  ```

### 2. Method Denylist (`method_denylist`)
- **Type**: Array of strings
- **Description**: HTTP methods to block
- **Features**:
  - Case-insensitive validation
  - Supports all standard HTTP methods
  - Custom validator for method validation
  - Default: Empty array
- **Example**:
  ```json
  "method_denylist": ["TRACE", "CONNECT", "DEBUG"]
  ```

### 3. Rate Limit Configuration (`rate_limit`)
- **Type**: Required record
- **Description**: Comprehensive rate limiting configuration
- **Fields**:
  - `requests_per_minute`: Max requests per minute (default: 100)
  - `requests_per_hour`: Max requests per hour (default: 1000)
  - `requests_per_day`: Max requests per day (default: 10000)
  - `window_size`: Time window in seconds (1-3600, default: 60)
  - `sync_rate`: Counter sync interval for clusters (1-60, default: 10)
- **Example**:
  ```json
  "rate_limit": {
    "requests_per_minute": 100,
    "requests_per_hour": 1000,
    "requests_per_day": 10000,
    "window_size": 60,
    "sync_rate": 10
  }
  ```

### 4. Burst Threshold Configuration (`burst_threshold`)
- **Type**: Required record
- **Description**: Burst traffic detection and mitigation
- **Fields**:
  - `max_requests`: Max requests in burst window (default: 50)
  - `window_seconds`: Burst detection window (1-300, default: 10)
  - `violation_threshold`: Violations before escalation (1-10, default: 3)
  - `cooldown_period`: Cooldown after burst (60-3600, default: 300)
- **Example**:
  ```json
  "burst_threshold": {
    "max_requests": 50,
    "window_seconds": 10,
    "violation_threshold": 3,
    "cooldown_period": 300
  }
  ```

### 5. Dry Run Mode (`dry_run`)
- **Type**: Boolean
- **Description**: Testing mode without enforcement
- **Features**:
  - When `true`: Detects and logs threats without blocking
  - When `false`: Enforces all configured protections
  - Default: `true` for safe testing
- **Example**:
  ```json
  "dry_run": true
  ```

### 6. Enhanced Admin API Integration (`admin_api`)
- **Type**: Required record
- **Description**: Kong Admin API integration for dynamic configuration
- **Enhanced Fields**:
  - `enabled`: Enable Admin API integration (default: true)
  - `admin_url`: Kong Admin API URL (default: "http://localhost:8001")
  - `admin_key`: API key for RBAC authentication
  - `timeout`: Request timeout in ms (1000-30000, default: 5000)
  - `auto_config_updates`: Automatic config pushes (default: false)
  - `backup_configs`: Create config backups (default: true)
  - `max_backups`: Maximum backup retention (1-50, default: 5)
  - `verify_ssl`: SSL certificate verification (default: true)
  - `retry_attempts`: Retry attempts for failed requests (1-10, default: 3)
  - `retry_delay`: Delay between retries in ms (100-10000, default: 1000)

### 7. Comprehensive Notification Targets (`notification_targets`)
- **Type**: Array of notification target records
- **Description**: Multi-platform notification system
- **Supported Types**: webhook, slack, email, sms, discord, teams
- **Features per Target**:
  - `name`: Unique identifier
  - `type`: Notification type
  - `endpoint`: Target URL or identifier
  - `enabled`: Enable/disable toggle
  - `severity_filter`: Severity levels to notify (default: ["high", "critical"])
  - `rate_limit`: Max notifications per hour (1-100, default: 10)
  - `timeout`: Delivery timeout in ms (1000-30000, default: 5000)
  - `retry_attempts`: Retry attempts (0-10, default: 3)
  - `template`: Message template name
  - `headers`: Custom headers for webhooks
  - `auth`: Authentication configuration (none, bearer, basic, api_key)
- **Example**:
  ```json
  "notification_targets": [
    {
      "name": "security-slack",
      "type": "slack",
      "endpoint": "https://hooks.slack.com/services/...",
      "enabled": true,
      "severity_filter": ["high", "critical"],
      "rate_limit": 10,
      "timeout": 5000,
      "auth": {
        "type": "none"
      }
    }
  ]
  ```

## Enhanced Validation Features

### Custom Validators
1. **IP/CIDR Validator**: Validates IPv4/IPv6 addresses and CIDR blocks
2. **HTTP Method Validator**: Validates against standard HTTP methods
3. **Notification Target Validator**: Comprehensive validation for notification configs

### Input Validation Rules
- **Range Validation**: Using `between`, `gt`, `gte` constraints
- **String Validation**: Using `one_of` for enumerated values
- **Required Fields**: Marking critical configuration as required
- **Default Values**: Safe defaults for all optional fields
- **Type Safety**: Strict type checking for all fields

### Error Messages
- Descriptive error messages for validation failures
- Clear guidance on valid input formats
- Examples provided in field descriptions

## Backward Compatibility

### Legacy Field Support
- Existing configurations continue to work
- Legacy fields marked as DEPRECATED with migration guidance
- Clear migration path to new Phase 2 fields

### Migration Guide
- `threat_detection.rules.blocked_ips` → `ip_blacklist`
- `threat_detection.rules.allowed_methods` → Configure `method_denylist` instead
- `notifications.webhook_url` → `notification_targets` with type="webhook"
- `notifications.slack_webhook` → `notification_targets` with type="slack"
- `notifications.email_config` → `notification_targets` with type="email"

## Kong Gateway 3.x+ Compatibility

### Declarative Schema Features
- Full compatibility with Kong's declarative configuration
- Proper schema typing for DB-less mode
- Support for Kong Admin API integration
- Konnect cloud compatibility

### Performance Optimizations
- Efficient validation with minimal overhead
- Caching support for validation results
- Optimized for high-throughput scenarios

### Security Enhancements
- SSL verification for external connections
- Authentication support for all notification types
- Secure credential handling
- Input sanitization and validation

## Usage Examples

### Basic Configuration
```yaml
kong-guard-ai:
  dry_run: false
  ip_blacklist: ["192.168.1.100", "10.0.0.0/8"]
  method_denylist: ["TRACE", "CONNECT"]
  rate_limit:
    requests_per_minute: 60
    requests_per_hour: 3600
  burst_threshold:
    max_requests: 30
    window_seconds: 10
```

### Production Configuration
```yaml
kong-guard-ai:
  dry_run: false
  rate_limit:
    requests_per_minute: 1000
    requests_per_hour: 50000
    requests_per_day: 1000000
  notification_targets:
    - name: "security-ops"
      type: "slack"
      endpoint: "https://hooks.slack.com/services/..."
      severity_filter: ["high", "critical"]
    - name: "security-email"
      type: "email"
      endpoint: "security@company.com"
      severity_filter: ["critical"]
  admin_api:
    enabled: true
    auto_config_updates: true
    backup_configs: true
```

## Testing and Validation

### Dry Run Mode
- Use `dry_run: true` for testing configurations
- Monitor logs for threat detection without blocking
- Validate notification delivery without enforcement

### Schema Validation
- Kong validates all configuration on plugin enable
- Custom validators provide detailed error messages
- Test configurations with Kong Admin API

### Monitoring
- Enhanced logging with structured JSON
- Performance metrics included in logs
- Notification delivery tracking

## Future Enhancements
- Additional notification types (PagerDuty, Microsoft Teams)
- Machine learning model integration
- Advanced geo-blocking features
- Custom validation rule engine
- Multi-tenant configuration support

---

**Generated by**: Kong Guard AI Schema Designer Agent  
**Phase**: 2 - Enhanced Configuration Schema  
**Kong Compatibility**: 3.x+  
**Last Updated**: 2025-08-19