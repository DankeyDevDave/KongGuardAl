-- Kong Guard AI - Advanced Remediation Schema Extension
-- PHASE 7: Configuration schema for advanced remediation and rollback features
-- This module extends the main schema with enterprise-grade remediation options

local _M = {}

-- Advanced remediation configuration fields
_M.advanced_remediation_fields = {
    -- PHASE 7: Advanced Remediation and Rollback Configuration
    {
        enable_advanced_remediation = {
            type = "boolean",
            default = false,
            description = "Enable advanced remediation with service/route modification and rollback capabilities. ENTERPRISE FEATURE: Use with extreme caution"
        }
    },
    {
        config_correlation_window = {
            type = "number", 
            default = 86400,
            between = { 3600, 604800 },
            description = "Time window in seconds for correlating 5xx errors with configuration changes (1 hour to 7 days)"
        }
    },
    {
        error_correlation_threshold = {
            type = "number",
            default = 0.15,
            between = { 0.01, 1.0 },
            description = "Error rate threshold (0-1) for triggering configuration correlation analysis"
        }
    },
    {
        enable_5xx_correlation = {
            type = "boolean",
            default = true,
            description = "Enable correlation of 5xx errors with recent configuration changes"
        }
    },
    {
        remediation_confidence_threshold = {
            type = "number",
            default = 0.8,
            between = { 0.1, 1.0 },
            description = "Minimum confidence level (0-1) required to trigger automated remediation"
        }
    },
    {
        enable_automatic_rollback = {
            type = "boolean",
            default = false,
            description = "Enable automatic configuration rollback for correlated 5xx events. DANGER: Can disrupt service"
        }
    },
    {
        rollback_confidence_threshold = {
            type = "number",
            default = 0.9,
            between = { 0.5, 1.0 },
            description = "Minimum confidence level required for automatic rollback (0.5-1.0)"
        }
    },
    {
        enable_traffic_rerouting = {
            type = "boolean",
            default = false,
            description = "Enable automatic traffic rerouting during error correlation events"
        }
    },
    {
        default_reroute_strategy = {
            type = "string",
            default = "immediate",
            one_of = { "immediate", "gradual", "canary", "blue_green" },
            description = "Default strategy for traffic rerouting during remediation"
        }
    },
    {
        gradual_shift_duration = {
            type = "number",
            default = 300,
            between = { 60, 3600 },
            description = "Duration in seconds for gradual traffic shifting (1 minute to 1 hour)"
        }
    },
    {
        enable_rollback_dry_run = {
            type = "boolean",
            default = true,
            description = "Always perform dry run validation before executing rollbacks"
        }
    },
    {
        enable_periodic_snapshots = {
            type = "boolean",
            default = true,
            description = "Enable periodic configuration snapshots for rollback purposes"
        }
    },
    {
        snapshot_interval_seconds = {
            type = "number",
            default = 3600,
            between = { 300, 86400 },
            description = "Interval in seconds between periodic configuration snapshots"
        }
    },
    {
        max_snapshots_retained = {
            type = "number",
            default = 168,
            between = { 24, 720 },
            description = "Maximum number of configuration snapshots to retain (24 = 1 day, 720 = 30 days)"
        }
    },
    {
        kong_admin_url = {
            type = "string",
            default = "http://localhost:8001",
            description = "Kong Admin API URL for configuration management"
        }
    },
    {
        kong_admin_api_key = {
            type = "string",
            description = "Kong Admin API key for authenticated configuration operations"
        }
    },
    {
        kong_workspace = {
            type = "string",
            description = "Kong workspace name for multi-tenant deployments"
        }
    },
    {
        enable_deck_integration = {
            type = "boolean",
            default = true,
            description = "Enable decK (Kong declarative configuration) integration for advanced operations"
        }
    },
    {
        deck_config_format = {
            type = "string",
            default = "yaml",
            one_of = { "yaml", "json" },
            description = "Configuration format for decK operations"
        }
    },
    {
        emergency_rollback_enabled = {
            type = "boolean",
            default = false,
            description = "Enable emergency rollback for critical error scenarios. EXTREME CAUTION: Can cause service disruption"
        }
    },
    {
        emergency_error_threshold = {
            type = "number",
            default = 0.5,
            between = { 0.2, 1.0 },
            description = "Error rate threshold for emergency rollback (0.2-1.0)"
        }
    },
    {
        circuit_breaker_enabled = {
            type = "boolean",
            default = true,
            description = "Enable circuit breaker pattern for failing services during error correlation"
        }
    },
    {
        circuit_breaker_failure_threshold = {
            type = "number",
            default = 10,
            between = { 3, 100 },
            description = "Number of consecutive failures before opening circuit breaker"
        }
    },
    {
        circuit_breaker_recovery_timeout = {
            type = "number",
            default = 60,
            between = { 10, 300 },
            description = "Time in seconds before attempting to close circuit breaker"
        }
    },
    {
        remediation_timeout_seconds = {
            type = "number",
            default = 300,
            between = { 30, 1800 },
            description = "Maximum time allowed for remediation operations to complete"
        }
    },
    {
        enable_remediation_validation = {
            type = "boolean",
            default = true,
            description = "Enable post-remediation validation to ensure changes were successful"
        }
    },
    {
        validation_timeout_seconds = {
            type = "number",
            default = 60,
            between = { 10, 300 },
            description = "Timeout for post-remediation validation checks"
        }
    },
    {
        backup_retention_days = {
            type = "number",
            default = 7,
            between = { 1, 30 },
            description = "Number of days to retain configuration backups"
        }
    },
    {
        enable_remediation_notifications = {
            type = "boolean",
            default = true,
            description = "Send notifications for remediation actions and rollbacks"
        }
    },
    {
        remediation_notification_channels = {
            type = "array",
            elements = {
                type = "string",
                one_of = { "slack", "email", "webhook", "teams", "pagerduty" }
            },
            default = { "webhook" },
            description = "Notification channels for remediation events"
        }
    }
}

return _M