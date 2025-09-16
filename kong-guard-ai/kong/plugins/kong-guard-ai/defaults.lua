-- Kong Guard AI Plugin Default Configuration Values
-- Security-first defaults for safe deployment and predictable behavior
-- Compatible with Kong Gateway 3.x+ and Kong AI Gateway integration

local defaults = {}

-- SECURITY-FIRST PRINCIPLE: All defaults favor safety over performance
-- Operators must explicitly enable aggressive features after understanding risks

---@section Core Plugin Defaults
defaults.core = {
    -- Enable dry run by default for safe initial deployment
    dry_run_mode = true,  -- SAFE: Logs threats but takes no action initially

    -- Conservative threat threshold requiring manual tuning
    threat_threshold = 8.0,  -- SAFE: High threshold, fewer false positives

    -- Minimal processing time to avoid request delays
    max_processing_time_ms = 5,  -- SAFE: Quick processing, minimal latency impact
}

---@section Threat Detection Defaults
defaults.threat_detection = {
    -- Rate limiting detection - moderate defaults
    enable_rate_limiting_detection = true,
    rate_limit_window_seconds = 60,
    rate_limit_threshold = 150,  -- SAFE: Higher than typical load

    -- IP reputation - enabled but with empty lists initially
    enable_ip_reputation = true,
    ip_whitelist = {},  -- SAFE: Empty, must be explicitly configured
    ip_blacklist = {},  -- SAFE: Empty, must be explicitly configured

    -- Payload analysis - enabled with conservative limits
    enable_payload_analysis = true,
    max_payload_size = 262144,  -- SAFE: 256KB, smaller than default 1MB

    -- Comprehensive suspicious patterns for common attack vectors
    suspicious_patterns = {
        -- SQL Injection patterns
        "(?i)(union\\s+select)",
        "(?i)(drop\\s+table)",
        "(?i)(insert\\s+into)",
        "(?i)(delete\\s+from)",
        "(?i)(update\\s+.*set)",
        "(?i)(select\\s+.*from)",
        "(?i)(exec\\s*\\()",
        "(?i)(sp_executesql)",

        -- XSS patterns
        "(?i)(<script[^>]*>)",
        "(?i)(javascript:)",
        "(?i)(on\\w+\\s*=)",
        "(?i)(eval\\s*\\()",
        "(?i)(expression\\s*\\()",

        -- Command injection patterns
        "(?i)(system\\s*\\()",
        "(?i)(exec\\s*\\()",
        "(?i)(passthru\\s*\\()",
        "(?i)(shell_exec\\s*\\()",
        "(?i)(\\|\\s*\\w+)",
        "(?i)(;\\s*\\w+)",

        -- Path traversal patterns
        "\\.\\./.*etc/passwd",
        "\\.\\./.*etc/shadow",
        "\\.\\./.*boot\\.ini",
        "\\.\\./.*win\\.ini",

        -- LDAP injection patterns
        "(?i)(\\*\\)\\()",
        "(?i)(\\|\\()",
        "(?i)(\\&\\()"
    }
}

---@section AI Gateway Integration Defaults
defaults.ai_gateway = {
    ai_gateway_enabled = false,  -- SAFE: Disabled by default, requires explicit configuration
    ai_gateway_model = "gpt-4o-mini",  -- SAFE: Cost-effective model choice
    ai_gateway_endpoint = "",  -- SAFE: Empty, must be configured
    ai_analysis_threshold = 6.0,  -- SAFE: Higher threshold for AI analysis
    ai_timeout_ms = 3000,  -- SAFE: Shorter timeout to avoid delays
}

---@section Response Configuration Defaults
defaults.response = {
    -- Auto-blocking disabled in dry run, conservative when enabled
    enable_auto_blocking = false,  -- SAFE: Disabled, requires explicit enablement
    block_duration_seconds = 1800,  -- SAFE: 30 minutes, shorter than default

    -- Rate limiting response enabled for gradual mitigation
    enable_rate_limiting_response = true,

    -- Config rollback disabled for safety
    enable_config_rollback = false,  -- SAFE: High-risk feature disabled
    rollback_threshold = 9.5,  -- SAFE: Very high threshold if enabled

    -- Error response sanitization enabled for security
    sanitize_error_responses = true,  -- SECURE: Prevent information disclosure
}

---@section Response Analysis Defaults
defaults.response_analysis = {
    analyze_response_body = false,  -- SAFE: Disabled, can impact performance
    max_response_body_size = 4096,  -- SAFE: 4KB, minimal impact
}

---@section Learning and Adaptation Defaults
defaults.learning = {
    enable_learning = false,  -- SAFE: Disabled initially, requires understanding
    learning_sample_rate = 0.05,  -- SAFE: Low sampling rate (5%)
    feedback_endpoint = "",  -- SAFE: Empty, must be configured
}

---@section Notification Defaults
defaults.notifications = {
    enable_notifications = true,

    -- All notification targets empty - must be configured
    slack_webhook_url = "",  -- SAFE: Empty, must be configured
    email_smtp_server = "",  -- SAFE: Empty, must be configured
    email_from = "",  -- SAFE: Empty, must be configured
    email_to = {},  -- SAFE: Empty array, must be configured
    webhook_urls = {},  -- SAFE: Empty array, must be configured

    -- Moderate notification threshold
    notification_threshold = 7.0,  -- SAFE: Higher threshold, fewer notifications
}

---@section Logging Defaults
defaults.logging = {
    external_logging_enabled = false,  -- SAFE: Disabled by default
    log_endpoint = "",  -- SAFE: Empty, must be configured
    log_level = "info",  -- SAFE: Balanced logging level
}

---@section Admin API Integration Defaults
defaults.admin_api = {
    admin_api_enabled = false,  -- SAFE: Disabled by default for security
    admin_api_key = "",  -- SAFE: Empty, must be configured
    admin_api_timeout_ms = 3000,  -- SAFE: Shorter timeout
}

---@section Status and Monitoring Defaults
defaults.monitoring = {
    status_endpoint_enabled = true,
    status_endpoint_path = "/_guard_ai/status",
    metrics_endpoint_enabled = true,
    metrics_endpoint_path = "/_guard_ai/metrics",
}

---@section Helper Functions

-- Generate complete default configuration for new deployments
function defaults.get_deployment_config()
    return {
        -- Core settings with security-first approach
        dry_run_mode = true,
        threat_threshold = 8.0,
        max_processing_time_ms = 5,

        -- Detection enabled with conservative thresholds
        enable_rate_limiting_detection = true,
        rate_limit_window_seconds = 60,
        rate_limit_threshold = 150,

        enable_ip_reputation = true,
        ip_whitelist = {},
        ip_blacklist = {},

        enable_payload_analysis = true,
        max_payload_size = 262144,
        suspicious_patterns = defaults.threat_detection.suspicious_patterns,

        -- AI Gateway disabled initially
        ai_gateway_enabled = false,
        ai_gateway_model = "gpt-4o-mini",
        ai_analysis_threshold = 6.0,
        ai_timeout_ms = 3000,

        -- Conservative response configuration
        enable_auto_blocking = false,
        block_duration_seconds = 1800,
        enable_rate_limiting_response = true,
        enable_config_rollback = false,
        rollback_threshold = 9.5,
        sanitize_error_responses = true,

        -- Response analysis disabled for performance
        analyze_response_body = false,
        max_response_body_size = 4096,

        -- Learning disabled initially
        enable_learning = false,
        learning_sample_rate = 0.05,

        -- Notifications enabled but targets must be configured
        enable_notifications = true,
        notification_threshold = 7.0,

        -- External integrations disabled
        external_logging_enabled = false,
        admin_api_enabled = false,

        -- Monitoring enabled
        status_endpoint_enabled = true,
        status_endpoint_path = "/_guard_ai/status",
        metrics_endpoint_enabled = true,
        metrics_endpoint_path = "/_guard_ai/metrics",

        -- Logging level
        log_level = "info"
    }
end

-- Generate production-ready configuration template
function defaults.get_production_template()
    return {
        -- NOTE: This template shows production settings but maintains security
        dry_run_mode = false,  -- PRODUCTION: Enable enforcement after testing
        threat_threshold = 7.0,  -- PRODUCTION: Slightly lower threshold
        max_processing_time_ms = 10,  -- PRODUCTION: Allow more processing time

        -- Keep conservative detection settings
        enable_rate_limiting_detection = true,
        rate_limit_threshold = 200,  -- PRODUCTION: Higher threshold for production load

        -- Production responses
        enable_auto_blocking = true,  -- PRODUCTION: Enable blocking
        block_duration_seconds = 3600,  -- PRODUCTION: 1 hour blocks

        -- Keep other defaults the same for safety
        -- Operators should explicitly configure advanced features
    }
end

-- Validate configuration completeness for specific deployment types
function defaults.validate_configuration(config, deployment_type)
    local validation_result = {
        valid = true,
        warnings = {},
        errors = {},
        recommendations = {}
    }

    if deployment_type == "production" then
        -- Production-specific validations
        if config.dry_run_mode == true then
            table.insert(validation_result.warnings, "dry_run_mode is enabled in production configuration")
        end

        if not config.admin_api_enabled then
            table.insert(validation_result.recommendations, "Consider enabling admin_api for production management")
        end

        if #config.email_to == 0 and config.slack_webhook_url == "" then
            table.insert(validation_result.warnings, "No notification targets configured for production")
        end
    end

    if deployment_type == "development" then
        -- Development-specific validations
        if config.dry_run_mode == false then
            table.insert(validation_result.recommendations, "Consider enabling dry_run_mode for development")
        end
    end

    return validation_result
end

return defaults
