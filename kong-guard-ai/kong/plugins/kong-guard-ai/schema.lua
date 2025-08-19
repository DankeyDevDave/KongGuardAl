-- Kong Guard AI Plugin Configuration Schema
-- Defines all configuration options for the autonomous threat response system
-- Compatible with Kong Gateway 3.x+ configuration validation

local typedefs = require "kong.db.schema.typedefs"

return {
    name = "kong-guard-ai",
    fields = {
        -- Standard Kong plugin fields
        { consumer = typedefs.no_consumer },
        { protocols = typedefs.protocols_http },
        { config = {
            type = "record",
            fields = {
                -- Core Plugin Configuration - SECURITY-FIRST DEFAULTS
                {
                    dry_run_mode = {
                        type = "boolean",
                        default = true,  -- SAFE: Default to dry run for safe deployment
                        description = "Enable dry run mode - logs threats but doesn't take action. RECOMMENDED: Start with true, disable after validation"
                    }
                },
                {
                    threat_threshold = {
                        type = "number",
                        default = 8.0,  -- SAFE: Higher threshold reduces false positives
                        between = { 1.0, 10.0 },
                        description = "Threat level threshold for triggering responses (1-10 scale). RECOMMENDED: Start with 8.0, lower gradually after tuning"
                    }
                },
                {
                    max_processing_time_ms = {
                        type = "number",
                        default = 5,  -- SAFE: Lower latency impact
                        between = { 1, 100 },
                        description = "Maximum allowed processing time per request in milliseconds. RECOMMENDED: Start with 5ms to minimize latency"
                    }
                },
                
                -- Threat Detection Configuration
                {
                    enable_rate_limiting_detection = {
                        type = "boolean",
                        default = true,
                        description = "Enable rate limiting based threat detection"
                    }
                },
                {
                    rate_limit_window_seconds = {
                        type = "number",
                        default = 60,
                        between = { 1, 3600 },
                        description = "Time window for rate limiting analysis in seconds"
                    }
                },
                {
                    rate_limit_threshold = {
                        type = "number",
                        default = 150,  -- SAFE: Higher threshold for legitimate traffic
                        between = { 1, 10000 },
                        description = "Request count threshold for rate limiting detection. RECOMMENDED: Start with 150, adjust based on traffic patterns"
                    }
                },
                {
                    enable_ip_reputation = {
                        type = "boolean",
                        default = true,
                        description = "Enable IP reputation based threat detection"
                    }
                },
                {
                    ip_whitelist = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "List of whitelisted IP addresses or CIDR blocks"
                    }
                },
                {
                    ip_blacklist = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "List of blacklisted IP addresses or CIDR blocks"
                    }
                },
                {
                    enable_payload_analysis = {
                        type = "boolean",
                        default = true,
                        description = "Enable request payload analysis for injection attacks"
                    }
                },
                {
                    max_payload_size = {
                        type = "number",
                        default = 262144,  -- SAFE: 256KB, smaller for performance
                        between = { 1024, 10485760 },  -- 1KB to 10MB
                        description = "Maximum payload size to analyze in bytes. RECOMMENDED: Start with 256KB for performance, increase if needed"
                    }
                },
                {
                    suspicious_patterns = {
                        type = "array",
                        elements = { type = "string" },
                        default = {
                            "union.*select",
                            "drop.*table",
                            "<script",
                            "javascript:",
                            "eval\\(",
                            "system\\(",
                            "\\.\\./.*etc/passwd"
                        },
                        description = "Regex patterns for detecting malicious payloads"
                    }
                },
                
                -- AI Gateway Integration - DISABLED BY DEFAULT FOR SAFETY
                {
                    ai_gateway_enabled = {
                        type = "boolean",
                        default = false,  -- SAFE: Disabled to prevent external dependencies
                        description = "Enable Kong AI Gateway integration for advanced threat analysis. CAUTION: Requires external service configuration and API costs"
                    }
                },
                {
                    ai_gateway_model = {
                        type = "string",
                        default = "gpt-4o-mini",  -- SAFE: Cost-effective model choice
                        description = "AI model to use for threat analysis via AI Gateway. RECOMMENDED: Use gpt-4o-mini for cost control"
                    }
                },
                {
                    ai_gateway_endpoint = {
                        type = "string",
                        description = "Kong AI Gateway endpoint URL"
                    }
                },
                {
                    ai_analysis_threshold = {
                        type = "number",
                        default = 6.0,  -- SAFE: Higher threshold for expensive AI analysis
                        between = { 1.0, 10.0 },
                        description = "Threat level threshold for triggering AI analysis. RECOMMENDED: Use 6.0+ to control AI costs"
                    }
                },
                {
                    ai_timeout_ms = {
                        type = "number",
                        default = 3000,  -- SAFE: Shorter timeout to prevent delays
                        between = { 100, 30000 },
                        description = "Timeout for AI Gateway requests in milliseconds. RECOMMENDED: Use 3000ms to prevent request delays"
                    }
                },
                
                -- Response Configuration - CONSERVATIVE DEFAULTS
                {
                    enable_auto_blocking = {
                        type = "boolean",
                        default = false,  -- SAFE: Disabled until explicitly enabled
                        description = "Enable automatic IP/Consumer blocking for high threat levels. CAUTION: Enable only after thorough testing"
                    }
                },
                {
                    block_duration_seconds = {
                        type = "number",
                        default = 1800,  -- SAFE: 30 minutes, shorter than default
                        between = { 60, 86400 },  -- 1 minute to 24 hours
                        description = "Duration to block threats in seconds. RECOMMENDED: Start with 1800s (30 min), increase if needed"
                    }
                },
                {
                    enable_rate_limiting_response = {
                        type = "boolean",
                        default = true,
                        description = "Enable dynamic rate limiting as threat response"
                    }
                },
                {
                    enable_config_rollback = {
                        type = "boolean",
                        default = false,  -- SAFE: High-risk feature disabled
                        description = "Enable automatic Kong config rollback for critical threats. DANGER: Can disrupt service, use with extreme caution"
                    }
                },
                {
                    rollback_threshold = {
                        type = "number",
                        default = 9.5,  -- SAFE: Very high threshold if enabled
                        between = { 5.0, 10.0 },
                        description = "Threat level threshold for triggering config rollback. RECOMMENDED: Use 9.5+ for critical-only rollbacks"
                    }
                },
                {
                    sanitize_error_responses = {
                        type = "boolean",
                        default = true,
                        description = "Sanitize error response headers to prevent information leakage"
                    }
                },
                
                -- Response Analysis
                {
                    analyze_response_body = {
                        type = "boolean",
                        default = false,
                        description = "Enable response body analysis for attack success detection"
                    }
                },
                {
                    max_response_body_size = {
                        type = "number",
                        default = 10240,  -- 10KB
                        between = { 1024, 1048576 },
                        description = "Maximum response body size to analyze in bytes"
                    }
                },
                
                -- Learning and Adaptation
                {
                    enable_learning = {
                        type = "boolean",
                        default = true,
                        description = "Enable machine learning for adaptive threat detection"
                    }
                },
                {
                    learning_sample_rate = {
                        type = "number",
                        default = 0.1,
                        between = { 0.01, 1.0 },
                        description = "Sampling rate for learning data collection (0.0-1.0)"
                    }
                },
                {
                    feedback_endpoint = {
                        type = "string",
                        description = "HTTP endpoint for receiving operator feedback on threat decisions"
                    }
                },
                
                -- Notification Configuration
                {
                    enable_notifications = {
                        type = "boolean",
                        default = true,
                        description = "Enable threat notifications"
                    }
                },
                {
                    slack_webhook_url = {
                        type = "string",
                        description = "Slack webhook URL for threat notifications"
                    }
                },
                {
                    email_smtp_server = {
                        type = "string",
                        description = "SMTP server for email notifications"
                    }
                },
                {
                    email_from = {
                        type = "string",
                        description = "From email address for notifications"
                    }
                },
                {
                    email_to = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "List of email addresses for threat notifications"
                    }
                },
                {
                    webhook_urls = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "List of webhook URLs for threat notifications"
                    }
                },
                {
                    notification_threshold = {
                        type = "number",
                        default = 7.0,  -- SAFE: Higher threshold to reduce notification noise
                        between = { 1.0, 10.0 },
                        description = "Threat level threshold for sending notifications. RECOMMENDED: Use 7.0+ to prevent notification spam"
                    }
                },
                
                -- Logging Configuration
                {
                    external_logging_enabled = {
                        type = "boolean",
                        default = false,
                        description = "Enable external logging system integration"
                    }
                },
                {
                    log_endpoint = {
                        type = "string",
                        description = "External logging endpoint URL"
                    }
                },
                {
                    log_level = {
                        type = "string",
                        default = "info",
                        one_of = { "debug", "info", "warn", "error" },
                        description = "Logging level for threat detection events"
                    }
                },
                
                -- Admin API Configuration - DISABLED BY DEFAULT FOR SECURITY
                {
                    admin_api_enabled = {
                        type = "boolean",
                        default = false,  -- SAFE: High-risk feature disabled by default
                        description = "Enable Kong Admin API integration for automated responses. CAUTION: High-security risk, enable only if necessary"
                    }
                },
                {
                    admin_api_key = {
                        type = "string",
                        description = "Kong Admin API key for automated configuration changes"
                    }
                },
                {
                    admin_api_timeout_ms = {
                        type = "number",
                        default = 3000,  -- SAFE: Shorter timeout to prevent delays
                        between = { 100, 30000 },
                        description = "Timeout for Admin API requests in milliseconds. RECOMMENDED: Use 3000ms to prevent blocking"
                    }
                },
                
                -- Status and Monitoring
                {
                    status_endpoint_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable status endpoint for monitoring plugin health"
                    }
                },
                {
                    status_endpoint_path = {
                        type = "string",
                        default = "/_guard_ai/status",
                        description = "Path for the status endpoint"
                    }
                },
                {
                    metrics_endpoint_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable metrics endpoint for performance monitoring"
                    }
                },
                {
                    metrics_endpoint_path = {
                        type = "string",
                        default = "/_guard_ai/metrics",
                        description = "Path for the metrics endpoint"
                    }
                }
            }
        }}
    }
}