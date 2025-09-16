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
                        description = "List of blacklisted IP addresses or CIDR blocks (supports IPv4 CIDR notation like 203.0.113.0/24)"
                    }
                },
                {
                    enable_ip_blacklist = {
                        type = "boolean",
                        default = true,
                        description = "Enable IP blacklist enforcement with O(1) lookup performance"
                    }
                },
                {
                    ip_blacklist_ttl_seconds = {
                        type = "number",
                        default = 3600,
                        between = { 60, 86400 },
                        description = "Default TTL for dynamically added blacklist entries (1 hour to 24 hours)"
                    }
                },
                {
                    trust_proxy_headers = {
                        type = "boolean",
                        default = true,
                        description = "Trust proxy headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP) for real client IP detection"
                    }
                },
                {
                    ip_blacklist_max_size = {
                        type = "number",
                        default = 10000,
                        between = { 100, 100000 },
                        description = "Maximum number of IPs in the blacklist to prevent memory exhaustion"
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
                        one_of = { "debug", "info", "warn", "error", "critical" },
                        description = "Logging level for threat detection events"
                    }
                },

                -- PHASE 3: Structured Logging Configuration
                {
                    structured_logging_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable structured JSON logging with metadata enrichment"
                    }
                },
                {
                    async_logging = {
                        type = "boolean",
                        default = true,
                        description = "Enable asynchronous log processing to reduce request latency impact"
                    }
                },
                {
                    log_sampling_rate = {
                        type = "number",
                        default = 1.0,
                        between = { 0.01, 1.0 },
                        description = "Sampling rate for structured logs (0.01-1.0). Use lower values for high traffic"
                    }
                },
                {
                    include_geolocation = {
                        type = "boolean",
                        default = false,
                        description = "Include geolocation data in structured logs (requires external GeoIP service)"
                    }
                },
                {
                    include_user_agent_parsing = {
                        type = "boolean",
                        default = true,
                        description = "Parse and include user agent details in structured logs"
                    }
                },
                {
                    max_log_entry_size = {
                        type = "number",
                        default = 32768,  -- 32KB
                        between = { 1024, 131072 },  -- 1KB to 128KB
                        description = "Maximum size of individual log entries in bytes"
                    }
                },
                {
                    log_correlation_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable request correlation IDs and session tracking"
                    }
                },
                {
                    external_log_timeout_ms = {
                        type = "number",
                        default = 1000,
                        between = { 100, 10000 },
                        description = "Timeout for external logging endpoint requests in milliseconds"
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

                -- Advanced Rate Limiting Configuration (PHASE 5)
                {
                    enable_advanced_rate_limiting = {
                        type = "boolean",
                        default = true,
                        description = "Enable advanced sliding window rate limiting with burst detection"
                    }
                },
                {
                    rate_limit_per_minute = {
                        type = "number",
                        default = 60,
                        between = { 1, 10000 },
                        description = "Requests per minute limit per IP address"
                    }
                },
                {
                    rate_limit_per_five_minutes = {
                        type = "number",
                        default = 300,
                        between = { 1, 50000 },
                        description = "Requests per 5 minutes limit per IP address"
                    }
                },
                {
                    rate_limit_per_hour = {
                        type = "number",
                        default = 3600,
                        between = { 1, 500000 },
                        description = "Requests per hour limit per IP address"
                    }
                },
                {
                    rate_limit_per_day = {
                        type = "number",
                        default = 86400,
                        between = { 1, 10000000 },
                        description = "Requests per day limit per IP address"
                    }
                },
                {
                    enable_burst_detection = {
                        type = "boolean",
                        default = true,
                        description = "Enable burst traffic detection and progressive penalties"
                    }
                },
                {
                    burst_threshold_light = {
                        type = "number",
                        default = 200,
                        between = { 100, 1000 },
                        description = "Percentage above baseline for light burst detection (200% = 2x normal)"
                    }
                },
                {
                    burst_threshold_medium = {
                        type = "number",
                        default = 500,
                        between = { 200, 2000 },
                        description = "Percentage above baseline for medium burst detection"
                    }
                },
                {
                    burst_threshold_severe = {
                        type = "number",
                        default = 1000,
                        between = { 500, 5000 },
                        description = "Percentage above baseline for severe burst detection"
                    }
                },
                {
                    progressive_penalty_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable progressive penalties (warn → throttle → block)"
                    }
                },
                {
                    penalty_warning_duration = {
                        type = "number",
                        default = 600,
                        between = { 60, 3600 },
                        description = "Duration in seconds for warning penalty"
                    }
                },
                {
                    penalty_throttle_duration = {
                        type = "number",
                        default = 1800,
                        between = { 300, 7200 },
                        description = "Duration in seconds for throttle penalty"
                    }
                },
                {
                    penalty_block_duration = {
                        type = "number",
                        default = 3600,
                        between = { 600, 86400 },
                        description = "Duration in seconds for block penalty"
                    }
                },
                {
                    rate_limit_bypass_whitelist = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "List of IP addresses exempt from rate limiting"
                    }
                },
                {
                    dynamic_rate_adjustment = {
                        type = "boolean",
                        default = true,
                        description = "Enable dynamic rate limit adjustment based on threat level"
                    }
                },

                -- Real-Time Analytics Dashboard Configuration (PHASE 6)
                {
                    analytics_dashboard_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable real-time analytics dashboard with threat intelligence"
                    }
                },
                {
                    analytics_endpoint_path = {
                        type = "string",
                        default = "/_guard_ai/analytics",
                        description = "Base path for analytics dashboard API endpoints"
                    }
                },
                {
                    enable_threat_intelligence = {
                        type = "boolean",
                        default = true,
                        description = "Enable threat intelligence feeds integration"
                    }
                },
                {
                    threat_intel_feeds = {
                        type = "array",
                        elements = { type = "string" },
                        default = {"alienvault_otx", "abuse_ch_malware", "spamhaus_drop"},
                        description = "List of threat intelligence feeds to integrate"
                    }
                },
                {
                    enable_geographic_analysis = {
                        type = "boolean",
                        default = true,
                        description = "Enable geographical attack pattern visualization"
                    }
                },
                {
                    geoip_service_url = {
                        type = "string",
                        description = "URL for GeoIP service API (e.g., MaxMind GeoIP2)"
                    }
                },
                {
                    enable_predictive_analytics = {
                        type = "boolean",
                        default = true,
                        description = "Enable predictive threat modeling based on historical data"
                    }
                },
                {
                    prediction_confidence_threshold = {
                        type = "number",
                        default = 0.7,
                        between = { 0.1, 1.0 },
                        description = "Minimum confidence level for threat predictions (0-1)"
                    }
                },
                {
                    enable_anomaly_detection = {
                        type = "boolean",
                        default = true,
                        description = "Enable automated anomaly detection in threat patterns"
                    }
                },
                {
                    anomaly_threshold_multiplier = {
                        type = "number",
                        default = 3.0,
                        between = { 1.5, 10.0 },
                        description = "Multiplier above baseline to trigger anomaly detection"
                    }
                },
                {
                    enable_correlation_analysis = {
                        type = "boolean",
                        default = true,
                        description = "Enable attack pattern correlation and multi-stage attack detection"
                    }
                },
                {
                    correlation_window_seconds = {
                        type = "number",
                        default = 300,
                        between = { 60, 3600 },
                        description = "Time window for correlating related attack patterns"
                    }
                },
                {
                    enable_automated_threat_hunting = {
                        type = "boolean",
                        default = false,
                        description = "Enable automated threat hunting capabilities (advanced feature)"
                    }
                },
                {
                    threat_hunting_interval = {
                        type = "number",
                        default = 3600,
                        between = { 300, 86400 },
                        description = "Interval in seconds for automated threat hunting scans"
                    }
                },
                {
                    enable_compliance_reporting = {
                        type = "boolean",
                        default = true,
                        description = "Enable compliance reporting (PCI DSS, SOX, GDPR)"
                    }
                },
                {
                    compliance_frameworks = {
                        type = "array",
                        elements = { type = "string" },
                        default = {"pci_dss", "gdpr"},
                        description = "List of compliance frameworks to report on"
                    }
                },
                {
                    executive_dashboard_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable executive dashboard with security KPIs"
                    }
                },
                {
                    analytics_data_retention_days = {
                        type = "number",
                        default = 30,
                        between = { 7, 365 },
                        description = "Number of days to retain analytics data"
                    }
                },
                {
                    external_threat_intel_api_key = {
                        type = "string",
                        description = "API key for external threat intelligence platforms"
                    }
                },
                {
                    threat_intel_update_interval = {
                        type = "number",
                        default = 3600,
                        between = { 300, 86400 },
                        description = "Interval in seconds for updating threat intelligence feeds"
                    }
                },

                -- PHASE 4: Path Regex Filtering Configuration
                {
                    enable_path_filtering = {
                        type = "boolean",
                        default = true,
                        description = "Enable regex-based path filtering for attack pattern detection"
                    }
                },
                {
                    path_filter_block_threshold = {
                        type = "number",
                        default = 7.0,
                        between = { 1.0, 10.0 },
                        description = "Threat level threshold for blocking requests based on path patterns"
                    }
                },
                {
                    path_filter_suspicious_threshold = {
                        type = "number",
                        default = 4.0,
                        between = { 1.0, 10.0 },
                        description = "Threat level threshold for marking requests as suspicious"
                    }
                },
                {
                    custom_path_patterns = {
                        type = "array",
                        elements = {
                            type = "record",
                            fields = {
                                { pattern = { type = "string", required = true } },
                                { priority = { type = "number", default = 2, between = { 1, 4 } } },
                                { description = { type = "string", default = "Custom pattern" } }
                            }
                        },
                        default = {},
                        description = "Custom regex patterns for path filtering with priority (1=critical, 4=low)"
                    }
                },
                {
                    path_whitelist = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "List of path patterns to whitelist (exact string matching)"
                    }
                },
                {
                    path_filter_skip_methods = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "HTTP methods to skip path filtering for (e.g., OPTIONS, HEAD)"
                    }
                },
                {
                    path_filter_case_sensitive = {
                        type = "boolean",
                        default = false,
                        description = "Enable case-sensitive path pattern matching"
                    }
                },
                {
                    path_filter_max_pattern_matches = {
                        type = "number",
                        default = 10,
                        between = { 1, 50 },
                        description = "Maximum number of pattern matches to process per request"
                    }
                },
                {
                    path_filter_analytics_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable path filtering analytics and false positive tracking"
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
                },

                -- PHASE 4: HTTP Method Filtering Configuration
                {
                    enable_method_filtering = {
                        type = "boolean",
                        default = true,
                        description = "Enable HTTP method denylist filtering to block dangerous methods like TRACE, CONNECT, DEBUG"
                    }
                },
                {
                    block_extended_methods = {
                        type = "boolean",
                        default = false,
                        description = "Block extended dangerous methods including WebDAV methods (LOCK, UNLOCK, MKCOL, etc.)"
                    }
                },
                {
                    custom_denied_methods = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "Custom HTTP methods to deny in addition to default dangerous methods"
                    }
                },
                {
                    custom_allowed_methods = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "Custom HTTP methods to explicitly allow (useful for APIs with non-standard methods)"
                    }
                },
                {
                    method_bypass_routes = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "Route patterns that bypass method filtering (e.g., ['/health', '/debug/*'] for internal endpoints)"
                    }
                },
                {
                    method_bypass_services = {
                        type = "array",
                        elements = { type = "string" },
                        default = {},
                        description = "Service IDs that bypass method filtering (useful for internal services requiring special methods)"
                    }
                },
                {
                    method_threat_threshold = {
                        type = "number",
                        default = 7.0,
                        between = { 1.0, 10.0 },
                        description = "Threat level threshold for method violations. Lower values = more sensitive blocking"
                    }
                },
                {
                    method_rate_limiting = {
                        type = "boolean",
                        default = false,
                        description = "Enable method-specific rate limiting for detected violations"
                    }
                },
                {
                    method_analytics_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable detailed analytics tracking for HTTP method violations and patterns"
                    }
                },

                -- PHASE 4: Incident Management Configuration
                {
                    incident_analytics_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable incident analytics dashboard and reporting"
                    }
                },
                {
                    incident_alerting_enabled = {
                        type = "boolean",
                        default = true,
                        description = "Enable real-time incident alerting and notifications"
                    }
                },
                {
                    incident_retention_days = {
                        type = "number",
                        default = 30,
                        between = { 1, 365 },
                        description = "Number of days to retain incident records before archival"
                    }
                },
                {
                    incident_body_snippet_size = {
                        type = "number",
                        default = 500,
                        between = { 100, 2048 },
                        description = "Maximum size of request body snippet to store in incident records"
                    }
                },

                -- Incident Alerting Configuration
                {
                    alert_notification_channels = {
                        type = "array",
                        elements = {
                            type = "string",
                            one_of = { "slack", "email", "webhook", "sms", "pagerduty", "teams" }
                        },
                        default = { "webhook" },
                        description = "Notification channels for incident alerts"
                    }
                },
                {
                    escalation_notification_channels = {
                        type = "array",
                        elements = {
                            type = "string",
                            one_of = { "slack", "email", "webhook", "sms", "pagerduty", "teams" }
                        },
                        description = "Notification channels for escalated alerts (defaults to alert_notification_channels)"
                    }
                },
                {
                    escalation_delay_seconds = {
                        type = "number",
                        default = 300,
                        between = { 60, 3600 },
                        description = "Delay in seconds before escalating unacknowledged critical alerts"
                    }
                },
                {
                    max_escalation_levels = {
                        type = "number",
                        default = 3,
                        between = { 1, 10 },
                        description = "Maximum number of escalation levels before stopping"
                    }
                },
                {
                    notification_retry_delay = {
                        type = "number",
                        default = 60,
                        between = { 30, 600 },
                        description = "Delay in seconds before retrying failed notifications"
                    }
                },
                {
                    notification_max_retries = {
                        type = "number",
                        default = 3,
                        between = { 1, 10 },
                        description = "Maximum number of retry attempts for failed notifications"
                    }
                },
                {
                    alert_retention_days = {
                        type = "number",
                        default = 7,
                        between = { 1, 30 },
                        description = "Number of days to retain alert records"
                    }
                },

                -- Webhook Notification Configuration
                {
                    webhook_notification_url = {
                        type = "string",
                        description = "Webhook URL for incident notifications"
                    }
                },
                {
                    webhook_auth_header = {
                        type = "string",
                        description = "Authorization header name for webhook authentication"
                    }
                },
                {
                    webhook_auth_token = {
                        type = "string",
                        description = "Authorization token for webhook authentication"
                    }
                },

                -- Teams Integration
                {
                    teams_webhook_url = {
                        type = "string",
                        description = "Microsoft Teams webhook URL for incident notifications"
                    }
                },

                -- SIEM Integration Configuration
                {
                    enable_siem_export = {
                        type = "boolean",
                        default = false,
                        description = "Enable automatic export of incidents to SIEM systems"
                    }
                },
                {
                    siem_export_formats = {
                        type = "array",
                        elements = {
                            type = "string",
                            one_of = { "json", "cef", "stix" }
                        },
                        default = { "json" },
                        description = "Export formats for SIEM integration"
                    }
                },
                {
                    siem_export_endpoint = {
                        type = "string",
                        description = "HTTP endpoint for sending incident data to SIEM systems"
                    }
                },
                {
                    siem_batch_size = {
                        type = "number",
                        default = 100,
                        between = { 1, 1000 },
                        description = "Number of incidents to batch before sending to SIEM"
                    }
                },
                {
                    siem_export_interval = {
                        type = "number",
                        default = 300,
                        between = { 60, 3600 },
                        description = "Interval in seconds for batched SIEM exports"
                    }
                },

                -- Threat Intelligence Enrichment
                {
                    enable_threat_enrichment = {
                        type = "boolean",
                        default = false,
                        description = "Enable enrichment of incidents with external threat intelligence"
                    }
                },
                {
                    threat_intel_providers = {
                        type = "array",
                        elements = {
                            type = "string",
                            one_of = { "virustotal", "abuseipdb", "threatfox", "custom" }
                        },
                        default = {},
                        description = "Threat intelligence providers for incident enrichment"
                    }
                },
                {
                    threat_intel_api_keys = {
                        type = "record",
                        fields = {
                            { virustotal = { type = "string" } },
                            { abuseipdb = { type = "string" } },
                            { threatfox = { type = "string" } },
                            { custom = { type = "string" } }
                        },
                        description = "API keys for threat intelligence providers"
                    }
                },
                {
                    threat_intel_cache_ttl = {
                        type = "number",
                        default = 3600,
                        between = { 300, 86400 },
                        description = "TTL in seconds for cached threat intelligence data"
                    }
                }
            }
        }}
    }
}
