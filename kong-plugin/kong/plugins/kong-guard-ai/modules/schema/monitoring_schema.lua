-- Monitoring and Notification Configuration Schema
-- Extracted from schema.lua for better modularity and maintainability

local _M = {}

--- Get monitoring and notification configuration schema fields
-- @return table configuration schema fields for monitoring
function _M.get_fields()
    return {
        -- Notification Configuration
        {
            enable_notifications = {
                type = "boolean",
                default = true,
                description = "Enable threat notifications"
            }
        },
        {
            notification_url = {
                type = "string",
                description = "Webhook URL for notifications (Slack, Email gateway, etc.)"
            }
        },
        {
            notification_channels = {
                type = "array",
                default = {"webhook"},
                elements = {
                    type = "string",
                    one_of = {"webhook", "slack", "email", "log", "prometheus"}
                },
                description = "Notification channels to use"
            }
        },
        {
            notification_severity_threshold = {
                type = "string",
                default = "medium",
                one_of = {"low", "medium", "high", "critical"},
                description = "Minimum severity level for notifications"
            }
        },
        -- Logging & Monitoring
        {
            log_level = {
                type = "string",
                default = "info",
                one_of = {"debug", "info", "warn", "error"},
                description = "Logging level for the plugin"
            }
        },
        {
            enable_audit_log = {
                type = "boolean",
                default = true,
                description = "Enable detailed audit logging"
            }
        },
        {
            audit_log_format = {
                type = "string",
                default = "json",
                one_of = {"json", "text", "structured"},
                description = "Format for audit logs"
            }
        },
        {
            enable_metrics = {
                type = "boolean",
                default = true,
                description = "Enable Prometheus metrics"
            }
        },
        {
            metrics_port = {
                type = "integer",
                default = 9090,
                between = {1024, 65535},
                description = "Port for Prometheus metrics endpoint"
            }
        },
        {
            metrics_path = {
                type = "string",
                default = "/metrics",
                description = "Path for Prometheus metrics endpoint"
            }
        },
        -- Performance Monitoring
        {
            enable_performance_monitoring = {
                type = "boolean",
                default = true,
                description = "Enable performance monitoring and statistics"
            }
        },
        {
            performance_sample_rate = {
                type = "number",
                default = 0.1,
                between = {0, 1},
                description = "Sample rate for performance monitoring (0-1)"
            }
        },
        {
            memory_threshold_mb = {
                type = "integer",
                default = 256,
                between = {64, 2048},
                description = "Memory usage threshold for alerts (MB)"
            }
        },
        {
            latency_threshold_ms = {
                type = "integer",
                default = 100,
                between = {10, 1000},
                description = "Request latency threshold for alerts (ms)"
            }
        },
        -- Health Monitoring
        {
            enable_health_checks = {
                type = "boolean",
                default = true,
                description = "Enable health monitoring"
            }
        },
        {
            health_check_interval = {
                type = "integer",
                default = 30,
                between = {10, 300},
                description = "Health check interval in seconds"
            }
        },
        {
            health_check_timeout = {
                type = "integer",
                default = 5,
                between = {1, 30},
                description = "Health check timeout in seconds"
            }
        },
        -- Dashboard Integration
        {
            enable_dashboard = {
                type = "boolean",
                default = false,
                description = "Enable web dashboard"
            }
        },
        {
            dashboard_port = {
                type = "integer",
                default = 8080,
                between = {1024, 65535},
                description = "Port for web dashboard"
            }
        },
        {
            dashboard_auth_token = {
                type = "string",
                description = "Authentication token for dashboard access"
            }
        }
    }
end

--- Get monitoring defaults
-- @return table default configuration values
function _M.get_defaults()
    return {
        enable_notifications = true,
        notification_channels = {"webhook"},
        notification_severity_threshold = "medium",
        log_level = "info",
        enable_audit_log = true,
        audit_log_format = "json",
        enable_metrics = true,
        metrics_port = 9090,
        metrics_path = "/metrics",
        enable_performance_monitoring = true,
        performance_sample_rate = 0.1,
        memory_threshold_mb = 256,
        latency_threshold_ms = 100,
        enable_health_checks = true,
        health_check_interval = 30,
        health_check_timeout = 5,
        enable_dashboard = false,
        dashboard_port = 8080
    }
end

--- Get notification channel configurations
-- @return table notification channel settings
function _M.get_notification_channels()
    return {
        webhook = {
            required_fields = {"notification_url"},
            format = "json",
            timeout = 5000
        },
        slack = {
            required_fields = {"slack_webhook_url"},
            format = "slack",
            timeout = 5000
        },
        email = {
            required_fields = {"smtp_server", "smtp_port", "email_recipients"},
            format = "email",
            timeout = 10000
        },
        log = {
            required_fields = {},
            format = "structured",
            timeout = 100
        },
        prometheus = {
            required_fields = {},
            format = "metrics",
            timeout = 1000
        }
    }
end

--- Validate monitoring configuration
-- @param config table configuration to validate
-- @return boolean true if valid
-- @return string error message if invalid
function _M.validate_config(config)
    if not config then
        return false, "Configuration is required"
    end
    
    -- Validate notification channels
    if config.notification_channels then
        local valid_channels = {"webhook", "slack", "email", "log", "prometheus"}
        for _, channel in ipairs(config.notification_channels) do
            local valid = false
            for _, valid_channel in ipairs(valid_channels) do
                if channel == valid_channel then
                    valid = true
                    break
                end
            end
            if not valid then
                return false, "Invalid notification channel: " .. channel
            end
        end
    end
    
    -- Validate webhook URL if webhook channel is enabled
    if config.notification_channels then
        for _, channel in ipairs(config.notification_channels) do
            if channel == "webhook" and not config.notification_url then
                return false, "notification_url is required when webhook channel is enabled"
            end
        end
    end
    
    -- Validate port numbers
    if config.metrics_port and (config.metrics_port < 1024 or config.metrics_port > 65535) then
        return false, "metrics_port must be between 1024 and 65535"
    end
    
    if config.dashboard_port and (config.dashboard_port < 1024 or config.dashboard_port > 65535) then
        return false, "dashboard_port must be between 1024 and 65535"
    end
    
    -- Validate performance monitoring settings
    if config.performance_sample_rate and (config.performance_sample_rate < 0 or config.performance_sample_rate > 1) then
        return false, "performance_sample_rate must be between 0 and 1"
    end
    
    -- Validate dashboard auth if dashboard is enabled
    if config.enable_dashboard and not config.dashboard_auth_token then
        return false, "dashboard_auth_token is required when dashboard is enabled"
    end
    
    return true
end

--- Get metric definitions for Prometheus
-- @return table metric definitions
function _M.get_metrics_definitions()
    return {
        {
            name = "kong_guard_ai_requests_total",
            type = "counter",
            help = "Total number of requests processed",
            labels = {"status", "threat_type"}
        },
        {
            name = "kong_guard_ai_threats_detected_total", 
            type = "counter",
            help = "Total number of threats detected",
            labels = {"threat_type", "severity", "action"}
        },
        {
            name = "kong_guard_ai_processing_duration_seconds",
            type = "histogram",
            help = "Request processing duration in seconds",
            buckets = {0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5}
        },
        {
            name = "kong_guard_ai_ai_service_calls_total",
            type = "counter", 
            help = "Total number of AI service calls",
            labels = {"model", "status"}
        },
        {
            name = "kong_guard_ai_memory_usage_bytes",
            type = "gauge",
            help = "Current memory usage in bytes"
        }
    }
end

return _M