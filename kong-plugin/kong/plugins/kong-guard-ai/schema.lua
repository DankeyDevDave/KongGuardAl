local typedefs = require "kong.db.schema.typedefs"

return {
    name = "kong-guard-ai",
    fields = {
        {
            protocols = typedefs.protocols_http
        },
        {
            config = {
                type = "record",
                fields = {
                    -- Threat Detection Thresholds
                    {
                        block_threshold = {
                            type = "number",
                            default = 0.8,
                            between = {0, 1},
                            required = true,
                            description = "Threat score threshold for blocking (0-1)"
                        }
                    },
                    {
                        rate_limit_threshold = {
                            type = "number",
                            default = 0.6,
                            between = {0, 1},
                            required = true,
                            description = "Threat score threshold for rate limiting (0-1)"
                        }
                    },
                    {
                        ddos_rpm_threshold = {
                            type = "integer",
                            default = 100,
                            required = true,
                            description = "Requests per minute threshold for DDoS detection"
                        }
                    },
                    
                    -- Operating Mode
                    {
                        dry_run = {
                            type = "boolean",
                            default = false,
                            required = true,
                            description = "Enable dry-run mode (log only, no enforcement)"
                        }
                    },
                    
                    -- ML Configuration
                    {
                        enable_ml = {
                            type = "boolean",
                            default = true,
                            required = true,
                            description = "Enable machine learning-based detection"
                        }
                    },
                    {
                        anomaly_threshold = {
                            type = "number",
                            default = 0.7,
                            between = {0, 1},
                            description = "Anomaly score threshold for ML detection"
                        }
                    },
                    
                    -- AI Gateway Integration (optional)
                    {
                        enable_ai_gateway = {
                            type = "boolean",
                            default = false,
                            description = "Enable Kong AI Gateway integration for advanced analysis"
                        }
                    },
                    {
                        ai_model = {
                            type = "string",
                            default = "claude-3-haiku",
                            one_of = {
                                "claude-3-haiku",
                                "claude-3-sonnet",
                                "gpt-4",
                                "gpt-3.5-turbo",
                                "llama2"
                            },
                            description = "AI model to use for analysis"
                        }
                    },
                    {
                        ai_temperature = {
                            type = "number",
                            default = 0.1,
                            between = {0, 1},
                            description = "AI model temperature for consistent decisions"
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
                                one_of = {"webhook", "slack", "email", "log"}
                            },
                            description = "Notification channels to use"
                        }
                    },
                    
                    -- Learning & Feedback
                    {
                        enable_learning = {
                            type = "boolean",
                            default = true,
                            description = "Enable continuous learning from feedback"
                        }
                    },
                    {
                        learning_rate = {
                            type = "number",
                            default = 0.001,
                            between = {0, 1},
                            description = "Learning rate for threshold adaptation"
                        }
                    },
                    {
                        feedback_endpoint = {
                            type = "string",
                            default = "/kong-guard-ai/feedback",
                            description = "Endpoint for operator feedback"
                        }
                    },
                    
                    -- Response Actions
                    {
                        auto_block_duration = {
                            type = "integer",
                            default = 3600,
                            description = "Duration to block threats (seconds)"
                        }
                    },
                    {
                        rate_limit_duration = {
                            type = "integer",
                            default = 300,
                            description = "Duration for rate limiting (seconds)"
                        }
                    },
                    {
                        rate_limit_requests = {
                            type = "integer",
                            default = 10,
                            description = "Number of requests allowed during rate limit period"
                        }
                    },
                    
                    -- Admin API Integration
                    {
                        enable_admin_api = {
                            type = "boolean",
                            default = true,
                            description = "Enable Admin API integration for dynamic configuration"
                        }
                    },
                    {
                        admin_api_url = {
                            type = "string",
                            default = "http://localhost:8001",
                            description = "Kong Admin API URL"
                        }
                    },
                    
                    -- Logging & Monitoring
                    {
                        log_level = {
                            type = "string",
                            default = "info",
                            one_of = {"debug", "info", "warn", "error", "critical"},
                            description = "General logging level"
                        }
                    },
                    {
                        log_threats = {
                            type = "boolean",
                            default = true,
                            description = "Log detected threats"
                        }
                    },
                    {
                        log_requests = {
                            type = "boolean",
                            default = false,
                            description = "Log all requests (verbose)"
                        }
                    },
                    {
                        log_decisions = {
                            type = "boolean",
                            default = true,
                            description = "Log blocking/rate-limiting decisions"
                        }
                    },
                    {
                        metrics_enabled = {
                            type = "boolean",
                            default = true,
                            description = "Enable metrics collection"
                        }
                    },
                    
                    -- Pattern Detection Rules
                    {
                        sql_injection_patterns = {
                            type = "array",
                            default = {
                                "union%s+select",
                                "drop%s+table",
                                "insert%s+into",
                                "select%s+from"
                            },
                            elements = {type = "string"},
                            description = "SQL injection detection patterns"
                        }
                    },
                    {
                        xss_patterns = {
                            type = "array",
                            default = {
                                "<script",
                                "javascript:",
                                "onerror=",
                                "onload="
                            },
                            elements = {type = "string"},
                            description = "XSS detection patterns"
                        }
                    },
                    
                    -- Geographic & IP Configuration
                    {
                        blocked_countries = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of blocked country codes"
                        }
                    },
                    {
                        blocked_ips = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of blocked IP addresses"
                        }
                    },
                    {
                        whitelist_ips = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of whitelisted IP addresses"
                        }
                    }
                }
            }
        }
    }
}