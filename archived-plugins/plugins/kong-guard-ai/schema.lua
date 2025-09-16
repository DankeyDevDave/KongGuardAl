-- Kong Guard AI Plugin Schema
-- Defines configuration options for the plugin

local typedefs = require "kong.db.schema.typedefs"

return {
  name = "kong-guard-ai",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          -- Basic configuration
          {
            dry_run = {
              type = "boolean",
              default = false,
              description = "Enable dry run mode (log only, no enforcement)"
            }
          },
          {
            log_level = {
              type = "string",
              default = "info",
              one_of = { "debug", "info", "warn", "error" },
              description = "Plugin logging level"
            }
          },

          -- Rate limiting configuration
          {
            rate_limit_enabled = {
              type = "boolean",
              default = true,
              description = "Enable rate limiting threat detection"
            }
          },
          {
            rate_limit_threshold = {
              type = "number",
              default = 100,
              description = "Requests per minute threshold"
            }
          },

          -- IP blocking configuration
          {
            ip_blocking_enabled = {
              type = "boolean",
              default = true,
              description = "Enable IP-based blocking"
            }
          },
          {
            blocked_ips = {
              type = "array",
              elements = { type = "string" },
              default = {},
              description = "List of blocked IP addresses"
            }
          },

          -- AI detection configuration
          {
            ai_detection_enabled = {
              type = "boolean",
              default = false,
              description = "Enable AI-powered threat detection"
            }
          },
          {
            ai_api_endpoint = {
              type = "string",
              description = "AI service endpoint for threat analysis"
            }
          },
          {
            ai_api_key = {
              type = "string",
              description = "API key for AI service"
            }
          },

          -- Notification configuration
          {
            notifications_enabled = {
              type = "boolean",
              default = true,
              description = "Enable threat notifications"
            }
          },
          {
            slack_webhook_url = {
              type = "string",
              description = "Slack webhook URL for notifications"
            }
          },
          {
            email_notifications = {
              type = "boolean",
              default = false,
              description = "Enable email notifications"
            }
          },
          {
            email_to = {
              type = "string",
              description = "Email address for notifications"
            }
          },

          -- Redis configuration for state management
          {
            redis_host = {
              type = "string",
              default = "redis",
              description = "Redis host for state storage"
            }
          },
          {
            redis_port = {
              type = "number",
              default = 6379,
              description = "Redis port"
            }
          },
          {
            redis_timeout = {
              type = "number",
              default = 1000,
              description = "Redis timeout in milliseconds"
            }
          },

          -- Advanced threat detection settings
          {
            payload_analysis_enabled = {
              type = "boolean",
              default = true,
              description = "Enable payload analysis for injection attacks"
            }
          },
          {
            max_payload_size = {
              type = "number",
              default = 1048576, -- 1MB
              description = "Maximum payload size to analyze"
            }
          },
          {
            suspicious_patterns = {
              type = "array",
              elements = { type = "string" },
              default = {
                "SELECT.*FROM",
                "<script",
                "javascript:",
                "onload=",
                "onerror=",
                "eval\\(",
                "union.*select",
                "drop.*table",
                "insert.*into",
                "update.*set",
                "delete.*from"
              },
              description = "Regex patterns for suspicious content detection"
            }
          },

          -- Response configuration
          {
            auto_block_duration = {
              type = "number",
              default = 3600, -- 1 hour
              description = "Auto-block duration in seconds"
            }
          },
          {
            custom_error_response = {
              type = "string",
              default = "Request blocked by security policy",
              description = "Custom error message for blocked requests"
            }
          }
        }
      }
    }
  }
}
