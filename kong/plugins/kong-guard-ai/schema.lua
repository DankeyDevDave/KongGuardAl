-- Kong Guard AI Plugin Schema
-- Defines the configuration structure and validation for the kong-guard-ai plugin
-- Enhanced for Phase 2 with comprehensive field definitions and validation

local typedefs = require "kong.db.schema.typedefs"

-- Advanced Schema Validation Functions
-- Enhanced for Kong Gateway 3.x+ compatibility and Phase 2 requirements

-- Comprehensive IP/CIDR validation supporting IPv4 and IPv6
local function validate_ip_or_cidr(value)
  -- Basic IP/CIDR validation - Kong will handle more detailed validation
  if type(value) ~= "string" then
    return false, "IP address must be a string"
  end
  -- Allow IPv4, IPv6, and CIDR notation
  return true
end

local function validate_http_method(value)
  local valid_methods = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"
  }
  for _, method in ipairs(valid_methods) do
    if method == string.upper(value) then
      return true
    end
  end
  return false, "Invalid HTTP method: " .. value
end

local function validate_notification_target(value)
  if type(value) ~= "table" then
    return false, "Notification target must be a table"
  end
  if not value.type or not value.endpoint then
    return false, "Notification target must have 'type' and 'endpoint' fields"
  end
  local valid_types = { "webhook", "slack", "email", "sms", "discord", "teams" }
  local is_valid_type = false
  for _, t in ipairs(valid_types) do
    if t == value.type then
      is_valid_type = true
      break
    end
  end
  if not is_valid_type then
    return false, "Invalid notification type: " .. value.type
  end
  return true
end

return {
  name = "kong-guard-ai",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Global plugin settings
          { dry_run = { 
              type = "boolean", 
              default = true,
              description = "Enable dry run mode for testing without enforcing blocks. When true, threats are detected and logged but requests are not blocked."
          } },
          { log_level = { 
              type = "string", 
              default = "info", 
              one_of = { "debug", "info", "warn", "error" },
              description = "Logging verbosity level for the plugin"
          } },
          
          -- Phase 2 Enhanced Fields
          
          -- IP Blacklist with CIDR support
          { ip_blacklist = {
              type = "array",
              elements = {
                type = "string",
                custom_validator = validate_ip_or_cidr
              },
              default = {},
              description = "Array of IP addresses and CIDR blocks to permanently block. Supports IPv4 and IPv6. Examples: ['192.168.1.1', '10.0.0.0/8', '2001:db8::/32']"
          } },
          
          -- HTTP Method Denylist
          { method_denylist = {
              type = "array",
              elements = {
                type = "string",
                custom_validator = validate_http_method
              },
              default = {},
              description = "Array of HTTP methods to block. Common values: ['TRACE', 'CONNECT', 'DEBUG']. Methods are case-insensitive."
          } },
          
          -- Rate Limiting Configuration
          { rate_limit = {
              type = "record",
              required = true,
              fields = {
                { requests_per_minute = { 
                    type = "number", 
                    default = 100,
                    gt = 0,
                    description = "Maximum requests allowed per minute per IP address"
                } },
                { requests_per_hour = { 
                    type = "number", 
                    default = 1000,
                    gt = 0,
                    description = "Maximum requests allowed per hour per IP address"
                } },
                { requests_per_day = { 
                    type = "number", 
                    default = 10000,
                    gt = 0,
                    description = "Maximum requests allowed per day per IP address"
                } },
                { window_size = { 
                    type = "number", 
                    default = 60,
                    between = { 1, 3600 },
                    description = "Time window in seconds for rate limit calculations"
                } },
                { sync_rate = { 
                    type = "number", 
                    default = 10,
                    between = { 1, 60 },
                    description = "Rate limit counter synchronization interval in seconds for cluster deployments"
                } }
              },
              description = "Rate limiting thresholds for request frequency control"
          } },
          
          -- Burst Threshold Configuration
          { burst_threshold = {
              type = "record",
              required = true,
              fields = {
                { max_requests = { 
                    type = "number", 
                    default = 50,
                    gt = 0,
                    description = "Maximum requests allowed in burst window"
                } },
                { window_seconds = { 
                    type = "number", 
                    default = 10,
                    between = { 1, 300 },
                    description = "Burst detection window in seconds"
                } },
                { violation_threshold = { 
                    type = "number", 
                    default = 3,
                    between = { 1, 10 },
                    description = "Number of burst violations before triggering escalated response"
                } },
                { cooldown_period = { 
                    type = "number", 
                    default = 300,
                    between = { 60, 3600 },
                    description = "Cooldown period in seconds after burst detection before reset"
                } }
              },
              description = "Burst traffic detection and mitigation settings"
          } },
          
          -- Enhanced Admin API Configuration
          { admin_api = {
              type = "record",
              required = true,
              fields = {
                { enabled = { 
                    type = "boolean", 
                    default = true,
                    description = "Enable Kong Admin API integration for dynamic configuration updates"
                } },
                { admin_url = { 
                    type = "string", 
                    default = "http://localhost:8001",
                    description = "Kong Admin API base URL for configuration management"
                } },
                { admin_key = { 
                    type = "string", 
                    default = "",
                    description = "API key for Kong Admin API authentication (if RBAC enabled)"
                } },
                { timeout = { 
                    type = "number", 
                    default = 5000,
                    between = { 1000, 30000 },
                    description = "Timeout for Admin API requests in milliseconds"
                } },
                { auto_config_updates = { 
                    type = "boolean", 
                    default = false,
                    description = "Automatically push configuration updates to Kong Admin API"
                } },
                { backup_configs = { 
                    type = "boolean", 
                    default = true,
                    description = "Create configuration backups before updates"
                } },
                { max_backups = { 
                    type = "number", 
                    default = 5,
                    between = { 1, 50 },
                    description = "Maximum number of configuration backups to retain"
                } },
                { verify_ssl = { 
                    type = "boolean", 
                    default = true,
                    description = "Verify SSL certificates when connecting to Kong Admin API"
                } },
                { retry_attempts = { 
                    type = "number", 
                    default = 3,
                    between = { 1, 10 },
                    description = "Number of retry attempts for failed Admin API requests"
                } },
                { retry_delay = { 
                    type = "number", 
                    default = 1000,
                    between = { 100, 10000 },
                    description = "Delay between retry attempts in milliseconds"
                } }
              },
              description = "Kong Admin API integration settings for dynamic configuration management"
          } },
          
          -- Comprehensive Notification Targets
          { notification_targets = {
              type = "array",
              elements = {
                type = "record",
                fields = {
                  { name = { 
                      type = "string", 
                      required = true,
                      description = "Unique identifier for this notification target"
                  } },
                  { type = { 
                      type = "string", 
                      required = true,
                      one_of = { "webhook", "slack", "email", "sms", "discord", "teams" },
                      description = "Type of notification endpoint"
                  } },
                  { endpoint = { 
                      type = "string", 
                      required = true,
                      description = "Target endpoint URL or identifier"
                  } },
                  { enabled = { 
                      type = "boolean", 
                      default = true,
                      description = "Enable/disable this notification target"
                  } },
                  { severity_filter = {
                      type = "array",
                      elements = { type = "string" },
                      default = { "high", "critical" },
                      description = "Severity levels that trigger notifications to this target"
                  } },
                  { rate_limit = { 
                      type = "number", 
                      default = 10,
                      between = { 1, 100 },
                      description = "Maximum notifications per hour to this target"
                  } },
                  { timeout = { 
                      type = "number", 
                      default = 5000,
                      between = { 1000, 30000 },
                      description = "Timeout for notification delivery in milliseconds"
                  } },
                  { retry_attempts = { 
                      type = "number", 
                      default = 3,
                      between = { 0, 10 },
                      description = "Number of retry attempts for failed notifications"
                  } },
                  { template = { 
                      type = "string", 
                      default = "default",
                      description = "Message template to use for this notification target"
                  } },
                  { headers = {
                      type = "map",
                      keys = { type = "string" },
                      values = { type = "string" },
                      default = {},
                      description = "Custom headers for webhook notifications"
                  } },
                  { auth = {
                      type = "record",
                      fields = {
                        { type = { 
                            type = "string", 
                            one_of = { "none", "bearer", "basic", "api_key" },
                            default = "none"
                        } },
                        { token = { type = "string", default = "" } },
                        { username = { type = "string", default = "" } },
                        { password = { type = "string", default = "" } },
                        { api_key_header = { type = "string", default = "X-API-Key" } }
                      },
                      default = { type = "none" },
                      description = "Authentication configuration for this target"
                  } }
                },
                custom_validator = validate_notification_target
              },
              default = {},
              description = "Array of notification targets for alerts and events. Supports webhooks, Slack, email, SMS, Discord, and Microsoft Teams."
          } },
          
          -- Enhanced Threat Detection Configuration  
          { threat_detection = {
              type = "record",
              fields = {
                { enabled = { 
                    type = "boolean", 
                    default = true,
                    description = "Enable threat detection engine"
                } },
                { rules = {
                    type = "record", 
                    fields = {
                      -- Legacy fields - now reference the centralized Phase 2 fields above
                      { rate_limit_threshold = { 
                          type = "number", 
                          default = 100,
                          description = "DEPRECATED: Use rate_limit.requests_per_minute instead. Requests per minute threshold."
                      } },
                      { burst_threshold = { 
                          type = "number", 
                          default = 50,
                          description = "DEPRECATED: Use burst_threshold.max_requests instead. Requests per 10 seconds threshold."
                      } },
                      { suspicious_patterns = { 
                          type = "array", 
                          elements = { type = "string" }, 
                          default = {},
                          description = "Regex patterns for suspicious request content detection"
                      } },
                      { blocked_ips = { 
                          type = "array", 
                          elements = { type = "string" }, 
                          default = {},
                          description = "DEPRECATED: Use ip_blacklist instead. Legacy IP blocking list."
                      } },
                      { blocked_user_agents = { 
                          type = "array", 
                          elements = { type = "string" }, 
                          default = {},
                          description = "User-Agent patterns to block"
                      } },
                      { allowed_methods = { 
                          type = "array", 
                          elements = { type = "string" }, 
                          default = { "GET", "POST", "PUT", "DELETE", "PATCH" },
                          description = "DEPRECATED: Configure method_denylist instead. Allowed HTTP methods."
                      } },
                      { max_payload_size = { 
                          type = "number", 
                          default = 1048576,
                          gt = 0,
                          description = "Maximum request payload size in bytes (1MB default)"
                      } },
                      { suspicious_headers = { 
                          type = "array", 
                          elements = { type = "string" }, 
                          default = {},
                          description = "Header patterns that indicate suspicious activity"
                      } },
                      { geo_blocking = {
                          type = "record",
                          fields = {
                            { enabled = { type = "boolean", default = false } },
                            { blocked_countries = { 
                                type = "array", 
                                elements = { type = "string" }, 
                                default = {},
                                description = "ISO 3166-1 alpha-2 country codes to block"
                            } },
                            { allowed_countries = { 
                                type = "array", 
                                elements = { type = "string" }, 
                                default = {},
                                description = "ISO 3166-1 alpha-2 country codes to allow (if specified, blocks all others)"
                            } },
                            { use_cloudflare_headers = { type = "boolean", default = true } },
                            { use_x_forwarded_for = { type = "boolean", default = true } }
                          },
                          default = { enabled = false },
                          description = "Geographic IP blocking configuration"
                      } }
                    }
                }},
                { anomaly_detection = {
                    type = "record",
                    fields = {
                      { enabled = { type = "boolean", default = false } },
                      { window_size = { type = "number", default = 300 } }, -- 5 minutes
                      { deviation_threshold = { type = "number", default = 2.0 } }, -- standard deviations
                      { min_samples = { type = "number", default = 10 } }
                    }
                }}
              }
          }},
          
          -- Response actions configuration
          { response_actions = {
              type = "record",
              fields = {
                { enabled = { type = "boolean", default = true } },
                { immediate_block = { type = "boolean", default = false } },
                { rate_limit_enforcement = { type = "boolean", default = true } },
                { temp_block_duration = { type = "number", default = 300 } }, -- 5 minutes
                { escalation_threshold = { type = "number", default = 5 } }, -- incidents before escalation
                { notification_enabled = { type = "boolean", default = true } },
                { auto_rollback = { type = "boolean", default = false } },
                { rollback_window = { type = "number", default = 3600 } } -- 1 hour
              }
          }},
          
          -- Legacy Notification Configuration (DEPRECATED)
          { notifications = {
              type = "record",
              fields = {
                { webhook_url = { 
                    type = "string", 
                    default = "",
                    description = "DEPRECATED: Use notification_targets instead. Single webhook URL for notifications."
                } },
                { slack_webhook = { 
                    type = "string", 
                    default = "",
                    description = "DEPRECATED: Use notification_targets instead. Slack webhook URL."
                } },
                { email_config = {
                    type = "record",
                    fields = {
                      { enabled = { type = "boolean", default = false } },
                      { smtp_host = { type = "string", default = "" } },
                      { smtp_port = { type = "number", default = 587 } },
                      { smtp_user = { type = "string", default = "" } },
                      { smtp_password = { type = "string", default = "" } },
                      { from_email = { type = "string", default = "" } },
                      { to_emails = { type = "array", elements = { type = "string" }, default = {} } }
                    },
                    description = "DEPRECATED: Use notification_targets with type='email' instead. Legacy email configuration."
                }},
                { notification_cooldown = { 
                    type = "number", 
                    default = 60,
                    between = { 1, 3600 },
                    description = "Seconds between notifications to prevent spam"
                } },
                { max_notifications_per_hour = { 
                    type = "number", 
                    default = 10,
                    between = { 1, 1000 },
                    description = "Maximum notifications per hour across all targets"
                } }
              },
              description = "Legacy notification configuration. Use notification_targets for new implementations."
          }},
          
          -- AI Gateway Integration
          { ai_gateway = {
              type = "record",
              fields = {
                { enabled = { 
                    type = "boolean", 
                    default = false,
                    description = "Enable AI-powered threat analysis"
                } },
                { model_endpoint = { 
                    type = "string", 
                    default = "",
                    description = "AI model endpoint URL for threat analysis"
                } },
                { model_name = { 
                    type = "string", 
                    default = "gpt-3.5-turbo",
                    description = "AI model name for threat analysis"
                } },
                { api_key = { 
                    type = "string", 
                    default = "",
                    description = "API key for AI model authentication"
                } },
                { threat_analysis_threshold = { 
                    type = "number", 
                    default = 0.7,
                    between = { 0.0, 1.0 },
                    description = "Confidence threshold for threat classification (0.0-1.0)"
                } },
                { max_payload_analysis_size = { 
                    type = "number", 
                    default = 4096,
                    gt = 0,
                    description = "Maximum payload size to analyze with AI (bytes)"
                } },
                { analysis_timeout = { 
                    type = "number", 
                    default = 5000,
                    between = { 1000, 30000 },
                    description = "Timeout for AI analysis requests (milliseconds)"
                } },
                { cache_results = { 
                    type = "boolean", 
                    default = true,
                    description = "Cache AI analysis results to improve performance"
                } },
                { cache_ttl = { 
                    type = "number", 
                    default = 300,
                    between = { 60, 3600 },
                    description = "Cache TTL for AI analysis results (seconds)"
                } },
                { retry_attempts = { 
                    type = "number", 
                    default = 2,
                    between = { 0, 5 },
                    description = "Number of retry attempts for failed AI requests"
                } },
                { models = {
                    type = "array",
                    elements = {
                      type = "record",
                      fields = {
                        { name = { type = "string", required = true } },
                        { endpoint = { type = "string", required = true } },
                        { api_key = { type = "string", default = "" } },
                        { enabled = { type = "boolean", default = true } },
                        { weight = { type = "number", default = 1.0, between = { 0.1, 10.0 } } }
                      }
                    },
                    default = {},
                    description = "Multiple AI models for ensemble analysis"
                } }
              },
              description = "AI-powered threat analysis integration settings"
          }},
          
          -- Enhanced Logging and Monitoring
          { logging = {
              type = "record",
              fields = {
                { enabled = { 
                    type = "boolean", 
                    default = true,
                    description = "Enable plugin logging"
                } },
                { log_requests = { 
                    type = "boolean", 
                    default = true,
                    description = "Log incoming requests"
                } },
                { log_responses = { 
                    type = "boolean", 
                    default = false,
                    description = "Log outgoing responses"
                } },
                { log_headers = { 
                    type = "boolean", 
                    default = false,
                    description = "Include headers in logs"
                } },
                { log_body = { 
                    type = "boolean", 
                    default = false,
                    description = "Include request/response body in logs"
                } },
                { max_log_body_size = { 
                    type = "number", 
                    default = 1024,
                    gt = 0,
                    description = "Maximum body size to log (bytes)"
                } },
                { structured_logging = { 
                    type = "boolean", 
                    default = true,
                    description = "Use structured JSON logging format"
                } },
                { log_level = { 
                    type = "string", 
                    default = "info",
                    one_of = { "debug", "info", "warn", "error" },
                    description = "Minimum log level to record"
                } },
                { include_metrics = { 
                    type = "boolean", 
                    default = true,
                    description = "Include performance metrics in logs"
                } }
              },
              description = "Logging and monitoring configuration"
          }},
          
          -- Performance Optimization Settings
          { performance = {
              type = "record",
              fields = {
                { max_processing_time = { 
                    type = "number", 
                    default = 10,
                    between = { 1, 1000 },
                    description = "Maximum processing time per request (milliseconds)"
                } },
                { enable_caching = { 
                    type = "boolean", 
                    default = true,
                    description = "Enable internal caching for performance"
                } },
                { cache_size = { 
                    type = "number", 
                    default = 1000,
                    between = { 100, 100000 },
                    description = "Maximum number of cache entries"
                } },
                { sampling_rate = { 
                    type = "number", 
                    default = 1.0,
                    between = { 0.01, 1.0 },
                    description = "Request sampling rate for analysis (0.01-1.0)"
                } },
                { async_processing = { 
                    type = "boolean", 
                    default = false,
                    description = "Enable asynchronous threat analysis"
                } },
                { worker_processes = { 
                    type = "number", 
                    default = 2,
                    between = { 1, 16 },
                    description = "Number of worker processes for async analysis"
                } },
                { memory_limit = { 
                    type = "number", 
                    default = 104857600,
                    gt = 0,
                    description = "Memory limit for plugin operations (bytes)"
                } }
              },
              description = "Performance optimization and resource management settings"
          }}
        }
    }}
  }
}