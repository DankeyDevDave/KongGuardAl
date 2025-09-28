-- Threat Detection Configuration Schema
-- Extracted from schema.lua for better modularity and maintainability

local _M = {}

--- Get threat detection configuration schema fields
-- @return table configuration schema fields for threat detection
function _M.get_fields()
    return {
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
            enable_ml_detection = {
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
        -- Pattern Detection Rules
        {
            enable_sql_injection_detection = {
                type = "boolean",
                default = true,
                description = "Enable SQL injection pattern detection"
            }
        },
        {
            enable_xss_detection = {
                type = "boolean",
                default = true,
                description = "Enable XSS pattern detection"
            }
        },
        {
            enable_path_traversal_detection = {
                type = "boolean",
                default = true,
                description = "Enable path traversal detection"
            }
        },
        {
            enable_command_injection_detection = {
                type = "boolean",
                default = true,
                description = "Enable command injection detection"
            }
        },
        {
            custom_threat_patterns = {
                type = "array",
                elements = {type = "string"},
                description = "Custom threat detection patterns (regex)"
            }
        },
        -- Response Actions
        {
            action_block = {
                type = "boolean",
                default = true,
                description = "Block requests when threshold is exceeded"
            }
        },
        {
            action_rate_limit = {
                type = "boolean",
                default = true,
                description = "Apply rate limiting when threshold is exceeded"
            }
        },
        {
            action_log = {
                type = "boolean",
                default = true,
                description = "Log threat detections"
            }
        },
        {
            action_notify = {
                type = "boolean",
                default = true,
                description = "Send notifications for threat detections"
            }
        }
    }
end

--- Get threat detection defaults
-- @return table default configuration values
function _M.get_defaults()
    return {
        block_threshold = 0.8,
        rate_limit_threshold = 0.6,
        ddos_rpm_threshold = 100,
        dry_run = false,
        enable_ml_detection = true,
        anomaly_threshold = 0.7,
        enable_sql_injection_detection = true,
        enable_xss_detection = true,
        enable_path_traversal_detection = true,
        enable_command_injection_detection = true,
        action_block = true,
        action_rate_limit = true,
        action_log = true,
        action_notify = true
    }
end

--- Validate threat detection configuration
-- @param config table configuration to validate
-- @return boolean true if valid
-- @return string error message if invalid
function _M.validate_config(config)
    if not config then
        return false, "Configuration is required"
    end
    
    -- Validate thresholds
    if config.block_threshold and config.rate_limit_threshold then
        if config.block_threshold <= config.rate_limit_threshold then
            return false, "block_threshold must be greater than rate_limit_threshold"
        end
    end
    
    -- Validate anomaly threshold
    if config.anomaly_threshold and (config.anomaly_threshold < 0 or config.anomaly_threshold > 1) then
        return false, "anomaly_threshold must be between 0 and 1"
    end
    
    -- Validate DDoS threshold
    if config.ddos_rpm_threshold and config.ddos_rpm_threshold < 1 then
        return false, "ddos_rpm_threshold must be at least 1"
    end
    
    return true
end

return _M