-- Kong Guard AI Configuration Parser
-- Handles configuration parsing, validation, and hot-reload capabilities
-- Compatible with Kong Gateway 3.x+ and Admin API workflows

local typedefs = require "kong.db.schema.typedefs"
local schema_def = require "kong.plugins.kong-guard-ai.schema"
local cjson = require "cjson"

local config_parser = {}

-- Cache for parsed configurations to improve performance
local config_cache = {}
local cache_ttl = 300 -- 5 minutes default cache TTL

-- Default configuration values
local DEFAULT_CONFIG = {
    -- Core Settings
    dry_run_mode = false,
    threat_threshold = 7.0,
    max_processing_time_ms = 10,

    -- Detection Settings
    enable_rate_limiting_detection = true,
    rate_limit_window_seconds = 60,
    rate_limit_threshold = 100,
    enable_ip_reputation = true,
    enable_payload_analysis = true,
    max_payload_size = 1048576,

    -- Response Settings
    enable_auto_blocking = true,
    block_duration_seconds = 3600,
    enable_rate_limiting_response = true,
    enable_config_rollback = false,
    rollback_threshold = 9.0,
    sanitize_error_responses = true,

    -- AI Gateway Settings
    ai_gateway_enabled = false,
    ai_gateway_model = "gpt-4",
    ai_analysis_threshold = 5.0,
    ai_timeout_ms = 5000,

    -- Notification Settings
    enable_notifications = true,
    notification_threshold = 6.0,

    -- Logging Settings
    external_logging_enabled = false,
    log_level = "info",

    -- Admin API Settings
    admin_api_enabled = true,
    admin_api_timeout_ms = 5000,

    -- Status/Monitoring Settings
    status_endpoint_enabled = true,
    status_endpoint_path = "/_guard_ai/status",
    metrics_endpoint_enabled = true,
    metrics_endpoint_path = "/_guard_ai/metrics",

    -- Learning Settings
    enable_learning = true,
    learning_sample_rate = 0.1,

    -- Response Analysis
    analyze_response_body = false,
    max_response_body_size = 10240,

    -- Default patterns for threat detection
    suspicious_patterns = {
        "union.*select",
        "drop.*table",
        "<script",
        "javascript:",
        "eval\\(",
        "system\\(",
        "\\.\\./.*etc/passwd"
    },

    -- Default IP lists
    ip_whitelist = {},
    ip_blacklist = {},

    -- Default email list
    email_to = {},

    -- Default webhook URLs
    webhook_urls = {}
}

-- Configuration validation rules
local VALIDATION_RULES = {
    threat_threshold = { min = 1.0, max = 10.0 },
    max_processing_time_ms = { min = 1, max = 100 },
    rate_limit_window_seconds = { min = 1, max = 3600 },
    rate_limit_threshold = { min = 1, max = 10000 },
    max_payload_size = { min = 1024, max = 10485760 },
    block_duration_seconds = { min = 60, max = 86400 },
    ai_analysis_threshold = { min = 1.0, max = 10.0 },
    ai_timeout_ms = { min = 100, max = 30000 },
    notification_threshold = { min = 1.0, max = 10.0 },
    admin_api_timeout_ms = { min = 100, max = 30000 },
    rollback_threshold = { min = 5.0, max = 10.0 },
    learning_sample_rate = { min = 0.01, max = 1.0 },
    max_response_body_size = { min = 1024, max = 1048576 }
}

-- Required fields validation
local REQUIRED_FIELDS = {
    conditional = {
        -- If AI Gateway is enabled, these fields are required
        ai_gateway_enabled = {
            required_when_true = { "ai_gateway_endpoint" }
        },
        -- If external logging is enabled, endpoint is required
        external_logging_enabled = {
            required_when_true = { "log_endpoint" }
        },
        -- If email notifications enabled, SMTP config required
        enable_notifications = {
            required_when_true = { "email_smtp_server", "email_from" }
        }
    }
}

-- Utility function to log configuration events
local function log_config_event(level, message, details)
    kong.log[level]("[kong-guard-ai:config_parser] " .. message ..
                    (details and (" | Details: " .. cjson.encode(details)) or ""))
end

-- Validate numeric value against range constraints
local function validate_numeric_range(key, value, rules)
    if not rules then return true, nil end

    if rules.min and value < rules.min then
        return false, string.format("Value %s for %s is below minimum %s", value, key, rules.min)
    end

    if rules.max and value > rules.max then
        return false, string.format("Value %s for %s exceeds maximum %s", value, key, rules.max)
    end

    return true, nil
end

-- Validate string patterns (for regex patterns)
local function validate_pattern(pattern)
    local ok, err = pcall(function()
        string.match("test", pattern)
    end)

    if not ok then
        return false, "Invalid regex pattern: " .. tostring(err)
    end

    return true, nil
end

-- Validate IP address format (basic validation)
local function validate_ip_address(ip)
    -- Basic IPv4 validation
    if string.match(ip, "^%d+%.%d+%.%d+%.%d+$") then
        for octet in string.gmatch(ip, "%d+") do
            local num = tonumber(octet)
            if not num or num < 0 or num > 255 then
                return false, "Invalid IPv4 address: " .. ip
            end
        end
        return true, nil
    end

    -- Basic CIDR notation support
    if string.match(ip, "^%d+%.%d+%.%d+%.%d+/%d+$") then
        local ip_part, cidr = string.match(ip, "^(.+)/(%d+)$")
        local valid_ip, err = validate_ip_address(ip_part)
        if not valid_ip then
            return false, err
        end

        local cidr_num = tonumber(cidr)
        if not cidr_num or cidr_num < 0 or cidr_num > 32 then
            return false, "Invalid CIDR notation: " .. ip
        end

        return true, nil
    end

    return false, "Invalid IP address format: " .. ip
end

-- Validate email address format (basic validation)
local function validate_email(email)
    if not string.match(email, "^[%w%._%+%-]+@[%w%.%-]+%.%w+$") then
        return false, "Invalid email format: " .. email
    end
    return true, nil
end

-- Validate URL format (basic validation)
local function validate_url(url)
    if not string.match(url, "^https?://[%w%.%-]+") then
        return false, "Invalid URL format: " .. url
    end
    return true, nil
end

-- Deep merge configuration with defaults
local function merge_with_defaults(config, defaults)
    local result = {}

    -- Copy defaults first
    for key, value in pairs(defaults) do
        if type(value) == "table" then
            result[key] = merge_with_defaults({}, value)
        else
            result[key] = value
        end
    end

    -- Override with provided config
    for key, value in pairs(config or {}) do
        if type(value) == "table" and type(result[key]) == "table" then
            result[key] = merge_with_defaults(value, result[key])
        else
            result[key] = value
        end
    end

    return result
end

-- Validate individual configuration fields
function config_parser.validate_field(key, value, field_type)
    if not value then
        return true, nil -- Allow nil values, defaults will be applied
    end

    -- Type validation
    if field_type == "boolean" and type(value) ~= "boolean" then
        return false, string.format("Field %s must be boolean, got %s", key, type(value))
    end

    if field_type == "number" and type(value) ~= "number" then
        return false, string.format("Field %s must be number, got %s", key, type(value))
    end

    if field_type == "string" and type(value) ~= "string" then
        return false, string.format("Field %s must be string, got %s", key, type(value))
    end

    if field_type == "array" and type(value) ~= "table" then
        return false, string.format("Field %s must be array, got %s", key, type(value))
    end

    -- Range validation for numbers
    if type(value) == "number" and VALIDATION_RULES[key] then
        return validate_numeric_range(key, value, VALIDATION_RULES[key])
    end

    -- Special field validations
    if key == "log_level" then
        local valid_levels = { debug = true, info = true, warn = true, error = true }
        if not valid_levels[value] then
            return false, "Invalid log_level: " .. tostring(value)
        end
    end

    if key == "suspicious_patterns" and type(value) == "table" then
        for i, pattern in ipairs(value) do
            local valid, err = validate_pattern(pattern)
            if not valid then
                return false, string.format("Invalid pattern at index %d: %s", i, err)
            end
        end
    end

    if (key == "ip_whitelist" or key == "ip_blacklist") and type(value) == "table" then
        for i, ip in ipairs(value) do
            local valid, err = validate_ip_address(ip)
            if not valid then
                return false, string.format("Invalid IP at index %d: %s", i, err)
            end
        end
    end

    if key == "email_to" and type(value) == "table" then
        for i, email in ipairs(value) do
            local valid, err = validate_email(email)
            if not valid then
                return false, string.format("Invalid email at index %d: %s", i, err)
            end
        end
    end

    if (key == "webhook_urls" or key == "ai_gateway_endpoint" or key == "log_endpoint") then
        if type(value) == "string" then
            local valid, err = validate_url(value)
            if not valid then
                return false, err
            end
        elseif type(value) == "table" then
            for i, url in ipairs(value) do
                local valid, err = validate_url(url)
                if not valid then
                    return false, string.format("Invalid URL at index %d: %s", i, err)
                end
            end
        end
    end

    return true, nil
end

-- Validate conditional requirements
function config_parser.validate_conditional_requirements(config)
    for field, conditions in pairs(REQUIRED_FIELDS.conditional) do
        local field_value = config[field]

        if conditions.required_when_true and field_value == true then
            for _, required_field in ipairs(conditions.required_when_true) do
                if not config[required_field] or config[required_field] == "" then
                    return false, string.format("Field %s is required when %s is enabled",
                                               required_field, field)
                end
            end
        end
    end

    return true, nil
end

-- Main configuration validation function
function config_parser.validate_config(config)
    local errors = {}

    log_config_event("debug", "Starting configuration validation", config)

    -- Validate each field in the configuration
    for key, value in pairs(config) do
        local field_type = "unknown"

        -- Determine expected type from defaults
        local default_value = DEFAULT_CONFIG[key]
        if default_value ~= nil then
            field_type = type(default_value)
        end

        local valid, err = config_parser.validate_field(key, value, field_type)
        if not valid then
            table.insert(errors, err)
        end
    end

    -- Validate conditional requirements
    local valid_conditional, err_conditional = config_parser.validate_conditional_requirements(config)
    if not valid_conditional then
        table.insert(errors, err_conditional)
    end

    if #errors > 0 then
        log_config_event("error", "Configuration validation failed", { errors = errors })
        return false, errors
    end

    log_config_event("info", "Configuration validation successful")
    return true, nil
end

-- Parse and validate incoming configuration
function config_parser.parse_config(raw_config)
    local config, errors

    -- Handle different input formats
    if type(raw_config) == "string" then
        -- Try to parse as JSON
        local ok, parsed = pcall(cjson.decode, raw_config)
        if not ok then
            log_config_event("error", "Failed to parse JSON configuration", { error = parsed })
            return nil, { "Invalid JSON configuration: " .. tostring(parsed) }
        end
        config = parsed
    elseif type(raw_config) == "table" then
        config = raw_config
    else
        log_config_event("error", "Invalid configuration type", { type = type(raw_config) })
        return nil, { "Configuration must be table or JSON string, got " .. type(raw_config) }
    end

    -- Merge with defaults
    local merged_config = merge_with_defaults(config, DEFAULT_CONFIG)

    -- Validate the merged configuration
    local valid, validation_errors = config_parser.validate_config(merged_config)
    if not valid then
        return nil, validation_errors
    end

    log_config_event("info", "Configuration parsed and validated successfully")
    return merged_config, nil
end

-- Load configuration with caching
function config_parser.load_config(config_source, cache_key)
    cache_key = cache_key or "default"

    -- Check cache first
    local cached = config_cache[cache_key]
    if cached and (ngx.time() - cached.timestamp) < cache_ttl then
        log_config_event("debug", "Using cached configuration", { cache_key = cache_key })
        return cached.config, nil
    end

    -- Parse new configuration
    local config, errors = config_parser.parse_config(config_source)
    if not config then
        log_config_event("error", "Failed to load configuration", { errors = errors })
        return nil, errors
    end

    -- Cache the successful configuration
    config_cache[cache_key] = {
        config = config,
        timestamp = ngx.time()
    }

    log_config_event("info", "Configuration loaded and cached", { cache_key = cache_key })
    return config, nil
end

-- Hot-reload configuration
function config_parser.reload_config(new_config, cache_key)
    cache_key = cache_key or "default"

    log_config_event("info", "Attempting configuration hot-reload", { cache_key = cache_key })

    -- Parse and validate new configuration
    local config, errors = config_parser.parse_config(new_config)
    if not config then
        log_config_event("error", "Hot-reload failed due to validation errors", { errors = errors })
        return false, errors
    end

    -- Update cache with new configuration
    config_cache[cache_key] = {
        config = config,
        timestamp = ngx.time()
    }

    log_config_event("info", "Configuration hot-reload successful", { cache_key = cache_key })
    return true, nil
end

-- Clear configuration cache
function config_parser.clear_cache(cache_key)
    if cache_key then
        config_cache[cache_key] = nil
        log_config_event("debug", "Cleared configuration cache", { cache_key = cache_key })
    else
        config_cache = {}
        log_config_event("debug", "Cleared all configuration caches")
    end
end

-- Get current cached configuration
function config_parser.get_cached_config(cache_key)
    cache_key = cache_key or "default"
    local cached = config_cache[cache_key]

    if cached and (ngx.time() - cached.timestamp) < cache_ttl then
        return cached.config
    end

    return nil
end

-- Set cache TTL
function config_parser.set_cache_ttl(ttl)
    cache_ttl = ttl or 300
    log_config_event("debug", "Cache TTL updated", { ttl = cache_ttl })
end

-- Export configuration for debugging/auditing
function config_parser.export_config(config, format)
    format = format or "json"

    if format == "json" then
        local ok, json_str = pcall(cjson.encode, config)
        if ok then
            return json_str
        else
            log_config_event("error", "Failed to export configuration as JSON", { error = json_str })
            return nil, "Failed to encode as JSON: " .. tostring(json_str)
        end
    end

    return nil, "Unsupported export format: " .. tostring(format)
end

-- Get default configuration
function config_parser.get_defaults()
    return DEFAULT_CONFIG
end

-- Get validation rules
function config_parser.get_validation_rules()
    return VALIDATION_RULES
end

-- Configuration diff utility
function config_parser.diff_configs(old_config, new_config)
    local changes = {}

    -- Check for modified or new keys
    for key, new_value in pairs(new_config) do
        local old_value = old_config[key]
        if old_value ~= new_value then
            changes[key] = {
                old = old_value,
                new = new_value,
                action = old_value == nil and "added" or "modified"
            }
        end
    end

    -- Check for removed keys
    for key, old_value in pairs(old_config) do
        if new_config[key] == nil then
            changes[key] = {
                old = old_value,
                new = nil,
                action = "removed"
            }
        end
    end

    return changes
end

return config_parser
