-- Kong Guard AI Configuration Loader
-- Handles configuration loading during Kong plugin lifecycle
-- Integrates with Kong's Admin API and Konnect workflows

local config_parser = require "kong.plugins.kong-guard-ai.config_parser"
local cjson = require "cjson"

local config_loader = {}

-- Configuration state management
local current_config = nil
local config_version = 0
local last_reload_time = 0

-- Kong plugin lifecycle integration
local kong_log = kong.log
local kong_cache = kong.cache

-- Configuration loading strategies
local LOADING_STRATEGIES = {
    PLUGIN_CONFIG = "plugin_config",      -- Standard Kong plugin configuration
    ADMIN_API = "admin_api",              -- Kong Admin API source
    KONNECT = "konnect",                  -- Kong Konnect integration
    FILE_WATCH = "file_watch",            -- File-based configuration watching
    ENVIRONMENT = "environment"           -- Environment variable based
}

-- Default loading strategy
local default_strategy = LOADING_STRATEGIES.PLUGIN_CONFIG

-- Utility function for logging
local function log_loader_event(level, message, details)
    kong_log[level]("[kong-guard-ai:config_loader] " .. message .. 
                    (details and (" | Details: " .. cjson.encode(details)) or ""))
end

-- Load configuration from Kong plugin config (standard approach)
function config_loader.load_from_plugin_config(plugin_config)
    log_loader_event("debug", "Loading configuration from plugin config")
    
    if not plugin_config then
        log_loader_event("error", "Plugin configuration is nil")
        return nil, { "Plugin configuration cannot be nil" }
    end
    
    -- Parse and validate configuration
    local config, errors = config_parser.parse_config(plugin_config)
    if not config then
        log_loader_event("error", "Failed to parse plugin configuration", { errors = errors })
        return nil, errors
    end
    
    -- Update current configuration state
    current_config = config
    config_version = config_version + 1
    last_reload_time = ngx.time()
    
    log_loader_event("info", "Configuration loaded from plugin config", {
        version = config_version,
        timestamp = last_reload_time
    })
    
    return config, nil
end

-- Load configuration from Kong Admin API
function config_loader.load_from_admin_api(admin_url, admin_key, plugin_id)
    log_loader_event("debug", "Loading configuration from Admin API", {
        admin_url = admin_url,
        plugin_id = plugin_id
    })
    
    -- Construct Admin API URL for plugin configuration
    local api_url = string.format("%s/plugins/%s", admin_url or "http://localhost:8001", plugin_id)
    
    -- Prepare HTTP request headers
    local headers = {
        ["Content-Type"] = "application/json"
    }
    
    if admin_key and admin_key ~= "" then
        headers["Kong-Admin-Token"] = admin_key
    end
    
    -- Make HTTP request to Admin API
    local httpc = require "resty.http"
    local client = httpc.new()
    
    -- Set timeout for Admin API requests
    client:set_timeout(5000) -- 5 seconds
    
    local res, err = client:request_uri(api_url, {
        method = "GET",
        headers = headers
    })
    
    if not res then
        log_loader_event("error", "Failed to connect to Admin API", { error = err })
        return nil, { "Admin API connection failed: " .. tostring(err) }
    end
    
    if res.status ~= 200 then
        log_loader_event("error", "Admin API returned error status", {
            status = res.status,
            body = res.body
        })
        return nil, { "Admin API error: " .. tostring(res.status) }
    end
    
    -- Parse Admin API response
    local ok, api_response = pcall(cjson.decode, res.body)
    if not ok then
        log_loader_event("error", "Failed to parse Admin API response", { error = api_response })
        return nil, { "Invalid Admin API response: " .. tostring(api_response) }
    end
    
    -- Extract plugin configuration
    local plugin_config = api_response.config
    if not plugin_config then
        log_loader_event("error", "No config field in Admin API response")
        return nil, { "Missing config field in Admin API response" }
    end
    
    -- Parse and validate configuration
    local config, errors = config_parser.parse_config(plugin_config)
    if not config then
        log_loader_event("error", "Failed to parse Admin API configuration", { errors = errors })
        return nil, errors
    end
    
    -- Update current configuration state
    current_config = config
    config_version = config_version + 1
    last_reload_time = ngx.time()
    
    log_loader_event("info", "Configuration loaded from Admin API", {
        version = config_version,
        timestamp = last_reload_time
    })
    
    return config, nil
end

-- Load configuration from environment variables
function config_loader.load_from_environment(prefix)
    prefix = prefix or "KONG_GUARD_AI_"
    
    log_loader_event("debug", "Loading configuration from environment variables", { prefix = prefix })
    
    local env_config = {}
    
    -- Map environment variables to configuration keys
    local env_mappings = {
        [prefix .. "DRY_RUN_MODE"] = { key = "dry_run_mode", type = "boolean" },
        [prefix .. "THREAT_THRESHOLD"] = { key = "threat_threshold", type = "number" },
        [prefix .. "MAX_PROCESSING_TIME_MS"] = { key = "max_processing_time_ms", type = "number" },
        [prefix .. "RATE_LIMIT_THRESHOLD"] = { key = "rate_limit_threshold", type = "number" },
        [prefix .. "BLOCK_DURATION_SECONDS"] = { key = "block_duration_seconds", type = "number" },
        [prefix .. "AI_GATEWAY_ENABLED"] = { key = "ai_gateway_enabled", type = "boolean" },
        [prefix .. "AI_GATEWAY_ENDPOINT"] = { key = "ai_gateway_endpoint", type = "string" },
        [prefix .. "AI_GATEWAY_MODEL"] = { key = "ai_gateway_model", type = "string" },
        [prefix .. "LOG_LEVEL"] = { key = "log_level", type = "string" },
        [prefix .. "SLACK_WEBHOOK_URL"] = { key = "slack_webhook_url", type = "string" },
        [prefix .. "NOTIFICATION_THRESHOLD"] = { key = "notification_threshold", type = "number" }
    }
    
    -- Process environment variables
    for env_var, mapping in pairs(env_mappings) do
        local env_value = os.getenv(env_var)
        if env_value then
            local converted_value
            
            if mapping.type == "boolean" then
                converted_value = env_value == "true" or env_value == "1"
            elseif mapping.type == "number" then
                converted_value = tonumber(env_value)
                if not converted_value then
                    log_loader_event("warn", "Invalid number in environment variable", {
                        var = env_var,
                        value = env_value
                    })
                end
            else
                converted_value = env_value
            end
            
            if converted_value ~= nil then
                env_config[mapping.key] = converted_value
            end
        end
    end
    
    -- Parse and validate configuration
    local config, errors = config_parser.parse_config(env_config)
    if not config then
        log_loader_event("error", "Failed to parse environment configuration", { errors = errors })
        return nil, errors
    end
    
    -- Update current configuration state
    current_config = config
    config_version = config_version + 1
    last_reload_time = ngx.time()
    
    log_loader_event("info", "Configuration loaded from environment", {
        version = config_version,
        timestamp = last_reload_time,
        vars_loaded = table.getn(env_config)
    })
    
    return config, nil
end

-- Generic configuration loader with strategy selection
function config_loader.load_configuration(strategy, options)
    strategy = strategy or default_strategy
    options = options or {}
    
    log_loader_event("info", "Loading configuration", {
        strategy = strategy,
        options = options
    })
    
    if strategy == LOADING_STRATEGIES.PLUGIN_CONFIG then
        return config_loader.load_from_plugin_config(options.plugin_config)
        
    elseif strategy == LOADING_STRATEGIES.ADMIN_API then
        return config_loader.load_from_admin_api(
            options.admin_url,
            options.admin_key,
            options.plugin_id
        )
        
    elseif strategy == LOADING_STRATEGIES.ENVIRONMENT then
        return config_loader.load_from_environment(options.env_prefix)
        
    else
        log_loader_event("error", "Unknown configuration loading strategy", { strategy = strategy })
        return nil, { "Unknown configuration loading strategy: " .. tostring(strategy) }
    end
end

-- Initialize configuration during Kong plugin initialization
function config_loader.initialize(plugin_config, options)
    options = options or {}
    
    log_loader_event("info", "Initializing configuration loader")
    
    -- Try primary loading strategy first
    local config, errors = config_loader.load_configuration(
        options.primary_strategy or LOADING_STRATEGIES.PLUGIN_CONFIG,
        { plugin_config = plugin_config, admin_url = options.admin_url, admin_key = options.admin_key }
    )
    
    if config then
        log_loader_event("info", "Configuration initialized successfully with primary strategy")
        return config, nil
    end
    
    -- Try fallback strategies if primary fails
    if options.fallback_strategies then
        for _, fallback_strategy in ipairs(options.fallback_strategies) do
            log_loader_event("warn", "Primary strategy failed, trying fallback", {
                strategy = fallback_strategy,
                primary_errors = errors
            })
            
            local fallback_config, fallback_errors = config_loader.load_configuration(
                fallback_strategy,
                options
            )
            
            if fallback_config then
                log_loader_event("info", "Configuration initialized with fallback strategy", {
                    strategy = fallback_strategy
                })
                return fallback_config, nil
            end
            
            log_loader_event("warn", "Fallback strategy failed", {
                strategy = fallback_strategy,
                errors = fallback_errors
            })
        end
    end
    
    -- All strategies failed, return errors
    log_loader_event("error", "All configuration loading strategies failed", { errors = errors })
    return nil, errors
end

-- Hot-reload configuration
function config_loader.hot_reload(strategy, options)
    log_loader_event("info", "Performing configuration hot-reload", { strategy = strategy })
    
    local new_config, errors = config_loader.load_configuration(strategy, options)
    if not new_config then
        log_loader_event("error", "Hot-reload failed", { errors = errors })
        return false, errors
    end
    
    -- Compare with current configuration
    if current_config then
        local changes = config_parser.diff_configs(current_config, new_config)
        log_loader_event("info", "Configuration changes detected", { changes = changes })
    end
    
    log_loader_event("info", "Configuration hot-reload successful", {
        version = config_version,
        timestamp = last_reload_time
    })
    
    return true, nil
end

-- Get current configuration
function config_loader.get_current_config()
    return current_config
end

-- Get configuration metadata
function config_loader.get_config_metadata()
    return {
        version = config_version,
        last_reload_time = last_reload_time,
        has_config = current_config ~= nil
    }
end

-- Validate current configuration health
function config_loader.health_check()
    local health = {
        status = "healthy",
        issues = {}
    }
    
    if not current_config then
        health.status = "unhealthy"
        table.insert(health.issues, "No configuration loaded")
        return health
    end
    
    -- Check configuration age
    local config_age = ngx.time() - last_reload_time
    if config_age > 86400 then -- 24 hours
        health.status = "warning"
        table.insert(health.issues, "Configuration is older than 24 hours")
    end
    
    -- Validate current configuration
    local valid, errors = config_parser.validate_config(current_config)
    if not valid then
        health.status = "unhealthy"
        for _, error in ipairs(errors) do
            table.insert(health.issues, "Validation error: " .. error)
        end
    end
    
    return health
end

-- Configuration monitoring and cache management
function config_loader.configure_caching(cache_options)
    cache_options = cache_options or {}
    
    -- Set cache TTL in config parser
    if cache_options.ttl then
        config_parser.set_cache_ttl(cache_options.ttl)
    end
    
    log_loader_event("debug", "Configuration caching configured", cache_options)
end

-- Export current configuration for debugging
function config_loader.export_current_config(format)
    if not current_config then
        return nil, "No configuration loaded"
    end
    
    return config_parser.export_config(current_config, format)
end

-- Reset configuration loader state
function config_loader.reset()
    current_config = nil
    config_version = 0
    last_reload_time = 0
    config_parser.clear_cache()
    
    log_loader_event("info", "Configuration loader state reset")
end

-- Set default loading strategy
function config_loader.set_default_strategy(strategy)
    if LOADING_STRATEGIES[strategy] then
        default_strategy = LOADING_STRATEGIES[strategy]
        log_loader_event("debug", "Default loading strategy updated", { strategy = strategy })
        return true
    else
        log_loader_event("error", "Invalid loading strategy", { strategy = strategy })
        return false
    end
end

-- Get available loading strategies
function config_loader.get_loading_strategies()
    return LOADING_STRATEGIES
end

return config_loader