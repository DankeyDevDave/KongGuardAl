-- Kong Guard AI Configuration Integration
-- Main integration module that coordinates configuration parsing, loading, and error handling
-- Provides a unified interface for the plugin handler to interact with configuration system

local config_parser = require "kong.plugins.kong-guard-ai.config_parser"
local config_loader = require "kong.plugins.kong-guard-ai.config_loader"
local config_errors = require "kong.plugins.kong-guard-ai.config_errors"
local cjson = require "cjson"

local config_integration = {}

-- Module state
local initialized = false
local current_config_version = 0
local performance_metrics = {
    config_loads = 0,
    config_validations = 0,
    config_errors = 0,
    hot_reloads = 0,
    cache_hits = 0,
    cache_misses = 0
}

-- Performance tracking
local function track_performance(metric_name, value)
    if performance_metrics[metric_name] then
        performance_metrics[metric_name] = performance_metrics[metric_name] + (value or 1)
    end
end

-- Utility logging function
local function log_integration_event(level, message, details)
    kong.log[level]("[kong-guard-ai:config_integration] " .. message ..
                    (details and (" | Details: " .. cjson.encode(details)) or ""))
end

-- Initialize the configuration system
function config_integration.initialize(plugin_config, options)
    options = options or {}

    log_integration_event("info", "Initializing configuration integration", {
        plugin_config_present = plugin_config ~= nil,
        options = options
    })

    -- Configure error handling
    if options.error_config then
        config_errors.configure(options.error_config)
    end

    -- Configure caching
    if options.cache_config then
        config_loader.configure_caching(options.cache_config)
    end

    -- Set up loading strategies with fallbacks
    local loading_options = {
        primary_strategy = options.primary_strategy or "plugin_config",
        fallback_strategies = options.fallback_strategies or { "environment" },
        admin_url = options.admin_url,
        admin_key = options.admin_key,
        plugin_id = options.plugin_id,
        env_prefix = options.env_prefix
    }

    -- Attempt to load configuration
    local config, errors = config_loader.initialize(plugin_config, loading_options)

    if not config then
        -- Handle initialization failure
        local error_obj = config_errors.handle_loading_error(
            loading_options.primary_strategy,
            "initialization",
            table.concat(errors or {}, "; "),
            { loading_options = loading_options }
        )

        -- Attempt error recovery
        local recovery_success, recovery_result = config_errors.execute_recovery(
            error_obj,
            { fallback_config = options.fallback_config }
        )

        if recovery_success and recovery_result.config then
            config = recovery_result.config
            log_integration_event("warn", "Configuration initialized with error recovery", {
                recovery_method = recovery_result.recovery_method
            })
        else
            log_integration_event("error", "Configuration initialization failed completely", {
                errors = errors,
                recovery_result = recovery_result
            })
            track_performance("config_errors")
            return false, errors
        end
    end

    -- Mark as initialized
    initialized = true
    current_config_version = current_config_version + 1
    track_performance("config_loads")

    log_integration_event("info", "Configuration integration initialized successfully", {
        version = current_config_version,
        config_keys = config and table.getn(config) or 0
    })

    return true, config
end

-- Get current configuration with validation
function config_integration.get_config(cache_key)
    if not initialized then
        log_integration_event("warn", "Configuration integration not initialized, returning defaults")
        return config_parser.get_defaults()
    end

    -- Try to get cached configuration first
    local cached_config = config_parser.get_cached_config(cache_key)
    if cached_config then
        track_performance("cache_hits")
        return cached_config
    end

    track_performance("cache_misses")

    -- Get current configuration from loader
    local current_config = config_loader.get_current_config()
    if not current_config then
        log_integration_event("warn", "No current configuration available, using defaults")
        return config_parser.get_defaults()
    end

    -- Validate current configuration health
    local valid, validation_errors = config_parser.validate_config(current_config)
    if not valid then
        log_integration_event("error", "Current configuration validation failed", {
            errors = validation_errors
        })

        -- Handle validation failure
        local error_obj = config_errors.handle_validation_error(
            "current_config",
            current_config,
            "valid configuration",
            { validation_errors = validation_errors }
        )

        -- Attempt recovery
        local recovery_success, recovery_result = config_errors.execute_recovery(
            error_obj,
            { fallback_config = config_parser.get_defaults() }
        )

        if recovery_success and recovery_result.config then
            current_config = recovery_result.config
            log_integration_event("warn", "Using recovered configuration", {
                recovery_method = recovery_result.recovery_method
            })
        else
            log_integration_event("error", "Configuration recovery failed, using defaults")
            current_config = config_parser.get_defaults()
        end

        track_performance("config_errors")
    end

    track_performance("config_validations")
    return current_config
end

-- Validate configuration update before applying
function config_integration.validate_update(new_config, current_config)
    log_integration_event("debug", "Validating configuration update")

    -- Parse and validate new configuration
    local parsed_config, parse_errors = config_parser.parse_config(new_config)
    if not parsed_config then
        return false, parse_errors
    end

    -- Check for critical changes that might break the system
    if current_config then
        local changes = config_parser.diff_configs(current_config, parsed_config)
        local critical_changes = {}

        -- Define critical configuration keys that require special handling
        local critical_keys = {
            "max_processing_time_ms",
            "threat_threshold",
            "admin_api_enabled",
            "ai_gateway_enabled"
        }

        for _, key in ipairs(critical_keys) do
            if changes[key] then
                table.insert(critical_changes, {
                    key = key,
                    change = changes[key]
                })
            end
        end

        if #critical_changes > 0 then
            log_integration_event("warn", "Critical configuration changes detected", {
                changes = critical_changes
            })
        end
    end

    track_performance("config_validations")
    return true, nil
end

-- Hot-reload configuration
function config_integration.hot_reload(new_config, options)
    options = options or {}

    log_integration_event("info", "Performing configuration hot-reload")

    -- Validate the update first
    local current_config = config_loader.get_current_config()
    local valid_update, validation_errors = config_integration.validate_update(new_config, current_config)

    if not valid_update then
        log_integration_event("error", "Hot-reload validation failed", {
            errors = validation_errors
        })
        return false, validation_errors
    end

    -- Perform the hot-reload
    local success, errors = config_loader.hot_reload(
        options.strategy or "plugin_config",
        { plugin_config = new_config }
    )

    if success then
        current_config_version = current_config_version + 1
        track_performance("hot_reloads")

        log_integration_event("info", "Configuration hot-reload successful", {
            version = current_config_version
        })

        -- Clear cache to force refresh
        config_parser.clear_cache()

        return true, nil
    else
        track_performance("config_errors")
        log_integration_event("error", "Configuration hot-reload failed", {
            errors = errors
        })

        return false, errors
    end
end

-- Get configuration status and health information
function config_integration.get_status()
    local status = {
        initialized = initialized,
        version = current_config_version,
        performance_metrics = performance_metrics
    }

    if initialized then
        -- Get loader metadata
        status.loader_metadata = config_loader.get_config_metadata()

        -- Get health information
        status.loader_health = config_loader.health_check()
        status.error_health = config_errors.health_check()

        -- Get recent errors
        status.recent_errors = config_errors.get_recent_errors(5)

        -- Get error statistics
        status.error_stats = config_errors.get_error_stats()
    end

    return status
end

-- Export current configuration for debugging/audit
function config_integration.export_config(format, options)
    format = format or "json"
    options = options or {}

    local current_config = config_loader.get_current_config()
    if not current_config then
        return nil, "No configuration loaded"
    end

    local exported, err = config_parser.export_config(current_config, format)
    if not exported then
        return nil, err
    end

    -- Add metadata if requested
    if options.include_metadata then
        local metadata = {
            export_timestamp = ngx.time(),
            config_version = current_config_version,
            config_data = exported
        }

        if format == "json" then
            exported = cjson.encode(metadata)
        end
    end

    return exported, nil
end

-- Reset configuration system (for testing/recovery)
function config_integration.reset()
    log_integration_event("info", "Resetting configuration integration")

    initialized = false
    current_config_version = 0

    -- Reset sub-modules
    config_loader.reset()
    config_parser.clear_cache()
    config_errors.clear_error_history()

    -- Reset performance metrics
    for key, _ in pairs(performance_metrics) do
        performance_metrics[key] = 0
    end
end

-- Handle configuration errors gracefully
function config_integration.handle_config_error(error_type, error_details, recovery_context)
    log_integration_event("warn", "Handling configuration error", {
        error_type = error_type,
        error_details = error_details
    })

    local error_obj

    if error_type == "validation" then
        error_obj = config_errors.handle_validation_error(
            error_details.field,
            error_details.value,
            error_details.expected,
            error_details
        )
    elseif error_type == "parsing" then
        error_obj = config_errors.handle_parsing_error(
            error_details.input_type,
            error_details.input_data,
            error_details.parse_error,
            error_details
        )
    elseif error_type == "loading" then
        error_obj = config_errors.handle_loading_error(
            error_details.strategy,
            error_details.source,
            error_details.error_message,
            error_details
        )
    elseif error_type == "network" then
        error_obj = config_errors.handle_network_error(
            error_details.endpoint,
            error_details.status_code,
            error_details.response_body,
            error_details
        )
    else
        error_obj = config_errors.create_error(
            config_errors.ERROR_CATEGORIES.RUNTIME,
            config_errors.ERROR_LEVELS.MEDIUM,
            "Unknown configuration error",
            error_details
        )
    end

    -- Execute recovery strategy
    local recovery_success, recovery_result = config_errors.execute_recovery(
        error_obj,
        recovery_context or {}
    )

    track_performance("config_errors")

    return recovery_success, recovery_result, error_obj
end

-- Performance monitoring
function config_integration.get_performance_metrics()
    return {
        metrics = performance_metrics,
        uptime_seconds = initialized and (ngx.time() - (config_loader.get_config_metadata().last_reload_time or ngx.time())) or 0
    }
end

-- Configuration diff utility
function config_integration.diff_with_current(new_config)
    local current_config = config_loader.get_current_config()
    if not current_config then
        return nil, "No current configuration to compare with"
    end

    local parsed_new, errors = config_parser.parse_config(new_config)
    if not parsed_new then
        return nil, errors
    end

    return config_parser.diff_configs(current_config, parsed_new), nil
end

-- Validate against schema (if schema module is available)
function config_integration.validate_against_schema(config_data)
    -- Try to load schema module
    local ok, schema = pcall(require, "kong.plugins.kong-guard-ai.schema")
    if not ok then
        log_integration_event("warn", "Schema module not available for validation")
        return true, nil
    end

    -- This would integrate with Kong's schema validation if needed
    -- For now, we rely on our custom validation
    return config_parser.validate_config(config_data)
end

-- Module health check
function config_integration.health_check()
    local health = {
        status = "healthy",
        issues = {},
        components = {}
    }

    -- Check initialization status
    if not initialized then
        health.status = "unhealthy"
        table.insert(health.issues, "Configuration integration not initialized")
        return health
    end

    -- Check sub-component health
    health.components.loader = config_loader.health_check()
    health.components.error_handler = config_errors.health_check()

    -- Check for component issues
    for component_name, component_health in pairs(health.components) do
        if component_health.status == "unhealthy" then
            health.status = "unhealthy"
            table.insert(health.issues, string.format("%s component is unhealthy", component_name))
        elseif component_health.status == "warning" and health.status == "healthy" then
            health.status = "warning"
        end
    end

    return health
end

return config_integration
