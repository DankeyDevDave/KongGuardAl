-- Kong Guard AI Configuration Error Handling
-- Provides robust error handling and recovery mechanisms for configuration management
-- Includes detailed logging, graceful degradation, and error reporting

local cjson = require "cjson"

local config_errors = {}

-- Error severity levels
local ERROR_LEVELS = {
    CRITICAL = "critical",    -- System cannot function
    HIGH = "high",           -- Major functionality impaired
    MEDIUM = "medium",       -- Some functionality affected
    LOW = "low",            -- Minor issues or warnings
    INFO = "info"           -- Informational messages
}

-- Error categories
local ERROR_CATEGORIES = {
    VALIDATION = "validation",           -- Configuration validation errors
    PARSING = "parsing",                -- Configuration parsing errors
    LOADING = "loading",                -- Configuration loading errors
    NETWORK = "network",                -- Network-related errors (Admin API, etc.)
    PERMISSION = "permission",          -- Permission/access errors
    DEPENDENCY = "dependency",          -- Missing dependencies
    RUNTIME = "runtime",                -- Runtime configuration errors
    TIMEOUT = "timeout",                -- Timeout-related errors
    FORMAT = "format"                   -- Data format errors
}

-- Error recovery strategies
local RECOVERY_STRATEGIES = {
    FALLBACK_CONFIG = "fallback_config",     -- Use fallback configuration
    DEFAULT_CONFIG = "default_config",       -- Use default configuration
    RETRY = "retry",                         -- Retry the operation
    DISABLE_FEATURE = "disable_feature",     -- Disable problematic feature
    GRACEFUL_DEGRADATION = "graceful_degradation", -- Reduce functionality
    FAIL_FAST = "fail_fast"                 -- Fail immediately
}

-- Error state tracking
local error_history = {}
local error_counts = {}
local last_error_time = {}
local recovery_attempts = {}

-- Configuration for error handling behavior
local error_config = {
    max_retry_attempts = 3,
    retry_delay_seconds = 5,
    error_history_limit = 100,
    rate_limit_window = 60,
    rate_limit_threshold = 10,
    enable_detailed_logging = true,
    enable_error_reporting = true
}

-- Utility function for logging errors
local function log_error_event(level, category, message, details)
    local timestamp = ngx.time()
    local log_entry = {
        timestamp = timestamp,
        level = level,
        category = category,
        message = message,
        details = details or {}
    }

    -- Add to error history
    table.insert(error_history, log_entry)

    -- Limit error history size
    if #error_history > error_config.error_history_limit then
        table.remove(error_history, 1)
    end

    -- Update error counts
    local error_key = category .. ":" .. level
    error_counts[error_key] = (error_counts[error_key] or 0) + 1
    last_error_time[error_key] = timestamp

    -- Log to Kong logger
    local log_message = string.format("[kong-guard-ai:config_errors] [%s:%s] %s",
                                     level, category, message)

    if error_config.enable_detailed_logging and details then
        log_message = log_message .. " | Details: " .. cjson.encode(details)
    end

    -- Choose appropriate log level
    if level == ERROR_LEVELS.CRITICAL or level == ERROR_LEVELS.HIGH then
        kong.log.err(log_message)
    elseif level == ERROR_LEVELS.MEDIUM then
        kong.log.warn(log_message)
    else
        kong.log.info(log_message)
    end
end

-- Create standardized error object
function config_errors.create_error(category, level, message, details, recovery_strategy)
    return {
        category = category or ERROR_CATEGORIES.RUNTIME,
        level = level or ERROR_LEVELS.MEDIUM,
        message = message or "Unknown configuration error",
        details = details or {},
        recovery_strategy = recovery_strategy,
        timestamp = ngx.time(),
        error_id = string.format("%s_%s_%d", category or "unknown",
                                level or "medium", ngx.time())
    }
end

-- Handle configuration validation errors
function config_errors.handle_validation_error(field, value, expected, details)
    local error_obj = config_errors.create_error(
        ERROR_CATEGORIES.VALIDATION,
        ERROR_LEVELS.HIGH,
        string.format("Configuration validation failed for field '%s'", field),
        {
            field = field,
            value = value,
            expected = expected,
            additional_details = details
        },
        RECOVERY_STRATEGIES.DEFAULT_CONFIG
    )

    log_error_event(error_obj.level, error_obj.category, error_obj.message, error_obj.details)

    return error_obj
end

-- Handle configuration parsing errors
function config_errors.handle_parsing_error(input_type, input_data, parse_error, details)
    local error_obj = config_errors.create_error(
        ERROR_CATEGORIES.PARSING,
        ERROR_LEVELS.HIGH,
        string.format("Failed to parse %s configuration", input_type),
        {
            input_type = input_type,
            input_size = type(input_data) == "string" and #input_data or "unknown",
            parse_error = parse_error,
            additional_details = details
        },
        RECOVERY_STRATEGIES.FALLBACK_CONFIG
    )

    log_error_event(error_obj.level, error_obj.category, error_obj.message, error_obj.details)

    return error_obj
end

-- Handle configuration loading errors
function config_errors.handle_loading_error(strategy, source, error_message, details)
    local error_obj = config_errors.create_error(
        ERROR_CATEGORIES.LOADING,
        ERROR_LEVELS.HIGH,
        string.format("Failed to load configuration using %s strategy", strategy),
        {
            strategy = strategy,
            source = source,
            error_message = error_message,
            additional_details = details
        },
        RECOVERY_STRATEGIES.RETRY
    )

    log_error_event(error_obj.level, error_obj.category, error_obj.message, error_obj.details)

    return error_obj
end

-- Handle network-related errors (Admin API, external services)
function config_errors.handle_network_error(endpoint, status_code, response_body, details)
    local level = ERROR_LEVELS.MEDIUM
    local recovery = RECOVERY_STRATEGIES.RETRY

    -- Determine severity based on status code
    if status_code >= 500 then
        level = ERROR_LEVELS.HIGH
    elseif status_code >= 400 then
        level = ERROR_LEVELS.MEDIUM
        recovery = RECOVERY_STRATEGIES.FALLBACK_CONFIG
    end

    local error_obj = config_errors.create_error(
        ERROR_CATEGORIES.NETWORK,
        level,
        string.format("Network error accessing %s (status: %s)", endpoint, status_code),
        {
            endpoint = endpoint,
            status_code = status_code,
            response_body = response_body,
            additional_details = details
        },
        recovery
    )

    log_error_event(error_obj.level, error_obj.category, error_obj.message, error_obj.details)

    return error_obj
end

-- Handle timeout errors
function config_errors.handle_timeout_error(operation, timeout_duration, details)
    local error_obj = config_errors.create_error(
        ERROR_CATEGORIES.TIMEOUT,
        ERROR_LEVELS.MEDIUM,
        string.format("Operation '%s' timed out after %s seconds", operation, timeout_duration),
        {
            operation = operation,
            timeout_duration = timeout_duration,
            additional_details = details
        },
        RECOVERY_STRATEGIES.RETRY
    )

    log_error_event(error_obj.level, error_obj.category, error_obj.message, error_obj.details)

    return error_obj
end

-- Handle permission/access errors
function config_errors.handle_permission_error(resource, action, user_context, details)
    local error_obj = config_errors.create_error(
        ERROR_CATEGORIES.PERMISSION,
        ERROR_LEVELS.HIGH,
        string.format("Permission denied for %s on %s", action, resource),
        {
            resource = resource,
            action = action,
            user_context = user_context,
            additional_details = details
        },
        RECOVERY_STRATEGIES.DISABLE_FEATURE
    )

    log_error_event(error_obj.level, error_obj.category, error_obj.message, error_obj.details)

    return error_obj
end

-- Error recovery execution
function config_errors.execute_recovery(error_obj, recovery_context)
    recovery_context = recovery_context or {}

    local recovery_strategy = error_obj.recovery_strategy
    if not recovery_strategy then
        log_error_event(ERROR_LEVELS.MEDIUM, ERROR_CATEGORIES.RUNTIME,
                       "No recovery strategy defined for error", { error_id = error_obj.error_id })
        return false, "No recovery strategy available"
    end

    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME,
                   "Executing error recovery", {
                       error_id = error_obj.error_id,
                       strategy = recovery_strategy
                   })

    -- Track recovery attempts
    local recovery_key = error_obj.error_id
    recovery_attempts[recovery_key] = (recovery_attempts[recovery_key] or 0) + 1

    -- Check if max retry attempts reached
    if recovery_attempts[recovery_key] > error_config.max_retry_attempts and
       recovery_strategy == RECOVERY_STRATEGIES.RETRY then
        log_error_event(ERROR_LEVELS.HIGH, ERROR_CATEGORIES.RUNTIME,
                       "Max retry attempts reached, switching to fallback",
                       { error_id = error_obj.error_id })
        recovery_strategy = RECOVERY_STRATEGIES.FALLBACK_CONFIG
    end

    -- Execute recovery strategy
    if recovery_strategy == RECOVERY_STRATEGIES.DEFAULT_CONFIG then
        return config_errors.recover_with_defaults(recovery_context)

    elseif recovery_strategy == RECOVERY_STRATEGIES.FALLBACK_CONFIG then
        return config_errors.recover_with_fallback(recovery_context)

    elseif recovery_strategy == RECOVERY_STRATEGIES.RETRY then
        return config_errors.recover_with_retry(recovery_context, error_obj)

    elseif recovery_strategy == RECOVERY_STRATEGIES.DISABLE_FEATURE then
        return config_errors.recover_with_feature_disable(recovery_context, error_obj)

    elseif recovery_strategy == RECOVERY_STRATEGIES.GRACEFUL_DEGRADATION then
        return config_errors.recover_with_degradation(recovery_context)

    elseif recovery_strategy == RECOVERY_STRATEGIES.FAIL_FAST then
        return false, "Fail-fast recovery strategy - no recovery attempted"

    else
        log_error_event(ERROR_LEVELS.MEDIUM, ERROR_CATEGORIES.RUNTIME,
                       "Unknown recovery strategy", { strategy = recovery_strategy })
        return false, "Unknown recovery strategy: " .. tostring(recovery_strategy)
    end
end

-- Recovery implementation: Use default configuration
function config_errors.recover_with_defaults(recovery_context)
    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME, "Recovering with default configuration")

    local config_parser = require "kong.plugins.kong-guard-ai.config_parser"
    local defaults = config_parser.get_defaults()

    return true, { config = defaults, recovery_method = "defaults" }
end

-- Recovery implementation: Use fallback configuration
function config_errors.recover_with_fallback(recovery_context)
    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME, "Recovering with fallback configuration")

    local fallback_config = recovery_context.fallback_config
    if not fallback_config then
        -- If no fallback provided, use defaults
        return config_errors.recover_with_defaults(recovery_context)
    end

    return true, { config = fallback_config, recovery_method = "fallback" }
end

-- Recovery implementation: Retry operation
function config_errors.recover_with_retry(recovery_context, error_obj)
    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME, "Recovering with retry")

    -- Add delay before retry
    if error_config.retry_delay_seconds > 0 then
        ngx.sleep(error_config.retry_delay_seconds)
    end

    -- Return instruction to retry - actual retry logic should be in calling code
    return true, {
        recovery_method = "retry",
        retry_attempt = recovery_attempts[error_obj.error_id],
        delay_applied = error_config.retry_delay_seconds
    }
end

-- Recovery implementation: Disable problematic feature
function config_errors.recover_with_feature_disable(recovery_context, error_obj)
    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME, "Recovering by disabling feature")

    local feature_to_disable = recovery_context.feature or "unknown"

    return true, {
        recovery_method = "feature_disable",
        disabled_feature = feature_to_disable,
        original_error = error_obj.error_id
    }
end

-- Recovery implementation: Graceful degradation
function config_errors.recover_with_degradation(recovery_context)
    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME, "Recovering with graceful degradation")

    return true, {
        recovery_method = "graceful_degradation",
        degraded_features = recovery_context.degraded_features or {}
    }
end

-- Error rate limiting (prevent error spam)
function config_errors.is_error_rate_limited(category, level)
    local error_key = category .. ":" .. level
    local current_time = ngx.time()
    local last_time = last_error_time[error_key] or 0
    local count = error_counts[error_key] or 0

    -- Reset count if outside window
    if current_time - last_time > error_config.rate_limit_window then
        error_counts[error_key] = 0
        return false
    end

    return count >= error_config.rate_limit_threshold
end

-- Get error statistics
function config_errors.get_error_stats()
    return {
        total_errors = #error_history,
        error_counts = error_counts,
        last_error_times = last_error_time,
        recovery_attempts = recovery_attempts,
        config = error_config
    }
end

-- Get recent errors
function config_errors.get_recent_errors(limit, category_filter, level_filter)
    limit = limit or 10
    local recent_errors = {}

    local start_index = math.max(1, #error_history - limit + 1)

    for i = start_index, #error_history do
        local error_entry = error_history[i]

        -- Apply filters
        if (not category_filter or error_entry.category == category_filter) and
           (not level_filter or error_entry.level == level_filter) then
            table.insert(recent_errors, error_entry)
        end
    end

    return recent_errors
end

-- Clear error history
function config_errors.clear_error_history()
    error_history = {}
    error_counts = {}
    last_error_time = {}
    recovery_attempts = {}

    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME, "Error history cleared")
end

-- Configure error handling behavior
function config_errors.configure(new_config)
    for key, value in pairs(new_config or {}) do
        if error_config[key] ~= nil then
            error_config[key] = value
        end
    end

    log_error_event(ERROR_LEVELS.INFO, ERROR_CATEGORIES.RUNTIME,
                   "Error handling configuration updated", error_config)
end

-- Health check for error handling system
function config_errors.health_check()
    local health = {
        status = "healthy",
        issues = {},
        stats = config_errors.get_error_stats()
    }

    -- Check error rates
    local current_time = ngx.time()
    local recent_critical_errors = 0

    for _, error_entry in ipairs(error_history) do
        if current_time - error_entry.timestamp <= 300 and -- Last 5 minutes
           error_entry.level == ERROR_LEVELS.CRITICAL then
            recent_critical_errors = recent_critical_errors + 1
        end
    end

    if recent_critical_errors > 0 then
        health.status = "unhealthy"
        table.insert(health.issues,
                    string.format("Found %d critical errors in last 5 minutes", recent_critical_errors))
    end

    -- Check if error history is getting full
    if #error_history > error_config.error_history_limit * 0.9 then
        health.status = "warning"
        table.insert(health.issues, "Error history approaching limit")
    end

    return health
end

-- Export error constants
config_errors.ERROR_LEVELS = ERROR_LEVELS
config_errors.ERROR_CATEGORIES = ERROR_CATEGORIES
config_errors.RECOVERY_STRATEGIES = RECOVERY_STRATEGIES

return config_errors
