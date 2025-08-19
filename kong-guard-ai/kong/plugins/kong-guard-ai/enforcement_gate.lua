-- Kong Guard AI - Enforcement Gate Module
-- Centralized dry-run mode enforcement control for all security actions
-- Ensures consistent dry-run behavior across all plugin components

local kong = kong
local json = require "cjson.safe"

local _M = {}

-- Enforcement action types for tracking and logging
local ENFORCEMENT_ACTIONS = {
    BLOCK_REQUEST = "block_request",
    RATE_LIMIT = "rate_limit", 
    BLOCK_IP = "block_ip",
    CONFIG_ROLLBACK = "config_rollback",
    MODIFY_HEADERS = "modify_headers",
    REDIRECT_REQUEST = "redirect_request",
    NOTIFICATION = "notification",
    ADMIN_API_CALL = "admin_api_call",
    UPSTREAM_MODIFICATION = "upstream_modification"
}

-- Dry-run action registry for tracking what would have been executed
local dry_run_registry = {}
local enforcement_stats = {
    dry_run_actions = 0,
    actual_actions = 0,
    blocked_actions = 0
}

---
-- Initialize enforcement gate system
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Enforcement Gate] Initializing enforcement control system")
    
    -- Initialize registries
    dry_run_registry.actions = {}
    dry_run_registry.sessions = {}
    
    -- Log initialization mode
    if conf.dry_run_mode then
        kong.log.warn("[Kong Guard AI Enforcement Gate] OPERATING IN DRY-RUN MODE - No enforcement actions will be executed")
    else
        kong.log.info("[Kong Guard AI Enforcement Gate] OPERATING IN ACTIVE MODE - Enforcement actions will be executed")
    end
    
    kong.log.info("[Kong Guard AI Enforcement Gate] Enforcement gate system initialized")
end

---
-- Central enforcement gate - all enforcement actions must pass through this function
-- @param action_type String identifying the type of enforcement action
-- @param action_data Table containing action parameters and context
-- @param conf Plugin configuration
-- @param execution_callback Function to execute if enforcement is allowed
-- @return Table containing enforcement result and dry-run information
---
function _M.enforce_action(action_type, action_data, conf, execution_callback)
    local enforcement_result = {
        action_type = action_type,
        dry_run_mode = conf.dry_run_mode,
        executed = false,
        simulated = false,
        timestamp = ngx.time(),
        request_id = ngx.var.request_id,
        details = {}
    }
    
    -- Validate action type
    if not _M.is_valid_action_type(action_type) then
        kong.log.error("[Kong Guard AI Enforcement Gate] Invalid action type: " .. tostring(action_type))
        enforcement_result.error = "invalid_action_type"
        return enforcement_result
    end
    
    -- Validate execution callback
    if type(execution_callback) ~= "function" then
        kong.log.error("[Kong Guard AI Enforcement Gate] Invalid execution callback for action: " .. action_type)
        enforcement_result.error = "invalid_callback"
        return enforcement_result
    end
    
    -- Log enforcement attempt
    kong.log.debug("[Kong Guard AI Enforcement Gate] Processing enforcement action: " .. action_type)
    
    if conf.dry_run_mode then
        -- DRY RUN MODE: Simulate and log the action without executing
        enforcement_result = _M.simulate_action(action_type, action_data, conf, enforcement_result)
        enforcement_stats.dry_run_actions = enforcement_stats.dry_run_actions + 1
    else
        -- ACTIVE MODE: Execute the enforcement action
        enforcement_result = _M.execute_action(action_type, action_data, conf, execution_callback, enforcement_result)
        enforcement_stats.actual_actions = enforcement_stats.actual_actions + 1
    end
    
    -- Store enforcement record for monitoring and reporting
    _M.store_enforcement_record(enforcement_result, action_data)
    
    return enforcement_result
end

---
-- Simulate enforcement action in dry-run mode
-- @param action_type Type of enforcement action
-- @param action_data Action parameters
-- @param conf Plugin configuration
-- @param enforcement_result Result object to populate
-- @return Updated enforcement result
---
function _M.simulate_action(action_type, action_data, conf, enforcement_result)
    enforcement_result.simulated = true
    enforcement_result.dry_run_details = {
        action_summary = _M.build_action_summary(action_type, action_data),
        would_execute = true,
        simulation_timestamp = ngx.time()
    }
    
    -- Build detailed simulation log
    local simulation_log = {
        action = action_type,
        parameters = action_data,
        impact_assessment = _M.assess_action_impact(action_type, action_data),
        execution_path = _M.trace_execution_path(action_type, action_data)
    }
    
    -- Log the dry-run action with clear indicators
    kong.log.warn(string.format(
        "[Kong Guard AI Enforcement Gate] 🧪 DRY RUN: Would execute %s - %s",
        action_type,
        simulation_log.impact_assessment
    ))
    
    -- Store detailed simulation data
    enforcement_result.details.simulation = simulation_log
    
    -- Add to dry-run registry for reporting
    _M.add_to_dry_run_registry(action_type, action_data, simulation_log)
    
    return enforcement_result
end

---
-- Execute enforcement action in active mode
-- @param action_type Type of enforcement action
-- @param action_data Action parameters
-- @param conf Plugin configuration
-- @param execution_callback Function to execute the action
-- @param enforcement_result Result object to populate
-- @return Updated enforcement result
---
function _M.execute_action(action_type, action_data, conf, execution_callback, enforcement_result)
    kong.log.info(string.format(
        "[Kong Guard AI Enforcement Gate] ⚡ EXECUTING: %s",
        action_type
    ))
    
    -- Execute the action via callback
    local execution_start = ngx.now()
    local success, result, error_message = pcall(execution_callback, action_data, conf)
    local execution_time = (ngx.now() - execution_start) * 1000 -- Convert to milliseconds
    
    -- Process execution result
    if success and result then
        enforcement_result.executed = true
        enforcement_result.execution_time_ms = execution_time
        enforcement_result.details.execution_result = result
        
        kong.log.info(string.format(
            "[Kong Guard AI Enforcement Gate] ✅ Successfully executed %s (%.2fms)",
            action_type,
            execution_time
        ))
    else
        enforcement_result.executed = false
        enforcement_result.error = error_message or "execution_failed"
        enforcement_result.details.error_details = {
            error_message = error_message,
            execution_time_ms = execution_time
        }
        
        kong.log.error(string.format(
            "[Kong Guard AI Enforcement Gate] ❌ Failed to execute %s: %s",
            action_type,
            error_message or "unknown error"
        ))
        
        enforcement_stats.blocked_actions = enforcement_stats.blocked_actions + 1
    end
    
    return enforcement_result
end

---
-- Build human-readable summary of enforcement action
-- @param action_type Type of action
-- @param action_data Action parameters
-- @return String summary of the action
---
function _M.build_action_summary(action_type, action_data)
    local summaries = {
        [ENFORCEMENT_ACTIONS.BLOCK_REQUEST] = function(data)
            return string.format("Block request from IP %s (reason: %s)", 
                data.client_ip or "unknown", data.reason or "threat_detected")
        end,
        [ENFORCEMENT_ACTIONS.RATE_LIMIT] = function(data)
            return string.format("Apply rate limit %d req/min to IP %s", 
                data.limit or 0, data.client_ip or "unknown")
        end,
        [ENFORCEMENT_ACTIONS.BLOCK_IP] = function(data)
            return string.format("Add IP %s to blocklist for %d seconds", 
                data.ip_address or "unknown", data.duration or 0)
        end,
        [ENFORCEMENT_ACTIONS.CONFIG_ROLLBACK] = function(data)
            return string.format("Rollback Kong configuration to version %s", 
                data.target_version or "previous")
        end,
        [ENFORCEMENT_ACTIONS.NOTIFICATION] = function(data)
            return string.format("Send %s notification via %s", 
                data.notification_type or "threat", data.channel or "default")
        end,
        [ENFORCEMENT_ACTIONS.ADMIN_API_CALL] = function(data)
            return string.format("Call Admin API: %s %s", 
                data.method or "POST", data.endpoint or "/unknown")
        end
    }
    
    local summary_func = summaries[action_type]
    if summary_func then
        return summary_func(action_data)
    else
        return string.format("Execute %s with parameters: %s", 
            action_type, json.encode(action_data))
    end
end

---
-- Assess the potential impact of an enforcement action
-- @param action_type Type of action
-- @param action_data Action parameters
-- @return String describing the impact
---
function _M.assess_action_impact(action_type, action_data)
    local impact_levels = {
        [ENFORCEMENT_ACTIONS.BLOCK_REQUEST] = "Medium - Single request blocked",
        [ENFORCEMENT_ACTIONS.RATE_LIMIT] = "Medium - Traffic throttled for IP",
        [ENFORCEMENT_ACTIONS.BLOCK_IP] = "High - IP completely blocked",
        [ENFORCEMENT_ACTIONS.CONFIG_ROLLBACK] = "Critical - Kong configuration changed",
        [ENFORCEMENT_ACTIONS.NOTIFICATION] = "Low - Alert sent to operators",
        [ENFORCEMENT_ACTIONS.ADMIN_API_CALL] = "High - Kong configuration modified"
    }
    
    return impact_levels[action_type] or "Unknown impact level"
end

---
-- Trace the execution path for an action (for debugging)
-- @param action_type Type of action
-- @param action_data Action parameters
-- @return Array of execution steps
---
function _M.trace_execution_path(action_type, action_data)
    local paths = {
        [ENFORCEMENT_ACTIONS.BLOCK_REQUEST] = {
            "Set response status and headers",
            "Call kong.response.exit()",
            "Log block action"
        },
        [ENFORCEMENT_ACTIONS.RATE_LIMIT] = {
            "Calculate dynamic rate limit",
            "Call Kong Admin API",
            "Update plugin configuration",
            "Apply rate limiting policy"
        },
        [ENFORCEMENT_ACTIONS.BLOCK_IP] = {
            "Add IP to blocklist cache",
            "Update Kong IP restriction plugin",
            "Set expiration timer"
        },
        [ENFORCEMENT_ACTIONS.CONFIG_ROLLBACK] = {
            "Fetch current configuration",
            "Identify previous safe configuration",
            "Validate rollback configuration",
            "Apply configuration via Admin API"
        }
    }
    
    return paths[action_type] or {"Execute action", "Log result"}
end

---
-- Add action to dry-run registry for reporting
-- @param action_type Type of action
-- @param action_data Action parameters
-- @param simulation_log Simulation details
---
function _M.add_to_dry_run_registry(action_type, action_data, simulation_log)
    if not dry_run_registry.actions[action_type] then
        dry_run_registry.actions[action_type] = {}
    end
    
    table.insert(dry_run_registry.actions[action_type], {
        timestamp = ngx.time(),
        request_id = ngx.var.request_id,
        action_data = action_data,
        simulation = simulation_log
    })
    
    -- Limit registry size to prevent memory issues
    if #dry_run_registry.actions[action_type] > 100 then
        table.remove(dry_run_registry.actions[action_type], 1)
    end
end

---
-- Store enforcement record for monitoring
-- @param enforcement_result Result of enforcement action
-- @param action_data Original action parameters
---
function _M.store_enforcement_record(enforcement_result, action_data)
    -- This could be extended to store in shared memory or external storage
    -- For now, we log comprehensive details
    
    local record = {
        enforcement_result = enforcement_result,
        action_context = action_data,
        timestamp = ngx.time(),
        kong_node_id = kong.node.get_id()
    }
    
    -- Log detailed enforcement record
    kong.log.info(string.format(
        "[Kong Guard AI Enforcement Gate] ENFORCEMENT_RECORD: %s",
        json.encode(record)
    ))
end

---
-- Validate if action type is supported
-- @param action_type Action type to validate
-- @return Boolean indicating if action type is valid
---
function _M.is_valid_action_type(action_type)
    for _, valid_type in pairs(ENFORCEMENT_ACTIONS) do
        if action_type == valid_type then
            return true
        end
    end
    return false
end

---
-- Get enforcement statistics for monitoring
-- @return Table containing enforcement metrics
---
function _M.get_enforcement_stats()
    local stats = {
        total_actions = enforcement_stats.dry_run_actions + enforcement_stats.actual_actions,
        dry_run_actions = enforcement_stats.dry_run_actions,
        actual_actions = enforcement_stats.actual_actions,
        blocked_actions = enforcement_stats.blocked_actions,
        success_rate = 0
    }
    
    if stats.total_actions > 0 then
        stats.success_rate = (stats.actual_actions - stats.blocked_actions) / stats.total_actions
    end
    
    return stats
end

---
-- Get dry-run registry for reporting
-- @return Table containing all simulated actions
---
function _M.get_dry_run_registry()
    return {
        actions = dry_run_registry.actions,
        summary = {
            total_simulated_actions = _M.count_simulated_actions(),
            action_types = _M.get_simulated_action_types(),
            latest_simulation = _M.get_latest_simulation()
        }
    }
end

---
-- Count total simulated actions
-- @return Number of simulated actions
---
function _M.count_simulated_actions()
    local count = 0
    for action_type, actions in pairs(dry_run_registry.actions) do
        count = count + #actions
    end
    return count
end

---
-- Get list of simulated action types
-- @return Array of action types that have been simulated
---
function _M.get_simulated_action_types()
    local types = {}
    for action_type, actions in pairs(dry_run_registry.actions) do
        if #actions > 0 then
            table.insert(types, action_type)
        end
    end
    return types
end

---
-- Get the most recent simulation
-- @return Table containing latest simulation details
---
function _M.get_latest_simulation()
    local latest = nil
    local latest_timestamp = 0
    
    for action_type, actions in pairs(dry_run_registry.actions) do
        for _, action in ipairs(actions) do
            if action.timestamp > latest_timestamp then
                latest_timestamp = action.timestamp
                latest = {
                    action_type = action_type,
                    timestamp = action.timestamp,
                    request_id = action.request_id,
                    summary = _M.build_action_summary(action_type, action.action_data)
                }
            end
        end
    end
    
    return latest
end

---
-- Clean up old enforcement records
---
function _M.cleanup_enforcement_records()
    local current_time = ngx.time()
    local cleanup_threshold = current_time - 3600 -- Clean records older than 1 hour
    
    for action_type, actions in pairs(dry_run_registry.actions) do
        local cleaned_actions = {}
        for _, action in ipairs(actions) do
            if action.timestamp >= cleanup_threshold then
                table.insert(cleaned_actions, action)
            end
        end
        dry_run_registry.actions[action_type] = cleaned_actions
    end
    
    kong.log.debug("[Kong Guard AI Enforcement Gate] Enforcement record cleanup completed")
end

---
-- Export enforcement action constants for use by other modules
---
function _M.get_action_types()
    return ENFORCEMENT_ACTIONS
end

return _M