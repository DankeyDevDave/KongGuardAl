-- Kong Guard AI - Dry-Run Status and Reporting Module
-- Provides status endpoints and detailed reporting for dry-run mode operations
-- Enables monitoring and validation of dry-run enforcement behavior

local kong = kong
local json = require "cjson.safe"
local enforcement_gate = require "kong.plugins.kong-guard-ai.enforcement_gate"
local method_filter = require "kong.plugins.kong-guard-ai.method_filter"

local _M = {}

---
-- Handle dry-run status endpoint requests
-- @param conf Plugin configuration
-- @return HTTP response with dry-run status and statistics
---
function _M.handle_status_request(conf)
    -- Check if status endpoint is enabled
    if not conf.status_endpoint_enabled then
        return kong.response.exit(404, {
            error = "Status endpoint disabled",
            message = "Enable status_endpoint_enabled in plugin configuration"
        })
    end
    
    -- Get current request path
    local request_path = kong.request.get_path()
    local status_path = conf.status_endpoint_path or "/_guard_ai/status"
    
    -- Only handle requests to the status endpoint
    if not request_path:match(status_path) then
        return nil -- Let other handlers process the request
    end
    
    -- Generate status response
    local status_response = _M.generate_status_response(conf)
    
    -- Set appropriate headers
    kong.response.set_header("Content-Type", "application/json")
    kong.response.set_header("X-Kong-Guard-AI-Status", "ok")
    
    -- Return status response
    return kong.response.exit(200, status_response)
end

---
-- Generate comprehensive dry-run status response
-- @param conf Plugin configuration
-- @return Table containing status information
---
function _M.generate_status_response(conf)
    local status = {
        plugin_info = {
            name = "kong-guard-ai",
            version = "0.1.0",
            dry_run_mode = conf.dry_run_mode,
            node_id = kong.node.get_id(),
            timestamp = ngx.time(),
            iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time())
        },
        enforcement_statistics = enforcement_gate.get_enforcement_stats(),
        dry_run_registry = enforcement_gate.get_dry_run_registry(),
        configuration_summary = _M.get_configuration_summary(conf),
        system_health = _M.get_system_health_status()
    }
    
    -- Add dry-run specific information
    if conf.dry_run_mode then
        status.dry_run_info = {
            mode = "TESTING",
            description = "Plugin is in dry-run mode - threats detected but no enforcement actions executed",
            simulated_actions_count = status.dry_run_registry.summary.total_simulated_actions,
            latest_simulation = status.dry_run_registry.summary.latest_simulation
        }
    else
        status.active_mode_info = {
            mode = "ACTIVE",
            description = "Plugin is actively enforcing security policies",
            enforcement_enabled = true
        }
    end
    
    return status
end

---
-- Get configuration summary for status reporting
-- @param conf Plugin configuration
-- @return Table containing relevant configuration details
---
function _M.get_configuration_summary(conf)
    return {
        threat_threshold = conf.threat_threshold,
        dry_run_mode = conf.dry_run_mode,
        ai_gateway_enabled = conf.ai_gateway_enabled,
        enable_auto_blocking = conf.enable_auto_blocking,
        enable_rate_limiting_response = conf.enable_rate_limiting_response,
        enable_config_rollback = conf.enable_config_rollback,
        enable_notifications = conf.enable_notifications,
        admin_api_enabled = conf.admin_api_enabled,
        status_endpoint_enabled = conf.status_endpoint_enabled,
        metrics_endpoint_enabled = conf.metrics_endpoint_enabled
    }
end

---
-- Get system health status
-- @return Table containing system health information
---
function _M.get_system_health_status()
    local health = {
        status = "healthy",
        checks = {
            memory_usage = "ok",
            processing_time = "ok",
            cache_status = "ok"
        },
        uptime_seconds = ngx.time() - (kong.configuration.start_time or ngx.time()),
        worker_id = ngx.worker.id()
    }
    
    -- Add any health checks here
    -- For example, check if enforcement gate is functioning
    local enforcement_stats = enforcement_gate.get_enforcement_stats()
    if enforcement_stats.total_actions > 0 then
        health.checks.enforcement_gate = "ok"
    else
        health.checks.enforcement_gate = "not_tested"
    end
    
    return health
end

---
-- Handle dry-run metrics endpoint requests
-- @param conf Plugin configuration
-- @return HTTP response with detailed metrics
---
function _M.handle_metrics_request(conf)
    -- Check if metrics endpoint is enabled
    if not conf.metrics_endpoint_enabled then
        return kong.response.exit(404, {
            error = "Metrics endpoint disabled",
            message = "Enable metrics_endpoint_enabled in plugin configuration"
        })
    end
    
    -- Get current request path
    local request_path = kong.request.get_path()
    local metrics_path = conf.metrics_endpoint_path or "/_guard_ai/metrics"
    
    -- Only handle requests to the metrics endpoint
    if not request_path:match(metrics_path) then
        return nil -- Let other handlers process the request
    end
    
    -- Generate metrics response
    local metrics_response = _M.generate_metrics_response(conf)
    
    -- Set appropriate headers
    kong.response.set_header("Content-Type", "application/json")
    kong.response.set_header("X-Kong-Guard-AI-Metrics", "ok")
    
    -- Return metrics response
    return kong.response.exit(200, metrics_response)
end

---
-- Generate detailed metrics response
-- @param conf Plugin configuration
-- @return Table containing metrics information
---
function _M.generate_metrics_response(conf)
    local metrics = {
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),
        plugin_mode = conf.dry_run_mode and "dry_run" or "active",
        enforcement_metrics = enforcement_gate.get_enforcement_stats()
    }
    
    -- Add HTTP method filtering metrics (PHASE 4)
    if conf.enable_method_filtering then
        metrics.method_filtering = method_filter.get_method_analytics()
        metrics.method_config = method_filter.get_config_summary()
    end
    
    -- Add dry-run specific metrics
    if conf.dry_run_mode then
        local dry_run_registry = enforcement_gate.get_dry_run_registry()
        metrics.dry_run_metrics = {
            total_simulated_actions = dry_run_registry.summary.total_simulated_actions,
            simulated_action_types = dry_run_registry.summary.action_types,
            actions_by_type = {},
            recent_simulations = _M.get_recent_simulations(dry_run_registry, 10)
        }
        
        -- Count actions by type
        for action_type, actions in pairs(dry_run_registry.actions) do
            metrics.dry_run_metrics.actions_by_type[action_type] = #actions
        end
    end
    
    return metrics
end

---
-- Get recent simulations for metrics
-- @param dry_run_registry Dry-run registry data
-- @param limit Maximum number of simulations to return
-- @return Array of recent simulation summaries
---
function _M.get_recent_simulations(dry_run_registry, limit)
    local simulations = {}
    local count = 0
    
    -- Collect all simulations with timestamps
    for action_type, actions in pairs(dry_run_registry.actions) do
        for _, action in ipairs(actions) do
            table.insert(simulations, {
                action_type = action_type,
                timestamp = action.timestamp,
                request_id = action.request_id,
                summary = action.simulation and action.simulation.impact_assessment or "No details"
            })
            count = count + 1
        end
    end
    
    -- Sort by timestamp (most recent first)
    table.sort(simulations, function(a, b)
        return a.timestamp > b.timestamp
    end)
    
    -- Return limited results
    local result = {}
    for i = 1, math.min(limit, #simulations) do
        table.insert(result, simulations[i])
    end
    
    return result
end

---
-- Generate Prometheus-style metrics output
-- @param conf Plugin configuration
-- @return String containing Prometheus metrics
---
function _M.generate_prometheus_metrics(conf)
    local enforcement_stats = enforcement_gate.get_enforcement_stats()
    local dry_run_registry = enforcement_gate.get_dry_run_registry()
    
    local metrics_lines = {
        "# HELP kong_guard_ai_total_actions Total number of enforcement actions processed",
        "# TYPE kong_guard_ai_total_actions counter",
        string.format("kong_guard_ai_total_actions %d", enforcement_stats.total_actions),
        "",
        "# HELP kong_guard_ai_dry_run_actions Number of actions simulated in dry-run mode",
        "# TYPE kong_guard_ai_dry_run_actions counter",
        string.format("kong_guard_ai_dry_run_actions %d", enforcement_stats.dry_run_actions),
        "",
        "# HELP kong_guard_ai_actual_actions Number of actual enforcement actions executed",
        "# TYPE kong_guard_ai_actual_actions counter",
        string.format("kong_guard_ai_actual_actions %d", enforcement_stats.actual_actions),
        "",
        "# HELP kong_guard_ai_blocked_actions Number of enforcement actions that failed",
        "# TYPE kong_guard_ai_blocked_actions counter",
        string.format("kong_guard_ai_blocked_actions %d", enforcement_stats.blocked_actions),
        "",
        "# HELP kong_guard_ai_dry_run_mode Current dry-run mode status (1=dry-run, 0=active)",
        "# TYPE kong_guard_ai_dry_run_mode gauge",
        string.format("kong_guard_ai_dry_run_mode %d", conf.dry_run_mode and 1 or 0)
    }
    
    -- Add per-action-type metrics for dry-run mode
    if conf.dry_run_mode then
        table.insert(metrics_lines, "")
        table.insert(metrics_lines, "# HELP kong_guard_ai_simulated_actions_by_type Number of simulated actions by type")
        table.insert(metrics_lines, "# TYPE kong_guard_ai_simulated_actions_by_type counter")
        
        for action_type, actions in pairs(dry_run_registry.actions) do
            table.insert(metrics_lines, string.format(
                'kong_guard_ai_simulated_actions_by_type{action_type="%s"} %d',
                action_type, #actions
            ))
        end
    end
    
    return table.concat(metrics_lines, "\n")
end

---
-- Handle Prometheus metrics endpoint
-- @param conf Plugin configuration
-- @return HTTP response with Prometheus metrics
---
function _M.handle_prometheus_request(conf)
    local request_path = kong.request.get_path()
    
    -- Check for Prometheus metrics path
    if not request_path:match("/_guard_ai/prometheus") then
        return nil
    end
    
    local prometheus_metrics = _M.generate_prometheus_metrics(conf)
    
    kong.response.set_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
    kong.response.set_header("X-Kong-Guard-AI-Prometheus", "ok")
    
    return kong.response.exit(200, prometheus_metrics)
end

---
-- Initialize status endpoints in access phase
-- @param conf Plugin configuration
-- @return Boolean indicating if request was handled
---
function _M.handle_status_endpoints(conf)
    -- Handle status endpoint
    local status_result = _M.handle_status_request(conf)
    if status_result then
        return true
    end
    
    -- Handle metrics endpoint
    local metrics_result = _M.handle_metrics_request(conf)
    if metrics_result then
        return true
    end
    
    -- Handle Prometheus endpoint
    local prometheus_result = _M.handle_prometheus_request(conf)
    if prometheus_result then
        return true
    end
    
    return false -- Request not handled by status endpoints
end

return _M