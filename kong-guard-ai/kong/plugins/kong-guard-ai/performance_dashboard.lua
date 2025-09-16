-- Kong Guard AI - Performance Monitoring Dashboard
-- Provides real-time performance metrics and monitoring capabilities
-- Exposes performance data via HTTP endpoints for external monitoring systems
--
-- Author: Performance Optimization Specialist Agent
-- Phase: 3 - Performance Optimization & Monitoring
--
-- FEATURES:
-- - Real-time performance metrics collection
-- - Circuit breaker status monitoring
-- - Memory usage tracking and alerts
-- - Performance trend analysis
-- - Integration with external monitoring systems

local kong = kong
local json = require "cjson.safe"
local performance_optimizer = require "kong.plugins.kong-guard-ai.performance_optimizer"
local path_filter = require "kong.plugins.kong-guard-ai.path_filter"

local _M = {}

-- Dashboard configuration
local DASHBOARD_CONFIG = {
    ENDPOINT_PATH = "/_guard_ai/performance",
    METRICS_ENDPOINT = "/_guard_ai/metrics",
    HEALTH_ENDPOINT = "/_guard_ai/health",
    REFRESH_INTERVAL_SECONDS = 30,
    METRICS_RETENTION_MINUTES = 60,
    ALERT_THRESHOLD_MS = 8,        -- Alert when average exceeds 8ms
    CRITICAL_THRESHOLD_MS = 15,    -- Critical when average exceeds 15ms
    MEMORY_ALERT_THRESHOLD_MB = 100
}

-- Metrics storage for dashboard
local dashboard_metrics = {
    last_update = 0,
    performance_samples = {},
    alert_history = {},
    system_status = "healthy"
}

---
-- Initialize performance dashboard
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Dashboard] Initializing performance dashboard")

    -- Initialize dashboard metrics
    dashboard_metrics.last_update = ngx.time()
    dashboard_metrics.performance_samples = {}
    dashboard_metrics.alert_history = {}
    dashboard_metrics.system_status = "healthy"

    kong.log.info("[Kong Guard AI Dashboard] Performance dashboard initialized")
end

---
-- Handle performance dashboard requests
-- @param conf Plugin configuration
-- @return Boolean indicating if request was handled
---
function _M.handle_dashboard_request(conf)
    local request_path = kong.request.get_path()
    local request_method = kong.request.get_method()

    -- Only handle GET requests to dashboard endpoints
    if request_method ~= "GET" then
        return false
    end

    -- Handle different dashboard endpoints
    if request_path == DASHBOARD_CONFIG.ENDPOINT_PATH then
        return _M.serve_performance_dashboard(conf)
    elseif request_path == DASHBOARD_CONFIG.METRICS_ENDPOINT then
        return _M.serve_metrics_endpoint(conf)
    elseif request_path == DASHBOARD_CONFIG.HEALTH_ENDPOINT then
        return _M.serve_health_endpoint(conf)
    end

    return false
end

---
-- Serve the main performance dashboard
-- @param conf Plugin configuration
-- @return Boolean indicating success
---
function _M.serve_performance_dashboard(conf)
    kong.log.debug("[Kong Guard AI Dashboard] Serving performance dashboard")

    -- Get comprehensive performance data
    local dashboard_data = _M.get_comprehensive_dashboard_data()

    -- Generate HTML dashboard
    local html_content = _M.generate_dashboard_html(dashboard_data)

    -- Set response headers
    kong.response.set_header("Content-Type", "text/html; charset=UTF-8")
    kong.response.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
    kong.response.set_header("Pragma", "no-cache")
    kong.response.set_header("Expires", "0")

    -- Send response
    kong.response.exit(200, html_content)

    return true
end

---
-- Serve metrics endpoint (JSON format for monitoring systems)
-- @param conf Plugin configuration
-- @return Boolean indicating success
---
function _M.serve_metrics_endpoint(conf)
    kong.log.debug("[Kong Guard AI Dashboard] Serving metrics endpoint")

    -- Get performance data from optimizer
    local performance_data = performance_optimizer.get_performance_dashboard_data()
    local recommendations = performance_optimizer.get_optimization_recommendations()

    -- Combine with dashboard-specific metrics
    local metrics_response = {
        timestamp = ngx.time(),
        performance = performance_data,
        recommendations = recommendations,
        dashboard_status = dashboard_metrics.system_status,
        uptime_seconds = ngx.time() - dashboard_metrics.last_update,
        version = "0.1.0"
    }

    -- Set JSON response headers
    kong.response.set_header("Content-Type", "application/json")
    kong.response.set_header("Cache-Control", "no-cache")

    -- Send JSON response
    kong.response.exit(200, json.encode(metrics_response))

    return true
end

---
-- Serve health endpoint (simple health check)
-- @param conf Plugin configuration
-- @return Boolean indicating success
---
function _M.serve_health_endpoint(conf)
    kong.log.debug("[Kong Guard AI Dashboard] Serving health endpoint")

    -- Get basic health status
    local performance_data = performance_optimizer.get_performance_dashboard_data()

    -- Determine health status
    local health_status = "healthy"
    local health_details = {}

    -- Check performance thresholds
    if performance_data.request_metrics.avg_processing_time_ms > DASHBOARD_CONFIG.CRITICAL_THRESHOLD_MS then
        health_status = "critical"
        table.insert(health_details, "Average processing time exceeds critical threshold")
    elseif performance_data.request_metrics.avg_processing_time_ms > DASHBOARD_CONFIG.ALERT_THRESHOLD_MS then
        health_status = "warning"
        table.insert(health_details, "Average processing time exceeds alert threshold")
    end

    -- Check circuit breaker status
    if performance_data.circuit_breaker.state ~= "closed" then
        health_status = health_status == "critical" and "critical" or "warning"
        table.insert(health_details, "Circuit breaker is " .. performance_data.circuit_breaker.state)
    end

    -- Check memory usage
    if performance_data.memory_metrics.memory_growth_kb > DASHBOARD_CONFIG.MEMORY_ALERT_THRESHOLD_MB * 1024 then
        health_status = health_status == "critical" and "critical" or "warning"
        table.insert(health_details, "Memory usage has grown significantly")
    end

    local health_response = {
        status = health_status,
        timestamp = ngx.time(),
        details = health_details,
        performance_summary = {
            avg_processing_time_ms = performance_data.request_metrics.avg_processing_time_ms,
            circuit_breaker_state = performance_data.circuit_breaker.state,
            memory_growth_kb = performance_data.memory_metrics.memory_growth_kb
        }
    }

    -- Set appropriate HTTP status code
    local http_status = 200
    if health_status == "critical" then
        http_status = 503 -- Service Unavailable
    elseif health_status == "warning" then
        http_status = 200 -- Still OK, but with warnings
    end

    kong.response.set_header("Content-Type", "application/json")
    kong.response.exit(http_status, json.encode(health_response))

    return true
end

---
-- Get comprehensive dashboard data
-- @return Table containing all dashboard data
---
function _M.get_comprehensive_dashboard_data()
    -- Get performance data from optimizer
    local performance_data = performance_optimizer.get_performance_dashboard_data()
    local recommendations = performance_optimizer.get_optimization_recommendations()

    -- PHASE 4: Get path filter analytics
    local path_filter_analytics = path_filter.get_analytics()

    -- Update dashboard metrics
    _M.update_dashboard_metrics(performance_data)

    return {
        timestamp = ngx.time(),
        performance = performance_data,
        recommendations = recommendations,
        trends = dashboard_metrics.performance_samples,
        alerts = dashboard_metrics.alert_history,
        system_status = dashboard_metrics.system_status,
        path_filtering = {
            analytics = path_filter_analytics,
            pattern_count = path_filter.get_pattern_count(),
            enabled = true -- This will be updated based on actual config in handler
        },
        config = DASHBOARD_CONFIG
    }
end

---
-- Update dashboard-specific metrics
-- @param performance_data Current performance data
---
function _M.update_dashboard_metrics(performance_data)
    local current_time = ngx.time()

    -- Add current performance sample
    table.insert(dashboard_metrics.performance_samples, {
        timestamp = current_time,
        avg_processing_time_ms = performance_data.request_metrics.avg_processing_time_ms,
        memory_usage_kb = performance_data.memory_metrics.current_memory_kb,
        circuit_breaker_state = performance_data.circuit_breaker.state,
        cpu_usage_percent = performance_data.cpu_metrics.current_cpu_percent
    })

    -- Keep only recent samples (last 60 minutes)
    local cutoff_time = current_time - (DASHBOARD_CONFIG.METRICS_RETENTION_MINUTES * 60)
    local filtered_samples = {}
    for _, sample in ipairs(dashboard_metrics.performance_samples) do
        if sample.timestamp >= cutoff_time then
            table.insert(filtered_samples, sample)
        end
    end
    dashboard_metrics.performance_samples = filtered_samples

    -- Check for new alerts
    _M.check_and_record_alerts(performance_data)

    -- Update system status
    dashboard_metrics.system_status = _M.determine_system_status(performance_data)
    dashboard_metrics.last_update = current_time
end

---
-- Check for alerts and record them
-- @param performance_data Current performance data
---
function _M.check_and_record_alerts(performance_data)
    local current_time = ngx.time()
    local alerts = {}

    -- Check processing time alerts
    if performance_data.request_metrics.avg_processing_time_ms > DASHBOARD_CONFIG.CRITICAL_THRESHOLD_MS then
        table.insert(alerts, {
            type = "performance",
            severity = "critical",
            message = "Average processing time critically high",
            value = performance_data.request_metrics.avg_processing_time_ms,
            threshold = DASHBOARD_CONFIG.CRITICAL_THRESHOLD_MS
        })
    elseif performance_data.request_metrics.avg_processing_time_ms > DASHBOARD_CONFIG.ALERT_THRESHOLD_MS then
        table.insert(alerts, {
            type = "performance",
            severity = "warning",
            message = "Average processing time elevated",
            value = performance_data.request_metrics.avg_processing_time_ms,
            threshold = DASHBOARD_CONFIG.ALERT_THRESHOLD_MS
        })
    end

    -- Check circuit breaker alerts
    if performance_data.circuit_breaker.state == "open" then
        table.insert(alerts, {
            type = "circuit_breaker",
            severity = "critical",
            message = "Circuit breaker is open",
            value = performance_data.circuit_breaker.state,
            failure_count = performance_data.circuit_breaker.failure_count
        })
    elseif performance_data.circuit_breaker.state == "half-open" then
        table.insert(alerts, {
            type = "circuit_breaker",
            severity = "warning",
            message = "Circuit breaker is half-open",
            value = performance_data.circuit_breaker.state,
            failure_count = performance_data.circuit_breaker.failure_count
        })
    end

    -- Check memory alerts
    if performance_data.memory_metrics.memory_growth_kb > DASHBOARD_CONFIG.MEMORY_ALERT_THRESHOLD_MB * 1024 then
        table.insert(alerts, {
            type = "memory",
            severity = "warning",
            message = "Memory usage has grown significantly",
            value = performance_data.memory_metrics.memory_growth_kb,
            threshold = DASHBOARD_CONFIG.MEMORY_ALERT_THRESHOLD_MB * 1024
        })
    end

    -- Record new alerts
    for _, alert in ipairs(alerts) do
        alert.timestamp = current_time
        table.insert(dashboard_metrics.alert_history, alert)
    end

    -- Keep only recent alerts (last 24 hours)
    local cutoff_time = current_time - (24 * 60 * 60)
    local filtered_alerts = {}
    for _, alert in ipairs(dashboard_metrics.alert_history) do
        if alert.timestamp >= cutoff_time then
            table.insert(filtered_alerts, alert)
        end
    end
    dashboard_metrics.alert_history = filtered_alerts
end

---
-- Determine overall system status
-- @param performance_data Current performance data
-- @return String system status
---
function _M.determine_system_status(performance_data)
    -- Check for critical conditions
    if performance_data.circuit_breaker.state == "open" then
        return "critical"
    end

    if performance_data.request_metrics.avg_processing_time_ms > DASHBOARD_CONFIG.CRITICAL_THRESHOLD_MS then
        return "critical"
    end

    -- Check for warning conditions
    if performance_data.circuit_breaker.state == "half-open" then
        return "warning"
    end

    if performance_data.request_metrics.avg_processing_time_ms > DASHBOARD_CONFIG.ALERT_THRESHOLD_MS then
        return "warning"
    end

    if performance_data.memory_metrics.memory_growth_kb > DASHBOARD_CONFIG.MEMORY_ALERT_THRESHOLD_MB * 1024 then
        return "warning"
    end

    return "healthy"
end

---
-- Generate HTML dashboard content
-- @param dashboard_data Complete dashboard data
-- @return String HTML content
---
function _M.generate_dashboard_html(dashboard_data)
    local status_color = dashboard_data.system_status == "healthy" and "green" or
                        dashboard_data.system_status == "warning" and "orange" or "red"

    local html = [[
<!DOCTYPE html>
<html>
<head>
    <title>Kong Guard AI - Performance Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .status { display: inline-block; padding: 5px 15px; border-radius: 15px; color: white; font-weight: bold; }
        .healthy { background-color: green; }
        .warning { background-color: orange; }
        .critical { background-color: red; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .metric-label { font-size: 0.9em; color: #7f8c8d; }
        .alert { padding: 10px; margin: 5px 0; border-radius: 4px; }
        .alert-critical { background-color: #ffebee; border-left: 4px solid #f44336; }
        .alert-warning { background-color: #fff3e0; border-left: 4px solid #ff9800; }
        .recommendations { background-color: #e8f5e8; border-left: 4px solid #4caf50; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .refresh-info { text-align: center; color: #7f8c8d; margin-top: 20px; }
    </style>
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(function() { location.reload(); }, 30000);
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Kong Guard AI - Performance Dashboard</h1>
            <p>Real-time performance monitoring and optimization</p>
            <span class="status ]] .. dashboard_data.system_status .. [[">]] .. dashboard_data.system_status:upper() .. [[</span>
            <span style="float: right;">Last Updated: ]] .. os.date("%Y-%m-%d %H:%M:%S", dashboard_data.timestamp) .. [[</span>
        </div>

        <div class="card">
            <h2>Performance Metrics</h2>
            <div class="metric">
                <div class="metric-value">]] .. string.format("%.2f", dashboard_data.performance.request_metrics.avg_processing_time_ms) .. [[ms</div>
                <div class="metric-label">Average Processing Time</div>
            </div>
            <div class="metric">
                <div class="metric-value">]] .. dashboard_data.performance.request_metrics.total_requests .. [[</div>
                <div class="metric-label">Total Requests</div>
            </div>
            <div class="metric">
                <div class="metric-value">]] .. string.format("%.1f", dashboard_data.performance.memory_metrics.current_memory_kb / 1024) .. [[MB</div>
                <div class="metric-label">Current Memory</div>
            </div>
            <div class="metric">
                <div class="metric-value">]] .. string.format("%.1f", dashboard_data.performance.cpu_metrics.current_cpu_percent) .. [[%</div>
                <div class="metric-label">CPU Usage</div>
            </div>
        </div>

        <div class="card">
            <h2>Circuit Breaker Status</h2>
            <p><strong>State:</strong> ]] .. dashboard_data.performance.circuit_breaker.state:upper() .. [[</p>
            <p><strong>Failure Count:</strong> ]] .. dashboard_data.performance.circuit_breaker.failure_count .. [[</p>
        </div>
]]

    -- Add alerts section if there are any
    if #dashboard_data.alerts > 0 then
        html = html .. [[
        <div class="card">
            <h2>Recent Alerts</h2>
]]
        for _, alert in ipairs(dashboard_data.alerts) do
            local alert_class = alert.severity == "critical" and "alert-critical" or "alert-warning"
            html = html .. [[
            <div class="alert ]] .. alert_class .. [[">
                <strong>]] .. alert.type:upper() .. [[:</strong> ]] .. alert.message .. [[
                <span style="float: right;">]] .. os.date("%H:%M:%S", alert.timestamp) .. [[</span>
            </div>
]]
        end
        html = html .. [[
        </div>
]]
    end

    -- Add recommendations section
    if dashboard_data.recommendations.recommendations and #dashboard_data.recommendations.recommendations > 0 then
        html = html .. [[
        <div class="card">
            <h2>Optimization Recommendations</h2>
]]
        for _, rec in ipairs(dashboard_data.recommendations.recommendations) do
            html = html .. [[
            <div class="alert recommendations">
                <strong>]] .. rec.type:upper() .. [[:</strong> ]] .. rec.message .. [[
                <br><small>]] .. rec.suggestion .. [[</small>
            </div>
]]
        end
        html = html .. [[
        </div>
]]
    end

    html = html .. [[
        <div class="refresh-info">
            <p>Dashboard auto-refreshes every 30 seconds</p>
            <p><a href="]] .. DASHBOARD_CONFIG.METRICS_ENDPOINT .. [[">JSON Metrics</a> | <a href="]] .. DASHBOARD_CONFIG.HEALTH_ENDPOINT .. [[">Health Check</a></p>
        </div>
    </div>
</body>
</html>
]]

    return html
end

---
-- Record custom dashboard event
-- @param event_type Type of event
-- @param event_data Event data
---
function _M.record_dashboard_event(event_type, event_data)
    local event = {
        timestamp = ngx.time(),
        type = event_type,
        data = event_data
    }

    -- Log the event
    kong.log.info("[Kong Guard AI Dashboard] Event recorded: " .. event_type)
end

return _M
