-- Kong Guard AI - HTTP Method Filter Test Module
-- Demonstrates and validates HTTP method filtering functionality
-- Tests O(1) lookup performance and security blocking

local kong = kong
local method_filter = require "kong.plugins.kong-guard-ai.method_filter"

local _M = {}

---
-- Test HTTP method filtering endpoint handler
-- @param conf Plugin configuration
-- @return Boolean indicating if request was handled
---
function _M.handle_test_endpoint(conf)
    -- Only handle test requests when in development/testing environments
    if not conf.enable_testing_endpoints then
        return false
    end
    
    local request_path = kong.request.get_path()
    local test_path = "/_guard_ai/test/method_filter"
    
    -- Check if this is a method filter test request
    if not request_path:match(test_path) then
        return false
    end
    
    kong.log.info("[Kong Guard AI Method Filter Test] Processing test request")
    
    -- Get the HTTP method from the current request
    local current_method = kong.request.get_method()
    
    -- Create mock request context for testing
    local test_request_context = {
        method = current_method,
        path = request_path,
        client_ip = kong.client.get_ip(),
        service_id = "test_service",
        route_id = "test_route",
        correlation_id = "test_" .. ngx.now()
    }
    
    -- Test method analysis
    local method_result = method_filter.analyze_method(current_method, test_request_context, conf)
    
    -- Get method analytics
    local analytics = method_filter.get_method_analytics()
    
    -- Get configuration summary
    local config_summary = method_filter.get_config_summary()
    
    -- Prepare test response
    local test_response = {
        test_info = {
            endpoint = test_path,
            timestamp = ngx.now(),
            iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.now()),
            tested_method = current_method
        },
        method_analysis = {
            threat_level = method_result.threat_level,
            threat_type = method_result.threat_type,
            confidence = method_result.confidence,
            recommended_action = method_result.recommended_action,
            details = method_result.details
        },
        configuration = config_summary,
        analytics = analytics,
        test_scenarios = _M.generate_test_scenarios(conf)
    }
    
    -- Set response headers
    kong.response.set_header("Content-Type", "application/json")
    kong.response.set_header("X-Kong-Guard-AI-Test", "method-filter")
    
    -- Return test response
    return kong.response.exit(200, test_response)
end

---
-- Generate test scenarios for different HTTP methods
-- @param conf Plugin configuration
-- @return Table containing test scenario information
---
function _M.generate_test_scenarios(conf)
    local test_methods = {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
        "TRACE", "CONNECT", "DEBUG", "TRACK", 
        "PATCH", "PURGE", "LOCK", "UNLOCK"
    }
    
    local scenarios = {}
    
    for _, method in ipairs(test_methods) do
        local mock_context = {
            method = method,
            path = "/_guard_ai/test/method_filter",
            client_ip = "127.0.0.1"
        }
        
        local result = method_filter.analyze_method(method, mock_context, conf)
        
        scenarios[method] = {
            would_block = result.recommended_action == "block",
            threat_level = result.threat_level,
            threat_type = result.threat_type,
            is_denied = result.details.is_denied or false,
            bypass_available = result.details.bypass_used or false
        }
    end
    
    return scenarios
end

---
-- Benchmark HTTP method filtering performance
-- @param conf Plugin configuration
-- @return Table containing performance metrics
---
function _M.benchmark_method_filtering(conf)
    local iterations = 10000
    local test_methods = {"GET", "POST", "TRACE", "CONNECT", "DEBUG"}
    local results = {}
    
    for _, method in ipairs(test_methods) do
        local mock_context = {
            method = method,
            path = "/api/test",
            client_ip = "203.0.113.100"
        }
        
        local start_time = ngx.now()
        
        for i = 1, iterations do
            method_filter.analyze_method(method, mock_context, conf)
        end
        
        local end_time = ngx.now()
        local total_time_ms = (end_time - start_time) * 1000
        local avg_time_microseconds = (total_time_ms * 1000) / iterations
        
        results[method] = {
            iterations = iterations,
            total_time_ms = total_time_ms,
            avg_time_microseconds = avg_time_microseconds,
            operations_per_second = iterations / (total_time_ms / 1000)
        }
    end
    
    return {
        benchmark_info = {
            timestamp = ngx.now(),
            test_note = "Performance test for O(1) HTTP method lookup",
            iterations_per_method = iterations
        },
        method_performance = results,
        performance_summary = {
            fastest_method = _M.find_fastest_method(results),
            slowest_method = _M.find_slowest_method(results),
            average_microseconds = _M.calculate_average_time(results)
        }
    }
end

---
-- Find the fastest tested method
-- @param results Performance test results
-- @return String method name and time
---
function _M.find_fastest_method(results)
    local fastest = nil
    local fastest_time = math.huge
    
    for method, data in pairs(results) do
        if data.avg_time_microseconds < fastest_time then
            fastest_time = data.avg_time_microseconds
            fastest = method
        end
    end
    
    return {
        method = fastest,
        avg_time_microseconds = fastest_time
    }
end

---
-- Find the slowest tested method
-- @param results Performance test results
-- @return String method name and time
---
function _M.find_slowest_method(results)
    local slowest = nil
    local slowest_time = 0
    
    for method, data in pairs(results) do
        if data.avg_time_microseconds > slowest_time then
            slowest_time = data.avg_time_microseconds
            slowest = method
        end
    end
    
    return {
        method = slowest,
        avg_time_microseconds = slowest_time
    }
end

---
-- Calculate average performance across all methods
-- @param results Performance test results
-- @return Number average time in microseconds
---
function _M.calculate_average_time(results)
    local total_time = 0
    local count = 0
    
    for _, data in pairs(results) do
        total_time = total_time + data.avg_time_microseconds
        count = count + 1
    end
    
    return count > 0 and (total_time / count) or 0
end

---
-- Handle method filter analytics endpoint
-- @param conf Plugin configuration
-- @return Boolean indicating if request was handled
---
function _M.handle_analytics_endpoint(conf)
    if not conf.enable_testing_endpoints or not conf.method_analytics_enabled then
        return false
    end
    
    local request_path = kong.request.get_path()
    local analytics_path = "/_guard_ai/analytics/method_filter"
    
    if not request_path:match(analytics_path) then
        return false
    end
    
    -- Get comprehensive analytics
    local analytics = method_filter.get_method_analytics()
    
    -- Add real-time statistics
    local enhanced_analytics = {
        timestamp = ngx.now(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.now()),
        method_analytics = analytics,
        configuration = method_filter.get_config_summary(),
        security_insights = _M.generate_security_insights(analytics),
        recommendations = _M.generate_security_recommendations(analytics, conf)
    }
    
    kong.response.set_header("Content-Type", "application/json")
    kong.response.set_header("X-Kong-Guard-AI-Analytics", "method-filter")
    
    return kong.response.exit(200, enhanced_analytics)
end

---
-- Generate security insights from analytics data
-- @param analytics Method filtering analytics
-- @return Table containing security insights
---
function _M.generate_security_insights(analytics)
    local insights = {
        security_posture = "unknown",
        threat_indicators = {},
        attack_patterns = {},
        recommendations = {}
    }
    
    -- Analyze security posture
    if analytics.total_blocks == 0 then
        insights.security_posture = "clean"
        insights.threat_indicators.no_blocked_methods = true
    elseif analytics.blocks_per_hour < 1 then
        insights.security_posture = "low_risk"
    elseif analytics.blocks_per_hour < 10 then
        insights.security_posture = "moderate_risk"
    else
        insights.security_posture = "high_risk"
        insights.threat_indicators.high_block_rate = true
    end
    
    -- Analyze attack patterns
    if analytics.threat_patterns then
        if next(analytics.threat_patterns.high_frequency_attacks) then
            insights.attack_patterns.high_frequency_detected = true
            insights.threat_indicators.automated_attacks = true
        end
        
        if next(analytics.threat_patterns.distributed_sources) then
            insights.attack_patterns.distributed_attacks = true
            insights.threat_indicators.coordinated_attacks = true
        end
        
        if next(analytics.threat_patterns.suspicious_timing) then
            insights.attack_patterns.recent_spike = true
            insights.threat_indicators.active_threat = true
        end
    end
    
    return insights
end

---
-- Generate security recommendations based on analytics
-- @param analytics Method filtering analytics
-- @param conf Plugin configuration
-- @return Array of recommendation strings
---
function _M.generate_security_recommendations(analytics, conf)
    local recommendations = {}
    
    -- Configuration recommendations
    if not conf.block_extended_methods and analytics.total_blocks > 0 then
        table.insert(recommendations, "Consider enabling block_extended_methods for enhanced security")
    end
    
    if not conf.method_rate_limiting and analytics.blocks_per_hour > 5 then
        table.insert(recommendations, "Enable method_rate_limiting to slow down attack attempts")
    end
    
    -- Security recommendations based on patterns
    if analytics.threat_patterns and analytics.threat_patterns.high_frequency_attacks then
        table.insert(recommendations, "High frequency method attacks detected - review IP blocking policies")
    end
    
    if analytics.threat_patterns and analytics.threat_patterns.distributed_sources then
        table.insert(recommendations, "Distributed method attacks detected - consider geo-blocking or enhanced IP reputation")
    end
    
    -- Performance recommendations
    if analytics.denied_methods_count > 20 then
        table.insert(recommendations, "Large denied methods list may impact performance - review necessity")
    end
    
    return recommendations
end

return _M