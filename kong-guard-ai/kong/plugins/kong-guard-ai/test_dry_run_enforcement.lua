-- Kong Guard AI - Dry-Run Enforcement Testing Module
-- Test suite for validating dry-run mode enforcement gates
-- Ensures all enforcement paths respect the dry_run flag

local kong = kong
local enforcement_gate = require "kong.plugins.kong-guard-ai.enforcement_gate"
local method_filter = require "kong.plugins.kong-guard-ai.method_filter"
local test_method_filter = require "kong.plugins.kong-guard-ai.test_method_filter"
local json = require "cjson.safe"

local _M = {}

-- Test configuration for dry-run mode
local test_conf_dry_run = {
    dry_run_mode = true,
    threat_threshold = 5.0,
    enable_auto_blocking = true,
    enable_rate_limiting_response = true,
    enable_config_rollback = true,
    admin_api_enabled = true,
    block_duration_seconds = 3600,
    enable_method_filtering = true,
    block_extended_methods = true,
    method_analytics_enabled = true,
    enable_testing_endpoints = true
}

-- Test configuration for active mode
local test_conf_active = {
    dry_run_mode = false,
    threat_threshold = 5.0,
    enable_auto_blocking = true,
    enable_rate_limiting_response = true,
    enable_config_rollback = true,
    admin_api_enabled = true,
    block_duration_seconds = 3600,
    enable_method_filtering = true,
    block_extended_methods = true,
    method_analytics_enabled = true,
    enable_testing_endpoints = true
}

-- Test results storage
local test_results = {
    total_tests = 0,
    passed_tests = 0,
    failed_tests = 0,
    test_details = {}
}

---
-- Run comprehensive dry-run enforcement test suite
-- @return Table containing test results
---
function _M.run_test_suite()
    kong.log.info("[Kong Guard AI Test] Starting dry-run enforcement test suite")
    
    -- Reset test results
    test_results = {
        total_tests = 0,
        passed_tests = 0,
        failed_tests = 0,
        test_details = {}
    }
    
    -- Test 1: Block request in dry-run mode
    _M.test_block_request_dry_run()
    
    -- Test 2: Block request in active mode
    _M.test_block_request_active()
    
    -- Test 3: Rate limiting in dry-run mode
    _M.test_rate_limiting_dry_run()
    
    -- Test 4: Rate limiting in active mode
    _M.test_rate_limiting_active()
    
    -- Test 5: IP blocking in dry-run mode
    _M.test_ip_blocking_dry_run()
    
    -- Test 6: IP blocking in active mode
    _M.test_ip_blocking_active()
    
    -- Test 7: Config rollback in dry-run mode
    _M.test_config_rollback_dry_run()
    
    -- Test 8: Config rollback in active mode
    _M.test_config_rollback_active()
    
    -- Test 9: Notification in dry-run mode
    _M.test_notification_dry_run()
    
    -- Test 10: Admin API call in dry-run mode
    _M.test_admin_api_dry_run()
    
    -- Log test summary
    _M.log_test_summary()
    
    return test_results
end

---
-- Test block request enforcement in dry-run mode
---
function _M.test_block_request_dry_run()
    local test_name = "Block Request - Dry Run Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        client_ip = "203.0.113.100",
        reason = "test_threat",
        threat_level = 8
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.BLOCK_REQUEST,
        action_data,
        test_conf_dry_run,
        function(data, conf)
            -- This should not execute in dry-run mode
            return { executed = true, action = "request_blocked" }
        end
    )
    
    -- Validate results
    local success = result.dry_run_mode == true and 
                   result.simulated == true and 
                   result.executed == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test block request enforcement in active mode
---
function _M.test_block_request_active()
    local test_name = "Block Request - Active Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        client_ip = "203.0.113.100",
        reason = "test_threat",
        threat_level = 8
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.BLOCK_REQUEST,
        action_data,
        test_conf_active,
        function(data, conf)
            -- This should execute in active mode
            return { executed = true, action = "request_blocked" }
        end
    )
    
    -- Validate results
    local success = result.dry_run_mode == false and 
                   result.executed == true and 
                   result.simulated == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test rate limiting enforcement in dry-run mode
---
function _M.test_rate_limiting_dry_run()
    local test_name = "Rate Limiting - Dry Run Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        client_ip = "203.0.113.101",
        rate_limit = 50,
        service_id = "test-service"
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.RATE_LIMIT,
        action_data,
        test_conf_dry_run,
        function(data, conf)
            return { rate_limit_applied = true, limit = data.rate_limit }
        end
    )
    
    -- Validate results
    local success = result.dry_run_mode == true and 
                   result.simulated == true and 
                   result.executed == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test rate limiting enforcement in active mode
---
function _M.test_rate_limiting_active()
    local test_name = "Rate Limiting - Active Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        client_ip = "203.0.113.101",
        rate_limit = 50,
        service_id = "test-service"
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.RATE_LIMIT,
        action_data,
        test_conf_active,
        function(data, conf)
            return { rate_limit_applied = true, limit = data.rate_limit }
        end
    )
    
    -- Validate results
    local success = result.dry_run_mode == false and 
                   result.executed == true
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test IP blocking enforcement in dry-run mode
---
function _M.test_ip_blocking_dry_run()
    local test_name = "IP Blocking - Dry Run Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        ip_address = "198.51.100.50",
        duration = 3600,
        reason = "automated_threat_response"
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.BLOCK_IP,
        action_data,
        test_conf_dry_run,
        function(data, conf)
            return { ip_blocked = true, ip = data.ip_address, duration = data.duration }
        end
    )
    
    -- Validate results
    local success = result.simulated == true and result.executed == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test IP blocking enforcement in active mode
---
function _M.test_ip_blocking_active()
    local test_name = "IP Blocking - Active Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        ip_address = "198.51.100.50",
        duration = 3600,
        reason = "automated_threat_response"
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.BLOCK_IP,
        action_data,
        test_conf_active,
        function(data, conf)
            return { ip_blocked = true, ip = data.ip_address, duration = data.duration }
        end
    )
    
    -- Validate results
    local success = result.executed == true and result.simulated == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test config rollback enforcement in dry-run mode
---
function _M.test_config_rollback_dry_run()
    local test_name = "Config Rollback - Dry Run Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        threat_result = { threat_level = 9, threat_type = "critical_attack" },
        rollback_reason = "critical_threat_detected"
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.CONFIG_ROLLBACK,
        action_data,
        test_conf_dry_run,
        function(data, conf)
            return { config_rolled_back = true, previous_version = "v1.2.3" }
        end
    )
    
    -- Validate results
    local success = result.simulated == true and result.executed == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test config rollback enforcement in active mode
---
function _M.test_config_rollback_active()
    local test_name = "Config Rollback - Active Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        threat_result = { threat_level = 9, threat_type = "critical_attack" },
        rollback_reason = "critical_threat_detected"
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.CONFIG_ROLLBACK,
        action_data,
        test_conf_active,
        function(data, conf)
            return { config_rolled_back = true, previous_version = "v1.2.3" }
        end
    )
    
    -- Validate results
    local success = result.executed == true and result.simulated == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test notification enforcement in dry-run mode
---
function _M.test_notification_dry_run()
    local test_name = "Notification - Dry Run Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        threat_result = { threat_type = "sql_injection", threat_level = 7 },
        notification_type = "threat_detected",
        channel = "slack"
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.NOTIFICATION,
        action_data,
        test_conf_dry_run,
        function(data, conf)
            return { notification_sent = true, channel = data.channel }
        end
    )
    
    -- Validate results
    local success = result.simulated == true and result.executed == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Test Admin API call enforcement in dry-run mode
---
function _M.test_admin_api_dry_run()
    local test_name = "Admin API Call - Dry Run Mode"
    kong.log.info("[Kong Guard AI Test] Running: " .. test_name)
    
    local action_types = enforcement_gate.get_action_types()
    local action_data = {
        method = "POST",
        endpoint = "/plugins",
        payload = { name = "rate-limiting", config = { minute = 100 } }
    }
    
    local result = enforcement_gate.enforce_action(
        action_types.ADMIN_API_CALL,
        action_data,
        test_conf_dry_run,
        function(data, conf)
            return { api_call_success = true, endpoint = data.endpoint }
        end
    )
    
    -- Validate results
    local success = result.simulated == true and result.executed == false
    
    _M.record_test_result(test_name, success, result)
end

---
-- Record test result
-- @param test_name Name of the test
-- @param success Boolean indicating if test passed
-- @param result Enforcement result data
---
function _M.record_test_result(test_name, success, result)
    test_results.total_tests = test_results.total_tests + 1
    
    if success then
        test_results.passed_tests = test_results.passed_tests + 1
        kong.log.info("[Kong Guard AI Test] ✅ PASSED: " .. test_name)
    else
        test_results.failed_tests = test_results.failed_tests + 1
        kong.log.error("[Kong Guard AI Test] ❌ FAILED: " .. test_name)
    end
    
    table.insert(test_results.test_details, {
        test_name = test_name,
        success = success,
        result = result,
        timestamp = ngx.time()
    })
end

---
-- Log test summary
---
function _M.log_test_summary()
    local summary = string.format(
        "[Kong Guard AI Test] Test Suite Complete: %d/%d tests passed (%.1f%% success rate)",
        test_results.passed_tests,
        test_results.total_tests,
        (test_results.passed_tests / test_results.total_tests) * 100
    )
    
    if test_results.failed_tests == 0 then
        kong.log.info(summary)
    else
        kong.log.error(summary)
        kong.log.error("[Kong Guard AI Test] Failed tests: " .. test_results.failed_tests)
    end
    
    -- Log detailed results
    kong.log.info("[Kong Guard AI Test] Detailed Results: " .. json.encode(test_results))
end

---
-- Get test results
-- @return Table containing test results
---
function _M.get_test_results()
    return test_results
end

---
-- Run tests and return results as HTTP response
-- @param conf Plugin configuration
-- @return HTTP response with test results
---
function _M.handle_test_endpoint(conf)
    local request_path = kong.request.get_path()
    
    -- Check for test endpoint path
    if not request_path:match("/_guard_ai/test") then
        return nil
    end
    
    -- Handle method filter specific test endpoints
    if request_path:match("/_guard_ai/test/method_filter") then
        return test_method_filter.handle_test_endpoint(conf)
    end
    
    if request_path:match("/_guard_ai/analytics/method_filter") then
        return test_method_filter.handle_analytics_endpoint(conf)
    end
    
    -- Run standard test suite
    local results = _M.run_test_suite()
    
    -- Prepare response
    local response = {
        test_summary = {
            total_tests = results.total_tests,
            passed_tests = results.passed_tests,
            failed_tests = results.failed_tests,
            success_rate = (results.passed_tests / results.total_tests) * 100
        },
        test_details = results.test_details,
        enforcement_stats = enforcement_gate.get_enforcement_stats(),
        dry_run_registry = enforcement_gate.get_dry_run_registry(),
        timestamp = ngx.time()
    }
    
    kong.response.set_header("Content-Type", "application/json")
    kong.response.set_header("X-Kong-Guard-AI-Test", "complete")
    
    local status_code = results.failed_tests == 0 and 200 or 500
    return kong.response.exit(status_code, response)
end

return _M