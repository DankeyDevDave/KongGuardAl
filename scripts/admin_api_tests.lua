-- Kong Guard AI Admin API Compatibility Test Suite
-- Validates plugin configuration compatibility with Kong Admin API and Konnect
-- This script provides automated testing for configuration validation, enforcement, and logging consistency

local http = require "resty.http"
local cjson = require "cjson.safe"
local pl_file = require "pl.file"
local pl_utils = require "pl.utils"

local _M = {}

-- Test configuration
local KONG_ADMIN_URL = os.getenv("KONG_ADMIN_URL") or "http://localhost:8001"
local KONG_PROXY_URL = os.getenv("KONG_PROXY_URL") or "http://localhost:8000"
local TEST_SERVICE_NAME = "kong-guard-ai-test-service"
local TEST_ROUTE_NAME = "kong-guard-ai-test-route"
local PLUGIN_NAME = "kong-guard-ai"

-- Test results tracking
local test_results = {
    passed = 0,
    failed = 0,
    errors = {},
    details = {}
}

-- Utility functions
local function log_test(test_name, passed, message)
    if passed then
        test_results.passed = test_results.passed + 1
        print(string.format("✅ PASS: %s", test_name))
    else
        test_results.failed = test_results.failed + 1
        print(string.format("❌ FAIL: %s - %s", test_name, message or ""))
        table.insert(test_results.errors, {test = test_name, message = message})
    end
    
    if message then
        test_results.details[test_name] = message
    end
end

local function make_admin_request(method, path, body)
    local httpc = http.new()
    httpc:set_timeout(10000)  -- 10 second timeout
    
    local headers = {
        ["Content-Type"] = "application/json"
    }
    
    local url = KONG_ADMIN_URL .. path
    local res, err = httpc:request_uri(url, {
        method = method,
        headers = headers,
        body = body and cjson.encode(body) or nil
    })
    
    if not res then
        return nil, err
    end
    
    local response_body = {}
    if res.body then
        response_body = cjson.decode(res.body) or {}
    end
    
    return {
        status = res.status,
        body = response_body,
        headers = res.headers
    }, nil
end

local function make_proxy_request(method, path, body, headers)
    local httpc = http.new()
    httpc:set_timeout(5000)  -- 5 second timeout
    
    local request_headers = headers or {}
    if body then
        request_headers["Content-Type"] = "application/json"
    end
    
    local url = KONG_PROXY_URL .. path
    local res, err = httpc:request_uri(url, {
        method = method,
        headers = request_headers,
        body = body and cjson.encode(body) or nil
    })
    
    if not res then
        return nil, err
    end
    
    return {
        status = res.status,
        body = res.body,
        headers = res.headers
    }, nil
end

-- Configuration schema validation tests
function _M.test_schema_validation()
    print("\n🔍 Testing Configuration Schema Validation...")
    
    -- Test 1: Valid minimal configuration
    local minimal_config = {
        dry_run = true,
        log_level = "info"
    }
    
    local res, err = make_admin_request("POST", "/schemas/plugins/validate", {
        name = PLUGIN_NAME,
        config = minimal_config
    })
    
    local test_passed = res and res.status == 200
    log_test("Minimal Configuration Validation", test_passed, 
        test_passed and "Minimal config accepted" or (err or "Failed validation"))
    
    -- Test 2: Invalid configuration - invalid log_level
    local invalid_config = {
        dry_run = true,
        log_level = "invalid_level"
    }
    
    res, err = make_admin_request("POST", "/schemas/plugins/validate", {
        name = PLUGIN_NAME,
        config = invalid_config
    })
    
    test_passed = res and res.status >= 400
    log_test("Invalid Log Level Rejection", test_passed,
        test_passed and "Invalid config properly rejected" or "Invalid config was accepted")
    
    -- Test 3: Complex valid configuration
    local complex_config = {
        dry_run = false,
        log_level = "debug",
        threat_detection = {
            enabled = true,
            rules = {
                rate_limit_threshold = 50,
                suspicious_patterns = {"SELECT.*FROM", "<script"},
                blocked_ips = {"203.0.113.100"},
                blocked_user_agents = {"malicious-bot"}
            }
        },
        response_actions = {
            enabled = true,
            immediate_block = true,
            rate_limit_enforcement = true
        },
        notifications = {
            webhook_url = "http://example.com/webhook",
            notification_cooldown = 30
        }
    }
    
    res, err = make_admin_request("POST", "/schemas/plugins/validate", {
        name = PLUGIN_NAME,
        config = complex_config
    })
    
    test_passed = res and res.status == 200
    log_test("Complex Configuration Validation", test_passed,
        test_passed and "Complex config accepted" or (err or "Failed validation"))
end

-- Plugin lifecycle tests
function _M.test_plugin_lifecycle()
    print("\n🔄 Testing Plugin Lifecycle Management...")
    
    -- Clean up any existing test resources
    _M.cleanup_test_resources()
    
    -- Test 1: Create test service
    local service_config = {
        name = TEST_SERVICE_NAME,
        url = "http://httpbin.org"
    }
    
    local res, err = make_admin_request("POST", "/services", service_config)
    local test_passed = res and res.status == 201
    log_test("Test Service Creation", test_passed,
        test_passed and "Service created successfully" or (err or "Service creation failed"))
    
    if not test_passed then
        return false
    end
    
    local service_id = res.body.id
    
    -- Test 2: Create test route
    local route_config = {
        name = TEST_ROUTE_NAME,
        service = {id = service_id},
        paths = {"/test-guard-ai"}
    }
    
    res, err = make_admin_request("POST", "/routes", route_config)
    test_passed = res and res.status == 201
    log_test("Test Route Creation", test_passed,
        test_passed and "Route created successfully" or (err or "Route creation failed"))
    
    if not test_passed then
        return false
    end
    
    local route_id = res.body.id
    
    -- Test 3: Add plugin to service
    local plugin_config = {
        name = PLUGIN_NAME,
        service = {id = service_id},
        config = {
            dry_run = true,
            log_level = "info",
            threat_detection = {
                enabled = true,
                rules = {
                    rate_limit_threshold = 10,
                    suspicious_patterns = {"test-attack"}
                }
            }
        }
    }
    
    res, err = make_admin_request("POST", "/plugins", plugin_config)
    test_passed = res and res.status == 201
    log_test("Plugin Installation", test_passed,
        test_passed and "Plugin installed successfully" or (err or "Plugin installation failed"))
    
    if not test_passed then
        return false
    end
    
    local plugin_id = res.body.id
    
    -- Test 4: Update plugin configuration
    local updated_config = {
        config = {
            dry_run = false,
            log_level = "debug",
            threat_detection = {
                enabled = true,
                rules = {
                    rate_limit_threshold = 5,
                    suspicious_patterns = {"test-attack", "malicious-payload"}
                }
            }
        }
    }
    
    res, err = make_admin_request("PATCH", "/plugins/" .. plugin_id, updated_config)
    test_passed = res and res.status == 200
    log_test("Plugin Configuration Update", test_passed,
        test_passed and "Plugin updated successfully" or (err or "Plugin update failed"))
    
    -- Test 5: Verify configuration persistence
    res, err = make_admin_request("GET", "/plugins/" .. plugin_id)
    test_passed = res and res.status == 200 and res.body.config.dry_run == false
    log_test("Configuration Persistence", test_passed,
        test_passed and "Updated config persisted" or "Config not properly persisted")
    
    return true
end

-- Hot reload testing
function _M.test_configuration_hot_reload()
    print("\n🔥 Testing Configuration Hot Reload...")
    
    -- Find our test plugin instance
    local res, err = make_admin_request("GET", "/plugins")
    if not res or res.status ~= 200 then
        log_test("Hot Reload Setup", false, "Could not fetch plugins")
        return false
    end
    
    local test_plugin = nil
    for _, plugin in ipairs(res.body.data or {}) do
        if plugin.name == PLUGIN_NAME then
            test_plugin = plugin
            break
        end
    end
    
    if not test_plugin then
        log_test("Hot Reload Setup", false, "Test plugin not found")
        return false
    end
    
    -- Test 1: Change dry_run mode and verify immediate effect
    local current_dry_run = test_plugin.config.dry_run
    local new_dry_run = not current_dry_run
    
    res, err = make_admin_request("PATCH", "/plugins/" .. test_plugin.id, {
        config = {
            dry_run = new_dry_run
        }
    })
    
    local test_passed = res and res.status == 200
    log_test("Hot Reload Configuration Change", test_passed,
        test_passed and "Config changed successfully" or (err or "Config change failed"))
    
    -- Test 2: Verify the change took effect immediately (no restart required)
    res, err = make_admin_request("GET", "/plugins/" .. test_plugin.id)
    test_passed = res and res.status == 200 and res.body.config.dry_run == new_dry_run
    log_test("Hot Reload Immediate Effect", test_passed,
        test_passed and "Config change applied immediately" or "Config change requires restart")
    
    -- Test 3: Test multiple rapid configuration changes
    local rapid_changes = {
        {log_level = "debug"},
        {log_level = "info"},
        {log_level = "warn"},
        {log_level = "error"}
    }
    
    local all_changes_successful = true
    for i, change in ipairs(rapid_changes) do
        res, err = make_admin_request("PATCH", "/plugins/" .. test_plugin.id, {config = change})
        if not res or res.status ~= 200 then
            all_changes_successful = false
            break
        end
        
        -- Small delay to avoid overwhelming the system
        os.execute("sleep 0.1")
    end
    
    log_test("Rapid Configuration Changes", all_changes_successful,
        all_changes_successful and "All rapid changes successful" or "Some rapid changes failed")
end

-- Dry run mode consistency testing
function _M.test_dry_run_consistency()
    print("\n🧪 Testing Dry Run Mode Consistency...")
    
    -- Find our test plugin and ensure it's in dry run mode
    local res, err = make_admin_request("GET", "/plugins")
    if not res or res.status ~= 200 then
        log_test("Dry Run Setup", false, "Could not fetch plugins")
        return false
    end
    
    local test_plugin = nil
    for _, plugin in ipairs(res.body.data or {}) do
        if plugin.name == PLUGIN_NAME then
            test_plugin = plugin
            break
        end
    end
    
    if not test_plugin then
        log_test("Dry Run Setup", false, "Test plugin not found")
        return false
    end
    
    -- Ensure dry run mode is enabled
    res, err = make_admin_request("PATCH", "/plugins/" .. test_plugin.id, {
        config = {dry_run = true}
    })
    
    if not res or res.status ~= 200 then
        log_test("Dry Run Mode Setup", false, "Could not enable dry run mode")
        return false
    end
    
    -- Test 1: Send a potentially malicious request and verify it's not blocked
    local malicious_request_body = {
        query = "SELECT * FROM users WHERE id = 1 OR 1=1",
        script = "<script>alert('xss')</script>"
    }
    
    local proxy_res, proxy_err = make_proxy_request("POST", "/test-guard-ai/post", 
        malicious_request_body, {["User-Agent"] = "test-malicious-bot"})
    
    -- In dry run mode, request should succeed but be logged
    local test_passed = proxy_res and proxy_res.status < 400
    log_test("Dry Run No Blocking", test_passed,
        test_passed and "Malicious request allowed in dry run" or "Request blocked in dry run mode")
    
    -- Test 2: Disable dry run and verify the same request gets blocked
    res, err = make_admin_request("PATCH", "/plugins/" .. test_plugin.id, {
        config = {dry_run = false}
    })
    
    if not res or res.status ~= 200 then
        log_test("Dry Run Disable", false, "Could not disable dry run mode")
        return false
    end
    
    -- Wait a moment for configuration to propagate
    os.execute("sleep 1")
    
    proxy_res, proxy_err = make_proxy_request("POST", "/test-guard-ai/post", 
        malicious_request_body, {["User-Agent"] = "test-malicious-bot"})
    
    -- With dry run disabled, request should be blocked
    test_passed = proxy_res and proxy_res.status >= 400
    log_test("Active Mode Blocking", test_passed,
        test_passed and "Malicious request blocked in active mode" or "Request not blocked in active mode")
    
    -- Test 3: Re-enable dry run and verify blocking stops
    res, err = make_admin_request("PATCH", "/plugins/" .. test_plugin.id, {
        config = {dry_run = true}
    })
    
    test_passed = res and res.status == 200
    log_test("Dry Run Re-enable", test_passed,
        test_passed and "Dry run re-enabled successfully" or "Could not re-enable dry run")
end

-- Konnect compatibility simulation
function _M.test_konnect_compatibility()
    print("\n☁️ Testing Konnect Compatibility (Simulation)...")
    
    -- Test 1: Export current configuration in Konnect-compatible format
    local res, err = make_admin_request("GET", "/config")
    local test_passed = res and res.status == 200
    log_test("Configuration Export", test_passed,
        test_passed and "Configuration exported successfully" or (err or "Export failed"))
    
    if not test_passed then
        return false
    end
    
    local exported_config = res.body
    
    -- Test 2: Validate exported configuration has required Konnect fields
    local has_format_version = exported_config._format_version ~= nil
    local has_transform = exported_config._transform ~= nil
    
    log_test("Konnect Format Compliance", has_format_version and has_transform,
        has_format_version and has_transform and "Config has Konnect format fields" or "Missing Konnect format fields")
    
    -- Test 3: Simulate declarative configuration reload
    -- First, save current config
    local config_backup = cjson.encode(exported_config)
    
    -- Modify config slightly and reimport
    if exported_config.plugins then
        for _, plugin in ipairs(exported_config.plugins) do
            if plugin.name == PLUGIN_NAME and plugin.config then
                plugin.config.log_level = "debug"
            end
        end
    end
    
    res, err = make_admin_request("POST", "/config", exported_config)
    test_passed = res and res.status == 200
    log_test("Declarative Configuration Reload", test_passed,
        test_passed and "Config reloaded successfully" or (err or "Config reload failed"))
    
    -- Test 4: Verify plugin still functions after declarative reload
    local proxy_res, proxy_err = make_proxy_request("GET", "/test-guard-ai/get")
    test_passed = proxy_res and proxy_res.status < 500
    log_test("Plugin Function After Reload", test_passed,
        test_passed and "Plugin functional after reload" or "Plugin broken after reload")
end

-- Performance and monitoring tests
function _M.test_performance_monitoring()
    print("\n📊 Testing Performance and Monitoring...")
    
    -- Test 1: Check if plugin exposes metrics
    local res, err = make_proxy_request("GET", "/_guard_ai/metrics")
    local test_passed = res and res.status == 200
    log_test("Metrics Endpoint Availability", test_passed,
        test_passed and "Metrics endpoint accessible" or "Metrics endpoint not available")
    
    -- Test 2: Check status endpoint
    res, err = make_proxy_request("GET", "/_guard_ai/status")
    test_passed = res and res.status == 200
    log_test("Status Endpoint Availability", test_passed,
        test_passed and "Status endpoint accessible" or "Status endpoint not available")
    
    -- Test 3: Performance under load (basic test)
    local start_time = os.clock()
    local successful_requests = 0
    local total_requests = 10
    
    for i = 1, total_requests do
        local proxy_res, proxy_err = make_proxy_request("GET", "/test-guard-ai/get")
        if proxy_res and proxy_res.status < 500 then
            successful_requests = successful_requests + 1
        end
    end
    
    local end_time = os.clock()
    local avg_response_time = (end_time - start_time) / total_requests
    
    test_passed = successful_requests >= (total_requests * 0.9) and avg_response_time < 1.0
    log_test("Basic Performance Test", test_passed,
        string.format("%.0f%% success rate, %.3fs avg response time", 
            (successful_requests/total_requests)*100, avg_response_time))
end

-- Error handling and recovery tests
function _M.test_error_handling()
    print("\n🚨 Testing Error Handling and Recovery...")
    
    -- Test 1: Invalid plugin configuration update
    local res, err = make_admin_request("GET", "/plugins")
    if not res or res.status ~= 200 then
        log_test("Error Handling Setup", false, "Could not fetch plugins")
        return false
    end
    
    local test_plugin = nil
    for _, plugin in ipairs(res.body.data or {}) do
        if plugin.name == PLUGIN_NAME then
            test_plugin = plugin
            break
        end
    end
    
    if not test_plugin then
        log_test("Error Handling Setup", false, "Test plugin not found")
        return false
    end
    
    -- Try to update with invalid configuration
    local invalid_update = {
        config = {
            dry_run = "invalid_boolean",  -- Should be boolean
            log_level = "invalid_level"   -- Should be one of debug, info, warn, error
        }
    }
    
    res, err = make_admin_request("PATCH", "/plugins/" .. test_plugin.id, invalid_update)
    local test_passed = res and res.status >= 400
    log_test("Invalid Configuration Rejection", test_passed,
        test_passed and "Invalid config properly rejected" or "Invalid config was accepted")
    
    -- Test 2: Verify plugin still works after invalid update attempt
    local proxy_res, proxy_err = make_proxy_request("GET", "/test-guard-ai/get")
    test_passed = proxy_res and proxy_res.status < 500
    log_test("Plugin Stability After Error", test_passed,
        test_passed and "Plugin functional after error" or "Plugin broken after error")
    
    -- Test 3: Configuration rollback capability
    local original_config = test_plugin.config
    res, err = make_admin_request("PATCH", "/plugins/" .. test_plugin.id, {
        config = original_config
    })
    
    test_passed = res and res.status == 200
    log_test("Configuration Rollback", test_passed,
        test_passed and "Configuration rolled back successfully" or "Rollback failed")
end

-- Cleanup function
function _M.cleanup_test_resources()
    print("\n🧹 Cleaning up test resources...")
    
    -- Remove test plugins
    local res, err = make_admin_request("GET", "/plugins")
    if res and res.status == 200 then
        for _, plugin in ipairs(res.body.data or {}) do
            if plugin.name == PLUGIN_NAME then
                local service_info = ""
                if plugin.service and plugin.service.name == TEST_SERVICE_NAME then
                    service_info = " (test service)"
                end
                
                make_admin_request("DELETE", "/plugins/" .. plugin.id)
                print(string.format("   Removed plugin %s%s", plugin.id, service_info))
            end
        end
    end
    
    -- Remove test route
    res, err = make_admin_request("GET", "/routes")
    if res and res.status == 200 then
        for _, route in ipairs(res.body.data or {}) do
            if route.name == TEST_ROUTE_NAME then
                make_admin_request("DELETE", "/routes/" .. route.id)
                print(string.format("   Removed route %s", route.name))
            end
        end
    end
    
    -- Remove test service
    res, err = make_admin_request("GET", "/services")
    if res and res.status == 200 then
        for _, service in ipairs(res.body.data or {}) do
            if service.name == TEST_SERVICE_NAME then
                make_admin_request("DELETE", "/services/" .. service.id)
                print(string.format("   Removed service %s", service.name))
            end
        end
    end
end

-- Generate test report
function _M.generate_report()
    local report = {
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        summary = {
            total_tests = test_results.passed + test_results.failed,
            passed = test_results.passed,
            failed = test_results.failed,
            success_rate = test_results.passed / (test_results.passed + test_results.failed) * 100
        },
        errors = test_results.errors,
        details = test_results.details
    }
    
    local report_json = cjson.encode(report)
    local report_file = "admin_api_compatibility_report.json"
    
    local file = io.open(report_file, "w")
    if file then
        file:write(report_json)
        file:close()
        print(string.format("\n📄 Test report saved to: %s", report_file))
    else
        print("\n❌ Could not save test report")
    end
    
    return report
end

-- Main test runner
function _M.run_all_tests()
    print("🚀 Starting Kong Guard AI Admin API Compatibility Test Suite")
    print("=" .. string.rep("=", 65))
    
    -- Reset test results
    test_results = {passed = 0, failed = 0, errors = {}, details = {}}
    
    -- Check Kong availability
    local res, err = make_admin_request("GET", "/status")
    if not res or res.status ~= 200 then
        print(string.format("❌ Kong Admin API not available at %s", KONG_ADMIN_URL))
        print("   Please ensure Kong is running and accessible")
        return false
    end
    
    print(string.format("✅ Kong Admin API available at %s", KONG_ADMIN_URL))
    print(string.format("✅ Kong Proxy API configured at %s", KONG_PROXY_URL))
    print("")
    
    -- Run test suites
    _M.test_schema_validation()
    _M.test_plugin_lifecycle()
    _M.test_configuration_hot_reload()
    _M.test_dry_run_consistency()
    _M.test_konnect_compatibility()
    _M.test_performance_monitoring()
    _M.test_error_handling()
    
    -- Clean up
    _M.cleanup_test_resources()
    
    -- Generate report
    local report = _M.generate_report()
    
    -- Print summary
    print("\n" .. string.rep("=", 70))
    print("🏁 TEST SUITE COMPLETE")
    print(string.rep("=", 70))
    print(string.format("Total Tests: %d", report.summary.total_tests))
    print(string.format("Passed: %d", report.summary.passed))
    print(string.format("Failed: %d", report.summary.failed))
    print(string.format("Success Rate: %.1f%%", report.summary.success_rate))
    
    if #report.errors > 0 then
        print("\nFailed Tests:")
        for _, error in ipairs(report.errors) do
            print(string.format("  - %s: %s", error.test, error.message))
        end
    end
    
    local exit_code = report.summary.failed == 0 and 0 or 1
    return exit_code == 0, report
end

return _M