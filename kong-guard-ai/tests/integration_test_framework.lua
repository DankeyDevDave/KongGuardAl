-- Kong Guard AI Integration Testing Framework
-- Comprehensive testing framework for Kong Guard AI plugin functionality
-- Supports end-to-end testing with Kong Gateway integration

local _M = {}

-- Dependencies
local cjson = require "cjson.safe"
local socket = require "socket"
local ngx = require "ngx"
local pl_file = require "pl.file"
local pl_path = require "pl.path"

-- Test framework constants
_M.TEST_MODES = {
    UNIT = "unit",
    INTEGRATION = "integration",
    E2E = "e2e",
    LOAD = "load",
    SECURITY = "security"
}

_M.KONG_MODES = {
    TRADITIONAL = "traditional",
    DBLESS = "dbless",
    HYBRID = "hybrid"
}

_M.TEST_ENVIRONMENTS = {
    LOCAL = "local",
    DOCKER = "docker",
    CI = "ci",
    STAGING = "staging"
}

-- Kong Gateway configuration for testing
_M.DEFAULT_KONG_CONFIG = {
    database = "off",
    declarative_config = "/tmp/kong-test.yml",
    admin_listen = "127.0.0.1:8001",
    proxy_listen = "127.0.0.1:8000",
    plugins = "bundled,kong-guard-ai",
    log_level = "info",
    nginx_worker_processes = "1",
    anonymous_reports = "off"
}

-- Default test configuration
_M.DEFAULT_TEST_CONFIG = {
    kong_mode = _M.KONG_MODES.DBLESS,
    environment = _M.TEST_ENVIRONMENTS.LOCAL,
    timeout = 30,
    parallel_workers = 4,
    enable_coverage = true,
    verbose = false,
    cleanup_on_exit = true,
    preserve_logs = false
}

-- Test result structure
local test_result_schema = {
    test_name = "",
    test_mode = "",
    status = "pending", -- pending, running, passed, failed, skipped
    start_time = 0,
    end_time = 0,
    duration_ms = 0,
    assertions = {
        total = 0,
        passed = 0,
        failed = 0
    },
    errors = {},
    warnings = {},
    metrics = {},
    artifacts = {}
}

-- Global test state
local test_state = {
    active_tests = {},
    completed_tests = {},
    kong_processes = {},
    temp_files = {},
    test_data_dir = nil,
    coverage_data = {}
}

---
-- Initialize the testing framework
-- @param config table Optional configuration overrides
-- @return boolean success
-- @return string error_message
---
function _M.initialize(config)
    config = config or {}

    -- Merge with default configuration
    local test_config = {}
    for k, v in pairs(_M.DEFAULT_TEST_CONFIG) do
        test_config[k] = config[k] or v
    end

    -- Create temporary test data directory
    test_state.test_data_dir = os.tmpname() .. "_kong_guard_ai_tests"
    local success, err = pcall(function()
        os.execute("mkdir -p " .. test_state.test_data_dir)
        os.execute("mkdir -p " .. test_state.test_data_dir .. "/logs")
        os.execute("mkdir -p " .. test_state.test_data_dir .. "/configs")
        os.execute("mkdir -p " .. test_state.test_data_dir .. "/artifacts")
    end)

    if not success then
        return false, "Failed to create test data directory: " .. (err or "unknown error")
    end

    -- Store configuration
    test_state.config = test_config

    print("[Integration Test Framework] Initialized with config:")
    print("  - Test data directory: " .. test_state.test_data_dir)
    print("  - Kong mode: " .. test_config.kong_mode)
    print("  - Environment: " .. test_config.environment)
    print("  - Parallel workers: " .. test_config.parallel_workers)

    return true
end

---
-- Start Kong Gateway with specified configuration
-- @param kong_config table Kong configuration
-- @param plugin_config table Kong Guard AI plugin configuration
-- @return boolean success
-- @return string kong_process_id
-- @return string error_message
---
function _M.start_kong(kong_config, plugin_config)
    kong_config = kong_config or _M.DEFAULT_KONG_CONFIG
    plugin_config = plugin_config or {}

    -- Generate unique process ID
    local process_id = "kong_" .. socket.gettime() .. "_" .. math.random(1000, 9999)

    -- Create Kong declarative configuration
    local declarative_config = {
        _format_version = "3.0",
        services = {
            {
                name = "test-service",
                url = "http://httpbin.org"
            }
        },
        routes = {
            {
                name = "test-route",
                service = "test-service",
                paths = { "/test" }
            }
        },
        plugins = {
            {
                name = "kong-guard-ai",
                service = "test-service",
                config = plugin_config
            }
        }
    }

    -- Write declarative config file
    local config_file = test_state.test_data_dir .. "/configs/" .. process_id .. ".yml"
    local yaml_content = require("lyaml").dump({declarative_config})

    local file = io.open(config_file, "w")
    if not file then
        return false, nil, "Failed to create Kong config file"
    end
    file:write(yaml_content)
    file:close()

    -- Update Kong config with paths
    kong_config.declarative_config = config_file
    kong_config.prefix = test_state.test_data_dir .. "/kong_" .. process_id

    -- Generate Kong configuration file
    local kong_conf_file = test_state.test_data_dir .. "/configs/kong_" .. process_id .. ".conf"
    local conf_content = {}
    for k, v in pairs(kong_config) do
        table.insert(conf_content, k .. " = " .. tostring(v))
    end

    local conf_file = io.open(kong_conf_file, "w")
    if not conf_file then
        return false, nil, "Failed to create Kong conf file"
    end
    conf_file:write(table.concat(conf_content, "\n"))
    conf_file:close()

    -- Start Kong process
    local kong_cmd = string.format(
        "kong start -c %s > %s/logs/kong_%s.log 2>&1 &",
        kong_conf_file,
        test_state.test_data_dir,
        process_id
    )

    local result = os.execute(kong_cmd)
    if result ~= 0 then
        return false, nil, "Failed to start Kong process"
    end

    -- Wait for Kong to be ready
    local max_wait = 30
    local wait_interval = 1
    local admin_url = "http://" .. kong_config.admin_listen

    for i = 1, max_wait do
        local health_check = os.execute(
            "curl -s " .. admin_url .. "/status >/dev/null 2>&1"
        )
        if health_check == 0 then
            break
        end

        if i == max_wait then
            _M.stop_kong(process_id)
            return false, nil, "Kong failed to start within " .. max_wait .. " seconds"
        end

        os.execute("sleep " .. wait_interval)
    end

    -- Store Kong process information
    test_state.kong_processes[process_id] = {
        config = kong_config,
        plugin_config = plugin_config,
        admin_url = admin_url,
        proxy_url = "http://" .. kong_config.proxy_listen,
        start_time = socket.gettime(),
        log_file = test_state.test_data_dir .. "/logs/kong_" .. process_id .. ".log"
    }

    print("[Integration Test Framework] Kong started with process ID: " .. process_id)
    print("  - Admin URL: " .. admin_url)
    print("  - Proxy URL: " .. test_state.kong_processes[process_id].proxy_url)

    return true, process_id
end

---
-- Stop Kong Gateway process
-- @param process_id string Kong process identifier
-- @return boolean success
---
function _M.stop_kong(process_id)
    if not test_state.kong_processes[process_id] then
        return false
    end

    local kong_info = test_state.kong_processes[process_id]
    local prefix = kong_info.config.prefix

    -- Stop Kong using prefix
    local stop_cmd = "kong stop -p " .. prefix .. " >/dev/null 2>&1"
    os.execute(stop_cmd)

    -- Remove from active processes
    test_state.kong_processes[process_id] = nil

    print("[Integration Test Framework] Kong process stopped: " .. process_id)
    return true
end

---
-- Execute HTTP request for testing
-- @param kong_process_id string Kong process to use
-- @param method string HTTP method
-- @param path string Request path
-- @param headers table Request headers
-- @param body string Request body
-- @param expected_status number Expected status code
-- @return table response
---
function _M.execute_request(kong_process_id, method, path, headers, body, expected_status)
    if not test_state.kong_processes[kong_process_id] then
        error("Kong process not found: " .. kong_process_id)
    end

    local kong_info = test_state.kong_processes[kong_process_id]
    local url = kong_info.proxy_url .. path

    -- Build curl command
    local curl_cmd = {"curl", "-s", "-w", "'%{http_code}|%{time_total}'", "-X", method}

    -- Add headers
    if headers then
        for name, value in pairs(headers) do
            table.insert(curl_cmd, "-H")
            table.insert(curl_cmd, "'" .. name .. ": " .. value .. "'")
        end
    end

    -- Add body
    if body then
        table.insert(curl_cmd, "-d")
        table.insert(curl_cmd, "'" .. body .. "'")
    end

    table.insert(curl_cmd, "'" .. url .. "'")

    -- Execute request
    local start_time = socket.gettime()
    local cmd = table.concat(curl_cmd, " ")
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()
    local end_time = socket.gettime()

    -- Parse response
    local response_parts = result:split("|")
    local response_body = response_parts[1] or ""
    local status_and_timing = response_parts[2] or "0|0"
    local timing_parts = status_and_timing:split("|")

    local response = {
        status_code = tonumber(timing_parts[1]) or 0,
        body = response_body,
        duration_ms = (tonumber(timing_parts[2]) or 0) * 1000,
        request_duration_ms = (end_time - start_time) * 1000,
        timestamp = start_time
    }

    -- Validate expected status if provided
    if expected_status and response.status_code ~= expected_status then
        error(string.format(
            "Expected status %d but got %d. Response: %s",
            expected_status, response.status_code, response.body
        ))
    end

    return response
end

---
-- Create a new test case
-- @param name string Test name
-- @param mode string Test mode (unit, integration, e2e, etc.)
-- @return table test_case
---
function _M.create_test(name, mode)
    mode = mode or _M.TEST_MODES.INTEGRATION

    local test_case = {}
    for k, v in pairs(test_result_schema) do
        if type(v) == "table" then
            test_case[k] = {}
            for kk, vv in pairs(v) do
                test_case[k][kk] = vv
            end
        else
            test_case[k] = v
        end
    end

    test_case.test_name = name
    test_case.test_mode = mode
    test_case.start_time = socket.gettime()
    test_case.status = "running"

    -- Add to active tests
    test_state.active_tests[name] = test_case

    print("[Test] Starting: " .. name .. " (" .. mode .. ")")

    return test_case
end

---
-- Assert function for tests
-- @param test_case table Test case object
-- @param condition boolean Condition to check
-- @param message string Error message if assertion fails
-- @return boolean success
---
function _M.assert(test_case, condition, message)
    test_case.assertions.total = test_case.assertions.total + 1

    if condition then
        test_case.assertions.passed = test_case.assertions.passed + 1
        return true
    else
        test_case.assertions.failed = test_case.assertions.failed + 1
        table.insert(test_case.errors, {
            type = "assertion",
            message = message or "Assertion failed",
            timestamp = socket.gettime()
        })
        return false
    end
end

---
-- Complete a test case
-- @param test_case table Test case object
-- @param status string Final status (passed, failed, skipped)
-- @return table completed_test
---
function _M.complete_test(test_case, status)
    status = status or (test_case.assertions.failed == 0 and "passed" or "failed")

    test_case.end_time = socket.gettime()
    test_case.duration_ms = (test_case.end_time - test_case.start_time) * 1000
    test_case.status = status

    -- Move from active to completed
    test_state.active_tests[test_case.test_name] = nil
    test_state.completed_tests[test_case.test_name] = test_case

    local status_icon = status == "passed" and "✅" or (status == "failed" and "❌" or "⏭️")
    print(string.format(
        "[Test] %s %s: %s (%.2fms, %d/%d assertions)",
        status_icon,
        status:upper(),
        test_case.test_name,
        test_case.duration_ms,
        test_case.assertions.passed,
        test_case.assertions.total
    ))

    -- Print errors if any
    if #test_case.errors > 0 then
        for _, error in ipairs(test_case.errors) do
            print("  Error: " .. error.message)
        end
    end

    return test_case
end

---
-- Run a test suite from a file
-- @param test_file string Path to test file
-- @param config table Test configuration
-- @return table test_results
---
function _M.run_test_suite(test_file, config)
    config = config or {}

    -- Load test file
    local success, test_module = pcall(dofile, test_file)
    if not success then
        error("Failed to load test file: " .. test_file .. " - " .. test_module)
    end

    -- Execute test suite
    local suite_results = {
        file = test_file,
        start_time = socket.gettime(),
        tests = {},
        summary = {
            total = 0,
            passed = 0,
            failed = 0,
            skipped = 0
        }
    }

    if type(test_module.run_tests) == "function" then
        local tests = test_module.run_tests(_M, config)
        for _, test in ipairs(tests or {}) do
            table.insert(suite_results.tests, test)
            suite_results.summary.total = suite_results.summary.total + 1
            if test.status == "passed" then
                suite_results.summary.passed = suite_results.summary.passed + 1
            elseif test.status == "failed" then
                suite_results.summary.failed = suite_results.summary.failed + 1
            else
                suite_results.summary.skipped = suite_results.summary.skipped + 1
            end
        end
    end

    suite_results.end_time = socket.gettime()
    suite_results.duration_ms = (suite_results.end_time - suite_results.start_time) * 1000

    return suite_results
end

---
-- Generate test report
-- @param format string Report format (json, html, text)
-- @return string report_content
---
function _M.generate_report(format)
    format = format or "text"

    local all_tests = {}
    for _, test in pairs(test_state.completed_tests) do
        table.insert(all_tests, test)
    end

    local summary = {
        total = #all_tests,
        passed = 0,
        failed = 0,
        skipped = 0,
        total_duration_ms = 0,
        total_assertions = 0,
        passed_assertions = 0,
        failed_assertions = 0
    }

    for _, test in ipairs(all_tests) do
        if test.status == "passed" then
            summary.passed = summary.passed + 1
        elseif test.status == "failed" then
            summary.failed = summary.failed + 1
        else
            summary.skipped = summary.skipped + 1
        end

        summary.total_duration_ms = summary.total_duration_ms + test.duration_ms
        summary.total_assertions = summary.total_assertions + test.assertions.total
        summary.passed_assertions = summary.passed_assertions + test.assertions.passed
        summary.failed_assertions = summary.failed_assertions + test.assertions.failed
    end

    if format == "json" then
        return cjson.encode({
            summary = summary,
            tests = all_tests,
            framework_info = {
                test_data_dir = test_state.test_data_dir,
                config = test_state.config
            }
        })
    elseif format == "html" then
        -- Basic HTML report
        local html = {"<html><head><title>Kong Guard AI Test Report</title></head><body>"}
        table.insert(html, "<h1>Kong Guard AI Integration Test Report</h1>")
        table.insert(html, "<h2>Summary</h2>")
        table.insert(html, string.format("<p>Total: %d, Passed: %d, Failed: %d, Skipped: %d</p>",
            summary.total, summary.passed, summary.failed, summary.skipped))
        table.insert(html, "<h2>Test Results</h2>")
        table.insert(html, "<table border='1'><tr><th>Name</th><th>Status</th><th>Duration</th><th>Assertions</th></tr>")

        for _, test in ipairs(all_tests) do
            local status_color = test.status == "passed" and "green" or (test.status == "failed" and "red" or "orange")
            table.insert(html, string.format(
                "<tr><td>%s</td><td style='color: %s'>%s</td><td>%.2fms</td><td>%d/%d</td></tr>",
                test.test_name, status_color, test.status, test.duration_ms,
                test.assertions.passed, test.assertions.total
            ))
        end

        table.insert(html, "</table></body></html>")
        return table.concat(html, "\n")
    else
        -- Text format
        local lines = {
            "Kong Guard AI Integration Test Report",
            "=====================================",
            "",
            "Summary:",
            string.format("  Total Tests: %d", summary.total),
            string.format("  Passed: %d (%.1f%%)", summary.passed, summary.total > 0 and (summary.passed / summary.total * 100) or 0),
            string.format("  Failed: %d (%.1f%%)", summary.failed, summary.total > 0 and (summary.failed / summary.total * 100) or 0),
            string.format("  Skipped: %d (%.1f%%)", summary.skipped, summary.total > 0 and (summary.skipped / summary.total * 100) or 0),
            string.format("  Total Duration: %.2fms", summary.total_duration_ms),
            string.format("  Total Assertions: %d (Passed: %d, Failed: %d)",
                summary.total_assertions, summary.passed_assertions, summary.failed_assertions),
            "",
            "Test Results:",
            "-------------"
        }

        for _, test in ipairs(all_tests) do
            local status_icon = test.status == "passed" and "✅" or (test.status == "failed" and "❌" or "⏭️")
            table.insert(lines, string.format(
                "%s %s (%.2fms, %d/%d assertions)",
                status_icon, test.test_name, test.duration_ms,
                test.assertions.passed, test.assertions.total
            ))

            if #test.errors > 0 then
                for _, error in ipairs(test.errors) do
                    table.insert(lines, "    Error: " .. error.message)
                end
            end
        end

        return table.concat(lines, "\n")
    end
end

---
-- Cleanup test environment
---
function _M.cleanup()
    print("[Integration Test Framework] Cleaning up test environment...")

    -- Stop all Kong processes
    for process_id, _ in pairs(test_state.kong_processes) do
        _M.stop_kong(process_id)
    end

    -- Remove temporary files if configured
    if test_state.config and test_state.config.cleanup_on_exit and test_state.test_data_dir then
        if not test_state.config.preserve_logs then
            os.execute("rm -rf " .. test_state.test_data_dir)
            print("  - Removed test data directory: " .. test_state.test_data_dir)
        else
            print("  - Preserved test data directory: " .. test_state.test_data_dir)
        end
    end

    -- Clear state
    test_state.active_tests = {}
    test_state.kong_processes = {}
    test_state.temp_files = {}

    print("  - Cleanup completed")
end

-- Utility function for string splitting
function string:split(delimiter)
    local result = {}
    local from = 1
    local delim_from, delim_to = string.find(self, delimiter, from)
    while delim_from do
        table.insert(result, string.sub(self, from, delim_from - 1))
        from = delim_to + 1
        delim_from, delim_to = string.find(self, delimiter, from)
    end
    table.insert(result, string.sub(self, from))
    return result
end

-- Set up cleanup on exit
local function at_exit()
    _M.cleanup()
end

-- Register cleanup handler
local ok, ffi = pcall(require, "ffi")
if ok then
    ffi.cdef[[
        int atexit(void (*function)(void));
    ]]
    ffi.C.atexit(at_exit)
end

return _M
