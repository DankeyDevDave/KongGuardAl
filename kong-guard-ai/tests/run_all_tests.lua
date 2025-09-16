#!/usr/bin/env lua

-- Kong Guard AI Comprehensive Test Runner
-- Orchestrates all integration tests and generates comprehensive reports

local framework = require "tests.integration_test_framework"

-- Test configuration
local test_config = {
    kong_mode = framework.KONG_MODES.DBLESS,
    environment = os.getenv("TEST_ENVIRONMENT") or framework.TEST_ENVIRONMENTS.LOCAL,
    timeout = 120,
    parallel_workers = 4,
    enable_coverage = true,
    verbose = os.getenv("VERBOSE") == "true",
    cleanup_on_exit = true,
    preserve_logs = os.getenv("PRESERVE_LOGS") == "true"
}

-- Test suites to run
local test_suites = {
    {
        name = "IP Blacklist Integration",
        file = "tests/integration/threat-detection/ip_blacklist_integration_test.lua",
        category = "threat-detection",
        priority = 1
    },
    {
        name = "Path Filter Integration",
        file = "tests/integration/threat-detection/path_filter_integration_test.lua",
        category = "threat-detection",
        priority = 1
    },
    {
        name = "Rate Limiting Integration",
        file = "tests/integration/threat-detection/rate_limiting_integration_test.lua",
        category = "threat-detection",
        priority = 1
    },
    {
        name = "Admin API Remediation",
        file = "tests/integration/remediation/admin_api_remediation_test.lua",
        category = "remediation",
        priority = 2
    },
    {
        name = "Observability and Monitoring",
        file = "tests/monitoring/observability_test.lua",
        category = "monitoring",
        priority = 3
    }
}

-- Global test results
local global_results = {
    start_time = 0,
    end_time = 0,
    total_duration_ms = 0,
    suites = {},
    summary = {
        total_suites = 0,
        passed_suites = 0,
        failed_suites = 0,
        total_tests = 0,
        passed_tests = 0,
        failed_tests = 0,
        skipped_tests = 0,
        total_assertions = 0,
        passed_assertions = 0,
        failed_assertions = 0
    },
    performance_metrics = {
        average_test_duration_ms = 0,
        max_test_duration_ms = 0,
        total_kong_instances = 0,
        average_kong_startup_time_ms = 0
    },
    environment_info = {
        test_environment = test_config.environment,
        kong_mode = test_config.kong_mode,
        lua_version = _VERSION,
        os_name = os.getenv("OS") or "unknown",
        ci = os.getenv("CI") == "true"
    }
}

---
-- Print colored output for better visibility
---
local function print_colored(text, color)
    local colors = {
        red = "\27[31m",
        green = "\27[32m",
        yellow = "\27[33m",
        blue = "\27[34m",
        magenta = "\27[35m",
        cyan = "\27[36m",
        reset = "\27[0m"
    }

    if colors[color] then
        print(colors[color] .. text .. colors.reset)
    else
        print(text)
    end
end

---
-- Print test progress
---
local function print_progress(current, total, suite_name)
    local percentage = math.floor((current / total) * 100)
    local progress_bar = string.rep("=", math.floor(percentage / 5)) .. string.rep("-", 20 - math.floor(percentage / 5))
    print(string.format("[%s] %d%% (%d/%d) - %s", progress_bar, percentage, current, total, suite_name))
end

---
-- Validate test environment
---
local function validate_environment()
    print_colored("🔍 Validating test environment...", "blue")

    -- Check if Kong is available
    local kong_check = os.execute("kong version >/dev/null 2>&1")
    if kong_check ~= 0 then
        print_colored("❌ Kong Gateway not found in PATH", "red")
        return false
    end

    -- Check if required Lua modules are available
    local required_modules = {"cjson.safe", "socket", "pl.file", "pl.path"}
    for _, module in ipairs(required_modules) do
        local success, _ = pcall(require, module)
        if not success then
            print_colored("❌ Required Lua module not found: " .. module, "red")
            return false
        end
    end

    -- Check Docker availability (if in Docker environment)
    if test_config.environment == framework.TEST_ENVIRONMENTS.DOCKER then
        local docker_check = os.execute("docker version >/dev/null 2>&1")
        if docker_check ~= 0 then
            print_colored("❌ Docker not available in Docker environment", "red")
            return false
        end
    end

    print_colored("✅ Environment validation passed", "green")
    return true
end

---
-- Filter test suites based on environment variables
---
local function filter_test_suites(suites)
    local test_suite_filter = os.getenv("TEST_SUITE")
    local test_category_filter = os.getenv("TEST_CATEGORY")

    if not test_suite_filter and not test_category_filter then
        return suites
    end

    local filtered = {}
    for _, suite in ipairs(suites) do
        local include = true

        if test_suite_filter then
            include = include and suite.name:lower():find(test_suite_filter:lower())
        end

        if test_category_filter then
            include = include and suite.category == test_category_filter
        end

        if include then
            table.insert(filtered, suite)
        end
    end

    return filtered
end

---
-- Run a single test suite
---
local function run_test_suite(suite_info, suite_index, total_suites)
    print_colored("\n" .. string.rep("=", 80), "cyan")
    print_colored("🧪 Running Test Suite: " .. suite_info.name, "cyan")
    print_colored("📁 File: " .. suite_info.file, "blue")
    print_colored("📂 Category: " .. suite_info.category, "blue")
    print_progress(suite_index, total_suites, suite_info.name)

    local suite_start_time = socket.gettime()

    -- Load and run test suite
    local suite_results
    local success, err = pcall(function()
        suite_results = framework.run_test_suite(suite_info.file, test_config)
    end)

    if not success then
        print_colored("❌ Test suite failed to run: " .. (err or "unknown error"), "red")
        suite_results = {
            file = suite_info.file,
            start_time = suite_start_time,
            end_time = socket.gettime(),
            tests = {},
            summary = {
                total = 0,
                passed = 0,
                failed = 1,
                skipped = 0
            },
            error = err
        }
    end

    -- Add suite metadata
    suite_results.name = suite_info.name
    suite_results.category = suite_info.category
    suite_results.priority = suite_info.priority

    -- Update global results
    global_results.summary.total_suites = global_results.summary.total_suites + 1
    global_results.summary.total_tests = global_results.summary.total_tests + suite_results.summary.total
    global_results.summary.passed_tests = global_results.summary.passed_tests + suite_results.summary.passed
    global_results.summary.failed_tests = global_results.summary.failed_tests + suite_results.summary.failed
    global_results.summary.skipped_tests = global_results.summary.skipped_tests + suite_results.summary.skipped

    if suite_results.summary.failed == 0 and suite_results.summary.total > 0 then
        global_results.summary.passed_suites = global_results.summary.passed_suites + 1
        print_colored("✅ Test suite passed: " .. suite_info.name, "green")
    else
        global_results.summary.failed_suites = global_results.summary.failed_suites + 1
        print_colored("❌ Test suite failed: " .. suite_info.name, "red")
    end

    -- Print suite summary
    print_colored(string.format(
        "📊 Suite Results: %d total, %d passed, %d failed, %d skipped (%.2fms)",
        suite_results.summary.total,
        suite_results.summary.passed,
        suite_results.summary.failed,
        suite_results.summary.skipped,
        suite_results.duration_ms or 0
    ), "blue")

    table.insert(global_results.suites, suite_results)
    return suite_results
end

---
-- Generate comprehensive test report
---
local function generate_report()
    print_colored("\n" .. string.rep("=", 80), "magenta")
    print_colored("📋 COMPREHENSIVE TEST REPORT", "magenta")
    print_colored(string.rep("=", 80), "magenta")

    -- Overall summary
    print_colored("\n📊 OVERALL SUMMARY", "cyan")
    print_colored("─────────────────", "cyan")
    print(string.format("Test Environment: %s", global_results.environment_info.test_environment))
    print(string.format("Kong Mode: %s", global_results.environment_info.kong_mode))
    print(string.format("Total Duration: %.2f seconds", global_results.total_duration_ms / 1000))
    print(string.format("Lua Version: %s", global_results.environment_info.lua_version))

    print_colored("\n🎯 TEST SUITE RESULTS", "cyan")
    print_colored("─────────────────────", "cyan")
    print(string.format("Total Suites: %d", global_results.summary.total_suites))
    print_colored(string.format("Passed Suites: %d", global_results.summary.passed_suites), "green")
    print_colored(string.format("Failed Suites: %d", global_results.summary.failed_suites),
        global_results.summary.failed_suites > 0 and "red" or "green")

    print_colored("\n🧪 INDIVIDUAL TEST RESULTS", "cyan")
    print_colored("─────────────────────────", "cyan")
    print(string.format("Total Tests: %d", global_results.summary.total_tests))
    print_colored(string.format("Passed Tests: %d", global_results.summary.passed_tests), "green")
    print_colored(string.format("Failed Tests: %d", global_results.summary.failed_tests),
        global_results.summary.failed_tests > 0 and "red" or "green")
    print_colored(string.format("Skipped Tests: %d", global_results.summary.skipped_tests), "yellow")

    local success_rate = global_results.summary.total_tests > 0 and
        (global_results.summary.passed_tests / global_results.summary.total_tests * 100) or 0
    print_colored(string.format("Success Rate: %.1f%%", success_rate),
        success_rate >= 90 and "green" or (success_rate >= 70 and "yellow" or "red"))

    -- Detailed suite breakdown
    print_colored("\n📋 SUITE BREAKDOWN", "cyan")
    print_colored("──────────────────", "cyan")

    for _, suite in ipairs(global_results.suites) do
        local suite_status = suite.summary.failed == 0 and suite.summary.total > 0 and "PASSED" or "FAILED"
        local status_color = suite_status == "PASSED" and "green" or "red"

        print_colored(string.format(
            "%s %s (%s)",
            suite_status == "PASSED" and "✅" or "❌",
            suite.name,
            suite.category
        ), status_color)

        print(string.format(
            "   Tests: %d passed, %d failed, %d skipped (%.2fms)",
            suite.summary.passed,
            suite.summary.failed,
            suite.summary.skipped,
            suite.duration_ms or 0
        ))

        -- Show failed tests
        if suite.summary.failed > 0 then
            for _, test in ipairs(suite.tests or {}) do
                if test.status == "failed" then
                    print_colored("   ❌ " .. test.test_name, "red")
                    for _, error in ipairs(test.errors or {}) do
                        print("      Error: " .. error.message)
                    end
                end
            end
        end
    end

    -- Performance analysis
    print_colored("\n⚡ PERFORMANCE ANALYSIS", "cyan")
    print_colored("─────────────────────", "cyan")

    local total_test_time = 0
    local max_test_time = 0
    local test_count = 0

    for _, suite in ipairs(global_results.suites) do
        for _, test in ipairs(suite.tests or {}) do
            total_test_time = total_test_time + (test.duration_ms or 0)
            max_test_time = math.max(max_test_time, test.duration_ms or 0)
            test_count = test_count + 1
        end
    end

    if test_count > 0 then
        print(string.format("Average Test Duration: %.2fms", total_test_time / test_count))
        print(string.format("Maximum Test Duration: %.2fms", max_test_time))
        print(string.format("Total Test Execution Time: %.2fs", total_test_time / 1000))
    end

    -- Final verdict
    print_colored("\n🏆 FINAL VERDICT", "cyan")
    print_colored("────────────────", "cyan")

    local overall_passed = global_results.summary.failed_tests == 0 and
                          global_results.summary.total_tests > 0

    if overall_passed then
        print_colored("🎉 ALL TESTS PASSED SUCCESSFULLY!", "green")
        print_colored("Kong Guard AI is ready for production deployment.", "green")
    else
        print_colored("💥 SOME TESTS FAILED!", "red")
        print_colored("Please review failed tests before deployment.", "red")
    end

    return overall_passed
end

---
-- Save detailed JSON report
---
local function save_json_report()
    local json_report = framework.generate_report("json")

    -- Add global results to JSON report
    local full_report = require("cjson.safe").decode(json_report) or {}
    full_report.global_results = global_results
    full_report.test_environment = test_config

    local report_file = "test-results/comprehensive-test-report.json"
    local file = io.open(report_file, "w")
    if file then
        file:write(require("cjson.safe").encode(full_report))
        file:close()
        print_colored("📄 Detailed JSON report saved: " .. report_file, "blue")
    else
        print_colored("⚠️ Failed to save JSON report", "yellow")
    end

    return report_file
end

---
-- Main execution
---
local function main()
    print_colored("🚀 Kong Guard AI Comprehensive Integration Test Suite", "magenta")
    print_colored("═══════════════════════════════════════════════════", "magenta")

    global_results.start_time = socket.gettime()

    -- Validate environment
    if not validate_environment() then
        print_colored("❌ Environment validation failed. Exiting.", "red")
        os.exit(1)
    end

    -- Initialize test framework
    local success, err = framework.initialize(test_config)
    if not success then
        print_colored("❌ Failed to initialize test framework: " .. (err or "unknown error"), "red")
        os.exit(1)
    end

    -- Filter test suites
    local filtered_suites = filter_test_suites(test_suites)

    print_colored(string.format("\n🎯 Running %d test suites", #filtered_suites), "blue")

    if #filtered_suites == 0 then
        print_colored("⚠️ No test suites match the specified filters", "yellow")
        os.exit(0)
    end

    -- Run test suites
    for i, suite in ipairs(filtered_suites) do
        run_test_suite(suite, i, #filtered_suites)
    end

    global_results.end_time = socket.gettime()
    global_results.total_duration_ms = (global_results.end_time - global_results.start_time) * 1000

    -- Generate reports
    local overall_success = generate_report()
    save_json_report()

    -- Exit with appropriate code
    if overall_success then
        print_colored("\n✨ Test suite completed successfully!", "green")
        os.exit(0)
    else
        print_colored("\n💥 Test suite completed with failures!", "red")
        os.exit(1)
    end
end

-- Socket library for timing
local socket = require "socket"

-- Execute main function
main()
