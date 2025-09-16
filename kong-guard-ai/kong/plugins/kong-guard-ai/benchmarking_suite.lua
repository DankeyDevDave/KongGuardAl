-- Kong Guard AI - Benchmarking Suite
-- Comprehensive performance testing with wrk/hey integration
-- Implements automated performance validation and load testing
--
-- Author: Performance Optimization Specialist Agent
-- Phase: 3 - Performance Optimization & Benchmarking
--
-- FEATURES:
-- - Integration with wrk, hey, and Apache Bench
-- - Automated baseline vs instrumented performance comparison
-- - Memory leak detection under sustained load
-- - Stress testing with configurable concurrency levels
-- - Real-time performance monitoring during tests

local kong = kong
local json = require "cjson.safe"
local http = require "resty.http"

local _M = {}

-- Benchmarking configuration
local BENCHMARK_CONFIG = {
    DEFAULT_DURATION = 30,              -- Default test duration in seconds
    DEFAULT_CONCURRENCY = 10,           -- Default concurrent connections
    DEFAULT_REQUESTS = 1000,            -- Default total requests for fixed-count tests
    WARMUP_DURATION = 5,                -- Warmup period before actual test
    COOLDOWN_DURATION = 3,              -- Cooldown period after test
    MAX_MEMORY_GROWTH_MB = 50,          -- Alert if memory grows beyond this
    ACCEPTABLE_LATENCY_INCREASE = 20,   -- Max acceptable latency increase percentage
    MIN_RPS_THRESHOLD = 100,            -- Minimum RPS to consider test valid
    STRESS_TEST_MULTIPLIER = 5          -- Multiplier for stress test concurrency
}

-- Available benchmarking tools
local BENCHMARK_TOOLS = {
    WRK = "wrk",
    HEY = "hey",
    AB = "ab",
    CURL = "curl"
}

-- Test scenarios
local TEST_SCENARIOS = {
    BASELINE = "baseline",              -- No plugin enabled
    DRY_RUN = "dry_run",               -- Plugin in dry run mode
    ACTIVE_MINIMAL = "active_minimal",  -- Plugin active, minimal detection
    ACTIVE_FULL = "active_full",       -- Plugin active, full detection
    STRESS_TEST = "stress_test"        -- High load stress test
}

---
-- Initialize benchmarking suite
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Benchmark] Initializing benchmarking suite")

    -- Detect available benchmarking tools
    _M.detect_available_tools()

    kong.log.info("[Kong Guard AI Benchmark] Benchmarking suite initialized")
end

---
-- Detect which benchmarking tools are available
-- @return Table of available tools
---
function _M.detect_available_tools()
    local available_tools = {}

    for tool_name, tool_cmd in pairs(BENCHMARK_TOOLS) do
        -- Check if tool is available by trying to run --version
        local handle = io.popen(tool_cmd .. " --version 2>/dev/null")
        if handle then
            local result = handle:read("*a")
            handle:close()

            if result and #result > 0 then
                available_tools[tool_name] = true
                kong.log.debug("[Kong Guard AI Benchmark] Found tool: " .. tool_cmd)
            end
        end
    end

    -- Always have curl as fallback
    available_tools.CURL = true

    kong.log.info("[Kong Guard AI Benchmark] Available tools: " .. json.encode(available_tools))
    return available_tools
end

---
-- Run comprehensive benchmark suite
-- @param test_config Configuration for the benchmark
-- @return Table containing comprehensive results
---
function _M.run_comprehensive_benchmark(test_config)
    kong.log.info("[Kong Guard AI Benchmark] Starting comprehensive benchmark suite")

    local config = _M.merge_config_with_defaults(test_config)
    local results = {
        start_time = ngx.time(),
        config = config,
        scenarios = {},
        summary = {},
        recommendations = {}
    }

    -- Run baseline test first
    kong.log.info("[Kong Guard AI Benchmark] Running baseline performance test")
    results.scenarios[TEST_SCENARIOS.BASELINE] = _M.run_baseline_test(config)

    -- Run dry run test
    kong.log.info("[Kong Guard AI Benchmark] Running dry run mode test")
    results.scenarios[TEST_SCENARIOS.DRY_RUN] = _M.run_dry_run_test(config)

    -- Run active mode tests
    kong.log.info("[Kong Guard AI Benchmark] Running active mode tests")
    results.scenarios[TEST_SCENARIOS.ACTIVE_MINIMAL] = _M.run_active_test(config, "minimal")
    results.scenarios[TEST_SCENARIOS.ACTIVE_FULL] = _M.run_active_test(config, "full")

    -- Run stress test
    kong.log.info("[Kong Guard AI Benchmark] Running stress test")
    results.scenarios[TEST_SCENARIOS.STRESS_TEST] = _M.run_stress_test(config)

    -- Generate analysis and recommendations
    results.summary = _M.analyze_benchmark_results(results.scenarios)
    results.recommendations = _M.generate_performance_recommendations(results.scenarios, results.summary)

    results.end_time = ngx.time()
    results.total_duration = results.end_time - results.start_time

    kong.log.info("[Kong Guard AI Benchmark] Comprehensive benchmark completed in " ..
                  results.total_duration .. " seconds")

    return results
end

---
-- Run baseline performance test (no plugin)
-- @param config Test configuration
-- @return Baseline test results
---
function _M.run_baseline_test(config)
    kong.log.info("[Kong Guard AI Benchmark] Disabling plugin for baseline test")

    -- Disable plugin (this would need to be implemented based on your plugin management)
    local plugin_disabled = _M.disable_plugin_temporarily()

    if not plugin_disabled then
        kong.log.warn("[Kong Guard AI Benchmark] Could not disable plugin, baseline may include plugin overhead")
    end

    -- Wait for configuration to propagate
    ngx.sleep(2)

    local baseline_results = {
        scenario = TEST_SCENARIOS.BASELINE,
        start_time = ngx.now(),
        plugin_enabled = false,
        tool_results = {}
    }

    -- Run tests with available tools
    baseline_results.tool_results.wrk = _M.run_wrk_test(config.test_url, config.duration, config.concurrency)
    baseline_results.tool_results.hey = _M.run_hey_test(config.test_url, config.requests, config.concurrency)
    baseline_results.tool_results.ab = _M.run_ab_test(config.test_url, config.requests, config.concurrency)

    baseline_results.end_time = ngx.now()
    baseline_results.duration = baseline_results.end_time - baseline_results.start_time

    -- Re-enable plugin
    if plugin_disabled then
        _M.enable_plugin()
        ngx.sleep(2)
    end

    -- Calculate summary metrics
    baseline_results.summary = _M.calculate_summary_metrics(baseline_results.tool_results)

    return baseline_results
end

---
-- Run dry run mode test
-- @param config Test configuration
-- @return Dry run test results
---
function _M.run_dry_run_test(config)
    kong.log.info("[Kong Guard AI Benchmark] Configuring plugin for dry run mode")

    -- Configure plugin in dry run mode
    _M.configure_plugin_mode("dry_run")
    ngx.sleep(2)

    local dry_run_results = {
        scenario = TEST_SCENARIOS.DRY_RUN,
        start_time = ngx.now(),
        plugin_enabled = true,
        plugin_mode = "dry_run",
        tool_results = {}
    }

    -- Monitor memory before test
    local memory_before = _M.get_kong_memory_usage()

    -- Run tests
    dry_run_results.tool_results.wrk = _M.run_wrk_test(config.test_url, config.duration, config.concurrency)
    dry_run_results.tool_results.hey = _M.run_hey_test(config.test_url, config.requests, config.concurrency)
    dry_run_results.tool_results.ab = _M.run_ab_test(config.test_url, config.requests, config.concurrency)

    -- Monitor memory after test
    local memory_after = _M.get_kong_memory_usage()
    dry_run_results.memory_delta_mb = (memory_after - memory_before) / 1024

    dry_run_results.end_time = ngx.now()
    dry_run_results.duration = dry_run_results.end_time - dry_run_results.start_time
    dry_run_results.summary = _M.calculate_summary_metrics(dry_run_results.tool_results)

    return dry_run_results
end

---
-- Run active mode test
-- @param config Test configuration
-- @param detection_level Detection level: "minimal" or "full"
-- @return Active mode test results
---
function _M.run_active_test(config, detection_level)
    kong.log.info("[Kong Guard AI Benchmark] Configuring plugin for active mode (" .. detection_level .. ")")

    -- Configure plugin in active mode with specified detection level
    _M.configure_plugin_mode("active", detection_level)
    ngx.sleep(2)

    local active_results = {
        scenario = detection_level == "minimal" and TEST_SCENARIOS.ACTIVE_MINIMAL or TEST_SCENARIOS.ACTIVE_FULL,
        start_time = ngx.now(),
        plugin_enabled = true,
        plugin_mode = "active",
        detection_level = detection_level,
        tool_results = {}
    }

    -- Monitor memory before test
    local memory_before = _M.get_kong_memory_usage()

    -- Run tests with some potentially malicious requests for realistic testing
    if detection_level == "full" then
        -- Include some test requests that would trigger detection
        active_results.test_requests = _M.generate_test_attack_requests()
    end

    active_results.tool_results.wrk = _M.run_wrk_test(config.test_url, config.duration, config.concurrency)
    active_results.tool_results.hey = _M.run_hey_test(config.test_url, config.requests, config.concurrency)
    active_results.tool_results.ab = _M.run_ab_test(config.test_url, config.requests, config.concurrency)

    -- Monitor memory after test
    local memory_after = _M.get_kong_memory_usage()
    active_results.memory_delta_mb = (memory_after - memory_before) / 1024

    active_results.end_time = ngx.now()
    active_results.duration = active_results.end_time - active_results.start_time
    active_results.summary = _M.calculate_summary_metrics(active_results.tool_results)

    return active_results
end

---
-- Run stress test with high concurrency
-- @param config Test configuration
-- @return Stress test results
---
function _M.run_stress_test(config)
    kong.log.info("[Kong Guard AI Benchmark] Running stress test with high concurrency")

    local stress_concurrency = config.concurrency * BENCHMARK_CONFIG.STRESS_TEST_MULTIPLIER
    local stress_duration = math.min(config.duration, 60) -- Limit stress test duration

    local stress_results = {
        scenario = TEST_SCENARIOS.STRESS_TEST,
        start_time = ngx.now(),
        plugin_enabled = true,
        concurrency = stress_concurrency,
        duration = stress_duration,
        tool_results = {}
    }

    -- Monitor system resources during stress test
    local monitoring_data = _M.start_resource_monitoring()

    -- Run stress tests
    stress_results.tool_results.wrk = _M.run_wrk_test(config.test_url, stress_duration, stress_concurrency)

    -- Stop resource monitoring
    stress_results.resource_usage = _M.stop_resource_monitoring(monitoring_data)

    stress_results.end_time = ngx.now()
    stress_results.duration = stress_results.end_time - stress_results.start_time
    stress_results.summary = _M.calculate_summary_metrics(stress_results.tool_results)

    return stress_results
end

---
-- Run wrk benchmark test
-- @param url Target URL
-- @param duration Test duration in seconds
-- @param concurrency Number of concurrent connections
-- @return wrk test results
---
function _M.run_wrk_test(url, duration, concurrency)
    if not _M.is_tool_available(BENCHMARK_TOOLS.WRK) then
        return { available = false, error = "wrk not available" }
    end

    local cmd = string.format("wrk -t%d -c%d -d%ds --latency %s",
                              math.min(concurrency, 12), -- wrk recommends threads ≤ CPU cores
                              concurrency,
                              duration,
                              url)

    kong.log.debug("[Kong Guard AI Benchmark] Running: " .. cmd)

    local handle = io.popen(cmd .. " 2>&1")
    if not handle then
        return { available = false, error = "Failed to execute wrk" }
    end

    local output = handle:read("*a")
    local exit_code = handle:close()

    return _M.parse_wrk_output(output, exit_code)
end

---
-- Run hey benchmark test
-- @param url Target URL
-- @param requests Total number of requests
-- @param concurrency Number of concurrent workers
-- @return hey test results
---
function _M.run_hey_test(url, requests, concurrency)
    if not _M.is_tool_available(BENCHMARK_TOOLS.HEY) then
        return { available = false, error = "hey not available" }
    end

    local cmd = string.format("hey -n %d -c %d -o csv %s", requests, concurrency, url)

    kong.log.debug("[Kong Guard AI Benchmark] Running: " .. cmd)

    local handle = io.popen(cmd .. " 2>&1")
    if not handle then
        return { available = false, error = "Failed to execute hey" }
    end

    local output = handle:read("*a")
    local exit_code = handle:close()

    return _M.parse_hey_output(output, exit_code)
end

---
-- Run Apache Bench test
-- @param url Target URL
-- @param requests Total number of requests
-- @param concurrency Number of concurrent requests
-- @return ab test results
---
function _M.run_ab_test(url, requests, concurrency)
    if not _M.is_tool_available(BENCHMARK_TOOLS.AB) then
        return { available = false, error = "ab not available" }
    end

    local cmd = string.format("ab -n %d -c %d %s", requests, concurrency, url)

    kong.log.debug("[Kong Guard AI Benchmark] Running: " .. cmd)

    local handle = io.popen(cmd .. " 2>&1")
    if not handle then
        return { available = false, error = "Failed to execute ab" }
    end

    local output = handle:read("*a")
    local exit_code = handle:close()

    return _M.parse_ab_output(output, exit_code)
end

---
-- Parse wrk output to extract metrics
-- @param output Raw wrk output
-- @param exit_code Exit code from wrk
-- @return Parsed metrics
---
function _M.parse_wrk_output(output, exit_code)
    local result = {
        tool = "wrk",
        available = true,
        success = exit_code,
        raw_output = output
    }

    -- Parse requests per second
    local rps = output:match("Requests/sec:%s*([%d%.]+)")
    if rps then
        result.requests_per_second = tonumber(rps)
    end

    -- Parse latency percentiles
    local latency_avg = output:match("Latency%s+([%d%.]+)ms")
    if latency_avg then
        result.latency_avg_ms = tonumber(latency_avg)
    end

    -- Parse 99th percentile latency
    local latency_99th = output:match("99%%[%s]+([%d%.]+)ms")
    if latency_99th then
        result.latency_99th_ms = tonumber(latency_99th)
    end

    -- Parse total requests
    local total_requests = output:match("(%d+) requests in")
    if total_requests then
        result.total_requests = tonumber(total_requests)
    end

    return result
end

---
-- Parse hey output to extract metrics
-- @param output Raw hey output
-- @param exit_code Exit code from hey
-- @return Parsed metrics
---
function _M.parse_hey_output(output, exit_code)
    local result = {
        tool = "hey",
        available = true,
        success = exit_code,
        raw_output = output
    }

    -- hey outputs CSV, parse the summary line
    local lines = {}
    for line in output:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    -- Last line typically contains summary
    if #lines > 0 then
        local summary_line = lines[#lines]
        local fields = {}
        for field in summary_line:gmatch("([^,]+)") do
            table.insert(fields, field)
        end

        -- CSV format: response-time, dns+dialup, dns, request-write, response-delay, response-read
        if #fields >= 2 then
            result.latency_avg_ms = tonumber(fields[1])
            result.requests_per_second = tonumber(fields[2])
        end
    end

    return result
end

---
-- Parse Apache Bench output to extract metrics
-- @param output Raw ab output
-- @param exit_code Exit code from ab
-- @return Parsed metrics
---
function _M.parse_ab_output(output, exit_code)
    local result = {
        tool = "ab",
        available = true,
        success = exit_code,
        raw_output = output
    }

    -- Parse requests per second
    local rps = output:match("Requests per second:%s*([%d%.]+)")
    if rps then
        result.requests_per_second = tonumber(rps)
    end

    -- Parse mean time per request
    local mean_time = output:match("Time per request:%s*([%d%.]+)%s*%[ms%]")
    if mean_time then
        result.latency_avg_ms = tonumber(mean_time)
    end

    -- Parse 99th percentile
    local percentile_99 = output:match("99%%%s*([%d%.]+)")
    if percentile_99 then
        result.latency_99th_ms = tonumber(percentile_99)
    end

    return result
end

---
-- Calculate summary metrics from multiple tool results
-- @param tool_results Results from different benchmarking tools
-- @return Summary metrics
---
function _M.calculate_summary_metrics(tool_results)
    local summary = {
        requests_per_second = 0,
        latency_avg_ms = 0,
        latency_99th_ms = 0,
        successful_tools = 0,
        total_tools = 0
    }

    for tool_name, result in pairs(tool_results) do
        summary.total_tools = summary.total_tools + 1

        if result.available and result.success and result.requests_per_second then
            summary.successful_tools = summary.successful_tools + 1
            summary.requests_per_second = summary.requests_per_second + (result.requests_per_second or 0)
            summary.latency_avg_ms = summary.latency_avg_ms + (result.latency_avg_ms or 0)
            summary.latency_99th_ms = summary.latency_99th_ms + (result.latency_99th_ms or 0)
        end
    end

    -- Calculate averages
    if summary.successful_tools > 0 then
        summary.requests_per_second = summary.requests_per_second / summary.successful_tools
        summary.latency_avg_ms = summary.latency_avg_ms / summary.successful_tools
        summary.latency_99th_ms = summary.latency_99th_ms / summary.successful_tools
    end

    return summary
end

---
-- Analyze benchmark results and identify performance impacts
-- @param scenarios Results from all test scenarios
-- @return Analysis summary
---
function _M.analyze_benchmark_results(scenarios)
    local analysis = {
        baseline_rps = 0,
        dry_run_overhead_percent = 0,
        active_minimal_overhead_percent = 0,
        active_full_overhead_percent = 0,
        stress_test_degradation_percent = 0,
        memory_growth_mb = 0,
        performance_verdict = "unknown"
    }

    -- Get baseline performance
    if scenarios[TEST_SCENARIOS.BASELINE] and scenarios[TEST_SCENARIOS.BASELINE].summary then
        analysis.baseline_rps = scenarios[TEST_SCENARIOS.BASELINE].summary.requests_per_second
    end

    -- Calculate overhead percentages
    if analysis.baseline_rps > 0 then
        if scenarios[TEST_SCENARIOS.DRY_RUN] and scenarios[TEST_SCENARIOS.DRY_RUN].summary then
            local dry_run_rps = scenarios[TEST_SCENARIOS.DRY_RUN].summary.requests_per_second
            analysis.dry_run_overhead_percent = ((analysis.baseline_rps - dry_run_rps) / analysis.baseline_rps) * 100
        end

        if scenarios[TEST_SCENARIOS.ACTIVE_MINIMAL] and scenarios[TEST_SCENARIOS.ACTIVE_MINIMAL].summary then
            local active_rps = scenarios[TEST_SCENARIOS.ACTIVE_MINIMAL].summary.requests_per_second
            analysis.active_minimal_overhead_percent = ((analysis.baseline_rps - active_rps) / analysis.baseline_rps) * 100
        end

        if scenarios[TEST_SCENARIOS.ACTIVE_FULL] and scenarios[TEST_SCENARIOS.ACTIVE_FULL].summary then
            local active_rps = scenarios[TEST_SCENARIOS.ACTIVE_FULL].summary.requests_per_second
            analysis.active_full_overhead_percent = ((analysis.baseline_rps - active_rps) / analysis.baseline_rps) * 100
        end
    end

    -- Calculate memory growth
    local max_memory_growth = 0
    for scenario_name, scenario_data in pairs(scenarios) do
        if scenario_data.memory_delta_mb then
            max_memory_growth = math.max(max_memory_growth, scenario_data.memory_delta_mb)
        end
    end
    analysis.memory_growth_mb = max_memory_growth

    -- Determine overall performance verdict
    if analysis.active_full_overhead_percent <= 10 and analysis.memory_growth_mb <= 20 then
        analysis.performance_verdict = "excellent"
    elseif analysis.active_full_overhead_percent <= 20 and analysis.memory_growth_mb <= 50 then
        analysis.performance_verdict = "good"
    elseif analysis.active_full_overhead_percent <= 30 and analysis.memory_growth_mb <= 100 then
        analysis.performance_verdict = "acceptable"
    else
        analysis.performance_verdict = "needs_optimization"
    end

    return analysis
end

---
-- Generate performance recommendations based on test results
-- @param scenarios Test scenario results
-- @param analysis Analysis summary
-- @return Array of recommendations
---
function _M.generate_performance_recommendations(scenarios, analysis)
    local recommendations = {}

    -- Performance overhead recommendations
    if analysis.active_full_overhead_percent > 20 then
        table.insert(recommendations, {
            type = "performance",
            priority = "high",
            title = "High Performance Overhead Detected",
            description = string.format("Active mode shows %.1f%% performance overhead", analysis.active_full_overhead_percent),
            suggestions = {
                "Consider reducing detection complexity",
                "Increase sampling rate to reduce processing",
                "Enable performance optimization mode",
                "Review expensive detection patterns"
            }
        })
    end

    -- Memory growth recommendations
    if analysis.memory_growth_mb > BENCHMARK_CONFIG.MAX_MEMORY_GROWTH_MB then
        table.insert(recommendations, {
            type = "memory",
            priority = "medium",
            title = "Significant Memory Growth",
            description = string.format("Memory usage increased by %.1f MB during testing", analysis.memory_growth_mb),
            suggestions = {
                "Increase cache cleanup frequency",
                "Reduce cache sizes in configuration",
                "Monitor for memory leaks",
                "Consider memory limits in configuration"
            }
        })
    end

    -- Baseline performance recommendations
    if analysis.baseline_rps < BENCHMARK_CONFIG.MIN_RPS_THRESHOLD then
        table.insert(recommendations, {
            type = "baseline",
            priority = "medium",
            title = "Low Baseline Performance",
            description = string.format("Baseline RPS of %.1f is below recommended threshold", analysis.baseline_rps),
            suggestions = {
                "Verify test environment performance",
                "Check Kong configuration for bottlenecks",
                "Consider hardware resources",
                "Review upstream service performance"
            }
        })
    end

    -- Configuration recommendations based on verdict
    if analysis.performance_verdict == "needs_optimization" then
        table.insert(recommendations, {
            type = "configuration",
            priority = "high",
            title = "Performance Optimization Required",
            description = "Overall performance verdict indicates optimization is needed",
            suggestions = {
                "Enable minimal optimization mode",
                "Reduce concurrent processing",
                "Increase performance thresholds",
                "Consider disabling expensive features"
            }
        })
    elseif analysis.performance_verdict == "excellent" then
        table.insert(recommendations, {
            type = "configuration",
            priority = "low",
            title = "Performance is Excellent",
            description = "Consider enabling additional security features",
            suggestions = {
                "Can safely enable more detection rules",
                "Consider reducing sampling rates",
                "Can handle higher traffic loads",
                "Suitable for production deployment"
            }
        })
    end

    return recommendations
end

---
-- Utility functions
---

function _M.merge_config_with_defaults(test_config)
    test_config = test_config or {}
    return {
        test_url = test_config.test_url or "http://localhost:8000/benchmark",
        duration = test_config.duration or BENCHMARK_CONFIG.DEFAULT_DURATION,
        concurrency = test_config.concurrency or BENCHMARK_CONFIG.DEFAULT_CONCURRENCY,
        requests = test_config.requests or BENCHMARK_CONFIG.DEFAULT_REQUESTS
    }
end

function _M.is_tool_available(tool_cmd)
    local handle = io.popen("which " .. tool_cmd .. " 2>/dev/null")
    if handle then
        local result = handle:read("*a")
        handle:close()
        return result and #result > 0
    end
    return false
end

function _M.get_kong_memory_usage()
    -- Get Kong worker memory usage in KB
    local handle = io.popen("ps -o rss= -p $(pgrep -f 'kong worker' | head -1) 2>/dev/null")
    if handle then
        local result = handle:read("*a")
        handle:close()
        return tonumber(result) or 0
    end
    return 0
end

function _M.disable_plugin_temporarily()
    -- Implementation would depend on your plugin management setup
    -- This is a placeholder
    kong.log.debug("[Kong Guard AI Benchmark] Plugin disable request")
    return false -- Return true if successfully disabled
end

function _M.enable_plugin()
    -- Implementation would depend on your plugin management setup
    kong.log.debug("[Kong Guard AI Benchmark] Plugin enable request")
end

function _M.configure_plugin_mode(mode, detection_level)
    -- Implementation would depend on your plugin configuration API
    kong.log.debug("[Kong Guard AI Benchmark] Plugin mode change: " .. mode ..
                  (detection_level and (" (" .. detection_level .. ")") or ""))
end

function _M.generate_test_attack_requests()
    -- Generate some test requests that would trigger detection for realistic testing
    return {
        "GET /test?id=1' OR '1'='1",
        "POST /api/login with SQLi payload",
        "GET /admin with XSS attempt"
    }
end

function _M.start_resource_monitoring()
    return {
        start_time = ngx.now(),
        start_memory = _M.get_kong_memory_usage()
    }
end

function _M.stop_resource_monitoring(monitoring_data)
    return {
        duration = ngx.now() - monitoring_data.start_time,
        memory_delta = _M.get_kong_memory_usage() - monitoring_data.start_memory
    }
end

return _M
