--- Benchmark Runner Module for Kong Guard AI
-- Provides comprehensive performance benchmarking, load testing, and metrics analysis
-- for optimizing and validating system performance under various conditions.

local _M = {}
local mt = { __index = _M }

-- Dependencies
local kong = kong
local ngx = ngx
local math = math
local table = table
local string = string
local os = os
local cjson = require("cjson.safe")

-- Constants
local DEFAULT_BENCHMARK_DURATION = 60
local DEFAULT_CONCURRENT_USERS = 100
local DEFAULT_RAMP_UP_TIME = 10
local DEFAULT_THINK_TIME = 1
local DEFAULT_METRICS_INTERVAL = 5
local DEFAULT_WARMUP_DURATION = 10

--- Create a new benchmark runner instance
-- @param config Configuration table with benchmark settings
-- @return Benchmark runner instance
function _M.new(config)
    if not config then
        return nil, "Configuration required for benchmark runner"
    end

    local self = {
        -- Configuration
        config = config,

        -- Benchmark scenarios
        scenarios = {
            light_load = {
                duration = 30,
                concurrent_users = 10,
                ramp_up_time = 5,
                think_time = 1,
                request_rate = 50
            },
            normal_load = {
                duration = 60,
                concurrent_users = 100,
                ramp_up_time = 10,
                think_time = 1,
                request_rate = 500
            },
            heavy_load = {
                duration = 120,
                concurrent_users = 500,
                ramp_up_time = 30,
                think_time = 0.5,
                request_rate = 2000
            },
            stress_test = {
                duration = 300,
                concurrent_users = 1000,
                ramp_up_time = 60,
                think_time = 0.1,
                request_rate = 5000
            }
        },

        -- Current benchmark state
        current_benchmark = {
            id = nil,
            scenario = nil,
            status = "idle",  -- idle, warming_up, running, completed, failed
            start_time = 0,
            end_time = 0,
            metrics = {},
            results = {}
        },

        -- Metrics collectors
        collectors = {
            response_times = {},
            throughput = {},
            error_rates = {},
            resource_usage = {},
            custom_metrics = {}
        },

        -- Performance thresholds
        thresholds = {
            max_response_time_ms = config.max_response_time_ms or 1000,
            max_error_rate_percent = config.max_error_rate_percent or 5,
            min_throughput_rps = config.min_throughput_rps or 100,
            max_memory_usage_mb = config.max_memory_usage_mb or 512,
            max_cpu_usage_percent = config.max_cpu_usage_percent or 80
        },

        -- Historical benchmark data
        history = {
            benchmarks = {},
            trends = {},
            regressions = {}
        },

        -- Automated benchmarking
        automation = {
            enabled = config.enable_automated_benchmarks or false,
            schedule = config.benchmark_schedule or "daily",
            scenarios = config.automated_scenarios or {"normal_load"},
            last_run = 0,
            next_run = 0
        },

        -- Performance metrics
        metrics = {
            benchmarks_run = 0,
            benchmarks_passed = 0,
            benchmarks_failed = 0,
            total_test_duration = 0,
            average_response_time = 0,
            peak_throughput = 0,
            regression_detected = 0
        }
    }

    return setmetatable(self, mt)
end

--- Initialize benchmark runner
function _M:init()
    -- Set up automated benchmarking if enabled
    if self.automation.enabled then
        self:_init_automated_benchmarking()
    end

    -- Initialize metrics collectors
    self:_init_metrics_collectors()

    kong.log.info("[kong-guard-ai] Benchmark runner initialized")
end

--- Initialize automated benchmarking
function _M:_init_automated_benchmarking()
    -- Set up timer for automated benchmarks
    local schedule_interval = self:_get_schedule_interval()

    local ok, err = ngx.timer.every(schedule_interval, function()
        self:_run_automated_benchmark()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize automated benchmarking: ", err)
    end

    self.automation.next_run = ngx.now() + schedule_interval
end

--- Get schedule interval in seconds
function _M:_get_schedule_interval()
    local schedule = self.automation.schedule

    if schedule == "hourly" then
        return 3600
    elseif schedule == "daily" then
        return 86400
    elseif schedule == "weekly" then
        return 604800
    else
        return 86400  -- Default to daily
    end
end

--- Initialize metrics collectors
function _M:_init_metrics_collectors()
    -- Set up periodic metrics collection
    local ok, err = ngx.timer.every(DEFAULT_METRICS_INTERVAL, function()
        if self.current_benchmark.status == "running" then
            self:_collect_metrics()
        end
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize metrics collection: ", err)
    end
end

--- Run a benchmark scenario
function _M:run_benchmark(scenario_name, custom_config)
    if self.current_benchmark.status ~= "idle" then
        return false, "Benchmark already running"
    end

    local scenario = self.scenarios[scenario_name]
    if not scenario then
        return false, "Unknown scenario: " .. scenario_name
    end

    -- Merge custom config
    if custom_config then
        for k, v in pairs(custom_config) do
            scenario[k] = v
        end
    end

    -- Initialize benchmark
    self.current_benchmark = {
        id = "benchmark-" .. ngx.now() .. "-" .. scenario_name,
        scenario = scenario_name,
        status = "warming_up",
        start_time = ngx.now(),
        end_time = 0,
        metrics = {},
        results = {}
    }

    kong.log.info("[kong-guard-ai] Starting benchmark: ", {
        id = self.current_benchmark.id,
        scenario = scenario_name,
        duration = scenario.duration,
        concurrent_users = scenario.concurrent_users
    })

    -- Start warmup phase
    self:_run_warmup_phase(scenario)

    -- Start main benchmark
    self:_run_main_benchmark(scenario)

    return true, self.current_benchmark.id
end

--- Run warmup phase
function _M:_run_warmup_phase(scenario)
    local warmup_duration = scenario.warmup_duration or DEFAULT_WARMUP_DURATION
    local warmup_users = math.floor(scenario.concurrent_users * 0.2)  -- 20% of full load

    kong.log.debug("[kong-guard-ai] Starting warmup phase: ", {
        duration = warmup_duration,
        users = warmup_users
    })

    -- Simulate warmup requests
    for i = 1, warmup_users do
        self:_simulate_request("warmup-" .. i, true)
    end

    -- Wait for warmup to complete
    ngx.sleep(warmup_duration)

    self.current_benchmark.status = "running"
    kong.log.debug("[kong-guard-ai] Warmup phase completed")
end

--- Run main benchmark phase
function _M:_run_main_benchmark(scenario)
    local start_time = ngx.now()
    local end_time = start_time + scenario.duration

    kong.log.debug("[kong-guard-ai] Starting main benchmark phase: ", {
        duration = scenario.duration,
        concurrent_users = scenario.concurrent_users
    })

    -- Simulate concurrent users
    for user_id = 1, scenario.concurrent_users do
        self:_simulate_user_session(user_id, scenario, end_time)
    end

    -- Wait for benchmark to complete
    while ngx.now() < end_time do
        ngx.sleep(1)
    end

    -- Complete benchmark
    self:_complete_benchmark()
end

--- Simulate a user session
function _M:_simulate_user_session(user_id, scenario, end_time)
    -- Run in separate "thread" (simulated with timer)
    local ok, err = ngx.timer.at(0, function()
        local request_count = 0

        while ngx.now() < end_time do
            local request_start = ngx.now()

            -- Simulate request
            local success, response_time = self:_simulate_request("user-" .. user_id .. "-req-" .. request_count)

            -- Record metrics
            self:_record_request_metrics(success, response_time, request_start)

            request_count = request_count + 1

            -- Think time between requests
            if scenario.think_time > 0 then
                ngx.sleep(scenario.think_time)
            end
        end
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to simulate user session: ", err)
    end
end

--- Simulate a single request
function _M:_simulate_request(request_id, is_warmup)
    local start_time = ngx.now()

    -- Simulate request processing
    local processing_time = math.random(10, 200) / 1000  -- 10-200ms
    ngx.sleep(processing_time)

    -- Simulate occasional failures
    local success = math.random() > 0.05  -- 95% success rate

    local end_time = ngx.now()
    local response_time = (end_time - start_time) * 1000  -- Convert to milliseconds

    if not is_warmup then
        kong.log.debug("[kong-guard-ai] Simulated request: ", {
            id = request_id,
            response_time_ms = response_time,
            success = success
        })
    end

    return success, response_time
end

--- Record request metrics
function _M:_record_request_metrics(success, response_time, request_time)
    -- Record response time
    table.insert(self.collectors.response_times, {
        time = request_time,
        value = response_time,
        success = success
    })

    -- Update throughput metrics
    local time_bucket = math.floor(request_time / DEFAULT_METRICS_INTERVAL)
    if not self.collectors.throughput[time_bucket] then
        self.collectors.throughput[time_bucket] = 0
    end
    self.collectors.throughput[time_bucket] = self.collectors.throughput[time_bucket] + 1

    -- Update error rate metrics
    if not success then
        if not self.collectors.error_rates[time_bucket] then
            self.collectors.error_rates[time_bucket] = {total = 0, errors = 0}
        end
        self.collectors.error_rates[time_bucket].total =
            self.collectors.error_rates[time_bucket].total + 1
        self.collectors.error_rates[time_bucket].errors =
            self.collectors.error_rates[time_bucket].errors + 1
    end
end

--- Collect system metrics
function _M:_collect_metrics()
    local current_time = ngx.now()

    -- Collect memory usage
    local memory_usage = collectgarbage("count") / 1024  -- Convert to MB
    table.insert(self.collectors.resource_usage, {
        time = current_time,
        memory_mb = memory_usage,
        type = "memory"
    })

    -- Collect CPU usage (simulated)
    local cpu_usage = math.random(10, 90)  -- Simulated CPU usage
    table.insert(self.collectors.resource_usage, {
        time = current_time,
        cpu_percent = cpu_usage,
        type = "cpu"
    })

    -- Store in current benchmark metrics
    if not self.current_benchmark.metrics[current_time] then
        self.current_benchmark.metrics[current_time] = {}
    end

    self.current_benchmark.metrics[current_time].memory_mb = memory_usage
    self.current_benchmark.metrics[current_time].cpu_percent = cpu_usage
end

--- Complete benchmark and analyze results
function _M:_complete_benchmark()
    self.current_benchmark.end_time = ngx.now()
    self.current_benchmark.status = "completed"

    -- Analyze results
    local results = self:_analyze_results()

    -- Check thresholds
    local passed = self:_check_thresholds(results)

    -- Store in history
    self:_store_benchmark_history(results, passed)

    -- Update metrics
    self.metrics.benchmarks_run = self.metrics.benchmarks_run + 1
    if passed then
        self.metrics.benchmarks_passed = self.metrics.benchmarks_passed + 1
    else
        self.metrics.benchmarks_failed = self.metrics.benchmarks_failed + 1
    end

    -- Check for regressions
    self:_check_for_regressions(results)

    self.current_benchmark.results = results

    kong.log.info("[kong-guard-ai] Benchmark completed: ", {
        id = self.current_benchmark.id,
        scenario = self.current_benchmark.scenario,
        passed = passed,
        duration = self.current_benchmark.end_time - self.current_benchmark.start_time,
        avg_response_time = results.average_response_time,
        throughput_rps = results.throughput_rps,
        error_rate_percent = results.error_rate_percent
    })

    -- Reset for next benchmark
    self.current_benchmark.status = "idle"
end

--- Analyze benchmark results
function _M:_analyze_results()
    local response_times = self.collectors.response_times
    local total_requests = #response_times
    local successful_requests = 0
    local total_response_time = 0
    local min_response_time = math.huge
    local max_response_time = 0

    -- Calculate response time statistics
    for _, request in ipairs(response_times) do
        if request.success then
            successful_requests = successful_requests + 1
        end
        total_response_time = total_response_time + request.value
        min_response_time = math.min(min_response_time, request.value)
        max_response_time = math.max(max_response_time, request.value)
    end

    local avg_response_time = total_requests > 0 and (total_response_time / total_requests) or 0
    local success_rate = total_requests > 0 and (successful_requests / total_requests) or 0
    local error_rate = 1 - success_rate

    -- Calculate throughput
    local benchmark_duration = self.current_benchmark.end_time - self.current_benchmark.start_time
    local throughput_rps = total_requests / benchmark_duration

    -- Calculate percentiles
    local sorted_times = {}
    for _, request in ipairs(response_times) do
        table.insert(sorted_times, request.value)
    end
    table.sort(sorted_times)

    local p50 = self:_calculate_percentile(sorted_times, 50)
    local p95 = self:_calculate_percentile(sorted_times, 95)
    local p99 = self:_calculate_percentile(sorted_times, 99)

    -- Calculate resource usage averages
    local avg_memory = 0
    local avg_cpu = 0
    local resource_count = 0

    for _, resource in ipairs(self.collectors.resource_usage) do
        if resource.type == "memory" then
            avg_memory = avg_memory + resource.memory_mb
        elseif resource.type == "cpu" then
            avg_cpu = avg_cpu + resource.cpu_percent
        end
        resource_count = resource_count + 1
    end

    if resource_count > 0 then
        avg_memory = avg_memory / resource_count
        avg_cpu = avg_cpu / resource_count
    end

    return {
        total_requests = total_requests,
        successful_requests = successful_requests,
        failed_requests = total_requests - successful_requests,
        average_response_time = avg_response_time,
        min_response_time = min_response_time,
        max_response_time = max_response_time,
        p50_response_time = p50,
        p95_response_time = p95,
        p99_response_time = p99,
        throughput_rps = throughput_rps,
        success_rate = success_rate,
        error_rate_percent = error_rate * 100,
        average_memory_mb = avg_memory,
        average_cpu_percent = avg_cpu,
        benchmark_duration = benchmark_duration
    }
end

--- Calculate percentile from sorted array
function _M:_calculate_percentile(sorted_array, percentile)
    if #sorted_array == 0 then
        return 0
    end

    local index = math.ceil((percentile / 100) * #sorted_array)
    return sorted_array[index]
end

--- Check if results meet performance thresholds
function _M:_check_thresholds(results)
    local passed = true

    if results.average_response_time > self.thresholds.max_response_time_ms then
        kong.log.warn("[kong-guard-ai] Response time threshold exceeded: ", {
            actual = results.average_response_time,
            threshold = self.thresholds.max_response_time_ms
        })
        passed = false
    end

    if results.error_rate_percent > self.thresholds.max_error_rate_percent then
        kong.log.warn("[kong-guard-ai] Error rate threshold exceeded: ", {
            actual = results.error_rate_percent,
            threshold = self.thresholds.max_error_rate_percent
        })
        passed = false
    end

    if results.throughput_rps < self.thresholds.min_throughput_rps then
        kong.log.warn("[kong-guard-ai] Throughput threshold not met: ", {
            actual = results.throughput_rps,
            threshold = self.thresholds.min_throughput_rps
        })
        passed = false
    end

    if results.average_memory_mb > self.thresholds.max_memory_usage_mb then
        kong.log.warn("[kong-guard-ai] Memory usage threshold exceeded: ", {
            actual = results.average_memory_mb,
            threshold = self.thresholds.max_memory_usage_mb
        })
        passed = false
    end

    return passed
end

--- Store benchmark results in history
function _M:_store_benchmark_history(results, passed)
    local benchmark_record = {
        id = self.current_benchmark.id,
        scenario = self.current_benchmark.scenario,
        timestamp = self.current_benchmark.start_time,
        duration = self.current_benchmark.end_time - self.current_benchmark.start_time,
        results = results,
        passed = passed,
        config = self.config
    }

    table.insert(self.history.benchmarks, benchmark_record)

    -- Keep only last 100 benchmarks
    if #self.history.benchmarks > 100 then
        table.remove(self.history.benchmarks, 1)
    end
end

--- Check for performance regressions
function _M:_check_for_regressions(current_results)
    if #self.history.benchmarks < 2 then
        return  -- Need at least 2 benchmarks for comparison
    end

    local previous_benchmark = self.history.benchmarks[#self.history.benchmarks - 1]
    local regression_threshold = 0.1  -- 10% degradation threshold

    -- Check response time regression
    local response_time_change = (current_results.average_response_time -
                                 previous_benchmark.results.average_response_time) /
                                 previous_benchmark.results.average_response_time

    if response_time_change > regression_threshold then
        self:_record_regression("response_time", response_time_change, current_results, previous_benchmark)
    end

    -- Check throughput regression
    local throughput_change = (previous_benchmark.results.throughput_rps -
                              current_results.throughput_rps) /
                              previous_benchmark.results.throughput_rps

    if throughput_change > regression_threshold then
        self:_record_regression("throughput", throughput_change, current_results, previous_benchmark)
    end

    -- Check error rate regression
    local error_rate_change = current_results.error_rate_percent -
                             previous_benchmark.results.error_rate_percent

    if error_rate_change > 1.0 then  -- 1% absolute increase
        self:_record_regression("error_rate", error_rate_change, current_results, previous_benchmark)
    end
end

--- Record a performance regression
function _M:_record_regression(type, change, current_results, previous_benchmark)
    local regression = {
        type = type,
        change_percent = change * 100,
        timestamp = ngx.now(),
        current_benchmark = self.current_benchmark.id,
        previous_benchmark = previous_benchmark.id,
        current_value = current_results[type == "response_time" and "average_response_time" or
                                       type == "throughput" and "throughput_rps" or
                                       "error_rate_percent"],
        previous_value = previous_benchmark.results[type == "response_time" and "average_response_time" or
                                                   type == "throughput" and "throughput_rps" or
                                                   "error_rate_percent"]
    }

    table.insert(self.history.regressions, regression)
    self.metrics.regression_detected = self.metrics.regression_detected + 1

    kong.log.warn("[kong-guard-ai] Performance regression detected: ", {
        type = type,
        change_percent = regression.change_percent,
        current_value = regression.current_value,
        previous_value = regression.previous_value
    })
end

--- Run automated benchmark
function _M:_run_automated_benchmark()
    if self.current_benchmark.status ~= "idle" then
        kong.log.debug("[kong-guard-ai] Skipping automated benchmark - already running")
        return
    end

    local scenario = self.automation.scenarios[math.random(#self.automation.scenarios)]
    local success, benchmark_id = self:run_benchmark(scenario)

    if success then
        self.automation.last_run = ngx.now()
        kong.log.info("[kong-guard-ai] Automated benchmark started: ", benchmark_id)
    else
        kong.log.warn("[kong-guard-ai] Failed to start automated benchmark: ", benchmark_id)
    end
end

--- Get benchmark status
function _M:get_status()
    return {
        current_benchmark = self.current_benchmark.status ~= "idle" and {
            id = self.current_benchmark.id,
            scenario = self.current_benchmark.scenario,
            status = self.current_benchmark.status,
            progress = self.current_benchmark.end_time > 0 and
                      ((ngx.now() - self.current_benchmark.start_time) /
                       (self.current_benchmark.end_time - self.current_benchmark.start_time)) or 0,
            start_time = self.current_benchmark.start_time
        } or nil,
        automation = self.automation.enabled and {
            schedule = self.automation.schedule,
            last_run = self.automation.last_run,
            next_run = self.automation.next_run
        } or nil,
        recent_results = self:_get_recent_results()
    }
end

--- Get recent benchmark results
function _M:_get_recent_results()
    local recent = {}
    local count = math.min(5, #self.history.benchmarks)

    for i = #self.history.benchmarks - count + 1, #self.history.benchmarks do
        if self.history.benchmarks[i] then
            table.insert(recent, {
                id = self.history.benchmarks[i].id,
                scenario = self.history.benchmarks[i].scenario,
                timestamp = self.history.benchmarks[i].timestamp,
                passed = self.history.benchmarks[i].passed,
                avg_response_time = self.history.benchmarks[i].results.average_response_time,
                throughput_rps = self.history.benchmarks[i].results.throughput_rps,
                error_rate_percent = self.history.benchmarks[i].results.error_rate_percent
            })
        end
    end

    return recent
end

--- Get comprehensive benchmark statistics
function _M:get_stats()
    local total_benchmarks = #self.history.benchmarks
    local passed_benchmarks = 0
    local total_response_time = 0
    local max_throughput = 0

    for _, benchmark in ipairs(self.history.benchmarks) do
        if benchmark.passed then
            passed_benchmarks = passed_benchmarks + 1
        end
        total_response_time = total_response_time + benchmark.results.average_response_time
        max_throughput = math.max(max_throughput, benchmark.results.throughput_rps)
    end

    local avg_response_time = total_benchmarks > 0 and (total_response_time / total_benchmarks) or 0
    local success_rate = total_benchmarks > 0 and (passed_benchmarks / total_benchmarks) or 0

    return {
        summary = {
            total_benchmarks = total_benchmarks,
            passed_benchmarks = passed_benchmarks,
            failed_benchmarks = total_benchmarks - passed_benchmarks,
            success_rate_percent = success_rate * 100,
            average_response_time = avg_response_time,
            peak_throughput_rps = max_throughput,
            regressions_detected = #self.history.regressions
        },
        thresholds = self.thresholds,
        scenarios = self.scenarios,
        recent_regressions = self:_get_recent_regressions(),
        performance_trends = self:_calculate_performance_trends()
    }
end

--- Get recent performance regressions
function _M:_get_recent_regressions()
    local recent = {}
    local count = math.min(10, #self.history.regressions)

    for i = #self.history.regressions - count + 1, #self.history.regressions do
        if self.history.regressions[i] then
            table.insert(recent, self.history.regressions[i])
        end
    end

    return recent
end

--- Calculate performance trends
function _M:_calculate_performance_trends()
    if #self.history.benchmarks < 2 then
        return {}
    end

    local trends = {}
    local recent_benchmarks = {}

    -- Get last 10 benchmarks
    local start_idx = math.max(1, #self.history.benchmarks - 9)
    for i = start_idx, #self.history.benchmarks do
        table.insert(recent_benchmarks, self.history.benchmarks[i])
    end

    -- Calculate trends
    local first = recent_benchmarks[1]
    local last = recent_benchmarks[#recent_benchmarks]

    if first and last then
        trends.response_time_trend = ((last.results.average_response_time - first.results.average_response_time) /
                                     first.results.average_response_time) * 100
        trends.throughput_trend = ((last.results.throughput_rps - first.results.throughput_rps) /
                                  first.results.throughput_rps) * 100
        trends.error_rate_trend = last.results.error_rate_percent - first.results.error_rate_percent
    end

    return trends
end

--- Clean up benchmark data
function _M:cleanup()
    -- Clear current benchmark data
    self.current_benchmark = {
        id = nil,
        scenario = nil,
        status = "idle",
        start_time = 0,
        end_time = 0,
        metrics = {},
        results = {}
    }

    -- Clear collectors
    self.collectors.response_times = {}
    self.collectors.throughput = {}
    self.collectors.error_rates = {}
    self.collectors.resource_usage = {}

    kong.log.info("[kong-guard-ai] Benchmark runner cleanup completed")
end

return _M
