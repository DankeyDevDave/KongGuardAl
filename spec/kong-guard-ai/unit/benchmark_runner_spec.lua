--- Unit tests for Benchmark Runner Module
-- Tests performance benchmarking, load testing, metrics analysis, and regression detection

local BenchmarkRunner = require("kong.plugins.kong-guard-ai.benchmark_runner")

describe("Benchmark Runner", function()
    local config
    local runner

    before_each(function()
        config = {
            max_response_time_ms = 1000,
            max_error_rate_percent = 5,
            min_throughput_rps = 100,
            max_memory_usage_mb = 512,
            max_cpu_usage_percent = 80,
            enable_automated_benchmarks = true,
            benchmark_schedule = "daily",
            automated_scenarios = {"normal_load"}
        }

        -- Mock kong global
        _G.kong = {
            log = {
                info = function(...) end,
                warn = function(...) end,
                err = function(...) end,
                debug = function(...) end
            }
        }

        -- Mock ngx global
        _G.ngx = {
            now = function() return os.time() end,
            timer = {
                at = function(delay, callback) return true end,
                every = function(interval, callback) return true end
            },
            sleep = function(seconds) end
        }

        -- Mock cjson
        _G.cjson = {
            encode = function(obj) return "{}" end,
            decode = function(str) return {} end
        }

        -- Mock math.random for predictable testing
        local original_random = math.random
        math.random = function(...)
            if ... then
                return original_random(...)
            else
                return 0.5  -- Return 0.5 for consistent behavior
            end
        end

        runner = BenchmarkRunner.new(config)
        assert.is_not_nil(runner)
    end)

    after_each(function()
        runner = nil
        _G.kong = nil
        _G.ngx = nil
        _G.cjson = nil
        math.random = _G.original_math_random or math.random
    end)

    describe("Initialization", function()
        it("should create runner with valid config", function()
            local rnr = BenchmarkRunner.new(config)
            assert.is_not_nil(rnr)
            assert.is_table(rnr.scenarios)
            assert.is_table(rnr.thresholds)
            assert.is_table(rnr.automation)
        end)

        it("should fail with invalid config", function()
            local rnr, err = BenchmarkRunner.new(nil)
            assert.is_nil(rnr)
            assert.is_string(err)
        end)

        it("should initialize with default scenarios", function()
            assert.is_table(runner.scenarios.light_load)
            assert.is_table(runner.scenarios.normal_load)
            assert.is_table(runner.scenarios.heavy_load)
            assert.is_table(runner.scenarios.stress_test)
        end)
    end)

    describe("Benchmark Execution", function()
        it("should run a benchmark scenario", function()
            local success, benchmark_id = runner:run_benchmark("light_load")
            assert.is_true(success)
            assert.is_string(benchmark_id)
            assert.equal("benchmark-", benchmark_id:sub(1, 11))
        end)

        it("should reject unknown scenarios", function()
            local success, err = runner:run_benchmark("unknown_scenario")
            assert.is_false(success)
            assert.equal("Unknown scenario: unknown_scenario", err)
        end)

        it("should reject concurrent benchmarks", function()
            -- Start first benchmark
            runner:run_benchmark("light_load")

            -- Try to start second benchmark
            local success, err = runner:run_benchmark("normal_load")
            assert.is_false(success)
            assert.equal("Benchmark already running", err)
        end)

        it("should handle custom benchmark config", function()
            local custom_config = {
                duration = 10,
                concurrent_users = 5
            }

            local success = runner:run_benchmark("normal_load", custom_config)
            assert.is_true(success)

            -- Verify custom config was applied
            assert.equal(10, runner.current_benchmark.scenario.duration)
        end)
    end)

    describe("Metrics Collection", function()
        it("should record request metrics", function()
            local success = true
            local response_time = 150
            local request_time = ngx.now()

            runner:_record_request_metrics(success, response_time, request_time)

            assert.equal(1, #runner.collectors.response_times)
            assert.equal(response_time, runner.collectors.response_times[1].value)
            assert.equal(success, runner.collectors.response_times[1].success)
        end)

        it("should collect system metrics", function()
            local initial_count = #runner.collectors.resource_usage

            runner:_collect_metrics()

            assert.is_true(#runner.collectors.resource_usage > initial_count)
        end)

        it("should calculate percentiles correctly", function()
            local sorted_array = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100}

            local p50 = runner:_calculate_percentile(sorted_array, 50)
            local p95 = runner:_calculate_percentile(sorted_array, 95)
            local p99 = runner:_calculate_percentile(sorted_array, 99)

            assert.equal(50, p50)  -- 50th percentile
            assert.equal(95, p95)  -- 95th percentile
            assert.equal(100, p99) -- 99th percentile
        end)
    end)

    describe("Results Analysis", function()
        before_each(function()
            -- Add some mock request data
            runner.collectors.response_times = {
                {time = ngx.now(), value = 100, success = true},
                {time = ngx.now(), value = 200, success = true},
                {time = ngx.now(), value = 300, success = false},
                {time = ngx.now(), value = 150, success = true}
            }

            runner.collectors.resource_usage = {
                {time = ngx.now(), memory_mb = 256, type = "memory"},
                {time = ngx.now(), cpu_percent = 45, type = "cpu"}
            }

            runner.current_benchmark.start_time = ngx.now() - 60
            runner.current_benchmark.end_time = ngx.now()
        end)

        it("should analyze benchmark results", function()
            local results = runner:_analyze_results()

            assert.is_table(results)
            assert.equal(4, results.total_requests)
            assert.equal(3, results.successful_requests)
            assert.equal(1, results.failed_requests)
            assert.equal(187.5, results.average_response_time)  -- (100+200+300+150)/4
            assert.equal(25, results.error_rate_percent)  -- 1/4 * 100
            assert.equal(256, results.average_memory_mb)
            assert.equal(45, results.average_cpu_percent)
        end)

        it("should check performance thresholds", function()
            local results = {
                average_response_time = 500,
                error_rate_percent = 2,
                throughput_rps = 150,
                average_memory_mb = 300
            }

            local passed = runner:_check_thresholds(results)
            assert.is_true(passed)
        end)

        it("should detect threshold violations", function()
            local results = {
                average_response_time = 1500,  -- Above threshold
                error_rate_percent = 2,
                throughput_rps = 150,
                average_memory_mb = 300
            }

            local passed = runner:_check_thresholds(results)
            assert.is_false(passed)
        end)
    end)

    describe("Regression Detection", function()
        before_each(function()
            -- Add historical benchmark data
            runner.history.benchmarks = {
                {
                    id = "benchmark-1",
                    scenario = "normal_load",
                    timestamp = ngx.now() - 86400,
                    results = {
                        average_response_time = 200,
                        throughput_rps = 500,
                        error_rate_percent = 1
                    },
                    passed = true
                }
            }
        end)

        it("should detect response time regression", function()
            local current_results = {
                average_response_time = 300,  -- 50% increase
                throughput_rps = 500,
                error_rate_percent = 1
            }

            runner:_check_for_regressions(current_results)

            assert.equal(1, #runner.history.regressions)
            assert.equal("response_time", runner.history.regressions[1].type)
            assert.equal(50, runner.history.regressions[1].change_percent)
        end)

        it("should detect throughput regression", function()
            local current_results = {
                average_response_time = 200,
                throughput_rps = 300,  -- 40% decrease
                error_rate_percent = 1
            }

            runner:_check_for_regressions(current_results)

            assert.equal(1, #runner.history.regressions)
            assert.equal("throughput", runner.history.regressions[1].type)
        end)

        it("should detect error rate regression", function()
            local current_results = {
                average_response_time = 200,
                throughput_rps = 500,
                error_rate_percent = 3  -- 2% absolute increase
            }

            runner:_check_for_regressions(current_results)

            assert.equal(1, #runner.history.regressions)
            assert.equal("error_rate", runner.history.regressions[1].type)
        end)

        it("should not detect regression for small changes", function()
            local current_results = {
                average_response_time = 210,  -- 5% increase (below threshold)
                throughput_rps = 475,        -- 5% decrease (below threshold)
                error_rate_percent = 1.5     -- 0.5% increase (below threshold)
            }

            local initial_regressions = #runner.history.regressions
            runner:_check_for_regressions(current_results)

            assert.equal(initial_regressions, #runner.history.regressions)
        end)
    end)

    describe("Benchmark History", function()
        it("should store benchmark results in history", function()
            local results = {
                total_requests = 100,
                average_response_time = 150,
                throughput_rps = 200,
                error_rate_percent = 2
            }

            local initial_count = #runner.history.benchmarks
            runner:_store_benchmark_history(results, true)

            assert.equal(initial_count + 1, #runner.history.benchmarks)
            assert.equal(results, runner.history.benchmarks[#runner.history.benchmarks].results)
            assert.is_true(runner.history.benchmarks[#runner.history.benchmarks].passed)
        end)

        it("should limit history size", function()
            -- Add 101 benchmarks (over the limit of 100)
            for i = 1, 101 do
                local results = {total_requests = i, average_response_time = 100}
                runner:_store_benchmark_history(results, true)
            end

            assert.equal(100, #runner.history.benchmarks)
        end)
    end)

    describe("Automated Benchmarking", function()
        it("should calculate schedule intervals", function()
            assert.equal(3600, runner:_get_schedule_interval("hourly"))
            assert.equal(86400, runner:_get_schedule_interval("daily"))
            assert.equal(604800, runner:_get_schedule_interval("weekly"))
            assert.equal(86400, runner:_get_schedule_interval("unknown"))
        end)

        it("should run automated benchmarks when enabled", function()
            runner.automation.enabled = true
            runner.automation.scenarios = {"light_load"}

            -- Mock the run_benchmark method to avoid actual execution
            local original_run = runner.run_benchmark
            local called = false
            runner.run_benchmark = function(self, scenario)
                called = true
                return true, "automated-benchmark-id"
            end

            runner:_run_automated_benchmark()

            assert.is_true(called)

            -- Restore original method
            runner.run_benchmark = original_run
        end)

        it("should skip automated benchmarks when already running", function()
            runner.current_benchmark.status = "running"

            local original_run = runner.run_benchmark
            local called = false
            runner.run_benchmark = function(self, scenario)
                called = true
                return false, "already running"
            end

            runner:_run_automated_benchmark()

            assert.is_false(called)

            runner.run_benchmark = original_run
        end)
    end)

    describe("Status and Statistics", function()
        it("should return current benchmark status", function()
            local status = runner:get_status()

            assert.is_table(status)
            assert.is_nil(status.current_benchmark)  -- No benchmark running

            -- Start a benchmark
            runner:run_benchmark("light_load")
            status = runner:get_status()

            assert.is_table(status.current_benchmark)
            assert.equal("benchmark-", status.current_benchmark.id:sub(1, 11))
            assert.equal("warming_up", status.current_benchmark.status)
        end)

        it("should return comprehensive statistics", function()
            -- Add some historical data
            runner.history.benchmarks = {
                {
                    id = "bench-1",
                    scenario = "light_load",
                    timestamp = ngx.now(),
                    passed = true,
                    results = {
                        average_response_time = 100,
                        throughput_rps = 200,
                        error_rate_percent = 1
                    }
                },
                {
                    id = "bench-2",
                    scenario = "normal_load",
                    timestamp = ngx.now(),
                    passed = false,
                    results = {
                        average_response_time = 150,
                        throughput_rps = 180,
                        error_rate_percent = 2
                    }
                }
            }

            local stats = runner:get_stats()

            assert.is_table(stats)
            assert.is_table(stats.summary)
            assert.equal(2, stats.summary.total_benchmarks)
            assert.equal(1, stats.summary.passed_benchmarks)
            assert.equal(1, stats.summary.failed_benchmarks)
            assert.equal(50, stats.summary.success_rate_percent)
            assert.equal(125, stats.summary.average_response_time)  -- (100+150)/2
            assert.equal(200, stats.summary.peak_throughput_rps)
        end)

        it("should calculate performance trends", function()
            -- Add historical data with clear trends
            runner.history.benchmarks = {
                {
                    timestamp = ngx.now() - 100,
                    results = {
                        average_response_time = 100,
                        throughput_rps = 200,
                        error_rate_percent = 1
                    }
                },
                {
                    timestamp = ngx.now(),
                    results = {
                        average_response_time = 120,  -- 20% increase
                        throughput_rps = 180,         -- 10% decrease
                        error_rate_percent = 1.5      -- 0.5% increase
                    }
                }
            }

            local trends = runner:_calculate_performance_trends()

            assert.is_table(trends)
            assert.equal(20, trends.response_time_trend)    -- 20% increase
            assert.equal(-10, trends.throughput_trend)      -- 10% decrease
            assert.equal(0.5, trends.error_rate_trend)      -- 0.5% increase
        end)
    end)

    describe("Request Simulation", function()
        it("should simulate requests successfully", function()
            local success, response_time = runner:_simulate_request("test-request")

            assert.is_boolean(success)
            assert.is_number(response_time)
            assert.is_true(response_time >= 10 and response_time <= 200)
        end)

        it("should simulate warmup requests without logging", function()
            local success, response_time = runner:_simulate_request("warmup-request", true)

            assert.is_boolean(success)
            assert.is_number(response_time)
        end)
    end)

    describe("Cleanup", function()
        it("should clean up benchmark data", function()
            -- Add some data
            runner.collectors.response_times = {{time = ngx.now(), value = 100, success = true}}
            runner.collectors.resource_usage = {{time = ngx.now(), memory_mb = 256, type = "memory"}}
            runner.current_benchmark.status = "running"

            runner:cleanup()

            assert.equal(0, #runner.collectors.response_times)
            assert.equal(0, #runner.collectors.resource_usage)
            assert.equal("idle", runner.current_benchmark.status)
        end)
    end)

    describe("Error Handling", function()
        it("should handle empty results analysis", function()
            runner.collectors.response_times = {}
            runner.collectors.resource_usage = {}

            local results = runner:_analyze_results()

            assert.is_table(results)
            assert.equal(0, results.total_requests)
            assert.equal(0, results.average_response_time)
            assert.equal(0, results.average_memory_mb)
        end)

        it("should handle empty percentile calculation", function()
            local percentile = runner:_calculate_percentile({}, 50)
            assert.equal(0, percentile)
        end)

        it("should handle single benchmark for trends", function()
            runner.history.benchmarks = {
                {
                    results = {average_response_time = 100}
                }
            }

            local trends = runner:_calculate_performance_trends()
            assert.equal(0, #trends)  -- Empty table for insufficient data
        end)
    end)
end)