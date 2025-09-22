--- Unit tests for Threat Hunting Engine

local ThreatHunter = require "kong.plugins.kong-guard-ai.threat_hunter"

describe("Threat Hunter", function()
    local hunter
    local mock_config

    before_each(function()
        mock_config = {
            threat_hunting = {
                enable_hunting = true,
                hunting_queries = {
                    "pattern:union select",
                    "pattern:<script",
                    "statistical:anomalous_traffic",
                    "correlation:ip_useragent"
                },
                data_retention_days = 30
            }
        }
        hunter = ThreatHunter.new(mock_config)
    end)

    describe("new()", function()
        it("should create a new threat hunter instance", function()
            assert.is_not_nil(hunter)
            assert.is_table(hunter)
        end)

        it("should return nil for invalid config", function()
            local invalid_hunter = ThreatHunter.new(nil)
            assert.is_nil(invalid_hunter)
        end)
    end)

    describe("init()", function()
        it("should initialize successfully with valid config", function()
            local success, err = hunter:init()
            assert.is_true(success)
            assert.is_nil(err)
        end)

        it("should fail with missing threat hunting config", function()
            local bad_config = {}
            local bad_hunter = ThreatHunter.new(bad_config)
            local success, err = bad_hunter:init()
            assert.is_false(success)
            assert.is_not_nil(err)
        end)

        it("should skip initialization when disabled", function()
            local disabled_config = {
                threat_hunting = { enable_hunting = false }
            }
            local disabled_hunter = ThreatHunter.new(disabled_config)
            local success, err = disabled_hunter:init()
            assert.is_true(success)
        end)
    end)

    describe("initialize_pattern_library()", function()
        it("should initialize pattern library with expected categories", function()
            hunter:initialize_pattern_library()
            assert.is_table(hunter.pattern_library)
            assert.is_not_nil(hunter.pattern_library.sql_injection)
            assert.is_not_nil(hunter.pattern_library.xss)
            assert.is_not_nil(hunter.pattern_library.directory_traversal)
            assert.is_not_nil(hunter.pattern_library.command_injection)
            assert.is_not_nil(hunter.pattern_library.suspicious_ua)
            assert.is_not_nil(hunter.pattern_library.anomalous_requests)
        end)

        it("should have correct pattern structure", function()
            hunter:initialize_pattern_library()
            local sql_pattern = hunter.pattern_library.sql_injection
            assert.is_table(sql_pattern.patterns)
            assert.equals("high", sql_pattern.severity)
            assert.equals("injection", sql_pattern.category)
        end)
    end)

    describe("matches_pattern()", function()
        it("should match patterns in request data", function()
            local data = {
                request_path = "/api/users?query=union select * from users",
                user_agent = "Mozilla/5.0",
                query_string = "union select",
                request_body = "some data"
            }

            assert.is_true(hunter:matches_pattern(data, "union select"))
            assert.is_false(hunter:matches_pattern(data, "nonexistent"))
        end)

        it("should handle nil data", function()
            assert.is_false(hunter:matches_pattern(nil, "pattern"))
            assert.is_false(hunter:matches_pattern({}, nil))
        end)

        it("should match patterns in headers", function()
            local data = {
                headers = { ["user-agent"] = "sqlmap/1.0" }
            }

            assert.is_true(hunter:matches_pattern(data, "sqlmap"))
        end)
    end)

    describe("calculate_pattern_severity()", function()
        it("should calculate correct severity for known patterns", function()
            assert.equals("high", hunter:calculate_pattern_severity("union select"))
            assert.equals("high", hunter:calculate_pattern_severity("<script"))
            assert.equals("critical", hunter:calculate_pattern_severity("| cat"))
        end)

        it("should return low severity for unknown patterns", function()
            assert.equals("low", hunter:calculate_pattern_severity("unknown_pattern"))
        end)
    end)

    describe("get_pattern_category()", function()
        it("should return correct category for known patterns", function()
            assert.equals("injection", hunter:get_pattern_category("union select"))
            assert.equals("injection", hunter:get_pattern_category("<script"))
            assert.equals("traversal", hunter:get_pattern_category("../"))
        end)

        it("should return unknown for unrecognized patterns", function()
            assert.equals("unknown", hunter:get_pattern_category("random_string"))
        end)
    end)

    describe("execute_pattern_query()", function()
        before_each(function()
            -- Add some test data
            hunter:add_correlation_data({
                timestamp = ngx.now(),
                client_ip = "192.168.1.100",
                request_path = "/api/users?query=union select * from users",
                user_agent = "Mozilla/5.0",
                threat_score = 0.8
            })
        end)

        it("should execute pattern queries and return matches", function()
            local results = hunter:execute_pattern_query("pattern:union select", ngx.now() - 3600)
            assert.is_table(results)
            assert.equals(1, #results)
            assert.equals("pattern_match", results[1].type)
            assert.equals("union select", results[1].pattern)
        end)

        it("should return empty results for non-matching patterns", function()
            local results = hunter:execute_pattern_query("pattern:nonexistent", ngx.now() - 3600)
            assert.is_table(results)
            assert.equals(0, #results)
        end)
    end)

    describe("execute_statistical_query()", function()
        before_each(function()
            -- Add test data for statistical analysis
            for i = 1, 150 do
                hunter:add_correlation_data({
                    timestamp = ngx.now(),
                    client_ip = "192.168.1.100",
                    request_path = "/api/users",
                    user_agent = "Mozilla/5.0",
                    threat_score = 0.1
                })
            end
        end)

        it("should analyze anomalous traffic patterns", function()
            local results = hunter:execute_statistical_query("statistical:anomalous_traffic", ngx.now() - 3600)
            assert.is_table(results)
            -- Should detect high frequency from single IP
            local found_anomaly = false
            for _, result in ipairs(results) do
                if result.anomaly_type == "high_frequency_ip" then
                    found_anomaly = true
                    assert.equals("192.168.1.100", result.ip)
                    assert.equals(150, result.request_count)
                    break
                end
            end
            assert.is_true(found_anomaly)
        end)
    end)

    describe("analyze_correlations()", function()
        it("should detect correlations between events", function()
            local results = {
                {
                    type = "pattern_match",
                    data = { client_ip = "192.168.1.100" },
                    timestamp = ngx.now(),
                    severity = "high",
                    category = "injection"
                },
                {
                    type = "pattern_match",
                    data = { client_ip = "192.168.1.100" },
                    timestamp = ngx.now() + 60,
                    severity = "high",
                    category = "injection"
                }
            }

            local correlated = hunter:analyze_correlations(results, 3600)
            assert.is_table(correlated)

            -- Should include correlation alert
            local found_correlation = false
            for _, result in ipairs(correlated) do
                if result.type == "correlation_alert" then
                    found_correlation = true
                    assert.equals("multi_vector_attack", result.correlation_type)
                    assert.equals("192.168.1.100", result.ip)
                    assert.equals(2, result.event_count)
                    break
                end
            end
            assert.is_true(found_correlation)
        end)

        it("should handle empty results", function()
            local correlated = hunter:analyze_correlations({}, 3600)
            assert.is_table(correlated)
            assert.equals(0, #correlated)
        end)
    end)

    describe("add_correlation_data()", function()
        it("should add data to correlation analysis", function()
            local initial_count = #hunter.correlation_data

            hunter:add_correlation_data({
                timestamp = ngx.now(),
                client_ip = "192.168.1.100",
                request_path = "/api/test",
                user_agent = "Test Agent"
            })

            assert.equals(initial_count + 1, #hunter.correlation_data)
        end)

        it("should handle nil data", function()
            local initial_count = #hunter.correlation_data
            hunter:add_correlation_data(nil)
            assert.equals(initial_count, #hunter.correlation_data)
        end)

        it("should handle data without timestamp", function()
            local initial_count = #hunter.correlation_data
            hunter:add_correlation_data({ client_ip = "192.168.1.100" })
            assert.equals(initial_count, #hunter.correlation_data)
        end)
    end)

    describe("execute_hunting_queries()", function()
        it("should execute all configured hunting queries", function()
            -- Add some test data
            hunter:add_correlation_data({
                timestamp = ngx.now(),
                client_ip = "192.168.1.100",
                request_path = "/api/users?query=union select * from users",
                user_agent = "Mozilla/5.0"
            })

            local results, err = hunter:execute_hunting_queries(3600)
            assert.is_table(results)
            assert.is_nil(err)
        end)

        it("should return error when hunting is disabled", function()
            local disabled_config = {
                threat_hunting = { enable_hunting = false }
            }
            local disabled_hunter = ThreatHunter.new(disabled_config)
            local results, err = disabled_hunter:execute_hunting_queries(3600)
            assert.is_table(results)
            assert.is_not_nil(err)
        end)
    end)

    describe("get_health_status()", function()
        it("should return health status information", function()
            local status = hunter:get_health_status()
            assert.is_table(status)
            assert.is_boolean(status.enabled)
            assert.is_number(status.correlation_data_count)
            assert.is_number(status.cache_entries)
            assert.is_number(status.pattern_library_size)
            assert.is_table(status.metrics)
            assert.is_number(status.data_retention_days)
        end)
    end)

    describe("cleanup_cache()", function()
        it("should clean up expired cache entries", function()
            -- Add an old cache entry
            hunter.query_cache["old_key"] = {
                results = {},
                timestamp = ngx.now() - 400 -- Older than CACHE_TTL (300)
            }

            local initial_cache_size = 0
            for _ in pairs(hunter.query_cache) do
                initial_cache_size = initial_cache_size + 1
            end

            hunter:cleanup_cache()

            local final_cache_size = 0
            for _ in pairs(hunter.query_cache) do
                final_cache_size = final_cache_size + 1
            end

            assert.is_true(final_cache_size < initial_cache_size)
        end)
    end)

    describe("cache functionality", function()
        it("should cache query results", function()
            local query = "pattern:test"
            local time_window = 3600

            -- First execution should cache
            hunter:execute_query(query, ngx.now() - time_window)
            assert.is_not_nil(hunter.query_cache[query .. "_" .. time_window])

            -- Second execution should use cache
            local initial_cache_hits = hunter.metrics.cache_hits
            hunter:execute_query(query, ngx.now() - time_window)
            assert.equals(initial_cache_hits + 1, hunter.metrics.cache_hits)
        end)
    end)
end)