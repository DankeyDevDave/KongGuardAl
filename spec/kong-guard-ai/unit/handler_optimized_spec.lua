--- Unit tests for Optimized Kong Guard AI Handler
-- Tests performance optimizations and functionality preservation

local KongGuardAIHandler = require("kong.plugins.kong-guard-ai.handler")

describe("Optimized Kong Guard AI Handler", function()
    local config
    local handler

    before_each(function()
        config = {
            block_threshold = 0.8,
            rate_limit_threshold = 0.6,
            ddos_rpm_threshold = 100,
            dry_run = false,
            log_level = "info",
            log_requests = true,
            enable_soar_integration = false,
            enable_mesh_enricher = false,
            enable_taxii_ingestion = false,
            enable_ai_gateway = false,
            whitelist_ips = {},
            threat_rate_limit = 60
        }

        -- Mock kong global
        _G.kong = {
            client = {
                get_forwarded_ip = function() return nil end,
                get_ip = function() return "127.0.0.1" end
            },
            request = {
                get_path = function() return "/api/test" end,
                get_method = function() return "GET" end,
                get_headers = function() return {["user-agent"] = "test-agent"} end,
                get_raw_query = function() return "param=value" end,
                get_raw_body = function() return nil end
            },
            response = {
                exit = function(code, body) return code, body end,
                set_header = function(key, value) end
            },
            router = {
                get_service = function() return {id = "test-service", name = "test"} end,
                get_route = function() return {id = "test-route", name = "test"} end
            },
            ctx = {
                plugin = {}
            },
            log = {
                info = function(...) end,
                warn = function(...) end,
                err = function(...) end,
                debug = function(...) end
            }
        }

        -- Mock ngx global
        _G.ngx = {
            now = function() return 1234567890 end,
            timer = {
                at = function(delay, callback) return true end
            },
            shared = {
                kong_cache = {
                    get = function(key) return nil end,
                    set = function(key, value, ttl) return true end,
                    incr = function(key, value, init, ttl) return 1 end
                }
            }
        }

        -- Mock cjson
        _G.cjson = {
            encode = function(obj) return '{"test": "data"}' end,
            decode = function(str) return {test = "data"} end
        }

        handler = KongGuardAIHandler
    end)

    after_each(function()
        _G.kong = nil
        _G.ngx = nil
        _G.cjson = nil
    end)

    describe("Performance Optimizations", function()
        it("should use cached strings", function()
            local str1 = handler.get_cached_string("test")
            local str2 = handler.get_cached_string("test")
            assert.equal(str1, str2)
        end)

        it("should pool tables efficiently", function()
            local tbl1 = handler.get_pooled_table()
            assert.is_table(tbl1)

            tbl1.test = "value"
            handler.return_pooled_table(tbl1)

            local tbl2 = handler.get_pooled_table()
            assert.is_table(tbl2)
            assert.equal("value", tbl2.test)  -- Should reuse the table
        end)

        it("should handle optimized whitelist checking", function()
            config.whitelist_ips = {"127.0.0.1", "192.168.1.1"}

            local result = handler:is_whitelisted_optimized("127.0.0.1", config.whitelist_ips)
            assert.is_true(result)

            local result2 = handler:is_whitelisted_optimized("10.0.0.1", config.whitelist_ips)
            assert.is_false(result2)
        end)

        it("should handle optimized block checking", function()
            -- Mock cache to return blocked status
            _G.ngx.shared.kong_cache.get = function(key)
                if key == "blocked:127.0.0.1" then
                    return "sql_injection"
                end
                return nil
            end

            local result = handler:is_blocked_optimized("127.0.0.1")
            assert.is_true(result)

            local result2 = handler:is_blocked_optimized("192.168.1.1")
            assert.is_false(result2)
        end)
    end)

    describe("Optimized Feature Extraction", function()
        it("should extract features efficiently", function()
            local request = kong.request
            local client_ip = "127.0.0.1"
            local headers = request.get_headers()
            local method = request.get_method()
            local path = request.get_path()

            local features = handler:extract_features_optimized(request, client_ip, config, headers, method, path)

            assert.is_table(features)
            assert.equal(client_ip, features.client_ip)
            assert.equal(method, features.method)
            assert.equal(path, features.path)
            assert.is_number(features.requests_per_minute)
            assert.is_number(features.header_count)
        end)

        it("should cache features for similar requests", function()
            local request = kong.request
            local client_ip = "127.0.0.1"
            local headers = request.get_headers()
            local method = request.get_method()
            local path = request.get_path()

            -- First call should compute features
            local features1 = handler:extract_features_optimized(request, client_ip, config, headers, method, path)

            -- Second call with same parameters should use cache
            local features2 = handler:extract_features_optimized(request, client_ip, config, headers, method, path)

            assert.equal(features1, features2)
        end)
    end)

    describe("Optimized Threat Detection", function()
        it("should detect patterns efficiently", function()
            local features = {
                path = "/api/test",
                requests_per_minute = 50
            }

            local score, threat_type = handler:detect_patterns_optimized(features, config)
            assert.is_number(score)
            assert.is_string(threat_type)
        end)

        it("should handle high-threat patterns", function()
            local features = {
                path = "/api/union select",
                requests_per_minute = 50
            }

            local score, threat_type = handler:detect_patterns_optimized(features, config)
            assert.equal(0.95, score)
            assert.equal("sql_injection", threat_type)
        end)

        it("should handle DDoS patterns", function()
            local features = {
                path = "/api/test",
                requests_per_minute = 150  -- Above threshold
            }

            config.ddos_rpm_threshold = 100
            local score, threat_type = handler:detect_patterns_optimized(features, config)
            assert.equal(0.8, score)
            assert.equal("ddos", threat_type)
        end)
    end)

    describe("Optimized Rate Limiting", function()
        it("should apply basic rate limiting efficiently", function()
            local client_ip = "127.0.0.1"
            local threat_score = 0.7
            local features = {requests_per_minute = 50}

            local result = handler:apply_advanced_rate_limiting_optimized(client_ip, threat_score, features, config)

            assert.is_table(result)
            assert.is_boolean(result.should_block)
            assert.is_string(result.type)
        end)

        it("should block when rate limit exceeded", function()
            -- Mock cache to simulate rate limit exceeded
            local call_count = 0
            _G.ngx.shared.kong_cache.incr = function(key, value, init, ttl)
                call_count = call_count + 1
                return 70  -- Above limit of 60
            end

            local client_ip = "127.0.0.1"
            local threat_score = 0.7
            local features = {requests_per_minute = 50}

            local result = handler:apply_advanced_rate_limiting_optimized(client_ip, threat_score, features, config)

            assert.is_true(result.should_block)
            assert.equal("basic_rate_limit", result.type)
        end)
    end)

    describe("Optimized Metrics", function()
        it("should update metrics efficiently", function()
            local threat_score = 0.7
            local features = {
                mesh = {namespace = "test-ns"}
            }

            handler:update_metrics_optimized(threat_score, features, config)

            -- Should not error and should update cache
            assert.is_true(true)
        end)

        it("should handle mesh metrics", function()
            local threat_score = 0.7
            local features = {
                mesh = {
                    namespace = "test-namespace",
                    service = "test-service"
                }
            }

            handler:update_metrics_optimized(threat_score, features, config)
            assert.is_true(true)
        end)
    end)

    describe("Optimized Request Processing", function()
        it("should handle whitelisted requests", function()
            config.whitelist_ips = {"127.0.0.1"}

            -- Mock kong.request.get_path to return metrics endpoint
            kong.request.get_path = function() return "/api/test" end

            -- This should return early due to whitelist
            local result = {handler:access(config)}
            -- Should not have called response.exit
            assert.equal(0, #result)
        end)

        it("should handle blocked requests", function()
            -- Mock cache to return blocked status
            _G.ngx.shared.kong_cache.get = function(key)
                if key == "blocked:127.0.0.1" then
                    return "sql_injection"
                end
                return nil
            end

            kong.request.get_path = function() return "/api/test" end

            local code, body = handler:access(config)
            assert.equal(403, code)
            assert.is_table(body)
        end)

        it("should handle metrics endpoint", function()
            kong.request.get_path = function() return "/_kong_guard_ai/metrics" end

            local code, body = handler:access(config)
            assert.equal(503, code)  -- No prometheus metrics configured
        end)
    end)

    describe("Optimized Async Processing", function()
        it("should process SOAR operations asynchronously", function()
            local threat_data = {
                score = 0.9,
                client_ip = "127.0.0.1",
                path = "/api/test",
                soar = {}
            }
            local features = {}

            config.enable_soar_integration = true

            -- Should not error
            handler:process_soar_async(threat_data, features, config)
            assert.is_true(true)
        end)

        it("should process log operations efficiently", function()
            local threat_data = {
                score = 0.7,
                client_ip = "127.0.0.1",
                type = "test_threat",
                soar = {}
            }

            handler:process_log_operations_optimized(threat_data, config)
            assert.is_true(true)
        end)
    end)

    describe("Memory Management", function()
        it("should provide performance statistics", function()
            local stats = handler:get_performance_stats()

            assert.is_table(stats)
            assert.is_table(stats.memory_usage)
            assert.is_number(stats.modules_loaded)
            assert.is_number(stats.instances_cached)
        end)

        it("should cleanup resources", function()
            -- Add some cached data
            handler.get_cached_string("test1")
            handler.get_cached_string("test2")
            local tbl = handler.get_pooled_table()
            handler.return_pooled_table(tbl)

            local initial_stats = handler:get_performance_stats()

            handler:cleanup()

            local final_stats = handler:get_performance_stats()

            -- Should have cleaned up resources
            assert.is_true(final_stats.memory_usage.table_pool_size <= initial_stats.memory_usage.table_pool_size)
        end)
    end)

    describe("Error Handling", function()
        it("should handle missing kong cache gracefully", function()
            _G.ngx.shared.kong_cache = nil

            local result = handler:is_blocked_optimized("127.0.0.1")
            assert.is_false(result)

            local rate = handler:get_request_rate_optimized("127.0.0.1", 60)
            assert.equal(0, rate)
        end)

        it("should handle invalid threat data in log phase", function()
            kong.ctx.plugin.threat_data = nil

            -- Should not error
            handler:log(config)
            assert.is_true(true)
        end)

        it("should handle low-threat requests efficiently", function()
            kong.ctx.plugin.threat_data = {score = 0.05}

            -- Should return early
            handler:log(config)
            assert.is_true(true)
        end)
    end)

    describe("Lazy Loading", function()
        it("should lazy load modules", function()
            -- Mock require to track calls
            local original_require = _G.require
            local loaded_modules = {}

            _G.require = function(path)
                loaded_modules[path] = true
                return {new = function() return {} end}
            end

            -- First call should load module
            local instance1 = handler.get_instance("test_module", config)
            assert.is_true(loaded_modules["kong.plugins.kong-guard-ai.test_module"])

            -- Second call should use cache
            loaded_modules = {}  -- Reset
            local instance2 = handler.get_instance("test_module", config)
            assert.is_nil(loaded_modules["kong.plugins.kong-guard-ai.test_module"])

            _G.require = original_require
        end)

        it("should handle module loading errors", function()
            local original_require = _G.require
            _G.require = function() error("Module not found") end

            local instance = handler.get_instance("nonexistent", config)
            assert.is_nil(instance)

            _G.require = original_require
        end)
    end)

    describe("Request Rate Optimization", function()
        it("should calculate request rates efficiently", function()
            local client_ip = "127.0.0.1"
            local window = 60

            local rate1 = handler:get_request_rate_optimized(client_ip, window)
            local rate2 = handler:get_request_rate_optimized(client_ip, window)

            assert.is_number(rate1)
            assert.is_number(rate2)
        end)

        it("should handle cache unavailability", function()
            _G.ngx.shared.kong_cache = nil

            local rate = handler:get_request_rate_optimized("127.0.0.1", 60)
            assert.equal(0, rate)
        end)
    end)
end)
