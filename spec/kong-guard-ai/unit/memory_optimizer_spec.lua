--- Unit tests for Memory Optimizer Module
-- Tests memory monitoring, object pooling, leak detection, and optimization features

local MemoryOptimizer = require("kong.plugins.kong-guard-ai.memory_optimizer")

describe("Memory Optimizer", function()
    local config
    local optimizer

    before_each(function()
        config = {
            memory_threshold_mb = 64,
            gc_threshold_ratio = 0.8,
            request_pool_size = 50,
            threat_pool_size = 50,
            cache_pool_size = 100,
            log_pool_size = 50,
            object_ttl = 1800,
            enable_leak_detection = true,
            leak_check_interval = 60,
            leak_threshold = 500,
            optimize_gc = true
        }

        -- Mock kong global
        _G.kong = {
            log = {
                info = function(...) end,
                warn = function(...) end,
                err = function(...) end,
                debug = function(...) end
            },
            metrics = {
                gauge = function(...) end,
                counter = function(...) end,
                histogram = function(...) end
            }
        }

        -- Mock ngx global
        _G.ngx = {
            now = function() return os.time() end,
            timer = {
                every = function(interval, callback)
                    return true
                end
            },
            var = {
                request_id = "test-request-123"
            }
        }

        optimizer = MemoryOptimizer.new(config)
        assert.is_not_nil(optimizer)
    end)

    after_each(function()
        optimizer = nil
        _G.kong = nil
        _G.ngx = nil
    end)

    describe("Initialization", function()
        it("should create optimizer with valid config", function()
            local opt = MemoryOptimizer.new(config)
            assert.is_not_nil(opt)
            assert.is_table(opt.memory_stats)
            assert.is_table(opt.pools)
            assert.is_table(opt.pool_configs)
        end)

        it("should fail with invalid config", function()
            local opt, err = MemoryOptimizer.new(nil)
            assert.is_nil(opt)
            assert.is_string(err)
        end)

        it("should initialize pools correctly", function()
            optimizer:init()

            for pool_name, pool in pairs(optimizer.pools) do
                assert.is_table(pool)
                assert.equal(optimizer.pool_configs[pool_name].max_size, #pool)
            end
        end)
    end)

    describe("Memory Monitoring", function()
        it("should monitor memory usage", function()
            local usage = optimizer:monitor_memory()
            assert.is_number(usage)
            assert.is_true(usage >= 0)
        end)

        it("should track peak memory usage", function()
            local initial_peak = optimizer.memory_stats.peak_usage
            optimizer:monitor_memory()
            assert.is_true(optimizer.memory_stats.peak_usage >= initial_peak)
        end)

        it("should handle memory alerts", function()
            -- Set low threshold to trigger alert
            optimizer.memory_stats.threshold_mb = 0.001  -- Very low threshold

            -- Mock collectgarbage to return high usage
            local original_collectgarbage = _G.collectgarbage
            _G.collectgarbage = function(cmd)
                if cmd == "count" then
                    return 1024 * 1024  -- 1GB in KB
                end
                return original_collectgarbage(cmd)
            end

            local initial_alerts = optimizer.memory_stats.alerts_triggered
            optimizer:monitor_memory()
            assert.is_true(optimizer.memory_stats.alerts_triggered > initial_alerts)

            -- Restore original function
            _G.collectgarbage = original_collectgarbage
        end)
    end)

    describe("Object Pooling", function()
        it("should get object from pool", function()
            local obj = optimizer:get_pooled_object("request_contexts", function()
                return {test = "data"}
            end)

            assert.is_table(obj)
            assert.equal("data", obj.test)
        end)

        it("should return object to pool", function()
            local obj = {test = "reusable"}
            local success = optimizer:return_to_pool("request_contexts", obj)
            assert.is_true(success)
        end)

        it("should handle pool misses", function()
            -- Fill pool
            for i = 1, optimizer.pool_configs.request_contexts.max_size do
                optimizer:return_to_pool("request_contexts", {id = i})
            end

            -- Next get should create new object
            local obj = optimizer:get_pooled_object("request_contexts", function()
                return {created = true}
            end)

            assert.is_table(obj)
            assert.is_true(obj.created)
        end)

        it("should create pooled request context", function()
            local context = optimizer:create_request_context()
            assert.is_table(context)
            assert.is_string(context.id)
            assert.is_number(context.start_time)
        end)

        it("should create pooled threat score", function()
            local score = optimizer:create_threat_score()
            assert.is_table(score)
            assert.equal(0, score.total_score)
            assert.is_table(score.components)
        end)

        it("should create pooled cache entry", function()
            local entry = optimizer:create_cache_entry()
            assert.is_table(entry)
            assert.is_nil(entry.key)
            assert.is_number(entry.created_at)
        end)

        it("should create pooled log entry", function()
            local entry = optimizer:create_log_entry()
            assert.is_table(entry)
            assert.equal("info", entry.level)
            assert.is_number(entry.timestamp)
        end)
    end)

    describe("Leak Detection", function()
        it("should track objects when enabled", function()
            local obj = {test = "object"}
            optimizer:track_object(obj, "test-obj-1", 300)

            assert.is_table(optimizer.leak_detector.tracked_objects["test-obj-1"])
            assert.equal(obj, optimizer.leak_detector.tracked_objects["test-obj-1"].object)
        end)

        it("should skip tracking when disabled", function()
            optimizer.leak_detector.enabled = false
            local obj = {test = "object"}
            optimizer:track_object(obj, "test-obj-2", 300)

            assert.is_nil(optimizer.leak_detector.tracked_objects["test-obj-2"])
        end)
    end)

    describe("Lazy Loading", function()
        it("should lazy load AI engine", function()
            -- Mock require to avoid actual module loading
            local original_require = _G.require
            _G.require = function(module)
                if module == "kong.plugins.kong-guard-ai.ai_engine" then
                    return {new = function() return {type = "ai_engine"} end}
                end
                return original_require(module)
            end

            local engine = optimizer:get_ai_engine()
            assert.is_table(engine)
            assert.equal("ai_engine", engine.type)

            -- Should return cached instance on second call
            local engine2 = optimizer:get_ai_engine()
            assert.equal(engine, engine2)

            _G.require = original_require
        end)

        it("should lazy load TAXII client", function()
            local original_require = _G.require
            _G.require = function(module)
                if module == "kong.plugins.kong-guard-ai.taxii_client" then
                    return {new = function() return {type = "taxii_client"} end}
                end
                return original_require(module)
            end

            local client = optimizer:get_taxii_client()
            assert.is_table(client)
            assert.equal("taxii_client", client.type)

            _G.require = original_require
        end)

        it("should lazy load SOAR client", function()
            local original_require = _G.require
            _G.require = function(module)
                if module == "kong.plugins.kong-guard-ai.soar_client" then
                    return {new = function() return {type = "soar_client"} end}
                end
                return original_require(module)
            end

            local client = optimizer:get_soar_client()
            assert.is_table(client)
            assert.equal("soar_client", client.type)

            _G.require = original_require
        end)

        it("should lazy load forensic collector", function()
            local original_require = _G.require
            _G.require = function(module)
                if module == "kong.plugins.kong-guard-ai.forensic_collector" then
                    return {new = function() return {type = "forensic_collector"} end}
                end
                return original_require(module)
            end

            local collector = optimizer:get_forensic_collector()
            assert.is_table(collector)
            assert.equal("forensic_collector", collector.type)

            _G.require = original_require
        end)
    end)

    describe("Statistics", function()
        it("should return comprehensive stats", function()
            -- Perform some operations to generate stats
            optimizer:create_request_context()
            optimizer:create_threat_score()
            optimizer:monitor_memory()

            local stats = optimizer:get_stats()
            assert.is_table(stats)
            assert.is_table(stats.memory)
            assert.is_table(stats.pools)
            assert.is_table(stats.performance)

            -- Check memory stats
            assert.is_number(stats.memory.current_usage_mb)
            assert.is_number(stats.memory.peak_usage_mb)

            -- Check pool stats
            assert.is_table(stats.pools.request_contexts)
            assert.is_number(stats.pools.request_contexts.size)

            -- Check performance stats
            assert.is_number(stats.performance.objects_created)
            assert.is_number(stats.performance.objects_reused)
        end)

        it("should include leak detection stats when enabled", function()
            local stats = optimizer:get_stats()
            assert.is_table(stats.leak_detection)
            assert.is_number(stats.leak_detection.tracked_objects)
        end)

        it("should exclude leak detection stats when disabled", function()
            optimizer.leak_detector.enabled = false
            local stats = optimizer:get_stats()
            assert.is_nil(stats.leak_detection)
        end)
    end)

    describe("Cleanup", function()
        it("should clean up resources", function()
            -- Add some objects to pools
            optimizer:return_to_pool("request_contexts", {test = "object"})
            optimizer:track_object({test = "tracked"}, "test-obj", 300)

            -- Verify objects exist
            assert.is_true(#optimizer.pools.request_contexts > 0)
            assert.is_table(optimizer.leak_detector.tracked_objects["test-obj"])

            -- Clean up
            optimizer:cleanup()

            -- Verify cleanup
            assert.equal(0, #optimizer.pools.request_contexts)
            assert.is_nil(optimizer.leak_detector.tracked_objects["test-obj"])
        end)
    end)

    describe("Error Handling", function()
        it("should handle unknown pool names gracefully", function()
            local obj = optimizer:get_pooled_object("unknown_pool", function()
                return {fallback = true}
            end)

            assert.is_table(obj)
            assert.is_true(obj.fallback)
        end)

        it("should handle nil objects in return_to_pool", function()
            local success = optimizer:return_to_pool("request_contexts", nil)
            assert.is_false(success)
        end)

        it("should handle unknown pool names in return_to_pool", function()
            local success = optimizer:return_to_pool("unknown_pool", {test = "object"})
            assert.is_false(success)
        end)
    end)
end)