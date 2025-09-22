--- Unit tests for Cache Optimizer Module
-- Tests LRU caching, multi-level caching, compression, and cache warming features

local CacheOptimizer = require("kong.plugins.kong-guard-ai.cache_optimizer")

describe("Cache Optimizer", function()
    local config
    local optimizer

    before_each(function()
        config = {
            cache_size = 1000,
            l1_ttl = 60,
            l1_max_size = 100,
            enable_l2_cache = true,
            l2_ttl = 300,
            l2_max_size = 500,
            enable_l3_cache = false,
            enable_compression = true,
            compression_threshold = 512,
            enable_cache_warming = true,
            warmup_interval = 300,
            warmup_keys = {"test-key-1", "test-key-2"},
            enable_size_based_eviction = true,
            enable_adaptive_eviction = false
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
                every = function(interval, callback)
                    return true
                end
            }
        }

        -- Mock cjson
        _G.cjson = {
            encode = function(obj)
                return type(obj) == "table" and '{"test": "data"}' or tostring(obj)
            end,
            decode = function(str)
                return {test = "data"}
            end
        }

        optimizer = CacheOptimizer.new(config)
        assert.is_not_nil(optimizer)
    end)

    after_each(function()
        optimizer = nil
        _G.kong = nil
        _G.ngx = nil
        _G.cjson = nil
    end)

    describe("Initialization", function()
        it("should create optimizer with valid config", function()
            local opt = CacheOptimizer.new(config)
            assert.is_not_nil(opt)
            assert.is_table(opt.layers)
            assert.is_table(opt.compression)
            assert.is_table(opt.warming)
        end)

        it("should fail with invalid config", function()
            local opt, err = CacheOptimizer.new(nil)
            assert.is_nil(opt)
            assert.is_string(err)
        end)

        it("should initialize cache layers correctly", function()
            optimizer:init()

            assert.is_table(optimizer.layers.l1.cache)
            assert.is_table(optimizer.layers.l2.cache)
            assert.is_table(optimizer.layers.l3.cache)
        end)
    end)

    describe("Basic Cache Operations", function()
        it("should set and get values", function()
            local key = "test-key"
            local value = {data = "test-value"}

            -- Set value
            local success = optimizer:set(key, value, 300)
            assert.is_true(success)

            -- Get value
            local retrieved = optimizer:get(key)
            assert.is_not_nil(retrieved)
            assert.equal("test-value", retrieved.data)
        end)

        it("should handle cache misses", function()
            local value, err = optimizer:get("nonexistent-key")
            assert.is_nil(value)
            assert.equal("Cache miss", err)
        end)

        it("should delete values", function()
            local key = "test-key"
            local value = "test-value"

            optimizer:set(key, value)
            local retrieved = optimizer:get(key)
            assert.equal("test-value", retrieved)

            optimizer:delete(key)
            local deleted, err = optimizer:get(key)
            assert.is_nil(deleted)
        end)

        it("should handle TTL expiration", function()
            local key = "ttl-test"
            local value = "expires-quickly"

            optimizer:set(key, value, 1)  -- 1 second TTL

            -- Mock time advancement
            local original_now = _G.ngx.now
            _G.ngx.now = function() return original_now() + 2 end

            local retrieved, err = optimizer:get(key)
            assert.is_nil(retrieved)
            assert.equal("Entry expired", err)

            _G.ngx.now = original_now
        end)
    end)

    describe("Multi-Level Caching", function()
        it("should promote entries from L2 to L1", function()
            -- Set in L2 only
            optimizer.layers.l1.enabled = false
            optimizer:set("test-key", "test-value", 300)
            optimizer.layers.l1.enabled = true

            -- Get should promote to L1
            local value = optimizer:get("test-key")
            assert.equal("test-value", value)

            -- Verify it's now in L1
            assert.is_not_nil(optimizer.layers.l1.cache["test-key"])
        end)

        it("should handle disabled layers", function()
            optimizer.layers.l2.enabled = false
            optimizer.layers.l3.enabled = false

            local success = optimizer:set("test-key", "test-value")
            assert.is_true(success)

            local value = optimizer:get("test-key")
            assert.equal("test-value", value)
        end)

        it("should respect layer-specific TTL", function()
            local key = "layer-ttl-test"
            local value = "test-value"

            -- Set with long TTL
            optimizer:set(key, value, 3600)

            -- L1 should have shorter TTL
            local l1_entry = optimizer.layers.l1.cache[key]
            assert.is_true(l1_entry.ttl <= optimizer.layers.l1.ttl)
        end)
    end)

    describe("LRU Eviction", function()
        it("should evict least recently used entries", function()
            -- Fill L1 cache
            for i = 1, optimizer.layers.l1.max_size + 5 do
                optimizer:set("key-" .. i, "value-" .. i, 3600)
            end

            -- Access first few entries to make them recently used
            for i = 1, 3 do
                optimizer:get("key-" .. i)
            end

            -- Add one more to trigger eviction
            optimizer:set("trigger-key", "trigger-value", 3600)

            -- Recently accessed entries should still be there
            for i = 1, 3 do
                local value = optimizer:get("key-" .. i)
                assert.is_not_nil(value)
            end
        end)

        it("should track eviction metrics", function()
            local initial_evictions = optimizer.metrics.evictions

            -- Fill cache and trigger eviction
            for i = 1, optimizer.layers.l1.max_size + 1 do
                optimizer:set("eviction-test-" .. i, "value-" .. i, 3600)
            end

            assert.is_true(optimizer.metrics.evictions > initial_evictions)
        end)
    end)

    describe("Compression", function()
        it("should compress large values", function()
            local large_value = string.rep("x", 1024)  -- Larger than threshold

            optimizer:set("compressed-key", large_value, 300)

            local entry = optimizer.layers.l1.cache["compressed-key"]
            assert.is_true(entry.compressed)
        end)

        it("should not compress small values", function()
            local small_value = "small"

            optimizer:set("uncompressed-key", small_value, 300)

            local entry = optimizer.layers.l1.cache["uncompressed-key"]
            assert.is_false(entry.compressed)
        end)

        it("should decompress values on retrieval", function()
            local large_value = string.rep("test", 200)

            optimizer:set("decompress-key", large_value, 300)
            local retrieved = optimizer:get("decompress-key")

            assert.equal(large_value, retrieved)
        end)
    end)

    describe("Cache Warming", function()
        it("should add keys to warmup list", function()
            local success = optimizer:add_warmup_key("warmup-key", "warmup-value")
            assert.is_true(success)

            assert.equal("warmup-value", optimizer.warming.warmup_data["warmup-key"])
        end)

        it("should perform cache warming", function()
            optimizer:add_warmup_key("warmup-key-1", "warmup-value-1")
            optimizer:add_warmup_key("warmup-key-2", "warmup-value-2")

            optimizer:_perform_cache_warming()

            local value1 = optimizer:get("warmup-key-1")
            local value2 = optimizer:get("warmup-key-2")

            assert.equal("warmup-value-1", value1)
            assert.equal("warmup-value-2", value2)
        end)

        it("should skip warming when disabled", function()
            optimizer.warming.enabled = false
            local success = optimizer:add_warmup_key("warmup-key", "warmup-value")
            assert.is_false(success)
        end)
    end)

    describe("Pattern Invalidation", function()
        it("should invalidate entries by pattern", function()
            -- Set multiple entries
            optimizer:set("user:123", "user-data-123", 300)
            optimizer:set("user:456", "user-data-456", 300)
            optimizer:set("post:789", "post-data-789", 300)

            -- Invalidate user entries
            local invalidated = optimizer:invalidate_pattern("^user:")
            assert.equal(2, invalidated)

            -- Verify invalidation
            local user1 = optimizer:get("user:123")
            local user2 = optimizer:get("user:456")
            local post = optimizer:get("post:789")

            assert.is_nil(user1)
            assert.is_nil(user2)
            assert.equal("post-data-789", post)
        end)

        it("should handle invalid patterns", function()
            local invalidated, err = optimizer:invalidate_pattern(nil)
            assert.equal(0, invalidated)
            assert.equal("Pattern required", err)
        end)
    end)

    describe("Statistics", function()
        it("should return comprehensive stats", function()
            -- Perform some operations
            optimizer:set("stats-key-1", "value-1", 300)
            optimizer:set("stats-key-2", "value-2", 300)
            optimizer:get("stats-key-1")
            optimizer:get("nonexistent-key")

            local stats = optimizer:get_stats()
            assert.is_table(stats)
            assert.is_table(stats.layers)
            assert.is_table(stats.performance)
            assert.is_table(stats.memory)

            -- Check performance stats
            assert.equal(2, stats.performance.total_requests)
            assert.equal(1, stats.performance.cache_hits)
            assert.equal(1, stats.performance.cache_misses)
            assert.equal(0.5, stats.performance.hit_ratio)
        end)

        it("should include compression stats when enabled", function()
            local large_value = string.rep("x", 1024)
            optimizer:set("compression-test", large_value, 300)

            local stats = optimizer:get_stats()
            assert.is_table(stats.compression)
            assert.is_number(stats.compression.compressed_entries)
        end)

        it("should include warming stats when enabled", function()
            optimizer:add_warmup_key("warmup-test", "warmup-value")

            local stats = optimizer:get_stats()
            assert.is_table(stats.warming)
            assert.equal(1, stats.warming.warmup_keys_count)
        end)
    end)

    describe("Cache Clearing", function()
        it("should clear all layers", function()
            -- Add entries to all layers
            optimizer:set("clear-test-1", "value-1", 300)
            optimizer:set("clear-test-2", "value-2", 300)

            -- Verify entries exist
            assert.is_not_nil(optimizer.layers.l1.cache["clear-test-1"])
            assert.is_not_nil(optimizer.layers.l2.cache["clear-test-1"])

            -- Clear cache
            optimizer:clear()

            -- Verify entries are gone
            assert.is_nil(optimizer.layers.l1.cache["clear-test-1"])
            assert.is_nil(optimizer.layers.l2.cache["clear-test-1"])

            -- Verify metrics reset
            assert.equal(0, optimizer.metrics.cache_hits)
            assert.equal(0, optimizer.metrics.evictions)
        end)
    end)

    describe("Error Handling", function()
        it("should handle nil keys", function()
            local success, err = optimizer:set(nil, "value")
            assert.is_false(success)
            assert.equal("Key and value required", err)

            local value, err = optimizer:get(nil)
            assert.is_nil(value)
            assert.equal("Key required", err)
        end)

        it("should handle nil values", function()
            local success, err = optimizer:set("key", nil)
            assert.is_false(success)
            assert.equal("Key and value required", err)
        end)

        it("should handle invalid layer access", function()
            local value, err = optimizer:_get_from_layer("invalid_layer", "key")
            assert.is_nil(value)
            assert.equal("Layer not available", err)
        end)
    end)

    describe("Memory Tracking", function()
        it("should calculate entry sizes", function()
            local string_size = optimizer:_calculate_entry_size("test string")
            local table_size = optimizer:_calculate_entry_size({key = "value"})
            local number_size = optimizer:_calculate_entry_size(42)

            assert.is_number(string_size)
            assert.is_number(table_size)
            assert.is_number(number_size)
            assert.equal(50, number_size)  -- Default size
        end)

        it("should track layer sizes", function()
            optimizer:set("size-test-1", "small", 300)
            optimizer:set("size-test-2", string.rep("x", 100), 300)

            local l1_size = optimizer:_get_layer_size(optimizer.layers.l1)
            assert.is_number(l1_size)
            assert.is_true(l1_size > 0)
        end)
    end)
end)