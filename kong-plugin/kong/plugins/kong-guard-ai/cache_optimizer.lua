--- Cache Optimizer Module for Kong Guard AI
-- Provides advanced caching capabilities including LRU, compression, warming,
-- and multi-level caching for optimal performance.

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
local DEFAULT_CACHE_SIZE = 10000
local DEFAULT_TTL_SECONDS = 300
local DEFAULT_COMPRESSION_THRESHOLD = 1024
local DEFAULT_WARMUP_INTERVAL = 300
local DEFAULT_MAX_MEMORY_MB = 256

--- Create a new cache optimizer instance
-- @param config Configuration table with cache optimization settings
-- @return Cache optimizer instance
function _M.new(config)
    if not config then
        return nil, "Configuration required for cache optimizer"
    end

    local self = {
        -- Configuration
        config = config,

        -- LRU Cache implementation
        lru_cache = {
            cache = {},
            access_order = {},
            max_size = config.cache_size or DEFAULT_CACHE_SIZE,
            current_size = 0,
            hits = 0,
            misses = 0,
            evictions = 0
        },

        -- Multi-level cache layers
        layers = {
            l1 = {  -- Fast in-memory cache
                enabled = true,
                cache = {},
                ttl = config.l1_ttl or 60,
                max_size = config.l1_max_size or 1000
            },
            l2 = {  -- Medium-term cache
                enabled = config.enable_l2_cache or false,
                cache = {},
                ttl = config.l2_ttl or 300,
                max_size = config.l2_max_size or 5000
            },
            l3 = {  -- Long-term persistent cache
                enabled = config.enable_l3_cache or false,
                cache = {},
                ttl = config.l3_ttl or 3600,
                max_size = config.l3_max_size or 10000
            }
        },

        -- Compression settings
        compression = {
            enabled = config.enable_compression or true,
            threshold = config.compression_threshold or DEFAULT_COMPRESSION_THRESHOLD,
            algorithm = config.compression_algorithm or "lz4",
            compressed = 0,
            savings_bytes = 0
        },

        -- Cache warming
        warming = {
            enabled = config.enable_cache_warming or false,
            interval = config.warmup_interval or DEFAULT_WARMUP_INTERVAL,
            last_warmup = 0,
            warmup_keys = config.warmup_keys or {},
            warmup_data = {}
        },

        -- Performance metrics
        metrics = {
            total_requests = 0,
            cache_hits = 0,
            cache_misses = 0,
            evictions = 0,
            compression_ratio = 0,
            memory_usage_mb = 0,
            warmup_operations = 0
        },

        -- Cache invalidation strategies
        invalidation = {
            strategies = {
                lru = true,
                ttl = true,
                size_based = config.enable_size_based_eviction or true,
                adaptive = config.enable_adaptive_eviction or false
            },
            patterns = config.invalidation_patterns or {},
            last_cleanup = ngx.now()
        }
    }

    return setmetatable(self, mt)
end

--- Initialize cache optimization features
function _M:init()
    -- Initialize cache layers
    for layer_name, layer in pairs(self.layers) do
        if layer.enabled then
            layer.cache = {}
            kong.log.info("[kong-guard-ai] Initialized cache layer: ", layer_name, {
                max_size = layer.max_size,
                ttl = layer.ttl
            })
        end
    end

    -- Set up cache warming if enabled
    if self.warming.enabled then
        self:_init_cache_warming()
    end

    -- Set up periodic cleanup
    local ok, err = ngx.timer.every(60, function()
        self:_periodic_cleanup()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize cache cleanup timer: ", err)
    end

    kong.log.info("[kong-guard-ai] Cache optimizer initialized")
end

--- Get value from cache with multi-level lookup
function _M:get(key)
    if not key then
        return nil, "Key required"
    end

    self.metrics.total_requests = self.metrics.total_requests + 1

    -- Try L1 cache first (fastest)
    if self.layers.l1.enabled then
        local value, err = self:_get_from_layer("l1", key)
        if value then
            self.metrics.cache_hits = self.metrics.cache_hits + 1
            return value
        end
    end

    -- Try L2 cache
    if self.layers.l2.enabled then
        local value, err = self:_get_from_layer("l2", key)
        if value then
            -- Promote to L1 for faster future access
            if self.layers.l1.enabled then
                self:_set_in_layer("l1", key, value, self.layers.l1.ttl)
            end
            self.metrics.cache_hits = self.metrics.cache_hits + 1
            return value
        end
    end

    -- Try L3 cache
    if self.layers.l3.enabled then
        local value, err = self:_get_from_layer("l3", key)
        if value then
            -- Promote to higher layers
            if self.layers.l1.enabled then
                self:_set_in_layer("l1", key, value, self.layers.l1.ttl)
            end
            if self.layers.l2.enabled then
                self:_set_in_layer("l2", key, value, self.layers.l2.ttl)
            end
            self.metrics.cache_hits = self.metrics.cache_hits + 1
            return value
        end
    end

    -- Cache miss
    self.metrics.cache_misses = self.metrics.cache_misses + 1
    return nil, "Cache miss"
end

--- Set value in cache with multi-level storage
function _M:set(key, value, ttl)
    if not key or not value then
        return false, "Key and value required"
    end

    ttl = ttl or DEFAULT_TTL_SECONDS

    -- Compress if enabled and value is large enough
    local final_value = value
    if self.compression.enabled and #cjson.encode(value) > self.compression.threshold then
        final_value = self:_compress_value(value)
    end

    -- Store in all enabled layers
    local success_count = 0

    if self.layers.l1.enabled then
        if self:_set_in_layer("l1", key, final_value, math.min(ttl, self.layers.l1.ttl)) then
            success_count = success_count + 1
        end
    end

    if self.layers.l2.enabled then
        if self:_set_in_layer("l2", key, final_value, math.min(ttl, self.layers.l2.ttl)) then
            success_count = success_count + 1
        end
    end

    if self.layers.l3.enabled then
        if self:_set_in_layer("l3", key, final_value, math.min(ttl, self.layers.l3.ttl)) then
            success_count = success_count + 1
        end
    end

    return success_count > 0
end

--- Delete value from all cache layers
function _M:delete(key)
    if not key then
        return false, "Key required"
    end

    local deleted_count = 0

    for layer_name, layer in pairs(self.layers) do
        if layer.enabled and layer.cache[key] then
            layer.cache[key] = nil
            deleted_count = deleted_count + 1
        end
    end

    return deleted_count > 0
end

--- Get value from specific cache layer
function _M:_get_from_layer(layer_name, key)
    local layer = self.layers[layer_name]
    if not layer or not layer.enabled then
        return nil, "Layer not available"
    end

    local entry = layer.cache[key]
    if not entry then
        return nil, "Key not found"
    end

    -- Check TTL
    if ngx.now() - entry.created_at > entry.ttl then
        layer.cache[key] = nil  -- Expired, remove
        return nil, "Entry expired"
    end

    -- Update access time for LRU
    entry.last_access = ngx.now()
    entry.access_count = (entry.access_count or 0) + 1

    -- Decompress if needed
    local value = entry.value
    if entry.compressed then
        value = self:_decompress_value(value)
    end

    return value
end

--- Set value in specific cache layer
function _M:_set_in_layer(layer_name, key, value, ttl)
    local layer = self.layers[layer_name]
    if not layer or not layer.enabled then
        return false
    end

    -- Check if we need to evict entries
    if not layer.cache[key] then
        while self:_get_layer_size(layer) >= layer.max_size do
            self:_evict_from_layer(layer_name)
        end
    end

    layer.cache[key] = {
        value = value,
        created_at = ngx.now(),
        last_access = ngx.now(),
        ttl = ttl,
        access_count = 1,
        compressed = (type(value) == "string" and value:match("^COMPRESSED:")),
        size = self:_calculate_entry_size(value)
    }

    return true
end

--- Calculate entry size for memory tracking
function _M:_calculate_entry_size(value)
    if type(value) == "string" then
        return #value
    elseif type(value) == "table" then
        return #cjson.encode(value) or 100  -- Fallback size
    else
        return 50  -- Default size for other types
    end
end

--- Get current size of cache layer
function _M:_get_layer_size(layer)
    local size = 0
    for _, entry in pairs(layer.cache) do
        size = size + (entry.size or 50)
    end
    return size
end

--- Evict entry from cache layer using LRU strategy
function _M:_evict_from_layer(layer_name)
    local layer = self.layers[layer_name]
    if not layer then return end

    local oldest_key = nil
    local oldest_time = ngx.now()

    for key, entry in pairs(layer.cache) do
        if entry.last_access < oldest_time then
            oldest_time = entry.last_access
            oldest_key = key
        end
    end

    if oldest_key then
        layer.cache[oldest_key] = nil
        self.metrics.evictions = self.metrics.evictions + 1
    end
end

--- Compress cache value
function _M:_compress_value(value)
    if not self.compression.enabled then
        return value
    end

    local encoded = cjson.encode(value)
    if not encoded or #encoded < self.compression.threshold then
        return value
    end

    -- Simple compression simulation (in real implementation, use proper compression library)
    local compressed = "COMPRESSED:" .. encoded  -- Placeholder for actual compression

    self.compression.compressed = self.compression.compressed + 1
    self.compression.savings_bytes = self.compression.savings_bytes + (#encoded - #compressed)

    return compressed
end

--- Decompress cache value
function _M:_decompress_value(value)
    if type(value) ~= "string" or not value:match("^COMPRESSED:") then
        return value
    end

    local decompressed = value:gsub("^COMPRESSED:", "")
    return cjson.decode(decompressed)
end

--- Initialize cache warming
function _M:_init_cache_warming()
    -- Set up timer for periodic warming
    local ok, err = ngx.timer.every(self.warming.interval, function()
        self:_perform_cache_warming()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize cache warming timer: ", err)
    end
end

--- Perform cache warming
function _M:_perform_cache_warming()
    if not self.warming.enabled then
        return
    end

    local warmed_count = 0

    for _, key in ipairs(self.warming.warmup_keys) do
        if self.warming.warmup_data[key] then
            self:set(key, self.warming.warmup_data[key], self.warming.interval)
            warmed_count = warmed_count + 1
        end
    end

    self.warming.last_warmup = ngx.now()
    self.metrics.warmup_operations = self.metrics.warmup_operations + warmed_count

    kong.log.debug("[kong-guard-ai] Cache warming completed: ", {
        keys_warmed = warmed_count,
        total_warmup_operations = self.metrics.warmup_operations
    })
end

--- Add key to warmup list
function _M:add_warmup_key(key, data)
    if not self.warming.enabled then
        return false, "Cache warming not enabled"
    end

    self.warming.warmup_data[key] = data
    table.insert(self.warming.warmup_keys, key)

    return true
end

--- Periodic cleanup of expired entries
function _M:_periodic_cleanup()
    local current_time = ngx.now()
    local cleaned_count = 0

    for layer_name, layer in pairs(self.layers) do
        if layer.enabled then
            for key, entry in pairs(layer.cache) do
                if current_time - entry.created_at > entry.ttl then
                    layer.cache[key] = nil
                    cleaned_count = cleaned_count + 1
                end
            end
        end
    end

    if cleaned_count > 0 then
        kong.log.debug("[kong-guard-ai] Periodic cleanup completed: ", {
            entries_cleaned = cleaned_count
        })
    end

    self.invalidation.last_cleanup = current_time
end

--- Clear all cache layers
function _M:clear()
    for layer_name, layer in pairs(self.layers) do
        if layer.enabled then
            layer.cache = {}
        end
    end

    -- Reset metrics
    self.metrics.cache_hits = 0
    self.metrics.cache_misses = 0
    self.metrics.evictions = 0

    kong.log.info("[kong-guard-ai] Cache cleared")
end

--- Get cache statistics
function _M:get_stats()
    local total_entries = 0
    local total_size = 0
    local layer_stats = {}

    for layer_name, layer in pairs(self.layers) do
        if layer.enabled then
            local layer_size = self:_get_layer_size(layer)
            local entry_count = 0
            for _ in pairs(layer.cache) do
                entry_count = entry_count + 1
            end

            layer_stats[layer_name] = {
                entries = entry_count,
                size_bytes = layer_size,
                max_size = layer.max_size,
                ttl = layer.ttl
            }

            total_entries = total_entries + entry_count
            total_size = total_size + layer_size
        end
    end

    local hit_ratio = 0
    if self.metrics.total_requests > 0 then
        hit_ratio = self.metrics.cache_hits / self.metrics.total_requests
    end

    return {
        layers = layer_stats,
        performance = {
            total_requests = self.metrics.total_requests,
            cache_hits = self.metrics.cache_hits,
            cache_misses = self.metrics.cache_misses,
            hit_ratio = hit_ratio,
            evictions = self.metrics.evictions
        },
        compression = self.compression.enabled and {
            compressed_entries = self.compression.compressed,
            savings_bytes = self.compression.savings_bytes,
            compression_ratio = self.compression.savings_bytes / (self.compression.savings_bytes + total_size)
        } or nil,
        warming = self.warming.enabled and {
            last_warmup = self.warming.last_warmup,
            warmup_keys_count = #self.warming.warmup_keys,
            total_warmup_operations = self.metrics.warmup_operations
        } or nil,
        memory = {
            total_size_bytes = total_size,
            total_entries = total_entries,
            average_entry_size = total_entries > 0 and (total_size / total_entries) or 0
        }
    }
end

--- Invalidate cache entries by pattern
function _M:invalidate_pattern(pattern)
    if not pattern then
        return 0, "Pattern required"
    end

    local invalidated_count = 0

    for layer_name, layer in pairs(self.layers) do
        if layer.enabled then
            for key in pairs(layer.cache) do
                if string.match(key, pattern) then
                    layer.cache[key] = nil
                    invalidated_count = invalidated_count + 1
                end
            end
        end
    end

    return invalidated_count
end

return _M