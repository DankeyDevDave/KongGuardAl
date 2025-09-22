--- Memory Optimizer Module for Kong Guard AI
-- Provides comprehensive memory optimization features including object pooling,
-- garbage collection management, memory monitoring, and leak detection.

local _M = {}
local mt = { __index = _M }

-- Dependencies
local kong = kong
local ngx = ngx
local math = math
local table = table
local string = string
local os = os
local collectgarbage = collectgarbage

-- Constants
local DEFAULT_MEMORY_THRESHOLD_MB = 128
local DEFAULT_GC_THRESHOLD_RATIO = 0.8
local DEFAULT_POOL_SIZE = 100
local DEFAULT_LEAK_CHECK_INTERVAL = 300
local DEFAULT_OBJECT_TTL = 3600

--- Create a new memory optimizer instance
-- @param config Configuration table with memory optimization settings
-- @return Memory optimizer instance
function _M.new(config)
    if not config then
        return nil, "Configuration required for memory optimizer"
    end

    local self = {
        -- Configuration
        config = config,

        -- Memory monitoring
        memory_stats = {
            current_usage = 0,
            peak_usage = 0,
            threshold_mb = config.memory_threshold_mb or DEFAULT_MEMORY_THRESHOLD_MB,
            last_gc_time = ngx.now(),
            gc_count = 0,
            alerts_triggered = 0
        },

        -- Object pools
        pools = {
            request_contexts = {},
            threat_scores = {},
            cache_entries = {},
            log_entries = {}
        },

        -- Pool configurations
        pool_configs = {
            request_contexts = {
                max_size = config.request_pool_size or DEFAULT_POOL_SIZE,
                ttl = config.object_ttl or DEFAULT_OBJECT_TTL,
                created = 0
            },
            threat_scores = {
                max_size = config.threat_pool_size or DEFAULT_POOL_SIZE,
                ttl = config.object_ttl or DEFAULT_OBJECT_TTL,
                created = 0
            },
            cache_entries = {
                max_size = config.cache_pool_size or DEFAULT_POOL_SIZE * 2,
                ttl = config.object_ttl or DEFAULT_OBJECT_TTL,
                created = 0
            },
            log_entries = {
                max_size = config.log_pool_size or DEFAULT_POOL_SIZE,
                ttl = config.object_ttl or DEFAULT_OBJECT_TTL,
                created = 0
            }
        },

        -- Leak detection
        leak_detector = {
            enabled = config.enable_leak_detection or false,
            check_interval = config.leak_check_interval or DEFAULT_LEAK_CHECK_INTERVAL,
            last_check = ngx.now(),
            tracked_objects = {},
            leak_threshold = config.leak_threshold or 1000
        },

        -- Lazy loading
        lazy_loaders = {
            ai_engine = false,
            taxii_client = false,
            soar_client = false,
            forensic_collector = false
        },

        -- Performance metrics
        metrics = {
            pool_hits = 0,
            pool_misses = 0,
            objects_created = 0,
            objects_reused = 0,
            gc_cycles = 0,
            memory_alerts = 0
        }
    }

    return setmetatable(self, mt)
end

--- Initialize memory optimization features
function _M:init()
    -- Set up garbage collection parameters
    if self.config.optimize_gc then
        collectgarbage("setpause", 100)  -- Default pause
        collectgarbage("setstepmul", 200)  -- Default step multiplier
    end

    -- Initialize object pools
    for pool_name, pool_config in pairs(self.pool_configs) do
        self.pools[pool_name] = {}
        for i = 1, pool_config.max_size do
            self.pools[pool_name][i] = nil
        end
    end

    -- Initialize leak detection if enabled
    if self.leak_detector.enabled then
        self:_init_leak_detection()
    end

    kong.log.info("[kong-guard-ai] Memory optimizer initialized")
end

--- Monitor current memory usage
function _M:monitor_memory()
    local current_usage = collectgarbage("count") / 1024  -- Convert to MB
    self.memory_stats.current_usage = current_usage

    -- Update peak usage
    if current_usage > self.memory_stats.peak_usage then
        self.memory_stats.peak_usage = current_usage
    end

    -- Check memory threshold
    if current_usage > self.memory_stats.threshold_mb then
        self:_handle_memory_alert(current_usage)
    end

    -- Trigger garbage collection if needed
    local gc_threshold = self.memory_stats.threshold_mb * (self.config.gc_threshold_ratio or DEFAULT_GC_THRESHOLD_RATIO)
    if current_usage > gc_threshold then
        self:_perform_gc_cycle()
    end

    return current_usage
end

--- Handle memory usage alerts
function _M:_handle_memory_alert(current_usage)
    self.memory_stats.alerts_triggered = self.memory_stats.alerts_triggered + 1
    self.metrics.memory_alerts = self.metrics.memory_alerts + 1

    kong.log.warn("[kong-guard-ai] Memory usage alert: ", {
        current_mb = current_usage,
        threshold_mb = self.memory_stats.threshold_mb,
        peak_mb = self.memory_stats.peak_usage,
        alerts_triggered = self.memory_stats.alerts_triggered
    })

    -- Emit metrics if Prometheus is available
    if kong.metrics then
        kong.metrics.gauge("kong_guard_ai_memory_usage_mb", current_usage)
        kong.metrics.gauge("kong_guard_ai_memory_peak_mb", self.memory_stats.peak_usage)
        kong.metrics.counter("kong_guard_ai_memory_alerts", self.memory_stats.alerts_triggered)
    end

    -- Force garbage collection in critical situations
    if current_usage > self.memory_stats.threshold_mb * 1.2 then
        collectgarbage("collect")
        self.memory_stats.gc_count = self.memory_stats.gc_count + 1
        self.metrics.gc_cycles = self.metrics.gc_cycles + 1
    end
end

--- Perform garbage collection cycle
function _M:_perform_gc_cycle()
    local start_time = ngx.now()
    collectgarbage("collect")
    local end_time = ngx.now()

    self.memory_stats.last_gc_time = end_time
    self.memory_stats.gc_count = self.memory_stats.gc_count + 1
    self.metrics.gc_cycles = self.metrics.gc_cycles + 1

    local duration = (end_time - start_time) * 1000  -- Convert to milliseconds

    kong.log.debug("[kong-guard-ai] GC cycle completed: ", {
        duration_ms = duration,
        total_gc_cycles = self.memory_stats.gc_count
    })

    -- Emit GC metrics
    if kong.metrics then
        kong.metrics.histogram("kong_guard_ai_gc_duration_ms", duration)
        kong.metrics.counter("kong_guard_ai_gc_cycles", self.memory_stats.gc_count)
    end
end

--- Get object from pool or create new one
function _M:get_pooled_object(pool_name, constructor, ...)
    if not self.pools[pool_name] then
        kong.log.warn("[kong-guard-ai] Unknown pool requested: ", pool_name)
        return constructor(...)
    end

    local pool = self.pools[pool_name]
    local pool_config = self.pool_configs[pool_name]

    -- Try to get object from pool
    for i, obj in ipairs(pool) do
        if obj then
            pool[i] = nil  -- Remove from pool
            self.metrics.pool_hits = self.metrics.pool_hits + 1
            self.metrics.objects_reused = self.metrics.objects_reused + 1
            return obj
        end
    end

    -- Pool miss - create new object
    self.metrics.pool_misses = self.metrics.pool_misses + 1
    self.metrics.objects_created = self.metrics.objects_created + 1
    pool_config.created = pool_config.created + 1

    return constructor(...)
end

--- Return object to pool
function _M:return_to_pool(pool_name, obj)
    if not self.pools[pool_name] or not obj then
        return false
    end

    local pool = self.pools[pool_name]
    local pool_config = self.pool_configs[pool_name]

    -- Find empty slot in pool
    for i = 1, pool_config.max_size do
        if not pool[i] then
            pool[i] = obj
            return true
        end
    end

    -- Pool is full, discard object
    return false
end

--- Create pooled request context
function _M:create_request_context()
    return self:get_pooled_object("request_contexts", function()
        return {
            id = ngx.var.request_id or kong.request.get_header("X-Request-ID") or ngx.now(),
            start_time = ngx.now(),
            threat_score = 0,
            analysis_results = {},
            metadata = {},
            created_at = ngx.now()
        }
    end)
end

--- Create pooled threat score object
function _M:create_threat_score()
    return self:get_pooled_object("threat_scores", function()
        return {
            total_score = 0,
            components = {},
            confidence = 0,
            timestamp = ngx.now(),
            metadata = {}
        }
    end)
end

--- Create pooled cache entry
function _M:create_cache_entry()
    return self:get_pooled_object("cache_entries", function()
        return {
            key = nil,
            value = nil,
            ttl = 0,
            created_at = ngx.now(),
            hits = 0,
            metadata = {}
        }
    end)
end

--- Create pooled log entry
function _M:create_log_entry()
    return self:get_pooled_object("log_entries", function()
        return {
            timestamp = ngx.now(),
            level = "info",
            message = "",
            context = {},
            metadata = {}
        }
    end)
end

--- Initialize leak detection
function _M:_init_leak_detection()
    -- Set up timer for periodic leak checks
    local ok, err = ngx.timer.every(self.leak_detector.check_interval, function()
        self:_check_for_leaks()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize leak detection timer: ", err)
    end
end

--- Check for memory leaks
function _M:_check_for_leaks()
    local current_time = ngx.now()
    local leaked_objects = 0

    -- Check tracked objects
    for obj_id, obj_info in pairs(self.leak_detector.tracked_objects) do
        if (current_time - obj_info.created_at) > obj_info.expected_ttl then
            leaked_objects = leaked_objects + 1
            kong.log.warn("[kong-guard-ai] Potential memory leak detected: ", {
                object_id = obj_id,
                created_at = obj_info.created_at,
                age_seconds = current_time - obj_info.created_at,
                expected_ttl = obj_info.expected_ttl
            })
        end
    end

    -- Alert if too many leaks detected
    if leaked_objects > self.leak_detector.leak_threshold then
        kong.log.err("[kong-guard-ai] Critical memory leak detected: ", {
            leaked_objects = leaked_objects,
            threshold = self.leak_detector.leak_threshold
        })

        -- Force garbage collection
        collectgarbage("collect")
    end

    -- Clean up old tracking data
    for obj_id, obj_info in pairs(self.leak_detector.tracked_objects) do
        if (current_time - obj_info.created_at) > (obj_info.expected_ttl * 2) then
            self.leak_detector.tracked_objects[obj_id] = nil
        end
    end

    self.leak_detector.last_check = current_time
end

--- Track object for leak detection
function _M:track_object(obj, obj_id, expected_ttl)
    if not self.leak_detector.enabled then
        return
    end

    self.leak_detector.tracked_objects[obj_id] = {
        object = obj,
        created_at = ngx.now(),
        expected_ttl = expected_ttl or DEFAULT_OBJECT_TTL
    }
end

--- Lazy load AI engine
function _M:get_ai_engine()
    if not self.lazy_loaders.ai_engine then
        local ai_engine = require("kong.plugins.kong-guard-ai.ai_engine")
        self.lazy_loaders.ai_engine = ai_engine.new(self.config)
        kong.log.debug("[kong-guard-ai] Lazy loaded AI engine")
    end
    return self.lazy_loaders.ai_engine
end

--- Lazy load TAXII client
function _M:get_taxii_client()
    if not self.lazy_loaders.taxii_client then
        local taxii_client = require("kong.plugins.kong-guard-ai.taxii_client")
        self.lazy_loaders.taxii_client = taxii_client.new(self.config)
        kong.log.debug("[kong-guard-ai] Lazy loaded TAXII client")
    end
    return self.lazy_loaders.taxii_client
end

--- Lazy load SOAR client
function _M:get_soar_client()
    if not self.lazy_loaders.soar_client then
        local soar_client = require("kong.plugins.kong-guard-ai.soar_client")
        self.lazy_loaders.soar_client = soar_client.new(self.config)
        kong.log.debug("[kong-guard-ai] Lazy loaded SOAR client")
    end
    return self.lazy_loaders.soar_client
end

--- Lazy load forensic collector
function _M:get_forensic_collector()
    if not self.lazy_loaders.forensic_collector then
        local forensic_collector = require("kong.plugins.kong-guard-ai.forensic_collector")
        self.lazy_loaders.forensic_collector = forensic_collector.new(self.config)
        kong.log.debug("[kong-guard-ai] Lazy loaded forensic collector")
    end
    return self.lazy_loaders.forensic_collector
end

--- Get memory optimization statistics
function _M:get_stats()
    local memory_usage = self:monitor_memory()

    return {
        memory = {
            current_usage_mb = memory_usage,
            peak_usage_mb = self.memory_stats.peak_usage,
            threshold_mb = self.memory_stats.threshold_mb,
            alerts_triggered = self.memory_stats.alerts_triggered,
            gc_cycles = self.memory_stats.gc_count,
            last_gc_time = self.memory_stats.last_gc_time
        },
        pools = {
            request_contexts = {
                size = #self.pools.request_contexts,
                max_size = self.pool_configs.request_contexts.max_size,
                created = self.pool_configs.request_contexts.created
            },
            threat_scores = {
                size = #self.pools.threat_scores,
                max_size = self.pool_configs.threat_scores.max_size,
                created = self.pool_configs.threat_scores.created
            },
            cache_entries = {
                size = #self.pools.cache_entries,
                max_size = self.pool_configs.cache_entries.max_size,
                created = self.pool_configs.cache_entries.created
            },
            log_entries = {
                size = #self.pools.log_entries,
                max_size = self.pool_configs.log_entries.max_size,
                created = self.pool_configs.log_entries.created
            }
        },
        performance = {
            pool_hit_ratio = self.metrics.pool_hits / (self.metrics.pool_hits + self.metrics.pool_misses),
            objects_created = self.metrics.objects_created,
            objects_reused = self.metrics.objects_reused,
            total_operations = self.metrics.pool_hits + self.metrics.pool_misses
        },
        leak_detection = self.leak_detector.enabled and {
            tracked_objects = #self.leak_detector.tracked_objects,
            last_check = self.leak_detector.last_check,
            check_interval = self.leak_detector.check_interval
        } or nil
    }
end

--- Clean up resources
function _M:cleanup()
    -- Clear all object pools
    for pool_name, pool in pairs(self.pools) do
        for i = 1, #pool do
            pool[i] = nil
        end
    end

    -- Clear tracked objects
    self.leak_detector.tracked_objects = {}

    -- Force garbage collection
    collectgarbage("collect")

    kong.log.info("[kong-guard-ai] Memory optimizer cleanup completed")
end

return _M
