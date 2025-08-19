-- Kong Guard AI - Performance Optimization Module
-- Ensures all instrumentation logic keeps request overhead below 10ms
-- Implements performance monitoring, profiling, and optimization utilities
--
-- Author: Performance Optimization Specialist Agent
-- Phase: 3 - Performance Optimization
--
-- CRITICAL REQUIREMENT: All operations must maintain <10ms latency under 5K+ RPS

local kong = kong
local json = require "cjson.safe"

local _M = {}

-- Performance metrics storage (worker-level)
local performance_metrics = {}
local cpu_sampler = {}
local memory_tracker = {}
local timing_cache = {}

-- Performance constants and thresholds
local PERFORMANCE_THRESHOLDS = {
    MAX_REQUEST_LATENCY_MS = 10,        -- Critical: Must stay under 10ms
    MAX_MEMORY_PER_REQUEST_KB = 50,     -- Maximum memory per request
    MAX_CPU_USAGE_PERCENT = 80,         -- CPU usage threshold
    CACHE_CLEANUP_INTERVAL = 1000,      -- Clean cache every N requests
    SAMPLING_RATE = 0.01,               -- 1% sampling rate for detailed profiling
    CIRCUIT_BREAKER_THRESHOLD = 5,      -- Failures before circuit breaker trips
    MEMORY_ALERT_THRESHOLD_MB = 100     -- Alert when worker memory exceeds this
}

-- Performance optimization techniques
local OPTIMIZATION_CONFIGS = {
    MINIMAL = {
        enable_detailed_timing = false,
        enable_memory_tracking = false,
        sampling_rate = 0.001,
        cache_size = 100
    },
    BALANCED = {
        enable_detailed_timing = true,
        enable_memory_tracking = true,
        sampling_rate = 0.01,
        cache_size = 1000
    },
    DETAILED = {
        enable_detailed_timing = true,
        enable_memory_tracking = true,
        sampling_rate = 0.1,
        cache_size = 5000
    }
}

---
-- Initialize performance optimization subsystem
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Perf] Initializing performance optimization engine")
    
    -- Initialize performance metrics storage
    performance_metrics = {
        request_count = 0,
        total_processing_time_ms = 0,
        max_processing_time_ms = 0,
        min_processing_time_ms = math.huge,
        memory_peak_kb = 0,
        cpu_samples = {},
        circuit_breaker_failures = 0,
        circuit_breaker_state = "closed", -- closed, open, half-open
        last_circuit_check = ngx.time()
    }
    
    -- Initialize memory tracking
    memory_tracker = {
        baseline_memory_kb = 0,
        peak_memory_kb = 0,
        request_memory_samples = {},
        cleanup_counter = 0
    }
    
    -- Initialize CPU sampler
    cpu_sampler = {
        samples = {},
        last_sample_time = ngx.now(),
        high_cpu_alerts = 0
    }
    
    -- Initialize timing cache for performance optimizations
    timing_cache = {
        compiled_patterns = {},
        cached_calculations = {},
        frequent_lookups = {}
    }
    
    -- Set baseline memory usage
    _M.capture_baseline_memory()
    
    -- Configure optimization level based on settings
    local optimization_level = conf.performance_optimization_level or "balanced"
    _M.apply_optimization_config(optimization_level)
    
    kong.log.info("[Kong Guard AI Perf] Performance optimization engine initialized")
end

---
-- Start performance monitoring for a request
-- CRITICAL: This function must execute in <0.1ms
-- @param request_id Unique request identifier
-- @return Table containing performance context
---
function _M.start_request_monitoring(request_id)
    local start_time = ngx.now()
    
    -- Check circuit breaker first (fastest path)
    if performance_metrics.circuit_breaker_state == "open" then
        if ngx.time() - performance_metrics.last_circuit_check > 60 then
            performance_metrics.circuit_breaker_state = "half-open"
            performance_metrics.last_circuit_check = ngx.time()
        else
            -- Return immediately - circuit breaker is open
            return {
                request_id = request_id,
                start_time = start_time,
                circuit_breaker_open = true,
                monitoring_disabled = true
            }
        end
    end
    
    -- Increment request counter
    performance_metrics.request_count = performance_metrics.request_count + 1
    
    -- Create performance context (minimal allocation)
    local perf_context = {
        request_id = request_id,
        start_time = start_time,
        memory_start = _M.get_current_memory_kb(),
        cpu_start_time = ngx.now(),
        circuit_breaker_open = false,
        monitoring_disabled = false,
        detailed_monitoring = math.random() < PERFORMANCE_THRESHOLDS.SAMPLING_RATE
    }
    
    -- Only do detailed monitoring for sampled requests
    if perf_context.detailed_monitoring then
        perf_context.detailed_timings = {}
        perf_context.memory_checkpoints = {}
    end
    
    return perf_context
end

---
-- Record a performance checkpoint during request processing
-- @param perf_context Performance context from start_request_monitoring
-- @param checkpoint_name Name of the checkpoint
-- @param operation_data Optional data about the operation
---
function _M.record_checkpoint(perf_context, checkpoint_name, operation_data)
    if not perf_context or perf_context.monitoring_disabled then
        return
    end
    
    local current_time = ngx.now()
    local elapsed_ms = (current_time - perf_context.start_time) * 1000
    
    -- Fast path: Only record if we're under threshold
    if elapsed_ms > PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS then
        -- Increment circuit breaker failure counter
        performance_metrics.circuit_breaker_failures = performance_metrics.circuit_breaker_failures + 1
        
        if performance_metrics.circuit_breaker_failures >= PERFORMANCE_THRESHOLDS.CIRCUIT_BREAKER_THRESHOLD then
            performance_metrics.circuit_breaker_state = "open"
            performance_metrics.last_circuit_check = ngx.time()
            kong.log.error("[Kong Guard AI Perf] Circuit breaker OPEN - Performance threshold exceeded")
        end
        
        kong.log.warn("[Kong Guard AI Perf] Performance threshold exceeded at " .. checkpoint_name .. 
                      ": " .. elapsed_ms .. "ms")
    end
    
    -- Detailed monitoring only for sampled requests
    if perf_context.detailed_monitoring and perf_context.detailed_timings then
        perf_context.detailed_timings[checkpoint_name] = {
            timestamp = current_time,
            elapsed_ms = elapsed_ms,
            operation_data = operation_data
        }
        
        -- Memory checkpoint
        local current_memory = _M.get_current_memory_kb()
        perf_context.memory_checkpoints[checkpoint_name] = current_memory
    end
end

---
-- Complete request monitoring and update metrics
-- @param perf_context Performance context from start_request_monitoring
-- @return Table containing performance summary
---
function _M.complete_request_monitoring(perf_context)
    if not perf_context or perf_context.monitoring_disabled then
        return { monitoring_disabled = true }
    end
    
    local end_time = ngx.now()
    local total_time_ms = (end_time - perf_context.start_time) * 1000
    local memory_end = _M.get_current_memory_kb()
    local memory_used = memory_end - (perf_context.memory_start or 0)
    
    -- Update global performance metrics
    performance_metrics.total_processing_time_ms = performance_metrics.total_processing_time_ms + total_time_ms
    
    if total_time_ms > performance_metrics.max_processing_time_ms then
        performance_metrics.max_processing_time_ms = total_time_ms
    end
    
    if total_time_ms < performance_metrics.min_processing_time_ms then
        performance_metrics.min_processing_time_ms = total_time_ms
    end
    
    -- Track memory usage
    if memory_used > 0 and memory_used < PERFORMANCE_THRESHOLDS.MAX_MEMORY_PER_REQUEST_KB then
        memory_tracker.peak_memory_kb = math.max(memory_tracker.peak_memory_kb, memory_end)
        
        -- Store memory sample for analysis (with sampling)
        if math.random() < 0.1 then -- 10% sampling for memory
            table.insert(memory_tracker.request_memory_samples, {
                timestamp = end_time,
                memory_kb = memory_used,
                request_id = perf_context.request_id
            })
            
            -- Keep only recent samples
            if #memory_tracker.request_memory_samples > 100 then
                table.remove(memory_tracker.request_memory_samples, 1)
            end
        end
    end
    
    -- Circuit breaker success case
    if performance_metrics.circuit_breaker_state == "half-open" and 
       total_time_ms <= PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS then
        performance_metrics.circuit_breaker_state = "closed"
        performance_metrics.circuit_breaker_failures = 0
        kong.log.info("[Kong Guard AI Perf] Circuit breaker CLOSED - Performance recovered")
    end
    
    -- Periodic cleanup
    memory_tracker.cleanup_counter = memory_tracker.cleanup_counter + 1
    if memory_tracker.cleanup_counter >= PERFORMANCE_THRESHOLDS.CACHE_CLEANUP_INTERVAL then
        _M.cleanup_performance_caches()
        memory_tracker.cleanup_counter = 0
    end
    
    return {
        total_time_ms = total_time_ms,
        memory_used_kb = memory_used,
        within_threshold = total_time_ms <= PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS,
        detailed_timings = perf_context.detailed_timings,
        memory_checkpoints = perf_context.memory_checkpoints
    }
end

---
-- Optimize string operations to reduce allocations
-- @param strings Array of strings to concatenate efficiently
-- @return String result
---
function _M.optimize_string_concat(strings)
    -- Use table.concat for better performance than string concatenation
    return table.concat(strings)
end

---
-- Optimize table operations for performance
-- @param source_table Source table
-- @param keys_to_extract Keys to extract (optional, extracts all if nil)
-- @return Optimized table
---
function _M.optimize_table_operations(source_table, keys_to_extract)
    if not source_table then
        return {}
    end
    
    local result = {}
    
    if keys_to_extract then
        -- Only extract specified keys
        for _, key in ipairs(keys_to_extract) do
            if source_table[key] ~= nil then
                result[key] = source_table[key]
            end
        end
    else
        -- Copy all keys (but use pre-allocated table size if possible)
        local table_size = 0
        for _ in pairs(source_table) do
            table_size = table_size + 1
        end
        
        -- Pre-allocate result table for better performance
        for key, value in pairs(source_table) do
            result[key] = value
        end
    end
    
    return result
end

---
-- Optimize ngx.shared.dict operations with batching
-- @param dict_name Shared dictionary name
-- @param operations Array of operations {action="get/set", key="key", value="value"}
-- @return Array of results
---
function _M.optimize_shared_dict_operations(dict_name, operations)
    local shm = ngx.shared[dict_name]
    if not shm then
        kong.log.warn("[Kong Guard AI Perf] Shared dict not available: " .. dict_name)
        return {}
    end
    
    local results = {}
    local batch_get_keys = {}
    local batch_set_operations = {}
    
    -- Separate operations for batching
    for i, op in ipairs(operations) do
        if op.action == "get" then
            table.insert(batch_get_keys, {index = i, key = op.key})
        elseif op.action == "set" then
            table.insert(batch_set_operations, {index = i, key = op.key, value = op.value, exptime = op.exptime})
        end
    end
    
    -- Batch process get operations
    for _, get_op in ipairs(batch_get_keys) do
        local value, flags = shm:get(get_op.key)
        results[get_op.index] = {success = true, value = value, flags = flags}
    end
    
    -- Batch process set operations
    for _, set_op in ipairs(batch_set_operations) do
        local success, err = shm:set(set_op.key, set_op.value, set_op.exptime or 0)
        results[set_op.index] = {success = success, error = err}
    end
    
    return results
end

---
-- Implement lazy evaluation for expensive operations
-- @param operation_id Unique identifier for the operation
-- @param compute_function Function to compute the value
-- @param cache_ttl_seconds Time to live for cached result
-- @return Computed or cached result
---
function _M.lazy_evaluate(operation_id, compute_function, cache_ttl_seconds)
    cache_ttl_seconds = cache_ttl_seconds or 300 -- Default 5 minutes
    
    -- Check cache first
    local cached_result = timing_cache.cached_calculations[operation_id]
    if cached_result and (ngx.time() - cached_result.timestamp) < cache_ttl_seconds then
        return cached_result.value
    end
    
    -- Compute the value
    local start_time = ngx.now()
    local result = compute_function()
    local compute_time = (ngx.now() - start_time) * 1000
    
    -- Cache the result
    timing_cache.cached_calculations[operation_id] = {
        value = result,
        timestamp = ngx.time(),
        compute_time_ms = compute_time
    }
    
    -- Log if computation was expensive
    if compute_time > 1 then -- >1ms
        kong.log.debug("[Kong Guard AI Perf] Expensive computation cached: " .. operation_id .. 
                      " (" .. compute_time .. "ms)")
    end
    
    return result
end

---
-- Get current memory usage for the worker process
-- @return Memory usage in KB
---
function _M.get_current_memory_kb()
    -- Try to get memory usage (this is system-dependent)
    local memory_kb = 0
    
    -- On Linux, we can read from /proc/self/status
    local status_file = io.open("/proc/self/status", "r")
    if status_file then
        for line in status_file:lines() do
            local vmrss = line:match("VmRSS:%s*(%d+)%s*kB")
            if vmrss then
                memory_kb = tonumber(vmrss)
                break
            end
        end
        status_file:close()
    end
    
    return memory_kb
end

---
-- Capture baseline memory usage
---
function _M.capture_baseline_memory()
    memory_tracker.baseline_memory_kb = _M.get_current_memory_kb()
    kong.log.debug("[Kong Guard AI Perf] Baseline memory: " .. memory_tracker.baseline_memory_kb .. "KB")
end

---
-- Sample CPU usage (approximation using timing)
-- @return CPU usage percentage estimate
---
function _M.sample_cpu_usage()
    local current_time = ngx.now()
    local time_diff = current_time - cpu_sampler.last_sample_time
    
    if time_diff < 0.1 then -- Don't sample too frequently
        return cpu_sampler.last_cpu_estimate or 0
    end
    
    -- Simple CPU estimation based on processing time vs wall time
    local processing_time_ratio = 0
    if performance_metrics.request_count > 0 then
        local avg_processing_time = performance_metrics.total_processing_time_ms / performance_metrics.request_count / 1000
        processing_time_ratio = math.min(avg_processing_time / time_diff, 1.0)
    end
    
    local cpu_estimate = processing_time_ratio * 100
    cpu_sampler.last_cpu_estimate = cpu_estimate
    cpu_sampler.last_sample_time = current_time
    
    -- Store sample for trending
    table.insert(cpu_sampler.samples, {
        timestamp = current_time,
        cpu_percent = cpu_estimate
    })
    
    -- Keep only recent samples
    if #cpu_sampler.samples > 60 then -- Keep 1 minute of samples
        table.remove(cpu_sampler.samples, 1)
    end
    
    -- Alert on high CPU usage
    if cpu_estimate > PERFORMANCE_THRESHOLDS.MAX_CPU_USAGE_PERCENT then
        cpu_sampler.high_cpu_alerts = cpu_sampler.high_cpu_alerts + 1
        if cpu_sampler.high_cpu_alerts % 10 == 1 then -- Alert every 10th occurrence
            kong.log.warn("[Kong Guard AI Perf] High CPU usage detected: " .. cpu_estimate .. "%")
        end
    else
        cpu_sampler.high_cpu_alerts = 0
    end
    
    return cpu_estimate
end

---
-- Generate performance monitoring dashboard data
-- @return Table containing comprehensive performance metrics
---
function _M.get_performance_dashboard_data()
    local current_memory = _M.get_current_memory_kb()
    local cpu_usage = _M.sample_cpu_usage()
    local avg_processing_time = 0
    
    if performance_metrics.request_count > 0 then
        avg_processing_time = performance_metrics.total_processing_time_ms / performance_metrics.request_count
    end
    
    return {
        timestamp = ngx.time(),
        request_metrics = {
            total_requests = performance_metrics.request_count,
            avg_processing_time_ms = avg_processing_time,
            max_processing_time_ms = performance_metrics.max_processing_time_ms,
            min_processing_time_ms = performance_metrics.min_processing_time_ms == math.huge and 0 or performance_metrics.min_processing_time_ms,
            within_threshold_percent = _M.calculate_threshold_compliance()
        },
        memory_metrics = {
            current_memory_kb = current_memory,
            baseline_memory_kb = memory_tracker.baseline_memory_kb,
            peak_memory_kb = memory_tracker.peak_memory_kb,
            memory_growth_kb = current_memory - memory_tracker.baseline_memory_kb
        },
        cpu_metrics = {
            current_cpu_percent = cpu_usage,
            high_cpu_alerts = cpu_sampler.high_cpu_alerts,
            recent_samples = cpu_sampler.samples
        },
        circuit_breaker = {
            state = performance_metrics.circuit_breaker_state,
            failure_count = performance_metrics.circuit_breaker_failures,
            last_check = performance_metrics.last_circuit_check
        },
        cache_metrics = {
            compiled_patterns_count = _M.count_table_entries(timing_cache.compiled_patterns),
            cached_calculations_count = _M.count_table_entries(timing_cache.cached_calculations),
            frequent_lookups_count = _M.count_table_entries(timing_cache.frequent_lookups)
        }
    }
end

---
-- Calculate compliance with performance thresholds
-- @return Percentage of requests within threshold
---
function _M.calculate_threshold_compliance()
    if performance_metrics.request_count == 0 then
        return 100
    end
    
    -- Estimate based on average vs threshold
    local avg_time = performance_metrics.total_processing_time_ms / performance_metrics.request_count
    if avg_time <= PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS then
        return 100
    else
        -- Conservative estimate based on how far over threshold we are
        return math.max(0, 100 - ((avg_time - PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS) / PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS * 100))
    end
end

---
-- Apply optimization configuration based on level
-- @param level Optimization level: "minimal", "balanced", "detailed"
---
function _M.apply_optimization_config(level)
    local config = OPTIMIZATION_CONFIGS[level:upper()] or OPTIMIZATION_CONFIGS.BALANCED
    
    -- Update sampling rate
    PERFORMANCE_THRESHOLDS.SAMPLING_RATE = config.sampling_rate
    
    -- Configure timing cache sizes
    timing_cache.max_cache_size = config.cache_size
    
    kong.log.info("[Kong Guard AI Perf] Applied optimization level: " .. level)
end

---
-- Cleanup performance caches to prevent memory leaks
---
function _M.cleanup_performance_caches()
    local current_time = ngx.time()
    local cleaned_count = 0
    
    -- Clean cached calculations (remove entries older than 1 hour)
    for operation_id, cached_data in pairs(timing_cache.cached_calculations) do
        if current_time - cached_data.timestamp > 3600 then
            timing_cache.cached_calculations[operation_id] = nil
            cleaned_count = cleaned_count + 1
        end
    end
    
    -- Clean memory samples (keep only recent ones)
    if #memory_tracker.request_memory_samples > 50 then
        local samples_to_keep = {}
        for i = #memory_tracker.request_memory_samples - 50, #memory_tracker.request_memory_samples do
            if memory_tracker.request_memory_samples[i] then
                table.insert(samples_to_keep, memory_tracker.request_memory_samples[i])
            end
        end
        memory_tracker.request_memory_samples = samples_to_keep
    end
    
    -- Limit compiled patterns cache
    if timing_cache.max_cache_size and _M.count_table_entries(timing_cache.compiled_patterns) > timing_cache.max_cache_size then
        local entries_to_remove = _M.count_table_entries(timing_cache.compiled_patterns) - timing_cache.max_cache_size
        local removed = 0
        for pattern_id, _ in pairs(timing_cache.compiled_patterns) do
            timing_cache.compiled_patterns[pattern_id] = nil
            removed = removed + 1
            if removed >= entries_to_remove then
                break
            end
        end
    end
    
    if cleaned_count > 0 then
        kong.log.debug("[Kong Guard AI Perf] Cache cleanup completed: " .. cleaned_count .. " entries removed")
    end
end

---
-- Count entries in a table efficiently
-- @param table_to_count Table to count
-- @return Number of entries
---
function _M.count_table_entries(table_to_count)
    local count = 0
    for _ in pairs(table_to_count) do
        count = count + 1
    end
    return count
end

---
-- Get performance optimization recommendations
-- @return Table containing optimization recommendations
---
function _M.get_optimization_recommendations()
    local recommendations = {}
    local dashboard_data = _M.get_performance_dashboard_data()
    
    -- Check average processing time
    if dashboard_data.request_metrics.avg_processing_time_ms > PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS then
        table.insert(recommendations, {
            type = "performance",
            priority = "high",
            message = "Average processing time exceeds threshold",
            suggestion = "Consider enabling minimal optimization mode or increasing sampling rate",
            current_value = dashboard_data.request_metrics.avg_processing_time_ms,
            threshold = PERFORMANCE_THRESHOLDS.MAX_REQUEST_LATENCY_MS
        })
    end
    
    -- Check memory growth
    if dashboard_data.memory_metrics.memory_growth_kb > PERFORMANCE_THRESHOLDS.MEMORY_ALERT_THRESHOLD_MB * 1024 then
        table.insert(recommendations, {
            type = "memory",
            priority = "medium",
            message = "Significant memory growth detected",
            suggestion = "Increase cache cleanup frequency or reduce cache sizes",
            current_value = dashboard_data.memory_metrics.memory_growth_kb,
            threshold = PERFORMANCE_THRESHOLDS.MEMORY_ALERT_THRESHOLD_MB * 1024
        })
    end
    
    -- Check CPU usage
    if dashboard_data.cpu_metrics.current_cpu_percent > PERFORMANCE_THRESHOLDS.MAX_CPU_USAGE_PERCENT then
        table.insert(recommendations, {
            type = "cpu",
            priority = "high",
            message = "High CPU usage detected",
            suggestion = "Reduce sampling rate or disable detailed monitoring",
            current_value = dashboard_data.cpu_metrics.current_cpu_percent,
            threshold = PERFORMANCE_THRESHOLDS.MAX_CPU_USAGE_PERCENT
        })
    end
    
    -- Check circuit breaker state
    if dashboard_data.circuit_breaker.state ~= "closed" then
        table.insert(recommendations, {
            type = "circuit_breaker",
            priority = "critical",
            message = "Circuit breaker is not in closed state",
            suggestion = "Investigate performance issues causing threshold violations",
            current_value = dashboard_data.circuit_breaker.state,
            failure_count = dashboard_data.circuit_breaker.failure_count
        })
    end
    
    return {
        timestamp = ngx.time(),
        recommendations = recommendations,
        overall_health = #recommendations == 0 and "healthy" or "needs_attention"
    }
end

---
-- Create a fast path for critical operations
-- @param operation_name Name of the operation
-- @param fast_function Fast version of the operation
-- @param full_function Full version of the operation
-- @param use_fast_path_condition Function that returns true if fast path should be used
-- @return Result of the appropriate function
---
function _M.create_fast_path(operation_name, fast_function, full_function, use_fast_path_condition)
    if use_fast_path_condition and use_fast_path_condition() then
        return fast_function()
    else
        return full_function()
    end
end

---
-- Reset all performance metrics (for testing or debugging)
---
function _M.reset_performance_metrics()
    performance_metrics = {
        request_count = 0,
        total_processing_time_ms = 0,
        max_processing_time_ms = 0,
        min_processing_time_ms = math.huge,
        memory_peak_kb = 0,
        cpu_samples = {},
        circuit_breaker_failures = 0,
        circuit_breaker_state = "closed",
        last_circuit_check = ngx.time()
    }
    
    memory_tracker.request_memory_samples = {}
    cpu_sampler.samples = {}
    timing_cache.cached_calculations = {}
    
    kong.log.info("[Kong Guard AI Perf] Performance metrics reset")
end

return _M