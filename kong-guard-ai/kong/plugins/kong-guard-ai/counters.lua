-- Kong Guard AI - Counter Management Module
-- Efficient per-IP and global counters using ngx.shared.dict
--
-- Features:
-- - High-performance counter operations for concurrent access
-- - Time-windowed counters (1min, 5min, 1hour)
-- - Memory-efficient key structures
-- - Automatic expiration and cleanup
-- - Response time percentile tracking
-- - Status code distribution tracking
-- - Error rate monitoring

local cjson = require "cjson"
local math = math
local ngx = ngx
local string = string
local table = table
local tonumber = tonumber
local tostring = tostring

local counters = {}

-- Shared memory dictionaries
local COUNTERS_DICT = "kong_guard_ai_counters"
local DATA_DICT = "kong_guard_ai_data"

-- Time window constants (in seconds)
local TIME_WINDOWS = {
    MINUTE = 60,
    FIVE_MINUTES = 300,
    HOUR = 3600
}

-- Counter types
local COUNTER_TYPES = {
    REQUESTS = "req",
    RESPONSES = "resp",
    ERRORS = "err",
    STATUS = "status",
    RESPONSE_TIME = "rt",
    BANDWIDTH = "bw"
}

-- Key prefixes for organized storage
local KEY_PREFIXES = {
    IP_COUNTER = "ip:",
    GLOBAL_COUNTER = "global:",
    PERCENTILE = "p:",
    CLEANUP = "cleanup:",
    METADATA = "meta:",
    ERRORS = "errors:"
}

-- Response time percentile buckets (in milliseconds)
local RESPONSE_TIME_BUCKETS = {10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

-- Maximum key length for efficient storage
local MAX_KEY_LENGTH = 128

-- Cleanup frequency (1 in N requests triggers cleanup)
local CLEANUP_FREQUENCY = 1000

---
-- Initialize counter management system
-- @param config table Plugin configuration
-- @return boolean Success status
---
function counters.init(config)
    local counters_shm = ngx.shared[COUNTERS_DICT]
    local data_shm = ngx.shared[DATA_DICT]

    if not counters_shm then
        ngx.log(ngx.ERR, "[Kong Guard AI Counters] Shared memory zone '", COUNTERS_DICT, "' not found")
        return false
    end

    if not data_shm then
        ngx.log(ngx.ERR, "[Kong Guard AI Counters] Shared memory zone '", DATA_DICT, "' not found")
        return false
    end

    -- Initialize global metadata
    local current_time = ngx.time()
    data_shm:set(KEY_PREFIXES.METADATA .. "init_time", current_time)
    data_shm:set(KEY_PREFIXES.METADATA .. "version", "1.0.0")

    ngx.log(ngx.INFO, "[Kong Guard AI Counters] Initialized successfully")
    return true
end

---
-- Generate efficient counter key
-- @param prefix string Key prefix
-- @param identifier string IP address or global identifier
-- @param counter_type string Type of counter
-- @param window number Time window in seconds
-- @param bucket number Optional time bucket for windowed counters
-- @return string Formatted key
---
local function generate_key(prefix, identifier, counter_type, window, bucket)
    local parts = {prefix, identifier, counter_type}

    if window then
        table.insert(parts, tostring(window))
        if bucket then
            table.insert(parts, tostring(bucket))
        end
    end

    local key = table.concat(parts, ":")

    -- Truncate key if too long for efficiency
    if #key > MAX_KEY_LENGTH then
        local hash = ngx.crc32_short(key)
        key = string.sub(key, 1, MAX_KEY_LENGTH - 16) .. ":" .. tostring(hash)
    end

    return key
end

---
-- Get current time bucket for windowed counters
-- @param window number Time window in seconds
-- @return number Current time bucket
---
local function get_time_bucket(window)
    return math.floor(ngx.time() / window)
end

---
-- Increment counter atomically
-- @param shm userdata Shared memory dictionary
-- @param key string Counter key
-- @param increment number Value to add (default: 1)
-- @param expiry number TTL in seconds (optional)
-- @return number New counter value, nil on error
---
local function atomic_increment(shm, key, increment, expiry)
    increment = increment or 1

    local new_value, err = shm:incr(key, increment, 0, expiry or 0)
    if err then
        ngx.log(ngx.WARN, "[Kong Guard AI Counters] Failed to increment counter '", key, "': ", err)
        return nil
    end

    return new_value
end

---
-- Increment IP-specific counter
-- @param ip string Client IP address
-- @param counter_type string Type of counter
-- @param window number Time window in seconds (optional)
-- @param increment number Value to add (default: 1)
-- @return table Counter values for different time windows
---
function counters.increment_ip_counter(ip, counter_type, window, increment)
    if not ip or not counter_type then
        ngx.log(ngx.ERR, "[Kong Guard AI Counters] Missing required parameters for IP counter")
        return nil
    end

    local counters_shm = ngx.shared[COUNTERS_DICT]
    if not counters_shm then
        return nil
    end

    increment = increment or 1
    local results = {}

    -- If specific window requested, increment only that
    if window then
        local bucket = get_time_bucket(window)
        local key = generate_key(KEY_PREFIXES.IP_COUNTER, ip, counter_type, window, bucket)
        local expiry = window * 2 -- Keep data for 2x window length

        results[tostring(window)] = atomic_increment(counters_shm, key, increment, expiry)
    else
        -- Increment all standard time windows
        for name, win_size in pairs(TIME_WINDOWS) do
            local bucket = get_time_bucket(win_size)
            local key = generate_key(KEY_PREFIXES.IP_COUNTER, ip, counter_type, win_size, bucket)
            local expiry = win_size * 2

            results[name:lower()] = atomic_increment(counters_shm, key, increment, expiry)
        end

        -- Also increment lifetime counter (no expiry)
        local lifetime_key = generate_key(KEY_PREFIXES.IP_COUNTER, ip, counter_type)
        results.lifetime = atomic_increment(counters_shm, lifetime_key, increment)
    end

    return results
end

---
-- Increment global counter
-- @param counter_type string Type of counter
-- @param window number Time window in seconds (optional)
-- @param increment number Value to add (default: 1)
-- @return table Counter values for different time windows
---
function counters.increment_global_counter(counter_type, window, increment)
    if not counter_type then
        ngx.log(ngx.ERR, "[Kong Guard AI Counters] Missing counter type for global counter")
        return nil
    end

    local counters_shm = ngx.shared[COUNTERS_DICT]
    if not counters_shm then
        return nil
    end

    increment = increment or 1
    local results = {}

    if window then
        local bucket = get_time_bucket(window)
        local key = generate_key(KEY_PREFIXES.GLOBAL_COUNTER, "all", counter_type, window, bucket)
        local expiry = window * 2

        results[tostring(window)] = atomic_increment(counters_shm, key, increment, expiry)
    else
        -- Increment all standard time windows
        for name, win_size in pairs(TIME_WINDOWS) do
            local bucket = get_time_bucket(win_size)
            local key = generate_key(KEY_PREFIXES.GLOBAL_COUNTER, "all", counter_type, win_size, bucket)
            local expiry = win_size * 2

            results[name:lower()] = atomic_increment(counters_shm, key, increment, expiry)
        end

        -- Lifetime counter
        local lifetime_key = generate_key(KEY_PREFIXES.GLOBAL_COUNTER, "all", counter_type)
        results.lifetime = atomic_increment(counters_shm, lifetime_key, increment)
    end

    return results
end

---
-- Track response time for percentile calculation
-- @param ip string Client IP address (optional, for per-IP percentiles)
-- @param response_time number Response time in milliseconds
-- @param window number Time window in seconds (optional)
---
function counters.track_response_time(ip, response_time, window)
    if not response_time or response_time < 0 then
        return
    end

    local counters_shm = ngx.shared[COUNTERS_DICT]
    if not counters_shm then
        return
    end

    -- Find appropriate bucket for response time
    local bucket_index = #RESPONSE_TIME_BUCKETS + 1
    for i, bucket_max in ipairs(RESPONSE_TIME_BUCKETS) do
        if response_time <= bucket_max then
            bucket_index = i
            break
        end
    end

    local bucket_name = bucket_index <= #RESPONSE_TIME_BUCKETS and
                       tostring(RESPONSE_TIME_BUCKETS[bucket_index]) or "inf"

    -- Track global response time distribution
    if window then
        local time_bucket = get_time_bucket(window)
        local key = generate_key(KEY_PREFIXES.PERCENTILE, "global", bucket_name, window, time_bucket)
        atomic_increment(counters_shm, key, 1, window * 2)
    else
        -- Track for all standard windows
        for name, win_size in pairs(TIME_WINDOWS) do
            local time_bucket = get_time_bucket(win_size)
            local key = generate_key(KEY_PREFIXES.PERCENTILE, "global", bucket_name, win_size, time_bucket)
            atomic_increment(counters_shm, key, 1, win_size * 2)
        end
    end

    -- Track per-IP response time distribution if IP provided
    if ip then
        if window then
            local time_bucket = get_time_bucket(window)
            local key = generate_key(KEY_PREFIXES.PERCENTILE, ip, bucket_name, window, time_bucket)
            atomic_increment(counters_shm, key, 1, window * 2)
        else
            for name, win_size in pairs(TIME_WINDOWS) do
                local time_bucket = get_time_bucket(win_size)
                local key = generate_key(KEY_PREFIXES.PERCENTILE, ip, bucket_name, win_size, time_bucket)
                atomic_increment(counters_shm, key, 1, win_size * 2)
            end
        end
    end
end

---
-- Track status code distribution
-- @param ip string Client IP address (optional)
-- @param status_code number HTTP status code
-- @param window number Time window in seconds (optional)
---
function counters.track_status_code(ip, status_code, window)
    if not status_code then
        return
    end

    local status_category = "other"
    if status_code >= 200 and status_code < 300 then
        status_category = "2xx"
    elseif status_code >= 300 and status_code < 400 then
        status_category = "3xx"
    elseif status_code >= 400 and status_code < 500 then
        status_category = "4xx"
    elseif status_code >= 500 and status_code < 600 then
        status_category = "5xx"
    end

    -- Track specific status code
    counters.increment_global_counter(COUNTER_TYPES.STATUS .. ":" .. tostring(status_code), window)
    -- Track status category
    counters.increment_global_counter(COUNTER_TYPES.STATUS .. ":" .. status_category, window)

    if ip then
        counters.increment_ip_counter(ip, COUNTER_TYPES.STATUS .. ":" .. tostring(status_code), window)
        counters.increment_ip_counter(ip, COUNTER_TYPES.STATUS .. ":" .. status_category, window)
    end
end

---
-- Get counter value
-- @param is_global boolean True for global counter, false for IP counter
-- @param identifier string IP address (for IP counters) or "all" (for global)
-- @param counter_type string Type of counter
-- @param window number Time window in seconds (optional)
-- @return number Counter value, 0 if not found
---
function counters.get_counter(is_global, identifier, counter_type, window)
    if not identifier or not counter_type then
        return 0
    end

    local counters_shm = ngx.shared[COUNTERS_DICT]
    if not counters_shm then
        return 0
    end

    local prefix = is_global and KEY_PREFIXES.GLOBAL_COUNTER or KEY_PREFIXES.IP_COUNTER
    local key

    if window then
        local bucket = get_time_bucket(window)
        key = generate_key(prefix, identifier, counter_type, window, bucket)
    else
        key = generate_key(prefix, identifier, counter_type)
    end

    return counters_shm:get(key) or 0
end

---
-- Get IP counter statistics
-- @param ip string Client IP address
-- @param counter_type string Type of counter (optional, returns all if nil)
-- @return table Counter statistics
---
function counters.get_ip_stats(ip, counter_type)
    if not ip then
        return {}
    end

    local stats = {}
    local types_to_check = counter_type and {counter_type} or {
        COUNTER_TYPES.REQUESTS,
        COUNTER_TYPES.RESPONSES,
        COUNTER_TYPES.ERRORS
    }

    for _, ctype in ipairs(types_to_check) do
        stats[ctype] = {
            minute = counters.get_counter(false, ip, ctype, TIME_WINDOWS.MINUTE),
            five_minutes = counters.get_counter(false, ip, ctype, TIME_WINDOWS.FIVE_MINUTES),
            hour = counters.get_counter(false, ip, ctype, TIME_WINDOWS.HOUR),
            lifetime = counters.get_counter(false, ip, ctype)
        }
    end

    return stats
end

---
-- Get global counter statistics
-- @param counter_type string Type of counter (optional, returns all if nil)
-- @return table Global counter statistics
---
function counters.get_global_stats(counter_type)
    local stats = {}
    local types_to_check = counter_type and {counter_type} or {
        COUNTER_TYPES.REQUESTS,
        COUNTER_TYPES.RESPONSES,
        COUNTER_TYPES.ERRORS
    }

    for _, ctype in ipairs(types_to_check) do
        stats[ctype] = {
            minute = counters.get_counter(true, "all", ctype, TIME_WINDOWS.MINUTE),
            five_minutes = counters.get_counter(true, "all", ctype, TIME_WINDOWS.FIVE_MINUTES),
            hour = counters.get_counter(true, "all", ctype, TIME_WINDOWS.HOUR),
            lifetime = counters.get_counter(true, "all", ctype)
        }
    end

    return stats
end

---
-- Calculate response time percentiles
-- @param identifier string "global" or IP address
-- @param window number Time window in seconds (optional)
-- @return table Percentile data
---
function counters.get_response_time_percentiles(identifier, window)
    if not identifier then
        identifier = "global"
    end

    local counters_shm = ngx.shared[COUNTERS_DICT]
    if not counters_shm then
        return {}
    end

    local bucket_counts = {}
    local total_requests = 0

    -- Collect bucket counts
    for _, bucket_max in ipairs(RESPONSE_TIME_BUCKETS) do
        local bucket_name = tostring(bucket_max)
        local count

        if window then
            local time_bucket = get_time_bucket(window)
            local key = generate_key(KEY_PREFIXES.PERCENTILE, identifier, bucket_name, window, time_bucket)
            count = counters_shm:get(key) or 0
        else
            -- Use lifetime data
            local key = generate_key(KEY_PREFIXES.PERCENTILE, identifier, bucket_name)
            count = counters_shm:get(key) or 0
        end

        bucket_counts[bucket_max] = count
        total_requests = total_requests + count
    end

    -- Handle overflow bucket (>10s)
    local inf_key = generate_key(KEY_PREFIXES.PERCENTILE, identifier, "inf", window)
    local inf_count = counters_shm:get(inf_key) or 0
    bucket_counts.inf = inf_count
    total_requests = total_requests + inf_count

    if total_requests == 0 then
        return {p50 = 0, p95 = 0, p99 = 0, total = 0}
    end

    -- Calculate percentiles
    local percentiles = {p50 = 0, p95 = 0, p99 = 0, total = total_requests}
    local cumulative = 0

    for _, bucket_max in ipairs(RESPONSE_TIME_BUCKETS) do
        cumulative = cumulative + bucket_counts[bucket_max]
        local percentile = cumulative / total_requests

        if percentiles.p50 == 0 and percentile >= 0.5 then
            percentiles.p50 = bucket_max
        end
        if percentiles.p95 == 0 and percentile >= 0.95 then
            percentiles.p95 = bucket_max
        end
        if percentiles.p99 == 0 and percentile >= 0.99 then
            percentiles.p99 = bucket_max
        end
    end

    -- Handle case where high percentiles are in overflow bucket
    if percentiles.p95 == 0 then percentiles.p95 = 10000 end
    if percentiles.p99 == 0 then percentiles.p99 = 10000 end

    return percentiles
end

---
-- Calculate error rate
-- @param identifier string "global" or IP address
-- @param window number Time window in seconds (optional)
-- @return table Error rate data
---
function counters.get_error_rate(identifier, window)
    local is_global = (identifier == "global")

    local total_requests = counters.get_counter(is_global, identifier, COUNTER_TYPES.REQUESTS, window)
    local total_errors = counters.get_counter(is_global, identifier, COUNTER_TYPES.ERRORS, window)

    local error_rate = 0
    if total_requests > 0 then
        error_rate = (total_errors / total_requests) * 100
    end

    return {
        error_rate = error_rate,
        total_requests = total_requests,
        total_errors = total_errors
    }
end

---
-- Get memory usage statistics
-- @return table Memory usage data
---
function counters.get_memory_usage()
    local counters_shm = ngx.shared[COUNTERS_DICT]
    local data_shm = ngx.shared[DATA_DICT]

    local stats = {
        counters_dict = {},
        data_dict = {}
    }

    if counters_shm then
        local total, used = counters_shm:capacity(), counters_shm:free_space()
        stats.counters_dict = {
            total_bytes = total,
            used_bytes = total - used,
            free_bytes = used,
            usage_percent = math.floor(((total - used) / total) * 100)
        }
    end

    if data_shm then
        local total, used = data_shm:capacity(), data_shm:free_space()
        stats.data_dict = {
            total_bytes = total,
            used_bytes = total - used,
            free_bytes = used,
            usage_percent = math.floor(((total - used) / total) * 100)
        }
    end

    return stats
end

---
-- Cleanup expired counters and perform maintenance
-- @return table Cleanup statistics
---
function counters.cleanup_expired_counters()
    local counters_shm = ngx.shared[COUNTERS_DICT]
    local data_shm = ngx.shared[DATA_DICT]

    if not counters_shm or not data_shm then
        return {cleaned = 0, error = "Shared memory not available"}
    end

    local cleanup_stats = {
        counters_cleaned = 0,
        data_cleaned = 0,
        start_time = ngx.now()
    }

    -- Record cleanup timestamp
    local cleanup_key = KEY_PREFIXES.CLEANUP .. "last_cleanup"
    data_shm:set(cleanup_key, ngx.time())

    -- Note: ngx.shared.dict doesn't provide a way to iterate over keys
    -- Cleanup happens automatically via TTL on individual keys
    -- This function mainly serves for monitoring and forced cleanup triggers

    cleanup_stats.end_time = ngx.now()
    cleanup_stats.duration_ms = (cleanup_stats.end_time - cleanup_stats.start_time) * 1000

    ngx.log(ngx.INFO, "[Kong Guard AI Counters] Cleanup completed in ",
            string.format("%.2f", cleanup_stats.duration_ms), "ms")

    return cleanup_stats
end

---
-- Reset specific counter
-- @param is_global boolean True for global counter
-- @param identifier string IP address or "all"
-- @param counter_type string Type of counter
-- @param window number Time window (optional, resets all windows if nil)
-- @return boolean Success status
---
function counters.reset_counter(is_global, identifier, counter_type, window)
    if not identifier or not counter_type then
        return false
    end

    local counters_shm = ngx.shared[COUNTERS_DICT]
    if not counters_shm then
        return false
    end

    local prefix = is_global and KEY_PREFIXES.GLOBAL_COUNTER or KEY_PREFIXES.IP_COUNTER

    if window then
        local bucket = get_time_bucket(window)
        local key = generate_key(prefix, identifier, counter_type, window, bucket)
        counters_shm:delete(key)
    else
        -- Reset all time windows
        for _, win_size in pairs(TIME_WINDOWS) do
            local bucket = get_time_bucket(win_size)
            local key = generate_key(prefix, identifier, counter_type, win_size, bucket)
            counters_shm:delete(key)
        end

        -- Reset lifetime counter
        local lifetime_key = generate_key(prefix, identifier, counter_type)
        counters_shm:delete(lifetime_key)
    end

    return true
end

---
-- Get comprehensive system statistics
-- @return table Complete system statistics
---
function counters.get_system_stats()
    local stats = {
        timestamp = ngx.time(),
        uptime_seconds = ngx.time() - (ngx.shared[DATA_DICT]:get(KEY_PREFIXES.METADATA .. "init_time") or ngx.time()),
        memory = counters.get_memory_usage(),
        global = counters.get_global_stats(),
        performance = {
            response_times = counters.get_response_time_percentiles("global"),
            error_rate = counters.get_error_rate("global")
        }
    }

    return stats
end

---
-- Periodic maintenance function (call from timer or occasionally)
-- @return table Maintenance statistics
---
function counters.maintenance()
    -- Trigger cleanup based on probability
    if math.random() < (1 / CLEANUP_FREQUENCY) then
        return counters.cleanup_expired_counters()
    end

    return {maintenance = "skipped", reason = "probability"}
end

-- Export counter types and constants for external use
counters.COUNTER_TYPES = COUNTER_TYPES
counters.TIME_WINDOWS = TIME_WINDOWS

return counters
