-- Kong Guard AI - Advanced Rate Limiting Module
-- Implements sliding window rate limiting with burst detection and adaptive thresholds
--
-- Features:
-- - Per-IP, per-user, and global rate limiting
-- - Multiple time windows (1min, 5min, 1hour, 24hour)
-- - Burst detection with configurable thresholds
-- - Progressive penalties (warn → throttle → block)
-- - Rate limit bypass for whitelisted IPs/users
-- - Dynamic rate limit adjustment based on threat level
-- - Sliding window algorithm for accurate rate limiting

local kong = kong
local math = math
local ngx = ngx
local string = string
local table = table
local tonumber = tonumber
local tostring = tostring
local cjson = require "cjson"

local rate_limiter = {}

-- Shared memory dictionaries
local RATE_LIMIT_DICT = "kong_guard_ai_rate_limits"
local BURST_DICT = "kong_guard_ai_burst_detection"

-- Time window constants (in seconds)
local TIME_WINDOWS = {
    MINUTE = 60,
    FIVE_MINUTES = 300,
    HOUR = 3600,
    DAY = 86400
}

-- Rate limit result codes
local RATE_LIMIT_CODES = {
    ALLOWED = 0,
    WARNING = 1,
    THROTTLED = 2,
    BLOCKED = 3,
    BURST_DETECTED = 4
}

-- Progressive penalty multipliers
local PENALTY_MULTIPLIERS = {
    WARNING = 1.0,
    THROTTLED = 0.5,    -- 50% rate limit reduction
    BLOCKED = 0.1       -- 90% rate limit reduction
}

-- Burst detection thresholds (percentage above normal rate)
local BURST_THRESHOLDS = {
    LIGHT = 200,    -- 200% of normal rate
    MEDIUM = 500,   -- 500% of normal rate
    SEVERE = 1000   -- 1000% of normal rate
}

-- Key prefixes for organized storage
local KEY_PREFIXES = {
    RATE_LIMIT = "rl:",
    BURST = "burst:",
    PENALTY = "penalty:",
    BASELINE = "baseline:",
    WHITELIST = "whitelist:",
    BYPASS = "bypass:"
}

---
-- Initialize rate limiter system
-- @param config table Plugin configuration
-- @return boolean Success status
---
function rate_limiter.init_worker(config)
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    local burst_shm = ngx.shared[BURST_DICT]
    
    if not rate_limit_shm then
        kong.log.err("[Kong Guard AI Rate Limiter] Shared memory zone '", RATE_LIMIT_DICT, "' not found")
        return false
    end
    
    if not burst_shm then
        kong.log.err("[Kong Guard AI Rate Limiter] Shared memory zone '", BURST_DICT, "' not found")
        return false
    end
    
    -- Initialize baseline rate data
    local current_time = ngx.time()
    rate_limit_shm:set("init_time", current_time)
    burst_shm:set("init_time", current_time)
    
    kong.log.info("[Kong Guard AI Rate Limiter] Initialized successfully")
    return true
end

---
-- Generate efficient rate limit key
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @param window number Time window in seconds
-- @param bucket number Time bucket for sliding window
-- @return string Rate limit key
---
local function generate_rate_key(ip, user_id, window, bucket)
    local identifier = user_id and (ip .. ":" .. user_id) or ip
    local key = KEY_PREFIXES.RATE_LIMIT .. identifier .. ":" .. tostring(window) .. ":" .. tostring(bucket)
    
    -- Truncate if too long for efficiency
    if #key > 128 then
        local hash = ngx.crc32_short(key)
        key = string.sub(key, 1, 100) .. ":" .. tostring(hash)
    end
    
    return key
end

---
-- Get current sliding window buckets for a time window
-- @param window number Time window in seconds
-- @param bucket_count number Number of buckets to split window into
-- @return table Array of bucket timestamps
---
local function get_sliding_window_buckets(window, bucket_count)
    bucket_count = bucket_count or 10  -- Default 10 buckets per window
    local bucket_size = window / bucket_count
    local current_time = ngx.time()
    local buckets = {}
    
    for i = 0, bucket_count - 1 do
        local bucket_start = current_time - (i * bucket_size)
        buckets[i + 1] = math.floor(bucket_start / bucket_size)
    end
    
    return buckets
end

---
-- Increment rate limit counter with sliding window
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @param window number Time window in seconds
-- @param increment number Value to add (default: 1)
-- @return table Sliding window totals
---
local function increment_sliding_window(ip, user_id, window, increment)
    increment = increment or 1
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    if not rate_limit_shm then
        return {}
    end
    
    local buckets = get_sliding_window_buckets(window)
    local current_bucket = buckets[1]
    local window_total = 0
    local bucket_counts = {}
    
    -- Increment current bucket
    local current_key = generate_rate_key(ip, user_id, window, current_bucket)
    local expiry = window * 2  -- Keep data for 2x window length
    local current_count = rate_limit_shm:incr(current_key, increment, 0, expiry) or 0
    
    -- Sum all buckets in the sliding window
    for _, bucket in ipairs(buckets) do
        local bucket_key = generate_rate_key(ip, user_id, window, bucket)
        local count = rate_limit_shm:get(bucket_key) or 0
        bucket_counts[bucket] = count
        window_total = window_total + count
    end
    
    return {
        total = window_total,
        current_bucket = current_count,
        buckets = bucket_counts,
        window = window
    }
end

---
-- Check if IP/user is whitelisted
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @param config table Plugin configuration
-- @return boolean True if whitelisted
---
local function is_whitelisted(ip, user_id, config)
    -- Check static whitelist from config
    if config.ip_whitelist then
        for _, whitelisted_ip in ipairs(config.ip_whitelist) do
            if ip == whitelisted_ip or string.find(ip, whitelisted_ip, 1, true) then
                return true
            end
        end
    end
    
    -- Check dynamic whitelist in shared memory
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    if rate_limit_shm then
        local whitelist_key = KEY_PREFIXES.WHITELIST .. ip
        if rate_limit_shm:get(whitelist_key) then
            return true
        end
        
        if user_id then
            local user_whitelist_key = KEY_PREFIXES.WHITELIST .. "user:" .. user_id
            if rate_limit_shm:get(user_whitelist_key) then
                return true
            end
        end
    end
    
    return false
end

---
-- Get current penalty level for IP/user
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @return table Penalty information
---
local function get_penalty_level(ip, user_id)
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    if not rate_limit_shm then
        return {level = "NONE", multiplier = 1.0, expires_at = 0}
    end
    
    local identifier = user_id and (ip .. ":" .. user_id) or ip
    local penalty_key = KEY_PREFIXES.PENALTY .. identifier
    local penalty_data = rate_limit_shm:get(penalty_key)
    
    if not penalty_data then
        return {level = "NONE", multiplier = 1.0, expires_at = 0}
    end
    
    local success, penalty = pcall(cjson.decode, penalty_data)
    if not success then
        return {level = "NONE", multiplier = 1.0, expires_at = 0}
    end
    
    -- Check if penalty has expired
    if penalty.expires_at <= ngx.time() then
        rate_limit_shm:delete(penalty_key)
        return {level = "NONE", multiplier = 1.0, expires_at = 0}
    end
    
    return penalty
end

---
-- Set penalty level for IP/user
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @param level string Penalty level (WARNING, THROTTLED, BLOCKED)
-- @param duration number Penalty duration in seconds
-- @param reason string Reason for penalty
---
local function set_penalty_level(ip, user_id, level, duration, reason)
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    if not rate_limit_shm then
        return
    end
    
    local identifier = user_id and (ip .. ":" .. user_id) or ip
    local penalty_key = KEY_PREFIXES.PENALTY .. identifier
    local expires_at = ngx.time() + duration
    
    local penalty_data = {
        level = level,
        multiplier = PENALTY_MULTIPLIERS[level] or 1.0,
        expires_at = expires_at,
        reason = reason,
        timestamp = ngx.time()
    }
    
    local success, encoded = pcall(cjson.encode, penalty_data)
    if success then
        rate_limit_shm:set(penalty_key, encoded, duration)
        kong.log.warn("[Kong Guard AI Rate Limiter] Applied penalty ", level, " to ", identifier, " for ", duration, "s: ", reason)
    end
end

---
-- Detect burst traffic patterns
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @param current_rates table Current rate data for all windows
-- @param config table Plugin configuration
-- @return table Burst detection result
---
local function detect_burst(ip, user_id, current_rates, config)
    local burst_shm = ngx.shared[BURST_DICT]
    if not burst_shm then
        return {detected = false, severity = "NONE"}
    end
    
    local identifier = user_id and (ip .. ":" .. user_id) or ip
    local baseline_key = KEY_PREFIXES.BASELINE .. identifier
    
    -- Get baseline rate (average over longer period)
    local baseline_data = burst_shm:get(baseline_key)
    local baseline_rate = 10  -- Default baseline if no history
    
    if baseline_data then
        local success, baseline = pcall(cjson.decode, baseline_data)
        if success and baseline.rate then
            baseline_rate = baseline.rate
        end
    end
    
    -- Compare current minute rate to baseline
    local minute_rate = current_rates.minute and current_rates.minute.total or 0
    local burst_ratio = baseline_rate > 0 and (minute_rate / baseline_rate * 100) or 0
    
    local burst_result = {
        detected = false,
        severity = "NONE",
        ratio = burst_ratio,
        baseline_rate = baseline_rate,
        current_rate = minute_rate
    }
    
    -- Determine burst severity
    if burst_ratio >= BURST_THRESHOLDS.SEVERE then
        burst_result.detected = true
        burst_result.severity = "SEVERE"
    elseif burst_ratio >= BURST_THRESHOLDS.MEDIUM then
        burst_result.detected = true
        burst_result.severity = "MEDIUM"
    elseif burst_ratio >= BURST_THRESHOLDS.LIGHT then
        burst_result.detected = true
        burst_result.severity = "LIGHT"
    end
    
    -- Update baseline rate (exponential moving average)
    if minute_rate > 0 then
        local new_baseline = (baseline_rate * 0.9) + (minute_rate * 0.1)
        local new_baseline_data = {
            rate = new_baseline,
            updated_at = ngx.time(),
            sample_count = (baseline.sample_count or 0) + 1
        }
        
        local success, encoded = pcall(cjson.encode, new_baseline_data)
        if success then
            burst_shm:set(baseline_key, encoded, TIME_WINDOWS.DAY)
        end
    end
    
    return burst_result
end

---
-- Calculate dynamic rate limits based on threat level
-- @param base_limit number Base rate limit
-- @param threat_level number Current threat level (0-10)
-- @param penalty table Current penalty information
-- @return number Adjusted rate limit
---
local function calculate_dynamic_limit(base_limit, threat_level, penalty)
    local limit = base_limit
    
    -- Apply threat level adjustment
    if threat_level > 5 then
        local threat_multiplier = 1.0 - ((threat_level - 5) * 0.1)  -- Reduce limit as threat increases
        limit = limit * threat_multiplier
    end
    
    -- Apply penalty multiplier
    limit = limit * penalty.multiplier
    
    -- Ensure minimum limit
    return math.max(limit, 1)
end

---
-- Main rate limiting check
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @param threat_level number Current threat level (0-10)
-- @param config table Plugin configuration
-- @return table Rate limit result
---
function rate_limiter.check_rate_limits(ip, user_id, threat_level, config)
    if not ip then
        return {
            allowed = true,
            code = RATE_LIMIT_CODES.ALLOWED,
            message = "No IP address provided"
        }
    end
    
    -- Check if whitelisted
    if is_whitelisted(ip, user_id, config) then
        return {
            allowed = true,
            code = RATE_LIMIT_CODES.ALLOWED,
            message = "IP/User whitelisted",
            whitelisted = true
        }
    end
    
    -- Get current penalty level
    local penalty = get_penalty_level(ip, user_id)
    
    -- Get current rates for all time windows
    local current_rates = {}
    for window_name, window_size in pairs(TIME_WINDOWS) do
        current_rates[window_name:lower()] = increment_sliding_window(ip, user_id, window_size, 1)
    end
    
    -- Detect burst patterns
    local burst_result = detect_burst(ip, user_id, current_rates, config)
    
    -- Get rate limits from config with dynamic adjustment
    local base_limits = {
        minute = config.rate_limit_per_minute or 60,
        five_minutes = config.rate_limit_per_five_minutes or 300,
        hour = config.rate_limit_per_hour or 3600,
        day = config.rate_limit_per_day or 86400
    }
    
    -- Calculate dynamic limits
    local dynamic_limits = {}
    for window, base_limit in pairs(base_limits) do
        dynamic_limits[window] = calculate_dynamic_limit(base_limit, threat_level or 0, penalty)
    end
    
    -- Check each time window
    local violations = {}
    local highest_violation_code = RATE_LIMIT_CODES.ALLOWED
    
    for window, limit in pairs(dynamic_limits) do
        local current_rate = current_rates[window]
        if current_rate and current_rate.total > limit then
            local violation = {
                window = window,
                limit = limit,
                current = current_rate.total,
                percentage = (current_rate.total / limit) * 100
            }
            table.insert(violations, violation)
            
            -- Determine violation severity
            if violation.percentage >= 200 then
                highest_violation_code = RATE_LIMIT_CODES.BLOCKED
            elseif violation.percentage >= 150 then
                highest_violation_code = math.max(highest_violation_code, RATE_LIMIT_CODES.THROTTLED)
            elseif violation.percentage >= 120 then
                highest_violation_code = math.max(highest_violation_code, RATE_LIMIT_CODES.WARNING)
            end
        end
    end
    
    -- Handle burst detection
    if burst_result.detected then
        highest_violation_code = RATE_LIMIT_CODES.BURST_DETECTED
        
        -- Apply progressive penalties for burst detection
        if burst_result.severity == "SEVERE" then
            set_penalty_level(ip, user_id, "BLOCKED", 3600, "Severe burst detected")
        elseif burst_result.severity == "MEDIUM" then
            set_penalty_level(ip, user_id, "THROTTLED", 1800, "Medium burst detected")
        elseif burst_result.severity == "LIGHT" then
            set_penalty_level(ip, user_id, "WARNING", 600, "Light burst detected")
        end
    end
    
    -- Build result
    local result = {
        allowed = highest_violation_code == RATE_LIMIT_CODES.ALLOWED,
        code = highest_violation_code,
        violations = violations,
        current_rates = current_rates,
        dynamic_limits = dynamic_limits,
        penalty = penalty,
        burst_detection = burst_result,
        threat_level = threat_level
    }
    
    -- Set appropriate message
    if highest_violation_code == RATE_LIMIT_CODES.BLOCKED then
        result.message = "Rate limit exceeded - request blocked"
    elseif highest_violation_code == RATE_LIMIT_CODES.THROTTLED then
        result.message = "Rate limit exceeded - request throttled"
    elseif highest_violation_code == RATE_LIMIT_CODES.WARNING then
        result.message = "Rate limit warning - approaching threshold"
    elseif highest_violation_code == RATE_LIMIT_CODES.BURST_DETECTED then
        result.message = "Burst traffic detected - " .. burst_result.severity:lower() .. " level"
    else
        result.message = "Request allowed"
    end
    
    return result
end

---
-- Add IP/user to whitelist
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @param duration number Whitelist duration in seconds (0 for permanent)
-- @param reason string Reason for whitelisting
-- @return boolean Success status
---
function rate_limiter.add_to_whitelist(ip, user_id, duration, reason)
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    if not rate_limit_shm then
        return false
    end
    
    local whitelist_data = {
        reason = reason or "Manual addition",
        timestamp = ngx.time(),
        duration = duration
    }
    
    local success, encoded = pcall(cjson.encode, whitelist_data)
    if not success then
        return false
    end
    
    local expiry = duration > 0 and duration or 0
    
    if ip then
        local whitelist_key = KEY_PREFIXES.WHITELIST .. ip
        rate_limit_shm:set(whitelist_key, encoded, expiry)
    end
    
    if user_id then
        local user_whitelist_key = KEY_PREFIXES.WHITELIST .. "user:" .. user_id
        rate_limit_shm:set(user_whitelist_key, encoded, expiry)
    end
    
    kong.log.info("[Kong Guard AI Rate Limiter] Added to whitelist: ", ip or "unknown", 
                  user_id and (" user:" .. user_id) or "", " for ", duration, "s")
    return true
end

---
-- Remove IP/user from whitelist
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @return boolean Success status
---
function rate_limiter.remove_from_whitelist(ip, user_id)
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    if not rate_limit_shm then
        return false
    end
    
    if ip then
        local whitelist_key = KEY_PREFIXES.WHITELIST .. ip
        rate_limit_shm:delete(whitelist_key)
    end
    
    if user_id then
        local user_whitelist_key = KEY_PREFIXES.WHITELIST .. "user:" .. user_id
        rate_limit_shm:delete(user_whitelist_key)
    end
    
    kong.log.info("[Kong Guard AI Rate Limiter] Removed from whitelist: ", ip or "unknown",
                  user_id and (" user:" .. user_id) or "")
    return true
end

---
-- Clear penalty for IP/user
-- @param ip string Client IP address
-- @param user_id string User identifier (optional)
-- @return boolean Success status
---
function rate_limiter.clear_penalty(ip, user_id)
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    if not rate_limit_shm then
        return false
    end
    
    local identifier = user_id and (ip .. ":" .. user_id) or ip
    local penalty_key = KEY_PREFIXES.PENALTY .. identifier
    rate_limit_shm:delete(penalty_key)
    
    kong.log.info("[Kong Guard AI Rate Limiter] Cleared penalty for: ", identifier)
    return true
end

---
-- Get rate limiting statistics
-- @param ip string Client IP address (optional, for per-IP stats)
-- @param user_id string User identifier (optional)
-- @return table Rate limiting statistics
---
function rate_limiter.get_statistics(ip, user_id)
    local stats = {
        timestamp = ngx.time(),
        global = {},
        per_ip = {}
    }
    
    -- Get global statistics from shared memory
    local rate_limit_shm = ngx.shared[RATE_LIMIT_DICT]
    local burst_shm = ngx.shared[BURST_DICT]
    
    if rate_limit_shm then
        stats.global.memory_usage = {
            capacity = rate_limit_shm:capacity(),
            free_space = rate_limit_shm:free_space()
        }
    end
    
    -- Get per-IP statistics if IP provided
    if ip then
        local current_rates = {}
        for window_name, window_size in pairs(TIME_WINDOWS) do
            local window_data = increment_sliding_window(ip, user_id, window_size, 0)  -- Read-only
            current_rates[window_name:lower()] = window_data
        end
        
        local penalty = get_penalty_level(ip, user_id)
        
        stats.per_ip = {
            ip = ip,
            user_id = user_id,
            current_rates = current_rates,
            penalty = penalty,
            whitelisted = is_whitelisted(ip, user_id, {ip_whitelist = {}})
        }
    end
    
    return stats
end

---
-- Cleanup expired rate limit data
-- @return table Cleanup statistics
---
function rate_limiter.cleanup()
    local cleanup_stats = {
        cleaned_entries = 0,
        start_time = ngx.now()
    }
    
    -- Note: Cleanup happens automatically via TTL on individual keys
    -- This function mainly serves for monitoring purposes
    
    cleanup_stats.end_time = ngx.now()
    cleanup_stats.duration_ms = (cleanup_stats.end_time - cleanup_stats.start_time) * 1000
    
    kong.log.debug("[Kong Guard AI Rate Limiter] Cleanup completed in ",
                   string.format("%.2f", cleanup_stats.duration_ms), "ms")
    
    return cleanup_stats
end

-- Export rate limit codes and time windows for external use
rate_limiter.RATE_LIMIT_CODES = RATE_LIMIT_CODES
rate_limiter.TIME_WINDOWS = TIME_WINDOWS
rate_limiter.PENALTY_MULTIPLIERS = PENALTY_MULTIPLIERS

return rate_limiter