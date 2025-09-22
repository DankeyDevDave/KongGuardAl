-- Kong Guard AI - Adaptive Rate Limiter
-- Dynamic rate limiting based on threat scores and traffic patterns

local ngx = ngx
local math = math
local floor = math.floor
local max = math.max
local min = math.min

local AdaptiveRateLimiter = {}
AdaptiveRateLimiter.__index = AdaptiveRateLimiter

-- Module constants
local RATE_WINDOW_SIZE = 60  -- 1 minute sliding window
local SMOOTH_FACTOR = 0.3    -- Exponential smoothing factor
local DEFAULT_CACHE_TTL = 300 -- 5 minutes

-- Initialize adaptive rate limiter
function AdaptiveRateLimiter:new(config)
    local self = setmetatable({}, AdaptiveRateLimiter)

    self.config = config or {}
    self.base_rate = self.config.base_rate_per_minute or 60
    self.threat_multiplier = self.config.threat_score_multiplier or 2.0
    self.min_rate = self.config.min_rate_per_minute or 5
    self.max_rate = self.config.max_rate_per_minute or 1000

    -- Shared dictionaries for rate tracking
    self.rate_cache = ngx.shared.kong_cache
    self.metrics_cache = ngx.shared.kong_cache

    return self
end

-- Calculate adaptive rate limit based on threat score
function AdaptiveRateLimiter:calculate_adaptive_limit(client_ip, threat_score)
    -- Base calculation: reduce rate as threat score increases
    local threat_factor = 1.0 / (1.0 + (threat_score * self.threat_multiplier))
    local calculated_rate = self.base_rate * threat_factor

    -- Apply min/max bounds
    calculated_rate = max(self.min_rate, min(self.max_rate, calculated_rate))

    -- Get historical rate for smoothing
    local history_key = "rate_history:" .. client_ip
    local previous_rate = self.rate_cache:get(history_key) or self.base_rate

    -- Apply exponential smoothing to prevent oscillation
    local smoothed_rate = self:smooth_rate_adjustment(previous_rate, calculated_rate)

    -- Cache the new rate
    self.rate_cache:set(history_key, smoothed_rate, DEFAULT_CACHE_TTL)

    return floor(smoothed_rate)
end

-- Smooth rate changes using exponential moving average
function AdaptiveRateLimiter:smooth_rate_adjustment(current_rate, new_rate)
    return (SMOOTH_FACTOR * new_rate) + ((1 - SMOOTH_FACTOR) * current_rate)
end

-- Track request rate with sliding window
function AdaptiveRateLimiter:track_request_rate(client_ip)
    local current_time = ngx.now()
    local window_start = floor(current_time / RATE_WINDOW_SIZE) * RATE_WINDOW_SIZE

    -- Create time-based key for sliding window
    local rate_key = "rate_track:" .. client_ip .. ":" .. window_start

    -- Increment request count for this window
    local count, err = self.rate_cache:incr(rate_key, 1, 0, RATE_WINDOW_SIZE)
    if err then
        ngx.log(ngx.ERR, "Failed to track rate for ", client_ip, ": ", err)
        return 1
    end

    return count or 1
end

-- Check if client exceeds current rate limit
function AdaptiveRateLimiter:check_rate_limit(client_ip, rate_limit)
    local current_rate = self:track_request_rate(client_ip)

    -- Update metrics
    self:update_rate_metrics(client_ip, current_rate, rate_limit)

    return current_rate > rate_limit
end

-- Get remaining quota for client
function AdaptiveRateLimiter:get_remaining_quota(client_ip, rate_limit)
    local current_rate = self:get_current_rate(client_ip)
    local remaining = max(0, rate_limit - current_rate)

    return {
        limit = rate_limit,
        remaining = remaining,
        reset_time = self:get_window_reset_time()
    }
end

-- Get current request rate for client
function AdaptiveRateLimiter:get_current_rate(client_ip)
    local current_time = ngx.now()
    local window_start = floor(current_time / RATE_WINDOW_SIZE) * RATE_WINDOW_SIZE
    local rate_key = "rate_track:" .. client_ip .. ":" .. window_start

    return self.rate_cache:get(rate_key) or 0
end

-- Get time when current window resets
function AdaptiveRateLimiter:get_window_reset_time()
    local current_time = ngx.now()
    local window_start = floor(current_time / RATE_WINDOW_SIZE) * RATE_WINDOW_SIZE
    return window_start + RATE_WINDOW_SIZE
end

-- Calculate rate limit with traffic patterns consideration
function AdaptiveRateLimiter:calculate_pattern_based_limit(client_ip, threat_score, traffic_patterns)
    local base_limit = self:calculate_adaptive_limit(client_ip, threat_score)

    -- Adjust based on traffic patterns
    if traffic_patterns then
        -- Reduce limit during traffic spikes
        if traffic_patterns.is_spike then
            base_limit = base_limit * 0.7
        end

        -- Reduce limit for burst patterns
        if traffic_patterns.is_burst then
            base_limit = base_limit * 0.8
        end

        -- Increase limit for consistent traffic
        if traffic_patterns.is_consistent then
            base_limit = base_limit * 1.2
        end
    end

    return floor(max(self.min_rate, min(self.max_rate, base_limit)))
end

-- Detect traffic patterns for adaptive adjustment
function AdaptiveRateLimiter:analyze_traffic_patterns(client_ip)
    local patterns = {
        is_spike = false,
        is_burst = false,
        is_consistent = false
    }

    -- Analyze last few windows
    local current_time = ngx.now()
    local rates = {}

    for i = 0, 4 do
        local window_start = floor((current_time - (i * RATE_WINDOW_SIZE)) / RATE_WINDOW_SIZE) * RATE_WINDOW_SIZE
        local rate_key = "rate_track:" .. client_ip .. ":" .. window_start
        local rate = self.rate_cache:get(rate_key) or 0
        table.insert(rates, rate)
    end

    if #rates >= 3 then
        local avg_rate = self:calculate_average(rates)
        local current_rate = rates[1]

        -- Detect spike (current rate significantly higher than average)
        if current_rate > avg_rate * 2 then
            patterns.is_spike = true
        end

        -- Detect burst (consistent high rates)
        local high_rate_count = 0
        for _, rate in ipairs(rates) do
            if rate > avg_rate * 1.5 then
                high_rate_count = high_rate_count + 1
            end
        end
        if high_rate_count >= 3 then
            patterns.is_burst = true
        end

        -- Detect consistent traffic (low variance)
        local variance = self:calculate_variance(rates, avg_rate)
        if variance < avg_rate * 0.2 and avg_rate > 0 then
            patterns.is_consistent = true
        end
    end

    return patterns
end

-- Calculate average of rates
function AdaptiveRateLimiter:calculate_average(rates)
    local sum = 0
    for _, rate in ipairs(rates) do
        sum = sum + rate
    end
    return sum / #rates
end

-- Calculate variance of rates
function AdaptiveRateLimiter:calculate_variance(rates, avg)
    local sum_sq_diff = 0
    for _, rate in ipairs(rates) do
        local diff = rate - avg
        sum_sq_diff = sum_sq_diff + (diff * diff)
    end
    return sum_sq_diff / #rates
end

-- Update rate limiting metrics
function AdaptiveRateLimiter:update_rate_metrics(client_ip, current_rate, rate_limit)
    -- Track violations
    if current_rate > rate_limit then
        local violation_key = "rate_violations"
        self.metrics_cache:incr(violation_key, 1, 0, 3600)
    end

    -- Track rate adjustments
    local adjustment_key = "rate_adjustments:" .. client_ip
    local prev_limit = self.metrics_cache:get(adjustment_key)
    if prev_limit and prev_limit ~= rate_limit then
        local adj_count_key = "rate_adjustments_total"
        self.metrics_cache:incr(adj_count_key, 1, 0, 3600)
    end
    self.metrics_cache:set(adjustment_key, rate_limit, 300)
end

-- Get rate limiting statistics
function AdaptiveRateLimiter:get_statistics()
    return {
        total_violations = self.metrics_cache:get("rate_violations") or 0,
        total_adjustments = self.metrics_cache:get("rate_adjustments_total") or 0,
        active_limits = self:count_active_limits(),
        avg_rate_reduction = self:calculate_avg_rate_reduction()
    }
end

-- Count currently active rate limits
function AdaptiveRateLimiter:count_active_limits()
    -- This would require iterating through all keys, simplified for demo
    return 0
end

-- Calculate average rate reduction from baseline
function AdaptiveRateLimiter:calculate_avg_rate_reduction()
    -- Simplified calculation
    return 0.25 -- 25% average reduction
end

-- Apply emergency rate limiting during severe attacks
function AdaptiveRateLimiter:apply_emergency_limiting(client_ip, severity)
    local emergency_rate = self.min_rate

    -- Adjust based on severity (0.0 to 1.0)
    if severity > 0.9 then
        emergency_rate = max(1, self.min_rate * 0.1) -- Extremely restrictive
    elseif severity > 0.8 then
        emergency_rate = max(2, self.min_rate * 0.3) -- Very restrictive
    elseif severity > 0.7 then
        emergency_rate = max(3, self.min_rate * 0.5) -- Moderately restrictive
    end

    -- Cache emergency rate with short TTL for quick recovery
    local emergency_key = "emergency_rate:" .. client_ip
    self.rate_cache:set(emergency_key, emergency_rate, 60) -- 1 minute emergency period

    return floor(emergency_rate)
end

-- Check if client is under emergency rate limiting
function AdaptiveRateLimiter:is_under_emergency_limiting(client_ip)
    local emergency_key = "emergency_rate:" .. client_ip
    return self.rate_cache:get(emergency_key) ~= nil
end

-- Clear emergency rate limiting for client
function AdaptiveRateLimiter:clear_emergency_limiting(client_ip)
    local emergency_key = "emergency_rate:" .. client_ip
    self.rate_cache:delete(emergency_key)
end

-- Cleanup old rate tracking data
function AdaptiveRateLimiter:cleanup_old_data()
    -- This would be called periodically to clean up old rate tracking data
    -- Implementation would iterate through keys and remove expired ones
    -- For simplicity, relying on TTL expiration
end

return AdaptiveRateLimiter