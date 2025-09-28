-- Advanced Rate Limiter for Kong Guard AI
-- Implements intelligent rate limiting with AI service protection
-- Addresses security hardening requirements from specification 004

local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local RateLimiter = {}
RateLimiter.__index = RateLimiter

-- Rate limiting strategies
local RATE_LIMIT_STRATEGIES = {
    FIXED_WINDOW = "fixed_window",
    SLIDING_WINDOW = "sliding_window",
    TOKEN_BUCKET = "token_bucket",
    ADAPTIVE = "adaptive"
}

-- Rate limit scopes
local RATE_LIMIT_SCOPES = {
    GLOBAL = "global",
    IP = "ip",
    USER = "user",
    API_KEY = "api_key",
    AI_SERVICE = "ai_service"
}

--- Initialize rate limiter
-- @param config table rate limiting configuration
function RateLimiter.new(config)
    local self = setmetatable({}, RateLimiter)

    self.config = config or {}
    self.limits = self.config.limits or {}
    self.strategy = self.config.strategy or RATE_LIMIT_STRATEGIES.SLIDING_WINDOW
    self.storage = {} -- In-memory storage (would use Redis in production)
    self.ai_service_calls = {} -- Track AI service calls separately

    -- Default limits
    self.default_limits = {
        [RATE_LIMIT_SCOPES.GLOBAL] = { requests = 10000, window = 60 },
        [RATE_LIMIT_SCOPES.IP] = { requests = 100, window = 60 },
        [RATE_LIMIT_SCOPES.USER] = { requests = 1000, window = 60 },
        [RATE_LIMIT_SCOPES.API_KEY] = { requests = 5000, window = 60 },
        [RATE_LIMIT_SCOPES.AI_SERVICE] = { requests = 50, window = 60 }
    }

    -- Merge with provided limits
    for scope, limit in pairs(self.limits) do
        self.default_limits[scope] = limit
    end

    return self
end

--- Check if request should be rate limited
-- @param request table request information
-- @return boolean should_limit
-- @return table limit_info (remaining, reset_time, etc.)
function RateLimiter:should_limit(request)
    local scope_checks = self:_get_applicable_scopes(request)

    for _, scope_info in ipairs(scope_checks) do
        local should_limit, limit_info = self:_check_scope_limit(scope_info.scope, scope_info.key, request)

        if should_limit then
            return true, {
                scope = scope_info.scope,
                key = scope_info.key,
                limit = limit_info.limit,
                remaining = limit_info.remaining,
                reset_time = limit_info.reset_time,
                retry_after = limit_info.retry_after
            }
        end
    end

    return false, nil
end

--- Record a request for rate limiting tracking
-- @param request table request information
-- @return boolean success
function RateLimiter:record_request(request)
    local scope_checks = self:_get_applicable_scopes(request)

    for _, scope_info in ipairs(scope_checks) do
        self:_record_scope_request(scope_info.scope, scope_info.key, request)
    end

    return true
end

--- Get applicable rate limiting scopes for request
-- @param request table request information
-- @return table list of applicable scopes with keys
function RateLimiter:_get_applicable_scopes(request)
    local scopes = {}

    -- Global scope always applies
    table.insert(scopes, {
        scope = RATE_LIMIT_SCOPES.GLOBAL,
        key = "global"
    })

    -- IP-based limiting
    if request.client_ip then
        table.insert(scopes, {
            scope = RATE_LIMIT_SCOPES.IP,
            key = request.client_ip
        })
    end

    -- User-based limiting
    if request.user_id then
        table.insert(scopes, {
            scope = RATE_LIMIT_SCOPES.USER,
            key = request.user_id
        })
    end

    -- API key-based limiting
    if request.api_key then
        table.insert(scopes, {
            scope = RATE_LIMIT_SCOPES.API_KEY,
            key = request.api_key
        })
    end

    -- AI service-specific limiting
    if request.is_ai_request or request.path and string.find(request.path, "/ai/") then
        local ai_key = request.user_id or request.api_key or request.client_ip or "anonymous"
        table.insert(scopes, {
            scope = RATE_LIMIT_SCOPES.AI_SERVICE,
            key = "ai_" .. ai_key
        })
    end

    return scopes
end

--- Check rate limit for specific scope
-- @param scope string rate limit scope
-- @param key string unique key for the scope
-- @param request table request information
-- @return boolean should_limit
-- @return table limit_info
function RateLimiter:_check_scope_limit(scope, key, request)
    local limit_config = self.default_limits[scope]
    if not limit_config then
        return false, nil
    end

    local storage_key = scope .. ":" .. key
    local current_time = os.time()

    if self.strategy == RATE_LIMIT_STRATEGIES.SLIDING_WINDOW then
        return self:_check_sliding_window_limit(storage_key, limit_config, current_time)
    elseif self.strategy == RATE_LIMIT_STRATEGIES.TOKEN_BUCKET then
        return self:_check_token_bucket_limit(storage_key, limit_config, current_time)
    elseif self.strategy == RATE_LIMIT_STRATEGIES.ADAPTIVE then
        return self:_check_adaptive_limit(storage_key, limit_config, current_time, request)
    else
        -- Default to fixed window
        return self:_check_fixed_window_limit(storage_key, limit_config, current_time)
    end
end

--- Check fixed window rate limit
-- @param storage_key string storage key
-- @param limit_config table limit configuration
-- @param current_time number current timestamp
-- @return boolean should_limit
-- @return table limit_info
function RateLimiter:_check_fixed_window_limit(storage_key, limit_config, current_time)
    local window_start = math.floor(current_time / limit_config.window) * limit_config.window
    local window_key = storage_key .. ":" .. window_start

    local current_count = self.storage[window_key] or 0

    if current_count >= limit_config.requests then
        local reset_time = window_start + limit_config.window
        return true, {
            limit = limit_config.requests,
            remaining = 0,
            reset_time = reset_time,
            retry_after = reset_time - current_time
        }
    end

    return false, {
        limit = limit_config.requests,
        remaining = limit_config.requests - current_count - 1,
        reset_time = window_start + limit_config.window,
        retry_after = 0
    }
end

--- Check sliding window rate limit
-- @param storage_key string storage key
-- @param limit_config table limit configuration
-- @param current_time number current timestamp
-- @return boolean should_limit
-- @return table limit_info
function RateLimiter:_check_sliding_window_limit(storage_key, limit_config, current_time)
    local window_start = current_time - limit_config.window

    -- Get request timestamps within the window
    local request_times = self.storage[storage_key] or {}

    -- Filter out old requests
    local valid_requests = {}
    for _, timestamp in ipairs(request_times) do
        if timestamp > window_start then
            table.insert(valid_requests, timestamp)
        end
    end

    if #valid_requests >= limit_config.requests then
        local oldest_request = valid_requests[1]
        local retry_after = oldest_request + limit_config.window - current_time

        return true, {
            limit = limit_config.requests,
            remaining = 0,
            reset_time = oldest_request + limit_config.window,
            retry_after = math.max(1, retry_after)
        }
    end

    return false, {
        limit = limit_config.requests,
        remaining = limit_config.requests - #valid_requests - 1,
        reset_time = current_time + limit_config.window,
        retry_after = 0
    }
end

--- Check token bucket rate limit
-- @param storage_key string storage key
-- @param limit_config table limit configuration
-- @param current_time number current timestamp
-- @return boolean should_limit
-- @return table limit_info
function RateLimiter:_check_token_bucket_limit(storage_key, limit_config, current_time)
    local bucket = self.storage[storage_key] or {
        tokens = limit_config.requests,
        last_refill = current_time
    }

    -- Calculate tokens to add based on time elapsed
    local time_elapsed = current_time - bucket.last_refill
    local tokens_to_add = math.floor(time_elapsed * (limit_config.requests / limit_config.window))

    bucket.tokens = math.min(limit_config.requests, bucket.tokens + tokens_to_add)
    bucket.last_refill = current_time

    if bucket.tokens < 1 then
        local refill_time = (1 - bucket.tokens) * (limit_config.window / limit_config.requests)
        return true, {
            limit = limit_config.requests,
            remaining = 0,
            reset_time = current_time + refill_time,
            retry_after = math.ceil(refill_time)
        }
    end

    -- Update storage without consuming token yet
    self.storage[storage_key] = bucket

    return false, {
        limit = limit_config.requests,
        remaining = math.floor(bucket.tokens) - 1,
        reset_time = current_time + limit_config.window,
        retry_after = 0
    }
end

--- Check adaptive rate limit (AI-enhanced)
-- @param storage_key string storage key
-- @param limit_config table limit configuration
-- @param current_time number current timestamp
-- @param request table request information
-- @return boolean should_limit
-- @return table limit_info
function RateLimiter:_check_adaptive_limit(storage_key, limit_config, current_time, request)
    -- Base check using sliding window
    local should_limit, limit_info = self:_check_sliding_window_limit(storage_key, limit_config, current_time)

    -- Apply adaptive adjustments based on request patterns
    local adjustment_factor = self:_calculate_adaptive_factor(storage_key, request, current_time)

    -- Adjust the limit based on factors
    local adjusted_limit = math.floor(limit_config.requests * adjustment_factor)

    if adjusted_limit < limit_info.limit then
        -- More restrictive limit applied
        local current_requests = limit_info.limit - limit_info.remaining

        if current_requests >= adjusted_limit then
            return true, {
                limit = adjusted_limit,
                remaining = 0,
                reset_time = limit_info.reset_time,
                retry_after = limit_info.retry_after,
                adaptive = true,
                adjustment_factor = adjustment_factor
            }
        end

        limit_info.limit = adjusted_limit
        limit_info.remaining = adjusted_limit - current_requests - 1
    end

    return should_limit, limit_info
end

--- Calculate adaptive adjustment factor
-- @param storage_key string storage key
-- @param request table request information
-- @param current_time number current timestamp
-- @return number adjustment factor (0.1 to 2.0)
function RateLimiter:_calculate_adaptive_factor(storage_key, request, current_time)
    local factor = 1.0

    -- Factor 1: Request size (larger requests get lower limits)
    if request.content_length then
        local size_mb = request.content_length / (1024 * 1024)
        if size_mb > 10 then
            factor = factor * 0.5 -- Halve limit for large requests
        elseif size_mb > 1 then
            factor = factor * 0.8
        end
    end

    -- Factor 2: Request complexity (AI requests get lower limits)
    if request.is_ai_request then
        factor = factor * 0.6 -- AI requests are more expensive
    end

    -- Factor 3: Historical behavior
    local history_key = storage_key .. ":history"
    local history = self.storage[history_key] or {
        violations = 0,
        last_violation = 0,
        total_requests = 0
    }

    -- Recent violations reduce the limit
    local time_since_violation = current_time - history.last_violation
    if time_since_violation < 300 then -- Within 5 minutes
        factor = factor * 0.7
    end

    -- High violation rate reduces the limit
    if history.violations > 0 and history.total_requests > 0 then
        local violation_rate = history.violations / history.total_requests
        if violation_rate > 0.1 then -- More than 10% violations
            factor = factor * 0.5
        elseif violation_rate > 0.05 then -- More than 5% violations
            factor = factor * 0.8
        end
    end

    -- Factor 4: Time of day (optional business logic)
    local hour = tonumber(os.date("%H", current_time))
    if hour >= 22 or hour <= 6 then -- Night hours
        factor = factor * 1.2 -- More lenient at night
    elseif hour >= 9 and hour <= 17 then -- Business hours
        factor = factor * 0.9 -- Slightly more restrictive
    end

    -- Ensure factor is within reasonable bounds
    return math.max(0.1, math.min(2.0, factor))
end

--- Record request for specific scope
-- @param scope string rate limit scope
-- @param key string unique key for the scope
-- @param request table request information
function RateLimiter:_record_scope_request(scope, key, request)
    local storage_key = scope .. ":" .. key
    local current_time = os.time()

    if self.strategy == RATE_LIMIT_STRATEGIES.SLIDING_WINDOW then
        local request_times = self.storage[storage_key] or {}
        table.insert(request_times, current_time)

        -- Keep only recent requests (within 2 windows for efficiency)
        local limit_config = self.default_limits[scope]
        local cutoff_time = current_time - (limit_config.window * 2)

        local filtered_times = {}
        for _, timestamp in ipairs(request_times) do
            if timestamp > cutoff_time then
                table.insert(filtered_times, timestamp)
            end
        end

        self.storage[storage_key] = filtered_times

    elseif self.strategy == RATE_LIMIT_STRATEGIES.TOKEN_BUCKET then
        local bucket = self.storage[storage_key]
        if bucket and bucket.tokens >= 1 then
            bucket.tokens = bucket.tokens - 1
            self.storage[storage_key] = bucket
        end

    else -- FIXED_WINDOW or ADAPTIVE
        local limit_config = self.default_limits[scope]
        local window_start = math.floor(current_time / limit_config.window) * limit_config.window
        local window_key = storage_key .. ":" .. window_start

        self.storage[window_key] = (self.storage[window_key] or 0) + 1

        -- Clean up old windows
        for stored_key, _ in pairs(self.storage) do
            if string.find(stored_key, storage_key .. ":") then
                local window_time = tonumber(string.match(stored_key, ":(%d+)$"))
                if window_time and window_time < window_start - limit_config.window then
                    self.storage[stored_key] = nil
                end
            end
        end
    end

    -- Update history for adaptive limiting
    if self.strategy == RATE_LIMIT_STRATEGIES.ADAPTIVE then
        local history_key = storage_key .. ":history"
        local history = self.storage[history_key] or {
            violations = 0,
            last_violation = 0,
            total_requests = 0
        }

        history.total_requests = history.total_requests + 1
        self.storage[history_key] = history
    end
end

--- Record a rate limit violation
-- @param scope string rate limit scope
-- @param key string unique key for the scope
function RateLimiter:record_violation(scope, key)
    if self.strategy == RATE_LIMIT_STRATEGIES.ADAPTIVE then
        local storage_key = scope .. ":" .. key
        local history_key = storage_key .. ":history"
        local history = self.storage[history_key] or {
            violations = 0,
            last_violation = 0,
            total_requests = 0
        }

        history.violations = history.violations + 1
        history.last_violation = os.time()
        self.storage[history_key] = history
    end
end

--- Get rate limiting statistics
-- @return table statistics
function RateLimiter:get_statistics()
    local stats = {
        total_requests = 0,
        total_violations = 0,
        scopes = {},
        strategy = self.strategy
    }

    for key, value in pairs(self.storage) do
        if string.find(key, ":history$") then
            local scope_key = string.gsub(key, ":history$", "")
            local scope = string.match(scope_key, "^([^:]+):")

            if not stats.scopes[scope] then
                stats.scopes[scope] = {
                    requests = 0,
                    violations = 0,
                    active_keys = 0
                }
            end

            stats.scopes[scope].requests = stats.scopes[scope].requests + value.total_requests
            stats.scopes[scope].violations = stats.scopes[scope].violations + value.violations
            stats.scopes[scope].active_keys = stats.scopes[scope].active_keys + 1

            stats.total_requests = stats.total_requests + value.total_requests
            stats.total_violations = stats.total_violations + value.violations
        end
    end

    return stats
end

--- Clear rate limiting data (for testing/reset)
-- @param scope string optional scope to clear (clears all if nil)
function RateLimiter:clear_data(scope)
    if scope then
        for key, _ in pairs(self.storage) do
            if string.find(key, "^" .. scope .. ":") then
                self.storage[key] = nil
            end
        end
    else
        self.storage = {}
    end
end

--- Get current rate limit status for a key
-- @param scope string rate limit scope
-- @param key string unique key for the scope
-- @return table status information
function RateLimiter:get_status(scope, key)
    local storage_key = scope .. ":" .. key
    local limit_config = self.default_limits[scope]

    if not limit_config then
        return nil
    end

    local current_time = os.time()
    local should_limit, limit_info = self:_check_scope_limit(scope, key, {})

    return {
        scope = scope,
        key = key,
        limit = limit_info and limit_info.limit or limit_config.requests,
        remaining = limit_info and limit_info.remaining or limit_config.requests,
        reset_time = limit_info and limit_info.reset_time or (current_time + limit_config.window),
        window = limit_config.window,
        strategy = self.strategy
    }
end

return RateLimiter
