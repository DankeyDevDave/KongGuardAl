-- Kong Guard AI - Circuit Breaker
-- Implements circuit breaker pattern for resilience against cascading failures

local ngx = ngx
local math = math
local floor = math.floor
local max = math.max
local min = math.min

local CircuitBreaker = {}
CircuitBreaker.__index = CircuitBreaker

-- Module constants
local STATE_CLOSED = "closed"
local STATE_OPEN = "open"
local STATE_HALF_OPEN = "half_open"

local DEFAULT_CACHE_TTL = 300 -- 5 minutes
local METRICS_WINDOW = 60 -- 1 minute for metrics calculation
local HALF_OPEN_MAX_REQUESTS = 3 -- Max requests allowed in half-open state

-- Initialize circuit breaker
function CircuitBreaker:new(config)
    local self = setmetatable({}, CircuitBreaker)

    self.config = config or {}
    self.failure_threshold = self.config.failure_threshold or 5
    self.recovery_timeout = self.config.recovery_timeout_seconds or 60
    self.success_threshold = self.config.success_threshold or 3
    self.request_timeout = self.config.request_timeout_seconds or 10

    -- Shared dictionaries for state tracking
    self.state_cache = ngx.shared.kong_cache
    self.metrics_cache = ngx.shared.kong_cache

    return self
end

-- Get circuit breaker state for a service/upstream
function CircuitBreaker:get_state(service_id)
    local state_key = "circuit_state:" .. service_id
    local state_data = self.state_cache:get(state_key)

    if not state_data then
        -- Initialize with closed state
        local initial_state = {
            state = STATE_CLOSED,
            failure_count = 0,
            success_count = 0,
            last_failure_time = 0,
            next_attempt_time = 0,
            half_open_requests = 0
        }
        self:set_state(service_id, initial_state)
        return initial_state
    end

    -- Parse stored state data
    local state_info = {}
    for key, value in state_data:gmatch("([^:]+):([^,]+)") do
        if key == "state" then
            state_info[key] = value
        else
            state_info[key] = tonumber(value) or 0
        end
    end

    return state_info
end

-- Set circuit breaker state for a service/upstream
function CircuitBreaker:set_state(service_id, state_info)
    local state_key = "circuit_state:" .. service_id
    local state_data = string.format(
        "state:%s,failure_count:%d,success_count:%d,last_failure_time:%d,next_attempt_time:%d,half_open_requests:%d",
        state_info.state,
        state_info.failure_count or 0,
        state_info.success_count or 0,
        state_info.last_failure_time or 0,
        state_info.next_attempt_time or 0,
        state_info.half_open_requests or 0
    )

    self.state_cache:set(state_key, state_data, DEFAULT_CACHE_TTL)

    -- Update metrics
    self:update_state_metrics(service_id, state_info.state)
end

-- Check if request should be allowed through circuit breaker
function CircuitBreaker:should_allow_request(service_id)
    local state_info = self:get_state(service_id)
    local current_time = ngx.now()

    if state_info.state == STATE_CLOSED then
        -- Allow all requests in closed state
        return true, "closed"

    elseif state_info.state == STATE_OPEN then
        -- Check if recovery timeout has passed
        if current_time >= state_info.next_attempt_time then
            -- Transition to half-open state
            state_info.state = STATE_HALF_OPEN
            state_info.half_open_requests = 0
            state_info.success_count = 0
            self:set_state(service_id, state_info)
            return true, "half_open_transition"
        else
            -- Still in open state, reject request
            return false, "circuit_open"
        end

    elseif state_info.state == STATE_HALF_OPEN then
        -- Allow limited requests in half-open state
        if state_info.half_open_requests < HALF_OPEN_MAX_REQUESTS then
            state_info.half_open_requests = state_info.half_open_requests + 1
            self:set_state(service_id, state_info)
            return true, "half_open_test"
        else
            -- Too many requests in half-open, wait for results
            return false, "half_open_limit"
        end
    end

    return false, "unknown_state"
end

-- Record successful request
function CircuitBreaker:record_success(service_id)
    local state_info = self:get_state(service_id)
    local current_time = ngx.now()

    -- Update success metrics
    self:update_request_metrics(service_id, "success")

    if state_info.state == STATE_HALF_OPEN then
        state_info.success_count = state_info.success_count + 1

        -- Check if we have enough successes to close circuit
        if state_info.success_count >= self.success_threshold then
            state_info.state = STATE_CLOSED
            state_info.failure_count = 0
            state_info.success_count = 0
            state_info.half_open_requests = 0
            state_info.last_failure_time = 0
            state_info.next_attempt_time = 0

            ngx.log(ngx.INFO, "Circuit breaker closed for service: ", service_id)
        end

        self:set_state(service_id, state_info)

    elseif state_info.state == STATE_CLOSED then
        -- Reset failure count on success in closed state
        if state_info.failure_count > 0 then
            state_info.failure_count = max(0, state_info.failure_count - 1)
            self:set_state(service_id, state_info)
        end
    end
end

-- Record failed request
function CircuitBreaker:record_failure(service_id, error_type)
    local state_info = self:get_state(service_id)
    local current_time = ngx.now()

    -- Update failure metrics
    self:update_request_metrics(service_id, "failure")

    if state_info.state == STATE_CLOSED then
        state_info.failure_count = state_info.failure_count + 1
        state_info.last_failure_time = current_time

        -- Check if failure threshold exceeded
        if state_info.failure_count >= self.failure_threshold then
            state_info.state = STATE_OPEN
            state_info.next_attempt_time = current_time + self.recovery_timeout
            state_info.half_open_requests = 0

            ngx.log(ngx.WARN, "Circuit breaker opened for service: ", service_id,
                   " after ", state_info.failure_count, " failures")
        end

        self:set_state(service_id, state_info)

    elseif state_info.state == STATE_HALF_OPEN then
        -- Any failure in half-open immediately opens circuit
        state_info.state = STATE_OPEN
        state_info.failure_count = state_info.failure_count + 1
        state_info.last_failure_time = current_time
        state_info.next_attempt_time = current_time + self.recovery_timeout
        state_info.half_open_requests = 0
        state_info.success_count = 0

        ngx.log(ngx.WARN, "Circuit breaker reopened for service: ", service_id,
               " during half-open test")

        self:set_state(service_id, state_info)
    end
end

-- Get circuit breaker health metrics
function CircuitBreaker:get_health_metrics(service_id)
    local state_info = self:get_state(service_id)
    local current_time = ngx.now()

    -- Calculate failure rate from recent metrics
    local failure_rate = self:calculate_failure_rate(service_id)
    local avg_response_time = self:get_avg_response_time(service_id)

    return {
        service_id = service_id,
        state = state_info.state,
        failure_count = state_info.failure_count,
        success_count = state_info.success_count,
        failure_rate = failure_rate,
        avg_response_time = avg_response_time,
        last_failure_time = state_info.last_failure_time,
        next_attempt_time = state_info.next_attempt_time,
        time_until_retry = max(0, state_info.next_attempt_time - current_time)
    }
end

-- Calculate failure rate over recent window
function CircuitBreaker:calculate_failure_rate(service_id)
    local current_time = ngx.now()
    local window_start = floor(current_time / METRICS_WINDOW) * METRICS_WINDOW

    local success_key = "cb_success:" .. service_id .. ":" .. window_start
    local failure_key = "cb_failure:" .. service_id .. ":" .. window_start

    local successes = self.metrics_cache:get(success_key) or 0
    local failures = self.metrics_cache:get(failure_key) or 0

    local total = successes + failures
    if total == 0 then
        return 0.0
    end

    return failures / total
end

-- Get average response time
function CircuitBreaker:get_avg_response_time(service_id)
    local current_time = ngx.now()
    local window_start = floor(current_time / METRICS_WINDOW) * METRICS_WINDOW

    local time_key = "cb_response_time:" .. service_id .. ":" .. window_start
    local count_key = "cb_response_count:" .. service_id .. ":" .. window_start

    local total_time = self.metrics_cache:get(time_key) or 0
    local count = self.metrics_cache:get(count_key) or 0

    if count == 0 then
        return 0.0
    end

    return total_time / count
end

-- Record response time for metrics
function CircuitBreaker:record_response_time(service_id, response_time)
    local current_time = ngx.now()
    local window_start = floor(current_time / METRICS_WINDOW) * METRICS_WINDOW

    local time_key = "cb_response_time:" .. service_id .. ":" .. window_start
    local count_key = "cb_response_count:" .. service_id .. ":" .. window_start

    self.metrics_cache:incr(time_key, response_time, 0, METRICS_WINDOW)
    self.metrics_cache:incr(count_key, 1, 0, METRICS_WINDOW)
end

-- Update request metrics (success/failure counts)
function CircuitBreaker:update_request_metrics(service_id, result_type)
    local current_time = ngx.now()
    local window_start = floor(current_time / METRICS_WINDOW) * METRICS_WINDOW

    local metric_key = "cb_" .. result_type .. ":" .. service_id .. ":" .. window_start
    self.metrics_cache:incr(metric_key, 1, 0, METRICS_WINDOW)
end

-- Update state transition metrics
function CircuitBreaker:update_state_metrics(service_id, new_state)
    local transition_key = "cb_state_changes:" .. new_state
    self.metrics_cache:incr(transition_key, 1, 0, 3600) -- 1 hour window

    local service_state_key = "cb_current_state:" .. service_id
    self.metrics_cache:set(service_state_key, new_state, DEFAULT_CACHE_TTL)
end

-- Check if service should be bypassed (always allow requests)
function CircuitBreaker:should_bypass_circuit(service_id, request_path)
    -- Bypass circuit breaker for health check endpoints
    local health_check_paths = {
        "/health",
        "/status",
        "/ping",
        "/heartbeat"
    }

    for _, path in ipairs(health_check_paths) do
        if request_path and request_path:match(path) then
            return true
        end
    end

    return false
end

-- Get circuit breaker statistics across all services
function CircuitBreaker:get_global_statistics()
    return {
        total_state_changes = {
            closed = self.metrics_cache:get("cb_state_changes:closed") or 0,
            open = self.metrics_cache:get("cb_state_changes:open") or 0,
            half_open = self.metrics_cache:get("cb_state_changes:half_open") or 0
        },
        active_circuits = self:count_active_circuits(),
        open_circuits = self:count_circuits_by_state(STATE_OPEN),
        half_open_circuits = self:count_circuits_by_state(STATE_HALF_OPEN)
    }
end

-- Count active circuit breakers
function CircuitBreaker:count_active_circuits()
    -- Simplified implementation - in practice would iterate through all circuit keys
    return 0
end

-- Count circuits in specific state
function CircuitBreaker:count_circuits_by_state(target_state)
    -- Simplified implementation - in practice would iterate through all circuit states
    return 0
end

-- Force circuit breaker state (for testing/emergency)
function CircuitBreaker:force_state(service_id, target_state, duration)
    local state_info = self:get_state(service_id)
    local current_time = ngx.now()

    state_info.state = target_state

    if target_state == STATE_OPEN then
        state_info.next_attempt_time = current_time + (duration or self.recovery_timeout)
    elseif target_state == STATE_CLOSED then
        state_info.failure_count = 0
        state_info.success_count = 0
        state_info.next_attempt_time = 0
    elseif target_state == STATE_HALF_OPEN then
        state_info.half_open_requests = 0
        state_info.success_count = 0
    end

    self:set_state(service_id, state_info)

    ngx.log(ngx.WARN, "Circuit breaker state forced to ", target_state,
           " for service: ", service_id)
end

-- Reset circuit breaker to initial state
function CircuitBreaker:reset_circuit(service_id)
    self:force_state(service_id, STATE_CLOSED)

    -- Clear metrics for this service
    local current_time = ngx.now()
    local window_start = floor(current_time / METRICS_WINDOW) * METRICS_WINDOW

    for i = 0, 5 do -- Clear last 5 windows
        local window = window_start - (i * METRICS_WINDOW)
        self.metrics_cache:delete("cb_success:" .. service_id .. ":" .. window)
        self.metrics_cache:delete("cb_failure:" .. service_id .. ":" .. window)
        self.metrics_cache:delete("cb_response_time:" .. service_id .. ":" .. window)
        self.metrics_cache:delete("cb_response_count:" .. service_id .. ":" .. window)
    end

    ngx.log(ngx.INFO, "Circuit breaker reset for service: ", service_id)
end

-- Cleanup old circuit breaker data
function CircuitBreaker:cleanup_old_data()
    -- This would be called periodically to clean up old metrics and state data
    -- Implementation would iterate through keys and remove expired ones
    -- For simplicity, relying on TTL expiration
end

return CircuitBreaker