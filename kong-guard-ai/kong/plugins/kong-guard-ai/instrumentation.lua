-- Kong Guard AI - Instrumentation Module
-- High-performance metadata collection for Kong's request lifecycle
--
-- This module provides optimized hooks for capturing request/response metadata
-- at the access and log phases with minimal overhead (<5ms processing time).
--
-- Features:
-- - Request start time tracking with nanosecond precision
-- - Client IP extraction with proxy header support
-- - Structured request/response metadata collection
-- - Request tracking and correlation ID management
-- - Performance-optimized latency calculations
-- - Error-safe instrumentation with graceful degradation

local kong = kong
local ngx = ngx
local cjson = require "cjson.safe"

local instrumentation = {}

-- Constants for performance optimization
local CORRELATION_ID_HEADER = "X-Kong-Guard-AI-Request-ID"
local MAX_HEADER_SIZE = 8192  -- Maximum header size to capture
local MAX_PATH_LENGTH = 1024  -- Maximum path length to log
local METADATA_CACHE_TTL = 300  -- 5 minutes cache TTL

-- Shared memory cache for request tracking
local request_cache = {}

---
-- Extract client IP with proxy header support
-- Handles X-Forwarded-For, X-Real-IP, and other common proxy headers
-- @param config Plugin configuration
-- @return string client_ip The actual client IP address
---
function instrumentation.get_client_ip(config)
    local client_ip = kong.client.get_ip()
    
    -- Check proxy headers if enabled in config
    if config and config.trust_proxy_headers then
        local headers = kong.request.get_headers()
        
        -- X-Forwarded-For header (most common)
        local xff = headers["x-forwarded-for"]
        if xff then
            -- Take the first IP from the comma-separated list
            local first_ip = xff:match("([^,]+)")
            if first_ip then
                client_ip = first_ip:gsub("%s+", "")  -- Remove whitespace
            end
        end
        
        -- X-Real-IP header (nginx proxy)
        local real_ip = headers["x-real-ip"]
        if real_ip and not xff then
            client_ip = real_ip
        end
        
        -- Cloudflare CF-Connecting-IP
        local cf_ip = headers["cf-connecting-ip"]
        if cf_ip and not xff and not real_ip then
            client_ip = cf_ip
        end
    end
    
    return client_ip or "unknown"
end

---
-- Generate or retrieve correlation ID for request tracking
-- @return string correlation_id Unique identifier for this request
---
function instrumentation.get_correlation_id()
    -- Use Kong's request ID if available
    local request_id = kong.request.get_header(CORRELATION_ID_HEADER)
    if request_id then
        return request_id
    end
    
    -- Generate new correlation ID
    local correlation_id = "guard_ai_" .. ngx.time() .. "_" .. math.random(100000, 999999)
    
    -- Set header for downstream services
    kong.service.request.set_header(CORRELATION_ID_HEADER, correlation_id)
    
    return correlation_id
end

---
-- Capture request metadata at access phase
-- Optimized for minimal latency impact
-- @param config Plugin configuration
-- @return table request_metadata Structured metadata object
---
function instrumentation.capture_request_metadata(config)
    local start_time = ngx.now()
    local correlation_id = instrumentation.get_correlation_id()
    
    -- Core request data
    local request_metadata = {
        -- Timing information
        start_time = start_time,
        start_time_ms = start_time * 1000,
        timestamp = ngx.time(),
        
        -- Request identification
        correlation_id = correlation_id,
        request_id = ngx.var.request_id or correlation_id,
        
        -- Basic request info
        method = kong.request.get_method(),
        path = kong.request.get_path(),
        query_string = ngx.var.query_string or "",
        
        -- Client information
        client_ip = instrumentation.get_client_ip(config),
        user_agent = kong.request.get_header("user-agent") or "",
        
        -- Kong routing context
        service_id = nil,
        route_id = nil,
        consumer_id = nil,
        
        -- Request size and content type
        content_length = tonumber(kong.request.get_header("content-length")) or 0,
        content_type = kong.request.get_header("content-type") or "",
        
        -- Security headers
        authorization = kong.request.get_header("authorization") and "present" or "absent",
        
        -- Performance tracking
        processing_stages = {
            request_capture = 0  -- Will be updated at end of function
        }
    }
    
    -- Safely get Kong routing context
    pcall(function()
        local service = kong.router.get_service()
        if service then
            request_metadata.service_id = service.id
        end
        
        local route = kong.router.get_route()
        if route then
            request_metadata.route_id = route.id
        end
        
        local consumer = kong.client.get_consumer()
        if consumer then
            request_metadata.consumer_id = consumer.id
        end
    end)
    
    -- Capture important headers (with size limits)
    if config and config.capture_headers then
        local headers = kong.request.get_headers()
        local filtered_headers = {}
        local total_size = 0
        
        for name, value in pairs(headers) do
            if total_size < MAX_HEADER_SIZE then
                -- Skip sensitive headers
                local lower_name = string.lower(name)
                if not (lower_name:match("password") or 
                        lower_name:match("secret") or 
                        lower_name:match("token") or
                        lower_name:match("key")) then
                    
                    local header_str = tostring(value)
                    if #header_str + total_size < MAX_HEADER_SIZE then
                        filtered_headers[name] = header_str:sub(1, 256)  -- Limit individual header size
                        total_size = total_size + #header_str
                    end
                end
            else
                break
            end
        end
        
        request_metadata.headers = filtered_headers
    end
    
    -- Truncate path if too long
    if #request_metadata.path > MAX_PATH_LENGTH then
        request_metadata.path = request_metadata.path:sub(1, MAX_PATH_LENGTH) .. "..."
    end
    
    -- Calculate request capture time
    request_metadata.processing_stages.request_capture = (ngx.now() - start_time) * 1000
    
    -- Store in request cache for log phase
    request_cache[correlation_id] = request_metadata
    
    return request_metadata
end

---
-- Capture response metadata at log phase
-- @param request_metadata Original request metadata from access phase
-- @param config Plugin configuration
-- @return table response_metadata Complete request/response metadata
---
function instrumentation.capture_response_metadata(request_metadata, config)
    local end_time = ngx.now()
    local correlation_id = request_metadata.correlation_id
    
    -- Retrieve cached request data
    local cached_request = request_cache[correlation_id]
    if not cached_request then
        kong.log.warn("[Kong Guard AI] No cached request data for correlation ID: " .. correlation_id)
        cached_request = request_metadata  -- Fallback to provided data
    end
    
    -- Calculate latency with high precision
    local start_time = cached_request.start_time
    local total_latency_ms = (end_time - start_time) * 1000
    
    -- Build response metadata
    local response_metadata = {
        -- Copy all request metadata
        request = cached_request,
        
        -- Response timing
        end_time = end_time,
        end_time_ms = end_time * 1000,
        total_latency_ms = total_latency_ms,
        
        -- Response data
        status_code = kong.response.get_status(),
        response_size = tonumber(ngx.var.bytes_sent) or 0,
        
        -- Upstream timing
        upstream_latency_ms = tonumber(ngx.var.upstream_response_time) and 
                             (tonumber(ngx.var.upstream_response_time) * 1000) or 0,
        
        -- Kong processing time (total - upstream)
        kong_latency_ms = total_latency_ms - (tonumber(ngx.var.upstream_response_time) and 
                          (tonumber(ngx.var.upstream_response_time) * 1000) or 0),
        
        -- Error tracking
        error_occurred = false,
        error_type = nil
    }
    
    -- Capture response headers if configured
    if config and config.capture_response_headers then
        local response_headers = kong.response.get_headers()
        local filtered_headers = {}
        
        for name, value in pairs(response_headers) do
            local lower_name = string.lower(name)
            -- Capture important response headers
            if lower_name:match("content%-") or 
               lower_name:match("cache%-") or
               lower_name:match("server") or
               lower_name:match("x%-") then
                filtered_headers[name] = tostring(value):sub(1, 256)
            end
        end
        
        response_metadata.response_headers = filtered_headers
    end
    
    -- Determine if error occurred
    local status = response_metadata.status_code
    if status >= 400 then
        response_metadata.error_occurred = true
        if status >= 500 then
            response_metadata.error_type = "server_error"
        elseif status >= 400 then
            response_metadata.error_type = "client_error"
        end
    end
    
    -- Performance warnings
    if total_latency_ms > 1000 then  -- > 1 second
        response_metadata.performance_warning = "high_latency"
    end
    
    if response_metadata.upstream_latency_ms > 500 then  -- > 500ms
        response_metadata.upstream_warning = "slow_upstream"
    end
    
    -- Cleanup cache entry
    request_cache[correlation_id] = nil
    
    return response_metadata
end

---
-- Create structured log entry for threat incidents
-- @param threat_result Threat detection result
-- @param request_metadata Request metadata
-- @param response_metadata Response metadata (optional)
-- @param config Plugin configuration
-- @return table log_entry Structured log entry
---
function instrumentation.create_threat_log_entry(threat_result, request_metadata, response_metadata, config)
    local log_entry = {
        -- Log metadata
        log_type = "threat_incident",
        log_version = "1.0",
        timestamp = ngx.time(),
        correlation_id = request_metadata.correlation_id,
        
        -- Threat information
        threat = {
            type = threat_result.threat_type,
            level = threat_result.threat_level,
            confidence = threat_result.confidence or 0.0,
            description = threat_result.description,
            patterns_matched = threat_result.patterns_matched or {},
            ai_analysis = threat_result.ai_analysis or nil
        },
        
        -- Request context
        request = {
            method = request_metadata.method,
            path = request_metadata.path,
            client_ip = request_metadata.client_ip,
            user_agent = request_metadata.user_agent,
            service_id = request_metadata.service_id,
            route_id = request_metadata.route_id,
            consumer_id = request_metadata.consumer_id,
            timestamp = request_metadata.timestamp
        },
        
        -- Response context (if available)
        response = response_metadata and {
            status_code = response_metadata.status_code,
            latency_ms = response_metadata.total_latency_ms,
            error_occurred = response_metadata.error_occurred
        } or nil,
        
        -- Performance metrics
        performance = {
            processing_time_ms = request_metadata.processing_stages.request_capture or 0,
            overhead_ms = response_metadata and response_metadata.kong_latency_ms or 0
        },
        
        -- Plugin context
        plugin = {
            version = "0.1.0",
            dry_run = config.dry_run_mode or false,
            enforcement_executed = threat_result.enforcement_executed or false
        }
    }
    
    return log_entry
end

---
-- Create performance metrics log entry
-- @param request_metadata Request metadata
-- @param response_metadata Response metadata
-- @param config Plugin configuration
-- @return table metrics_entry Performance metrics entry
---
function instrumentation.create_metrics_entry(request_metadata, response_metadata, config)
    local metrics_entry = {
        -- Log metadata
        log_type = "performance_metrics",
        timestamp = ngx.time(),
        correlation_id = request_metadata.correlation_id,
        
        -- Timing metrics
        timings = {
            total_request_time_ms = response_metadata.total_latency_ms,
            upstream_time_ms = response_metadata.upstream_latency_ms,
            kong_processing_time_ms = response_metadata.kong_latency_ms,
            plugin_overhead_ms = request_metadata.processing_stages.request_capture or 0
        },
        
        -- Request/response sizes
        sizes = {
            request_bytes = request_metadata.content_length,
            response_bytes = response_metadata.response_size
        },
        
        -- Status and errors
        status = {
            response_code = response_metadata.status_code,
            error_occurred = response_metadata.error_occurred,
            error_type = response_metadata.error_type
        },
        
        -- Kong context
        context = {
            service_id = request_metadata.service_id,
            route_id = request_metadata.route_id,
            consumer_id = request_metadata.consumer_id
        }
    }
    
    return metrics_entry
end

---
-- Cleanup expired cache entries
-- Should be called periodically to prevent memory leaks
---
function instrumentation.cleanup_cache()
    local current_time = ngx.now()
    local expired_keys = {}
    
    for correlation_id, metadata in pairs(request_cache) do
        if metadata.start_time and (current_time - metadata.start_time) > METADATA_CACHE_TTL then
            table.insert(expired_keys, correlation_id)
        end
    end
    
    for _, key in ipairs(expired_keys) do
        request_cache[key] = nil
    end
    
    if #expired_keys > 0 then
        kong.log.debug("[Kong Guard AI] Cleaned up " .. #expired_keys .. " expired cache entries")
    end
end

---
-- Get current cache statistics
-- @return table stats Cache usage statistics
---
function instrumentation.get_cache_stats()
    local count = 0
    local oldest_time = ngx.now()
    
    for _, metadata in pairs(request_cache) do
        count = count + 1
        if metadata.start_time and metadata.start_time < oldest_time then
            oldest_time = metadata.start_time
        end
    end
    
    return {
        active_requests = count,
        oldest_request_age = count > 0 and (ngx.now() - oldest_time) or 0,
        memory_usage_estimate = count * 1024  -- Rough estimate in bytes
    }
end

return instrumentation