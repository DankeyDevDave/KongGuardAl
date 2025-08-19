-- Kong Guard AI - Custom Log Format Module
-- Structured JSON logging for access and log phases with optimized performance
-- Captures request/response metadata for threat analysis and instrumentation
-- Compatible with ELK Stack, Splunk, and other structured logging systems

local kong = kong
local json = require "cjson.safe"
local ngx = ngx

local _M = {}

-- Log level constants aligned with schema configuration
local LOG_LEVELS = {
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4
}

-- Log level names for output
local LOG_LEVEL_NAMES = {
    [LOG_LEVELS.DEBUG] = "DEBUG",
    [LOG_LEVELS.INFO] = "INFO", 
    [LOG_LEVELS.WARN] = "WARN",
    [LOG_LEVELS.ERROR] = "ERROR"
}

-- Default header selection for structured logging (security-focused subset)
local DEFAULT_LOG_HEADERS = {
    "user-agent",
    "authorization",
    "content-type",
    "content-length", 
    "x-forwarded-for",
    "x-real-ip",
    "x-forwarded-proto",
    "referer",
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "host"
}

-- Performance optimization: pre-compiled header lookup table
local header_lookup = {}
for _, header in ipairs(DEFAULT_LOG_HEADERS) do
    header_lookup[header] = true
end

---
-- Initialize log format module
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Log Format] Initializing structured logging")
    
    -- Configure log level from schema
    _M.current_log_level = _M.parse_log_level(conf.log_level or "info")
    
    kong.log.info("[Kong Guard AI Log Format] Structured logging initialized at level: " .. 
                  LOG_LEVEL_NAMES[_M.current_log_level])
end

---
-- Parse log level string to numeric value
-- @param level_str String log level from configuration
-- @return Numeric log level
---
function _M.parse_log_level(level_str)
    local level_map = {
        debug = LOG_LEVELS.DEBUG,
        info = LOG_LEVELS.INFO,
        warn = LOG_LEVELS.WARN,
        error = LOG_LEVELS.ERROR
    }
    
    return level_map[string.lower(level_str)] or LOG_LEVELS.INFO
end

---
-- Get real client IP with X-Forwarded-For and X-Real-IP detection
-- Handles proxy chains and CDN scenarios
-- @return String containing real client IP
---
function _M.get_real_client_ip()
    -- Priority order: X-Real-IP, X-Forwarded-For (first IP), remote_addr
    local headers = kong.request.get_headers()
    
    -- Check X-Real-IP first (most reliable for single proxy)
    local real_ip = headers["x-real-ip"]
    if real_ip and real_ip ~= "" then
        return real_ip
    end
    
    -- Parse X-Forwarded-For (comma-separated list, first is original client)
    local forwarded_for = headers["x-forwarded-for"]
    if forwarded_for and forwarded_for ~= "" then
        -- Extract first IP from comma-separated list
        local first_ip = string.match(forwarded_for, "([^,]+)")
        if first_ip then
            -- Trim whitespace
            first_ip = string.gsub(first_ip, "^%s*(.-)%s*$", "%1")
            if first_ip ~= "" then
                return first_ip
            end
        end
    end
    
    -- Fallback to Kong's direct client IP detection
    return kong.client.get_ip()
end

---
-- Extract selected headers for logging (security and performance optimized)
-- Only captures essential headers to minimize log size and exposure
-- @param headers_table Table of request headers
-- @return Table containing filtered headers
---
function _M.extract_selected_headers(headers_table)
    local selected_headers = {}
    
    for header_name, header_value in pairs(headers_table) do
        local lower_name = string.lower(header_name)
        if header_lookup[lower_name] then
            -- Special handling for Authorization header (security)
            if lower_name == "authorization" then
                local auth_type = string.match(header_value, "^(%w+)")
                selected_headers[lower_name] = auth_type and (auth_type .. " [REDACTED]") or "[REDACTED]"
            else
                -- Truncate very long header values to prevent log bloat
                if #header_value > 512 then
                    selected_headers[lower_name] = string.sub(header_value, 1, 509) .. "..."
                else
                    selected_headers[lower_name] = header_value
                end
            end
        end
    end
    
    return selected_headers
end

---
-- Generate structured access log entry for request initiation
-- Called during access phase to capture request metadata
-- @param conf Plugin configuration
-- @return Table containing structured access log data
---
function _M.create_access_log_entry(conf)
    local request_start_time = kong.ctx.plugin.guard_ai_request_start_time or ngx.now()
    local headers = kong.request.get_headers()
    
    local log_entry = {
        -- Timestamp and correlation
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),
        request_id = ngx.var.request_id or kong.log.serialize().request.id,
        kong_request_id = kong.log.serialize().request.id,
        
        -- Request identification
        client_ip = _M.get_real_client_ip(),
        method = kong.request.get_method(),
        path = kong.request.get_path(),
        raw_query_string = kong.request.get_raw_query(),
        scheme = kong.request.get_scheme(),
        
        -- Headers subset (security filtered)
        headers = _M.extract_selected_headers(headers),
        
        -- Kong context
        service_id = kong.router.get_service() and kong.router.get_service().id,
        service_name = kong.router.get_service() and kong.router.get_service().name,
        route_id = kong.router.get_route() and kong.router.get_route().id,
        route_name = kong.router.get_route() and kong.router.get_route().name,
        consumer_id = kong.client.get_consumer() and kong.client.get_consumer().id,
        consumer_username = kong.client.get_consumer() and kong.client.get_consumer().username,
        
        -- Request details
        request_size = tonumber(headers["content-length"]) or 0,
        request_start_time = request_start_time,
        
        -- Kong Guard AI context
        guard_ai_version = "0.1.0",
        dry_run_mode = conf.dry_run_mode,
        log_type = "access",
        
        -- Performance tracking
        processing_phase = "access"
    }
    
    return log_entry
end

---
-- Generate structured log entry for response completion
-- Called during log phase to capture response metadata and latency
-- @param conf Plugin configuration
-- @param processing_time_ms Processing time in milliseconds
-- @return Table containing structured response log data
---
function _M.create_response_log_entry(conf, processing_time_ms)
    local request_start_time = kong.ctx.plugin.guard_ai_request_start_time or ngx.now()
    local request_time = ngx.now() - request_start_time
    local response_headers = kong.response.get_headers()
    
    local log_entry = {
        -- Timestamp and correlation
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),
        request_id = ngx.var.request_id or kong.log.serialize().request.id,
        kong_request_id = kong.log.serialize().request.id,
        
        -- Request identification (for correlation)
        client_ip = _M.get_real_client_ip(),
        method = kong.request.get_method(),
        path = kong.request.get_path(),
        
        -- Response details
        status = kong.response.get_status(),
        response_size = tonumber(response_headers["content-length"]) or 0,
        response_headers = _M.extract_response_headers(response_headers),
        
        -- Kong context
        service_id = kong.router.get_service() and kong.router.get_service().id,
        service_name = kong.router.get_service() and kong.router.get_service().name,
        route_id = kong.router.get_route() and kong.router.get_route().id,
        route_name = kong.router.get_route() and kong.router.get_route().name,
        consumer_id = kong.client.get_consumer() and kong.client.get_consumer().id,
        consumer_username = kong.client.get_consumer() and kong.client.get_consumer().username,
        
        -- Latency and performance metrics
        latency = {
            request = math.floor(request_time * 1000), -- Total request time in ms
            kong = math.floor((kong.ctx.plugin.guard_ai_processing_time or 0)), -- Kong processing time
            upstream = kong.ctx.balancer and kong.ctx.balancer.get_last_latency() or 0,
            guard_ai_processing = processing_time_ms or 0
        },
        
        -- Kong Guard AI context
        guard_ai_version = "0.1.0",
        dry_run_mode = conf.dry_run_mode,
        log_type = "response",
        
        -- Performance tracking
        processing_phase = "log"
    }
    
    return log_entry
end

---
-- Extract selected response headers for logging
-- @param response_headers Table of response headers
-- @return Table containing filtered response headers
---
function _M.extract_response_headers(response_headers)
    local selected = {}
    
    -- Response headers of interest for security analysis
    local response_header_whitelist = {
        "content-type",
        "content-length",
        "server",
        "x-powered-by",
        "set-cookie", -- Important for session analysis
        "location",   -- For redirect analysis
        "cache-control",
        "expires",
        "etag",
        "last-modified"
    }
    
    for _, header_name in ipairs(response_header_whitelist) do
        local header_value = response_headers[header_name]
        if header_value then
            -- Special handling for Set-Cookie (security)
            if header_name == "set-cookie" then
                -- Only log cookie names, not values for security
                if type(header_value) == "table" then
                    local cookie_names = {}
                    for _, cookie in ipairs(header_value) do
                        local name = string.match(cookie, "^([^=]+)")
                        if name then
                            table.insert(cookie_names, name)
                        end
                    end
                    selected[header_name] = cookie_names
                else
                    local name = string.match(header_value, "^([^=]+)")
                    selected[header_name] = name or "[COOKIE]"
                end
            else
                selected[header_name] = header_value
            end
        end
    end
    
    return selected
end

---
-- Create threat incident log entry with detailed context
-- Called when threats are detected for comprehensive incident logging
-- @param threat_result Threat detection result
-- @param request_context Request context data
-- @param response_action Response action taken
-- @param conf Plugin configuration
-- @return Table containing structured threat incident log
---
function _M.create_threat_incident_log(threat_result, request_context, response_action, conf)
    local log_entry = {
        -- Timestamp and correlation
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),
        request_id = ngx.var.request_id or kong.log.serialize().request.id,
        kong_request_id = kong.log.serialize().request.id,
        
        -- Incident classification
        incident_id = "guard_ai_" .. ngx.time() .. "_" .. string.sub(ngx.var.request_id or "", 1, 8),
        incident_type = "threat_detected",
        severity = _M.map_threat_level_to_severity(threat_result.threat_level),
        
        -- Threat details
        threat = {
            type = threat_result.threat_type,
            level = threat_result.threat_level,
            confidence = threat_result.confidence or 1.0,
            details = threat_result.details,
            patterns_matched = threat_result.patterns_matched,
            risk_score = threat_result.risk_score
        },
        
        -- Request context
        request = {
            client_ip = request_context.client_ip,
            method = request_context.method,
            path = request_context.path,
            headers = _M.extract_selected_headers(request_context.headers or {}),
            query_params = request_context.query,
            user_agent = request_context.headers and request_context.headers["user-agent"]
        },
        
        -- Response action
        response_action = {
            action_type = response_action.action_type,
            executed = response_action.executed,
            simulated = response_action.simulated,
            success = response_action.success,
            details = response_action.details,
            execution_time_ms = response_action.execution_time_ms
        },
        
        -- Kong context
        kong_context = {
            service_id = request_context.service_id,
            route_id = request_context.route_id,
            consumer_id = request_context.consumer_id,
            node_id = kong.node.get_id()
        },
        
        -- Kong Guard AI metadata
        guard_ai = {
            version = "0.1.0",
            dry_run_mode = conf.dry_run_mode,
            processing_time_ms = kong.ctx.plugin.guard_ai_processing_time or 0,
            detection_engine = threat_result.detection_engine or "static_rules"
        },
        
        -- Log metadata
        log_type = "threat_incident",
        log_level = "WARN"
    }
    
    return log_entry
end

---
-- Emit structured log entry with appropriate log level
-- @param log_entry Table containing log data
-- @param level Optional log level (defaults to INFO)
---
function _M.emit_structured_log(log_entry, level)
    level = level or LOG_LEVELS.INFO
    
    -- Only emit if meets current log level threshold
    if level < _M.current_log_level then
        return
    end
    
    -- Add log level to entry
    log_entry.log_level = LOG_LEVEL_NAMES[level]
    
    -- Serialize to JSON with error handling
    local json_log, err = json.encode(log_entry)
    if not json_log then
        kong.log.error("[Kong Guard AI Log Format] Failed to encode log entry: " .. (err or "unknown error"))
        return
    end
    
    -- Emit via appropriate Kong log level
    if level == LOG_LEVELS.ERROR then
        kong.log.err("[KONG_GUARD_AI_STRUCTURED] " .. json_log)
    elseif level == LOG_LEVELS.WARN then
        kong.log.warn("[KONG_GUARD_AI_STRUCTURED] " .. json_log)
    elseif level == LOG_LEVELS.DEBUG then
        kong.log.debug("[KONG_GUARD_AI_STRUCTURED] " .. json_log)
    else
        kong.log.info("[KONG_GUARD_AI_STRUCTURED] " .. json_log)
    end
end

---
-- Map threat level to severity string for incident classification
-- @param threat_level Numerical threat level (1-10)
-- @return String severity level
---
function _M.map_threat_level_to_severity(threat_level)
    if threat_level >= 9 then
        return "critical"
    elseif threat_level >= 7 then
        return "high"
    elseif threat_level >= 5 then
        return "medium"
    elseif threat_level >= 3 then
        return "low"
    else
        return "info"
    end
end

---
-- Create performance metrics log entry
-- @param metrics Table containing performance metrics
-- @param conf Plugin configuration
-- @return Table containing structured metrics log
---
function _M.create_metrics_log_entry(metrics, conf)
    local log_entry = {
        -- Timestamp
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),
        
        -- Metrics data
        metrics = metrics,
        
        -- Kong context
        kong_node_id = kong.node.get_id(),
        
        -- Kong Guard AI metadata
        guard_ai_version = "0.1.0",
        dry_run_mode = conf.dry_run_mode,
        
        -- Log metadata
        log_type = "performance_metrics",
        log_level = "INFO"
    }
    
    return log_entry
end

---
-- Validate log entry structure for debugging
-- @param log_entry Log entry to validate
-- @return Boolean indicating if valid
---
function _M.validate_log_entry(log_entry)
    local required_fields = {"timestamp", "log_type", "request_id"}
    
    for _, field in ipairs(required_fields) do
        if not log_entry[field] then
            kong.log.warn("[Kong Guard AI Log Format] Missing required field: " .. field)
            return false
        end
    end
    
    return true
end

---
-- Get log format configuration summary
-- @param conf Plugin configuration
-- @return Table containing log format info
---
function _M.get_log_format_info(conf)
    return {
        version = "0.1.0",
        current_log_level = LOG_LEVEL_NAMES[_M.current_log_level or LOG_LEVELS.INFO],
        structured_logging = true,
        header_filtering = true,
        security_redaction = true,
        performance_optimized = true,
        supported_systems = {"ELK Stack", "Splunk", "Datadog", "CloudWatch", "Fluentd"},
        log_types = {"access", "response", "threat_incident", "performance_metrics"}
    }
end

return _M