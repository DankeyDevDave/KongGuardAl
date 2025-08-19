-- Kong Guard AI Structured Logger
-- Production-ready structured log emission with captured metadata
-- Designed for minimal latency impact and high-volume logging

local kong = kong
local cjson = require "cjson.safe"
local socket = require "socket"

local _M = {}

-- Log level constants and priorities
local LOG_LEVELS = {
    DEBUG = { level = 1, name = "DEBUG" },
    INFO = { level = 2, name = "INFO" },
    WARN = { level = 3, name = "WARN" },
    ERROR = { level = 4, name = "ERROR" },
    CRITICAL = { level = 5, name = "CRITICAL" }
}

-- Logger state and configuration
local logger_config = {
    enabled = true,
    min_log_level = LOG_LEVELS.INFO.level,
    include_request_id = true,
    include_performance_metrics = true,
    include_geolocation = false,
    async_logging = true,
    sampling_rate = 1.0,
    max_log_size = 32768, -- 32KB max per log entry
    destinations = {
        kong_log = true,
        file = false,
        syslog = false,
        external = false
    },
    external_endpoint = nil,
    external_timeout_ms = 1000,
    log_rotation = {
        enabled = false,
        max_size_mb = 100,
        max_files = 10
    }
}

-- Performance counters and session tracking
local session_counter = 0
local request_counter = 0
local log_queue = {}
local log_stats = {
    total_logs = 0,
    dropped_logs = 0,
    error_logs = 0,
    async_queue_size = 0
}

-- Cache for geolocation data and user agent parsing
local geo_cache = {}
local user_agent_cache = {}

---
-- Initialize structured logger
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Structured Logger] Initializing structured logging system")
    
    -- Configure logger from plugin configuration
    _M.configure_logger(conf)
    
    -- Initialize async logging queue if enabled
    if logger_config.async_logging then
        _M.init_async_logging()
    end
    
    -- Initialize external destinations
    if logger_config.destinations.external and conf.log_endpoint then
        _M.init_external_logging(conf.log_endpoint)
    end
    
    kong.log.info("[Kong Guard AI Structured Logger] Structured logging initialized")
end

---
-- Configure logger from plugin configuration
-- @param conf Plugin configuration
---
function _M.configure_logger(conf)
    if conf.log_level then
        logger_config.min_log_level = _M.parse_log_level(conf.log_level)
    end
    
    if conf.external_logging_enabled then
        logger_config.destinations.external = true
        logger_config.external_endpoint = conf.log_endpoint
    end
    
    -- Configure sampling rate based on load
    if conf.max_processing_time_ms and conf.max_processing_time_ms < 3 then
        logger_config.sampling_rate = 0.8 -- Reduce logging under high performance requirements
    end
    
    -- Enable geolocation if threat intelligence is available
    if conf.enable_ip_reputation then
        logger_config.include_geolocation = true
    end
    
    kong.log.debug("[Kong Guard AI Structured Logger] Logger configured", {
        min_level = logger_config.min_log_level,
        async = logger_config.async_logging,
        sampling_rate = logger_config.sampling_rate
    })
end

---
-- Parse log level string to numeric value
-- @param level_str Log level string
-- @return number Log level priority
---
function _M.parse_log_level(level_str)
    level_str = level_str:upper()
    for _, level_info in pairs(LOG_LEVELS) do
        if level_info.name == level_str then
            return level_info.level
        end
    end
    return LOG_LEVELS.INFO.level -- Default fallback
end

---
-- Initialize async logging subsystem
---
function _M.init_async_logging()
    -- Create background timer for processing log queue
    local ok, err = ngx.timer.every(0.1, _M.process_log_queue)
    if not ok then
        kong.log.error("[Kong Guard AI Structured Logger] Failed to create async timer: " .. tostring(err))
        logger_config.async_logging = false
    end
end

---
-- Initialize external logging connection
-- @param endpoint External logging endpoint URL
---
function _M.init_external_logging(endpoint)
    logger_config.external_endpoint = endpoint
    kong.log.info("[Kong Guard AI Structured Logger] External logging configured: " .. endpoint)
end

---
-- Create correlation ID for request tracking
-- @param request_context Request context data
-- @return string Correlation ID
---
function _M.create_correlation_id(request_context)
    request_counter = request_counter + 1
    local timestamp = ngx.now() * 1000 -- Milliseconds
    local service_id = request_context.service_id or "unknown"
    local short_service = service_id:sub(1, 8)
    
    return string.format("guard_ai_%s_%d_%d", short_service, timestamp, request_counter)
end

---
-- Create session ID for user tracking
-- @param client_ip Client IP address
-- @param user_agent User agent string
-- @return string Session ID
---
function _M.create_session_id(client_ip, user_agent)
    session_counter = session_counter + 1
    local hash_input = (client_ip or "unknown") .. "_" .. (user_agent or "unknown")
    local hash = ngx.crc32_long(hash_input)
    
    return string.format("session_%x_%d", hash, session_counter)
end

---
-- Enrich log data with geolocation information
-- @param client_ip Client IP address
-- @return table Geolocation data
---
function _M.enrich_geolocation(client_ip)
    if not logger_config.include_geolocation or not client_ip then
        return {}
    end
    
    -- Check cache first
    if geo_cache[client_ip] then
        return geo_cache[client_ip]
    end
    
    -- Simple geolocation enrichment (in production, integrate with GeoIP service)
    local geo_data = {
        country = "unknown",
        region = "unknown",
        city = "unknown",
        isp = "unknown",
        is_proxy = false,
        is_tor = false
    }
    
    -- Basic IP classification
    if client_ip:match("^10%.") or client_ip:match("^192%.168%.") or client_ip:match("^172%.1[6-9]%.") then
        geo_data.is_private = true
    elseif client_ip:match("^127%.") then
        geo_data.is_localhost = true
    end
    
    -- Cache geolocation data (with TTL in production)
    geo_cache[client_ip] = geo_data
    
    return geo_data
end

---
-- Parse and enrich user agent information
-- @param user_agent User agent string
-- @return table Parsed user agent data
---
function _M.enrich_user_agent(user_agent)
    if not user_agent then
        return { parsed = false }
    end
    
    -- Check cache first
    if user_agent_cache[user_agent] then
        return user_agent_cache[user_agent]
    end
    
    -- Simple user agent parsing (in production, use comprehensive library)
    local ua_data = {
        browser = "unknown",
        browser_version = "unknown",
        os = "unknown",
        os_version = "unknown",
        device_type = "unknown",
        is_bot = false,
        is_mobile = false,
        parsed = true
    }
    
    -- Basic bot detection
    local bot_patterns = {
        "bot", "crawler", "spider", "scraper", "python-requests", "curl/", "wget/"
    }
    
    local ua_lower = user_agent:lower()
    for _, pattern in ipairs(bot_patterns) do
        if ua_lower:find(pattern) then
            ua_data.is_bot = true
            ua_data.device_type = "bot"
            break
        end
    end
    
    -- Basic mobile detection
    if ua_lower:find("mobile") or ua_lower:find("android") or ua_lower:find("iphone") then
        ua_data.is_mobile = true
        ua_data.device_type = "mobile"
    end
    
    -- Basic browser detection
    if ua_lower:find("chrome/") then
        ua_data.browser = "Chrome"
    elseif ua_lower:find("firefox/") then
        ua_data.browser = "Firefox"
    elseif ua_lower:find("safari/") then
        ua_data.browser = "Safari"
    elseif ua_lower:find("edge/") then
        ua_data.browser = "Edge"
    end
    
    -- Cache user agent data (with size limit in production)
    user_agent_cache[user_agent] = ua_data
    
    return ua_data
end

---
-- Create comprehensive log entry with all metadata
-- @param level Log level
-- @param message Log message
-- @param threat_result Threat detection result
-- @param request_context Request context
-- @param response_context Response context (optional)
-- @param conf Plugin configuration
-- @return table Structured log entry
---
function _M.create_log_entry(level, message, threat_result, request_context, response_context, conf)
    local timestamp = ngx.now()
    local correlation_id = _M.create_correlation_id(request_context)
    local session_id = _M.create_session_id(request_context.client_ip, request_context.headers["user-agent"])
    
    -- Base log structure
    local log_entry = {
        -- Core fields
        timestamp = timestamp,
        timestamp_iso = os.date("!%Y-%m-%dT%H:%M:%S.000Z", timestamp),
        level = level.name,
        level_num = level.level,
        message = message,
        source = "kong-guard-ai",
        version = "0.1.0",
        
        -- Correlation and tracking
        correlation_id = correlation_id,
        session_id = session_id,
        request_id = ngx.var.request_id,
        
        -- Request information
        request = {
            method = request_context.method,
            path = request_context.path,
            query_string = kong.request.get_raw_query(),
            client_ip = request_context.client_ip,
            user_agent = request_context.headers["user-agent"],
            referer = request_context.headers["referer"],
            content_type = request_context.headers["content-type"],
            content_length = request_context.headers["content-length"],
            header_count = 0
        },
        
        -- Kong context
        kong = {
            service_id = request_context.service_id,
            route_id = request_context.route_id,
            consumer_id = request_context.consumer_id,
            worker_pid = ngx.worker.pid(),
            node_id = kong.node.get_id()
        },
        
        -- Configuration context
        config = {
            dry_run_mode = conf.dry_run_mode,
            threat_threshold = conf.threat_threshold,
            plugin_enabled = true
        }
    }
    
    -- Count request headers
    for _ in pairs(request_context.headers) do
        log_entry.request.header_count = log_entry.request.header_count + 1
    end
    
    -- Add threat information if available
    if threat_result then
        log_entry.threat = {
            detected = threat_result.threat_level > 0,
            level = threat_result.threat_level,
            type = threat_result.threat_type,
            confidence = threat_result.confidence,
            recommended_action = threat_result.recommended_action,
            requires_ai_analysis = threat_result.requires_ai_analysis,
            details = threat_result.details
        }
        
        -- Add response analysis if available
        if threat_result.response_analysis then
            log_entry.threat.response_analysis = threat_result.response_analysis
        end
    end
    
    -- Add response information if available
    if response_context then
        log_entry.response = {
            status = response_context.status,
            headers = response_context.headers,
            body_size = response_context.body_size,
            processing_time_ms = response_context.processing_time_ms
        }
    end
    
    -- Add performance metrics
    if logger_config.include_performance_metrics then
        log_entry.performance = {
            processing_time_ms = kong.ctx.plugin.guard_ai_processing_time or 0,
            memory_usage_kb = math.floor(collectgarbage("count")),
            request_count = request_counter,
            log_queue_size = #log_queue
        }
    end
    
    -- Add geolocation enrichment
    if logger_config.include_geolocation then
        log_entry.geolocation = _M.enrich_geolocation(request_context.client_ip)
    end
    
    -- Add user agent enrichment
    if request_context.headers["user-agent"] then
        log_entry.user_agent_parsed = _M.enrich_user_agent(request_context.headers["user-agent"])
    end
    
    -- Add threat intelligence hooks (placeholder for integration)
    log_entry.threat_intelligence = {
        ip_reputation_score = 0, -- Placeholder for external threat intel
        domain_reputation_score = 0,
        asn_reputation_score = 0,
        threat_feeds_checked = false
    }
    
    return log_entry
end

---
-- Log structured entry with specified level
-- @param level Log level
-- @param message Log message
-- @param threat_result Threat detection result
-- @param request_context Request context
-- @param response_context Response context (optional)
-- @param conf Plugin configuration
---
function _M.log(level, message, threat_result, request_context, response_context, conf)
    -- Check if logging is enabled and level meets threshold
    if not logger_config.enabled or level.level < logger_config.min_log_level then
        return
    end
    
    -- Apply sampling rate for high-volume scenarios
    if math.random() > logger_config.sampling_rate then
        log_stats.dropped_logs = log_stats.dropped_logs + 1
        return
    end
    
    -- Create structured log entry
    local log_entry = _M.create_log_entry(level, message, threat_result, request_context, response_context, conf)
    
    -- Serialize to JSON
    local json_log, err = cjson.encode(log_entry)
    if not json_log then
        kong.log.error("[Kong Guard AI Structured Logger] Failed to encode log entry: " .. tostring(err))
        log_stats.error_logs = log_stats.error_logs + 1
        return
    end
    
    -- Check log size limits
    if #json_log > logger_config.max_log_size then
        kong.log.warn("[Kong Guard AI Structured Logger] Log entry too large, truncating")
        log_entry.message = log_entry.message:sub(1, 1000) .. "... [TRUNCATED]"
        log_entry.truncated = true
        json_log = cjson.encode(log_entry)
    end
    
    log_stats.total_logs = log_stats.total_logs + 1
    
    -- Route to configured destinations
    if logger_config.async_logging then
        _M.queue_log_async(json_log, level)
    else
        _M.emit_log_sync(json_log, level)
    end
end

---
-- Queue log for async processing
-- @param json_log JSON log string
-- @param level Log level
---
function _M.queue_log_async(json_log, level)
    table.insert(log_queue, {
        json = json_log,
        level = level,
        timestamp = ngx.now()
    })
    
    log_stats.async_queue_size = #log_queue
    
    -- Prevent queue from growing too large
    if #log_queue > 1000 then
        table.remove(log_queue, 1) -- Remove oldest
        log_stats.dropped_logs = log_stats.dropped_logs + 1
    end
end

---
-- Emit log synchronously to all destinations
-- @param json_log JSON log string
-- @param level Log level
---
function _M.emit_log_sync(json_log, level)
    -- Kong native logging
    if logger_config.destinations.kong_log then
        local kong_level = level.name:lower()
        if kong_level == "critical" then
            kong_level = "crit"
        end
        kong.log[kong_level]("[STRUCTURED] " .. json_log)
    end
    
    -- External endpoint logging
    if logger_config.destinations.external and logger_config.external_endpoint then
        _M.send_to_external_endpoint(json_log)
    end
    
    -- File logging (if configured)
    if logger_config.destinations.file then
        _M.write_to_file(json_log)
    end
    
    -- Syslog (if configured)
    if logger_config.destinations.syslog then
        _M.send_to_syslog(json_log, level)
    end
end

---
-- Process async log queue (called by timer)
-- @param premature Timer premature flag
---
function _M.process_log_queue(premature)
    if premature then
        return
    end
    
    local batch_size = math.min(50, #log_queue) -- Process up to 50 logs per batch
    
    for i = 1, batch_size do
        local log_item = table.remove(log_queue, 1)
        if log_item then
            _M.emit_log_sync(log_item.json, log_item.level)
        end
    end
    
    log_stats.async_queue_size = #log_queue
end

---
-- Send log to external endpoint
-- @param json_log JSON log string
---
function _M.send_to_external_endpoint(json_log)
    if not logger_config.external_endpoint then
        return
    end
    
    local httpc = require "resty.http"
    local client = httpc.new()
    client:set_timeout(logger_config.external_timeout_ms)
    
    local res, err = client:request_uri(logger_config.external_endpoint, {
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["User-Agent"] = "Kong-Guard-AI-Logger/0.1.0"
        },
        body = json_log
    })
    
    if not res then
        kong.log.error("[Kong Guard AI Structured Logger] External logging failed: " .. tostring(err))
        log_stats.error_logs = log_stats.error_logs + 1
    elseif res.status >= 400 then
        kong.log.warn("[Kong Guard AI Structured Logger] External logging error: " .. res.status)
    end
end

---
-- Write log to file (placeholder for file rotation)
-- @param json_log JSON log string
---
function _M.write_to_file(json_log)
    -- File logging implementation would go here
    -- Include proper file rotation and error handling
    kong.log.debug("[Kong Guard AI Structured Logger] File logging not implemented")
end

---
-- Send log to syslog
-- @param json_log JSON log string
-- @param level Log level
---
function _M.send_to_syslog(json_log, level)
    -- Syslog integration implementation would go here
    kong.log.debug("[Kong Guard AI Structured Logger] Syslog logging not implemented")
end

---
-- Convenience functions for different log levels
---
function _M.debug(message, threat_result, request_context, response_context, conf)
    _M.log(LOG_LEVELS.DEBUG, message, threat_result, request_context, response_context, conf)
end

function _M.info(message, threat_result, request_context, response_context, conf)
    _M.log(LOG_LEVELS.INFO, message, threat_result, request_context, response_context, conf)
end

function _M.warn(message, threat_result, request_context, response_context, conf)
    _M.log(LOG_LEVELS.WARN, message, threat_result, request_context, response_context, conf)
end

function _M.error(message, threat_result, request_context, response_context, conf)
    _M.log(LOG_LEVELS.ERROR, message, threat_result, request_context, response_context, conf)
end

function _M.critical(message, threat_result, request_context, response_context, conf)
    _M.log(LOG_LEVELS.CRITICAL, message, threat_result, request_context, response_context, conf)
end

---
-- Log threat detection event
-- @param threat_result Threat detection result
-- @param request_context Request context
-- @param enforcement_result Enforcement result
-- @param conf Plugin configuration
---
function _M.log_threat_event(threat_result, request_context, enforcement_result, conf)
    local level = LOG_LEVELS.WARN
    if threat_result.threat_level >= 9 then
        level = LOG_LEVELS.CRITICAL
    elseif threat_result.threat_level >= 7 then
        level = LOG_LEVELS.ERROR
    end
    
    local message = string.format("Threat detected: %s (level: %.1f, confidence: %.2f)",
        threat_result.threat_type or "unknown",
        threat_result.threat_level,
        threat_result.confidence or 0)
    
    local response_context = {
        status = kong.response.get_status(),
        processing_time_ms = kong.ctx.plugin.guard_ai_processing_time or 0
    }
    
    -- Add enforcement information to threat result
    if enforcement_result then
        threat_result.enforcement = {
            action_taken = enforcement_result.action_type,
            executed = enforcement_result.executed,
            simulated = enforcement_result.simulated,
            dry_run = conf.dry_run_mode
        }
    end
    
    _M.log(level, message, threat_result, request_context, response_context, conf)
end

---
-- Log performance metrics
-- @param processing_time_ms Processing time in milliseconds
-- @param request_context Request context
-- @param conf Plugin configuration
---
function _M.log_performance_metrics(processing_time_ms, request_context, conf)
    if processing_time_ms <= 2 then
        return -- Skip logging for very fast requests
    end
    
    local level = LOG_LEVELS.DEBUG
    if processing_time_ms > 10 then
        level = LOG_LEVELS.WARN
    elseif processing_time_ms > 5 then
        level = LOG_LEVELS.INFO
    end
    
    local message = string.format("Request processing completed in %.2fms", processing_time_ms)
    
    local response_context = {
        status = kong.response.get_status(),
        processing_time_ms = processing_time_ms
    }
    
    _M.log(level, message, nil, request_context, response_context, conf)
end

---
-- Get logging statistics
-- @return table Logging statistics
---
function _M.get_stats()
    return {
        total_logs = log_stats.total_logs,
        dropped_logs = log_stats.dropped_logs,
        error_logs = log_stats.error_logs,
        async_queue_size = log_stats.async_queue_size,
        cache_sizes = {
            geo_cache = 0, -- Would implement cache size tracking
            user_agent_cache = 0
        },
        config = logger_config
    }
end

---
-- Health check for logging system
-- @return table Health status
---
function _M.health_check()
    local health = {
        status = "healthy",
        issues = {}
    }
    
    -- Check queue size
    if log_stats.async_queue_size > 500 then
        health.status = "warning"
        table.insert(health.issues, "Log queue size high: " .. log_stats.async_queue_size)
    end
    
    -- Check error rate
    local error_rate = log_stats.error_logs / math.max(log_stats.total_logs, 1)
    if error_rate > 0.1 then
        health.status = "unhealthy"
        table.insert(health.issues, "High error rate: " .. (error_rate * 100) .. "%")
    end
    
    return health
end

---
-- Cleanup resources and caches
---
function _M.cleanup()
    -- Cleanup caches to prevent memory leaks
    local current_time = ngx.time()
    
    -- Clear old geo cache entries (1 hour TTL)
    for ip, data in pairs(geo_cache) do
        if not data.timestamp or current_time - data.timestamp > 3600 then
            geo_cache[ip] = nil
        end
    end
    
    -- Limit user agent cache size
    local ua_count = 0
    for _ in pairs(user_agent_cache) do
        ua_count = ua_count + 1
    end
    
    if ua_count > 1000 then
        user_agent_cache = {} -- Simple cache reset
    end
    
    kong.log.debug("[Kong Guard AI Structured Logger] Cache cleanup completed")
end

return _M