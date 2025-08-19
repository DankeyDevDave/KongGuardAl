-- Kong Guard AI - Threat Detection Module
-- Handles all threat detection logic including pattern matching, ML analysis, and anomaly detection
-- Designed for <10ms processing time under high load

local kong = kong
local json = require "cjson.safe"

local _M = {}

-- Worker-level detection state
local detection_cache = {}
local pattern_cache = {}
local learning_data = {}

-- Detection constants
local THREAT_LEVELS = {
    LOW = 3,
    MEDIUM = 5,
    HIGH = 7,
    CRITICAL = 9
}

local THREAT_TYPES = {
    SQL_INJECTION = "sql_injection",
    XSS = "cross_site_scripting", 
    RATE_LIMIT_VIOLATION = "rate_limit_violation",
    IP_REPUTATION = "ip_reputation",
    PAYLOAD_INJECTION = "payload_injection",
    ANOMALOUS_BEHAVIOR = "anomalous_behavior",
    CREDENTIAL_STUFFING = "credential_stuffing",
    DDoS = "distributed_denial_of_service",
    API_ABUSE = "api_abuse"
}

---
-- Initialize worker-level threat detection resources
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Detector] Initializing threat detection engine")
    
    -- Compile regex patterns for performance
    _M.compile_patterns(conf.suspicious_patterns)
    
    -- Initialize rate limiting cache
    detection_cache.rate_limits = {}
    detection_cache.ip_reputation = {}
    
    -- Initialize learning system if enabled
    if conf.enable_learning then
        learning_data.request_patterns = {}
        learning_data.response_patterns = {}
    end
    
    kong.log.info("[Kong Guard AI Detector] Detection engine initialized")
end

---
-- Compile regex patterns for optimal performance
-- @param patterns Array of regex pattern strings
---
function _M.compile_patterns(patterns)
    pattern_cache.compiled = {}
    for i, pattern in ipairs(patterns) do
        local compiled, err = ngx.re.compile(pattern, "ijo")
        if compiled then
            pattern_cache.compiled[i] = compiled
            kong.log.debug("[Kong Guard AI Detector] Compiled pattern: " .. pattern)
        else
            kong.log.error("[Kong Guard AI Detector] Failed to compile pattern: " .. pattern .. " Error: " .. (err or "unknown"))
        end
    end
end

---
-- Main threat analysis function
-- @param request_context Table containing request data
-- @param conf Plugin configuration
-- @return Table containing threat analysis results
---
function _M.analyze_request(request_context, conf)
    local threat_result = {
        threat_level = 0,
        threat_type = nil,
        confidence = 0,
        details = {},
        requires_ai_analysis = false,
        recommended_action = "allow"
    }
    
    -- 1. IP Reputation Analysis
    if conf.enable_ip_reputation then
        local ip_threat = _M.analyze_ip_reputation(request_context.client_ip, conf)
        _M.merge_threat_result(threat_result, ip_threat)
    end
    
    -- 2. Rate Limiting Analysis  
    if conf.enable_rate_limiting_detection then
        local rate_threat = _M.analyze_rate_limiting(request_context, conf)
        _M.merge_threat_result(threat_result, rate_threat)
    end
    
    -- 3. Payload Analysis
    if conf.enable_payload_analysis then
        local payload_threat = _M.analyze_payload(request_context, conf)
        _M.merge_threat_result(threat_result, payload_threat)
    end
    
    -- 4. Behavioral Analysis
    local behavior_threat = _M.analyze_behavior(request_context, conf)
    _M.merge_threat_result(threat_result, behavior_threat)
    
    -- 5. Determine if AI analysis is needed
    if threat_result.threat_level >= conf.ai_analysis_threshold then
        threat_result.requires_ai_analysis = true
    end
    
    -- 6. Set recommended action based on threat level
    threat_result.recommended_action = _M.determine_action(threat_result.threat_level, conf)
    
    return threat_result
end

---
-- Analyze IP reputation and blocklist status
-- @param client_ip Client IP address
-- @param conf Plugin configuration
-- @return Table containing IP threat analysis
---
function _M.analyze_ip_reputation(client_ip, conf)
    local threat_result = {
        threat_level = 0,
        threat_type = THREAT_TYPES.IP_REPUTATION,
        confidence = 0,
        details = { source_ip = client_ip }
    }
    
    -- Check whitelist first (override any other checks)
    for _, whitelisted_ip in ipairs(conf.ip_whitelist) do
        if _M.ip_matches_cidr(client_ip, whitelisted_ip) then
            kong.log.debug("[Kong Guard AI Detector] IP whitelisted: " .. client_ip)
            return threat_result -- Return with threat_level 0
        end
    end
    
    -- Check blacklist
    for _, blacklisted_ip in ipairs(conf.ip_blacklist) do
        if _M.ip_matches_cidr(client_ip, blacklisted_ip) then
            threat_result.threat_level = THREAT_LEVELS.CRITICAL
            threat_result.confidence = 1.0
            threat_result.details.blacklist_match = blacklisted_ip
            kong.log.warn("[Kong Guard AI Detector] Blacklisted IP detected: " .. client_ip)
            return threat_result
        end
    end
    
    -- Check reputation cache for repeat offenders
    local ip_history = detection_cache.ip_reputation[client_ip]
    if ip_history then
        local recent_violations = 0
        local current_time = ngx.time()
        
        -- Count violations in the last hour
        for _, violation_time in ipairs(ip_history.violations) do
            if current_time - violation_time < 3600 then
                recent_violations = recent_violations + 1
            end
        end
        
        if recent_violations >= 3 then
            threat_result.threat_level = THREAT_LEVELS.HIGH
            threat_result.confidence = 0.8
            threat_result.details.repeat_offender = true
            threat_result.details.recent_violations = recent_violations
        elseif recent_violations >= 1 then
            threat_result.threat_level = THREAT_LEVELS.MEDIUM
            threat_result.confidence = 0.6
            threat_result.details.recent_violations = recent_violations
        end
    end
    
    return threat_result
end

---
-- Analyze request rate patterns for DDoS and abuse
-- @param request_context Request context data
-- @param conf Plugin configuration
-- @return Table containing rate limiting threat analysis
---
function _M.analyze_rate_limiting(request_context, conf)
    local threat_result = {
        threat_level = 0,
        threat_type = THREAT_TYPES.RATE_LIMIT_VIOLATION,
        confidence = 0,
        details = {}
    }
    
    local current_time = ngx.time()
    local window_start = current_time - conf.rate_limit_window_seconds
    local client_ip = request_context.client_ip
    
    -- Initialize or update rate limit tracking
    if not detection_cache.rate_limits[client_ip] then
        detection_cache.rate_limits[client_ip] = {
            requests = {},
            first_seen = current_time
        }
    end
    
    local ip_data = detection_cache.rate_limits[client_ip]
    
    -- Add current request
    table.insert(ip_data.requests, current_time)
    
    -- Clean old requests outside window
    local valid_requests = {}
    for _, req_time in ipairs(ip_data.requests) do
        if req_time >= window_start then
            table.insert(valid_requests, req_time)
        end
    end
    ip_data.requests = valid_requests
    
    local request_count = #valid_requests
    threat_result.details.request_count = request_count
    threat_result.details.window_seconds = conf.rate_limit_window_seconds
    
    -- Evaluate threat level based on request count
    if request_count > conf.rate_limit_threshold * 3 then
        threat_result.threat_level = THREAT_LEVELS.CRITICAL
        threat_result.confidence = 0.9
        threat_result.threat_type = THREAT_TYPES.DDoS
    elseif request_count > conf.rate_limit_threshold * 2 then
        threat_result.threat_level = THREAT_LEVELS.HIGH
        threat_result.confidence = 0.8
    elseif request_count > conf.rate_limit_threshold then
        threat_result.threat_level = THREAT_LEVELS.MEDIUM
        threat_result.confidence = 0.7
    end
    
    return threat_result
end

---
-- Analyze request payload for injection attacks
-- @param request_context Request context data
-- @param conf Plugin configuration
-- @return Table containing payload threat analysis
---
function _M.analyze_payload(request_context, conf)
    local threat_result = {
        threat_level = 0,
        threat_type = THREAT_TYPES.PAYLOAD_INJECTION,
        confidence = 0,
        details = { patterns_matched = {} }
    }
    
    -- Get request body if available and within size limits
    local body = kong.request.get_raw_body()
    local query_string = kong.request.get_raw_query()
    
    -- Combine all text to analyze
    local text_to_analyze = {}
    
    if query_string then
        table.insert(text_to_analyze, query_string)
    end
    
    if body and #body <= conf.max_payload_size then
        table.insert(text_to_analyze, body)
    end
    
    -- Analyze headers for injection attempts
    for header_name, header_value in pairs(request_context.headers) do
        if type(header_value) == "string" then
            table.insert(text_to_analyze, header_value)
        end
    end
    
    -- Check all text against compiled patterns
    local total_matches = 0
    for _, text in ipairs(text_to_analyze) do
        for pattern_idx, compiled_pattern in pairs(pattern_cache.compiled) do
            local match = ngx.re.match(text, compiled_pattern, "ijo")
            if match then
                total_matches = total_matches + 1
                table.insert(threat_result.details.patterns_matched, {
                    pattern_index = pattern_idx,
                    match = match[0],
                    context = text:sub(1, 100) -- First 100 chars for context
                })
                
                -- Determine threat type based on pattern
                if match[0]:match("union.*select") or match[0]:match("drop.*table") then
                    threat_result.threat_type = THREAT_TYPES.SQL_INJECTION
                elseif match[0]:match("<script") or match[0]:match("javascript:") then
                    threat_result.threat_type = THREAT_TYPES.XSS
                end
            end
        end
    end
    
    -- Calculate threat level based on matches
    if total_matches >= 3 then
        threat_result.threat_level = THREAT_LEVELS.CRITICAL
        threat_result.confidence = 0.9
    elseif total_matches >= 2 then
        threat_result.threat_level = THREAT_LEVELS.HIGH
        threat_result.confidence = 0.8
    elseif total_matches >= 1 then
        threat_result.threat_level = THREAT_LEVELS.MEDIUM
        threat_result.confidence = 0.6
    end
    
    threat_result.details.total_matches = total_matches
    
    return threat_result
end

---
-- Analyze behavioral patterns for anomalies
-- @param request_context Request context data
-- @param conf Plugin configuration
-- @return Table containing behavioral threat analysis
---
function _M.analyze_behavior(request_context, conf)
    local threat_result = {
        threat_level = 0,
        threat_type = THREAT_TYPES.ANOMALOUS_BEHAVIOR,
        confidence = 0,
        details = {}
    }
    
    -- Check for suspicious user agent patterns
    local user_agent = request_context.headers["user-agent"]
    if user_agent then
        -- Check for bot-like behavior
        local bot_patterns = {
            "python-requests", "curl/", "wget/", "scrapy/", "bot", "crawler", "spider"
        }
        
        for _, pattern in ipairs(bot_patterns) do
            if user_agent:lower():find(pattern) then
                threat_result.threat_level = THREAT_LEVELS.LOW
                threat_result.confidence = 0.4
                threat_result.details.suspicious_user_agent = pattern
                break
            end
        end
        
        -- Check for empty or very short user agents
        if #user_agent < 10 then
            threat_result.threat_level = math.max(threat_result.threat_level, THREAT_LEVELS.LOW)
            threat_result.confidence = 0.3
            threat_result.details.short_user_agent = true
        end
    else
        -- Missing user agent is suspicious
        threat_result.threat_level = THREAT_LEVELS.LOW
        threat_result.confidence = 0.5
        threat_result.details.missing_user_agent = true
    end
    
    -- Check for unusual HTTP methods
    local method = request_context.method
    if method == "TRACE" or method == "CONNECT" or method == "DEBUG" then
        threat_result.threat_level = math.max(threat_result.threat_level, THREAT_LEVELS.MEDIUM)
        threat_result.confidence = 0.7
        threat_result.details.unusual_method = method
    end
    
    -- Check for path traversal attempts
    local path = request_context.path
    if path:find("%.%./") or path:find("%%2e%%2e%%2f") then
        threat_result.threat_level = THREAT_LEVELS.HIGH
        threat_result.confidence = 0.8
        threat_result.details.path_traversal = true
    end
    
    return threat_result
end

---
-- Analyze response headers for attack success indicators
-- @param headers Response headers
-- @param status_code HTTP status code
-- @param original_threat Original threat assessment
-- @param conf Plugin configuration
-- @return Table containing response analysis
---
function _M.analyze_response_headers(headers, status_code, original_threat, conf)
    local analysis = {
        suspicious = false,
        indicators = {}
    }
    
    -- Check for information disclosure in error responses
    if status_code >= 500 then
        for header_name, header_value in pairs(headers) do
            local lower_name = header_name:lower()
            
            -- Look for technology disclosure
            if lower_name == "server" or lower_name == "x-powered-by" then
                table.insert(analysis.indicators, "technology_disclosure")
            end
            
            -- Look for detailed error information
            if lower_name:find("error") or lower_name:find("exception") then
                table.insert(analysis.indicators, "detailed_error_info")
                analysis.suspicious = true
            end
        end
    end
    
    -- If original request was flagged as injection attack and we get a DB error,
    -- this might indicate successful exploitation
    if original_threat.threat_type == THREAT_TYPES.SQL_INJECTION and status_code == 500 then
        analysis.suspicious = true
        table.insert(analysis.indicators, "potential_sql_injection_success")
    end
    
    return analysis
end

---
-- Analyze response body for attack success patterns
-- @param body Response body
-- @param original_threat Original threat assessment  
-- @param conf Plugin configuration
-- @return Table containing body analysis
---
function _M.analyze_response_body(body, original_threat, conf)
    local analysis = {
        suspicious = false,
        indicators = {}
    }
    
    -- Look for database error messages
    local db_error_patterns = {
        "ORA-%d+", -- Oracle
        "MySQL.*Error", -- MySQL
        "PostgreSQL.*ERROR", -- PostgreSQL
        "Microsoft.*ODBC", -- SQL Server
        "SQLite.*error" -- SQLite
    }
    
    for _, pattern in ipairs(db_error_patterns) do
        if ngx.re.match(body, pattern, "ijo") then
            analysis.suspicious = true
            table.insert(analysis.indicators, "database_error")
            break
        end
    end
    
    -- Look for successful XSS execution indicators
    if original_threat.threat_type == THREAT_TYPES.XSS then
        if body:find("alert(") or body:find("prompt(") or body:find("confirm(") then
            analysis.suspicious = true
            table.insert(analysis.indicators, "potential_xss_success")
        end
    end
    
    return analysis
end

---
-- Merge AI analysis results with original threat assessment
-- @param original_threat Original threat result
-- @param ai_result AI analysis result
-- @return Table containing merged threat assessment
---
function _M.merge_ai_results(original_threat, ai_result)
    local merged = original_threat
    
    -- Use AI result if confidence is higher
    if ai_result.confidence > original_threat.confidence then
        merged.threat_level = math.max(original_threat.threat_level, ai_result.threat_level)
        merged.threat_type = ai_result.threat_type or original_threat.threat_type
        merged.confidence = ai_result.confidence
        merged.details.ai_analysis = ai_result
    end
    
    return merged
end

---
-- Learn from response patterns for adaptive detection
-- @param threat_result Threat assessment result
-- @param request_context Original request context
-- @param conf Plugin configuration
---
function _M.learn_from_response(threat_result, request_context, conf)
    if not conf.enable_learning then
        return
    end
    
    -- Sample learning data based on configured rate
    if math.random() > conf.learning_sample_rate then
        return
    end
    
    -- Store learning data (in production, this would go to a proper ML pipeline)
    local learning_entry = {
        timestamp = ngx.time(),
        threat_assessment = threat_result,
        request_features = {
            method = request_context.method,
            path_length = #request_context.path,
            header_count = 0,
            has_user_agent = request_context.headers["user-agent"] ~= nil,
            client_ip = request_context.client_ip
        },
        response_status = kong.response.get_status()
    }
    
    -- Count headers
    for _ in pairs(request_context.headers) do
        learning_entry.request_features.header_count = learning_entry.request_features.header_count + 1
    end
    
    table.insert(learning_data.request_patterns, learning_entry)
    
    kong.log.debug("[Kong Guard AI Detector] Learning data collected")
end

---
-- Clean up old cache entries to prevent memory leaks
-- @param conf Plugin configuration
---
function _M.cleanup_cache(conf)
    local current_time = ngx.time()
    local cleanup_threshold = current_time - 3600 -- Clean entries older than 1 hour
    
    -- Clean rate limiting cache
    for ip, data in pairs(detection_cache.rate_limits) do
        if data.first_seen < cleanup_threshold then
            detection_cache.rate_limits[ip] = nil
        end
    end
    
    -- Clean IP reputation cache
    for ip, data in pairs(detection_cache.ip_reputation) do
        local cleaned_violations = {}
        for _, violation_time in ipairs(data.violations) do
            if violation_time >= cleanup_threshold then
                table.insert(cleaned_violations, violation_time)
            end
        end
        
        if #cleaned_violations > 0 then
            data.violations = cleaned_violations
        else
            detection_cache.ip_reputation[ip] = nil
        end
    end
    
    kong.log.debug("[Kong Guard AI Detector] Cache cleanup completed")
end

---
-- Helper function to merge threat results
-- @param main_result Main threat result to merge into
-- @param additional_result Additional threat result to merge
---
function _M.merge_threat_result(main_result, additional_result)
    -- Use highest threat level
    if additional_result.threat_level > main_result.threat_level then
        main_result.threat_level = additional_result.threat_level
        main_result.threat_type = additional_result.threat_type
        main_result.confidence = additional_result.confidence
    end
    
    -- Merge details
    for key, value in pairs(additional_result.details) do
        main_result.details[key] = value
    end
end

---
-- Determine recommended action based on threat level
-- @param threat_level Numerical threat level (1-10)
-- @param conf Plugin configuration
-- @return String action recommendation
---
function _M.determine_action(threat_level, conf)
    if threat_level >= THREAT_LEVELS.CRITICAL then
        return "block"
    elseif threat_level >= THREAT_LEVELS.HIGH then
        return "rate_limit"
    elseif threat_level >= THREAT_LEVELS.MEDIUM then
        return "monitor"
    else
        return "allow"
    end
end

---
-- Check if IP matches CIDR block
-- @param ip IP address to check
-- @param cidr CIDR block or single IP
-- @return Boolean indicating match
---
function _M.ip_matches_cidr(ip, cidr)
    -- Simple implementation - in production, use proper CIDR matching library
    if cidr:find("/") then
        -- CIDR block matching would need proper implementation
        return false
    else
        -- Simple IP matching
        return ip == cidr
    end
end

return _M