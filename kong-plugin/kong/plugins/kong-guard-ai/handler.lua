local cjson = require "cjson"
local http = require "resty.http"
local AIEngine = require "kong.plugins.kong-guard-ai.ai_engine"

local KongGuardAIHandler = {
    VERSION = "2.0.0",  -- Enterprise AI version
    PRIORITY = 2000
}

-- AI Engine instance (initialized in init_worker)
local ai_engine = nil

-- Log level constants
local LOG_LEVELS = {
    debug = 0,
    info = 1,
    warn = 2,
    error = 3,
    critical = 4
}

-- Helper function to check if logging is enabled for a level
local function should_log(config_level, msg_level)
    return LOG_LEVELS[msg_level] >= LOG_LEVELS[config_level]
end

-- Helper function for structured logging with level checks
local function log_message(config, level, message, data)
    if should_log(config.log_level, level) then
        if level == "debug" then
            kong.log.debug(message, data)
        elseif level == "info" then
            kong.log.info(message, data)
        elseif level == "warn" then
            kong.log.warn(message, data)
        elseif level == "error" then
            kong.log.err(message, data)
        elseif level == "critical" then
            kong.log.crit(message, data)
        end
    end
end

-- init_worker phase: Initialize AI engine and caches
function KongGuardAIHandler:init_worker()
    -- Initialize shared memory for threat tracking
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:set("threat_counter", 0)
        kong_cache:set("false_positive_rate", 0)
        kong_cache:set("total_requests", 0)
        kong_cache:set("ai_requests", 0)
        kong_cache:set("ai_blocks", 0)
    end
    
    kong.log.info("Kong Guard AI Enterprise v2.0: Worker initialized with AI capabilities")
end

-- access phase: Monitor and analyze incoming requests
function KongGuardAIHandler:access(config)
    
    -- Check whitelist first (early exit for performance)
    local client_ip = kong.client.get_forwarded_ip() or kong.client.get_ip()
    if config.whitelist_ips and self:is_whitelisted(client_ip, config.whitelist_ips) then
        return
    end
    
    -- Check if already blocked (performance optimization)
    if self:is_blocked(client_ip) then
        return kong.response.exit(403, {
            message = "Request blocked - IP temporarily banned",
            incident_id = self:generate_incident_id()
        })
    end
    
    local path = kong.request.get_path()
    local method = kong.request.get_method()
    local headers = kong.request.get_headers()
    
    -- Extract features for threat detection
    local features = self:extract_features(kong.request, client_ip)
    
    -- Perform comprehensive threat detection
    local threat_score, threat_type, threat_details = self:detect_threat(features, config)
    
    -- Store context for later phases
    kong.ctx.plugin.threat_data = {
        score = threat_score,
        type = threat_type,
        details = threat_details,
        features = features,
        timestamp = ngx.now(),
        client_ip = client_ip,
        path = path,
        method = method
    }
    
    -- Log request if enabled
    if config.log_requests and should_log(config.log_level, "debug") then
        log_message(config, "debug", "Request analyzed", {
            client_ip = client_ip,
            path = path,
            method = method,
            threat_score = threat_score
        })
    end
    
    -- Take graduated response based on threat level
    if threat_score > config.block_threshold then
        -- Block request
        if not config.dry_run then
            log_message(config, "warn", "Blocking high-threat request", {
                threat_type = threat_type,
                client_ip = client_ip,
                threat_score = threat_score,
                details = threat_details
            })
            
            self:block_request(threat_type, client_ip)
            
            return kong.response.exit(403, {
                message = "Request blocked by Kong Guard AI",
                threat_type = threat_type,
                incident_id = self:generate_incident_id()
            })
        else
            log_message(config, "info", "Would block request (dry-run mode)", {
                threat_type = threat_type,
                threat_score = threat_score
            })
        end
        
    elseif threat_score > config.rate_limit_threshold then
        -- Apply rate limiting
        if not config.dry_run then
            local is_rate_limited = self:apply_rate_limit(client_ip, config)
            
            if is_rate_limited then
                log_message(config, "info", "Rate limiting applied", {
                    client_ip = client_ip,
                    threat_score = threat_score
                })
                
                return kong.response.exit(429, {
                    message = "Rate limit exceeded",
                    retry_after = "60"
                })
            end
        else
            log_message(config, "debug", "Would rate-limit (dry-run mode)", {
                client_ip = client_ip,
                threat_score = threat_score
            })
        end
    end
    
    -- Track metrics
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:incr("total_requests", 1, 0)
        if threat_score > 0 then
            kong_cache:incr("threats_detected", 1, 0)
        end
    end
end

-- log phase: Log results and send notifications
function KongGuardAIHandler:log(config)
    local threat_data = kong.ctx.plugin.threat_data
    if not threat_data then
        return
    end
    
    -- Only log threats above monitoring threshold
    if threat_data.score > 0.3 and config.log_threats then
        local log_level = threat_data.score > config.block_threshold and "warn" or "info"
        log_message(config, log_level, "Threat detected in request", threat_data)
    end
    
    -- Send notifications for significant threats (async)
    if threat_data.score > config.rate_limit_threshold and config.enable_notifications then
        ngx.timer.at(0, function()
            self:send_notification(threat_data, config)
        end)
    end
    
    -- Update learning metrics (async)
    if threat_data.score > 0 then
        ngx.timer.at(0, function()
            self:update_learning_metrics(threat_data)
        end)
    end
end

-- Comprehensive threat detection with AI
function KongGuardAIHandler:detect_threat(features, config)
    local threat_score = 0
    local threat_type = "none"
    local threat_details = {}
    
    -- Use External AI Service if enabled
    if config.enable_ai_gateway then
        -- Get AI service URL from environment or config
        local ai_service_url = os.getenv("AI_SERVICE_URL") or config.ai_service_url or "http://ai-service:8000"
        
        -- Build request payload for AI service matching expected schema
        local raw_query = kong.request.get_raw_query() or ""
        local raw_body = kong.request.get_raw_body() or ""
        local headers = kong.request.get_headers()
        
        -- Combine query and body for analysis
        local query_content = raw_query
        if raw_body and #raw_body > 0 then
            query_content = query_content .. " " .. raw_body
        end
        
        local request_data = {
            features = {
                method = features.method or kong.request.get_method(),
                path = features.path or kong.request.get_path(),
                client_ip = features.client_ip,
                user_agent = features.user_agent or "",
                requests_per_minute = features.requests_per_minute or 0,
                content_length = features.content_length or 0,
                query_param_count = features.query_param_count or 0,
                header_count = features.header_count or 0,
                hour_of_day = features.hour_of_day or 0,
                query = query_content,
                headers = headers
            },
            context = {
                previous_requests = self:get_request_count(features.client_ip),
                failed_attempts = self:get_failed_attempts(features.client_ip),
                anomaly_score = self:calculate_anomaly_score(features)
            }
        }
        
        -- Call external AI service
        local httpc = http.new()
        httpc:set_timeout(500) -- 500ms timeout for AI analysis
        
        local res, err = httpc:request_uri(ai_service_url .. "/analyze", {
            method = "POST",
            body = cjson.encode(request_data),
            headers = {
                ["Content-Type"] = "application/json"
            }
        })
        
        if res and res.status == 200 then
            local ai_analysis = cjson.decode(res.body)
            
            -- Track AI usage
            local kong_cache = ngx.shared.kong_cache
            if kong_cache then
                kong_cache:incr("ai_requests", 1, 0)
            end
            
            -- Use AI results
            threat_score = ai_analysis.threat_score or 0
            threat_type = ai_analysis.threat_type or "none"
            threat_details = {
                ai_powered = true,
                ai_model = ai_analysis.model or "gemini",
                confidence = ai_analysis.confidence or 0,
                reasoning = ai_analysis.reasoning or "AI analysis",
                indicators = ai_analysis.indicators or {},
                recommended_action = ai_analysis.recommended_action or "monitor",
                thinking_time_ms = ai_analysis.processing_time_ms or 0,
                context_analyzed = ai_analysis.context_analyzed or false
            }
            
            -- Log AI decision
            if config.log_decisions then
                kong.log.info("AI Threat Analysis: ", cjson.encode(ai_analysis))
            end
            
            -- Track blocks if threat is high
            if threat_score > config.block_threshold and kong_cache then
                kong_cache:incr("ai_blocks", 1, 0)
            end
            
            -- Return AI-based detection results
            return threat_score, threat_type, threat_details
        else
            -- Log error but continue with rule-based detection
            kong.log.warn("Failed to reach AI service: ", err or "unknown error")
        end
    end
    
    -- Fallback to rule-based detection
    threat_details.detection_method = "rule_based"
    
    -- 1. SQL Injection Detection
    local sql_score = self:detect_sql_injection(features)
    if sql_score > 0 then
        threat_score = math.max(threat_score, sql_score)
        threat_type = "sql_injection"
        threat_details.sql_patterns = true
    end
    
    -- 2. XSS Detection
    local xss_score = self:detect_xss(features)
    if xss_score > 0 then
        threat_score = math.max(threat_score, xss_score)
        if threat_score == xss_score then
            threat_type = "xss"
        end
        threat_details.xss_patterns = true
    end
    
    -- 3. Path Traversal Detection
    local traversal_score = self:detect_path_traversal(features)
    if traversal_score > 0 then
        threat_score = math.max(threat_score, traversal_score)
        if threat_score == traversal_score then
            threat_type = "path_traversal"
        end
        threat_details.path_traversal = true
    end
    
    -- 4. DDoS Pattern Detection
    local ddos_score = self:detect_ddos_patterns(features, config)
    if ddos_score > 0 then
        threat_score = math.max(threat_score, ddos_score)
        if threat_score == ddos_score then
            threat_type = "ddos"
        end
        threat_details.high_rate = features.requests_per_minute
    end
    
    -- 5. Credential Stuffing Detection
    local cred_score = self:detect_credential_stuffing(features)
    if cred_score > 0 then
        threat_score = math.max(threat_score, cred_score)
        if threat_score == cred_score then
            threat_type = "credential_stuffing"
        end
        threat_details.login_attempts = features.requests_per_minute
    end
    
    -- 6. Command Injection Detection
    local cmd_score = self:detect_command_injection(features)
    if cmd_score > 0 then
        threat_score = math.max(threat_score, cmd_score)
        if threat_score == cmd_score then
            threat_type = "command_injection"
        end
        threat_details.command_patterns = true
    end
    
    -- 7. Anomaly Detection (if enabled)
    if config.enable_ml_detection then
        local anomaly_score = self:calculate_anomaly_score(features)
        if anomaly_score > 0.6 then
            threat_score = math.max(threat_score, anomaly_score)
            if threat_type == "none" then
                threat_type = "anomaly"
            end
            threat_details.anomaly_score = anomaly_score
        end
    end
    
    return threat_score, threat_type, threat_details
end

-- SQL Injection detection using string patterns
function KongGuardAIHandler:detect_sql_injection(features)
    local score = 0
    local path = kong.request.get_path()
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()
    
    -- Combine all input for checking
    local input = string.lower(path .. " " .. query)
    if body and #body < 10000 then -- Limit body size for performance
        input = input .. " " .. string.lower(body)
    end
    
    -- Check for SQL injection patterns
    local sql_patterns = {
        "union%s+select",
        "drop%s+table",
        "drop%s+database",
        "insert%s+into",
        "delete%s+from",
        "update%s+.*%s+set",
        "exec%s*%(", 
        "execute%s*%(",
        "script%s*>",
        "select%s+.*%s+from",
        "';%s*drop",
        "1%s*=%s*1",
        "or%s+1%s*=%s*1",
        "waitfor%s+delay",
        "benchmark%s*%(",
        "sleep%s*%("
    }
    
    for _, pattern in ipairs(sql_patterns) do
        if string.match(input, pattern) then
            score = 0.95
            break
        end
    end
    
    -- Check for SQL comment patterns
    if string.match(input, "%-%-") or string.match(input, "/%*") or string.match(input, "%*/") then
        score = math.max(score, 0.8)
    end
    
    return score
end

-- XSS detection using string patterns
function KongGuardAIHandler:detect_xss(features)
    local score = 0
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()
    local headers = kong.request.get_headers()
    
    -- Check query and body
    local input = string.lower(query)
    if body and #body < 10000 then
        input = input .. " " .. string.lower(body)
    end
    
    -- Check user-controlled headers
    for key, value in pairs(headers) do
        if key:lower():match("referer") or key:lower():match("user%-agent") then
            input = input .. " " .. string.lower(tostring(value))
        end
    end
    
    -- Check for XSS patterns
    local xss_patterns = {
        "<script",
        "javascript:",
        "onerror%s*=",
        "onload%s*=",
        "onclick%s*=",
        "onmouseover%s*=",
        "<iframe",
        "<embed",
        "<object",
        "document%.cookie",
        "document%.write",
        "window%.location",
        "eval%s*%(",
        "alert%s*%(",
        "<img%s+src"
    }
    
    for _, pattern in ipairs(xss_patterns) do
        if string.match(input, pattern) then
            score = 0.9
            break
        end
    end
    
    return score
end

-- Path traversal detection
function KongGuardAIHandler:detect_path_traversal(features)
    local score = 0
    local path = kong.request.get_path()
    local query = kong.request.get_raw_query() or ""
    
    local input = path .. " " .. query
    
    -- Check for path traversal patterns
    local traversal_patterns = {
        "%.%./",
        "%.%.\\",
        "%%2e%%2e%%2f",
        "%%252e%%252e%%252f",
        "/etc/passwd",
        "/windows/system32",
        "/proc/self",
        "c:\\windows",
        "c:\\winnt"
    }
    
    for _, pattern in ipairs(traversal_patterns) do
        if string.match(string.lower(input), pattern) then
            score = 0.85
            break
        end
    end
    
    return score
end

-- Command injection detection
function KongGuardAIHandler:detect_command_injection(features)
    local score = 0
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()
    
    local input = query
    if body and #body < 10000 then
        input = input .. " " .. body
    end
    
    -- Check for command injection patterns
    local cmd_patterns = {
        "%$%(.*%)",
        "`.*`",
        ";%s*ls%s",
        ";%s*cat%s",
        ";%s*wget%s",
        ";%s*curl%s",
        "|%s*nc%s",
        "&&%s*whoami",
        "%|%|%s*id%s"
    }
    
    for _, pattern in ipairs(cmd_patterns) do
        if string.match(input, pattern) then
            score = 0.9
            break
        end
    end
    
    return score
end

-- DDoS pattern detection
function KongGuardAIHandler:detect_ddos_patterns(features, config)
    local score = 0
    
    -- Check request rate
    if features.requests_per_minute > config.ddos_rpm_threshold then
        score = 0.8
        
        -- Increase score for very high rates
        if features.requests_per_minute > config.ddos_rpm_threshold * 2 then
            score = 0.95
        end
    end
    
    -- Check for request patterns (same path repeatedly)
    local path_key = "path_count:" .. features.client_ip .. ":" .. kong.request.get_path()
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        local path_count = kong_cache:incr(path_key, 1, 0, 60) or 1
        if path_count > 50 then -- Same path more than 50 times per minute
            score = math.max(score, 0.85)
        end
    end
    
    return score
end

-- Credential stuffing detection
function KongGuardAIHandler:detect_credential_stuffing(features)
    local score = 0
    local path = kong.request.get_path()
    
    -- Check if it's a login endpoint
    if features.method == "POST" and 
       (path:match("/login") or path:match("/auth") or path:match("/signin")) then
        
        -- Check failed login attempts
        local failed_key = "failed_login:" .. features.client_ip
        local kong_cache = ngx.shared.kong_cache
        if kong_cache then
            local failed_count = kong_cache:get(failed_key) or 0
            
            if failed_count > 5 then -- More than 5 failed attempts
                score = 0.8
            elseif failed_count > 10 then
                score = 0.95
            end
        end
        
        -- Check rapid login attempts
        if features.requests_per_minute > 10 then
            score = math.max(score, 0.75)
        end
    end
    
    return score
end

-- Feature extraction for threat detection
function KongGuardAIHandler:extract_features(request, client_ip)
    local features = {
        -- Temporal features
        hour_of_day = tonumber(os.date("%H")),
        day_of_week = tonumber(os.date("%w")),
        
        -- Request features
        method = request.get_method(),
        path = request.get_path(),
        path_depth = select(2, request.get_path():gsub("/", "")),
        query_param_count = 0,
        header_count = 0,
        
        -- Rate features
        requests_per_minute = self:get_request_rate(client_ip, 60),
        requests_per_hour = self:get_request_rate(client_ip, 3600),
        
        -- Payload features
        content_length = tonumber(request.get_header("Content-Length") or 0),
        
        -- Client features
        user_agent = request.get_header("User-Agent") or "",
        client_ip = client_ip,
        accept_language = request.get_header("Accept-Language") or ""
    }
    
    -- Count query parameters
    local query = request.get_query()
    if query then
        for k, v in pairs(query) do
            features.query_param_count = features.query_param_count + 1
        end
    end
    
    -- Count headers
    local headers = request.get_headers()
    if headers then
        for k, v in pairs(headers) do
            features.header_count = features.header_count + 1
        end
    end
    
    return features
end

-- Anomaly detection using statistical methods
function KongGuardAIHandler:calculate_anomaly_score(features)
    local score = 0
    
    -- Request rate anomaly
    local avg_rpm = 30 -- baseline average
    if features.requests_per_minute > avg_rpm * 3 then
        score = score + 0.3
    end
    
    -- Unusual time of day (late night/early morning)
    if features.hour_of_day >= 0 and features.hour_of_day <= 5 then
        score = score + 0.2
    end
    
    -- Unusual header count
    if features.header_count > 30 or features.header_count < 3 then
        score = score + 0.2
    end
    
    -- Large payload anomaly
    if features.content_length > 1000000 then -- > 1MB
        score = score + 0.3
    end
    
    -- Many query parameters
    if features.query_param_count > 10 then
        score = score + 0.2
    end
    
    return math.min(score, 1.0)
end

-- Check if IP is whitelisted
function KongGuardAIHandler:is_whitelisted(client_ip, whitelist)
    for _, ip in ipairs(whitelist) do
        if client_ip == ip then
            return true
        end
    end
    return false
end

-- Check if IP is currently blocked
function KongGuardAIHandler:is_blocked(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return false
    end
    
    local blocked = kong_cache:get("blocked:" .. client_ip)
    return blocked ~= nil
end

-- Get request count for IP
function KongGuardAIHandler:get_request_count(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return 0
    end
    
    local count_key = "request_count:" .. client_ip
    return kong_cache:get(count_key) or 0
end

-- Get failed authentication attempts
function KongGuardAIHandler:get_failed_attempts(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return 0
    end
    
    local failed_key = "failed_login:" .. client_ip
    return kong_cache:get(failed_key) or 0
end

-- Get request rate for IP
function KongGuardAIHandler:get_request_rate(client_ip, window)
    local cache_key = "rate:" .. client_ip .. ":" .. math.floor(ngx.now() / window)
    local kong_cache = ngx.shared.kong_cache
    
    if not kong_cache then
        return 0
    end
    
    local count = kong_cache:incr(cache_key, 1, 0, window + 10) or 1
    return count
end

-- Block request by IP
function KongGuardAIHandler:block_request(threat_type, client_ip)
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        -- Block for 1 hour
        kong_cache:set("blocked:" .. client_ip, threat_type, 3600)
        kong_cache:incr("threat_counter", 1, 0)
    end
end

-- Apply rate limiting
function KongGuardAIHandler:apply_rate_limit(client_ip, config)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return false
    end
    
    local rate_key = "rate_limit:" .. client_ip
    local current = kong_cache:incr(rate_key, 1, 0, 60) or 1
    
    -- Check if over rate limit (default 60 requests per minute when threatened)
    local limit = config.threat_rate_limit or 60
    return current > limit
end

-- Send notification (non-blocking)
function KongGuardAIHandler:send_notification(threat_data, config)
    if not config.notification_url then
        return
    end
    
    local httpc = http.new()
    httpc:set_timeout(1000) -- 1 second timeout
    
    local payload = {
        incident_id = self:generate_incident_id(),
        threat_type = threat_data.type,
        threat_score = threat_data.score,
        threat_details = threat_data.details,
        timestamp = threat_data.timestamp,
        client_ip = threat_data.client_ip,
        path = threat_data.path,
        method = threat_data.method,
        service = kong.router.get_service() and kong.router.get_service().name,
        route = kong.router.get_route() and kong.router.get_route().name
    }
    
    local res, err = httpc:request_uri(config.notification_url, {
        method = "POST",
        body = cjson.encode(payload),
        headers = {
            ["Content-Type"] = "application/json",
            ["X-Kong-Guard-AI"] = "v1.0.0"
        }
    })
    
    if err then
        kong.log.err("Failed to send notification: ", err)
    end
end

-- Update learning metrics
function KongGuardAIHandler:update_learning_metrics(threat_data)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return
    end
    
    -- Track threat type patterns
    local pattern_key = "pattern:" .. threat_data.type
    kong_cache:incr(pattern_key, 1, 0, 86400) -- Keep for 24 hours
    
    -- Track threat scores for calibration
    local score_bucket = math.floor(threat_data.score * 10) / 10
    local score_key = "score_dist:" .. tostring(score_bucket)
    kong_cache:incr(score_key, 1, 0, 86400)
end

-- Generate unique incident ID
function KongGuardAIHandler:generate_incident_id()
    return string.format("KGA-%s-%s", os.time(), math.random(10000, 99999))
end

return KongGuardAIHandler