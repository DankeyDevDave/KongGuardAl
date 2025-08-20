local cjson = require "cjson"
local http = require "resty.http"

local KongGuardAIHandler = {
    VERSION = "1.0.0",
    PRIORITY = 2000
}

-- init_worker phase: Initialize ML models and caches
function KongGuardAIHandler:init_worker()
    -- Initialize shared memory for threat tracking
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:set("threat_counter", 0)
        kong_cache:set("false_positive_rate", 0)
    end
    
    kong.log.debug("Kong Guard AI: Worker initialized")
end

-- access phase: Monitor and analyze incoming requests
function KongGuardAIHandler:access(config)
    
    local client_ip = kong.client.get_forwarded_ip() or kong.client.get_ip()
    local path = kong.request.get_path()
    local method = kong.request.get_method()
    local headers = kong.request.get_headers()
    
    -- Extract features for threat detection
    local features = self:extract_features(kong.request, client_ip)
    
    -- Perform threat detection
    local threat_score, threat_type = self:detect_threat(features, config)
    
    -- Log detection
    kong.log.info("Kong Guard AI: Request analyzed", {
        client_ip = client_ip,
        path = path,
        threat_score = threat_score,
        threat_type = threat_type
    })
    
    -- Take action based on threat level
    if threat_score > config.block_threshold then
        -- Block request
        if not config.dry_run then
            self:block_request(threat_type, client_ip)
            return kong.response.exit(403, {
                message = "Request blocked by Kong Guard AI",
                threat_type = threat_type,
                incident_id = self:generate_incident_id()
            })
        else
            kong.log.warn("Kong Guard AI: Would block request (dry-run mode)", {
                threat_type = threat_type,
                client_ip = client_ip
            })
        end
    elseif threat_score > config.rate_limit_threshold then
        -- Apply rate limiting
        if not config.dry_run then
            self:apply_rate_limit(client_ip, config)
        else
            kong.log.warn("Kong Guard AI: Would rate-limit request (dry-run mode)", {
                client_ip = client_ip
            })
        end
    end
    
    -- Store threat data for learning
    kong.ctx.plugin.threat_data = {
        score = threat_score,
        type = threat_type,
        features = features,
        timestamp = ngx.now()
    }
end

-- log phase: Log results and learn from feedback
function KongGuardAIHandler:log(config)
    
    local threat_data = kong.ctx.plugin.threat_data
    if not threat_data then
        return
    end
    
    -- Log to external systems if configured
    if config.enable_notifications then
        self:send_notification(threat_data, config)
    end
    
    -- Update learning metrics
    self:update_learning_metrics(threat_data)
end

-- Feature extraction for ML
function KongGuardAIHandler:extract_features(request, client_ip)
    local features = {
        -- Temporal features
        hour_of_day = tonumber(os.date("%H")),
        day_of_week = tonumber(os.date("%w")),
        
        -- Request features
        method = request.get_method(),
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
        client_ip = client_ip
    }
    
    -- Count query parameters
    local query = request.get_query()
    for k, v in pairs(query) do
        features.query_param_count = features.query_param_count + 1
    end
    
    -- Count headers
    local headers = request.get_headers()
    for k, v in pairs(headers) do
        features.header_count = features.header_count + 1
    end
    
    return features
end

-- Threat detection logic
function KongGuardAIHandler:detect_threat(features, config)
    local threat_score = 0
    local threat_type = "none"
    
    -- Rule-based detection
    -- Check for DDoS patterns
    if features.requests_per_minute > config.ddos_rpm_threshold then
        threat_score = math.max(threat_score, 0.8)
        threat_type = "ddos"
    end
    
    -- Check for suspicious paths (SQL injection patterns)
    local path = kong.request.get_path()
    if path:match("['\";<>]") or path:match("union%s+select") or path:match("drop%s+table") then
        threat_score = math.max(threat_score, 0.9)
        threat_type = "sql_injection"
    end
    
    -- Check for XSS patterns
    local query = kong.request.get_raw_query()
    if query and (query:match("<script") or query:match("javascript:")) then
        threat_score = math.max(threat_score, 0.85)
        threat_type = "xss"
    end
    
    -- Check for credential stuffing
    if features.method == "POST" and path:match("/login") and features.requests_per_minute > 10 then
        threat_score = math.max(threat_score, 0.75)
        threat_type = "credential_stuffing"
    end
    
    -- ML-based anomaly detection (simplified scoring)
    local anomaly_score = self:calculate_anomaly_score(features)
    if anomaly_score > 0.7 then
        threat_score = math.max(threat_score, anomaly_score)
        if threat_type == "none" then
            threat_type = "anomaly"
        end
    end
    
    return threat_score, threat_type
end

-- Simplified anomaly detection
function KongGuardAIHandler:calculate_anomaly_score(features)
    -- Isolation Forest-like scoring (simplified)
    local score = 0
    
    -- Check if request rate is anomalous
    local avg_rpm = 30 -- baseline
    local rpm_deviation = math.abs(features.requests_per_minute - avg_rpm) / avg_rpm
    score = score + math.min(rpm_deviation * 0.3, 0.3)
    
    -- Check if header count is anomalous
    local avg_headers = 10
    local header_deviation = math.abs(features.header_count - avg_headers) / avg_headers
    score = score + math.min(header_deviation * 0.2, 0.2)
    
    -- Check time-based anomalies (requests at unusual hours)
    if features.hour_of_day < 6 or features.hour_of_day > 22 then
        score = score + 0.2
    end
    
    -- Check payload size anomalies
    if features.content_length > 1000000 then -- > 1MB
        score = score + 0.3
    end
    
    return math.min(score, 1.0)
end

-- Get request rate for IP
function KongGuardAIHandler:get_request_rate(client_ip, window)
    local cache_key = "rate:" .. client_ip .. ":" .. window
    local kong_cache = ngx.shared.kong_cache
    
    if not kong_cache then
        return 0
    end
    
    local count = kong_cache:get(cache_key) or 0
    kong_cache:incr(cache_key, 1, 0, window)
    
    return count
end

-- Block request by updating Kong configuration
function KongGuardAIHandler:block_request(threat_type, client_ip)
    -- Update shared memory with blocked IP
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:set("blocked:" .. client_ip, threat_type, 3600) -- Block for 1 hour
        kong_cache:incr("threat_counter", 1, 0)
    end
    
    -- Log incident
    kong.log.err("Kong Guard AI: Blocking request", {
        threat_type = threat_type,
        client_ip = client_ip,
        timestamp = ngx.now()
    })
end

-- Apply rate limiting
function KongGuardAIHandler:apply_rate_limit(client_ip, config)
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:set("rate_limited:" .. client_ip, true, 300) -- Rate limit for 5 minutes
    end
end

-- Send notification
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
        timestamp = threat_data.timestamp,
        service = kong.router.get_service().name,
        route = kong.router.get_route().name
    }
    
    -- Send asynchronously
    ngx.timer.at(0, function()
        local res, err = httpc:request_uri(config.notification_url, {
            method = "POST",
            body = cjson.encode(payload),
            headers = {
                ["Content-Type"] = "application/json"
            }
        })
        
        if err then
            kong.log.err("Failed to send notification: ", err)
        end
    end)
end

-- Update learning metrics
function KongGuardAIHandler:update_learning_metrics(threat_data)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return
    end
    
    -- Track detection patterns for learning
    local pattern_key = "pattern:" .. threat_data.type
    kong_cache:incr(pattern_key, 1, 0, 86400) -- Keep for 24 hours
end

-- Generate unique incident ID
function KongGuardAIHandler:generate_incident_id()
    return string.format("inc_%s_%s", os.time(), math.random(10000, 99999))
end

return KongGuardAIHandler