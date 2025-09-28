-- Kong Guard AI - AI Service Integration Module
-- Extracted from handler.lua for better maintainability
-- Handles external AI service communication and response parsing

local cjson = require "cjson"
local http = require "resty.http"

local AIService = {}
AIService.__index = AIService

-- Initialize AI Service client
function AIService.new(config)
    local self = setmetatable({}, AIService)
    self.config = config or {}
    self.ai_service_url = os.getenv("AI_SERVICE_URL") or config.ai_service_url or "http://ai-service:8000"
    self.timeout = config.ai_timeout or 500  -- 500ms default timeout
    self.max_body_size = config.ai_max_body_size or 10000  -- 10KB limit
    self.cache = {}  -- Simple in-memory cache for responses

    return self
end

-- Main AI threat detection function
-- This replaces the AI detection logic from handler.lua detect_threat function
function AIService:detect_ai_optimized(features, config)
    if not config.enable_ai_gateway then
        return 0, "none", {}
    end

    local httpc = http.new()
    httpc:set_timeout(self.timeout)

    -- Build request data optimized for performance
    local request_data = self:build_optimized_request_data(features)

    -- Check cache first for identical requests
    local cache_key = self:generate_cache_key(request_data)
    if self.cache[cache_key] then
        local cached_result = self.cache[cache_key]
        if (ngx.now() - cached_result.timestamp) < 30 then  -- 30 second cache
            return cached_result.threat_score, cached_result.threat_type, cached_result.details
        end
    end

    local res, err = httpc:request_uri(self.ai_service_url .. "/analyze", {
        method = "POST",
        body = cjson.encode(request_data),
        headers = {
            ["Content-Type"] = "application/json",
            ["X-Kong-Guard-AI"] = "v2.0.0"
        }
    })

    if res and res.status == 200 then
        local ai_analysis = self:parse_ai_response(res.body)

        -- Track AI usage metrics
        self:update_ai_metrics(config)

        -- Cache successful response
        self.cache[cache_key] = {
            threat_score = ai_analysis.threat_score,
            threat_type = ai_analysis.threat_type,
            details = ai_analysis,
            timestamp = ngx.now()
        }

        return ai_analysis.threat_score or 0, ai_analysis.threat_type or "none", ai_analysis
    else
        -- Log error but don't fail - fallback to rule-based detection
        kong.log.warn("AI service unavailable: ", err or "HTTP " .. (res and res.status or "timeout"))
        return 0, "none", {error = "ai_service_unavailable"}
    end
end

-- Build optimized request data for AI service
function AIService:build_optimized_request_data(features)
    -- Get request data efficiently
    local raw_query = kong.request.get_raw_query() or ""
    local raw_body = kong.request.get_raw_body() or ""
    local headers = kong.request.get_headers()

    -- Limit body size for performance
    if #raw_body > self.max_body_size then
        raw_body = string.sub(raw_body, 1, self.max_body_size) .. "...[truncated]"
    end

    -- Combine query and body for analysis
    local query_content = raw_query
    if raw_body and #raw_body > 0 then
        query_content = query_content .. " " .. raw_body
    end

    return {
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
            headers = self:extract_relevant_headers(headers)
        },
        context = {
            previous_requests = self:get_request_count(features.client_ip),
            failed_attempts = self:get_failed_attempts(features.client_ip),
            anomaly_score = self:calculate_anomaly_score(features)
        },
        metadata = {
            timestamp = ngx.now(),
            kong_version = kong.version,
            plugin_version = "2.0.0"
        }
    }
end

-- Extract only relevant headers for AI analysis (privacy-conscious)
function AIService:extract_relevant_headers(headers)
    local relevant_headers = {}
    local allowed_headers = {
        "content-type", "accept", "accept-language", "accept-encoding",
        "referer", "origin", "cache-control", "x-requested-with"
    }

    for _, header_name in ipairs(allowed_headers) do
        if headers[header_name] then
            relevant_headers[header_name] = headers[header_name]
        end
    end

    return relevant_headers
end

-- Parse AI service response
function AIService:parse_ai_response(response_body)
    local ok, ai_analysis = pcall(cjson.decode, response_body)
    if not ok then
        kong.log.err("Failed to parse AI service response: ", response_body)
        return {
            threat_score = 0,
            threat_type = "parse_error",
            error = "Invalid AI response format"
        }
    end

    -- Ensure required fields with defaults
    local result = {
        threat_score = ai_analysis.threat_score or 0,
        threat_type = ai_analysis.threat_type or "none",
        confidence = ai_analysis.confidence or 0,
        reasoning = ai_analysis.reasoning or "AI analysis",
        indicators = ai_analysis.indicators or {},
        recommended_action = ai_analysis.recommended_action or "monitor",
        ai_powered = true,
        ai_model = ai_analysis.model or "unknown",
        thinking_time_ms = ai_analysis.processing_time_ms or 0,
        context_analyzed = ai_analysis.context_analyzed or false
    }

    -- Validate threat score range
    result.threat_score = math.max(0, math.min(1, result.threat_score))

    return result
end

-- Generate cache key for request data
function AIService:generate_cache_key(request_data)
    local key_data = {
        request_data.features.method,
        request_data.features.path,
        request_data.features.client_ip,
        request_data.features.query
    }
    return ngx.md5(table.concat(key_data, ":"))
end

-- Update AI usage metrics
function AIService:update_ai_metrics(config)
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:incr("ai_requests", 1, 0)

        -- Track AI response times
        local response_time = ngx.now() - (ngx.ctx.request_start_time or ngx.now())
        kong_cache:set("ai_last_response_time", response_time * 1000)
    end
end

-- Get request count for IP (helper function)
function AIService:get_request_count(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return 0
    end

    local count_key = "request_count:" .. client_ip
    return kong_cache:get(count_key) or 0
end

-- Get failed attempts for IP (helper function)
function AIService:get_failed_attempts(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return 0
    end

    local failed_key = "failed_login:" .. client_ip
    return kong_cache:get(failed_key) or 0
end

-- Calculate anomaly score (helper function)
function AIService:calculate_anomaly_score(features)
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

-- Health check for AI service
function AIService:health_check()
    local httpc = http.new()
    httpc:set_timeout(1000)  -- 1 second timeout for health check

    local res, err = httpc:request_uri(self.ai_service_url .. "/health", {
        method = "GET",
        headers = {
            ["X-Kong-Guard-AI"] = "health-check"
        }
    })

    return {
        available = res and res.status == 200,
        status_code = res and res.status,
        error = err,
        response_time_ms = (ngx.now() - (ngx.ctx.health_check_start or ngx.now())) * 1000
    }
end

-- Clear cache (for cleanup)
function AIService:clear_cache()
    self.cache = {}
end

-- Get AI service statistics
function AIService:get_statistics()
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return {
            ai_requests = 0,
            ai_blocks = 0,
            last_response_time = 0,
            cache_size = #self.cache
        }
    end

    return {
        ai_requests = kong_cache:get("ai_requests") or 0,
        ai_blocks = kong_cache:get("ai_blocks") or 0,
        last_response_time = kong_cache:get("ai_last_response_time") or 0,
        cache_size = self:get_cache_size(),
        service_url = self.ai_service_url,
        timeout_ms = self.timeout
    }
end

-- Get current cache size
function AIService:get_cache_size()
    local count = 0
    for _ in pairs(self.cache) do
        count = count + 1
    end
    return count
end

-- Configure AI service settings
function AIService:configure(new_config)
    self.config = new_config or self.config
    self.ai_service_url = os.getenv("AI_SERVICE_URL") or new_config.ai_service_url or self.ai_service_url
    self.timeout = new_config.ai_timeout or self.timeout
    self.max_body_size = new_config.ai_max_body_size or self.max_body_size
end

return AIService
