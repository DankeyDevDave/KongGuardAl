-- Kong Guard AI - AI Gateway Integration Module
-- Interfaces with Kong AI Gateway for advanced threat analysis using LLMs
-- Provides AI-powered threat detection and behavioral analysis

local kong = kong
local http = require "resty.http"
local json = require "cjson.safe"

local _M = {}

-- AI analysis cache to prevent duplicate requests
local ai_cache = {}

-- AI Gateway constants
local AI_ANALYSIS_PROMPTS = {
    THREAT_DETECTION = [[
Analyze the following HTTP request for security threats and anomalies:

Request Method: %s
Request Path: %s
Headers: %s
Query Parameters: %s
Client IP: %s
User Agent: %s

Initial threat assessment:
- Threat Type: %s
- Threat Level: %d/10
- Confidence: %.2f

Please provide:
1. Validation of the initial threat assessment
2. Additional threat indicators not detected by rule-based analysis
3. Risk score (1-10) with explanation
4. Recommended response action
5. Confidence level (0-1) in your analysis

Focus on detecting:
- SQL injection attempts
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Authentication bypass attempts
- API abuse patterns
- Anomalous behavior patterns

Respond in JSON format:
{
  "threat_validated": boolean,
  "threat_type": "string",
  "threat_level": number,
  "confidence": number,
  "additional_indicators": ["array of strings"],
  "recommended_action": "string",
  "explanation": "string"
}
]],

    BEHAVIORAL_ANALYSIS = [[
Analyze the following request pattern for behavioral anomalies:

Recent requests from IP %s:
%s

Current request:
Method: %s, Path: %s, Headers: %d, Time: %s

Please identify:
1. Unusual access patterns
2. Potential automation/bot behavior
3. Credential stuffing indicators
4. API abuse patterns
5. Session anomalies

Respond in JSON format with risk assessment and recommendations.
]],

    PAYLOAD_ANALYSIS = [[
Analyze this request payload for injection attacks and malicious content:

Payload: %s
Content-Type: %s
Size: %d bytes

Look for:
1. SQL injection patterns
2. XSS payloads
3. Command injection
4. Serialization attacks
5. Template injection
6. NoSQL injection

Provide detailed analysis with threat level and mitigation recommendations.
]]
}

---
-- Initialize AI Gateway integration
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Gateway] Initializing AI Gateway integration")
    
    -- Validate AI Gateway configuration
    if not conf.ai_gateway_endpoint then
        kong.log.warn("[Kong Guard AI Gateway] No AI Gateway endpoint configured")
        return
    end
    
    -- Initialize AI cache
    ai_cache.requests = {}
    ai_cache.responses = {}
    
    -- Test AI Gateway connectivity
    _M.test_ai_gateway_connection(conf)
    
    kong.log.info("[Kong Guard AI Gateway] AI Gateway integration initialized")
end

---
-- Analyze threat using AI Gateway
-- @param request_context Original request context
-- @param threat_result Initial threat assessment
-- @param conf Plugin configuration
-- @return Table containing AI analysis result or nil
---
function _M.analyze_threat(request_context, threat_result, conf)
    if not conf.ai_gateway_enabled then
        return nil
    end
    
    -- Check cache first to avoid duplicate AI requests
    local cache_key = _M.generate_cache_key(request_context, threat_result)
    local cached_result = ai_cache.responses[cache_key]
    
    if cached_result and (ngx.time() - cached_result.timestamp) < 300 then -- 5 minute cache
        kong.log.debug("[Kong Guard AI Gateway] Using cached AI analysis")
        return cached_result.result
    end
    
    kong.log.debug("[Kong Guard AI Gateway] Performing AI threat analysis")
    
    -- Prepare AI analysis request
    local ai_prompt = _M.build_threat_analysis_prompt(request_context, threat_result)
    local ai_response = _M.call_ai_gateway(ai_prompt, conf)
    
    if not ai_response then
        kong.log.warn("[Kong Guard AI Gateway] AI Gateway request failed")
        return nil
    end
    
    -- Parse AI response
    local ai_result = _M.parse_ai_response(ai_response)
    
    if ai_result then
        -- Cache the result
        ai_cache.responses[cache_key] = {
            result = ai_result,
            timestamp = ngx.time()
        }
        
        kong.log.info("[Kong Guard AI Gateway] AI analysis completed - Threat Level: " .. 
                     (ai_result.threat_level or "unknown"))
    end
    
    return ai_result
end

---
-- Build threat analysis prompt for AI Gateway
-- @param request_context Request context data
-- @param threat_result Initial threat assessment
-- @return String containing formatted prompt
---
function _M.build_threat_analysis_prompt(request_context, threat_result)
    -- Prepare request data for analysis
    local headers_str = json.encode(request_context.headers or {})
    local query_str = json.encode(request_context.query or {})
    local user_agent = request_context.headers and request_context.headers["user-agent"] or "unknown"
    
    local prompt = string.format(
        AI_ANALYSIS_PROMPTS.THREAT_DETECTION,
        request_context.method or "unknown",
        request_context.path or "/",
        headers_str,
        query_str,
        request_context.client_ip or "unknown",
        user_agent,
        threat_result.threat_type or "unknown",
        threat_result.threat_level or 0,
        threat_result.confidence or 0
    )
    
    return prompt
end

---
-- Call Kong AI Gateway for analysis
-- @param prompt AI analysis prompt
-- @param conf Plugin configuration
-- @return String AI response or nil
---
function _M.call_ai_gateway(prompt, conf)
    local httpc = http.new()
    httpc:set_timeout(conf.ai_timeout_ms)
    
    -- Prepare AI Gateway request payload
    local ai_request = {
        model = conf.ai_gateway_model,
        messages = {
            {
                role = "system",
                content = "You are a cybersecurity expert analyzing HTTP requests for threats. Provide accurate, actionable threat assessments."
            },
            {
                role = "user", 
                content = prompt
            }
        },
        max_tokens = 1000,
        temperature = 0.1 -- Low temperature for consistent security analysis
    }
    
    local headers = {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "Kong-Guard-AI/0.1.0"
    }
    
    -- Add authentication if configured
    if conf.ai_gateway_api_key then
        headers["Authorization"] = "Bearer " .. conf.ai_gateway_api_key
    end
    
    local res, err = httpc:request_uri(conf.ai_gateway_endpoint, {
        method = "POST",
        headers = headers,
        body = json.encode(ai_request),
        ssl_verify = false
    })
    
    if not res then
        kong.log.error("[Kong Guard AI Gateway] AI Gateway request failed: " .. (err or "unknown error"))
        return nil
    end
    
    if res.status ~= 200 then
        kong.log.error("[Kong Guard AI Gateway] AI Gateway returned status: " .. res.status)
        kong.log.debug("[Kong Guard AI Gateway] Response body: " .. (res.body or "empty"))
        return nil
    end
    
    return res.body
end

---
-- Parse AI Gateway response
-- @param response_body Raw AI response body
-- @return Table containing parsed AI analysis or nil
---
function _M.parse_ai_response(response_body)
    local response_data, err = json.decode(response_body)
    if not response_data then
        kong.log.error("[Kong Guard AI Gateway] Failed to parse AI response: " .. (err or "unknown"))
        return nil
    end
    
    -- Extract content from AI Gateway response format
    local ai_content
    if response_data.choices and response_data.choices[1] and response_data.choices[1].message then
        ai_content = response_data.choices[1].message.content
    elseif response_data.content then
        ai_content = response_data.content
    else
        kong.log.error("[Kong Guard AI Gateway] Unexpected AI response format")
        return nil
    end
    
    -- Parse AI analysis JSON
    local ai_analysis, parse_err = json.decode(ai_content)
    if not ai_analysis then
        kong.log.error("[Kong Guard AI Gateway] Failed to parse AI analysis JSON: " .. (parse_err or "unknown"))
        -- Try to extract structured data from plain text response
        return _M.extract_analysis_from_text(ai_content)
    end
    
    -- Validate required fields
    local result = {
        threat_validated = ai_analysis.threat_validated or false,
        threat_type = ai_analysis.threat_type,
        threat_level = tonumber(ai_analysis.threat_level) or 0,
        confidence = tonumber(ai_analysis.confidence) or 0,
        additional_indicators = ai_analysis.additional_indicators or {},
        recommended_action = ai_analysis.recommended_action,
        explanation = ai_analysis.explanation,
        ai_source = "ai_gateway"
    }
    
    return result
end

---
-- Extract analysis from plain text AI response (fallback)
-- @param text_content Plain text AI response
-- @return Table containing extracted analysis or nil
---
function _M.extract_analysis_from_text(text_content)
    kong.log.debug("[Kong Guard AI Gateway] Attempting to extract analysis from text response")
    
    local result = {
        threat_validated = false,
        threat_level = 0,
        confidence = 0,
        explanation = text_content,
        ai_source = "ai_gateway_text"
    }
    
    -- Simple pattern matching for key information
    local threat_level = text_content:match("threat.?level:?%s*(%d+)")
    if threat_level then
        result.threat_level = tonumber(threat_level)
    end
    
    local confidence = text_content:match("confidence:?%s*([%d%.]+)")
    if confidence then
        result.confidence = tonumber(confidence)
    end
    
    -- Look for threat validation
    if text_content:lower():find("threat.?validated") or text_content:lower():find("confirmed") then
        result.threat_validated = true
    end
    
    -- Extract recommended action
    local action = text_content:match("recommend.?action:?%s*(%w+)")
    if action then
        result.recommended_action = action:lower()
    end
    
    return result
end

---
-- Analyze behavioral patterns using AI
-- @param request_context Current request context
-- @param request_history Historical requests from same IP
-- @param conf Plugin configuration
-- @return Table containing behavioral analysis
---
function _M.analyze_behavior(request_context, request_history, conf)
    if not conf.ai_gateway_enabled then
        return nil
    end
    
    kong.log.debug("[Kong Guard AI Gateway] Performing AI behavioral analysis")
    
    -- Build behavioral analysis prompt
    local history_str = json.encode(request_history or {})
    local prompt = string.format(
        AI_ANALYSIS_PROMPTS.BEHAVIORAL_ANALYSIS,
        request_context.client_ip,
        history_str,
        request_context.method,
        request_context.path,
        _M.count_headers(request_context.headers),
        os.date("%Y-%m-%d %H:%M:%S", ngx.time())
    )
    
    local ai_response = _M.call_ai_gateway(prompt, conf)
    if not ai_response then
        return nil
    end
    
    return _M.parse_ai_response(ai_response)
end

---
-- Analyze request payload using AI
-- @param payload Request body/payload
-- @param content_type Content type header
-- @param conf Plugin configuration
-- @return Table containing payload analysis
---
function _M.analyze_payload(payload, content_type, conf)
    if not conf.ai_gateway_enabled or not payload then
        return nil
    end
    
    -- Limit payload size for AI analysis
    if #payload > 10240 then -- 10KB limit
        payload = payload:sub(1, 10240) .. "... [truncated]"
    end
    
    kong.log.debug("[Kong Guard AI Gateway] Performing AI payload analysis")
    
    local prompt = string.format(
        AI_ANALYSIS_PROMPTS.PAYLOAD_ANALYSIS,
        payload,
        content_type or "unknown",
        #payload
    )
    
    local ai_response = _M.call_ai_gateway(prompt, conf)
    if not ai_response then
        return nil
    end
    
    return _M.parse_ai_response(ai_response)
end

---
-- Test AI Gateway connectivity
-- @param conf Plugin configuration
---
function _M.test_ai_gateway_connection(conf)
    kong.log.debug("[Kong Guard AI Gateway] Testing AI Gateway connectivity")
    
    local test_prompt = "Test connection. Respond with 'OK' if you receive this message."
    local response = _M.call_ai_gateway(test_prompt, conf)
    
    if response then
        kong.log.info("[Kong Guard AI Gateway] AI Gateway connectivity test successful")
    else
        kong.log.warn("[Kong Guard AI Gateway] AI Gateway connectivity test failed")
    end
end

---
-- Generate cache key for AI requests
-- @param request_context Request context
-- @param threat_result Threat result
-- @return String cache key
---
function _M.generate_cache_key(request_context, threat_result)
    local key_components = {
        request_context.method or "",
        request_context.path or "",
        request_context.client_ip or "",
        threat_result.threat_type or "",
        tostring(threat_result.threat_level or 0)
    }
    
    return table.concat(key_components, "|")
end

---
-- Count headers in request
-- @param headers Headers table
-- @return Number of headers
---
function _M.count_headers(headers)
    if not headers then
        return 0
    end
    
    local count = 0
    for _ in pairs(headers) do
        count = count + 1
    end
    
    return count
end

---
-- Get AI Gateway metrics
-- @return Table containing AI metrics
---
function _M.get_ai_metrics()
    local metrics = {
        total_requests = 0,
        cache_hits = 0,
        cache_misses = 0,
        successful_analyses = 0,
        failed_analyses = 0
    }
    
    if ai_cache.requests then
        metrics.total_requests = #ai_cache.requests
    end
    
    if ai_cache.responses then
        metrics.successful_analyses = 0
        for _ in pairs(ai_cache.responses) do
            metrics.successful_analyses = metrics.successful_analyses + 1
        end
    end
    
    return metrics
end

---
-- Clean up AI cache
---
function _M.cleanup_ai_cache()
    local current_time = ngx.time()
    local cache_ttl = 300 -- 5 minutes
    
    -- Clean response cache
    if ai_cache.responses then
        for cache_key, cached_data in pairs(ai_cache.responses) do
            if current_time - cached_data.timestamp > cache_ttl then
                ai_cache.responses[cache_key] = nil
            end
        end
    end
    
    -- Clean request cache
    if ai_cache.requests then
        local cleaned_requests = {}
        for _, request_data in ipairs(ai_cache.requests) do
            if current_time - request_data.timestamp < 3600 then -- Keep 1 hour
                table.insert(cleaned_requests, request_data)
            end
        end
        ai_cache.requests = cleaned_requests
    end
    
    kong.log.debug("[Kong Guard AI Gateway] AI cache cleanup completed")
end

---
-- Send feedback to AI system for learning
-- @param original_analysis Original AI analysis
-- @param actual_outcome Actual security outcome
-- @param operator_feedback Human operator feedback
-- @param conf Plugin configuration
---
function _M.send_feedback(original_analysis, actual_outcome, operator_feedback, conf)
    if not conf.ai_gateway_enabled or not conf.enable_learning then
        return
    end
    
    kong.log.debug("[Kong Guard AI Gateway] Sending feedback to AI system")
    
    local feedback_data = {
        original_analysis = original_analysis,
        actual_outcome = actual_outcome,
        operator_feedback = operator_feedback,
        timestamp = ngx.time()
    }
    
    -- In production, this would send feedback to an AI training pipeline
    -- For now, just log the feedback
    kong.log.info("[Kong Guard AI Gateway] AI Feedback: " .. json.encode(feedback_data))
end

return _M