-- Kong Guard AI - Enhanced AI Gateway Integration Module
-- Production-ready LLM integration for advanced threat analysis
-- Supports multiple AI models with failover, caching, and performance optimization

local kong = kong
local http = require "resty.http"
local json = require "cjson.safe"
local lrucache = require "resty.lrucache"
local cjson = require "cjson"

local _M = {}

-- Enhanced AI response cache with TTL and model-specific storage
local ai_response_cache = lrucache.new(1000)  -- Cache 1000 responses
local user_behavior_cache = lrucache.new(500) -- Cache 500 user profiles
local model_performance_cache = lrucache.new(50) -- Track model performance

-- Multi-model AI Gateway configuration
local AI_MODELS = {
    GPT4 = {
        name = "gpt-4-turbo",
        max_tokens = 2000,
        temperature = 0.1,
        cost_per_token = 0.00003,
        latency_avg = 2500, -- ms
        reliability = 0.98
    },
    CLAUDE = {
        name = "claude-3-sonnet-20240229",
        max_tokens = 2000,
        temperature = 0.1,
        cost_per_token = 0.000015,
        latency_avg = 2000,
        reliability = 0.99
    },
    GEMINI = {
        name = "gemini-1.5-pro",
        max_tokens = 2000,
        temperature = 0.1,
        cost_per_token = 0.00001,
        latency_avg = 1800,
        reliability = 0.97
    }
}

-- Enhanced AI analysis prompts with context and multi-turn conversation support
local AI_ANALYSIS_PROMPTS = {
    THREAT_DETECTION = [[
You are an expert cybersecurity analyst specializing in API threat detection. Analyze the following HTTP request for security threats with high precision.

REQUEST CONTEXT:
Method: %s
Path: %s
Headers: %s
Query Parameters: %s
Body Preview: %s
Client IP: %s
User Agent: %s
Session Info: %s
Timestamp: %s

INITIAL ASSESSMENT:
- Threat Type: %s
- Threat Level: %d/10
- Confidence: %.2f
- Rule-based Indicators: %s

ANALYSIS REQUIREMENTS:
1. Validate initial threat assessment with detailed reasoning
2. Identify additional threat vectors not detected by rule-based systems
3. Assess payload obfuscation techniques
4. Evaluate injection attack sophistication
5. Check for APT-style reconnaissance patterns
6. Analyze evasion techniques and encoding attempts

DETECTION FOCUS:
- SQL injection (all variants including blind, time-based, boolean)
- XSS (stored, reflected, DOM-based, mutation-based)
- Command injection and shell metacharacters
- Path traversal and directory climbing
- LDAP/XML/NoSQL injection
- Server-side template injection (SSTI)
- Deserialization attacks
- Authentication bypass techniques
- API abuse and business logic flaws
- Zero-day exploitation patterns

RESPONSE FORMAT (JSON only):
{
  "threat_validated": boolean,
  "threat_type": "string (specific attack type)",
  "threat_level": number (1-10),
  "confidence": number (0.0-1.0),
  "sophistication_level": "basic|intermediate|advanced|apt",
  "attack_vectors": ["array of specific techniques"],
  "evasion_techniques": ["array of detected evasions"],
  "payload_analysis": {
    "obfuscated": boolean,
    "encoding_used": ["array of encodings"],
    "injection_points": ["array of locations"],
    "payload_complexity": number (1-10)
  },
  "recommended_action": "block|challenge|monitor|allow",
  "mitigation_steps": ["array of specific countermeasures"],
  "false_positive_likelihood": number (0.0-1.0),
  "explanation": "detailed technical analysis",
  "indicators_of_compromise": ["array of specific IOCs"]
}
]],

    BEHAVIORAL_ANALYSIS = [[
You are a behavioral analysis expert specializing in detecting automated attacks and anomalous user patterns. Analyze the following request sequence for suspicious behavior.

USER BEHAVIOR PROFILE:
IP Address: %s
Session Duration: %s
Request History (last 24h): %s
User Agent Consistency: %s
Geographic Indicators: %s
Rate Pattern: %s

CURRENT REQUEST CONTEXT:
Method: %s
Path: %s
Headers Count: %d
Request Size: %d bytes
Time Since Last Request: %s
Session State: %s

BEHAVIOR ANALYSIS REQUIREMENTS:
1. Detect automation patterns and bot behavior
2. Identify credential stuffing campaigns
3. Assess API enumeration attempts
4. Evaluate session hijacking indicators
5. Check for distributed attack coordination
6. Analyze timing patterns for script behavior

DETECTION PATTERNS:
- Request timing anomalies
- User-Agent rotation patterns
- Header inconsistencies
- Geographic impossibilities
- Rate limiting evasion techniques
- Session token anomalies
- Credential validation patterns
- API discovery scanning

RESPONSE FORMAT (JSON only):
{
  "is_automated": boolean,
  "automation_confidence": number (0.0-1.0),
  "behavior_type": "human|bot|scraper|attacker|unknown",
  "attack_campaign": {
    "detected": boolean,
    "campaign_type": "credential_stuffing|enumeration|ddos|reconnaissance",
    "coordination_level": "single|distributed|botnet"
  },
  "anomaly_score": number (0.0-10.0),
  "timing_analysis": {
    "human_like": boolean,
    "rate_consistent": boolean,
    "burst_pattern": boolean
  },
  "session_analysis": {
    "hijack_indicators": boolean,
    "token_anomalies": boolean,
    "state_inconsistencies": ["array of issues"]
  },
  "geographic_analysis": {
    "impossible_travel": boolean,
    "proxy_indicators": boolean,
    "tor_usage": boolean
  },
  "recommended_action": "allow|challenge|rate_limit|block",
  "confidence_factors": ["array of detection reasons"],
  "user_risk_score": number (1-10)
}
]],

    PAYLOAD_ANALYSIS = [[
You are a payload analysis specialist expert in detecting sophisticated injection attacks and malicious content. Perform deep analysis of the following request payload.

PAYLOAD CONTEXT:
Content: %s
Content-Type: %s
Content-Length: %d bytes
Encoding: %s
Content-Encoding: %s
Boundary/Delimiter: %s
Structure Type: %s

ANALYSIS REQUIREMENTS:
1. Deep payload structure analysis
2. Multi-layer encoding detection
3. Obfuscation technique identification
4. Injection vector assessment
5. Malicious code pattern recognition
6. Data exfiltration attempt detection

DETECTION CATEGORIES:
- SQL injection (all database types)
- NoSQL injection (MongoDB, Redis, etc.)
- LDAP injection
- XML/XXE injection
- JSON injection
- Command injection (OS commands)
- Code injection (script languages)
- Template injection (Jinja2, Freemarker, etc.)
- Path traversal payloads
- File upload attacks
- Serialization exploits
- Buffer overflow attempts

RESPONSE FORMAT (JSON only):
{
  "malicious_payload": boolean,
  "injection_type": ["array of detected injection types"],
  "payload_sophistication": number (1-10),
  "obfuscation_detected": boolean,
  "encoding_layers": ["array of encoding methods"],
  "injection_vectors": [{
    "type": "string",
    "location": "string",
    "payload_snippet": "string",
    "severity": number (1-10)
  }],
  "evasion_techniques": ["array of evasion methods"],
  "target_technology": ["array of likely targets"],
  "attack_complexity": "low|medium|high|advanced",
  "data_exfiltration_risk": boolean,
  "file_manipulation_risk": boolean,
  "recommended_action": "block|sanitize|monitor|allow",
  "sanitization_suggestions": ["array of specific fixes"],
  "threat_level": number (1-10),
  "confidence": number (0.0-1.0)
}
]],

    CONTEXTUAL_ASSESSMENT = [[
You are a contextual threat assessment expert. Analyze the following multi-dimensional threat context to provide a comprehensive security assessment.

COMPREHENSIVE CONTEXT:
Request Details: %s
Behavioral Profile: %s
Payload Analysis: %s
Historical Threats: %s
Current Security Posture: %s
Business Context: %s

CONTEXTUAL ANALYSIS REQUIREMENTS:
1. Synthesize multi-source threat intelligence
2. Assess business impact potential
3. Evaluate attack progression indicators
4. Determine threat actor sophistication
5. Predict attack evolution likelihood
6. Recommend adaptive countermeasures

RESPONSE FORMAT (JSON only):
{
  "overall_threat_level": number (1-10),
  "business_impact_score": number (1-10),
  "attack_progression": {
    "current_stage": "reconnaissance|initial_access|persistence|escalation|exfiltration",
    "next_likely_actions": ["array of predicted actions"],
    "timeline_urgency": "immediate|hours|days|weeks"
  },
  "threat_actor_profile": {
    "sophistication": "script_kiddie|criminal|nation_state|insider",
    "motivations": ["array of likely motivations"],
    "capabilities": ["array of demonstrated capabilities"]
  },
  "adaptive_response": {
    "immediate_actions": ["array of immediate responses"],
    "medium_term_adjustments": ["array of policy changes"],
    "long_term_improvements": ["array of strategic changes"]
  },
  "confidence_assessment": number (0.0-1.0),
  "recommended_alert_level": "info|low|medium|high|critical"
}
]]
}

-- Model performance tracking and selection
local model_stats = {
    last_update = 0,
    performance_window = 300 -- 5 minutes
}

-- Cost optimization settings
local COST_OPTIMIZATION = {
    max_daily_cost = 100.0, -- $100 daily limit
    sampling_rate = {
        low_risk = 0.1,    -- Sample 10% of low-risk requests
        medium_risk = 0.5, -- Sample 50% of medium-risk requests
        high_risk = 1.0    -- Analyze 100% of high-risk requests
    },
    cache_ttl = {
        threat_analysis = 300,    -- 5 minutes
        behavioral = 600,         -- 10 minutes
        payload_analysis = 180    -- 3 minutes
    }
}

-- Feedback loop for continuous learning
local feedback_data = {
    false_positives = {},
    false_negatives = {},
    analyst_corrections = {}
}

---
-- Initialize enhanced AI Gateway integration with multi-model support
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Gateway] Initializing Enhanced AI Gateway integration")

    -- Validate AI Gateway configuration
    if not conf.ai_gateway_enabled then
        kong.log.info("[Kong Guard AI Gateway] AI Gateway disabled in configuration")
        return
    end

    if not conf.ai_gateway_endpoint then
        kong.log.warn("[Kong Guard AI Gateway] No AI Gateway endpoint configured")
        return
    end

    -- Initialize enhanced cache systems
    _M.init_cache_systems()

    -- Initialize model performance tracking
    _M.init_model_tracking(conf)

    -- Test AI Gateway connectivity for all configured models
    _M.test_multi_model_connectivity(conf)

    -- Initialize feedback collection system
    _M.init_feedback_system()

    kong.log.info("[Kong Guard AI Gateway] Enhanced AI Gateway integration initialized with %d models",
                  _M.count_available_models(conf))
end

---
-- Initialize cache systems for enhanced performance
---
function _M.init_cache_systems()
    -- Initialize cache with performance monitoring
    ai_response_cache:flush_all()
    user_behavior_cache:flush_all()
    model_performance_cache:flush_all()

    kong.log.debug("[Kong Guard AI Gateway] Cache systems initialized")
end

---
-- Initialize model performance tracking
-- @param conf Plugin configuration
---
function _M.init_model_tracking(conf)
    -- Initialize performance metrics for each model
    for model_name, model_config in pairs(AI_MODELS) do
        if conf["ai_" .. string.lower(model_name) .. "_enabled"] then
            model_performance_cache:set("perf_" .. model_name, {
                total_requests = 0,
                successful_requests = 0,
                avg_latency = model_config.latency_avg,
                total_cost = 0.0,
                last_success = ngx.time(),
                error_count = 0
            }, 3600) -- 1 hour TTL
        end
    end

    model_stats.last_update = ngx.time()
    kong.log.debug("[Kong Guard AI Gateway] Model performance tracking initialized")
end

---
-- Test connectivity for all configured AI models
-- @param conf Plugin configuration
---
function _M.test_multi_model_connectivity(conf)
    local available_models = 0

    for model_name, model_config in pairs(AI_MODELS) do
        if conf["ai_" .. string.lower(model_name) .. "_enabled"] then
            local success = _M.test_model_connectivity(model_name, model_config, conf)
            if success then
                available_models = available_models + 1
                kong.log.info("[Kong Guard AI Gateway] Model %s connectivity verified", model_name)
            else
                kong.log.warn("[Kong Guard AI Gateway] Model %s connectivity failed", model_name)
            end
        end
    end

    if available_models == 0 then
        kong.log.error("[Kong Guard AI Gateway] No AI models available - AI Gateway will be disabled")
    end

    return available_models > 0
end

---
-- Initialize feedback collection system for continuous learning
---
function _M.init_feedback_system()
    feedback_data.false_positives = {}
    feedback_data.false_negatives = {}
    feedback_data.analyst_corrections = {}

    kong.log.debug("[Kong Guard AI Gateway] Feedback system initialized for continuous learning")
end

---
-- Count available AI models
-- @param conf Plugin configuration
-- @return Number of available models
---
function _M.count_available_models(conf)
    local count = 0
    for model_name, _ in pairs(AI_MODELS) do
        if conf["ai_" .. string.lower(model_name) .. "_enabled"] then
            count = count + 1
        end
    end
    return count
end

---
-- Enhanced threat analysis using AI Gateway with multi-model support
-- @param request_context Original request context
-- @param threat_result Initial threat assessment
-- @param conf Plugin configuration
-- @return Table containing comprehensive AI analysis result or nil
---
function _M.analyze_threat(request_context, threat_result, conf)
    if not conf.ai_gateway_enabled then
        return nil
    end

    -- Determine analysis complexity and model selection
    local analysis_type = _M.determine_analysis_type(request_context, threat_result)
    local risk_level = _M.calculate_risk_level(threat_result)

    -- Apply cost optimization sampling
    if not _M.should_analyze_request(risk_level, conf) then
        kong.log.debug("[Kong Guard AI Gateway] Request skipped due to cost optimization")
        return nil
    end

    -- Check enhanced cache first
    local cache_key = _M.generate_enhanced_cache_key(request_context, threat_result, analysis_type)
    local cached_result = _M.get_cached_analysis(cache_key, analysis_type)

    if cached_result then
        kong.log.debug("[Kong Guard AI Gateway] Using cached AI analysis")
        return cached_result
    end

    kong.log.debug("[Kong Guard AI Gateway] Performing enhanced AI threat analysis - Type: %s, Risk: %s",
                   analysis_type, risk_level)

    -- Select optimal model based on analysis requirements
    local selected_model = _M.select_optimal_model(analysis_type, risk_level, conf)
    if not selected_model then
        kong.log.warn("[Kong Guard AI Gateway] No AI models available for analysis")
        return nil
    end

    -- Perform comprehensive analysis
    local ai_result = _M.perform_comprehensive_analysis(request_context, threat_result, selected_model, conf)

    if ai_result then
        -- Cache the result with appropriate TTL
        _M.cache_analysis_result(cache_key, ai_result, analysis_type)

        -- Update model performance metrics
        _M.update_model_performance(selected_model.name, true, ai_result.confidence or 0)

        kong.log.info("[Kong Guard AI Gateway] Enhanced AI analysis completed - Model: %s, Threat Level: %d, Confidence: %.2f",
                     selected_model.name, ai_result.threat_level or 0, ai_result.confidence or 0)
    else
        -- Update model performance for failed request
        _M.update_model_performance(selected_model.name, false, 0)
    end

    return ai_result
end

---
-- Determine the type of analysis required based on request characteristics
-- @param request_context Request context data
-- @param threat_result Initial threat assessment
-- @return String analysis type
---
function _M.determine_analysis_type(request_context, threat_result)
    local threat_level = threat_result.threat_level or 0
    local has_payload = request_context.body and string.len(request_context.body) > 0
    local is_behavioral = threat_result.threat_type and string.find(threat_result.threat_type, "behavioral")

    if threat_level >= 8 then
        return "comprehensive" -- Full multi-model analysis
    elseif has_payload and threat_level >= 5 then
        return "payload_focused" -- Deep payload analysis
    elseif is_behavioral then
        return "behavioral_focused" -- Behavioral pattern analysis
    else
        return "standard" -- Standard threat detection
    end
end

---
-- Calculate risk level for cost optimization
-- @param threat_result Initial threat assessment
-- @return String risk level
---
function _M.calculate_risk_level(threat_result)
    local threat_level = threat_result.threat_level or 0
    local confidence = threat_result.confidence or 0

    if threat_level >= 8 or confidence >= 0.9 then
        return "high"
    elseif threat_level >= 5 or confidence >= 0.7 then
        return "medium"
    else
        return "low"
    end
end

---
-- Determine if request should be analyzed based on sampling rules
-- @param risk_level Risk level of the request
-- @param conf Plugin configuration
-- @return Boolean whether to analyze
---
function _M.should_analyze_request(risk_level, conf)
    -- Always analyze if cost optimization is disabled
    if not conf.ai_cost_optimization_enabled then
        return true
    end

    local sampling_rate = COST_OPTIMIZATION.sampling_rate[risk_level] or 1.0
    local random_value = math.random()

    return random_value <= sampling_rate
end

---
-- Select optimal AI model based on analysis requirements and performance
-- @param analysis_type Type of analysis required
-- @param risk_level Risk level of the request
-- @param conf Plugin configuration
-- @return Table selected model configuration or nil
---
function _M.select_optimal_model(analysis_type, risk_level, conf)
    local available_models = {}

    -- Get available models with current performance metrics
    for model_name, model_config in pairs(AI_MODELS) do
        if conf["ai_" .. string.lower(model_name) .. "_enabled"] then
            local perf_data = model_performance_cache:get("perf_" .. model_name)
            if perf_data and perf_data.error_count < 5 then -- Model is healthy
                table.insert(available_models, {
                    name = model_name,
                    config = model_config,
                    performance = perf_data
                })
            end
        end
    end

    if #available_models == 0 then
        return nil
    end

    -- Select model based on analysis type and performance
    return _M.select_best_model(available_models, analysis_type, risk_level)
end

---
-- Select the best model based on analysis requirements and performance
-- @param available_models Array of available models
-- @param analysis_type Type of analysis required
-- @param risk_level Risk level of the request
-- @return Table selected model
---
function _M.select_best_model(available_models, analysis_type, risk_level)
    -- For high-risk requests, prefer most reliable model
    if risk_level == "high" then
        table.sort(available_models, function(a, b)
            return a.config.reliability > b.config.reliability
        end)
        return available_models[1]
    end

    -- For comprehensive analysis, prefer most capable model
    if analysis_type == "comprehensive" then
        -- Prefer Claude for comprehensive analysis (best reasoning)
        for _, model in ipairs(available_models) do
            if model.name == "CLAUDE" then
                return model
            end
        end
    end

    -- For cost-sensitive requests, prefer most cost-effective model
    table.sort(available_models, function(a, b)
        local cost_a = a.config.cost_per_token * (a.performance.avg_latency / 1000)
        local cost_b = b.config.cost_per_token * (b.performance.avg_latency / 1000)
        return cost_a < cost_b
    end)

    return available_models[1]
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
-- Enhanced AI model calling with multi-model support and failover
-- @param prompt AI analysis prompt
-- @param selected_model Selected model configuration
-- @param conf Plugin configuration
-- @return String AI response or nil
---
function _M.call_ai_model(prompt, selected_model, conf)
    local start_time = ngx.now() * 1000
    local httpc = http.new()
    httpc:set_timeout(conf.ai_timeout_ms or 10000)

    -- Build model-specific request
    local ai_request = _M.build_model_request(prompt, selected_model, conf)
    local endpoint = _M.get_model_endpoint(selected_model.name, conf)
    local headers = _M.get_model_headers(selected_model.name, conf)

    local res, err = httpc:request_uri(endpoint, {
        method = "POST",
        headers = headers,
        body = json.encode(ai_request),
        ssl_verify = conf.ai_ssl_verify or false
    })

    local latency = ngx.now() * 1000 - start_time

    if not res then
        kong.log.error("[Kong Guard AI Gateway] %s model request failed: %s", selected_model.name, err or "unknown error")
        _M.record_model_error(selected_model.name, latency)

        -- Try failover to next best model
        return _M.try_failover_model(prompt, selected_model, conf)
    end

    if res.status ~= 200 then
        kong.log.error("[Kong Guard AI Gateway] %s model returned status: %d", selected_model.name, res.status)
        kong.log.debug("[Kong Guard AI Gateway] Response body: %s", res.body or "empty")
        _M.record_model_error(selected_model.name, latency)

        -- Try failover to next best model
        return _M.try_failover_model(prompt, selected_model, conf)
    end

    -- Record successful request
    _M.record_model_success(selected_model.name, latency)

    return res.body
end

---
-- Build model-specific request payload
-- @param prompt Analysis prompt
-- @param selected_model Selected model configuration
-- @param conf Plugin configuration
-- @return Table request payload
---
function _M.build_model_request(prompt, selected_model, conf)
    local base_request = {
        messages = {
            {
                role = "system",
                content = "You are an expert cybersecurity analyst. Analyze HTTP requests for security threats with high precision. Always respond in valid JSON format."
            },
            {
                role = "user",
                content = prompt
            }
        },
        max_tokens = selected_model.config.max_tokens,
        temperature = selected_model.config.temperature
    }

    -- Add model-specific configuration
    if selected_model.name == "GPT4" then
        base_request.model = "gpt-4-turbo"
        base_request.response_format = { type = "json_object" }
    elseif selected_model.name == "CLAUDE" then
        base_request.model = "claude-3-sonnet-20240229"
        base_request.anthropic_version = "2023-06-01"
    elseif selected_model.name == "GEMINI" then
        base_request.model = "gemini-1.5-pro"
        base_request.generationConfig = {
            temperature = selected_model.config.temperature,
            maxOutputTokens = selected_model.config.max_tokens
        }
    end

    return base_request
end

---
-- Get model-specific endpoint
-- @param model_name Name of the model
-- @param conf Plugin configuration
-- @return String endpoint URL
---
function _M.get_model_endpoint(model_name, conf)
    if model_name == "GPT4" then
        return conf.openai_endpoint or "https://api.openai.com/v1/chat/completions"
    elseif model_name == "CLAUDE" then
        return conf.anthropic_endpoint or "https://api.anthropic.com/v1/messages"
    elseif model_name == "GEMINI" then
        return conf.gemini_endpoint or "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
    else
        return conf.ai_gateway_endpoint
    end
end

---
-- Get model-specific headers
-- @param model_name Name of the model
-- @param conf Plugin configuration
-- @return Table headers
---
function _M.get_model_headers(model_name, conf)
    local headers = {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "Kong-Guard-AI/0.1.0"
    }

    if model_name == "GPT4" and conf.openai_api_key then
        headers["Authorization"] = "Bearer " .. conf.openai_api_key
    elseif model_name == "CLAUDE" and conf.anthropic_api_key then
        headers["x-api-key"] = conf.anthropic_api_key
        headers["anthropic-version"] = "2023-06-01"
    elseif model_name == "GEMINI" and conf.gemini_api_key then
        headers["x-goog-api-key"] = conf.gemini_api_key
    elseif conf.ai_gateway_api_key then
        headers["Authorization"] = "Bearer " .. conf.ai_gateway_api_key
    end

    return headers
end

---
-- Try failover to next best available model
-- @param prompt Analysis prompt
-- @param failed_model Failed model configuration
-- @param conf Plugin configuration
-- @return String AI response or nil
---
function _M.try_failover_model(prompt, failed_model, conf)
    kong.log.warn("[Kong Guard AI Gateway] Attempting failover from %s model", failed_model.name)

    -- Find next best model (excluding the failed one)
    local available_models = {}
    for model_name, model_config in pairs(AI_MODELS) do
        if model_name ~= failed_model.name and conf["ai_" .. string.lower(model_name) .. "_enabled"] then
            local perf_data = model_performance_cache:get("perf_" .. model_name)
            if perf_data and perf_data.error_count < 3 then
                table.insert(available_models, {
                    name = model_name,
                    config = model_config,
                    performance = perf_data
                })
            end
        end
    end

    if #available_models == 0 then
        kong.log.error("[Kong Guard AI Gateway] No failover models available")
        return nil
    end

    -- Select most reliable model for failover
    table.sort(available_models, function(a, b)
        return a.config.reliability > b.config.reliability
    end)

    local failover_model = available_models[1]
    kong.log.info("[Kong Guard AI Gateway] Using failover model: %s", failover_model.name)

    -- Recursive call with failover model (prevent infinite recursion)
    if not failover_model._failover_attempt then
        failover_model._failover_attempt = true
        return _M.call_ai_model(prompt, failover_model, conf)
    end

    return nil
end

---
-- Legacy function for backward compatibility
-- @param prompt AI analysis prompt
-- @param conf Plugin configuration
-- @return String AI response or nil
---
function _M.call_ai_gateway(prompt, conf)
    -- Use default model for legacy calls
    local default_model = {
        name = "GPT4",
        config = AI_MODELS.GPT4
    }

    return _M.call_ai_model(prompt, default_model, conf)
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
