-- Kong Guard AI - Enterprise AI Engine
local cjson = require "cjson"
local http = require "resty.http"

local AIEngine = {}
AIEngine.__index = AIEngine

-- Initialize AI Engine
function AIEngine:new(config)
    local self = setmetatable({}, AIEngine)
    self.config = config
    self.model = config.ai_model or "claude-3-haiku"
    self.temperature = config.ai_temperature or 0.1
    self.api_key = config.ai_api_key or os.getenv("AI_API_KEY")
    self.endpoint = config.ai_endpoint
    
    -- Initialize threat intelligence database
    self.threat_intelligence = {
        known_patterns = {},
        learned_threats = {},
        false_positives = {},
        confidence_adjustments = {}
    }
    
    return self
end

-- Analyze request using AI model
function AIEngine:analyze_threat(features, context)
    -- Build comprehensive analysis prompt
    local prompt = self:build_analysis_prompt(features, context)
    
    -- Call AI model for analysis
    local ai_response = self:call_ai_model(prompt)
    
    -- Parse and validate AI response
    local threat_analysis = self:parse_ai_response(ai_response)
    
    -- Apply confidence adjustments based on learning
    threat_analysis = self:apply_confidence_adjustments(threat_analysis)
    
    return threat_analysis
end

-- Build analysis prompt for AI model
function AIEngine:build_analysis_prompt(features, context)
    local prompt = {
        system = [[You are an advanced security AI analyzing HTTP requests for threats.
Analyze the following request and provide a threat assessment.
Return a JSON object with:
- threat_score: 0.0 to 1.0 (confidence of threat)
- threat_type: specific threat category
- reasoning: brief explanation
- recommended_action: block/rate_limit/monitor/allow
- confidence: your confidence in this assessment (0-1)
- indicators: list of specific threat indicators found]],
        
        user = string.format([[
Analyze this HTTP request for security threats:

Request Details:
- Method: %s
- Path: %s
- Client IP: %s
- User Agent: %s
- Request Rate: %d requests/minute
- Content Length: %d bytes
- Query Parameters: %d
- Headers Count: %d
- Time: %s (hour %d)

Request Content:
%s

Historical Context:
- Previous requests from IP: %d
- Failed auth attempts: %d
- Anomaly score: %.2f

Identify any:
1. SQL injection attempts
2. XSS (Cross-site scripting)
3. Path traversal
4. Command injection
5. DDoS patterns
6. Credential stuffing
7. API abuse
8. Zero-day exploits
9. Suspicious behavioral patterns

Provide detailed threat analysis.]],
            features.method,
            features.path,
            features.client_ip,
            features.user_agent,
            features.requests_per_minute,
            features.content_length,
            features.query_param_count,
            features.header_count,
            os.date("%Y-%m-%d %H:%M:%S"),
            features.hour_of_day,
            self:get_request_content(features),
            context.previous_requests or 0,
            context.failed_attempts or 0,
            context.anomaly_score or 0
        )
    }
    
    return prompt
end

-- Call AI model API
function AIEngine:call_ai_model(prompt)
    local httpc = http.new()
    httpc:set_timeout(5000) -- 5 second timeout
    
    local request_body = {}
    local headers = {}
    
    -- Configure based on model type
    if self.model:match("claude") then
        -- Anthropic Claude API
        request_body = {
            model = self.model,
            messages = {
                {role = "system", content = prompt.system},
                {role = "user", content = prompt.user}
            },
            max_tokens = 500,
            temperature = self.temperature
        }
        headers = {
            ["Content-Type"] = "application/json",
            ["X-API-Key"] = self.api_key,
            ["anthropic-version"] = "2023-06-01"
        }
        self.endpoint = self.endpoint or "https://api.anthropic.com/v1/messages"
        
    elseif self.model:match("gpt") then
        -- OpenAI GPT API
        request_body = {
            model = self.model,
            messages = {
                {role = "system", content = prompt.system},
                {role = "user", content = prompt.user}
            },
            max_tokens = 500,
            temperature = self.temperature,
            response_format = { type = "json_object" }
        }
        headers = {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer " .. self.api_key
        }
        self.endpoint = self.endpoint or "https://api.openai.com/v1/chat/completions"
        
    elseif self.model:match("gemini") then
        -- Google Gemini API
        request_body = {
            contents = {
                {
                    parts = {
                        {text = prompt.system .. "\n\n" .. prompt.user}
                    }
                }
            },
            generationConfig = {
                temperature = self.temperature,
                topP = 0.1,
                topK = 1,
                maxOutputTokens = 1024,
                responseMimeType = "application/json"
            },
            safetySettings = {
                {
                    category = "HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold = "BLOCK_NONE"
                }
            }
        }
        headers = {
            ["Content-Type"] = "application/json"
        }
        self.endpoint = self.endpoint or "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key=" .. self.api_key
        
    elseif self.model:match("llama") then
        -- Local Llama model or custom endpoint
        request_body = {
            prompt = prompt.system .. "\n\n" .. prompt.user,
            max_tokens = 500,
            temperature = self.temperature
        }
        headers = {
            ["Content-Type"] = "application/json"
        }
        self.endpoint = self.endpoint or "http://localhost:11434/api/generate"
    end
    
    -- For testing without API key, return mock response
    if not self.api_key or self.api_key == "" then
        return self:mock_ai_response(prompt.user)
    end
    
    -- Make API request
    local res, err = httpc:request_uri(self.endpoint, {
        method = "POST",
        body = cjson.encode(request_body),
        headers = headers
    })
    
    if not res then
        kong.log.err("AI API request failed: ", err)
        -- Fallback to rule-based detection
        return self:fallback_analysis(prompt.user)
    end
    
    return res.body
end

-- Parse AI model response
function AIEngine:parse_ai_response(response)
    local ok, parsed = pcall(cjson.decode, response)
    if not ok then
        kong.log.err("Failed to parse AI response: ", response)
        return self:default_threat_analysis()
    end
    
    -- Extract threat analysis from model response
    local analysis = {}
    
    if parsed.choices and parsed.choices[1] then
        -- OpenAI format
        local content = parsed.choices[1].message.content
        local threat_data = cjson.decode(content)
        analysis = threat_data
        
    elseif parsed.content and parsed.content[1] then
        -- Claude format
        local content = parsed.content[1].text
        local threat_data = cjson.decode(content)
        analysis = threat_data
        
    elseif parsed.candidates and parsed.candidates[1] then
        -- Gemini format
        local content = parsed.candidates[1].content.parts[1].text
        local threat_data = cjson.decode(content)
        analysis = threat_data
        
    elseif parsed.response then
        -- Custom format
        local threat_data = cjson.decode(parsed.response)
        analysis = threat_data
    else
        -- Direct JSON response
        analysis = parsed
    end
    
    -- Ensure required fields
    analysis.threat_score = analysis.threat_score or 0
    analysis.threat_type = analysis.threat_type or "none"
    analysis.reasoning = analysis.reasoning or "No specific threats detected"
    analysis.recommended_action = analysis.recommended_action or "allow"
    analysis.confidence = analysis.confidence or 0.5
    analysis.indicators = analysis.indicators or {}
    
    return analysis
end

-- Mock AI response for testing
function AIEngine:mock_ai_response(prompt)
    -- Simulate AI analysis based on patterns in prompt
    local threat_score = 0
    local threat_type = "none"
    local indicators = {}
    local reasoning = ""
    
    -- Check for SQL injection patterns
    if prompt:lower():match("union%s+select") or 
       prompt:lower():match("drop%s+table") or
       prompt:match("'%s*or%s*1%s*=%s*1") then
        threat_score = 0.95
        threat_type = "sql_injection"
        table.insert(indicators, "SQL keywords detected")
        reasoning = "High confidence SQL injection attempt detected with classic patterns"
    
    -- Check for XSS patterns
    elseif prompt:match("<script") or 
           prompt:match("javascript:") or
           prompt:match("onerror%s*=") then
        threat_score = 0.9
        threat_type = "xss"
        table.insert(indicators, "JavaScript execution attempt")
        reasoning = "Cross-site scripting attempt with script injection"
    
    -- Check for path traversal
    elseif prompt:match("%.%./") or prompt:match("/etc/passwd") then
        threat_score = 0.85
        threat_type = "path_traversal"
        table.insert(indicators, "Directory traversal patterns")
        reasoning = "Path traversal attempt to access system files"
    
    -- Check for high request rates (DDoS)
    elseif prompt:match("requests/minute: (%d+)") then
        local rate = tonumber(prompt:match("requests/minute: (%d+)"))
        if rate and rate > 100 then
            threat_score = 0.8
            threat_type = "ddos"
            table.insert(indicators, "Abnormal request rate")
            reasoning = string.format("Request rate of %d/min exceeds normal patterns", rate)
        end
    
    -- Check for suspicious patterns
    elseif prompt:match("Failed auth attempts: (%d+)") then
        local attempts = tonumber(prompt:match("Failed auth attempts: (%d+)"))
        if attempts and attempts > 5 then
            threat_score = 0.75
            threat_type = "credential_stuffing"
            table.insert(indicators, "Multiple failed authentication attempts")
            reasoning = "Potential credential stuffing or brute force attack"
        end
    end
    
    -- Add anomaly detection
    if prompt:match("Anomaly score: ([%d%.]+)") then
        local anomaly = tonumber(prompt:match("Anomaly score: ([%d%.]+)"))
        if anomaly and anomaly > 0.7 then
            threat_score = math.max(threat_score, anomaly)
            if threat_type == "none" then
                threat_type = "anomaly"
            end
            table.insert(indicators, "Behavioral anomaly detected")
            reasoning = reasoning .. ". Unusual request patterns detected."
        end
    end
    
    local recommended_action = "allow"
    if threat_score > 0.8 then
        recommended_action = "block"
    elseif threat_score > 0.6 then
        recommended_action = "rate_limit"
    elseif threat_score > 0.3 then
        recommended_action = "monitor"
    end
    
    local response = {
        threat_score = threat_score,
        threat_type = threat_type,
        reasoning = reasoning ~= "" and reasoning or "Request appears safe",
        recommended_action = recommended_action,
        confidence = threat_score > 0 and 0.85 or 0.95,
        indicators = indicators,
        ai_model = "mock_ai_for_testing"
    }
    
    return cjson.encode(response)
end

-- Fallback to rule-based analysis
function AIEngine:fallback_analysis(prompt)
    kong.log.warn("Falling back to rule-based analysis")
    return self:mock_ai_response(prompt)
end

-- Apply confidence adjustments based on learning
function AIEngine:apply_confidence_adjustments(analysis)
    -- Check if this pattern was previously marked as false positive
    local pattern_key = analysis.threat_type .. ":" .. 
                       string.sub(analysis.reasoning, 1, 50)
    
    if self.threat_intelligence.false_positives[pattern_key] then
        -- Reduce confidence for known false positives
        analysis.threat_score = analysis.threat_score * 0.5
        analysis.confidence = analysis.confidence * 0.7
        analysis.reasoning = analysis.reasoning .. " (Adjusted for known false positive)"
    end
    
    -- Apply learned confidence adjustments
    if self.threat_intelligence.confidence_adjustments[analysis.threat_type] then
        local adjustment = self.threat_intelligence.confidence_adjustments[analysis.threat_type]
        analysis.threat_score = analysis.threat_score * adjustment
    end
    
    return analysis
end

-- Learn from feedback
function AIEngine:learn_from_feedback(threat_data, feedback)
    local pattern_key = threat_data.threat_type .. ":" .. 
                       string.sub(threat_data.reasoning, 1, 50)
    
    if feedback.false_positive then
        self.threat_intelligence.false_positives[pattern_key] = true
        
        -- Adjust future confidence for this threat type
        local current_adjustment = self.threat_intelligence.confidence_adjustments[threat_data.threat_type] or 1.0
        self.threat_intelligence.confidence_adjustments[threat_data.threat_type] = current_adjustment * 0.9
    
    elseif feedback.confirmed_threat then
        -- Increase confidence for confirmed threats
        local current_adjustment = self.threat_intelligence.confidence_adjustments[threat_data.threat_type] or 1.0
        self.threat_intelligence.confidence_adjustments[threat_data.threat_type] = 
            math.min(current_adjustment * 1.1, 1.5)
    end
    
    -- Store learning data
    self.threat_intelligence.learned_threats[pattern_key] = {
        timestamp = ngx.now(),
        feedback = feedback,
        original_score = threat_data.threat_score
    }
end

-- Get request content for analysis
function AIEngine:get_request_content(features)
    local content = ""
    
    -- Add query string
    local query = kong.request.get_raw_query()
    if query and query ~= "" then
        content = content .. "Query: " .. query .. "\n"
    end
    
    -- Add body if present
    local body = kong.request.get_raw_body()
    if body and #body > 0 and #body < 10000 then
        content = content .. "Body: " .. body .. "\n"
    end
    
    -- Add relevant headers
    local headers = kong.request.get_headers()
    local important_headers = {"referer", "origin", "x-forwarded-for", "cookie"}
    for _, header in ipairs(important_headers) do
        if headers[header] then
            content = content .. header .. ": " .. tostring(headers[header]) .. "\n"
        end
    end
    
    return content ~= "" and content or "No content"
end

-- Generate detailed threat explanation
function AIEngine:generate_threat_explanation(threat_analysis)
    local explanation = {
        summary = string.format(
            "Detected %s with %.0f%% confidence",
            threat_analysis.threat_type:gsub("_", " "),
            threat_analysis.confidence * 100
        ),
        details = threat_analysis.reasoning,
        indicators = threat_analysis.indicators,
        recommended_action = threat_analysis.recommended_action,
        threat_score = threat_analysis.threat_score,
        ai_model_used = self.model,
        analysis_timestamp = ngx.now()
    }
    
    return explanation
end

-- Default threat analysis structure
function AIEngine:default_threat_analysis()
    return {
        threat_score = 0,
        threat_type = "none",
        reasoning = "Unable to perform AI analysis",
        recommended_action = "allow",
        confidence = 0,
        indicators = {}
    }
end

return AIEngine