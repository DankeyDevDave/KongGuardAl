-- Security Orchestrator for Kong Guard AI
-- Coordinates all security modules and implements comprehensive security policies
-- Addresses security hardening requirements from specification 004

local RateLimiter = require "kong.plugins.kong-guard-ai.modules.security.rate_limiter"
local RequestValidator = require "kong.plugins.kong-guard-ai.modules.security.request_validator"
local AuthManager = require "kong.plugins.kong-guard-ai.modules.security.auth_manager"
local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local SecurityOrchestrator = {}
SecurityOrchestrator.__index = SecurityOrchestrator

-- Security policy levels
local SECURITY_LEVELS = {
    PERMISSIVE = "permissive",
    STANDARD = "standard",
    STRICT = "strict",
    PARANOID = "paranoid"
}

-- Security action types
local SECURITY_ACTIONS = {
    ALLOW = "allow",
    WARN = "warn",
    BLOCK = "block",
    RATE_LIMIT = "rate_limit",
    REQUIRE_AUTH = "require_auth"
}

--- Initialize security orchestrator
-- @param config table security configuration
function SecurityOrchestrator.new(config)
    local self = setmetatable({}, SecurityOrchestrator)

    self.config = config or {}
    self.security_level = self.config.security_level or SECURITY_LEVELS.STANDARD
    self.enabled_modules = self.config.enabled_modules or {
        "rate_limiter",
        "request_validator",
        "auth_manager"
    }

    -- Initialize security modules
    self.modules = {}

    if self:_is_module_enabled("rate_limiter") then
        self.modules.rate_limiter = RateLimiter.new(self.config.rate_limiter or {})
    end

    if self:_is_module_enabled("request_validator") then
        self.modules.request_validator = RequestValidator.new(self.config.request_validator or {})
    end

    if self:_is_module_enabled("auth_manager") then
        self.modules.auth_manager = AuthManager.new(self.config.auth_manager or {})
    end

    -- Security policies based on level
    self.policies = self:_initialize_security_policies()

    -- Security headers configuration
    self.security_headers = self.config.security_headers or self:_get_default_security_headers()

    -- CORS configuration
    self.cors_config = self.config.cors or {
        enabled = false,
        allowed_origins = {},
        allowed_methods = {"GET", "POST", "PUT", "DELETE"},
        allowed_headers = {"Content-Type", "Authorization"},
        max_age = 3600
    }

    -- Statistics and monitoring
    self.stats = {
        total_requests = 0,
        blocked_requests = 0,
        security_incidents = {},
        policy_violations = {},
        response_times = {}
    }

    return self
end

--- Process request through security pipeline
-- @param request table request object
-- @return boolean allowed
-- @return table security_result (comprehensive security analysis)
function SecurityOrchestrator:process_request(request)
    local security_result = {
        allowed = true,
        action = SECURITY_ACTIONS.ALLOW,
        security_level = self.security_level,
        modules_executed = {},
        violations = {},
        warnings = {},
        auth_result = nil,
        rate_limit_result = nil,
        validation_result = nil,
        risk_score = 0,
        processing_time = 0,
        security_headers = {},
        cors_headers = {}
    }

    local start_time = performance_utils.get_time()

    self.stats.total_requests = self.stats.total_requests + 1

    -- 1. Rate Limiting Check
    if self.modules.rate_limiter then
        local rate_limited, rate_info = self.modules.rate_limiter:should_limit(request)
        security_result.rate_limit_result = rate_info

        if rate_limited then
            security_result.allowed = false
            security_result.action = SECURITY_ACTIONS.RATE_LIMIT
            table.insert(security_result.violations, {
                module = "rate_limiter",
                severity = "high",
                message = "Rate limit exceeded",
                details = rate_info
            })
            security_result.risk_score = security_result.risk_score + 30
        else
            -- Record the request for rate limiting tracking
            self.modules.rate_limiter:record_request(request)
        end

        table.insert(security_result.modules_executed, "rate_limiter")
    end

    -- 2. Request Validation
    if self.modules.request_validator then
        local valid, validation_info = self.modules.request_validator:validate_request(request)
        security_result.validation_result = validation_info

        if not valid then
            -- Determine action based on security level and validation errors
            local action = self:_determine_validation_action(validation_info)

            if action == SECURITY_ACTIONS.BLOCK then
                security_result.allowed = false
                security_result.action = SECURITY_ACTIONS.BLOCK
                table.insert(security_result.violations, {
                    module = "request_validator",
                    severity = "high",
                    message = "Request validation failed",
                    details = validation_info
                })
            elseif action == SECURITY_ACTIONS.WARN then
                table.insert(security_result.warnings, {
                    module = "request_validator",
                    severity = "medium",
                    message = "Request validation warnings",
                    details = validation_info
                })
            end
        end

        security_result.risk_score = security_result.risk_score + (validation_info.risk_score or 0)
        table.insert(security_result.modules_executed, "request_validator")
    end

    -- 3. Authentication & Authorization
    if self.modules.auth_manager then
        local authenticated, auth_info = self.modules.auth_manager:authenticate_request(request)
        security_result.auth_result = auth_info

        if not authenticated and self:_requires_authentication(request) then
            security_result.allowed = false
            security_result.action = SECURITY_ACTIONS.REQUIRE_AUTH
            table.insert(security_result.violations, {
                module = "auth_manager",
                severity = "high",
                message = "Authentication required",
                details = auth_info
            })
            security_result.risk_score = security_result.risk_score + 25
        end

        -- Authorization check for authenticated requests
        if authenticated then
            local authorized, authz_info = self.modules.auth_manager:check_authorization(
                auth_info,
                request.path or request.uri,
                request.method
            )

            if not authorized then
                security_result.allowed = false
                security_result.action = SECURITY_ACTIONS.BLOCK
                table.insert(security_result.violations, {
                    module = "auth_manager",
                    severity = "high",
                    message = "Authorization failed",
                    details = authz_info
                })
                security_result.risk_score = security_result.risk_score + 20
            end
        end

        table.insert(security_result.modules_executed, "auth_manager")
    end

    -- 4. Apply Security Policies
    self:_apply_security_policies(request, security_result)

    -- 5. Generate Security Headers
    security_result.security_headers = self:_generate_security_headers(request, security_result)

    -- 6. Handle CORS
    if self.cors_config.enabled then
        security_result.cors_headers = self:_generate_cors_headers(request)
    end

    -- 7. Calculate final risk score and action
    self:_finalize_security_decision(security_result)

    security_result.processing_time = performance_utils.get_time() - start_time

    -- Update statistics
    self:_update_security_statistics(security_result)

    return security_result.allowed, security_result
end

--- Initialize security policies based on security level
-- @return table security policies
function SecurityOrchestrator:_initialize_security_policies()
    local policies = {}

    if self.security_level == SECURITY_LEVELS.PERMISSIVE then
        policies = {
            block_on_validation_errors = false,
            require_auth_for_ai_endpoints = false,
            strict_rate_limiting = false,
            block_suspicious_user_agents = false,
            max_risk_score_threshold = 80
        }
    elseif self.security_level == SECURITY_LEVELS.STANDARD then
        policies = {
            block_on_validation_errors = true,
            require_auth_for_ai_endpoints = true,
            strict_rate_limiting = false,
            block_suspicious_user_agents = false,
            max_risk_score_threshold = 60
        }
    elseif self.security_level == SECURITY_LEVELS.STRICT then
        policies = {
            block_on_validation_errors = true,
            require_auth_for_ai_endpoints = true,
            strict_rate_limiting = true,
            block_suspicious_user_agents = true,
            max_risk_score_threshold = 40
        }
    elseif self.security_level == SECURITY_LEVELS.PARANOID then
        policies = {
            block_on_validation_errors = true,
            require_auth_for_ai_endpoints = true,
            strict_rate_limiting = true,
            block_suspicious_user_agents = true,
            max_risk_score_threshold = 20,
            block_unknown_user_agents = true,
            require_tls = true
        }
    end

    -- Merge with custom policies
    if self.config.custom_policies then
        for key, value in pairs(self.config.custom_policies) do
            policies[key] = value
        end
    end

    return policies
end

--- Apply security policies to the request
-- @param request table request object
-- @param security_result table security result to update
function SecurityOrchestrator:_apply_security_policies(request, security_result)
    -- Policy: Block on high risk score
    if security_result.risk_score >= self.policies.max_risk_score_threshold then
        security_result.allowed = false
        security_result.action = SECURITY_ACTIONS.BLOCK
        table.insert(security_result.violations, {
            module = "security_policies",
            severity = "high",
            message = "Risk score exceeds threshold",
            risk_score = security_result.risk_score,
            threshold = self.policies.max_risk_score_threshold
        })
    end

    -- Policy: Require TLS
    if self.policies.require_tls then
        local is_https = request.scheme == "https" or
                        (request.headers and request.headers["x-forwarded-proto"] == "https")

        if not is_https then
            security_result.allowed = false
            security_result.action = SECURITY_ACTIONS.BLOCK
            table.insert(security_result.violations, {
                module = "security_policies",
                severity = "high",
                message = "TLS required for all requests"
            })
        end
    end

    -- Policy: Block unknown user agents
    if self.policies.block_unknown_user_agents then
        local user_agent = request.headers and request.headers["user-agent"]
        if not user_agent or string.len(user_agent) < 10 then
            security_result.allowed = false
            security_result.action = SECURITY_ACTIONS.BLOCK
            table.insert(security_result.violations, {
                module = "security_policies",
                severity = "medium",
                message = "Unknown or missing user agent"
            })
        end
    end

    -- Policy: AI endpoint protection
    if self.policies.require_auth_for_ai_endpoints then
        local path = request.path or request.uri
        if path and string.find(path, "^/ai/") then
            if not security_result.auth_result or not security_result.auth_result.authenticated then
                security_result.allowed = false
                security_result.action = SECURITY_ACTIONS.REQUIRE_AUTH
                table.insert(security_result.violations, {
                    module = "security_policies",
                    severity = "high",
                    message = "Authentication required for AI endpoints"
                })
            end
        end
    end
end

--- Determine action for validation errors
-- @param validation_result table validation result
-- @return string action
function SecurityOrchestrator:_determine_validation_action(validation_result)
    -- Check for attack patterns - always block
    if validation_result.attack_patterns_detected and #validation_result.attack_patterns_detected > 0 then
        return SECURITY_ACTIONS.BLOCK
    end

    -- Check risk score
    if validation_result.risk_score >= 50 then
        return SECURITY_ACTIONS.BLOCK
    elseif validation_result.risk_score >= 25 then
        return SECURITY_ACTIONS.WARN
    end

    -- Check errors based on security level
    if validation_result.errors and #validation_result.errors > 0 then
        if self.policies.block_on_validation_errors then
            return SECURITY_ACTIONS.BLOCK
        else
            return SECURITY_ACTIONS.WARN
        end
    end

    return SECURITY_ACTIONS.ALLOW
end

--- Check if request requires authentication
-- @param request table request object
-- @return boolean requires_auth
function SecurityOrchestrator:_requires_authentication(request)
    local path = request.path or request.uri

    -- AI endpoints always require authentication in standard+ mode
    if path and string.find(path, "^/ai/") and
       self.security_level ~= SECURITY_LEVELS.PERMISSIVE then
        return true
    end

    -- Admin endpoints require authentication
    if path and string.find(path, "^/admin/") then
        return true
    end

    -- Configuration endpoints require authentication for write operations
    if path and string.find(path, "^/config/") and
       request.method and request.method ~= "GET" then
        return true
    end

    -- Check auth manager configuration
    if self.modules.auth_manager and self.modules.auth_manager.require_auth then
        return true
    end

    return false
end

--- Generate security headers
-- @param request table request object
-- @param security_result table security result
-- @return table headers
function SecurityOrchestrator:_generate_security_headers(request, security_result)
    local headers = {}

    -- Apply configured security headers
    for header_name, header_value in pairs(self.security_headers) do
        headers[header_name] = header_value
    end

    -- Add security-specific headers
    headers["X-Kong-Guard-AI"] = "enabled"
    headers["X-Security-Level"] = self.security_level
    headers["X-Risk-Score"] = tostring(security_result.risk_score)

    -- Rate limiting headers
    if security_result.rate_limit_result then
        headers["X-RateLimit-Limit"] = tostring(security_result.rate_limit_result.limit or 0)
        headers["X-RateLimit-Remaining"] = tostring(security_result.rate_limit_result.remaining or 0)
        headers["X-RateLimit-Reset"] = tostring(security_result.rate_limit_result.reset_time or 0)
    end

    -- Authentication headers
    if security_result.auth_result and security_result.auth_result.authenticated then
        headers["X-Auth-Method"] = security_result.auth_result.method_used or "unknown"
        headers["X-Auth-Level"] = tostring(security_result.auth_result.auth_level or 0)
    end

    return headers
end

--- Generate CORS headers
-- @param request table request object
-- @return table cors_headers
function SecurityOrchestrator:_generate_cors_headers(request)
    local headers = {}
    local origin = request.headers and request.headers.origin

    -- Check if origin is allowed
    local allowed_origin = self:_is_origin_allowed(origin)

    if allowed_origin then
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Methods"] = table.concat(self.cors_config.allowed_methods, ", ")
        headers["Access-Control-Allow-Headers"] = table.concat(self.cors_config.allowed_headers, ", ")
        headers["Access-Control-Max-Age"] = tostring(self.cors_config.max_age)

        -- Allow credentials if origin is specifically allowed (not wildcard)
        if origin ~= "*" then
            headers["Access-Control-Allow-Credentials"] = "true"
        end
    end

    return headers
end

--- Check if origin is allowed for CORS
-- @param origin string request origin
-- @return boolean allowed
function SecurityOrchestrator:_is_origin_allowed(origin)
    if not origin then
        return false
    end

    -- Check against allowed origins list
    for _, allowed_origin in ipairs(self.cors_config.allowed_origins) do
        if allowed_origin == "*" or allowed_origin == origin then
            return true
        end

        -- Check for wildcard patterns (e.g., *.example.com)
        if string.find(allowed_origin, "*") then
            local pattern = string.gsub(allowed_origin, "*", ".*")
            if string.match(origin, "^" .. pattern .. "$") then
                return true
            end
        end
    end

    return false
end

--- Finalize security decision
-- @param security_result table security result to update
function SecurityOrchestrator:_finalize_security_decision(security_result)
    -- If any module blocked the request, final decision is block
    if not security_result.allowed then
        return
    end

    -- Check if warnings should be escalated to blocks
    if self.security_level == SECURITY_LEVELS.PARANOID and #security_result.warnings > 0 then
        security_result.allowed = false
        security_result.action = SECURITY_ACTIONS.BLOCK
        table.insert(security_result.violations, {
            module = "security_orchestrator",
            severity = "high",
            message = "Warnings escalated to block in paranoid mode",
            warning_count = #security_result.warnings
        })
    end
end

--- Get default security headers
-- @return table default headers
function SecurityOrchestrator:_get_default_security_headers()
    return {
        ["X-Content-Type-Options"] = "nosniff",
        ["X-Frame-Options"] = "DENY",
        ["X-XSS-Protection"] = "1; mode=block",
        ["Referrer-Policy"] = "strict-origin-when-cross-origin",
        ["Content-Security-Policy"] = "default-src 'self'",
        ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    }
end

--- Check if security module is enabled
-- @param module_name string module name
-- @return boolean enabled
function SecurityOrchestrator:_is_module_enabled(module_name)
    for _, enabled_module in ipairs(self.enabled_modules) do
        if enabled_module == module_name then
            return true
        end
    end
    return false
end

--- Update security statistics
-- @param security_result table security result
function SecurityOrchestrator:_update_security_statistics(security_result)
    -- Track blocked requests
    if not security_result.allowed then
        self.stats.blocked_requests = self.stats.blocked_requests + 1
    end

    -- Track security incidents by type
    for _, violation in ipairs(security_result.violations) do
        local incident_type = violation.module .. ":" .. (violation.message or "unknown")
        if not self.stats.security_incidents[incident_type] then
            self.stats.security_incidents[incident_type] = 0
        end
        self.stats.security_incidents[incident_type] = self.stats.security_incidents[incident_type] + 1
    end

    -- Track policy violations
    for _, violation in ipairs(security_result.violations) do
        if violation.module == "security_policies" then
            local policy_name = violation.message or "unknown"
            if not self.stats.policy_violations[policy_name] then
                self.stats.policy_violations[policy_name] = 0
            end
            self.stats.policy_violations[policy_name] = self.stats.policy_violations[policy_name] + 1
        end
    end

    -- Track response times
    table.insert(self.stats.response_times, security_result.processing_time)

    -- Keep only last 1000 response times for memory efficiency
    if #self.stats.response_times > 1000 then
        table.remove(self.stats.response_times, 1)
    end
end

--- Get comprehensive security statistics
-- @return table statistics
function SecurityOrchestrator:get_statistics()
    local stats = {
        total_requests = self.stats.total_requests,
        blocked_requests = self.stats.blocked_requests,
        block_rate = self.stats.total_requests > 0 and
                     (self.stats.blocked_requests / self.stats.total_requests) or 0,
        security_level = self.security_level,
        enabled_modules = self.enabled_modules,
        security_incidents = self.stats.security_incidents,
        policy_violations = self.stats.policy_violations,
        average_processing_time = self:_calculate_average_processing_time(),
        module_stats = {}
    }

    -- Get statistics from individual modules
    if self.modules.rate_limiter then
        stats.module_stats.rate_limiter = self.modules.rate_limiter:get_statistics()
    end

    if self.modules.request_validator then
        stats.module_stats.request_validator = self.modules.request_validator:get_statistics()
    end

    if self.modules.auth_manager then
        stats.module_stats.auth_manager = self.modules.auth_manager:get_statistics()
    end

    return stats
end

--- Calculate average processing time
-- @return number average time in seconds
function SecurityOrchestrator:_calculate_average_processing_time()
    if #self.stats.response_times == 0 then
        return 0
    end

    local total = 0
    for _, time in ipairs(self.stats.response_times) do
        total = total + time
    end

    return total / #self.stats.response_times
end

--- Reset security statistics
function SecurityOrchestrator:reset_statistics()
    self.stats = {
        total_requests = 0,
        blocked_requests = 0,
        security_incidents = {},
        policy_violations = {},
        response_times = {}
    }

    -- Reset module statistics
    if self.modules.rate_limiter and self.modules.rate_limiter.clear_data then
        self.modules.rate_limiter:clear_data()
    end

    if self.modules.request_validator and self.modules.request_validator.reset_statistics then
        self.modules.request_validator:reset_statistics()
    end
end

--- Create security incident report
-- @param time_period number seconds to look back (default: 3600 = 1 hour)
-- @return table incident report
function SecurityOrchestrator:create_incident_report(time_period)
    time_period = time_period or 3600

    local report = {
        report_time = os.time(),
        time_period = time_period,
        summary = {
            total_requests = self.stats.total_requests,
            blocked_requests = self.stats.blocked_requests,
            block_rate = self.stats.total_requests > 0 and
                         (self.stats.blocked_requests / self.stats.total_requests) or 0
        },
        top_incidents = {},
        recommendations = {}
    }

    -- Get top security incidents
    local incident_counts = {}
    for incident_type, count in pairs(self.stats.security_incidents) do
        table.insert(incident_counts, {type = incident_type, count = count})
    end

    table.sort(incident_counts, function(a, b) return a.count > b.count end)

    for i = 1, math.min(10, #incident_counts) do
        table.insert(report.top_incidents, incident_counts[i])
    end

    -- Generate recommendations
    if self.stats.blocked_requests > self.stats.total_requests * 0.1 then
        table.insert(report.recommendations,
            "High block rate detected. Consider reviewing security policies.")
    end

    if self.stats.policy_violations["Risk score exceeds threshold"] and
       self.stats.policy_violations["Risk score exceeds threshold"] > 10 then
        table.insert(report.recommendations,
            "Frequent risk score violations. Consider adjusting risk thresholds.")
    end

    return report
end

return SecurityOrchestrator
