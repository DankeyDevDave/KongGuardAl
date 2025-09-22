-- Request Validator for Kong Guard AI
-- Implements comprehensive request validation and sanitization
-- Addresses security hardening requirements from specification 004

local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local RequestValidator = {}
RequestValidator.__index = RequestValidator

-- Validation rule types
local VALIDATION_TYPES = {
    SIZE_LIMIT = "size_limit",
    CONTENT_TYPE = "content_type",
    HEADER_VALIDATION = "header_validation",
    PATH_VALIDATION = "path_validation",
    QUERY_VALIDATION = "query_validation",
    BODY_VALIDATION = "body_validation",
    RATE_LIMITING = "rate_limiting",
    AUTHENTICATION = "authentication"
}

-- Common attack patterns
local ATTACK_PATTERNS = {
    SQL_INJECTION = {
        "union%s+select",
        "select%s+.*%s+from",
        "'%s*or%s+'",
        "'%s*;%s*drop",
        "'%s*;%s*insert",
        "'%s*;%s*update",
        "'%s*;%s*delete",
        "exec%s*%(",
        "sp_executesql"
    },
    XSS = {
        "<script[^>]*>",
        "</script>",
        "javascript:",
        "vbscript:",
        "on%w+%s*=",
        "expression%s*%(",
        "url%s*%(",
        "<%s*iframe",
        "<%s*object"
    },
    PATH_TRAVERSAL = {
        "%.%./",
        "%.%.\\",
        "/%.%./",
        "\\%.%.\\",
        "%.%.%./",
        "%.%.%.%./",
        "%%2e%%2e%%2f",
        "%%2e%%2e%%5c"
    },
    COMMAND_INJECTION = {
        ";%s*cat%s+",
        ";%s*ls%s+",
        ";%s*pwd",
        ";%s*id",
        ";%s*whoami",
        "|%s*cat%s+",
        "|%s*ls%s+",
        "&&%s*cat%s+",
        "&&%s*ls%s+",
        "`.*`",
        "$%(.*%)"
    }
}

--- Initialize request validator
-- @param config table validation configuration
function RequestValidator.new(config)
    local self = setmetatable({}, RequestValidator)

    self.config = config or {}
    self.rules = self.config.rules or {}
    self.strict_mode = self.config.strict_mode or false
    self.max_request_size = self.config.max_request_size or 10485760 -- 10MB default
    self.max_header_size = self.config.max_header_size or 32768 -- 32KB default
    self.max_query_params = self.config.max_query_params or 100
    self.max_header_count = self.config.max_header_count or 50

    -- Allowed content types
    self.allowed_content_types = self.config.allowed_content_types or {
        "application/json",
        "application/xml",
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data"
    }

    -- Initialize validation statistics
    self.stats = {
        total_requests = 0,
        blocked_requests = 0,
        validation_errors = {},
        attack_attempts = {}
    }

    return self
end

--- Validate incoming request
-- @param request table request object
-- @return boolean valid
-- @return table validation_result (errors, warnings, metadata)
function RequestValidator:validate_request(request)
    local validation_result = {
        valid = true,
        errors = {},
        warnings = {},
        blocked_reasons = {},
        attack_patterns_detected = {},
        validation_time = 0,
        risk_score = 0
    }

    local start_time = performance_utils.get_time()

    self.stats.total_requests = self.stats.total_requests + 1

    -- 1. Size validation
    self:_validate_request_size(request, validation_result)

    -- 2. Header validation
    self:_validate_headers(request, validation_result)

    -- 3. Content type validation
    self:_validate_content_type(request, validation_result)

    -- 4. Path validation
    self:_validate_path(request, validation_result)

    -- 5. Query parameter validation
    self:_validate_query_parameters(request, validation_result)

    -- 6. Body validation
    self:_validate_body(request, validation_result)

    -- 7. Attack pattern detection
    self:_detect_attack_patterns(request, validation_result)

    -- 8. Calculate risk score
    validation_result.risk_score = self:_calculate_risk_score(validation_result)

    -- 9. Apply blocking rules
    if self:_should_block_request(validation_result) then
        validation_result.valid = false
        self.stats.blocked_requests = self.stats.blocked_requests + 1
    end

    validation_result.validation_time = performance_utils.get_time() - start_time

    -- Update statistics
    self:_update_statistics(validation_result)

    return validation_result.valid, validation_result
end

--- Validate request size limits
-- @param request table request object
-- @param result table validation result to update
function RequestValidator:_validate_request_size(request, result)
    -- Check total request size
    local content_length = request.headers and request.headers["content-length"]
    if content_length then
        local size = tonumber(content_length)
        if size and size > self.max_request_size then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.SIZE_LIMIT,
                field = "content-length",
                message = "Request size exceeds maximum allowed size",
                max_size = self.max_request_size,
                actual_size = size
            })
            table.insert(result.blocked_reasons, "Request size too large")
            result.risk_score = result.risk_score + 20
        end
    end

    -- Check individual header sizes
    if request.headers then
        local total_header_size = 0
        local header_count = 0

        for name, value in pairs(request.headers) do
            header_count = header_count + 1
            local header_size = string.len(name) + string.len(tostring(value))
            total_header_size = total_header_size + header_size

            -- Check individual header size
            if header_size > 8192 then -- 8KB per header
                table.insert(result.errors, {
                    type = VALIDATION_TYPES.HEADER_VALIDATION,
                    field = name,
                    message = "Header size too large",
                    max_size = 8192,
                    actual_size = header_size
                })
                result.risk_score = result.risk_score + 10
            end
        end

        -- Check total header size
        if total_header_size > self.max_header_size then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.HEADER_VALIDATION,
                field = "total-headers",
                message = "Total header size exceeds limit",
                max_size = self.max_header_size,
                actual_size = total_header_size
            })
            table.insert(result.blocked_reasons, "Headers too large")
            result.risk_score = result.risk_score + 15
        end

        -- Check header count
        if header_count > self.max_header_count then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.HEADER_VALIDATION,
                field = "header-count",
                message = "Too many headers",
                max_count = self.max_header_count,
                actual_count = header_count
            })
            result.risk_score = result.risk_score + 10
        end
    end
end

--- Validate HTTP headers
-- @param request table request object
-- @param result table validation result to update
function RequestValidator:_validate_headers(request, result)
    if not request.headers then
        return
    end

    -- Required headers validation
    local required_headers = self.config.required_headers or {}
    for _, header_name in ipairs(required_headers) do
        if not request.headers[header_name] then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.HEADER_VALIDATION,
                field = header_name,
                message = "Required header missing"
            })
            result.risk_score = result.risk_score + 5
        end
    end

    -- Forbidden headers validation
    local forbidden_headers = self.config.forbidden_headers or {
        "x-forwarded-host", -- Potential host header injection
        "x-cluster-client-ip" -- Potential IP spoofing
    }
    for _, header_name in ipairs(forbidden_headers) do
        if request.headers[header_name] then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.HEADER_VALIDATION,
                field = header_name,
                message = "Forbidden header present"
            })
            result.risk_score = result.risk_score + 15
        end
    end

    -- Host header validation
    if request.headers.host then
        local host = request.headers.host
        if not self:_validate_host_header(host) then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.HEADER_VALIDATION,
                field = "host",
                message = "Invalid host header format",
                value = host
            })
            result.risk_score = result.risk_score + 20
        end
    end

    -- User-Agent validation
    if request.headers["user-agent"] then
        local user_agent = request.headers["user-agent"]
        if self:_is_suspicious_user_agent(user_agent) then
            table.insert(result.warnings, {
                type = VALIDATION_TYPES.HEADER_VALIDATION,
                field = "user-agent",
                message = "Suspicious user agent detected",
                value = user_agent
            })
            result.risk_score = result.risk_score + 5
        end
    end
end

--- Validate content type
-- @param request table request object
-- @param result table validation result to update
function RequestValidator:_validate_content_type(request, result)
    local content_type = request.headers and request.headers["content-type"]

    if content_type then
        -- Extract main content type (ignore charset, boundary etc.)
        local main_type = string.match(content_type, "^([^;]+)")
        if main_type then
            main_type = string.lower(string.gsub(main_type, "%s+", ""))
        end

        local allowed = false
        for _, allowed_type in ipairs(self.allowed_content_types) do
            if main_type == allowed_type then
                allowed = true
                break
            end
        end

        if not allowed then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.CONTENT_TYPE,
                field = "content-type",
                message = "Unsupported content type",
                value = content_type,
                allowed_types = self.allowed_content_types
            })
            result.risk_score = result.risk_score + 10
        end
    end
end

--- Validate request path
-- @param request table request object
-- @param result table validation result to update
function RequestValidator:_validate_path(request, result)
    local path = request.path or request.uri
    if not path then
        return
    end

    -- Path length validation
    if string.len(path) > 2048 then
        table.insert(result.errors, {
            type = VALIDATION_TYPES.PATH_VALIDATION,
            field = "path",
            message = "Path too long",
            max_length = 2048,
            actual_length = string.len(path)
        })
        result.risk_score = result.risk_score + 10
    end

    -- Path traversal detection
    for _, pattern in ipairs(ATTACK_PATTERNS.PATH_TRAVERSAL) do
        if string.find(string.lower(path), pattern) then
            table.insert(result.attack_patterns_detected, {
                type = "PATH_TRAVERSAL",
                pattern = pattern,
                field = "path",
                value = path
            })
            result.risk_score = result.risk_score + 30
        end
    end

    -- Null byte detection
    if string.find(path, "\0") then
        table.insert(result.errors, {
            type = VALIDATION_TYPES.PATH_VALIDATION,
            field = "path",
            message = "Null byte detected in path"
        })
        result.risk_score = result.risk_score + 25
    end

    -- Invalid characters detection
    local invalid_chars = "[<>\"'%|%*%?]"
    if string.find(path, invalid_chars) then
        table.insert(result.warnings, {
            type = VALIDATION_TYPES.PATH_VALIDATION,
            field = "path",
            message = "Invalid characters in path",
            value = path
        })
        result.risk_score = result.risk_score + 5
    end
end

--- Validate query parameters
-- @param request table request object
-- @param result table validation result to update
function RequestValidator:_validate_query_parameters(request, result)
    local query_params = request.query_params or request.args
    if not query_params then
        return
    end

    local param_count = 0
    local total_query_size = 0

    for key, value in pairs(query_params) do
        param_count = param_count + 1
        local param_size = string.len(key) + string.len(tostring(value))
        total_query_size = total_query_size + param_size

        -- Individual parameter size check
        if param_size > 4096 then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.QUERY_VALIDATION,
                field = key,
                message = "Query parameter too large",
                max_size = 4096,
                actual_size = param_size
            })
            result.risk_score = result.risk_score + 10
        end

        -- Attack pattern detection in parameters
        local combined_value = key .. "=" .. tostring(value)
        self:_check_attack_patterns_in_string(combined_value, "query_param:" .. key, result)
    end

    -- Parameter count validation
    if param_count > self.max_query_params then
        table.insert(result.errors, {
            type = VALIDATION_TYPES.QUERY_VALIDATION,
            field = "param-count",
            message = "Too many query parameters",
            max_count = self.max_query_params,
            actual_count = param_count
        })
        result.risk_score = result.risk_score + 15
    end

    -- Total query size validation
    if total_query_size > 8192 then -- 8KB limit for query string
        table.insert(result.errors, {
            type = VALIDATION_TYPES.QUERY_VALIDATION,
            field = "total-size",
            message = "Query string too large",
            max_size = 8192,
            actual_size = total_query_size
        })
        result.risk_score = result.risk_score + 10
    end
end

--- Validate request body
-- @param request table request object
-- @param result table validation result to update
function RequestValidator:_validate_body(request, result)
    local body = request.body
    if not body then
        return
    end

    local body_str = tostring(body)

    -- Body size already checked in size validation

    -- JSON validation if content type is JSON
    local content_type = request.headers and request.headers["content-type"]
    if content_type and string.find(content_type, "application/json") then
        local success, parsed = pcall(function()
            return require("cjson").decode(body_str)
        end)

        if not success then
            table.insert(result.errors, {
                type = VALIDATION_TYPES.BODY_VALIDATION,
                field = "json-body",
                message = "Invalid JSON format",
                error = parsed
            })
            result.risk_score = result.risk_score + 10
        else
            -- Validate JSON structure
            self:_validate_json_structure(parsed, result)
        end
    end

    -- Attack pattern detection in body
    self:_check_attack_patterns_in_string(body_str, "body", result)

    -- Null byte detection
    if string.find(body_str, "\0") then
        table.insert(result.errors, {
            type = VALIDATION_TYPES.BODY_VALIDATION,
            field = "body",
            message = "Null byte detected in body"
        })
        result.risk_score = result.risk_score + 25
    end
end

--- Detect attack patterns across request
-- @param request table request object
-- @param result table validation result to update
function RequestValidator:_detect_attack_patterns(request, result)
    -- Check all string fields for attack patterns
    local fields_to_check = {
        path = request.path or request.uri,
        user_agent = request.headers and request.headers["user-agent"],
        referer = request.headers and request.headers["referer"],
        origin = request.headers and request.headers["origin"]
    }

    for field_name, field_value in pairs(fields_to_check) do
        if field_value then
            self:_check_attack_patterns_in_string(tostring(field_value), field_name, result)
        end
    end
end

--- Check for attack patterns in a string
-- @param str string string to check
-- @param field_name string name of the field being checked
-- @param result table validation result to update
function RequestValidator:_check_attack_patterns_in_string(str, field_name, result)
    local lower_str = string.lower(str)

    -- SQL Injection detection
    for _, pattern in ipairs(ATTACK_PATTERNS.SQL_INJECTION) do
        if string.find(lower_str, pattern) then
            table.insert(result.attack_patterns_detected, {
                type = "SQL_INJECTION",
                pattern = pattern,
                field = field_name,
                value = str
            })
            result.risk_score = result.risk_score + 40
        end
    end

    -- XSS detection
    for _, pattern in ipairs(ATTACK_PATTERNS.XSS) do
        if string.find(lower_str, pattern) then
            table.insert(result.attack_patterns_detected, {
                type = "XSS",
                pattern = pattern,
                field = field_name,
                value = str
            })
            result.risk_score = result.risk_score + 35
        end
    end

    -- Command Injection detection
    for _, pattern in ipairs(ATTACK_PATTERNS.COMMAND_INJECTION) do
        if string.find(lower_str, pattern) then
            table.insert(result.attack_patterns_detected, {
                type = "COMMAND_INJECTION",
                pattern = pattern,
                field = field_name,
                value = str
            })
            result.risk_score = result.risk_score + 45
        end
    end
end

--- Validate JSON structure for security issues
-- @param json_data table parsed JSON data
-- @param result table validation result to update
function RequestValidator:_validate_json_structure(json_data, result)
    local function check_depth(obj, current_depth)
        if current_depth > 10 then -- Prevent deeply nested JSON DoS
            table.insert(result.errors, {
                type = VALIDATION_TYPES.BODY_VALIDATION,
                field = "json-depth",
                message = "JSON nesting too deep",
                max_depth = 10,
                current_depth = current_depth
            })
            result.risk_score = result.risk_score + 20
            return
        end

        if type(obj) == "table" then
            local count = 0
            for key, value in pairs(obj) do
                count = count + 1

                -- Check for too many properties
                if count > 1000 then
                    table.insert(result.errors, {
                        type = VALIDATION_TYPES.BODY_VALIDATION,
                        field = "json-properties",
                        message = "Too many JSON properties",
                        max_properties = 1000
                    })
                    result.risk_score = result.risk_score + 15
                    break
                end

                -- Recursively check nested objects
                check_depth(value, current_depth + 1)
            end
        end
    end

    check_depth(json_data, 1)
end

--- Calculate overall risk score
-- @param result table validation result
-- @return number risk score (0-100)
function RequestValidator:_calculate_risk_score(result)
    local base_score = result.risk_score

    -- Bonus scoring for multiple attack patterns
    if #result.attack_patterns_detected > 1 then
        base_score = base_score + (#result.attack_patterns_detected * 10)
    end

    -- Bonus scoring for multiple error types
    local error_types = {}
    for _, error in ipairs(result.errors) do
        error_types[error.type] = true
    end

    local unique_error_types = 0
    for _ in pairs(error_types) do
        unique_error_types = unique_error_types + 1
    end

    if unique_error_types > 2 then
        base_score = base_score + (unique_error_types * 5)
    end

    -- Cap at 100
    return math.min(100, base_score)
end

--- Determine if request should be blocked
-- @param result table validation result
-- @return boolean should block
function RequestValidator:_should_block_request(result)
    -- Block if high risk score
    if result.risk_score >= 50 then
        table.insert(result.blocked_reasons, "High risk score: " .. result.risk_score)
        return true
    end

    -- Block if attack patterns detected
    if #result.attack_patterns_detected > 0 then
        table.insert(result.blocked_reasons, "Attack patterns detected")
        return true
    end

    -- Block if critical errors present
    for _, error in ipairs(result.errors) do
        if error.type == VALIDATION_TYPES.SIZE_LIMIT or
           error.type == VALIDATION_TYPES.BODY_VALIDATION then
            table.insert(result.blocked_reasons, "Critical validation error: " .. error.message)
            return true
        end
    end

    -- Block in strict mode if any errors
    if self.strict_mode and #result.errors > 0 then
        table.insert(result.blocked_reasons, "Strict mode: validation errors present")
        return true
    end

    return false
end

--- Validate host header format
-- @param host string host header value
-- @return boolean valid
function RequestValidator:_validate_host_header(host)
    -- Basic host header validation
    -- Should be hostname[:port]
    local pattern = "^[a-zA-Z0-9.-]+(:?[0-9]+)?$"
    return string.match(host, pattern) ~= nil
end

--- Check if user agent is suspicious
-- @param user_agent string user agent string
-- @return boolean suspicious
function RequestValidator:_is_suspicious_user_agent(user_agent)
    local suspicious_patterns = {
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "burp",
        "gobuster",
        "dirb",
        "wfuzz",
        "curl", -- Can be suspicious in some contexts
        "wget",
        "python-requests"
    }

    local lower_ua = string.lower(user_agent)
    for _, pattern in ipairs(suspicious_patterns) do
        if string.find(lower_ua, pattern) then
            return true
        end
    end

    return false
end

--- Update validation statistics
-- @param result table validation result
function RequestValidator:_update_statistics(result)
    -- Update error statistics
    for _, error in ipairs(result.errors) do
        local error_type = error.type
        if not self.stats.validation_errors[error_type] then
            self.stats.validation_errors[error_type] = 0
        end
        self.stats.validation_errors[error_type] = self.stats.validation_errors[error_type] + 1
    end

    -- Update attack pattern statistics
    for _, attack in ipairs(result.attack_patterns_detected) do
        local attack_type = attack.type
        if not self.stats.attack_attempts[attack_type] then
            self.stats.attack_attempts[attack_type] = 0
        end
        self.stats.attack_attempts[attack_type] = self.stats.attack_attempts[attack_type] + 1
    end
end

--- Get validation statistics
-- @return table statistics
function RequestValidator:get_statistics()
    local stats = {
        total_requests = self.stats.total_requests,
        blocked_requests = self.stats.blocked_requests,
        block_rate = self.stats.total_requests > 0 and
                     (self.stats.blocked_requests / self.stats.total_requests) or 0,
        validation_errors = self.stats.validation_errors,
        attack_attempts = self.stats.attack_attempts,
        config = {
            strict_mode = self.strict_mode,
            max_request_size = self.max_request_size,
            max_header_size = self.max_header_size,
            allowed_content_types = self.allowed_content_types
        }
    }

    return stats
end

--- Reset validation statistics
function RequestValidator:reset_statistics()
    self.stats = {
        total_requests = 0,
        blocked_requests = 0,
        validation_errors = {},
        attack_attempts = {}
    }
end

return RequestValidator
