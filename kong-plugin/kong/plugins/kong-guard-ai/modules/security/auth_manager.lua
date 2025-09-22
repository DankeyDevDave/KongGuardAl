-- Authentication Manager for Kong Guard AI
-- Implements enhanced authentication and authorization mechanisms
-- Addresses security hardening requirements from specification 004

local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local AuthManager = {}
AuthManager.__index = AuthManager

-- Authentication methods
local AUTH_METHODS = {
    API_KEY = "api_key",
    JWT = "jwt",
    BASIC = "basic",
    OAUTH = "oauth",
    HMAC = "hmac",
    MUTUAL_TLS = "mutual_tls"
}

-- Authorization levels
local AUTH_LEVELS = {
    NONE = 0,
    READ = 1,
    WRITE = 2,
    ADMIN = 3,
    SUPER_ADMIN = 4
}

-- Token types
local TOKEN_TYPES = {
    ACCESS = "access",
    REFRESH = "refresh",
    API_KEY = "api_key"
}

--- Initialize authentication manager
-- @param config table authentication configuration
function AuthManager.new(config)
    local self = setmetatable({}, AuthManager)

    self.config = config or {}
    self.auth_methods = self.config.auth_methods or {AUTH_METHODS.API_KEY}
    self.require_auth = self.config.require_auth ~= false
    self.strict_mode = self.config.strict_mode or false

    -- JWT configuration
    self.jwt_config = self.config.jwt or {
        secret = self.config.jwt_secret or "default-secret-change-in-production",
        algorithm = "HS256",
        access_token_ttl = 3600,
        refresh_token_ttl = 86400 * 7
    }

    -- API key configuration
    self.api_key_config = self.config.api_key or {
        header_name = "X-API-Key",
        query_param = "api_key",
        prefix = "kg_",
        length = 32
    }

    -- Rate limiting per user/key
    self.auth_rate_limits = self.config.auth_rate_limits or {
        failed_attempts_window = 300, -- 5 minutes
        max_failed_attempts = 5,
        lockout_duration = 900 -- 15 minutes
    }

    -- Storage for authentication data (would use Redis in production)
    self.storage = {
        api_keys = {},
        users = {},
        sessions = {},
        failed_attempts = {},
        blacklisted_tokens = {}
    }

    -- Statistics
    self.stats = {
        total_auth_requests = 0,
        successful_auths = 0,
        failed_auths = 0,
        blocked_attempts = 0,
        auth_methods_used = {}
    }

    return self
end

--- Authenticate incoming request
-- @param request table request object
-- @return boolean authenticated
-- @return table auth_result (user_info, permissions, method_used, etc.)
function AuthManager:authenticate_request(request)
    local auth_result = {
        authenticated = false,
        user_info = nil,
        permissions = {},
        auth_level = AUTH_LEVELS.NONE,
        method_used = nil,
        token_info = nil,
        errors = {},
        warnings = {}
    }

    local start_time = performance_utils.get_time()

    self.stats.total_auth_requests = self.stats.total_auth_requests + 1

    -- Skip authentication if not required
    if not self.require_auth then
        auth_result.authenticated = true
        auth_result.auth_level = AUTH_LEVELS.READ
        auth_result.method_used = "none"
        return true, auth_result
    end

    -- Check for rate limiting on failed attempts
    if self:_is_rate_limited(request) then
        table.insert(auth_result.errors, {
            code = "RATE_LIMITED",
            message = "Too many failed authentication attempts"
        })
        self.stats.blocked_attempts = self.stats.blocked_attempts + 1
        return false, auth_result
    end

    -- Try each configured authentication method
    for _, method in ipairs(self.auth_methods) do
        local success, method_result = self:_try_auth_method(method, request)

        if success then
            auth_result.authenticated = true
            auth_result.user_info = method_result.user_info
            auth_result.permissions = method_result.permissions
            auth_result.auth_level = method_result.auth_level
            auth_result.method_used = method
            auth_result.token_info = method_result.token_info

            self.stats.successful_auths = self.stats.successful_auths + 1
            self:_record_auth_method_usage(method)
            self:_clear_failed_attempts(request)

            break
        else
            -- Collect errors from failed attempts
            if method_result.errors then
                for _, error in ipairs(method_result.errors) do
                    table.insert(auth_result.errors, error)
                end
            end
        end
    end

    -- Record failed attempt if authentication failed
    if not auth_result.authenticated then
        self.stats.failed_auths = self.stats.failed_auths + 1
        self:_record_failed_attempt(request)
    end

    auth_result.auth_time = performance_utils.get_time() - start_time

    return auth_result.authenticated, auth_result
end

--- Try specific authentication method
-- @param method string authentication method
-- @param request table request object
-- @return boolean success
-- @return table method_result
function AuthManager:_try_auth_method(method, request)
    if method == AUTH_METHODS.API_KEY then
        return self:_authenticate_api_key(request)
    elseif method == AUTH_METHODS.JWT then
        return self:_authenticate_jwt(request)
    elseif method == AUTH_METHODS.BASIC then
        return self:_authenticate_basic(request)
    elseif method == AUTH_METHODS.OAUTH then
        return self:_authenticate_oauth(request)
    elseif method == AUTH_METHODS.HMAC then
        return self:_authenticate_hmac(request)
    elseif method == AUTH_METHODS.MUTUAL_TLS then
        return self:_authenticate_mutual_tls(request)
    else
        return false, {
            errors = {{
                code = "UNSUPPORTED_METHOD",
                message = "Unsupported authentication method: " .. method
            }}
        }
    end
end

--- Authenticate using API key
-- @param request table request object
-- @return boolean success
-- @return table result
function AuthManager:_authenticate_api_key(request)
    local api_key = self:_extract_api_key(request)

    if not api_key then
        return false, {
            errors = {{
                code = "API_KEY_MISSING",
                message = "API key not found in request"
            }}
        }
    end

    -- Validate API key format
    if not self:_validate_api_key_format(api_key) then
        return false, {
            errors = {{
                code = "API_KEY_INVALID_FORMAT",
                message = "API key format is invalid"
            }}
        }
    end

    -- Look up API key
    local key_info = self.storage.api_keys[api_key]
    if not key_info then
        return false, {
            errors = {{
                code = "API_KEY_NOT_FOUND",
                message = "API key not found"
            }}
        }
    end

    -- Check if API key is active
    if not key_info.active then
        return false, {
            errors = {{
                code = "API_KEY_INACTIVE",
                message = "API key is inactive"
            }}
        }
    end

    -- Check expiration
    if key_info.expires_at and os.time() > key_info.expires_at then
        return false, {
            errors = {{
                code = "API_KEY_EXPIRED",
                message = "API key has expired"
            }}
        }
    end

    -- Update last used
    key_info.last_used = os.time()
    key_info.usage_count = (key_info.usage_count or 0) + 1

    return true, {
        user_info = {
            id = key_info.user_id,
            name = key_info.name,
            type = "api_key"
        },
        permissions = key_info.permissions or {},
        auth_level = key_info.auth_level or AUTH_LEVELS.READ,
        token_info = {
            type = TOKEN_TYPES.API_KEY,
            key = api_key,
            expires_at = key_info.expires_at
        }
    }
end

--- Authenticate using JWT token
-- @param request table request object
-- @return boolean success
-- @return table result
function AuthManager:_authenticate_jwt(request)
    local token = self:_extract_jwt_token(request)

    if not token then
        return false, {
            errors = {{
                code = "JWT_TOKEN_MISSING",
                message = "JWT token not found in request"
            }}
        }
    end

    -- Check if token is blacklisted
    if self.storage.blacklisted_tokens[token] then
        return false, {
            errors = {{
                code = "JWT_TOKEN_BLACKLISTED",
                message = "JWT token has been revoked"
            }}
        }
    end

    -- Verify and decode JWT
    local success, decoded = self:_verify_jwt_token(token)
    if not success then
        return false, {
            errors = {{
                code = "JWT_TOKEN_INVALID",
                message = "JWT token verification failed",
                details = decoded
            }}
        }
    end

    -- Check token expiration
    if decoded.exp and os.time() > decoded.exp then
        return false, {
            errors = {{
                code = "JWT_TOKEN_EXPIRED",
                message = "JWT token has expired"
            }}
        }
    end

    -- Check token type (access vs refresh)
    local token_type = decoded.type or TOKEN_TYPES.ACCESS
    if token_type ~= TOKEN_TYPES.ACCESS then
        return false, {
            errors = {{
                code = "JWT_TOKEN_WRONG_TYPE",
                message = "Wrong token type for authentication"
            }}
        }
    end

    return true, {
        user_info = {
            id = decoded.sub,
            name = decoded.name,
            email = decoded.email,
            type = "user"
        },
        permissions = decoded.permissions or {},
        auth_level = decoded.auth_level or AUTH_LEVELS.READ,
        token_info = {
            type = TOKEN_TYPES.ACCESS,
            token = token,
            expires_at = decoded.exp,
            issued_at = decoded.iat
        }
    }
end

--- Authenticate using Basic auth
-- @param request table request object
-- @return boolean success
-- @return table result
function AuthManager:_authenticate_basic(request)
    local auth_header = request.headers and request.headers.authorization

    if not auth_header or not string.find(auth_header, "^Basic ") then
        return false, {
            errors = {{
                code = "BASIC_AUTH_MISSING",
                message = "Basic authentication header not found"
            }}
        }
    end

    -- Decode base64 credentials
    local encoded_creds = string.gsub(auth_header, "^Basic ", "")
    local decoded_creds = self:_base64_decode(encoded_creds)

    if not decoded_creds then
        return false, {
            errors = {{
                code = "BASIC_AUTH_INVALID_ENCODING",
                message = "Invalid base64 encoding in Basic auth"
            }}
        }
    end

    -- Extract username and password
    local username, password = string.match(decoded_creds, "^([^:]+):(.*)$")

    if not username or not password then
        return false, {
            errors = {{
                code = "BASIC_AUTH_INVALID_FORMAT",
                message = "Invalid Basic auth format"
            }}
        }
    end

    -- Verify credentials
    local user_info = self.storage.users[username]
    if not user_info then
        return false, {
            errors = {{
                code = "BASIC_AUTH_USER_NOT_FOUND",
                message = "User not found"
            }}
        }
    end

    -- Check password (in production, use proper password hashing)
    if not self:_verify_password(password, user_info.password_hash) then
        return false, {
            errors = {{
                code = "BASIC_AUTH_INVALID_PASSWORD",
                message = "Invalid password"
            }}
        }
    end

    -- Check if user is active
    if not user_info.active then
        return false, {
            errors = {{
                code = "BASIC_AUTH_USER_INACTIVE",
                message = "User account is inactive"
            }}
        }
    end

    return true, {
        user_info = {
            id = user_info.id,
            name = user_info.name,
            email = user_info.email,
            type = "user"
        },
        permissions = user_info.permissions or {},
        auth_level = user_info.auth_level or AUTH_LEVELS.READ,
        token_info = {
            type = "basic",
            username = username
        }
    }
end

--- Placeholder for OAuth authentication
-- @param request table request object
-- @return boolean success
-- @return table result
function AuthManager:_authenticate_oauth(request)
    -- OAuth implementation would integrate with external OAuth providers
    return false, {
        errors = {{
            code = "OAUTH_NOT_IMPLEMENTED",
            message = "OAuth authentication not yet implemented"
        }}
    }
end

--- Placeholder for HMAC authentication
-- @param request table request object
-- @return boolean success
-- @return table result
function AuthManager:_authenticate_hmac(request)
    -- HMAC implementation for API request signing
    return false, {
        errors = {{
            code = "HMAC_NOT_IMPLEMENTED",
            message = "HMAC authentication not yet implemented"
        }}
    }
end

--- Placeholder for Mutual TLS authentication
-- @param request table request object
-- @return boolean success
-- @return table result
function AuthManager:_authenticate_mutual_tls(request)
    -- mTLS implementation using client certificates
    return false, {
        errors = {{
            code = "MTLS_NOT_IMPLEMENTED",
            message = "Mutual TLS authentication not yet implemented"
        }}
    }
end

--- Check authorization for specific resource/action
-- @param auth_result table authentication result
-- @param resource string resource being accessed
-- @param action string action being performed
-- @return boolean authorized
-- @return table authorization_result
function AuthManager:check_authorization(auth_result, resource, action)
    local authz_result = {
        authorized = false,
        required_level = AUTH_LEVELS.NONE,
        user_level = auth_result.auth_level or AUTH_LEVELS.NONE,
        resource = resource,
        action = action,
        errors = {}
    }

    if not auth_result.authenticated then
        table.insert(authz_result.errors, {
            code = "NOT_AUTHENTICATED",
            message = "User must be authenticated"
        })
        return false, authz_result
    end

    -- Define resource authorization requirements
    local resource_requirements = self:_get_resource_requirements(resource, action)
    authz_result.required_level = resource_requirements.auth_level

    -- Check authentication level
    if auth_result.auth_level < resource_requirements.auth_level then
        table.insert(authz_result.errors, {
            code = "INSUFFICIENT_PRIVILEGES",
            message = "Insufficient authentication level",
            required = resource_requirements.auth_level,
            current = auth_result.auth_level
        })
        return false, authz_result
    end

    -- Check specific permissions
    if resource_requirements.permissions then
        for _, required_perm in ipairs(resource_requirements.permissions) do
            local has_permission = false

            for _, user_perm in ipairs(auth_result.permissions) do
                if user_perm == required_perm or user_perm == "*" then
                    has_permission = true
                    break
                end
            end

            if not has_permission then
                table.insert(authz_result.errors, {
                    code = "MISSING_PERMISSION",
                    message = "Missing required permission",
                    required_permission = required_perm
                })
                return false, authz_result
            end
        end
    end

    authz_result.authorized = true
    return true, authz_result
end

--- Get authorization requirements for resource/action
-- @param resource string resource name
-- @param action string action name
-- @return table requirements
function AuthManager:_get_resource_requirements(resource, action)
    -- Default requirements
    local requirements = {
        auth_level = AUTH_LEVELS.READ,
        permissions = {}
    }

    -- AI service endpoints require higher privileges
    if string.find(resource, "^/ai/") then
        requirements.auth_level = AUTH_LEVELS.WRITE
        table.insert(requirements.permissions, "ai:access")

        if action == "POST" or action == "PUT" or action == "DELETE" then
            requirements.auth_level = AUTH_LEVELS.ADMIN
            table.insert(requirements.permissions, "ai:write")
        end
    end

    -- Admin endpoints
    if string.find(resource, "^/admin/") then
        requirements.auth_level = AUTH_LEVELS.ADMIN
        table.insert(requirements.permissions, "admin:access")
    end

    -- Configuration endpoints
    if string.find(resource, "^/config/") then
        if action == "GET" then
            requirements.auth_level = AUTH_LEVELS.READ
            table.insert(requirements.permissions, "config:read")
        else
            requirements.auth_level = AUTH_LEVELS.ADMIN
            table.insert(requirements.permissions, "config:write")
        end
    end

    return requirements
end

--- Extract API key from request
-- @param request table request object
-- @return string api_key or nil
function AuthManager:_extract_api_key(request)
    -- Check header
    local header_name = self.api_key_config.header_name
    if request.headers and request.headers[header_name] then
        return request.headers[header_name]
    end

    -- Check query parameter
    local query_param = self.api_key_config.query_param
    if request.query_params and request.query_params[query_param] then
        return request.query_params[query_param]
    end

    return nil
end

--- Extract JWT token from request
-- @param request table request object
-- @return string token or nil
function AuthManager:_extract_jwt_token(request)
    local auth_header = request.headers and request.headers.authorization

    if auth_header and string.find(auth_header, "^Bearer ") then
        return string.gsub(auth_header, "^Bearer ", "")
    end

    return nil
end

--- Validate API key format
-- @param api_key string API key to validate
-- @return boolean valid
function AuthManager:_validate_api_key_format(api_key)
    local prefix = self.api_key_config.prefix
    local expected_length = self.api_key_config.length

    -- Check prefix
    if prefix and not string.find(api_key, "^" .. prefix) then
        return false
    end

    -- Check length
    if expected_length and string.len(api_key) ~= expected_length + string.len(prefix or "") then
        return false
    end

    -- Check characters (alphanumeric)
    if not string.match(api_key, "^[a-zA-Z0-9_-]+$") then
        return false
    end

    return true
end

--- Verify JWT token (simplified implementation)
-- @param token string JWT token
-- @return boolean success
-- @return table decoded_payload or error_message
function AuthManager:_verify_jwt_token(token)
    -- In production, use a proper JWT library like lua-resty-jwt
    -- This is a simplified implementation for demonstration

    local parts = {}
    for part in string.gmatch(token, "[^.]+") do
        table.insert(parts, part)
    end

    if #parts ~= 3 then
        return false, "Invalid JWT format"
    end

    -- Decode payload (base64url)
    local payload_encoded = parts[2]
    local payload_json = self:_base64url_decode(payload_encoded)

    if not payload_json then
        return false, "Invalid payload encoding"
    end

    -- Parse JSON
    local success, payload = pcall(function()
        return require("cjson").decode(payload_json)
    end)

    if not success then
        return false, "Invalid payload JSON"
    end

    -- In production: verify signature using parts[1] (header) and parts[3] (signature)
    -- For now, just return the payload
    return true, payload
end

--- Verify password against hash (simplified)
-- @param password string plaintext password
-- @param hash string password hash
-- @return boolean valid
function AuthManager:_verify_password(password, hash)
    -- In production, use proper password hashing like bcrypt
    -- This is simplified for demonstration
    return password == hash -- Obviously not secure!
end

--- Base64 decode (simplified)
-- @param encoded string base64 encoded string
-- @return string decoded or nil
function AuthManager:_base64_decode(encoded)
    -- Simplified implementation - use proper base64 library in production
    return encoded -- Placeholder
end

--- Base64url decode (simplified)
-- @param encoded string base64url encoded string
-- @return string decoded or nil
function AuthManager:_base64url_decode(encoded)
    -- Simplified implementation - use proper base64url library in production
    return encoded -- Placeholder
end

--- Check if request is rate limited due to failed attempts
-- @param request table request object
-- @return boolean rate_limited
function AuthManager:_is_rate_limited(request)
    local client_ip = request.client_ip or "unknown"
    local current_time = os.time()

    local attempts = self.storage.failed_attempts[client_ip]
    if not attempts then
        return false
    end

    -- Check if still in lockout period
    if attempts.locked_until and current_time < attempts.locked_until then
        return true
    end

    -- Check if too many recent failures
    local recent_failures = 0
    local window_start = current_time - self.auth_rate_limits.failed_attempts_window

    for _, attempt_time in ipairs(attempts.attempts or {}) do
        if attempt_time > window_start then
            recent_failures = recent_failures + 1
        end
    end

    return recent_failures >= self.auth_rate_limits.max_failed_attempts
end

--- Record failed authentication attempt
-- @param request table request object
function AuthManager:_record_failed_attempt(request)
    local client_ip = request.client_ip or "unknown"
    local current_time = os.time()

    if not self.storage.failed_attempts[client_ip] then
        self.storage.failed_attempts[client_ip] = {
            attempts = {},
            locked_until = nil
        }
    end

    local attempts = self.storage.failed_attempts[client_ip]
    table.insert(attempts.attempts, current_time)

    -- Clean old attempts
    local window_start = current_time - self.auth_rate_limits.failed_attempts_window
    local recent_attempts = {}

    for _, attempt_time in ipairs(attempts.attempts) do
        if attempt_time > window_start then
            table.insert(recent_attempts, attempt_time)
        end
    end

    attempts.attempts = recent_attempts

    -- Apply lockout if too many attempts
    if #recent_attempts >= self.auth_rate_limits.max_failed_attempts then
        attempts.locked_until = current_time + self.auth_rate_limits.lockout_duration
    end
end

--- Clear failed attempts for successful authentication
-- @param request table request object
function AuthManager:_clear_failed_attempts(request)
    local client_ip = request.client_ip or "unknown"
    self.storage.failed_attempts[client_ip] = nil
end

--- Record authentication method usage
-- @param method string authentication method used
function AuthManager:_record_auth_method_usage(method)
    if not self.stats.auth_methods_used[method] then
        self.stats.auth_methods_used[method] = 0
    end
    self.stats.auth_methods_used[method] = self.stats.auth_methods_used[method] + 1
end

--- Create API key
-- @param user_id string user identifier
-- @param permissions table list of permissions
-- @param expires_in number seconds until expiration (optional)
-- @return string api_key
function AuthManager:create_api_key(user_id, permissions, expires_in)
    local api_key = self.api_key_config.prefix .. self:_generate_random_string(self.api_key_config.length)

    local key_info = {
        user_id = user_id,
        permissions = permissions or {},
        active = true,
        created_at = os.time(),
        expires_at = expires_in and (os.time() + expires_in) or nil,
        usage_count = 0,
        last_used = nil
    }

    self.storage.api_keys[api_key] = key_info

    return api_key
end

--- Generate random string for API keys
-- @param length number desired length
-- @return string random string
function AuthManager:_generate_random_string(length)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local result = ""

    math.randomseed(os.time() + os.clock() * 1000000)

    for i = 1, length do
        local rand_index = math.random(1, #chars)
        result = result .. string.sub(chars, rand_index, rand_index)
    end

    return result
end

--- Get authentication statistics
-- @return table statistics
function AuthManager:get_statistics()
    local total_requests = self.stats.total_auth_requests

    return {
        total_auth_requests = total_requests,
        successful_auths = self.stats.successful_auths,
        failed_auths = self.stats.failed_auths,
        blocked_attempts = self.stats.blocked_attempts,
        success_rate = total_requests > 0 and (self.stats.successful_auths / total_requests) or 0,
        auth_methods_used = self.stats.auth_methods_used,
        active_api_keys = self:_count_active_api_keys(),
        locked_ips = self:_count_locked_ips()
    }
end

--- Count active API keys
-- @return number count
function AuthManager:_count_active_api_keys()
    local count = 0
    for _, key_info in pairs(self.storage.api_keys) do
        if key_info.active and (not key_info.expires_at or os.time() < key_info.expires_at) then
            count = count + 1
        end
    end
    return count
end

--- Count locked IP addresses
-- @return number count
function AuthManager:_count_locked_ips()
    local count = 0
    local current_time = os.time()

    for _, attempts in pairs(self.storage.failed_attempts) do
        if attempts.locked_until and current_time < attempts.locked_until then
            count = count + 1
        end
    end

    return count
end

return AuthManager
