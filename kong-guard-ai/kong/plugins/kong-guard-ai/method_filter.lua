-- Kong Guard AI - HTTP Method Filter Module
-- Fast O(1) HTTP method denylist filtering for enhanced security
-- Prevents dangerous HTTP methods like TRACE, CONNECT, DEBUG from reaching upstream

local kong = kong
local ngx = ngx

local _M = {}

-- Default denied HTTP methods (high security risk)
local DEFAULT_DENIED_METHODS = {
    "TRACE",    -- Can be used for XSS and information disclosure
    "CONNECT",  -- Can be used for tunneling attacks
    "DEBUG",    -- Non-standard method that can expose debug info
    "TRACK",    -- Similar to TRACE, can leak sensitive data
    "OPTIONS",  -- Can reveal server capabilities (optional to block)
}

-- Additional dangerous methods that might be blocked in high-security environments
local EXTENDED_DENIED_METHODS = {
    "PATCH",    -- Can be dangerous if not properly validated
    "PURGE",    -- Cache purge method, usually internal only
    "LOCK",     -- WebDAV method, rarely needed in APIs
    "UNLOCK",   -- WebDAV method, rarely needed in APIs
    "MKCOL",    -- WebDAV method for creating collections
    "COPY",     -- WebDAV method for copying resources
    "MOVE",     -- WebDAV method for moving resources
    "PROPFIND", -- WebDAV property discovery method
    "PROPPATCH",-- WebDAV property modification method
}

-- O(1) lookup hash tables for fast method checking
local denied_methods_hash = {}
local bypass_routes_hash = {}
local method_analytics = {}

-- Threat levels for different method violations
local METHOD_THREAT_LEVELS = {
    TRACE = 8.5,    -- High threat - often used in attacks
    CONNECT = 8.0,  -- High threat - tunneling attempts
    DEBUG = 7.5,    -- Medium-high threat - information disclosure
    TRACK = 7.5,    -- Medium-high threat - similar to TRACE  
    OPTIONS = 4.0,  -- Low threat - information gathering
    PATCH = 3.0,    -- Low threat - if allowed normally
    PURGE = 6.0,    -- Medium threat - cache manipulation
    LOCK = 5.0,     -- Medium threat - resource locking
    UNLOCK = 5.0,   -- Medium threat - resource unlocking
    MKCOL = 5.0,    -- Medium threat - collection creation
    COPY = 4.0,     -- Low-medium threat - resource duplication
    MOVE = 4.0,     -- Low-medium threat - resource relocation
    PROPFIND = 6.0, -- Medium threat - property discovery
    PROPPATCH = 6.0 -- Medium threat - property modification
}

---
-- Initialize HTTP method filter system
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Method Filter] Initializing HTTP method filtering")
    
    -- Build O(1) lookup hash from configuration
    _M.build_denied_methods_hash(conf)
    
    -- Initialize bypass routes if configured
    _M.build_bypass_routes_hash(conf)
    
    -- Initialize analytics tracking
    method_analytics = {
        blocked_methods = {},
        bypass_used = {},
        total_blocks = 0,
        start_time = ngx.now()
    }
    
    kong.log.info("[Kong Guard AI Method Filter] Method filtering initialized with " .. 
                  _M.get_denied_methods_count() .. " denied methods")
end

---
-- Build hash table for O(1) method lookup
-- @param conf Plugin configuration
---
function _M.build_denied_methods_hash(conf)
    denied_methods_hash = {}
    
    local methods_to_deny = {}
    
    -- Start with default denied methods
    for _, method in ipairs(DEFAULT_DENIED_METHODS) do
        table.insert(methods_to_deny, method)
    end
    
    -- Add extended methods if configured
    if conf.block_extended_methods then
        for _, method in ipairs(EXTENDED_DENIED_METHODS) do
            table.insert(methods_to_deny, method)
        end
    end
    
    -- Add custom denied methods from configuration
    if conf.custom_denied_methods and type(conf.custom_denied_methods) == "table" then
        for _, method in ipairs(conf.custom_denied_methods) do
            table.insert(methods_to_deny, method)
        end
    end
    
    -- Build hash table for O(1) lookup with case normalization
    for _, method in ipairs(methods_to_deny) do
        local normalized_method = string.upper(method)
        denied_methods_hash[normalized_method] = true
        kong.log.debug("[Kong Guard AI Method Filter] Added denied method: " .. normalized_method)
    end
end

---
-- Build hash table for bypass routes
-- @param conf Plugin configuration  
---
function _M.build_bypass_routes_hash(conf)
    bypass_routes_hash = {}
    
    if conf.method_bypass_routes and type(conf.method_bypass_routes) == "table" then
        for _, route_pattern in ipairs(conf.method_bypass_routes) do
            bypass_routes_hash[route_pattern] = true
            kong.log.debug("[Kong Guard AI Method Filter] Added bypass route: " .. route_pattern)
        end
    end
end

---
-- Check if HTTP method should be denied
-- @param method HTTP method string
-- @param request_context Request context for bypass checking
-- @param conf Plugin configuration
-- @return Table containing method analysis result
---
function _M.analyze_method(method, request_context, conf)
    local threat_result = {
        threat_level = 0,
        threat_type = "http_method_violation",
        confidence = 0,
        details = {
            method = method,
            is_denied = false,
            bypass_used = false,
            threat_category = "method_security"
        },
        requires_ai_analysis = false,
        recommended_action = "allow"
    }
    
    -- Normalize method to uppercase for consistent checking
    local normalized_method = string.upper(method or "GET")
    threat_result.details.normalized_method = normalized_method
    
    -- Check if method is in denied list (O(1) lookup)
    if denied_methods_hash[normalized_method] then
        threat_result.details.is_denied = true
        
        -- Check for bypass routes before blocking
        local bypass_allowed = _M.check_bypass_routes(request_context, conf)
        if bypass_allowed then
            threat_result.details.bypass_used = true
            threat_result.details.bypass_reason = "route_whitelist"
            _M.track_bypass_usage(normalized_method, request_context.path)
            kong.log.info("[Kong Guard AI Method Filter] Method " .. normalized_method .. 
                         " allowed via bypass for route: " .. request_context.path)
            return threat_result
        end
        
        -- Method is denied and no bypass applies
        local threat_level = METHOD_THREAT_LEVELS[normalized_method] or 7.0
        threat_result.threat_level = threat_level
        threat_result.confidence = 0.95 -- High confidence for explicit method blocks
        threat_result.recommended_action = "block"
        threat_result.details.block_reason = "method_denied"
        
        -- Track analytics
        _M.track_blocked_method(normalized_method, request_context)
        
        kong.log.warn("[Kong Guard AI Method Filter] Blocked HTTP method: " .. normalized_method .. 
                      " from " .. (request_context.client_ip or "unknown") .. 
                      " (threat level: " .. threat_level .. ")")
    end
    
    return threat_result
end

---
-- Check if request should bypass method filtering
-- @param request_context Request context data
-- @param conf Plugin configuration
-- @return Boolean indicating if bypass is allowed
---
function _M.check_bypass_routes(request_context, conf)
    if not request_context.path then
        return false
    end
    
    -- Check exact path matches first (O(1) lookup)
    if bypass_routes_hash[request_context.path] then
        return true
    end
    
    -- Check pattern matches (only if no exact match found)
    for route_pattern, _ in pairs(bypass_routes_hash) do
        if route_pattern:find("*") or route_pattern:find("^") then
            local pattern_match = ngx.re.match(request_context.path, route_pattern, "jo")
            if pattern_match then
                return true
            end
        end
    end
    
    -- Check service-specific bypass
    if conf.method_bypass_services and request_context.service_id then
        for _, service_id in ipairs(conf.method_bypass_services) do
            if service_id == request_context.service_id then
                return true
            end
        end
    end
    
    return false
end

---
-- Execute method blocking response
-- @param threat_result Method analysis result
-- @param request_context Request context
-- @param conf Plugin configuration
-- @return Response execution result
---
function _M.execute_method_block(threat_result, request_context, conf)
    local method = threat_result.details.normalized_method or "UNKNOWN"
    
    -- Prepare 405 Method Not Allowed response
    local response_body = {
        error = "Method Not Allowed",
        message = "The HTTP method '" .. method .. "' is not allowed for this resource",
        code = 405,
        timestamp = ngx.now(),
        correlation_id = request_context.correlation_id,
        allowed_methods = _M.get_allowed_methods_list(conf)
    }
    
    -- Set appropriate headers
    kong.response.set_header("Allow", table.concat(_M.get_allowed_methods_list(conf), ", "))
    kong.response.set_header("X-Kong-Guard-AI", "method-blocked")
    kong.response.set_header("X-Block-Reason", "http-method-denied")
    
    -- Return structured response
    return kong.response.exit(405, response_body, {
        ["Content-Type"] = "application/json"
    })
end

---
-- Get list of allowed HTTP methods
-- @param conf Plugin configuration
-- @return Array of allowed method strings
---
function _M.get_allowed_methods_list(conf)
    local standard_methods = {"GET", "POST", "PUT", "DELETE", "HEAD"}
    local allowed_methods = {}
    
    for _, method in ipairs(standard_methods) do
        if not denied_methods_hash[method] then
            table.insert(allowed_methods, method)
        end
    end
    
    -- Add any explicitly allowed custom methods
    if conf.custom_allowed_methods and type(conf.custom_allowed_methods) == "table" then
        for _, method in ipairs(conf.custom_allowed_methods) do
            local normalized = string.upper(method)
            if not denied_methods_hash[normalized] then
                table.insert(allowed_methods, normalized)
            end
        end
    end
    
    return allowed_methods
end

---
-- Track blocked method for analytics
-- @param method Blocked HTTP method
-- @param request_context Request context
---
function _M.track_blocked_method(method, request_context)
    if not method_analytics.blocked_methods[method] then
        method_analytics.blocked_methods[method] = {
            count = 0,
            first_seen = ngx.now(),
            last_seen = ngx.now(),
            source_ips = {}
        }
    end
    
    local method_stats = method_analytics.blocked_methods[method]
    method_stats.count = method_stats.count + 1
    method_stats.last_seen = ngx.now()
    method_analytics.total_blocks = method_analytics.total_blocks + 1
    
    -- Track unique source IPs (limit to prevent memory bloat)
    local client_ip = request_context.client_ip
    if client_ip and not method_stats.source_ips[client_ip] then
        if _M.count_table_entries(method_stats.source_ips) < 100 then
            method_stats.source_ips[client_ip] = {
                first_seen = ngx.now(),
                count = 1
            }
        end
    elseif client_ip and method_stats.source_ips[client_ip] then
        method_stats.source_ips[client_ip].count = method_stats.source_ips[client_ip].count + 1
    end
end

---
-- Track bypass usage for monitoring
-- @param method HTTP method that was bypassed
-- @param path Request path that triggered bypass
---
function _M.track_bypass_usage(method, path)
    if not method_analytics.bypass_used[method] then
        method_analytics.bypass_used[method] = {
            count = 0,
            paths = {}
        }
    end
    
    local bypass_stats = method_analytics.bypass_used[method]
    bypass_stats.count = bypass_stats.count + 1
    
    -- Track unique paths (limit to prevent memory bloat)
    if not bypass_stats.paths[path] and _M.count_table_entries(bypass_stats.paths) < 50 then
        bypass_stats.paths[path] = {
            first_used = ngx.now(),
            count = 1
        }
    elseif bypass_stats.paths[path] then
        bypass_stats.paths[path].count = bypass_stats.paths[path].count + 1
    end
end

---
-- Get method filtering analytics
-- @return Table containing analytics data
---
function _M.get_method_analytics()
    local runtime_seconds = ngx.now() - method_analytics.start_time
    local blocks_per_hour = method_analytics.total_blocks / (runtime_seconds / 3600)
    
    return {
        runtime_seconds = runtime_seconds,
        total_blocks = method_analytics.total_blocks,
        blocks_per_hour = blocks_per_hour,
        denied_methods_count = _M.get_denied_methods_count(),
        bypass_routes_count = _M.count_table_entries(bypass_routes_hash),
        blocked_methods = method_analytics.blocked_methods,
        bypass_usage = method_analytics.bypass_used,
        top_blocked_methods = _M.get_top_blocked_methods(5),
        threat_patterns = _M.analyze_threat_patterns()
    }
end

---
-- Get count of denied methods
-- @return Number of denied methods configured
---
function _M.get_denied_methods_count()
    return _M.count_table_entries(denied_methods_hash)
end

---
-- Get top blocked methods for reporting
-- @param limit Maximum number of methods to return
-- @return Array of method statistics sorted by count
---
function _M.get_top_blocked_methods(limit)
    local methods = {}
    
    for method, stats in pairs(method_analytics.blocked_methods) do
        table.insert(methods, {
            method = method,
            count = stats.count,
            unique_ips = _M.count_table_entries(stats.source_ips),
            first_seen = stats.first_seen,
            last_seen = stats.last_seen
        })
    end
    
    -- Sort by count descending
    table.sort(methods, function(a, b) return a.count > b.count end)
    
    -- Return limited results
    local result = {}
    for i = 1, math.min(limit or 10, #methods) do
        table.insert(result, methods[i])
    end
    
    return result
end

---
-- Analyze threat patterns in blocked methods
-- @return Table containing threat pattern analysis
---
function _M.analyze_threat_patterns()
    local patterns = {
        high_frequency_attacks = {},
        distributed_sources = {},
        suspicious_timing = {}
    }
    
    for method, stats in pairs(method_analytics.blocked_methods) do
        local runtime_hours = (ngx.now() - method_analytics.start_time) / 3600
        local requests_per_hour = stats.count / math.max(runtime_hours, 0.01)
        
        -- High frequency attacks (>10 requests per hour)
        if requests_per_hour > 10 then
            patterns.high_frequency_attacks[method] = {
                requests_per_hour = requests_per_hour,
                total_count = stats.count
            }
        end
        
        -- Distributed sources (>5 unique IPs)
        local unique_ips = _M.count_table_entries(stats.source_ips)
        if unique_ips > 5 then
            patterns.distributed_sources[method] = {
                unique_ips = unique_ips,
                total_count = stats.count
            }
        end
        
        -- Suspicious timing (recent spike in activity)
        local recent_threshold = ngx.now() - 3600 -- Last hour
        if stats.last_seen > recent_threshold and stats.count > 10 then
            patterns.suspicious_timing[method] = {
                last_seen = stats.last_seen,
                total_count = stats.count
            }
        end
    end
    
    return patterns
end

---
-- Cleanup method filter cache (called periodically)
---
function _M.cleanup_cache()
    local current_time = ngx.now()
    local cleanup_threshold = current_time - 86400 -- 24 hours
    
    -- Clean old analytics data to prevent memory bloat
    for method, stats in pairs(method_analytics.blocked_methods) do
        if stats.last_seen < cleanup_threshold then
            kong.log.debug("[Kong Guard AI Method Filter] Cleaning old analytics for method: " .. method)
            method_analytics.blocked_methods[method] = nil
        else
            -- Clean old IP tracking data
            for ip, ip_stats in pairs(stats.source_ips) do
                if ip_stats.first_seen < cleanup_threshold then
                    stats.source_ips[ip] = nil
                end
            end
        end
    end
end

---
-- Count entries in a table (utility function)
-- @param tbl Table to count
-- @return Number of entries
---
function _M.count_table_entries(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

---
-- Get method filter configuration summary
-- @return Table containing configuration details
---
function _M.get_config_summary()
    return {
        denied_methods = _M.get_denied_methods_list(),
        denied_methods_count = _M.get_denied_methods_count(),
        bypass_routes_count = _M.count_table_entries(bypass_routes_hash),
        analytics_enabled = true,
        default_action = "block_405"
    }
end

---
-- Get list of currently denied methods
-- @return Array of denied method names
---
function _M.get_denied_methods_list()
    local methods = {}
    for method, _ in pairs(denied_methods_hash) do
        table.insert(methods, method)
    end
    table.sort(methods)
    return methods
end

return _M