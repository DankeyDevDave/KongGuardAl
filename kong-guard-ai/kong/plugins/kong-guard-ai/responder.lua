-- Kong Guard AI - Automated Response Module
-- Handles threat response actions including blocking, rate limiting, and Kong config changes
-- Uses Kong Admin API for dynamic configuration updates

local kong = kong
local http = require "resty.http"
local json = require "cjson.safe"
local enforcement_gate = require "kong.plugins.kong-guard-ai.enforcement_gate"
local method_filter = require "kong.plugins.kong-guard-ai.method_filter"

local _M = {}

-- Response action types
local RESPONSE_ACTIONS = {
    BLOCK = "block",
    RATE_LIMIT = "rate_limit",
    MONITOR = "monitor",
    ROLLBACK_CONFIG = "rollback_config",
    MODIFY_HEADERS = "modify_headers",
    REDIRECT = "redirect"
}

-- Cache for tracking applied responses
local response_cache = {}

---
-- Execute automated response based on threat assessment
-- @param threat_result Threat analysis result
-- @param request_context Original request context
-- @param conf Plugin configuration
-- @return Table containing response action details
---
function _M.execute_response(threat_result, request_context, conf)
    local response_action = {
        action_type = threat_result.recommended_action,
        success = false,
        details = {},
        timestamp = ngx.time()
    }

    kong.log.info("[Kong Guard AI Responder] Executing response: " .. threat_result.recommended_action ..
                  " for threat: " .. threat_result.threat_type)

    -- Execute specific response based on threat level and type
    if threat_result.recommended_action == "block" then
        response_action = _M.execute_block_response(threat_result, request_context, conf)
    elseif threat_result.recommended_action == "rate_limit" then
        response_action = _M.execute_rate_limit_response(threat_result, request_context, conf)
    elseif threat_result.recommended_action == "monitor" then
        response_action = _M.execute_monitor_response(threat_result, request_context, conf)
    end

    -- PHASE 7: Check if advanced remediation is needed for critical threats
    if conf.enable_advanced_remediation and threat_result.threat_level >= (conf.rollback_threshold or 9.0) then
        local advanced_remediation = require "kong.plugins.kong-guard-ai.advanced_remediation"

        -- Trigger advanced remediation analysis
        local remediation_result = advanced_remediation.execute_advanced_remediation(
            advanced_remediation.REMEDIATION_ACTIONS.CONFIG_ROLLBACK,
            {
                type = "service",
                id = request_context.service_id,
                route_id = request_context.route_id
            },
            {
                strategy = conf.default_reroute_strategy or "immediate",
                threat_level = threat_result.threat_level,
                confidence = threat_result.confidence,
                rollback_reason = "critical_threat_detected"
            },
            conf
        )

        response_action.advanced_remediation_attempted = true
        response_action.advanced_remediation_result = remediation_result

        if remediation_result.success then
            kong.log.warn(string.format(
                "[Kong Guard AI Responder] Advanced remediation executed: %s",
                remediation_result.remediation_id
            ))
        else
            kong.log.error(string.format(
                "[Kong Guard AI Responder] Advanced remediation failed: %s",
                remediation_result.details.reason or "unknown"
            ))
        end
    elseif conf.enable_config_rollback and threat_result.threat_level >= (conf.rollback_threshold or 9.0) then
        -- Legacy config rollback for backward compatibility
        local action_types = enforcement_gate.get_action_types()
        local rollback_result = enforcement_gate.enforce_action(
            action_types.CONFIG_ROLLBACK,
            {
                threat_result = threat_result,
                rollback_reason = "critical_threat_detected"
            },
            conf,
            function(action_data, config)
                return _M.execute_config_rollback(action_data.threat_result, config)
            end
        )
        response_action.rollback_attempted = rollback_result
    end

    -- Store response in cache for tracking
    _M.store_response_action(response_action, request_context)

    return response_action
end

---
-- Execute blocking response - immediately reject the request
-- @param threat_result Threat analysis result
-- @param request_context Original request context
-- @param conf Plugin configuration
-- @return Table containing block action details
---
function _M.execute_block_response(threat_result, request_context, conf)
    local response_action = {
        action_type = RESPONSE_ACTIONS.BLOCK,
        success = false,
        details = {
            blocked_ip = request_context.client_ip,
            threat_type = threat_result.threat_type,
            threat_level = threat_result.threat_level
        }
    }

    -- Add IP to temporary block list through enforcement gate
    if conf.enable_auto_blocking then
        local action_types = enforcement_gate.get_action_types()
        local block_result = enforcement_gate.enforce_action(
            action_types.BLOCK_IP,
            {
                ip_address = request_context.client_ip,
                duration = conf.block_duration_seconds,
                reason = "automated_threat_response"
            },
            conf,
            function(action_data, config)
                return _M.add_ip_to_blocklist(action_data.ip_address, config)
            end
        )
        response_action.details.ip_block_result = block_result
        response_action.details.added_to_blocklist = block_result.executed or block_result.simulated
    end

    -- Set response headers to indicate blocking
    kong.response.set_header("X-Kong-Guard-AI", "threat_blocked")
    kong.response.set_header("X-Threat-Type", threat_result.threat_type)

    -- Return appropriate error response
    local status_code = 403
    local error_message = "Access denied due to security policy violation"

    -- Customize response based on threat type
    if threat_result.threat_type == "rate_limit_violation" or threat_result.threat_type == "distributed_denial_of_service" then
        status_code = 429
        error_message = "Too many requests"
    elseif threat_result.threat_type == "sql_injection" or threat_result.threat_type == "cross_site_scripting" then
        status_code = 400
        error_message = "Invalid request"
    elseif threat_result.threat_type == "http_method_violation" then
        -- Use specialized method blocking response
        return method_filter.execute_method_block(threat_result, request_context, conf)
    end

    kong.response.exit(status_code, {
        error = error_message,
        incident_id = "guard_ai_" .. ngx.time() .. "_" .. ngx.var.request_id,
        timestamp = ngx.time()
    })

    response_action.success = true
    response_action.details.status_code = status_code

    return response_action
end

---
-- Execute rate limiting response - apply dynamic rate limits
-- @param threat_result Threat analysis result
-- @param request_context Original request context
-- @param conf Plugin configuration
-- @return Table containing rate limit action details
---
function _M.execute_rate_limit_response(threat_result, request_context, conf)
    local response_action = {
        action_type = RESPONSE_ACTIONS.RATE_LIMIT,
        success = false,
        details = {
            target_ip = request_context.client_ip,
            limit_applied = false
        }
    }

    if not conf.enable_rate_limiting_response then
        response_action.details.reason = "rate_limiting_disabled"
        return response_action
    end

    -- Calculate dynamic rate limit based on threat level
    local base_limit = 100 -- requests per minute
    local threat_multiplier = (10 - threat_result.threat_level) / 10
    local dynamic_limit = math.floor(base_limit * threat_multiplier)

    -- Ensure minimum limit
    if dynamic_limit < 10 then
        dynamic_limit = 10
    end

    response_action.details.calculated_limit = dynamic_limit

    -- Apply rate limit via Kong Admin API through enforcement gate
    if conf.admin_api_enabled then
        local action_types = enforcement_gate.get_action_types()
        local rate_limit_result = enforcement_gate.enforce_action(
            action_types.ADMIN_API_CALL,
            {
                method = "POST",
                endpoint = "/plugins",
                client_ip = request_context.client_ip,
                dynamic_limit = dynamic_limit,
                service_id = request_context.service_id
            },
            conf,
            function(action_data, config)
                return _M.apply_dynamic_rate_limit(
                    action_data.client_ip,
                    action_data.dynamic_limit,
                    action_data.service_id,
                    config
                )
            end
        )

        response_action.success = rate_limit_result.executed or rate_limit_result.simulated
        response_action.details.limit_applied = rate_limit_result.executed or rate_limit_result.simulated
        response_action.details.rate_limit_result = rate_limit_result
    end

    -- Set response headers to indicate rate limiting
    kong.response.set_header("X-Kong-Guard-AI", "rate_limited")
    kong.response.set_header("X-RateLimit-Applied", tostring(dynamic_limit))
    kong.response.set_header("X-Threat-Level", tostring(threat_result.threat_level))

    return response_action
end

---
-- Execute monitoring response - enhanced logging and tracking
-- @param threat_result Threat analysis result
-- @param request_context Original request context
-- @param conf Plugin configuration
-- @return Table containing monitor action details
---
function _M.execute_monitor_response(threat_result, request_context, conf)
    local response_action = {
        action_type = RESPONSE_ACTIONS.MONITOR,
        success = true,
        details = {
            monitoring_enabled = true,
            enhanced_logging = true
        }
    }

    -- Add monitoring headers (for debugging/analysis)
    kong.response.set_header("X-Kong-Guard-AI", "monitoring")
    kong.response.set_header("X-Threat-Score", tostring(threat_result.threat_level))

    -- Enable enhanced request tracking
    kong.ctx.plugin.enhanced_monitoring = true
    kong.ctx.plugin.threat_score = threat_result.threat_level

    return response_action
end

---
-- Add IP address to Kong's rate limiting or blocking configuration
-- @param ip_address IP address to block
-- @param conf Plugin configuration
-- @return Boolean indicating success
---
function _M.add_ip_to_blocklist(ip_address, conf)
    if not conf.admin_api_enabled then
        kong.log.warn("[Kong Guard AI Responder] Admin API disabled, cannot add IP to blocklist")
        return false
    end

    -- In a real implementation, this would interact with Kong's Admin API
    -- to add the IP to a rate limiting or IP restriction plugin
    kong.log.info("[Kong Guard AI Responder] Adding IP to blocklist: " .. ip_address)

    -- Store in local cache for immediate blocking
    if not response_cache.blocked_ips then
        response_cache.blocked_ips = {}
    end

    response_cache.blocked_ips[ip_address] = {
        blocked_at = ngx.time(),
        expires_at = ngx.time() + conf.block_duration_seconds,
        reason = "automated_threat_response"
    }

    return true
end

---
-- Apply dynamic rate limiting via Kong Admin API
-- @param ip_address Target IP address
-- @param rate_limit Requests per minute limit
-- @param service_id Kong service ID
-- @param conf Plugin configuration
-- @return Boolean indicating success
---
function _M.apply_dynamic_rate_limit(ip_address, rate_limit, service_id, conf)
    if not conf.admin_api_enabled then
        return false
    end

    kong.log.info("[Kong Guard AI Responder] Applying rate limit: " .. rate_limit ..
                  " requests/min for IP: " .. ip_address)

    -- This would normally make an HTTP request to Kong's Admin API
    -- For now, we'll simulate the API call
    local success = _M.call_kong_admin_api("rate-limiting", {
        config = {
            minute = rate_limit,
            policy = "local",
            hide_client_headers = false
        },
        consumer = { custom_id = ip_address },
        service = { id = service_id }
    }, conf)

    return success
end

---
-- Execute configuration rollback for critical threats
-- @param threat_result Threat analysis result
-- @param conf Plugin configuration
-- @return Table containing rollback action details
---
function _M.execute_config_rollback(threat_result, conf)
    local rollback_action = {
        attempted = true,
        success = false,
        details = {}
    }

    kong.log.warn("[Kong Guard AI Responder] Critical threat detected, attempting config rollback")

    if not conf.admin_api_enabled then
        rollback_action.details.reason = "admin_api_disabled"
        return rollback_action
    end

    -- Get current configuration snapshot
    local current_config = _M.get_current_kong_config(conf)
    if not current_config then
        rollback_action.details.reason = "failed_to_get_current_config"
        return rollback_action
    end

    -- Get previous configuration from backup
    local previous_config = _M.get_previous_kong_config(conf)
    if not previous_config then
        rollback_action.details.reason = "no_previous_config_available"
        return rollback_action
    end

    -- Apply rollback
    local rollback_success = _M.apply_kong_config(previous_config, conf)
    rollback_action.success = rollback_success

    if rollback_success then
        rollback_action.details.rolled_back_to = previous_config.timestamp
        kong.log.info("[Kong Guard AI Responder] Configuration rollback successful")
    else
        rollback_action.details.reason = "rollback_application_failed"
        kong.log.error("[Kong Guard AI Responder] Configuration rollback failed")
    end

    return rollback_action
end

---
-- Make HTTP request to Kong Admin API
-- @param endpoint API endpoint
-- @param data Request payload
-- @param conf Plugin configuration
-- @return Boolean indicating success
---
function _M.call_kong_admin_api(endpoint, data, conf)
    local httpc = http.new()
    httpc:set_timeout(conf.admin_api_timeout_ms)

    -- Construct Admin API URL (normally would be configured)
    local admin_url = os.getenv("KONG_ADMIN_API_URL") or "http://localhost:8001"
    local url = admin_url .. "/plugins"

    local headers = {
        ["Content-Type"] = "application/json"
    }

    -- Add API key if configured
    if conf.admin_api_key then
        headers["Kong-Admin-Token"] = conf.admin_api_key
    end

    local body = json.encode(data)

    local res, err = httpc:request_uri(url, {
        method = "POST",
        headers = headers,
        body = body,
        ssl_verify = false
    })

    if not res then
        kong.log.error("[Kong Guard AI Responder] Admin API request failed: " .. (err or "unknown error"))
        return false
    end

    if res.status >= 200 and res.status < 300 then
        kong.log.debug("[Kong Guard AI Responder] Admin API request successful")
        return true
    else
        kong.log.error("[Kong Guard AI Responder] Admin API request failed with status: " .. res.status)
        return false
    end
end

---
-- Get current Kong configuration
-- @param conf Plugin configuration
-- @return Table containing current configuration or nil
---
function _M.get_current_kong_config(conf)
    -- This would normally call Kong Admin API to get current config
    -- For demonstration, return a mock configuration
    return {
        timestamp = ngx.time(),
        services = {},
        routes = {},
        plugins = {}
    }
end

---
-- Get previous Kong configuration from backup
-- @param conf Plugin configuration
-- @return Table containing previous configuration or nil
---
function _M.get_previous_kong_config(conf)
    -- This would normally retrieve a backed-up configuration
    -- In production, integrate with decK or Konnect for config history
    return nil -- No previous config available for demo
end

---
-- Apply Kong configuration
-- @param config Configuration to apply
-- @param conf Plugin configuration
-- @return Boolean indicating success
---
function _M.apply_kong_config(config, conf)
    -- This would normally apply the configuration via Admin API
    -- In production, use decK or similar tools for declarative config
    kong.log.info("[Kong Guard AI Responder] Applying configuration rollback")
    return false -- Not implemented for demo
end

---
-- Store response action for tracking and metrics
-- @param response_action Response action details
-- @param request_context Original request context
---
function _M.store_response_action(response_action, request_context)
    -- Initialize response tracking
    if not response_cache.actions then
        response_cache.actions = {}
    end

    -- Store action with request context
    local action_record = {
        action = response_action,
        request_id = ngx.var.request_id,
        client_ip = request_context.client_ip,
        service_id = request_context.service_id,
        route_id = request_context.route_id,
        timestamp = ngx.time()
    }

    table.insert(response_cache.actions, action_record)

    -- Limit cache size
    if #response_cache.actions > 1000 then
        table.remove(response_cache.actions, 1)
    end

    kong.log.debug("[Kong Guard AI Responder] Response action stored")
end

---
-- Check if IP is currently blocked
-- @param ip_address IP address to check
-- @return Boolean indicating if IP is blocked
---
function _M.is_ip_blocked(ip_address)
    if not response_cache.blocked_ips then
        return false
    end

    local block_data = response_cache.blocked_ips[ip_address]
    if not block_data then
        return false
    end

    -- Check if block has expired
    if ngx.time() > block_data.expires_at then
        response_cache.blocked_ips[ip_address] = nil
        return false
    end

    return true
end

---
-- Get response metrics for monitoring
-- @return Table containing response metrics
---
function _M.get_response_metrics()
    local metrics = {
        total_responses = 0,
        blocks = 0,
        rate_limits = 0,
        monitors = 0,
        rollbacks = 0,
        blocked_ips_count = 0
    }

    if response_cache.actions then
        metrics.total_responses = #response_cache.actions

        for _, action_record in ipairs(response_cache.actions) do
            local action_type = action_record.action.action_type
            if action_type == RESPONSE_ACTIONS.BLOCK then
                metrics.blocks = metrics.blocks + 1
            elseif action_type == RESPONSE_ACTIONS.RATE_LIMIT then
                metrics.rate_limits = metrics.rate_limits + 1
            elseif action_type == RESPONSE_ACTIONS.MONITOR then
                metrics.monitors = metrics.monitors + 1
            end

            if action_record.action.rollback_attempted then
                metrics.rollbacks = metrics.rollbacks + 1
            end
        end
    end

    if response_cache.blocked_ips then
        metrics.blocked_ips_count = 0
        for ip, block_data in pairs(response_cache.blocked_ips) do
            if ngx.time() <= block_data.expires_at then
                metrics.blocked_ips_count = metrics.blocked_ips_count + 1
            end
        end
    end

    return metrics
end

---
-- Clean up expired response cache entries
---
function _M.cleanup_response_cache()
    local current_time = ngx.time()

    -- Clean expired blocked IPs
    if response_cache.blocked_ips then
        for ip, block_data in pairs(response_cache.blocked_ips) do
            if current_time > block_data.expires_at then
                response_cache.blocked_ips[ip] = nil
            end
        end
    end

    -- Clean old response actions (keep last 24 hours)
    if response_cache.actions then
        local cleaned_actions = {}
        local threshold = current_time - 86400 -- 24 hours

        for _, action_record in ipairs(response_cache.actions) do
            if action_record.timestamp >= threshold then
                table.insert(cleaned_actions, action_record)
            end
        end

        response_cache.actions = cleaned_actions
    end

    kong.log.debug("[Kong Guard AI Responder] Response cache cleanup completed")
end

return _M
