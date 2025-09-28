--- Privacy API Handler for Kong Guard AI
-- Provides REST API endpoints for GDPR and CCPA data subject rights requests

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local privacy_manager = require("kong.plugins.kong-guard-ai.privacy_manager")

-- API endpoints and their handlers
local API_ENDPOINTS = {
    -- GDPR endpoints
    ["/kong-guard-ai/privacy/gdpr/right-to-be-forgotten"] = {
        method = "POST",
        handler = "handle_gdpr_deletion",
        description = "GDPR Right to be Forgotten request"
    },
    ["/kong-guard-ai/privacy/gdpr/data-portability"] = {
        method = "GET",
        handler = "handle_gdpr_portability",
        description = "GDPR Data Portability request"
    },
    ["/kong-guard-ai/privacy/gdpr/access-request"] = {
        method = "GET",
        handler = "handle_gdpr_access",
        description = "GDPR Access Request"
    },
    ["/kong-guard-ai/privacy/gdpr/consent-withdrawal"] = {
        method = "POST",
        handler = "handle_gdpr_consent_withdrawal",
        description = "GDPR Consent Withdrawal"
    },
    ["/kong-guard-ai/privacy/gdpr/rectification"] = {
        method = "PUT",
        handler = "handle_gdpr_rectification",
        description = "GDPR Data Rectification"
    },
    ["/kong-guard-ai/privacy/gdpr/restriction"] = {
        method = "POST",
        handler = "handle_gdpr_restriction",
        description = "GDPR Processing Restriction"
    },
    ["/kong-guard-ai/privacy/gdpr/objection"] = {
        method = "POST",
        handler = "handle_gdpr_objection",
        description = "GDPR Objection to Processing"
    },

    -- CCPA endpoints
    ["/kong-guard-ai/privacy/ccpa/do-not-sell"] = {
        method = "POST",
        handler = "handle_ccpa_do_not_sell",
        description = "CCPA Do Not Sell request"
    },
    ["/kong-guard-ai/privacy/ccpa/do-not-share"] = {
        method = "POST",
        handler = "handle_ccpa_do_not_share",
        description = "CCPA Do Not Share request"
    },
    ["/kong-guard-ai/privacy/ccpa/data-deletion"] = {
        method = "POST",
        handler = "handle_ccpa_deletion",
        description = "CCPA Data Deletion request"
    },
    ["/kong-guard-ai/privacy/ccpa/data-access"] = {
        method = "GET",
        handler = "handle_ccpa_access",
        description = "CCPA Data Access request"
    },
    ["/kong-guard-ai/privacy/ccpa/opt-out"] = {
        method = "POST",
        handler = "handle_ccpa_opt_out",
        description = "CCPA Opt-Out request"
    },
    ["/kong-guard-ai/privacy/ccpa/limit-use"] = {
        method = "POST",
        handler = "handle_ccpa_limit_use",
        description = "CCPA Limit Use request"
    },

    -- General privacy endpoints
    ["/kong-guard-ai/privacy/consent"] = {
        method = "GET",
        handler = "handle_get_consent",
        description = "Get user consent status"
    },
    ["/kong-guard-ai/privacy/consent"] = {
        method = "POST",
        handler = "handle_set_consent",
        description = "Set user consent"
    },
    ["/kong-guard-ai/privacy/status"] = {
        method = "GET",
        handler = "handle_privacy_status",
        description = "Get privacy compliance status"
    }
}

--- Initialize privacy API
function _M.init()
    kong.log.info("[kong-guard-ai] Privacy API initialized")
end

--- Handle privacy API requests
function _M.handle_request(config)
    local request_path = kong.request.get_path()
    local request_method = kong.request.get_method()

    -- Find matching endpoint
    local endpoint_config = API_ENDPOINTS[request_path]

    if not endpoint_config then
        return _M._send_error(404, "Endpoint not found")
    end

    if endpoint_config.method ~= request_method then
        return _M._send_error(405, "Method not allowed")
    end

    -- Get privacy manager instance
    local pm_config = {
        gdpr_compliance = config.regulatory_config.gdpr_compliance,
        ccpa_compliance = config.regulatory_config.ccpa_compliance,
        consent_tracking = config.privacy_config.consent_tracking,
        data_anonymization = config.privacy_config.data_anonymization,
        pii_detection_rules = config.privacy_config.pii_detection_rules,
        anonymization_level = config.privacy_config.anonymization_level
    }

    local pm = privacy_manager.new(pm_config)

    -- Call the appropriate handler
    local handler_name = endpoint_config.handler
    local handler = _M[handler_name]

    if not handler then
        return _M._send_error(500, "Handler not implemented")
    end

    -- Parse request data
    local request_data = _M._parse_request_data()

    -- Call handler
    local success, result = handler(pm, request_data, config)

    if success then
        return _M._send_success(result)
    else
        return _M._send_error(400, result or "Request failed")
    end
end

--- GDPR Handlers

function _M.handle_gdpr_deletion(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_gdpr_request("right_to_be_forgotten", user_id, request_data)
end

function _M.handle_gdpr_portability(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_gdpr_request("data_portability", user_id, request_data)
end

function _M.handle_gdpr_access(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_gdpr_request("access_request", user_id, request_data)
end

function _M.handle_gdpr_consent_withdrawal(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_gdpr_request("consent_withdrawal", user_id, request_data)
end

function _M.handle_gdpr_rectification(pm, request_data, config)
    local user_id = request_data.user_id
    local rectification_data = request_data.rectification_data

    if not user_id or not rectification_data then
        return false, "User ID and rectification data required"
    end

    return pm:handle_gdpr_request("rectification", user_id, {
        rectification_data = rectification_data
    })
end

function _M.handle_gdpr_restriction(pm, request_data, config)
    local user_id = request_data.user_id
    local restriction_type = request_data.restriction_type
    local duration_days = request_data.duration_days

    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_gdpr_request("restriction", user_id, {
        restriction_type = restriction_type,
        duration_days = duration_days
    })
end

function _M.handle_gdpr_objection(pm, request_data, config)
    local user_id = request_data.user_id
    local objection_type = request_data.objection_type

    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_gdpr_request("objection", user_id, {
        objection_type = objection_type
    })
end

--- CCPA Handlers

function _M.handle_ccpa_do_not_sell(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_ccpa_request("do_not_sell", user_id, request_data)
end

function _M.handle_ccpa_do_not_share(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_ccpa_request("do_not_share", user_id, request_data)
end

function _M.handle_ccpa_deletion(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_ccpa_request("data_deletion", user_id, request_data)
end

function _M.handle_ccpa_access(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_ccpa_request("data_access", user_id, request_data)
end

function _M.handle_ccpa_opt_out(pm, request_data, config)
    local user_id = request_data.user_id
    local opt_out_type = request_data.opt_out_type

    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_ccpa_request("opt_out", user_id, {
        opt_out_type = opt_out_type
    })
end

function _M.handle_ccpa_limit_use(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    return pm:handle_ccpa_request("limit_use", user_id, request_data)
end

--- General Privacy Handlers

function _M.handle_get_consent(pm, request_data, config)
    local user_id = request_data.user_id
    if not user_id then
        return false, "User ID required"
    end

    local consent_status = pm:_get_user_consent_status(user_id)
    return true, {
        user_id = user_id,
        consent_status = consent_status,
        timestamp = ngx.time()
    }
end

function _M.handle_set_consent(pm, request_data, config)
    local user_id = request_data.user_id
    local purpose = request_data.purpose
    local consent_given = request_data.consent_given

    if not user_id or not purpose then
        return false, "User ID and purpose required"
    end

    if consent_given == nil then
        consent_given = true -- Default to granting consent
    end

    local success, err = pm:set_consent(user_id, purpose, consent_given, request_data)
    if success then
        return true, {
            user_id = user_id,
            purpose = purpose,
            consent_given = consent_given,
            timestamp = ngx.time()
        }
    else
        return false, err
    end
end

function _M.handle_privacy_status(pm, request_data, config)
    local stats = pm:get_stats()
    local compliance_valid, compliance_issues = pm:validate_compliance()

    return true, {
        compliance_status = compliance_valid and "compliant" or "issues_found",
        compliance_issues = compliance_issues,
        statistics = stats,
        timestamp = ngx.time()
    }
end

--- Helper functions

function _M._parse_request_data()
    local method = kong.request.get_method()
    local data = {}

    if method == "GET" then
        data = kong.request.get_query()
    elseif method == "POST" or method == "PUT" then
        local body = kong.request.get_raw_body()
        if body then
            data = cjson.decode(body) or {}
        end
    end

    return data
end

function _M._send_success(data)
    kong.response.set_header("Content-Type", "application/json")
    kong.response.exit(200, cjson.encode({
        success = true,
        data = data,
        timestamp = ngx.time()
    }))
end

function _M._send_error(status_code, message)
    kong.response.set_header("Content-Type", "application/json")
    kong.response.exit(status_code, cjson.encode({
        success = false,
        error = message,
        timestamp = ngx.time()
    }))
end

--- Get API documentation
function _M.get_api_documentation()
    local docs = {
        title = "Kong Guard AI Privacy API",
        version = "1.0.0",
        description = "REST API for GDPR and CCPA data subject rights requests",
        endpoints = {}
    }

    for path, config in pairs(API_ENDPOINTS) do
        docs.endpoints[path] = {
            method = config.method,
            description = config.description
        }
    end

    return docs
end

return _M
