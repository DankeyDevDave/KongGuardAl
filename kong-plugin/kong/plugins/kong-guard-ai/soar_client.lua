--- SOAR Client Module for Kong Guard AI
-- Provides integration with SIEM and SOAR platforms for security orchestration

local cjson = require "cjson.safe"
local http = require "resty.http"
local ngx = ngx
local kong = kong

local _M = {}

-- Module constants
local DEFAULT_TIMEOUT = 5000
local MAX_BATCH_SIZE = 100
local RETRY_ATTEMPTS = 3
local RETRY_BACKOFF = 1000

--- Create a new SOAR client instance
-- @param config The plugin configuration
-- @return SOAR client instance
function _M.new(config)
    if not config then
        return nil, "Configuration is required"
    end

    local self = {
        config = config,
        http_client = http.new(),
        batch_queue = {},
        last_batch_time = ngx.now(),
        retry_count = 0
    }

    -- Set HTTP client timeout
    self.http_client:set_timeout(config.timeout_ms or DEFAULT_TIMEOUT)

    return setmetatable(self, { __index = _M })
end

--- Initialize the SOAR client
-- @return success, error
function _M:init()
    if not self.config.enable_soar_integration then
        kong.log.debug("SOAR integration is disabled")
        return true
    end

    -- Validate configuration
    if not self.config.soar_config then
        return false, "SOAR configuration is missing"
    end

    -- Validate required endpoints
    local has_siem = self.config.soar_config.siem_endpoint and #self.config.soar_config.siem_endpoint > 0
    local has_soar = self.config.soar_config.soar_endpoint and #self.config.soar_config.soar_endpoint > 0

    if not has_siem and not has_soar then
        return false, "At least one of SIEM or SOAR endpoint must be configured"
    end

    kong.log.info("SOAR client initialized successfully")
    return true
end

--- Forward security event to SIEM platform
-- @param event The security event data
-- @return success, error
function _M:forward_to_siem(event)
    if not self.config.soar_config.siem_endpoint then
        return true -- SIEM not configured, skip
    end

    local siem_event = self:format_siem_event(event)
    if not siem_event then
        return false, "Failed to format SIEM event"
    end

    local success, err = self:send_http_request(
        self.config.soar_config.siem_endpoint,
        "POST",
        siem_event,
        { ["Content-Type"] = "application/json" }
    )

    if success then
        kong.log.info("Successfully forwarded event to SIEM: ", event.id or "unknown")
    else
        kong.log.err("Failed to forward event to SIEM: ", err)
    end

    return success, err
end

--- Create incident in SOAR platform
-- @param threat_data The threat detection data
-- @return incident_id, error
function _M:create_incident(threat_data)
    if not self.config.soar_config.soar_endpoint then
        return nil, "SOAR endpoint not configured"
    end

    local incident_data = self:format_incident_data(threat_data)
    if not incident_data then
        return nil, "Failed to format incident data"
    end

    local success, response, err = self:send_http_request(
        self.config.soar_config.soar_endpoint .. "/incidents",
        "POST",
        incident_data,
        {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer " .. (self.config.soar_config.api_key or "")
        }
    )

    if success and response then
        local response_data = cjson.decode(response)
        if response_data and response_data.id then
            kong.log.info("Successfully created SOAR incident: ", response_data.id)
            return response_data.id
        end
    end

    kong.log.err("Failed to create SOAR incident: ", err)
    return nil, err
end

--- Update incident status in SOAR platform
-- @param incident_id The incident ID
-- @param status The new status
-- @param details Additional details
-- @return success, error
function _M:update_incident_status(incident_id, status, details)
    if not self.config.soar_config.soar_endpoint then
        return false, "SOAR endpoint not configured"
    end

    local update_data = {
        status = status,
        updated_at = ngx.now() * 1000,
        details = details or {}
    }

    local success, response, err = self:send_http_request(
        self.config.soar_config.soar_endpoint .. "/incidents/" .. incident_id,
        "PUT",
        update_data,
        {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer " .. (self.config.soar_config.api_key or "")
        }
    )

    if success then
        kong.log.info("Successfully updated SOAR incident status: ", incident_id, " -> ", status)
    else
        kong.log.err("Failed to update SOAR incident status: ", err)
    end

    return success, err
end

--- Execute SOAR playbook
-- @param playbook_id The playbook ID to execute
-- @param context The execution context
-- @return execution_id, error
function _M:execute_playbook(playbook_id, context)
    if not self.config.soar_config.soar_endpoint then
        return nil, "SOAR endpoint not configured"
    end

    local execution_data = {
        playbook_id = playbook_id,
        context = context or {},
        triggered_at = ngx.now() * 1000
    }

    local success, response, err = self:send_http_request(
        self.config.soar_config.soar_endpoint .. "/playbooks/" .. playbook_id .. "/execute",
        "POST",
        execution_data,
        {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer " .. (self.config.soar_config.api_key or "")
        }
    )

    if success and response then
        local response_data = cjson.decode(response)
        if response_data and response_data.execution_id then
            kong.log.info("Successfully executed SOAR playbook: ", playbook_id)
            return response_data.execution_id
        end
    end

    kong.log.err("Failed to execute SOAR playbook: ", err)
    return nil, err
end

--- Add event to batch queue for bulk processing
-- @param event The security event
function _M:queue_event(event)
    table.insert(self.batch_queue, event)

    -- Check if we should flush the batch
    if #self.batch_queue >= MAX_BATCH_SIZE or
       (ngx.now() - self.last_batch_time) > 30 then -- 30 seconds
        self:flush_batch()
    end
end

--- Flush batched events to SIEM
function _M:flush_batch()
    if #self.batch_queue == 0 then
        return
    end

    if not self.config.soar_config.siem_endpoint then
        self.batch_queue = {} -- Clear queue if SIEM not configured
        return
    end

    local batch_data = {
        events = self.batch_queue,
        batch_id = ngx.now() .. "_" .. #self.batch_queue,
        timestamp = ngx.now() * 1000
    }

    local success, err = self:send_http_request(
        self.config.soar_config.siem_endpoint .. "/batch",
        "POST",
        batch_data,
        { ["Content-Type"] = "application/json" }
    )

    if success then
        kong.log.info("Successfully flushed batch of ", #self.batch_queue, " events to SIEM")
        self.batch_queue = {}
        self.last_batch_time = ngx.now()
        self.retry_count = 0
    else
        kong.log.err("Failed to flush batch to SIEM: ", err)
        self.retry_count = self.retry_count + 1

        -- Retry logic
        if self.retry_count < RETRY_ATTEMPTS then
            ngx.timer.at(RETRY_BACKOFF / 1000 * self.retry_count, function()
                self:flush_batch()
            end)
        else
            kong.log.err("Max retries exceeded for batch flush, dropping ", #self.batch_queue, " events")
            self.batch_queue = {}
            self.retry_count = 0
        end
    end
end

--- Format event for SIEM consumption
-- @param event Raw security event
-- @return Formatted SIEM event
function _M:format_siem_event(event)
    if not event then return nil end

    return {
        event_id = event.id or ngx.now(),
        timestamp = event.timestamp or (ngx.now() * 1000),
        source = "kong-guard-ai",
        severity = self:calculate_severity(event.threat_score or 0),
        message = event.message or "Security threat detected",
        details = {
            threat_score = event.threat_score or 0,
            client_ip = event.client_ip,
            request_path = event.request_path,
            user_agent = event.user_agent,
            threat_details = event.threat_details or {},
            raw_data = event
        }
    }
end

--- Format incident data for SOAR platform
-- @param threat_data Threat detection data
-- @return Formatted incident data
function _M:format_incident_data(threat_data)
    if not threat_data then return nil end

    return {
        title = "Kong Guard AI Security Incident",
        description = threat_data.message or "Security threat detected by Kong Guard AI",
        severity = self:calculate_severity(threat_data.threat_score or 0),
        status = "open",
        created_at = ngx.now() * 1000,
        source = "kong-guard-ai",
        details = {
            threat_score = threat_data.threat_score or 0,
            client_ip = threat_data.client_ip,
            request_path = threat_data.request_path,
            user_agent = threat_data.user_agent,
            threat_details = threat_data.threat_details or {},
            raw_data = threat_data
        },
        tags = {"kong", "waf", "security", "automated"}
    }
end

--- Calculate severity level from threat score
-- @param threat_score Numeric threat score (0-1)
-- @return Severity string
function _M:calculate_severity(threat_score)
    if threat_score >= 0.9 then
        return "critical"
    elseif threat_score >= 0.7 then
        return "high"
    elseif threat_score >= 0.5 then
        return "medium"
    elseif threat_score >= 0.3 then
        return "low"
    else
        return "info"
    end
end

--- Send HTTP request with error handling
-- @param url The URL to request
-- @param method HTTP method
-- @param body Request body
-- @param headers Request headers
-- @return success, response_body, error
function _M:send_http_request(url, method, body, headers)
    if not url then
        return false, nil, "URL is required"
    end

    local request_body = nil
    if body and type(body) == "table" then
        request_body = cjson.encode(body)
    elseif body then
        request_body = tostring(body)
    end

    local res, err = self.http_client:request_uri(url, {
        method = method or "GET",
        body = request_body,
        headers = headers or {},
        ssl_verify = true
    })

    if not res then
        return false, nil, err
    end

    if res.status >= 200 and res.status < 300 then
        return true, res.body
    else
        return false, res.body, "HTTP " .. res.status .. ": " .. (res.body or "Unknown error")
    end
end

--- Get client health status
-- @return status table
function _M:get_health_status()
    local status = {
        enabled = self.config.enable_soar_integration or false,
        siem_configured = self.config.soar_config and self.config.soar_config.siem_endpoint,
        soar_configured = self.config.soar_config and self.config.soar_config.soar_endpoint,
        batch_queue_size = #self.batch_queue,
        last_batch_time = self.last_batch_time,
        retry_count = self.retry_count
    }

    return status
end

return _M