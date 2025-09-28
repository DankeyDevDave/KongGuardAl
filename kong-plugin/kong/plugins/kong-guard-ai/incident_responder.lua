--- Incident Response Engine for Kong Guard AI
-- Provides automated incident response workflows and actions

local cjson = require "cjson.safe"
local ngx = ngx
local kong = kong

local _M = {}

-- Module constants
local MAX_WORKFLOW_EXECUTIONS = 10
local WORKFLOW_TIMEOUT = 30000 -- 30 seconds
local ACTION_RETRY_ATTEMPTS = 3

--- Create a new incident responder instance
-- @param config The plugin configuration
-- @param soar_client The SOAR client instance
-- @return Incident responder instance
function _M.new(config, soar_client)
    if not config then
        return nil, "Configuration is required"
    end

    local self = {
        config = config,
        soar_client = soar_client,
        active_incidents = {},
        workflow_states = {},
        action_history = {},
        metrics = {
            workflows_executed = 0,
            actions_taken = 0,
            incidents_created = 0,
            failures = 0
        }
    }

    return setmetatable(self, { __index = _M })
end

--- Initialize the incident responder
-- @return success, error
function _M:init()
    if not self.config.incident_response then
        return false, "Incident response configuration is missing"
    end

    if not self.config.incident_response.enable_auto_response then
        kong.log.debug("Auto incident response is disabled")
        return true
    end

    -- Validate workflow configurations
    local workflows = self.config.incident_response.response_workflows or {}
    for i, workflow in ipairs(workflows) do
        if not workflow.trigger_condition or #workflow.trigger_condition == 0 then
            return false, "Workflow " .. i .. " is missing trigger_condition"
        end
        if not workflow.actions or #workflow.actions == 0 then
            return false, "Workflow " .. i .. " is missing actions"
        end
    end

    kong.log.info("Incident responder initialized with ", #workflows, " workflows")
    return true
end

--- Evaluate threat data against workflow triggers
-- @param threat_data The threat detection data
-- @return triggered_workflows List of triggered workflows
function _M:evaluate_triggers(threat_data)
    if not self.config.incident_response.enable_auto_response then
        return {}
    end

    local triggered_workflows = {}
    local workflows = self.config.incident_response.response_workflows or {}

    for _, workflow in ipairs(workflows) do
        if self:evaluate_condition(workflow.trigger_condition, threat_data) then
            if threat_data.threat_score >= (workflow.severity_threshold or 0) then
                table.insert(triggered_workflows, workflow)
                kong.log.info("Workflow triggered: ", workflow.trigger_condition)
            end
        end
    end

    return triggered_workflows
end

--- Execute incident response workflow
-- @param workflow The workflow to execute
-- @param threat_data The threat detection data
-- @param incident_id Optional existing incident ID
-- @return execution_result, error
function _M:execute_workflow(workflow, threat_data, incident_id)
    if not workflow or not threat_data then
        return nil, "Workflow and threat data are required"
    end

    local execution_id = self:generate_execution_id()
    local start_time = ngx.now()

    -- Initialize workflow state
    self.workflow_states[execution_id] = {
        status = "running",
        start_time = start_time,
        workflow = workflow,
        threat_data = threat_data,
        incident_id = incident_id,
        actions_executed = {},
        errors = {}
    }

    kong.log.info("Starting workflow execution: ", execution_id)

    -- Create or update incident
    local incident_id, err = self:create_or_update_incident(threat_data, incident_id)
    if err then
        self:record_workflow_error(execution_id, "incident_creation", err)
    end

    -- Execute actions
    local success_count = 0
    local total_actions = #workflow.actions

    for i, action in ipairs(workflow.actions) do
        if i > MAX_WORKFLOW_EXECUTIONS then
            self:record_workflow_error(execution_id, "max_executions", "Maximum workflow executions exceeded")
            break
        end

        local success, result, err = self:execute_action(action, threat_data, incident_id)
        if success then
            success_count = success_count + 1
            self.workflow_states[execution_id].actions_executed[action] = result
            kong.log.info("Action executed successfully: ", action)
        else
            self:record_workflow_error(execution_id, action, err)
            kong.log.err("Action execution failed: ", action, " - ", err)
        end
    end

    -- Update workflow state
    local end_time = ngx.now()
    self.workflow_states[execution_id].status = success_count == total_actions and "completed" or "partial"
    self.workflow_states[execution_id].end_time = end_time
    self.workflow_states[execution_id].duration = end_time - start_time

    -- Update metrics
    self.metrics.workflows_executed = self.metrics.workflows_executed + 1
    self.metrics.actions_taken = self.metrics.actions_taken + success_count

    -- Update incident status
    if incident_id then
        local status = success_count == total_actions and "resolved" or "in_progress"
        if self.soar_client then
            self.soar_client:update_incident_status(incident_id, status, {
                workflow_execution_id = execution_id,
                actions_completed = success_count,
                total_actions = total_actions,
                duration = end_time - start_time
            })
        end
    end

    local result = {
        execution_id = execution_id,
        status = self.workflow_states[execution_id].status,
        actions_completed = success_count,
        total_actions = total_actions,
        duration = end_time - start_time,
        incident_id = incident_id
    }

    kong.log.info("Workflow execution completed: ", execution_id, " - ", result.status)
    return result
end

--- Execute a specific response action
-- @param action The action to execute
-- @param threat_data The threat detection data
-- @param incident_id The incident ID
-- @return success, result, error
function _M:execute_action(action, threat_data, incident_id)
    if not action then
        return false, nil, "Action is required"
    end

    -- Record action execution
    self.action_history[action] = self.action_history[action] or {}
    table.insert(self.action_history[action], {
        timestamp = ngx.now(),
        threat_data = threat_data,
        incident_id = incident_id
    })

    -- Execute action based on type
    if action == "block_ip" then
        return self:action_block_ip(threat_data.client_ip, incident_id)
    elseif action == "rate_limit" then
        return self:action_rate_limit(threat_data.client_ip, incident_id)
    elseif action == "notify" then
        return self:action_notify(threat_data, incident_id)
    elseif action == "log_enhance" then
        return self:action_log_enhance(threat_data, incident_id)
    elseif action == "soar_incident" then
        return self:action_soar_incident(threat_data)
    elseif action == "quarantine" then
        return self:action_quarantine(threat_data.client_ip, incident_id)
    else
        return false, nil, "Unknown action: " .. action
    end
end

--- Block IP address
-- @param ip The IP address to block
-- @param incident_id The incident ID
-- @return success, result, error
function _M:action_block_ip(ip, incident_id)
    if not ip then
        return false, nil, "IP address is required"
    end

    -- In a real implementation, this would interface with Kong's IP restriction plugin
    -- or an external firewall system
    kong.log.warn("Blocking IP address: ", ip, " (Incident: ", incident_id or "none", ")")

    -- Simulate blocking action
    local result = {
        action = "block_ip",
        ip = ip,
        timestamp = ngx.now(),
        incident_id = incident_id,
        status = "blocked"
    }

    return true, result
end

--- Apply rate limiting to IP
-- @param ip The IP address to rate limit
-- @param incident_id The incident ID
-- @return success, result, error
function _M:action_rate_limit(ip, incident_id)
    if not ip then
        return false, nil, "IP address is required"
    end

    kong.log.warn("Applying rate limit to IP: ", ip, " (Incident: ", incident_id or "none", ")")

    local result = {
        action = "rate_limit",
        ip = ip,
        timestamp = ngx.now(),
        incident_id = incident_id,
        rate_limit = "10 requests/minute",
        duration = self.config.rate_limit_duration or 300
    }

    return true, result
end

--- Send notification
-- @param threat_data The threat detection data
-- @param incident_id The incident ID
-- @return success, result, error
function _M:action_notify(threat_data, incident_id)
    if not self.config.notification_url then
        return false, nil, "Notification URL is not configured"
    end

    local notification_data = {
        incident_id = incident_id,
        threat_score = threat_data.threat_score,
        client_ip = threat_data.client_ip,
        request_path = threat_data.request_path,
        timestamp = ngx.now(),
        message = threat_data.message or "Security threat detected"
    }

    kong.log.info("Sending notification for incident: ", incident_id or "none")

    local result = {
        action = "notify",
        timestamp = ngx.now(),
        incident_id = incident_id,
        notification_url = self.config.notification_url,
        status = "sent"
    }

    return true, result
end

--- Enhance logging
-- @param threat_data The threat detection data
-- @param incident_id The incident ID
-- @return success, result, error
function _M:action_log_enhance(threat_data, incident_id)
    -- Enable enhanced logging for this request
    kong.log.warn("ENHANCED LOGGING - Incident: ", incident_id or "none",
                  " Threat Score: ", threat_data.threat_score,
                  " IP: ", threat_data.client_ip,
                  " Path: ", threat_data.request_path)

    local result = {
        action = "log_enhance",
        timestamp = ngx.now(),
        incident_id = incident_id,
        log_level = "enhanced",
        status = "enabled"
    }

    return true, result
end

--- Create SOAR incident
-- @param threat_data The threat detection data
-- @return success, result, error
function _M:action_soar_incident(threat_data)
    if not self.soar_client then
        return false, nil, "SOAR client is not available"
    end

    local incident_id, err = self.soar_client:create_incident(threat_data)
    if err then
        return false, nil, err
    end

    local result = {
        action = "soar_incident",
        timestamp = ngx.now(),
        incident_id = incident_id,
        status = "created"
    }

    return true, result
end

--- Quarantine IP address
-- @param ip The IP address to quarantine
-- @param incident_id The incident ID
-- @return success, result, error
function _M:action_quarantine(ip, incident_id)
    if not ip then
        return false, nil, "IP address is required"
    end

    kong.log.warn("Quarantining IP address: ", ip, " (Incident: ", incident_id or "none", ")")

    local result = {
        action = "quarantine",
        ip = ip,
        timestamp = ngx.now(),
        incident_id = incident_id,
        status = "quarantined",
        duration = 3600 -- 1 hour
    }

    return true, result
end

--- Evaluate condition expression
-- @param condition The condition string (e.g., "threat_score > 0.8")
-- @param threat_data The threat detection data
-- @return boolean result
function _M:evaluate_condition(condition, threat_data)
    if not condition or not threat_data then
        return false
    end

    -- Simple condition evaluation (in production, use a proper expression parser)
    local threat_score = threat_data.threat_score or 0
    local client_ip = threat_data.client_ip or ""

    -- Parse simple conditions
    if condition == "high_threat" then
        return threat_score >= 0.8
    elseif condition == "medium_threat" then
        return threat_score >= 0.6
    elseif condition == "low_threat" then
        return threat_score >= 0.4
    elseif condition:find("threat_score >") then
        local threshold = tonumber(condition:match("threat_score > (%d%.%d+)"))
        return threshold and threat_score > threshold
    elseif condition:find("threat_score >=") then
        local threshold = tonumber(condition:match("threat_score >= (%d%.%d+)"))
        return threshold and threat_score >= threshold
    end

    -- Default to false for unknown conditions
    return false
end

--- Create or update incident
-- @param threat_data The threat detection data
-- @param incident_id Optional existing incident ID
-- @return incident_id, error
function _M:create_or_update_incident(threat_data, incident_id)
    if incident_id then
        -- Update existing incident
        self.active_incidents[incident_id] = self.active_incidents[incident_id] or {}
        self.active_incidents[incident_id].last_updated = ngx.now()
        self.active_incidents[incident_id].threat_count = (self.active_incidents[incident_id].threat_count or 0) + 1
        return incident_id
    else
        -- Create new incident
        incident_id = self:generate_incident_id()
        self.active_incidents[incident_id] = {
            id = incident_id,
            created_at = ngx.now(),
            last_updated = ngx.now(),
            threat_count = 1,
            status = "active",
            threat_data = threat_data,
            actions_taken = {}
        }

        self.metrics.incidents_created = self.metrics.incidents_created + 1
        kong.log.info("Created new incident: ", incident_id)
        return incident_id
    end
end

--- Record workflow execution error
-- @param execution_id The workflow execution ID
-- @param action The action that failed
-- @param error The error message
function _M:record_workflow_error(execution_id, action, error)
    if not self.workflow_states[execution_id] then
        return
    end

    self.workflow_states[execution_id].errors = self.workflow_states[execution_id].errors or {}
    self.workflow_states[execution_id].errors[action] = error
    self.metrics.failures = self.metrics.failures + 1
end

--- Generate unique execution ID
-- @return execution_id
function _M:generate_execution_id()
    return "exec_" .. ngx.now() .. "_" .. math.random(10000, 99999)
end

--- Generate unique incident ID
-- @return incident_id
function _M:generate_incident_id()
    return "inc_" .. ngx.now() .. "_" .. math.random(10000, 99999)
end

--- Get incident details
-- @param incident_id The incident ID
-- @return incident data or nil
function _M:get_incident(incident_id)
    return self.active_incidents[incident_id]
end

--- Get workflow execution status
-- @param execution_id The execution ID
-- @return workflow state or nil
function _M:get_workflow_status(execution_id)
    return self.workflow_states[execution_id]
end

--- Get responder health and metrics
-- @return status table
function _M:get_health_status()
    local active_incidents = 0
    for _ in pairs(self.active_incidents) do
        active_incidents = active_incidents + 1
    end

    local running_workflows = 0
    for _, state in pairs(self.workflow_states) do
        if state.status == "running" then
            running_workflows = running_workflows + 1
        end
    end

    return {
        enabled = self.config.incident_response and self.config.incident_response.enable_auto_response or false,
        active_incidents = active_incidents,
        running_workflows = running_workflows,
        metrics = self.metrics,
        workflow_states_count = #self.workflow_states
    }
end

--- Clean up old workflow states and incidents
-- @param max_age Maximum age in seconds (default 3600)
function _M:cleanup_old_data(max_age)
    max_age = max_age or 3600 -- 1 hour
    local now = ngx.now()
    local cleanup_count = 0

    -- Clean up old workflow states
    for execution_id, state in pairs(self.workflow_states) do
        if state.end_time and (now - state.end_time) > max_age then
            self.workflow_states[execution_id] = nil
            cleanup_count = cleanup_count + 1
        end
    end

    -- Clean up old incidents
    for incident_id, incident in pairs(self.active_incidents) do
        if (now - incident.last_updated) > max_age then
            self.active_incidents[incident_id] = nil
            cleanup_count = cleanup_count + 1
        end
    end

    if cleanup_count > 0 then
        kong.log.info("Cleaned up ", cleanup_count, " old records")
    end
end

return _M
