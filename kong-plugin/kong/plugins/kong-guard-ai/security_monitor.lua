--- Security Monitoring and Alerting Module for Kong Guard AI
-- Monitors security events, detects anomalies, and manages alerts

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local math = math
local table = table

-- Alert severity levels
local ALERT_SEVERITY = {
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high",
    CRITICAL = "critical"
}

-- Alert types
local ALERT_TYPES = {
    BRUTE_FORCE = "brute_force_attack",
    DDoS_ATTACK = "ddos_attack",
    SQL_INJECTION = "sql_injection_attempt",
    XSS_ATTACK = "xss_attack",
    UNAUTHORIZED_ACCESS = "unauthorized_access",
    DATA_BREACH = "data_breach",
    ANOMALOUS_TRAFFIC = "anomalous_traffic",
    CONFIGURATION_CHANGE = "configuration_change",
    COMPLIANCE_VIOLATION = "compliance_violation",
    SYSTEM_ANOMALY = "system_anomaly"
}

-- Monitoring metrics
local MONITORING_METRICS = {
    REQUEST_RATE = "request_rate",
    ERROR_RATE = "error_rate",
    BLOCKED_REQUESTS = "blocked_requests",
    AUTH_FAILURES = "auth_failures",
    SUSPICIOUS_PATTERNS = "suspicious_patterns",
    DATA_ACCESS_PATTERNS = "data_access_patterns",
    CONFIGURATION_CHANGES = "configuration_changes",
    COMPLIANCE_VIOLATIONS = "compliance_violations"
}

--- Create a new security monitor instance
function _M.new(config)
    local self = {
        config = config or {},
        alerts = {},
        monitoring_data = {},
        anomaly_detectors = {},
        alert_rules = {},
        notification_channels = config.notification_channels or {},
        alert_thresholds = config.alert_thresholds or {},
        monitoring_window = config.monitoring_window or 300, -- 5 minutes
        enable_anomaly_detection = config.enable_anomaly_detection or true,
        enable_automated_response = config.enable_automated_response or false,
        alert_cooldown_period = config.alert_cooldown_period or 300, -- 5 minutes
        max_alerts_per_window = config.max_alerts_per_window or 100
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the security monitor
function _M:init()
    -- Set up monitoring data collection
    local ok, err = ngx.timer.every(60, function() -- Every minute
        self:_collect_monitoring_data()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize monitoring data collection: ", err)
    end

    -- Set up alert processing
    local ok2, err2 = ngx.timer.every(30, function() -- Every 30 seconds
        self:_process_alerts()
    end)

    if not ok2 then
        kong.log.err("[kong-guard-ai] Failed to initialize alert processing: ", err2)
    end

    -- Set up anomaly detection
    if self.enable_anomaly_detection then
        local ok3, err3 = ngx.timer.every(120, function() -- Every 2 minutes
            self:_run_anomaly_detection()
        end)

        if not ok3 then
            kong.log.err("[kong-guard-ai] Failed to initialize anomaly detection: ", err3)
        end
    end

    -- Initialize default alert rules
    self:_initialize_default_alert_rules()

    kong.log.info("[kong-guard-ai] Security monitor initialized")
end

--- Record security event
function _M:record_security_event(event_type, event_data, context)
    if not event_type or not event_data then
        return false, "Event type and data are required"
    end

    local event = {
        event_id = self:_generate_event_id(),
        event_type = event_type,
        timestamp = ngx.now(),
        data = event_data,
        context = context or {},
        severity = self:_calculate_event_severity(event_type, event_data),
        source_ip = context.client_ip or context.ip_address,
        user_id = context.user_id,
        session_id = context.session_id,
        user_agent = context.user_agent
    }

    -- Store event for monitoring
    self:_store_monitoring_event(event)

    -- Check against alert rules
    local alerts_triggered = self:_check_alert_rules(event)

    -- Process triggered alerts
    for _, alert in ipairs(alerts_triggered) do
        self:_process_triggered_alert(alert, event)
    end

    kong.log.debug("[kong-guard-ai] Security event recorded: ", event.event_id, " type: ", event_type)

    return true, {
        event_id = event.event_id,
        alerts_triggered = #alerts_triggered,
        severity = event.severity
    }
end

--- Create custom alert rule
function _M:create_alert_rule(rule_data, context)
    if not rule_data.name or not rule_data.condition then
        return false, "Rule name and condition are required"
    end

    local rule_id = self:_generate_rule_id()
    local rule = {
        rule_id = rule_id,
        name = rule_data.name,
        description = rule_data.description,
        event_type = rule_data.event_type,
        condition = rule_data.condition,
        threshold = rule_data.threshold or 1,
        severity = rule_data.severity or ALERT_SEVERITY.MEDIUM,
        time_window = rule_data.time_window or 300, -- 5 minutes
        cooldown_period = rule_data.cooldown_period or self.alert_cooldown_period,
        enabled = rule_data.enabled ~= false,
        created_at = ngx.now(),
        created_by = context.user_id,
        last_triggered = nil,
        trigger_count = 0
    }

    self.alert_rules[rule_id] = rule

    kong.log.info("[kong-guard-ai] Alert rule created: ", rule_id, " - ", rule_data.name)

    return true, rule
end

--- Update alert rule
function _M:update_alert_rule(rule_id, updates, context)
    local rule = self.alert_rules[rule_id]
    if not rule then
        return false, "Alert rule not found"
    end

    -- Apply updates
    for key, value in pairs(updates) do
        if key ~= "rule_id" and key ~= "created_at" and key ~= "created_by" then
            rule[key] = value
        end
    end

    rule.updated_at = ngx.now()
    rule.updated_by = context.user_id

    kong.log.info("[kong-guard-ai] Alert rule updated: ", rule_id)

    return true, rule
end

--- Delete alert rule
function _M:delete_alert_rule(rule_id, context)
    if not self.alert_rules[rule_id] then
        return false, "Alert rule not found"
    end

    self.alert_rules[rule_id] = nil

    kong.log.info("[kong-guard-ai] Alert rule deleted: ", rule_id)

    return true
end

--- Get active alerts
function _M:get_active_alerts(options)
    options = options or {}
    local active_alerts = {}

    for _, alert in pairs(self.alerts) do
        if not alert.resolved_at then
            -- Check if alert matches filters
            if self:_matches_alert_filter(alert, options) then
                table.insert(active_alerts, alert)
            end
        end
    end

    -- Sort by severity and timestamp
    table.sort(active_alerts, function(a, b)
        if a.severity ~= b.severity then
            local severity_order = {critical = 4, high = 3, medium = 2, low = 1}
            return severity_order[a.severity] > severity_order[b.severity]
        end
        return a.timestamp > b.timestamp
    end)

    -- Apply limit
    if options.limit then
        local limited = {}
        for i = 1, math.min(options.limit, #active_alerts) do
            table.insert(limited, active_alerts[i])
        end
        active_alerts = limited
    end

    return active_alerts
end

--- Resolve alert
function _M:resolve_alert(alert_id, resolution_data, context)
    local alert = self.alerts[alert_id]
    if not alert then
        return false, "Alert not found"
    end

    if alert.resolved_at then
        return false, "Alert already resolved"
    end

    alert.resolved_at = ngx.now()
    alert.resolution = resolution_data.resolution or "Manually resolved"
    alert.resolved_by = context.user_id
    alert.resolution_notes = resolution_data.notes

    kong.log.info("[kong-guard-ai] Alert resolved: ", alert_id, " - ", alert.resolution)

    return true, alert
end

--- Get security metrics
function _M:get_security_metrics(time_window)
    time_window = time_window or 3600 -- 1 hour
    local current_time = ngx.now()
    local start_time = current_time - time_window

    local metrics = {
        time_window_seconds = time_window,
        total_events = 0,
        events_by_type = {},
        events_by_severity = {},
        alerts_generated = 0,
        alerts_by_severity = {},
        active_alerts = 0,
        resolved_alerts = 0,
        top_attack_types = {},
        geographic_distribution = {},
        response_times = {}
    }

    -- Aggregate monitoring data
    for _, event_list in pairs(self.monitoring_data) do
        for _, event in ipairs(event_list) do
            if event.timestamp >= start_time then
                metrics.total_events = metrics.total_events + 1

                -- Count by type
                metrics.events_by_type[event.event_type] = (metrics.events_by_type[event.event_type] or 0) + 1

                -- Count by severity
                metrics.events_by_severity[event.severity] = (metrics.events_by_severity[event.severity] or 0) + 1
            end
        end
    end

    -- Aggregate alert data
    for _, alert in pairs(self.alerts) do
        if alert.timestamp >= start_time then
            metrics.alerts_generated = metrics.alerts_generated + 1
            metrics.alerts_by_severity[alert.severity] = (metrics.alerts_by_severity[alert.severity] or 0) + 1
        end

        if not alert.resolved_at then
            metrics.active_alerts = metrics.active_alerts + 1
        elseif alert.resolved_at >= start_time then
            metrics.resolved_alerts = metrics.resolved_alerts + 1
        end
    end

    return metrics
end

--- Send alert notification
function _M:send_alert_notification(alert, channels)
    channels = channels or self.notification_channels

    for _, channel in ipairs(channels) do
        if channel.enabled then
            local success = self:_send_notification_to_channel(alert, channel)
            if success then
                kong.log.debug("[kong-guard-ai] Alert notification sent via ", channel.type)
            else
                kong.log.warn("[kong-guard-ai] Failed to send alert notification via ", channel.type)
            end
        end
    end
end

--- Helper functions

function _M:_generate_event_id()
    return "evt_" .. ngx.now() .. "_" .. math.random(1000000, 9999999)
end

function _M:_generate_rule_id()
    return "rule_" .. ngx.now() .. "_" .. math.random(1000000, 9999999)
end

function _M:_calculate_event_severity(event_type, event_data)
    -- Default severity mappings
    local severity_map = {
        [ALERT_TYPES.BRUTE_FORCE] = ALERT_SEVERITY.HIGH,
        [ALERT_TYPES.DDoS_ATTACK] = ALERT_SEVERITY.CRITICAL,
        [ALERT_TYPES.SQL_INJECTION] = ALERT_SEVERITY.HIGH,
        [ALERT_TYPES.XSS_ATTACK] = ALERT_SEVERITY.MEDIUM,
        [ALERT_TYPES.UNAUTHORIZED_ACCESS] = ALERT_SEVERITY.HIGH,
        [ALERT_TYPES.DATA_BREACH] = ALERT_SEVERITY.CRITICAL,
        [ALERT_TYPES.ANOMALOUS_TRAFFIC] = ALERT_SEVERITY.MEDIUM,
        [ALERT_TYPES.CONFIGURATION_CHANGE] = ALERT_SEVERITY.LOW,
        [ALERT_TYPES.COMPLIANCE_VIOLATION] = ALERT_SEVERITY.MEDIUM,
        [ALERT_TYPES.SYSTEM_ANOMALY] = ALERT_SEVERITY.MEDIUM
    }

    return severity_map[event_type] or ALERT_SEVERITY.MEDIUM
end

function _M:_store_monitoring_event(event)
    local event_type = event.event_type

    if not self.monitoring_data[event_type] then
        self.monitoring_data[event_type] = {}
    end

    table.insert(self.monitoring_data[event_type], event)

    -- Limit stored events per type to prevent unbounded growth
    if #self.monitoring_data[event_type] > 10000 then
        table.remove(self.monitoring_data[event_type], 1)
    end
end

function _M:_check_alert_rules(event)
    local triggered_alerts = {}

    for rule_id, rule in pairs(self.alert_rules) do
        if rule.enabled and (not rule.event_type or rule.event_type == event.event_type) then
            if self:_evaluate_alert_rule(rule, event) then
                local alert = self:_create_alert_from_rule(rule, event)
                table.insert(triggered_alerts, alert)
            end
        end
    end

    return triggered_alerts
end

function _M:_evaluate_alert_rule(rule, event)
    -- Check cooldown period
    if rule.last_triggered and ngx.now() - rule.last_triggered < rule.cooldown_period then
        return false
    end

    -- Evaluate condition (simplified - in production would use a proper expression evaluator)
    if rule.condition == "threshold_exceeded" then
        local event_count = self:_count_events_in_window(rule.event_type, rule.time_window)
        return event_count >= rule.threshold
    elseif rule.condition == "severity_match" then
        return event.severity == rule.severity
    elseif rule.condition == "pattern_match" then
        return self:_check_pattern_match(event, rule.pattern)
    end

    return false
end

function _M:_create_alert_from_rule(rule, event)
    local alert_id = "alert_" .. ngx.now() .. "_" .. math.random(1000000, 9999999)

    local alert = {
        alert_id = alert_id,
        rule_id = rule.rule_id,
        rule_name = rule.name,
        severity = rule.severity,
        title = rule.name,
        description = rule.description or "Alert triggered by rule: " .. rule.name,
        event_type = event.event_type,
        event_id = event.event_id,
        timestamp = ngx.now(),
        source_ip = event.source_ip,
        user_id = event.user_id,
        details = {
            event_data = event.data,
            context = event.context,
            rule_condition = rule.condition,
            threshold = rule.threshold
        },
        status = "active",
        resolved_at = nil,
        resolution = nil,
        notifications_sent = 0
    }

    -- Store alert
    self.alerts[alert_id] = alert

    -- Update rule trigger info
    rule.last_triggered = ngx.now()
    rule.trigger_count = rule.trigger_count + 1

    return alert
end

function _M:_process_triggered_alert(alert, event)
    -- Send notifications
    self:send_alert_notification(alert)

    -- Execute automated response if enabled
    if self.enable_automated_response then
        self:_execute_automated_response(alert, event)
    end

    -- Update alert
    alert.notifications_sent = alert.notifications_sent + 1

    kong.log.warn("[kong-guard-ai] Alert triggered: ", alert.alert_id, " - ", alert.title)
end

function _M:_initialize_default_alert_rules()
    -- Create default alert rules
    local default_rules = {
        {
            name = "Brute Force Attack Detection",
            event_type = ALERT_TYPES.BRUTE_FORCE,
            condition = "threshold_exceeded",
            threshold = 5,
            severity = ALERT_SEVERITY.HIGH,
            time_window = 300
        },
        {
            name = "DDoS Attack Detection",
            event_type = ALERT_TYPES.DDoS_ATTACK,
            condition = "threshold_exceeded",
            threshold = 1000,
            severity = ALERT_SEVERITY.CRITICAL,
            time_window = 60
        },
        {
            name = "SQL Injection Attempt",
            event_type = ALERT_TYPES.SQL_INJECTION,
            condition = "threshold_exceeded",
            threshold = 1,
            severity = ALERT_SEVERITY.HIGH,
            time_window = 300
        },
        {
            name = "Unauthorized Access Attempt",
            event_type = ALERT_TYPES.UNAUTHORIZED_ACCESS,
            condition = "threshold_exceeded",
            threshold = 3,
            severity = ALERT_SEVERITY.MEDIUM,
            time_window = 300
        },
        {
            name = "Data Breach Detection",
            event_type = ALERT_TYPES.DATA_BREACH,
            condition = "threshold_exceeded",
            threshold = 1,
            severity = ALERT_SEVERITY.CRITICAL,
            time_window = 300
        }
    }

    for _, rule_data in ipairs(default_rules) do
        self:create_alert_rule(rule_data, {user_id = "system"})
    end
end

function _M:_collect_monitoring_data()
    -- Collect current monitoring metrics
    local metrics = {
        timestamp = ngx.now(),
        request_rate = self:_get_current_request_rate(),
        error_rate = self:_get_current_error_rate(),
        blocked_requests = self:_get_current_blocked_requests(),
        auth_failures = self:_get_current_auth_failures()
    }

    -- Store metrics (keep last 100 entries)
    if not self.monitoring_data.metrics then
        self.monitoring_data.metrics = {}
    end

    table.insert(self.monitoring_data.metrics, metrics)

    if #self.monitoring_data.metrics > 100 then
        table.remove(self.monitoring_data.metrics, 1)
    end
end

function _M:_process_alerts()
    -- Process active alerts (escalation, auto-resolution, etc.)
    local current_time = ngx.now()

    for alert_id, alert in pairs(self.alerts) do
        if not alert.resolved_at then
            -- Check for alert escalation
            local age = current_time - alert.timestamp
            if age > 1800 and alert.severity == ALERT_SEVERITY.MEDIUM then -- 30 minutes
                alert.severity = ALERT_SEVERITY.HIGH
                kong.log.warn("[kong-guard-ai] Alert escalated: ", alert_id)
            end

            -- Check for auto-resolution based on time
            if age > 7200 then -- 2 hours
                self:resolve_alert(alert_id, {
                    resolution = "Auto-resolved due to age",
                    notes = "Alert automatically resolved after 2 hours"
                }, {user_id = "system"})
            end
        end
    end
end

function _M:_run_anomaly_detection()
    -- Run anomaly detection on monitoring data
    local anomalies = {}

    -- Check for request rate anomalies
    local request_rate_anomaly = self:_detect_request_rate_anomaly()
    if request_rate_anomaly then
        table.insert(anomalies, request_rate_anomaly)
    end

    -- Check for error rate anomalies
    local error_rate_anomaly = self:_detect_error_rate_anomaly()
    if error_rate_anomaly then
        table.insert(anomalies, error_rate_anomaly)
    end

    -- Process detected anomalies
    for _, anomaly in ipairs(anomalies) do
        self:record_security_event(ALERT_TYPES.SYSTEM_ANOMALY, anomaly, {
            anomaly_type = anomaly.type,
            detected_by = "anomaly_detection"
        })
    end
end

function _M:_count_events_in_window(event_type, time_window)
    local current_time = ngx.now()
    local start_time = current_time - time_window
    local count = 0

    local events = self.monitoring_data[event_type] or {}
    for _, event in ipairs(events) do
        if event.timestamp >= start_time then
            count = count + 1
        end
    end

    return count
end

function _M:_matches_alert_filter(alert, filters)
    if filters.severity and alert.severity ~= filters.severity then
        return false
    end

    if filters.event_type and alert.event_type ~= filters.event_type then
        return false
    end

    if filters.source_ip and alert.source_ip ~= filters.source_ip then
        return false
    end

    return true
end

function _M:_send_notification_to_channel(alert, channel)
    -- Mock notification sending - in production would integrate with actual notification services
    if channel.type == "email" then
        return self:_send_email_notification(alert, channel)
    elseif channel.type == "slack" then
        return self:_send_slack_notification(alert, channel)
    elseif channel.type == "webhook" then
        return self:_send_webhook_notification(alert, channel)
    end

    return false
end

function _M:_execute_automated_response(alert, event)
    -- Mock automated response - in production would implement actual response actions
    if alert.event_type == ALERT_TYPES.BRUTE_FORCE then
        kong.log.info("[kong-guard-ai] Executing automated response for brute force: blocking IP")
    elseif alert.event_type == ALERT_TYPES.DDoS_ATTACK then
        kong.log.info("[kong-guard-ai] Executing automated response for DDoS: enabling rate limiting")
    end
end

function _M:_detect_request_rate_anomaly()
    -- Mock anomaly detection
    return nil
end

function _M:_detect_error_rate_anomaly()
    -- Mock anomaly detection
    return nil
end

function _M:_get_current_request_rate()
    -- Mock metric collection
    return 100
end

function _M:_get_current_error_rate()
    -- Mock metric collection
    return 0.05
end

function _M:_get_current_blocked_requests()
    -- Mock metric collection
    return 5
end

function _M:_get_current_auth_failures()
    -- Mock metric collection
    return 2
end

function _M:_check_pattern_match(event, pattern)
    -- Mock pattern matching
    return false
end

function _M:_send_email_notification(alert, channel)
    -- Mock email sending
    kong.log.debug("[kong-guard-ai] Email notification would be sent to: ", channel.recipient)
    return true
end

function _M:_send_slack_notification(alert, channel)
    -- Mock Slack notification
    kong.log.debug("[kong-guard-ai] Slack notification would be sent to: ", channel.channel)
    return true
end

function _M:_send_webhook_notification(alert, channel)
    -- Mock webhook notification
    kong.log.debug("[kong-guard-ai] Webhook notification would be sent to: ", channel.url)
    return true
end

--- Get monitoring statistics
function _M:get_monitoring_statistics()
    return {
        total_alerts = self:_count_table_fields(self.alerts),
        active_alerts = self:_count_active_alerts(),
        total_rules = self:_count_table_fields(self.alert_rules),
        enabled_rules = self:_count_enabled_rules(),
        monitoring_enabled = true,
        anomaly_detection_enabled = self.enable_anomaly_detection,
        automated_response_enabled = self.enable_automated_response
    }
end

function _M:_count_active_alerts()
    local count = 0
    for _, alert in pairs(self.alerts) do
        if not alert.resolved_at then
            count = count + 1
        end
    end
    return count
end

function _M:_count_enabled_rules()
    local count = 0
    for _, rule in pairs(self.alert_rules) do
        if rule.enabled then
            count = count + 1
        end
    end
    return count
end

function _M:_count_table_fields(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

--- Validate monitoring configuration
function _M:validate_configuration()
    local issues = {}

    if self.monitoring_window < 60 then
        table.insert(issues, "Monitoring window is too short (minimum 60 seconds recommended)")
    end

    if self.alert_cooldown_period < 60 then
        table.insert(issues, "Alert cooldown period is too short (minimum 60 seconds recommended)")
    end

    if self.enable_automated_response and not self.notification_channels then
        table.insert(issues, "Automated response enabled but no notification channels configured")
    end

    return #issues == 0, issues
end

return _M
