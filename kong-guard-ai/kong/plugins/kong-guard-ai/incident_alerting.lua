-- Kong Guard AI - Incident Alerting and Real-time Notification Module
-- PHASE 4: Real-time incident alerting, escalation, and notification management
-- Handles critical incident alerts, team notifications, and escalation workflows

local kong = kong
local json = require "cjson.safe"
local http = require "resty.http"

local _M = {}

-- Alert severity thresholds
local ALERT_THRESHOLDS = {
    CRITICAL_INCIDENT_COUNT = 5,    -- Critical alert if 5+ incidents in 5 minutes
    HIGH_SEVERITY_IMMEDIATE = true, -- Immediate alert for high/critical severity
    REPEAT_OFFENDER_THRESHOLD = 3,  -- Alert if same IP has 3+ incidents
    ATTACK_CAMPAIGN_THRESHOLD = 10  -- Alert if campaign has 10+ incidents
}

-- Notification channels
local NOTIFICATION_CHANNELS = {
    SLACK = "slack",
    EMAIL = "email",
    WEBHOOK = "webhook",
    SMS = "sms",
    PAGERDUTY = "pagerduty",
    TEAMS = "teams"
}

-- Alert levels
local ALERT_LEVELS = {
    INFO = "info",
    WARNING = "warning",
    CRITICAL = "critical",
    EMERGENCY = "emergency"
}

-- Alert state tracking
local alert_state = {}
local notification_queue = {}
local escalation_timers = {}

---
-- Initialize incident alerting system
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Incident Alerting] Initializing alerting system")

    -- Initialize alert state
    alert_state.active_alerts = {}
    alert_state.suppressed_alerts = {}
    alert_state.alert_history = {}
    alert_state.last_cleanup = ngx.time()

    -- Initialize notification queue
    notification_queue.pending = {}
    notification_queue.failed = {}
    notification_queue.sent = {}

    -- Initialize escalation tracking
    escalation_timers.active = {}
    escalation_timers.completed = {}

    kong.log.info("[Kong Guard AI Incident Alerting] Alerting system initialized")
end

---
-- Process incident for alerting
-- @param incident Incident record
-- @param conf Plugin configuration
---
function _M.process_incident_for_alerting(incident, conf)
    -- Skip alerting if disabled
    if not conf.incident_alerting_enabled then
        return
    end

    -- Determine if this incident should trigger an alert
    local should_alert, alert_level = _M.should_trigger_alert(incident, conf)

    if should_alert then
        kong.log.info(string.format(
            "[Kong Guard AI Incident Alerting] Triggering %s alert for incident %s",
            alert_level,
            incident.incident_id
        ))

        -- Create alert
        local alert = _M.create_alert(incident, alert_level, conf)

        -- Send notifications
        _M.send_alert_notifications(alert, conf)

        -- Setup escalation if needed
        if alert_level == ALERT_LEVELS.CRITICAL or alert_level == ALERT_LEVELS.EMERGENCY then
            _M.setup_escalation(alert, conf)
        end

        -- Store alert
        alert_state.active_alerts[alert.alert_id] = alert
    end

    -- Check for attack patterns that require alerting
    _M.check_attack_patterns(incident, conf)
end

---
-- Determine if incident should trigger an alert
-- @param incident Incident record
-- @param conf Plugin configuration
-- @return Boolean should_alert, String alert_level
---
function _M.should_trigger_alert(incident, conf)
    local severity = incident.severity_level
    local incident_type = incident.type
    local source_ip = incident.network_forensics.source_ip

    -- Always alert for critical severity
    if severity == "critical" then
        return true, ALERT_LEVELS.EMERGENCY
    end

    -- Alert for high severity incidents
    if severity == "high" and ALERT_THRESHOLDS.HIGH_SEVERITY_IMMEDIATE then
        return true, ALERT_LEVELS.CRITICAL
    end

    -- Check for repeat offender
    if incident.correlation_data.incident_count_for_ip >= ALERT_THRESHOLDS.REPEAT_OFFENDER_THRESHOLD then
        return true, ALERT_LEVELS.WARNING
    end

    -- Check for attack campaigns
    if incident.correlation_data.campaign_id then
        local campaign_incidents = _M.count_campaign_incidents(incident.correlation_data.campaign_id)
        if campaign_incidents >= ALERT_THRESHOLDS.ATTACK_CAMPAIGN_THRESHOLD then
            return true, ALERT_LEVELS.CRITICAL
        end
    end

    -- Check for high incident rate
    local recent_incidents = _M.count_recent_incidents(300) -- Last 5 minutes
    if recent_incidents >= ALERT_THRESHOLDS.CRITICAL_INCIDENT_COUNT then
        return true, ALERT_LEVELS.CRITICAL
    end

    -- Check for specific threat types that always require alerting
    local critical_threat_types = {
        "sql_injection",
        "distributed_denial_of_service",
        "credential_stuffing"
    }

    for _, threat_type in ipairs(critical_threat_types) do
        if incident_type == threat_type then
            return true, ALERT_LEVELS.WARNING
        end
    end

    return false, nil
end

---
-- Create alert record
-- @param incident Incident that triggered the alert
-- @param alert_level Alert severity level
-- @param conf Plugin configuration
-- @return Table alert record
---
function _M.create_alert(incident, alert_level, conf)
    local alert_id = string.format("ALERT-%d-%s", ngx.time(), string.sub(incident.incident_id, -6))

    local alert = {
        alert_id = alert_id,
        incident_id = incident.incident_id,
        alert_level = alert_level,
        created_at = ngx.time(),
        status = "active",

        -- Alert context
        title = _M.generate_alert_title(incident, alert_level),
        description = _M.generate_alert_description(incident),
        source_ip = incident.network_forensics.source_ip,
        threat_type = incident.type,

        -- Incident summary
        incident_summary = {
            severity = incident.severity_level,
            confidence = incident.threat_analysis.confidence,
            enforcement_action = incident.decision,
            correlation_count = #incident.correlation_data.related_incidents
        },

        -- Notification tracking
        notifications_sent = {},
        escalations = {},

        -- Resolution tracking
        acknowledged_by = nil,
        acknowledged_at = nil,
        resolved_at = nil,
        resolution_notes = nil
    }

    return alert
end

---
-- Generate alert title
-- @param incident Incident record
-- @param alert_level Alert level
-- @return String alert title
---
function _M.generate_alert_title(incident, alert_level)
    local severity_emoji = {
        [ALERT_LEVELS.INFO] = "ℹ️",
        [ALERT_LEVELS.WARNING] = "⚠️",
        [ALERT_LEVELS.CRITICAL] = "🚨",
        [ALERT_LEVELS.EMERGENCY] = "🔥"
    }

    local emoji = severity_emoji[alert_level] or "🛡️"

    return string.format("%s Kong Guard AI Alert: %s detected from %s",
        emoji,
        incident.type:gsub("_", " "):gsub("^%l", string.upper),
        incident.network_forensics.source_ip
    )
end

---
-- Generate alert description
-- @param incident Incident record
-- @return String alert description
---
function _M.generate_alert_description(incident)
    local description_parts = {
        string.format("Incident ID: %s", incident.incident_id),
        string.format("Threat Type: %s", incident.type),
        string.format("Severity: %s", incident.severity_level),
        string.format("Source IP: %s", incident.network_forensics.source_ip),
        string.format("Action Taken: %s", incident.decision),
        string.format("Confidence: %.1f%%", (incident.threat_analysis.confidence or 0) * 100)
    }

    if incident.correlation_data.campaign_id then
        table.insert(description_parts, string.format("Campaign: %s", incident.correlation_data.campaign_id))
    end

    if #incident.correlation_data.related_incidents > 0 then
        table.insert(description_parts, string.format("Related incidents: %d", #incident.correlation_data.related_incidents))
    end

    if incident.request_forensics.user_agent then
        table.insert(description_parts, string.format("User Agent: %s",
            string.sub(incident.request_forensics.user_agent, 1, 100)))
    end

    return table.concat(description_parts, "\n")
end

---
-- Send alert notifications through configured channels
-- @param alert Alert record
-- @param conf Plugin configuration
---
function _M.send_alert_notifications(alert, conf)
    local notification_channels = conf.alert_notification_channels or {"webhook"}

    for _, channel in ipairs(notification_channels) do
        local success = false

        if channel == NOTIFICATION_CHANNELS.SLACK then
            success = _M.send_slack_notification(alert, conf)
        elseif channel == NOTIFICATION_CHANNELS.EMAIL then
            success = _M.send_email_notification(alert, conf)
        elseif channel == NOTIFICATION_CHANNELS.WEBHOOK then
            success = _M.send_webhook_notification(alert, conf)
        elseif channel == NOTIFICATION_CHANNELS.SMS then
            success = _M.send_sms_notification(alert, conf)
        elseif channel == NOTIFICATION_CHANNELS.PAGERDUTY then
            success = _M.send_pagerduty_notification(alert, conf)
        elseif channel == NOTIFICATION_CHANNELS.TEAMS then
            success = _M.send_teams_notification(alert, conf)
        end

        -- Track notification result
        alert.notifications_sent[channel] = {
            success = success,
            sent_at = ngx.time(),
            retry_count = 0
        }

        if success then
            kong.log.info(string.format(
                "[Kong Guard AI Incident Alerting] Sent %s notification for alert %s",
                channel, alert.alert_id
            ))
        else
            kong.log.error(string.format(
                "[Kong Guard AI Incident Alerting] Failed to send %s notification for alert %s",
                channel, alert.alert_id
            ))

            -- Queue for retry
            _M.queue_notification_retry(alert, channel, conf)
        end
    end
end

---
-- Send Slack notification
-- @param alert Alert record
-- @param conf Plugin configuration
-- @return Boolean success
---
function _M.send_slack_notification(alert, conf)
    if not conf.slack_webhook_url then
        return false
    end

    local color = {
        [ALERT_LEVELS.INFO] = "good",
        [ALERT_LEVELS.WARNING] = "warning",
        [ALERT_LEVELS.CRITICAL] = "danger",
        [ALERT_LEVELS.EMERGENCY] = "danger"
    }

    local payload = {
        username = "Kong Guard AI",
        icon_emoji = ":shield:",
        attachments = {{
            color = color[alert.alert_level] or "warning",
            title = alert.title,
            text = alert.description,
            fields = {
                {
                    title = "Alert Level",
                    value = alert.alert_level:upper(),
                    short = true
                },
                {
                    title = "Incident ID",
                    value = alert.incident_id,
                    short = true
                },
                {
                    title = "Source IP",
                    value = alert.source_ip,
                    short = true
                },
                {
                    title = "Threat Type",
                    value = alert.threat_type,
                    short = true
                }
            },
            footer = "Kong Guard AI",
            ts = alert.created_at
        }}
    }

    return _M.send_http_notification(conf.slack_webhook_url, payload, conf)
end

---
-- Send webhook notification
-- @param alert Alert record
-- @param conf Plugin configuration
-- @return Boolean success
---
function _M.send_webhook_notification(alert, conf)
    if not conf.webhook_notification_url then
        return false
    end

    local payload = {
        alert = alert,
        timestamp = ngx.time(),
        source = "kong-guard-ai"
    }

    return _M.send_http_notification(conf.webhook_notification_url, payload, conf)
end

---
-- Send HTTP notification (generic)
-- @param url Webhook URL
-- @param payload Payload data
-- @param conf Plugin configuration
-- @return Boolean success
---
function _M.send_http_notification(url, payload, conf)
    local httpc = http.new()
    httpc:set_timeout(5000) -- 5 second timeout

    local body = json.encode(payload)
    local headers = {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "Kong-Guard-AI/1.0"
    }

    -- Add authentication if configured
    if conf.webhook_auth_header and conf.webhook_auth_token then
        headers[conf.webhook_auth_header] = conf.webhook_auth_token
    end

    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = body,
        headers = headers,
        ssl_verify = false -- TODO: Make configurable
    })

    if not res then
        kong.log.error("[Kong Guard AI Incident Alerting] HTTP notification failed: " .. (err or "unknown error"))
        return false
    end

    if res.status >= 200 and res.status < 300 then
        return true
    else
        kong.log.error(string.format(
            "[Kong Guard AI Incident Alerting] HTTP notification failed with status %d: %s",
            res.status, res.body or "no response body"
        ))
        return false
    end
end

---
-- Send Teams notification
-- @param alert Alert record
-- @param conf Plugin configuration
-- @return Boolean success
---
function _M.send_teams_notification(alert, conf)
    if not conf.teams_webhook_url then
        return false
    end

    local card_color = {
        [ALERT_LEVELS.INFO] = "0078D4",
        [ALERT_LEVELS.WARNING] = "FFA500",
        [ALERT_LEVELS.CRITICAL] = "FF4444",
        [ALERT_LEVELS.EMERGENCY] = "CC0000"
    }

    local payload = {
        ["@type"] = "MessageCard",
        ["@context"] = "https://schema.org/extensions",
        themeColor = card_color[alert.alert_level] or "FFA500",
        title = alert.title,
        text = alert.description,
        sections = {{
            facts = {
                {name = "Alert Level", value = alert.alert_level:upper()},
                {name = "Incident ID", value = alert.incident_id},
                {name = "Source IP", value = alert.source_ip},
                {name = "Threat Type", value = alert.threat_type}
            }
        }}
    }

    return _M.send_http_notification(conf.teams_webhook_url, payload, conf)
end

---
-- Send email notification (placeholder)
-- @param alert Alert record
-- @param conf Plugin configuration
-- @return Boolean success
---
function _M.send_email_notification(alert, conf)
    -- Email implementation would require SMTP integration
    kong.log.warn("[Kong Guard AI Incident Alerting] Email notifications not implemented")
    return false
end

---
-- Send SMS notification (placeholder)
-- @param alert Alert record
-- @param conf Plugin configuration
-- @return Boolean success
---
function _M.send_sms_notification(alert, conf)
    -- SMS implementation would require Twilio/AWS SNS integration
    kong.log.warn("[Kong Guard AI Incident Alerting] SMS notifications not implemented")
    return false
end

---
-- Send PagerDuty notification (placeholder)
-- @param alert Alert record
-- @param conf Plugin configuration
-- @return Boolean success
---
function _M.send_pagerduty_notification(alert, conf)
    -- PagerDuty implementation would use their Events API
    kong.log.warn("[Kong Guard AI Incident Alerting] PagerDuty notifications not implemented")
    return false
end

---
-- Setup escalation for critical alerts
-- @param alert Alert record
-- @param conf Plugin configuration
---
function _M.setup_escalation(alert, conf)
    local escalation_delay = conf.escalation_delay_seconds or 300 -- 5 minutes default

    local escalation = {
        alert_id = alert.alert_id,
        escalation_level = 1,
        next_escalation_at = ngx.time() + escalation_delay,
        max_escalations = conf.max_escalation_levels or 3
    }

    escalation_timers.active[alert.alert_id] = escalation

    kong.log.info(string.format(
        "[Kong Guard AI Incident Alerting] Escalation scheduled for alert %s in %d seconds",
        alert.alert_id, escalation_delay
    ))
end

---
-- Check and process escalations
-- @param conf Plugin configuration
---
function _M.process_escalations(conf)
    local current_time = ngx.time()

    for alert_id, escalation in pairs(escalation_timers.active) do
        if current_time >= escalation.next_escalation_at then
            local alert = alert_state.active_alerts[alert_id]

            if alert and alert.status == "active" and not alert.acknowledged_at then
                kong.log.warn(string.format(
                    "[Kong Guard AI Incident Alerting] Escalating alert %s (level %d)",
                    alert_id, escalation.escalation_level
                ))

                -- Send escalation notification
                _M.send_escalation_notification(alert, escalation, conf)

                -- Setup next escalation if not at max level
                if escalation.escalation_level < escalation.max_escalations then
                    escalation.escalation_level = escalation.escalation_level + 1
                    escalation.next_escalation_at = current_time + (conf.escalation_delay_seconds or 300)
                else
                    -- Max escalations reached
                    escalation_timers.completed[alert_id] = escalation
                    escalation_timers.active[alert_id] = nil
                end
            else
                -- Alert resolved or acknowledged, remove escalation
                escalation_timers.active[alert_id] = nil
            end
        end
    end
end

---
-- Send escalation notification
-- @param alert Alert record
-- @param escalation Escalation record
-- @param conf Plugin configuration
---
function _M.send_escalation_notification(alert, escalation, conf)
    -- Create escalated alert with higher urgency
    local escalated_alert = {
        alert_id = alert.alert_id .. "-ESC" .. escalation.escalation_level,
        incident_id = alert.incident_id,
        alert_level = ALERT_LEVELS.EMERGENCY,
        title = string.format("🔥 ESCALATED: %s (Level %d)", alert.title, escalation.escalation_level),
        description = string.format("Alert %s has been escalated to level %d due to lack of acknowledgment.\n\n%s",
            alert.alert_id, escalation.escalation_level, alert.description),
        source_ip = alert.source_ip,
        threat_type = alert.threat_type,
        created_at = ngx.time(),
        escalation_level = escalation.escalation_level
    }

    -- Send to escalation channels (might be different from regular channels)
    local escalation_channels = conf.escalation_notification_channels or conf.alert_notification_channels or {"webhook"}

    for _, channel in ipairs(escalation_channels) do
        if channel == NOTIFICATION_CHANNELS.SLACK then
            _M.send_slack_notification(escalated_alert, conf)
        elseif channel == NOTIFICATION_CHANNELS.WEBHOOK then
            _M.send_webhook_notification(escalated_alert, conf)
        elseif channel == NOTIFICATION_CHANNELS.TEAMS then
            _M.send_teams_notification(escalated_alert, conf)
        end
    end

    -- Track escalation
    table.insert(alert.escalations, {
        level = escalation.escalation_level,
        escalated_at = ngx.time(),
        alert_id = escalated_alert.alert_id
    })
end

---
-- Queue notification for retry
-- @param alert Alert record
-- @param channel Notification channel
-- @param conf Plugin configuration
---
function _M.queue_notification_retry(alert, channel, conf)
    local retry_item = {
        alert = alert,
        channel = channel,
        retry_count = (alert.notifications_sent[channel] and alert.notifications_sent[channel].retry_count or 0) + 1,
        next_retry_at = ngx.time() + (conf.notification_retry_delay or 60),
        max_retries = conf.notification_max_retries or 3
    }

    table.insert(notification_queue.failed, retry_item)
end

---
-- Process notification retry queue
-- @param conf Plugin configuration
---
function _M.process_notification_retries(conf)
    local current_time = ngx.time()
    local retry_queue = notification_queue.failed
    notification_queue.failed = {}

    for _, retry_item in ipairs(retry_queue) do
        if current_time >= retry_item.next_retry_at and retry_item.retry_count <= retry_item.max_retries then
            kong.log.info(string.format(
                "[Kong Guard AI Incident Alerting] Retrying %s notification for alert %s (attempt %d)",
                retry_item.channel, retry_item.alert.alert_id, retry_item.retry_count
            ))

            local success = false
            if retry_item.channel == NOTIFICATION_CHANNELS.SLACK then
                success = _M.send_slack_notification(retry_item.alert, conf)
            elseif retry_item.channel == NOTIFICATION_CHANNELS.WEBHOOK then
                success = _M.send_webhook_notification(retry_item.alert, conf)
            elseif retry_item.channel == NOTIFICATION_CHANNELS.TEAMS then
                success = _M.send_teams_notification(retry_item.alert, conf)
            end

            if success then
                -- Update alert notification status
                retry_item.alert.notifications_sent[retry_item.channel] = {
                    success = true,
                    sent_at = current_time,
                    retry_count = retry_item.retry_count
                }
            else
                -- Queue for another retry if under max attempts
                if retry_item.retry_count < retry_item.max_retries then
                    retry_item.retry_count = retry_item.retry_count + 1
                    retry_item.next_retry_at = current_time + (conf.notification_retry_delay or 60)
                    table.insert(notification_queue.failed, retry_item)
                end
            end
        elseif retry_item.retry_count <= retry_item.max_retries then
            -- Not time to retry yet, keep in queue
            table.insert(notification_queue.failed, retry_item)
        end
    end
end

---
-- Helper functions
---

function _M.count_campaign_incidents(campaign_id)
    -- This would integrate with incident_manager to count incidents in campaign
    return math.random(5, 15) -- Placeholder
end

function _M.count_recent_incidents(timeframe_seconds)
    -- This would integrate with incident_manager to count recent incidents
    return math.random(0, 10) -- Placeholder
end

function _M.check_attack_patterns(incident, conf)
    -- Check for coordinated attack patterns that require immediate alerting
    -- This would analyze incident correlations and patterns
end

---
-- Acknowledge alert
-- @param alert_id Alert ID
-- @param acknowledged_by User who acknowledged
-- @return Boolean success
---
function _M.acknowledge_alert(alert_id, acknowledged_by)
    local alert = alert_state.active_alerts[alert_id]
    if alert then
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = ngx.time()
        alert.status = "acknowledged"

        -- Remove from escalation queue
        escalation_timers.active[alert_id] = nil

        kong.log.info(string.format(
            "[Kong Guard AI Incident Alerting] Alert %s acknowledged by %s",
            alert_id, acknowledged_by
        ))
        return true
    end
    return false
end

---
-- Resolve alert
-- @param alert_id Alert ID
-- @param resolved_by User who resolved
-- @param resolution_notes Resolution notes
-- @return Boolean success
---
function _M.resolve_alert(alert_id, resolved_by, resolution_notes)
    local alert = alert_state.active_alerts[alert_id]
    if alert then
        alert.resolved_at = ngx.time()
        alert.status = "resolved"
        alert.resolution_notes = resolution_notes

        -- Move to history
        alert_state.alert_history[alert_id] = alert
        alert_state.active_alerts[alert_id] = nil

        -- Remove from escalation queue
        escalation_timers.active[alert_id] = nil

        kong.log.info(string.format(
            "[Kong Guard AI Incident Alerting] Alert %s resolved by %s",
            alert_id, resolved_by or "system"
        ))
        return true
    end
    return false
end

---
-- Get alerting statistics
-- @return Table containing alert metrics
---
function _M.get_alerting_statistics()
    local stats = {
        active_alerts = 0,
        total_alerts_24h = 0,
        escalated_alerts = 0,
        notification_success_rate = 0,
        alerts_by_level = {},
        top_alert_sources = {}
    }

    -- Count active alerts
    for _ in pairs(alert_state.active_alerts) do
        stats.active_alerts = stats.active_alerts + 1
    end

    -- Count escalated alerts
    for _ in pairs(escalation_timers.active) do
        stats.escalated_alerts = stats.escalated_alerts + 1
    end

    return stats
end

---
-- Cleanup old alert data
-- @param conf Plugin configuration
---
function _M.cleanup_alert_data(conf)
    local current_time = ngx.time()
    local retention_period = (conf.alert_retention_days or 7) * 24 * 3600
    local cleanup_threshold = current_time - retention_period

    local cleaned_count = 0

    -- Clean alert history
    for alert_id, alert in pairs(alert_state.alert_history) do
        if alert.created_at < cleanup_threshold then
            alert_state.alert_history[alert_id] = nil
            cleaned_count = cleaned_count + 1
        end
    end

    -- Clean completed escalations
    for alert_id, escalation in pairs(escalation_timers.completed) do
        local alert = alert_state.alert_history[alert_id]
        if not alert or alert.created_at < cleanup_threshold then
            escalation_timers.completed[alert_id] = nil
        end
    end

    if cleaned_count > 0 then
        kong.log.info(string.format(
            "[Kong Guard AI Incident Alerting] Cleaned up %d old alert records",
            cleaned_count
        ))
    end
end

---
-- Periodic maintenance
-- @param conf Plugin configuration
---
function _M.maintenance(conf)
    _M.process_escalations(conf)
    _M.process_notification_retries(conf)

    -- Cleanup every hour
    if ngx.time() - alert_state.last_cleanup > 3600 then
        _M.cleanup_alert_data(conf)
        alert_state.last_cleanup = ngx.time()
    end
end

return _M
