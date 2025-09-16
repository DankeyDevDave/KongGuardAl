-- Kong Guard AI - Notification Module
-- Handles threat notifications via Slack, email, webhooks, and external logging
-- Designed for non-blocking, async notification delivery

local kong = kong
local http = require "resty.http"
local json = require "cjson.safe"

local _M = {}

-- Notification types
local NOTIFICATION_TYPES = {
    THREAT_DETECTED = "threat_detected",
    RESPONSE_EXECUTED = "response_executed",
    SYSTEM_STATUS = "system_status",
    CONFIG_CHANGE = "config_change"
}

-- Notification cache for rate limiting and tracking
local notification_cache = {}

---
-- Initialize notification system
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Notifier] Initializing notification system")

    -- Initialize notification rate limiting
    notification_cache.sent_notifications = {}
    notification_cache.rate_limits = {}

    -- Test notification endpoints if configured
    if conf.enable_notifications then
        _M.test_notification_endpoints(conf)
    end

    kong.log.info("[Kong Guard AI Notifier] Notification system initialized")
end

---
-- Send threat detection notification
-- @param threat_result Threat analysis result
-- @param response_action Response action taken
-- @param conf Plugin configuration
---
function _M.send_threat_notification(threat_result, response_action, conf)
    if not conf.enable_notifications then
        return
    end

    -- Check if threat level meets notification threshold
    if threat_result.threat_level < conf.notification_threshold then
        kong.log.debug("[Kong Guard AI Notifier] Threat level below notification threshold")
        return
    end

    -- Check notification rate limiting
    if _M.is_rate_limited("threat_notification", conf) then
        kong.log.debug("[Kong Guard AI Notifier] Threat notification rate limited")
        return
    end

    -- Prepare notification payload
    local notification = _M.build_threat_notification(threat_result, response_action, conf)

    -- Send to all configured channels (async)
    _M.send_to_all_channels(notification, conf)

    -- Update rate limiting
    _M.update_rate_limit("threat_notification")
end

---
-- Send incident log to external systems
-- @param incident_log Detailed incident log
-- @param conf Plugin configuration
---
function _M.send_incident_log(incident_log, conf)
    if not conf.external_logging_enabled then
        return
    end

    kong.log.debug("[Kong Guard AI Notifier] Sending incident log to external systems")

    -- Send to external log endpoint
    if conf.log_endpoint then
        _M.send_to_log_endpoint(incident_log, conf)
    end

    -- Could also send to other log aggregation systems
    -- (Elasticsearch, Splunk, Datadog, etc.)
end

---
-- Build comprehensive threat notification
-- @param threat_result Threat analysis result
-- @param response_action Response action taken
-- @param conf Plugin configuration
-- @return Table containing formatted notification
---
function _M.build_threat_notification(threat_result, response_action, conf)
    local notification = {
        type = NOTIFICATION_TYPES.THREAT_DETECTED,
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),
        severity = _M.map_threat_level_to_severity(threat_result.threat_level),

        -- Threat details
        threat = {
            type = threat_result.threat_type,
            level = threat_result.threat_level,
            confidence = threat_result.confidence,
            details = threat_result.details
        },

        -- Response details
        response = {
            action = response_action.action_type,
            success = response_action.success,
            details = response_action.details
        },

        -- System context
        system = {
            kong_node_id = kong.node.get_id(),
            plugin_version = "0.1.0",
            dry_run_mode = conf.dry_run_mode
        }
    }

    return notification
end

---
-- Send notification to all configured channels
-- @param notification Notification payload
-- @param conf Plugin configuration
---
function _M.send_to_all_channels(notification, conf)
    -- Send to Slack
    if conf.slack_webhook_url then
        _M.send_slack_notification(notification, conf)
    end

    -- Send to email
    if conf.email_smtp_server and #conf.email_to > 0 then
        _M.send_email_notification(notification, conf)
    end

    -- Send to webhooks
    if #conf.webhook_urls > 0 then
        for _, webhook_url in ipairs(conf.webhook_urls) do
            _M.send_webhook_notification(notification, webhook_url, conf)
        end
    end
end

---
-- Send Slack notification
-- @param notification Notification payload
-- @param conf Plugin configuration
---
function _M.send_slack_notification(notification, conf)
    local slack_message = _M.format_slack_message(notification)

    local payload = {
        text = "🚨 Kong Guard AI - Threat Detected",
        attachments = {
            {
                color = _M.get_slack_color(notification.severity),
                title = "Threat Detection Alert",
                fields = slack_message.fields,
                ts = notification.timestamp,
                footer = "Kong Guard AI",
                footer_icon = "https://konghq.com/wp-content/uploads/2018/08/kong-combination-mark-color-256px.png"
            }
        }
    }

    _M.send_async_http_request(conf.slack_webhook_url, "POST", payload, {
        ["Content-Type"] = "application/json"
    })
end

---
-- Send email notification
-- @param notification Notification payload
-- @param conf Plugin configuration
---
function _M.send_email_notification(notification, conf)
    -- Email sending would require SMTP client implementation
    -- For now, log the email that would be sent
    local email_content = _M.format_email_message(notification, conf)

    kong.log.info("[Kong Guard AI Notifier] Email notification (SMTP not implemented): " ..
                  json.encode(email_content))

    -- In production, implement SMTP client here
    -- Could use external email service API (SendGrid, AWS SES, etc.)
end

---
-- Send webhook notification
-- @param notification Notification payload
-- @param webhook_url Target webhook URL
-- @param conf Plugin configuration
---
function _M.send_webhook_notification(notification, webhook_url, conf)
    kong.log.debug("[Kong Guard AI Notifier] Sending webhook notification to: " .. webhook_url)

    _M.send_async_http_request(webhook_url, "POST", notification, {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "Kong-Guard-AI/0.1.0"
    })
end

---
-- Send to external log endpoint
-- @param incident_log Incident log data
-- @param conf Plugin configuration
---
function _M.send_to_log_endpoint(incident_log, conf)
    kong.log.debug("[Kong Guard AI Notifier] Sending to log endpoint: " .. conf.log_endpoint)

    _M.send_async_http_request(conf.log_endpoint, "POST", incident_log, {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "Kong-Guard-AI/0.1.0"
    })
end

---
-- Send asynchronous HTTP request (non-blocking)
-- @param url Target URL
-- @param method HTTP method
-- @param body Request body
-- @param headers Request headers
---
function _M.send_async_http_request(url, method, body, headers)
    -- Use ngx.timer.at for async execution to avoid blocking request processing
    local ok, err = ngx.timer.at(0, function(premature)
        if premature then
            return
        end

        local httpc = http.new()
        httpc:set_timeout(5000) -- 5 second timeout

        local json_body = json.encode(body)

        local res, err = httpc:request_uri(url, {
            method = method,
            headers = headers,
            body = json_body,
            ssl_verify = false
        })

        if not res then
            kong.log.error("[Kong Guard AI Notifier] HTTP request failed: " .. (err or "unknown error"))
        elseif res.status >= 200 and res.status < 300 then
            kong.log.debug("[Kong Guard AI Notifier] HTTP request successful to: " .. url)
        else
            kong.log.warn("[Kong Guard AI Notifier] HTTP request failed with status " ..
                         res.status .. " to: " .. url)
        end

        httpc:close()
    end)

    if not ok then
        kong.log.error("[Kong Guard AI Notifier] Failed to schedule async HTTP request: " .. (err or "unknown"))
    end
end

---
-- Format Slack message
-- @param notification Notification payload
-- @return Table containing Slack message format
---
function _M.format_slack_message(notification)
    local fields = {
        {
            title = "Threat Type",
            value = notification.threat.type,
            short = true
        },
        {
            title = "Threat Level",
            value = notification.threat.level .. "/10",
            short = true
        },
        {
            title = "Response Action",
            value = notification.response.action,
            short = true
        },
        {
            title = "Success",
            value = notification.response.success and "✅" or "❌",
            short = true
        },
        {
            title = "Timestamp",
            value = notification.iso_timestamp,
            short = false
        }
    }

    -- Add threat details if available
    if notification.threat.details.source_ip then
        table.insert(fields, {
            title = "Source IP",
            value = notification.threat.details.source_ip,
            short = true
        })
    end

    if notification.threat.details.blocked_ip then
        table.insert(fields, {
            title = "Blocked IP",
            value = notification.threat.details.blocked_ip,
            short = true
        })
    end

    -- Add dry run indicator
    if notification.system.dry_run_mode then
        table.insert(fields, {
            title = "Mode",
            value = "🧪 DRY RUN",
            short = true
        })
    end

    return {
        fields = fields
    }
end

---
-- Format email message
-- @param notification Notification payload
-- @param conf Plugin configuration
-- @return Table containing email content
---
function _M.format_email_message(notification, conf)
    local subject = string.format("[Kong Guard AI] %s Threat Detected - %s",
                                 notification.severity:upper(),
                                 notification.threat.type)

    local body = string.format([[
Kong Guard AI Threat Detection Alert

Threat Details:
- Type: %s
- Level: %d/10
- Confidence: %.2f
- Timestamp: %s

Response Action:
- Action Taken: %s
- Success: %s

System Information:
- Kong Node: %s
- Plugin Version: %s
- Mode: %s

For more details, check the Kong Gateway logs.

--
Kong Guard AI Autonomous Threat Response
]],
        notification.threat.type,
        notification.threat.level,
        notification.threat.confidence,
        notification.iso_timestamp,
        notification.response.action,
        notification.response.success and "Yes" or "No",
        notification.system.kong_node_id,
        notification.system.plugin_version,
        notification.system.dry_run_mode and "DRY RUN" or "ACTIVE"
    )

    return {
        from = conf.email_from,
        to = conf.email_to,
        subject = subject,
        body = body
    }
end

---
-- Test notification endpoints during initialization
-- @param conf Plugin configuration
---
function _M.test_notification_endpoints(conf)
    kong.log.debug("[Kong Guard AI Notifier] Testing notification endpoints")

    local test_notification = {
        type = NOTIFICATION_TYPES.SYSTEM_STATUS,
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),
        message = "Kong Guard AI notification system initialized",
        test = true
    }

    -- Test Slack webhook
    if conf.slack_webhook_url then
        local test_slack = {
            text = "✅ Kong Guard AI - System Initialized",
            attachments = {
                {
                    color = "good",
                    title = "Notification Test",
                    text = "Kong Guard AI notification system is working correctly.",
                    ts = test_notification.timestamp
                }
            }
        }

        _M.send_async_http_request(conf.slack_webhook_url, "POST", test_slack, {
            ["Content-Type"] = "application/json"
        })
    end

    -- Test webhooks
    for _, webhook_url in ipairs(conf.webhook_urls) do
        _M.send_async_http_request(webhook_url, "POST", test_notification, {
            ["Content-Type"] = "application/json",
            ["User-Agent"] = "Kong-Guard-AI/0.1.0"
        })
    end
end

---
-- Check if notification type is rate limited
-- @param notification_type Type of notification
-- @param conf Plugin configuration
-- @return Boolean indicating if rate limited
---
function _M.is_rate_limited(notification_type, conf)
    local current_time = ngx.time()
    local rate_limit_window = 300 -- 5 minutes
    local max_notifications = 10 -- Max 10 notifications per 5 minutes per type

    if not notification_cache.rate_limits[notification_type] then
        notification_cache.rate_limits[notification_type] = {}
    end

    local rate_data = notification_cache.rate_limits[notification_type]

    -- Clean old entries
    local cleaned_entries = {}
    for _, timestamp in ipairs(rate_data) do
        if current_time - timestamp < rate_limit_window then
            table.insert(cleaned_entries, timestamp)
        end
    end

    notification_cache.rate_limits[notification_type] = cleaned_entries

    -- Check if rate limit exceeded
    return #cleaned_entries >= max_notifications
end

---
-- Update rate limit tracking for notification type
-- @param notification_type Type of notification
---
function _M.update_rate_limit(notification_type)
    if not notification_cache.rate_limits[notification_type] then
        notification_cache.rate_limits[notification_type] = {}
    end

    table.insert(notification_cache.rate_limits[notification_type], ngx.time())
end

---
-- Map threat level to severity string
-- @param threat_level Numerical threat level (1-10)
-- @return String severity level
---
function _M.map_threat_level_to_severity(threat_level)
    if threat_level >= 9 then
        return "critical"
    elseif threat_level >= 7 then
        return "high"
    elseif threat_level >= 5 then
        return "medium"
    elseif threat_level >= 3 then
        return "low"
    else
        return "info"
    end
end

---
-- Get Slack color based on severity
-- @param severity Severity string
-- @return String Slack color
---
function _M.get_slack_color(severity)
    local colors = {
        critical = "danger",
        high = "warning",
        medium = "#ff9500",
        low = "good",
        info = "#36a64f"
    }

    return colors[severity] or "#36a64f"
end

---
-- Get notification statistics
-- @return Table containing notification metrics
---
function _M.get_notification_metrics()
    local metrics = {
        total_sent = 0,
        rate_limited = 0,
        by_type = {}
    }

    if notification_cache.sent_notifications then
        metrics.total_sent = #notification_cache.sent_notifications
    end

    -- Count rate limited notifications
    for notification_type, rate_data in pairs(notification_cache.rate_limits) do
        metrics.by_type[notification_type] = #rate_data
    end

    return metrics
end

---
-- Clean up notification cache
---
function _M.cleanup_notification_cache()
    local current_time = ngx.time()
    local cleanup_threshold = current_time - 3600 -- 1 hour

    -- Clean sent notifications
    if notification_cache.sent_notifications then
        local cleaned_notifications = {}
        for _, notification in ipairs(notification_cache.sent_notifications) do
            if notification.timestamp >= cleanup_threshold then
                table.insert(cleaned_notifications, notification)
            end
        end
        notification_cache.sent_notifications = cleaned_notifications
    end

    -- Clean rate limit data
    for notification_type, rate_data in pairs(notification_cache.rate_limits) do
        local cleaned_entries = {}
        for _, timestamp in ipairs(rate_data) do
            if current_time - timestamp < 3600 then -- Keep 1 hour of data
                table.insert(cleaned_entries, timestamp)
            end
        end
        notification_cache.rate_limits[notification_type] = cleaned_entries
    end

    kong.log.debug("[Kong Guard AI Notifier] Notification cache cleanup completed")
end

return _M
