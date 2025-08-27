-- Kong Guard AI Plugin Handler
-- Main plugin logic for the Autonomous API Threat Response Agent

local BasePlugin = require "kong.plugins.base_plugin"
local cjson = require "cjson"
local http = require "resty.http"

-- Initialize the plugin handler
local KongGuardAIHandler = BasePlugin:extend()

KongGuardAIHandler.PRIORITY = 1000  -- Execute early in the plugin chain
KongGuardAIHandler.VERSION = "1.0.0"

-- Plugin lifecycle methods
function KongGuardAIHandler:new()
  KongGuardAIHandler.super.new(self, "kong-guard-ai")
end

-- Initialize worker-level resources
function KongGuardAIHandler:init_worker()
  KongGuardAIHandler.super.init_worker(self)
  
  -- Initialize shared memory dictionaries for threat tracking
  local shared_dict = ngx.shared.kong_guard_ai_data
  if not shared_dict then
    ngx.log(ngx.ERR, "[kong-guard-ai] Shared dictionary 'kong_guard_ai_data' not found")
  end
  
  -- Initialize threat counters
  local threat_counters = ngx.shared.kong_guard_ai_counters
  if not threat_counters then
    ngx.log(ngx.ERR, "[kong-guard-ai] Shared dictionary 'kong_guard_ai_counters' not found")
  end
  
  ngx.log(ngx.INFO, "[kong-guard-ai] Plugin initialized in worker")
end

-- Access phase - main threat detection logic
function KongGuardAIHandler:access(config)
  KongGuardAIHandler.super.access(self)
  
  local start_time = ngx.now()
  
  -- Skip processing if dry_run is disabled and plugin is not enabled
  if not config.threat_detection.enabled then
    return
  end
  
  -- Get request data
  local request_data = self:get_request_data()
  
  -- Perform threat detection
  local threat_detected, threat_info = self:detect_threats(config, request_data)
  
  if threat_detected then
    -- Log the threat
    self:log_threat(config, threat_info, request_data)
    
    -- Execute response actions (if not in dry_run mode)
    if not config.dry_run and config.response_actions.enabled then
      self:execute_response_actions(config, threat_info, request_data)
    else
      ngx.log(ngx.WARN, "[kong-guard-ai] DRY RUN: Would execute response actions for threat: " .. threat_info.type)
    end
    
    -- Send notifications
    if config.notifications and config.response_actions.notification_enabled then
      self:send_notification(config, threat_info, request_data)
    end
  end
  
  -- Track performance
  local processing_time = (ngx.now() - start_time) * 1000
  if processing_time > config.performance.max_processing_time then
    ngx.log(ngx.WARN, "[kong-guard-ai] Processing time exceeded limit: " .. processing_time .. "ms")
  end
  
  -- Store processing metrics
  self:update_metrics(processing_time, threat_detected)
end

-- Log phase - for post-request analysis
function KongGuardAIHandler:log(config)
  KongGuardAIHandler.super.log(self)
  
  if not config.logging.enabled then
    return
  end
  
  -- Log request/response data for analysis
  local log_data = {
    timestamp = ngx.time(),
    request_id = ngx.var.request_id,
    method = ngx.var.request_method,
    uri = ngx.var.request_uri,
    status = ngx.status,
    response_time = ngx.var.request_time,
    upstream_response_time = ngx.var.upstream_response_time
  }
  
  if config.logging.structured_logging then
    ngx.log(ngx.INFO, "[kong-guard-ai] " .. cjson.encode(log_data))
  end
end

-- Helper function to extract request data
function KongGuardAIHandler:get_request_data()
  return {
    method = ngx.var.request_method,
    uri = ngx.var.request_uri,
    headers = ngx.req.get_headers(),
    remote_addr = ngx.var.remote_addr,
    user_agent = ngx.var.http_user_agent or "",
    timestamp = ngx.time(),
    request_id = ngx.var.request_id or "",
    body_size = tonumber(ngx.var.content_length) or 0
  }
end

-- Main threat detection logic
function KongGuardAIHandler:detect_threats(config, request_data)
  local rules = config.threat_detection.rules
  
  -- Check blocked IPs
  if self:check_blocked_ips(rules.blocked_ips, request_data.remote_addr) then
    return true, {
      type = "blocked_ip",
      severity = "high",
      source_ip = request_data.remote_addr,
      description = "Request from blocked IP address"
    }
  end
  
  -- Check blocked user agents
  if self:check_blocked_user_agents(rules.blocked_user_agents, request_data.user_agent) then
    return true, {
      type = "blocked_user_agent",
      severity = "medium",
      user_agent = request_data.user_agent,
      description = "Request from blocked user agent"
    }
  end
  
  -- Check suspicious patterns in URI
  if self:check_suspicious_patterns(rules.suspicious_patterns, request_data.uri) then
    return true, {
      type = "suspicious_pattern",
      severity = "high",
      uri = request_data.uri,
      description = "Suspicious pattern detected in request URI"
    }
  end
  
  -- Check rate limiting
  if self:check_rate_limit(rules.rate_limit_threshold, request_data.remote_addr) then
    return true, {
      type = "rate_limit_exceeded",
      severity = "medium",
      source_ip = request_data.remote_addr,
      description = "Rate limit threshold exceeded"
    }
  end
  
  -- Check payload size
  if request_data.body_size > rules.max_payload_size then
    return true, {
      type = "oversized_payload",
      severity = "medium",
      payload_size = request_data.body_size,
      description = "Request payload exceeds maximum allowed size"
    }
  end
  
  return false, nil
end

-- Check if IP is in blocked list
function KongGuardAIHandler:check_blocked_ips(blocked_ips, client_ip)
  for _, ip in ipairs(blocked_ips) do
    if ip == client_ip then
      return true
    end
  end
  return false
end

-- Check if user agent is in blocked list
function KongGuardAIHandler:check_blocked_user_agents(blocked_agents, user_agent)
  for _, agent in ipairs(blocked_agents) do
    if string.find(string.lower(user_agent), string.lower(agent), 1, true) then
      return true
    end
  end
  return false
end

-- Check for suspicious patterns using regex
function KongGuardAIHandler:check_suspicious_patterns(patterns, text)
  for _, pattern in ipairs(patterns) do
    if ngx.re.match(text, pattern, "ijo") then
      return true
    end
  end
  return false
end

-- Simple rate limiting check using shared dictionary
function KongGuardAIHandler:check_rate_limit(threshold, client_ip)
  local counters = ngx.shared.kong_guard_ai_counters
  if not counters then
    return false
  end
  
  local key = "rate_limit:" .. client_ip
  local current_time = ngx.time()
  local window_start = current_time - 60  -- 1 minute window
  
  -- Clean old entries and count current requests
  local count = 0
  for i = window_start, current_time do
    local minute_key = key .. ":" .. i
    local minute_count = counters:get(minute_key) or 0
    count = count + minute_count
  end
  
  -- Increment current minute counter
  local current_minute_key = key .. ":" .. current_time
  counters:incr(current_minute_key, 1, 0, 61)  -- Expire after 61 seconds
  
  return count >= threshold
end

-- Execute response actions when threats are detected
function KongGuardAIHandler:execute_response_actions(config, threat_info, request_data)
  local actions = config.response_actions
  
  if actions.immediate_block and threat_info.severity == "high" then
    ngx.status = 403
    ngx.say(cjson.encode({
      error = "Request blocked",
      reason = threat_info.description,
      request_id = request_data.request_id
    }))
    ngx.exit(403)
  end
  
  -- Additional response actions would be implemented here
  -- such as temporary IP blocking, rate limit adjustments, etc.
end

-- Log threat information
function KongGuardAIHandler:log_threat(config, threat_info, request_data)
  local log_entry = {
    timestamp = ngx.time(),
    threat_type = threat_info.type,
    severity = threat_info.severity,
    source_ip = request_data.remote_addr,
    method = request_data.method,
    uri = request_data.uri,
    user_agent = request_data.user_agent,
    description = threat_info.description,
    request_id = request_data.request_id
  }
  
  ngx.log(ngx.WARN, "[kong-guard-ai] THREAT DETECTED: " .. cjson.encode(log_entry))
end

-- Send notifications about threats
function KongGuardAIHandler:send_notification(config, threat_info, request_data)
  -- This would be implemented to send notifications via webhook, Slack, email, etc.
  -- For now, just log the notification
  ngx.log(ngx.INFO, "[kong-guard-ai] NOTIFICATION: Threat " .. threat_info.type .. " detected from " .. request_data.remote_addr)
end

-- Update performance metrics
function KongGuardAIHandler:update_metrics(processing_time, threat_detected)
  local shared_dict = ngx.shared.kong_guard_ai_data
  if shared_dict then
    shared_dict:incr("total_requests", 1, 0)
    if threat_detected then
      shared_dict:incr("threats_detected", 1, 0)
    end
    
    -- Update average processing time
    local total_time = shared_dict:get("total_processing_time") or 0
    local total_requests = shared_dict:get("total_requests") or 1
    shared_dict:set("total_processing_time", total_time + processing_time)
    shared_dict:set("avg_processing_time", (total_time + processing_time) / total_requests)
  end
end

return KongGuardAIHandler