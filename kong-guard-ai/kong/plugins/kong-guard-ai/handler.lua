-- Kong Guard AI Plugin Handler
-- Autonomous API Threat Response Agent for Kong Gateway 3.x+
--
-- Architecture: This handler implements the Kong plugin lifecycle for real-time
-- API threat monitoring and automated remediation. It follows Kong's best practices
-- for performance (<10ms overhead) and stateless design.
--
-- Lifecycle Phases:
-- 1. init_worker: Initialize threat detection models and shared memory
-- 2. access: Real-time traffic analysis and threat detection
-- 3. header_filter: Response header analysis for upstream anomalies
-- 4. response: Full response analysis and pattern learning
-- 5. log: Incident logging and notification triggering

local kong = kong
local detector = require "kong.plugins.kong-guard-ai.detector"
local responder = require "kong.plugins.kong-guard-ai.responder"
local notifier = require "kong.plugins.kong-guard-ai.notifier"
local ai_gateway = require "kong.plugins.kong-guard-ai.ai_gateway"
local enforcement_gate = require "kong.plugins.kong-guard-ai.enforcement_gate"
local dry_run_status = require "kong.plugins.kong-guard-ai.dry_run_status"
local test_dry_run_enforcement = require "kong.plugins.kong-guard-ai.test_dry_run_enforcement"
local instrumentation = require "kong.plugins.kong-guard-ai.instrumentation"
local log_format = require "kong.plugins.kong-guard-ai.log_format"
local structured_logger = require "kong.plugins.kong-guard-ai.structured_logger"
local counters = require "kong.plugins.kong-guard-ai.counters"
local performance_optimizer = require "kong.plugins.kong-guard-ai.performance_optimizer"

-- Plugin metadata - required by Kong
local KongGuardAIHandler = {
    VERSION = "0.1.0",
    PRIORITY = 1000  -- High priority for security plugins (executed early)
}

-- Shared memory for threat detection state (worker-level)
local threat_cache = {}
local incident_counter = 0

---
-- Initialize worker-level resources
-- Called once per worker process startup
-- Used for: ML model loading, shared memory setup, background tasks
---
function KongGuardAIHandler:init_worker(conf)
    kong.log.info("[Kong Guard AI] Initializing threat detection worker")
    
    -- Initialize enforcement gate system first (controls all enforcement actions)
    enforcement_gate.init_worker(conf)
    
    -- Initialize threat detection engine
    detector.init_worker(conf)
    
    -- Initialize structured logging system
    structured_logger.init_worker(conf)
    log_format.init_worker(conf)
    
    -- Initialize AI Gateway connection if enabled
    if conf.ai_gateway_enabled then
        ai_gateway.init_worker(conf)
        kong.log.info("[Kong Guard AI] AI Gateway integration enabled")
    end
    
    -- Initialize notification system
    notifier.init_worker(conf)
    
    -- Initialize performance optimization system (PHASE 3)
    performance_optimizer.init_worker(conf)
    kong.log.info("[Kong Guard AI] Performance optimization engine initialized")
    
    -- Initialize counter management system
    local counters_initialized = counters.init(conf)
    if counters_initialized then
        kong.log.info("[Kong Guard AI] Counter management system initialized")
    else
        kong.log.warn("[Kong Guard AI] Counter management system failed to initialize")
    end
    
    -- Setup shared memory for cross-request threat tracking
    local shm_name = "kong_guard_ai_cache"
    local shm = ngx.shared[shm_name]
    if shm then
        kong.log.info("[Kong Guard AI] Shared memory initialized: " .. shm_name)
    else
        kong.log.warn("[Kong Guard AI] Shared memory not available, using local cache")
    end
    
    kong.log.info("[Kong Guard AI] Worker initialization complete")
end

---
-- Access phase - executed for every request before upstream
-- CRITICAL: This must be optimized for <10ms latency under 5K+ RPS
-- Performs: Real-time threat detection and immediate response
---
function KongGuardAIHandler:access(conf)
    local phase_start_time = ngx.now()
    
    -- PHASE 3 ENHANCEMENT: Start performance monitoring for this request
    local perf_context = performance_optimizer.start_request_monitoring(ngx.var.request_id or "unknown")
    
    -- Handle status and metrics endpoints first
    if dry_run_status.handle_status_endpoints(conf) then
        return -- Request was handled by status endpoint
    end
    
    -- Handle test endpoint (if enabled in development/testing environments)
    if test_dry_run_enforcement.handle_test_endpoint(conf) then
        return -- Request was handled by test endpoint
    end
    
    -- PHASE 3 ENHANCEMENT: Capture comprehensive request metadata using instrumentation module
    -- This provides optimized metadata collection with minimal overhead
    local request_metadata = instrumentation.capture_request_metadata(conf)
    
    -- COUNTER MANAGEMENT: Track request counters for rate limiting and monitoring
    local client_ip = request_metadata.client_ip
    
    -- Increment global request counter
    counters.increment_global_counter(counters.COUNTER_TYPES.REQUESTS)
    
    -- Increment per-IP request counter
    counters.increment_ip_counter(client_ip, counters.COUNTER_TYPES.REQUESTS)
    
    -- Store metadata in Kong context for log phase access
    kong.ctx.plugin.guard_ai_request_metadata = request_metadata
    
    -- Legacy request context for backward compatibility with existing detector
    local request_context = {
        method = request_metadata.method,
        path = request_metadata.path,
        headers = kong.request.get_headers(),
        query = kong.request.get_query(),
        client_ip = request_metadata.client_ip,
        service_id = request_metadata.service_id,
        route_id = request_metadata.route_id,
        consumer_id = request_metadata.consumer_id,
        timestamp = request_metadata.timestamp,
        correlation_id = request_metadata.correlation_id
    }
    
    -- Perform threat detection analysis
    local threat_result = detector.analyze_request(request_context, conf)
    
    -- AI Gateway analysis for advanced threats (if enabled and warranted)
    if conf.ai_gateway_enabled and threat_result.requires_ai_analysis then
        local ai_result = ai_gateway.analyze_threat(request_context, threat_result, conf)
        if ai_result then
            threat_result = detector.merge_ai_results(threat_result, ai_result)
        end
    end
    
    -- Execute automated response if threat detected
    if threat_result.threat_level > conf.threat_threshold then
        kong.log.warn("[Kong Guard AI] Threat detected: " .. threat_result.threat_type .. 
                      " (level: " .. threat_result.threat_level .. ")")
        
        -- Increment incident counter for monitoring
        incident_counter = incident_counter + 1
        
        -- Execute response through enforcement gate (handles dry-run mode automatically)
        local action_types = enforcement_gate.get_action_types()
        local enforcement_result = enforcement_gate.enforce_action(
            action_types.BLOCK_REQUEST,
            {
                threat_result = threat_result,
                request_context = request_context,
                recommended_action = threat_result.recommended_action
            },
            conf,
            function(action_data, config)
                -- This callback executes the actual enforcement only if not in dry-run mode
                return responder.execute_response(action_data.threat_result, action_data.request_context, config)
            end
        )
        
        -- Log enforcement result
        if enforcement_result.executed then
            kong.log.info("[Kong Guard AI] Response executed: " .. enforcement_result.action_type)
        elseif enforcement_result.simulated then
            kong.log.info("[Kong Guard AI] [DRY RUN] Simulated: " .. enforcement_result.action_type)
        end
        
        -- Send notification through enforcement gate
        local notification_result = enforcement_gate.enforce_action(
            action_types.NOTIFICATION,
            {
                threat_result = threat_result,
                response_action = enforcement_result,
                notification_type = "threat_detected"
            },
            conf,
            function(action_data, config)
                return notifier.send_threat_notification(
                    action_data.threat_result, 
                    action_data.response_action, 
                    config
                )
            end
        )
        
        -- Store threat data for learning and reporting (using correlation ID for tracking)
        threat_cache[request_metadata.correlation_id] = {
            threat_result = threat_result,
            request_context = request_context,
            request_metadata = request_metadata,
            enforcement_result = enforcement_result,
            notification_result = notification_result,
            timestamp = ngx.now()
        }
    end
    
    -- Performance monitoring (using phase start time for accurate measurement)
    local processing_time = (ngx.now() - phase_start_time) * 1000  -- Convert to milliseconds
    if processing_time > 5 then  -- Warn if processing takes >5ms
        kong.log.warn("[Kong Guard AI] High access phase processing time: " .. processing_time .. "ms")
    end
    
    -- Store processing time for metrics and correlation
    kong.ctx.plugin.guard_ai_processing_time = processing_time
    kong.ctx.plugin.guard_ai_access_phase_time = processing_time
end

---
-- Header filter phase - executed when response headers received from upstream
-- Used for: Upstream response analysis, header-based threat detection
---
function KongGuardAIHandler:header_filter(conf)
    -- Analyze upstream response headers for anomalies
    local response_headers = kong.response.get_headers()
    local status_code = kong.response.get_status()
    
    -- Get correlation ID from request metadata
    local request_metadata = kong.ctx.plugin.guard_ai_request_metadata
    if not request_metadata then
        return -- No metadata captured in access phase
    end
    
    local correlation_id = request_metadata.correlation_id
    
    -- Check for suspicious upstream behavior
    if threat_cache[correlation_id] then
        local threat_data = threat_cache[correlation_id]
        
        -- Analyze response patterns that might indicate successful attacks
        local response_analysis = detector.analyze_response_headers(
            response_headers, 
            status_code, 
            threat_data.threat_result,
            conf
        )
        
        if response_analysis.suspicious then
            kong.log.warn("[Kong Guard AI] Suspicious upstream response detected")
            
            -- Update threat assessment
            threat_data.threat_result.response_analysis = response_analysis
            
            -- Potentially modify response headers to prevent information leakage
            if conf.sanitize_error_responses and status_code >= 500 then
                kong.response.set_header("Server", "Kong")
                kong.response.clear_header("X-Powered-By")
            end
        end
    end
end

---
-- Response phase - executed after full response received from upstream
-- Used for: Response body analysis, pattern learning, adaptive tuning
---
function KongGuardAIHandler:response(conf)
    -- Get correlation ID from request metadata
    local request_metadata = kong.ctx.plugin.guard_ai_request_metadata
    if not request_metadata then
        return -- No metadata captured in access phase
    end
    
    local correlation_id = request_metadata.correlation_id
    
    -- Only analyze responses for requests that triggered threat detection
    if threat_cache[correlation_id] then
        local threat_data = threat_cache[correlation_id]
        
        -- Analyze response body if configured and size is reasonable
        if conf.analyze_response_body and kong.response.get_source() == "service" then
            local body = kong.response.get_raw_body()
            if body and #body < conf.max_response_body_size then
                local body_analysis = detector.analyze_response_body(
                    body,
                    threat_data.threat_result,
                    conf
                )
                
                threat_data.threat_result.body_analysis = body_analysis
            end
        end
        
        -- Feed response data back to learning system
        if conf.enable_learning then
            detector.learn_from_response(threat_data.threat_result, threat_data.request_context, conf)
        end
    end
end

---
-- Log phase - executed after response sent to client
-- PHASE 3 ENHANCEMENT: Complete rewrite for structured logging with instrumentation
-- Used for: Final incident logging, metrics collection, cleanup
---
function KongGuardAIHandler:log(conf)
    local log_phase_start = ngx.now()
    
    -- Get request metadata from access phase
    local request_metadata = kong.ctx.plugin.guard_ai_request_metadata
    if not request_metadata then
        kong.log.debug("[Kong Guard AI] No request metadata found in log phase")
        return
    end
    
    local correlation_id = request_metadata.correlation_id
    local access_processing_time = kong.ctx.plugin.guard_ai_access_phase_time or 0
    
    -- PHASE 3: Capture complete response metadata using instrumentation
    local response_metadata = instrumentation.capture_response_metadata(request_metadata, conf)
    
    -- Check if this request had threat detection
    local threat_data = threat_cache[correlation_id]
    
    if threat_data then
        -- THREAT INCIDENT LOGGING
        kong.log.info("[Kong Guard AI] Processing threat incident for correlation ID: " .. correlation_id)
        
        -- Create structured threat log using instrumentation
        local threat_log = instrumentation.create_threat_log_entry(
            threat_data.threat_result,
            threat_data.request_metadata,
            response_metadata,
            conf
        )
        
        -- Add enforcement results to log
        threat_log.enforcement = {
            action_executed = threat_data.enforcement_result.executed or false,
            action_simulated = threat_data.enforcement_result.simulated or false,
            action_type = threat_data.enforcement_result.action_type,
            notification_sent = threat_data.notification_result.success or false
        }
        
        -- Emit structured threat incident log
        kong.log.alert("[Kong Guard AI] THREAT_INCIDENT: " .. kong.json.encode(threat_log))
        
        -- Send to external logging systems if configured
        if conf.external_logging_enabled then
            pcall(function()
                notifier.send_incident_log(threat_log, conf)
            end)
        end
        
        -- Cleanup threat cache entry
        threat_cache[correlation_id] = nil
        
    elseif conf.log_all_requests then
        -- PERFORMANCE METRICS LOGGING (for all requests if enabled)
        local metrics_log = instrumentation.create_metrics_entry(request_metadata, response_metadata, conf)
        kong.log.debug("[Kong Guard AI] METRICS: " .. kong.json.encode(metrics_log))
    end
    
    -- Log performance warnings for high latency requests
    local total_processing_time = access_processing_time + ((ngx.now() - log_phase_start) * 1000)
    if total_processing_time > 10 then  -- Total plugin overhead > 10ms
        kong.log.warn("[Kong Guard AI] High total plugin processing time: " .. 
                      string.format("%.2f", total_processing_time) .. 
                      "ms (access: " .. string.format("%.2f", access_processing_time) .. 
                      "ms, log: " .. string.format("%.2f", (ngx.now() - log_phase_start) * 1000) .. "ms)")
    end
    
    -- Log high-latency requests for investigation
    if response_metadata.total_latency_ms > (conf.high_latency_threshold or 2000) then
        kong.log.warn("[Kong Guard AI] High latency request detected: " .. 
                      string.format("%.2f", response_metadata.total_latency_ms) .. 
                      "ms for " .. request_metadata.method .. " " .. request_metadata.path)
    end
    
    -- Periodic maintenance and cleanup
    if math.random() < 0.002 then  -- 0.2% chance per request (increased frequency)
        kong.log.debug("[Kong Guard AI] Performing periodic maintenance")
        
        -- Cleanup threat detection cache
        pcall(function()
            detector.cleanup_cache(conf)
        end)
        
        -- Cleanup enforcement gate records
        pcall(function()
            enforcement_gate.cleanup_enforcement_records()
        end)
        
        -- Cleanup instrumentation cache
        pcall(function()
            instrumentation.cleanup_cache()
        end)
        
        -- Log cache statistics for monitoring
        local cache_stats = instrumentation.get_cache_stats()
        if cache_stats.active_requests > 100 then  -- Alert if many pending requests
            kong.log.warn("[Kong Guard AI] High cache usage: " .. cache_stats.active_requests .. 
                          " active requests, oldest: " .. string.format("%.1f", cache_stats.oldest_request_age) .. "s")
        end
    end
    
    -- Final performance tracking
    local log_phase_time = (ngx.now() - log_phase_start) * 1000
    if log_phase_time > 3 then  -- Warn if log phase takes >3ms
        kong.log.warn("[Kong Guard AI] High log phase processing time: " .. 
                      string.format("%.2f", log_phase_time) .. "ms")
    end
end

return KongGuardAIHandler