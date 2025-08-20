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
local performance_dashboard = require "kong.plugins.kong-guard-ai.performance_dashboard"
local method_filter = require "kong.plugins.kong-guard-ai.method_filter"
local path_filter = require "kong.plugins.kong-guard-ai.path_filter"
local rate_limiter = require "kong.plugins.kong-guard-ai.rate_limiter"
local analytics_dashboard = require "kong.plugins.kong-guard-ai.analytics_dashboard"
local incident_manager = require "kong.plugins.kong-guard-ai.incident_manager"
local ip_blacklist = require "kong.plugins.kong-guard-ai.ip_blacklist"
local advanced_remediation = require "kong.plugins.kong-guard-ai.advanced_remediation"

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
    
    -- Initialize incident management system (PHASE 4)
    incident_manager.init_worker(conf)
    kong.log.info("[Kong Guard AI] Incident management system initialized")
    
    -- Initialize incident analytics and dashboard (PHASE 4)
    incident_analytics.init_worker(conf)
    kong.log.info("[Kong Guard AI] Incident analytics system initialized")
    
    -- Initialize incident alerting system (PHASE 4)
    incident_alerting.init_worker(conf)
    kong.log.info("[Kong Guard AI] Incident alerting system initialized")
    
    -- Initialize IP blacklist enforcement system (PHASE 4)  
    ip_blacklist.init_worker(conf)
    kong.log.info("[Kong Guard AI] IP blacklist enforcement system initialized")
    
    -- Initialize threat detection engine
    detector.init_worker(conf)
    
    -- Initialize path filtering system (PHASE 4)
    path_filter.init_worker(conf)
    kong.log.info("[Kong Guard AI] Path regex filtering system initialized")
    
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
    
    -- Initialize performance dashboard (PHASE 3)
    performance_dashboard.init_worker(conf)
    kong.log.info("[Kong Guard AI] Performance dashboard initialized")
    
    -- Initialize counter management system
    local counters_initialized = counters.init(conf)
    if counters_initialized then
        kong.log.info("[Kong Guard AI] Counter management system initialized")
    else
        kong.log.warn("[Kong Guard AI] Counter management system failed to initialize")
    end
    
    -- PHASE 5: Initialize advanced rate limiting system
    if conf.enable_advanced_rate_limiting then
        local rate_limiter_initialized = rate_limiter.init_worker(conf)
        if rate_limiter_initialized then
            kong.log.info("[Kong Guard AI] Advanced rate limiting system initialized")
        else
            kong.log.warn("[Kong Guard AI] Advanced rate limiting system failed to initialize")
        end
    end
    
    -- PHASE 6: Initialize analytics dashboard and threat intelligence
    if conf.analytics_dashboard_enabled then
        local analytics_initialized = analytics_dashboard.init_worker(conf)
        if analytics_initialized then
            kong.log.info("[Kong Guard AI] Analytics dashboard and threat intelligence initialized")
        else
            kong.log.warn("[Kong Guard AI] Analytics dashboard failed to initialize")
        end
    end
    
    -- PHASE 7: Initialize advanced remediation system
    if conf.enable_advanced_remediation then
        local remediation_initialized = advanced_remediation.init_worker(conf)
        if remediation_initialized then
            kong.log.info("[Kong Guard AI] Advanced remediation system initialized")
        else
            kong.log.warn("[Kong Guard AI] Advanced remediation system failed to initialize")
        end
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
    
    -- PHASE 3 ENHANCEMENT: Handle performance dashboard requests
    if performance_dashboard.handle_dashboard_request(conf) then
        return -- Request was handled by performance dashboard
    end
    
    -- PHASE 6: Handle analytics dashboard requests
    if conf.analytics_dashboard_enabled and analytics_dashboard.handle_dashboard_request(conf) then
        return -- Request was handled by analytics dashboard
    end
    
    -- PHASE 4: Handle incident analytics dashboard requests
    if conf.incident_analytics_enabled and incident_analytics.handle_dashboard_request(conf) then
        return -- Request was handled by incident analytics dashboard
    end
    
    -- PHASE 4 ENHANCEMENT: Handle IP blacklist Admin API requests
    if ip_blacklist.handle_admin_api_request(conf) then
        return -- Request was handled by IP blacklist Admin API
    end
    
    -- Handle test endpoint (if enabled in development/testing environments)
    if test_dry_run_enforcement.handle_test_endpoint(conf) then
        return -- Request was handled by test endpoint
    end
    
    -- PHASE 4 ENHANCEMENT: IP Blacklist Enforcement - HIGHEST PRIORITY
    -- This check happens BEFORE all other processing for immediate blocking
    local ip_enforcement_result = ip_blacklist.enforce_ip_blacklist(conf)
    if ip_enforcement_result and ip_enforcement_result.executed then
        -- IP was blocked and response was sent, execution stops here
        return
    elseif ip_enforcement_result and ip_enforcement_result.simulated then
        -- Log dry-run IP block simulation
        kong.log.warn("[Kong Guard AI] [DRY RUN] Would block IP: " .. 
                      (ip_enforcement_result.details and ip_enforcement_result.details.client_ip or "unknown"))
    end
    
    -- PHASE 3 ENHANCEMENT: Capture comprehensive request metadata using instrumentation module
    -- This provides optimized metadata collection with minimal overhead
    local request_metadata = instrumentation.capture_request_metadata(conf)
    
    -- Performance checkpoint: metadata collection
    performance_optimizer.record_checkpoint(perf_context, "metadata_collection")
    
    -- PHASE 4: Path Regex Filtering - Check for malicious path patterns
    local path_threat_result = nil
    if path_filter.should_filter_path(conf, request_metadata) then
        path_threat_result = path_filter.analyze_path(request_metadata, conf)
        
        -- Performance checkpoint: path filtering
        performance_optimizer.record_checkpoint(perf_context, "path_filtering", {
            path_result = path_threat_result.result,
            threat_level = path_threat_result.threat_level,
            matches = #path_threat_result.matched_patterns
        })
        
        -- Handle path-based threats immediately if they exceed threshold
        if path_threat_result.result == path_filter.get_filter_results().BLOCK then
            kong.log.warn("[Kong Guard AI] Malicious path pattern detected: " .. 
                          (path_threat_result.threat_category or "unknown") .. 
                          " (level: " .. path_threat_result.threat_level .. ")")
            
            -- Create threat result for enforcement system
            local path_based_threat = {
                threat_level = path_threat_result.threat_level,
                threat_type = "malicious_path",
                threat_category = path_threat_result.threat_category,
                confidence = path_threat_result.confidence,
                details = path_threat_result,
                requires_ai_analysis = false,
                recommended_action = "block"
            }
            
            -- Execute blocking response through enforcement gate
            local action_types = enforcement_gate.get_action_types()
            local enforcement_result = enforcement_gate.enforce_action(
                action_types.BLOCK_REQUEST,
                {
                    threat_result = path_based_threat,
                    request_context = request_metadata,
                    recommended_action = "block",
                    path_filter_result = path_threat_result
                },
                conf,
                function(action_data, config)
                    -- Create path filter incident log
                    local incident_log = path_filter.create_incident_log(
                        action_data.path_filter_result, 
                        action_data.request_context, 
                        config
                    )
                    
                    -- Log the incident
                    kong.log.warn("[Kong Guard AI] PATH FILTER BLOCK: " .. 
                                  kong.json.encode(incident_log))
                    
                    -- Execute blocking response
                    return responder.execute_response(action_data.threat_result, action_data.request_context, config)
                end
            )
            
            -- Send notification for path-based block
            enforcement_gate.enforce_action(
                action_types.NOTIFICATION,
                {
                    threat_result = path_based_threat,
                    response_action = enforcement_result,
                    notification_type = "path_filter_block",
                    path_filter_result = path_threat_result
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
            
            -- Store in threat cache for log phase
            threat_cache[request_metadata.correlation_id] = {
                threat_result = path_based_threat,
                request_context = request_metadata,
                request_metadata = request_metadata,
                enforcement_result = enforcement_result,
                path_filter_result = path_threat_result,
                timestamp = ngx.now()
            }
            
            return -- Request blocked, no further processing needed
        end
        
        -- Log suspicious paths for monitoring
        if path_threat_result.result == path_filter.get_filter_results().SUSPICIOUS then
            kong.log.info("[Kong Guard AI] Suspicious path pattern detected: " .. 
                          (path_threat_result.threat_category or "unknown") .. 
                          " (level: " .. path_threat_result.threat_level .. ")")
        end
    end
    
    -- Store path filter result in Kong context for later phases
    kong.ctx.plugin.guard_ai_path_filter_result = path_threat_result
    
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
    
    -- PHASE 5: Advanced rate limiting check (before threat detection for performance)
    local rate_limit_result = nil
    if conf.enable_advanced_rate_limiting then
        local user_id = request_metadata.consumer_id
        rate_limit_result = rate_limiter.check_rate_limits(client_ip, user_id, 0, conf)  -- Initial check with no threat level
        
        -- Performance checkpoint: rate limiting
        performance_optimizer.record_checkpoint(perf_context, "rate_limiting", {
            rate_limit_code = rate_limit_result.code,
            allowed = rate_limit_result.allowed
        })
        
        -- Handle rate limit violations immediately
        if not rate_limit_result.allowed then
            kong.log.warn("[Kong Guard AI] Rate limit exceeded for IP: " .. client_ip .. 
                          " (" .. rate_limit_result.message .. ")")
            
            -- Set appropriate HTTP status and headers
            local status_code = 429  -- Too Many Requests
            if rate_limit_result.code == rate_limiter.RATE_LIMIT_CODES.BLOCKED then
                status_code = 403  -- Forbidden
            end
            
            kong.response.set_status(status_code)
            kong.response.set_header("X-RateLimit-Limit", tostring(rate_limit_result.dynamic_limits.minute or 60))
            kong.response.set_header("X-RateLimit-Remaining", "0")
            kong.response.set_header("X-RateLimit-Reset", tostring(ngx.time() + 60))
            kong.response.set_header("X-Kong-Guard-AI", "rate-limited")
            
            -- Record rate limit event for analytics
            if conf.analytics_dashboard_enabled then
                local rate_limit_threat = {
                    threat_type = "rate_limit_violation",
                    threat_level = rate_limit_result.code == rate_limiter.RATE_LIMIT_CODES.BLOCKED and 9.0 or 7.0,
                    recommended_action = "rate_limit"
                }
                analytics_dashboard.record_threat_event(rate_limit_threat, request_metadata, conf)
            end
            
            kong.response.exit(status_code, {
                error = "Rate limit exceeded",
                message = rate_limit_result.message,
                retry_after = 60
            })
            return
        end
    end
    
    -- Perform threat detection analysis
    local threat_result = detector.analyze_request(request_context, conf)
    
    -- PHASE 4: Merge path filter results with threat detection
    if path_threat_result and path_threat_result.threat_level > 0 then
        -- Enhance threat result with path filtering data
        if path_threat_result.threat_level > threat_result.threat_level then
            threat_result.threat_level = path_threat_result.threat_level
            threat_result.threat_type = "malicious_path"
            threat_result.recommended_action = path_threat_result.recommended_action
        end
        
        -- Add path filter details to threat result
        threat_result.path_filter = {
            result = path_threat_result.result,
            threat_category = path_threat_result.threat_category,
            matched_patterns = path_threat_result.matched_patterns,
            confidence = path_threat_result.confidence
        }
        
        -- Combine confidence scores
        if path_threat_result.confidence > threat_result.confidence then
            threat_result.confidence = path_threat_result.confidence
        end
    end
    
    -- Performance checkpoint: threat detection
    performance_optimizer.record_checkpoint(perf_context, "threat_detection", {
        threat_level = threat_result.threat_level,
        threat_type = threat_result.threat_type,
        path_filter_applied = path_threat_result ~= nil
    })
    
    -- PHASE 5: Re-check rate limits with threat level for dynamic adjustment
    if conf.enable_advanced_rate_limiting and conf.dynamic_rate_adjustment and threat_result.threat_level > 0 then
        local user_id = request_metadata.consumer_id
        local updated_rate_result = rate_limiter.check_rate_limits(client_ip, user_id, threat_result.threat_level, conf)
        
        -- If threat level causes additional rate limit violations, handle them
        if rate_limit_result.allowed and not updated_rate_result.allowed then
            kong.log.warn("[Kong Guard AI] Dynamic rate limit triggered by threat level: " .. 
                          threat_result.threat_level .. " for IP: " .. client_ip)
            
            kong.response.set_status(429)
            kong.response.set_header("X-RateLimit-Threat-Adjusted", "true")
            kong.response.set_header("X-Kong-Guard-AI", "threat-rate-limited")
            
            kong.response.exit(429, {
                error = "Rate limit exceeded due to threat level",
                message = updated_rate_result.message,
                threat_level = threat_result.threat_level
            })
            return
        end
        
        rate_limit_result = updated_rate_result
    end
    
    -- AI Gateway analysis for advanced threats (if enabled and warranted)
    if conf.ai_gateway_enabled and threat_result.requires_ai_analysis then
        local ai_result = ai_gateway.analyze_threat(request_context, threat_result, conf)
        if ai_result then
            threat_result = detector.merge_ai_results(threat_result, ai_result)
        end
        
        -- Performance checkpoint: AI analysis
        performance_optimizer.record_checkpoint(perf_context, "ai_analysis", {
            ai_enabled = true,
            ai_result_received = ai_result ~= nil
        })
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
        
        -- PHASE 4: Create comprehensive incident record
        local incident_record = incident_manager.create_incident(
            threat_result,
            request_context, 
            enforcement_result,
            conf
        )
        
        -- PHASE 4: Process incident for real-time alerting
        incident_alerting.process_incident_for_alerting(incident_record, conf)
        
        -- Store threat data for learning and reporting (using correlation ID for tracking)
        threat_cache[request_metadata.correlation_id] = {
            threat_result = threat_result,
            request_context = request_context,
            request_metadata = request_metadata,
            enforcement_result = enforcement_result,
            notification_result = notification_result,
            incident_record = incident_record,
            rate_limit_result = rate_limit_result,
            timestamp = ngx.now()
        }
        
        -- PHASE 6: Record threat event for analytics dashboard
        if conf.analytics_dashboard_enabled then
            analytics_dashboard.record_threat_event(threat_result, request_metadata, conf)
        end
    end
    
    -- PHASE 3 ENHANCEMENT: Complete performance monitoring and get summary
    local perf_summary = performance_optimizer.complete_request_monitoring(perf_context)
    
    -- Store performance data in Kong context for logging
    kong.ctx.plugin.guard_ai_processing_time = perf_summary.total_time_ms
    kong.ctx.plugin.guard_ai_performance_summary = perf_summary
    kong.ctx.plugin.guard_ai_perf_context = perf_context
    
    -- Log performance warnings if thresholds exceeded
    if perf_summary.total_time_ms > 10 then -- 10ms threshold
        kong.log.warn("[Kong Guard AI] Performance threshold exceeded: " .. 
                      perf_summary.total_time_ms .. "ms (threshold: 10ms)")
    end
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
    
    -- PHASE 7: Advanced remediation - 5xx error correlation and automated remediation
    if conf.enable_advanced_remediation and conf.enable_5xx_correlation and status_code >= 500 then
        kong.log.debug(string.format(
            "[Kong Guard AI Advanced Remediation] 5xx error detected: %d for service=%s, route=%s",
            status_code, request_metadata.service_id or "none", request_metadata.route_id or "none"
        ))
        
        -- Perform error correlation analysis in the background
        ngx.timer.at(0, function(premature)
            if premature then return end
            
            -- Correlate 5xx errors with recent configuration changes
            local correlation_result = advanced_remediation.correlate_5xx_errors_with_config_changes(
                request_metadata.service_id,
                request_metadata.route_id,
                1, -- Single error for this request
                conf.config_correlation_window or 3600, -- 1 hour default
                conf
            )
            
            kong.log.debug(string.format(
                "[Kong Guard AI Advanced Remediation] Correlation analysis: found=%s, confidence=%.2f",
                tostring(correlation_result.correlation_found), correlation_result.confidence
            ))
            
            -- If correlation is found and confidence is high enough, trigger remediation
            if correlation_result.correlation_found and 
               correlation_result.confidence >= (conf.remediation_confidence_threshold or 0.8) then
                
                kong.log.warn(string.format(
                    "[Kong Guard AI Advanced Remediation] High-confidence correlation detected (%.2f), evaluating remediation actions",
                    correlation_result.confidence
                ))
                
                -- Determine if automatic remediation should be triggered
                if conf.enable_automatic_rollback and 
                   correlation_result.confidence >= (conf.rollback_confidence_threshold or 0.9) then
                    
                    -- Execute automatic rollback
                    for _, action in ipairs(correlation_result.recommended_actions) do
                        if action == advanced_remediation.REMEDIATION_ACTIONS.CONFIG_ROLLBACK then
                            local rollback_result = advanced_remediation.execute_advanced_remediation(
                                advanced_remediation.REMEDIATION_ACTIONS.CONFIG_ROLLBACK,
                                {
                                    type = "service",
                                    id = request_metadata.service_id,
                                    original_url = "current"
                                },
                                {
                                    strategy = conf.default_reroute_strategy or "immediate",
                                    confidence = correlation_result.confidence
                                },
                                conf
                            )
                            
                            if rollback_result.success then
                                kong.log.warn(string.format(
                                    "[Kong Guard AI Advanced Remediation] Automatic rollback executed: %s",
                                    rollback_result.remediation_id
                                ))
                            else
                                kong.log.error(string.format(
                                    "[Kong Guard AI Advanced Remediation] Automatic rollback failed: %s",
                                    rollback_result.details.reason or "unknown"
                                ))
                            end
                            break
                        end
                    end
                end
                
                -- Execute traffic rerouting if enabled
                if conf.enable_traffic_rerouting then
                    for _, action in ipairs(correlation_result.recommended_actions) do
                        if action == advanced_remediation.REMEDIATION_ACTIONS.TRAFFIC_REROUTE then
                            -- Note: This would require backup upstream/service configuration
                            kong.log.info("[Kong Guard AI Advanced Remediation] Traffic rerouting would be triggered here")
                            break
                        end
                    end
                end
            end
        end)
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
    
    -- COUNTER MANAGEMENT: Track response metrics
    local client_ip = request_metadata.client_ip
    local status_code = response_metadata.status_code
    local response_time_ms = response_metadata.total_latency_ms
    
    -- Increment response counters
    counters.increment_global_counter(counters.COUNTER_TYPES.RESPONSES)
    counters.increment_ip_counter(client_ip, counters.COUNTER_TYPES.RESPONSES)
    
    -- Track status code distribution
    counters.track_status_code(client_ip, status_code)
    
    -- Track response time percentiles
    counters.track_response_time(client_ip, response_time_ms)
    
    -- Check if this request had threat detection or IP blacklist incident
    local threat_data = threat_cache[correlation_id]
    local ip_incident = kong.ctx.plugin.ip_blacklist_incident
    
    if threat_data then
        -- THREAT INCIDENT LOGGING - PHASE 3 ENHANCED
        kong.log.info("[Kong Guard AI] Processing threat incident for correlation ID: " .. correlation_id)
        
        -- Create comprehensive response context for structured logger
        local response_context = {
            status = kong.response.get_status(),
            headers = kong.response.get_headers(),
            body_size = tonumber(ngx.var.bytes_sent) or 0,
            processing_time_ms = response_metadata.total_latency_ms
        }
        
        -- Log threat event using structured logger with full context
        structured_logger.log_threat_event(
            threat_data.threat_result,
            threat_data.request_metadata,
            threat_data.enforcement_result,
            conf
        )
        
        -- Create legacy threat log for backward compatibility
        local threat_log = instrumentation.create_threat_log_entry(
            threat_data.threat_result,
            threat_data.request_metadata,
            response_metadata,
            conf
        )
        
        -- Add enforcement results to legacy log
        threat_log.enforcement = {
            action_executed = threat_data.enforcement_result.executed or false,
            action_simulated = threat_data.enforcement_result.simulated or false,
            action_type = threat_data.enforcement_result.action_type,
            notification_sent = threat_data.notification_result and threat_data.notification_result.success or false
        }
        
        -- Emit structured threat incident log using log_format module
        local formatted_incident = log_format.create_threat_incident_log(
            threat_data.threat_result,
            threat_data.request_metadata,
            threat_data.enforcement_result,
            conf
        )
        log_format.emit_structured_log(formatted_incident, 3) -- WARN level
        
        -- Send to external logging systems if configured
        if conf.external_logging_enabled then
            pcall(function()
                notifier.send_incident_log(threat_log, conf)
            end)
        end
        
        -- Cleanup threat cache entry
        threat_cache[correlation_id] = nil
        
    elseif ip_incident then
        -- IP BLACKLIST INCIDENT LOGGING - PHASE 4
        kong.log.info("[Kong Guard AI] Processing IP blacklist incident for IP: " .. 
                      (ip_incident.client_ip or "unknown"))
        
        -- Create comprehensive IP blacklist incident log
        local ip_incident_log = ip_blacklist.create_incident_log(
            ip_incident.enforcement_result,
            ip_incident.block_result,
            ip_incident.client_ip,
            conf
        )
        
        -- Log IP blacklist event using structured logger
        structured_logger.warn(
            "IP blacklist enforcement executed",
            ip_incident_log,
            request_metadata,
            {
                incident_type = "ip_blacklist_block",
                client_ip = ip_incident.client_ip,
                block_reason = ip_incident.block_result.reason,
                match_type = ip_incident.block_result.match_type
            },
            conf
        )
        
        -- Emit structured IP blacklist incident log
        local formatted_ip_incident = log_format.create_threat_incident_log(
            {
                threat_type = "ip_blacklist_violation",
                threat_level = 9.0,
                confidence = 1.0,
                description = "IP address blocked by blacklist enforcement",
                ip_block_details = ip_incident.block_result
            },
            request_metadata,
            ip_incident.enforcement_result,
            conf
        )
        log_format.emit_structured_log(formatted_ip_incident, 3) -- WARN level
        
        -- Send to external logging systems if configured
        if conf.external_logging_enabled then
            pcall(function()
                notifier.send_incident_log(ip_incident_log, conf)
            end)
        end
        
    elseif conf.log_all_requests then
        -- PERFORMANCE METRICS LOGGING (for all requests if enabled)
        local metrics_log = instrumentation.create_metrics_entry(request_metadata, response_metadata, conf)
        kong.log.debug("[Kong Guard AI] METRICS: " .. kong.json.encode(metrics_log))
    end
    
    -- PHASE 3: Enhanced performance logging using structured logger
    local total_processing_time = access_processing_time + ((ngx.now() - log_phase_start) * 1000)
    
    -- Log performance metrics using structured logger for all requests
    structured_logger.log_performance_metrics(
        total_processing_time,
        request_metadata,
        conf
    )
    
    -- Warn about high latency plugin overhead
    if total_processing_time > 10 then  -- Total plugin overhead > 10ms
        structured_logger.warn(
            string.format("High plugin processing time: %.2fms (access: %.2fms, log: %.2fms)",
                total_processing_time,
                access_processing_time,
                (ngx.now() - log_phase_start) * 1000),
            nil,
            request_metadata,
            { processing_time_ms = total_processing_time },
            conf
        )
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
        
        -- Cleanup counter system
        pcall(function()
            counters.maintenance()
        end)
        
        -- Cleanup structured logger caches (PHASE 3)
        pcall(function()
            structured_logger.cleanup()
        end)
        
        -- PHASE 4: Incident system maintenance
        pcall(function()
            incident_manager.cleanup_incidents(conf)
        end)
        
        pcall(function()
            incident_analytics.cleanup_analytics_cache()
        end)
        
        pcall(function()
            incident_alerting.maintenance(conf)
        end)
        
        -- Cleanup method filter analytics (PHASE 4)
        pcall(function()
            method_filter.cleanup_cache()
        end)
        
        -- PHASE 5: Cleanup rate limiter data
        if conf.enable_advanced_rate_limiting then
            pcall(function()
                rate_limiter.cleanup()
            end)
        end
        
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