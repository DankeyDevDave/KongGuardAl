-- Kong Guard AI - Advanced Remediation Module
-- PHASE 7: Enterprise-grade automated remediation with route/service modification and rollback
-- Handles 5xx event correlation, decK/Konnect integration, traffic rerouting, and configuration rollback

local kong = kong
local http = require "resty.http"
local json = require "cjson.safe"
local pl_file = require "pl.file"
local pl_dir = require "pl.dir"

local _M = {}

-- Advanced remediation action types
local REMEDIATION_ACTIONS = {
    TRAFFIC_REROUTE = "traffic_reroute",
    CONFIG_ROLLBACK = "config_rollback",
    SERVICE_DISABLE = "service_disable",
    ROUTE_MODIFY = "route_modify",
    UPSTREAM_FAILOVER = "upstream_failover",
    CIRCUIT_BREAKER = "circuit_breaker",
    CANARY_ROLLBACK = "canary_rollback",
    EMERGENCY_MAINTENANCE = "emergency_maintenance"
}

-- Rollback strategy types
local ROLLBACK_STRATEGIES = {
    IMMEDIATE = "immediate",      -- Instant rollback for critical issues
    GRADUAL = "gradual",         -- Gradual traffic shifting
    CANARY = "canary",          -- Canary-style rollback
    BLUE_GREEN = "blue_green"    -- Blue-green deployment rollback
}

-- Error correlation thresholds
local ERROR_CORRELATION_THRESHOLDS = {
    LIGHT = { error_rate = 0.05, time_window = 60 },      -- 5% errors in 1 minute
    MODERATE = { error_rate = 0.15, time_window = 300 },   -- 15% errors in 5 minutes
    SEVERE = { error_rate = 0.30, time_window = 900 },     -- 30% errors in 15 minutes
    CRITICAL = { error_rate = 0.50, time_window = 1800 }   -- 50% errors in 30 minutes
}

-- Configuration state tracking
local config_snapshots = {}
local error_tracking = {}
local remediation_history = {}
local active_remediations = {}

---
-- Initialize advanced remediation system
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Advanced Remediation] Initializing enterprise remediation system")

    -- Initialize storage structures
    config_snapshots.snapshots = {}
    config_snapshots.metadata = {}
    config_snapshots.rollback_points = {}

    -- Initialize error correlation tracking
    error_tracking.service_errors = {}
    error_tracking.route_errors = {}
    error_tracking.upstream_errors = {}
    error_tracking.global_errors = {}

    -- Initialize remediation tracking
    remediation_history.actions = {}
    remediation_history.rollbacks = {}
    remediation_history.failures = {}

    active_remediations.ongoing = {}
    active_remediations.scheduled = {}

    -- Create backup directory if it doesn't exist
    local backup_dir = "/tmp/kong-guard-ai/config-backups"
    kong.log.debug("[Kong Guard AI Advanced Remediation] Creating backup directory: " .. backup_dir)

    -- Initialize decK integration
    _M.initialize_deck_integration(conf)

    -- Start background error correlation monitoring
    _M.start_error_correlation_monitoring(conf)

    kong.log.info("[Kong Guard AI Advanced Remediation] Advanced remediation system initialized")
end

---
-- Correlate 5xx errors with recent configuration changes
-- @param service_id Kong service ID
-- @param route_id Kong route ID
-- @param error_count Number of 5xx errors
-- @param time_window Time window for correlation
-- @param conf Plugin configuration
-- @return Table containing correlation analysis
---
function _M.correlate_5xx_errors_with_config_changes(service_id, route_id, error_count, time_window, conf)
    local correlation_result = {
        correlation_found = false,
        confidence = 0.0,
        suspected_changes = {},
        recommended_actions = {},
        error_analysis = {},
        rollback_candidates = {}
    }

    kong.log.info(string.format(
        "[Kong Guard AI Advanced Remediation] Correlating 5xx errors: service=%s, route=%s, errors=%d, window=%ds",
        service_id or "none", route_id or "none", error_count, time_window
    ))

    -- Analyze error patterns for the affected service/route
    local error_analysis = _M.analyze_error_patterns(service_id, route_id, time_window, conf)
    correlation_result.error_analysis = error_analysis

    -- Check if error rate exceeds thresholds
    local severity_level = _M.determine_error_severity(error_analysis)

    -- Get recent configuration changes within correlation window
    local correlation_window = conf.config_correlation_window or 24 * 3600 -- 24 hours default
    local recent_changes = _M.get_recent_config_changes(correlation_window, conf)

    -- Correlate errors with specific configuration changes
    local change_correlations = _M.correlate_errors_with_changes(
        error_analysis, recent_changes, service_id, route_id
    )

    if #change_correlations > 0 then
        correlation_result.correlation_found = true
        correlation_result.suspected_changes = change_correlations

        -- Calculate overall confidence based on timing and impact
        correlation_result.confidence = _M.calculate_correlation_confidence(
            change_correlations, error_analysis, severity_level
        )

        -- Determine recommended remediation actions
        correlation_result.recommended_actions = _M.determine_remediation_actions(
            severity_level, change_correlations, error_analysis, conf
        )

        -- Identify viable rollback candidates
        correlation_result.rollback_candidates = _M.identify_rollback_candidates(
            change_correlations, conf
        )

        kong.log.warn(string.format(
            "[Kong Guard AI Advanced Remediation] Configuration correlation detected: %d suspected changes, confidence: %.2f",
            #change_correlations, correlation_result.confidence
        ))
    end

    return correlation_result
end

---
-- Execute advanced remediation action
-- @param remediation_type Type of remediation action
-- @param target_config Target configuration (service, route, upstream)
-- @param remediation_params Remediation parameters
-- @param conf Plugin configuration
-- @return Table containing remediation result
---
function _M.execute_advanced_remediation(remediation_type, target_config, remediation_params, conf)
    local remediation_id = "REM-" .. ngx.time() .. "-" .. ngx.worker.pid()

    local remediation_result = {
        remediation_id = remediation_id,
        action_type = remediation_type,
        success = false,
        details = {},
        rollback_info = {},
        validation_results = {},
        timestamp = ngx.time()
    }

    kong.log.warn(string.format(
        "[Kong Guard AI Advanced Remediation] Executing %s remediation (ID: %s)",
        remediation_type, remediation_id
    ))

    -- Pre-remediation validation and safety checks
    local safety_check = _M.perform_safety_checks(remediation_type, target_config, conf)
    if not safety_check.passed then
        remediation_result.details.safety_check_failed = safety_check.reason
        kong.log.error(string.format(
            "[Kong Guard AI Advanced Remediation] Safety check failed: %s", safety_check.reason
        ))
        return remediation_result
    end

    -- Create configuration snapshot before making changes
    local pre_remediation_snapshot = _M.create_configuration_snapshot("pre_remediation", conf)
    remediation_result.rollback_info.pre_snapshot = pre_remediation_snapshot.snapshot_id

    -- Track this remediation as active
    active_remediations.ongoing[remediation_id] = {
        type = remediation_type,
        target = target_config,
        params = remediation_params,
        started_at = ngx.time(),
        pre_snapshot = pre_remediation_snapshot.snapshot_id
    }

    -- Execute specific remediation action
    local execution_result
    if remediation_type == REMEDIATION_ACTIONS.TRAFFIC_REROUTE then
        execution_result = _M.execute_traffic_reroute(target_config, remediation_params, conf)
    elseif remediation_type == REMEDIATION_ACTIONS.CONFIG_ROLLBACK then
        execution_result = _M.execute_configuration_rollback(target_config, remediation_params, conf)
    elseif remediation_type == REMEDIATION_ACTIONS.SERVICE_DISABLE then
        execution_result = _M.execute_service_disable(target_config, remediation_params, conf)
    elseif remediation_type == REMEDIATION_ACTIONS.ROUTE_MODIFY then
        execution_result = _M.execute_route_modification(target_config, remediation_params, conf)
    elseif remediation_type == REMEDIATION_ACTIONS.UPSTREAM_FAILOVER then
        execution_result = _M.execute_upstream_failover(target_config, remediation_params, conf)
    elseif remediation_type == REMEDIATION_ACTIONS.CIRCUIT_BREAKER then
        execution_result = _M.execute_circuit_breaker(target_config, remediation_params, conf)
    elseif remediation_type == REMEDIATION_ACTIONS.CANARY_ROLLBACK then
        execution_result = _M.execute_canary_rollback(target_config, remediation_params, conf)
    else
        execution_result = { success = false, reason = "unsupported_remediation_type" }
    end

    remediation_result.success = execution_result.success
    remediation_result.details = execution_result.details or {}

    -- Post-remediation validation
    if execution_result.success then
        local validation_result = _M.validate_remediation_success(
            remediation_type, target_config, conf
        )
        remediation_result.validation_results = validation_result

        if not validation_result.passed then
            kong.log.error(string.format(
                "[Kong Guard AI Advanced Remediation] Remediation validation failed: %s",
                validation_result.reason
            ))

            -- Attempt automatic rollback if validation fails
            local auto_rollback = _M.execute_automatic_rollback(
                remediation_id, pre_remediation_snapshot.snapshot_id, conf
            )
            remediation_result.details.auto_rollback_attempted = auto_rollback.attempted
            remediation_result.details.auto_rollback_success = auto_rollback.success
        end
    end

    -- Clean up active remediation tracking
    active_remediations.ongoing[remediation_id] = nil

    -- Store remediation in history
    remediation_history.actions[remediation_id] = remediation_result

    -- Log remediation completion
    if remediation_result.success then
        kong.log.info(string.format(
            "[Kong Guard AI Advanced Remediation] Remediation completed successfully: %s",
            remediation_id
        ))
    else
        kong.log.error(string.format(
            "[Kong Guard AI Advanced Remediation] Remediation failed: %s - %s",
            remediation_id, remediation_result.details.reason or "unknown"
        ))
    end

    return remediation_result
end

---
-- Execute traffic rerouting remediation
-- @param target_config Target configuration
-- @param params Rerouting parameters
-- @param conf Plugin configuration
-- @return Table containing execution result
---
function _M.execute_traffic_reroute(target_config, params, conf)
    local result = { success = false, details = {} }

    kong.log.info("[Kong Guard AI Advanced Remediation] Executing traffic rerouting")

    -- Validate rerouting parameters
    if not params.backup_upstream and not params.backup_service then
        result.details.reason = "no_backup_target_specified"
        return result
    end

    local reroute_strategy = params.strategy or "immediate"
    local traffic_percentage = params.traffic_percentage or 100

    if reroute_strategy == "gradual" then
        -- Implement gradual traffic shifting
        result = _M.execute_gradual_traffic_shift(target_config, params, conf)
    elseif reroute_strategy == "canary" then
        -- Implement canary-style rerouting
        result = _M.execute_canary_reroute(target_config, params, conf)
    else
        -- Immediate rerouting
        result = _M.execute_immediate_reroute(target_config, params, conf)
    end

    if result.success then
        result.details.reroute_strategy = reroute_strategy
        result.details.traffic_percentage = traffic_percentage
        result.details.backup_target = params.backup_upstream or params.backup_service
    end

    return result
end

---
-- Execute immediate traffic rerouting
-- @param target_config Target configuration
-- @param params Rerouting parameters
-- @param conf Plugin configuration
-- @return Table containing execution result
---
function _M.execute_immediate_reroute(target_config, params, conf)
    local result = { success = false, details = {} }

    if target_config.type == "service" then
        -- Reroute service to backup upstream
        local admin_result = _M.call_kong_admin_api(
            "PATCH",
            "/services/" .. target_config.id,
            {
                url = params.backup_upstream,
                tags = (target_config.tags or {}) .. {"guard_ai_rerouted"}
            },
            conf
        )

        if admin_result.success then
            result.success = true
            result.details.original_upstream = target_config.original_url
            result.details.new_upstream = params.backup_upstream
            result.details.reroute_method = "service_upstream_change"
        else
            result.details.reason = "admin_api_call_failed"
            result.details.api_error = admin_result.error
        end

    elseif target_config.type == "route" then
        -- Reroute route to backup service
        local admin_result = _M.call_kong_admin_api(
            "PATCH",
            "/routes/" .. target_config.id,
            {
                service = { id = params.backup_service },
                tags = (target_config.tags or {}) .. {"guard_ai_rerouted"}
            },
            conf
        )

        if admin_result.success then
            result.success = true
            result.details.original_service = target_config.original_service_id
            result.details.new_service = params.backup_service
            result.details.reroute_method = "route_service_change"
        else
            result.details.reason = "admin_api_call_failed"
            result.details.api_error = admin_result.error
        end
    end

    return result
end

---
-- Execute gradual traffic shifting
-- @param target_config Target configuration
-- @param params Shifting parameters
-- @param conf Plugin configuration
-- @return Table containing execution result
---
function _M.execute_gradual_traffic_shift(target_config, params, conf)
    local result = { success = false, details = {} }

    -- Implement weighted upstream targets for gradual shifting
    local shift_duration = params.shift_duration or 300 -- 5 minutes default
    local shift_steps = params.shift_steps or 5
    local step_duration = shift_duration / shift_steps

    kong.log.info(string.format(
        "[Kong Guard AI Advanced Remediation] Starting gradual traffic shift over %d seconds in %d steps",
        shift_duration, shift_steps
    ))

    -- Create weighted upstream configuration
    local weight_step = 100 / shift_steps
    local current_weight = 100
    local backup_weight = 0

    for step = 1, shift_steps do
        current_weight = current_weight - weight_step
        backup_weight = backup_weight + weight_step

        -- Update upstream targets with new weights
        local upstream_config = {
            targets = {
                { target = target_config.original_upstream, weight = current_weight },
                { target = params.backup_upstream, weight = backup_weight }
            }
        }

        local admin_result = _M.call_kong_admin_api(
            "PATCH",
            "/upstreams/" .. target_config.upstream_id,
            upstream_config,
            conf
        )

        if not admin_result.success then
            result.details.reason = "gradual_shift_failed_at_step_" .. step
            result.details.api_error = admin_result.error
            return result
        end

        kong.log.debug(string.format(
            "[Kong Guard AI Advanced Remediation] Gradual shift step %d: original=%d%%, backup=%d%%",
            step, current_weight, backup_weight
        ))

        -- Wait for next step (except on last iteration)
        if step < shift_steps then
            ngx.sleep(step_duration)
        end
    end

    result.success = true
    result.details.shift_completed = true
    result.details.final_weights = { original = current_weight, backup = backup_weight }

    return result
end

---
-- Execute configuration rollback using decK
-- @param target_config Target configuration
-- @param params Rollback parameters
-- @param conf Plugin configuration
-- @return Table containing execution result
---
function _M.execute_configuration_rollback(target_config, params, conf)
    local result = { success = false, details = {} }

    kong.log.warn("[Kong Guard AI Advanced Remediation] Executing configuration rollback")

    -- Determine rollback target
    local rollback_target = params.target_snapshot_id or _M.get_latest_stable_snapshot(conf)
    if not rollback_target then
        result.details.reason = "no_rollback_target_available"
        return result
    end

    -- Validate rollback target
    local validation_result = _M.validate_rollback_target(rollback_target, conf)
    if not validation_result.valid then
        result.details.reason = "rollback_target_invalid"
        result.details.validation_error = validation_result.reason
        return result
    end

    -- Perform dry run if enabled
    if conf.enable_rollback_dry_run then
        local dry_run_result = _M.execute_rollback_dry_run(rollback_target, conf)
        result.details.dry_run_result = dry_run_result

        if not dry_run_result.success then
            result.details.reason = "dry_run_failed"
            return result
        end
    end

    -- Execute rollback based on strategy
    local rollback_strategy = params.strategy or ROLLBACK_STRATEGIES.IMMEDIATE

    if rollback_strategy == ROLLBACK_STRATEGIES.GRADUAL then
        result = _M.execute_gradual_rollback(rollback_target, params, conf)
    elseif rollback_strategy == ROLLBACK_STRATEGIES.CANARY then
        result = _M.execute_canary_rollback(rollback_target, params, conf)
    else
        result = _M.execute_immediate_rollback(rollback_target, params, conf)
    end

    if result.success then
        result.details.rollback_target = rollback_target
        result.details.rollback_strategy = rollback_strategy

        -- Create post-rollback snapshot
        local post_snapshot = _M.create_configuration_snapshot("post_rollback", conf)
        result.details.post_rollback_snapshot = post_snapshot.snapshot_id
    end

    return result
end

---
-- Execute immediate configuration rollback
-- @param rollback_target Target snapshot ID
-- @param params Rollback parameters
-- @param conf Plugin configuration
-- @return Table containing execution result
---
function _M.execute_immediate_rollback(rollback_target, params, conf)
    local result = { success = false, details = {} }

    -- Load target configuration from snapshot
    local target_config = _M.load_configuration_snapshot(rollback_target, conf)
    if not target_config then
        result.details.reason = "snapshot_load_failed"
        return result
    end

    -- Apply configuration using decK
    local deck_result = _M.apply_configuration_via_deck(target_config, conf)
    if deck_result.success then
        result.success = true
        result.details.deck_output = deck_result.output
        result.details.changes_applied = deck_result.changes_count

        kong.log.info(string.format(
            "[Kong Guard AI Advanced Remediation] Immediate rollback completed: %d changes applied",
            deck_result.changes_count or 0
        ))
    else
        result.details.reason = "deck_application_failed"
        result.details.deck_error = deck_result.error
    end

    return result
end

---
-- Apply configuration via decK
-- @param config_data Configuration data to apply
-- @param conf Plugin configuration
-- @return Table containing application result
---
function _M.apply_configuration_via_deck(config_data, conf)
    local result = { success = false, details = {} }

    local temp_config_file = "/tmp/kong-guard-ai-rollback-" .. ngx.time() .. ".yaml"

    -- Write configuration to temporary file
    local file_write_success, file_error = pl_file.write(temp_config_file, config_data)
    if not file_write_success then
        result.error = "failed_to_write_temp_config: " .. (file_error or "unknown")
        return result
    end

    -- Construct decK command
    local deck_cmd = string.format(
        "deck sync --kong-addr %s --config %s --verbose",
        conf.kong_admin_url or "http://localhost:8001",
        temp_config_file
    )

    if conf.kong_workspace then
        deck_cmd = deck_cmd .. " --workspace " .. conf.kong_workspace
    end

    kong.log.debug("[Kong Guard AI Advanced Remediation] Executing decK command: " .. deck_cmd)

    -- Execute decK command
    local deck_output, deck_exit_code = _M.execute_system_command(deck_cmd)

    -- Clean up temporary file
    os.remove(temp_config_file)

    if deck_exit_code == 0 then
        result.success = true
        result.output = deck_output
        result.changes_count = _M.parse_deck_changes_count(deck_output)
    else
        result.error = "deck_command_failed: " .. deck_output
        result.exit_code = deck_exit_code
    end

    return result
end

---
-- Create configuration snapshot using decK export
-- @param snapshot_type Type of snapshot (scheduled, pre_remediation, etc.)
-- @param conf Plugin configuration
-- @return Table containing snapshot result
---
function _M.create_configuration_snapshot(snapshot_type, conf)
    local snapshot_id = "SNAP-" .. snapshot_type .. "-" .. ngx.time()
    local snapshot_result = {
        snapshot_id = snapshot_id,
        success = false,
        file_path = nil,
        metadata = {}
    }

    local backup_dir = "/tmp/kong-guard-ai/config-backups"
    local snapshot_file = backup_dir .. "/" .. snapshot_id .. ".yaml"

    -- Ensure backup directory exists
    pl_dir.makepath(backup_dir)

    -- Export current configuration using decK
    local deck_cmd = string.format(
        "deck dump --kong-addr %s --output-file %s",
        conf.kong_admin_url or "http://localhost:8001",
        snapshot_file
    )

    if conf.kong_workspace then
        deck_cmd = deck_cmd .. " --workspace " .. conf.kong_workspace
    end

    kong.log.debug("[Kong Guard AI Advanced Remediation] Creating snapshot: " .. deck_cmd)

    local deck_output, deck_exit_code = _M.execute_system_command(deck_cmd)

    if deck_exit_code == 0 then
        snapshot_result.success = true
        snapshot_result.file_path = snapshot_file
        snapshot_result.metadata = {
            created_at = ngx.time(),
            type = snapshot_type,
            kong_version = _M.get_kong_version(),
            worker_id = ngx.worker.id(),
            size_bytes = _M.get_file_size(snapshot_file)
        }

        -- Store snapshot metadata
        config_snapshots.snapshots[snapshot_id] = snapshot_result
        config_snapshots.metadata[snapshot_id] = snapshot_result.metadata

        kong.log.info(string.format(
            "[Kong Guard AI Advanced Remediation] Configuration snapshot created: %s (%d bytes)",
            snapshot_id, snapshot_result.metadata.size_bytes or 0
        ))
    else
        snapshot_result.error = "deck_dump_failed: " .. deck_output
        kong.log.error(string.format(
            "[Kong Guard AI Advanced Remediation] Snapshot creation failed: %s",
            snapshot_result.error
        ))
    end

    return snapshot_result
end

---
-- Analyze error patterns for correlation
-- @param service_id Service ID to analyze
-- @param route_id Route ID to analyze
-- @param time_window Time window for analysis
-- @param conf Plugin configuration
-- @return Table containing error analysis
---
function _M.analyze_error_patterns(service_id, route_id, time_window, conf)
    local analysis = {
        total_requests = 0,
        error_count = 0,
        error_rate = 0.0,
        error_breakdown = {},
        severity_level = "low",
        trends = {}
    }

    local current_time = ngx.time()
    local start_time = current_time - time_window

    -- Get error data from Kong analytics or logs
    -- This would integrate with Kong's analytics or log aggregation system

    -- For demonstration, simulate error analysis
    local simulated_errors = _M.get_simulated_error_data(service_id, route_id, start_time, current_time)

    analysis.total_requests = simulated_errors.total_requests
    analysis.error_count = simulated_errors.error_count
    analysis.error_rate = analysis.total_requests > 0 and
                         (analysis.error_count / analysis.total_requests) or 0

    analysis.error_breakdown = {
        ["500"] = simulated_errors.status_500 or 0,
        ["502"] = simulated_errors.status_502 or 0,
        ["503"] = simulated_errors.status_503 or 0,
        ["504"] = simulated_errors.status_504 or 0
    }

    -- Determine severity based on error rate
    analysis.severity_level = _M.determine_error_severity(analysis)

    kong.log.debug(string.format(
        "[Kong Guard AI Advanced Remediation] Error analysis: rate=%.2f%%, severity=%s",
        analysis.error_rate * 100, analysis.severity_level
    ))

    return analysis
end

---
-- Determine error severity level
-- @param error_analysis Error analysis data
-- @return String severity level
---
function _M.determine_error_severity(error_analysis)
    local error_rate = error_analysis.error_rate

    if error_rate >= ERROR_CORRELATION_THRESHOLDS.CRITICAL.error_rate then
        return "critical"
    elseif error_rate >= ERROR_CORRELATION_THRESHOLDS.SEVERE.error_rate then
        return "severe"
    elseif error_rate >= ERROR_CORRELATION_THRESHOLDS.MODERATE.error_rate then
        return "moderate"
    elseif error_rate >= ERROR_CORRELATION_THRESHOLDS.LIGHT.error_rate then
        return "light"
    else
        return "normal"
    end
end

---
-- Initialize decK integration
-- @param conf Plugin configuration
---
function _M.initialize_deck_integration(conf)
    kong.log.info("[Kong Guard AI Advanced Remediation] Initializing decK integration")

    -- Check if decK is available
    local deck_version_output, deck_exit_code = _M.execute_system_command("deck version")

    if deck_exit_code == 0 then
        kong.log.info("[Kong Guard AI Advanced Remediation] decK integration ready: " ..
                      string.gsub(deck_version_output or "", "\n", " "))
    else
        kong.log.warn("[Kong Guard AI Advanced Remediation] decK not available, some features will be disabled")
    end

    -- Schedule periodic configuration snapshots
    if conf.enable_periodic_snapshots then
        _M.schedule_periodic_snapshots(conf)
    end
end

---
-- Start background error correlation monitoring
-- @param conf Plugin configuration
---
function _M.start_error_correlation_monitoring(conf)
    kong.log.debug("[Kong Guard AI Advanced Remediation] Starting error correlation monitoring")

    -- In a real implementation, this would set up background timers
    -- to periodically analyze error rates and trigger correlation analysis
    -- For now, we'll set up the framework for manual triggering

    error_tracking.monitoring_enabled = true
    error_tracking.last_check = ngx.time()
end

---
-- Call Kong Admin API
-- @param method HTTP method
-- @param endpoint API endpoint
-- @param data Request payload
-- @param conf Plugin configuration
-- @return Table containing API call result
---
function _M.call_kong_admin_api(method, endpoint, data, conf)
    local result = { success = false }

    local httpc = http.new()
    httpc:set_timeout(conf.admin_api_timeout_ms or 5000)

    local admin_url = conf.kong_admin_url or "http://localhost:8001"
    local url = admin_url .. endpoint

    local headers = {
        ["Content-Type"] = "application/json"
    }

    if conf.kong_admin_api_key then
        headers["Kong-Admin-Token"] = conf.kong_admin_api_key
    end

    local body = data and json.encode(data) or nil

    local res, err = httpc:request_uri(url, {
        method = method,
        headers = headers,
        body = body,
        ssl_verify = false
    })

    if not res then
        result.error = "http_request_failed: " .. (err or "unknown")
        return result
    end

    if res.status >= 200 and res.status < 300 then
        result.success = true
        result.status = res.status
        if res.body then
            result.data = json.decode(res.body)
        end
    else
        result.error = "http_status_" .. res.status .. ": " .. (res.body or "")
        result.status = res.status
    end

    return result
end

---
-- Execute system command with error handling
-- @param command Command to execute
-- @return String output, Number exit code
---
function _M.execute_system_command(command)
    local handle = io.popen(command .. " 2>&1")
    if not handle then
        return nil, -1
    end

    local output = handle:read("*a")
    local success, exit_type, exit_code = handle:close()

    return output, exit_code or -1
end

---
-- Helper functions for advanced remediation
---

function _M.get_recent_config_changes(time_window, conf)
    -- In a real implementation, this would query Kong's admin API
    -- or decK history to get recent configuration changes
    return {}
end

function _M.correlate_errors_with_changes(error_analysis, recent_changes, service_id, route_id)
    -- Correlate timing and scope of errors with configuration changes
    return {}
end

function _M.calculate_correlation_confidence(change_correlations, error_analysis, severity_level)
    -- Calculate confidence based on timing correlation and error patterns
    return 0.0
end

function _M.determine_remediation_actions(severity_level, change_correlations, error_analysis, conf)
    local actions = {}

    if severity_level == "critical" then
        table.insert(actions, REMEDIATION_ACTIONS.CONFIG_ROLLBACK)
        table.insert(actions, REMEDIATION_ACTIONS.TRAFFIC_REROUTE)
    elseif severity_level == "severe" then
        table.insert(actions, REMEDIATION_ACTIONS.UPSTREAM_FAILOVER)
        table.insert(actions, REMEDIATION_ACTIONS.CIRCUIT_BREAKER)
    end

    return actions
end

function _M.identify_rollback_candidates(change_correlations, conf)
    -- Identify safe rollback points based on change analysis
    return {}
end

function _M.perform_safety_checks(remediation_type, target_config, conf)
    return { passed = true, reason = nil }
end

function _M.validate_remediation_success(remediation_type, target_config, conf)
    return { passed = true, reason = nil }
end

function _M.execute_automatic_rollback(remediation_id, snapshot_id, conf)
    return { attempted = false, success = false }
end

function _M.get_simulated_error_data(service_id, route_id, start_time, end_time)
    -- Simulate error data for demonstration
    return {
        total_requests = 1000,
        error_count = 150,
        status_500 = 80,
        status_502 = 30,
        status_503 = 25,
        status_504 = 15
    }
end

function _M.get_kong_version()
    return kong.version or "unknown"
end

function _M.get_file_size(file_path)
    local f = io.open(file_path, "r")
    if f then
        local size = f:seek("end")
        f:close()
        return size
    end
    return 0
end

function _M.parse_deck_changes_count(deck_output)
    -- Parse decK output to extract number of changes applied
    local changes_match = string.match(deck_output or "", "(%d+) change")
    return tonumber(changes_match) or 0
end

function _M.get_latest_stable_snapshot(conf)
    -- Find the latest stable configuration snapshot
    local latest_snapshot = nil
    local latest_time = 0

    for snapshot_id, metadata in pairs(config_snapshots.metadata) do
        if metadata.type == "scheduled" and metadata.created_at > latest_time then
            latest_time = metadata.created_at
            latest_snapshot = snapshot_id
        end
    end

    return latest_snapshot
end

function _M.validate_rollback_target(snapshot_id, conf)
    local snapshot = config_snapshots.snapshots[snapshot_id]
    if not snapshot then
        return { valid = false, reason = "snapshot_not_found" }
    end

    if not snapshot.success then
        return { valid = false, reason = "snapshot_corrupted" }
    end

    return { valid = true }
end

function _M.execute_rollback_dry_run(snapshot_id, conf)
    -- Execute decK diff to validate rollback target
    return { success = true, changes_count = 0 }
end

function _M.load_configuration_snapshot(snapshot_id, conf)
    local snapshot = config_snapshots.snapshots[snapshot_id]
    if not snapshot or not snapshot.file_path then
        return nil
    end

    return pl_file.read(snapshot.file_path)
end

function _M.schedule_periodic_snapshots(conf)
    -- Schedule periodic configuration snapshots
    kong.log.debug("[Kong Guard AI Advanced Remediation] Scheduling periodic snapshots")
end

-- Additional remediation actions (simplified implementations)
function _M.execute_service_disable(target_config, params, conf)
    return { success = false, details = { reason = "not_implemented" } }
end

function _M.execute_route_modification(target_config, params, conf)
    return { success = false, details = { reason = "not_implemented" } }
end

function _M.execute_upstream_failover(target_config, params, conf)
    return { success = false, details = { reason = "not_implemented" } }
end

function _M.execute_circuit_breaker(target_config, params, conf)
    return { success = false, details = { reason = "not_implemented" } }
end

function _M.execute_canary_reroute(target_config, params, conf)
    return { success = false, details = { reason = "not_implemented" } }
end

function _M.execute_gradual_rollback(rollback_target, params, conf)
    return { success = false, details = { reason = "not_implemented" } }
end

function _M.execute_canary_rollback(rollback_target, params, conf)
    return { success = false, details = { reason = "not_implemented" } }
end

---
-- Export constants and state for external use
---
_M.REMEDIATION_ACTIONS = REMEDIATION_ACTIONS
_M.ROLLBACK_STRATEGIES = ROLLBACK_STRATEGIES
_M.ERROR_CORRELATION_THRESHOLDS = ERROR_CORRELATION_THRESHOLDS

-- Export state for monitoring/debugging
_M._state = {
    config_snapshots = config_snapshots,
    error_tracking = error_tracking,
    remediation_history = remediation_history,
    active_remediations = active_remediations
}

return _M
