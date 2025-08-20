-- Kong Guard AI - Incident Management Module
-- PHASE 4: Comprehensive incident record system for blocked requests with forensic data
-- Handles incident creation, storage, correlation, enrichment, and lifecycle management

local kong = kong
local json = require "cjson.safe"

local _M = {}

-- Incident type constants
local INCIDENT_TYPES = {
    IP_BLACKLIST = "ip_blacklist",
    METHOD_DENIED = "method_denied", 
    PATH_BLOCKED = "path_blocked",
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded",
    PAYLOAD_INJECTION = "payload_injection",
    SQL_INJECTION = "sql_injection",
    XSS_ATTACK = "cross_site_scripting",
    PATH_TRAVERSAL = "path_traversal",
    BOT_DETECTION = "bot_detection",
    ANOMALOUS_BEHAVIOR = "anomalous_behavior",
    CREDENTIAL_STUFFING = "credential_stuffing",
    DDOS_ATTACK = "distributed_denial_of_service",
    API_ABUSE = "api_abuse",
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
}

-- Incident scope levels
local INCIDENT_SCOPES = {
    REQUEST = "request",           -- Single request incident
    SESSION = "session",           -- Multiple requests from same session
    IP_ADDRESS = "ip_address",     -- Multiple requests from same IP
    GLOBAL = "global"              -- System-wide threat pattern
}

-- Enforcement decisions
local ENFORCEMENT_DECISIONS = {
    BLOCK = "block",
    RATE_LIMIT = "rate_limit", 
    MONITOR = "monitor",
    ESCALATE = "escalate",
    ALLOW_WITH_WARNING = "allow_with_warning"
}

-- Severity levels for incidents
local SEVERITY_LEVELS = {
    LOW = "low",
    MEDIUM = "medium", 
    HIGH = "high",
    CRITICAL = "critical"
}

-- Storage for incident records (worker-level)
local incident_storage = {}
local incident_correlations = {}
local incident_counter = 0

---
-- Initialize incident management system
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Incident Manager] Initializing incident management system")
    
    -- Initialize storage structures
    incident_storage.records = {}
    incident_storage.active_incidents = {}
    incident_storage.resolved_incidents = {}
    incident_storage.archived_incidents = {}
    
    -- Initialize correlation tracking
    incident_correlations.by_ip = {}
    incident_correlations.by_pattern = {}
    incident_correlations.by_user_agent = {}
    incident_correlations.by_path = {}
    
    -- Initialize counters
    incident_counter = 0
    
    kong.log.info("[Kong Guard AI Incident Manager] Incident management system initialized")
end

---
-- Create a new incident record from threat detection
-- @param threat_result Threat analysis result from detector
-- @param request_context Request context data
-- @param enforcement_result Enforcement action result
-- @param conf Plugin configuration
-- @return Table containing incident record
---
function _M.create_incident(threat_result, request_context, enforcement_result, conf)
    incident_counter = incident_counter + 1
    
    local incident_id = string.format("INC-%d-%d", ngx.time(), incident_counter)
    local correlation_id = request_context.correlation_id or ngx.var.request_id or incident_id
    
    -- Determine incident type based on threat analysis
    local incident_type = _M.determine_incident_type(threat_result)
    
    -- Determine incident scope based on threat patterns
    local incident_scope = _M.determine_incident_scope(threat_result, request_context)
    
    -- Build comprehensive evidence package
    local evidence = _M.build_evidence_package(threat_result, request_context, enforcement_result, conf)
    
    -- Determine enforcement decision
    local enforcement_decision = _M.map_enforcement_decision(enforcement_result.action_type, threat_result.recommended_action)
    
    -- Calculate severity level
    local severity_level = _M.calculate_severity(threat_result, incident_scope, evidence)
    
    -- Create incident record with all required fields
    local incident = {
        -- Core identification
        incident_id = incident_id,
        correlation_id = correlation_id,
        timestamp = ngx.time(),
        created_at = ngx.utctime(),
        
        -- Classification
        type = incident_type,
        scope = incident_scope,
        severity_level = severity_level,
        
        -- Evidence package
        evidence = evidence,
        
        -- Decision and action
        decision = enforcement_decision,
        enforcement_result = enforcement_result,
        
        -- Request forensics
        request_forensics = {
            method = request_context.method,
            path = request_context.path,
            query_string = kong.request.get_raw_query(),
            headers = request_context.headers,
            body_snippet = _M.get_safe_body_snippet(conf),
            user_agent = request_context.headers["user-agent"],
            referer = request_context.headers["referer"],
            content_type = request_context.headers["content-type"],
            content_length = request_context.headers["content-length"]
        },
        
        -- Network forensics
        network_forensics = {
            source_ip = request_context.client_ip,
            x_forwarded_for = request_context.headers["x-forwarded-for"],
            x_real_ip = request_context.headers["x-real-ip"],
            via = request_context.headers["via"],
            port = ngx.var.remote_port or "unknown",
            protocol = ngx.var.server_protocol or "HTTP/1.1"
        },
        
        -- Kong context
        kong_context = {
            service_id = request_context.service_id,
            route_id = request_context.route_id, 
            consumer_id = request_context.consumer_id,
            node_id = kong.node.get_id(),
            worker_pid = ngx.worker.pid(),
            request_id = ngx.var.request_id
        },
        
        -- Threat analysis details
        threat_analysis = {
            threat_level = threat_result.threat_level,
            threat_type = threat_result.threat_type,
            confidence = threat_result.confidence,
            patterns_matched = threat_result.details.patterns_matched or {},
            ai_analysis = threat_result.details.ai_analysis,
            behavioral_indicators = threat_result.details
        },
        
        -- Lifecycle tracking
        lifecycle = {
            status = "active",
            created_by = "kong-guard-ai-detector",
            assigned_to = nil,
            last_updated = ngx.time(),
            resolution_notes = nil,
            archived_at = nil
        },
        
        -- Correlation and aggregation
        correlation_data = {
            related_incidents = {},
            attack_pattern = nil,
            campaign_id = nil,
            repeat_offender = _M.is_repeat_offender(request_context.client_ip),
            incident_count_for_ip = _M.get_incident_count_for_ip(request_context.client_ip)
        },
        
        -- Enrichment data (to be populated by enrichment process)
        enrichment = {
            geo_location = nil,
            ip_reputation = nil,
            threat_intelligence = nil,
            asn_info = nil,
            enriched_at = nil
        },
        
        -- Export metadata
        export_metadata = {
            exported_to_siem = false,
            siem_event_id = nil,
            exported_formats = {},
            last_export_attempt = nil
        }
    }
    
    -- Store incident record
    incident_storage.records[incident_id] = incident
    incident_storage.active_incidents[incident_id] = incident
    
    -- Add to correlation indexes
    _M.add_to_correlation_indexes(incident)
    
    -- Perform automatic correlation with existing incidents
    _M.correlate_incident(incident)
    
    -- Log incident creation
    kong.log.warn(string.format(
        "[Kong Guard AI Incident Manager] Created incident %s: %s (%s severity) for IP %s",
        incident_id,
        incident_type, 
        severity_level,
        request_context.client_ip
    ))
    
    return incident
end

---
-- Determine incident type based on threat analysis
-- @param threat_result Threat analysis result
-- @return String incident type
---
function _M.determine_incident_type(threat_result)
    local threat_type = threat_result.threat_type
    local details = threat_result.details
    
    -- Map threat types to incident types
    local type_mapping = {
        ["sql_injection"] = INCIDENT_TYPES.SQL_INJECTION,
        ["cross_site_scripting"] = INCIDENT_TYPES.XSS_ATTACK,
        ["ip_reputation"] = INCIDENT_TYPES.IP_BLACKLIST,
        ["rate_limit_violation"] = INCIDENT_TYPES.RATE_LIMIT_EXCEEDED,
        ["payload_injection"] = INCIDENT_TYPES.PAYLOAD_INJECTION,
        ["anomalous_behavior"] = INCIDENT_TYPES.ANOMALOUS_BEHAVIOR,
        ["distributed_denial_of_service"] = INCIDENT_TYPES.DDOS_ATTACK,
        ["api_abuse"] = INCIDENT_TYPES.API_ABUSE,
        ["credential_stuffing"] = INCIDENT_TYPES.CREDENTIAL_STUFFING
    }
    
    local mapped_type = type_mapping[threat_type]
    if mapped_type then
        return mapped_type
    end
    
    -- Additional logic for specific detection patterns
    if details.blacklist_match then
        return INCIDENT_TYPES.IP_BLACKLIST
    elseif details.unusual_method then
        return INCIDENT_TYPES.METHOD_DENIED
    elseif details.path_traversal then
        return INCIDENT_TYPES.PATH_TRAVERSAL
    elseif details.suspicious_user_agent then
        return INCIDENT_TYPES.SUSPICIOUS_USER_AGENT
    elseif details.path_blocked then
        return INCIDENT_TYPES.PATH_BLOCKED
    else
        -- Default to anomalous behavior
        return INCIDENT_TYPES.ANOMALOUS_BEHAVIOR
    end
end

---
-- Determine incident scope based on threat patterns
-- @param threat_result Threat analysis result
-- @param request_context Request context
-- @return String incident scope
---
function _M.determine_incident_scope(threat_result, request_context)
    local client_ip = request_context.client_ip
    
    -- Check if this is part of a broader attack pattern
    local ip_incident_count = _M.get_incident_count_for_ip(client_ip)
    
    if threat_result.threat_type == "distributed_denial_of_service" then
        return INCIDENT_SCOPES.GLOBAL
    elseif ip_incident_count >= 5 then
        return INCIDENT_SCOPES.IP_ADDRESS
    elseif _M.has_session_indicators(request_context) then
        return INCIDENT_SCOPES.SESSION
    else
        return INCIDENT_SCOPES.REQUEST
    end
end

---
-- Build comprehensive evidence package
-- @param threat_result Threat analysis result
-- @param request_context Request context
-- @param enforcement_result Enforcement action result
-- @param conf Plugin configuration
-- @return Table containing evidence
---
function _M.build_evidence_package(threat_result, request_context, enforcement_result, conf)
    local evidence = {
        matched_patterns = {},
        source_ip = request_context.client_ip,
        request_details = {
            method = request_context.method,
            path = request_context.path,
            timestamp = ngx.time(),
            size_bytes = tonumber(ngx.var.request_length) or 0
        },
        headers = {},
        detection_details = {},
        enforcement_action = enforcement_result.action_type,
        confidence_score = threat_result.confidence
    }
    
    -- Extract matched patterns from threat result
    if threat_result.details.patterns_matched then
        for _, pattern_match in ipairs(threat_result.details.patterns_matched) do
            table.insert(evidence.matched_patterns, {
                pattern = pattern_match.pattern_index,
                match = pattern_match.match,
                context = pattern_match.context
            })
        end
    end
    
    -- Sanitize and store relevant headers
    local security_relevant_headers = {
        "user-agent", "referer", "x-forwarded-for", "x-real-ip", 
        "authorization", "cookie", "content-type", "accept", "origin"
    }
    
    for _, header_name in ipairs(security_relevant_headers) do
        local header_value = request_context.headers[header_name]
        if header_value then
            evidence.headers[header_name] = _M.sanitize_header_value(header_value)
        end
    end
    
    -- Add specific detection details based on threat type
    if threat_result.details.blacklist_match then
        evidence.detection_details.blacklist_rule = threat_result.details.blacklist_match
    end
    
    if threat_result.details.request_count then
        evidence.detection_details.request_rate = {
            count = threat_result.details.request_count,
            window_seconds = threat_result.details.window_seconds
        }
    end
    
    if threat_result.details.suspicious_user_agent then
        evidence.detection_details.user_agent_pattern = threat_result.details.suspicious_user_agent
    end
    
    return evidence
end

---
-- Calculate incident severity based on multiple factors
-- @param threat_result Threat analysis result
-- @param incident_scope Incident scope
-- @param evidence Evidence package
-- @return String severity level
---
function _M.calculate_severity(threat_result, incident_scope, evidence)
    local base_severity_score = 0
    
    -- Base score from threat level
    base_severity_score = threat_result.threat_level or 0
    
    -- Scope multiplier
    local scope_multipliers = {
        [INCIDENT_SCOPES.REQUEST] = 1.0,
        [INCIDENT_SCOPES.SESSION] = 1.2,
        [INCIDENT_SCOPES.IP_ADDRESS] = 1.5,
        [INCIDENT_SCOPES.GLOBAL] = 2.0
    }
    
    base_severity_score = base_severity_score * (scope_multipliers[incident_scope] or 1.0)
    
    -- Confidence multiplier
    base_severity_score = base_severity_score * (threat_result.confidence or 0.5)
    
    -- Evidence quality bonus
    local evidence_bonus = 0
    if evidence.matched_patterns and #evidence.matched_patterns > 0 then
        evidence_bonus = evidence_bonus + (#evidence.matched_patterns * 0.5)
    end
    
    local final_score = base_severity_score + evidence_bonus
    
    -- Map score to severity levels
    if final_score >= 8.0 then
        return SEVERITY_LEVELS.CRITICAL
    elseif final_score >= 6.0 then
        return SEVERITY_LEVELS.HIGH
    elseif final_score >= 4.0 then
        return SEVERITY_LEVELS.MEDIUM
    else
        return SEVERITY_LEVELS.LOW
    end
end

---
-- Map enforcement action to decision
-- @param action_type Enforcement action type
-- @param recommended_action Recommended action from detector
-- @return String enforcement decision
---
function _M.map_enforcement_decision(action_type, recommended_action)
    local decision_mapping = {
        ["block_request"] = ENFORCEMENT_DECISIONS.BLOCK,
        ["rate_limit"] = ENFORCEMENT_DECISIONS.RATE_LIMIT,
        ["monitor"] = ENFORCEMENT_DECISIONS.MONITOR,
        ["escalate"] = ENFORCEMENT_DECISIONS.ESCALATE
    }
    
    return decision_mapping[action_type] or decision_mapping[recommended_action] or ENFORCEMENT_DECISIONS.MONITOR
end

---
-- Add incident to correlation indexes for fast lookup
-- @param incident Incident record
---
function _M.add_to_correlation_indexes(incident)
    local client_ip = incident.network_forensics.source_ip
    local user_agent = incident.request_forensics.user_agent
    local path = incident.request_forensics.path
    
    -- IP-based correlation
    if not incident_correlations.by_ip[client_ip] then
        incident_correlations.by_ip[client_ip] = {}
    end
    table.insert(incident_correlations.by_ip[client_ip], incident.incident_id)
    
    -- User-Agent based correlation
    if user_agent then
        local ua_hash = ngx.md5(user_agent)
        if not incident_correlations.by_user_agent[ua_hash] then
            incident_correlations.by_user_agent[ua_hash] = {}
        end
        table.insert(incident_correlations.by_user_agent[ua_hash], incident.incident_id)
    end
    
    -- Path-based correlation
    if path then
        if not incident_correlations.by_path[path] then
            incident_correlations.by_path[path] = {}
        end
        table.insert(incident_correlations.by_path[path], incident.incident_id)
    end
    
    -- Pattern-based correlation
    for _, pattern_match in ipairs(incident.evidence.matched_patterns) do
        local pattern_key = "pattern_" .. pattern_match.pattern
        if not incident_correlations.by_pattern[pattern_key] then
            incident_correlations.by_pattern[pattern_key] = {}
        end
        table.insert(incident_correlations.by_pattern[pattern_key], incident.incident_id)
    end
end

---
-- Correlate incident with existing incidents to identify attack patterns
-- @param incident Current incident to correlate
---
function _M.correlate_incident(incident)
    local correlations = {}
    local client_ip = incident.network_forensics.source_ip
    
    -- Find related incidents by IP (within last hour)
    local ip_incidents = incident_correlations.by_ip[client_ip] or {}
    local recent_threshold = ngx.time() - 3600
    
    for _, related_id in ipairs(ip_incidents) do
        if related_id ~= incident.incident_id then
            local related_incident = incident_storage.records[related_id]
            if related_incident and related_incident.timestamp >= recent_threshold then
                table.insert(correlations, {
                    incident_id = related_id,
                    correlation_type = "same_ip",
                    correlation_strength = 0.8
                })
            end
        end
    end
    
    -- Find pattern-based correlations
    for _, pattern_match in ipairs(incident.evidence.matched_patterns) do
        local pattern_key = "pattern_" .. pattern_match.pattern
        local pattern_incidents = incident_correlations.by_pattern[pattern_key] or {}
        
        for _, related_id in ipairs(pattern_incidents) do
            if related_id ~= incident.incident_id then
                local related_incident = incident_storage.records[related_id]
                if related_incident and related_incident.timestamp >= recent_threshold then
                    table.insert(correlations, {
                        incident_id = related_id,
                        correlation_type = "same_pattern",
                        correlation_strength = 0.6
                    })
                end
            end
        end
    end
    
    -- Update incident with correlations
    incident.correlation_data.related_incidents = correlations
    
    -- Detect attack campaigns
    if #correlations >= 3 then
        local campaign_id = "CAMP-" .. ngx.time() .. "-" .. string.sub(ngx.md5(client_ip), 1, 8)
        incident.correlation_data.campaign_id = campaign_id
        
        kong.log.warn(string.format(
            "[Kong Guard AI Incident Manager] Attack campaign detected: %s (IP: %s, %d related incidents)",
            campaign_id,
            client_ip,
            #correlations
        ))
    end
end

---
-- Update incident status and lifecycle
-- @param incident_id Incident ID
-- @param new_status New status (active, investigating, resolved, archived)
-- @param notes Optional resolution notes
-- @param assigned_to Optional assignee
-- @return Boolean success
---
function _M.update_incident_status(incident_id, new_status, notes, assigned_to)
    local incident = incident_storage.records[incident_id]
    if not incident then
        kong.log.error("[Kong Guard AI Incident Manager] Incident not found: " .. incident_id)
        return false
    end
    
    local old_status = incident.lifecycle.status
    
    -- Update lifecycle information
    incident.lifecycle.status = new_status
    incident.lifecycle.last_updated = ngx.time()
    
    if notes then
        incident.lifecycle.resolution_notes = notes
    end
    
    if assigned_to then
        incident.lifecycle.assigned_to = assigned_to
    end
    
    -- Move between storage buckets based on status
    if new_status == "resolved" then
        incident_storage.active_incidents[incident_id] = nil
        incident_storage.resolved_incidents[incident_id] = incident
        incident.lifecycle.resolved_at = ngx.time()
    elseif new_status == "archived" then
        incident_storage.active_incidents[incident_id] = nil
        incident_storage.resolved_incidents[incident_id] = nil 
        incident_storage.archived_incidents[incident_id] = incident
        incident.lifecycle.archived_at = ngx.time()
    elseif old_status ~= "active" and new_status == "active" then
        incident_storage.resolved_incidents[incident_id] = nil
        incident_storage.archived_incidents[incident_id] = nil
        incident_storage.active_incidents[incident_id] = incident
    end
    
    kong.log.info(string.format(
        "[Kong Guard AI Incident Manager] Updated incident %s status: %s -> %s",
        incident_id,
        old_status,
        new_status
    ))
    
    return true
end

---
-- Enrich incident with threat intelligence data
-- @param incident_id Incident ID
-- @param enrichment_data Enrichment data from external sources
-- @return Boolean success
---
function _M.enrich_incident(incident_id, enrichment_data)
    local incident = incident_storage.records[incident_id]
    if not incident then
        return false
    end
    
    -- Merge enrichment data
    for key, value in pairs(enrichment_data) do
        incident.enrichment[key] = value
    end
    
    incident.enrichment.enriched_at = ngx.time()
    
    kong.log.debug(string.format(
        "[Kong Guard AI Incident Manager] Enriched incident %s with external data",
        incident_id
    ))
    
    return true
end

---
-- Export incident in specified format
-- @param incident_id Incident ID
-- @param export_format Format (json, cef, stix)
-- @return String exported data or nil on error
---
function _M.export_incident(incident_id, export_format)
    local incident = incident_storage.records[incident_id]
    if not incident then
        return nil
    end
    
    local exported_data
    
    if export_format == "json" then
        exported_data = _M.export_to_json(incident)
    elseif export_format == "cef" then
        exported_data = _M.export_to_cef(incident)
    elseif export_format == "stix" then
        exported_data = _M.export_to_stix(incident)
    else
        kong.log.error("[Kong Guard AI Incident Manager] Unsupported export format: " .. export_format)
        return nil
    end
    
    -- Update export metadata
    if exported_data then
        incident.export_metadata.last_export_attempt = ngx.time()
        table.insert(incident.export_metadata.exported_formats, export_format)
    end
    
    return exported_data
end

---
-- Export incident as JSON
-- @param incident Incident record
-- @return String JSON data
---
function _M.export_to_json(incident)
    return json.encode(incident)
end

---
-- Export incident as CEF (Common Event Format)
-- @param incident Incident record
-- @return String CEF data
---
function _M.export_to_cef(incident)
    local cef_header = string.format(
        "CEF:0|Kong|Kong Guard AI|1.0|%s|%s|%s|",
        incident.type,
        "Security Incident",
        _M.severity_to_cef_score(incident.severity_level)
    )
    
    local cef_extensions = {
        string.format("src=%s", incident.network_forensics.source_ip),
        string.format("suser=%s", incident.kong_context.consumer_id or "anonymous"),
        string.format("requestMethod=%s", incident.request_forensics.method),
        string.format("requestUrl=%s", incident.request_forensics.path),
        string.format("requestClientApplication=%s", incident.request_forensics.user_agent or "unknown"),
        string.format("act=%s", incident.decision),
        string.format("cat=%s", incident.type),
        string.format("cs1=%s", incident.incident_id),
        string.format("cs1Label=IncidentID"),
        string.format("cn1=%d", incident.threat_analysis.threat_level),
        string.format("cn1Label=ThreatLevel")
    }
    
    return cef_header .. table.concat(cef_extensions, " ")
end

---
-- Export incident as STIX (Structured Threat Information eXpression)
-- @param incident Incident record
-- @return String STIX JSON data
---
function _M.export_to_stix(incident)
    local stix_object = {
        type = "indicator",
        id = "indicator--" .. string.gsub(incident.incident_id, "-", ""),
        created = incident.created_at,
        modified = incident.created_at,
        labels = {"malicious-activity"},
        pattern = string.format("[ipv4-addr:value = '%s']", incident.network_forensics.source_ip),
        threat_types = {incident.type},
        kill_chain_phases = {
            {
                kill_chain_name = "mitre-attack",
                phase_name = _M.map_incident_to_mitre_phase(incident.type)
            }
        }
    }
    
    return json.encode(stix_object)
end

---
-- Helper functions
---

function _M.get_safe_body_snippet(conf)
    local max_size = conf.incident_body_snippet_size or 500
    local body = kong.request.get_raw_body()
    
    if not body then
        return nil
    end
    
    if #body > max_size then
        return string.sub(body, 1, max_size) .. "... (truncated)"
    end
    
    return body
end

function _M.sanitize_header_value(value)
    -- Remove sensitive data patterns
    local sanitized = value
    
    -- Mask potential auth tokens
    sanitized = string.gsub(sanitized, "(Bearer%s+)[%w%+/=]+", "%1[REDACTED]")
    sanitized = string.gsub(sanitized, "(token%s*=%s*)[%w%+/=]+", "%1[REDACTED]")
    
    -- Truncate if too long
    if #sanitized > 200 then
        sanitized = string.sub(sanitized, 1, 200) .. "... (truncated)"
    end
    
    return sanitized
end

function _M.is_repeat_offender(client_ip)
    local ip_incidents = incident_correlations.by_ip[client_ip] or {}
    return #ip_incidents > 1
end

function _M.get_incident_count_for_ip(client_ip)
    local ip_incidents = incident_correlations.by_ip[client_ip] or {}
    return #ip_incidents
end

function _M.has_session_indicators(request_context)
    -- Check for session cookies or tokens
    local cookie_header = request_context.headers["cookie"]
    return cookie_header and (cookie_header:find("session") or cookie_header:find("auth"))
end

function _M.severity_to_cef_score(severity)
    local scores = {
        [SEVERITY_LEVELS.LOW] = "3",
        [SEVERITY_LEVELS.MEDIUM] = "5", 
        [SEVERITY_LEVELS.HIGH] = "8",
        [SEVERITY_LEVELS.CRITICAL] = "10"
    }
    return scores[severity] or "5"
end

function _M.map_incident_to_mitre_phase(incident_type)
    local phase_mapping = {
        [INCIDENT_TYPES.SQL_INJECTION] = "exploitation",
        [INCIDENT_TYPES.XSS_ATTACK] = "exploitation",
        [INCIDENT_TYPES.PATH_TRAVERSAL] = "discovery",
        [INCIDENT_TYPES.RATE_LIMIT_EXCEEDED] = "impact",
        [INCIDENT_TYPES.DDOS_ATTACK] = "impact",
        [INCIDENT_TYPES.CREDENTIAL_STUFFING] = "credential-access"
    }
    return phase_mapping[incident_type] or "initial-access"
end

---
-- Get incident statistics
-- @return Table containing incident metrics
---
function _M.get_incident_statistics()
    local stats = {
        total_incidents = #incident_storage.records,
        active_incidents = 0,
        resolved_incidents = 0,
        archived_incidents = 0,
        incidents_by_type = {},
        incidents_by_severity = {},
        top_attacking_ips = {},
        incident_trends = {}
    }
    
    -- Count by status
    for _ in pairs(incident_storage.active_incidents) do
        stats.active_incidents = stats.active_incidents + 1
    end
    
    for _ in pairs(incident_storage.resolved_incidents) do
        stats.resolved_incidents = stats.resolved_incidents + 1
    end
    
    for _ in pairs(incident_storage.archived_incidents) do
        stats.archived_incidents = stats.archived_incidents + 1
    end
    
    -- Count by type and severity
    for _, incident in pairs(incident_storage.records) do
        stats.incidents_by_type[incident.type] = (stats.incidents_by_type[incident.type] or 0) + 1
        stats.incidents_by_severity[incident.severity_level] = (stats.incidents_by_severity[incident.severity_level] or 0) + 1
    end
    
    return stats
end

---
-- Clean up old incident records
-- @param conf Plugin configuration
---
function _M.cleanup_incidents(conf)
    local max_age = conf.incident_retention_days or 30
    local cleanup_threshold = ngx.time() - (max_age * 24 * 3600)
    
    local cleaned_count = 0
    
    -- Clean archived incidents older than retention period
    for incident_id, incident in pairs(incident_storage.archived_incidents) do
        if incident.timestamp < cleanup_threshold then
            incident_storage.archived_incidents[incident_id] = nil
            incident_storage.records[incident_id] = nil
            cleaned_count = cleaned_count + 1
        end
    end
    
    -- Clean correlation indexes
    for ip, incident_list in pairs(incident_correlations.by_ip) do
        local cleaned_list = {}
        for _, incident_id in ipairs(incident_list) do
            if incident_storage.records[incident_id] then
                table.insert(cleaned_list, incident_id)
            end
        end
        incident_correlations.by_ip[ip] = cleaned_list
    end
    
    if cleaned_count > 0 then
        kong.log.info(string.format(
            "[Kong Guard AI Incident Manager] Cleaned up %d old incident records",
            cleaned_count
        ))
    end
end

---
-- Export constants for external use
---
_M.INCIDENT_TYPES = INCIDENT_TYPES
_M.INCIDENT_SCOPES = INCIDENT_SCOPES
_M.ENFORCEMENT_DECISIONS = ENFORCEMENT_DECISIONS
_M.SEVERITY_LEVELS = SEVERITY_LEVELS

return _M