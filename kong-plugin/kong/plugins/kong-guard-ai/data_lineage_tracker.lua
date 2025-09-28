--- Data Lineage Tracking Module for Kong Guard AI
-- Tracks data flow, transformations, and relationships throughout the system

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local uuid = require("resty.uuid")

-- Lineage event types
local LINEAGE_EVENTS = {
    DATA_INGESTION = "data_ingestion",
    DATA_TRANSFORMATION = "data_transformation",
    DATA_ACCESS = "data_access",
    DATA_TRANSFER = "data_transfer",
    DATA_DELETION = "data_deletion",
    DATA_ANONYMIZATION = "data_anonymization",
    DATA_EXPORT = "data_export"
}

-- Data flow types
local DATA_FLOW_TYPES = {
    REQUEST = "request",
    RESPONSE = "response",
    INTERNAL = "internal",
    EXTERNAL = "external"
}

--- Create a new data lineage tracker instance
function _M.new(config)
    local self = {
        config = config or {},
        lineage_store = {}, -- In-memory storage, in production use database
        data_relationships = {},
        transformation_history = {},
        access_patterns = {},
        retention_days = config.retention_days or 90,
        enable_detailed_tracking = config.enable_detailed_tracking or false
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the lineage tracker
function _M:init()
    -- Set up cleanup of old lineage data
    local ok, err = ngx.timer.every(3600, function() -- Every hour
        self:_cleanup_old_lineage_data()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize lineage cleanup: ", err)
    end

    kong.log.info("[kong-guard-ai] Data lineage tracker initialized")
end

--- Track data lineage event
function _M:track_event(event_type, data_id, metadata, context)
    if not event_type or not data_id then
        return false, "Event type and data ID are required"
    end

    local event_id = uuid.generate()
    local timestamp = ngx.now()

    local lineage_event = {
        event_id = event_id,
        event_type = event_type,
        data_id = data_id,
        timestamp = timestamp,
        metadata = metadata or {},
        context = context or {},
        data_flow = self:_determine_data_flow(context),
        source_system = context.source_system or "kong-guard-ai",
        target_system = context.target_system,
        user_id = context.user_id,
        session_id = context.session_id,
        request_id = context.request_id,
        ip_address = context.ip_address,
        user_agent = context.user_agent
    }

    -- Add detailed tracking if enabled
    if self.enable_detailed_tracking then
        lineage_event.detailed_metadata = self:_collect_detailed_metadata(data_id, context)
    end

    -- Store the event
    if not self.lineage_store[data_id] then
        self.lineage_store[data_id] = {}
    end
    table.insert(self.lineage_store[data_id], lineage_event)

    -- Update data relationships
    self:_update_data_relationships(data_id, lineage_event)

    -- Track transformation history if applicable
    if event_type == LINEAGE_EVENTS.DATA_TRANSFORMATION then
        self:_track_transformation(data_id, lineage_event)
    end

    -- Track access patterns
    if event_type == LINEAGE_EVENTS.DATA_ACCESS then
        self:_track_access_pattern(data_id, lineage_event)
    end

    kong.log.debug("[kong-guard-ai] Lineage event tracked: ", {
        event_id = event_id,
        event_type = event_type,
        data_id = data_id
    })

    return true, lineage_event
end

--- Track data ingestion
function _M:track_data_ingestion(data_id, source, metadata, context)
    local ingestion_metadata = {
        source = source,
        data_size = metadata.data_size,
        data_type = metadata.data_type,
        ingestion_method = metadata.ingestion_method or "api",
        source_format = metadata.source_format,
        target_format = metadata.target_format
    }

    return self:track_event(LINEAGE_EVENTS.DATA_INGESTION, data_id, ingestion_metadata, context)
end

--- Track data transformation
function _M:track_data_transformation(data_id, transformation_type, before_state, after_state, context)
    local transformation_metadata = {
        transformation_type = transformation_type,
        before_state = self:_summarize_data_state(before_state),
        after_state = self:_summarize_data_state(after_state),
        transformation_rules = context.transformation_rules,
        processing_time_ms = context.processing_time_ms
    }

    return self:track_event(LINEAGE_EVENTS.DATA_TRANSFORMATION, data_id, transformation_metadata, context)
end

--- Track data access
function _M:track_data_access(data_id, access_type, purpose, context)
    local access_metadata = {
        access_type = access_type,
        purpose = purpose,
        access_method = context.access_method or "read",
        fields_accessed = context.fields_accessed,
        records_returned = context.records_returned,
        query_pattern = context.query_pattern
    }

    return self:track_event(LINEAGE_EVENTS.DATA_ACCESS, data_id, access_metadata, context)
end

--- Track data transfer
function _M:track_data_transfer(data_id, destination, transfer_method, context)
    local transfer_metadata = {
        destination = destination,
        transfer_method = transfer_method,
        destination_system = context.destination_system,
        encryption_used = context.encryption_used,
        transfer_size = context.transfer_size,
        transfer_time_ms = context.transfer_time_ms
    }

    return self:track_event(LINEAGE_EVENTS.DATA_TRANSFER, data_id, transfer_metadata, context)
end

--- Track data deletion
function _M:track_data_deletion(data_id, deletion_reason, context)
    local deletion_metadata = {
        deletion_reason = deletion_reason,
        deletion_method = context.deletion_method or "soft_delete",
        backup_created = context.backup_created,
        deletion_scope = context.deletion_scope or "single_record"
    }

    return self:track_event(LINEAGE_EVENTS.DATA_DELETION, data_id, deletion_metadata, context)
end

--- Track data anonymization
function _M:track_data_anonymization(data_id, anonymization_method, fields_anonymized, context)
    local anonymization_metadata = {
        anonymization_method = anonymization_method,
        fields_anonymized = fields_anonymized,
        anonymization_level = context.anonymization_level,
        effectiveness_score = context.effectiveness_score
    }

    return self:track_event(LINEAGE_EVENTS.DATA_ANONYMIZATION, data_id, anonymization_metadata, context)
end

--- Track data export
function _M:track_data_export(data_id, export_format, destination, context)
    local export_metadata = {
        export_format = export_format,
        destination = destination,
        records_exported = context.records_exported,
        export_scope = context.export_scope,
        compression_used = context.compression_used
    }

    return self:track_event(LINEAGE_EVENTS.DATA_EXPORT, data_id, export_metadata, context)
end

--- Get data lineage
function _M:get_data_lineage(data_id, options)
    options = options or {}

    local lineage_data = self.lineage_store[data_id]
    if not lineage_data then
        return {}
    end

    -- Sort by timestamp
    table.sort(lineage_data, function(a, b) return a.timestamp < b.timestamp end)

    -- Apply filters if specified
    if options.event_type then
        lineage_data = self:_filter_events(lineage_data, "event_type", options.event_type)
    end

    if options.time_range then
        lineage_data = self:_filter_time_range(lineage_data, options.time_range)
    end

    if options.limit then
        lineage_data = self:_limit_results(lineage_data, options.limit)
    end

    return lineage_data
end

--- Get data relationships
function _M:get_data_relationships(data_id)
    return self.data_relationships[data_id] or {}
end

--- Get transformation history
function _M:get_transformation_history(data_id)
    return self.transformation_history[data_id] or {}
end

--- Get access patterns
function _M:get_access_patterns(data_id, time_window)
    local patterns = self.access_patterns[data_id] or {}
    if not time_window then
        return patterns
    end

    -- Filter by time window
    local current_time = ngx.now()
    local filtered_patterns = {}

    for _, pattern in ipairs(patterns) do
        if current_time - pattern.timestamp <= time_window then
            table.insert(filtered_patterns, pattern)
        end
    end

    return filtered_patterns
end

--- Analyze data flow
function _M:analyze_data_flow(data_id, analysis_type)
    local lineage = self:get_data_lineage(data_id)
    if #lineage == 0 then
        return {}
    end

    if analysis_type == "flow_summary" then
        return self:_analyze_flow_summary(lineage)
    elseif analysis_type == "access_analysis" then
        return self:_analyze_access_patterns(lineage)
    elseif analysis_type == "transformation_chain" then
        return self:_analyze_transformation_chain(lineage)
    elseif analysis_type == "risk_assessment" then
        return self:_analyze_risk_assessment(lineage)
    end

    return {}
end

--- Helper functions

function _M:_determine_data_flow(context)
    if context.request_path then
        return DATA_FLOW_TYPES.REQUEST
    elseif context.response_headers then
        return DATA_FLOW_TYPES.RESPONSE
    elseif context.external_system then
        return DATA_FLOW_TYPES.EXTERNAL
    else
        return DATA_FLOW_TYPES.INTERNAL
    end
end

function _M:_collect_detailed_metadata(data_id, context)
    -- Collect detailed metadata for comprehensive tracking
    return {
        data_size_bytes = context.data_size_bytes,
        data_hash = context.data_hash,
        schema_version = context.schema_version,
        processing_node = context.processing_node,
        environment = context.environment,
        data_classification = context.data_classification
    }
end

function _M:_update_data_relationships(data_id, event)
    if not self.data_relationships[data_id] then
        self.data_relationships[data_id] = {
            related_data_ids = {},
            parent_data_id = nil,
            child_data_ids = {},
            last_updated = ngx.now()
        }
    end

    local relationships = self.data_relationships[data_id]

    -- Update relationships based on event type
    if event.metadata.parent_data_id then
        relationships.parent_data_id = event.metadata.parent_data_id
    end

    if event.metadata.child_data_ids then
        for _, child_id in ipairs(event.metadata.child_data_ids) do
            if not self:_array_contains(relationships.child_data_ids, child_id) then
                table.insert(relationships.child_data_ids, child_id)
            end
        end
    end

    if event.metadata.related_data_ids then
        for _, related_id in ipairs(event.metadata.related_data_ids) do
            if not self:_array_contains(relationships.related_data_ids, related_id) then
                table.insert(relationships.related_data_ids, related_id)
            end
        end
    end

    relationships.last_updated = ngx.now()
end

function _M:_track_transformation(data_id, event)
    if not self.transformation_history[data_id] then
        self.transformation_history[data_id] = {}
    end

    local transformation = {
        timestamp = event.timestamp,
        transformation_type = event.metadata.transformation_type,
        before_state = event.metadata.before_state,
        after_state = event.metadata.after_state,
        transformation_rules = event.metadata.transformation_rules,
        processing_time_ms = event.metadata.processing_time_ms
    }

    table.insert(self.transformation_history[data_id], transformation)
end

function _M:_track_access_pattern(data_id, event)
    if not self.access_patterns[data_id] then
        self.access_patterns[data_id] = {}
    end

    local pattern = {
        timestamp = event.timestamp,
        access_type = event.metadata.access_type,
        purpose = event.metadata.purpose,
        user_id = event.user_id,
        ip_address = event.ip_address,
        user_agent = event.user_agent
    }

    table.insert(self.access_patterns[data_id], pattern)

    -- Limit access pattern history to prevent unbounded growth
    if #self.access_patterns[data_id] > 1000 then
        table.remove(self.access_patterns[data_id], 1)
    end
end

function _M:_summarize_data_state(data_state)
    if not data_state then return {} end

    return {
        data_type = type(data_state),
        size = #cjson.encode(data_state) or 0,
        field_count = type(data_state) == "table" and self:_count_table_fields(data_state) or 0,
        has_sensitive_data = self:_check_sensitive_data(data_state)
    }
end

function _M:_count_table_fields(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

function _M:_check_sensitive_data(data)
    -- Simple check for sensitive data patterns
    local data_string = cjson.encode(data) or ""
    return string.find(data_string:lower(), "password|ssn|credit") ~= nil
end

function _M:_filter_events(events, field, value)
    local filtered = {}
    for _, event in ipairs(events) do
        if event[field] == value then
            table.insert(filtered, event)
        end
    end
    return filtered
end

function _M:_filter_time_range(events, time_range)
    local filtered = {}
    local current_time = ngx.now()

    for _, event in ipairs(events) do
        if current_time - event.timestamp <= time_range then
            table.insert(filtered, event)
        end
    end

    return filtered
end

function _M:_limit_results(events, limit)
    local limited = {}
    for i = 1, math.min(limit, #events) do
        table.insert(limited, events[i])
    end
    return limited
end

function _M:_array_contains(array, value)
    for _, item in ipairs(array) do
        if item == value then
            return true
        end
    end
    return false
end

function _M:_analyze_flow_summary(lineage)
    local summary = {
        total_events = #lineage,
        event_types = {},
        time_span = 0,
        data_flows = {},
        systems_involved = {}
    }

    if #lineage > 0 then
        summary.time_span = lineage[#lineage].timestamp - lineage[1].timestamp
    end

    for _, event in ipairs(lineage) do
        -- Count event types
        summary.event_types[event.event_type] = (summary.event_types[event.event_type] or 0) + 1

        -- Track data flows
        summary.data_flows[event.data_flow] = (summary.data_flows[event.data_flow] or 0) + 1

        -- Track systems involved
        if event.source_system then
            summary.systems_involved[event.source_system] = true
        end
        if event.target_system then
            summary.systems_involved[event.target_system] = true
        end
    end

    return summary
end

function _M:_analyze_access_patterns(lineage)
    local analysis = {
        total_accesses = 0,
        unique_users = {},
        access_frequency = {},
        peak_access_times = {},
        access_purposes = {}
    }

    for _, event in ipairs(lineage) do
        if event.event_type == LINEAGE_EVENTS.DATA_ACCESS then
            analysis.total_accesses = analysis.total_accesses + 1

            -- Track unique users
            if event.user_id then
                analysis.unique_users[event.user_id] = true
            end

            -- Track access purposes
            if event.metadata.purpose then
                analysis.access_purposes[event.metadata.purpose] = (analysis.access_purposes[event.metadata.purpose] or 0) + 1
            end

            -- Track access times (hourly)
            local hour = os.date("%H", event.timestamp)
            analysis.access_frequency[hour] = (analysis.access_frequency[hour] or 0) + 1
        end
    end

    analysis.unique_user_count = self:_count_table_fields(analysis.unique_users)

    return analysis
end

function _M:_analyze_transformation_chain(lineage)
    local chain = {
        transformations = {},
        data_states = {},
        transformation_sequence = {}
    }

    for _, event in ipairs(lineage) do
        if event.event_type == LINEAGE_EVENTS.DATA_TRANSFORMATION then
            table.insert(chain.transformations, {
                type = event.metadata.transformation_type,
                timestamp = event.timestamp,
                rules = event.metadata.transformation_rules
            })

            table.insert(chain.transformation_sequence, event.metadata.transformation_type)

            if event.metadata.before_state then
                table.insert(chain.data_states, event.metadata.before_state)
            end
        end
    end

    return chain
end

function _M:_analyze_risk_assessment(lineage)
    local risk = {
        risk_score = 0,
        risk_factors = {},
        recommendations = {}
    }

    -- Analyze various risk factors
    local access_analysis = self:_analyze_access_patterns(lineage)

    -- High access frequency
    if access_analysis.total_accesses > 1000 then
        table.insert(risk.risk_factors, "High access frequency detected")
        risk.risk_score = risk.risk_score + 20
    end

    -- Many unique users
    if access_analysis.unique_user_count > 50 then
        table.insert(risk.risk_factors, "Broad user access detected")
        risk.risk_score = risk.risk_score + 15
    end

    -- Cross-system data flows
    local flow_summary = self:_analyze_flow_summary(lineage)
    if self:_count_table_fields(flow_summary.systems_involved) > 3 then
        table.insert(risk.risk_factors, "Complex cross-system data flows")
        risk.risk_score = risk.risk_score + 25
    end

    -- Generate recommendations
    if risk.risk_score > 50 then
        table.insert(risk.recommendations, "Implement additional access controls")
        table.insert(risk.recommendations, "Review data classification and handling procedures")
    end

    if access_analysis.total_accesses > 500 then
        table.insert(risk.recommendations, "Consider implementing data access auditing")
    end

    return risk
end

--- Cleanup old lineage data
function _M:_cleanup_old_lineage_data()
    local current_time = ngx.now()
    local retention_seconds = self.retention_days * 24 * 60 * 60
    local cleaned = 0

    -- Clean lineage store
    for data_id, events in pairs(self.lineage_store) do
        local filtered_events = {}
        for _, event in ipairs(events) do
            if current_time - event.timestamp <= retention_seconds then
                table.insert(filtered_events, event)
            end
        end

        if #filtered_events == 0 then
            self.lineage_store[data_id] = nil
            cleaned = cleaned + 1
        else
            self.lineage_store[data_id] = filtered_events
        end
    end

    -- Clean transformation history
    for data_id, transformations in pairs(self.transformation_history) do
        local filtered_transformations = {}
        for _, transformation in ipairs(transformations) do
            if current_time - transformation.timestamp <= retention_seconds then
                table.insert(filtered_transformations, transformation)
            end
        end

        if #filtered_transformations == 0 then
            self.transformation_history[data_id] = nil
        else
            self.transformation_history[data_id] = filtered_transformations
        end
    end

    if cleaned > 0 then
        kong.log.info("[kong-guard-ai] Cleaned up ", cleaned, " old lineage records")
    end
end

--- Get lineage statistics
function _M:get_statistics()
    local stats = {
        total_data_ids = self:_count_table_fields(self.lineage_store),
        total_events = 0,
        event_types = {},
        data_relationships = self:_count_table_fields(self.data_relationships),
        transformation_records = self:_count_table_fields(self.transformation_history),
        retention_days = self.retention_days,
        enable_detailed_tracking = self.enable_detailed_tracking
    }

    -- Count total events and event types
    for _, events in pairs(self.lineage_store) do
        stats.total_events = stats.total_events + #events
        for _, event in ipairs(events) do
            stats.event_types[event.event_type] = (stats.event_types[event.event_type] or 0) + 1
        end
    end

    return stats
end

return _M
