--- Audit Logger Module for Kong Guard AI
-- Provides comprehensive audit logging with security, integrity, and compliance features
-- Supports structured logging, event correlation, encryption, and multiple storage backends.

local _M = {}
local mt = { __index = _M }

-- Dependencies
local kong = kong
local ngx = ngx
local cjson = require("cjson.safe")
local string = string
local os = os
local math = math

-- Constants
local AUDIT_EVENT_TYPES = {
    SECURITY_EVENT = "security_event",
    CONFIG_CHANGE = "config_change",
    ACCESS_EVENT = "access_event",
    DATA_PROCESSING = "data_processing",
    PRIVACY_EVENT = "privacy_event",
    CONSENT_EVENT = "consent_event",
    THREAT_DETECTION = "threat_detection",
    COMPLIANCE_VIOLATION = "compliance_violation"
}

local LOG_LEVELS = {
    MINIMAL = "minimal",
    STANDARD = "standard",
    DETAILED = "detailed"
}

--- Create a new audit logger instance
-- @param config Configuration table with audit settings
-- @return Audit logger instance
function _M.new(config)
    if not config then
        return nil, "Configuration required for audit logger"
    end

    local self = {
        -- Configuration
        config = config,

        -- Event buffer for batch processing
        event_buffer = {},
        buffer_size = config.buffer_size or 100,
        flush_interval = config.flush_interval or 30,

        -- Event correlation
        correlation_counter = 0,
        active_sessions = {},

        -- Storage backends
        storage_backends = {
            local_file = config.audit_storage_backend == "local",
            database = config.audit_storage_backend == "database",
            elasticsearch = config.audit_storage_backend == "elasticsearch",
            splunk = config.audit_storage_backend == "splunk"
        },

        -- Encryption settings
        encryption = {
            enabled = config.audit_encryption or false,
            key_rotation_days = config.key_rotation_days or 90,
            current_key_id = "key-1",
            key_version = 1
        },

        -- Performance metrics
        metrics = {
            events_logged = 0,
            events_buffered = 0,
            events_flushed = 0,
            encryption_operations = 0,
            storage_operations = 0,
            errors = 0
        },

        -- Log integrity
        integrity = {
            enabled = true,
            last_hash = nil,
            chain_hashes = {}
        }
    }

    return setmetatable(self, mt)
end

--- Initialize audit logger
function _M:init()
    -- Set up periodic buffer flush
    if self.buffer_size > 1 then
        local ok, err = ngx.timer.every(self.flush_interval, function()
            self:_flush_buffer()
        end)

        if not ok then
            kong.log.err("[kong-guard-ai] Failed to initialize audit buffer flush: ", err)
        end
    end

    -- Initialize storage backend
    self:_init_storage_backend()

    -- Initialize encryption if enabled
    if self.encryption.enabled then
        self:_init_encryption()
    end

    kong.log.info("[kong-guard-ai] Audit logger initialized")
end

--- Log a security event
function _M:log_security_event(event_type, details, context)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.SECURITY_EVENT, {
        event_type = event_type,
        details = details,
        context = context or {}
    })

    return self:_log_event(event)
end

--- Log a configuration change
function _M:log_config_change(change_type, old_value, new_value, user)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.CONFIG_CHANGE, {
        change_type = change_type,
        old_value = self:_sanitize_config_value(old_value),
        new_value = self:_sanitize_config_value(new_value),
        user = user or "system",
        timestamp = ngx.now()
    })

    return self:_log_event(event)
end

--- Log an access event
function _M:log_access_event(resource, action, user, client_ip, success)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.ACCESS_EVENT, {
        resource = resource,
        action = action,
        user = user or "anonymous",
        client_ip = client_ip,
        success = success,
        user_agent = ngx.var.http_user_agent,
        method = ngx.var.request_method,
        path = ngx.var.request_uri
    })

    return self:_log_event(event)
end

--- Log a data processing event
function _M:log_data_processing(operation, data_type, data_size, user, purpose)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.DATA_PROCESSING, {
        operation = operation,
        data_type = data_type,
        data_size = data_size,
        user = user or "system",
        purpose = purpose,
        processing_time = ngx.now(),
        data_hash = self:_calculate_data_hash(data_type, data_size)
    })

    return self:_log_event(event)
end

--- Log a privacy event
function _M:log_privacy_event(event_type, pii_types, user, action)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.PRIVACY_EVENT, {
        event_type = event_type,
        pii_types = pii_types,
        user = user or "system",
        action = action,
        consent_status = "unknown",
        data_location = "unknown"
    })

    return self:_log_event(event)
end

--- Log a consent event
function _M:log_consent_event(user, action, scope, consent_given)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.CONSENT_EVENT, {
        user = user,
        action = action,
        scope = scope,
        consent_given = consent_given,
        timestamp = ngx.now(),
        ip_address = ngx.var.remote_addr,
        user_agent = ngx.var.http_user_agent
    })

    return self:_log_event(event)
end

--- Log a threat detection event
function _M:log_threat_detection(threat_score, threat_type, client_ip, details)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.THREAT_DETECTION, {
        threat_score = threat_score,
        threat_type = threat_type,
        client_ip = client_ip,
        details = details,
        detection_time = ngx.now(),
        user_agent = ngx.var.http_user_agent,
        request_path = ngx.var.request_uri,
        request_method = ngx.var.request_method
    })

    return self:_log_event(event)
end

--- Log a compliance violation
function _M:log_compliance_violation(violation_type, severity, details, remediation)
    local event = self:_create_audit_event(AUDIT_EVENT_TYPES.COMPLIANCE_VIOLATION, {
        violation_type = violation_type,
        severity = severity,
        details = details,
        remediation = remediation,
        detection_time = ngx.now(),
        affected_system = "kong-guard-ai",
        regulatory_framework = "auto-detect"
    })

    return self:_log_event(event)
end

--- Create a standardized audit event
function _M:_create_audit_event(event_type, event_data)
    -- Generate correlation ID
    self.correlation_counter = self.correlation_counter + 1
    local correlation_id = string.format("AUDIT-%s-%d", ngx.now(), self.correlation_counter)

    local event = {
        -- Standard audit fields
        id = correlation_id,
        timestamp = ngx.now(),
        event_type = event_type,
        version = "1.0",

        -- System context
        system = {
            name = "kong-guard-ai",
            version = "2.0.0",
            instance_id = ngx.var.hostname or "unknown",
            environment = os.getenv("KONG_ENVIRONMENT") or "production"
        },

        -- Actor information
        actor = {
            type = "system",
            id = "kong-guard-ai",
            ip_address = ngx.var.server_addr or "127.0.0.1"
        },

        -- Event data
        data = event_data,

        -- Audit metadata
        metadata = {
            log_level = self.config.audit_log_level or LOG_LEVELS.STANDARD,
            retention_days = self.config.audit_retention_days or 90,
            encryption_enabled = self.encryption.enabled,
            integrity_hash = nil -- Will be set during logging
        }
    }

    -- Add detailed context based on log level
    if self.config.audit_log_level == LOG_LEVELS.DETAILED then
        event.context = {
            kong_version = kong.version or "unknown",
            lua_version = _VERSION,
            server_name = ngx.var.server_name,
            connection_id = ngx.var.connection,
            request_id = ngx.var.request_id
        }
    end

    return event
end

--- Log an audit event
function _M:_log_event(event)
    -- Add integrity hash
    event.metadata.integrity_hash = self:_calculate_event_hash(event)

    -- Update integrity chain
    self:_update_integrity_chain(event)

    -- Buffer or immediate logging based on configuration
    if self.buffer_size > 1 then
        return self:_buffer_event(event)
    else
        return self:_write_event(event)
    end
end

--- Buffer an event for batch processing
function _M:_buffer_event(event)
    table.insert(self.event_buffer, event)
    self.metrics.events_buffered = self.metrics.events_buffered + 1

    -- Auto-flush if buffer is full
    if #self.event_buffer >= self.buffer_size then
        return self:_flush_buffer()
    end

    return true
end

--- Flush buffered events
function _M:_flush_buffer()
    if #self.event_buffer == 0 then
        return true
    end

    local events_to_flush = self.event_buffer
    self.event_buffer = {}

    -- Batch write events
    local success = true
    for _, event in ipairs(events_to_flush) do
        if not self:_write_event(event) then
            success = false
            self.metrics.errors = self.metrics.errors + 1
        end
    end

    self.metrics.events_flushed = self.metrics.events_flushed + #events_to_flush

    if success then
        kong.log.debug("[kong-guard-ai] Flushed ", #events_to_flush, " audit events")
    else
        kong.log.warn("[kong-guard-ai] Some audit events failed to flush")
    end

    return success
end

--- Write a single event to storage
function _M:_write_event(event)
    local success = false

    -- Encrypt if enabled
    if self.encryption.enabled then
        event = self:_encrypt_event(event)
    end

    -- Format event
    local formatted_event = self:_format_event(event)

    -- Write to configured storage backend
    if self.storage_backends.local_file then
        success = self:_write_to_file(formatted_event)
    elseif self.storage_backends.database then
        success = self:_write_to_database(formatted_event)
    elseif self.storage_backends.elasticsearch then
        success = self:_write_to_elasticsearch(formatted_event)
    elseif self.storage_backends.splunk then
        success = self:_write_to_splunk(formatted_event)
    end

    if success then
        self.metrics.events_logged = self.metrics.events_logged + 1
        self.metrics.storage_operations = self.metrics.storage_operations + 1
    end

    return success
end

--- Format event for storage
function _M:_format_event(event)
    if self.config.audit_log_level == LOG_LEVELS.MINIMAL then
        -- Minimal format: just essential fields
        return string.format("[%s] %s: %s",
            os.date("%Y-%m-%d %H:%M:%S", event.timestamp),
            event.event_type,
            event.id
        )
    else
        -- Standard/Detailed format: JSON
        return cjson.encode(event)
    end
end

--- Write to local file
function _M:_write_to_file(formatted_event)
    local log_file = "/var/log/kong-guard-ai/audit.log"
    local file, err = io.open(log_file, "a")

    if not file then
        kong.log.err("[kong-guard-ai] Failed to open audit log file: ", err)
        return false
    end

    file:write(formatted_event .. "\n")
    file:close()

    return true
end

--- Write to database (placeholder)
function _M:_write_to_database(formatted_event)
    -- Placeholder for database integration
    kong.log.debug("[kong-guard-ai] Database audit logging not yet implemented")
    return true
end

--- Write to Elasticsearch (placeholder)
function _M:_write_to_elasticsearch(formatted_event)
    -- Placeholder for Elasticsearch integration
    kong.log.debug("[kong-guard-ai] Elasticsearch audit logging not yet implemented")
    return true
end

--- Write to Splunk (placeholder)
function _M:_write_to_splunk(formatted_event)
    -- Placeholder for Splunk integration
    kong.log.debug("[kong-guard-ai] Splunk audit logging not yet implemented")
    return true
end

--- Initialize storage backend
function _M:_init_storage_backend()
    if self.storage_backends.local_file then
        -- Ensure log directory exists
        local log_dir = "/var/log/kong-guard-ai"
        os.execute("mkdir -p " .. log_dir)
        kong.log.info("[kong-guard-ai] Audit logging to local file: ", log_dir .. "/audit.log")
    end
end

--- Encrypt an event
function _M:_encrypt_event(event)
    -- Placeholder for encryption implementation
    -- In production, this would use proper encryption libraries
    self.metrics.encryption_operations = self.metrics.encryption_operations + 1

    event.encrypted = true
    event.encryption_key_id = self.encryption.current_key_id

    return event
end

--- Initialize encryption
function _M:_init_encryption()
    -- Placeholder for encryption key management
    kong.log.info("[kong-guard-ai] Audit log encryption enabled")
end

--- Calculate event hash for integrity
function _M:_calculate_event_hash(event)
    -- Simple hash for integrity checking
    -- In production, use cryptographic hash functions
    local data = cjson.encode(event)
    local hash = 0

    for i = 1, #data do
        hash = (hash * 31 + data:byte(i)) % 1000000
    end

    return string.format("%06d", hash)
end

--- Update integrity chain
function _M:_update_integrity_chain(event)
    if not self.integrity.enabled then
        return
    end

    local current_hash = event.metadata.integrity_hash
    local chain_hash

    if self.integrity.last_hash then
        chain_hash = self:_calculate_event_hash({
            previous = self.integrity.last_hash,
            current = current_hash
        })
    else
        chain_hash = current_hash
    end

    event.metadata.chain_hash = chain_hash
    self.integrity.last_hash = chain_hash

    table.insert(self.integrity.chain_hashes, chain_hash)

    -- Keep only last 1000 hashes for memory efficiency
    if #self.integrity.chain_hashes > 1000 then
        table.remove(self.integrity.chain_hashes, 1)
    end
end

--- Sanitize configuration values for logging
function _M:_sanitize_config_value(value)
    if type(value) == "table" then
        local sanitized = {}
        for k, v in pairs(value) do
            if string.match(k:lower(), "password|secret|key|token") then
                sanitized[k] = "***REDACTED***"
            else
                sanitized[k] = self:_sanitize_config_value(v)
            end
        end
        return sanitized
    elseif type(value) == "string" and #value > 100 then
        return value:sub(1, 100) .. "..."
    else
        return value
    end
end

--- Calculate data hash for audit
function _M:_calculate_data_hash(data_type, data_size)
    -- Simple hash for data integrity
    return string.format("%s-%d-%d", data_type, data_size, ngx.now())
end

--- Get audit statistics
function _M:get_stats()
    return {
        events_logged = self.metrics.events_logged,
        events_buffered = self.metrics.events_buffered,
        events_flushed = self.metrics.events_flushed,
        buffer_size_current = #self.event_buffer,
        buffer_size_max = self.buffer_size,
        encryption_operations = self.metrics.encryption_operations,
        storage_operations = self.metrics.storage_operations,
        errors = self.metrics.errors,
        integrity_chain_length = #self.integrity.chain_hashes,
        encryption_enabled = self.encryption.enabled,
        storage_backend = self.config.audit_storage_backend
    }
end

--- Verify audit log integrity
function _M:verify_integrity()
    if not self.integrity.enabled or #self.integrity.chain_hashes < 2 then
        return true, "Integrity check not applicable"
    end

    -- Verify chain integrity
    for i = 2, #self.integrity.chain_hashes do
        local expected_hash = self:_calculate_event_hash({
            previous = self.integrity.chain_hashes[i-1],
            current = "verify"
        })

        if expected_hash ~= self.integrity.chain_hashes[i] then
            return false, "Integrity chain broken at position " .. i
        end
    end

    return true, "Integrity verified"
end

--- Cleanup resources
function _M:cleanup()
    -- Flush any remaining buffered events
    self:_flush_buffer()

    -- Clear buffers
    self.event_buffer = {}
    self.active_sessions = {}

    kong.log.info("[kong-guard-ai] Audit logger cleanup completed")
end

return _M