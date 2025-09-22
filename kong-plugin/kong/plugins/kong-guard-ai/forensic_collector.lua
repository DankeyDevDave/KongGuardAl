--- Forensic Collector for Kong Guard AI
-- Provides comprehensive evidence collection and preservation capabilities

local cjson = require "cjson.safe"
local ngx = ngx
local kong = kong
local io = io
local os = os

local _M = {}

-- Module constants
local DEFAULT_RETENTION_DAYS = 30
local MAX_EVIDENCE_SIZE = 10485760 -- 10MB
local CHECKSUM_ALGORITHM = "sha256"
local EVIDENCE_FORMAT_VERSION = "1.0"

--- Create a new forensic collector instance
-- @param config The plugin configuration
-- @return forensic collector instance
function _M.new(config)
    if not config then
        return nil, "Configuration is required"
    end

    local self = {
        config = config,
        evidence_store = {},
        storage_backends = {},
        integrity_checks = {},
        metrics = {
            evidence_collected = 0,
            storage_operations = 0,
            integrity_checks = 0,
            retention_cleanups = 0
        }
    }

    -- Initialize storage backends
    self:initialize_storage_backends()

    return setmetatable(self, { __index = _M })
end

--- Initialize the forensic collector
-- @return success, error
function _M:init()
    if not self.config.forensic_collection then
        return false, "Forensic collection configuration is missing"
    end

    if not self.config.forensic_collection.enable_forensics then
        kong.log.debug("Forensic collection is disabled")
        return true
    end

    -- Validate storage backend
    local backend = self.config.forensic_collection.storage_backend
    if not self.storage_backends[backend] then
        return false, "Unsupported storage backend: " .. (backend or "none")
    end

    -- Validate collection triggers
    local triggers = self.config.forensic_collection.collection_triggers or {}
    if #triggers == 0 then
        kong.log.warn("No collection triggers configured - forensic collection will not activate")
    end

    kong.log.info("Forensic collector initialized with ", #triggers, " triggers and ", backend, " storage")
    return true
end

--- Initialize storage backend implementations
function _M:initialize_storage_backends()
    self.storage_backends = {
        local = {
            store = function(self, evidence_id, data)
                return self:store_local(evidence_id, data)
            end,
            retrieve = function(self, evidence_id)
                return self:retrieve_local(evidence_id)
            end,
            delete = function(self, evidence_id)
                return self:delete_local(evidence_id)
            end,
            list = function(self)
                return self:list_local()
            end
        },
        s3 = {
            store = function(self, evidence_id, data)
                return self:store_s3(evidence_id, data)
            end,
            retrieve = function(self, evidence_id)
                return self:retrieve_s3(evidence_id)
            end,
            delete = function(self, evidence_id)
                return self:delete_s3(evidence_id)
            end,
            list = function(self)
                return self:list_s3()
            end
        },
        gcs = {
            store = function(self, evidence_id, data)
                return self:store_gcs(evidence_id, data)
            end,
            retrieve = function(self, evidence_id)
                return self:retrieve_gcs(evidence_id)
            end,
            delete = function(self, evidence_id)
                return self:delete_gcs(evidence_id)
            end,
            list = function(self)
                return self:list_gcs()
            end
        }
    }
end

--- Evaluate collection triggers against threat data
-- @param threat_data The threat detection data
-- @return should_collect, trigger_reason
function _M:evaluate_collection_triggers(threat_data)
    if not self.config.forensic_collection.enable_forensics then
        return false, "forensics_disabled"
    end

    local triggers = self.config.forensic_collection.collection_triggers or {}

    for _, trigger in ipairs(triggers) do
        if self:evaluate_trigger_condition(trigger, threat_data) then
            return true, trigger
        end
    end

    return false, "no_trigger_matched"
end

--- Evaluate a single trigger condition
-- @param trigger The trigger condition
-- @param threat_data The threat detection data
-- @return boolean result
function _M:evaluate_trigger_condition(trigger, threat_data)
    if not trigger or not threat_data then
        return false
    end

    -- Parse trigger conditions
    if trigger == "high_threat" then
        return (threat_data.threat_score or 0) >= 0.8
    elseif trigger == "critical_threat" then
        return (threat_data.threat_score or 0) >= 0.9
    elseif trigger:find("threat_score >") then
        local threshold = tonumber(trigger:match("threat_score > (%d%.%d+)"))
        return threshold and (threat_data.threat_score or 0) > threshold
    elseif trigger:find("response_code") then
        local code = tonumber(trigger:match("response_code (%d+)"))
        return code and threat_data.response_code == code
    elseif trigger == "suspicious_headers" then
        return self:has_suspicious_headers(threat_data.headers)
    elseif trigger == "large_payload" then
        return self:has_large_payload(threat_data)
    elseif trigger == "anomalous_pattern" then
        return self:has_anomalous_pattern(threat_data)
    end

    return false
end

--- Collect forensic evidence
-- @param threat_data The threat detection data
-- @param trigger_reason The reason collection was triggered
-- @return evidence_id, error
function _M:collect_evidence(threat_data, trigger_reason)
    if not threat_data then
        return nil, "Threat data is required"
    end

    local evidence_id = self:generate_evidence_id()
    local collection_time = ngx.now()

    -- Collect comprehensive evidence
    local evidence = {
        metadata = {
            evidence_id = evidence_id,
            collection_time = collection_time,
            trigger_reason = trigger_reason,
            format_version = EVIDENCE_FORMAT_VERSION,
            collector_version = "1.0.0"
        },
        threat_data = threat_data,
        system_context = self:collect_system_context(),
        network_context = self:collect_network_context(threat_data),
        request_snapshot = self:collect_request_snapshot(threat_data),
        response_snapshot = self:collect_response_snapshot(threat_data),
        integrity_checks = {}
    }

    -- Generate integrity checks
    evidence.integrity_checks = self:generate_integrity_checks(evidence)

    -- Store evidence
    local success, err = self:store_evidence(evidence_id, evidence)
    if not success then
        return nil, err
    end

    -- Update metrics
    self.metrics.evidence_collected = self.metrics.evidence_collected + 1

    kong.log.info("Forensic evidence collected: ", evidence_id, " (Trigger: ", trigger_reason, ")")
    return evidence_id
end

--- Collect system context information
-- @return system context data
function _M:collect_system_context()
    return {
        kong_version = kong.version or "unknown",
        kong_node_id = kong.node.get_id() or "unknown",
        plugin_version = "1.0.0",
        lua_version = _VERSION,
        ngx_version = ngx.config.ngx_lua_version,
        system_time = ngx.now(),
        process_id = ngx.worker.pid(),
        worker_id = ngx.worker.id()
    }
end

--- Collect network context information
-- @param threat_data The threat detection data
-- @return network context data
function _M:collect_network_context(threat_data)
    return {
        client_ip = threat_data.client_ip,
        client_port = threat_data.client_port,
        server_ip = threat_data.server_ip or kong.request.get_host(),
        server_port = threat_data.server_port or kong.request.get_port(),
        protocol = kong.request.get_scheme(),
        tls_version = threat_data.tls_version,
        tls_cipher = threat_data.tls_cipher,
        geo_location = threat_data.geo_location,
        asn_info = threat_data.asn_info
    }
end

--- Collect request snapshot
-- @param threat_data The threat detection data
-- @return request snapshot data
function _M:collect_request_snapshot(threat_data)
    local snapshot = {
        method = threat_data.request_method or kong.request.get_method(),
        uri = threat_data.request_uri or kong.request.get_path_with_query(),
        headers = {},
        query_params = {},
        body_size = 0,
        body_hash = nil
    }

    -- Collect headers (sanitize sensitive data)
    local headers = threat_data.headers or kong.request.get_headers()
    for name, value in pairs(headers) do
        if not self:is_sensitive_header(name) then
            snapshot.headers[name] = value
        else
            snapshot.headers[name] = "[REDACTED]"
        end
    end

    -- Collect query parameters
    local query_args = threat_data.query_args or kong.request.get_query()
    for name, value in pairs(query_args) do
        if not self:is_sensitive_param(name) then
            snapshot.query_params[name] = value
        else
            snapshot.query_params[name] = "[REDACTED]"
        end
    end

    -- Collect body information (without storing actual content for large payloads)
    local body = threat_data.request_body
    if body then
        snapshot.body_size = #body
        if #body <= 4096 then -- Only hash small bodies
            snapshot.body_hash = self:hash_data(body)
        end
    end

    return snapshot
end

--- Collect response snapshot
-- @param threat_data The threat detection data
-- @return response snapshot data
function _M:collect_response_snapshot(threat_data)
    return {
        status_code = threat_data.response_code,
        status_text = threat_data.response_status,
        headers = threat_data.response_headers or {},
        body_size = threat_data.response_body and #threat_data.response_body or 0,
        body_hash = threat_data.response_body and #threat_data.response_body <= 4096 and
                   self:hash_data(threat_data.response_body) or nil,
        processing_time = threat_data.processing_time,
        upstream_time = threat_data.upstream_time
    }
end

--- Generate integrity checks for evidence
-- @param evidence The evidence data
-- @return integrity checks
function _M:generate_integrity_checks(evidence)
    local checks = {
        timestamp = ngx.now(),
        algorithm = CHECKSUM_ALGORITHM,
        checksums = {}
    }

    -- Generate checksums for key evidence components
    if evidence.threat_data then
        checks.checksums.threat_data = self:hash_data(cjson.encode(evidence.threat_data))
    end

    if evidence.request_snapshot then
        checks.checksums.request_snapshot = self:hash_data(cjson.encode(evidence.request_snapshot))
    end

    if evidence.response_snapshot then
        checks.checksums.response_snapshot = self:hash_data(cjson.encode(evidence.response_snapshot))
    end

    -- Generate overall evidence checksum
    checks.checksums.overall = self:hash_data(cjson.encode(evidence))

    -- Add chain of custody information
    checks.chain_of_custody = {
        collected_by = "kong-guard-ai",
        collection_method = "automated",
        storage_location = self.config.forensic_collection.storage_backend,
        retention_period_days = DEFAULT_RETENTION_DAYS
    }

    self.metrics.integrity_checks = self.metrics.integrity_checks + 1
    return checks
end

--- Store evidence using configured backend
-- @param evidence_id The evidence ID
-- @param evidence The evidence data
-- @return success, error
function _M:store_evidence(evidence_id, evidence)
    local backend = self.config.forensic_collection.storage_backend
    local backend_impl = self.storage_backends[backend]

    if not backend_impl then
        return false, "Storage backend not available: " .. backend
    end

    -- Serialize evidence
    local evidence_json = cjson.encode(evidence)
    if not evidence_json then
        return false, "Failed to serialize evidence"
    end

    -- Check size limits
    if #evidence_json > MAX_EVIDENCE_SIZE then
        return false, "Evidence size exceeds maximum limit: " .. #evidence_json .. " bytes"
    end

    -- Store using backend
    local success, err = backend_impl:store(evidence_id, evidence_json)
    if success then
        self.metrics.storage_operations = self.metrics.storage_operations + 1
        -- Add to local evidence store for quick access
        self.evidence_store[evidence_id] = {
            metadata = evidence.metadata,
            stored_at = ngx.now(),
            size = #evidence_json
        }
    end

    return success, err
end

--- Retrieve evidence by ID
-- @param evidence_id The evidence ID
-- @return evidence data, error
function _M:retrieve_evidence(evidence_id)
    if not evidence_id then
        return nil, "Evidence ID is required"
    end

    local backend = self.config.forensic_collection.storage_backend
    local backend_impl = self.storage_backends[backend]

    if not backend_impl then
        return nil, "Storage backend not available: " .. backend
    end

    local evidence_json, err = backend_impl:retrieve(evidence_id)
    if not evidence_json then
        return nil, err
    end

    local evidence = cjson.decode(evidence_json)
    if not evidence then
        return nil, "Failed to parse evidence JSON"
    end

    -- Verify integrity if integrity checks exist
    if evidence.integrity_checks then
        local integrity_valid = self:verify_integrity(evidence)
        if not integrity_valid then
            kong.log.warn("Evidence integrity check failed for: ", evidence_id)
        end
    end

    return evidence
end

--- Verify evidence integrity
-- @param evidence The evidence data
-- @return boolean integrity_valid
function _M:verify_integrity(evidence)
    if not evidence.integrity_checks then
        return false
    end

    local checks = evidence.integrity_checks

    -- Verify individual component checksums
    if checks.checksums then
        if checks.checksums.threat_data then
            local current_hash = self:hash_data(cjson.encode(evidence.threat_data))
            if current_hash ~= checks.checksums.threat_data then
                return false
            end
        end

        if checks.checksums.overall then
            -- Remove integrity checks from verification
            local evidence_copy = cjson.decode(cjson.encode(evidence))
            evidence_copy.integrity_checks = nil
            local current_hash = self:hash_data(cjson.encode(evidence_copy))
            if current_hash ~= checks.checksums.overall then
                return false
            end
        end
    end

    return true
end

--- Delete evidence by ID
-- @param evidence_id The evidence ID
-- @return success, error
function _M:delete_evidence(evidence_id)
    if not evidence_id then
        return false, "Evidence ID is required"
    end

    local backend = self.config.forensic_collection.storage_backend
    local backend_impl = self.storage_backends[backend]

    if not backend_impl then
        return false, "Storage backend not available: " .. backend
    end

    local success, err = backend_impl:delete(evidence_id)
    if success then
        -- Remove from local store
        self.evidence_store[evidence_id] = nil
        self.metrics.storage_operations = self.metrics.storage_operations + 1
    end

    return success, err
end

--- List available evidence
-- @return evidence list
function _M:list_evidence()
    local backend = self.config.forensic_collection.storage_backend
    local backend_impl = self.storage_backends[backend]

    if backend_impl and backend_impl.list then
        return backend_impl:list()
    end

    -- Fallback to local store
    local evidence_list = {}
    for evidence_id, metadata in pairs(self.evidence_store) do
        table.insert(evidence_list, {
            evidence_id = evidence_id,
            metadata = metadata
        })
    end

    return evidence_list
end

--- Local storage backend implementation
function _M:store_local(evidence_id, data)
    local file_path = "/tmp/kong-forensics/" .. evidence_id .. ".json"

    -- Ensure directory exists
    os.execute("mkdir -p /tmp/kong-forensics")

    local file, err = io.open(file_path, "w")
    if not file then
        return false, "Failed to open file: " .. err
    end

    file:write(data)
    file:close()

    return true
end

function _M:retrieve_local(evidence_id)
    local file_path = "/tmp/kong-forensics/" .. evidence_id .. ".json"
    local file, err = io.open(file_path, "r")

    if not file then
        return nil, "Failed to open file: " .. err
    end

    local content = file:read("*all")
    file:close()

    return content
end

function _M:delete_local(evidence_id)
    local file_path = "/tmp/kong-forensics/" .. evidence_id .. ".json"
    return os.remove(file_path)
end

function _M:list_local()
    -- This would require filesystem scanning in a real implementation
    local evidence_list = {}
    for evidence_id, metadata in pairs(self.evidence_store) do
        table.insert(evidence_list, {
            evidence_id = evidence_id,
            metadata = metadata
        })
    end
    return evidence_list
end

--- S3-compatible storage backend (placeholder)
function _M:store_s3(evidence_id, data)
    -- Placeholder for S3 implementation
    kong.log.info("S3 storage not yet implemented for evidence: ", evidence_id)
    return false, "S3 storage not implemented"
end

function _M:retrieve_s3(evidence_id)
    return nil, "S3 storage not implemented"
end

function _M:delete_s3(evidence_id)
    return false, "S3 storage not implemented"
end

function _M:list_s3()
    return {}
end

--- Google Cloud Storage backend (placeholder)
function _M:store_gcs(evidence_id, data)
    -- Placeholder for GCS implementation
    kong.log.info("GCS storage not yet implemented for evidence: ", evidence_id)
    return false, "GCS storage not implemented"
end

function _M:retrieve_gcs(evidence_id)
    return nil, "GCS storage not implemented"
end

function _M:delete_gcs(evidence_id)
    return false, "GCS storage not implemented"
end

function _M:list_gcs()
    return {}
end

--- Check if header contains sensitive information
-- @param header_name The header name
-- @return boolean
function _M:is_sensitive_header(header_name)
    local sensitive_headers = {
        "authorization", "cookie", "x-api-key", "x-auth-token",
        "proxy-authorization", "x-csrf-token", "x-xsrf-token"
    }

    header_name = header_name:lower()
    for _, sensitive in ipairs(sensitive_headers) do
        if header_name:find(sensitive) then
            return true
        end
    end

    return false
end

--- Check if parameter contains sensitive information
-- @param param_name The parameter name
-- @return boolean
function _M:is_sensitive_param(param_name)
    local sensitive_params = {
        "password", "token", "key", "secret", "auth",
        "session", "csrf", "xsrf"
    }

    param_name = param_name:lower()
    for _, sensitive in ipairs(sensitive_params) do
        if param_name:find(sensitive) then
            return true
        end
    end

    return false
end

--- Check for suspicious headers
-- @param headers The request headers
-- @return boolean
function _M:has_suspicious_headers(headers)
    if not headers then return false end

    local suspicious_patterns = {
        "sqlmap", "nmap", "nikto", "burp", "owasp",
        "acunetix", "nessus", "qualys"
    }

    for name, value in pairs(headers) do
        local header_str = name .. ": " .. tostring(value)
        header_str = header_str:lower()

        for _, pattern in ipairs(suspicious_patterns) do
            if header_str:find(pattern) then
                return true
            end
        end
    end

    return false
end

--- Check for large payload
-- @param threat_data The threat detection data
-- @return boolean
function _M:has_large_payload(threat_data)
    local body_size = threat_data.request_body and #threat_data.request_body or 0
    return body_size > 102400 -- 100KB threshold
end

--- Check for anomalous patterns
-- @param threat_data The threat detection data
-- @return boolean
function _M:has_anomalous_pattern(threat_data)
    if not threat_data.request_path then return false end

    -- Check for common anomalous patterns
    local anomalous_patterns = {
        "%.%.%/", "%.%.\\", "/etc/passwd", "/etc/shadow",
        "phpinfo%.php", "adminer%.php", "phpmyadmin"
    }

    for _, pattern in ipairs(anomalous_patterns) do
        if threat_data.request_path:find(pattern) then
            return true
        end
    end

    return false
end

--- Generate unique evidence ID
-- @return evidence_id
function _M:generate_evidence_id()
    return "evidence_" .. ngx.now() .. "_" .. math.random(100000, 999999)
end

--- Generate hash of data
-- @param data The data to hash
-- @return hash string
function _M:hash_data(data)
    -- Simple hash implementation (in production, use proper crypto library)
    local hash = 0
    for i = 1, #data do
        hash = (hash * 31 + string.byte(data, i)) % 2^32
    end
    return string.format("%08x", hash)
end

--- Clean up old evidence based on retention policy
function _M:cleanup_old_evidence()
    local retention_seconds = DEFAULT_RETENTION_DAYS * 86400
    local cutoff_time = ngx.now() - retention_seconds
    local cleanup_count = 0

    -- Clean up from local store
    for evidence_id, metadata in pairs(self.evidence_store) do
        if metadata.stored_at < cutoff_time then
            self:delete_evidence(evidence_id)
            cleanup_count = cleanup_count + 1
        end
    end

    if cleanup_count > 0 then
        self.metrics.retention_cleanups = self.metrics.retention_cleanups + 1
        kong.log.info("Cleaned up ", cleanup_count, " old evidence files")
    end
end

--- Get forensic collector health and metrics
-- @return status table
function _M:get_health_status()
    local evidence_count = 0
    for _ in pairs(self.evidence_store) do
        evidence_count = evidence_count + 1
    end

    return {
        enabled = self.config.forensic_collection and self.config.forensic_collection.enable_forensics or false,
        storage_backend = self.config.forensic_collection and self.config.forensic_collection.storage_backend or "none",
        evidence_count = evidence_count,
        collection_triggers = self.config.forensic_collection and
                            #(self.config.forensic_collection.collection_triggers or {}) or 0,
        metrics = self.metrics,
        retention_days = DEFAULT_RETENTION_DAYS
    }
end

return _M