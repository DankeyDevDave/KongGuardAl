-- Kong Guard AI - AI-Powered Threat Detection Module
-- Extracted from handler.lua for better maintainability
-- Handles AI-enhanced threat detection, confidence scoring, and learning

local cjson = require "cjson"

local ThreatDetector = {}
ThreatDetector.__index = ThreatDetector

-- Pre-computed threat type weightings for performance
local THREAT_TYPES = {
    sql_injection = 0.95,
    xss = 0.9,
    path_traversal = 0.85,
    ddos = 0.8,
    credential_stuffing = 0.75,
    command_injection = 0.9,
    mesh_anomaly = 0.7,
    taxii_ip_blocklist = 0.9,
    taxii_domain_blocklist = 0.8,
    anomaly = 0.6
}

-- Initialize Threat Detector
function ThreatDetector.new(config)
    local self = setmetatable({}, ThreatDetector)
    self.config = config or {}

    -- AI learning and confidence tracking
    self.learning_data = {
        false_positives = {},
        confirmed_threats = {},
        confidence_adjustments = {},
        pattern_history = {}
    }

    -- Performance optimization settings
    self.enable_caching = config.enable_threat_caching ~= false
    self.cache_ttl = config.threat_cache_ttl or 300  -- 5 minutes
    self.threat_cache = {}

    return self
end

-- Main optimized threat detection with AI integration
-- This replaces the detect_threat_optimized function from handler.lua
function ThreatDetector:detect_threat_optimized(features, config)
    local threat_score = 0
    local threat_type = "none"
    local threat_details = self:get_pooled_threat_details()

    -- Check cache first for performance
    local cache_key = self:generate_threat_cache_key(features)
    if self.enable_caching and self.threat_cache[cache_key] then
        local cached = self.threat_cache[cache_key]
        if (ngx.now() - cached.timestamp) < self.cache_ttl then
            return cached.score, cached.type, cached.details
        end
    end

    -- 1. Fast pattern-based detection (rule-based)
    local pattern_score, pattern_type = self:detect_patterns_optimized(features, config)
    if pattern_score > threat_score then
        threat_score = pattern_score
        threat_type = pattern_type
        threat_details.detection_method = "pattern_based"
    end

    -- 2. AI-based detection (if enabled and not already high confidence)
    if config.enable_ai_gateway and threat_score < 0.8 then
        local ai_service = require "kong.plugins.kong-guard-ai.modules.ai.ai_service"
        local ai_client = ai_service.new(config)

        local ai_score, ai_type, ai_details = ai_client:detect_ai_optimized(features, config)
        if ai_score > threat_score then
            threat_score = ai_score
            threat_type = ai_type
            threat_details.ai_powered = true
            threat_details.ai_details = ai_details
            threat_details.detection_method = "ai_enhanced"
        end
    end

    -- 3. TAXII threat intelligence (if enabled)
    if config.enable_taxii_ingestion then
        local taxii_score, taxii_type, taxii_details = self:check_taxii_optimized(features, config)
        if taxii_score > threat_score then
            threat_score = taxii_score
            threat_type = taxii_type
            threat_details.taxii = taxii_details
            threat_details.detection_method = "taxii_intelligence"
        end
    end

    -- 4. Mesh-based detection (if available)
    if features.mesh then
        local mesh_score = features.mesh.mesh_score or 0
        if mesh_score > threat_score then
            threat_score = mesh_score
            threat_type = "mesh_anomaly"
            threat_details.mesh = features.mesh
            threat_details.detection_method = "mesh_analysis"
        end
    end

    -- 5. Apply AI confidence scoring and learning adjustments
    threat_score, threat_details = self:apply_confidence_scoring(threat_score, threat_type, threat_details, features)

    -- Cache result for performance
    if self.enable_caching then
        self.threat_cache[cache_key] = {
            score = threat_score,
            type = threat_type,
            details = threat_details,
            timestamp = ngx.now()
        }
    end

    return threat_score, threat_type, threat_details
end

-- Optimized pattern detection (extracted from handler.lua)
function ThreatDetector:detect_patterns_optimized(features, config)
    local score = 0
    local threat_type = "none"

    -- Get input data efficiently
    local path = features.path or ""
    local query = kong.request.get_raw_query() or ""
    local input = string.lower(path .. " " .. query)

    -- Fast string matching with pre-compiled patterns
    if self:detect_sql_injection_pattern(input) then
        score = THREAT_TYPES.sql_injection
        threat_type = "sql_injection"
    elseif self:detect_xss_pattern(input) then
        score = THREAT_TYPES.xss
        threat_type = "xss"
    elseif self:detect_path_traversal_pattern(input) then
        score = THREAT_TYPES.path_traversal
        threat_type = "path_traversal"
    elseif self:detect_command_injection_pattern(input) then
        score = THREAT_TYPES.command_injection
        threat_type = "command_injection"
    elseif features.requests_per_minute > (config.ddos_rpm_threshold or 100) then
        score = THREAT_TYPES.ddos
        threat_type = "ddos"
    end

    return score, threat_type
end

-- Fast SQL injection pattern detection
function ThreatDetector:detect_sql_injection_pattern(input)
    return string.match(input, "union%s+select") or
           string.match(input, "drop%s+table") or
           string.match(input, "insert%s+into") or
           string.match(input, "delete%s+from") or
           string.match(input, "1%s*=%s*1") or
           string.match(input, "or%s+1%s*=%s*1")
end

-- Fast XSS pattern detection
function ThreatDetector:detect_xss_pattern(input)
    return string.match(input, "<script") or
           string.match(input, "javascript:") or
           string.match(input, "onerror%s*=") or
           string.match(input, "onload%s*=") or
           string.match(input, "onclick%s*=")
end

-- Fast path traversal pattern detection
function ThreatDetector:detect_path_traversal_pattern(input)
    return string.match(input, "%.%./") or
           string.match(input, "%%2e%%2e%%2f") or
           string.match(input, "/etc/passwd") or
           string.match(input, "/windows/system32")
end

-- Fast command injection pattern detection
function ThreatDetector:detect_command_injection_pattern(input)
    return string.match(input, "%$%(.*%)") or
           string.match(input, "`.*`") or
           string.match(input, ";%s*ls%s") or
           string.match(input, ";%s*cat%s") or
           string.match(input, "|%s*nc%s")
end

-- Optimized TAXII checking (simplified interface)
function ThreatDetector:check_taxii_optimized(features, config)
    local module_loader = require "kong.plugins.kong-guard-ai.modules.utils.module_loader"
    local taxii_cache = module_loader.get_instance("taxii_cache", config)

    if not taxii_cache then
        return 0, "none", {}
    end

    -- Fast IP lookup only for performance
    if features.client_ip then
        local ip_match = taxii_cache:lookup_ip(features.client_ip)
        if ip_match then
            return 0.9, "taxii_ip_blocklist", {ip_match = ip_match}
        end
    end

    return 0, "none", {}
end

-- AI confidence scoring and learning system
function ThreatDetector:apply_confidence_scoring(threat_score, threat_type, threat_details, features)
    -- Apply learned confidence adjustments
    local pattern_key = threat_type .. ":" .. (features.client_ip or "unknown")

    -- Check for known false positives
    if self.learning_data.false_positives[pattern_key] then
        threat_score = threat_score * 0.5
        threat_details.confidence_adjusted = true
        threat_details.adjustment_reason = "known_false_positive"
    end

    -- Apply threat type specific adjustments
    if self.learning_data.confidence_adjustments[threat_type] then
        local adjustment = self.learning_data.confidence_adjustments[threat_type]
        threat_score = threat_score * adjustment
        threat_details.confidence_adjusted = true
        threat_details.adjustment_factor = adjustment
    end

    -- Track pattern for future learning
    self:track_pattern(threat_type, features, threat_score)

    return threat_score, threat_details
end

-- Track threat patterns for machine learning
function ThreatDetector:track_pattern(threat_type, features, threat_score)
    local pattern_key = threat_type .. ":" .. (features.client_ip or "unknown")

    if not self.learning_data.pattern_history[pattern_key] then
        self.learning_data.pattern_history[pattern_key] = {
            count = 0,
            total_score = 0,
            first_seen = ngx.now(),
            last_seen = ngx.now()
        }
    end

    local pattern = self.learning_data.pattern_history[pattern_key]
    pattern.count = pattern.count + 1
    pattern.total_score = pattern.total_score + threat_score
    pattern.last_seen = ngx.now()
    pattern.avg_score = pattern.total_score / pattern.count
end

-- Learn from feedback (for continuous improvement)
function ThreatDetector:learn_from_feedback(threat_data, feedback)
    local pattern_key = threat_data.type .. ":" .. (threat_data.client_ip or "unknown")

    if feedback.false_positive then
        self.learning_data.false_positives[pattern_key] = true

        -- Reduce confidence for this threat type
        local current_adjustment = self.learning_data.confidence_adjustments[threat_data.type] or 1.0
        self.learning_data.confidence_adjustments[threat_data.type] = math.max(current_adjustment * 0.9, 0.1)

        kong.log.info("Learning: False positive recorded for ", threat_data.type)

    elseif feedback.confirmed_threat then
        -- Increase confidence for confirmed threats
        local current_adjustment = self.learning_data.confidence_adjustments[threat_data.type] or 1.0
        self.learning_data.confidence_adjustments[threat_data.type] = math.min(current_adjustment * 1.1, 1.5)

        kong.log.info("Learning: Confirmed threat recorded for ", threat_data.type)
    end

    -- Store feedback with timestamp
    self.learning_data.confirmed_threats[pattern_key] = {
        timestamp = ngx.now(),
        feedback = feedback,
        original_score = threat_data.score
    }
end

-- Generate cache key for threat detection results
function ThreatDetector:generate_threat_cache_key(features)
    local key_components = {
        features.method or "GET",
        features.path or "/",
        features.client_ip or "unknown",
        features.requests_per_minute or 0
    }
    return ngx.md5(table.concat(key_components, ":"))
end

-- Get pooled threat details object for performance
function ThreatDetector:get_pooled_threat_details()
    return {
        detection_method = "unknown",
        ai_powered = false,
        confidence_adjusted = false,
        timestamp = ngx.now()
    }
end

-- Clear threat cache (for cleanup)
function ThreatDetector:clear_cache()
    self.threat_cache = {}
end

-- Get threat detection statistics
function ThreatDetector:get_statistics()
    local stats = {
        cache_size = 0,
        false_positives = 0,
        confirmed_threats = 0,
        confidence_adjustments = 0,
        pattern_history = 0
    }

    -- Count cache entries
    for _ in pairs(self.threat_cache) do
        stats.cache_size = stats.cache_size + 1
    end

    -- Count learning data
    for _ in pairs(self.learning_data.false_positives) do
        stats.false_positives = stats.false_positives + 1
    end

    for _ in pairs(self.learning_data.confirmed_threats) do
        stats.confirmed_threats = stats.confirmed_threats + 1
    end

    for _ in pairs(self.learning_data.confidence_adjustments) do
        stats.confidence_adjustments = stats.confidence_adjustments + 1
    end

    for _ in pairs(self.learning_data.pattern_history) do
        stats.pattern_history = stats.pattern_history + 1
    end

    return stats
end

-- Export learning data for analysis
function ThreatDetector:export_learning_data()
    return {
        false_positives = self.learning_data.false_positives,
        confirmed_threats = self.learning_data.confirmed_threats,
        confidence_adjustments = self.learning_data.confidence_adjustments,
        pattern_history = self.learning_data.pattern_history,
        export_timestamp = ngx.now()
    }
end

-- Import learning data (for restoring from backup)
function ThreatDetector:import_learning_data(data)
    if not data then return false end

    self.learning_data.false_positives = data.false_positives or {}
    self.learning_data.confirmed_threats = data.confirmed_threats or {}
    self.learning_data.confidence_adjustments = data.confidence_adjustments or {}
    self.learning_data.pattern_history = data.pattern_history or {}

    kong.log.info("Threat detector learning data imported successfully")
    return true
end

-- Cleanup old entries from learning data and cache
function ThreatDetector:cleanup_old_entries()
    local current_time = ngx.now()
    local max_age = 86400 * 30  -- 30 days

    -- Clean up old cache entries
    for key, entry in pairs(self.threat_cache) do
        if (current_time - entry.timestamp) > self.cache_ttl then
            self.threat_cache[key] = nil
        end
    end

    -- Clean up old pattern history
    for key, pattern in pairs(self.learning_data.pattern_history) do
        if (current_time - pattern.last_seen) > max_age then
            self.learning_data.pattern_history[key] = nil
        end
    end

    kong.log.debug("Threat detector cleanup completed")
end

-- Configure threat detector settings
function ThreatDetector:configure(new_config)
    self.config = new_config or self.config
    self.enable_caching = new_config.enable_threat_caching ~= false
    self.cache_ttl = new_config.threat_cache_ttl or self.cache_ttl
end

return ThreatDetector
