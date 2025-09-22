-- Threat Detection Orchestrator Module
-- Coordinates multiple threat detection modules for comprehensive analysis

local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"
local module_loader = require "kong.plugins.kong-guard-ai.modules.utils.module_loader"

local ThreatOrchestrator = {}
ThreatOrchestrator.__index = ThreatOrchestrator

--- Initialize threat orchestrator
function ThreatOrchestrator.new(config)
    local self = setmetatable({}, ThreatOrchestrator)
    self.config = config or {}
    self.log_level = config.log_level or "info"
    
    -- Initialize individual detectors
    self.detectors = {}
    
    -- Load SQL injection detector
    local sql_detector_class = module_loader.load_module("modules.threat.sql_injection_detector")
    self.detectors.sql_injection = sql_detector_class.new(config)
    
    -- Load XSS detector
    local xss_detector_class = module_loader.load_module("modules.threat.xss_detector")
    self.detectors.xss = xss_detector_class.new(config)
    
    -- Load path traversal detector
    local path_detector_class = module_loader.load_module("modules.threat.path_traversal_detector")
    self.detectors.path_traversal = path_detector_class.new(config)
    
    -- Detection cache for performance
    self.detection_cache = {}
    self.cache_ttl = config.threat_cache_ttl or 300 -- 5 minutes
    
    performance_utils.log_message(config, "info", "Threat orchestrator initialized",
        {detectors = {"sql_injection", "xss", "path_traversal"}})
    
    return self
end

--- Run comprehensive threat detection analysis
-- @param features table containing request features
-- @return number highest threat score (0.0 to 1.0)
-- @return string threat type detected
-- @return table detailed detection results
function ThreatOrchestrator:detect_threats(features)
    local results = {
        max_score = 0,
        threat_type = "none",
        detections = {},
        summary = ""
    }
    
    -- Generate cache key from request features
    local cache_key = self:_generate_cache_key(features)
    
    -- Check cache first
    local cached_result = self:_get_cached_result(cache_key)
    if cached_result then
        performance_utils.log_message(self.config, "debug", "Using cached threat detection result")
        return cached_result.max_score, cached_result.threat_type, cached_result
    end
    
    -- Run all detectors
    for detector_name, detector in pairs(self.detectors) do
        local score, details = detector:detect(features)
        
        results.detections[detector_name] = {
            score = score,
            details = details or "",
            timestamp = os.time()
        }
        
        -- Track highest score and corresponding threat type
        if score > results.max_score then
            results.max_score = score
            results.threat_type = detector_name
        end
        
        performance_utils.log_message(self.config, "debug", 
            "Threat detection completed", {detector = detector_name, score = score})
    end
    
    -- Generate summary
    results.summary = self:_generate_summary(results.detections)
    
    -- Cache the result
    self:_cache_result(cache_key, results)
    
    performance_utils.log_message(self.config, "info", "Threat orchestration completed",
        {max_score = results.max_score, threat_type = results.threat_type})
    
    return results.max_score, results.threat_type, results
end

--- Validate input against all threat detectors
-- @param input string to validate
-- @return boolean true if any threats detected
-- @return table list of threat types detected
function ThreatOrchestrator:validate_input(input)
    local threats_detected = {}
    local has_threats = false
    
    for detector_name, detector in pairs(self.detectors) do
        if detector.validate_input and detector:validate_input(input) then
            table.insert(threats_detected, detector_name)
            has_threats = true
        end
    end
    
    return has_threats, threats_detected
end

--- Get statistics from all detectors
-- @return table comprehensive statistics
function ThreatOrchestrator:get_stats()
    local stats = {
        orchestrator = {
            active_detectors = 0,
            cache_size = 0,
            cache_ttl = self.cache_ttl
        },
        detectors = {}
    }
    
    -- Count cache entries
    for _ in pairs(self.detection_cache) do
        stats.orchestrator.cache_size = stats.orchestrator.cache_size + 1
    end
    
    -- Get stats from each detector
    for detector_name, detector in pairs(self.detectors) do
        stats.orchestrator.active_detectors = stats.orchestrator.active_detectors + 1
        if detector.get_stats then
            stats.detectors[detector_name] = detector:get_stats()
        end
    end
    
    return stats
end

--- Update threat patterns across all detectors
-- @param updates table with detector-specific pattern updates
function ThreatOrchestrator:update_threat_patterns(updates)
    for detector_name, new_patterns in pairs(updates) do
        local detector = self.detectors[detector_name]
        if detector and detector.update_patterns then
            detector:update_patterns(new_patterns)
        end
    end
    
    -- Clear cache when patterns are updated
    self:clear_cache()
end

--- Clear detection cache
function ThreatOrchestrator:clear_cache()
    self.detection_cache = {}
    performance_utils.log_message(self.config, "info", "Threat detection cache cleared")
end

-- Private methods

--- Generate cache key from request features
-- @param features table containing request features
-- @return string cache key
function ThreatOrchestrator:_generate_cache_key(features)
    local path = kong.request.get_path() or ""
    local method = kong.request.get_method() or ""
    local query = kong.request.get_raw_query() or ""
    
    -- Create a simple hash-like key
    local key_data = method .. ":" .. path .. ":" .. query
    return string.gsub(key_data, "[^%w%d%-_]", "_")
end

--- Get cached detection result
-- @param cache_key string cache key
-- @return table cached result or nil
function ThreatOrchestrator:_get_cached_result(cache_key)
    local cached = self.detection_cache[cache_key]
    if not cached then
        return nil
    end
    
    -- Check if cache entry is still valid
    if os.time() - cached.timestamp > self.cache_ttl then
        self.detection_cache[cache_key] = nil
        return nil
    end
    
    return cached.result
end

--- Cache detection result
-- @param cache_key string cache key
-- @param result table detection result to cache
function ThreatOrchestrator:_cache_result(cache_key, result)
    self.detection_cache[cache_key] = {
        result = result,
        timestamp = os.time()
    }
end

--- Generate summary from detection results
-- @param detections table detection results from all detectors
-- @return string summary text
function ThreatOrchestrator:_generate_summary(detections)
    local summary_parts = {}
    
    for detector_name, detection in pairs(detections) do
        if detection.score > 0 then
            table.insert(summary_parts, string.format("%s: %.2f", detector_name, detection.score))
        end
    end
    
    if #summary_parts > 0 then
        return "Threats detected - " .. table.concat(summary_parts, ", ")
    else
        return "No threats detected"
    end
end

return ThreatOrchestrator