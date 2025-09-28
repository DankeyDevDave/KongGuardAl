-- Path Traversal Detection Module
-- Extracted from handler.lua for better maintainability and testing

local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local PathTraversalDetector = {}
PathTraversalDetector.__index = PathTraversalDetector

-- Path traversal patterns for detection
local TRAVERSAL_PATTERNS = {
    "%.%./",                    -- ../
    "%.%.\\",                   -- ..\
    "%%2e%%2e%%2f",            -- URL encoded ../
    "%%252e%%252e%%252f",      -- Double URL encoded ../
    "/etc/passwd",             -- Unix password file
    "/windows/system32",       -- Windows system directory
    "/proc/self",              -- Linux process info
    "c:\\windows",             -- Windows directory
    "c:\\winnt",               -- Windows NT directory
    "/var/log",                -- Unix log directory
    "/usr/bin",                -- Unix binaries
    "/boot/",                  -- Boot directory
    "%%5c",                    -- URL encoded backslash
    "%%2f",                    -- URL encoded forward slash
    "..%%2f",                  -- Mixed encoding
    "%%2e%%2e",                -- URL encoded ..
}

-- Sensitive file patterns
local SENSITIVE_FILES = {
    "passwd",
    "shadow", 
    "hosts",
    "config",
    "web%.config",
    "application%.properties",
    "settings%.py",
    "database%.yml"
}

--- Initialize path traversal detector
function PathTraversalDetector.new(config)
    local self = setmetatable({}, PathTraversalDetector)
    self.config = config or {}
    self.log_level = config.log_level or "info"
    self.check_query = config.check_query ~= false -- default true
    self.check_headers = config.check_headers or false -- default false
    return self
end

--- Detect path traversal patterns in request features
-- @param features table containing request features
-- @return number threat score (0.0 to 1.0)
-- @return string detection details
function PathTraversalDetector:detect(features)
    local score = 0
    local details = {}
    
    -- Get request data
    local path = kong.request.get_path() or ""
    local query = kong.request.get_raw_query() or ""
    
    local input = path
    if self.check_query then
        input = input .. " " .. query
    end
    
    -- Check headers if enabled
    if self.check_headers then
        local headers = kong.request.get_headers()
        for key, value in pairs(headers) do
            if key:lower():match("file") or key:lower():match("path") then
                input = input .. " " .. tostring(value)
            end
        end
    end
    
    local normalized_input = string.lower(input)
    
    -- Check for path traversal patterns
    for _, pattern in ipairs(TRAVERSAL_PATTERNS) do
        if string.match(normalized_input, pattern) then
            score = 0.85
            table.insert(details, "Path traversal pattern detected: " .. pattern)
            performance_utils.log_message(self.config, "warn",
                "Path traversal pattern detected", {pattern = pattern, path = path})
            break
        end
    end
    
    -- Check for sensitive file access attempts (lower score)
    if score < 0.7 then
        for _, file_pattern in ipairs(SENSITIVE_FILES) do
            if string.match(normalized_input, file_pattern) then
                score = math.max(score, 0.7)
                table.insert(details, "Sensitive file access attempt: " .. file_pattern)
                performance_utils.log_message(self.config, "info",
                    "Sensitive file access detected", {file_pattern = file_pattern})
            end
        end
    end
    
    return score, table.concat(details, "; ")
end

--- Validate path against traversal patterns
-- @param path string to validate
-- @return boolean true if suspicious patterns found
function PathTraversalDetector:validate_path(path)
    if not path or type(path) ~= "string" then
        return false
    end
    
    local normalized_path = string.lower(path)
    
    for _, pattern in ipairs(TRAVERSAL_PATTERNS) do
        if string.match(normalized_path, pattern) then
            return true
        end
    end
    
    return false
end

--- Get detector statistics
-- @return table with detection statistics
function PathTraversalDetector:get_stats()
    return {
        detector_type = "path_traversal",
        patterns_count = #TRAVERSAL_PATTERNS,
        sensitive_files_count = #SENSITIVE_FILES,
        check_query = self.check_query,
        check_headers = self.check_headers
    }
end

--- Sanitize path by removing traversal sequences
-- @param path string to sanitize
-- @return string sanitized path
function PathTraversalDetector:sanitize_path(path)
    if not path or type(path) ~= "string" then
        return path
    end
    
    local sanitized = path
    
    -- Remove common traversal sequences
    sanitized = sanitized:gsub("%.%./", "")
    sanitized = sanitized:gsub("%.%.\\", "")
    sanitized = sanitized:gsub("//+", "/")  -- Remove multiple slashes
    sanitized = sanitized:gsub("\\\\+", "\\") -- Remove multiple backslashes
    
    return sanitized
end

--- Update patterns (for dynamic threat intelligence)
-- @param new_patterns table of new patterns to add
function PathTraversalDetector:update_patterns(new_patterns)
    if new_patterns and type(new_patterns) == "table" then
        for _, pattern in ipairs(new_patterns) do
            table.insert(TRAVERSAL_PATTERNS, pattern)
        end
        performance_utils.log_message(self.config, "info",
            "Updated path traversal patterns", {new_count = #new_patterns})
    end
end

return PathTraversalDetector