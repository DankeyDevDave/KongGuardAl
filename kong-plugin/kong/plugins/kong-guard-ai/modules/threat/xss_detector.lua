-- XSS (Cross-Site Scripting) Detection Module
-- Extracted from handler.lua for better maintainability and testing

local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local XSSDetector = {}
XSSDetector.__index = XSSDetector

-- XSS patterns for detection
local XSS_PATTERNS = {
    "<script",
    "javascript:",
    "onerror%s*=",
    "onload%s*=", 
    "onclick%s*=",
    "onmouseover%s*=",
    "<iframe",
    "<embed",
    "<object",
    "document%.cookie",
    "document%.write", 
    "window%.location",
    "eval%s*%(",
    "alert%s*%(",
    "<img%s+src"
}

-- Headers to check for XSS (user-controlled)
local USER_CONTROLLED_HEADERS = {
    "referer",
    "user%-agent",
    "x%-forwarded%-for",
    "x%-real%-ip"
}

--- Initialize XSS detector
function XSSDetector.new(config)
    local self = setmetatable({}, XSSDetector)
    self.config = config or {}
    self.max_body_size = config.max_body_size or 10000
    self.log_level = config.log_level or "info"
    self.check_headers = config.check_headers ~= false -- default true
    return self
end

--- Detect XSS patterns in request features
-- @param features table containing request features
-- @return number threat score (0.0 to 1.0)
-- @return string detection details
function XSSDetector:detect(features)
    local score = 0
    local details = {}
    
    -- Get request data
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()
    local headers = kong.request.get_headers()
    
    -- Start with query and body
    local input = string.lower(query)
    if body and #body < self.max_body_size then
        input = input .. " " .. string.lower(body)
    end
    
    -- Check user-controlled headers if enabled
    if self.check_headers then
        for key, value in pairs(headers) do
            local lower_key = key:lower()
            for _, header_pattern in ipairs(USER_CONTROLLED_HEADERS) do
                if lower_key:match(header_pattern) then
                    input = input .. " " .. string.lower(tostring(value))
                    break
                end
            end
        end
    end
    
    -- Check for XSS patterns
    for _, pattern in ipairs(XSS_PATTERNS) do
        if string.match(input, pattern) then
            score = 0.9
            table.insert(details, "XSS pattern detected: " .. pattern)
            performance_utils.log_message(self.config, "warn",
                "XSS pattern detected", {pattern = pattern})
            break
        end
    end
    
    return score, table.concat(details, "; ")
end

--- Validate input against XSS patterns
-- @param input string to validate
-- @return boolean true if suspicious patterns found
function XSSDetector:validate_input(input)
    if not input or type(input) ~= "string" then
        return false
    end
    
    local normalized_input = string.lower(input)
    
    for _, pattern in ipairs(XSS_PATTERNS) do
        if string.match(normalized_input, pattern) then
            return true
        end
    end
    
    return false
end

--- Get detector statistics
-- @return table with detection statistics
function XSSDetector:get_stats()
    return {
        detector_type = "xss",
        patterns_count = #XSS_PATTERNS,
        max_body_size = self.max_body_size,
        check_headers = self.check_headers,
        monitored_headers = USER_CONTROLLED_HEADERS
    }
end

--- Update patterns (for dynamic threat intelligence)
-- @param new_patterns table of new patterns to add
function XSSDetector:update_patterns(new_patterns)
    if new_patterns and type(new_patterns) == "table" then
        for _, pattern in ipairs(new_patterns) do
            table.insert(XSS_PATTERNS, pattern)
        end
        performance_utils.log_message(self.config, "info",
            "Updated XSS patterns", {new_count = #new_patterns})
    end
end

--- Sanitize input by removing/encoding XSS patterns
-- @param input string to sanitize
-- @return string sanitized input
function XSSDetector:sanitize_input(input)
    if not input or type(input) ~= "string" then
        return input
    end
    
    local sanitized = input
    
    -- Basic HTML encoding for dangerous characters
    sanitized = sanitized:gsub("<", "&lt;")
    sanitized = sanitized:gsub(">", "&gt;")
    sanitized = sanitized:gsub("\"", "&quot;")
    sanitized = sanitized:gsub("'", "&#x27;")
    sanitized = sanitized:gsub("/", "&#x2F;")
    
    return sanitized
end

return XSSDetector