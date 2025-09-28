-- SQL Injection Detection Module
-- Extracted from handler.lua for better maintainability and testing

local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local SQLInjectionDetector = {}
SQLInjectionDetector.__index = SQLInjectionDetector

-- SQL injection patterns for detection
local SQL_PATTERNS = {
    "union%s+select",
    "drop%s+table",
    "drop%s+database", 
    "insert%s+into",
    "delete%s+from",
    "update%s+.*%s+set",
    "exec%s*%(",
    "execute%s*%(",
    "script%s*>",
    "select%s+.*%s+from",
    "';%s*drop",
    "1%s*=%s*1",
    "or%s+1%s*=%s*1",
    "waitfor%s+delay",
    "benchmark%s*%(",
    "sleep%s*%("
}

-- SQL comment patterns
local COMMENT_PATTERNS = {
    "%-%-",     -- SQL line comment
    "/%*",      -- Start of block comment
    "%*/"       -- End of block comment
}

--- Initialize SQL injection detector
function SQLInjectionDetector.new(config)
    local self = setmetatable({}, SQLInjectionDetector)
    self.config = config or {}
    self.max_body_size = config.max_body_size or 10000
    self.log_level = config.log_level or "info"
    return self
end

--- Detect SQL injection patterns in request features
-- @param features table containing request features
-- @return number threat score (0.0 to 1.0)
-- @return string detection details
function SQLInjectionDetector:detect(features)
    local score = 0
    local details = {}
    
    -- Get request data
    local path = kong.request.get_path() or ""
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()
    
    -- Combine all input for checking
    local input = string.lower(path .. " " .. query)
    if body and #body < self.max_body_size then
        input = input .. " " .. string.lower(body)
    end
    
    -- Check for SQL injection patterns
    for _, pattern in ipairs(SQL_PATTERNS) do
        if string.match(input, pattern) then
            score = 0.95
            table.insert(details, "SQL pattern detected: " .. pattern)
            performance_utils.log_message(self.config, "warn", 
                "SQL injection pattern detected", {pattern = pattern})
            break
        end
    end
    
    -- Check for SQL comment patterns (lower severity)
    if score < 0.8 then
        for _, pattern in ipairs(COMMENT_PATTERNS) do
            if string.match(input, pattern) then
                score = math.max(score, 0.8)
                table.insert(details, "SQL comment pattern detected: " .. pattern)
                performance_utils.log_message(self.config, "warn",
                    "SQL comment pattern detected", {pattern = pattern})
            end
        end
    end
    
    return score, table.concat(details, "; ")
end

--- Get detector statistics
-- @return table with detection statistics
function SQLInjectionDetector:get_stats()
    return {
        detector_type = "sql_injection",
        patterns_count = #SQL_PATTERNS,
        comment_patterns_count = #COMMENT_PATTERNS,
        max_body_size = self.max_body_size
    }
end

--- Validate input against SQL injection patterns
-- @param input string to validate
-- @return boolean true if suspicious patterns found
function SQLInjectionDetector:validate_input(input)
    if not input or type(input) ~= "string" then
        return false
    end
    
    local normalized_input = string.lower(input)
    
    for _, pattern in ipairs(SQL_PATTERNS) do
        if string.match(normalized_input, pattern) then
            return true
        end
    end
    
    return false
end

--- Update patterns (for dynamic threat intelligence)
-- @param new_patterns table of new patterns to add
function SQLInjectionDetector:update_patterns(new_patterns)
    if new_patterns and type(new_patterns) == "table" then
        for _, pattern in ipairs(new_patterns) do
            table.insert(SQL_PATTERNS, pattern)
        end
        performance_utils.log_message(self.config, "info",
            "Updated SQL injection patterns", {new_count = #new_patterns})
    end
end

return SQLInjectionDetector