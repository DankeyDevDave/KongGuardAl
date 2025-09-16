-- Kong Guard AI - Path Regex Filter Module
-- Implements comprehensive regex-based path filtering for attack vector detection
-- Phase 4: Advanced path pattern matching with minimal false positives

local kong = kong
local ngx_re = ngx.re
local json = require "cjson.safe"
local string_find = string.find
local string_gsub = string.gsub
local string_lower = string.lower
local url_decode = ngx.unescape_uri

local _M = {}

-- Path filtering constants
local FILTER_RESULT = {
    ALLOW = "allow",
    BLOCK = "block",
    SUSPICIOUS = "suspicious"
}

local ATTACK_CATEGORIES = {
    SQL_INJECTION = "sql_injection",
    XSS = "cross_site_scripting",
    PATH_TRAVERSAL = "path_traversal",
    ADMIN_ACCESS = "admin_access",
    FILE_INCLUSION = "file_inclusion",
    COMMAND_INJECTION = "command_injection",
    CONFIG_EXPOSURE = "config_exposure",
    INFORMATION_DISCLOSURE = "information_disclosure"
}

-- Pre-compiled regex patterns organized by attack category
local COMPILED_PATTERNS = {}
local PATTERN_CACHE = {}
local PATH_ANALYTICS = {
    total_checks = 0,
    blocks = 0,
    suspicious = 0,
    false_positives = 0,
    pattern_effectiveness = {}
}

-- Default regex patterns for common attack vectors
local DEFAULT_PATTERNS = {
    [ATTACK_CATEGORIES.SQL_INJECTION] = {
        {pattern = "(?i)\\bunion\\s+select\\b", priority = 1, description = "SQL Union Select"},
        {pattern = "(?i)\\bselect\\s+.*\\bfrom\\b", priority = 2, description = "SQL Select statements"},
        {pattern = "(?i)\\bdrop\\s+table\\b", priority = 1, description = "SQL Drop table"},
        {pattern = "(?i)\\binsert\\s+into\\b", priority = 2, description = "SQL Insert statements"},
        {pattern = "(?i)\\bdelete\\s+from\\b", priority = 2, description = "SQL Delete statements"},
        {pattern = "(?i)\\bupdate\\s+.*\\bset\\b", priority = 2, description = "SQL Update statements"},
        {pattern = "(?i)['\"]\\s*;\\s*drop\\b", priority = 1, description = "SQL injection with semicolon"},
        {pattern = "(?i)\\bor\\s+1\\s*=\\s*1\\b", priority = 3, description = "SQL boolean injection"},
        {pattern = "(?i)\\band\\s+1\\s*=\\s*1\\b", priority = 3, description = "SQL boolean injection"},
        {pattern = "(?i)['\"]\\s*\\bor\\s+['\"]", priority = 2, description = "SQL OR injection"},
    },

    [ATTACK_CATEGORIES.XSS] = {
        {pattern = "(?i)<script[^>]*>", priority = 1, description = "Script tag injection"},
        {pattern = "(?i)javascript\\s*:", priority = 1, description = "Javascript protocol"},
        {pattern = "(?i)on\\w+\\s*=", priority = 2, description = "HTML event handlers"},
        {pattern = "(?i)<iframe[^>]*>", priority = 2, description = "Iframe injection"},
        {pattern = "(?i)<object[^>]*>", priority = 2, description = "Object tag injection"},
        {pattern = "(?i)<embed[^>]*>", priority = 2, description = "Embed tag injection"},
        {pattern = "(?i)\\beval\\s*\\(", priority = 2, description = "Javascript eval function"},
        {pattern = "(?i)document\\.(cookie|domain|location)", priority = 2, description = "DOM manipulation"},
        {pattern = "(?i)\\balert\\s*\\(", priority = 3, description = "Javascript alert function"},
        {pattern = "(?i)\\bconfirm\\s*\\(", priority = 3, description = "Javascript confirm function"},
    },

    [ATTACK_CATEGORIES.PATH_TRAVERSAL] = {
        {pattern = "\\.\\.[\\/\\\\]", priority = 1, description = "Directory traversal"},
        {pattern = "\\.\\.[\\/\\\\].*etc[\\/\\\\]passwd", priority = 1, description = "Unix password file access"},
        {pattern = "\\.\\.[\\/\\\\].*windows[\\/\\\\]system32", priority = 1, description = "Windows system access"},
        {pattern = "\\.\\.[\\/\\\\].*boot\\.ini", priority = 1, description = "Windows boot file access"},
        {pattern = "(?i)[\\/\\\\]etc[\\/\\\\]hosts", priority = 2, description = "System hosts file access"},
        {pattern = "(?i)[\\/\\\\]proc[\\/\\\\]version", priority = 2, description = "Linux proc access"},
        {pattern = "(?i)[\\/\\\\]var[\\/\\\\]log", priority = 3, description = "Log file access attempt"},
        {pattern = "%2e%2e[\\/\\\\]", priority = 1, description = "URL encoded traversal"},
        {pattern = "%252e%252e", priority = 1, description = "Double URL encoded traversal"},
    },

    [ATTACK_CATEGORIES.ADMIN_ACCESS] = {
        {pattern = "(?i)[\\/\\\\]admin[\\/\\\\]?", priority = 2, description = "Admin panel access"},
        {pattern = "(?i)[\\/\\\\]wp-admin[\\/\\\\]?", priority = 2, description = "WordPress admin access"},
        {pattern = "(?i)[\\/\\\\]administrator[\\/\\\\]?", priority = 2, description = "Administrator panel"},
        {pattern = "(?i)[\\/\\\\]phpmyadmin[\\/\\\\]?", priority = 2, description = "phpMyAdmin access"},
        {pattern = "(?i)[\\/\\\\]cpanel[\\/\\\\]?", priority = 2, description = "cPanel access"},
        {pattern = "(?i)[\\/\\\\]manager[\\/\\\\]html", priority = 2, description = "Tomcat manager"},
        {pattern = "(?i)[\\/\\\\]solr[\\/\\\\]admin", priority = 2, description = "Solr admin interface"},
        {pattern = "(?i)[\\/\\\\]server-status", priority = 3, description = "Apache server status"},
        {pattern = "(?i)[\\/\\\\]server-info", priority = 3, description = "Apache server info"},
    },

    [ATTACK_CATEGORIES.FILE_INCLUSION] = {
        {pattern = "(?i)[\\/\\\\]proc[\\/\\\\]self[\\/\\\\]environ", priority = 1, description = "Environment variable exposure"},
        {pattern = "(?i)file\\s*:\\s*[\\/\\\\]", priority = 1, description = "File protocol inclusion"},
        {pattern = "(?i)php\\s*:\\/\\/", priority = 1, description = "PHP wrapper inclusion"},
        {pattern = "(?i)data\\s*:\\/\\/", priority = 2, description = "Data URI inclusion"},
        {pattern = "(?i)expect\\s*:\\/\\/", priority = 1, description = "Expect wrapper"},
        {pattern = "(?i)zip\\s*:\\/\\/", priority = 2, description = "ZIP wrapper inclusion"},
        {pattern = "(?i)phar\\s*:\\/\\/", priority = 2, description = "PHAR wrapper inclusion"},
    },

    [ATTACK_CATEGORIES.COMMAND_INJECTION] = {
        {pattern = "(?i)[;&|]\\s*(cat|ls|ps|id|whoami|uname)\\b", priority = 1, description = "Unix command injection"},
        {pattern = "(?i)[;&|]\\s*(dir|type|net|ipconfig)\\b", priority = 1, description = "Windows command injection"},
        {pattern = "(?i)\\$\\(.*\\)", priority = 2, description = "Command substitution"},
        {pattern = "(?i)`.*`", priority = 2, description = "Backtick command execution"},
        {pattern = "(?i)\\|\\s*(nc|netcat|curl|wget)\\b", priority = 1, description = "Network command injection"},
        {pattern = "(?i)\\bsystem\\s*\\(", priority = 2, description = "System function call"},
        {pattern = "(?i)\\bexec\\s*\\(", priority = 2, description = "Exec function call"},
    },

    [ATTACK_CATEGORIES.CONFIG_EXPOSURE] = {
        {pattern = "(?i)\\.env(?:\\.|$)", priority = 1, description = "Environment file access"},
        {pattern = "(?i)\\.config(?:\\.|[\\/\\\\])", priority = 2, description = "Config file access"},
        {pattern = "(?i)config\\.(?:php|xml|json|yaml|yml)$", priority = 2, description = "Configuration files"},
        {pattern = "(?i)\\.htaccess$", priority = 2, description = "Apache config file"},
        {pattern = "(?i)web\\.config$", priority = 2, description = "IIS config file"},
        {pattern = "(?i)\\.git[\\/\\\\]", priority = 2, description = "Git repository access"},
        {pattern = "(?i)\\.svn[\\/\\\\]", priority = 2, description = "SVN repository access"},
        {pattern = "(?i)composer\\.(?:json|lock)$", priority = 3, description = "Composer files"},
        {pattern = "(?i)package\\.json$", priority = 3, description = "NPM package file"},
    },

    [ATTACK_CATEGORIES.INFORMATION_DISCLOSURE] = {
        {pattern = "(?i)\\.bak$", priority = 3, description = "Backup file access"},
        {pattern = "(?i)\\.backup$", priority = 3, description = "Backup file access"},
        {pattern = "(?i)\\.old$", priority = 3, description = "Old file access"},
        {pattern = "(?i)\\.tmp$", priority = 3, description = "Temporary file access"},
        {pattern = "(?i)\\.log$", priority = 3, description = "Log file access"},
        {pattern = "(?i)readme\\.(?:txt|md)$", priority = 4, description = "Documentation access"},
        {pattern = "(?i)changelog\\.(?:txt|md)$", priority = 4, description = "Changelog access"},
        {pattern = "(?i)phpinfo\\.php$", priority = 2, description = "PHP info disclosure"},
        {pattern = "(?i)test\\.php$", priority = 3, description = "Test file access"},
    }
}

---
-- Initialize path filter worker
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Path Filter] Initializing path regex filtering system")

    -- Initialize analytics
    PATH_ANALYTICS.total_checks = 0
    PATH_ANALYTICS.blocks = 0
    PATH_ANALYTICS.suspicious = 0
    PATH_ANALYTICS.false_positives = 0
    PATH_ANALYTICS.pattern_effectiveness = {}

    -- Compile default patterns
    _M.compile_default_patterns()

    -- Compile custom patterns if provided
    if conf.custom_path_patterns then
        _M.compile_custom_patterns(conf.custom_path_patterns)
    end

    kong.log.info("[Kong Guard AI Path Filter] Initialized with " .. _M.get_pattern_count() .. " compiled patterns")
end

---
-- Compile default attack patterns for performance
---
function _M.compile_default_patterns()
    COMPILED_PATTERNS = {}
    local total_patterns = 0

    for category, patterns in pairs(DEFAULT_PATTERNS) do
        COMPILED_PATTERNS[category] = {}
        for i, pattern_def in ipairs(patterns) do
            local compiled, err = ngx_re.compile(pattern_def.pattern, "jo")
            if compiled then
                COMPILED_PATTERNS[category][i] = {
                    compiled = compiled,
                    priority = pattern_def.priority,
                    description = pattern_def.description,
                    original = pattern_def.pattern
                }
                total_patterns = total_patterns + 1
                -- Initialize effectiveness tracking
                PATH_ANALYTICS.pattern_effectiveness[category .. "_" .. i] = {
                    matches = 0,
                    false_positives = 0,
                    true_positives = 0
                }
            else
                kong.log.error("[Kong Guard AI Path Filter] Failed to compile pattern: " ..
                              pattern_def.pattern .. " Error: " .. (err or "unknown"))
            end
        end
    end

    kong.log.info("[Kong Guard AI Path Filter] Compiled " .. total_patterns .. " default patterns")
end

---
-- Compile custom patterns from configuration
-- @param custom_patterns Array of custom pattern definitions
---
function _M.compile_custom_patterns(custom_patterns)
    if not COMPILED_PATTERNS.CUSTOM then
        COMPILED_PATTERNS.CUSTOM = {}
    end

    local custom_count = 0
    for i, pattern_def in ipairs(custom_patterns) do
        local pattern = pattern_def.pattern or pattern_def
        local priority = pattern_def.priority or 2
        local description = pattern_def.description or "Custom pattern " .. i

        local compiled, err = ngx_re.compile(pattern, "jo")
        if compiled then
            COMPILED_PATTERNS.CUSTOM[i] = {
                compiled = compiled,
                priority = priority,
                description = description,
                original = pattern
            }
            custom_count = custom_count + 1
            PATH_ANALYTICS.pattern_effectiveness["CUSTOM_" .. i] = {
                matches = 0,
                false_positives = 0,
                true_positives = 0
            }
        else
            kong.log.error("[Kong Guard AI Path Filter] Failed to compile custom pattern: " ..
                          pattern .. " Error: " .. (err or "unknown"))
        end
    end

    kong.log.info("[Kong Guard AI Path Filter] Compiled " .. custom_count .. " custom patterns")
end

---
-- Analyze path for malicious patterns
-- @param request_context Request context containing path and metadata
-- @param conf Plugin configuration
-- @return Table containing analysis results
---
function _M.analyze_path(request_context, conf)
    PATH_ANALYTICS.total_checks = PATH_ANALYTICS.total_checks + 1

    local filter_result = {
        result = FILTER_RESULT.ALLOW,
        threat_level = 0,
        threat_category = nil,
        matched_patterns = {},
        normalized_path = nil,
        confidence = 0,
        details = {},
        recommended_action = "allow"
    }

    -- Extract and normalize path
    local raw_path = request_context.path or kong.request.get_path()
    if not raw_path then
        return filter_result
    end

    -- Path normalization and decoding
    local normalized_path = _M.normalize_path(raw_path)
    filter_result.normalized_path = normalized_path

    -- Check against all pattern categories
    local highest_threat = 0
    local total_matches = 0

    for category, patterns in pairs(COMPILED_PATTERNS) do
        local category_result = _M.check_category_patterns(normalized_path, category, patterns, conf)

        if category_result.matches > 0 then
            -- Merge results
            for _, match in ipairs(category_result.matched_patterns) do
                table.insert(filter_result.matched_patterns, match)
                total_matches = total_matches + 1
            end

            -- Update threat level based on highest priority match
            if category_result.threat_level > highest_threat then
                highest_threat = category_result.threat_level
                filter_result.threat_category = category
            end
        end
    end

    -- Calculate final threat level and confidence
    filter_result.threat_level = _M.calculate_threat_level(filter_result.matched_patterns, conf)
    filter_result.confidence = _M.calculate_confidence(filter_result.matched_patterns, total_matches)

    -- Determine action based on threat level and false positive mitigation
    if filter_result.threat_level >= (conf.path_filter_block_threshold or 7) then
        if _M.is_likely_false_positive(normalized_path, filter_result.matched_patterns, conf) then
            filter_result.result = FILTER_RESULT.SUSPICIOUS
            filter_result.recommended_action = "log_and_monitor"
            PATH_ANALYTICS.suspicious = PATH_ANALYTICS.suspicious + 1
        else
            filter_result.result = FILTER_RESULT.BLOCK
            filter_result.recommended_action = "block"
            PATH_ANALYTICS.blocks = PATH_ANALYTICS.blocks + 1
        end
    elseif filter_result.threat_level >= (conf.path_filter_suspicious_threshold or 4) then
        filter_result.result = FILTER_RESULT.SUSPICIOUS
        filter_result.recommended_action = "log_and_monitor"
        PATH_ANALYTICS.suspicious = PATH_ANALYTICS.suspicious + 1
    end

    -- Update pattern effectiveness analytics
    _M.update_pattern_analytics(filter_result.matched_patterns, filter_result.result)

    return filter_result
end

---
-- Normalize path for consistent pattern matching
-- @param path Raw request path
-- @return Normalized path string
---
function _M.normalize_path(path)
    -- URL decode multiple times to handle double/triple encoding
    local decoded = path
    local previous = ""
    local iterations = 0

    -- Decode up to 3 times or until no changes
    while decoded ~= previous and iterations < 3 do
        previous = decoded
        decoded = url_decode(decoded) or decoded
        iterations = iterations + 1
    end

    -- Convert to lowercase for case-insensitive matching
    decoded = string_lower(decoded)

    -- Normalize path separators
    decoded = string_gsub(decoded, "\\", "/")

    -- Remove multiple consecutive slashes
    decoded = string_gsub(decoded, "/+", "/")

    -- Handle null bytes and other dangerous characters
    decoded = string_gsub(decoded, "%z", "")
    decoded = string_gsub(decoded, "\r", "")
    decoded = string_gsub(decoded, "\n", "")

    return decoded
end

---
-- Check path against patterns in a specific category
-- @param path Normalized path to check
-- @param category Pattern category name
-- @param patterns Compiled patterns for the category
-- @param conf Plugin configuration
-- @return Table containing category check results
---
function _M.check_category_patterns(path, category, patterns, conf)
    local result = {
        category = category,
        matches = 0,
        matched_patterns = {},
        threat_level = 0
    }

    for i, pattern_def in pairs(patterns) do
        local match, err = ngx_re.find(path, pattern_def.compiled, "jo")
        if match then
            result.matches = result.matches + 1

            local match_info = {
                category = category,
                pattern_id = category .. "_" .. i,
                description = pattern_def.description,
                priority = pattern_def.priority,
                matched_text = match,
                original_pattern = pattern_def.original
            }

            table.insert(result.matched_patterns, match_info)

            -- Update analytics
            local analytics_key = category .. "_" .. i
            if PATH_ANALYTICS.pattern_effectiveness[analytics_key] then
                PATH_ANALYTICS.pattern_effectiveness[analytics_key].matches =
                    PATH_ANALYTICS.pattern_effectiveness[analytics_key].matches + 1
            end

            -- Calculate threat contribution based on priority
            local threat_contribution = _M.priority_to_threat_level(pattern_def.priority)
            if threat_contribution > result.threat_level then
                result.threat_level = threat_contribution
            end
        elseif err then
            kong.log.error("[Kong Guard AI Path Filter] Regex error in category " .. category ..
                          ": " .. err)
        end
    end

    return result
end

---
-- Convert pattern priority to threat level
-- @param priority Pattern priority (1-4)
-- @return Threat level (1-10)
---
function _M.priority_to_threat_level(priority)
    local priority_map = {
        [1] = 9,  -- Critical threats (immediate block)
        [2] = 7,  -- High threats (likely block)
        [3] = 5,  -- Medium threats (suspicious)
        [4] = 3   -- Low threats (monitor)
    }
    return priority_map[priority] or 5
end

---
-- Calculate overall threat level from matched patterns
-- @param matched_patterns Array of pattern matches
-- @param conf Plugin configuration
-- @return Threat level (0-10)
---
function _M.calculate_threat_level(matched_patterns, conf)
    if #matched_patterns == 0 then
        return 0
    end

    local max_threat = 0
    local threat_sum = 0
    local high_priority_count = 0

    for _, match in ipairs(matched_patterns) do
        local threat = _M.priority_to_threat_level(match.priority)
        max_threat = math.max(max_threat, threat)
        threat_sum = threat_sum + threat

        if match.priority <= 2 then  -- High priority patterns
            high_priority_count = high_priority_count + 1
        end
    end

    -- Base threat is the highest individual threat
    local final_threat = max_threat

    -- Increase threat for multiple high-priority matches
    if high_priority_count > 1 then
        final_threat = math.min(10, final_threat + high_priority_count)
    end

    -- Increase threat for many matches (volume indicator)
    if #matched_patterns > 3 then
        final_threat = math.min(10, final_threat + 1)
    end

    return final_threat
end

---
-- Calculate confidence score for the analysis
-- @param matched_patterns Array of pattern matches
-- @param total_matches Total number of pattern matches
-- @return Confidence score (0-100)
---
function _M.calculate_confidence(matched_patterns, total_matches)
    if total_matches == 0 then
        return 100  -- High confidence in allowing clean paths
    end

    local high_priority_matches = 0
    local category_diversity = {}

    for _, match in ipairs(matched_patterns) do
        if match.priority <= 2 then
            high_priority_matches = high_priority_matches + 1
        end
        category_diversity[match.category] = true
    end

    -- Base confidence on high-priority matches
    local confidence = math.min(95, high_priority_matches * 30)

    -- Increase confidence for matches across multiple categories
    local categories = 0
    for _ in pairs(category_diversity) do
        categories = categories + 1
    end
    if categories > 1 then
        confidence = math.min(95, confidence + (categories * 10))
    end

    return confidence
end

---
-- Check if the result is likely a false positive
-- @param path Normalized path
-- @param matched_patterns Array of pattern matches
-- @param conf Plugin configuration
-- @return Boolean indicating if likely false positive
---
function _M.is_likely_false_positive(path, matched_patterns, conf)
    -- Check if path is in whitelist
    if conf.path_whitelist then
        for _, whitelisted_path in ipairs(conf.path_whitelist) do
            if string_find(path, whitelisted_path, 1, true) then
                return true
            end
        end
    end

    -- Check for legitimate file extensions that might trigger patterns
    local legitimate_extensions = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"}
    for _, ext in ipairs(legitimate_extensions) do
        if string_find(path, ext, -#ext, true) then
            -- Only consider false positive if matches are low priority
            local has_high_priority = false
            for _, match in ipairs(matched_patterns) do
                if match.priority <= 2 then
                    has_high_priority = true
                    break
                end
            end
            if not has_high_priority then
                return true
            end
        end
    end

    -- Check for common false positive patterns
    if _M.is_common_false_positive(path, matched_patterns) then
        return true
    end

    return false
end

---
-- Check for common false positive patterns
-- @param path Normalized path
-- @param matched_patterns Array of pattern matches
-- @return Boolean indicating if common false positive
---
function _M.is_common_false_positive(path, matched_patterns)
    -- API endpoints that might contain SQL-like keywords
    if string_find(path, "/api/", 1, true) or string_find(path, "/v1/", 1, true) or string_find(path, "/v2/", 1, true) then
        for _, match in ipairs(matched_patterns) do
            if match.category == ATTACK_CATEGORIES.SQL_INJECTION and match.priority >= 3 then
                return true
            end
        end
    end

    -- Search endpoints that might contain query-like terms
    if string_find(path, "/search", 1, true) or string_find(path, "/query", 1, true) then
        for _, match in ipairs(matched_patterns) do
            if match.category == ATTACK_CATEGORIES.SQL_INJECTION and match.priority >= 3 then
                return true
            end
        end
    end

    return false
end

---
-- Update pattern effectiveness analytics
-- @param matched_patterns Array of pattern matches
-- @param result Filter result (allow/block/suspicious)
---
function _M.update_pattern_analytics(matched_patterns, result)
    for _, match in ipairs(matched_patterns) do
        local analytics_key = match.pattern_id
        if PATH_ANALYTICS.pattern_effectiveness[analytics_key] then
            if result == FILTER_RESULT.BLOCK then
                PATH_ANALYTICS.pattern_effectiveness[analytics_key].true_positives =
                    PATH_ANALYTICS.pattern_effectiveness[analytics_key].true_positives + 1
            elseif result == FILTER_RESULT.ALLOW then
                PATH_ANALYTICS.pattern_effectiveness[analytics_key].false_positives =
                    PATH_ANALYTICS.pattern_effectiveness[analytics_key].false_positives + 1
                PATH_ANALYTICS.false_positives = PATH_ANALYTICS.false_positives + 1
            end
        end
    end
end

---
-- Get pattern count for all categories
-- @return Total number of compiled patterns
---
function _M.get_pattern_count()
    local count = 0
    for category, patterns in pairs(COMPILED_PATTERNS) do
        for _ in pairs(patterns) do
            count = count + 1
        end
    end
    return count
end

---
-- Get path filter analytics
-- @return Table containing analytics data
---
function _M.get_analytics()
    local analytics = {
        total_checks = PATH_ANALYTICS.total_checks,
        blocks = PATH_ANALYTICS.blocks,
        suspicious = PATH_ANALYTICS.suspicious,
        false_positives = PATH_ANALYTICS.false_positives,
        block_rate = 0,
        false_positive_rate = 0,
        pattern_effectiveness = {}
    }

    if PATH_ANALYTICS.total_checks > 0 then
        analytics.block_rate = (PATH_ANALYTICS.blocks / PATH_ANALYTICS.total_checks) * 100
        analytics.false_positive_rate = (PATH_ANALYTICS.false_positives / PATH_ANALYTICS.total_checks) * 100
    end

    -- Calculate pattern effectiveness
    for pattern_id, stats in pairs(PATH_ANALYTICS.pattern_effectiveness) do
        if stats.matches > 0 then
            analytics.pattern_effectiveness[pattern_id] = {
                matches = stats.matches,
                accuracy = stats.true_positives / (stats.true_positives + stats.false_positives),
                true_positives = stats.true_positives,
                false_positives = stats.false_positives
            }
        end
    end

    return analytics
end

---
-- Create path filter incident log entry
-- @param filter_result Path filter analysis result
-- @param request_context Request context
-- @param conf Plugin configuration
-- @return Table containing structured log entry
---
function _M.create_incident_log(filter_result, request_context, conf)
    local incident_log = {
        timestamp = ngx.time(),
        event_type = "path_filter_match",
        severity = filter_result.result == FILTER_RESULT.BLOCK and "high" or "medium",
        source_ip = request_context.client_ip,
        method = request_context.method,
        path = request_context.path,
        normalized_path = filter_result.normalized_path,
        user_agent = kong.request.get_header("User-Agent"),
        threat_level = filter_result.threat_level,
        threat_category = filter_result.threat_category,
        confidence = filter_result.confidence,
        action_taken = filter_result.recommended_action,
        matched_patterns = filter_result.matched_patterns,
        correlation_id = request_context.correlation_id
    }

    return incident_log
end

---
-- Check if path filtering is enabled for request
-- @param conf Plugin configuration
-- @param request_context Request context
-- @return Boolean indicating if filtering should be applied
---
function _M.should_filter_path(conf, request_context)
    -- Skip if path filtering is disabled
    if not conf.enable_path_filtering then
        return false
    end

    -- Skip for whitelisted IPs
    if conf.ip_whitelist then
        for _, ip in ipairs(conf.ip_whitelist) do
            if request_context.client_ip == ip then
                return false
            end
        end
    end

    -- Skip for specific methods if configured
    if conf.path_filter_skip_methods then
        for _, method in ipairs(conf.path_filter_skip_methods) do
            if request_context.method == method then
                return false
            end
        end
    end

    return true
end

---
-- Cleanup path filter caches and analytics
---
function _M.cleanup_cache()
    -- Reset analytics if they get too large
    if PATH_ANALYTICS.total_checks > 1000000 then
        kong.log.info("[Kong Guard AI Path Filter] Resetting analytics after 1M checks")
        PATH_ANALYTICS.total_checks = 0
        PATH_ANALYTICS.blocks = 0
        PATH_ANALYTICS.suspicious = 0
        PATH_ANALYTICS.false_positives = 0

        -- Reset pattern effectiveness but keep structure
        for pattern_id in pairs(PATH_ANALYTICS.pattern_effectiveness) do
            PATH_ANALYTICS.pattern_effectiveness[pattern_id] = {
                matches = 0,
                false_positives = 0,
                true_positives = 0
            }
        end
    end

    -- Clear any temporary caches
    PATTERN_CACHE = {}
end

---
-- Export attack categories for use by other modules
---
function _M.get_attack_categories()
    return ATTACK_CATEGORIES
end

---
-- Export filter results for use by other modules
---
function _M.get_filter_results()
    return FILTER_RESULT
end

return _M
