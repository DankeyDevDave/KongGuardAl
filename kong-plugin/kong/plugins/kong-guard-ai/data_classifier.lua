--- Data Classification Module for Kong Guard AI
-- Automatically classifies data based on content, context, and usage patterns

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local string = string
local math = math

-- Data classification levels
local CLASSIFICATION_LEVELS = {
    PUBLIC = "public",
    INTERNAL = "internal",
    CONFIDENTIAL = "confidential",
    RESTRICTED = "restricted",
    HIGHLY_RESTRICTED = "highly_restricted"
}

-- Data categories
local DATA_CATEGORIES = {
    PERSONAL = "personal",
    FINANCIAL = "financial",
    HEALTH = "health",
    SENSITIVE = "sensitive",
    BUSINESS = "business",
    TECHNICAL = "technical"
}

-- Data sensitivity scores (0-100)
local SENSITIVITY_THRESHOLDS = {
    [CLASSIFICATION_LEVELS.PUBLIC] = {min = 0, max = 20},
    [CLASSIFICATION_LEVELS.INTERNAL] = {min = 21, max = 40},
    [CLASSIFICATION_LEVELS.CONFIDENTIAL] = {min = 41, max = 60},
    [CLASSIFICATION_LEVELS.RESTRICTED] = {min = 61, max = 80},
    [CLASSIFICATION_LEVELS.HIGHLY_RESTRICTED] = {min = 81, max = 100}
}

-- Classification rules
local CLASSIFICATION_RULES = {
    -- Content-based rules
    content_rules = {
        {
            pattern = "[a-zA-Z0-9._%%+-]+@[a-zA-Z0-9.-]+%.[a-zA-Z]{2,}",
            category = DATA_CATEGORIES.PERSONAL,
            sensitivity = 70,
            description = "Email address detected"
        },
        {
            pattern = "%+?[%d%s%-%(%)]{10,}",
            category = DATA_CATEGORIES.PERSONAL,
            sensitivity = 60,
            description = "Phone number detected"
        },
        {
            pattern = "%d{4}%s?%d{4}%s?%d{4}%s?%d{4}",
            category = DATA_CATEGORIES.FINANCIAL,
            sensitivity = 90,
            description = "Credit card number detected"
        },
        {
            pattern = "%d{3}%-%d{2}%-%d{4}",
            category = DATA_CATEGORIES.PERSONAL,
            sensitivity = 80,
            description = "Social Security Number detected"
        },
        {
            pattern = "[A-Z][a-z]+%s+[A-Z][a-z]+",
            category = DATA_CATEGORIES.PERSONAL,
            sensitivity = 40,
            description = "Full name detected"
        },
        {
            pattern = "%d+%.%d+%.%d+%.%d+",
            category = DATA_CATEGORIES.TECHNICAL,
            sensitivity = 30,
            description = "IP address detected"
        },
        {
            pattern = "password|passwd|pwd",
            category = DATA_CATEGORIES.SENSITIVE,
            sensitivity = 85,
            description = "Password-related content detected"
        },
        {
            pattern = "ssn|social.security|socialsecurity",
            category = DATA_CATEGORIES.PERSONAL,
            sensitivity = 85,
            description = "SSN reference detected"
        }
    },

    -- Context-based rules
    context_rules = {
        {
            path_pattern = "/user/profile",
            category = DATA_CATEGORIES.PERSONAL,
            sensitivity = 60,
            description = "User profile endpoint"
        },
        {
            path_pattern = "/payment",
            category = DATA_CATEGORIES.FINANCIAL,
            sensitivity = 80,
            description = "Payment-related endpoint"
        },
        {
            path_pattern = "/health",
            category = DATA_CATEGORIES.HEALTH,
            sensitivity = 90,
            description = "Health-related endpoint"
        },
        {
            path_pattern = "/admin",
            category = DATA_CATEGORIES.SENSITIVE,
            sensitivity = 95,
            description = "Administrative endpoint"
        },
        {
            header_pattern = "authorization|auth",
            category = DATA_CATEGORIES.SENSITIVE,
            sensitivity = 75,
            description = "Authentication header"
        }
    },

    -- Usage pattern rules
    usage_rules = {
        {
            condition = "high_frequency_access",
            category = DATA_CATEGORIES.BUSINESS,
            sensitivity = 50,
            description = "High-frequency data access"
        },
        {
            condition = "cross_border_transfer",
            category = DATA_CATEGORIES.SENSITIVE,
            sensitivity = 70,
            description = "Cross-border data transfer"
        },
        {
            condition = "third_party_access",
            category = DATA_CATEGORIES.BUSINESS,
            sensitivity = 55,
            description = "Third-party data access"
        }
    }
}

--- Create a new data classifier instance
function _M.new(config)
    local self = {
        config = config or {},
        classification_cache = {},
        cache_ttl = config.cache_ttl or 300, -- 5 minutes
        enable_machine_learning = config.enable_ml_classification or false,
        custom_rules = config.custom_classification_rules or {}
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the classifier
function _M:init()
    -- Set up cache cleanup
    local ok, err = ngx.timer.every(self.cache_ttl, function()
        self:_cleanup_cache()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize classification cache cleanup: ", err)
    end

    kong.log.info("[kong-guard-ai] Data classifier initialized")
end

--- Classify data based on content, context, and usage
function _M:classify_data(data, context)
    if not data then
        return self:_get_default_classification()
    end

    local cache_key = self:_generate_cache_key(data, context)
    local cached_result = self.classification_cache[cache_key]

    if cached_result and (ngx.now() - cached_result.timestamp) < self.cache_ttl then
        return cached_result.classification
    end

    -- Perform classification
    local classification = self:_perform_classification(data, context)

    -- Cache the result
    self.classification_cache[cache_key] = {
        classification = classification,
        timestamp = ngx.now()
    }

    return classification
end

--- Perform the actual classification
function _M:_perform_classification(data, context)
    local classification = {
        level = CLASSIFICATION_LEVELS.PUBLIC,
        category = DATA_CATEGORIES.TECHNICAL,
        sensitivity_score = 0,
        confidence = 0,
        indicators = {},
        rules_matched = {},
        timestamp = ngx.now()
    }

    -- 1. Content-based classification
    local content_result = self:_classify_by_content(data)
    if content_result then
        table.insert(classification.indicators, content_result.indicator)
        table.insert(classification.rules_matched, content_result.rule)
        classification.sensitivity_score = math.max(classification.sensitivity_score, content_result.sensitivity)
        classification.category = content_result.category
    end

    -- 2. Context-based classification
    local context_result = self:_classify_by_context(context)
    if context_result then
        table.insert(classification.indicators, context_result.indicator)
        table.insert(classification.rules_matched, context_result.rule)
        classification.sensitivity_score = math.max(classification.sensitivity_score, context_result.sensitivity)
        if context_result.category ~= DATA_CATEGORIES.TECHNICAL then
            classification.category = context_result.category
        end
    end

    -- 3. Usage pattern-based classification
    local usage_result = self:_classify_by_usage(context)
    if usage_result then
        table.insert(classification.indicators, usage_result.indicator)
        table.insert(classification.rules_matched, usage_result.rule)
        classification.sensitivity_score = math.max(classification.sensitivity_score, usage_result.sensitivity)
    end

    -- 4. Machine learning-based classification (if enabled)
    if self.enable_machine_learning then
        local ml_result = self:_classify_with_ml(data, context)
        if ml_result then
            table.insert(classification.indicators, ml_result.indicator)
            classification.sensitivity_score = math.max(classification.sensitivity_score, ml_result.sensitivity)
            classification.confidence = ml_result.confidence
        end
    end

    -- 5. Apply custom classification rules
    local custom_result = self:_apply_custom_rules(data, context)
    if custom_result then
        table.insert(classification.indicators, custom_result.indicator)
        table.insert(classification.rules_matched, custom_result.rule)
        classification.sensitivity_score = math.max(classification.sensitivity_score, custom_result.sensitivity)
    end

    -- Determine final classification level
    classification.level = self:_determine_classification_level(classification.sensitivity_score)

    -- Calculate overall confidence
    classification.confidence = self:_calculate_confidence(classification)

    -- Add metadata
    classification.data_size = #cjson.encode(data) or 0
    classification.rules_count = #classification.rules_matched

    return classification
end

--- Classify by content analysis
function _M:_classify_by_content(data)
    local data_string = ""

    -- Convert data to string for pattern matching
    if type(data) == "table" then
        data_string = cjson.encode(data) or ""
    elseif type(data) == "string" then
        data_string = data
    else
        data_string = tostring(data)
    end

    -- Check each content rule
    for _, rule in ipairs(CLASSIFICATION_RULES.content_rules) do
        local matches = self:_find_pattern_matches(data_string, rule.pattern)
        if #matches > 0 then
            return {
                category = rule.category,
                sensitivity = rule.sensitivity,
                indicator = rule.description,
                rule = {
                    type = "content",
                    pattern = rule.pattern,
                    matches = #matches
                }
            }
        end
    end

    return nil
end

--- Classify by context analysis
function _M:_classify_by_context(context)
    if not context then return nil end

    -- Check path patterns
    if context.path then
        for _, rule in ipairs(CLASSIFICATION_RULES.context_rules) do
            if rule.path_pattern and string.find(context.path, rule.path_pattern) then
                return {
                    category = rule.category,
                    sensitivity = rule.sensitivity,
                    indicator = rule.description,
                    rule = {
                        type = "context",
                        pattern = rule.path_pattern,
                        field = "path"
                    }
                }
            end
        end
    end

    -- Check header patterns
    if context.headers then
        for header_name, header_value in pairs(context.headers) do
            for _, rule in ipairs(CLASSIFICATION_RULES.context_rules) do
                if rule.header_pattern and
                   (string.find(header_name:lower(), rule.header_pattern) or
                    string.find(header_value:lower(), rule.header_pattern)) then
                    return {
                        category = rule.category,
                        sensitivity = rule.sensitivity,
                        indicator = rule.description,
                        rule = {
                            type = "context",
                            pattern = rule.header_pattern,
                            field = "header",
                            header_name = header_name
                        }
                    }
                end
            end
        end
    end

    return nil
end

--- Classify by usage patterns
function _M:_classify_by_usage(context)
    if not context then return nil end

    -- Check usage conditions
    for _, rule in ipairs(CLASSIFICATION_RULES.usage_rules) do
        if self:_check_usage_condition(rule.condition, context) then
            return {
                category = rule.category,
                sensitivity = rule.sensitivity,
                indicator = rule.description,
                rule = {
                    type = "usage",
                    condition = rule.condition
                }
            }
        end
    end

    return nil
end

--- Check usage condition
function _M:_check_usage_condition(condition, context)
    if condition == "high_frequency_access" then
        return (context.requests_per_minute or 0) > 100
    elseif condition == "cross_border_transfer" then
        return context.cross_border or false
    elseif condition == "third_party_access" then
        return context.third_party or false
    end

    return false
end

--- Classify with machine learning (mock implementation)
function _M:_classify_with_ml(data, context)
    -- Mock ML classification - in production would call actual ML model
    if self.enable_machine_learning then
        return {
            category = DATA_CATEGORIES.BUSINESS,
            sensitivity = 45,
            confidence = 0.85,
            indicator = "ML-based classification",
            rule = {
                type = "machine_learning",
                model = "data_classifier_v1",
                confidence = 0.85
            }
        }
    end

    return nil
end

--- Apply custom classification rules
function _M:_apply_custom_rules(data, context)
    if not self.custom_rules or #self.custom_rules == 0 then
        return nil
    end

    -- Apply custom rules (implementation depends on custom rule format)
    for _, rule in ipairs(self.custom_rules) do
        if self:_evaluate_custom_rule(rule, data, context) then
            return {
                category = rule.category or DATA_CATEGORIES.BUSINESS,
                sensitivity = rule.sensitivity or 50,
                indicator = rule.description or "Custom rule matched",
                rule = {
                    type = "custom",
                    rule_id = rule.id,
                    description = rule.description
                }
            }
        end
    end

    return nil
end

--- Evaluate custom rule (mock implementation)
function _M:_evaluate_custom_rule(rule, data, context)
    -- Mock custom rule evaluation
    return false
end

--- Determine classification level from sensitivity score
function _M:_determine_classification_level(sensitivity_score)
    for level, threshold in pairs(SENSITIVITY_THRESHOLDS) do
        if sensitivity_score >= threshold.min and sensitivity_score <= threshold.max then
            return level
        end
    end

    -- Default to highest level for very high scores
    if sensitivity_score > 80 then
        return CLASSIFICATION_LEVELS.HIGHLY_RESTRICTED
    end

    return CLASSIFICATION_LEVELS.PUBLIC
end

--- Calculate overall confidence score
function _M:_calculate_confidence(classification)
    local base_confidence = 0.5
    local indicators_count = #classification.indicators

    -- Increase confidence based on number of indicators
    if indicators_count > 0 then
        base_confidence = base_confidence + (indicators_count * 0.1)
    end

    -- Increase confidence for higher sensitivity scores
    if classification.sensitivity_score > 50 then
        base_confidence = base_confidence + 0.2
    end

    -- Cap at 0.95
    return math.min(base_confidence, 0.95)
end

--- Get default classification
function _M:_get_default_classification()
    return {
        level = CLASSIFICATION_LEVELS.PUBLIC,
        category = DATA_CATEGORIES.TECHNICAL,
        sensitivity_score = 0,
        confidence = 0.5,
        indicators = {},
        rules_matched = {},
        timestamp = ngx.now()
    }
end

--- Find pattern matches in data
function _M:_find_pattern_matches(data, pattern)
    local matches = {}
    local start_pos = 1

    while true do
        local match_start, match_end = string.find(data, pattern, start_pos)
        if not match_start then
            break
        end

        local match = string.sub(data, match_start, match_end)
        table.insert(matches, match)

        start_pos = match_end + 1

        -- Limit matches to prevent excessive processing
        if #matches >= 10 then
            break
        end
    end

    return matches
end

--- Generate cache key
function _M:_generate_cache_key(data, context)
    local data_hash = ngx.md5(cjson.encode(data) or "")
    local context_hash = ngx.md5(cjson.encode(context) or "")
    return data_hash .. ":" .. context_hash
end

--- Cleanup cache
function _M:_cleanup_cache()
    local current_time = ngx.now()
    local cleaned = 0

    for key, entry in pairs(self.classification_cache) do
        if current_time - entry.timestamp > self.cache_ttl then
            self.classification_cache[key] = nil
            cleaned = cleaned + 1
        end
    end

    if cleaned > 0 then
        kong.log.debug("[kong-guard-ai] Cleaned ", cleaned, " classification cache entries")
    end
end

--- Get classification statistics
function _M:get_statistics()
    return {
        cache_entries = self:_count_cache_entries(),
        cache_ttl = self.cache_ttl,
        enable_machine_learning = self.enable_machine_learning,
        custom_rules_count = #self.custom_rules
    }
end

--- Count cache entries
function _M:_count_cache_entries()
    local count = 0
    for _ in pairs(self.classification_cache) do
        count = count + 1
    end
    return count
end

--- Validate classification configuration
function _M:validate_configuration()
    local issues = {}

    if self.enable_machine_learning and not self.config.ml_model_endpoint then
        table.insert(issues, "Machine learning enabled but no model endpoint configured")
    end

    if #self.custom_rules > 0 and not self:_validate_custom_rules() then
        table.insert(issues, "Invalid custom classification rules")
    end

    return #issues == 0, issues
end

--- Validate custom rules (mock implementation)
function _M:_validate_custom_rules()
    -- Mock validation
    return true
end

return _M