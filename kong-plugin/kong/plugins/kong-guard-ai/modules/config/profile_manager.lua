-- Configuration Profile Manager
-- Simplifies configuration management for KongGuardAI plugin
-- Addresses the overwhelming 2000+ configuration options problem

local schema_orchestrator = require "kong.plugins.kong-guard-ai.modules.schema.schema_orchestrator"
local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local ProfileManager = {}
ProfileManager.__index = ProfileManager

--- Initialize profile manager
-- @param config table base configuration
function ProfileManager.new(config)
    local self = setmetatable({}, ProfileManager)
    self.config = config or {}
    self.applied_profiles = {}
    self.validation_errors = {}

    return self
end

--- Get all available configuration profiles
-- @return table available profiles with descriptions
function ProfileManager:get_available_profiles()
    local profiles = schema_orchestrator.get_configuration_profiles()
    local profile_list = {}

    for name, profile in pairs(profiles) do
        table.insert(profile_list, {
            name = name,
            title = profile.name,
            description = profile.description,
            suitable_for = self:_get_profile_use_cases(name)
        })
    end

    return profile_list
end

--- Apply a configuration profile
-- @param profile_name string name of profile to apply
-- @param merge_with_existing boolean whether to merge with existing config
-- @return boolean success
-- @return string error message if failed
function ProfileManager:apply_profile(profile_name, merge_with_existing)
    local base_config = merge_with_existing and self.config or {}

    local merged_config, success, error_msg = schema_orchestrator.apply_configuration_profile(
        profile_name, base_config
    )

    if not success then
        table.insert(self.validation_errors, error_msg)
        return false, error_msg
    end

    -- Validate the resulting configuration
    local valid, validation_error = schema_orchestrator.validate_complete_config(merged_config)
    if not valid then
        table.insert(self.validation_errors, validation_error)
        return false, "Profile validation failed: " .. validation_error
    end

    self.config = merged_config
    table.insert(self.applied_profiles, {
        name = profile_name,
        applied_at = os.time(),
        merged = merge_with_existing or false
    })

    performance_utils.log_message(self.config, "info",
        "Configuration profile applied successfully",
        {profile = profile_name, merged = merge_with_existing})

    return true, nil
end

--- Create a custom profile from current configuration
-- @param profile_name string name for the new profile
-- @param description string description of the profile
-- @return boolean success
-- @return string error message if failed
function ProfileManager:create_custom_profile(profile_name, description)
    if not profile_name or profile_name == "" then
        return false, "Profile name is required"
    end

    if not description or description == "" then
        return false, "Profile description is required"
    end

    -- Validate current configuration
    local valid, error_msg = schema_orchestrator.validate_complete_config(self.config)
    if not valid then
        return false, "Cannot create profile from invalid configuration: " .. error_msg
    end

    -- Store custom profile (in real implementation, this would persist to storage)
    local custom_profile = {
        name = profile_name,
        description = description,
        config = self.config,
        created_at = os.time(),
        created_by = "profile_manager"
    }

    -- Log profile creation
    performance_utils.log_message(self.config, "info",
        "Custom configuration profile created",
        {profile_name = profile_name, config_fields = self:_count_config_fields()})

    return true, nil
end

--- Get configuration wizard for guided setup
-- @param use_case string intended use case ("basic", "enterprise", "compliance", "performance")
-- @return table wizard steps
function ProfileManager:get_configuration_wizard(use_case)
    local wizard_steps = {}

    if use_case == "basic" then
        wizard_steps = {
            {
                step = 1,
                title = "Basic Threat Detection",
                description = "Configure essential security thresholds",
                fields = {
                    {name = "block_threshold", type = "number", default = 0.8, range = {0.5, 1.0}},
                    {name = "enable_ml_detection", type = "boolean", default = true},
                    {name = "log_level", type = "select", options = {"debug", "info", "warn", "error"}, default = "info"}
                }
            },
            {
                step = 2,
                title = "Monitoring Setup",
                description = "Configure logging and metrics",
                fields = {
                    {name = "enable_metrics", type = "boolean", default = true},
                    {name = "enable_notifications", type = "boolean", default = true},
                    {name = "notification_url", type = "string", optional = true}
                }
            }
        }
    elseif use_case == "enterprise" then
        wizard_steps = {
            {
                step = 1,
                title = "AI Integration",
                description = "Configure AI-powered threat detection",
                fields = {
                    {name = "enable_ai_gateway", type = "boolean", default = true},
                    {name = "ai_model", type = "select", options = {"claude-3-haiku", "gpt-4", "gemini-pro"}, default = "claude-3-haiku"},
                    {name = "ai_confidence_threshold", type = "number", default = 0.8, range = {0.5, 1.0}}
                }
            },
            {
                step = 2,
                title = "Performance Optimization",
                description = "Configure advanced performance features",
                fields = {
                    {name = "enable_adaptive_rate_limiting", type = "boolean", default = true},
                    {name = "enable_circuit_breaker", type = "boolean", default = true},
                    {name = "cache_config", type = "object", fields = {
                        {name = "max_cache_size_mb", type = "number", default = 128, range = {64, 512}}
                    }}
                }
            },
            {
                step = 3,
                title = "Enterprise Security",
                description = "Configure advanced security features",
                fields = {
                    {name = "enable_ddos_mitigation", type = "boolean", default = true},
                    {name = "enable_audit_log", type = "boolean", default = true},
                    {name = "enable_performance_monitoring", type = "boolean", default = true}
                }
            }
        }
    elseif use_case == "compliance" then
        wizard_steps = {
            {
                step = 1,
                title = "Compliance Framework Selection",
                description = "Choose applicable compliance frameworks",
                fields = {
                    {name = "enable_gdpr_compliance", type = "boolean", default = false},
                    {name = "enable_ccpa_compliance", type = "boolean", default = false},
                    {name = "enable_hipaa_compliance", type = "boolean", default = false},
                    {name = "enable_pci_compliance", type = "boolean", default = false},
                    {name = "enable_soc2_compliance", type = "boolean", default = false}
                }
            },
            {
                step = 2,
                title = "Privacy Configuration",
                description = "Configure privacy protection settings",
                fields = {
                    {name = "privacy_config", type = "object", fields = {
                        {name = "enable_pii_detection", type = "boolean", default = true},
                        {name = "anonymization_method", type = "select", options = {"mask", "hash", "encrypt"}, default = "hash"}
                    }}
                }
            },
            {
                step = 3,
                title = "Audit and Retention",
                description = "Configure audit logging and data retention",
                fields = {
                    {name = "enable_audit_log", type = "boolean", default = true},
                    {name = "gdpr_config", type = "object", fields = {
                        {name = "data_retention_days", type = "number", default = 30, range = {1, 2555}}
                    }}
                }
            }
        }
    else -- performance
        wizard_steps = {
            {
                step = 1,
                title = "Performance Thresholds",
                description = "Configure performance-optimized settings",
                fields = {
                    {name = "block_threshold", type = "number", default = 0.9, range = {0.8, 1.0}},
                    {name = "performance_sample_rate", type = "number", default = 0.01, range = {0.001, 0.1}}
                }
            },
            {
                step = 2,
                title = "Caching and Rate Limiting",
                description = "Optimize caching and rate limiting",
                fields = {
                    {name = "enable_adaptive_rate_limiting", type = "boolean", default = true},
                    {name = "cache_config", type = "object", fields = {
                        {name = "max_cache_size_mb", type = "number", default = 256, range = {128, 1024}},
                        {name = "threat_detection_ttl", type = "number", default = 600, range = {300, 3600}}
                    }}
                }
            }
        }
    end

    return wizard_steps
end

--- Apply wizard configuration step by step
-- @param wizard_data table configuration data from wizard
-- @return boolean success
-- @return string error message if failed
function ProfileManager:apply_wizard_configuration(wizard_data)
    if not wizard_data or not wizard_data.steps then
        return false, "Wizard data is required"
    end

    local config = {}

    -- Process each wizard step
    for _, step_data in ipairs(wizard_data.steps) do
        if step_data.values then
            for field_name, value in pairs(step_data.values) do
                -- Handle nested objects
                if type(value) == "table" and step_data.nested_fields then
                    if not config[field_name] then
                        config[field_name] = {}
                    end
                    for nested_field, nested_value in pairs(value) do
                        config[field_name][nested_field] = nested_value
                    end
                else
                    config[field_name] = value
                end
            end
        end
    end

    -- Validate the wizard configuration
    local valid, error_msg = schema_orchestrator.validate_complete_config(config)
    if not valid then
        table.insert(self.validation_errors, error_msg)
        return false, "Wizard configuration validation failed: " .. error_msg
    end

    self.config = config

    performance_utils.log_message(self.config, "info",
        "Wizard configuration applied successfully",
        {steps_completed = #wizard_data.steps, use_case = wizard_data.use_case or "unknown"})

    return true, nil
end

--- Get configuration validation report
-- @return table validation report with recommendations
function ProfileManager:get_validation_report()
    local report = {
        is_valid = true,
        errors = {},
        warnings = {},
        recommendations = {},
        score = 0
    }

    -- Validate current configuration
    local valid, error_msg = schema_orchestrator.validate_complete_config(self.config)
    if not valid then
        report.is_valid = false
        table.insert(report.errors, error_msg)
    end

    -- Add accumulated validation errors
    for _, error in ipairs(self.validation_errors) do
        table.insert(report.errors, error)
    end

    -- Generate recommendations based on configuration
    report.recommendations = self:_generate_recommendations()

    -- Calculate configuration score (0-100)
    report.score = self:_calculate_config_score()

    return report
end

--- Export current configuration
-- @param format string export format ("json", "yaml", "lua")
-- @return string exported configuration
-- @return boolean success
function ProfileManager:export_configuration(format)
    format = format or "json"

    local export_data = {
        configuration = self.config,
        applied_profiles = self.applied_profiles,
        exported_at = os.time(),
        version = "2.0.0"
    }

    if format == "json" then
        local cjson = require "cjson"
        return cjson.encode(export_data), true
    elseif format == "lua" then
        return "return " .. self:_table_to_lua_string(export_data), true
    else
        return nil, false, "Unsupported export format: " .. format
    end
end

-- Private methods

--- Get use cases for a profile
-- @param profile_name string profile name
-- @return table use cases
function ProfileManager:_get_profile_use_cases(profile_name)
    local use_cases = {
        basic_security = {"Small applications", "Development environments", "Simple APIs"},
        enterprise_ai = {"Large-scale applications", "High-security environments", "AI-powered threat detection"},
        gdpr_compliant = {"EU-based services", "Privacy-focused applications", "Data protection compliance"},
        high_performance = {"High-traffic sites", "Performance-critical applications", "Large-scale deployments"},
        development = {"Testing environments", "Development workflows", "Debugging scenarios"}
    }

    return use_cases[profile_name] or {"General purpose"}
end

--- Generate configuration recommendations
-- @return table recommendations list
function ProfileManager:_generate_recommendations()
    local recommendations = {}

    -- Check for AI gateway without API keys
    if self.config.enable_ai_gateway and not (self.config.claude_api_key or self.config.openai_api_key) then
        table.insert(recommendations, {
            type = "warning",
            message = "AI gateway is enabled but no API keys are configured",
            suggestion = "Add API keys for your chosen AI model"
        })
    end

    -- Check for compliance without audit logging
    if (self.config.enable_gdpr_compliance or self.config.enable_hipaa_compliance) and not self.config.enable_audit_log then
        table.insert(recommendations, {
            type = "error",
            message = "Compliance frameworks require audit logging",
            suggestion = "Enable audit logging for compliance requirements"
        })
    end

    -- Check performance settings
    if self.config.enable_adaptive_rate_limiting and not self.config.enable_ml_detection then
        table.insert(recommendations, {
            type = "info",
            message = "Adaptive rate limiting works best with ML detection enabled",
            suggestion = "Consider enabling ML detection for better adaptive behavior"
        })
    end

    return recommendations
end

--- Calculate configuration score
-- @return number score (0-100)
function ProfileManager:_calculate_config_score()
    local score = 0
    local max_score = 0

    -- Security features (30 points)
    max_score = max_score + 30
    if self.config.enable_ml_detection then score = score + 10 end
    if self.config.block_threshold and self.config.block_threshold > 0.7 then score = score + 10 end
    if self.config.enable_ddos_mitigation then score = score + 10 end

    -- Monitoring features (25 points)
    max_score = max_score + 25
    if self.config.enable_metrics then score = score + 10 end
    if self.config.enable_audit_log then score = score + 10 end
    if self.config.enable_notifications then score = score + 5 end

    -- Performance features (25 points)
    max_score = max_score + 25
    if self.config.enable_request_caching then score = score + 10 end
    if self.config.enable_adaptive_rate_limiting then score = score + 10 end
    if self.config.enable_circuit_breaker then score = score + 5 end

    -- Compliance features (20 points)
    max_score = max_score + 20
    if self.config.enable_gdpr_compliance or self.config.enable_ccpa_compliance then score = score + 10 end
    if self.config.privacy_config and self.config.privacy_config.enable_pii_detection then score = score + 10 end

    return math.floor((score / max_score) * 100)
end

--- Count configuration fields
-- @return number field count
function ProfileManager:_count_config_fields()
    local count = 0
    for _ in pairs(self.config) do
        count = count + 1
    end
    return count
end

--- Convert table to Lua string representation
-- @param tbl table to convert
-- @return string Lua representation
function ProfileManager:_table_to_lua_string(tbl)
    local function serialize(obj, depth)
        depth = depth or 0
        local indent = string.rep("  ", depth)

        if type(obj) == "table" then
            local result = "{\n"
            for k, v in pairs(obj) do
                result = result .. indent .. "  "
                if type(k) == "string" then
                    result = result .. '["' .. k .. '"] = '
                else
                    result = result .. "[" .. tostring(k) .. "] = "
                end
                result = result .. serialize(v, depth + 1) .. ",\n"
            end
            result = result .. indent .. "}"
            return result
        elseif type(obj) == "string" then
            return '"' .. obj .. '"'
        else
            return tostring(obj)
        end
    end

    return serialize(tbl)
end

return ProfileManager
