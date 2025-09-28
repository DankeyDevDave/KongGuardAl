-- Schema Orchestrator Module
-- Combines all modular schemas into the main plugin schema

local threat_detection_schema = require "kong.plugins.kong-guard-ai.modules.schema.threat_detection_schema"
local ai_integration_schema = require "kong.plugins.kong-guard-ai.modules.schema.ai_integration_schema"
local monitoring_schema = require "kong.plugins.kong-guard-ai.modules.schema.monitoring_schema"
local performance_schema = require "kong.plugins.kong-guard-ai.modules.schema.performance_schema"
local compliance_schema = require "kong.plugins.kong-guard-ai.modules.schema.compliance_schema"

local _M = {}

--- Combine all schema modules into the main configuration schema
-- @return table complete configuration schema
function _M.get_complete_schema()
    local fields = {}
    
    -- Add threat detection fields
    local threat_fields = threat_detection_schema.get_fields()
    for _, field in ipairs(threat_fields) do
        table.insert(fields, field)
    end
    
    -- Add AI integration fields
    local ai_fields = ai_integration_schema.get_fields()
    for _, field in ipairs(ai_fields) do
        table.insert(fields, field)
    end
    
    -- Add monitoring fields
    local monitoring_fields = monitoring_schema.get_fields()
    for _, field in ipairs(monitoring_fields) do
        table.insert(fields, field)
    end
    
    -- Add performance fields
    local performance_fields = performance_schema.get_fields()
    for _, field in ipairs(performance_fields) do
        table.insert(fields, field)
    end
    
    -- Add compliance fields
    local compliance_fields = compliance_schema.get_fields()
    for _, field in ipairs(compliance_fields) do
        table.insert(fields, field)
    end
    
    return fields
end

--- Get all default configuration values
-- @return table complete default configuration
function _M.get_all_defaults()
    local defaults = {}
    
    -- Merge all default configurations
    local threat_defaults = threat_detection_schema.get_defaults()
    local ai_defaults = ai_integration_schema.get_defaults()
    local monitoring_defaults = monitoring_schema.get_defaults()
    local performance_defaults = performance_schema.get_defaults()
    local compliance_defaults = compliance_schema.get_defaults()
    
    -- Merge all defaults into one table
    for key, value in pairs(threat_defaults) do
        defaults[key] = value
    end
    
    for key, value in pairs(ai_defaults) do
        defaults[key] = value
    end
    
    for key, value in pairs(monitoring_defaults) do
        defaults[key] = value
    end
    
    for key, value in pairs(performance_defaults) do
        defaults[key] = value
    end
    
    for key, value in pairs(compliance_defaults) do
        defaults[key] = value
    end
    
    return defaults
end

--- Validate complete configuration across all modules
-- @param config table configuration to validate
-- @return boolean true if valid
-- @return string error message if invalid
function _M.validate_complete_config(config)
    if not config then
        return false, "Configuration is required"
    end
    
    -- Validate each module's configuration
    local validators = {
        {name = "threat_detection", validator = threat_detection_schema.validate_config},
        {name = "ai_integration", validator = ai_integration_schema.validate_config},
        {name = "monitoring", validator = monitoring_schema.validate_config},
        {name = "performance", validator = performance_schema.validate_config},
        {name = "compliance", validator = compliance_schema.validate_config}
    }
    
    for _, validator_info in ipairs(validators) do
        local valid, error_msg = validator_info.validator(config)
        if not valid then
            return false, validator_info.name .. ": " .. error_msg
        end
    end
    
    -- Cross-module validation
    local cross_validation_result, cross_error = _M._validate_cross_module_dependencies(config)
    if not cross_validation_result then
        return false, "Cross-module validation: " .. cross_error
    end
    
    return true
end

--- Validate cross-module dependencies
-- @param config table configuration to validate
-- @return boolean true if valid
-- @return string error message if invalid
function _M._validate_cross_module_dependencies(config)
    -- AI and performance validation
    if config.enable_ai_gateway and config.ai_timeout then
        if config.circuit_breaker and config.circuit_breaker.timeout then
            if config.ai_timeout > (config.circuit_breaker.timeout * 1000) then
                return false, "AI timeout cannot exceed circuit breaker timeout"
            end
        end
    end
    
    -- Compliance and monitoring validation
    if config.enable_gdpr_compliance or config.enable_hipaa_compliance or config.enable_soc2_compliance then
        if not config.enable_audit_log then
            return false, "Audit logging is required for compliance frameworks"
        end
    end
    
    -- Performance and threat detection validation
    if config.enable_adaptive_rate_limiting and not config.enable_ml_detection then
        return false, "ML detection is required for adaptive rate limiting"
    end
    
    -- AI and compliance validation
    if config.enable_ai_gateway and (config.enable_hipaa_compliance or config.enable_pci_compliance) then
        if not config.enable_data_encryption then
            return false, "Data encryption is required when using AI with HIPAA or PCI compliance"
        end
    end
    
    -- Cache and memory validation
    if config.cache_config and config.memory_management then
        local cache_size_mb = config.cache_config.max_cache_size_mb or 64
        local max_memory_mb = config.memory_management.max_memory_usage_mb or 256
        
        if cache_size_mb > (max_memory_mb * 0.5) then
            return false, "Cache size cannot exceed 50% of maximum memory usage"
        end
    end
    
    return true
end

--- Get configuration profiles for common use cases
-- @return table configuration profiles
function _M.get_configuration_profiles()
    return {
        basic_security = {
            name = "Basic Security",
            description = "Essential threat detection with minimal overhead",
            config = {
                -- Threat Detection
                enable_ml_detection = true,
                block_threshold = 0.8,
                rate_limit_threshold = 0.6,
                
                -- Monitoring
                enable_metrics = true,
                log_level = "info",
                
                -- Performance
                enable_request_caching = true,
                
                -- AI disabled for basic profile
                enable_ai_gateway = false
            }
        },
        
        enterprise_ai = {
            name = "Enterprise AI Protection",
            description = "Full AI-powered threat detection with advanced features",
            config = {
                -- Threat Detection
                enable_ml_detection = true,
                block_threshold = 0.85,
                rate_limit_threshold = 0.7,
                
                -- AI Integration
                enable_ai_gateway = true,
                ai_model = "claude-3-haiku",
                ai_confidence_threshold = 0.8,
                
                -- Performance
                enable_adaptive_rate_limiting = true,
                enable_circuit_breaker = true,
                enable_request_caching = true,
                
                -- Monitoring
                enable_metrics = true,
                enable_performance_monitoring = true,
                log_level = "info"
            }
        },
        
        gdpr_compliant = {
            name = "GDPR Compliant",
            description = "GDPR compliance with privacy protection",
            config = {
                -- Compliance
                enable_gdpr_compliance = true,
                gdpr_config = {
                    data_retention_days = 30,
                    enable_consent_management = true,
                    enable_right_to_be_forgotten = true
                },
                
                -- Privacy
                privacy_config = {
                    enable_pii_detection = true,
                    anonymization_method = "hash"
                },
                
                -- Monitoring
                enable_audit_log = true,
                audit_log_format = "json",
                
                -- Basic threat detection
                enable_ml_detection = true,
                block_threshold = 0.8
            }
        },
        
        high_performance = {
            name = "High Performance",
            description = "Optimized for high-throughput environments",
            config = {
                -- Performance
                enable_adaptive_rate_limiting = true,
                adaptive_rate_config = {
                    base_rate_per_minute = 1000,
                    max_rate_per_minute = 10000
                },
                enable_request_caching = true,
                cache_config = {
                    threat_detection_ttl = 600,
                    max_cache_size_mb = 128
                },
                
                -- Threat Detection (optimized)
                enable_ml_detection = true,
                block_threshold = 0.9, -- Higher threshold for fewer false positives
                
                -- Monitoring (reduced)
                enable_metrics = true,
                performance_sample_rate = 0.01, -- 1% sampling
                log_level = "warn"
            }
        },
        
        development = {
            name = "Development",
            description = "Development environment with detailed logging",
            config = {
                -- Development settings
                dry_run = true,
                
                -- Detailed monitoring
                log_level = "debug",
                enable_audit_log = true,
                enable_performance_monitoring = true,
                
                -- Relaxed thresholds
                block_threshold = 0.95,
                rate_limit_threshold = 0.9,
                
                -- Basic features only
                enable_ml_detection = true,
                enable_ai_gateway = false,
                enable_metrics = true
            }
        }
    }
end

--- Apply a configuration profile
-- @param profile_name string name of the profile to apply
-- @param base_config table existing configuration to merge with
-- @return table merged configuration
-- @return boolean true if successful
-- @return string error message if failed
function _M.apply_configuration_profile(profile_name, base_config)
    local profiles = _M.get_configuration_profiles()
    local profile = profiles[profile_name]
    
    if not profile then
        return nil, false, "Unknown configuration profile: " .. profile_name
    end
    
    local merged_config = base_config or {}
    
    -- Merge profile configuration with base configuration
    for key, value in pairs(profile.config) do
        if type(value) == "table" and type(merged_config[key]) == "table" then
            -- Deep merge for nested tables
            for nested_key, nested_value in pairs(value) do
                if not merged_config[key] then
                    merged_config[key] = {}
                end
                merged_config[key][nested_key] = nested_value
            end
        else
            merged_config[key] = value
        end
    end
    
    return merged_config, true, nil
end

--- Get schema documentation
-- @return table documentation for all configuration options
function _M.get_schema_documentation()
    return {
        threat_detection = threat_detection_schema.get_fields(),
        ai_integration = ai_integration_schema.get_fields(),
        monitoring = monitoring_schema.get_fields(),
        performance = performance_schema.get_fields(),
        compliance = compliance_schema.get_fields(),
        profiles = _M.get_configuration_profiles(),
        ai_models = ai_integration_schema.get_ai_models(),
        compliance_frameworks = compliance_schema.get_compliance_frameworks(),
        metrics = monitoring_schema.get_metrics_definitions()
    }
end

return _M