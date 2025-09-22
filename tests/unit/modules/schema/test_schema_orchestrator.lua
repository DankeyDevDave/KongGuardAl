-- Unit tests for schema orchestrator module
-- Tests the modular schema architecture and configuration profiles

local lu = require('luaunit')

-- Mock require for testing
local original_require = require
local mock_modules = {}

-- Mock schema modules
mock_modules["kong.plugins.kong-guard-ai.modules.schema.threat_detection_schema"] = {
    get_fields = function()
        return {
            {block_threshold = {type = "number", default = 0.8}},
            {enable_ml_detection = {type = "boolean", default = true}}
        }
    end,
    get_defaults = function()
        return {block_threshold = 0.8, enable_ml_detection = true}
    end,
    validate_config = function(config)
        if config.block_threshold and (config.block_threshold < 0 or config.block_threshold > 1) then
            return false, "block_threshold must be between 0 and 1"
        end
        return true
    end
}

mock_modules["kong.plugins.kong-guard-ai.modules.schema.ai_integration_schema"] = {
    get_fields = function()
        return {
            {enable_ai_gateway = {type = "boolean", default = false}},
            {ai_timeout = {type = "integer", default = 500}}
        }
    end,
    get_defaults = function()
        return {enable_ai_gateway = false, ai_timeout = 500}
    end,
    validate_config = function(config)
        if config.ai_timeout and config.ai_timeout < 100 then
            return false, "ai_timeout must be at least 100ms"
        end
        return true
    end,
    get_ai_models = function()
        return {
            ["claude-3-haiku"] = {provider = "anthropic", max_tokens = 4000}
        }
    end
}

mock_modules["kong.plugins.kong-guard-ai.modules.schema.monitoring_schema"] = {
    get_fields = function()
        return {
            {enable_metrics = {type = "boolean", default = true}},
            {log_level = {type = "string", default = "info"}}
        }
    end,
    get_defaults = function()
        return {enable_metrics = true, log_level = "info"}
    end,
    validate_config = function(config)
        return true
    end,
    get_metrics_definitions = function()
        return {
            {name = "requests_total", type = "counter"}
        }
    end
}

mock_modules["kong.plugins.kong-guard-ai.modules.schema.performance_schema"] = {
    get_fields = function()
        return {
            {enable_request_caching = {type = "boolean", default = true}},
            {circuit_breaker = {type = "record", fields = {}}}
        }
    end,
    get_defaults = function()
        return {
            enable_request_caching = true,
            circuit_breaker = {timeout = 30}
        }
    end,
    validate_config = function(config)
        return true
    end
}

mock_modules["kong.plugins.kong-guard-ai.modules.schema.compliance_schema"] = {
    get_fields = function()
        return {
            {enable_gdpr_compliance = {type = "boolean", default = false}},
            {enable_audit_log = {type = "boolean", default = true}}
        }
    end,
    get_defaults = function()
        return {enable_gdpr_compliance = false, enable_audit_log = true}
    end,
    validate_config = function(config)
        return true
    end,
    get_compliance_frameworks = function()
        return {
            gdpr = {name = "GDPR", jurisdiction = "EU"}
        }
    end
}

-- Override require to use mocks
_G.require = function(module_name)
    if mock_modules[module_name] then
        return mock_modules[module_name]
    end
    return original_require(module_name)
end

local schema_orchestrator = require('kong.plugins.kong-guard-ai.modules.schema.schema_orchestrator')

TestSchemaOrchestrator = {}

function TestSchemaOrchestrator:setUp()
    -- Reset any state if needed
end

function TestSchemaOrchestrator:tearDown()
    -- Clean up
end

function TestSchemaOrchestrator:test_get_complete_schema()
    local schema = schema_orchestrator.get_complete_schema()
    
    lu.assertIsTable(schema)
    lu.assertTrue(#schema > 0)
    
    -- Should contain fields from all modules
    local field_names = {}
    for _, field in ipairs(schema) do
        for key, _ in pairs(field) do
            table.insert(field_names, key)
        end
    end
    
    -- Check for fields from different modules
    lu.assertContains(field_names, "block_threshold") -- threat detection
    lu.assertContains(field_names, "enable_ai_gateway") -- AI integration
    lu.assertContains(field_names, "enable_metrics") -- monitoring
    lu.assertContains(field_names, "enable_request_caching") -- performance
    lu.assertContains(field_names, "enable_gdpr_compliance") -- compliance
end

function TestSchemaOrchestrator:test_get_all_defaults()
    local defaults = schema_orchestrator.get_all_defaults()
    
    lu.assertIsTable(defaults)
    
    -- Should contain defaults from all modules
    lu.assertEquals(defaults.block_threshold, 0.8)
    lu.assertEquals(defaults.enable_ai_gateway, false)
    lu.assertEquals(defaults.enable_metrics, true)
    lu.assertEquals(defaults.enable_request_caching, true)
    lu.assertEquals(defaults.enable_gdpr_compliance, false)
end

function TestSchemaOrchestrator:test_validate_complete_config_valid()
    local valid_config = {
        block_threshold = 0.7,
        enable_ai_gateway = true,
        ai_timeout = 1000,
        enable_metrics = true,
        log_level = "info"
    }
    
    local valid, error_msg = schema_orchestrator.validate_complete_config(valid_config)
    lu.assertTrue(valid)
    lu.assertNil(error_msg)
end

function TestSchemaOrchestrator:test_validate_complete_config_invalid()
    local invalid_config = {
        block_threshold = 1.5, -- Invalid - should be between 0 and 1
        ai_timeout = 50 -- Invalid - should be at least 100
    }
    
    local valid, error_msg = schema_orchestrator.validate_complete_config(invalid_config)
    lu.assertFalse(valid)
    lu.assertIsString(error_msg)
    lu.assertStrContains(error_msg, "block_threshold")
end

function TestSchemaOrchestrator:test_validate_cross_module_dependencies()
    -- Test AI timeout vs circuit breaker timeout
    local config_with_conflict = {
        enable_ai_gateway = true,
        ai_timeout = 60000, -- 60 seconds
        circuit_breaker = {timeout = 30} -- 30 seconds
    }
    
    local valid, error_msg = schema_orchestrator.validate_complete_config(config_with_conflict)
    lu.assertFalse(valid)
    lu.assertStrContains(error_msg, "AI timeout cannot exceed circuit breaker timeout")
end

function TestSchemaOrchestrator:test_get_configuration_profiles()
    local profiles = schema_orchestrator.get_configuration_profiles()
    
    lu.assertIsTable(profiles)
    
    -- Check for expected profiles
    lu.assertNotNil(profiles.basic_security)
    lu.assertNotNil(profiles.enterprise_ai)
    lu.assertNotNil(profiles.gdpr_compliant)
    lu.assertNotNil(profiles.high_performance)
    lu.assertNotNil(profiles.development)
    
    -- Validate profile structure
    local basic_profile = profiles.basic_security
    lu.assertIsString(basic_profile.name)
    lu.assertIsString(basic_profile.description)
    lu.assertIsTable(basic_profile.config)
    
    -- Check profile configuration makes sense
    lu.assertFalse(basic_profile.config.enable_ai_gateway) -- Basic shouldn't have AI
    lu.assertTrue(profiles.enterprise_ai.config.enable_ai_gateway) -- Enterprise should have AI
end

function TestSchemaOrchestrator:test_apply_configuration_profile_success()
    local base_config = {
        custom_setting = "test",
        block_threshold = 0.9
    }
    
    local merged_config, success, error_msg = schema_orchestrator.apply_configuration_profile("basic_security", base_config)
    
    lu.assertTrue(success)
    lu.assertNil(error_msg)
    lu.assertIsTable(merged_config)
    
    -- Should preserve base config
    lu.assertEquals(merged_config.custom_setting, "test")
    
    -- Should apply profile config (profile should override base)
    lu.assertNotEquals(merged_config.block_threshold, 0.9) -- Should be overridden by profile
    lu.assertFalse(merged_config.enable_ai_gateway) -- From basic_security profile
end

function TestSchemaOrchestrator:test_apply_configuration_profile_invalid()
    local merged_config, success, error_msg = schema_orchestrator.apply_configuration_profile("nonexistent_profile", {})
    
    lu.assertFalse(success)
    lu.assertIsString(error_msg)
    lu.assertStrContains(error_msg, "Unknown configuration profile")
    lu.assertNil(merged_config)
end

function TestSchemaOrchestrator:test_apply_configuration_profile_deep_merge()
    local base_config = {
        cache_config = {
            existing_setting = "keep_me",
            max_cache_size_mb = 32
        }
    }
    
    -- Assume high_performance profile has cache_config with different settings
    mock_modules["kong.plugins.kong-guard-ai.modules.schema.performance_schema"].get_defaults = function()
        return {
            enable_request_caching = true,
            cache_config = {
                threat_detection_ttl = 600,
                max_cache_size_mb = 128
            }
        }
    end
    
    -- Update the profile to include cache config
    local original_get_profiles = schema_orchestrator.get_configuration_profiles
    schema_orchestrator.get_configuration_profiles = function()
        local profiles = original_get_profiles()
        profiles.high_performance.config.cache_config = {
            threat_detection_ttl = 600,
            max_cache_size_mb = 128
        }
        return profiles
    end
    
    local merged_config, success, error_msg = schema_orchestrator.apply_configuration_profile("high_performance", base_config)
    
    lu.assertTrue(success)
    lu.assertIsTable(merged_config.cache_config)
    
    -- Should preserve base config nested values
    lu.assertEquals(merged_config.cache_config.existing_setting, "keep_me")
    
    -- Should merge profile nested values
    lu.assertEquals(merged_config.cache_config.threat_detection_ttl, 600)
    lu.assertEquals(merged_config.cache_config.max_cache_size_mb, 128) -- Profile should override
end

function TestSchemaOrchestrator:test_get_schema_documentation()
    local docs = schema_orchestrator.get_schema_documentation()
    
    lu.assertIsTable(docs)
    
    -- Should contain documentation from all modules
    lu.assertIsTable(docs.threat_detection)
    lu.assertIsTable(docs.ai_integration)
    lu.assertIsTable(docs.monitoring)
    lu.assertIsTable(docs.performance)
    lu.assertIsTable(docs.compliance)
    
    -- Should contain additional documentation
    lu.assertIsTable(docs.profiles)
    lu.assertIsTable(docs.ai_models)
    lu.assertIsTable(docs.compliance_frameworks)
    lu.assertIsTable(docs.metrics)
end

function TestSchemaOrchestrator:test_edge_cases()
    -- Test with nil config
    local valid, error_msg = schema_orchestrator.validate_complete_config(nil)
    lu.assertFalse(valid)
    lu.assertStrContains(error_msg, "Configuration is required")
    
    -- Test with empty config
    local valid2, error_msg2 = schema_orchestrator.validate_complete_config({})
    lu.assertTrue(valid2) -- Empty config should be valid (uses defaults)
    
    -- Test apply profile with nil base config
    local merged_config, success, error_msg3 = schema_orchestrator.apply_configuration_profile("basic_security", nil)
    lu.assertTrue(success)
    lu.assertIsTable(merged_config)
end

-- Restore original require
_G.require = original_require

-- Helper function to check if a table contains a value
function TestSchemaOrchestrator:assertContains(table_list, value)
    for _, item in ipairs(table_list) do
        if item == value then
            return
        end
    end
    lu.fail("Value '" .. tostring(value) .. "' not found in table")
end

-- Run tests when file is executed directly
if arg and arg[0]:match("test_schema_orchestrator.lua$") then
    os.exit(lu.LuaUnit.run())
end

return TestSchemaOrchestrator