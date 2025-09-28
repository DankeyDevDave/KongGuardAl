-- Configuration Profile Manager Tests
-- Comprehensive test suite for profile management functionality

local ProfileManager = require "kong.plugins.kong-guard-ai.modules.config.profile_manager"

describe("ProfileManager", function()
    local manager

    before_each(function()
        manager = ProfileManager.new({
            ai_enabled = false,
            threat_detection_enabled = true
        })
    end)

    describe("initialization", function()
        it("should create new instance with default config", function()
            local default_manager = ProfileManager.new()
            assert.is_not_nil(default_manager)
            assert.is_table(default_manager.config)
        end)

        it("should create new instance with provided config", function()
            local config = { test_option = true }
            local test_manager = ProfileManager.new(config)
            assert.equals(true, test_manager.config.test_option)
        end)

        it("should initialize empty applied_profiles list", function()
            assert.is_table(manager.applied_profiles)
            assert.equals(0, #manager.applied_profiles)
        end)

        it("should initialize empty validation_errors list", function()
            assert.is_table(manager.validation_errors)
            assert.equals(0, #manager.validation_errors)
        end)
    end)

    describe("get_available_profiles", function()
        it("should return list of available profiles", function()
            local profiles = manager:get_available_profiles()
            assert.is_table(profiles)
            assert.is_true(#profiles > 0)
        end)

        it("should include profile metadata", function()
            local profiles = manager:get_available_profiles()
            local first_profile = profiles[1]

            assert.is_string(first_profile.name)
            assert.is_string(first_profile.title)
            assert.is_string(first_profile.description)
            assert.is_table(first_profile.suitable_for)
        end)
    end)

    describe("apply_profile", function()
        it("should apply basic_security profile successfully", function()
            local success, error_msg = manager:apply_profile("basic_security", false)
            assert.is_true(success)
            assert.is_nil(error_msg)
        end)

        it("should merge with existing config when requested", function()
            manager.config.custom_setting = "test_value"
            local success = manager:apply_profile("basic_security", true)

            assert.is_true(success)
            assert.equals("test_value", manager.config.custom_setting)
        end)

        it("should replace config when merge_with_existing is false", function()
            manager.config.custom_setting = "test_value"
            local success = manager:apply_profile("basic_security", false)

            assert.is_true(success)
            assert.is_nil(manager.config.custom_setting)
        end)

        it("should return error for invalid profile", function()
            local success, error_msg = manager:apply_profile("invalid_profile", false)
            assert.is_false(success)
            assert.is_string(error_msg)
        end)
    end)

    describe("validate_current_config", function()
        it("should validate basic configuration", function()
            manager:apply_profile("basic_security", false)
            local valid, errors = manager:validate_current_config()

            if not valid then
                for _, error in ipairs(errors) do
                    print("Validation error: " .. error)
                end
            end
            assert.is_true(valid)
        end)

        it("should detect invalid configuration", function()
            manager.config = {
                ai_enabled = "invalid_type", -- should be boolean
                threat_detection_enabled = true
            }

            local valid, errors = manager:validate_current_config()
            assert.is_false(valid)
            assert.is_table(errors)
            assert.is_true(#errors > 0)
        end)
    end)

    describe("get_config_recommendations", function()
        it("should provide recommendations for basic config", function()
            local recommendations = manager:get_config_recommendations()
            assert.is_table(recommendations)
        end)

        it("should include performance recommendations", function()
            manager.config.ai_enabled = true
            manager.config.ai_timeout = 30.0 -- Too high

            local recommendations = manager:get_config_recommendations()
            local has_performance_rec = false

            for _, rec in ipairs(recommendations) do
                if rec.category == "performance" then
                    has_performance_rec = true
                    break
                end
            end

            assert.is_true(has_performance_rec)
        end)
    end)

    describe("create_custom_profile", function()
        it("should create custom profile from current config", function()
            manager:apply_profile("basic_security", false)

            local profile_name = "my_custom_profile"
            local success = manager:create_custom_profile(profile_name, "Test profile")

            assert.is_true(success)
            assert.is_not_nil(manager.custom_profiles[profile_name])
        end)

        it("should validate custom profile", function()
            manager.config = {
                ai_enabled = "invalid" -- Invalid type
            }

            local success, error_msg = manager:create_custom_profile("invalid_profile", "Test")
            assert.is_false(success)
            assert.is_string(error_msg)
        end)
    end)

    describe("export_config", function()
        it("should export config in JSON format", function()
            manager:apply_profile("basic_security", false)

            local exported = manager:export_config("json")
            assert.is_string(exported)

            -- Should be valid JSON
            local success, parsed = pcall(function()
                return require("cjson").decode(exported)
            end)
            assert.is_true(success)
            assert.is_table(parsed)
        end)

        it("should export config in YAML format", function()
            manager:apply_profile("basic_security", false)

            local exported = manager:export_config("yaml")
            assert.is_string(exported)
            assert.is_true(string.find(exported, "ai_enabled:") ~= nil)
        end)

        it("should export config in Lua format", function()
            manager:apply_profile("basic_security", false)

            local exported = manager:export_config("lua")
            assert.is_string(exported)
            assert.is_true(string.find(exported, "return {") ~= nil)
        end)
    end)

    describe("import_config", function()
        it("should import JSON config", function()
            local json_config = '{"ai_enabled": true, "threat_detection_enabled": false}'

            local success = manager:import_config(json_config, "json")
            assert.is_true(success)
            assert.is_true(manager.config.ai_enabled)
            assert.is_false(manager.config.threat_detection_enabled)
        end)

        it("should validate imported config", function()
            local invalid_json = '{"ai_enabled": "invalid_type"}'

            local success, error_msg = manager:import_config(invalid_json, "json")
            assert.is_false(success)
            assert.is_string(error_msg)
        end)
    end)

    describe("configuration wizard", function()
        it("should start configuration wizard", function()
            local wizard = manager:start_configuration_wizard()
            assert.is_table(wizard)
            assert.is_string(wizard.current_step)
            assert.is_table(wizard.questions)
        end)

        it("should process wizard answers", function()
            local wizard = manager:start_configuration_wizard()

            local answers = {
                use_case = "web_application",
                traffic_volume = "medium",
                compliance_required = false,
                ai_features = true
            }

            local success = manager:process_wizard_answers(wizard, answers)
            assert.is_true(success)
        end)
    end)

    describe("profile comparison", function()
        it("should compare two profiles", function()
            local comparison = manager:compare_profiles("basic_security", "enterprise_ai")

            assert.is_table(comparison)
            assert.is_table(comparison.differences)
            assert.is_table(comparison.common_settings)
        end)

        it("should identify key differences", function()
            local comparison = manager:compare_profiles("basic_security", "enterprise_ai")

            -- Should find AI-related differences
            local ai_difference_found = false
            for _, diff in ipairs(comparison.differences) do
                if string.find(diff.field, "ai") then
                    ai_difference_found = true
                    break
                end
            end

            assert.is_true(ai_difference_found)
        end)
    end)

    describe("error handling", function()
        it("should handle nil config gracefully", function()
            local nil_manager = ProfileManager.new(nil)
            assert.is_table(nil_manager.config)
        end)

        it("should handle invalid profile names", function()
            local success, error_msg = manager:apply_profile("", false)
            assert.is_false(success)
            assert.is_string(error_msg)
        end)

        it("should handle export errors gracefully", function()
            manager.config = {
                circular_ref = {}
            }
            manager.config.circular_ref.self = manager.config.circular_ref

            local exported = manager:export_config("json")
            -- Should handle circular references without crashing
            assert.is_string(exported)
        end)
    end)

    describe("performance", function()
        it("should handle large configurations efficiently", function()
            -- Create large config
            local large_config = {}
            for i = 1, 1000 do
                large_config["setting_" .. i] = "value_" .. i
            end

            local large_manager = ProfileManager.new(large_config)

            local start_time = os.clock()
            large_manager:validate_current_config()
            local end_time = os.clock()

            -- Should complete within reasonable time (1 second)
            assert.is_true((end_time - start_time) < 1.0)
        end)

        it("should cache profile data efficiently", function()
            -- First call
            local start_time = os.clock()
            manager:get_available_profiles()
            local first_call_time = os.clock() - start_time

            -- Second call (should be cached)
            start_time = os.clock()
            manager:get_available_profiles()
            local second_call_time = os.clock() - start_time

            -- Second call should be faster (cached)
            assert.is_true(second_call_time <= first_call_time)
        end)
    end)
end)
