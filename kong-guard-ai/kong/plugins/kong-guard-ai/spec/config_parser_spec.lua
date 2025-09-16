-- Kong Guard AI Configuration Parser Test Suite
-- Comprehensive tests for configuration parsing, validation, and error handling

describe("Kong Guard AI Configuration Parser", function()
    local config_parser
    local config_loader
    local config_errors

    setup(function()
        config_parser = require "kong.plugins.kong-guard-ai.config_parser"
        config_loader = require "kong.plugins.kong-guard-ai.config_loader"
        config_errors = require "kong.plugins.kong-guard-ai.config_errors"
    end)

    describe("Configuration Parsing", function()
        it("should parse valid configuration table", function()
            local input_config = {
                dry_run_mode = true,
                threat_threshold = 8.0,
                rate_limit_threshold = 150
            }

            local config, errors = config_parser.parse_config(input_config)

            assert.is_nil(errors)
            assert.is_not_nil(config)
            assert.is_true(config.dry_run_mode)
            assert.are.equal(8.0, config.threat_threshold)
            assert.are.equal(150, config.rate_limit_threshold)
        end)

        it("should parse valid JSON string configuration", function()
            local json_config = '{"dry_run_mode": false, "threat_threshold": 6.5}'

            local config, errors = config_parser.parse_config(json_config)

            assert.is_nil(errors)
            assert.is_not_nil(config)
            assert.is_false(config.dry_run_mode)
            assert.are.equal(6.5, config.threat_threshold)
        end)

        it("should merge configuration with defaults", function()
            local input_config = {
                threat_threshold = 9.0
            }

            local config, errors = config_parser.parse_config(input_config)

            assert.is_nil(errors)
            assert.is_not_nil(config)
            assert.are.equal(9.0, config.threat_threshold)
            assert.are.equal(false, config.dry_run_mode) -- Should use default
            assert.are.equal(100, config.rate_limit_threshold) -- Should use default
        end)

        it("should reject invalid JSON", function()
            local invalid_json = '{"invalid": json}'

            local config, errors = config_parser.parse_config(invalid_json)

            assert.is_nil(config)
            assert.is_not_nil(errors)
            assert.is_table(errors)
            assert.is_true(#errors > 0)
        end)

        it("should reject invalid configuration type", function()
            local invalid_config = "not a table or json"

            local config, errors = config_parser.parse_config(invalid_config)

            assert.is_nil(config)
            assert.is_not_nil(errors)
            assert.is_table(errors)
        end)
    end)

    describe("Configuration Validation", function()
        it("should validate numeric ranges", function()
            local config_with_invalid_threshold = {
                threat_threshold = 15.0 -- Should be between 1.0 and 10.0
            }

            local config, errors = config_parser.parse_config(config_with_invalid_threshold)

            assert.is_nil(config)
            assert.is_not_nil(errors)
            assert.is_true(#errors > 0)
        end)

        it("should validate enum values", function()
            local config_with_invalid_log_level = {
                log_level = "invalid_level"
            }

            local config, errors = config_parser.parse_config(config_with_invalid_log_level)

            assert.is_nil(config)
            assert.is_not_nil(errors)
        end)

        it("should validate IP addresses", function()
            local config_with_invalid_ip = {
                ip_whitelist = { "203.0.113.1", "invalid.ip.address", "198.51.100.0/24" }
            }

            local config, errors = config_parser.parse_config(config_with_invalid_ip)

            assert.is_nil(config)
            assert.is_not_nil(errors)
        end)

        it("should validate email addresses", function()
            local config_with_invalid_email = {
                email_to = { "valid@example.com", "invalid-email" }
            }

            local config, errors = config_parser.parse_config(config_with_invalid_email)

            assert.is_nil(config)
            assert.is_not_nil(errors)
        end)

        it("should validate URL formats", function()
            local config_with_invalid_url = {
                webhook_urls = { "https://valid.example.com", "not-a-url" }
            }

            local config, errors = config_parser.parse_config(config_with_invalid_url)

            assert.is_nil(config)
            assert.is_not_nil(errors)
        end)

        it("should validate regex patterns", function()
            local config_with_invalid_pattern = {
                suspicious_patterns = { "valid.*pattern", "[invalid regex" }
            }

            local config, errors = config_parser.parse_config(config_with_invalid_pattern)

            assert.is_nil(config)
            assert.is_not_nil(errors)
        end)

        it("should validate conditional requirements", function()
            local config_with_missing_ai_endpoint = {
                ai_gateway_enabled = true
                -- Missing ai_gateway_endpoint
            }

            local config, errors = config_parser.parse_config(config_with_missing_ai_endpoint)

            assert.is_nil(config)
            assert.is_not_nil(errors)
        end)
    end)

    describe("Configuration Loading", function()
        it("should load from plugin config", function()
            local plugin_config = {
                dry_run_mode = true,
                threat_threshold = 7.5
            }

            local config, errors = config_loader.load_from_plugin_config(plugin_config)

            assert.is_nil(errors)
            assert.is_not_nil(config)
            assert.is_true(config.dry_run_mode)
        end)

        it("should handle nil plugin config", function()
            local config, errors = config_loader.load_from_plugin_config(nil)

            assert.is_nil(config)
            assert.is_not_nil(errors)
        end)

        it("should initialize with fallback strategies", function()
            local options = {
                primary_strategy = "invalid_strategy",
                fallback_strategies = { "plugin_config" }
            }

            local config, errors = config_loader.initialize({dry_run_mode = true}, options)

            -- Should succeed with fallback
            assert.is_not_nil(config)
        end)
    end)

    describe("Configuration Caching", function()
        it("should cache parsed configurations", function()
            local test_config = { threat_threshold = 8.0 }

            -- Load configuration (should cache it)
            local config1, errors1 = config_loader.load_config(test_config, "test_cache")
            assert.is_nil(errors1)
            assert.is_not_nil(config1)

            -- Get cached configuration
            local cached_config = config_parser.get_cached_config("test_cache")
            assert.is_not_nil(cached_config)
            assert.are.equal(8.0, cached_config.threat_threshold)
        end)

        it("should clear cache when requested", function()
            local test_config = { threat_threshold = 6.0 }

            -- Load and cache configuration
            config_loader.load_config(test_config, "clear_test")

            -- Verify cached
            local cached = config_parser.get_cached_config("clear_test")
            assert.is_not_nil(cached)

            -- Clear cache
            config_parser.clear_cache("clear_test")

            -- Verify cleared
            local cleared = config_parser.get_cached_config("clear_test")
            assert.is_nil(cleared)
        end)
    end)

    describe("Error Handling", function()
        it("should create error objects with correct structure", function()
            local error_obj = config_errors.create_error(
                config_errors.ERROR_CATEGORIES.VALIDATION,
                config_errors.ERROR_LEVELS.HIGH,
                "Test error message",
                { test_detail = "value" },
                config_errors.RECOVERY_STRATEGIES.DEFAULT_CONFIG
            )

            assert.are.equal(config_errors.ERROR_CATEGORIES.VALIDATION, error_obj.category)
            assert.are.equal(config_errors.ERROR_LEVELS.HIGH, error_obj.level)
            assert.are.equal("Test error message", error_obj.message)
            assert.are.equal("value", error_obj.details.test_detail)
            assert.are.equal(config_errors.RECOVERY_STRATEGIES.DEFAULT_CONFIG, error_obj.recovery_strategy)
        end)

        it("should handle validation errors", function()
            local error_obj = config_errors.handle_validation_error(
                "threat_threshold", 15.0, "1.0-10.0", { context = "test" }
            )

            assert.are.equal(config_errors.ERROR_CATEGORIES.VALIDATION, error_obj.category)
            assert.are.equal(config_errors.ERROR_LEVELS.HIGH, error_obj.level)
        end)

        it("should handle parsing errors", function()
            local error_obj = config_errors.handle_parsing_error(
                "JSON", '{"invalid": json}', "syntax error"
            )

            assert.are.equal(config_errors.ERROR_CATEGORIES.PARSING, error_obj.category)
        end)

        it("should execute default config recovery", function()
            local success, result = config_errors.recover_with_defaults({})

            assert.is_true(success)
            assert.is_not_nil(result.config)
            assert.are.equal("defaults", result.recovery_method)
        end)

        it("should execute fallback config recovery", function()
            local fallback = { dry_run_mode = true }
            local success, result = config_errors.recover_with_fallback({
                fallback_config = fallback
            })

            assert.is_true(success)
            assert.are.equal(fallback, result.config)
            assert.are.equal("fallback", result.recovery_method)
        end)
    end)

    describe("Configuration Health Check", function()
        it("should report healthy state with valid config", function()
            local valid_config = { dry_run_mode = true }
            config_loader.load_from_plugin_config(valid_config)

            local health = config_loader.health_check()

            assert.are.equal("healthy", health.status)
            assert.are.equal(0, #health.issues)
        end)

        it("should report unhealthy state with no config", function()
            config_loader.reset()

            local health = config_loader.health_check()

            assert.are.equal("unhealthy", health.status)
            assert.is_true(#health.issues > 0)
        end)
    end)

    describe("Configuration Diff", function()
        it("should detect configuration changes", function()
            local old_config = {
                dry_run_mode = true,
                threat_threshold = 7.0,
                rate_limit_threshold = 100
            }

            local new_config = {
                dry_run_mode = false,
                threat_threshold = 8.0,
                max_payload_size = 2048576
            }

            local changes = config_parser.diff_configs(old_config, new_config)

            assert.are.equal("modified", changes.dry_run_mode.action)
            assert.are.equal("modified", changes.threat_threshold.action)
            assert.are.equal("removed", changes.rate_limit_threshold.action)
            assert.are.equal("added", changes.max_payload_size.action)
        end)
    end)

    describe("Configuration Export", function()
        it("should export configuration as JSON", function()
            local test_config = {
                dry_run_mode = true,
                threat_threshold = 7.5
            }

            local json_str, err = config_parser.export_config(test_config, "json")

            assert.is_nil(err)
            assert.is_not_nil(json_str)
            assert.is_string(json_str)

            -- Verify it's valid JSON by parsing it back
            local parsed_back = require("cjson").decode(json_str)
            assert.is_true(parsed_back.dry_run_mode)
            assert.are.equal(7.5, parsed_back.threat_threshold)
        end)
    end)

    describe("Field-Level Validation", function()
        it("should validate boolean fields", function()
            local valid, err = config_parser.validate_field("dry_run_mode", true, "boolean")
            assert.is_true(valid)
            assert.is_nil(err)

            local invalid, err2 = config_parser.validate_field("dry_run_mode", "not_boolean", "boolean")
            assert.is_false(invalid)
            assert.is_not_nil(err2)
        end)

        it("should validate number fields", function()
            local valid, err = config_parser.validate_field("threat_threshold", 5.0, "number")
            assert.is_true(valid)
            assert.is_nil(err)

            local invalid, err2 = config_parser.validate_field("threat_threshold", "not_number", "number")
            assert.is_false(invalid)
            assert.is_not_nil(err2)
        end)

        it("should validate string fields", function()
            local valid, err = config_parser.validate_field("log_level", "info", "string")
            assert.is_true(valid)
            assert.is_nil(err)

            local invalid, err2 = config_parser.validate_field("log_level", 123, "string")
            assert.is_false(invalid)
            assert.is_not_nil(err2)
        end)

        it("should validate array fields", function()
            local valid, err = config_parser.validate_field("ip_whitelist", {"203.0.113.1"}, "array")
            assert.is_true(valid)
            assert.is_nil(err)

            local invalid, err2 = config_parser.validate_field("ip_whitelist", "not_array", "array")
            assert.is_false(invalid)
            assert.is_not_nil(err2)
        end)
    end)

    teardown(function()
        -- Clean up any test state
        config_parser.clear_cache()
        config_loader.reset()
        config_errors.clear_error_history()
    end)
end)
