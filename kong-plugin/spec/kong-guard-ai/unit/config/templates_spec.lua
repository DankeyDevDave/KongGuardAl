-- Configuration Templates Tests
-- Test suite for environment-specific configuration templates

local Templates = require "kong.plugins.kong-guard-ai.modules.config.templates"

describe("Templates", function()

    describe("template retrieval", function()
        it("should get development template", function()
            local template = Templates.development()

            assert.is_table(template)
            assert.equals("Development Environment", template.name)
            assert.is_table(template.config)
            assert.is_true(template.config.debug_mode)
        end)

        it("should get production template", function()
            local template = Templates.production()

            assert.is_table(template)
            assert.equals("Production Environment", template.name)
            assert.is_table(template.config)
            assert.is_false(template.config.debug_mode)
            assert.is_true(template.config.require_auth)
        end)

        it("should get staging template", function()
            local template = Templates.staging()

            assert.is_table(template)
            assert.equals("Staging Environment", template.name)
            assert.is_table(template.config)
        end)

        it("should get high_volume template", function()
            local template = Templates.high_volume()

            assert.is_table(template)
            assert.equals("High Volume Environment", template.name)
            assert.is_table(template.config)
            assert.is_true(template.config.ai_queue_enabled)
            assert.equals(50000, template.config.rate_limit)
        end)

        it("should get compliance template", function()
            local template = Templates.compliance()

            assert.is_table(template)
            assert.equals("Compliance Environment", template.name)
            assert.is_table(template.config)
            assert.is_true(template.config.gdpr_compliance)
            assert.is_true(template.config.audit_trail)
        end)
    end)

    describe("get_template by name", function()
        it("should get template by exact name", function()
            local template = Templates.get_template("development")
            assert.is_not_nil(template)
            assert.equals("Development Environment", template.name)
        end)

        it("should get template by alias", function()
            local dev_template = Templates.get_template("dev")
            local prod_template = Templates.get_template("prod")

            assert.is_not_nil(dev_template)
            assert.is_not_nil(prod_template)
            assert.equals("Development Environment", dev_template.name)
            assert.equals("Production Environment", prod_template.name)
        end)

        it("should return nil for invalid template name", function()
            local template = Templates.get_template("invalid_template")
            assert.is_nil(template)
        end)

        it("should handle empty string", function()
            local template = Templates.get_template("")
            assert.is_nil(template)
        end)

        it("should handle nil input", function()
            local template = Templates.get_template(nil)
            assert.is_nil(template)
        end)
    end)

    describe("get_all_templates", function()
        it("should return all available templates", function()
            local templates = Templates.get_all_templates()

            assert.is_table(templates)
            assert.equals(5, #templates) -- dev, prod, staging, high_volume, compliance

            -- Verify all templates have required structure
            for _, template in ipairs(templates) do
                assert.is_string(template.name)
                assert.is_string(template.description)
                assert.is_table(template.config)
            end
        end)

        it("should include unique template names", function()
            local templates = Templates.get_all_templates()
            local names = {}

            for _, template in ipairs(templates) do
                assert.is_nil(names[template.name], "Duplicate template name: " .. template.name)
                names[template.name] = true
            end
        end)
    end)

    describe("template validation", function()
        it("should validate complete template", function()
            local template = Templates.development()
            local valid, errors = Templates.validate_template(template)

            if not valid then
                for _, error in ipairs(errors) do
                    print("Validation error: " .. error)
                end
            end

            assert.is_true(valid)
            assert.equals(0, #errors)
        end)

        it("should detect missing name field", function()
            local template = {
                description = "Test template",
                config = {}
            }

            local valid, errors = Templates.validate_template(template)
            assert.is_false(valid)
            assert.is_true(#errors > 0)

            local name_error_found = false
            for _, error in ipairs(errors) do
                if string.find(error, "name") then
                    name_error_found = true
                    break
                end
            end
            assert.is_true(name_error_found)
        end)

        it("should detect missing description field", function()
            local template = {
                name = "Test Template",
                config = {}
            }

            local valid, errors = Templates.validate_template(template)
            assert.is_false(valid)

            local desc_error_found = false
            for _, error in ipairs(errors) do
                if string.find(error, "description") then
                    desc_error_found = true
                    break
                end
            end
            assert.is_true(desc_error_found)
        end)

        it("should detect missing config field", function()
            local template = {
                name = "Test Template",
                description = "Test description"
            }

            local valid, errors = Templates.validate_template(template)
            assert.is_false(valid)

            local config_error_found = false
            for _, error in ipairs(errors) do
                if string.find(error, "config") then
                    config_error_found = true
                    break
                end
            end
            assert.is_true(config_error_found)
        end)

        it("should detect invalid config type", function()
            local template = {
                name = "Test Template",
                description = "Test description",
                config = "invalid_type"
            }

            local valid, errors = Templates.validate_template(template)
            assert.is_false(valid)

            local type_error_found = false
            for _, error in ipairs(errors) do
                if string.find(error, "must be a table") then
                    type_error_found = true
                    break
                end
            end
            assert.is_true(type_error_found)
        end)

        it("should detect missing required config fields", function()
            local template = {
                name = "Test Template",
                description = "Test description",
                config = {
                    -- Missing required fields
                    some_other_field = true
                }
            }

            local valid, errors = Templates.validate_template(template)
            assert.is_false(valid)
            assert.is_true(#errors > 0)
        end)
    end)

    describe("template configuration structure", function()
        it("should have consistent AI configuration structure", function()
            local templates = Templates.get_all_templates()

            for _, template in ipairs(templates) do
                assert.is_not_nil(template.config.ai_enabled,
                    "Template " .. template.name .. " missing ai_enabled")
                assert.is_boolean(template.config.ai_enabled,
                    "Template " .. template.name .. " ai_enabled not boolean")

                if template.config.ai_enabled then
                    assert.is_number(template.config.ai_timeout,
                        "Template " .. template.name .. " missing ai_timeout")
                    assert.is_number(template.config.ai_batch_size,
                        "Template " .. template.name .. " missing ai_batch_size")
                end
            end
        end)

        it("should have consistent threat detection structure", function()
            local templates = Templates.get_all_templates()

            for _, template in ipairs(templates) do
                assert.is_not_nil(template.config.threat_detection_enabled,
                    "Template " .. template.name .. " missing threat_detection_enabled")
                assert.is_boolean(template.config.threat_detection_enabled,
                    "Template " .. template.name .. " threat_detection_enabled not boolean")
            end
        end)

        it("should have consistent monitoring structure", function()
            local templates = Templates.get_all_templates()

            for _, template in ipairs(templates) do
                assert.is_not_nil(template.config.logging_level,
                    "Template " .. template.name .. " missing logging_level")
                assert.is_string(template.config.logging_level,
                    "Template " .. template.name .. " logging_level not string")

                assert.is_not_nil(template.config.metrics_enabled,
                    "Template " .. template.name .. " missing metrics_enabled")
                assert.is_boolean(template.config.metrics_enabled,
                    "Template " .. template.name .. " metrics_enabled not boolean")
            end
        end)
    end)

    describe("environment-specific optimizations", function()
        it("should optimize development for debugging", function()
            local dev_template = Templates.development()

            assert.equals("debug", dev_template.config.logging_level)
            assert.is_true(dev_template.config.debug_mode)
            assert.is_true(dev_template.config.hot_reload)
            assert.is_false(dev_template.config.require_auth)
        end)

        it("should optimize production for security", function()
            local prod_template = Templates.production()

            assert.equals("info", prod_template.config.logging_level)
            assert.is_false(prod_template.config.debug_mode)
            assert.is_false(prod_template.config.hot_reload)
            assert.is_true(prod_template.config.require_auth)
            assert.is_true(prod_template.config.security_headers)
        end)

        it("should optimize high_volume for performance", function()
            local hv_template = Templates.high_volume()

            assert.is_true(hv_template.config.rate_limit > 10000)
            assert.is_true(hv_template.config.max_concurrent_requests > 1000)
            assert.is_true(hv_template.config.connection_pooling)
            assert.equals("warn", hv_template.config.logging_level)
        end)

        it("should optimize compliance for audit requirements", function()
            local comp_template = Templates.compliance()

            assert.equals("debug", comp_template.config.logging_level)
            assert.is_true(comp_template.config.audit_logging)
            assert.is_true(comp_template.config.compliance_reporting)
            assert.is_true(comp_template.config.data_encryption)
            assert.equals(2555, comp_template.config.data_retention_days) -- 7 years
        end)
    end)

    describe("performance characteristics", function()
        it("should generate templates quickly", function()
            local start_time = os.clock()

            for i = 1, 100 do
                Templates.development()
                Templates.production()
                Templates.staging()
            end

            local end_time = os.clock()
            local duration = end_time - start_time

            -- Should complete 300 template generations in under 1 second
            assert.is_true(duration < 1.0, "Template generation too slow: " .. duration .. "s")
        end)

        it("should validate templates quickly", function()
            local templates = Templates.get_all_templates()

            local start_time = os.clock()

            for _, template in ipairs(templates) do
                Templates.validate_template(template)
            end

            local end_time = os.clock()
            local duration = end_time - start_time

            -- Should validate all templates in under 0.1 seconds
            assert.is_true(duration < 0.1, "Template validation too slow: " .. duration .. "s")
        end)
    end)
end)
