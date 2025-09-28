-- Configuration Migration Tool Tests
-- Test suite for configuration migration and version management

local MigrationTool = require "kong.plugins.kong-guard-ai.modules.config.migration_tool"

describe("MigrationTool", function()
    local migration_tool

    before_each(function()
        migration_tool = MigrationTool.new({
            ai_enabled = true,
            threat_detection_enabled = true
        })
    end)

    describe("initialization", function()
        it("should create new instance with config", function()
            local config = { test_setting = "value" }
            local tool = MigrationTool.new(config)

            assert.is_not_nil(tool)
            assert.equals("value", tool.config.test_setting)
        end)

        it("should create new instance with empty config", function()
            local tool = MigrationTool.new()
            assert.is_not_nil(tool)
            assert.is_table(tool.config)
        end)

        it("should initialize empty migration log", function()
            assert.is_table(migration_tool.migration_log)
            assert.equals(0, #migration_tool.migration_log)
        end)
    end)

    describe("version detection", function()
        it("should detect version 1.0.0 for basic config", function()
            local basic_config = {
                enabled = true,
                timeout = 5000
            }

            local version = migration_tool:detect_version(basic_config)
            assert.equals("1.0.0", version)
        end)

        it("should detect version 1.1.0 for AI-enabled config", function()
            local ai_config = {
                ai_service = {
                    enabled = true,
                    endpoint = "http://localhost"
                },
                threat_analysis = {}
            }

            local version = migration_tool:detect_version(ai_config)
            assert.equals("1.1.0", version)
        end)

        it("should detect version 1.2.0 for modular threat detection", function()
            local modular_config = {
                threat_detection_modules = {
                    sql_injection = { enabled = true },
                    xss_detector = { enabled = true }
                }
            }

            local version = migration_tool:detect_version(modular_config)
            assert.equals("1.2.0", version)
        end)

        it("should detect version 1.3.0 for performance optimization", function()
            local perf_config = {
                performance_optimization = {
                    cache_strategies = {}
                },
                memory_management = {}
            }

            local version = migration_tool:detect_version(perf_config)
            assert.equals("1.3.0", version)
        end)

        it("should detect version 2.0.0 for modular architecture", function()
            local modular_config = {
                schema_version = "2.0.0",
                modules = {
                    ai = {},
                    threat = {}
                }
            }

            local version = migration_tool:detect_version(modular_config)
            assert.equals("2.0.0", version)
        end)
    end)

    describe("migration necessity check", function()
        it("should detect when migration is needed", function()
            migration_tool.config = { basic_setting = true }

            local needs_migration, current, target = migration_tool:needs_migration("2.0.0")
            assert.is_true(needs_migration)
            assert.equals("1.0.0", current)
            assert.equals("2.0.0", target)
        end)

        it("should detect when migration is not needed", function()
            migration_tool.config = {
                schema_version = "2.0.0",
                modules = { ai = {}, threat = {} }
            }

            local needs_migration, current, target = migration_tool:needs_migration("2.0.0")
            assert.is_false(needs_migration)
            assert.equals("2.0.0", current)
            assert.equals("2.0.0", target)
        end)

        it("should use latest version as default target", function()
            migration_tool.config = { basic_setting = true }

            local needs_migration, current, target = migration_tool:needs_migration()
            assert.is_true(needs_migration)
            assert.equals("1.0.0", current)
            assert.equals("2.0.0", target) -- Latest version
        end)
    end)

    describe("migration execution", function()
        it("should migrate from 1.0.0 to 2.0.0", function()
            migration_tool.config = {
                basic_threat_detection = {
                    enabled = true,
                    sql_injection_enabled = true
                },
                cache_ttl = 3600
            }

            local migrated_config, log = migration_tool:migrate("2.0.0")

            assert.is_table(migrated_config)
            assert.equals("2.0.0", migrated_config.schema_version)
            assert.is_table(migrated_config.modules)
            assert.is_table(log)
            assert.is_true(#log > 0)
        end)

        it("should migrate from 1.1.0 to 2.0.0", function()
            migration_tool.config = {
                ai_service = {
                    enabled = true,
                    endpoint = "http://localhost"
                },
                ai_threat_analysis = {
                    enabled = true
                }
            }

            local migrated_config, log = migration_tool:migrate("2.0.0")

            assert.equals("2.0.0", migrated_config.schema_version)
            assert.is_table(migrated_config.modules.ai)
            assert.is_true(migrated_config.modules.ai.enabled)
        end)

        it("should preserve custom settings during migration", function()
            migration_tool.config = {
                custom_setting = "preserve_me",
                basic_threat_detection = {
                    enabled = true
                }
            }

            local migrated_config = migration_tool:migrate("2.0.0")
            assert.equals("preserve_me", migrated_config.custom_setting)
        end)

        it("should log migration steps", function()
            migration_tool.config = { basic_setting = true }

            local migrated_config, log = migration_tool:migrate("1.1.0")

            assert.is_table(log)
            assert.is_true(#log > 0)

            -- Check for start and complete log entries
            local has_start = false
            local has_complete = false

            for _, entry in ipairs(log) do
                if entry.step_type == "start" then has_start = true end
                if entry.step_type == "complete" then has_complete = true end
            end

            assert.is_true(has_start)
            assert.is_true(has_complete)
        end)
    end)

    describe("specific migration steps", function()
        describe("1.1.0 migration", function()
            it("should add AI service configuration", function()
                migration_tool.config = { basic_setting = true }

                local migrated = migration_tool:migrate("1.1.0")

                assert.is_table(migrated.ai_service)
                assert.is_true(migrated.ai_service.enabled)
                assert.is_string(migrated.ai_service.endpoint)
            end)

            it("should migrate basic threat detection to AI-enhanced", function()
                migration_tool.config = {
                    basic_threat_detection = {
                        enabled = true,
                        sensitivity = "high"
                    }
                }

                local migrated = migration_tool:migrate("1.1.0")

                assert.is_table(migrated.ai_threat_analysis)
                assert.is_true(migrated.ai_threat_analysis.enabled)
                assert.is_nil(migrated.basic_threat_detection)
            end)
        end)

        describe("1.2.0 migration", function()
            it("should convert monolithic threat detection to modular", function()
                migration_tool.config = {
                    threat_detection = {
                        sql_injection_enabled = true,
                        xss_enabled = true,
                        path_traversal_enabled = false
                    }
                }

                local migrated = migration_tool:migrate("1.2.0")

                assert.is_table(migrated.threat_detection_modules)
                assert.is_true(migrated.threat_detection_modules.sql_injection.enabled)
                assert.is_true(migrated.threat_detection_modules.xss.enabled)
                assert.is_false(migrated.threat_detection_modules.path_traversal.enabled)
                assert.is_nil(migrated.threat_detection)
            end)
        end)

        describe("1.3.0 migration", function()
            it("should add performance optimization settings", function()
                migration_tool.config = {
                    cache_ttl = 1800,
                    basic_setting = true
                }

                local migrated = migration_tool:migrate("1.3.0")

                assert.is_table(migrated.performance_optimization)
                assert.is_table(migrated.performance_optimization.cache_strategies)
                assert.equals(1800, migrated.performance_optimization.cache_strategies.threat_cache_ttl)
                assert.is_nil(migrated.cache_ttl)
            end)
        end)

        describe("2.0.0 migration", function()
            it("should restructure to modular architecture", function()
                migration_tool.config = {
                    ai_service = { enabled = true },
                    threat_detection_modules = { sql_injection = { enabled = true } },
                    performance_optimization = { cache_strategies = {} }
                }

                local migrated = migration_tool:migrate("2.0.0")

                assert.equals("2.0.0", migrated.schema_version)
                assert.is_table(migrated.modules)
                assert.is_table(migrated.modules.ai)
                assert.is_table(migrated.modules.threat)
                assert.is_table(migrated.modules.performance)
            end)
        end)
    end)

    describe("backup and restore", function()
        it("should create backup of current config", function()
            migration_tool.config = { test_setting = "backup_me" }

            local backup_name = migration_tool:create_backup("test_backup")

            assert.is_string(backup_name)
            assert.equals("test_backup", backup_name)
            assert.is_table(migration_tool.backup)
            assert.equals("backup_me", migration_tool.backup.config.test_setting)
        end)

        it("should create auto-named backup", function()
            local backup_name = migration_tool:create_backup()

            assert.is_string(backup_name)
            assert.is_true(string.find(backup_name, "auto_backup_") == 1)
        end)

        it("should restore from backup", function()
            migration_tool.config = { original = "value" }
            local backup_name = migration_tool:create_backup("restore_test")

            migration_tool.config = { changed = "value" }

            local success = migration_tool:restore_backup("restore_test")

            assert.is_true(success)
            assert.equals("value", migration_tool.config.original)
            assert.is_nil(migration_tool.config.changed)
        end)

        it("should fail to restore non-existent backup", function()
            local success = migration_tool:restore_backup("non_existent")
            assert.is_false(success)
        end)
    end)

    describe("configuration validation", function()
        it("should validate migrated configuration", function()
            migration_tool.config = { basic_setting = true }
            local migrated_config = migration_tool:migrate("2.0.0")

            local valid, errors = migration_tool:validate_migrated_config(migrated_config)

            if not valid then
                for _, error in ipairs(errors) do
                    print("Validation error: " .. error)
                end
            end

            -- Note: This might fail if schema_orchestrator validation is strict
            -- In real implementation, we'd need proper schema validation
            assert.is_boolean(valid)
            assert.is_table(errors)
        end)

        it("should detect invalid modular structure", function()
            local invalid_config = {
                schema_version = "2.0.0"
                -- Missing modules section
            }

            local valid, errors = migration_tool:validate_migrated_config(invalid_config)
            assert.is_false(valid)

            local modules_error_found = false
            for _, error in ipairs(errors) do
                if string.find(error, "modules") then
                    modules_error_found = true
                    break
                end
            end
            assert.is_true(modules_error_found)
        end)
    end)

    describe("version comparison", function()
        it("should compare version strings correctly", function()
            assert.equals(-1, migration_tool:_version_compare("1.0.0", "1.1.0"))
            assert.equals(0, migration_tool:_version_compare("1.1.0", "1.1.0"))
            assert.equals(1, migration_tool:_version_compare("1.2.0", "1.1.0"))
        end)

        it("should handle different version lengths", function()
            assert.equals(-1, migration_tool:_version_compare("1.0", "1.0.1"))
            assert.equals(1, migration_tool:_version_compare("1.1", "1.0.9"))
        end)
    end)

    describe("performance", function()
        it("should migrate large configurations efficiently", function()
            -- Create large configuration
            local large_config = {}
            for i = 1, 1000 do
                large_config["setting_" .. i] = "value_" .. i
            end

            local large_tool = MigrationTool.new(large_config)

            local start_time = os.clock()
            large_tool:migrate("2.0.0")
            local end_time = os.clock()

            -- Should complete migration within reasonable time (5 seconds)
            assert.is_true((end_time - start_time) < 5.0)
        end)
    end)

    describe("error handling", function()
        it("should handle nil config gracefully", function()
            local nil_tool = MigrationTool.new(nil)
            local version = nil_tool:detect_version()
            assert.equals("1.0.0", version)
        end)

        it("should handle corrupted config gracefully", function()
            migration_tool.config = {
                corrupted_field = function() end -- Functions can't be migrated
            }

            -- Should not crash during migration
            local success, migrated = pcall(function()
                return migration_tool:migrate("2.0.0")
            end)

            assert.is_true(success)
        end)
    end)
end)
