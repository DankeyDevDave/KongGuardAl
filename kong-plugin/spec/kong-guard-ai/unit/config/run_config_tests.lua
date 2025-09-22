#!/usr/bin/env lua

-- Test Runner for Configuration Management Module
-- Runs all configuration-related tests and reports results

local function run_tests()
    print("=== Kong Guard AI - Configuration Module Tests ===")
    print("")

    -- Test files to run
    local test_files = {
        "profile_manager_spec.lua",
        "templates_spec.lua",
        "migration_tool_spec.lua"
    }

    local total_tests = 0
    local passed_tests = 0
    local failed_tests = 0
    local test_results = {}

    for _, test_file in ipairs(test_files) do
        print("Running " .. test_file .. "...")

        local success, result = pcall(function()
            return dofile(test_file)
        end)

        if success then
            print("✓ " .. test_file .. " - PASSED")
            passed_tests = passed_tests + 1
            table.insert(test_results, {file = test_file, status = "PASSED"})
        else
            print("✗ " .. test_file .. " - FAILED")
            print("  Error: " .. tostring(result))
            failed_tests = failed_tests + 1
            table.insert(test_results, {file = test_file, status = "FAILED", error = result})
        end

        total_tests = total_tests + 1
        print("")
    end

    -- Summary
    print("=== Test Summary ===")
    print("Total tests: " .. total_tests)
    print("Passed: " .. passed_tests)
    print("Failed: " .. failed_tests)
    print("")

    if failed_tests > 0 then
        print("Failed tests:")
        for _, result in ipairs(test_results) do
            if result.status == "FAILED" then
                print("  " .. result.file .. ": " .. tostring(result.error))
            end
        end
        print("")
    end

    local success_rate = (passed_tests / total_tests) * 100
    print(string.format("Success rate: %.1f%%", success_rate))

    if failed_tests == 0 then
        print("🎉 All configuration tests passed!")
        return 0
    else
        print("❌ Some tests failed. Please review and fix.")
        return 1
    end
end

-- Performance benchmark
local function run_performance_tests()
    print("\n=== Configuration Module Performance Tests ===")

    local ProfileManager = require "kong.plugins.kong-guard-ai.modules.config.profile_manager"
    local Templates = require "kong.plugins.kong-guard-ai.modules.config.templates"
    local MigrationTool = require "kong.plugins.kong-guard-ai.modules.config.migration_tool"

    -- Profile Manager Performance
    print("Profile Manager Performance:")
    local start_time = os.clock()

    for i = 1, 100 do
        local manager = ProfileManager.new({})
        manager:get_available_profiles()
        manager:apply_profile("basic_security", false)
    end

    local profile_time = os.clock() - start_time
    print(string.format("  100 profile operations: %.3fs", profile_time))

    -- Templates Performance
    print("Templates Performance:")
    start_time = os.clock()

    for i = 1, 1000 do
        Templates.get_all_templates()
    end

    local template_time = os.clock() - start_time
    print(string.format("  1000 template retrievals: %.3fs", template_time))

    -- Migration Performance
    print("Migration Performance:")
    start_time = os.clock()

    for i = 1, 50 do
        local tool = MigrationTool.new({basic_setting = true})
        tool:migrate("2.0.0")
    end

    local migration_time = os.clock() - start_time
    print(string.format("  50 migrations: %.3fs", migration_time))

    print("\nPerformance Summary:")
    print(string.format("  Profile ops/sec: %.0f", 100 / profile_time))
    print(string.format("  Template ops/sec: %.0f", 1000 / template_time))
    print(string.format("  Migration ops/sec: %.0f", 50 / migration_time))
end

-- Memory usage test
local function run_memory_tests()
    print("\n=== Configuration Module Memory Tests ===")

    local function get_memory_usage()
        collectgarbage("collect")
        return collectgarbage("count")
    end

    local initial_memory = get_memory_usage()
    print(string.format("Initial memory: %.2f KB", initial_memory))

    -- Test memory usage with large configurations
    local ProfileManager = require "kong.plugins.kong-guard-ai.modules.config.profile_manager"

    local managers = {}
    for i = 1, 100 do
        local large_config = {}
        for j = 1, 100 do
            large_config["setting_" .. j] = "value_" .. j
        end

        managers[i] = ProfileManager.new(large_config)
    end

    local peak_memory = get_memory_usage()
    print(string.format("Peak memory with 100 managers: %.2f KB", peak_memory))
    print(string.format("Memory increase: %.2f KB", peak_memory - initial_memory))

    -- Clean up
    managers = nil
    collectgarbage("collect")

    local final_memory = get_memory_usage()
    print(string.format("Final memory after cleanup: %.2f KB", final_memory))

    local memory_leak = final_memory - initial_memory
    if memory_leak > 50 then -- More than 50KB leak
        print("⚠️  Potential memory leak detected: " .. memory_leak .. " KB")
    else
        print("✓ No significant memory leak detected")
    end
end

-- Integration test
local function run_integration_tests()
    print("\n=== Configuration Module Integration Tests ===")

    local ProfileManager = require "kong.plugins.kong-guard-ai.modules.config.profile_manager"
    local Templates = require "kong.plugins.kong-guard-ai.modules.config.templates"
    local MigrationTool = require "kong.plugins.kong-guard-ai.modules.config.migration_tool"

    print("Testing complete configuration workflow...")

    -- 1. Start with basic configuration
    local manager = ProfileManager.new({
        basic_setting = true
    })

    -- 2. Apply a template-based profile
    local dev_template = Templates.development()
    manager.config = dev_template.config

    -- 3. Migrate to latest version
    local migration_tool = MigrationTool.new(manager.config)
    local migrated_config, log = migration_tool:migrate("2.0.0")

    -- 4. Validate the final configuration
    manager.config = migrated_config
    local valid, errors = manager:validate_current_config()

    if valid then
        print("✓ Complete workflow successful")
        print("  - Template applied")
        print("  - Migration completed (" .. #log .. " steps)")
        print("  - Configuration validated")
    else
        print("✗ Integration test failed")
        for _, error in ipairs(errors) do
            print("  Error: " .. error)
        end
    end

    -- 5. Test profile comparison
    local comparison = manager:compare_profiles("development", "production")
    if comparison and #comparison.differences > 0 then
        print("✓ Profile comparison working")
        print("  - Found " .. #comparison.differences .. " differences")
    else
        print("✗ Profile comparison failed")
    end

    -- 6. Test export/import
    local exported = manager:export_config("json")
    if exported and string.len(exported) > 0 then
        print("✓ Configuration export working")

        local import_success = manager:import_config(exported, "json")
        if import_success then
            print("✓ Configuration import working")
        else
            print("✗ Configuration import failed")
        end
    else
        print("✗ Configuration export failed")
    end
end

-- Main execution
local function main()
    local exit_code = run_tests()

    if exit_code == 0 then
        run_performance_tests()
        run_memory_tests()
        run_integration_tests()

        print("\n🎉 All configuration module tests completed successfully!")
    else
        print("\n❌ Test failures detected. Fix issues before proceeding.")
    end

    return exit_code
end

-- Run if executed directly
if arg and arg[0] and arg[0]:match("run_config_tests.lua$") then
    os.exit(main())
end

return main
