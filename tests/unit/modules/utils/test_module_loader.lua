-- Unit tests for module_loader utility
-- Following TDD approach for the refactoring effort

local lu = require('luaunit')
local module_loader = require('kong.plugins.kong-guard-ai.modules.utils.module_loader')

TestModuleLoader = {}

function TestModuleLoader:setUp()
    -- Clear caches before each test
    module_loader.clear_caches()
end

function TestModuleLoader:tearDown()
    -- Clean up after each test
    module_loader.clear_caches()
end

function TestModuleLoader:test_cache_stats_initial_state()
    local stats = module_loader.get_cache_stats()
    lu.assertIsTable(stats)
    lu.assertEquals(stats.loaded_modules, 0)
    lu.assertEquals(stats.cached_instances, 0)
end

function TestModuleLoader:test_is_module_loaded_initial_state()
    lu.assertFalse(module_loader.is_module_loaded("nonexistent"))
end

function TestModuleLoader:test_has_instance_initial_state()
    lu.assertFalse(module_loader.has_instance("nonexistent"))
end

function TestModuleLoader:test_clear_caches()
    -- Verify clear_caches doesn't error on empty caches
    lu.assertNotError(function()
        module_loader.clear_caches()
    end)
end

function TestModuleLoader:test_load_module_with_mock()
    -- Mock require function for testing
    local original_require = require
    local mock_module = {name = "mock_module"}

    _G.require = function(name)
        if name == "kong.plugins.kong-guard-ai.test_module" then
            return mock_module
        end
        return original_require(name)
    end

    -- Test loading module
    local loaded = module_loader.load_module("test_module")
    lu.assertEquals(loaded, mock_module)

    -- Test caching - should return same instance
    local loaded2 = module_loader.load_module("test_module")
    lu.assertIs(loaded, loaded2)

    -- Verify cache stats
    local stats = module_loader.get_cache_stats()
    lu.assertEquals(stats.loaded_modules, 1)

    -- Verify is_module_loaded
    lu.assertTrue(module_loader.is_module_loaded("test_module"))
    lu.assertFalse(module_loader.is_module_loaded("other_module"))

    -- Restore require
    _G.require = original_require
end

function TestModuleLoader:test_get_instance_with_constructor()
    -- Mock require and module with constructor
    local original_require = require
    local instance_created = false
    local passed_config = nil

    local mock_module = {
        new = function(config)
            instance_created = true
            passed_config = config
            return {instance = true}
        end
    }

    _G.require = function(name)
        if name == "kong.plugins.kong-guard-ai.test_module" then
            return mock_module
        end
        return original_require(name)
    end

    -- Test getting instance with config
    local config = {test = "config"}
    local instance = module_loader.get_instance("test_module", config)

    lu.assertTrue(instance_created)
    lu.assertEquals(passed_config, config)
    lu.assertTrue(instance.instance)

    -- Test caching - should return same instance
    local instance2 = module_loader.get_instance("test_module", {different = "config"})
    lu.assertIs(instance, instance2)

    -- Verify cache stats
    local stats = module_loader.get_cache_stats()
    lu.assertEquals(stats.loaded_modules, 1)
    lu.assertEquals(stats.cached_instances, 1)

    -- Verify has_instance
    lu.assertTrue(module_loader.has_instance("test_module"))
    lu.assertFalse(module_loader.has_instance("other_module"))

    -- Restore require
    _G.require = original_require
end

function TestModuleLoader:test_get_instance_without_constructor()
    -- Mock require and module without constructor
    local original_require = require
    local mock_module = {name = "mock_without_constructor"}

    _G.require = function(name)
        if name == "kong.plugins.kong-guard-ai.test_module" then
            return mock_module
        end
        return original_require(name)
    end

    -- Test getting instance without constructor
    local instance = module_loader.get_instance("test_module", {})
    lu.assertEquals(instance, mock_module)

    -- Verify caching
    local instance2 = module_loader.get_instance("test_module", {})
    lu.assertIs(instance, instance2)

    -- Restore require
    _G.require = original_require
end

-- Run tests when file is executed directly
if arg and arg[0]:match("test_module_loader.lua$") then
    os.exit(lu.LuaUnit.run())
end

return TestModuleLoader
