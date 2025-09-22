-- Unit tests for performance_utils module
-- Following TDD approach for the refactoring effort

local lu = require('luaunit')
local performance_utils = require('kong.plugins.kong-guard-ai.modules.utils.performance_utils')

TestPerformanceUtils = {}

function TestPerformanceUtils:setUp()
    -- Clear caches before each test
    performance_utils.clear_caches()
end

function TestPerformanceUtils:tearDown()
    -- Clean up after each test
    performance_utils.clear_caches()
end

function TestPerformanceUtils:test_get_cached_string_returns_same_instance()
    local str1 = "test_string"
    local cached1 = performance_utils.get_cached_string(str1)
    local cached2 = performance_utils.get_cached_string(str1)

    lu.assertEquals(cached1, cached2)
    lu.assertIs(cached1, cached2) -- Should be the same instance
end

function TestPerformanceUtils:test_get_cached_string_different_strings()
    local str1 = "test_string_1"
    local str2 = "test_string_2"
    local cached1 = performance_utils.get_cached_string(str1)
    local cached2 = performance_utils.get_cached_string(str2)

    lu.assertNotEquals(cached1, cached2)
end

function TestPerformanceUtils:test_table_pool_basic_functionality()
    local table1 = performance_utils.get_pooled_table()
    lu.assertIsTable(table1)

    -- Add some data to table
    table1.test_key = "test_value"

    -- Return to pool
    performance_utils.return_pooled_table(table1)

    -- Get another table (should be the same instance, but cleared)
    local table2 = performance_utils.get_pooled_table()
    lu.assertIs(table1, table2) -- Should be same instance
    lu.assertNil(table2.test_key) -- Should be cleared
end

function TestPerformanceUtils:test_table_pool_with_nil()
    -- Should handle nil gracefully
    lu.assertNotError(function()
        performance_utils.return_pooled_table(nil)
    end)
end

function TestPerformanceUtils:test_should_log_level_checking()
    lu.assertTrue(performance_utils.should_log("debug", "error"))
    lu.assertTrue(performance_utils.should_log("info", "error"))
    lu.assertFalse(performance_utils.should_log("error", "debug"))
    lu.assertFalse(performance_utils.should_log("error", "info"))

    -- Test default level
    lu.assertTrue(performance_utils.should_log(nil, "error"))
    lu.assertFalse(performance_utils.should_log(nil, "debug"))
end

function TestPerformanceUtils:test_log_message_with_mock_kong()
    -- Mock kong.log for testing
    local log_called = false
    local logged_message = nil
    local logged_data = nil

    _G.kong = {
        log = {
            info = function(message, data)
                log_called = true
                logged_message = message
                logged_data = data
            end
        }
    }

    local config = {log_level = "info"}
    performance_utils.log_message(config, "info", "test message", {key = "value"})

    lu.assertTrue(log_called)
    lu.assertEquals(logged_message, "test message")
    lu.assertEquals(logged_data.key, "value")

    -- Clean up
    _G.kong = nil
end

function TestPerformanceUtils:test_get_performance_stats()
    -- Add some cached strings
    performance_utils.get_cached_string("test1")
    performance_utils.get_cached_string("test2")

    -- Get and return some tables
    local table1 = performance_utils.get_pooled_table()
    performance_utils.return_pooled_table(table1)

    local stats = performance_utils.get_performance_stats()
    lu.assertIsTable(stats)
    lu.assertIsNumber(stats.string_cache_size)
    lu.assertIsNumber(stats.table_pool_size)
end

function TestPerformanceUtils:test_clear_caches()
    -- Add some cached data
    performance_utils.get_cached_string("test")
    local table1 = performance_utils.get_pooled_table()
    performance_utils.return_pooled_table(table1)

    -- Clear caches
    performance_utils.clear_caches()

    -- Verify caches are cleared
    local stats = performance_utils.get_performance_stats()
    lu.assertEquals(stats.string_cache_size, 0)
    lu.assertEquals(stats.table_pool_size, 0)
end

-- Run tests when file is executed directly
if arg and arg[0]:match("test_performance_utils.lua$") then
    os.exit(lu.LuaUnit.run())
end

return TestPerformanceUtils
