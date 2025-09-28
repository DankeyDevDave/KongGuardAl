-- Unit tests for SQL injection detector module
-- Following TDD approach for the refactoring effort

local lu = require('luaunit')

-- Mock kong for testing
_G.kong = {
    request = {
        get_path = function() return "/api/users" end,
        get_raw_query = function() return "id=1" end,
        get_raw_body = function() return nil end
    }
}

local sql_injection_detector = require('kong.plugins.kong-guard-ai.modules.threat.sql_injection_detector')

TestSQLInjectionDetector = {}

function TestSQLInjectionDetector:setUp()
    self.config = {log_level = "debug", max_body_size = 10000}
    self.detector = sql_injection_detector.new(self.config)
end

function TestSQLInjectionDetector:test_detector_initialization()
    lu.assertNotNil(self.detector)
    lu.assertEquals(self.detector.max_body_size, 10000)
    lu.assertEquals(self.detector.log_level, "debug")
end

function TestSQLInjectionDetector:test_no_sql_injection_clean_request()
    -- Mock clean request
    _G.kong.request.get_path = function() return "/api/users" end
    _G.kong.request.get_raw_query = function() return "page=1&limit=10" end
    _G.kong.request.get_raw_body = function() return nil end
    
    local score, details = self.detector:detect({})
    lu.assertEquals(score, 0)
    lu.assertStrContains(details, "", true) -- Empty or minimal details
end

function TestSQLInjectionDetector:test_detect_union_select_attack()
    -- Mock malicious request with UNION SELECT
    _G.kong.request.get_path = function() return "/api/users" end
    _G.kong.request.get_raw_query = function() return "id=1 UNION SELECT password FROM users" end
    _G.kong.request.get_raw_body = function() return nil end
    
    local score, details = self.detector:detect({})
    lu.assertEquals(score, 0.95)
    lu.assertStrContains(details, "union%s+select")
end

function TestSQLInjectionDetector:test_detect_drop_table_attack()
    -- Mock malicious request with DROP TABLE
    _G.kong.request.get_path = function() return "/api/admin" end
    _G.kong.request.get_raw_query = function() return "action=1; DROP TABLE users;" end
    _G.kong.request.get_raw_body = function() return nil end
    
    local score, details = self.detector:detect({})
    lu.assertEquals(score, 0.95)
    lu.assertStrContains(details, "drop%s+table")
end

function TestSQLInjectionDetector:test_detect_sql_comment_patterns()
    -- Mock request with SQL comments
    _G.kong.request.get_path = function() return "/api/login" end
    _G.kong.request.get_raw_query = function() return "user=admin'-- password=anything" end
    _G.kong.request.get_raw_body = function() return nil end
    
    local score, details = self.detector:detect({})
    lu.assertEquals(score, 0.8)
    lu.assertStrContains(details, "comment")
end

function TestSQLInjectionDetector:test_detect_in_request_body()
    -- Mock request with SQL injection in body
    _G.kong.request.get_path = function() return "/api/search" end
    _G.kong.request.get_raw_query = function() return "" end
    _G.kong.request.get_raw_body = function() return '{"query": "test OR 1=1"}' end
    
    local score, details = self.detector:detect({})
    lu.assertEquals(score, 0.95)
    lu.assertStrContains(details, "or%s+1%s*=%s*1")
end

function TestSQLInjectionDetector:test_large_body_ignored()
    -- Mock request with large body (should be ignored)
    _G.kong.request.get_path = function() return "/api/upload" end
    _G.kong.request.get_raw_query = function() return "" end
    _G.kong.request.get_raw_body = function() 
        return string.rep("a", 50000) .. "UNION SELECT"  -- Large body with SQL injection
    end
    
    local score, details = self.detector:detect({})
    lu.assertEquals(score, 0) -- Should be ignored due to size
end

function TestSQLInjectionDetector:test_validate_input_method()
    lu.assertTrue(self.detector:validate_input("SELECT * FROM users WHERE id=1 UNION SELECT password"))
    lu.assertTrue(self.detector:validate_input("admin'; DROP TABLE users;--"))
    lu.assertFalse(self.detector:validate_input("normal user input"))
    lu.assertFalse(self.detector:validate_input(nil))
    lu.assertFalse(self.detector:validate_input(123))
end

function TestSQLInjectionDetector:test_get_stats()
    local stats = self.detector:get_stats()
    lu.assertIsTable(stats)
    lu.assertEquals(stats.detector_type, "sql_injection")
    lu.assertIsNumber(stats.patterns_count)
    lu.assertTrue(stats.patterns_count > 0)
    lu.assertIsNumber(stats.comment_patterns_count)
    lu.assertEquals(stats.max_body_size, 10000)
end

function TestSQLInjectionDetector:test_update_patterns()
    local initial_stats = self.detector:get_stats()
    local initial_count = initial_stats.patterns_count
    
    -- Add new patterns
    self.detector:update_patterns({"custom%s+pattern", "another%s+attack"})
    
    local updated_stats = self.detector:get_stats()
    lu.assertEquals(updated_stats.patterns_count, initial_count + 2)
end

function TestSQLInjectionDetector:test_case_insensitive_detection()
    -- Test that detection works regardless of case
    _G.kong.request.get_path = function() return "/api/test" end
    _G.kong.request.get_raw_query = function() return "id=1 UNION SELECT" end
    _G.kong.request.get_raw_body = function() return nil end
    
    local score1, _ = self.detector:detect({})
    
    _G.kong.request.get_raw_query = function() return "id=1 union select" end
    local score2, _ = self.detector:detect({})
    
    _G.kong.request.get_raw_query = function() return "id=1 Union Select" end
    local score3, _ = self.detector:detect({})
    
    lu.assertEquals(score1, 0.95)
    lu.assertEquals(score2, 0.95)
    lu.assertEquals(score3, 0.95)
end

function TestSQLInjectionDetector:test_time_based_attacks()
    -- Test detection of time-based SQL injection
    _G.kong.request.get_path = function() return "/api/login" end
    _G.kong.request.get_raw_query = function() return "user=admin' AND (SELECT SLEEP(5))--" end
    _G.kong.request.get_raw_body = function() return nil end
    
    local score, details = self.detector:detect({})
    lu.assertEquals(score, 0.95)
    lu.assertStrContains(details, "sleep")
end

-- Run tests when file is executed directly
if arg and arg[0]:match("test_sql_injection_detector.lua$") then
    os.exit(lu.LuaUnit.run())
end

return TestSQLInjectionDetector