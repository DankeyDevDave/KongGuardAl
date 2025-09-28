-- SQL Injection Detector Unit Tests
-- Tests for the extracted SQL injection detection functionality

local luaunit = require 'luaunit'

-- Mock Kong dependencies
local mock_kong = {
    request = {
        get_path = function() return "/api/users" end,
        get_raw_query = function() return "id=1" end,
        get_raw_body = function() return nil end
    },
    log = {
        warn = function(...) end,
        err = function(...) end,
        info = function(...) end,
        debug = function(...) end
    }
}

-- Set up global kong mock
_G.kong = mock_kong

-- Load the module under test
local SQLInjectionDetector = require 'kong.plugins.kong-guard-ai.modules.threat.sql_injection_detector'

-- Test suite
describe("SQLInjectionDetector", function()
    local detector
    local config
    
    before_each(function()
        config = {
            log_level = "debug",
            max_body_size = 10000
        }
        detector = SQLInjectionDetector.new(config)
    end)
    
    describe("initialization", function()
        it("should create detector with default config", function()
            local default_detector = SQLInjectionDetector.new()
            assert.is_not_nil(default_detector)
            assert.equals(10000, default_detector.max_body_size)
        end)
        
        it("should create detector with custom config", function()
            assert.is_not_nil(detector)
            assert.equals(10000, detector.max_body_size)
            assert.equals("debug", detector.log_level)
        end)
    end)
    
    describe("threat detection", function()
        it("should return zero score for clean requests", function()
            mock_kong.request.get_path = function() return "/api/users" end
            mock_kong.request.get_raw_query = function() return "page=1&limit=10" end
            mock_kong.request.get_raw_body = function() return nil end
            
            local score, details = detector:detect({})
            assert.equals(0, score)
        end)
        
        it("should detect UNION SELECT attacks", function()
            mock_kong.request.get_path = function() return "/api/users" end
            mock_kong.request.get_raw_query = function() return "id=1 UNION SELECT password FROM users" end
            mock_kong.request.get_raw_body = function() return nil end
            
            local score, details = detector:detect({})
            assert.equals(0.95, score)
            assert.is_string(details)
            assert.is_true(#details > 0)
        end)
        
        it("should detect DROP TABLE attacks", function()
            mock_kong.request.get_path = function() return "/api/admin" end
            mock_kong.request.get_raw_query = function() return "action=1; DROP TABLE users;" end
            mock_kong.request.get_raw_body = function() return nil end
            
            local score, details = detector:detect({})
            assert.equals(0.95, score)
            assert.is_true(string.find(details, "drop") ~= nil)
        end)
        
        it("should detect SQL comment injection", function()
            mock_kong.request.get_path = function() return "/api/login" end
            mock_kong.request.get_raw_query = function() return "user=admin'-- password=anything" end
            mock_kong.request.get_raw_body = function() return nil end
            
            local score, details = detector:detect({})
            assert.equals(0.8, score)
            assert.is_true(string.find(details, "comment") ~= nil)
        end)
        
        it("should detect SQL injection in request body", function()
            mock_kong.request.get_path = function() return "/api/search" end
            mock_kong.request.get_raw_query = function() return "" end
            mock_kong.request.get_raw_body = function() return '{"query": "test OR 1=1"}' end
            
            local score, details = detector:detect({})
            assert.equals(0.95, score)
        end)
        
        it("should ignore oversized request bodies", function()
            mock_kong.request.get_path = function() return "/api/upload" end
            mock_kong.request.get_raw_query = function() return "" end
            mock_kong.request.get_raw_body = function() 
                return string.rep("a", 50000) .. "UNION SELECT"
            end
            
            local score, details = detector:detect({})
            assert.equals(0, score)
        end)
        
        it("should be case insensitive", function()
            local test_cases = {
                "id=1 UNION SELECT",
                "id=1 union select", 
                "id=1 Union Select"
            }
            
            for _, query in ipairs(test_cases) do
                mock_kong.request.get_raw_query = function() return query end
                local score, _ = detector:detect({})
                assert.equals(0.95, score)
            end
        end)
    end)
    
    describe("input validation", function()
        it("should validate malicious inputs", function()
            assert.is_true(detector:validate_input("SELECT * FROM users WHERE id=1 UNION SELECT password"))
            assert.is_true(detector:validate_input("admin'; DROP TABLE users;--"))
            assert.is_true(detector:validate_input("test' OR 1=1--"))
        end)
        
        it("should pass clean inputs", function()
            assert.is_false(detector:validate_input("normal user input"))
            assert.is_false(detector:validate_input("search for products"))
            assert.is_false(detector:validate_input("user@example.com"))
        end)
        
        it("should handle edge cases", function()
            assert.is_false(detector:validate_input(nil))
            assert.is_false(detector:validate_input(123))
            assert.is_false(detector:validate_input({}))
            assert.is_false(detector:validate_input(""))
        end)
    end)
    
    describe("statistics and management", function()
        it("should provide detector statistics", function()
            local stats = detector:get_stats()
            assert.is_table(stats)
            assert.equals("sql_injection", stats.detector_type)
            assert.is_number(stats.patterns_count)
            assert.is_true(stats.patterns_count > 0)
            assert.is_number(stats.comment_patterns_count)
            assert.equals(10000, stats.max_body_size)
        end)
        
        it("should allow pattern updates", function()
            local initial_stats = detector:get_stats()
            local initial_count = initial_stats.patterns_count
            
            detector:update_patterns({"custom%s+pattern", "another%s+attack"})
            
            local updated_stats = detector:get_stats()
            assert.equals(initial_count + 2, updated_stats.patterns_count)
        end)
        
        it("should handle invalid pattern updates", function()
            assert.has_no.errors(function()
                detector:update_patterns(nil)
                detector:update_patterns("not a table")
                detector:update_patterns({})
            end)
        end)
    end)
    
    describe("performance considerations", function()
        it("should handle multiple detections efficiently", function()
            mock_kong.request.get_raw_query = function() return "id=1 UNION SELECT" end
            
            local start_time = os.clock()
            for i = 1, 100 do
                detector:detect({})
            end
            local end_time = os.clock()
            
            -- Should complete 100 detections in reasonable time (< 1 second)
            assert.is_true((end_time - start_time) < 1.0)
        end)
        
        it("should not crash on malformed input", function()
            local malformed_requests = {
                function() return string.rep("UNION", 10000) end,
                function() return string.char(0, 1, 2, 3) end,
                function() return "unicode: 你好 UNION SELECT" end
            }
            
            for _, request_func in ipairs(malformed_requests) do
                mock_kong.request.get_raw_query = request_func
                assert.has_no.errors(function()
                    detector:detect({})
                end)
            end
        end)
    end)
end)