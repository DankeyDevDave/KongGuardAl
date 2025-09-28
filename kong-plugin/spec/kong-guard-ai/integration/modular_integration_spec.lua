-- Modular Integration Tests
-- Tests that validate extracted modules work together seamlessly

local luaunit = require 'luaunit'

-- Mock Kong environment for integration testing
local mock_kong = {
    request = {
        get_path = function() return "/api/test" end,
        get_raw_query = function() return "param=value" end,
        get_raw_body = function() return nil end,
        get_method = function() return "GET" end,
        get_headers = function() return {} end
    },
    log = {
        warn = function(...) end,
        err = function(...) end,
        info = function(...) end,
        debug = function(...) end
    },
    cache = {
        get = function(key) return nil end,
        set = function(key, value, ttl) return true end
    }
}

-- Mock ngx for performance utilities
local mock_ngx = {
    shared = {
        kong_cache = {
            cache = {},
            get = function(self, key) return self.cache[key] end,
            set = function(self, key, value, ttl) self.cache[key] = value end
        }
    },
    now = function() return os.time() end
}

-- Set up global mocks
_G.kong = mock_kong
_G.ngx = mock_ngx

-- Load all the extracted modules
local performance_utils = require 'kong.plugins.kong-guard-ai.modules.utils.performance_utils'
local module_loader = require 'kong.plugins.kong-guard-ai.modules.utils.module_loader'
local sql_injection_detector = require 'kong.plugins.kong-guard-ai.modules.threat.sql_injection_detector'
local xss_detector = require 'kong.plugins.kong-guard-ai.modules.threat.xss_detector'
local path_traversal_detector = require 'kong.plugins.kong-guard-ai.modules.threat.path_traversal_detector'
local threat_orchestrator = require 'kong.plugins.kong-guard-ai.modules.threat.threat_orchestrator'

describe("Modular Integration Tests", function()
    local config
    local orchestrator
    
    before_each(function()
        config = {
            log_level = "debug",
            max_body_size = 10000,
            threat_cache_ttl = 300
        }
        orchestrator = threat_orchestrator.new(config)
    end)
    
    describe("module loading and initialization", function()
        it("should load all utility modules successfully", function()
            assert.is_not_nil(performance_utils)
            assert.is_not_nil(module_loader)
            assert.is_function(performance_utils.get_cached_string)
            assert.is_function(module_loader.load_module)
        end)
        
        it("should load all threat detection modules successfully", function()
            assert.is_not_nil(sql_injection_detector)
            assert.is_not_nil(xss_detector)
            assert.is_not_nil(path_traversal_detector)
            assert.is_not_nil(threat_orchestrator)
        end)
        
        it("should initialize threat orchestrator with all detectors", function()
            assert.is_not_nil(orchestrator)
            local stats = orchestrator:get_stats()
            assert.equals(3, stats.orchestrator.active_detectors)
            assert.is_table(stats.detectors.sql_injection)
            assert.is_table(stats.detectors.xss)
            assert.is_table(stats.detectors.path_traversal)
        end)
    end)
    
    describe("end-to-end threat detection", function()
        it("should detect SQL injection through orchestrator", function()
            mock_kong.request.get_raw_query = function() return "id=1 UNION SELECT password" end
            
            local score, threat_type, details = orchestrator:detect_threats({})
            
            assert.is_true(score > 0.9)
            assert.equals("sql_injection", threat_type)
            assert.is_table(details)
            assert.is_table(details.detections)
            assert.is_true(details.detections.sql_injection.score > 0.9)
        end)
        
        it("should detect XSS through orchestrator", function()
            mock_kong.request.get_raw_query = function() return "comment=<script>alert('xss')</script>" end
            
            local score, threat_type, details = orchestrator:detect_threats({})
            
            assert.is_true(score > 0.8)
            assert.equals("xss", threat_type)
            assert.is_table(details.detections)
            assert.is_true(details.detections.xss.score > 0.8)
        end)
        
        it("should detect path traversal through orchestrator", function()
            mock_kong.request.get_path = function() return "/api/files" end
            mock_kong.request.get_raw_query = function() return "file=../../../etc/passwd" end
            
            local score, threat_type, details = orchestrator:detect_threats({})
            
            assert.is_true(score > 0.8)
            assert.equals("path_traversal", threat_type)
            assert.is_table(details.detections)
            assert.is_true(details.detections.path_traversal.score > 0.8)
        end)
        
        it("should return clean results for legitimate requests", function()
            mock_kong.request.get_path = function() return "/api/users" end
            mock_kong.request.get_raw_query = function() return "page=1&limit=10" end
            
            local score, threat_type, details = orchestrator:detect_threats({})
            
            assert.equals(0, score)
            assert.equals("none", threat_type)
            assert.is_table(details.detections)
        end)
    end)
    
    describe("performance and caching integration", function()
        it("should use performance utilities for string caching", function()
            local str1 = performance_utils.get_cached_string("test_string")
            local str2 = performance_utils.get_cached_string("test_string")
            
            -- Should return the same cached instance
            assert.is_true(str1 == str2)
        end)
        
        it("should use performance utilities for table pooling", function()
            local table1 = performance_utils.get_pooled_table()
            table1.test = "data"
            performance_utils.return_pooled_table(table1)
            
            local table2 = performance_utils.get_pooled_table()
            
            -- Should reuse the same table instance (but cleared)
            assert.is_true(table1 == table2)
            assert.is_nil(table2.test)
        end)
        
        it("should cache threat detection results", function()
            mock_kong.request.get_path = function() return "/api/test" end
            mock_kong.request.get_raw_query = function() return "param=value" end
            
            -- First detection - should compute
            local start_time = os.clock()
            local score1, threat_type1, details1 = orchestrator:detect_threats({})
            local first_time = os.clock() - start_time
            
            -- Second detection - should use cache
            start_time = os.clock()
            local score2, threat_type2, details2 = orchestrator:detect_threats({})
            local second_time = os.clock() - start_time
            
            -- Results should be identical
            assert.equals(score1, score2)
            assert.equals(threat_type1, threat_type2)
            
            -- Second call should be faster (cached)
            -- Note: This is a rough check, in real scenarios the difference would be more significant
            assert.is_true(second_time <= first_time + 0.001) -- Allow for small timing variations
        end)
    end)
    
    describe("module interoperability", function()
        it("should allow individual detector usage", function()
            local sql_det = sql_injection_detector.new(config)
            local xss_det = xss_detector.new(config)
            local path_det = path_traversal_detector.new(config)
            
            assert.is_not_nil(sql_det)
            assert.is_not_nil(xss_det)
            assert.is_not_nil(path_det)
            
            -- Each should have their own detect method
            assert.is_function(sql_det.detect)
            assert.is_function(xss_det.detect)
            assert.is_function(path_det.detect)
        end)
        
        it("should support pattern updates across detectors", function()
            local updates = {
                sql_injection = {"custom_sql_pattern"},
                xss = {"custom_xss_pattern"},
                path_traversal = {"custom_path_pattern"}
            }
            
            orchestrator:update_threat_patterns(updates)
            
            -- Verify patterns were updated (check stats)
            local stats = orchestrator:get_stats()
            assert.is_table(stats.detectors.sql_injection)
            assert.is_table(stats.detectors.xss)
            assert.is_table(stats.detectors.path_traversal)
        end)
        
        it("should handle module loader for dynamic loading", function()
            -- Test that module loader can load modules dynamically
            local loaded_module = module_loader.load_module("modules.threat.sql_injection_detector")
            assert.is_not_nil(loaded_module)
            assert.is_function(loaded_module.new)
            
            -- Test caching
            local loaded_again = module_loader.load_module("modules.threat.sql_injection_detector")
            assert.is_true(loaded_module == loaded_again)
        end)
    end)
    
    describe("error handling and resilience", function()
        it("should handle malformed requests gracefully", function()
            mock_kong.request.get_path = function() error("simulated error") end
            
            assert.has_no.errors(function()
                local score, threat_type, details = orchestrator:detect_threats({})
                -- Should return safe defaults on error
                assert.is_number(score)
                assert.is_string(threat_type)
                assert.is_table(details)
            end)
        end)
        
        it("should handle missing request data gracefully", function()
            mock_kong.request.get_path = function() return nil end
            mock_kong.request.get_raw_query = function() return nil end
            mock_kong.request.get_raw_body = function() return nil end
            
            assert.has_no.errors(function()
                local score, threat_type, details = orchestrator:detect_threats({})
                assert.is_number(score)
                assert.is_string(threat_type)
            end)
        end)
        
        it("should maintain performance under load", function()
            -- Simulate multiple concurrent detections
            local start_time = os.clock()
            
            for i = 1, 50 do
                mock_kong.request.get_raw_query = function() return "param" .. i .. "=value" .. i end
                orchestrator:detect_threats({})
            end
            
            local total_time = os.clock() - start_time
            
            -- Should handle 50 detections in reasonable time
            assert.is_true(total_time < 2.0) -- Less than 2 seconds
        end)
    end)
end)