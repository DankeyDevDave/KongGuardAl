-- AI Integration Test
-- Tests the integration between the extracted AI modules and the handler

local luaunit = require 'luaunit'

-- Mock Kong environment
local mock_ngx = {
    shared = {
        kong_cache = {
            cache = {},
            get = function(self, key) return self.cache[key] end,
            set = function(self, key, value, ttl) self.cache[key] = value end,
            incr = function(self, key, value, init, ttl)
                self.cache[key] = (self.cache[key] or init or 0) + (value or 1)
                return self.cache[key]
            end
        }
    },
    now = function() return 1609459200 end,
    md5 = function(s) return "test_md5_" .. #s end,
    log = {
        warn = function(...) end,
        err = function(...) end,
        info = function(...) end,
        debug = function(...) end
    }
}

local mock_kong = {
    request = {
        get_method = function() return "POST" end,
        get_path = function() return "/api/login" end,
        get_headers = function()
            return {
                ["user-agent"] = "Mozilla/5.0",
                ["content-type"] = "application/json"
            }
        end,
        get_raw_query = function() return "username=admin&password=admin" end,
        get_raw_body = function() return '{"username":"admin","password":"admin"}' end
    },
    client = {
        get_ip = function() return "192.168.1.100" end,
        get_forwarded_ip = function() return "192.168.1.100" end
    }
}

-- Set up test environment
_G.ngx = mock_ngx
_G.kong = mock_kong

-- Load modules
local AIService = require "kong.plugins.kong-guard-ai.modules.ai.ai_service"
local ThreatDetector = require "kong.plugins.kong-guard-ai.modules.ai.threat_detector"

TestAIIntegration = {}

function TestAIIntegration:setUp()
    mock_ngx.shared.kong_cache.cache = {}

    self.config = {
        enable_ai_gateway = false,  -- Disable for unit test
        enable_taxii_ingestion = false,
        ddos_rpm_threshold = 100,
        ai_service_url = "http://test-ai:8000",
        ai_timeout = 1000
    }

    self.ai_service = AIService.new(self.config)
    self.threat_detector = ThreatDetector.new(self.config)
end

function TestAIIntegration:test_end_to_end_sql_injection_detection()
    -- Simulate SQL injection attack
    mock_kong.request.get_raw_query = function()
        return "id=1 union select username,password from users"
    end

    local features = {
        method = "GET",
        path = "/api/user",
        client_ip = "192.168.1.100",
        user_agent = "AttackBot/1.0",
        requests_per_minute = 5,
        content_length = 100,
        query_param_count = 2,
        header_count = 8,
        hour_of_day = 14
    }

    -- Test threat detection
    local threat_score, threat_type, threat_details = self.threat_detector:detect_threat_optimized(features, self.config)

    luaunit.assertEquals(threat_score, 0.95)
    luaunit.assertEquals(threat_type, "sql_injection")
    luaunit.assertNotNil(threat_details)
end

function TestAIIntegration:test_end_to_end_xss_detection()
    -- Simulate XSS attack
    mock_kong.request.get_raw_query = function()
        return "search=<script>alert('xss')</script>"
    end

    local features = {
        method = "GET",
        path = "/search",
        client_ip = "192.168.1.101",
        user_agent = "Mozilla/5.0",
        requests_per_minute = 3,
        content_length = 50,
        query_param_count = 1,
        header_count = 10,
        hour_of_day = 10
    }

    local threat_score, threat_type, threat_details = self.threat_detector:detect_threat_optimized(features, self.config)

    luaunit.assertEquals(threat_score, 0.9)
    luaunit.assertEquals(threat_type, "xss")
end

function TestAIIntegration:test_end_to_end_ddos_detection()
    -- Simulate DDoS attack
    mock_kong.request.get_raw_query = function() return "page=1" end

    local features = {
        method = "GET",
        path = "/api/data",
        client_ip = "192.168.1.102",
        user_agent = "DDoSBot/1.0",
        requests_per_minute = 150,  -- Above threshold
        content_length = 20,
        query_param_count = 1,
        header_count = 5,
        hour_of_day = 12
    }

    local threat_score, threat_type, threat_details = self.threat_detector:detect_threat_optimized(features, self.config)

    luaunit.assertEquals(threat_score, 0.8)
    luaunit.assertEquals(threat_type, "ddos")
end

function TestAIIntegration:test_end_to_end_safe_request()
    -- Simulate safe request
    mock_kong.request.get_raw_query = function() return "page=1&limit=10" end

    local features = {
        method = "GET",
        path = "/api/products",
        client_ip = "192.168.1.200",
        user_agent = "Mozilla/5.0",
        requests_per_minute = 5,
        content_length = 0,
        query_param_count = 2,
        header_count = 8,
        hour_of_day = 14
    }

    local threat_score, threat_type, threat_details = self.threat_detector:detect_threat_optimized(features, self.config)

    luaunit.assertEquals(threat_score, 0)
    luaunit.assertEquals(threat_type, "none")
end

function TestAIIntegration:test_learning_integration()
    -- Test learning from false positive
    local threat_data = {
        type = "sql_injection",
        client_ip = "192.168.1.100",
        score = 0.9
    }

    local feedback = {false_positive = true}

    -- Record false positive
    self.threat_detector:learn_from_feedback(threat_data, feedback)

    -- Test that confidence is adjusted on next detection
    local features = {
        method = "GET",
        path = "/api/user",
        client_ip = "192.168.1.100",
        requests_per_minute = 5
    }

    mock_kong.request.get_raw_query = function()
        return "id=1 union select username,password from users"
    end

    local score, type, details = self.threat_detector:detect_threat_optimized(features, self.config)

    -- Score should be reduced due to false positive learning
    luaunit.assertTrue(score < 0.9)
    luaunit.assertTrue(details.confidence_adjusted)
end

function TestAIIntegration:test_caching_integration()
    -- Test caching behavior
    local features = {
        method = "GET",
        path = "/api/test",
        client_ip = "192.168.1.150",
        requests_per_minute = 5
    }

    mock_kong.request.get_raw_query = function() return "test=safe" end

    -- First call
    local start_time = os.clock()
    local score1, type1, details1 = self.threat_detector:detect_threat_optimized(features, self.config)
    local first_call_time = os.clock() - start_time

    -- Second call (should be cached)
    start_time = os.clock()
    local score2, type2, details2 = self.threat_detector:detect_threat_optimized(features, self.config)
    local second_call_time = os.clock() - start_time

    -- Results should be identical
    luaunit.assertEquals(score1, score2)
    luaunit.assertEquals(type1, type2)

    -- Second call should be faster (cached)
    -- Note: In a real environment, this would be more noticeable
end

function TestAIIntegration:test_statistics_integration()
    -- Test statistics collection across modules

    -- Generate some test activity
    local features = {
        method = "POST",
        path = "/api/login",
        client_ip = "192.168.1.200",
        requests_per_minute = 5
    }

    -- Run detection a few times
    for i = 1, 5 do
        self.threat_detector:detect_threat_optimized(features, self.config)
    end

    -- Check threat detector statistics
    local detector_stats = self.threat_detector:get_statistics()
    luaunit.assertNotNil(detector_stats)
    luaunit.assertNotNil(detector_stats.cache_size)

    -- Check AI service statistics
    local ai_stats = self.ai_service:get_statistics()
    luaunit.assertNotNil(ai_stats)
    luaunit.assertNotNil(ai_stats.service_url)
    luaunit.assertNotNil(ai_stats.timeout_ms)
end

function TestAIIntegration:test_configuration_consistency()
    -- Test that configuration is properly shared between modules
    local new_config = {
        ai_timeout = 2000,
        threat_cache_ttl = 600,
        enable_threat_caching = false
    }

    self.ai_service:configure(new_config)
    self.threat_detector:configure(new_config)

    luaunit.assertEquals(self.ai_service.timeout, 2000)
    luaunit.assertEquals(self.threat_detector.cache_ttl, 600)
    luaunit.assertFalse(self.threat_detector.enable_caching)
end

-- Run the tests
os.exit(luaunit.LuaUnit.run())
