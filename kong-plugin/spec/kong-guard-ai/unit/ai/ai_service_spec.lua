-- AI Service Module Unit Tests
-- Tests for the extracted AI service integration functionality

local luaunit = require 'luaunit'

-- Mock dependencies
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
    now = function() return 1609459200 end, -- Fixed timestamp for testing
    md5 = function(s) return "mocked_md5_" .. #s end,
    log = {
        warn = function(...) end,
        err = function(...) end,
        info = function(...) end
    },
    ctx = {}
}

local mock_kong = {
    request = {
        get_method = function() return "GET" end,
        get_path = function() return "/api/test" end,
        get_headers = function() return {["user-agent"] = "test-agent"} end,
        get_raw_query = function() return "param=value" end,
        get_raw_body = function() return '{"test": "data"}' end
    },
    version = "2.8.0"
}

-- Set up test environment
_G.ngx = mock_ngx
_G.kong = mock_kong

-- Require the module under test
local AIService = require "kong.plugins.kong-guard-ai.modules.ai.ai_service"

TestAIService = {}

function TestAIService:setUp()
    -- Reset mock state before each test
    mock_ngx.shared.kong_cache.cache = {}
    self.ai_service = AIService.new({
        ai_service_url = "http://test-ai-service:8000",
        ai_timeout = 1000,
        ai_max_body_size = 5000
    })
end

function TestAIService:test_new_initializes_correctly()
    local config = {
        ai_service_url = "http://custom-ai:8000",
        ai_timeout = 2000,
        ai_max_body_size = 20000
    }

    local service = AIService.new(config)

    luaunit.assertEquals(service.ai_service_url, "http://custom-ai:8000")
    luaunit.assertEquals(service.timeout, 2000)
    luaunit.assertEquals(service.max_body_size, 20000)
    luaunit.assertNotNil(service.cache)
end

function TestAIService:test_new_uses_defaults()
    local service = AIService.new({})

    luaunit.assertEquals(service.ai_service_url, "http://ai-service:8000")
    luaunit.assertEquals(service.timeout, 500)
    luaunit.assertEquals(service.max_body_size, 10000)
end

function TestAIService:test_build_optimized_request_data()
    local features = {
        method = "POST",
        path = "/api/login",
        client_ip = "192.168.1.100",
        user_agent = "Mozilla/5.0",
        requests_per_minute = 10,
        content_length = 100,
        query_param_count = 2,
        header_count = 5,
        hour_of_day = 14
    }

    local request_data = self.ai_service:build_optimized_request_data(features)

    luaunit.assertNotNil(request_data.features)
    luaunit.assertEquals(request_data.features.method, "POST")
    luaunit.assertEquals(request_data.features.path, "/api/login")
    luaunit.assertEquals(request_data.features.client_ip, "192.168.1.100")
    luaunit.assertNotNil(request_data.context)
    luaunit.assertNotNil(request_data.metadata)
    luaunit.assertEquals(request_data.metadata.plugin_version, "2.0.0")
end

function TestAIService:test_extract_relevant_headers()
    local headers = {
        ["content-type"] = "application/json",
        ["authorization"] = "Bearer secret-token",
        ["accept"] = "application/json",
        ["x-custom-header"] = "custom-value",
        ["user-agent"] = "test-agent"
    }

    local relevant = self.ai_service:extract_relevant_headers(headers)

    luaunit.assertNotNil(relevant["content-type"])
    luaunit.assertNotNil(relevant["accept"])
    luaunit.assertNil(relevant["authorization"]) -- Should be filtered out
    luaunit.assertNil(relevant["x-custom-header"]) -- Should be filtered out
end

function TestAIService:test_parse_ai_response_valid_json()
    local response_body = '{"threat_score": 0.8, "threat_type": "sql_injection", "confidence": 0.9}'

    local result = self.ai_service:parse_ai_response(response_body)

    luaunit.assertEquals(result.threat_score, 0.8)
    luaunit.assertEquals(result.threat_type, "sql_injection")
    luaunit.assertEquals(result.confidence, 0.9)
    luaunit.assertTrue(result.ai_powered)
end

function TestAIService:test_parse_ai_response_invalid_json()
    local response_body = 'invalid json'

    local result = self.ai_service:parse_ai_response(response_body)

    luaunit.assertEquals(result.threat_score, 0)
    luaunit.assertEquals(result.threat_type, "parse_error")
    luaunit.assertNotNil(result.error)
end

function TestAIService:test_parse_ai_response_validates_threat_score()
    local response_body = '{"threat_score": 2.5, "threat_type": "test"}'

    local result = self.ai_service:parse_ai_response(response_body)

    luaunit.assertEquals(result.threat_score, 1.0) -- Should be clamped to 1.0
end

function TestAIService:test_parse_ai_response_ensures_defaults()
    local response_body = '{"some_field": "value"}'

    local result = self.ai_service:parse_ai_response(response_body)

    luaunit.assertEquals(result.threat_score, 0)
    luaunit.assertEquals(result.threat_type, "none")
    luaunit.assertEquals(result.reasoning, "AI analysis")
    luaunit.assertEquals(result.recommended_action, "monitor")
    luaunit.assertNotNil(result.indicators)
end

function TestAIService:test_generate_cache_key()
    local request_data = {
        features = {
            method = "GET",
            path = "/test",
            client_ip = "127.0.0.1",
            query = "param=value"
        }
    }

    local key = self.ai_service:generate_cache_key(request_data)

    luaunit.assertNotNil(key)
    luaunit.assertTrue(#key > 0)
end

function TestAIService:test_update_ai_metrics()
    local config = {}

    self.ai_service:update_ai_metrics(config)

    luaunit.assertEquals(mock_ngx.shared.kong_cache:get("ai_requests"), 1)
    luaunit.assertNotNil(mock_ngx.shared.kong_cache:get("ai_last_response_time"))
end

function TestAIService:test_get_request_count()
    mock_ngx.shared.kong_cache:set("request_count:192.168.1.1", 5)

    local count = self.ai_service:get_request_count("192.168.1.1")

    luaunit.assertEquals(count, 5)
end

function TestAIService:test_get_failed_attempts()
    mock_ngx.shared.kong_cache:set("failed_login:192.168.1.1", 3)

    local attempts = self.ai_service:get_failed_attempts("192.168.1.1")

    luaunit.assertEquals(attempts, 3)
end

function TestAIService:test_calculate_anomaly_score()
    local features = {
        requests_per_minute = 120, -- High rate (anomaly)
        hour_of_day = 2, -- Late night (anomaly)
        header_count = 35, -- Too many headers (anomaly)
        content_length = 2000000, -- Large payload (anomaly)
        query_param_count = 15 -- Many parameters (anomaly)
    }

    local score = self.ai_service:calculate_anomaly_score(features)

    luaunit.assertTrue(score > 0.5)
    luaunit.assertTrue(score <= 1.0)
end

function TestAIService:test_calculate_anomaly_score_normal()
    local features = {
        requests_per_minute = 10, -- Normal rate
        hour_of_day = 14, -- Daytime
        header_count = 8, -- Normal headers
        content_length = 1000, -- Small payload
        query_param_count = 3 -- Few parameters
    }

    local score = self.ai_service:calculate_anomaly_score(features)

    luaunit.assertEquals(score, 0)
end

function TestAIService:test_clear_cache()
    self.ai_service.cache["test_key"] = "test_value"

    self.ai_service:clear_cache()

    luaunit.assertEquals(self.ai_service:get_cache_size(), 0)
end

function TestAIService:test_get_statistics()
    mock_ngx.shared.kong_cache:set("ai_requests", 10)
    mock_ngx.shared.kong_cache:set("ai_blocks", 2)
    mock_ngx.shared.kong_cache:set("ai_last_response_time", 150)

    local stats = self.ai_service:get_statistics()

    luaunit.assertEquals(stats.ai_requests, 10)
    luaunit.assertEquals(stats.ai_blocks, 2)
    luaunit.assertEquals(stats.last_response_time, 150)
    luaunit.assertNotNil(stats.service_url)
    luaunit.assertNotNil(stats.timeout_ms)
end

function TestAIService:test_configure()
    local new_config = {
        ai_service_url = "http://new-ai:9000",
        ai_timeout = 3000,
        ai_max_body_size = 15000
    }

    self.ai_service:configure(new_config)

    luaunit.assertEquals(self.ai_service.ai_service_url, "http://new-ai:9000")
    luaunit.assertEquals(self.ai_service.timeout, 3000)
    luaunit.assertEquals(self.ai_service.max_body_size, 15000)
end

-- Run the tests
os.exit(luaunit.LuaUnit.run())
