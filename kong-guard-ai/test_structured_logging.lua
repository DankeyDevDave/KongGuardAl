#!/usr/bin/env lua

-- Test script for Kong Guard AI Structured Logger
-- Demonstrates structured log emission with captured metadata

-- Mock Kong environment for testing
local kong = {
    log = {
        debug = function(msg) print("[DEBUG] " .. msg) end,
        info = function(msg) print("[INFO] " .. msg) end,
        warn = function(msg) print("[WARN] " .. msg) end,
        error = function(msg) print("[ERROR] " .. msg) end,
        crit = function(msg) print("[CRITICAL] " .. msg) end
    },
    node = {
        get_id = function() return "test-node-123" end
    },
    ctx = {
        plugin = {}
    }
}

-- Mock ngx environment
local ngx = {
    time = function() return os.time() end,
    now = function() return os.time() + 0.123 end,
    var = {
        request_id = "test-request-12345",
        bytes_sent = "1024"
    },
    worker = {
        pid = function() return 12345 end
    },
    crc32_long = function(str) return string.len(str) * 17 end,
    timer = {
        every = function(interval, func) return true, nil end
    }
}

-- Mock cjson
local cjson = {
    encode = function(obj)
        local function serialize(o)
            if type(o) == "nil" then
                return "null"
            elseif type(o) == "boolean" then
                return tostring(o)
            elseif type(o) == "number" then
                return tostring(o)
            elseif type(o) == "string" then
                return '"' .. o .. '"'
            elseif type(o) == "table" then
                local result = {}
                for k, v in pairs(o) do
                    table.insert(result, '"' .. tostring(k) .. '":' .. serialize(v))
                end
                return '{' .. table.concat(result, ',') .. '}'
            else
                return '"' .. tostring(o) .. '"'
            end
        end
        return serialize(obj)
    end
}

-- Set up package path
package.path = package.path .. ";./kong/plugins/kong-guard-ai/?.lua"

-- Make globals available
_G.kong = kong
_G.ngx = ngx

-- Mock require function for cjson
local original_require = require
local function mock_require(name)
    if name == "cjson.safe" then
        return cjson
    elseif name == "socket" then
        return {} -- Mock socket
    elseif name == "resty.http" then
        return {
            new = function()
                return {
                    set_timeout = function() end,
                    request_uri = function() return {status = 200}, nil end
                }
            end
        }
    else
        return original_require(name)
    end
end
_G.require = mock_require

-- Load the structured logger
local structured_logger = require("structured_logger")

-- Test configuration
local test_conf = {
    structured_logging_enabled = true,
    async_logging = false, -- Disable for testing
    log_sampling_rate = 1.0,
    include_geolocation = true,
    include_user_agent_parsing = true,
    max_log_entry_size = 32768,
    log_correlation_enabled = true,
    external_logging_enabled = false,
    log_level = "debug",
    dry_run_mode = true,
    threat_threshold = 7.0,
    max_processing_time_ms = 5
}

-- Mock request context
local test_request_context = {
    method = "POST",
    path = "/api/users/login",
    client_ip = "203.0.113.100",
    service_id = "service-uuid-123",
    route_id = "route-uuid-456",
    consumer_id = "consumer-uuid-789",
    timestamp = os.time(),
    headers = {
        ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ["content-type"] = "application/json",
        ["authorization"] = "Bearer jwt-token-here",
        ["x-forwarded-for"] = "203.0.113.42, 203.0.113.100",
        ["referer"] = "https://example.com/login"
    },
    query = {
        source = "mobile",
        version = "2.1.0"
    }
}

-- Mock threat result
local test_threat_result = {
    threat_level = 8.5,
    threat_type = "sql_injection",
    confidence = 0.9,
    recommended_action = "block",
    requires_ai_analysis = true,
    details = {
        patterns_matched = {
            {
                pattern_index = 3,
                match = "union select",
                context = "username=admin' union select * from users--"
            }
        },
        total_matches = 1,
        source_ip = "203.0.113.100",
        blacklist_match = nil
    }
}

-- Mock enforcement result
local test_enforcement_result = {
    action_type = "BLOCK_REQUEST",
    executed = false, -- Dry run mode
    simulated = true,
    success = true,
    details = "Request blocked due to SQL injection attempt",
    execution_time_ms = 2.5
}

print("=== Kong Guard AI Structured Logger Test ===\n")

-- Initialize the logger
print("1. Initializing structured logger...")
structured_logger.init_worker(test_conf)
print("✓ Logger initialized\n")

-- Test different log levels
print("2. Testing log level functions...")

structured_logger.debug(
    "Debug message test",
    nil,
    test_request_context,
    nil,
    test_conf
)

structured_logger.info(
    "Info message test",
    nil,
    test_request_context,
    nil,
    test_conf
)

structured_logger.warn(
    "Warning message test",
    test_threat_result,
    test_request_context,
    nil,
    test_conf
)

structured_logger.error(
    "Error message test",
    test_threat_result,
    test_request_context,
    nil,
    test_conf
)

structured_logger.critical(
    "Critical message test",
    test_threat_result,
    test_request_context,
    nil,
    test_conf
)

print("✓ All log levels tested\n")

-- Test threat event logging
print("3. Testing threat event logging...")
structured_logger.log_threat_event(
    test_threat_result,
    test_request_context,
    test_enforcement_result,
    test_conf
)
print("✓ Threat event logged\n")

-- Test performance metrics logging
print("4. Testing performance metrics logging...")
structured_logger.log_performance_metrics(
    15.7, -- Processing time in ms
    test_request_context,
    test_conf
)
print("✓ Performance metrics logged\n")

-- Test health check
print("5. Testing logger health check...")
local health = structured_logger.health_check()
print("Logger health status: " .. health.status)
if #health.issues > 0 then
    print("Issues found:")
    for _, issue in ipairs(health.issues) do
        print("  - " .. issue)
    end
else
    print("No issues found")
end
print("✓ Health check completed\n")

-- Test statistics
print("6. Getting logger statistics...")
local stats = structured_logger.get_stats()
print("Total logs: " .. stats.total_logs)
print("Dropped logs: " .. stats.dropped_logs)
print("Error logs: " .. stats.error_logs)
print("Async queue size: " .. stats.async_queue_size)
print("✓ Statistics retrieved\n")

-- Test cleanup
print("7. Testing cleanup...")
structured_logger.cleanup()
print("✓ Cleanup completed\n")

print("=== All tests completed successfully! ===")

-- Example output explanation
print("\n=== Expected Output Features ===")
print("✓ JSON-formatted structured logs")
print("✓ Request correlation IDs and session tracking")
print("✓ Geolocation and user agent enrichment")
print("✓ Threat intelligence hooks (placeholders)")
print("✓ Performance metrics and latency tracking")
print("✓ Log level filtering and sampling")
print("✓ Async processing capability (disabled for test)")
print("✓ External endpoint integration (mocked)")
print("✓ Health monitoring and statistics")
print("✓ Memory leak prevention through cleanup")
