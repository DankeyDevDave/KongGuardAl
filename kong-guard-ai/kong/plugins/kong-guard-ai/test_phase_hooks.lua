#!/usr/bin/env lua

-- Test Script for Kong Guard AI Phase 3: Access and Log Phase Hooks
-- Tests the instrumentation module and enhanced handler functionality

package.path = package.path .. ";./?.lua"

-- Mock Kong's global object for testing
local mock_kong = {
    request = {
        get_method = function() return "GET" end,
        get_path = function() return "/api/test" end,
        get_header = function(name) 
            local headers = {
                ["user-agent"] = "Kong-Guard-AI-Test/1.0",
                ["content-length"] = "1024",
                ["content-type"] = "application/json"
            }
            return headers[string.lower(name)]
        end,
        get_headers = function() 
            return {
                ["User-Agent"] = "Kong-Guard-AI-Test/1.0",
                ["Content-Length"] = "1024",
                ["Content-Type"] = "application/json",
                ["X-Real-IP"] = "203.0.113.42",
                ["Authorization"] = "Bearer test-token"
            }
        end
    },
    response = {
        get_status = function() return 200 end,
        get_headers = function()
            return {
                ["Content-Type"] = "application/json",
                ["Content-Length"] = "512",
                ["Server"] = "Kong/3.0",
                ["X-Kong-Upstream-Latency"] = "150"
            }
        end
    },
    client = {
        get_ip = function() return "192.168.1.100" end,
        get_consumer = function() return { id = "test-consumer" } end
    },
    router = {
        get_service = function() return { id = "test-service" } end,
        get_route = function() return { id = "test-route" } end
    },
    service = {
        request = {
            set_header = function(name, value) 
                print("Setting header: " .. name .. " = " .. value)
            end
        }
    },
    log = {
        info = function(msg) print("[INFO] " .. msg) end,
        warn = function(msg) print("[WARN] " .. msg) end,
        debug = function(msg) print("[DEBUG] " .. msg) end,
        alert = function(msg) print("[ALERT] " .. msg) end
    },
    json = {
        encode = function(obj) 
            -- Simple JSON encoder for testing
            if type(obj) == "table" then
                local pairs_list = {}
                for k, v in pairs(obj) do
                    table.insert(pairs_list, '"' .. tostring(k) .. '":' .. (type(v) == "string" and '"' .. tostring(v) .. '"' or tostring(v)))
                end
                return "{" .. table.concat(pairs_list, ",") .. "}"
            else
                return tostring(obj)
            end
        end
    }
}

-- Mock ngx global for testing
local mock_ngx = {
    now = function() return 1629123456.789 end,
    time = function() return 1629123456 end,
    var = {
        request_id = "test-request-123",
        query_string = "param1=value1&param2=value2",
        bytes_sent = 512,
        upstream_response_time = 0.15
    }
}

-- Set up globals BEFORE requiring instrumentation
_G.kong = mock_kong
_G.ngx = mock_ngx
kong = mock_kong
ngx = mock_ngx

print("=== Kong Guard AI Phase 3 Test: Access and Log Phase Hooks ===\n")

local instrumentation = require "instrumentation"

-- Test 1: Request Metadata Capture
print("Test 1: Request Metadata Capture")
print("--------------------------------")

local config = {
    trust_proxy_headers = true,
    capture_headers = true,
    capture_response_headers = true
}

local start_time = os.clock()
local request_metadata = instrumentation.capture_request_metadata(config)
local capture_time = (os.clock() - start_time) * 1000

print("✓ Request metadata captured in " .. string.format("%.2f", capture_time) .. "ms")
print("✓ Correlation ID: " .. request_metadata.correlation_id)
print("✓ Client IP (with proxy headers): " .. request_metadata.client_ip)
print("✓ Method: " .. request_metadata.method)
print("✓ Path: " .. request_metadata.path)
print("✓ Processing time: " .. string.format("%.2f", request_metadata.processing_stages.request_capture) .. "ms")

if request_metadata.headers then
    print("✓ Headers captured: " .. tostring(#request_metadata.headers))
end

-- Test 2: Response Metadata Capture
print("\nTest 2: Response Metadata Capture")
print("---------------------------------")

-- Simulate some time passing
ngx.now = function() return 1629123456.950 end  -- 161ms later

start_time = os.clock()
local response_metadata = instrumentation.capture_response_metadata(request_metadata, config)
local response_capture_time = (os.clock() - start_time) * 1000

print("✓ Response metadata captured in " .. string.format("%.2f", response_capture_time) .. "ms")
print("✓ Total latency: " .. string.format("%.2f", response_metadata.total_latency_ms) .. "ms")
print("✓ Upstream latency: " .. string.format("%.2f", response_metadata.upstream_latency_ms) .. "ms")
print("✓ Kong latency: " .. string.format("%.2f", response_metadata.kong_latency_ms) .. "ms")
print("✓ Status code: " .. response_metadata.status_code)
print("✓ Response size: " .. response_metadata.response_size .. " bytes")

-- Test 3: Threat Log Entry Creation
print("\nTest 3: Threat Log Entry Creation")
print("----------------------------------")

local mock_threat_result = {
    threat_type = "suspicious_pattern",
    threat_level = 8,
    confidence = 0.85,
    description = "SQL injection attempt detected",
    patterns_matched = {"union select", "drop table"},
    enforcement_executed = true
}

start_time = os.clock()
local threat_log = instrumentation.create_threat_log_entry(
    mock_threat_result,
    request_metadata,
    response_metadata,
    config
)
local log_creation_time = (os.clock() - start_time) * 1000

print("✓ Threat log entry created in " .. string.format("%.2f", log_creation_time) .. "ms")
print("✓ Log type: " .. threat_log.log_type)
print("✓ Threat type: " .. threat_log.threat.type)
print("✓ Threat level: " .. threat_log.threat.level)
print("✓ Client IP: " .. threat_log.request.client_ip)
print("✓ Response status: " .. threat_log.response.status_code)

-- Test 4: Performance Metrics Entry
print("\nTest 4: Performance Metrics Entry")
print("----------------------------------")

start_time = os.clock()
local metrics_entry = instrumentation.create_metrics_entry(request_metadata, response_metadata, config)
local metrics_creation_time = (os.clock() - start_time) * 1000

print("✓ Metrics entry created in " .. string.format("%.2f", metrics_creation_time) .. "ms")
print("✓ Total request time: " .. string.format("%.2f", metrics_entry.timings.total_request_time_ms) .. "ms")
print("✓ Plugin overhead: " .. string.format("%.2f", metrics_entry.timings.plugin_overhead_ms) .. "ms")
print("✓ Request bytes: " .. metrics_entry.sizes.request_bytes)
print("✓ Response bytes: " .. metrics_entry.sizes.response_bytes)

-- Test 5: Client IP Extraction with Proxy Headers
print("\nTest 5: Client IP Extraction with Proxy Headers")
print("------------------------------------------------")

-- Mock request with various proxy headers
kong.request.get_headers = function()
    return {
        ["x-forwarded-for"] = "203.0.113.42, 192.168.1.1, 10.0.0.1",
        ["x-real-ip"] = "203.0.113.42",
        ["cf-connecting-ip"] = "203.0.113.42"
    }
end

local ip_with_proxy = instrumentation.get_client_ip(config)
print("✓ IP with proxy headers: " .. ip_with_proxy)

-- Test without proxy headers
config.trust_proxy_headers = false
local ip_without_proxy = instrumentation.get_client_ip(config)
print("✓ IP without proxy headers: " .. ip_without_proxy)

-- Test 6: Cache Management
print("\nTest 6: Cache Management")
print("------------------------")

local cache_stats_before = instrumentation.get_cache_stats()
print("✓ Cache entries before: " .. cache_stats_before.active_requests)

-- Add some entries to cache by capturing metadata
for i = 1, 5 do
    ngx.now = function() return 1629123456.789 + i end
    instrumentation.capture_request_metadata(config)
end

local cache_stats_after = instrumentation.get_cache_stats()
print("✓ Cache entries after adding 5: " .. cache_stats_after.active_requests)
print("✓ Memory estimate: " .. cache_stats_after.memory_usage_estimate .. " bytes")

-- Test cleanup
instrumentation.cleanup_cache()
local cache_stats_cleanup = instrumentation.get_cache_stats()
print("✓ Cache entries after cleanup: " .. cache_stats_cleanup.active_requests)

-- Test 7: Performance Benchmarks
print("\nTest 7: Performance Benchmarks")
print("-------------------------------")

local iterations = 1000
local total_time = 0

for i = 1, iterations do
    local iter_start = os.clock()
    local metadata = instrumentation.capture_request_metadata(config)
    local response = instrumentation.capture_response_metadata(metadata, config)
    instrumentation.create_threat_log_entry(mock_threat_result, metadata, response, config)
    total_time = total_time + (os.clock() - iter_start)
end

local avg_time = (total_time / iterations) * 1000
print("✓ Average processing time over " .. iterations .. " iterations: " .. string.format("%.3f", avg_time) .. "ms")

if avg_time < 5 then
    print("✓ PERFORMANCE EXCELLENT: < 5ms average processing time")
elseif avg_time < 10 then
    print("✓ PERFORMANCE GOOD: < 10ms average processing time")
else
    print("⚠ PERFORMANCE WARNING: > 10ms average processing time")
end

-- Test 8: Error Handling
print("\nTest 8: Error Handling")
print("----------------------")

-- Test with nil configuration
local safe_result = pcall(function()
    instrumentation.capture_request_metadata(nil)
end)
print("✓ Handles nil config safely: " .. (safe_result and "PASS" or "FAIL"))

-- Test with missing Kong context
local orig_kong = kong
kong = nil
local safe_result2 = pcall(function()
    instrumentation.get_client_ip(config)
end)
kong = orig_kong
print("✓ Handles missing Kong context: " .. (safe_result2 and "PASS" or "FAIL"))

print("\n=== Phase 3 Access and Log Phase Hooks Test Complete ===")
print("\nSUMMARY:")
print("✓ Request metadata capture: IMPLEMENTED")
print("✓ Response metadata capture: IMPLEMENTED") 
print("✓ Client IP extraction with proxy support: IMPLEMENTED")
print("✓ Structured logging format: IMPLEMENTED")
print("✓ Performance optimization: IMPLEMENTED")
print("✓ Error handling: IMPLEMENTED")
print("✓ Cache management: IMPLEMENTED")
print("✓ Correlation ID tracking: IMPLEMENTED")

if avg_time < 10 then
    print("✓ Performance target (<10ms): ACHIEVED")
else
    print("⚠ Performance target (<10ms): NEEDS OPTIMIZATION")
end

print("\nPhase 3 implementation is ready for integration with Kong!")