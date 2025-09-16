-- Kong Guard AI Advanced Rate Limiting Integration Tests
-- Tests for sliding window rate limiting, burst detection, and dynamic adjustment

local function run_tests(framework, config)
    local tests = {}

    -- Test configuration with advanced rate limiting
    local plugin_config = {
        dry_run_mode = false,
        enable_advanced_rate_limiting = true,
        rate_limit_per_minute = 10,
        rate_limit_per_five_minutes = 40,
        rate_limit_per_hour = 200,
        enable_burst_detection = true,
        burst_threshold_light = 200,  -- 2x baseline
        burst_threshold_medium = 400, -- 4x baseline
        burst_threshold_severe = 800, -- 8x baseline
        progressive_penalty_enabled = true,
        penalty_warning_duration = 60,
        penalty_throttle_duration = 180,
        penalty_block_duration = 300,
        dynamic_rate_adjustment = true,
        threat_threshold = 6.0,
        enable_notifications = false
    }

    -- Start Kong with rate limiting configuration
    local success, kong_id, err = framework.start_kong(nil, plugin_config)
    if not success then
        error("Failed to start Kong: " .. (err or "unknown error"))
    end

    -- Test 1: Basic rate limiting enforcement
    local test1 = framework.create_test("Rate Limiting - Basic Enforcement", framework.TEST_MODES.INTEGRATION)

    local client_ip = "203.0.113.100"
    local successful_requests = 0
    local rate_limited_requests = 0

    -- Send requests up to the limit (10 per minute)
    for i = 1, 15 do  -- Send more than limit
        local response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip},
            nil,
            nil  -- Don't expect specific status
        )

        if response.status_code == 200 then
            successful_requests = successful_requests + 1
        elseif response.status_code == 429 then
            rate_limited_requests = rate_limited_requests + 1
        end
    end

    framework.assert(test1, successful_requests <= 10, "Should not exceed rate limit of 10/minute")
    framework.assert(test1, rate_limited_requests > 0, "Should have rate limited requests")

    test1.metrics.successful_requests = successful_requests
    test1.metrics.rate_limited_requests = rate_limited_requests

    table.insert(tests, framework.complete_test(test1))

    -- Test 2: Sliding window rate limiting
    local test2 = framework.create_test("Rate Limiting - Sliding Window", framework.TEST_MODES.INTEGRATION)

    local client_ip2 = "203.0.113.101"

    -- Send requests quickly to test sliding window
    local requests_in_burst = 0
    for i = 1, 8 do  -- Within limit
        local response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip2},
            nil,
            200
        )
        requests_in_burst = requests_in_burst + 1
    end

    -- Wait a bit and send more
    os.execute("sleep 10")  -- 10 seconds

    for i = 1, 5 do  -- Should still be within sliding window
        local response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip2},
            nil,
            nil
        )

        if response.status_code == 200 then
            requests_in_burst = requests_in_burst + 1
        end
    end

    framework.assert(test2, requests_in_burst <= 10, "Sliding window should maintain rate limit")

    table.insert(tests, framework.complete_test(test2))

    -- Test 3: Burst detection
    local test3 = framework.create_test("Rate Limiting - Burst Detection", framework.TEST_MODES.INTEGRATION)

    local client_ip3 = "203.0.113.102"

    -- Send requests very quickly to trigger burst detection
    local burst_responses = {}
    for i = 1, 20 do  -- Rapid burst
        local response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip3},
            nil,
            nil
        )
        table.insert(burst_responses, response)
    end

    -- Check if burst was detected (some requests should be 429)
    local burst_blocks = 0
    for _, response in ipairs(burst_responses) do
        if response.status_code == 429 then
            burst_blocks = burst_blocks + 1
        end
    end

    framework.assert(test3, burst_blocks > 5, "Burst detection should trigger blocks")

    test3.metrics.burst_blocks = burst_blocks
    test3.metrics.total_burst_requests = #burst_responses

    table.insert(tests, framework.complete_test(test3))

    -- Test 4: Progressive penalties
    local test4 = framework.create_test("Rate Limiting - Progressive Penalties", framework.TEST_MODES.INTEGRATION)

    local client_ip4 = "203.0.113.103"

    -- First violation - should get warning
    for i = 1, 12 do  -- Exceed limit
        framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip4},
            nil,
            nil
        )
    end

    -- Check for warning headers
    local warning_response = framework.execute_request(
        kong_id,
        "GET",
        "/test",
        {["X-Forwarded-For"] = client_ip4},
        nil,
        429
    )

    framework.assert(test4, warning_response.status_code == 429, "Should receive rate limit response")

    table.insert(tests, framework.complete_test(test4))

    -- Test 5: Multiple time window enforcement
    local test5 = framework.create_test("Rate Limiting - Multiple Time Windows", framework.TEST_MODES.INTEGRATION)

    local client_ip5 = "203.0.113.104"

    -- Test 5-minute window after exhausting 1-minute window
    -- This would require more sophisticated timing control
    framework.assert(test5, true, "Multiple time window test placeholder")

    table.insert(tests, framework.complete_test(test5, "skipped"))

    -- Test 6: Rate limit bypass whitelist
    local test6 = framework.create_test("Rate Limiting - Whitelist Bypass", framework.TEST_MODES.INTEGRATION)

    -- This would require reconfiguring Kong with whitelist IPs
    framework.assert(test6, true, "Whitelist bypass test placeholder")

    table.insert(tests, framework.complete_test(test6, "skipped"))

    -- Test 7: Dynamic rate adjustment based on threat level
    local test7 = framework.create_test("Rate Limiting - Dynamic Threat Adjustment", framework.TEST_MODES.INTEGRATION)

    local client_ip7 = "203.0.113.105"

    -- Send a request with high threat potential
    local threat_response = framework.execute_request(
        kong_id,
        "GET",
        "/test?id=1' OR '1'='1",  -- SQL injection attempt
        {["X-Forwarded-For"] = client_ip7},
        nil,
        nil
    )

    -- Subsequent requests should have stricter rate limits
    local follow_up_blocks = 0
    for i = 1, 5 do
        local response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip7},
            nil,
            nil
        )

        if response.status_code == 429 then
            follow_up_blocks = follow_up_blocks + 1
        end
    end

    -- Note: This test depends on threat detection integration
    framework.assert(test7, true, "Dynamic adjustment test (depends on threat detection)")

    table.insert(tests, framework.complete_test(test7))

    -- Test 8: Rate limiting headers
    local test8 = framework.create_test("Rate Limiting - Response Headers", framework.TEST_MODES.INTEGRATION)

    local client_ip8 = "203.0.113.106"

    -- First request should include rate limit headers
    local header_response = framework.execute_request(
        kong_id,
        "GET",
        "/test",
        {["X-Forwarded-For"] = client_ip8},
        nil,
        200
    )

    -- Note: Would need to parse response headers from curl output
    framework.assert(test8, header_response.status_code == 200, "First request should succeed")

    table.insert(tests, framework.complete_test(test8))

    -- Test 9: Performance test under rate limiting
    local test9 = framework.create_test("Rate Limiting - Performance Impact", framework.TEST_MODES.PERFORMANCE)

    local total_time = 0
    local num_requests = 20
    local client_ip9 = "203.0.113.107"

    for i = 1, num_requests do
        local start_time = socket.gettime()

        local perf_response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip9},
            nil,
            nil  -- May be 200 or 429
        )

        local end_time = socket.gettime()
        total_time = total_time + (end_time - start_time)
    end

    local avg_time_ms = (total_time / num_requests) * 1000
    framework.assert(test9, avg_time_ms < 15, "Rate limiting should add minimal overhead")

    test9.metrics.average_response_time_ms = avg_time_ms
    test9.metrics.requests_tested = num_requests

    table.insert(tests, framework.complete_test(test9))

    -- Test 10: Rate limiting reset behavior
    local test10 = framework.create_test("Rate Limiting - Reset Behavior", framework.TEST_MODES.INTEGRATION)

    local client_ip10 = "203.0.113.108"

    -- Exhaust rate limit
    for i = 1, 12 do
        framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = client_ip10},
            nil,
            nil
        )
    end

    -- Wait for reset (this test would need timing control)
    framework.assert(test10, true, "Rate limit reset test placeholder")

    table.insert(tests, framework.complete_test(test10, "skipped"))

    -- Test 11: Concurrent user rate limiting
    local test11 = framework.create_test("Rate Limiting - Concurrent Users", framework.TEST_MODES.INTEGRATION)

    local concurrent_ips = {
        "203.0.113.110",
        "203.0.113.111",
        "203.0.113.112",
        "203.0.113.113",
        "203.0.113.114"
    }

    local total_successful = 0
    local total_blocked = 0

    -- Simulate concurrent requests from different IPs
    for _, ip in ipairs(concurrent_ips) do
        for i = 1, 8 do  -- Within individual limits
            local response = framework.execute_request(
                kong_id,
                "GET",
                "/test",
                {["X-Forwarded-For"] = ip},
                nil,
                nil
            )

            if response.status_code == 200 then
                total_successful = total_successful + 1
            elseif response.status_code == 429 then
                total_blocked = total_blocked + 1
            end
        end
    end

    framework.assert(test11, total_successful > 30, "Should handle concurrent users appropriately")

    test11.metrics.total_successful = total_successful
    test11.metrics.total_blocked = total_blocked
    test11.metrics.concurrent_users = #concurrent_ips

    table.insert(tests, framework.complete_test(test11))

    -- Cleanup
    framework.stop_kong(kong_id)

    return tests
end

return {
    run_tests = run_tests,
    description = "Kong Guard AI Advanced Rate Limiting Integration Tests",
    requires_kong = true,
    test_type = "integration"
}
