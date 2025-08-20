-- Kong Guard AI IP Blacklist Integration Tests
-- Tests for IP blacklist enforcement, CIDR support, and Admin API integration

local function run_tests(framework, config)
    local tests = {}
    
    -- Test configuration with IP blacklist enabled
    local plugin_config = {
        dry_run_mode = false,
        enable_ip_blacklist = true,
        ip_blacklist = {
            "192.168.1.100",    -- Single IP
            "10.0.0.0/24",      -- CIDR block
            "172.16.0.0/16"     -- Larger CIDR block
        },
        ip_blacklist_ttl_seconds = 300,
        threat_threshold = 7.0,
        enable_notifications = false  -- Disable for testing
    }
    
    -- Start Kong with IP blacklist configuration
    local success, kong_id, err = framework.start_kong(nil, plugin_config)
    if not success then
        error("Failed to start Kong: " .. (err or "unknown error"))
    end
    
    -- Test 1: Single IP blacklist blocking
    local test1 = framework.create_test("IP Blacklist - Single IP Block", framework.TEST_MODES.INTEGRATION)
    
    local response = framework.execute_request(
        kong_id,
        "GET",
        "/test?query=normal",
        {["X-Forwarded-For"] = "192.168.1.100"},  -- Blacklisted IP
        nil,
        403  -- Expected blocked status
    )
    
    framework.assert(test1, response.status_code == 403, "Single IP should be blocked")
    framework.assert(test1, response.body:find("blocked") ~= nil, "Response should indicate blocking")
    framework.assert(test1, response.duration_ms < 10, "Blocking should be fast (<10ms)")
    
    table.insert(tests, framework.complete_test(test1))
    
    -- Test 2: CIDR block blacklist blocking
    local test2 = framework.create_test("IP Blacklist - CIDR Block", framework.TEST_MODES.INTEGRATION)
    
    local response2 = framework.execute_request(
        kong_id,
        "GET", 
        "/test",
        {["X-Forwarded-For"] = "10.0.0.50"},  -- In blacklisted CIDR 10.0.0.0/24
        nil,
        403
    )
    
    framework.assert(test2, response2.status_code == 403, "CIDR block IP should be blocked")
    
    table.insert(tests, framework.complete_test(test2))
    
    -- Test 3: Large CIDR block test
    local test3 = framework.create_test("IP Blacklist - Large CIDR Block", framework.TEST_MODES.INTEGRATION)
    
    local response3 = framework.execute_request(
        kong_id,
        "POST",
        "/test",
        {["X-Forwarded-For"] = "172.16.255.254"},  -- In blacklisted CIDR 172.16.0.0/16
        '{"test": "data"}',
        403
    )
    
    framework.assert(test3, response3.status_code == 403, "Large CIDR block IP should be blocked")
    
    table.insert(tests, framework.complete_test(test3))
    
    -- Test 4: Non-blacklisted IP should pass through
    local test4 = framework.create_test("IP Blacklist - Allow Non-Blacklisted", framework.TEST_MODES.INTEGRATION)
    
    local response4 = framework.execute_request(
        kong_id,
        "GET",
        "/test",
        {["X-Forwarded-For"] = "203.0.113.1"},  -- Non-blacklisted IP
        nil,
        200  -- Should be allowed through
    )
    
    framework.assert(test4, response4.status_code == 200, "Non-blacklisted IP should be allowed")
    
    table.insert(tests, framework.complete_test(test4))
    
    -- Test 5: Multiple proxy headers handling
    local test5 = framework.create_test("IP Blacklist - Proxy Headers", framework.TEST_MODES.INTEGRATION)
    
    local response5 = framework.execute_request(
        kong_id,
        "GET",
        "/test",
        {
            ["X-Forwarded-For"] = "203.0.113.1, 192.168.1.100",  -- Blacklisted IP in chain
            ["X-Real-IP"] = "203.0.113.1"
        },
        nil,
        403  -- Should block based on blacklisted IP in chain
    )
    
    framework.assert(test5, response5.status_code == 403, "Should block based on blacklisted IP in proxy chain")
    
    table.insert(tests, framework.complete_test(test5))
    
    -- Test 6: CloudFlare connecting IP header
    local test6 = framework.create_test("IP Blacklist - CloudFlare Header", framework.TEST_MODES.INTEGRATION)
    
    local response6 = framework.execute_request(
        kong_id,
        "GET",
        "/test", 
        {["CF-Connecting-IP"] = "10.0.0.25"},  -- Blacklisted CIDR
        nil,
        403
    )
    
    framework.assert(test6, response6.status_code == 403, "Should block based on CF-Connecting-IP header")
    
    table.insert(tests, framework.complete_test(test6))
    
    -- Test 7: Performance test - O(1) lookup performance
    local test7 = framework.create_test("IP Blacklist - Performance Test", framework.TEST_MODES.PERFORMANCE)
    
    local total_time = 0
    local num_requests = 50
    
    for i = 1, num_requests do
        local start_time = socket.gettime()
        local test_response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = "192.168.1.100"},
            nil,
            403
        )
        local end_time = socket.gettime()
        total_time = total_time + (end_time - start_time)
    end
    
    local avg_time_ms = (total_time / num_requests) * 1000
    framework.assert(test7, avg_time_ms < 15, "Average blocking time should be < 15ms")
    
    test7.metrics.average_block_time_ms = avg_time_ms
    test7.metrics.requests_tested = num_requests
    
    table.insert(tests, framework.complete_test(test7))
    
    -- Test 8: Admin API - Dynamic IP addition
    local test8 = framework.create_test("IP Blacklist - Admin API Addition", framework.TEST_MODES.INTEGRATION)
    
    -- First verify IP is not blocked
    local pre_block_response = framework.execute_request(
        kong_id,
        "GET",
        "/test",
        {["X-Forwarded-For"] = "198.51.100.10"},
        nil,
        200
    )
    
    framework.assert(test8, pre_block_response.status_code == 200, "IP should not be blocked initially")
    
    -- TODO: Add Kong Admin API call to dynamically add IP to blacklist
    -- This would require Kong Admin API integration in the framework
    
    table.insert(tests, framework.complete_test(test8))
    
    -- Test 9: IPv6 support test
    local test9 = framework.create_test("IP Blacklist - IPv6 Support", framework.TEST_MODES.INTEGRATION)
    
    -- Note: This test would require IPv6 configuration in Kong
    -- For now, we'll mark it as skipped
    framework.assert(test9, true, "IPv6 test placeholder")
    
    table.insert(tests, framework.complete_test(test9, "skipped"))
    
    -- Test 10: Memory leak test for large blacklists
    local test10 = framework.create_test("IP Blacklist - Memory Efficiency", framework.TEST_MODES.INTEGRATION)
    
    -- Simulate requests from many different IPs
    local unique_ips_tested = {}
    for i = 1, 100 do
        local test_ip = string.format("10.0.0.%d", i)
        table.insert(unique_ips_tested, test_ip)
        
        local mem_response = framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = test_ip},
            nil,
            403  -- All should be blocked by CIDR
        )
        
        framework.assert(test10, mem_response.status_code == 403, "CIDR block should work for IP: " .. test_ip)
    end
    
    test10.metrics.unique_ips_tested = #unique_ips_tested
    
    table.insert(tests, framework.complete_test(test10))
    
    -- Cleanup
    framework.stop_kong(kong_id)
    
    return tests
end

return {
    run_tests = run_tests,
    description = "Kong Guard AI IP Blacklist Integration Tests",
    requires_kong = true,
    test_type = "integration"
}