-- Kong Guard AI Path Filter Integration Tests
-- Tests for regex-based path filtering, attack pattern detection, and false positive handling

local function run_tests(framework, config)
    local tests = {}

    -- Test configuration with path filtering enabled
    local plugin_config = {
        dry_run_mode = false,
        enable_path_filtering = true,
        path_filter_block_threshold = 7.0,
        path_filter_suspicious_threshold = 4.0,
        path_filter_case_sensitive = false,
        custom_path_patterns = {
            {
                pattern = "/admin/backdoor.*",
                priority = 1,  -- Critical
                description = "Custom backdoor detection"
            },
            {
                pattern = ".*\\.env$",
                priority = 2,  -- High
                description = "Environment file access"
            }
        },
        path_whitelist = {
            "/health",
            "/status",
            "/api/v1/docs"
        },
        threat_threshold = 6.0,
        enable_notifications = false
    }

    -- Start Kong with path filtering configuration
    local success, kong_id, err = framework.start_kong(nil, plugin_config)
    if not success then
        error("Failed to start Kong: " .. (err or "unknown error"))
    end

    -- Test 1: SQL Injection in URL path
    local test1 = framework.create_test("Path Filter - SQL Injection Detection", framework.TEST_MODES.INTEGRATION)

    local response = framework.execute_request(
        kong_id,
        "GET",
        "/api/users/1' OR '1'='1",  -- SQL injection pattern
        {},
        nil,
        403  -- Should be blocked
    )

    framework.assert(test1, response.status_code == 403, "SQL injection path should be blocked")
    framework.assert(test1, response.duration_ms < 10, "Path filtering should be fast")

    table.insert(tests, framework.complete_test(test1))

    -- Test 2: Directory traversal attack
    local test2 = framework.create_test("Path Filter - Directory Traversal", framework.TEST_MODES.INTEGRATION)

    local response2 = framework.execute_request(
        kong_id,
        "GET",
        "/../../etc/passwd",  -- Directory traversal
        {},
        nil,
        403
    )

    framework.assert(test2, response2.status_code == 403, "Directory traversal should be blocked")

    table.insert(tests, framework.complete_test(test2))

    -- Test 3: XSS in path parameters
    local test3 = framework.create_test("Path Filter - XSS in Path", framework.TEST_MODES.INTEGRATION)

    local response3 = framework.execute_request(
        kong_id,
        "GET",
        "/search/<script>alert('xss')</script>",  -- XSS pattern
        {},
        nil,
        403
    )

    framework.assert(test3, response3.status_code == 403, "XSS pattern in path should be blocked")

    table.insert(tests, framework.complete_test(test3))

    -- Test 4: Custom pattern detection (backdoor)
    local test4 = framework.create_test("Path Filter - Custom Pattern (Backdoor)", framework.TEST_MODES.INTEGRATION)

    local response4 = framework.execute_request(
        kong_id,
        "GET",
        "/admin/backdoor/shell.php",  -- Custom pattern
        {},
        nil,
        403
    )

    framework.assert(test4, response4.status_code == 403, "Custom backdoor pattern should be blocked")

    table.insert(tests, framework.complete_test(test4))

    -- Test 5: Environment file access detection
    local test5 = framework.create_test("Path Filter - Environment File Access", framework.TEST_MODES.INTEGRATION)

    local response5 = framework.execute_request(
        kong_id,
        "GET",
        "/config/.env",  -- Environment file pattern
        {},
        nil,
        403
    )

    framework.assert(test5, response5.status_code == 403, "Environment file access should be blocked")

    table.insert(tests, framework.complete_test(test5))

    -- Test 6: Whitelisted path should be allowed
    local test6 = framework.create_test("Path Filter - Whitelisted Path", framework.TEST_MODES.INTEGRATION)

    local response6 = framework.execute_request(
        kong_id,
        "GET",
        "/health",  -- Whitelisted path
        {},
        nil,
        200  -- Should be allowed
    )

    framework.assert(test6, response6.status_code == 200, "Whitelisted path should be allowed")

    table.insert(tests, framework.complete_test(test6))

    -- Test 7: Admin panel detection
    local test7 = framework.create_test("Path Filter - Admin Panel Detection", framework.TEST_MODES.INTEGRATION)

    local response7 = framework.execute_request(
        kong_id,
        "GET",
        "/wp-admin/admin.php",  -- WordPress admin
        {},
        nil,
        403
    )

    framework.assert(test7, response7.status_code == 403, "WordPress admin path should be blocked")

    table.insert(tests, framework.complete_test(test7))

    -- Test 8: Configuration file exposure
    local test8 = framework.create_test("Path Filter - Config File Exposure", framework.TEST_MODES.INTEGRATION)

    local response8 = framework.execute_request(
        kong_id,
        "GET",
        "/config/database.yml",  -- Configuration file
        {},
        nil,
        403
    )

    framework.assert(test8, response8.status_code == 403, "Configuration file access should be blocked")

    table.insert(tests, framework.complete_test(test8))

    -- Test 9: Case sensitivity test
    local test9 = framework.create_test("Path Filter - Case Insensitive Matching", framework.TEST_MODES.INTEGRATION)

    local response9 = framework.execute_request(
        kong_id,
        "GET",
        "/API/USERS/1' OR '1'='1",  -- Uppercase SQL injection
        {},
        nil,
        403
    )

    framework.assert(test9, response9.status_code == 403, "Case insensitive matching should work")

    table.insert(tests, framework.complete_test(test9))

    -- Test 10: Suspicious threshold test (should not block but log)
    local test10 = framework.create_test("Path Filter - Suspicious Threshold", framework.TEST_MODES.INTEGRATION)

    local response10 = framework.execute_request(
        kong_id,
        "GET",
        "/debug/info.php",  -- Suspicious but below block threshold
        {},
        nil,
        200  -- Should be allowed but logged as suspicious
    )

    framework.assert(test10, response10.status_code == 200, "Suspicious path should be allowed but logged")

    table.insert(tests, framework.complete_test(test10))

    -- Test 11: Performance test with multiple patterns
    local test11 = framework.create_test("Path Filter - Performance Test", framework.TEST_MODES.PERFORMANCE)

    local total_time = 0
    local num_requests = 100
    local test_paths = {
        "/normal/path",
        "/api/users/123",
        "/docs/readme.html",
        "/assets/style.css",
        "/images/logo.png"
    }

    for i = 1, num_requests do
        local test_path = test_paths[(i % #test_paths) + 1]
        local start_time = socket.gettime()

        local perf_response = framework.execute_request(
            kong_id,
            "GET",
            test_path,
            {},
            nil,
            200
        )

        local end_time = socket.gettime()
        total_time = total_time + (end_time - start_time)
    end

    local avg_time_ms = (total_time / num_requests) * 1000
    framework.assert(test11, avg_time_ms < 5, "Average path filtering should be < 5ms")

    test11.metrics.average_filter_time_ms = avg_time_ms
    test11.metrics.requests_tested = num_requests

    table.insert(tests, framework.complete_test(test11))

    -- Test 12: Complex URL encoding bypass attempt
    local test12 = framework.create_test("Path Filter - URL Encoding Bypass", framework.TEST_MODES.INTEGRATION)

    local response12 = framework.execute_request(
        kong_id,
        "GET",
        "/..%2f..%2fetc%2fpasswd",  -- URL encoded directory traversal
        {},
        nil,
        403
    )

    framework.assert(test12, response12.status_code == 403, "URL encoded traversal should be blocked")

    table.insert(tests, framework.complete_test(test12))

    -- Test 13: Multiple attack patterns in single path
    local test13 = framework.create_test("Path Filter - Multiple Attack Patterns", framework.TEST_MODES.INTEGRATION)

    local response13 = framework.execute_request(
        kong_id,
        "GET",
        "/admin/../../../etc/passwd?id=1' OR '1'='1",  -- Multiple patterns
        {},
        nil,
        403
    )

    framework.assert(test13, response13.status_code == 403, "Multiple attack patterns should be blocked")

    table.insert(tests, framework.complete_test(test13))

    -- Test 14: HTTP method bypass test
    local test14 = framework.create_test("Path Filter - HTTP Method Independence", framework.TEST_MODES.INTEGRATION)

    local methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    for _, method in ipairs(methods) do
        local method_response = framework.execute_request(
            kong_id,
            method,
            "/../../etc/passwd",
            {},
            method == "POST" and '{"test": "data"}' or nil,
            403
        )

        framework.assert(test14, method_response.status_code == 403,
            "Path filtering should work for " .. method .. " method")
    end

    table.insert(tests, framework.complete_test(test14))

    -- Test 15: Large path handling
    local test15 = framework.create_test("Path Filter - Large Path Handling", framework.TEST_MODES.INTEGRATION)

    -- Create a very long path with attack pattern
    local long_path = "/api/" .. string.rep("a", 1000) .. "/../../etc/passwd"

    local response15 = framework.execute_request(
        kong_id,
        "GET",
        long_path,
        {},
        nil,
        403
    )

    framework.assert(test15, response15.status_code == 403, "Large path with attack pattern should be blocked")
    framework.assert(test15, response15.duration_ms < 20, "Large path filtering should still be fast")

    table.insert(tests, framework.complete_test(test15))

    -- Cleanup
    framework.stop_kong(kong_id)

    return tests
end

return {
    run_tests = run_tests,
    description = "Kong Guard AI Path Filter Integration Tests",
    requires_kong = true,
    test_type = "integration"
}
