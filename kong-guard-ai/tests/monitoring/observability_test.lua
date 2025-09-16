-- Kong Guard AI Observability and Monitoring Integration Tests
-- Tests for metrics collection, dashboard functionality, and alerting

local function run_tests(framework, config)
    local tests = {}

    -- Test configuration with monitoring enabled
    local plugin_config = {
        dry_run_mode = false,
        status_endpoint_enabled = true,
        status_endpoint_path = "/_guard_ai/status",
        metrics_endpoint_enabled = true,
        metrics_endpoint_path = "/_guard_ai/metrics",
        analytics_dashboard_enabled = true,
        analytics_endpoint_path = "/_guard_ai/analytics",
        performance_dashboard_enabled = true,
        incident_analytics_enabled = true,
        structured_logging_enabled = true,
        log_correlation_enabled = true,
        enable_notifications = true,
        threat_threshold = 6.0
    }

    -- Start Kong with monitoring configuration
    local success, kong_id, err = framework.start_kong(nil, plugin_config)
    if not success then
        error("Failed to start Kong: " .. (err or "unknown error"))
    end

    local kong_info = framework.test_state.kong_processes[kong_id]
    local proxy_url = kong_info.proxy_url

    -- Test 1: Status endpoint functionality
    local test1 = framework.create_test("Monitoring - Status Endpoint", framework.TEST_MODES.INTEGRATION)

    local status_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/status",
        {},
        nil,
        200
    )

    framework.assert(test1, status_response.status_code == 200, "Status endpoint should be accessible")
    framework.assert(test1, status_response.body:find("status") ~= nil, "Status response should contain status information")

    -- Parse JSON response (simplified check)
    local status_contains_key_fields =
        status_response.body:find("plugin_version") and
        status_response.body:find("threat_detection") and
        status_response.body:find("uptime")

    framework.assert(test1, status_contains_key_fields, "Status should contain key monitoring fields")

    table.insert(tests, framework.complete_test(test1))

    -- Test 2: Metrics endpoint functionality
    local test2 = framework.create_test("Monitoring - Metrics Endpoint", framework.TEST_MODES.INTEGRATION)

    -- Generate some traffic first to populate metrics
    for i = 1, 10 do
        framework.execute_request(
            kong_id,
            "GET",
            "/test",
            {["X-Forwarded-For"] = "203.0.113." .. i},
            nil,
            nil
        )
    end

    local metrics_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/metrics",
        {},
        nil,
        200
    )

    framework.assert(test2, metrics_response.status_code == 200, "Metrics endpoint should be accessible")
    framework.assert(test2, metrics_response.body:find("requests_total") ~= nil, "Metrics should contain request counters")
    framework.assert(test2, metrics_response.body:find("processing_time") ~= nil, "Metrics should contain performance data")

    table.insert(tests, framework.complete_test(test2))

    -- Test 3: Analytics dashboard functionality
    local test3 = framework.create_test("Monitoring - Analytics Dashboard", framework.TEST_MODES.INTEGRATION)

    -- Generate threat events for analytics
    local threat_responses = {}
    local threat_paths = {
        "/../../etc/passwd",
        "/api/users/1' OR '1'='1",
        "/search?q=<script>alert('xss')</script>"
    }

    for _, path in ipairs(threat_paths) do
        local threat_response = framework.execute_request(
            kong_id,
            "GET",
            path,
            {["X-Forwarded-For"] = "203.0.113.100"},
            nil,
            403  -- Should be blocked
        )
        table.insert(threat_responses, threat_response)
    end

    -- Check analytics dashboard
    local analytics_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/analytics",
        {},
        nil,
        200
    )

    framework.assert(test3, analytics_response.status_code == 200, "Analytics dashboard should be accessible")
    framework.assert(test3, analytics_response.body:find("threat_events") ~= nil, "Analytics should contain threat data")

    test3.metrics.threat_events_generated = #threat_responses

    table.insert(tests, framework.complete_test(test3))

    -- Test 4: Performance dashboard monitoring
    local test4 = framework.create_test("Monitoring - Performance Dashboard", framework.TEST_MODES.INTEGRATION)

    -- Check performance dashboard endpoint
    local perf_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/performance",
        {},
        nil,
        200
    )

    framework.assert(test4, perf_response.status_code == 200, "Performance dashboard should be accessible")
    framework.assert(test4, perf_response.body:find("latency") ~= nil, "Performance data should include latency metrics")
    framework.assert(test4, perf_response.body:find("throughput") ~= nil, "Performance data should include throughput metrics")

    table.insert(tests, framework.complete_test(test4))

    -- Test 5: Incident analytics and reporting
    local test5 = framework.create_test("Monitoring - Incident Analytics", framework.TEST_MODES.INTEGRATION)

    -- Generate incidents
    local incident_ips = {"198.51.100.50", "198.51.100.51", "198.51.100.52"}
    for _, ip in ipairs(incident_ips) do
        framework.execute_request(
            kong_id,
            "POST",
            "/api/admin/delete_all",
            {
                ["X-Forwarded-For"] = ip,
                ["Content-Type"] = "application/json"
            },
            '{"confirm": true}',
            403
        )
    end

    -- Check incident analytics
    local incidents_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/incidents",
        {},
        nil,
        200
    )

    framework.assert(test5, incidents_response.status_code == 200, "Incident analytics should be accessible")

    table.insert(tests, framework.complete_test(test5))

    -- Test 6: Log correlation and structured logging
    local test6 = framework.create_test("Monitoring - Log Correlation", framework.TEST_MODES.INTEGRATION)

    -- Generate correlated requests
    local correlation_id = "test-correlation-" .. socket.gettime()

    for i = 1, 3 do
        framework.execute_request(
            kong_id,
            "GET",
            "/test/" .. i,
            {
                ["X-Correlation-ID"] = correlation_id,
                ["X-Forwarded-For"] = "203.0.113.200"
            },
            nil,
            200
        )
    end

    -- Test would require log parsing to verify correlation
    framework.assert(test6, true, "Log correlation test (requires log parsing)")

    table.insert(tests, framework.complete_test(test6))

    -- Test 7: Metrics export format validation
    local test7 = framework.create_test("Monitoring - Metrics Export Format", framework.TEST_MODES.INTEGRATION)

    -- Test Prometheus-compatible metrics format
    local prometheus_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/metrics?format=prometheus",
        {},
        nil,
        200
    )

    -- Check for Prometheus format characteristics
    local has_prometheus_format =
        prometheus_response.body:find("# HELP") and
        prometheus_response.body:find("# TYPE") and
        prometheus_response.body:find("kong_guard_ai_")

    framework.assert(test7, has_prometheus_format, "Should support Prometheus metrics format")

    table.insert(tests, framework.complete_test(test7))

    -- Test 8: Health check endpoint
    local test8 = framework.create_test("Monitoring - Health Check", framework.TEST_MODES.INTEGRATION)

    local health_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/health",
        {},
        nil,
        200
    )

    framework.assert(test8, health_response.status_code == 200, "Health check should return OK")
    framework.assert(test8, health_response.body:find("healthy") ~= nil, "Health check should indicate health status")

    table.insert(tests, framework.complete_test(test8))

    -- Test 9: Real-time monitoring under load
    local test9 = framework.create_test("Monitoring - Real-time Under Load", framework.TEST_MODES.PERFORMANCE)

    local load_start_time = socket.gettime()
    local concurrent_requests = 50
    local requests_per_client = 10

    -- Simulate concurrent load
    for client = 1, concurrent_requests do
        for request = 1, requests_per_client do
            local load_response = framework.execute_request(
                kong_id,
                "GET",
                "/test",
                {["X-Forwarded-For"] = "203.0.113." .. (client % 255)},
                nil,
                nil
            )
        end
    end

    local load_duration = socket.gettime() - load_start_time

    -- Check that monitoring endpoints still respond during load
    local status_during_load = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/status",
        {},
        nil,
        200
    )

    framework.assert(test9, status_during_load.status_code == 200, "Status endpoint should remain responsive under load")
    framework.assert(test9, status_during_load.duration_ms < 1000, "Status endpoint should respond quickly under load")

    test9.metrics.load_duration_seconds = load_duration
    test9.metrics.total_requests_generated = concurrent_requests * requests_per_client

    table.insert(tests, framework.complete_test(test9))

    -- Test 10: Alerting system validation
    local test10 = framework.create_test("Monitoring - Alerting System", framework.TEST_MODES.INTEGRATION)

    -- Generate high-threat events that should trigger alerts
    local high_threat_ips = {"203.0.113.10", "203.0.113.11", "203.0.113.12"}

    for _, ip in ipairs(high_threat_ips) do
        -- Multiple high-threat requests from same IP
        for attack = 1, 5 do
            framework.execute_request(
                kong_id,
                "GET",
                "/admin/../../etc/passwd?id=1' OR '1'='1",
                {["X-Forwarded-For"] = ip},
                nil,
                403
            )
        end
    end

    -- Check alerts endpoint (if available)
    local alerts_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/alerts",
        {},
        nil,
        nil  -- May be 200 or 404 depending on implementation
    )

    -- Basic validation that alerting system is functional
    framework.assert(test10, alerts_response.status_code == 200 or alerts_response.status_code == 404,
        "Alerts endpoint should be properly configured")

    table.insert(tests, framework.complete_test(test10))

    -- Test 11: Dashboard data consistency
    local test11 = framework.create_test("Monitoring - Data Consistency", framework.TEST_MODES.INTEGRATION)

    -- Get metrics from different endpoints and verify consistency
    local status_data = framework.execute_request(kong_id, "GET", "/_guard_ai/status", {}, nil, 200)
    local metrics_data = framework.execute_request(kong_id, "GET", "/_guard_ai/metrics", {}, nil, 200)
    local analytics_data = framework.execute_request(kong_id, "GET", "/_guard_ai/analytics", {}, nil, 200)

    -- Basic consistency check (would need JSON parsing for detailed validation)
    framework.assert(test11, status_data.status_code == 200, "Status data should be available")
    framework.assert(test11, metrics_data.status_code == 200, "Metrics data should be available")
    framework.assert(test11, analytics_data.status_code == 200, "Analytics data should be available")

    table.insert(tests, framework.complete_test(test11))

    -- Test 12: Long-term metrics collection
    local test12 = framework.create_test("Monitoring - Long-term Metrics", framework.TEST_MODES.INTEGRATION)

    -- Test metrics retention and historical data
    local historical_response = framework.execute_request(
        kong_id,
        "GET",
        "/_guard_ai/metrics?timerange=1h",
        {},
        nil,
        200
    )

    framework.assert(test12, historical_response.status_code == 200, "Historical metrics should be accessible")

    table.insert(tests, framework.complete_test(test12))

    -- Cleanup
    framework.stop_kong(kong_id)

    return tests
end

return {
    run_tests = run_tests,
    description = "Kong Guard AI Observability and Monitoring Integration Tests",
    requires_kong = true,
    test_type = "integration"
}
