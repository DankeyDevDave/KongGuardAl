-- Kong Guard AI - Path Filter Test Specification
-- Comprehensive tests for regex-based path filtering system

local path_filter = require "kong.plugins.kong-guard-ai.path_filter"

describe("Kong Guard AI Path Filter", function()

    local test_conf = {
        enable_path_filtering = true,
        path_filter_block_threshold = 7.0,
        path_filter_suspicious_threshold = 4.0,
        custom_path_patterns = {},
        path_whitelist = {},
        path_filter_skip_methods = {"OPTIONS"},
        path_filter_case_sensitive = false,
        path_filter_max_pattern_matches = 10,
        path_filter_analytics_enabled = true
    }

    local test_request_context = {
        method = "GET",
        client_ip = "203.0.113.100",
        correlation_id = "test-123"
    }

    before_each(function()
        -- Initialize path filter before each test
        path_filter.init_worker(test_conf)
    end)

    describe("Initialization", function()
        it("should initialize with default patterns", function()
            path_filter.init_worker(test_conf)
            local pattern_count = path_filter.get_pattern_count()
            assert.is_true(pattern_count > 50) -- Should have many default patterns
        end)

        it("should compile custom patterns", function()
            local custom_conf = {
                enable_path_filtering = true,
                custom_path_patterns = {
                    {pattern = "(?i)custom_attack", priority = 1, description = "Custom attack pattern"}
                }
            }
            path_filter.init_worker(custom_conf)
            -- Should not throw errors during compilation
            assert.is_true(true)
        end)
    end)

    describe("Path Normalization", function()
        it("should decode URL encoded paths", function()
            local normalized = path_filter.normalize_path("/test%2E%2E%2Fetc%2Fpasswd")
            assert.equals("/test../etc/passwd", normalized)
        end)

        it("should handle double URL encoding", function()
            local normalized = path_filter.normalize_path("/test%252E%252E%252Fetc")
            assert.equals("/test../etc", normalized)
        end)

        it("should convert to lowercase", function()
            local normalized = path_filter.normalize_path("/ADMIN/LOGIN")
            assert.equals("/admin/login", normalized)
        end)

        it("should normalize path separators", function()
            local normalized = path_filter.normalize_path("/test\\admin\\config")
            assert.equals("/test/admin/config", normalized)
        end)

        it("should remove null bytes", function()
            local normalized = path_filter.normalize_path("/test\0/admin")
            assert.equals("/test/admin", normalized)
        end)
    end)

    describe("SQL Injection Detection", function()
        it("should detect UNION SELECT attacks", function()
            local request = {
                path = "/search?q=test' UNION SELECT password FROM users--",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-sql-1"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
            assert.is_true(result.threat_level >= 7)
            assert.equals("sql_injection", result.threat_category)
        end)

        it("should detect SQL injection with OR clause", function()
            local request = {
                path = "/login?username=admin' OR 1=1--",
                method = "POST",
                client_ip = "203.0.113.100",
                correlation_id = "test-sql-2"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(result.threat_level > 0)
            assert.equals("sql_injection", result.threat_category)
        end)

        it("should detect DROP TABLE attacks", function()
            local request = {
                path = "/api/data?query='; DROP TABLE users; --",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-sql-3"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
            assert.is_true(result.threat_level >= 7)
        end)
    end)

    describe("XSS Detection", function()
        it("should detect script tag injection", function()
            local request = {
                path = "/profile?name=<script>alert('xss')</script>",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-xss-1"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
            assert.equals("cross_site_scripting", result.threat_category)
        end)

        it("should detect javascript protocol", function()
            local request = {
                path = "/redirect?url=javascript:alert(document.cookie)",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-xss-2"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
        end)

        it("should detect event handler injection", function()
            local request = {
                path = "/search?q=test\" onload=alert('xss')",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-xss-3"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(result.threat_level > 0)
        end)
    end)

    describe("Path Traversal Detection", function()
        it("should detect directory traversal", function()
            local request = {
                path = "/download?file=../../../etc/passwd",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-traversal-1"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
            assert.equals("path_traversal", result.threat_category)
        end)

        it("should detect URL encoded traversal", function()
            local request = {
                path = "/file?path=%2e%2e%2fetc%2fpasswd",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-traversal-2"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
        end)

        it("should detect Windows system access", function()
            local request = {
                path = "/logs?file=..\\..\\windows\\system32\\config\\sam",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-traversal-3"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
        end)
    end)

    describe("Admin Access Detection", function()
        it("should detect admin panel access", function()
            local request = {
                path = "/admin/",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-admin-1"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(result.threat_level >= 4) -- Should be suspicious or blocked
            assert.equals("admin_access", result.threat_category)
        end)

        it("should detect WordPress admin access", function()
            local request = {
                path = "/wp-admin/admin.php",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-admin-2"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(result.threat_level >= 4)
        end)

        it("should detect phpMyAdmin access", function()
            local request = {
                path = "/phpmyadmin/index.php",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-admin-3"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(result.threat_level >= 4)
        end)
    end)

    describe("Configuration File Access Detection", function()
        it("should detect .env file access", function()
            local request = {
                path = "/.env",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-config-1"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.equals(path_filter.get_filter_results().BLOCK, result.result)
            assert.equals("config_exposure", result.threat_category)
        end)

        it("should detect .htaccess access", function()
            local request = {
                path = "/.htaccess",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-config-2"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(result.threat_level >= 4)
        end)

        it("should detect git repository access", function()
            local request = {
                path = "/.git/config",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-config-3"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(result.threat_level >= 4)
        end)
    end)

    describe("False Positive Mitigation", function()
        it("should allow legitimate API endpoints", function()
            local request = {
                path = "/api/v1/users/select",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-fp-1"
            }

            local result = path_filter.analyze_path(request, test_conf)
            -- Should not block legitimate API calls even if they contain SQL keywords
            assert.not_equals(path_filter.get_filter_results().BLOCK, result.result)
        end)

        it("should respect whitelist", function()
            local whitelist_conf = {
                enable_path_filtering = true,
                path_filter_block_threshold = 7.0,
                path_filter_suspicious_threshold = 4.0,
                path_whitelist = {"/admin/dashboard"},
                custom_path_patterns = {}
            }

            local request = {
                path = "/admin/dashboard",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-fp-2"
            }

            local result = path_filter.analyze_path(request, whitelist_conf)
            -- Should allow whitelisted paths
            assert.equals(path_filter.get_filter_results().ALLOW, result.result)
        end)

        it("should handle static file requests", function()
            local request = {
                path = "/assets/admin.css",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-fp-3"
            }

            local result = path_filter.analyze_path(request, test_conf)
            -- Should not block static files even if path contains admin
            assert.not_equals(path_filter.get_filter_results().BLOCK, result.result)
        end)
    end)

    describe("Method Filtering", function()
        it("should skip filtering for excluded methods", function()
            local skip_conf = {
                enable_path_filtering = true,
                path_filter_skip_methods = {"OPTIONS", "HEAD"}
            }

            local request = {
                path = "/admin/config",
                method = "OPTIONS",
                client_ip = "203.0.113.100",
                correlation_id = "test-method-1"
            }

            local should_filter = path_filter.should_filter_path(skip_conf, request)
            assert.is_false(should_filter)
        end)

        it("should filter non-excluded methods", function()
            local request = {
                path = "/admin/config",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-method-2"
            }

            local should_filter = path_filter.should_filter_path(test_conf, request)
            assert.is_true(should_filter)
        end)
    end)

    describe("Analytics", function()
        it("should track analytics", function()
            local request = {
                path = "/test/path",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-analytics-1"
            }

            -- Perform multiple analyses
            for i = 1, 5 do
                path_filter.analyze_path(request, test_conf)
            end

            local analytics = path_filter.get_analytics()
            assert.is_true(analytics.total_checks >= 5)
        end)

        it("should calculate block rate", function()
            -- Create request that should be blocked
            local malicious_request = {
                path = "/test' UNION SELECT * FROM users--",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-analytics-2"
            }

            -- Create benign request
            local benign_request = {
                path = "/test/normal",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-analytics-3"
            }

            -- Analyze both
            path_filter.analyze_path(malicious_request, test_conf)
            path_filter.analyze_path(benign_request, test_conf)

            local analytics = path_filter.get_analytics()
            assert.is_true(analytics.block_rate >= 0)
            assert.is_true(analytics.block_rate <= 100)
        end)
    end)

    describe("Custom Patterns", function()
        it("should use custom patterns", function()
            local custom_conf = {
                enable_path_filtering = true,
                path_filter_block_threshold = 7.0,
                custom_path_patterns = {
                    {pattern = "(?i)custom_malicious_pattern", priority = 1, description = "Custom attack"}
                }
            }

            path_filter.init_worker(custom_conf)

            local request = {
                path = "/test/custom_malicious_pattern/attack",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-custom-1"
            }

            local result = path_filter.analyze_path(request, custom_conf)
            assert.is_true(result.threat_level >= 7)
            assert.is_true(#result.matched_patterns > 0)
        end)
    end)

    describe("Performance", function()
        it("should process requests efficiently", function()
            local request = {
                path = "/api/v1/users",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-perf-1"
            }

            local start_time = ngx.now()

            -- Perform 100 analyses
            for i = 1, 100 do
                path_filter.analyze_path(request, test_conf)
            end

            local end_time = ngx.now()
            local total_time = (end_time - start_time) * 1000 -- Convert to milliseconds
            local avg_time = total_time / 100

            -- Should process each request in under 1ms on average
            assert.is_true(avg_time < 1.0, "Average processing time: " .. avg_time .. "ms")
        end)
    end)

    describe("Multiple Pattern Matches", function()
        it("should handle multiple pattern matches correctly", function()
            local request = {
                path = "/admin/login?username=admin' OR 1=1--&redirect=<script>alert('xss')</script>",
                method = "GET",
                client_ip = "203.0.113.100",
                correlation_id = "test-multi-1"
            }

            local result = path_filter.analyze_path(request, test_conf)
            assert.is_true(#result.matched_patterns > 1) -- Should match multiple patterns
            assert.is_true(result.threat_level >= 7) -- High threat due to multiple matches
        end)
    end)
end)
