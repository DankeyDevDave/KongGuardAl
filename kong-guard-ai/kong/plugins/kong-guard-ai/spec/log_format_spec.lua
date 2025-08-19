-- Kong Guard AI - Log Format Module Test Specification
-- Test structured JSON logging functionality and security features
-- Compatible with Kong's busted test framework

local log_format = require "kong.plugins.kong-guard-ai.log_format"

describe("Kong Guard AI Log Format", function()
    
    local mock_kong, mock_ngx
    
    before_each(function()
        -- Mock Kong API
        mock_kong = {
            log = {
                info = function() end,
                warn = function() end,
                error = function() end,
                debug = function() end,
                serialize = function() 
                    return { request = { id = "test-request-123" } }
                end
            },
            request = {
                get_method = function() return "POST" end,
                get_path = function() return "/api/v1/users" end,
                get_headers = function() 
                    return {
                        ["user-agent"] = "curl/7.68.0",
                        ["content-type"] = "application/json",
                        ["authorization"] = "Bearer abc123xyz789",
                        ["x-forwarded-for"] = "203.0.113.1, 192.168.1.1",
                        ["x-real-ip"] = "203.0.113.1",
                        ["content-length"] = "156",
                        ["host"] = "api.example.com"
                    }
                end,
                get_raw_query = function() return "format=json&limit=10" end,
                get_scheme = function() return "https" end
            },
            response = {
                get_status = function() return 200 end,
                get_headers = function()
                    return {
                        ["content-type"] = "application/json",
                        ["content-length"] = "512",
                        ["server"] = "nginx/1.21.0",
                        ["set-cookie"] = "session=abc123; Path=/; HttpOnly"
                    }
                end
            },
            client = {
                get_ip = function() return "203.0.113.1" end,
                get_consumer = function() 
                    return { id = "consumer-123", username = "test_user" }
                end
            },
            router = {
                get_service = function() 
                    return { id = "service-456", name = "user-service" }
                end,
                get_route = function() 
                    return { id = "route-789", name = "users-route" }
                end
            },
            node = {
                get_id = function() return "kong-node-1" end
            },
            ctx = {
                plugin = {
                    guard_ai_request_start_time = 1640995200.123,
                    guard_ai_processing_time = 2.5
                }
            }
        }
        
        -- Mock ngx API
        mock_ngx = {
            time = function() return 1640995200 end,
            now = function() return 1640995200.456 end,
            var = {
                request_id = "req-test-456"
            }
        }
        
        -- Set globals
        _G.kong = mock_kong
        _G.ngx = mock_ngx
    end)
    
    describe("Real IP Detection", function()
        it("should extract IP from X-Real-IP header", function()
            local ip = log_format.get_real_client_ip()
            assert.equals("203.0.113.1", ip)
        end)
        
        it("should extract first IP from X-Forwarded-For when X-Real-IP missing", function()
            mock_kong.request.get_headers = function()
                return {
                    ["x-forwarded-for"] = "203.0.113.5, 192.168.1.1, 10.0.0.1"
                }
            end
            
            local ip = log_format.get_real_client_ip()
            assert.equals("203.0.113.5", ip)
        end)
        
        it("should fallback to Kong client IP when headers missing", function()
            mock_kong.request.get_headers = function() return {} end
            
            local ip = log_format.get_real_client_ip()
            assert.equals("203.0.113.1", ip)
        end)
    end)
    
    describe("Header Filtering", function()
        it("should filter and include only selected headers", function()
            local headers = {
                ["user-agent"] = "curl/7.68.0",
                ["authorization"] = "Bearer secret123",
                ["content-type"] = "application/json",
                ["x-internal-secret"] = "should-not-appear",
                ["accept"] = "application/json"
            }
            
            local filtered = log_format.extract_selected_headers(headers)
            
            assert.is_not_nil(filtered["user-agent"])
            assert.is_not_nil(filtered["authorization"])
            assert.is_not_nil(filtered["content-type"])
            assert.is_not_nil(filtered["accept"])
            assert.is_nil(filtered["x-internal-secret"])
        end)
        
        it("should redact authorization header values", function()
            local headers = {
                ["authorization"] = "Bearer secret123token"
            }
            
            local filtered = log_format.extract_selected_headers(headers)
            
            assert.equals("Bearer [REDACTED]", filtered["authorization"])
        end)
        
        it("should truncate very long header values", function()
            local long_value = string.rep("x", 600)
            local headers = {
                ["user-agent"] = long_value
            }
            
            local filtered = log_format.extract_selected_headers(headers)
            
            assert.is_true(#filtered["user-agent"] <= 512)
            assert.is_true(string.find(filtered["user-agent"], "%.%.%.$"))
        end)
    end)
    
    describe("Access Log Entry", function()
        it("should create structured access log with all required fields", function()
            local conf = { dry_run_mode = false, log_level = "info" }
            local entry = log_format.create_access_log_entry(conf)
            
            -- Verify required fields
            assert.is_not_nil(entry.timestamp)
            assert.is_not_nil(entry.iso_timestamp)
            assert.is_not_nil(entry.request_id)
            assert.equals("203.0.113.1", entry.client_ip)
            assert.equals("POST", entry.method)
            assert.equals("/api/v1/users", entry.path)
            assert.equals("access", entry.log_type)
            
            -- Verify Kong context
            assert.equals("service-456", entry.service_id)
            assert.equals("user-service", entry.service_name)
            assert.equals("route-789", entry.route_id)
            assert.equals("consumer-123", entry.consumer_id)
            
            -- Verify headers are filtered
            assert.is_not_nil(entry.headers["user-agent"])
            assert.equals("Bearer [REDACTED]", entry.headers["authorization"])
        end)
    end)
    
    describe("Response Log Entry", function()
        it("should create structured response log with latency metrics", function()
            local conf = { dry_run_mode = true, log_level = "info" }
            local processing_time = 3.2
            local entry = log_format.create_response_log_entry(conf, processing_time)
            
            -- Verify required fields
            assert.is_not_nil(entry.timestamp)
            assert.equals("203.0.113.1", entry.client_ip)
            assert.equals(200, entry.status)
            assert.equals("response", entry.log_type)
            
            -- Verify latency metrics
            assert.is_not_nil(entry.latency)
            assert.is_not_nil(entry.latency.request)
            assert.equals(3.2, entry.latency.guard_ai_processing)
            
            -- Verify response headers filtering
            assert.is_not_nil(entry.response_headers["content-type"])
            assert.is_not_nil(entry.response_headers["server"])
        end)
    end)
    
    describe("Threat Incident Log", function()
        it("should create comprehensive threat incident log", function()
            local threat_result = {
                threat_type = "sql_injection",
                threat_level = 8.5,
                confidence = 0.95,
                details = { pattern_matched = "union select" },
                patterns_matched = {"union.*select"},
                risk_score = 8.5,
                detection_engine = "static_rules"
            }
            
            local request_context = {
                client_ip = "203.0.113.1",
                method = "POST",
                path = "/api/v1/search",
                headers = {
                    ["user-agent"] = "BadBot/1.0",
                    ["content-type"] = "application/json"
                },
                service_id = "service-456",
                route_id = "route-789",
                consumer_id = "consumer-123"
            }
            
            local response_action = {
                action_type = "block_request",
                executed = true,
                simulated = false,
                success = true,
                details = "Request blocked due to SQL injection",
                execution_time_ms = 1.2
            }
            
            local conf = { dry_run_mode = false }
            
            local entry = log_format.create_threat_incident_log(
                threat_result, request_context, response_action, conf)
            
            -- Verify incident structure
            assert.equals("threat_incident", entry.log_type)
            assert.equals("threat_detected", entry.incident_type)
            assert.equals("high", entry.severity)
            assert.is_not_nil(entry.incident_id)
            
            -- Verify threat details
            assert.equals("sql_injection", entry.threat.type)
            assert.equals(8.5, entry.threat.level)
            assert.equals(0.95, entry.threat.confidence)
            
            -- Verify response action
            assert.equals("block_request", entry.response_action.action_type)
            assert.is_true(entry.response_action.executed)
            assert.is_true(entry.response_action.success)
        end)
    end)
    
    describe("Log Level Parsing", function()
        it("should parse valid log levels correctly", function()
            assert.equals(1, log_format.parse_log_level("debug"))
            assert.equals(2, log_format.parse_log_level("info"))
            assert.equals(3, log_format.parse_log_level("warn"))
            assert.equals(4, log_format.parse_log_level("error"))
        end)
        
        it("should default to INFO for invalid log levels", function()
            assert.equals(2, log_format.parse_log_level("invalid"))
            assert.equals(2, log_format.parse_log_level(""))
            assert.equals(2, log_format.parse_log_level(nil))
        end)
    end)
    
    describe("Security Features", function()
        it("should redact authorization headers in request logs", function()
            local headers = {
                ["authorization"] = "Bearer very-secret-token-12345"
            }
            
            local filtered = log_format.extract_selected_headers(headers)
            assert.is_true(string.find(filtered["authorization"], "%[REDACTED%]"))
        end)
        
        it("should sanitize cookie values in response headers", function()
            local response_headers = {
                ["set-cookie"] = "session=secret123; Path=/; HttpOnly"
            }
            
            local filtered = log_format.extract_response_headers(response_headers)
            assert.equals("session", filtered["set-cookie"])
        end)
        
        it("should handle multiple cookies", function()
            local response_headers = {
                ["set-cookie"] = {
                    "session=value1; Path=/",
                    "csrf=value2; HttpOnly"
                }
            }
            
            local filtered = log_format.extract_response_headers(response_headers)
            assert.same({"session", "csrf"}, filtered["set-cookie"])
        end)
    end)
    
    describe("Performance Optimization", function()
        it("should validate log entries efficiently", function()
            local valid_entry = {
                timestamp = 1640995200,
                log_type = "access",
                request_id = "test-123"
            }
            
            assert.is_true(log_format.validate_log_entry(valid_entry))
        end)
        
        it("should detect invalid log entries", function()
            local invalid_entry = {
                timestamp = 1640995200
                -- Missing log_type and request_id
            }
            
            assert.is_false(log_format.validate_log_entry(invalid_entry))
        end)
    end)
    
    describe("Severity Mapping", function()
        it("should map threat levels to correct severities", function()
            assert.equals("critical", log_format.map_threat_level_to_severity(9.5))
            assert.equals("high", log_format.map_threat_level_to_severity(7.8))
            assert.equals("medium", log_format.map_threat_level_to_severity(5.2))
            assert.equals("low", log_format.map_threat_level_to_severity(3.1))
            assert.equals("info", log_format.map_threat_level_to_severity(1.5))
        end)
    end)
end)