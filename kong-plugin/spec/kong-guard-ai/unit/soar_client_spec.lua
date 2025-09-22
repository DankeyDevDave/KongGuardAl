--- Unit tests for SOAR client module

local SOARClient = require "kong.plugins.kong-guard-ai.soar_client"

describe("SOAR Client", function()
    local client
    local mock_config

    before_each(function()
        mock_config = {
            enable_soar_integration = true,
            soar_config = {
                siem_endpoint = "http://mock-siem:8080/events",
                soar_endpoint = "http://mock-soar:8080/api",
                api_key = "test-api-key",
                timeout_ms = 5000
            }
        }
        client = SOARClient.new(mock_config)
    end)

    describe("new()", function()
        it("should create a new client instance", function()
            assert.is_not_nil(client)
            assert.is_table(client)
        end)

        it("should return nil for invalid config", function()
            local invalid_client = SOARClient.new(nil)
            assert.is_nil(invalid_client)
        end)
    end)

    describe("init()", function()
        it("should initialize successfully with valid config", function()
            local success, err = client:init()
            assert.is_true(success)
            assert.is_nil(err)
        end)

        it("should fail with missing SOAR config", function()
            local bad_config = { enable_soar_integration = true }
            local bad_client = SOARClient.new(bad_config)
            local success, err = bad_client:init()
            assert.is_false(success)
            assert.is_not_nil(err)
        end)

        it("should skip initialization when disabled", function()
            local disabled_config = { enable_soar_integration = false }
            local disabled_client = SOARClient.new(disabled_config)
            local success, err = disabled_client:init()
            assert.is_true(success)
        end)
    end)

    describe("format_siem_event()", function()
        it("should format a security event for SIEM", function()
            local event = {
                id = "test-event-123",
                threat_score = 0.8,
                client_ip = "192.168.1.100",
                request_path = "/api/users",
                message = "SQL injection detected"
            }

            local formatted = client:format_siem_event(event)
            assert.is_not_nil(formatted)
            assert.equals("test-event-123", formatted.event_id)
            assert.equals("high", formatted.severity)
            assert.equals("kong-guard-ai", formatted.source)
            assert.is_table(formatted.details)
        end)

        it("should handle nil event", function()
            local formatted = client:format_siem_event(nil)
            assert.is_nil(formatted)
        end)
    end)

    describe("format_incident_data()", function()
        it("should format threat data for SOAR incident", function()
            local threat_data = {
                threat_score = 0.9,
                client_ip = "10.0.0.1",
                request_path = "/admin",
                message = "High severity threat detected"
            }

            local formatted = client:format_incident_data(threat_data)
            assert.is_not_nil(formatted)
            assert.equals("Kong Guard AI Security Incident", formatted.title)
            assert.equals("critical", formatted.severity)
            assert.equals("open", formatted.status)
            assert.is_table(formatted.details)
        end)

        it("should handle nil threat data", function()
            local formatted = client:format_incident_data(nil)
            assert.is_nil(formatted)
        end)
    end)

    describe("calculate_severity()", function()
        it("should calculate critical severity for high scores", function()
            assert.equals("critical", client:calculate_severity(0.95))
            assert.equals("critical", client:calculate_severity(0.9))
        end)

        it("should calculate high severity for medium-high scores", function()
            assert.equals("high", client:calculate_severity(0.8))
            assert.equals("high", client:calculate_severity(0.7))
        end)

        it("should calculate medium severity for medium scores", function()
            assert.equals("medium", client:calculate_severity(0.6))
            assert.equals("medium", client:calculate_severity(0.5))
        end)

        it("should calculate low severity for low-medium scores", function()
            assert.equals("low", client:calculate_severity(0.4))
            assert.equals("low", client:calculate_severity(0.3))
        end)

        it("should calculate info severity for low scores", function()
            assert.equals("info", client:calculate_severity(0.2))
            assert.equals("info", client:calculate_severity(0.1))
            assert.equals("info", client:calculate_severity(0.0))
        end)
    end)

    describe("queue_event()", function()
        it("should add events to batch queue", function()
            local event = { id = "test-event", threat_score = 0.5 }
            client:queue_event(event)
            assert.equals(1, #client.batch_queue)
            assert.equals(event, client.batch_queue[1])
        end)
    end)

    describe("get_health_status()", function()
        it("should return health status information", function()
            local status = client:get_health_status()
            assert.is_table(status)
            assert.is_boolean(status.enabled)
            assert.is_boolean(status.siem_configured)
            assert.is_boolean(status.soar_configured)
            assert.is_number(status.batch_queue_size)
            assert.is_number(status.last_batch_time)
            assert.is_number(status.retry_count)
        end)
    end)

    describe("send_http_request()", function()
        it("should handle nil URL", function()
            local success, response, err = client:send_http_request(nil, "GET")
            assert.is_false(success)
            assert.is_nil(response)
            assert.is_not_nil(err)
        end)

        it("should handle table body encoding", function()
            local body = { test = "data", number = 123 }
            -- This would normally make an HTTP request, but we're just testing the method exists
            assert.is_function(client.send_http_request)
        end)
    end)
end)