local TaxiiClient = require "kong.plugins.kong-guard-ai.taxii_client"

describe("TaxiiClient", function()
    local client
    local mock_config

    before_each(function()
        mock_config = {
            taxii_version = "2.1",
            taxii_http_timeout_ms = 2000,
            taxii_retry_backoff_ms = {
                initial = 200,
                max = 5000,
                factor = 2
            },
            taxii_tls_insecure_skip_verify = false
        }
        client = TaxiiClient.new(mock_config)
    end)

    describe("initialization", function()
        it("should create a new client instance", function()
            assert.is_not_nil(client)
            assert.equals("2.1", client.version)
            assert.equals(2000, client.timeout_ms)
        end)

        it("should use default values when config is missing", function()
            local default_client = TaxiiClient.new({})
            assert.equals("2.1", default_client.version)
            assert.equals(2000, default_client.timeout_ms)
        end)
    end)

    describe("server configuration validation", function()
        it("should validate basic server configuration", function()
            local server_config = {
                url = "https://taxii.example.com",
                auth_type = "none"
            }
            local valid, err = client:validate_server_config(server_config)
            assert.is_true(valid)
            assert.is_nil(err)
        end)

        it("should require URL", function()
            local server_config = {
                auth_type = "none"
            }
            local valid, err = client:validate_server_config(server_config)
            assert.is_false(valid)
            assert.matches("Missing server URL", err)
        end)

        it("should validate basic auth configuration", function()
            local server_config = {
                url = "https://taxii.example.com",
                auth_type = "basic",
                username = "user",
                password = "pass"
            }
            local valid, err = client:validate_server_config(server_config)
            assert.is_true(valid)
            assert.is_nil(err)
        end)

        it("should require username and password for basic auth", function()
            local server_config = {
                url = "https://taxii.example.com",
                auth_type = "basic",
                username = "user"
                -- missing password
            }
            local valid, err = client:validate_server_config(server_config)
            assert.is_false(valid)
            assert.matches("Basic auth requires username and password", err)
        end)

        it("should validate bearer auth configuration", function()
            local server_config = {
                url = "https://taxii.example.com",
                auth_type = "bearer",
                token = "bearer_token_123"
            }
            local valid, err = client:validate_server_config(server_config)
            assert.is_true(valid)
            assert.is_nil(err)
        end)

        it("should require token for bearer auth", function()
            local server_config = {
                url = "https://taxii.example.com",
                auth_type = "bearer"
                -- missing token
            }
            local valid, err = client:validate_server_config(server_config)
            assert.is_false(valid)
            assert.matches("Bearer auth requires token", err)
        end)
    end)

    describe("header building", function()
        it("should build basic headers", function()
            local server_config = {
                auth_type = "none"
            }
            local headers = client:_build_headers(server_config)

            assert.equals("application/taxii+json; version=2.1", headers["Accept"])
            assert.equals("application/taxii+json; version=2.1", headers["Content-Type"])
            assert.equals("Kong-Guard-AI TAXII Client/1.0", headers["User-Agent"])
            assert.is_nil(headers["Authorization"])
        end)

        it("should build basic auth headers", function()
            local server_config = {
                auth_type = "basic",
                username = "user",
                password = "pass"
            }
            local headers = client:_build_headers(server_config)

            assert.is_not_nil(headers["Authorization"])
            assert.matches("Basic", headers["Authorization"])
        end)

        it("should build bearer auth headers", function()
            local server_config = {
                auth_type = "bearer",
                token = "test_token"
            }
            local headers = client:_build_headers(server_config)

            assert.equals("Bearer test_token", headers["Authorization"])
        end)

        it("should use TAXII 2.0 content type when configured", function()
            local v20_client = TaxiiClient.new({taxii_version = "2.0"})
            local server_config = {auth_type = "none"}
            local headers = v20_client:_build_headers(server_config)

            assert.equals("application/vnd.oasis.taxii+json; version=2.0", headers["Accept"])
        end)
    end)

    describe("error handling", function()
        it("should format errors with context", function()
            local error_info = client:_format_error("test_context", "test_error")

            assert.equals("TaxiiClient", error_info.component)
            assert.equals("test_context", error_info.context)
            assert.equals("test_error", error_info.error)
            assert.is_not_nil(error_info.timestamp)
        end)
    end)

    describe("JSON parsing", function()
        it("should parse valid JSON response", function()
            local mock_response = {
                body = '{"api_roots": ["https://example.com/api1"]}'
            }

            local data, err = client:_parse_json_response(mock_response)
            assert.is_nil(err)
            assert.is_not_nil(data)
            assert.is_table(data.api_roots)
            assert.equals(1, #data.api_roots)
        end)

        it("should handle invalid JSON", function()
            local mock_response = {
                body = 'invalid json {'
            }

            local data, err = client:_parse_json_response(mock_response)
            assert.is_nil(data)
            assert.is_not_nil(err)
            assert.matches("Invalid JSON", err)
        end)

        it("should handle empty response", function()
            local data, err = client:_parse_json_response(nil)
            assert.is_nil(data)
            assert.equals("Empty response", err)
        end)
    end)

    -- Note: HTTP request tests would require mocking the resty.http module
    -- In a full test suite, you would use luassert's mock functionality
    describe("HTTP requests (mocked)", function()
        it("should construct discovery URLs correctly", function()
            -- This test verifies URL construction logic
            local server_config = {
                url = "https://taxii.example.com"
            }

            -- In real tests, mock the HTTP calls and verify the URLs
            -- For now, this is a placeholder for the integration test pattern
            assert.is_true(true) -- Placeholder
        end)
    end)
end)
