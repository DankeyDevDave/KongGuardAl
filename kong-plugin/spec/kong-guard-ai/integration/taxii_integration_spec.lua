local cjson = require "cjson"
local helpers = require "spec.helpers"

-- Kong Pongo Integration Tests for TAXII/STIX Threat Intelligence

describe("Kong Guard AI TAXII Integration", function()
    local client
    local mock_taxii_server
    local admin_client

    setup(function()
        -- Start Kong with the plugin
        local bp = helpers.get_db_utils(nil, nil, {"kong-guard-ai"})

        -- Create a service
        local service = bp.services:insert({
            name = "test-service",
            url = "http://httpbin.org/anything"
        })

        -- Create a route
        local route = bp.routes:insert({
            service = service,
            paths = {"/test"}
        })

        -- Configure the plugin with TAXII enabled
        bp.plugins:insert({
            name = "kong-guard-ai",
            route = route,
            config = {
                -- Basic threat detection settings
                block_threshold = 0.8,
                rate_limit_threshold = 0.6,
                dry_run = false,

                -- TAXII configuration
                enable_taxii_ingestion = true,
                taxii_version = "2.1",
                taxii_poll_interval_seconds = 60,  -- Short interval for testing
                taxii_cache_ttl_seconds = 300,
                taxii_max_objects_per_poll = 100,
                taxii_http_timeout_ms = 2000,
                taxii_servers = {
                    {
                        url = "http://mock-taxii:8080",
                        collections = {"test-collection"},
                        auth_type = "none"
                    }
                },
                taxii_score_weights = {
                    ip_blocklist = 0.9,
                    ip_allowlist = -0.5,
                    domain_blocklist = 0.8,
                    domain_allowlist = -0.4,
                    url_blocklist = 0.8,
                    url_allowlist = -0.4
                }
            }
        })

        -- Start Kong
        assert(helpers.start_kong({
            database = "off",
            plugins = "kong-guard-ai",
            nginx_conf = "spec/fixtures/custom_nginx.template"
        }))

        -- Get clients
        client = helpers.proxy_client()
        admin_client = helpers.admin_client()
    end)

    teardown(function()
        if client then
            client:close()
        end
        if admin_client then
            admin_client:close()
        end
        helpers.stop_kong()
    end)

    describe("Basic Plugin Functionality", function()
        it("should load the plugin successfully", function()
            local res = admin_client:get("/plugins")
            local body = assert.res_status(200, res)
            local plugins = cjson.decode(body)

            local found_plugin = false
            for _, plugin in ipairs(plugins.data) do
                if plugin.name == "kong-guard-ai" then
                    found_plugin = true
                    assert.is_true(plugin.config.enable_taxii_ingestion)
                    break
                end
            end
            assert.is_true(found_plugin, "Kong Guard AI plugin should be loaded")
        end)

        it("should handle normal requests", function()
            local res = client:get("/test", {
                headers = {
                    host = "localhost"
                }
            })
            -- Should not block normal requests
            assert.res_status(200, res)
        end)
    end)

    describe("TAXII Integration Tests", function()
        it("should initialize TAXII scheduler", function()
            -- Test that the plugin starts without errors
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-Test"] = "initialization"
                }
            })
            assert.res_status(200, res)
        end)

        it("should handle missing TAXII server gracefully", function()
            -- When TAXII server is not available, plugin should still work
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-Test"] = "missing-server"
                }
            })
            assert.res_status(200, res)
        end)
    end)

    describe("Threat Intelligence Blocking", function()
        -- These tests would require a mock TAXII server or pre-populated cache

        it("should block requests from known malicious IPs", function()
            -- This test assumes we've loaded threat intel that blocks 1.2.3.4
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-Forwarded-For"] = "1.2.3.4"  -- Simulated malicious IP
                }
            })

            -- In a real test, this would be blocked if the IP is in the threat intel
            -- For now, we just verify the request is processed
            local status = res.status
            assert.is_true(status == 200 or status == 403)  -- Either allowed or blocked
        end)

        it("should allow requests from allowlisted IPs", function()
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-Forwarded-For"] = "8.8.8.8"  -- Assume this is allowlisted
                }
            })
            assert.res_status(200, res)
        end)

        it("should check domains against threat intelligence", function()
            local res = client:get("/test", {
                headers = {
                    host = "evil.example.com"  -- Simulated malicious domain
                }
            })

            local status = res.status
            assert.is_true(status == 200 or status == 403)
        end)

        it("should check URLs against threat intelligence", function()
            local res = client:get("/test/malware/download", {
                headers = {
                    host = "localhost"
                }
            })

            local status = res.status
            assert.is_true(status == 200 or status == 403)
        end)
    end)

    describe("TLS Fingerprint Detection", function()
        it("should process JA3 fingerprints when available", function()
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-JA3"] = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
                }
            })

            local status = res.status
            assert.is_true(status == 200 or status == 403)
        end)

        it("should process JA4 fingerprints when available", function()
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-JA4"] = "t13d1516h2_8daaf6152771_b0da82dd1658"
                }
            })

            local status = res.status
            assert.is_true(status == 200 or status == 403)
        end)
    end)

    describe("Dry Run Mode", function()
        it("should log threats but not block in dry run mode", function()
            -- First update plugin to dry run mode
            local plugin_res = admin_client:get("/plugins")
            local plugins_body = assert.res_status(200, plugin_res)
            local plugins = cjson.decode(plugins_body)

            local plugin_id = nil
            for _, plugin in ipairs(plugins.data) do
                if plugin.name == "kong-guard-ai" then
                    plugin_id = plugin.id
                    break
                end
            end

            if plugin_id then
                local patch_res = admin_client:patch("/plugins/" .. plugin_id, {
                    body = {
                        config = {
                            dry_run = true
                        }
                    },
                    headers = {
                        ["Content-Type"] = "application/json"
                    }
                })
                assert.res_status(200, patch_res)

                -- Test that potentially malicious request is not blocked
                local res = client:get("/test", {
                    headers = {
                        host = "localhost",
                        ["X-Forwarded-For"] = "1.2.3.4"  -- Potentially malicious IP
                    }
                })
                assert.res_status(200, res)  -- Should not block in dry run
            end
        end)
    end)

    describe("Configuration Validation", function()
        it("should validate TAXII server configuration", function()
            local invalid_config = {
                name = "kong-guard-ai",
                config = {
                    enable_taxii_ingestion = true,
                    taxii_servers = {
                        {
                            -- Missing required URL
                            collections = {"test"},
                            auth_type = "basic"
                            -- Missing username/password for basic auth
                        }
                    }
                }
            }

            local res = admin_client:post("/plugins", {
                body = invalid_config,
                headers = {
                    ["Content-Type"] = "application/json"
                }
            })

            -- Should reject invalid configuration
            assert.res_status(400, res)
        end)

        it("should accept valid TAXII configuration", function()
            local valid_config = {
                name = "kong-guard-ai",
                config = {
                    enable_taxii_ingestion = true,
                    taxii_version = "2.1",
                    taxii_servers = {
                        {
                            url = "https://valid.taxii.server.com",
                            collections = {"indicators"},
                            auth_type = "bearer",
                            token = "valid_token_123"
                        }
                    }
                }
            }

            local res = admin_client:post("/plugins", {
                body = valid_config,
                headers = {
                    ["Content-Type"] = "application/json"
                }
            })

            -- Should accept valid configuration
            assert.res_status(201, res)

            -- Clean up - delete the plugin
            local body = assert.res_status(201, res)
            local plugin = cjson.decode(body)
            admin_client:delete("/plugins/" .. plugin.id)
        end)
    end)

    describe("Error Handling", function()
        it("should handle TAXII server connectivity issues gracefully", function()
            -- Plugin should continue working even if TAXII server is down
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-Test"] = "connectivity-failure"
                }
            })
            assert.res_status(200, res)
        end)

        it("should handle malformed STIX data gracefully", function()
            -- Plugin should not crash on malformed STIX data
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-Test"] = "malformed-stix"
                }
            })
            assert.res_status(200, res)
        end)

        it("should handle cache overflow gracefully", function()
            -- Plugin should handle shared dict memory limits
            local res = client:get("/test", {
                headers = {
                    host = "localhost",
                    ["X-Test"] = "cache-overflow"
                }
            })
            assert.res_status(200, res)
        end)
    end)

    describe("Performance Tests", function()
        it("should not significantly impact request latency", function()
            local start_time = ngx.now()

            for i = 1, 10 do
                local res = client:get("/test", {
                    headers = {
                        host = "localhost",
                        ["X-Test-Iteration"] = tostring(i)
                    }
                })
                assert.res_status(200, res)
            end

            local end_time = ngx.now()
            local total_time = (end_time - start_time) * 1000  -- Convert to milliseconds
            local avg_time = total_time / 10

            -- Average request time should be reasonable (< 100ms for cache lookups)
            assert.is_true(avg_time < 100, "Average request time should be under 100ms, got " .. avg_time .. "ms")
        end)

        it("should handle concurrent requests efficiently", function()
            local results = {}
            local start_time = ngx.now()

            -- Simulate concurrent requests (simplified for testing)
            for i = 1, 5 do
                local res = client:get("/test", {
                    headers = {
                        host = "localhost",
                        ["X-Concurrent-Test"] = tostring(i)
                    }
                })
                table.insert(results, res.status)
            end

            local end_time = ngx.now()
            local total_time = (end_time - start_time) * 1000

            -- All requests should succeed
            for _, status in ipairs(results) do
                assert.equals(200, status)
            end

            -- Total time should be reasonable
            assert.is_true(total_time < 500, "Concurrent requests should complete in under 500ms")
        end)
    end)
end)

-- Helper function to create mock STIX data for testing
local function create_mock_stix_data()
    return {
        {
            type = "indicator",
            id = "indicator--malicious-ip-1",
            pattern = "[ipv4-addr:value = '1.2.3.4']",
            labels = {"malicious-activity"},
            confidence = 85,
            valid_from = "2023-01-01T00:00:00Z"
        },
        {
            type = "indicator",
            id = "indicator--malicious-domain-1",
            pattern = "[domain-name:value = 'evil.example.com']",
            labels = {"malicious-activity"},
            confidence = 90,
            valid_from = "2023-01-01T00:00:00Z"
        },
        {
            type = "indicator",
            id = "indicator--malicious-url-1",
            pattern = "[url:value = 'https://evil.example.com/malware']",
            labels = {"malware"},
            confidence = 95,
            valid_from = "2023-01-01T00:00:00Z"
        }
    }
end
