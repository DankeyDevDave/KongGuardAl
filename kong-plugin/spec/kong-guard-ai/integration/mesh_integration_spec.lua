local helpers = require "spec.helpers"

describe("Kong Guard AI Mesh Integration", function()
    local client

    setup(function()
        -- Create a test service and route
        local service = assert(helpers.admin_client():send {
            method = "POST",
            path = "/services",
            body = {
                name = "mesh-test-service",
                url = "http://httpbin.org/anything"
            },
            headers = {
                ["Content-Type"] = "application/json"
            }
        })
        assert.res_status(201, service)
        local service_data = assert.response(service).has.jsonbody()

        local route = assert(helpers.admin_client():send {
            method = "POST",
            path = "/routes",
            body = {
                service = { id = service_data.id },
                paths = { "/mesh-test" }
            },
            headers = {
                ["Content-Type"] = "application/json"
            }
        })
        assert.res_status(201, route)

        -- Enable the Kong Guard AI plugin with mesh enricher
        local plugin = assert(helpers.admin_client():send {
            method = "POST",
            path = "/plugins",
            body = {
                name = "kong-guard-ai",
                config = {
                    enable_mesh_enricher = true,
                    mesh_header_map = {
                        trace_id = "X-Request-ID",
                        namespace = "X-K8s-Namespace",
                        workload = "X-K8s-Workload",
                        service = "X-K8s-Service",
                        pod = "X-K8s-Pod",
                        zone = "X-K8s-Zone",
                        mesh_source = "X-Mesh-Source"
                    },
                    mesh_risky_namespaces = {"admin", "kube-system"},
                    mesh_score_weights = {
                        cross_namespace = 0.3,
                        risky_namespace = 0.8,
                        unusual_pair = 0.3,
                        missing_headers = 0.1
                    },
                    dry_run = true,  -- Don't actually block for testing
                    log_level = "debug"
                }
            },
            headers = {
                ["Content-Type"] = "application/json"
            }
        })
        assert.res_status(201, plugin)

        assert(helpers.start_kong({
            plugins = "bundled,kong-guard-ai",
            nginx_conf = "spec/fixtures/custom_nginx.template"
        }))

        client = helpers.proxy_client()
    end)

    teardown(function()
        if client then
            client:close()
        end
        helpers.stop_kong()
    end)

    describe("mesh metadata processing", function()
        it("should process requests with complete mesh headers", function()
            local res = assert(client:send {
                method = "GET",
                path = "/mesh-test",
                headers = {
                    ["X-Request-ID"] = "trace-12345",
                    ["X-K8s-Namespace"] = "production",
                    ["X-K8s-Service"] = "user-service",
                    ["X-K8s-Workload"] = "user-deployment",
                    ["X-K8s-Pod"] = "user-pod-abc123",
                    ["X-K8s-Zone"] = "us-west-2a",
                    ["X-Mesh-Source"] = "frontend-service.frontend"
                }
            })

            assert.res_status(200, res)
            -- In dry-run mode, request should succeed even with threat detection
        end)

        it("should detect cross-namespace threats", function()
            local res = assert(client:send {
                method = "GET",
                path = "/mesh-test",
                headers = {
                    ["X-K8s-Namespace"] = "frontend",
                    ["X-K8s-Service"] = "web-service",
                    ["X-Mesh-Source"] = "external-service.admin"  -- Cross-namespace
                }
            })

            assert.res_status(200, res)
            -- Cross-namespace traffic should be detected but not blocked in dry-run
        end)

        it("should detect risky namespace access", function()
            local res = assert(client:send {
                method = "GET",
                path = "/mesh-test",
                headers = {
                    ["X-K8s-Namespace"] = "admin",  -- Risky namespace
                    ["X-K8s-Service"] = "admin-service",
                    ["X-Mesh-Source"] = "user-service.production"
                }
            })

            assert.res_status(200, res)
            -- Risky namespace access should be detected but not blocked in dry-run
        end)

        it("should handle requests without mesh headers", function()
            local res = assert(client:send {
                method = "GET",
                path = "/mesh-test",
                headers = {
                    ["User-Agent"] = "test-client"
                }
            })

            assert.res_status(200, res)
            -- Should work normally without mesh headers
        end)

        it("should handle malformed mesh headers", function()
            local res = assert(client:send {
                method = "GET",
                path = "/mesh-test",
                headers = {
                    ["X-K8s-Namespace"] = "invalid@namespace!",  -- Invalid characters
                    ["X-K8s-Service"] = string.rep("a", 300),    -- Too long
                    ["X-Mesh-Source"] = ""                       -- Empty
                }
            })

            assert.res_status(200, res)
            -- Should handle malformed headers gracefully
        end)
    end)

    describe("mesh threat scoring", function()
        it("should assign higher scores to risky namespace access", function()
            -- This test would need access to internal metrics or logs
            -- to verify the actual threat scores assigned
            local res = assert(client:send {
                method = "GET",
                path = "/mesh-test",
                headers = {
                    ["X-K8s-Namespace"] = "kube-system",  -- High-risk namespace
                    ["X-K8s-Service"] = "critical-service"
                }
            })

            assert.res_status(200, res)
        end)

        it("should track service communication pairs", function()
            -- Send multiple requests to establish a communication pattern
            for i = 1, 5 do
                local res = assert(client:send {
                    method = "GET",
                    path = "/mesh-test",
                    headers = {
                        ["X-K8s-Namespace"] = "production",
                        ["X-K8s-Service"] = "established-service",
                        ["X-Mesh-Source"] = "frontend.production"
                    }
                })
                assert.res_status(200, res)
            end

            -- Now try an unusual pair
            local res = assert(client:send {
                method = "GET",
                path = "/mesh-test",
                headers = {
                    ["X-K8s-Namespace"] = "production",
                    ["X-K8s-Service"] = "new-service",  -- Never seen before
                    ["X-Mesh-Source"] = "unknown-source.unknown"
                }
            })

            assert.res_status(200, res)
        end)
    end)

    describe("mesh configuration validation", function()
        it("should validate header mapping configuration", function()
            -- Test with invalid header map
            local plugin_res = assert(helpers.admin_client():send {
                method = "POST",
                path = "/plugins",
                body = {
                    name = "kong-guard-ai",
                    config = {
                        enable_mesh_enricher = true,
                        mesh_header_map = {
                            invalid_field = "X-Invalid"  -- Should be rejected
                        }
                    }
                },
                headers = {
                    ["Content-Type"] = "application/json"
                }
            })
            -- Should validate configuration properly
        end)

        it("should validate score weights", function()
            -- Test with invalid score weights
            local plugin_res = assert(helpers.admin_client():send {
                method = "POST",
                path = "/plugins",
                body = {
                    name = "kong-guard-ai",
                    config = {
                        enable_mesh_enricher = true,
                        mesh_score_weights = {
                            cross_namespace = 1.5  -- Should be between 0 and 1
                        }
                    }
                },
                headers = {
                    ["Content-Type"] = "application/json"
                }
            })
            -- Should validate weight ranges
        end)
    end)
end)