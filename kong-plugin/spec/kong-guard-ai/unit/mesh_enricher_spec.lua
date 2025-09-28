local MeshEnricher = require "kong.plugins.kong-guard-ai.mesh_enricher"

describe("Mesh Enricher", function()
    local config, mesh_enricher

    before_each(function()
        config = {
            mesh_header_map = {
                trace_id = "X-Request-ID",
                namespace = "X-K8s-Namespace",
                workload = "X-K8s-Workload",
                service = "X-K8s-Service",
                pod = "X-K8s-Pod",
                zone = "X-K8s-Zone",
                mesh_source = "X-Mesh-Source"
            },
            mesh_cache_ttl_seconds = 300,
            mesh_risky_namespaces = {"admin", "kube-system", "istio-system"},
            mesh_score_weights = {
                cross_namespace = 0.3,
                risky_namespace = 0.3,
                unusual_pair = 0.3,
                missing_headers = 0.1
            },
            mesh_pair_window_seconds = 3600
        }

        mesh_enricher = MeshEnricher:new(config)

        -- Mock ngx.shared.kong_cache
        _G.ngx = {
            shared = {
                kong_cache = {
                    get = function(self, key) return nil end,
                    incr = function(self, key, value, init, ttl) return value end,
                    set = function(self, key, value, ttl) return true end
                }
            }
        }

        -- Mock kong.log
        _G.kong = {
            log = {
                warn = function(...) end,
                info = function(...) end,
                debug = function(...) end
            },
            router = {
                get_service = function() return nil end,
                get_route = function() return nil end
            }
        }
    end)

    describe("initialization", function()
        it("should create a new MeshEnricher instance with config", function()
            assert.is_not_nil(mesh_enricher)
            assert.equals(300, mesh_enricher.cache_ttl)
            assert.equals(3600, mesh_enricher.pair_window)
        end)

        it("should use default values when config is missing", function()
            local default_enricher = MeshEnricher:new({})
            assert.equals(300, default_enricher.cache_ttl)
            assert.equals(3600, default_enricher.pair_window)
        end)
    end)

    describe("read_headers", function()
        local mock_request

        before_each(function()
            mock_request = {
                get_headers = function()
                    return {
                        ["X-Request-ID"] = "trace-123",
                        ["X-K8s-Namespace"] = "production",
                        ["X-K8s-Service"] = "user-service",
                        ["X-K8s-Workload"] = "user-deployment",
                        ["X-K8s-Pod"] = "user-pod-abc123",
                        ["X-K8s-Zone"] = "us-west-2a",
                        ["X-Mesh-Source"] = "frontend-service.production"
                    }
                end
            }
        end)

        it("should extract all mesh metadata from headers", function()
            local mesh_data = mesh_enricher:read_headers(mock_request, config)

            assert.equals("trace-123", mesh_data.trace_id)
            assert.equals("production", mesh_data.namespace)
            assert.equals("user-service", mesh_data.service)
            assert.equals("user-deployment", mesh_data.workload)
            assert.equals("user-pod-abc123", mesh_data.pod)
            assert.equals("us-west-2a", mesh_data.zone)
            assert.equals("frontend-service.production", mesh_data.mesh_source)
        end)

        it("should handle missing headers gracefully", function()
            mock_request.get_headers = function()
                return {
                    ["X-K8s-Namespace"] = "production",
                    ["X-K8s-Service"] = "user-service"
                }
            end

            local mesh_data = mesh_enricher:read_headers(mock_request, config)

            assert.is_nil(mesh_data.trace_id)
            assert.equals("production", mesh_data.namespace)
            assert.equals("user-service", mesh_data.service)
            assert.is_nil(mesh_data.workload)
        end)

        it("should handle empty headers", function()
            mock_request.get_headers = function()
                return {}
            end

            local mesh_data = mesh_enricher:read_headers(mock_request, config)

            assert.is_nil(mesh_data.namespace)
            assert.is_nil(mesh_data.service)
            assert.is_nil(mesh_data.workload)
        end)
    end)

    describe("normalize", function()
        it("should normalize valid values", function()
            assert.equals("production", mesh_enricher:normalize("Production"))
            assert.equals("user-service", mesh_enricher:normalize("  User-Service  "))
            assert.equals("my.namespace", mesh_enricher:normalize("My.Namespace"))
        end)

        it("should reject invalid values", function()
            assert.is_nil(mesh_enricher:normalize(nil))
            assert.is_nil(mesh_enricher:normalize(""))
            assert.is_nil(mesh_enricher:normalize("  "))
            assert.is_nil(mesh_enricher:normalize("invalid@namespace"))
            assert.is_nil(mesh_enricher:normalize(string.rep("a", 300))) -- too long
        end)

        it("should handle non-string inputs", function()
            assert.is_nil(mesh_enricher:normalize(123))
            assert.is_nil(mesh_enricher:normalize(true))
            assert.is_nil(mesh_enricher:normalize({}))
        end)
    end)

    describe("is_risky_namespace", function()
        it("should identify risky namespaces", function()
            assert.is_true(mesh_enricher:is_risky_namespace("admin"))
            assert.is_true(mesh_enricher:is_risky_namespace("kube-system"))
            assert.is_true(mesh_enricher:is_risky_namespace("istio-system"))
        end)

        it("should not flag safe namespaces", function()
            assert.is_false(mesh_enricher:is_risky_namespace("production"))
            assert.is_false(mesh_enricher:is_risky_namespace("default"))
            assert.is_false(mesh_enricher:is_risky_namespace("user-app"))
        end)

        it("should handle nil namespace", function()
            assert.is_false(mesh_enricher:is_risky_namespace(nil))
        end)
    end)

    describe("generate_pair_key", function()
        it("should generate stable pair keys", function()
            local source = {namespace = "frontend", service = "web"}
            local destination = {namespace = "backend", service = "api"}

            local key = mesh_enricher:generate_pair_key(source, destination)
            assert.equals("mesh_pair:frontend:web->backend:api", key)
        end)

        it("should handle missing source or destination", function()
            local source = {namespace = "frontend", service = "web"}

            assert.is_nil(mesh_enricher:generate_pair_key(nil, source))
            assert.is_nil(mesh_enricher:generate_pair_key(source, nil))
        end)

        it("should handle missing namespace or service fields", function()
            local source = {namespace = "frontend"}
            local destination = {service = "api"}

            local key = mesh_enricher:generate_pair_key(source, destination)
            assert.equals("mesh_pair:frontend:unknown->unknown:api", key)
        end)
    end)

    describe("analyze", function()
        local mesh_data

        before_each(function()
            mesh_data = {
                namespace = "production",
                service = "user-service",
                workload = "user-deployment"
            }
        end)

        it("should detect missing headers", function()
            local incomplete_data = {service = "user-service"}
            local analysis = mesh_enricher:analyze(incomplete_data, config)

            assert.is_true(analysis.missing_headers)
        end)

        it("should detect risky namespace", function()
            mesh_data.namespace = "admin"
            local analysis = mesh_enricher:analyze(mesh_data, config)

            assert.is_true(analysis.risky_namespace)
        end)

        it("should populate source info correctly", function()
            local analysis = mesh_enricher:analyze(mesh_data, config)

            assert.equals("production", analysis.source_info.namespace)
            assert.equals("user-service", analysis.source_info.service)
            assert.equals("user-deployment", analysis.source_info.workload)
        end)
    end)

    describe("calculate_score", function()
        it("should calculate correct scores based on factors", function()
            local analysis = {
                cross_namespace = true,
                risky_namespace = true,
                unusual_pair = false,
                missing_headers = false
            }

            local score = mesh_enricher:calculate_score(analysis, config)
            assert.equals(0.6, score) -- 0.3 + 0.3
        end)

        it("should cap score at 1.0", function()
            local analysis = {
                cross_namespace = true,
                risky_namespace = true,
                unusual_pair = true,
                missing_headers = true
            }

            local score = mesh_enricher:calculate_score(analysis, config)
            assert.equals(1.0, score)
        end)

        it("should return 0 for no threats", function()
            local analysis = {
                cross_namespace = false,
                risky_namespace = false,
                unusual_pair = false,
                missing_headers = false
            }

            local score = mesh_enricher:calculate_score(analysis, config)
            assert.equals(0, score)
        end)
    end)

    describe("generate_threat_details", function()
        it("should generate comprehensive threat details", function()
            local analysis = {
                cross_namespace = true,
                risky_namespace = false,
                unusual_pair = true,
                missing_headers = false,
                source_info = {namespace = "frontend", service = "web"},
                destination_info = {namespace = "backend", service = "api"},
                pair_count = 5
            }

            local score = 0.6
            local details = mesh_enricher:generate_threat_details(analysis, score)

            assert.equals(0.6, details.score)
            assert.equals(5, details.pair_count)
            assert.is_table(details.factors)
            assert.is_table(details.source)
            assert.is_table(details.destination)

            -- Check that factors include the detected threats
            local has_cross_namespace = false
            local has_unusual_pair = false
            for _, factor in ipairs(details.factors) do
                if factor == "cross_namespace_communication" then
                    has_cross_namespace = true
                elseif factor == "unusual_service_pair" then
                    has_unusual_pair = true
                end
            end
            assert.is_true(has_cross_namespace)
            assert.is_true(has_unusual_pair)
        end)
    end)
end)
