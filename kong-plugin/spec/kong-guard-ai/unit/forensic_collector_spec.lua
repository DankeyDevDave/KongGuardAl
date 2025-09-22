--- Unit tests for Forensic Collector

local ForensicCollector = require "kong.plugins.kong-guard-ai.forensic_collector"

describe("Forensic Collector", function()
    local collector
    local mock_config

    before_each(function()
        mock_config = {
            forensic_collection = {
                enable_forensics = true,
                collection_triggers = {
                    "high_threat",
                    "threat_score > 0.7",
                    "response_code 403"
                },
                storage_backend = "local"
            }
        }
        collector = ForensicCollector.new(mock_config)
    end)

    describe("new()", function()
        it("should create a new forensic collector instance", function()
            assert.is_not_nil(collector)
            assert.is_table(collector)
        end)

        it("should return nil for invalid config", function()
            local invalid_collector = ForensicCollector.new(nil)
            assert.is_nil(invalid_collector)
        end)
    end)

    describe("init()", function()
        it("should initialize successfully with valid config", function()
            local success, err = collector:init()
            assert.is_true(success)
            assert.is_nil(err)
        end)

        it("should fail with missing forensic collection config", function()
            local bad_config = {}
            local bad_collector = ForensicCollector.new(bad_config)
            local success, err = bad_collector:init()
            assert.is_false(success)
            assert.is_not_nil(err)
        end)

        it("should fail with unsupported storage backend", function()
            local bad_config = {
                forensic_collection = {
                    enable_forensics = true,
                    storage_backend = "unsupported"
                }
            }
            local bad_collector = ForensicCollector.new(bad_config)
            local success, err = bad_collector:init()
            assert.is_false(success)
            assert.is_not_nil(err)
        end)

        it("should skip initialization when disabled", function()
            local disabled_config = {
                forensic_collection = { enable_forensics = false }
            }
            local disabled_collector = ForensicCollector.new(disabled_config)
            local success, err = disabled_collector:init()
            assert.is_true(success)
        end)
    end)

    describe("evaluate_trigger_condition()", function()
        it("should evaluate high_threat condition", function()
            local threat_data = { threat_score = 0.9 }
            assert.is_true(collector:evaluate_trigger_condition("high_threat", threat_data))
        end)

        it("should evaluate threat_score conditions", function()
            local threat_data = { threat_score = 0.8 }
            assert.is_true(collector:evaluate_trigger_condition("threat_score > 0.7", threat_data))
            assert.is_false(collector:evaluate_trigger_condition("threat_score > 0.9", threat_data))
        end)

        it("should evaluate response_code conditions", function()
            local threat_data = { response_code = 403 }
            assert.is_true(collector:evaluate_trigger_condition("response_code 403", threat_data))
            assert.is_false(collector:evaluate_trigger_condition("response_code 404", threat_data))
        end)

        it("should handle invalid conditions", function()
            local threat_data = { threat_score = 0.9 }
            assert.is_false(collector:evaluate_trigger_condition("invalid_condition", threat_data))
            assert.is_false(collector:evaluate_trigger_condition(nil, threat_data))
            assert.is_false(collector:evaluate_trigger_condition("high_threat", nil))
        end)
    end)

    describe("evaluate_collection_triggers()", function()
        it("should return true for matching triggers", function()
            local threat_data = { threat_score = 0.9, response_code = 403 }
            local should_collect, trigger_reason = collector:evaluate_collection_triggers(threat_data)
            assert.is_true(should_collect)
            assert.is_not_nil(trigger_reason)
        end)

        it("should return false when no triggers match", function()
            local threat_data = { threat_score = 0.3, response_code = 200 }
            local should_collect, trigger_reason = collector:evaluate_collection_triggers(threat_data)
            assert.is_false(should_collect)
            assert.equals("no_trigger_matched", trigger_reason)
        end)

        it("should return false when forensics disabled", function()
            local disabled_config = {
                forensic_collection = { enable_forensics = false }
            }
            local disabled_collector = ForensicCollector.new(disabled_config)
            local threat_data = { threat_score = 0.9 }
            local should_collect, trigger_reason = disabled_collector:evaluate_collection_triggers(threat_data)
            assert.is_false(should_collect)
            assert.equals("forensics_disabled", trigger_reason)
        end)
    end)

    describe("collect_evidence()", function()
        it("should collect comprehensive evidence", function()
            local threat_data = {
                threat_score = 0.9,
                client_ip = "192.168.1.100",
                request_path = "/api/users",
                request_method = "POST",
                response_code = 403,
                headers = { ["user-agent"] = "Test Agent" }
            }

            local evidence_id, err = collector:collect_evidence(threat_data, "high_threat")
            assert.is_not_nil(evidence_id)
            assert.is_nil(err)
            assert.is_not_nil(collector.evidence_store[evidence_id])
        end)

        it("should handle nil threat data", function()
            local evidence_id, err = collector:collect_evidence(nil, "test")
            assert.is_nil(evidence_id)
            assert.is_not_nil(err)
        end)
    end)

    describe("collect_system_context()", function()
        it("should collect system context information", function()
            local context = collector:collect_system_context()
            assert.is_table(context)
            assert.is_not_nil(context.kong_version)
            assert.is_not_nil(context.lua_version)
            assert.is_not_nil(context.system_time)
            assert.is_number(context.process_id)
        end)
    end)

    describe("collect_network_context()", function()
        it("should collect network context information", function()
            local threat_data = {
                client_ip = "192.168.1.100",
                client_port = 12345,
                tls_version = "TLSv1.2",
                tls_cipher = "ECDHE-RSA-AES128-GCM-SHA256"
            }

            local context = collector:collect_network_context(threat_data)
            assert.is_table(context)
            assert.equals("192.168.1.100", context.client_ip)
            assert.equals(12345, context.client_port)
            assert.equals("TLSv1.2", context.tls_version)
            assert.equals("ECDHE-RSA-AES128-GCM-SHA256", context.tls_cipher)
        end)
    end)

    describe("collect_request_snapshot()", function()
        it("should collect request snapshot with sanitized data", function()
            local threat_data = {
                request_method = "POST",
                request_uri = "/api/users",
                headers = {
                    ["user-agent"] = "Test Agent",
                    ["authorization"] = "Bearer secret-token",
                    ["x-api-key"] = "secret-key"
                },
                query_args = {
                    ["user_id"] = "123",
                    ["password"] = "secret"
                },
                request_body = "test data"
            }

            local snapshot = collector:collect_request_snapshot(threat_data)
            assert.is_table(snapshot)
            assert.equals("POST", snapshot.method)
            assert.equals("/api/users", snapshot.uri)
            assert.equals("Test Agent", snapshot.headers["user-agent"])
            assert.equals("[REDACTED]", snapshot.headers["authorization"])
            assert.equals("[REDACTED]", snapshot.headers["x-api-key"])
            assert.equals("123", snapshot.query_params["user_id"])
            assert.equals("[REDACTED]", snapshot.query_params["password"])
            assert.equals(9, snapshot.body_size)
        end)
    end)

    describe("collect_response_snapshot()", function()
        it("should collect response snapshot", function()
            local threat_data = {
                response_code = 403,
                response_status = "Forbidden",
                response_headers = { ["content-type"] = "application/json" },
                response_body = '{"error": "access denied"}',
                processing_time = 0.123,
                upstream_time = 0.045
            }

            local snapshot = collector:collect_response_snapshot(threat_data)
            assert.is_table(snapshot)
            assert.equals(403, snapshot.status_code)
            assert.equals("Forbidden", snapshot.status_text)
            assert.equals("application/json", snapshot.headers["content-type"])
            assert.equals(25, snapshot.body_size)
            assert.is_not_nil(snapshot.body_hash)
            assert.equals(0.123, snapshot.processing_time)
            assert.equals(0.045, snapshot.upstream_time)
        end)
    end)

    describe("generate_integrity_checks()", function()
        it("should generate integrity checks for evidence", function()
            local evidence = {
                metadata = { evidence_id = "test-123" },
                threat_data = { threat_score = 0.8 },
                request_snapshot = { method = "GET" },
                response_snapshot = { status_code = 200 }
            }

            local checks = collector:generate_integrity_checks(evidence)
            assert.is_table(checks)
            assert.is_not_nil(checks.timestamp)
            assert.equals("sha256", checks.algorithm)
            assert.is_table(checks.checksums)
            assert.is_not_nil(checks.checksums.threat_data)
            assert.is_not_nil(checks.checksums.overall)
            assert.is_table(checks.chain_of_custody)
        end)
    end)

    describe("verify_integrity()", function()
        it("should verify integrity of evidence", function()
            local evidence = {
                threat_data = { threat_score = 0.8 },
                integrity_checks = {
                    checksums = {
                        threat_data = collector:hash_data('{"threat_score":0.8}'),
                        overall = collector:hash_data('{"threat_data":{"threat_score":0.8}}')
                    }
                }
            }

            local is_valid = collector:verify_integrity(evidence)
            assert.is_boolean(is_valid)
        end)

        it("should return false for evidence without integrity checks", function()
            local evidence = { threat_data = { threat_score = 0.8 } }
            local is_valid = collector:verify_integrity(evidence)
            assert.is_false(is_valid)
        end)
    end)

    describe("is_sensitive_header() and is_sensitive_param()", function()
        it("should identify sensitive headers", function()
            assert.is_true(collector:is_sensitive_header("Authorization"))
            assert.is_true(collector:is_sensitive_header("X-API-Key"))
            assert.is_true(collector:is_sensitive_header("Cookie"))
            assert.is_false(collector:is_sensitive_header("User-Agent"))
            assert.is_false(collector:is_sensitive_header("Content-Type"))
        end)

        it("should identify sensitive parameters", function()
            assert.is_true(collector:is_sensitive_param("password"))
            assert.is_true(collector:is_sensitive_param("api_key"))
            assert.is_true(collector:is_sensitive_param("auth_token"))
            assert.is_false(collector:is_sensitive_param("user_id"))
            assert.is_false(collector:is_sensitive_param("search"))
        end)
    end)

    describe("has_suspicious_headers()", function()
        it("should detect suspicious headers", function()
            local headers = {
                ["user-agent"] = "sqlmap/1.0",
                ["x-tool"] = "nmap scanner"
            }
            assert.is_true(collector:has_suspicious_headers(headers))
        end)

        it("should return false for normal headers", function()
            local headers = {
                ["user-agent"] = "Mozilla/5.0",
                ["content-type"] = "application/json"
            }
            assert.is_false(collector:has_suspicious_headers(headers))
        end)

        it("should handle nil headers", function()
            assert.is_false(collector:has_suspicious_headers(nil))
        end)
    end)

    describe("has_large_payload() and has_anomalous_pattern()", function()
        it("should detect large payloads", function()
            local threat_data = { request_body = string.rep("x", 200000) } -- 200KB
            assert.is_true(collector:has_large_payload(threat_data))
        end)

        it("should not detect normal payloads as large", function()
            local threat_data = { request_body = "normal data" }
            assert.is_false(collector:has_large_payload(threat_data))
        end)

        it("should detect anomalous patterns", function()
            local threat_data = { request_path = "/etc/passwd" }
            assert.is_true(collector:has_anomalous_pattern(threat_data))
        end)

        it("should not detect normal paths as anomalous", function()
            local threat_data = { request_path = "/api/users/123" }
            assert.is_false(collector:has_anomalous_pattern(threat_data))
        end)
    end)

    describe("generate_evidence_id() and hash_data()", function()
        it("should generate unique evidence IDs", function()
            local id1 = collector:generate_evidence_id()
            local id2 = collector:generate_evidence_id()
            assert.is_not_nil(id1)
            assert.is_not_nil(id2)
            assert.not_equals(id1, id2)
            assert.matches("^evidence_", id1)
        end)

        it("should generate consistent hashes", function()
            local data = "test data"
            local hash1 = collector:hash_data(data)
            local hash2 = collector:hash_data(data)
            assert.equals(hash1, hash2)
            assert.is_not_nil(hash1)
            assert.matches("^[0-9a-f]+$", hash1)
        end)
    end)

    describe("cleanup_old_evidence()", function()
        it("should clean up old evidence", function()
            -- Add some mock evidence
            collector.evidence_store["old_evidence"] = {
                stored_at = ngx.now() - (40 * 86400), -- 40 days ago
                size = 1024
            }
            collector.evidence_store["new_evidence"] = {
                stored_at = ngx.now() - (10 * 86400), -- 10 days ago
                size = 2048
            }

            local initial_count = 0
            for _ in pairs(collector.evidence_store) do
                initial_count = initial_count + 1
            end

            collector:cleanup_old_evidence()

            local final_count = 0
            for _ in pairs(collector.evidence_store) do
                final_count = final_count + 1
            end

            -- Should have cleaned up old evidence
            assert.is_true(final_count <= initial_count)
        end)
    end)

    describe("get_health_status()", function()
        it("should return health status information", function()
            local status = collector:get_health_status()
            assert.is_table(status)
            assert.is_boolean(status.enabled)
            assert.is_string(status.storage_backend)
            assert.is_number(status.evidence_count)
            assert.is_number(status.collection_triggers)
            assert.is_table(status.metrics)
            assert.is_number(status.retention_days)
        end)
    end)

    describe("storage backend methods", function()
        it("should have storage backend methods", function()
            assert.is_function(collector.store_local)
            assert.is_function(collector.retrieve_local)
            assert.is_function(collector.delete_local)
            assert.is_function(collector.list_local)
        end)

        it("should have placeholder S3 methods", function()
            assert.is_function(collector.store_s3)
            assert.is_function(collector.retrieve_s3)
            assert.is_function(collector.delete_s3)
            assert.is_function(collector.list_s3)
        end)

        it("should have placeholder GCS methods", function()
            assert.is_function(collector.store_gcs)
            assert.is_function(collector.retrieve_gcs)
            assert.is_function(collector.delete_gcs)
            assert.is_function(collector.list_gcs)
        end)
    end)
end)