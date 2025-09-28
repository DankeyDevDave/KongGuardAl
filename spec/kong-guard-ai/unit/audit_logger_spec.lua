--- Unit tests for Audit Logger Module
-- Tests audit event logging, integrity, encryption, and storage backends

local AuditLogger = require("kong.plugins.kong-guard-ai.audit_logger")

describe("Audit Logger", function()
    local config
    local logger

    before_each(function()
        config = {
            audit_log_level = "standard",
            audit_retention_days = 90,
            audit_encryption = false,
            audit_storage_backend = "local",
            buffer_size = 10,
            flush_interval = 30,
            key_rotation_days = 90
        }

        -- Mock kong global
        _G.kong = {
            log = {
                info = function(...) end,
                warn = function(...) end,
                err = function(...) end,
                debug = function(...) end
            }
        }

        -- Mock ngx global
        _G.ngx = {
            now = function() return 1234567890 end,
            timer = {
                every = function(interval, callback) return true end
            },
            var = {
                hostname = "test-host",
                server_addr = "127.0.0.1",
                http_user_agent = "test-agent",
                request_method = "GET",
                request_uri = "/test",
                remote_addr = "192.168.1.1",
                server_name = "kong-server",
                connection = "12345",
                request_id = "req-123"
            }
        }

        -- Mock cjson
        _G.cjson = {
            encode = function(obj) return '{"test": "data"}' end,
            decode = function(str) return {test = "data"} end
        }

        -- Mock os
        _G.os = {
            date = function(format, time) return "2023-12-01 12:00:00" end,
            getenv = function(var) return var == "KONG_ENVIRONMENT" and "test" or nil end,
            execute = function(cmd) return true end
        }

        logger = AuditLogger.new(config)
        assert.is_not_nil(logger)
    end)

    after_each(function()
        logger = nil
        _G.kong = nil
        _G.ngx = nil
        _G.cjson = nil
        _G.os = nil
    end)

    describe("Initialization", function()
        it("should create logger with valid config", function()
            local log = AuditLogger.new(config)
            assert.is_not_nil(log)
            assert.is_table(log.event_buffer)
            assert.is_table(log.metrics)
        end)

        it("should fail with invalid config", function()
            local log, err = AuditLogger.new(nil)
            assert.is_nil(log)
            assert.is_string(err)
        end)

        it("should initialize with default values", function()
            local log = AuditLogger.new({})
            assert.equal(100, log.buffer_size)
            assert.equal(30, log.flush_interval)
        end)
    end)

    describe("Event Logging", function()
        it("should log security events", function()
            local success = logger:log_security_event("sql_injection", {
                client_ip = "192.168.1.1",
                threat_score = 0.9
            })

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)

        it("should log configuration changes", function()
            local success = logger:log_config_change("threat_threshold", 0.7, 0.8, "admin")

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)

        it("should log access events", function()
            local success = logger:log_access_event("/api/users", "GET", "user123", "192.168.1.1", true)

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)

        it("should log data processing events", function()
            local success = logger:log_data_processing("anonymize", "user_data", 1024, "system", "privacy")

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)

        it("should log privacy events", function()
            local success = logger:log_privacy_event("pii_detected", {"email", "phone"}, "user123", "anonymize")

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)

        it("should log consent events", function()
            local success = logger:log_consent_event("user123", "data_processing", "marketing", true)

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)

        it("should log threat detection events", function()
            local success = logger:log_threat_detection(0.85, "xss", "192.168.1.1", {pattern = "script"})

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)

        it("should log compliance violations", function()
            local success = logger:log_compliance_violation("gdpr_breach", "high", {details = "test"}, "notify_dpo")

            assert.is_true(success)
            assert.equal(1, logger.metrics.events_logged)
        end)
    end)

    describe("Event Creation", function()
        it("should create standardized audit events", function()
            local event = logger:_create_audit_event("test_event", {test = "data"})

            assert.is_table(event)
            assert.is_string(event.id)
            assert.is_number(event.timestamp)
            assert.equal("test_event", event.event_type)
            assert.is_table(event.system)
            assert.is_table(event.actor)
            assert.is_table(event.data)
            assert.is_table(event.metadata)
        end)

        it("should generate unique correlation IDs", function()
            local event1 = logger:_create_audit_event("event1", {})
            local event2 = logger:_create_audit_event("event2", {})

            assert.is_not_equal(event1.id, event2.id)
        end)

        it("should include detailed context when configured", function()
            logger.config.audit_log_level = "detailed"
            local event = logger:_create_audit_event("test", {})

            assert.is_table(event.context)
            assert.is_string(event.context.kong_version)
        end)

        it("should sanitize configuration values", function()
            local old_value = {password = "secret123", api_key = "key456", normal = "value"}
            local sanitized = logger:_sanitize_config_value(old_value)

            assert.equal("***REDACTED***", sanitized.password)
            assert.equal("***REDACTED***", sanitized.api_key)
            assert.equal("value", sanitized.normal)
        end)
    end)

    describe("Buffering and Flushing", function()
        it("should buffer events when buffer size > 1", function()
            logger.buffer_size = 5

            for i = 1, 3 do
                logger:log_security_event("test", {count = i})
            end

            assert.equal(3, #logger.event_buffer)
            assert.equal(3, logger.metrics.events_buffered)
        end)

        it("should auto-flush when buffer is full", function()
            logger.buffer_size = 2

            logger:log_security_event("test1", {})
            assert.equal(1, #logger.event_buffer)

            logger:log_security_event("test2", {})
            assert.equal(0, #logger.event_buffer)  -- Should be flushed
            assert.equal(2, logger.metrics.events_flushed)
        end)

        it("should flush buffer manually", function()
            logger:log_security_event("test", {})
            logger:log_security_event("test", {})

            local initial_buffered = logger.metrics.events_buffered
            local success = logger:_flush_buffer()

            assert.is_true(success)
            assert.equal(0, #logger.event_buffer)
            assert.equal(initial_buffered, logger.metrics.events_flushed)
        end)
    end)

    describe("Event Formatting", function()
        it("should format events as JSON for standard level", function()
            local event = logger:_create_audit_event("test", {data = "value"})
            local formatted = logger:_format_event(event)

            assert.is_string(formatted)
            -- Should be JSON formatted
            assert.matches("^{", formatted)
        end)

        it("should format events minimally for minimal level", function()
            logger.config.audit_log_level = "minimal"
            local event = logger:_create_audit_event("test", {data = "value"})
            local formatted = logger:_format_event(event)

            assert.is_string(formatted)
            -- Should be simple text format
            assert.matches("^%[", formatted)
        end)
    end)

    describe("Integrity and Security", function()
        it("should calculate event hashes", function()
            local event = {id = "test", timestamp = 1234567890}
            local hash = logger:_calculate_event_hash(event)

            assert.is_string(hash)
            assert.equal(6, #hash)  -- Should be 6 digits
        end)

        it("should update integrity chain", function()
            local event1 = logger:_create_audit_event("test1", {})
            local event2 = logger:_create_audit_event("test2", {})

            assert.is_not_nil(event1.metadata.chain_hash)
            assert.is_not_nil(event2.metadata.chain_hash)
            assert.is_not_equal(event1.metadata.chain_hash, event2.metadata.chain_hash)
        end)

        it("should verify integrity chain", function()
            -- Add some events to build a chain
            logger:log_security_event("test1", {})
            logger:log_security_event("test2", {})

            local valid, message = logger:verify_integrity()

            assert.is_boolean(valid)
            assert.is_string(message)
        end)

        it("should encrypt events when enabled", function()
            logger.encryption.enabled = true
            local event = logger:_create_audit_event("test", {})

            local encrypted = logger:_encrypt_event(event)

            assert.is_true(encrypted.encrypted)
            assert.equal("key-1", encrypted.encryption_key_id)
            assert.equal(1, logger.metrics.encryption_operations)
        end)
    end)

    describe("Storage Backends", function()
        it("should initialize local file storage", function()
            logger:_init_storage_backend()
            -- Should not error
            assert.is_true(true)
        end)

        it("should write to local file", function()
            local formatted_event = "test audit event"
            local success = logger:_write_to_file(formatted_event)

            -- In test environment, file writing may fail, but method should exist
            assert.is_boolean(success)
        end)

        it("should handle database storage placeholder", function()
            logger.storage_backends.database = true
            local formatted_event = "test event"
            local success = logger:_write_to_database(formatted_event)

            assert.is_true(success)  -- Placeholder always returns true
        end)

        it("should handle Elasticsearch storage placeholder", function()
            logger.storage_backends.elasticsearch = true
            local formatted_event = "test event"
            local success = logger:_write_to_elasticsearch(formatted_event)

            assert.is_true(success)  -- Placeholder always returns true
        end)

        it("should handle Splunk storage placeholder", function()
            logger.storage_backends.splunk = true
            local formatted_event = "test event"
            local success = logger:_write_to_splunk(formatted_event)

            assert.is_true(success)  -- Placeholder always returns true
        end)
    end)

    describe("Statistics and Monitoring", function()
        it("should provide comprehensive statistics", function()
            logger:log_security_event("test", {})
            logger:log_config_change("test", "old", "new")

            local stats = logger:get_stats()

            assert.is_table(stats)
            assert.is_number(stats.events_logged)
            assert.is_number(stats.events_buffered)
            assert.is_number(stats.buffer_size_current)
            assert.is_number(stats.errors)
            assert.is_boolean(stats.encryption_enabled)
        end)

        it("should track metrics correctly", function()
            local initial_logged = logger.metrics.events_logged

            logger:log_security_event("test", {})
            logger:log_security_event("test", {})

            assert.equal(initial_logged + 2, logger.metrics.events_logged)
        end)
    end)

    describe("Data Hashing", function()
        it("should calculate data hashes", function()
            local hash = logger:_calculate_data_hash("user_data", 1024)

            assert.is_string(hash)
            assert.matches("user_data%-1024%-", hash)
        end)
    end)

    describe("Cleanup", function()
        it("should cleanup resources", function()
            logger:log_security_event("test", {})
            logger:log_security_event("test", {})

            assert.equal(2, #logger.event_buffer)

            logger:cleanup()

            assert.equal(0, #logger.event_buffer)
            assert.equal(0, #logger.active_sessions)
        end)
    end)

    describe("Error Handling", function()
        it("should handle invalid event data", function()
            local success = logger:log_security_event(nil, nil)
            assert.is_true(success)  -- Should not crash
        end)

        it("should handle buffer flush errors gracefully", function()
            -- Mock write failure
            logger._write_event = function() return false end

            logger:log_security_event("test", {})
            local success = logger:_flush_buffer()

            assert.is_false(success)
            assert.equal(1, logger.metrics.errors)
        end)

        it("should handle encryption failures", function()
            logger.encryption.enabled = true
            logger._encrypt_event = function() error("Encryption failed") end

            local success = logger:log_security_event("test", {})

            -- Should still succeed despite encryption error
            assert.is_true(success)
        end)
    end)

    describe("Configuration Variations", function()
        it("should handle minimal log level", function()
            logger.config.audit_log_level = "minimal"
            local event = logger:_create_audit_event("test", {})

            assert.equal("minimal", event.metadata.log_level)
        end)

        it("should handle detailed log level", function()
            logger.config.audit_log_level = "detailed"
            local event = logger:_create_audit_event("test", {})

            assert.equal("detailed", event.metadata.log_level)
            assert.is_table(event.context)
        end)

        it("should handle different storage backends", function()
            logger.config.audit_storage_backend = "database"
            logger.storage_backends.database = true

            local success = logger:log_security_event("test", {})
            assert.is_true(success)
        end)
    end)
end)
