--- Unit tests for Privacy Manager Module
-- Tests PII detection, data anonymization, consent management, and compliance features

local PrivacyManager = require("kong.plugins.kong-guard-ai.privacy_manager")

describe("Privacy Manager", function()
    local config
    local manager

    before_each(function()
        config = {
            data_anonymization = true,
            pii_detection = true,
            consent_tracking = true,
            anonymization_level = "standard",
            anonymization_salt = "test-salt",
            pii_detection_rules = {"email", "phone", "credit_card", "ssn"},
            gdpr_compliance = true,
            ccpa_compliance = false,
            cache_ttl = 300
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
                remote_addr = "192.168.1.1",
                http_user_agent = "test-agent"
            }
        }

        -- Mock cjson
        _G.cjson = {
            encode = function(obj) return '{"test": "data"}' end,
            decode = function(str) return {test = "data"} end
        }

        manager = PrivacyManager.new(config)
        assert.is_not_nil(manager)
    end)

    after_each(function()
        manager = nil
        _G.kong = nil
        _G.ngx = nil
        _G.cjson = nil
    end)

    describe("Initialization", function()
        it("should create manager with valid config", function()
            local mgr = PrivacyManager.new(config)
            assert.is_not_nil(mgr)
            assert.is_table(mgr.pii_patterns)
            assert.is_table(mgr.anonymization)
            assert.is_table(mgr.consent)
        end)

        it("should fail with invalid config", function()
            local mgr, err = PrivacyManager.new(nil)
            assert.is_nil(mgr)
            assert.is_string(err)
        end)

        it("should initialize with default values", function()
            local mgr = PrivacyManager.new({})
            assert.equal("standard", mgr.anonymization.level)
            assert.is_true(mgr.consent.enabled)
        end)
    end)

    describe("PII Detection", function()
        it("should detect email addresses", function()
            local data = "Contact user@example.com for support"
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_true(has_pii)
            assert.is_table(detected.email)
            assert.equal(1, detected.email.count)
        end)

        it("should detect phone numbers", function()
            local data = "Call +1-555-123-4567 for help"
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_true(has_pii)
            assert.is_table(detected.phone)
            assert.equal(1, detected.phone.count)
        end)

        it("should detect credit card numbers", function()
            local data = "Card number: 4111111111111111"
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_true(has_pii)
            assert.is_table(detected.credit_card)
            assert.equal(1, detected.credit_card.count)
        end)

        it("should detect SSNs", function()
            local data = "SSN: 123-45-6789"
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_true(has_pii)
            assert.is_table(detected.ssn)
            assert.equal(1, detected.ssn.count)
        end)

        it("should detect IP addresses", function()
            local data = "IP: 192.168.1.100"
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_true(has_pii)
            assert.is_table(detected.ip_address)
            assert.equal(1, detected.ip_address.count)
        end)

        it("should handle multiple PII types", function()
            local data = {
                email = "user@example.com",
                phone = "+1-555-123-4567",
                message = "Contact me"
            }
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_true(has_pii)
            assert.is_table(detected.email)
            assert.is_table(detected.phone)
        end)

        it("should respect PII detection rules", function()
            manager.config.pii_detection_rules = {"email"}  -- Only detect email
            local data = "Email: user@example.com Phone: +1-555-123-4567"
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_true(has_pii)
            assert.is_table(detected.email)
            assert.is_nil(detected.phone)
        end)

        it("should handle no PII detection", function()
            local data = "This is just regular text with no sensitive information"
            local detected, has_pii = manager:detect_pii(data, "test")

            assert.is_false(has_pii)
            assert.equal(0, manager:_count_table_keys(detected))
        end)
    end)

    describe("Data Anonymization", function()
        it("should anonymize email addresses with standard level", function()
            local detected_pii = {
                email = {
                    matches = {"user@example.com"}
                }
            }
            local data = "Contact user@example.com"
            local anonymized = manager:anonymize_data(data, detected_pii, "test")

            assert.is_string(anonymized)
            assert.matches("HASH%-", anonymized)
        end)

        it("should anonymize with minimal level", function()
            manager.anonymization.level = "minimal"
            local detected_pii = {
                email = {
                    matches = {"user@example.com"}
                }
            }
            local data = "Contact user@example.com"
            local anonymized = manager:anonymize_data(data, detected_pii, "test")

            assert.is_string(anonymized)
            assert.matches("u%*%*%*%*@", anonymized)
        end)

        it("should anonymize with aggressive level", function()
            manager.anonymization.level = "aggressive"
            local detected_pii = {
                email = {
                    matches = {"user@example.com"}
                }
            }
            local data = "Contact user@example.com"
            local anonymized = manager:anonymize_data(data, detected_pii, "test")

            assert.is_string(anonymized)
            assert.matches("%[REDACTED%]", anonymized)
        end)

        it("should anonymize phone numbers", function()
            local detected_pii = {
                phone = {
                    matches = {"+1-555-123-4567"}
                }
            }
            local data = "Call +1-555-123-4567"
            local anonymized = manager:anonymize_data(data, detected_pii, "test")

            assert.is_string(anonymized)
            assert.matches("HASH%-", anonymized)
        end)

        it("should anonymize credit card numbers", function()
            local detected_pii = {
                credit_card = {
                    matches = {"4111111111111111"}
                }
            }
            local data = "Card: 4111111111111111"
            local anonymized = manager:anonymize_data(data, detected_pii, "test")

            assert.is_string(anonymized)
            assert.matches("HASH%-", anonymized)
        end)

        it("should handle table data anonymization", function()
            local detected_pii = {
                email = {
                    matches = {"user@example.com"}
                }
            }
            local data = {
                contact = "user@example.com",
                message = "Hello world"
            }
            local anonymized = manager:anonymize_data(data, detected_pii, "test")

            assert.is_table(anonymized)
            assert.matches("HASH%-", anonymized.contact)
            assert.equal("Hello world", anonymized.message)
        end)
    end)

    describe("Consent Management", function()
        it("should check consent when enabled", function()
            local user_id = "user123"
            local purpose = "data_processing"

            -- No consent record exists
            local has_consent = manager:check_consent(user_id, purpose, "test")
            assert.equal(manager.consent.default_consent, has_consent)
        end)

        it("should grant consent", function()
            local user_id = "user123"
            local purpose = "data_processing"

            local success = manager:set_consent(user_id, purpose, true, "test")
            assert.is_true(success)

            local has_consent = manager:check_consent(user_id, purpose, "test")
            assert.is_true(has_consent)
        end)

        it("should revoke consent", function()
            local user_id = "user123"
            local purpose = "data_processing"

            -- Grant consent first
            manager:set_consent(user_id, purpose, true, "test")

            -- Then revoke
            local success = manager:set_consent(user_id, purpose, false, "test")
            assert.is_true(success)

            local has_consent = manager:check_consent(user_id, purpose, "test")
            assert.is_false(has_consent)
        end)

        it("should handle consent expiration", function()
            local user_id = "user123"
            local purpose = "data_processing"

            -- Set short TTL for testing
            manager.consent.consent_ttl = 1  -- 1 second

            manager:set_consent(user_id, purpose, true, "test")

            -- Simulate time passing
            local original_now = _G.ngx.now
            _G.ngx.now = function() return original_now() + 2 end

            local has_consent = manager:check_consent(user_id, purpose, "test")
            assert.equal(manager.consent.default_consent, has_consent)

            _G.ngx.now = original_now
        end)

        it("should skip consent checks when disabled", function()
            manager.consent.enabled = false
            local has_consent = manager:check_consent("user123", "data_processing", "test")
            assert.is_true(has_consent)  -- Always true when disabled
        end)
    end)

    describe("Data Processing", function()
        it("should process data with PII detection", function()
            local data = "Contact user@example.com for support"
            local context = {user_id = "user123"}

            local processed_data, result = manager:process_data(data, context)

            assert.is_table(result)
            assert.is_true(result.pii_detected)
            assert.is_true(result.consent_validated)
            assert.is_true(result.data_anonymized)
        end)

        it("should block processing without consent", function()
            local data = "Contact user@example.com"
            local context = {user_id = "user123"}

            -- Ensure no consent
            manager.consent.default_consent = false

            local processed_data, result = manager:process_data(data, context)

            assert.is_nil(processed_data)
            assert.is_true(result.processing_blocked)
        end)

        it("should handle data without PII", function()
            local data = "This is regular text"
            local context = {user_id = "user123"}

            local processed_data, result = manager:process_data(data, context)

            assert.equal(data, processed_data)
            assert.is_false(result.pii_detected)
            assert.is_false(result.data_anonymized)
        end)

        it("should skip anonymization when disabled", function()
            manager.config.data_anonymization = false
            local data = "Contact user@example.com"
            local context = {user_id = "user123"}

            local processed_data, result = manager:process_data(data, context)

            assert.equal(data, processed_data)
            assert.is_true(result.pii_detected)
            assert.is_false(result.data_anonymized)
        end)
    end)

    describe("Regulatory Compliance", function()
        describe("GDPR Compliance", function()
            it("should handle right to be forgotten", function()
                local success, message = manager:handle_gdpr_request("right_to_be_forgotten", "user123", "test")

                assert.is_true(success)
                assert.is_string(message)
                assert.equal(1, manager.metrics.gdpr_requests)
            end)

            it("should handle data portability", function()
                local success, message = manager:handle_gdpr_request("data_portability", "user123", "test")

                assert.is_true(success)
                assert.is_string(message)
            end)

            it("should handle consent withdrawal", function()
                local success, message = manager:handle_gdpr_request("consent_withdrawal", "user123", "test")

                assert.is_true(success)
                assert.is_string(message)
            end)

            it("should reject unknown GDPR request types", function()
                local success, message = manager:handle_gdpr_request("unknown_request", "user123", "test")

                assert.is_false(success)
                assert.is_string(message)
            end)

            it("should reject GDPR requests when disabled", function()
                manager.compliance.gdpr_enabled = false
                local success, message = manager:handle_gdpr_request("right_to_be_forgotten", "user123", "test")

                assert.is_false(success)
                assert.equal("GDPR compliance not enabled", message)
            end)
        end)

        describe("CCPA Compliance", function()
            before_each(function()
                manager.compliance.ccpa_enabled = true
            end)

            it("should handle do not sell requests", function()
                local success = manager:handle_ccpa_request("do_not_sell", "user123", "test")

                assert.is_true(success)
                assert.equal(1, manager.metrics.ccpa_requests)
            end)

            it("should handle data deletion requests", function()
                local success, message = manager:handle_ccpa_request("data_deletion", "user123", "test")

                assert.is_true(success)
                assert.is_string(message)
            end)

            it("should handle data access requests", function()
                local success, message = manager:handle_ccpa_request("data_access", "user123", "test")

                assert.is_true(success)
                assert.is_string(message)
            end)

            it("should reject CCPA requests when disabled", function()
                manager.compliance.ccpa_enabled = false
                local success, message = manager:handle_ccpa_request("do_not_sell", "user123", "test")

                assert.is_false(success)
                assert.equal("CCPA compliance not enabled", message)
            end)
        end)
    end)

    describe("Statistics and Monitoring", function()
        it("should provide comprehensive statistics", function()
            -- Perform some operations to generate metrics
            manager:detect_pii("user@example.com", "test")
            manager:set_consent("user123", "data_processing", true, "test")
            manager:handle_gdpr_request("right_to_be_forgotten", "user123", "test")

            local stats = manager:get_stats()

            assert.is_table(stats)
            assert.is_table(stats.pii_detection)
            assert.is_table(stats.consent_management)
            assert.is_table(stats.regulatory_compliance)
            assert.is_table(stats.configuration)
            assert.is_table(stats.cache)

            assert.equal(1, stats.pii_detection.pii_detected)
            assert.equal(1, stats.consent_management.consent_checks)
            assert.equal(1, stats.regulatory_compliance.gdpr_requests)
        end)

        it("should validate compliance configuration", function()
            local valid, issues = manager:validate_compliance()

            assert.is_boolean(valid)
            assert.is_table(issues)
        end)

        it("should detect configuration issues", function()
            manager.config.data_anonymization = true
            manager.config.pii_detection = false

            local valid, issues = manager:validate_compliance()

            assert.is_false(valid)
            assert.is_true(#issues > 0)
        end)
    end)

    describe("Cache Management", function()
        it("should cleanup expired cache entries", function()
            -- Add a cache entry
            manager.processing_cache["test"] = {
                timestamp = ngx.now() - 400  -- Expired
            }

            local initial_count = manager:_count_cache_entries()
            manager:_cleanup_cache()

            local final_count = manager:_count_cache_entries()
            assert.is_true(final_count < initial_count)
        end)

        it("should handle cache operations", function()
            local count = manager:_count_cache_entries()
            assert.is_number(count)
        end)
    end)

    describe("Utility Functions", function()
        it("should deep copy tables", function()
            local original = {a = 1, b = {c = 2}}
            local copy = manager:_deep_copy(original)

            assert.equal(original.a, copy.a)
            assert.equal(original.b.c, copy.b.c)
            assert.is_not_equal(original, copy)
            assert.is_not_equal(original.b, copy.b)
        end)

        it("should deep copy non-table values", function()
            local original = "test string"
            local copy = manager:_deep_copy(original)

            assert.equal(original, copy)
        end)

        it("should count table keys", function()
            local tbl = {a = 1, b = 2, c = 3}
            local count = manager:_count_table_keys(tbl)

            assert.equal(3, count)
        end)

        it("should handle empty tables", function()
            local count = manager:_count_table_keys({})
            assert.equal(0, count)
        end)
    end)

    describe("Cleanup", function()
        it("should cleanup resources", function()
            -- Add some data
            manager:set_consent("user123", "test", true, "test")
            manager.processing_cache["test"] = {timestamp = ngx.now()}

            manager:cleanup()

            assert.equal(0, manager:_count_consent_records())
            assert.equal(0, manager:_count_cache_entries())
        end)
    end)

    describe("Error Handling", function()
        it("should handle invalid data in PII detection", function()
            local detected, has_pii = manager:detect_pii(nil, "test")

            assert.is_table(detected)
            assert.is_false(has_pii)
        end)

        it("should handle invalid data in anonymization", function()
            local result = manager:anonymize_data(nil, {}, "test")
            assert.is_nil(result)
        end)

        it("should handle consent operations when disabled", function()
            manager.consent.enabled = false

            local success, err = manager:set_consent("user123", "test", true, "test")
            assert.is_false(success)
            assert.equal("Consent tracking not enabled", err)
        end)

        it("should handle invalid regulatory requests", function()
            local success, message = manager:handle_gdpr_request("invalid_type", "user123", "test")

            assert.is_false(success)
            assert.is_string(message)
        end)
    end)

    -- Helper function for tests
    function manager:_count_table_keys(tbl)
        local count = 0
        for _ in pairs(tbl) do
            count = count + 1
        end
        return count
    end

    function manager:_count_consent_records()
        return self:_count_table_keys(self.consent.storage)
    end
end)
