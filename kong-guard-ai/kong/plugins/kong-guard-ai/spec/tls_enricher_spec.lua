local helpers = require "spec.helpers"
local TLSEnricher = require "kong.plugins.kong-guard-ai.tls_enricher"

describe("TLS Enricher", function()
    local enricher, config

    before_each(function()
        config = {
            tls_cache_ttl_seconds = 600,
            tls_header_map = {
                ja3 = "X-JA3",
                ja3s = "X-JA3S",
                ja4 = "X-JA4",
                ja4s = "X-JA4S",
                tls_version = "X-TLS-Version",
                tls_cipher = "X-TLS-Cipher",
                sni = "X-TLS-ServerName"
            },
            tls_blocklist = {
                "e7d705a3286e19ea42f587b344ee6865",
                "malicious*",
                "*bad*fingerprint*"
            },
            tls_allowlist = {
                "a0e9f5d64349fb13191bc781f81f42e1",
                "chrome*",
                "*safe*"
            },
            tls_rare_fp_min_ips = 5
        }
        enricher = TLSEnricher:new(config)
    end)

    describe("initialization", function()
        it("should create new enricher with config", function()
            assert.is_not_nil(enricher)
            assert.equals(600, enricher.cache_ttl)
        end)

        it("should use default TTL when not specified", function()
            local default_enricher = TLSEnricher:new({})
            assert.equals(600, default_enricher.cache_ttl)
        end)
    end)

    describe("normalize", function()
        it("should normalize valid fingerprints", function()
            assert.equals("abcdef123456", enricher:normalize("ABCDEF123456"))
            assert.equals("abcdef123456", enricher:normalize("  abcdef123456  "))
            assert.equals("abc-def_123.456", enricher:normalize("ABC-DEF_123.456"))
        end)

        it("should return nil for invalid input", function()
            assert.is_nil(enricher:normalize(nil))
            assert.is_nil(enricher:normalize(""))
            assert.is_nil(enricher:normalize("   "))
        end)

        it("should truncate overly long fingerprints", function()
            local long_fp = string.rep("a", 300)
            local result = enricher:normalize(long_fp)
            assert.equals(256, #result)
        end)

        it("should handle non-string input gracefully", function()
            assert.is_nil(enricher:normalize(123))
            assert.is_nil(enricher:normalize({}))
            assert.is_nil(enricher:normalize(true))
        end)
    end)

    describe("read_headers", function()
        local mock_request

        before_each(function()
            mock_request = {
                get_headers = function()
                    return {
                        ["X-JA3"] = "e7d705a3286e19ea42f587b344ee6865",
                        ["X-JA4"] = "t13d1516h2_8daaf6152771_02713d6af862",
                        ["X-TLS-Version"] = "1.3",
                        ["X-TLS-Cipher"] = "TLS_AES_128_GCM_SHA256"
                    }
                end
            }
        end)

        it("should extract TLS headers successfully", function()
            local tls_data = enricher:read_headers(mock_request, config)

            assert.equals("e7d705a3286e19ea42f587b344ee6865", tls_data.ja3)
            assert.equals("t13d1516h2_8daaf6152771_02713d6af862", tls_data.ja4)
            assert.is_nil(tls_data.ja3s) -- Not present in mock
            assert.is_nil(tls_data.ja4s) -- Not present in mock
            assert.equals("1.3", tls_data.tls_version)
            assert.equals("tls_aes_128_gcm_sha256", tls_data.tls_cipher)
        end)

        it("should handle missing headers gracefully", function()
            mock_request.get_headers = function() return {} end
            local tls_data = enricher:read_headers(mock_request, config)

            assert.is_nil(tls_data.ja3)
            assert.is_nil(tls_data.ja4)
            assert.is_nil(tls_data.ja3s)
            assert.is_nil(tls_data.ja4s)
        end)

        it("should handle case-insensitive headers", function()
            mock_request.get_headers = function()
                return {
                    ["x-ja3"] = "test123",  -- lowercase
                    ["X-JA4"] = "test456"   -- uppercase
                }
            end
            local tls_data = enricher:read_headers(mock_request, config)

            assert.equals("test123", tls_data.ja3)
            assert.equals("test456", tls_data.ja4)
        end)
    end)

    describe("enrich", function()
        it("should enrich valid TLS data", function()
            local tls_data = {
                ja3 = "e7d705a3286e19ea42f587b344ee6865",
                ja4 = "t13d1516h2_8daaf6152771_02713d6af862",
                ja3s = nil,
                ja4s = nil,
                tls_version = "1.3",
                tls_cipher = "TLS_AES_128_GCM_SHA256",
                sni = "example.com"
            }

            local enriched = enricher:enrich(tls_data)

            assert.is_true(enriched.valid)
            assert.equals(2, enriched.fingerprint_count)
            assert.is_true(enriched.has_client_fingerprint)
            assert.is_false(enriched.has_server_fingerprint)
            assert.equals("e7d705a3286e19ea42f587b344ee6865", enriched.ja3)
            assert.equals("1.3", enriched.tls_version)
        end)

        it("should handle empty TLS data", function()
            local enriched = enricher:enrich(nil)

            assert.is_false(enriched.valid)
            assert.equals(0, enriched.fingerprint_count)
            assert.is_false(enriched.has_client_fingerprint)
            assert.is_false(enriched.has_server_fingerprint)
        end)

        it("should count server fingerprints correctly", function()
            local tls_data = {
                ja3 = "client_fingerprint",
                ja3s = "server_fingerprint",
                ja4 = nil,
                ja4s = "server_ja4_fingerprint"
            }

            local enriched = enricher:enrich(tls_data)

            assert.is_true(enriched.valid)
            assert.equals(3, enriched.fingerprint_count)
            assert.is_true(enriched.has_client_fingerprint)
            assert.is_true(enriched.has_server_fingerprint)
        end)
    end)

    describe("pattern matching", function()
        it("should match exact patterns", function()
            local result = enricher:matches_pattern("exact_match", "exact_match")
            assert.is_true(result)

            result = enricher:matches_pattern("exact_match", "different")
            assert.is_false(result)
        end)

        it("should match wildcard patterns", function()
            assert.is_true(enricher:matches_pattern("test123", "test*"))
            assert.is_true(enricher:matches_pattern("prefix_test_suffix", "*test*"))
            assert.is_true(enricher:matches_pattern("test_suffix", "*suffix"))
            assert.is_false(enricher:matches_pattern("nomatch", "test*"))
        end)

        it("should handle edge cases", function()
            assert.is_false(enricher:matches_pattern(nil, "pattern"))
            assert.is_false(enricher:matches_pattern("test", nil))
            assert.is_false(enricher:matches_pattern(nil, nil))
        end)
    end)

    describe("matches_any_pattern", function()
        local tls_data

        before_each(function()
            tls_data = {
                ja3 = "e7d705a3286e19ea42f587b344ee6865",
                ja4 = "malicious_fingerprint",
                ja3s = "safe_server_fingerprint",
                ja4s = nil
            }
        end)

        it("should match against blocklist", function()
            local matched, info = enricher:matches_any_pattern(tls_data, config.tls_blocklist)

            assert.is_true(matched)
            assert.equals("e7d705a3286e19ea42f587b344ee6865", info.fingerprint)
            assert.equals("e7d705a3286e19ea42f587b344ee6865", info.pattern)
        end)

        it("should match wildcard patterns in blocklist", function()
            local matched, info = enricher:matches_any_pattern(tls_data, config.tls_blocklist)

            assert.is_true(matched)
            -- Should match either exact JA3 or wildcard malicious* pattern
            assert.is_not_nil(info.fingerprint)
            assert.is_not_nil(info.pattern)
        end)

        it("should return false for no matches", function()
            local safe_tls_data = {
                ja3 = "safe_fingerprint",
                ja4 = "another_safe_fingerprint"
            }

            local matched, info = enricher:matches_any_pattern(safe_tls_data, config.tls_blocklist)
            assert.is_false(matched)
            assert.is_nil(info)
        end)

        it("should handle empty pattern list", function()
            local matched, info = enricher:matches_any_pattern(tls_data, {})
            assert.is_false(matched)
            assert.is_nil(info)
        end)
    end)

    describe("User-Agent to JA3 plausibility", function()
        it("should return true for missing data", function()
            assert.is_true(enricher:check_ua_ja3_plausibility(nil, "ja3"))
            assert.is_true(enricher:check_ua_ja3_plausibility("Mozilla/5.0", nil))
            assert.is_true(enricher:check_ua_ja3_plausibility(nil, nil))
        end)

        it("should return true for basic implementation", function()
            -- Current implementation is basic and returns true
            -- In production, this would have more sophisticated checks
            local result = enricher:check_ua_ja3_plausibility(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "e7d705a3286e19ea42f587b344ee6865"
            )
            assert.is_true(result)
        end)
    end)

    describe("cache operations", function()
        before_each(function()
            -- Mock ngx.shared.kong_cache for testing
            _G.ngx = _G.ngx or {}
            _G.ngx.shared = _G.ngx.shared or {}
            _G.ngx.shared.kong_cache = {
                data = {},
                get = function(self, key)
                    return self.data[key]
                end,
                set = function(self, key, value, ttl)
                    self.data[key] = value
                    return true, nil, false
                end,
                incr = function(self, key, value, init, ttl)
                    local current = self.data[key] or init or 0
                    self.data[key] = current + value
                    return self.data[key]
                end
            }
        end)

        after_each(function()
            if _G.ngx and _G.ngx.shared and _G.ngx.shared.kong_cache then
                _G.ngx.shared.kong_cache.data = {}
            end
        end)

        it("should cache and retrieve values", function()
            local success = enricher:cache_set("test_key", "test_value", 300)
            assert.is_true(success)

            local value = enricher:cache_get("test_key")
            assert.equals("test_value", value)
        end)

        it("should return nil for missing cache entries", function()
            local value = enricher:cache_get("nonexistent_key")
            assert.is_nil(value)
        end)
    end)

    describe("fingerprint statistics", function()
        before_each(function()
            -- Setup mock cache
            _G.ngx = _G.ngx or {}
            _G.ngx.shared = _G.ngx.shared or {}
            _G.ngx.shared.kong_cache = {
                data = {},
                get = function(self, key) return self.data[key] end,
                set = function(self, key, value, ttl)
                    self.data[key] = value
                    return true, nil, false
                end,
                incr = function(self, key, value, init, ttl)
                    local current = self.data[key] or init or 0
                    self.data[key] = current + value
                    return self.data[key]
                end
            }
        end)

        it("should return default stats for unknown fingerprint", function()
            local stats = enricher:get_fingerprint_stats("unknown_fp")

            assert.equals(0, stats.request_count)
            assert.equals(0, stats.unique_ips)
            assert.is_nil(stats.first_seen)
            assert.is_nil(stats.last_seen)
        end)

        it("should update fingerprint statistics", function()
            local fp = "test_fingerprint"
            local client_ip = "192.168.1.1"

            enricher:update_fingerprint_stats(fp, client_ip)

            local stats = enricher:get_fingerprint_stats(fp)
            assert.equals(1, stats.request_count)
            assert.equals(1, stats.unique_ips)
            assert.is_not_nil(stats.first_seen)
            assert.is_not_nil(stats.last_seen)
        end)

        it("should track velocity correctly", function()
            local fp = "velocity_test_fp"

            local velocity1 = enricher:increment_fingerprint_velocity(fp)
            assert.equals(1, velocity1)

            local velocity2 = enricher:increment_fingerprint_velocity(fp)
            assert.equals(2, velocity2)

            local current_velocity = enricher:get_fingerprint_velocity(fp)
            assert.equals(2, current_velocity)
        end)
    end)

    describe("error handling", function()
        it("should handle missing ngx.shared.kong_cache gracefully", function()
            -- Temporarily remove the mock cache
            local original_cache = _G.ngx and _G.ngx.shared and _G.ngx.shared.kong_cache
            if _G.ngx and _G.ngx.shared then
                _G.ngx.shared.kong_cache = nil
            end

            local success = enricher:cache_set("test", "value")
            assert.is_false(success)

            local value = enricher:cache_get("test")
            assert.is_nil(value)

            local velocity = enricher:increment_fingerprint_velocity("test_fp")
            assert.equals(0, velocity)

            -- Restore cache
            if _G.ngx and _G.ngx.shared then
                _G.ngx.shared.kong_cache = original_cache
            end
        end)

        it("should handle invalid JSON in cached stats", function()
            -- Mock invalid JSON in cache
            _G.ngx = _G.ngx or {}
            _G.ngx.shared = _G.ngx.shared or {}
            _G.ngx.shared.kong_cache = {
                get = function(self, key)
                    if key:match("tls_fp_stats:") then
                        return "invalid_json{"
                    end
                    return nil
                end
            }

            local stats = enricher:get_fingerprint_stats("test_fp")

            -- Should return default stats when JSON parsing fails
            assert.equals(0, stats.request_count)
            assert.equals(0, stats.unique_ips)
        end)
    end)
end)
