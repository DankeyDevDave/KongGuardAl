local TaxiiCache = require "kong.plugins.kong-guard-ai.taxii_cache"

describe("TaxiiCache", function()
    local cache
    local mock_config

    -- Mock ngx.shared.kong_cache
    local mock_shared_dict = {}
    local shared_data = {}

    before_each(function()
        mock_config = {
            taxii_cache_ttl_seconds = 3600
        }

        -- Reset mock shared dict data
        shared_data = {}

        -- Mock shared dict methods
        mock_shared_dict.get = function(self, key)
            return shared_data[key], nil
        end

        mock_shared_dict.set = function(self, key, value, ttl)
            shared_data[key] = value
            return true, nil
        end

        mock_shared_dict.delete = function(self, key)
            shared_data[key] = nil
            return true
        end

        mock_shared_dict.incr = function(self, key, value, init, ttl)
            local current = shared_data[key] or init or 0
            shared_data[key] = current + value
            return shared_data[key], nil
        end

        mock_shared_dict.get_keys = function(self, max_count)
            local keys = {}
            for key, _ in pairs(shared_data) do
                table.insert(keys, key)
                if #keys >= (max_count or 1000) then
                    break
                end
            end
            return keys
        end

        mock_shared_dict.capacity = function(self)
            return 1048576  -- 1MB
        end

        mock_shared_dict.free_space = function(self)
            return 524288   -- 512KB
        end

        -- Mock ngx.shared.kong_cache
        _G.ngx = _G.ngx or {}
        _G.ngx.shared = _G.ngx.shared or {}
        _G.ngx.shared.kong_cache = mock_shared_dict

        cache = TaxiiCache.new(mock_config)
    end)

    describe("initialization", function()
        it("should create a new cache instance", function()
            assert.is_not_nil(cache)
            assert.equals(3600, cache.ttl)
        end)

        it("should return nil if shared dict not available", function()
            _G.ngx.shared.kong_cache = nil
            local failed_cache = TaxiiCache.new(mock_config)
            assert.is_nil(failed_cache)
        end)
    end)

    describe("version management", function()
        it("should get current version", function()
            local version = cache:get_current_version()
            assert.equals("1", version)  -- Default initial version
        end)

        it("should generate next version", function()
            cache:get_current_version()  -- Initialize version
            local next_version = cache:generate_next_version()
            assert.equals("2", next_version)
        end)

        it("should handle non-numeric versions", function()
            shared_data["taxii:version"] = "abc"
            local next_version = cache:generate_next_version()
            assert.equals("2", next_version)  -- Should default to incrementing from 1
        end)
    end)

    describe("metadata management", function()
        it("should set and get metadata", function()
            local test_metadata = {
                last_update = 1234567890,
                sources = {"server1", "server2"}
            }

            local success = cache:set_metadata(test_metadata)
            assert.is_true(success)

            local retrieved = cache:get_metadata()
            assert.is_not_nil(retrieved)
            assert.equals(1234567890, retrieved.last_update)
            assert.equals(2, #retrieved.sources)
        end)

        it("should return empty table for missing metadata", function()
            local metadata = cache:get_metadata()
            assert.is_table(metadata)
            assert.equals(0, #metadata)
        end)
    end)

    describe("indicator storage", function()
        it("should store indicators", function()
            local success = cache:store_indicator("1", "ip", "192.168.1.1", {
                source_id = "test-indicator",
                labels = {"malicious"}
            })
            assert.is_true(success)

            -- Verify data was stored
            local key = "taxii:1:ip:192.168.1.1"
            assert.is_not_nil(shared_data[key])
        end)

        it("should store complex metadata", function()
            local metadata = {
                source_id = "indicator--test-123",
                labels = {"malicious-activity", "botnet"},
                confidence = 85,
                valid_from = "2023-01-01T00:00:00Z",
                valid_until = "2024-01-01T00:00:00Z"
            }

            local success = cache:store_indicator("1", "domain", "evil.com", metadata)
            assert.is_true(success)
        end)
    end)

    describe("bulk loading", function()
        it("should bulk load indicator sets", function()
            local indicator_sets = {
                ip_set = {
                    ["192.168.1.1"] = {
                        source_id = "test-1",
                        labels = {"malicious"}
                    },
                    ["10.0.0.1"] = {
                        source_id = "test-2",
                        labels = {"suspicious"}
                    }
                },
                domain_set = {
                    ["evil.com"] = {
                        source_id = "test-3",
                        labels = {"malicious"}
                    }
                },
                ja3_set = {
                    ["a1b2c3d4e5f6"] = {
                        source_id = "test-4",
                        labels = {"bot"}
                    }
                }
            }

            local result = cache:bulk_load_indicators("1", indicator_sets)
            assert.equals(4, result.loaded)
            assert.equals(0, result.errors)

            -- Verify indicators were stored
            assert.is_not_nil(shared_data["taxii:1:ip:192.168.1.1"])
            assert.is_not_nil(shared_data["taxii:1:domain:evil.com"])
            assert.is_not_nil(shared_data["taxii:1:ja3:a1b2c3d4e5f6"])
        end)

        it("should handle empty sets", function()
            local result = cache:bulk_load_indicators("1", {})
            assert.equals(0, result.loaded)
            assert.equals(0, result.errors)
        end)
    end)

    describe("lookups", function()
        before_each(function()
            -- Pre-populate cache with test data
            cache:store_indicator("1", "ip", "192.168.1.1", {
                source_id = "malicious-ip",
                labels = {"malicious-activity"}
            })
            cache:store_indicator("1", "domain", "evil.com", {
                source_id = "malicious-domain",
                labels = {"malicious-activity"}
            })
            cache:store_indicator("1", "url", "https://evil.com/malware", {
                source_id = "malicious-url",
                labels = {"malware"}
            })
            cache:store_indicator("1", "ja3", "a1b2c3d4e5f6", {
                source_id = "bot-fingerprint",
                labels = {"bot"}
            })
        end)

        it("should lookup IP addresses", function()
            local result = cache:lookup_ip("192.168.1.1")
            assert.is_not_nil(result)
            assert.equals("malicious-ip", result.metadata.source_id)
        end)

        it("should return nil for non-existent IPs", function()
            local result = cache:lookup_ip("1.2.3.4")
            assert.is_nil(result)
        end)

        it("should lookup domains", function()
            local result = cache:lookup_domain("evil.com")
            assert.is_not_nil(result)
            assert.equals("malicious-domain", result.metadata.source_id)
        end)

        it("should lookup URLs", function()
            local result = cache:lookup_url("https://evil.com/malware")
            assert.is_not_nil(result)
            assert.equals("malicious-url", result.metadata.source_id)
        end)

        it("should lookup JA3 fingerprints", function()
            local result = cache:lookup_ja3("a1b2c3d4e5f6")
            assert.is_not_nil(result)
            assert.equals("bot-fingerprint", result.metadata.source_id)
        end)

        it("should handle missing version", function()
            shared_data["taxii:version"] = nil
            cache.current_version = nil
            local result = cache:lookup_ip("192.168.1.1")
            assert.is_nil(result)
        end)
    end)

    describe("collection state management", function()
        it("should store and retrieve collection state", function()
            local state = {
                last_poll = "2023-01-01T12:00:00Z",
                cursor = "abc123",
                last_success = 1672574400
            }

            local success = cache:store_collection_state("https://taxii.example.com", "collection-1", state)
            assert.is_true(success)

            local retrieved = cache:get_collection_state("https://taxii.example.com", "collection-1")
            assert.equals("2023-01-01T12:00:00Z", retrieved.last_poll)
            assert.equals("abc123", retrieved.cursor)
        end)

        it("should return default state for missing collection", function()
            local state = cache:get_collection_state("https://new-server.com", "new-collection")
            assert.is_nil(state.last_poll)
            assert.is_nil(state.cursor)
            assert.is_nil(state.last_success)
        end)
    end)

    describe("version swapping", function()
        it("should perform atomic version swap", function()
            cache:get_current_version()  -- Initialize version to "1"

            local success, err = cache:atomic_swap_version("2")
            assert.is_true(success)
            assert.is_nil(err)

            local current_version = cache:get_current_version()
            assert.equals("2", current_version)
        end)

        it("should handle swap failures", function()
            -- Mock a failure in set operation
            mock_shared_dict.set = function(self, key, value, ttl)
                if key == "taxii:version" then
                    return false, "mock error"
                end
                shared_data[key] = value
                return true, nil
            end

            local success, err = cache:atomic_swap_version("2")
            assert.is_false(success)
            assert.is_not_nil(err)
        end)
    end)

    describe("statistics", function()
        it("should return cache statistics", function()
            -- Add some test data
            cache:store_indicator("1", "ip", "1.1.1.1", {source_id = "test"})
            cache:store_indicator("1", "domain", "test.com", {source_id = "test"})

            local stats = cache:get_stats()
            assert.is_not_nil(stats.version)
            assert.is_number(stats.total_keys)
            assert.is_table(stats.by_type)
            assert.is_number(stats.cache_capacity)
        end)
    end)

    describe("cache clearing", function()
        it("should clear all TAXII data", function()
            -- Add some test data
            cache:store_indicator("1", "ip", "1.1.1.1", {source_id = "test"})
            cache:set_metadata({test = "data"})

            local cleared = cache:clear_all()
            assert.is_number(cleared)
            assert.is_true(cleared > 0)

            -- Version should be reset
            cache.current_version = nil
            local version = cache:get_current_version()
            assert.equals("1", version)  -- Should reinitialize
        end)
    end)

    describe("CIDR matching", function()
        it("should check if IP is in CIDR range", function()
            local in_range = cache:ip_in_cidr("192.168.1.100", "192.168.1.0/24")
            assert.is_true(in_range)
        end)

        it("should handle invalid CIDR ranges", function()
            local in_range = cache:ip_in_cidr("192.168.1.100", "invalid/24")
            assert.is_false(in_range)
        end)
    end)

    describe("indicator counting", function()
        it("should count indicators in sets", function()
            local indicator_sets = {
                ip_set = {
                    ["1.1.1.1"] = {},
                    ["2.2.2.2"] = {}
                },
                domain_set = {
                    ["evil.com"] = {}
                }
            }

            local count = cache:count_sets(indicator_sets)
            assert.equals(3, count)
        end)

        it("should handle empty sets", function()
            local count = cache:count_sets({})
            assert.equals(0, count)
        end)
    end)
end)