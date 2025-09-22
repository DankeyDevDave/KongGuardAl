local TaxiiScheduler = require "kong.plugins.kong-guard-ai.taxii_scheduler"

describe("TaxiiScheduler", function()
    local scheduler
    local mock_config

    -- Mock dependencies
    local mock_client = {}
    local mock_normalizer = {}
    local mock_cache = {}
    local mock_shared_dict = {}
    local shared_data = {}

    before_each(function()
        mock_config = {
            enable_taxii_ingestion = true,
            taxii_poll_interval_seconds = 300,
            taxii_max_objects_per_poll = 500,
            taxii_servers = {
                {
                    url = "https://taxii.example.com",
                    collections = {"collection-1"},
                    auth_type = "none"
                }
            }
        }

        -- Reset shared dict data
        shared_data = {}

        -- Mock shared dict methods
        mock_shared_dict.get = function(self, key)
            return shared_data[key], nil
        end

        mock_shared_dict.set = function(self, key, value, ttl)
            shared_data[key] = value
            return true, nil
        end

        mock_shared_dict.incr = function(self, key, value, init, ttl)
            local current = shared_data[key] or init or 0
            shared_data[key] = current + value
            return shared_data[key], nil
        end

        -- Mock ngx.shared.kong_cache
        _G.ngx = _G.ngx or {}
        _G.ngx.shared = _G.ngx.shared or {}
        _G.ngx.shared.kong_cache = mock_shared_dict
        _G.ngx.time = function() return 1672574400 end
        _G.ngx.now = function() return 1672574400.123 end

        -- Mock timer functionality
        _G.ngx.timer = _G.ngx.timer or {}
        _G.ngx.timer.at = function(delay, callback)
            return true, nil  -- Simulate successful timer scheduling
        end

        -- Mock TAXII client
        mock_client.discover_server = function(self, server_config)
            return {
                api_roots = {"https://taxii.example.com/api1"}
            }, nil
        end

        mock_client.get_collections = function(self, server_config, api_root)
            return {
                {id = "collection-1", title = "Test Collection"}
            }, nil
        end

        mock_client.poll_collection = function(self, server_config, api_root, collection_id, options)
            return {
                objects = {
                    {
                        type = "indicator",
                        id = "indicator--test-1",
                        pattern = "[ipv4-addr:value = '192.168.1.1']",
                        labels = {"malicious-activity"}
                    }
                },
                more = false,
                next = nil
            }, nil
        end

        mock_client.test_connection = function(self, server_config)
            return true, nil
        end

        -- Mock STIX normalizer
        mock_normalizer.process_objects = function(self, objects)
            return {
                indicators = {
                    {
                        id = "indicator--test-1",
                        indicators = {
                            ips = {"192.168.1.1"},
                            domains = {},
                            urls = {},
                            hashes = {},
                            regexes = {},
                            tls_fingerprints = {}
                        }
                    }
                },
                stats = {
                    total_objects = #objects,
                    indicators_parsed = 1,
                    ips_extracted = 1,
                    domains_extracted = 0,
                    urls_extracted = 0,
                    errors = 0
                }
            }, nil
        end

        mock_normalizer.create_lookup_sets = function(self, indicators)
            return {
                ip_set = {
                    ["192.168.1.1"] = {
                        source_id = "indicator--test-1",
                        labels = {"malicious-activity"}
                    }
                },
                domain_set = {},
                url_set = {},
                ja3_set = {},
                ja4_set = {}
            }
        end

        -- Mock TAXII cache
        mock_cache.get_collection_state = function(self, server_url, collection_id)
            return {
                last_poll = nil,
                cursor = nil,
                last_success = nil
            }
        end

        mock_cache.store_collection_state = function(self, server_url, collection_id, state)
            return true
        end

        mock_cache.generate_next_version = function(self)
            return "2"
        end

        mock_cache.bulk_load_indicators = function(self, version, indicator_sets)
            return {
                loaded = 1,
                errors = 0
            }
        end

        mock_cache.get_metadata = function(self)
            return {}
        end

        mock_cache.set_metadata = function(self, metadata)
            return true
        end

        mock_cache.atomic_swap_version = function(self, new_version)
            return true, nil
        end

        -- Create scheduler with mocked dependencies
        scheduler = TaxiiScheduler.new(mock_config)
        scheduler.client = mock_client
        scheduler.normalizer = mock_normalizer
        scheduler.cache = mock_cache
    end)

    describe("initialization", function()
        it("should create a new scheduler instance", function()
            assert.is_not_nil(scheduler)
            assert.is_true(scheduler.enabled)
            assert.equals(300, scheduler.poll_interval)
            assert.equals(500, scheduler.max_objects)
        end)

        it("should be disabled when taxii ingestion is disabled", function()
            local disabled_config = {enable_taxii_ingestion = false}
            local disabled_scheduler = TaxiiScheduler.new(disabled_config)
            assert.is_false(disabled_scheduler.enabled)
        end)

        it("should use default values", function()
            local default_scheduler = TaxiiScheduler.new({})
            assert.equals(300, default_scheduler.poll_interval)
            assert.equals(500, default_scheduler.max_objects)
        end)
    end)

    describe("scheduler lifecycle", function()
        it("should start successfully when enabled", function()
            local success = scheduler:start()
            assert.is_true(success)
            assert.is_true(scheduler.running)
        end)

        it("should not start when disabled", function()
            scheduler.enabled = false
            local success = scheduler:start()
            assert.is_true(success)  -- Returns true but doesn't actually start
            assert.is_false(scheduler.running)
        end)

        it("should not start twice", function()
            scheduler:start()
            local success = scheduler:start()
            assert.is_true(success)  -- Should handle gracefully
        end)

        it("should stop successfully", function()
            scheduler:start()
            scheduler:stop()
            assert.is_false(scheduler.running)
        end)
    end)

    describe("server polling", function()
        it("should poll configured servers", function()
            local indicators, errors = scheduler:poll_server(mock_config.taxii_servers[1])
            assert.equals(1, indicators)
            assert.equals(0, errors)
        end)

        it("should handle discovery failures", function()
            mock_client.discover_server = function(self, server_config)
                return nil, "Connection failed"
            end

            local indicators, errors = scheduler:poll_server(mock_config.taxii_servers[1])
            assert.equals(0, indicators)
            assert.equals(1, errors)
        end)

        it("should handle collection fetch failures", function()
            mock_client.get_collections = function(self, server_config, api_root)
                return nil, "Collections fetch failed"
            end

            local indicators, errors = scheduler:poll_server(mock_config.taxii_servers[1])
            assert.equals(0, indicators)
            assert.equals(1, errors)
        end)

        it("should filter collections based on configuration", function()
            mock_client.get_collections = function(self, server_config, api_root)
                return {
                    {id = "collection-1", title = "Wanted Collection"},
                    {id = "collection-2", title = "Unwanted Collection"}
                }, nil
            end

            -- Configure to only poll collection-1
            local server_config = {
                url = "https://taxii.example.com",
                collections = {"collection-1"},
                auth_type = "none"
            }

            local indicators, errors = scheduler:poll_server(server_config)
            assert.equals(1, indicators)  -- Should only process collection-1
            assert.equals(0, errors)
        end)
    end)

    describe("collection polling", function()
        it("should poll collections with pagination", function()
            local collection = {id = "collection-1"}
            local indicators, errors = scheduler:poll_collection(
                mock_config.taxii_servers[1],
                "https://taxii.example.com/api1",
                collection
            )
            assert.equals(1, indicators)
            assert.equals(0, errors)
        end)

        it("should handle polling failures", function()
            mock_client.poll_collection = function(self, server_config, api_root, collection_id, options)
                return nil, "Polling failed"
            end

            local collection = {id = "collection-1"}
            local indicators, errors = scheduler:poll_collection(
                mock_config.taxii_servers[1],
                "https://taxii.example.com/api1",
                collection
            )
            assert.equals(0, indicators)
            assert.equals(1, errors)
        end)

        it("should handle pagination", function()
            local call_count = 0
            mock_client.poll_collection = function(self, server_config, api_root, collection_id, options)
                call_count = call_count + 1
                if call_count == 1 then
                    return {
                        objects = {{type = "indicator", id = "ind-1", pattern = "[ipv4-addr:value='1.1.1.1']", labels = {"mal"}}},
                        more = true,
                        next = "cursor123"
                    }, nil
                else
                    return {
                        objects = {{type = "indicator", id = "ind-2", pattern = "[ipv4-addr:value='2.2.2.2']", labels = {"mal"}}},
                        more = false,
                        next = nil
                    }, nil
                end
            end

            local collection = {id = "collection-1"}
            local indicators, errors = scheduler:poll_collection(
                mock_config.taxii_servers[1],
                "https://taxii.example.com/api1",
                collection
            )
            assert.equals(2, indicators)  -- Should process both batches
            assert.equals(0, errors)
        end)
    end)

    describe("STIX processing", function()
        it("should process STIX objects successfully", function()
            local stix_objects = {
                {
                    type = "indicator",
                    id = "indicator--test-1",
                    pattern = "[ipv4-addr:value = '192.168.1.1']",
                    labels = {"malicious-activity"}
                }
            }

            local processed = scheduler:process_stix_objects(
                stix_objects,
                "https://taxii.example.com",
                "collection-1"
            )
            assert.equals(1, processed)
        end)

        it("should handle empty STIX objects", function()
            local processed = scheduler:process_stix_objects(
                {},
                "https://taxii.example.com",
                "collection-1"
            )
            assert.equals(0, processed)
        end)

        it("should handle STIX processing failures", function()
            mock_normalizer.process_objects = function(self, objects)
                return nil, "Processing failed"
            end

            local stix_objects = {
                {type = "indicator", id = "test"}
            }

            local processed = scheduler:process_stix_objects(
                stix_objects,
                "https://taxii.example.com",
                "collection-1"
            )
            assert.equals(0, processed)
        end)

        it("should handle cache version generation failures", function()
            mock_cache.generate_next_version = function(self)
                return nil
            end

            local stix_objects = {
                {
                    type = "indicator",
                    id = "indicator--test-1",
                    pattern = "[ipv4-addr:value = '192.168.1.1']",
                    labels = {"malicious-activity"}
                }
            }

            local processed = scheduler:process_stix_objects(
                stix_objects,
                "https://taxii.example.com",
                "collection-1"
            )
            assert.equals(0, processed)
        end)
    end)

    describe("metrics management", function()
        it("should update metrics", function()
            scheduler:update_metrics("test_counter", 5)
            scheduler:update_metrics("test_gauge", 10)

            -- Verify metrics were stored
            assert.equals(5, shared_data["taxii_metrics:test_counter"])
            assert.equals(10, shared_data["taxii_metrics:test_gauge"])
        end)

        it("should get metrics", function()
            -- Set some test metrics
            shared_data["taxii_metrics:polls_total"] = 10
            shared_data["taxii_metrics:indicators_loaded"] = 50
            shared_data["taxii_metrics:errors_total"] = 2

            local metrics = scheduler:get_metrics()
            assert.equals(10, metrics.polls_total)
            assert.equals(50, metrics.indicators_loaded)
            assert.equals(2, metrics.errors_total)
        end)

        it("should handle missing metrics", function()
            local metrics = scheduler:get_metrics()
            assert.equals(0, metrics.polls_total)
            assert.equals(0, metrics.indicators_loaded)
        end)
    end)

    describe("status reporting", function()
        it("should report scheduler status", function()
            scheduler:start()

            local status = scheduler:get_status()
            assert.is_true(status.running)
            assert.is_true(status.enabled)
            assert.equals(300, status.poll_interval_seconds)
            assert.equals(1, status.servers_configured)
            assert.is_table(status.metrics)
            assert.is_table(status.cache)
        end)

        it("should handle never polled state", function()
            local status = scheduler:get_status()
            assert.equals("never", status.last_poll_time)
        end)
    end)

    describe("connectivity testing", function()
        it("should test connectivity to all servers", function()
            local results = scheduler:test_connectivity()
            assert.equals(1, #results)
            assert.equals("https://taxii.example.com", results[1].url)
            assert.is_true(results[1].success)
            assert.is_nil(results[1].error)
        end)

        it("should handle connection failures", function()
            mock_client.test_connection = function(self, server_config)
                return false, "Connection timeout"
            end

            local results = scheduler:test_connectivity()
            assert.equals(1, #results)
            assert.is_false(results[1].success)
            assert.equals("Connection timeout", results[1].error)
        end)
    end)

    describe("force polling", function()
        it("should allow force polling when enabled", function()
            local success, err = scheduler:force_poll()
            assert.is_true(success)
            assert.is_nil(err)
        end)

        it("should reject force polling when disabled", function()
            scheduler.enabled = false
            local success, err = scheduler:force_poll()
            assert.is_false(success)
            assert.equals("TAXII ingestion disabled", err)
        end)
    end)

    describe("reset functionality", function()
        it("should reset scheduler state and metrics", function()
            -- Set some test data
            scheduler:update_metrics("polls_total", 5)
            shared_data["taxii:scheduler_state"] = "test_state"

            scheduler:reset()

            -- Verify data was cleared
            assert.is_nil(shared_data["taxii_metrics:polls_total"])
            assert.is_nil(shared_data["taxii:scheduler_state"])
        end)
    end)

    describe("failure backoff", function()
        it("should calculate backoff intervals", function()
            local backoff_interval = scheduler:handle_failure_backoff("https://test.com", 3)
            assert.equals(900, backoff_interval)  -- 300 * 3
        end)

        it("should cap backoff at maximum", function()
            local backoff_interval = scheduler:handle_failure_backoff("https://test.com", 10)
            assert.equals(1500, backoff_interval)  -- 300 * 5 (capped at 5x)
        end)
    end)

    describe("cleanup", function()
        it("should cleanup gracefully", function()
            scheduler:start()
            scheduler:cleanup()
            assert.is_false(scheduler.running)
        end)
    end)
end)