local StixNormalizer = require "kong.plugins.kong-guard-ai.stix_normalizer"

describe("StixNormalizer", function()
    local normalizer
    local mock_config

    before_each(function()
        mock_config = {
            taxii_enable_dedup = true
        }
        normalizer = StixNormalizer.new(mock_config)
    end)

    describe("initialization", function()
        it("should create a new normalizer instance", function()
            assert.is_not_nil(normalizer)
            assert.is_true(normalizer.enable_dedup)
        end)

        it("should use default values when config is missing", function()
            local default_normalizer = StixNormalizer.new({})
            assert.is_not_nil(default_normalizer)
        end)
    end)

    describe("IP address normalization", function()
        it("should normalize valid IPv4 addresses", function()
            local normalized = normalizer:_normalize_ipv4("192.168.1.1")
            assert.equals("192.168.1.1", normalized)
        end)

        it("should normalize IPv4 with leading zeros", function()
            local normalized = normalizer:_normalize_ipv4("192.168.001.001")
            assert.equals("192.168.1.1", normalized)
        end)

        it("should reject invalid IPv4 addresses", function()
            assert.is_nil(normalizer:_normalize_ipv4("256.1.1.1"))
            assert.is_nil(normalizer:_normalize_ipv4("192.168.1"))
            assert.is_nil(normalizer:_normalize_ipv4("192.168.1.1.1"))
            assert.is_nil(normalizer:_normalize_ipv4("not.an.ip.address"))
        end)

        it("should normalize valid IPv6 addresses", function()
            local normalized = normalizer:_normalize_ipv6("2001:db8::1")
            assert.equals("2001:db8::1", normalized)
        end)

        it("should normalize IPv6 to lowercase", function()
            local normalized = normalizer:_normalize_ipv6("2001:DB8::1")
            assert.equals("2001:db8::1", normalized)
        end)

        it("should reject invalid IPv6 addresses", function()
            assert.is_nil(normalizer:_normalize_ipv6("invalid::ipv6::address"))
            assert.is_nil(normalizer:_normalize_ipv6("2001:db8::g"))
        end)
    end)

    describe("domain normalization", function()
        it("should normalize valid domains", function()
            local normalized = normalizer:_normalize_domain("Example.COM")
            assert.equals("example.com", normalized)
        end)

        it("should remove leading dots", function()
            local normalized = normalizer:_normalize_domain(".example.com")
            assert.equals("example.com", normalized)
        end)

        it("should reject invalid domains", function()
            assert.is_nil(normalizer:_normalize_domain("example..com"))
            assert.is_nil(normalizer:_normalize_domain("-example.com"))
            assert.is_nil(normalizer:_normalize_domain("example.com-"))
            assert.is_nil(normalizer:_normalize_domain("example@invalid.com"))
        end)
    end)

    describe("URL normalization", function()
        it("should normalize valid URLs", function()
            local normalized = normalizer:_normalize_url("HTTP://Example.COM/Path")
            assert.equals("http://example.com/path", normalized)
        end)

        it("should preserve query parameters case", function()
            local normalized = normalizer:_normalize_url("https://example.com/path?Param=Value")
            assert.equals("https://example.com/path?Param=Value", normalized)
        end)

        it("should reject invalid URLs", function()
            assert.is_nil(normalizer:_normalize_url("not-a-url"))
            assert.is_nil(normalizer:_normalize_url("ftp://example.com"))
        end)
    end)

    describe("hash normalization", function()
        it("should normalize valid MD5 hashes", function()
            local hash = "5D41402ABC4B2A76B9719D911017C592"
            local normalized = normalizer:_normalize_hash(hash, "md5")
            assert.equals("5d41402abc4b2a76b9719d911017c592", normalized)
        end)

        it("should normalize valid SHA-1 hashes", function()
            local hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
            local normalized = normalizer:_normalize_hash(hash, "sha1")
            assert.equals("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", normalized)
        end)

        it("should normalize valid SHA-256 hashes", function()
            local hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            local normalized = normalizer:_normalize_hash(hash, "sha256")
            assert.equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", normalized)
        end)

        it("should reject invalid hash lengths", function()
            assert.is_nil(normalizer:_normalize_hash("tooshort", "md5"))
            assert.is_nil(normalizer:_normalize_hash("waytoolongforthehashtype", "md5"))
        end)

        it("should reject non-hex characters", function()
            assert.is_nil(normalizer:_normalize_hash("5d41402abc4b2a76b9719d911017c59g", "md5"))
        end)
    end)

    describe("CIDR parsing", function()
        it("should parse valid IPv4 CIDR", function()
            local cidr = normalizer:_parse_cidr("192.168.1.0/24")
            assert.is_not_nil(cidr)
            assert.equals("192.168.1.0", cidr.ip)
            assert.equals(24, cidr.mask)
            assert.equals("192.168.1.0/24", cidr.cidr)
        end)

        it("should parse valid IPv6 CIDR", function()
            local cidr = normalizer:_parse_cidr("2001:db8::/32")
            assert.is_not_nil(cidr)
            assert.equals("2001:db8::", cidr.ip)
            assert.equals(32, cidr.mask)
        end)

        it("should reject invalid CIDR notation", function()
            assert.is_nil(normalizer:_parse_cidr("192.168.1.0/33"))  -- Invalid IPv4 mask
            assert.is_nil(normalizer:_parse_cidr("192.168.1.0"))     -- No mask
            assert.is_nil(normalizer:_parse_cidr("invalid/24"))      -- Invalid IP
        end)
    end)

    describe("regex validation", function()
        it("should validate simple regex patterns", function()
            local pattern = normalizer:_validate_regex("test.*pattern")
            assert.equals("test.*pattern", pattern)
        end)

        it("should reject overly complex patterns", function()
            local complex_pattern = "((((((((((test.*pattern))))))))))"
            local pattern = normalizer:_validate_regex(complex_pattern)
            assert.is_nil(pattern)
        end)

        it("should reject invalid regex patterns", function()
            local invalid_pattern = "test[unclosed"
            local pattern = normalizer:_validate_regex(invalid_pattern)
            assert.is_nil(pattern)
        end)
    end)

    describe("TLS fingerprint extraction", function()
        it("should extract JA3 from text", function()
            local text = "JA3: a1b2c3d4e5f6"
            local fingerprints = normalizer:_extract_tls_fingerprints(text)
            assert.equals("a1b2c3d4e5f6", fingerprints.ja3)
        end)

        it("should extract JA4 from text", function()
            local text = "JA4_hash=t13d1516h2_8daaf6152771_b0da82dd1658"
            local fingerprints = normalizer:_extract_tls_fingerprints(text)
            assert.equals("t13d1516h2_8daaf6152771_b0da82dd1658", fingerprints.ja4)
        end)

        it("should handle multiple fingerprints", function()
            local text = "JA3: a1b2c3 JA4: t13d1516h2"
            local fingerprints = normalizer:_extract_tls_fingerprints(text)
            assert.equals("a1b2c3", fingerprints.ja3)
            assert.equals("t13d1516h2", fingerprints.ja4)
        end)
    end)

    describe("STIX indicator parsing", function()
        it("should parse IP indicator", function()
            local stix_object = {
                type = "indicator",
                id = "indicator--test-1",
                pattern = "[ipv4-addr:value = '192.168.1.1']",
                labels = {"malicious-activity"}
            }

            local result = normalizer:parse_indicator(stix_object)
            assert.is_not_nil(result)
            assert.equals("indicator--test-1", result.id)
            assert.equals(1, #result.indicators.ips)
            assert.equals("192.168.1.1", result.indicators.ips[1])
        end)

        it("should parse domain indicator", function()
            local stix_object = {
                type = "indicator",
                id = "indicator--test-2",
                pattern = "[domain-name:value = 'evil.com']",
                labels = {"malicious-activity"}
            }

            local result = normalizer:parse_indicator(stix_object)
            assert.is_not_nil(result)
            assert.equals(1, #result.indicators.domains)
            assert.equals("evil.com", result.indicators.domains[1])
        end)

        it("should parse URL indicator", function()
            local stix_object = {
                type = "indicator",
                id = "indicator--test-3",
                pattern = "[url:value = 'https://evil.com/malware']",
                labels = {"malicious-activity"}
            }

            local result = normalizer:parse_indicator(stix_object)
            assert.is_not_nil(result)
            assert.equals(1, #result.indicators.urls)
            assert.equals("https://evil.com/malware", result.indicators.urls[1])
        end)

        it("should parse file hash indicators", function()
            local stix_object = {
                type = "indicator",
                id = "indicator--test-4",
                pattern = "[file:hashes.MD5 = '5d41402abc4b2a76b9719d911017c592']",
                labels = {"malicious-activity"}
            }

            local result = normalizer:parse_indicator(stix_object)
            assert.is_not_nil(result)
            assert.is_not_nil(result.indicators.hashes.md5)
            assert.equals(1, #result.indicators.hashes.md5)
            assert.equals("5d41402abc4b2a76b9719d911017c592", result.indicators.hashes.md5[1])
        end)

        it("should handle multiple indicators in one pattern", function()
            local stix_object = {
                type = "indicator",
                id = "indicator--test-5",
                pattern = "[ipv4-addr:value = '192.168.1.1'] OR [domain-name:value = 'evil.com']",
                labels = {"malicious-activity"}
            }

            local result = normalizer:parse_indicator(stix_object)
            assert.is_not_nil(result)
            assert.equals(1, #result.indicators.ips)
            assert.equals(1, #result.indicators.domains)
        end)

        it("should return nil for non-indicator objects", function()
            local stix_object = {
                type = "malware",
                id = "malware--test-1"
            }

            local result = normalizer:parse_indicator(stix_object)
            assert.is_nil(result)
        end)

        it("should return nil for indicators without patterns", function()
            local stix_object = {
                type = "indicator",
                id = "indicator--test-6",
                labels = ["malicious-activity"]
                -- missing pattern
            }

            local result = normalizer:parse_indicator(stix_object)
            assert.is_nil(result)
        end)
    end)

    describe("indicator validation", function()
        it("should validate current indicators", function()
            local indicator = {
                valid_from = nil,
                valid_until = nil
            }
            local is_valid = normalizer:is_indicator_valid(indicator, ngx.time())
            assert.is_true(is_valid)
        end)

        it("should handle future valid_from", function()
            local future_time = ngx.time() + 3600
            local indicator = {
                valid_from = os.date("!%Y-%m-%dT%H:%M:%SZ", future_time)
            }
            local is_valid = normalizer:is_indicator_valid(indicator, ngx.time())
            assert.is_false(is_valid)
        end)

        it("should handle past valid_until", function()
            local past_time = ngx.time() - 3600
            local indicator = {
                valid_until = os.date("!%Y-%m-%dT%H:%M:%SZ", past_time)
            }
            local is_valid = normalizer:is_indicator_valid(indicator, ngx.time())
            assert.is_false(is_valid)
        end)
    end)

    describe("batch processing", function()
        it("should process multiple STIX objects", function()
            local stix_objects = {
                {
                    type = "indicator",
                    id = "indicator--test-1",
                    pattern = "[ipv4-addr:value = '192.168.1.1']",
                    labels = {"malicious-activity"}
                },
                {
                    type = "indicator",
                    id = "indicator--test-2",
                    pattern = "[domain-name:value = 'evil.com']",
                    labels = {"malicious-activity"}
                },
                {
                    type = "malware",
                    id = "malware--test-1"
                }
            }

            local results, err = normalizer:process_objects(stix_objects)
            assert.is_nil(err)
            assert.is_not_nil(results)
            assert.equals(3, results.stats.total_objects)
            assert.equals(2, results.stats.indicators_parsed)
            assert.equals(1, results.stats.ips_extracted)
            assert.equals(1, results.stats.domains_extracted)
        end)

        it("should handle deduplication", function()
            local stix_objects = {
                {
                    type = "indicator",
                    id = "indicator--duplicate",
                    pattern = "[ipv4-addr:value = '192.168.1.1']",
                    labels = {"malicious-activity"}
                },
                {
                    type = "indicator",
                    id = "indicator--duplicate",  -- Same ID
                    pattern = "[ipv4-addr:value = '192.168.1.2']",
                    labels = {"malicious-activity"}
                }
            }

            local results, err = normalizer:process_objects(stix_objects)
            assert.is_nil(err)
            assert.equals(1, results.stats.indicators_parsed)  -- Should be deduplicated
        end)

        it("should handle empty input", function()
            local results, err = normalizer:process_objects({})
            assert.is_nil(err)
            assert.equals(0, results.stats.total_objects)
            assert.equals(0, results.stats.indicators_parsed)
        end)
    end)

    describe("lookup sets creation", function()
        it("should create lookup sets from parsed indicators", function()
            local parsed_indicators = {
                {
                    id = "indicator--test-1",
                    labels = {"malicious-activity"},
                    valid_from = nil,
                    valid_until = nil,
                    confidence = 85,
                    indicators = {
                        ips = {"192.168.1.1"},
                        domains = {"evil.com"},
                        urls = {},
                        hashes = {},
                        regexes = {},
                        tls_fingerprints = {}
                    }
                }
            }

            local sets = normalizer:create_lookup_sets(parsed_indicators)
            assert.is_not_nil(sets.ip_set["192.168.1.1"])
            assert.is_not_nil(sets.domain_set["evil.com"])
            assert.equals("indicator--test-1", sets.ip_set["192.168.1.1"].source_id)
        end)
    end)
end)