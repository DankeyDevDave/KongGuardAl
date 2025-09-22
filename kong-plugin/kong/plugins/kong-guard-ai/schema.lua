local typedefs = require "kong.db.schema.typedefs"

return {
    name = "kong-guard-ai",
    fields = {
        {
            protocols = typedefs.protocols_http
        },
        {
            config = {
                type = "record",
                fields = {
                    -- Threat Detection Thresholds
                    {
                        block_threshold = {
                            type = "number",
                            default = 0.8,
                            between = {0, 1},
                            required = true,
                            description = "Threat score threshold for blocking (0-1)"
                        }
                    },
                    {
                        rate_limit_threshold = {
                            type = "number",
                            default = 0.6,
                            between = {0, 1},
                            required = true,
                            description = "Threat score threshold for rate limiting (0-1)"
                        }
                    },
                    {
                        ddos_rpm_threshold = {
                            type = "integer",
                            default = 100,
                            required = true,
                            description = "Requests per minute threshold for DDoS detection"
                        }
                    },

                    -- Operating Mode
                    {
                        dry_run = {
                            type = "boolean",
                            default = false,
                            required = true,
                            description = "Enable dry-run mode (log only, no enforcement)"
                        }
                    },

                    -- ML Configuration
                    {
                        enable_ml_detection = {
                            type = "boolean",
                            default = true,
                            required = true,
                            description = "Enable machine learning-based detection"
                        }
                    },
                    {
                        anomaly_threshold = {
                            type = "number",
                            default = 0.7,
                            between = {0, 1},
                            description = "Anomaly score threshold for ML detection"
                        }
                    },

                    -- AI Gateway Integration (optional)
                    {
                        enable_ai_gateway = {
                            type = "boolean",
                            default = false,
                            description = "Enable Kong AI Gateway integration for advanced analysis"
                        }
                    },
                    {
                        ai_service_url = {
                            type = "string",
                            default = "http://ai-service:8000",
                            description = "URL of the AI threat analysis service"
                        }
                    },
                    {
                        ai_model = {
                            type = "string",
                            default = "claude-3-haiku",
                            one_of = {
                                "claude-3-haiku",
                                "claude-3-sonnet",
                                "gpt-4",
                                "gpt-3.5-turbo",
                                "llama2"
                            },
                            description = "AI model to use for analysis"
                        }
                    },
                    {
                        ai_temperature = {
                            type = "number",
                            default = 0.1,
                            between = {0, 1},
                            description = "AI model temperature for consistent decisions"
                        }
                    },

                    -- Notification Configuration
                    {
                        enable_notifications = {
                            type = "boolean",
                            default = true,
                            description = "Enable threat notifications"
                        }
                    },
                    {
                        notification_url = {
                            type = "string",
                            description = "Webhook URL for notifications (Slack, Email gateway, etc.)"
                        }
                    },
                    {
                        notification_channels = {
                            type = "array",
                            default = {"webhook"},
                            elements = {
                                type = "string",
                                one_of = {"webhook", "slack", "email", "log"}
                            },
                            description = "Notification channels to use"
                        }
                    },

                    -- Learning & Feedback
                    {
                        enable_learning = {
                            type = "boolean",
                            default = true,
                            description = "Enable continuous learning from feedback"
                        }
                    },
                    {
                        learning_rate = {
                            type = "number",
                            default = 0.001,
                            between = {0, 1},
                            description = "Learning rate for threshold adaptation"
                        }
                    },
                    {
                        feedback_endpoint = {
                            type = "string",
                            default = "/kong-guard-ai/feedback",
                            description = "Endpoint for operator feedback"
                        }
                    },

                    -- Response Actions
                    {
                        auto_block_duration = {
                            type = "integer",
                            default = 3600,
                            description = "Duration to block threats (seconds)"
                        }
                    },
                    {
                        rate_limit_duration = {
                            type = "integer",
                            default = 300,
                            description = "Duration for rate limiting (seconds)"
                        }
                    },
                    {
                        rate_limit_requests = {
                            type = "integer",
                            default = 10,
                            description = "Number of requests allowed during rate limit period"
                        }
                    },

                    -- Advanced Rate Limiting Configuration
                    {
                        enable_adaptive_rate_limiting = {
                            type = "boolean",
                            default = false,
                            description = "Enable adaptive rate limiting based on threat scores"
                        }
                    },
                    {
                        adaptive_rate_config = {
                            type = "record",
                            fields = {
                                {
                                    base_rate_per_minute = {
                                        type = "integer",
                                        default = 60,
                                        between = {1, 10000},
                                        description = "Base rate limit per minute"
                                    }
                                },
                                {
                                    threat_score_multiplier = {
                                        type = "number",
                                        default = 2.0,
                                        between = {0.1, 10.0},
                                        description = "Multiplier to reduce rate based on threat score"
                                    }
                                },
                                {
                                    min_rate_per_minute = {
                                        type = "integer",
                                        default = 5,
                                        between = {1, 1000},
                                        description = "Minimum rate limit per minute"
                                    }
                                },
                                {
                                    max_rate_per_minute = {
                                        type = "integer",
                                        default = 1000,
                                        between = {10, 100000},
                                        description = "Maximum rate limit per minute"
                                    }
                                }
                            }
                        }
                    },

                    -- DDoS Protection Configuration
                    {
                        enable_ddos_mitigation = {
                            type = "boolean",
                            default = false,
                            description = "Enable advanced DDoS mitigation with challenge-response"
                        }
                    },
                    {
                        ddos_protection = {
                            type = "record",
                            fields = {
                                {
                                    ddos_threshold_rps = {
                                        type = "integer",
                                        default = 100,
                                        between = {1, 10000},
                                        description = "DDoS detection threshold in requests per second"
                                    }
                                },
                                {
                                    challenge_response_enabled = {
                                        type = "boolean",
                                        default = true,
                                        description = "Enable challenge-response mechanism for DDoS mitigation"
                                    }
                                },
                                {
                                    challenge_timeout_seconds = {
                                        type = "integer",
                                        default = 30,
                                        between = {5, 300},
                                        description = "Timeout for challenge response in seconds"
                                    }
                                },
                                {
                                    challenge_difficulty = {
                                        type = "integer",
                                        default = 2,
                                        between = {1, 10},
                                        description = "Difficulty level for proof-of-work challenges"
                                    }
                                },
                                {
                                    mitigation_actions = {
                                        type = "array",
                                        elements = {
                                            type = "string",
                                            one_of = {"challenge", "block", "rate_limit", "delay"}
                                        },
                                        default = {"challenge", "rate_limit"},
                                        description = "Actions to take during DDoS attack"
                                    }
                                }
                            }
                        }
                    },

                    -- Geographic Rate Limiting Configuration
                    {
                        enable_geo_limiting = {
                            type = "boolean",
                            default = false,
                            description = "Enable geographic-based rate limiting"
                        }
                    },
                    {
                        geographic_limiting = {
                            type = "record",
                            fields = {
                                {
                                    geo_rate_limits = {
                                        type = "array",
                                        elements = {
                                            type = "record",
                                            fields = {
                                                {
                                                    country_code = {
                                                        type = "string",
                                                        description = "ISO 3166-1 alpha-2 country code"
                                                    }
                                                },
                                                {
                                                    rate_per_minute = {
                                                        type = "integer",
                                                        between = {1, 100000},
                                                        description = "Rate limit per minute for this country"
                                                    }
                                                }
                                            }
                                        },
                                        default = {},
                                        description = "Country-specific rate limits"
                                    }
                                },
                                {
                                    default_rate_per_minute = {
                                        type = "integer",
                                        default = 100,
                                        between = {1, 100000},
                                        description = "Default rate limit for unlisted countries"
                                    }
                                },
                                {
                                    enable_geo_anomaly_detection = {
                                        type = "boolean",
                                        default = true,
                                        description = "Detect geographic anomalies (VPN/proxy usage)"
                                    }
                                },
                                {
                                    geo_anomaly_threshold = {
                                        type = "number",
                                        default = 0.8,
                                        between = {0.1, 1.0},
                                        description = "Threshold for geographic anomaly detection"
                                    }
                                }
                            }
                        }
                    },

                    -- Circuit Breaker Configuration
                    {
                        enable_circuit_breakers = {
                            type = "boolean",
                            default = false,
                            description = "Enable circuit breaker pattern for resilience"
                        }
                    },
                    {
                        circuit_breakers = {
                            type = "record",
                            fields = {
                                {
                                    failure_threshold = {
                                        type = "integer",
                                        default = 5,
                                        between = {1, 100},
                                        description = "Number of failures before circuit trips"
                                    }
                                },
                                {
                                    recovery_timeout_seconds = {
                                        type = "integer",
                                        default = 60,
                                        between = {5, 3600},
                                        description = "Time before attempting recovery"
                                    }
                                },
                                {
                                    success_threshold = {
                                        type = "integer",
                                        default = 3,
                                        between = {1, 10},
                                        description = "Successful requests needed to close circuit"
                                    }
                                },
                                {
                                    timeout_seconds = {
                                        type = "integer",
                                        default = 10,
                                        between = {1, 60},
                                        description = "Request timeout for circuit breaker"
                                    }
                                }
                            }
                        }
                    },

                    -- Advanced Rate Limiting Metrics
                    {
                        enable_rate_limiting_metrics = {
                            type = "boolean",
                            default = true,
                            description = "Enable detailed rate limiting metrics"
                        }
                    },

                    -- Admin API Integration
                    {
                        enable_admin_api = {
                            type = "boolean",
                            default = true,
                            description = "Enable Admin API integration for dynamic configuration"
                        }
                    },
                    {
                        admin_api_url = {
                            type = "string",
                            default = "http://localhost:8001",
                            description = "Kong Admin API URL"
                        }
                    },

                    -- Logging & Monitoring
                    {
                        log_level = {
                            type = "string",
                            default = "info",
                            one_of = {"debug", "info", "warn", "error", "critical"},
                            description = "General logging level"
                        }
                    },
                    -- Normalization & Canonicalization
                    {
                        normalize_url = {
                            type = "boolean",
                            default = true,
                            description = "Enable URL canonicalization prior to analysis"
                        }
                    },
                    {
                        normalize_body = {
                            type = "boolean",
                            default = false,
                            description = "Enable request body normalization prior to analysis"
                        }
                    },
                    {
                        normalization_profile = {
                            type = "string",
                            default = "lenient",
                            one_of = {"lenient", "strict"},
                            description = "Normalization strictness profile"
                        }
                    },
                    -- GraphQL Detection & Limits
                    {
                        enable_graphql_detection = {
                            type = "boolean",
                            default = true,
                            description = "Enable GraphQL request detection and limits enforcement"
                        }
                    },
                    {
                        graphql_max_depth = {
                            type = "integer",
                            default = 12,
                            between = {1, 1000},
                            description = "Maximum allowed GraphQL selection set depth"
                        }
                    },
                    {
                        graphql_max_complexity = {
                            type = "integer",
                            default = 2000,
                            between = {1, 1000000},
                            description = "Maximum allowed GraphQL complexity score (heuristic)"
                        }
                    },
                    -- gRPC Detection & Limits
                    {
                        enable_grpc_detection = {
                            type = "boolean",
                            default = true,
                            description = "Enable gRPC request detection and method-aware controls"
                        }
                    },
                    {
                        grpc_max_message_size = {
                            type = "integer",
                            default = 4194304,
                            between = {1024, 104857600},
                            description = "Maximum allowed gRPC message size in bytes (default 4MB)"
                        }
                    },
                    {
                        grpc_blocked_methods = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of blocked gRPC service.method patterns (e.g., 'admin.*', '*.DeleteUser')"
                        }
                    },
                    {
                        grpc_rate_limit_per_method = {
                            type = "integer",
                            default = 100,
                            between = {1, 10000},
                            description = "Rate limit per gRPC method per minute"
                        }
                    },

                    -- TLS Fingerprinting Configuration
                    {
                        enable_tls_fingerprints = {
                            type = "boolean",
                            default = false,
                            description = "Enable TLS fingerprinting (JA3/JA4) threat detection"
                        }
                    },
                    {
                        tls_header_map = {
                            type = "record",
                            default = {
                                ja3 = "X-JA3",
                                ja3s = "X-JA3S",
                                ja4 = "X-JA4",
                                ja4s = "X-JA4S",
                                tls_version = "X-TLS-Version",
                                tls_cipher = "X-TLS-Cipher",
                                sni = "X-TLS-ServerName"
                            },
                            fields = {
                                {
                                    ja3 = {
                                        type = "string",
                                        default = "X-JA3",
                                        description = "Header name for JA3 fingerprint"
                                    }
                                },
                                {
                                    ja3s = {
                                        type = "string",
                                        default = "X-JA3S",
                                        description = "Header name for JA3S fingerprint"
                                    }
                                },
                                {
                                    ja4 = {
                                        type = "string",
                                        default = "X-JA4",
                                        description = "Header name for JA4 fingerprint"
                                    }
                                },
                                {
                                    ja4s = {
                                        type = "string",
                                        default = "X-JA4S",
                                        description = "Header name for JA4S fingerprint"
                                    }
                                },
                                {
                                    tls_version = {
                                        type = "string",
                                        default = "X-TLS-Version",
                                        description = "Header name for TLS version"
                                    }
                                },
                                {
                                    tls_cipher = {
                                        type = "string",
                                        default = "X-TLS-Cipher",
                                        description = "Header name for TLS cipher suite"
                                    }
                                },
                                {
                                    sni = {
                                        type = "string",
                                        default = "X-TLS-ServerName",
                                        description = "Header name for SNI (Server Name Indication)"
                                    }
                                }
                            },
                            description = "Mapping of TLS fingerprint types to HTTP header names"
                        }
                    },
                    {
                        tls_cache_ttl_seconds = {
                            type = "integer",
                            default = 600,
                            between = {60, 3600},
                            description = "TTL for TLS fingerprint cache entries (seconds)"
                        }
                    },
                    {
                        tls_blocklist = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of blocked TLS fingerprints (supports * wildcard)"
                        }
                    },
                    {
                        tls_allowlist = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of allowed TLS fingerprints (supports * wildcard)"
                        }
                    },
                    {
                        tls_score_weights = {
                            type = "record",
                            default = {
                                match_blocklist = 0.7,
                                match_allowlist = -0.4,
                                ua_mismatch = 0.2,
                                rare_fingerprint = 0.2,
                                velocity = 0.3
                            },
                            fields = {
                                {
                                    match_blocklist = {
                                        type = "number",
                                        default = 0.7,
                                        between = {0, 1},
                                        description = "Score weight for blocklist matches"
                                    }
                                },
                                {
                                    match_allowlist = {
                                        type = "number",
                                        default = -0.4,
                                        between = {-1, 0},
                                        description = "Score weight for allowlist matches (negative)"
                                    }
                                },
                                {
                                    ua_mismatch = {
                                        type = "number",
                                        default = 0.2,
                                        between = {0, 1},
                                        description = "Score weight for User-Agent to JA3 mismatches"
                                    }
                                },
                                {
                                    rare_fingerprint = {
                                        type = "number",
                                        default = 0.2,
                                        between = {0, 1},
                                        description = "Score weight for rare fingerprints"
                                    }
                                },
                                {
                                    velocity = {
                                        type = "number",
                                        default = 0.3,
                                        between = {0, 1},
                                        description = "Score weight for high velocity fingerprints"
                                    }
                                }
                            },
                            description = "Scoring weights for different TLS fingerprint signals"
                        }
                    },
                    {
                        tls_rare_fp_min_ips = {
                            type = "integer",
                            default = 5,
                            between = {1, 100},
                            description = "Minimum unique IPs required before fingerprint is no longer considered rare"
                        }
                    },
                    {
                        tls_rate_limit_per_fp = {
                            type = "integer",
                            default = 120,
                            between = {1, 10000},
                            description = "Rate limit threshold per fingerprint per minute"
                        }
                    },
                    {
                        log_threats = {
                            type = "boolean",
                            default = true,
                            description = "Log detected threats"
                        }
                    },
                    {
                        log_requests = {
                            type = "boolean",
                            default = false,
                            description = "Log all requests (verbose)"
                        }
                    },
                    {
                        log_decisions = {
                            type = "boolean",
                            default = true,
                            description = "Log blocking/rate-limiting decisions"
                        }
                    },
                    {
                        metrics_enabled = {
                            type = "boolean",
                            default = true,
                            description = "Enable metrics collection"
                        }
                    },

                    -- Pattern Detection Rules
                    {
                        sql_injection_patterns = {
                            type = "array",
                            default = {
                                "union%s+select",
                                "drop%s+table",
                                "insert%s+into",
                                "select%s+from"
                            },
                            elements = {type = "string"},
                            description = "SQL injection detection patterns"
                        }
                    },
                    {
                        xss_patterns = {
                            type = "array",
                            default = {
                                "<script",
                                "javascript:",
                                "onerror=",
                                "onload="
                            },
                            elements = {type = "string"},
                            description = "XSS detection patterns"
                        }
                    },

                    -- Geographic & IP Configuration
                    {
                        blocked_countries = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of blocked country codes"
                        }
                    },
                    {
                        blocked_ips = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of blocked IP addresses"
                        }
                    },
                    {
                        whitelist_ips = {
                            type = "array",
                            default = {},
                            elements = {type = "string"},
                            description = "List of whitelisted IP addresses"
                        }
                    },

                    -- TAXII/STIX Threat Intelligence Configuration
                    {
                        enable_taxii_ingestion = {
                            type = "boolean",
                            default = false,
                            description = "Enable TAXII threat intelligence ingestion"
                        }
                    },
                    {
                        taxii_version = {
                            type = "string",
                            default = "2.1",
                            one_of = {"2.0", "2.1"},
                            description = "TAXII protocol version to use"
                        }
                    },
                    {
                        taxii_servers = {
                            type = "array",
                            default = {},
                            elements = {
                                type = "record",
                                fields = {
                                    {
                                        url = {
                                            type = "string",
                                            required = true,
                                            description = "TAXII server base URL"
                                        }
                                    },
                                    {
                                        collections = {
                                            type = "array",
                                            default = {},
                                            elements = {type = "string"},
                                            description = "List of collection IDs to poll"
                                        }
                                    },
                                    {
                                        auth_type = {
                                            type = "string",
                                            default = "none",
                                            one_of = {"none", "basic", "bearer"},
                                            description = "Authentication type for this server"
                                        }
                                    },
                                    {
                                        username = {
                                            type = "string",
                                            description = "Username for basic authentication"
                                        }
                                    },
                                    {
                                        password = {
                                            type = "string",
                                            description = "Password for basic authentication"
                                        }
                                    },
                                    {
                                        token = {
                                            type = "string",
                                            description = "Bearer token for authentication"
                                        }
                                    }
                                }
                            },
                            description = "TAXII server configurations"
                        }
                    },
                    {
                        taxii_poll_interval_seconds = {
                            type = "integer",
                            default = 300,
                            between = {60, 86400},
                            description = "Polling interval for TAXII feeds in seconds"
                        }
                    },
                    {
                        taxii_cache_ttl_seconds = {
                            type = "integer",
                            default = 3600,
                            between = {300, 604800},
                            description = "Cache TTL for TAXII indicators in seconds"
                        }
                    },
                    {
                        taxii_max_objects_per_poll = {
                            type = "integer",
                            default = 500,
                            between = {10, 10000},
                            description = "Maximum objects to fetch per poll"
                        }
                    },
                    {
                        taxii_http_timeout_ms = {
                            type = "integer",
                            default = 2000,
                            between = {1000, 30000},
                            description = "HTTP timeout for TAXII requests in milliseconds"
                        }
                    },
                    {
                        taxii_retry_backoff_ms = {
                            type = "record",
                            default = {
                                initial = 200,
                                max = 5000,
                                factor = 2
                            },
                            fields = {
                                {
                                    initial = {
                                        type = "integer",
                                        default = 200,
                                        between = {100, 5000},
                                        description = "Initial backoff delay in milliseconds"
                                    }
                                },
                                {
                                    max = {
                                        type = "integer",
                                        default = 5000,
                                        between = {1000, 60000},
                                        description = "Maximum backoff delay in milliseconds"
                                    }
                                },
                                {
                                    factor = {
                                        type = "number",
                                        default = 2,
                                        between = {1.1, 10},
                                        description = "Backoff multiplication factor"
                                    }
                                }
                            },
                            description = "Retry backoff configuration"
                        }
                    },
                    {
                        taxii_enable_dedup = {
                            type = "boolean",
                            default = true,
                            description = "Enable deduplication of STIX indicators"
                        }
                    },
                    {
                        taxii_tls_insecure_skip_verify = {
                            type = "boolean",
                            default = false,
                            description = "Skip TLS certificate verification (insecure)"
                        }
                    },
                    {
                        taxii_proxy_url = {
                            type = "string",
                            description = "HTTP proxy URL for TAXII connections"
                        }
                    },
                    {
                        taxii_score_weights = {
                            type = "record",
                            default = {
                                ip_blocklist = 0.9,
                                ip_allowlist = -0.5,
                                domain_blocklist = 0.8,
                                domain_allowlist = -0.4,
                                url_blocklist = 0.8,
                                url_allowlist = -0.4,
                                ja3_blocklist = 0.7,
                                ja3_allowlist = -0.3,
                                ja4_blocklist = 0.7,
                                ja4_allowlist = -0.3,
                                regex_match = 0.6
                            },
                            fields = {
                                {
                                    ip_blocklist = {
                                        type = "number",
                                        default = 0.9,
                                        between = {0, 1},
                                        description = "Score weight for IP blocklist matches"
                                    }
                                },
                                {
                                    ip_allowlist = {
                                        type = "number",
                                        default = -0.5,
                                        between = {-1, 0},
                                        description = "Score weight for IP allowlist matches"
                                    }
                                },
                                {
                                    domain_blocklist = {
                                        type = "number",
                                        default = 0.8,
                                        between = {0, 1},
                                        description = "Score weight for domain blocklist matches"
                                    }
                                },
                                {
                                    domain_allowlist = {
                                        type = "number",
                                        default = -0.4,
                                        between = {-1, 0},
                                        description = "Score weight for domain allowlist matches"
                                    }
                                },
                                {
                                    url_blocklist = {
                                        type = "number",
                                        default = 0.8,
                                        between = {0, 1},
                                        description = "Score weight for URL blocklist matches"
                                    }
                                },
                                {
                                    url_allowlist = {
                                        type = "number",
                                        default = -0.4,
                                        between = {-1, 0},
                                        description = "Score weight for URL allowlist matches"
                                    }
                                },
                                {
                                    ja3_blocklist = {
                                        type = "number",
                                        default = 0.7,
                                        between = {0, 1},
                                        description = "Score weight for JA3 blocklist matches"
                                    }
                                },
                                {
                                    ja3_allowlist = {
                                        type = "number",
                                        default = -0.3,
                                        between = {-1, 0},
                                        description = "Score weight for JA3 allowlist matches"
                                    }
                                },
                                {
                                    ja4_blocklist = {
                                        type = "number",
                                        default = 0.7,
                                        between = {0, 1},
                                        description = "Score weight for JA4 blocklist matches"
                                    }
                                },
                                {
                                    ja4_allowlist = {
                                        type = "number",
                                        default = -0.3,
                                        between = {-1, 0},
                                        description = "Score weight for JA4 allowlist matches"
                                    }
                                },
                                {
                                    regex_match = {
                                        type = "number",
                                        default = 0.6,
                                        between = {0, 1},
                                        description = "Score weight for regex pattern matches"
                                    }
                                }
                            },
                            description = "Scoring weights for TAXII threat intelligence matches"
                        }
                    },

                    -- K8s/Service Mesh Metadata Enricher Configuration
                    {
                        enable_mesh_enricher = {
                            type = "boolean",
                            default = false,
                            description = "Enable Kubernetes/Service Mesh metadata enrichment"
                        }
                    },
                    {
                        mesh_header_map = {
                            type = "record",
                            default = {
                                trace_id = "X-Request-ID",
                                namespace = "X-K8s-Namespace",
                                workload = "X-K8s-Workload",
                                service = "X-K8s-Service",
                                pod = "X-K8s-Pod",
                                zone = "X-K8s-Zone",
                                mesh_source = "X-Mesh-Source"
                            },
                            fields = {
                                {
                                    trace_id = {
                                        type = "string",
                                        default = "X-Request-ID",
                                        description = "Header name for trace/request ID"
                                    }
                                },
                                {
                                    namespace = {
                                        type = "string",
                                        default = "X-K8s-Namespace",
                                        description = "Header name for Kubernetes namespace"
                                    }
                                },
                                {
                                    workload = {
                                        type = "string",
                                        default = "X-K8s-Workload",
                                        description = "Header name for Kubernetes workload"
                                    }
                                },
                                {
                                    service = {
                                        type = "string",
                                        default = "X-K8s-Service",
                                        description = "Header name for Kubernetes service"
                                    }
                                },
                                {
                                    pod = {
                                        type = "string",
                                        default = "X-K8s-Pod",
                                        description = "Header name for Kubernetes pod"
                                    }
                                },
                                {
                                    zone = {
                                        type = "string",
                                        default = "X-K8s-Zone",
                                        description = "Header name for Kubernetes zone/region"
                                    }
                                },
                                {
                                    mesh_source = {
                                        type = "string",
                                        default = "X-Mesh-Source",
                                        description = "Header name for mesh source/caller identity"
                                    }
                                }
                            },
                            description = "Mapping of mesh metadata types to HTTP header names"
                        }
                    },
                    {
                        mesh_cache_ttl_seconds = {
                            type = "integer",
                            default = 300,
                            between = {60, 3600},
                            description = "TTL for mesh metadata cache entries (seconds)"
                        }
                    },
                    {
                        mesh_risky_namespaces = {
                            type = "array",
                            default = {"admin", "kube-system", "istio-system"},
                            elements = {type = "string"},
                            description = "List of high-risk namespaces that trigger alerts"
                        }
                    },
                    {
                        mesh_score_weights = {
                            type = "record",
                            default = {
                                cross_namespace = 0.3,
                                risky_namespace = 0.3,
                                unusual_pair = 0.3,
                                missing_headers = 0.1
                            },
                            fields = {
                                {
                                    cross_namespace = {
                                        type = "number",
                                        default = 0.3,
                                        between = {0, 1},
                                        description = "Score weight for cross-namespace traffic"
                                    }
                                },
                                {
                                    risky_namespace = {
                                        type = "number",
                                        default = 0.3,
                                        between = {0, 1},
                                        description = "Score weight for traffic involving risky namespaces"
                                    }
                                },
                                {
                                    unusual_pair = {
                                        type = "number",
                                        default = 0.3,
                                        between = {0, 1},
                                        description = "Score weight for unusual service communication pairs"
                                    }
                                },
                                {
                                    missing_headers = {
                                        type = "number",
                                        default = 0.1,
                                        between = {0, 1},
                                        description = "Score weight for missing mesh headers (low trust)"
                                    }
                                }
                            },
                            description = "Scoring weights for mesh-based threat detection"
                        }
                    },
                    {
                        mesh_pair_window_seconds = {
                            type = "integer",
                            default = 3600,
                            between = {300, 86400},
                            description = "Time window for tracking service communication pairs (seconds)"
                        }
                    },

                    -- Performance & Scalability Configuration
                    {
                        performance_config = {
                            type = "record",
                            fields = {
                                {
                                    enable_performance_mode = {
                                        type = "boolean",
                                        default = false,
                                        description = "Enable performance optimization mode with reduced feature set"
                                    }
                                },
                                {
                                    memory_optimization = {
                                        type = "boolean",
                                        default = true,
                                        description = "Enable memory optimization features (object pooling, lazy loading)"
                                    }
                                },
                                {
                                    cache_optimization = {
                                        type = "boolean",
                                        default = true,
                                        description = "Enable cache optimization features (LRU, compression)"
                                    }
                                }
                            },
                            description = "Performance optimization configuration settings"
                        }
                    },
                    {
                        scaling_config = {
                            type = "record",
                            fields = {
                                {
                                    enable_horizontal_scaling = {
                                        type = "boolean",
                                        default = false,
                                        description = "Enable horizontal scaling across multiple Kong instances"
                                    }
                                },
                                {
                                    worker_processes = {
                                        type = "integer",
                                        default = 1,
                                        between = {1, 128},
                                        description = "Number of worker processes for load distribution"
                                    }
                                },
                                {
                                    shared_memory_size = {
                                        type = "string",
                                        default = "64m",
                                        description = "Size of shared memory for inter-process communication"
                                    }
                                }
                            },
                            description = "Horizontal scaling configuration settings"
                        }
                    },
                    {
                        benchmarking_config = {
                            type = "record",
                            fields = {
                                {
                                    enable_benchmarks = {
                                        type = "boolean",
                                        default = false,
                                        description = "Enable automatic performance benchmarking"
                                    }
                                },
                                {
                                    benchmark_interval_seconds = {
                                        type = "integer",
                                        default = 300,
                                        between = {60, 3600},
                                        description = "Interval between benchmark runs in seconds"
                                    }
                                },
                                {
                                    performance_thresholds = {
                                        type = "record",
                                        fields = {
                                            {
                                                max_response_time_ms = {
                                                    type = "integer",
                                                    default = 100,
                                                    between = {10, 5000},
                                                    description = "Maximum acceptable response time in milliseconds"
                                                }
                                            },
                                            {
                                                max_memory_usage_mb = {
                                                    type = "integer",
                                                    default = 128,
                                                    between = {32, 2048},
                                                    description = "Maximum acceptable memory usage in MB"
                                                }
                                            },
                                            {
                                                min_throughput_rps = {
                                                    type = "integer",
                                                    default = 1000,
                                                    between = {100, 100000},
                                                    description = "Minimum acceptable throughput in requests per second"
                                                }
                                            }
                                        },
                                        description = "Performance threshold settings for alerting"
                                    }
                                }
                            },
                            description = "Performance benchmarking and monitoring configuration"
                        }
                    },

                    -- SOAR Integration Configuration
                    {
                        enable_soar_integration = {
                            type = "boolean",
                            default = false,
                            description = "Enable SOAR (Security Orchestration, Automation, Response) integration"
                        }
                    },
                    {
                        soar_config = {
                            type = "record",
                            fields = {
                                {
                                    siem_endpoint = {
                                        type = "string",
                                        description = "SIEM platform endpoint URL for event forwarding"
                                    }
                                },
                                {
                                    soar_endpoint = {
                                        type = "string",
                                        description = "SOAR platform endpoint URL for incident creation"
                                    }
                                },
                                {
                                    api_key = {
                                        type = "string",
                                        description = "API key for SOAR/SIEM authentication"
                                    }
                                },
                                {
                                    timeout_ms = {
                                        type = "integer",
                                        default = 5000,
                                        between = {1000, 30000},
                                        description = "Timeout for SOAR/SIEM API calls in milliseconds"
                                    }
                                }
                            },
                            description = "SOAR platform configuration settings"
                        }
                    },

                    -- Incident Response Configuration
                    {
                        incident_response = {
                            type = "record",
                            fields = {
                                {
                                    enable_auto_response = {
                                        type = "boolean",
                                        default = false,
                                        description = "Enable automatic incident response workflows"
                                    }
                                },
                                {
                                    response_workflows = {
                                        type = "array",
                                        default = {},
                                        elements = {
                                            type = "record",
                                            fields = {
                                                {
                                                    trigger_condition = {
                                                        type = "string",
                                                        required = true,
                                                        description = "Condition that triggers this workflow (e.g., 'threat_score > 0.8')"
                                                    }
                                                },
                                                {
                                                    actions = {
                                                        type = "array",
                                                        default = {},
                                                        elements = {type = "string"},
                                                        description = "List of actions to execute (e.g., 'block_ip', 'rate_limit', 'notify')"
                                                    }
                                                },
                                                {
                                                    severity_threshold = {
                                                        type = "number",
                                                        default = 0.7,
                                                        between = {0, 1},
                                                        description = "Severity threshold for triggering this workflow"
                                                    }
                                                }
                                            }
                                        },
                                        description = "Automated incident response workflows"
                                    }
                                }
                            },
                            description = "Incident response automation settings"
                        }
                    },

                    -- Threat Hunting Configuration
                    {
                        threat_hunting = {
                            type = "record",
                            fields = {
                                {
                                    enable_hunting = {
                                        type = "boolean",
                                        default = false,
                                        description = "Enable threat hunting capabilities"
                                    }
                                },
                                {
                                    hunting_queries = {
                                        type = "array",
                                        default = {},
                                        elements = {type = "string"},
                                        description = "List of threat hunting queries to execute"
                                    }
                                },
                                {
                                    data_retention_days = {
                                        type = "integer",
                                        default = 30,
                                        between = {1, 365},
                                        description = "Number of days to retain threat hunting data"
                                    }
                                }
                            },
                            description = "Threat hunting configuration settings"
                        }
                    },

                     -- Forensic Collection Configuration
                     {
                         forensic_collection = {
                             type = "record",
                             fields = {
                                 {
                                     enable_forensics = {
                                         type = "boolean",
                                         default = false,
                                         description = "Enable forensic data collection"
                                     }
                                 },
                                 {
                                     collection_triggers = {
                                         type = "array",
                                         default = {},
                                         elements = {type = "string"},
                                         description = "Conditions that trigger forensic collection (e.g., 'threat_score > 0.9')"
                                     }
                                 },
                                 {
                                     storage_backend = {
                                         type = "string",
                                         default = "local",
                                         one_of = {"local", "s3", "gcs"},
                                         description = "Storage backend for forensic data"
                                     }
                                 }
                             },
                             description = "Forensic data collection settings"
                         }
                     },

                     -- Compliance & Audit Configuration
                     {
                         compliance_config = {
                             type = "record",
                             fields = {
                                 {
                                     enable_gdpr_compliance = {
                                         type = "boolean",
                                         default = false,
                                         description = "Enable GDPR compliance features and data protection"
                                     }
                                 },
                                 {
                                     enable_audit_logging = {
                                         type = "boolean",
                                         default = true,
                                         description = "Enable comprehensive audit logging for security events"
                                     }
                                 },
                                 {
                                     enable_data_retention = {
                                         type = "boolean",
                                         default = true,
                                         description = "Enable automated data retention and cleanup policies"
                                     }
                                 }
                             },
                             description = "Core compliance and audit configuration settings"
                         }
                     },

                     -- Privacy Configuration
                     {
                         privacy_config = {
                             type = "record",
                             fields = {
                                 {
                                     data_anonymization = {
                                         type = "boolean",
                                         default = true,
                                         description = "Enable automatic data anonymization for privacy protection"
                                     }
                                 },
                                 {
                                     pii_detection = {
                                         type = "boolean",
                                         default = true,
                                         description = "Enable personally identifiable information (PII) detection"
                                     }
                                 },
                                 {
                                     consent_tracking = {
                                         type = "boolean",
                                         default = false,
                                         description = "Enable user consent tracking for data processing"
                                     }
                                 },
                                 {
                                     pii_detection_rules = {
                                         type = "array",
                                         default = {"email", "phone", "credit_card", "ssn", "ip_address"},
                                         elements = {
                                             type = "string",
                                             one_of = {"email", "phone", "credit_card", "ssn", "ip_address", "name", "address"}
                                         },
                                         description = "Types of PII to detect and protect"
                                     }
                                 },
                                 {
                                     anonymization_level = {
                                         type = "string",
                                         default = "standard",
                                         one_of = {"minimal", "standard", "aggressive"},
                                         description = "Level of data anonymization (minimal=mask, standard=hash, aggressive=remove)"
                                     }
                                 }
                             },
                             description = "Privacy protection and PII handling configuration"
                         }
                     },

                     -- Audit Configuration
                     {
                         audit_config = {
                             type = "record",
                             fields = {
                                 {
                                     audit_log_level = {
                                         type = "string",
                                         default = "standard",
                                         one_of = {"minimal", "standard", "detailed"},
                                         description = "Level of detail for audit logging (minimal=security only, standard=all events, detailed=full context)"
                                     }
                                 },
                                 {
                                     audit_retention_days = {
                                         type = "integer",
                                         default = 90,
                                         between = {30, 2555}, -- 7 years max
                                         description = "Number of days to retain audit logs"
                                     }
                                 },
                                 {
                                     audit_encryption = {
                                         type = "boolean",
                                         default = true,
                                         description = "Enable encryption for audit logs at rest"
                                     }
                                 },
                                 {
                                     audit_events = {
                                         type = "array",
                                         default = {"security_events", "config_changes", "access_events", "data_processing"},
                                         elements = {
                                             type = "string",
                                             one_of = {"security_events", "config_changes", "access_events", "data_processing", "privacy_events", "consent_events"}
                                         },
                                         description = "Types of events to audit"
                                     }
                                 },
                                 {
                                     audit_storage_backend = {
                                         type = "string",
                                         default = "local",
                                         one_of = {"local", "database", "elasticsearch", "splunk"},
                                         description = "Storage backend for audit logs"
                                     }
                                 }
                             },
                             description = "Audit logging and retention configuration"
                         }
                     },

                     -- Data Retention Policies Configuration
                     {
                         retention_policies = {
                             type = "record",
                             fields = {
                                 {
                                     threat_data_retention_days = {
                                         type = "integer",
                                         default = 30,
                                         between = {7, 365},
                                         description = "Number of days to retain threat detection data"
                                     }
                                 },
                                 {
                                     user_data_retention_days = {
                                         type = "integer",
                                         default = 90,
                                         between = {30, 2555}, -- 7 years max
                                         description = "Number of days to retain user-related data"
                                     }
                                 },
                                 {
                                     log_retention_days = {
                                         type = "integer",
                                         default = 365,
                                         between = {90, 2555}, -- 7 years max
                                         description = "Number of days to retain general log data"
                                     }
                                 },
                                 {
                                     audit_retention_days = {
                                         type = "integer",
                                         default = 2555, -- 7 years
                                         between = {365, 2555},
                                         description = "Number of days to retain audit logs (regulatory requirement)"
                                     }
                                 },
                                 {
                                     cleanup_schedule = {
                                         type = "string",
                                         default = "daily",
                                         one_of = {"hourly", "daily", "weekly", "monthly"},
                                         description = "Frequency of automated data cleanup"
                                     }
                                 },
                                 {
                                     secure_deletion = {
                                         type = "boolean",
                                         default = true,
                                         description = "Use secure deletion methods for sensitive data"
                                     }
                                 }
                             },
                             description = "Data retention and cleanup policy configuration"
                         }
                     },

                      -- Regulatory Compliance Configuration
                      {
                          regulatory_config = {
                              type = "record",
                              fields = {
                                  {
                                      gdpr_compliance = {
                                          type = "boolean",
                                          default = false,
                                          description = "Enable GDPR compliance features"
                                      }
                                  },
                                  {
                                      ccpa_compliance = {
                                          type = "boolean",
                                          default = false,
                                          description = "Enable CCPA compliance features"
                                      }
                                  },
                                  {
                                      soc2_compliance = {
                                          type = "boolean",
                                          default = false,
                                          description = "Enable SOC 2 compliance controls"
                                      }
                                  },
                                  {
                                      data_residency = {
                                          type = "string",
                                          default = "us",
                                          one_of = {"us", "eu", "uk", "ca", "au", "jp", "global"},
                                          description = "Data residency region for compliance"
                                      }
                                  },
                                  {
                                      breach_notification_enabled = {
                                          type = "boolean",
                                          default = true,
                                          description = "Enable automated breach notification"
                                      }
                                  },
                                  {
                                      breach_notification_emails = {
                                          type = "array",
                                          default = {},
                                          elements = {type = "string"},
                                          description = "Email addresses for breach notifications"
                                      }
                                  }
                              },
                              description = "Regulatory compliance framework configuration"
                          }
                      },

                      -- Data Governance Configuration
                      {
                          enable_data_governance = {
                              type = "boolean",
                              default = false,
                              description = "Enable data governance features"
                          }
                      },
                      {
                          data_governance = {
                              type = "record",
                              fields = {
                                  {
                                      enable_classification = {
                                          type = "boolean",
                                          default = true,
                                          description = "Enable automatic data classification"
                                      }
                                  },
                                  {
                                      enable_lineage_tracking = {
                                          type = "boolean",
                                          default = true,
                                          description = "Enable data lineage tracking"
                                      }
                                  },
                                  {
                                      enable_quality_monitoring = {
                                          type = "boolean",
                                          default = true,
                                          description = "Enable data quality monitoring"
                                      }
                                  },
                                  {
                                      enable_catalog_integration = {
                                          type = "boolean",
                                          default = false,
                                          description = "Enable data catalog integration"
                                      }
                                  },
                                  {
                                      catalog_system = {
                                          type = "string",
                                          default = "generic_rest",
                                          one_of = {"alation", "collibra", "datahub", "amundsen", "generic_rest"},
                                          description = "Data catalog system to integrate with"
                                      }
                                  },
                                  {
                                      catalog_endpoint = {
                                          type = "string",
                                          description = "Data catalog API endpoint URL"
                                      }
                                  },
                                  {
                                      catalog_api_key = {
                                          type = "string",
                                          description = "API key for data catalog authentication"
                                      }
                                  },
                                  {
                                      catalog_sync_interval = {
                                          type = "integer",
                                          default = 3600,
                                          between = {300, 86400},
                                          description = "Interval for catalog metadata sync (seconds)"
                                      }
                                  },
                                  {
                                      enable_ml_classification = {
                                          type = "boolean",
                                          default = false,
                                          description = "Enable machine learning-based data classification"
                                      }
                                  },
                                  {
                                      ml_model_endpoint = {
                                          type = "string",
                                          description = "Machine learning model endpoint for classification"
                                      }
                                  },
                                  {
                                      lineage_retention_days = {
                                          type = "integer",
                                          default = 90,
                                          between = {30, 365},
                                          description = "Number of days to retain data lineage information"
                                      }
                                  },
                                  {
                                      quality_monitoring_window = {
                                          type = "integer",
                                          default = 3600,
                                          between = {300, 86400},
                                          description = "Time window for quality monitoring (seconds)"
                                      }
                                  },
                                  {
                                      enable_anomaly_detection = {
                                          type = "boolean",
                                          default = false,
                                          description = "Enable anomaly detection in data quality monitoring"
                                      }
                                  }
                               },
                               description = "Data governance and catalog integration configuration"
                           }
                       },

                       -- Security Controls Configuration
                       {
                           enable_security_controls = {
                               type = "boolean",
                               default = false,
                               description = "Enable enterprise security controls (access management, encryption, monitoring)"
                           }
                       },
                       {
                           security_controls = {
                               type = "record",
                               fields = {
                                   {
                                       enable_access_management = {
                                           type = "boolean",
                                           default = true,
                                           description = "Enable role-based access control and authentication"
                                       }
                                   },
                                   {
                                       enable_encryption = {
                                           type = "boolean",
                                           default = false,
                                           description = "Enable field-level encryption for sensitive data"
                                       }
                                   },
                                   {
                                       enable_monitoring = {
                                           type = "boolean",
                                           default = true,
                                           description = "Enable security monitoring and alerting"
                                       }
                                   },
                                   {
                                       require_authentication = {
                                           type = "boolean",
                                           default = false,
                                           description = "Require authentication for all API requests"
                                       }
                                   },
                                   {
                                       access_config = {
                                           type = "record",
                                           fields = {
                                               {
                                                   enable_rbac = {
                                                       type = "boolean",
                                                       default = true,
                                                       description = "Enable role-based access control"
                                                   }
                                               },
                                               {
                                                   enable_abac = {
                                                       type = "boolean",
                                                       default = false,
                                                       description = "Enable attribute-based access control"
                                                   }
                                               },
                                               {
                                                   session_timeout = {
                                                       type = "integer",
                                                       default = 3600,
                                                       between = {300, 86400},
                                                       description = "Session timeout in seconds"
                                                   }
                                               },
                                               {
                                                   max_login_attempts = {
                                                       type = "integer",
                                                       default = 5,
                                                       between = {3, 20},
                                                       description = "Maximum login attempts before account lockout"
                                                   }
                                               },
                                               {
                                                   lockout_duration = {
                                                       type = "integer",
                                                       default = 900,
                                                       between = {300, 3600},
                                                       description = "Account lockout duration in seconds"
                                                   }
                                               }
                                           },
                                           description = "Access control configuration settings"
                                       }
                                   },
                                   {
                                       encryption_config = {
                                           type = "record",
                                           fields = {
                                               {
                                                   encryption_algorithm = {
                                                       type = "string",
                                                       default = "aes-256-gcm",
                                                       one_of = {"aes-256-gcm", "aes-256-cbc", "chacha20-poly1305"},
                                                       description = "Encryption algorithm for data protection"
                                                   }
                                               },
                                               {
                                                   key_rotation_enabled = {
                                                       type = "boolean",
                                                       default = true,
                                                       description = "Enable automatic key rotation"
                                                   }
                                               },
                                               {
                                                   key_rotation_interval_days = {
                                                       type = "integer",
                                                       default = 30,
                                                       between = {7, 365},
                                                       description = "Key rotation interval in days"
                                                   }
                                               },
                                               {
                                                   enable_fips_compliance = {
                                                       type = "boolean",
                                                       default = false,
                                                       description = "Enable FIPS 140-2 compliance mode"
                                                   }
                                               },
                                               {
                                                   sensitive_fields = {
                                                       type = "array",
                                                       default = {"password", "credit_card", "ssn", "api_key"},
                                                       elements = {type = "string"},
                                                       description = "List of sensitive field names to encrypt"
                                                   }
                                               }
                                           },
                                           description = "Encryption configuration settings"
                                       }
                                   },
                                   {
                                       monitoring_config = {
                                           type = "record",
                                           fields = {
                                               {
                                                   enable_anomaly_detection = {
                                                       type = "boolean",
                                                       default = true,
                                                       description = "Enable anomaly detection in security monitoring"
                                                   }
                                               },
                                               {
                                                   enable_automated_response = {
                                                       type = "boolean",
                                                       default = false,
                                                       description = "Enable automated incident response"
                                                   }
                                               },
                                               {
                                                   alert_threshold = {
                                                       type = "number",
                                                       default = 0.7,
                                                       between = {0, 1},
                                                       description = "Threat score threshold for alerts"
                                                   }
                                               },
                                               {
                                                   monitoring_window_seconds = {
                                                       type = "integer",
                                                       default = 300,
                                                       between = {60, 3600},
                                                       description = "Monitoring time window in seconds"
                                                   }
                                               },
                                               {
                                                   alert_cooldown_period = {
                                                       type = "integer",
                                                       default = 300,
                                                       between = {60, 1800},
                                                       description = "Cooldown period between similar alerts"
                                                   }
                                               },
                                               {
                                                   max_alerts_per_window = {
                                                       type = "integer",
                                                       default = 100,
                                                       between = {10, 1000},
                                                       description = "Maximum alerts per monitoring window"
                                                   }
                                               },
                                               {
                                                   notification_channels = {
                                                       type = "array",
                                                       default = {},
                                                       elements = {
                                                           type = "record",
                                                           fields = {
                                                               {
                                                                   type = {
                                                                       type = "string",
                                                                       default = "email",
                                                                       one_of = {"email", "slack", "webhook"},
                                                                       description = "Notification channel type"
                                                                   }
                                                               },
                                                               {
                                                                   enabled = {
                                                                       type = "boolean",
                                                                       default = true,
                                                                       description = "Enable this notification channel"
                                                                   }
                                                               },
                                                               {
                                                                   recipient = {
                                                                       type = "string",
                                                                       description = "Email address or Slack channel for notifications"
                                                                   }
                                                               },
                                                               {
                                                                   url = {
                                                                       type = "string",
                                                                       description = "Webhook URL for notifications"
                                                                   }
                                                               }
                                                           }
                                                       },
                                                       description = "Notification channels for security alerts"
                                                   }
                                               }
                                           },
                                           description = "Security monitoring and alerting configuration"
                                       }
                                   }
                               },
                               description = "Enterprise security controls configuration"
                           }
                       }
                  }
              }
          }
      }
  }

