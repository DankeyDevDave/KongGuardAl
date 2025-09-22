-- Performance and Rate Limiting Configuration Schema
-- Extracted from schema.lua for better modularity and maintainability

local _M = {}

--- Get performance and rate limiting configuration schema fields
-- @return table configuration schema fields for performance
function _M.get_fields()
    return {
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
                        burst_detection_threshold = {
                            type = "integer",
                            default = 200,
                            between = {10, 10000},
                            description = "Request burst threshold for DDoS detection"
                        }
                    },
                    {
                        burst_time_window = {
                            type = "integer",
                            default = 60,
                            between = {10, 600},
                            description = "Time window for burst detection (seconds)"
                        }
                    },
                    {
                        challenge_mode = {
                            type = "string",
                            default = "captcha",
                            one_of = {"captcha", "js_challenge", "rate_limit", "block"},
                            description = "Challenge mode for suspected DDoS"
                        }
                    },
                    {
                        mitigation_duration = {
                            type = "integer",
                            default = 300,
                            between = {60, 3600},
                            description = "Duration of DDoS mitigation (seconds)"
                        }
                    }
                }
            }
        },
        -- Circuit Breaker Configuration
        {
            enable_circuit_breaker = {
                type = "boolean",
                default = false,
                description = "Enable circuit breaker for external services"
            }
        },
        {
            circuit_breaker = {
                type = "record",
                fields = {
                    {
                        failure_threshold = {
                            type = "integer",
                            default = 5,
                            between = {1, 100},
                            description = "Number of failures before opening circuit"
                        }
                    },
                    {
                        success_threshold = {
                            type = "integer",
                            default = 3,
                            between = {1, 20},
                            description = "Number of successes to close circuit"
                        }
                    },
                    {
                        timeout = {
                            type = "integer",
                            default = 30,
                            between = {5, 300},
                            description = "Circuit breaker timeout (seconds)"
                        }
                    },
                    {
                        half_open_max_calls = {
                            type = "integer",
                            default = 3,
                            between = {1, 10},
                            description = "Max calls in half-open state"
                        }
                    }
                }
            }
        },
        -- Cache Configuration
        {
            enable_request_caching = {
                type = "boolean",
                default = true,
                description = "Enable request result caching"
            }
        },
        {
            cache_config = {
                type = "record",
                fields = {
                    {
                        threat_detection_ttl = {
                            type = "integer",
                            default = 300,
                            between = {30, 3600},
                            description = "Threat detection cache TTL (seconds)"
                        }
                    },
                    {
                        ai_response_ttl = {
                            type = "integer",
                            default = 600,
                            between = {60, 7200},
                            description = "AI response cache TTL (seconds)"
                        }
                    },
                    {
                        max_cache_size_mb = {
                            type = "integer",
                            default = 64,
                            between = {16, 512},
                            description = "Maximum cache size (MB)"
                        }
                    },
                    {
                        cache_cleanup_interval = {
                            type = "integer",
                            default = 300,
                            between = {60, 1800},
                            description = "Cache cleanup interval (seconds)"
                        }
                    }
                }
            }
        },
        -- Memory Management
        {
            memory_management = {
                type = "record",
                fields = {
                    {
                        max_memory_usage_mb = {
                            type = "integer",
                            default = 256,
                            between = {64, 2048},
                            description = "Maximum memory usage (MB)"
                        }
                    },
                    {
                        gc_step_multiplier = {
                            type = "number",
                            default = 200,
                            between = {100, 500},
                            description = "Lua garbage collection step multiplier"
                        }
                    },
                    {
                        gc_pause = {
                            type = "integer",
                            default = 200,
                            between = {100, 500},
                            description = "Lua garbage collection pause percentage"
                        }
                    }
                }
            }
        },
        -- Connection Pooling
        {
            connection_pooling = {
                type = "record",
                fields = {
                    {
                        pool_size = {
                            type = "integer",
                            default = 10,
                            between = {1, 100},
                            description = "Connection pool size for external services"
                        }
                    },
                    {
                        max_idle_timeout = {
                            type = "integer",
                            default = 60,
                            between = {10, 300},
                            description = "Maximum idle connection timeout (seconds)"
                        }
                    },
                    {
                        keepalive_requests = {
                            type = "integer",
                            default = 100,
                            between = {10, 1000},
                            description = "Number of requests per keepalive connection"
                        }
                    }
                }
            }
        }
    }
end

--- Get performance defaults
-- @return table default configuration values
function _M.get_defaults()
    return {
        enable_adaptive_rate_limiting = false,
        adaptive_rate_config = {
            base_rate_per_minute = 60,
            threat_score_multiplier = 2.0,
            min_rate_per_minute = 5,
            max_rate_per_minute = 1000
        },
        enable_ddos_mitigation = false,
        ddos_protection = {
            burst_detection_threshold = 200,
            burst_time_window = 60,
            challenge_mode = "captcha",
            mitigation_duration = 300
        },
        enable_circuit_breaker = false,
        circuit_breaker = {
            failure_threshold = 5,
            success_threshold = 3,
            timeout = 30,
            half_open_max_calls = 3
        },
        enable_request_caching = true,
        cache_config = {
            threat_detection_ttl = 300,
            ai_response_ttl = 600,
            max_cache_size_mb = 64,
            cache_cleanup_interval = 300
        },
        memory_management = {
            max_memory_usage_mb = 256,
            gc_step_multiplier = 200,
            gc_pause = 200
        },
        connection_pooling = {
            pool_size = 10,
            max_idle_timeout = 60,
            keepalive_requests = 100
        }
    }
end

--- Validate performance configuration
-- @param config table configuration to validate
-- @return boolean true if valid
-- @return string error message if invalid
function _M.validate_config(config)
    if not config then
        return false, "Configuration is required"
    end
    
    -- Validate adaptive rate limiting config
    if config.adaptive_rate_config then
        local arc = config.adaptive_rate_config
        if arc.min_rate_per_minute and arc.max_rate_per_minute then
            if arc.min_rate_per_minute >= arc.max_rate_per_minute then
                return false, "min_rate_per_minute must be less than max_rate_per_minute"
            end
        end
        
        if arc.base_rate_per_minute and arc.min_rate_per_minute and arc.max_rate_per_minute then
            if arc.base_rate_per_minute < arc.min_rate_per_minute or arc.base_rate_per_minute > arc.max_rate_per_minute then
                return false, "base_rate_per_minute must be between min_rate_per_minute and max_rate_per_minute"
            end
        end
    end
    
    -- Validate DDoS protection config
    if config.ddos_protection then
        local ddos = config.ddos_protection
        if ddos.burst_time_window and ddos.mitigation_duration then
            if ddos.burst_time_window >= ddos.mitigation_duration then
                return false, "burst_time_window must be less than mitigation_duration"
            end
        end
    end
    
    -- Validate circuit breaker config
    if config.circuit_breaker then
        local cb = config.circuit_breaker
        if cb.failure_threshold and cb.success_threshold then
            if cb.success_threshold > cb.failure_threshold then
                return false, "success_threshold must be less than or equal to failure_threshold"
            end
        end
    end
    
    -- Validate cache config
    if config.cache_config then
        local cache = config.cache_config
        if cache.max_cache_size_mb and cache.max_cache_size_mb < 16 then
            return false, "max_cache_size_mb must be at least 16 MB"
        end
    end
    
    return true
end

return _M