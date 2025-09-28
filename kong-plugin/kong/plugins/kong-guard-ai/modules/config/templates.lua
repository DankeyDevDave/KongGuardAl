-- Configuration Templates
-- Environment-specific configuration templates for Kong Guard AI
-- Provides optimized defaults for different deployment scenarios

local Templates = {}

--- Development environment template
-- Optimized for rapid development and debugging
function Templates.development()
    return {
        name = "Development Environment",
        description = "Optimized for local development with debug features",
        config = {
            -- AI Detection Settings
            ai_enabled = true,
            ai_timeout = 10.0,
            ai_batch_size = 5,
            ai_confidence_threshold = 0.3,

            -- Threat Detection
            threat_detection_enabled = true,
            sql_injection_enabled = true,
            xss_detection_enabled = true,
            path_traversal_enabled = true,

            -- Performance (relaxed for development)
            cache_ttl = 300,
            rate_limit = 1000,
            max_concurrent_requests = 50,

            -- Monitoring (verbose for debugging)
            logging_level = "debug",
            metrics_enabled = true,
            audit_logging = true,

            -- Security (development-friendly)
            require_auth = false,
            cors_enabled = true,
            cors_origins = {"*"},

            -- Development-specific features
            debug_mode = true,
            hot_reload = true,
            test_mode = true
        }
    }
end

--- Production environment template
-- Optimized for production deployment with security focus
function Templates.production()
    return {
        name = "Production Environment",
        description = "Production-ready configuration with enhanced security",
        config = {
            -- AI Detection Settings
            ai_enabled = true,
            ai_timeout = 5.0,
            ai_batch_size = 10,
            ai_confidence_threshold = 0.7,

            -- Threat Detection (comprehensive)
            threat_detection_enabled = true,
            sql_injection_enabled = true,
            xss_detection_enabled = true,
            path_traversal_enabled = true,
            ddos_protection = true,

            -- Performance (optimized)
            cache_ttl = 3600,
            rate_limit = 10000,
            max_concurrent_requests = 500,
            connection_pooling = true,

            -- Monitoring (production-appropriate)
            logging_level = "info",
            metrics_enabled = true,
            audit_logging = true,
            health_checks = true,

            -- Security (hardened)
            require_auth = true,
            cors_enabled = false,
            security_headers = true,
            request_validation = true,

            -- Production-specific features
            debug_mode = false,
            hot_reload = false,
            test_mode = false,
            backup_enabled = true
        }
    }
end

--- Staging environment template
-- Balanced configuration for pre-production testing
function Templates.staging()
    return {
        name = "Staging Environment",
        description = "Pre-production testing with production-like settings",
        config = {
            -- AI Detection Settings
            ai_enabled = true,
            ai_timeout = 7.0,
            ai_batch_size = 8,
            ai_confidence_threshold = 0.5,

            -- Threat Detection
            threat_detection_enabled = true,
            sql_injection_enabled = true,
            xss_detection_enabled = true,
            path_traversal_enabled = true,

            -- Performance (moderate)
            cache_ttl = 1800,
            rate_limit = 5000,
            max_concurrent_requests = 200,

            -- Monitoring (detailed for testing)
            logging_level = "info",
            metrics_enabled = true,
            audit_logging = true,
            performance_monitoring = true,

            -- Security (production-like but flexible)
            require_auth = true,
            cors_enabled = true,
            cors_origins = {"*.staging.domain.com"},
            security_headers = true,

            -- Staging-specific features
            debug_mode = false,
            hot_reload = false,
            test_mode = false
        }
    }
end

--- High-volume environment template
-- Optimized for high-traffic production environments
function Templates.high_volume()
    return {
        name = "High Volume Environment",
        description = "Optimized for high-traffic production with performance focus",
        config = {
            -- AI Detection Settings (optimized for speed)
            ai_enabled = true,
            ai_timeout = 3.0,
            ai_batch_size = 20,
            ai_confidence_threshold = 0.8,
            ai_queue_enabled = true,

            -- Threat Detection (efficient)
            threat_detection_enabled = true,
            sql_injection_enabled = true,
            xss_detection_enabled = true,
            path_traversal_enabled = true,
            ddos_protection = true,

            -- Performance (maximized)
            cache_ttl = 7200,
            rate_limit = 50000,
            max_concurrent_requests = 2000,
            connection_pooling = true,
            compression_enabled = true,

            -- Monitoring (essential only)
            logging_level = "warn",
            metrics_enabled = true,
            audit_logging = false,
            sampling_rate = 0.1,

            -- Security (balanced with performance)
            require_auth = true,
            cors_enabled = false,
            security_headers = true,
            fast_validation = true,

            -- High-volume specific features
            debug_mode = false,
            hot_reload = false,
            test_mode = false,
            auto_scaling = true
        }
    }
end

--- Compliance-focused environment template
-- Optimized for strict compliance requirements (GDPR, HIPAA, etc.)
function Templates.compliance()
    return {
        name = "Compliance Environment",
        description = "Strict compliance configuration with enhanced audit trails",
        config = {
            -- AI Detection Settings
            ai_enabled = true,
            ai_timeout = 10.0,
            ai_batch_size = 5,
            ai_confidence_threshold = 0.9,
            ai_audit_trail = true,

            -- Threat Detection (comprehensive)
            threat_detection_enabled = true,
            sql_injection_enabled = true,
            xss_detection_enabled = true,
            path_traversal_enabled = true,
            data_leakage_detection = true,

            -- Performance (security over speed)
            cache_ttl = 1800,
            rate_limit = 1000,
            max_concurrent_requests = 100,

            -- Monitoring (comprehensive)
            logging_level = "debug",
            metrics_enabled = true,
            audit_logging = true,
            compliance_reporting = true,
            data_retention_days = 2555, -- 7 years

            -- Security (maximum)
            require_auth = true,
            cors_enabled = false,
            security_headers = true,
            request_validation = true,
            data_encryption = true,

            -- Compliance-specific features
            debug_mode = false,
            hot_reload = false,
            test_mode = false,
            gdpr_compliance = true,
            hipaa_compliance = true,
            audit_trail = true
        }
    }
end

--- Get template by environment name
-- @param environment string environment name
-- @return table template configuration or nil
function Templates.get_template(environment)
    local templates = {
        development = Templates.development,
        dev = Templates.development,
        production = Templates.production,
        prod = Templates.production,
        staging = Templates.staging,
        stage = Templates.staging,
        high_volume = Templates.high_volume,
        performance = Templates.high_volume,
        compliance = Templates.compliance,
        secure = Templates.compliance
    }

    local template_func = templates[environment]
    if template_func then
        return template_func()
    end

    return nil
end

--- Get all available templates
-- @return table list of all available templates
function Templates.get_all_templates()
    return {
        Templates.development(),
        Templates.production(),
        Templates.staging(),
        Templates.high_volume(),
        Templates.compliance()
    }
end

--- Validate template configuration
-- @param template table template to validate
-- @return boolean valid
-- @return table validation errors if any
function Templates.validate_template(template)
    local errors = {}

    -- Check required fields
    if not template.name then
        table.insert(errors, "Template missing required field: name")
    end

    if not template.description then
        table.insert(errors, "Template missing required field: description")
    end

    if not template.config then
        table.insert(errors, "Template missing required field: config")
    elseif type(template.config) ~= "table" then
        table.insert(errors, "Template config must be a table")
    end

    -- Validate config structure
    if template.config then
        local required_config_fields = {
            "ai_enabled",
            "threat_detection_enabled",
            "logging_level",
            "metrics_enabled"
        }

        for _, field in ipairs(required_config_fields) do
            if template.config[field] == nil then
                table.insert(errors, "Template config missing required field: " .. field)
            end
        end
    end

    return #errors == 0, errors
end

return Templates
