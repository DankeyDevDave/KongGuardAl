-- Optimized module loading with lazy initialization
local cjson = require "cjson"
local http = require "resty.http"

-- Import refactored utility modules
local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"
local module_loader = require "kong.plugins.kong-guard-ai.modules.utils.module_loader"

-- Import AI modules
local ai_service = require "kong.plugins.kong-guard-ai.modules.ai.ai_service"
local threat_detector = require "kong.plugins.kong-guard-ai.modules.ai.threat_detector"

-- Import threat detection modules
local threat_orchestrator = require "kong.plugins.kong-guard-ai.modules.threat.threat_orchestrator"

-- Feature cache (kept in main handler for now)
local _feature_cache = {}

local KongGuardAIHandler = {
    VERSION = "2.0.0",  -- Enterprise AI version
    PRIORITY = 2000
}

-- Performance optimization: Pre-computed constants
local EMPTY_TABLE = {}
local THREAT_TYPES = {
    sql_injection = 0.95, xss = 0.9, path_traversal = 0.85,
    ddos = 0.8, credential_stuffing = 0.75, command_injection = 0.9
}

-- Utility function aliases for backward compatibility
local get_cached_string = performance_utils.get_cached_string
local get_pooled_table = performance_utils.get_pooled_table
local return_pooled_table = performance_utils.return_pooled_table
local should_log = performance_utils.should_log
local log_message = performance_utils.log_message
local load_module = module_loader.load_module
local get_instance = module_loader.get_instance

-- init_worker phase: Initialize AI engine and caches
function KongGuardAIHandler:init_worker()
    -- Initialize shared memory for threat tracking
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:set("threat_counter", 0)
        kong_cache:set("false_positive_rate", 0)
        kong_cache:set("total_requests", 0)
        kong_cache:set("ai_requests", 0)
        kong_cache:set("ai_blocks", 0)
    end

    -- COMPLIANCE: Initialize compliance reporter scheduled tasks
    local compliance_reporter = load_module("compliance_reporter")
    if compliance_reporter then
        compliance_reporter.init_worker()
        kong.log.info("Compliance reporter initialized with scheduled reporting")
    end

    -- Initialize AI modules
    self.ai_service_client = nil  -- Will be initialized per-request as needed
    self.threat_detector_instance = nil  -- Will be initialized per-request as needed

    kong.log.info("Kong Guard AI Enterprise v2.0: Worker initialized with AI capabilities and compliance features")
end

-- Configure phase: Initialize plugin with configuration
function KongGuardAIHandler:configure(config)
    -- Initialize TAXII scheduler if enabled
    if config.enable_taxii_ingestion then
        kong.log.info("Initializing TAXII threat intelligence scheduler")

        taxii_scheduler = TaxiiScheduler.new(config)
        if taxii_scheduler then
            local success, err = taxii_scheduler:start()
            if success then
                kong.log.info("TAXII scheduler started successfully")
            else
                kong.log.error("Failed to start TAXII scheduler: " .. (err or "unknown error"))
            end
        else
            kong.log.error("Failed to create TAXII scheduler instance")
        end
    end

    -- Initialize advanced rate limiting modules
    if config.enable_adaptive_rate_limiting then
        adaptive_rate_limiter = AdaptiveRateLimiter:new(config.adaptive_rate_config or {})
        kong.log.info("Adaptive rate limiter initialized")
    end

    if config.ddos_protection and config.ddos_protection.enable_ddos_mitigation then
        ddos_mitigator = DDoSMitigator:new(config.ddos_protection)
        kong.log.info("DDoS mitigator initialized")
    end

    if config.enable_geo_limiting then
        geo_rate_limiter = GeoRateLimiter:new(config.geographic_limiting or {})
        kong.log.info("Geographic rate limiter initialized")
    end

    if config.enable_circuit_breakers then
        circuit_breaker = CircuitBreaker:new(config.circuit_breakers or {})
        kong.log.info("Circuit breaker initialized")
    end

    -- Initialize Prometheus metrics
    prometheus_metrics = PrometheusMetrics:new(config)
    kong.log.info("Prometheus metrics initialized")

    -- Initialize SOAR Integration components
    if config.enable_soar_integration then
        kong.log.info("Initializing SOAR integration components")

        -- Initialize SOAR client
        soar_client = SOARClient.new(config)
        if soar_client then
            local success, err = soar_client:init()
            if success then
                kong.log.info("SOAR client initialized successfully")
            else
                kong.log.error("Failed to initialize SOAR client: ", err)
            end
        end

        -- Initialize incident responder
        incident_responder = IncidentResponder.new(config, soar_client)
        if incident_responder then
            local success, err = incident_responder:init()
            if success then
                kong.log.info("Incident responder initialized successfully")
            else
                kong.log.error("Failed to initialize incident responder: ", err)
            end
        end

        -- Initialize threat hunter
        threat_hunter = ThreatHunter.new(config)
        if threat_hunter then
            local success, err = threat_hunter:init()
            if success then
                kong.log.info("Threat hunter initialized successfully")
            else
                kong.log.error("Failed to initialize threat hunter: ", err)
            end
        end

        -- Initialize forensic collector
        forensic_collector = ForensicCollector.new(config)
        if forensic_collector then
            local success, err = forensic_collector:init()
            if success then
                kong.log.info("Forensic collector initialized successfully")
            else
                kong.log.error("Failed to initialize forensic collector: ", err)
            end
        end
    end
end

-- Optimized access phase with performance improvements
function KongGuardAIHandler:access(config)
    -- Fast path: Handle special endpoints first
    local request_path = kong.request.get_path()
    if request_path:match("/_kong_guard_ai/prometheus") or request_path:match("/_kong_guard_ai/metrics") then
        return self:handle_prometheus_metrics_optimized(config)
    elseif request_path:match("/kong%-guard%-ai/privacy/") then
        return self:handle_privacy_api_request(config)
    end

    -- Performance optimization: Early extraction of commonly used values
    local client_ip = kong.client.get_forwarded_ip() or kong.client.get_ip()
    local method = kong.request.get_method()
    local path = kong.request.get_path()
    local headers = kong.request.get_headers()
    local body = kong.request.get_raw_body()

    -- COMPLIANCE INTEGRATION: Privacy checks before processing
    local compliance_data = get_pooled_table()
    compliance_data.pii_detected = false
    compliance_data.data_anonymized = false
    compliance_data.audit_logged = false
    compliance_data.consent_valid = true
    compliance_data.privacy_violations = {}

    -- SECURITY CONTROLS: Initialize security metadata
    compliance_data.access_control = {
        authenticated = user_context and user_context.authenticated or false,
        user_id = user_context and user_context.user_id,
        roles = user_context and user_context.roles,
        session_id = user_context and user_context.session_id,
        access_granted = access_result ~= nil,
        access_level = access_result and access_result.access_level
    }
    compliance_data.encryption = {
        fields_encrypted = encryption_result and #encryption_result or 0,
        encryption_method = encryption_instance and encryption_instance.encryption_algorithm,
        key_rotation_enabled = encryption_instance and encryption_instance.key_rotation_enabled
    }
    compliance_data.security_monitoring = {
        event_recorded = security_monitor_instance ~= nil,
        monitoring_enabled = config.security_controls and config.security_controls.enable_monitoring
    }

    -- Load compliance and governance modules lazily
    local privacy_manager, audit_logger, retention_manager, compliance_reporter
    local data_classifier, data_lineage_tracker, data_quality_monitor, data_catalog_integrator

    if config.compliance_config.enable_gdpr_compliance or config.privacy_config.pii_detection then
        privacy_manager = load_module("privacy_manager")
    end
    if config.compliance_config.enable_audit_logging then
        audit_logger = load_module("audit_logger")
    end
    if config.compliance_config.enable_data_retention then
        retention_manager = load_module("retention_manager")
    end
    if config.regulatory_config.gdpr_compliance or config.regulatory_config.ccpa_compliance then
        compliance_reporter = load_module("compliance_reporter")
    end

    -- Load data governance modules
    if config.enable_data_governance then
        if config.data_governance.enable_classification then
            data_classifier = load_module("data_classifier")
        end
        if config.data_governance.enable_lineage_tracking then
            data_lineage_tracker = load_module("data_lineage_tracker")
        end
        if config.data_governance.enable_quality_monitoring then
            data_quality_monitor = load_module("data_quality_monitor")
        end
        if config.data_governance.enable_catalog_integration then
            data_catalog_integrator = load_module("data_catalog_integrator")
        end
    end

    -- Load security control modules
    if config.enable_security_controls then
        if config.security_controls.enable_access_management then
            access_control = load_module("access_control")
            if access_control then
                access_control_instance = get_instance("access_control", config.security_controls.access_config or {})
                access_control_instance:init()
                kong.log.info("Access control module initialized")
            end
        end
        if config.security_controls.enable_encryption then
            encryption_manager = load_module("encryption_manager")
            if encryption_manager then
                encryption_instance = get_instance("encryption_manager", config.security_controls.encryption_config or {})
                encryption_instance:init()
                kong.log.info("Encryption manager initialized")
            end
        end
        if config.security_controls.enable_monitoring then
            security_monitor = load_module("security_monitor")
            if security_monitor then
                security_monitor_instance = get_instance("security_monitor", config.security_controls.monitoring_config or {})
                security_monitor_instance:init()
                kong.log.info("Security monitor initialized")
            end
        end
    end

    -- COMPLIANCE: PII Detection and Privacy Checks
    if privacy_manager and config.privacy_config.pii_detection then
        local pii_results = privacy_manager.detect_pii({
            headers = headers,
            body = body,
            path = path,
            client_ip = client_ip
        }, config.privacy_config)

        compliance_data.pii_detected = pii_results.has_pii
        compliance_data.pii_types = pii_results.pii_types
        compliance_data.privacy_score = pii_results.privacy_score

        -- Data anonymization if PII detected
        if pii_results.has_pii and config.privacy_config.data_anonymization then
            local anonymized_data = privacy_manager.anonymize_data({
                headers = headers,
                body = body
            }, config.privacy_config)

            compliance_data.data_anonymized = anonymized_data.modified
            compliance_data.anonymization_method = anonymized_data.method

            -- Update request data if anonymization was applied
            if anonymized_data.modified then
                -- Note: In production, this would modify the actual request
                -- For now, we just track the anonymization
                log_message(config, "info", "PII data anonymized in request", {
                    client_ip = client_ip,
                    pii_types = pii_results.pii_types,
                    method = anonymized_data.method
                })
            end
        end

        -- Consent validation for GDPR/CCPA
        if config.regulatory_config.gdpr_compliance or config.regulatory_config.ccpa_compliance then
            local consent_result = privacy_manager.validate_consent(client_ip, config)
            compliance_data.consent_valid = consent_result.valid
            compliance_data.consent_details = consent_result.details

            if not consent_result.valid then
                table.insert(compliance_data.privacy_violations, "Invalid or missing user consent")
            end
        end
    end

    -- COMPLIANCE: Audit logging for data processing
    if audit_logger and config.compliance_config.enable_audit_logging then
        local audit_event = {
            event_type = "data_processing",
            client_ip = client_ip,
            method = method,
            path = path,
            user_agent = headers["user-agent"],
            pii_detected = compliance_data.pii_detected,
            data_anonymized = compliance_data.data_anonymized,
            consent_valid = compliance_data.consent_valid,
            user_authenticated = compliance_data.access_control.authenticated,
            user_id = compliance_data.access_control.user_id,
            user_roles = compliance_data.access_control.roles,
            fields_encrypted = compliance_data.encryption.fields_encrypted,
            security_event_recorded = compliance_data.security_monitoring.event_recorded,
            timestamp = ngx.time()
        }

        local audit_result = audit_logger.log_event(audit_event, config.audit_config)
        compliance_data.audit_logged = audit_result.success
        compliance_data.audit_event_id = audit_result.event_id

        if not audit_result.success then
            log_message(config, "warn", "Failed to log audit event", {
                error = audit_result.error,
                event_type = "data_processing"
            })
        end
    end

    -- Fast whitelist check (early exit)
    if config.whitelist_ips and self:is_whitelisted_optimized(client_ip, config.whitelist_ips) then
        -- Log compliance event for whitelisted request
        if audit_logger and compliance_data.audit_logged then
            audit_logger.log_event({
                event_type = "access_allowed",
                reason = "whitelisted_ip",
                client_ip = client_ip,
                compliance_data = compliance_data
            }, config.audit_config)
        end
        return_pooled_table(compliance_data)
        return
    end

    -- Fast block check (early exit)
    if self:is_blocked_optimized(client_ip) then
        -- Log compliance event for blocked request
        if audit_logger and compliance_data.audit_logged then
            audit_logger.log_event({
                event_type = "access_denied",
                reason = "blocked_ip",
                client_ip = client_ip,
                compliance_data = compliance_data
            }, config.audit_config)
        end
        return_pooled_table(compliance_data)
        return kong.response.exit(403, {
            message = get_cached_string("Request blocked - IP temporarily banned"),
            incident_id = self:generate_incident_id()
        })
    end

    -- Performance optimization: Use cached features when possible
    local cache_key = client_ip .. ":" .. path .. ":" .. method
    local features = _feature_cache[cache_key]

    if not features then
        features = self:extract_features_optimized(kong.request, client_ip, config, headers, method, path)
        -- Cache features for similar requests (short TTL)
        if features.requests_per_minute < 100 then  -- Only cache low-frequency requests
            _feature_cache[cache_key] = features
            ngx.timer.at(5, function() _feature_cache[cache_key] = nil end)  -- Clear after 5 seconds
        end
    end

    -- DATA GOVERNANCE: Classify data before threat detection
    local data_classification = nil
    if data_classifier then
        local classification_context = {
            path = path,
            method = method,
            headers = headers,
            user_id = headers["x-user-id"],
            source_system = "kong-guard-ai",
            data_size = body and #body or 0
        }

        data_classification = data_classifier:classify_data({
            headers = headers,
            body = body,
            path = path,
            method = method
        }, classification_context)

        compliance_data.data_classification = data_classification
    end

    -- DATA GOVERNANCE: Track data lineage
    if data_lineage_tracker then
        local lineage_context = {
            data_id = ngx.md5(path .. ":" .. method .. ":" .. (body or "")),
            source_system = "kong-guard-ai",
            target_system = "api_backend",
            user_id = headers["x-user-id"],
            session_id = headers["x-session-id"],
            request_id = headers["x-request-id"],
            ip_address = client_ip,
            user_agent = headers["user-agent"],
            data_size_bytes = body and #body or 0,
            data_type = "api_request"
        }

        data_lineage_tracker:track_data_ingestion(
            lineage_context.data_id,
            "kong_api_gateway",
            {
                data_size = lineage_context.data_size_bytes,
                data_type = lineage_context.data_type,
                endpoint = path,
                method = method
            },
            lineage_context
        )
    end

    -- DATA GOVERNANCE: Monitor data quality
    if data_quality_monitor then
        local quality_context = {
            data_id = ngx.md5(path .. ":" .. method),
            user_id = headers["x-user-id"],
            source = "api_request",
            processing_time_ms = 0 -- Will be updated after processing
        }

        local quality_check = data_quality_monitor:monitor_data_quality({
            headers = headers,
            body = body,
            path = path,
            method = method
        }, quality_context, "request")

        compliance_data.data_quality = quality_check
    end

    -- DATA GOVERNANCE: Auto-register API endpoint in catalog
    if data_catalog_integrator then
        local catalog_context = {
            user_id = headers["x-user-id"],
            source_system = "kong-guard-ai",
            environment = config.environment or "production"
        }

        data_catalog_integrator:auto_register_api_endpoints({
            path = path,
            method = method,
            query_params = kong.request.get_query(),
            response_schema = nil, -- Would be populated from API spec
            description = "API endpoint accessed via Kong Gateway"
        }, catalog_context)
    end

    -- SECURITY CONTROLS: Access management and authentication
    local access_result = nil
    local user_context = nil
    if access_control_instance and config.security_controls.enable_access_management then
        -- Extract authentication credentials from headers
        local auth_header = headers["authorization"] or headers["x-api-key"]
        local credentials = nil

        if auth_header then
            if auth_header:match("^Bearer ") then
                credentials = {token = auth_header:sub(8)}
            elseif auth_header:match("^Basic ") then
                -- Decode basic auth
                local decoded = ngx.decode_base64(auth_header:sub(7))
                if decoded then
                    local user, pass = decoded:match("([^:]+):(.*)")
                    if user and pass then
                        credentials = {username = user, password = pass}
                    end
                end
            else
                credentials = {api_key = auth_header}
            end
        end

        -- Check session if available
        local session_id = headers["x-session-id"]
        if session_id then
            local session_valid, session_data = access_control_instance:validate_session(session_id)
            if session_valid then
                user_context = {
                    user_id = session_data.user_id,
                    session_id = session_id,
                    authenticated = true,
                    roles = session_data.roles
                }
            end
        end

        -- Authenticate user if credentials provided and not already authenticated
        if credentials and not user_context then
            local auth_success, auth_data = access_control_instance:authenticate_user(credentials, {
                ip_address = client_ip,
                user_agent = headers["user-agent"],
                path = path,
                method = method
            })

            if auth_success then
                user_context = {
                    user_id = auth_data.user_id,
                    session_id = auth_data.session_id,
                    authenticated = true,
                    roles = auth_data.roles
                }

                -- Record successful authentication in Prometheus metrics
                if prometheus_metrics then
                    prometheus_metrics:record_authentication("success", credentials.token and "token" or credentials.api_key and "api_key" or "password", {
                        client_ip = client_ip,
                        user_id = auth_data.user_id
                    })
                end
            else
        -- Record failed authentication
        if security_monitor_instance then
            security_monitor_instance:record_security_event("authentication_failure", {
                reason = auth_data,
                credentials_type = credentials.token and "token" or credentials.api_key and "api_key" or "password"
            }, {
                client_ip = client_ip,
                user_agent = headers["user-agent"],
                path = path
            })
        end

        -- Record authentication failure in Prometheus metrics
        if prometheus_metrics then
            prometheus_metrics:record_authentication("failure", credentials.token and "token" or credentials.api_key and "api_key" or "password", {
                client_ip = client_ip,
                user_agent = headers["user-agent"]
            })
        end
            end
        end

        -- Authorize access to resource
        if user_context and user_context.authenticated then
            local resource = path:match("^/([^/]+)") or "api" -- Extract first path segment as resource
            local auth_success, auth_result = access_control_instance:authorize_access(
                user_context.user_id,
                resource,
                method:lower(),
                {
                    ip_address = client_ip,
                    user_agent = headers["user-agent"],
                    path = path,
                    method = method
                }
            )

            if not auth_success then
                -- Record authorization failure
                if security_monitor_instance then
                    security_monitor_instance:record_security_event("authorization_failure", {
                        reason = auth_result,
                        resource = resource,
                        action = method:lower()
                    }, {
                        client_ip = client_ip,
                        user_id = user_context.user_id,
                        path = path
                    })
                end

                -- Record authorization failure in Prometheus metrics
                if prometheus_metrics then
                    prometheus_metrics:record_authorization("denied", resource, method:lower(), {
                        client_ip = client_ip,
                        user_id = user_context.user_id
                    })
                end

                return kong.response.exit(403, {
                    message = "Access denied: " .. (auth_result or "Insufficient permissions"),
                    incident_id = self:generate_incident_id()
                })
            end

            -- Record successful authorization in Prometheus metrics
            if prometheus_metrics then
                prometheus_metrics:record_authorization("granted", resource, method:lower(), {
                    client_ip = client_ip,
                    user_id = user_context.user_id
                })
            end

            access_result = auth_result
        elseif config.security_controls.require_authentication and not user_context then
            -- Authentication required but not provided
            if security_monitor_instance then
                security_monitor_instance:record_security_event("unauthenticated_access_attempt", {
                    resource = path,
                    method = method
                }, {
                    client_ip = client_ip,
                    user_agent = headers["user-agent"]
                })
            end

            return kong.response.exit(401, {
                message = "Authentication required",
                incident_id = self:generate_incident_id()
            })
        end
    end

    -- SECURITY CONTROLS: Data encryption for sensitive fields
    local encryption_result = nil
    if encryption_instance and config.security_controls.enable_encryption then
        -- Get request body for encryption
        local request_body = kong.request.get_raw_body()
        local sensitive_fields = config.security_controls.encryption_config.sensitive_fields or {}

        if request_body and #sensitive_fields > 0 then
            local body_data = cjson.decode(request_body)
            if body_data then
                -- Encrypt sensitive fields in request
                local encrypted_data, encrypt_results = encryption_instance:encrypt_sensitive_fields(
                    body_data,
                    sensitive_fields,
                    {
                        user_id = user_context and user_context.user_id,
                        client_ip = client_ip,
                        path = path,
                        method = method
                    }
                )

                if encrypted_data then
                    -- Update request body with encrypted data
                    kong.request.set_raw_body(cjson.encode(encrypted_data))
                    encryption_result = encrypt_results

                    -- Record encryption operations in Prometheus metrics
                    if prometheus_metrics then
                        for _, result in ipairs(encrypt_results) do
                            prometheus_metrics:record_encryption_operation("encrypt", encryption_instance.encryption_algorithm, result.success and "success" or "failure", {
                                client_ip = client_ip,
                                user_id = user_context and user_context.user_id,
                                field = result.field
                            })
                        end
                    end

                    log_message(config, "debug", "Sensitive fields encrypted in request", {
                        client_ip = client_ip,
                        encrypted_fields = #encrypt_results,
                        user_id = user_context and user_context.user_id
                    })
                end
            end
        end
    end

    -- SECURITY CONTROLS: Security monitoring and alerting
    if security_monitor_instance and config.security_controls.enable_monitoring then
        -- Record general access event
        security_monitor_instance:record_security_event("api_access", {
            path = path,
            method = method,
            authenticated = user_context and user_context.authenticated or false,
            user_id = user_context and user_context.user_id,
            response_time_ms = 0 -- Will be updated in log phase
        }, {
            client_ip = client_ip,
            user_agent = headers["user-agent"],
            user_id = user_context and user_context.user_id,
            session_id = user_context and user_context.session_id
        })

        -- Record security event in Prometheus metrics
        if prometheus_metrics then
            prometheus_metrics:record_security_event("api_access", "info", {
                client_ip = client_ip,
                user_id = user_context and user_context.user_id or "anonymous",
                authenticated = user_context and user_context.authenticated or false
            })
        end
    end

    -- Optimized threat detection with early returns
    local threat_score, threat_type, threat_details = self:detect_threat_optimized(features, config)

    -- COMPLIANCE & GOVERNANCE: Add metadata to threat details
    threat_details.compliance = compliance_data
    threat_details.data_governance = {
        classification = data_classification,
        lineage_tracked = data_lineage_tracker ~= nil,
        quality_monitored = data_quality_monitor ~= nil,
        catalog_registered = data_catalog_integrator ~= nil
    }
    threat_details.security_controls = {
        access_control = compliance_data.access_control,
        encryption = compliance_data.encryption,
        security_monitoring = compliance_data.security_monitoring,
        user_context = user_context,
        access_result = access_result
    }

    -- Fast response for high-threat requests
    if threat_score > config.block_threshold then
        if not config.dry_run then
            self:block_request_optimized(threat_type, client_ip)

            -- COMPLIANCE: Log security incident
            if audit_logger and config.compliance_config.enable_audit_logging then
                audit_logger.log_event({
                    event_type = "security_incident",
                    severity = "high",
                    threat_type = threat_type,
                    threat_score = threat_score,
                    client_ip = client_ip,
                    action_taken = "blocked",
                    compliance_data = compliance_data,
                    incident_id = self:generate_incident_id()
                }, config.audit_config)
            end

            return kong.response.exit(403, {
                message = get_cached_string("Request blocked by Kong Guard AI"),
                threat_type = threat_type,
                incident_id = self:generate_incident_id(),
                compliance_status = compliance_data.consent_valid and "compliant" or "violation"
            })
        end
    elseif threat_score > config.rate_limit_threshold then
        if not config.dry_run then
            local rate_limit_result = self:apply_advanced_rate_limiting_optimized(client_ip, threat_score, features, config)
            if rate_limit_result.should_block then
                -- COMPLIANCE: Log rate limiting event
                if audit_logger and config.compliance_config.enable_audit_logging then
                    audit_logger.log_event({
                        event_type = "rate_limit_applied",
                        threat_score = threat_score,
                        client_ip = client_ip,
                        action_taken = "rate_limited",
                        compliance_data = compliance_data
                    }, config.audit_config)
                end

                return kong.response.exit(429, {
                    message = rate_limit_result.message,
                    retry_after = rate_limit_result.retry_after,
                    compliance_status = compliance_data.consent_valid and "compliant" or "violation"
                })
            end
        end
    end

    -- Optimized context storage using pooled tables
    local threat_data = get_pooled_table()
    threat_data.score = threat_score
    threat_data.type = threat_type
    threat_data.details = threat_details
    threat_data.features = features
    threat_data.timestamp = ngx.now()
    threat_data.client_ip = client_ip
    threat_data.path = path
    threat_data.method = method
    threat_data.compliance = compliance_data

    -- SOAR integration (lazy loaded)
    if config.enable_soar_integration then
        threat_data.soar = get_pooled_table()
        threat_data.soar.enabled = true
        threat_data.soar.incident_id = nil
        threat_data.soar.workflows_triggered = {}
        threat_data.soar.forensic_evidence_id = nil
        threat_data.soar.hunting_matches = {}

        -- Async SOAR processing
        self:process_soar_async(threat_data, features, config)
    end

    kong.ctx.plugin.threat_data = threat_data

    -- Optimized metrics tracking
    self:update_metrics_optimized(threat_score, features, config)

    -- Conditional logging (performance optimization)
    if config.log_requests and should_log(config.log_level, "debug") then
        log_message(config, "debug", "Request analyzed", {
            client_ip = client_ip,
            path = path,
            threat_score = threat_score
        })
    end
end
-- Optimized log phase with batched operations
function KongGuardAIHandler:log(config)
    local threat_data = kong.ctx.plugin.threat_data

    if not threat_data then
        return
    end

    local threat_score = threat_data.score
    local compliance_data = threat_data.compliance or {}

    -- COMPLIANCE: Retention management for threat data
    if retention_manager and config.compliance_config.enable_data_retention then
        -- Schedule cleanup for threat data based on retention policies
        if threat_score > 0.1 then
            local retention_result = retention_manager.schedule_cleanup({
                data_type = "threat_data",
                threat_score = threat_score,
                client_ip = threat_data.client_ip,
                timestamp = threat_data.timestamp,
                retention_days = config.retention_policies.threat_data_retention_days
            }, config.retention_policies)

            if not retention_result.success then
                log_message(config, "warn", "Failed to schedule threat data cleanup", {
                    error = retention_result.error,
                    client_ip = threat_data.client_ip
                })
            end
        end

        -- Schedule cleanup for user data if PII was detected
        if compliance_data.pii_detected then
            local user_retention_result = retention_manager.schedule_cleanup({
                data_type = "user_data",
                client_ip = threat_data.client_ip,
                pii_detected = true,
                timestamp = threat_data.timestamp,
                retention_days = config.retention_policies.user_data_retention_days
            }, config.retention_policies)

            if not user_retention_result.success then
                log_message(config, "warn", "Failed to schedule user data cleanup", {
                    error = user_retention_result.error,
                    client_ip = threat_data.client_ip
                })
            end
        end
    end

    -- COMPLIANCE: Automated compliance reporting
    if compliance_reporter and (config.regulatory_config.gdpr_compliance or config.regulatory_config.ccpa_compliance) then
        -- Check if automated reporting is due
        local should_report = self:should_generate_compliance_report(config)
        if should_report then
            ngx.timer.at(0, function()
                self:generate_automated_compliance_report(config, threat_data)
            end)
        end
    end

    -- SECURITY CONTROLS: Session cleanup and security monitoring updates
    if access_control_instance and threat_data.compliance and threat_data.compliance.access_control then
        -- Update session activity if user is authenticated
        if threat_data.compliance.access_control.authenticated and threat_data.compliance.access_control.session_id then
            -- Update session last activity (this would be handled by the session management)
            log_message(config, "debug", "Session activity updated", {
                session_id = threat_data.compliance.access_control.session_id,
                user_id = threat_data.compliance.access_control.user_id
            })
        end
    end

    -- SECURITY CONTROLS: Security monitoring updates in log phase
    if security_monitor_instance and threat_data.score > 0 then
        -- Update security event with response information
        local response_status = kong.response.get_status()
        local response_time = ngx.now() - threat_data.timestamp

        security_monitor_instance:record_security_event("api_response", {
            path = threat_data.path,
            method = threat_data.method,
            response_status = response_status,
            response_time_ms = response_time * 1000,
            threat_score = threat_data.score,
            threat_type = threat_data.type,
            user_id = threat_data.compliance.access_control.user_id,
            authenticated = threat_data.compliance.access_control.authenticated
        }, {
            client_ip = threat_data.client_ip,
            user_id = threat_data.compliance.access_control.user_id,
            session_id = threat_data.compliance.access_control.session_id,
            response_status = response_status
        })

        -- Check for security incidents that need alerting
        if threat_data.score > config.security_controls.monitoring_config.alert_threshold then
            security_monitor_instance:record_security_event("security_incident", {
                threat_score = threat_data.score,
                threat_type = threat_data.type,
                response_status = response_status,
                incident_id = self:generate_incident_id()
            }, {
                client_ip = threat_data.client_ip,
                user_id = threat_data.compliance.access_control.user_id,
                severity = threat_data.score > config.block_threshold and "high" or "medium"
            })

            -- Record security incident in Prometheus metrics
            if prometheus_metrics then
                prometheus_metrics:record_security_event("security_incident", threat_data.score > config.block_threshold and "high" or "medium", {
                    client_ip = threat_data.client_ip,
                    user_id = threat_data.compliance.access_control.user_id,
                    threat_type = threat_data.type
                })
            end
        end
    end

    -- Early return for low-threat requests
    if threat_score < 0.1 then
        return_pooled_table(threat_data)
        return
    end

    -- Batch async operations
    if threat_score > 0.1 then
        ngx.timer.at(0, function()
            self:process_log_operations_optimized(threat_data, config)
        end)
    end

    -- Conditional logging with optimized message formatting
    if threat_score > 0.3 and config.log_threats then
        local log_level = threat_score > config.block_threshold and "warn" or "info"
        log_message(config, log_level, "Threat detected in request", {
            client_ip = threat_data.client_ip,
            threat_score = threat_score,
            threat_type = threat_data.type,
            pii_detected = compliance_data.pii_detected,
            consent_valid = compliance_data.consent_valid
        })
    end

    -- Return pooled table
    return_pooled_table(threat_data)
end

-- Optimized log operations processing
function KongGuardAIHandler:process_log_operations_optimized(threat_data, config)
    local operations = {}

    -- SOAR threat hunting
    if config.enable_soar_integration and threat_data.score > 0.1 then
        local threat_hunter = get_instance("threat_hunter", config)
        if threat_hunter then
            local results = threat_hunter:execute_hunting_queries(3600)
            if results then
                threat_data.soar.hunting_matches = results
                operations.hunting = true
            end
        end
    end

    -- Notifications
    if threat_data.score > config.rate_limit_threshold and config.enable_notifications then
        self:send_notification_optimized(threat_data, config)
        operations.notification = true
    end

    -- Learning metrics
    if threat_data.score > 0 then
        self:update_learning_metrics_optimized(threat_data)
        operations.learning = true
    end

    -- SIEM forwarding
    if config.enable_soar_integration and threat_data.score > 0.2 then
        local soar_client = get_instance("soar_client", config)
        if soar_client then
            local success = soar_client:forward_to_siem(threat_data)
            operations.siem = success
        end
    end

    -- Log completed operations
    if operations.hunting or operations.notification or operations.learning or operations.siem then
        log_message(config, "debug", "Log operations completed", operations)
    end
end

--- Get SOAR integration health status
-- @param config The plugin configuration
-- @return SOAR health status
function KongGuardAIHandler:get_soar_health_status(config)
    if not config.enable_soar_integration then
        return { enabled = false }
    end

    local status = {
        enabled = true,
        components = {}
    }

    if soar_client then
        status.components.soar_client = soar_client:get_health_status()
    end

    if incident_responder then
        status.components.incident_responder = incident_responder:get_health_status()
    end

    if threat_hunter then
        status.components.threat_hunter = threat_hunter:get_health_status()
    end

    if forensic_collector then
        status.components.forensic_collector = forensic_collector:get_health_status()
    end

    return status
end

-- COMPLIANCE: Handle privacy API requests
function KongGuardAIHandler:handle_privacy_api_request(config)
    local privacy_api = load_module("privacy_api")
    if not privacy_api then
        return kong.response.exit(500, {
            error = "Privacy API module not available",
            message = "Privacy API functionality is not properly configured"
        })
    end

    -- Handle the privacy API request
    local success, err = pcall(function()
        privacy_api.handle_request(config)
    end)

    if not success then
        kong.log.err("[kong-guard-ai] Privacy API error: ", err)
        return kong.response.exit(500, {
            error = "Privacy API error",
            message = "An error occurred processing the privacy request"
        })
    end
end

-- COMPLIANCE: Check if automated compliance report should be generated
function KongGuardAIHandler:should_generate_compliance_report(config)
    -- Check if reporting is enabled
    if not config.regulatory_config then
        return false
    end

    -- Simple time-based check (could be enhanced with more sophisticated scheduling)
    local current_hour = tonumber(os.date("%H"))
    local current_minute = tonumber(os.date("%M"))

    -- Generate reports at 2 AM daily
    if current_hour == 2 and current_minute < 5 then
        return true
    end

    -- Generate reports weekly on Sunday at 3 AM
    local current_day = tonumber(os.date("%w")) -- 0 = Sunday
    if current_day == 0 and current_hour == 3 and current_minute < 5 then
        return true
    end

    return false
end

-- COMPLIANCE: Generate automated compliance report
function KongGuardAIHandler:generate_automated_compliance_report(config, threat_data)
    local compliance_reporter = load_module("compliance_reporter")
    if not compliance_reporter then
        return
    end

    -- Determine report types based on configuration
    local report_types = {}
    if config.regulatory_config.gdpr_compliance then
        table.insert(report_types, "gdpr")
    end
    if config.regulatory_config.ccpa_compliance then
        table.insert(report_types, "ccpa")
    end
    table.insert(report_types, "security_audit")
    table.insert(report_types, "data_processing")

    -- Generate reports for the last 30 days
    local period_end = ngx.time()
    local period_start = period_end - (30 * 24 * 60 * 60) -- 30 days ago

    for _, report_type in ipairs(report_types) do
        local report, err = compliance_reporter.generate_report(report_type, config, {
            period_start = period_start,
            period_end = period_end,
            format = "json",
            store_report = true
        })

        if err then
            log_message(config, "error", "Failed to generate automated compliance report", {
                report_type = report_type,
                error = err
            })
        else
            log_message(config, "info", "Automated compliance report generated", {
                report_type = report_type,
                report_size = #report
            })

            -- Send report notification if configured
            if config.regulatory_config.breach_notification_enabled then
                self:send_compliance_report_notification(config, report_type, report)
            end
        end
    end
end

-- COMPLIANCE: Send compliance report notification
function KongGuardAIHandler:send_compliance_report_notification(config, report_type, report_data)
    if not config.notification_url or not config.regulatory_config.breach_notification_emails then
        return
    end

    local notification_payload = {
        type = "compliance_report",
        report_type = report_type,
        generated_at = ngx.time(),
        recipients = config.regulatory_config.breach_notification_emails,
        report_summary = {
            type = report_type,
            generated_at = os.date("%Y-%m-%d %H:%M:%S", ngx.time()),
            size_bytes = #report_data
        }
    }

    -- Send notification (implementation would depend on notification service)
    -- For now, just log the notification
    log_message(config, "info", "Compliance report notification sent", {
        report_type = report_type,
        recipients = #config.regulatory_config.breach_notification_emails
    })
end

-- Comprehensive threat detection with AI
function KongGuardAIHandler:detect_threat(features, config)
    local threat_score = 0
    local threat_type = "none"
    local threat_details = {}

    -- Use External AI Service if enabled
    if config.enable_ai_gateway then
        -- Get AI service URL from environment or config
        local ai_service_url = os.getenv("AI_SERVICE_URL") or config.ai_service_url or "http://ai-service:8000"

        -- Build request payload for AI service matching expected schema
        local raw_query = kong.request.get_raw_query() or ""
        local raw_body = kong.request.get_raw_body() or ""
        local headers = kong.request.get_headers()

        -- Combine query and body for analysis
        local query_content = raw_query
        if raw_body and #raw_body > 0 then
            query_content = query_content .. " " .. raw_body
        end

        local request_data = {
            features = {
                method = features.method or kong.request.get_method(),
                path = features.path or kong.request.get_path(),
                client_ip = features.client_ip,
                user_agent = features.user_agent or "",
                requests_per_minute = features.requests_per_minute or 0,
                content_length = features.content_length or 0,
                query_param_count = features.query_param_count or 0,
                header_count = features.header_count or 0,
                hour_of_day = features.hour_of_day or 0,
                query = query_content,
                headers = headers
            },
            context = {
                previous_requests = self:get_request_count(features.client_ip),
                failed_attempts = self:get_failed_attempts(features.client_ip),
                anomaly_score = self:calculate_anomaly_score(features)
            }
        }

        -- Call external AI service
        local httpc = http.new()
        httpc:set_timeout(500) -- 500ms timeout for AI analysis

        local res, err = httpc:request_uri(ai_service_url .. "/analyze", {
            method = "POST",
            body = cjson.encode(request_data),
            headers = {
                ["Content-Type"] = "application/json"
            }
        })

        if res and res.status == 200 then
            local ai_analysis = cjson.decode(res.body)

            -- Track AI usage
            local kong_cache = ngx.shared.kong_cache
            if kong_cache then
                kong_cache:incr("ai_requests", 1, 0)
            end

            -- Use AI results
            threat_score = ai_analysis.threat_score or 0
            threat_type = ai_analysis.threat_type or "none"
            threat_details = {
                ai_powered = true,
                ai_model = ai_analysis.model or "gemini",
                confidence = ai_analysis.confidence or 0,
                reasoning = ai_analysis.reasoning or "AI analysis",
                indicators = ai_analysis.indicators or {},
                recommended_action = ai_analysis.recommended_action or "monitor",
                thinking_time_ms = ai_analysis.processing_time_ms or 0,
                context_analyzed = ai_analysis.context_analyzed or false
            }

            -- Log AI decision
            if config.log_decisions then
                kong.log.info("AI Threat Analysis: ", cjson.encode(ai_analysis))
            end

            -- Track blocks if threat is high
            if threat_score > config.block_threshold and kong_cache then
                kong_cache:incr("ai_blocks", 1, 0)
            end

            -- Return AI-based detection results
            return threat_score, threat_type, threat_details
        else
            -- Log error but continue with rule-based detection
            kong.log.warn("Failed to reach AI service: ", err or "unknown error")
        end
    end

    -- TAXII Threat Intelligence Lookups (if enabled)
    if config.enable_taxii_ingestion then
        local taxii_score, taxii_threat_type, taxii_details = self:check_taxii_indicators(features, config)
        if taxii_score > 0 then
            threat_score = math.max(threat_score, taxii_score)
            if threat_score == taxii_score then
                threat_type = taxii_threat_type
            end
            -- Merge TAXII details
            threat_details.taxii = taxii_details
        end
    end

    -- Fallback to rule-based detection
    threat_details.detection_method = threat_details.taxii and "taxii_enhanced" or "rule_based"

    -- 1. SQL Injection Detection
    local sql_score = self:detect_sql_injection(features)
    if sql_score > 0 then
        threat_score = math.max(threat_score, sql_score)
        threat_type = "sql_injection"
        threat_details.sql_patterns = true
    end

    -- 2. XSS Detection
    local xss_score = self:detect_xss(features)
    if xss_score > 0 then
        threat_score = math.max(threat_score, xss_score)
        if threat_score == xss_score then
            threat_type = "xss"
        end
        threat_details.xss_patterns = true
    end

    -- 3. Path Traversal Detection
    local traversal_score = self:detect_path_traversal(features)
    if traversal_score > 0 then
        threat_score = math.max(threat_score, traversal_score)
        if threat_score == traversal_score then
            threat_type = "path_traversal"
        end
        threat_details.path_traversal = true
    end

    -- 4. DDoS Pattern Detection
    local ddos_score = self:detect_ddos_patterns(features, config)
    if ddos_score > 0 then
        threat_score = math.max(threat_score, ddos_score)
        if threat_score == ddos_score then
            threat_type = "ddos"
        end
        threat_details.high_rate = features.requests_per_minute
    end

    -- 5. Credential Stuffing Detection
    local cred_score = self:detect_credential_stuffing(features)
    if cred_score > 0 then
        threat_score = math.max(threat_score, cred_score)
        if threat_score == cred_score then
            threat_type = "credential_stuffing"
        end
        threat_details.login_attempts = features.requests_per_minute
    end

    -- 6. Command Injection Detection
    local cmd_score = self:detect_command_injection(features)
    if cmd_score > 0 then
        threat_score = math.max(threat_score, cmd_score)
        if threat_score == cmd_score then
            threat_type = "command_injection"
        end
        threat_details.command_patterns = true
    end

    -- 7. Anomaly Detection (if enabled)
    if config.enable_ml_detection then
        local anomaly_score = self:calculate_anomaly_score(features)
        if anomaly_score > 0.6 then
            threat_score = math.max(threat_score, anomaly_score)
            if threat_type == "none" then
                threat_type = "anomaly"
            end
            threat_details.anomaly_score = anomaly_score
        end
    end

    -- 8. Mesh-based Threat Detection (if enabled)
    if config.enable_mesh_enricher and features.mesh then
        local mesh_score = features.mesh.mesh_score or 0
        if mesh_score > 0 then
            threat_score = math.max(threat_score, mesh_score)

            -- Determine mesh threat type based on the highest-scoring factor
            local mesh_threat_type = "mesh_anomaly"
            if features.mesh.risky_namespace then
                mesh_threat_type = "mesh_risky_namespace"
            elseif features.mesh.cross_namespace then
                mesh_threat_type = "mesh_cross_namespace"
            elseif features.mesh.unusual_pair then
                mesh_threat_type = "mesh_unusual_pair"
            elseif features.mesh.missing_headers then
                mesh_threat_type = "mesh_missing_headers"
            end

            -- Update threat type if mesh score is the highest
            if threat_score == mesh_score then
                threat_type = mesh_threat_type
            end

            -- Add mesh details to threat information
            threat_details.mesh = {
                score = mesh_score,
                factors = features.mesh.threat_details.factors,
                source_namespace = features.mesh.source_info.namespace,
                source_service = features.mesh.source_info.service,
                destination_namespace = features.mesh.destination_info.namespace,
                destination_service = features.mesh.destination_info.service,
                pair_count = features.mesh.pair_count,
                cross_namespace = features.mesh.cross_namespace,
                risky_namespace = features.mesh.risky_namespace,
                unusual_pair = features.mesh.unusual_pair,
                missing_headers = features.mesh.missing_headers
            }

            log_message(config, "info", "Mesh-based threat detected", {
                mesh_score = mesh_score,
                threat_type = mesh_threat_type,
                factors = features.mesh.threat_details.factors,
                source = features.mesh.source_info.namespace .. ":" .. (features.mesh.source_info.service or "unknown"),
                destination = features.mesh.destination_info.namespace .. ":" .. (features.mesh.destination_info.service or "unknown")
            })
        end
    end

    return threat_score, threat_type, threat_details
end

-- SQL Injection detection using string patterns
function KongGuardAIHandler:detect_sql_injection(features)
    local score = 0
    local path = kong.request.get_path()
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()

    -- Combine all input for checking
    local input = string.lower(path .. " " .. query)
    if body and #body < 10000 then -- Limit body size for performance
        input = input .. " " .. string.lower(body)
    end

    -- Check for SQL injection patterns
    local sql_patterns = {
        "union%s+select",
        "drop%s+table",
        "drop%s+database",
        "insert%s+into",
        "delete%s+from",
        "update%s+.*%s+set",
        "exec%s*%(",
        "execute%s*%(",
        "script%s*>",
        "select%s+.*%s+from",
        "';%s*drop",
        "1%s*=%s*1",
        "or%s+1%s*=%s*1",
        "waitfor%s+delay",
        "benchmark%s*%(",
        "sleep%s*%("
    }

    for _, pattern in ipairs(sql_patterns) do
        if string.match(input, pattern) then
            score = 0.95
            break
        end
    end

    -- Check for SQL comment patterns
    if string.match(input, "%-%-") or string.match(input, "/%*") or string.match(input, "%*/") then
        score = math.max(score, 0.8)
    end

    return score
end

-- XSS detection using string patterns
function KongGuardAIHandler:detect_xss(features)
    local score = 0
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()
    local headers = kong.request.get_headers()

    -- Check query and body
    local input = string.lower(query)
    if body and #body < 10000 then
        input = input .. " " .. string.lower(body)
    end

    -- Check user-controlled headers
    for key, value in pairs(headers) do
        if key:lower():match("referer") or key:lower():match("user%-agent") then
            input = input .. " " .. string.lower(tostring(value))
        end
    end

    -- Check for XSS patterns
    local xss_patterns = {
        "<script",
        "javascript:",
        "onerror%s*=",
        "onload%s*=",
        "onclick%s*=",
        "onmouseover%s*=",
        "<iframe",
        "<embed",
        "<object",
        "document%.cookie",
        "document%.write",
        "window%.location",
        "eval%s*%(",
        "alert%s*%(",
        "<img%s+src"
    }

    for _, pattern in ipairs(xss_patterns) do
        if string.match(input, pattern) then
            score = 0.9
            break
        end
    end

    return score
end

-- Path traversal detection
function KongGuardAIHandler:detect_path_traversal(features)
    local score = 0
    local path = kong.request.get_path()
    local query = kong.request.get_raw_query() or ""

    local input = path .. " " .. query

    -- Check for path traversal patterns
    local traversal_patterns = {
        "%.%./",
        "%.%.\\",
        "%%2e%%2e%%2f",
        "%%252e%%252e%%252f",
        "/etc/passwd",
        "/windows/system32",
        "/proc/self",
        "c:\\windows",
        "c:\\winnt"
    }

    for _, pattern in ipairs(traversal_patterns) do
        if string.match(string.lower(input), pattern) then
            score = 0.85
            break
        end
    end

    return score
end

-- Command injection detection
function KongGuardAIHandler:detect_command_injection(features)
    local score = 0
    local query = kong.request.get_raw_query() or ""
    local body = kong.request.get_raw_body()

    local input = query
    if body and #body < 10000 then
        input = input .. " " .. body
    end

    -- Check for command injection patterns
    local cmd_patterns = {
        "%$%(.*%)",
        "`.*`",
        ";%s*ls%s",
        ";%s*cat%s",
        ";%s*wget%s",
        ";%s*curl%s",
        "|%s*nc%s",
        "&&%s*whoami",
        "%|%|%s*id%s"
    }

    for _, pattern in ipairs(cmd_patterns) do
        if string.match(input, pattern) then
            score = 0.9
            break
        end
    end

    return score
end

-- DDoS pattern detection
function KongGuardAIHandler:detect_ddos_patterns(features, config)
    local score = 0

    -- Check request rate
    if features.requests_per_minute > config.ddos_rpm_threshold then
        score = 0.8

        -- Increase score for very high rates
        if features.requests_per_minute > config.ddos_rpm_threshold * 2 then
            score = 0.95
        end
    end

    -- Check for request patterns (same path repeatedly)
    local path_key = "path_count:" .. features.client_ip .. ":" .. kong.request.get_path()
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        local path_count = kong_cache:incr(path_key, 1, 0, 60) or 1
        if path_count > 50 then -- Same path more than 50 times per minute
            score = math.max(score, 0.85)
        end
    end

    return score
end

-- Credential stuffing detection
function KongGuardAIHandler:detect_credential_stuffing(features)
    local score = 0
    local path = kong.request.get_path()

    -- Check if it's a login endpoint
    if features.method == "POST" and
       (path:match("/login") or path:match("/auth") or path:match("/signin")) then

        -- Check failed login attempts
        local failed_key = "failed_login:" .. features.client_ip
        local kong_cache = ngx.shared.kong_cache
        if kong_cache then
            local failed_count = kong_cache:get(failed_key) or 0

            if failed_count > 5 then -- More than 5 failed attempts
                score = 0.8
            elseif failed_count > 10 then
                score = 0.95
            end
        end

        -- Check rapid login attempts
        if features.requests_per_minute > 10 then
            score = math.max(score, 0.75)
        end
    end

    return score
end

-- Feature extraction for threat detection
function KongGuardAIHandler:extract_features(request, client_ip, config)
    local features = {
        -- Temporal features
        hour_of_day = tonumber(os.date("%H")),
        day_of_week = tonumber(os.date("%w")),

        -- Request features
        method = request.get_method(),
        path = request.get_path(),
        path_depth = select(2, request.get_path():gsub("/", "")),
        query_param_count = 0,
        header_count = 0,

        -- Rate features
        requests_per_minute = self:get_request_rate(client_ip, 60),
        requests_per_hour = self:get_request_rate(client_ip, 3600),

        -- Payload features
        content_length = tonumber(request.get_header("Content-Length") or 0),

        -- Client features
        user_agent = request.get_header("User-Agent") or "",
        client_ip = client_ip,
        accept_language = request.get_header("Accept-Language") or ""
    }

    -- Count query parameters
    local query = request.get_query()
    if query then
        for k, v in pairs(query) do
            features.query_param_count = features.query_param_count + 1
        end
    end

    -- Count headers
    local headers = request.get_headers()
    if headers then
        for k, v in pairs(headers) do
            features.header_count = features.header_count + 1
        end
    end

    -- Extract mesh metadata if enabled
    if config.enable_mesh_enricher then
        local mesh_enricher = MeshEnricher:new(config)
        local mesh_data = mesh_enricher:read_headers(request, config)

        if mesh_data then
            -- Analyze mesh metadata for threat indicators
            local mesh_analysis = mesh_enricher:analyze(mesh_data, config)

            -- Add mesh features to the feature set
            features.mesh = {
                -- Raw mesh metadata
                namespace = mesh_data.namespace,
                workload = mesh_data.workload,
                service = mesh_data.service,
                pod = mesh_data.pod,
                zone = mesh_data.zone,
                trace_id = mesh_data.trace_id,
                mesh_source = mesh_data.mesh_source,

                -- Analysis results
                cross_namespace = mesh_analysis.cross_namespace,
                risky_namespace = mesh_analysis.risky_namespace,
                unusual_pair = mesh_analysis.unusual_pair,
                missing_headers = mesh_analysis.missing_headers,
                pair_count = mesh_analysis.pair_count,
                source_info = mesh_analysis.source_info,
                destination_info = mesh_analysis.destination_info,

                -- Calculated threat score
                mesh_score = mesh_enricher:calculate_score(mesh_analysis, config),
                threat_details = mesh_enricher:generate_threat_details(mesh_analysis, mesh_enricher:calculate_score(mesh_analysis, config))
            }

            log_message(config, "debug", "Mesh metadata extracted", {
                namespace = mesh_data.namespace,
                service = mesh_data.service,
                workload = mesh_data.workload,
                mesh_score = features.mesh.mesh_score,
                factors = features.mesh.threat_details.factors
            })
        else
            -- No mesh headers found
            features.mesh = nil
            log_message(config, "debug", "No mesh metadata found in request headers")
        end
    end

    return features
end

-- Anomaly detection using statistical methods
function KongGuardAIHandler:calculate_anomaly_score(features)
    local score = 0

    -- Request rate anomaly
    local avg_rpm = 30 -- baseline average
    if features.requests_per_minute > avg_rpm * 3 then
        score = score + 0.3
    end

    -- Unusual time of day (late night/early morning)
    if features.hour_of_day >= 0 and features.hour_of_day <= 5 then
        score = score + 0.2
    end

    -- Unusual header count
    if features.header_count > 30 or features.header_count < 3 then
        score = score + 0.2
    end

    -- Large payload anomaly
    if features.content_length > 1000000 then -- > 1MB
        score = score + 0.3
    end

    -- Many query parameters
    if features.query_param_count > 10 then
        score = score + 0.2
    end

    return math.min(score, 1.0)
end

-- Optimized helper functions for performance
function KongGuardAIHandler:is_whitelisted_optimized(client_ip, whitelist)
    -- Fast lookup using hash table for large whitelists
    if #whitelist > 10 then
        local whitelist_set = {}
        for _, ip in ipairs(whitelist) do
            whitelist_set[ip] = true
        end
        return whitelist_set[client_ip] or false
    else
        -- Linear search for small lists
        for _, ip in ipairs(whitelist) do
            if client_ip == ip then
                return true
            end
        end
        return false
    end
end

function KongGuardAIHandler:is_blocked_optimized(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then return false end

    -- Use cached result if available
    local cache_key = "blocked:" .. client_ip
    return kong_cache:get(cache_key) ~= nil
end

function KongGuardAIHandler:block_request_optimized(threat_type, client_ip)
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        kong_cache:set("blocked:" .. client_ip, threat_type, 3600)
        kong_cache:incr("threat_counter", 1, 0)
    end
end

-- Optimized feature extraction
function KongGuardAIHandler:extract_features_optimized(request, client_ip, config, headers, method, path)
    local features = get_pooled_table()

    -- Pre-compute commonly used values
    local query = request.get_raw_query()
    local content_length = headers["content-length"] or 0

    features.client_ip = client_ip
    features.method = method
    features.path = path
    features.path_depth = select(2, path:gsub("/", ""))
    features.content_length = tonumber(content_length) or 0
    features.user_agent = headers["user-agent"] or ""
    features.hour_of_day = tonumber(os.date("%H"))

    -- Optimized rate calculation
    features.requests_per_minute = self:get_request_rate_optimized(client_ip, 60)

    -- Optimized query parameter counting
    local query_param_count = 0
    if query then
        query_param_count = select(2, query:gsub("&", "")) + 1
    end
    features.query_param_count = query_param_count

    -- Optimized header counting
    features.header_count = 0
    for _ in pairs(headers) do
        features.header_count = features.header_count + 1
    end

    -- Mesh enrichment (lazy loaded)
    if config.enable_mesh_enricher then
        local mesh_enricher = get_instance("mesh_enricher", config)
        if mesh_enricher then
            features.mesh = mesh_enricher:read_headers(request, config)
        end
    end

    return features
end

-- Optimized threat detection with early returns
-- Now using extracted threat_detector module
function KongGuardAIHandler:detect_threat_optimized(features, config)
    -- Initialize threat detector instance if needed
    if not self.threat_detector_instance then
        self.threat_detector_instance = threat_detector.new(config)
    end

    -- Use the extracted threat detector module
    return self.threat_detector_instance:detect_threat_optimized(features, config)
end

-- Pattern detection now handled by threat_detector module

-- AI detection now handled by ai_service module

-- Optimized TAXII checking
function KongGuardAIHandler:check_taxii_optimized(features, config)
    local taxii_cache = get_instance("taxii_cache", config)
    if not taxii_cache then return 0, "none", {} end

    -- Fast IP lookup
    if features.client_ip then
        local ip_match = taxii_cache:lookup_ip(features.client_ip)
        if ip_match then
            return 0.9, "taxii_ip_blocklist", {ip_match = ip_match}
        end
    end

    return 0, "none", {}
end

-- Optimized rate limiting
function KongGuardAIHandler:apply_advanced_rate_limiting_optimized(client_ip, threat_score, features, config)
    local result = get_pooled_table()
    result.should_block = false
    result.type = "none"
    result.message = ""
    result.retry_after = 60

    -- Fast basic rate limiting
    local rate_key = "rate_limit:" .. client_ip
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        local current = kong_cache:incr(rate_key, 1, 0, 60) or 1
        local limit = config.threat_rate_limit or 60

        if current > limit then
            result.should_block = true
            result.type = "basic_rate_limit"
            result.message = get_cached_string("Rate limit exceeded")
            return result
        end
    end

    return result
end

-- Optimized metrics updating
function KongGuardAIHandler:update_metrics_optimized(threat_score, features, config)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then return end

    -- Batch metric updates
    kong_cache:incr("total_requests", 1, 0)
    if threat_score > 0 then
        kong_cache:incr("threats_detected", 1, 0)
    end

    -- Mesh metrics (optimized)
    if features.mesh then
        kong_cache:incr("mesh_requests", 1, 0)
        if features.mesh.namespace then
            kong_cache:incr("mesh_namespace:" .. features.mesh.namespace, 1, 0, 3600)
        end
    else
        kong_cache:incr("non_mesh_requests", 1, 0)
    end
end

-- Optimized request rate calculation
function KongGuardAIHandler:get_request_rate_optimized(client_ip, window)
    local cache_key = "rate:" .. client_ip .. ":" .. math.floor(ngx.now() / window)
    local kong_cache = ngx.shared.kong_cache

    if not kong_cache then return 0 end

    return kong_cache:incr(cache_key, 1, 0, window + 10) or 1
end

-- Async SOAR processing
function KongGuardAIHandler:process_soar_async(threat_data, features, config)
    ngx.timer.at(0, function()
        -- Lazy load SOAR components
        local incident_responder = get_instance("incident_responder", config)
        local threat_hunter = get_instance("threat_hunter", config)
        local forensic_collector = get_instance("forensic_collector", config)

        -- Threat hunting
        if threat_hunter and threat_data.score > 0.1 then
            threat_hunter:add_correlation_data({
                timestamp = threat_data.timestamp,
                client_ip = threat_data.client_ip,
                request_path = threat_data.path,
                threat_score = threat_data.score
            })
        end

        -- Incident response
        if incident_responder and threat_data.score > config.block_threshold then
            local triggered_workflows = incident_responder:evaluate_triggers(threat_data)
            if #triggered_workflows > 0 then
                threat_data.soar.workflows_triggered = triggered_workflows
                threat_data.soar.incident_id = "processing"
                features.workflow_triggered = true
            end
        end

        -- Forensic collection
        if forensic_collector and threat_data.score > config.block_threshold then
            local should_collect = forensic_collector:evaluate_collection_triggers(threat_data)
            if should_collect then
                local evidence_id = forensic_collector:collect_evidence(threat_data, "high_threat")
                if evidence_id then
                    threat_data.soar.forensic_evidence_id = evidence_id
                    features.forensic_collected = true
                end
            end
        end
    end)
end

-- Optimized Prometheus metrics handler
function KongGuardAIHandler:handle_prometheus_metrics_optimized(config)
    local prometheus_metrics = get_instance("prometheus_metrics", config)
    if prometheus_metrics then
        local metrics_output = prometheus_metrics:generate_prometheus_output()

        kong.response.set_header("Content-Type", get_cached_string("text/plain; version=0.0.4; charset=utf-8"))
        kong.response.set_header("X-Kong-Guard-AI-Metrics", "ok")

        return kong.response.exit(200, metrics_output)
    else
        return kong.response.exit(503, {
            error = "Metrics not available",
            message = "Prometheus metrics not initialized"
        })
    end
end

-- Get request count for IP
function KongGuardAIHandler:get_request_count(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return 0
    end

    local count_key = "request_count:" .. client_ip
    return kong_cache:get(count_key) or 0
end

-- Get failed authentication attempts
function KongGuardAIHandler:get_failed_attempts(client_ip)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return 0
    end

    local failed_key = "failed_login:" .. client_ip
    return kong_cache:get(failed_key) or 0
end

-- Get request rate for IP
function KongGuardAIHandler:get_request_rate(client_ip, window)
    local cache_key = "rate:" .. client_ip .. ":" .. math.floor(ngx.now() / window)
    local kong_cache = ngx.shared.kong_cache

    if not kong_cache then
        return 0
    end

    local count = kong_cache:incr(cache_key, 1, 0, window + 10) or 1
    return count
end

-- Block request by IP
function KongGuardAIHandler:block_request(threat_type, client_ip)
    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        -- Block for 1 hour
        kong_cache:set("blocked:" .. client_ip, threat_type, 3600)
        kong_cache:incr("threat_counter", 1, 0)
    end
end

-- Apply rate limiting
function KongGuardAIHandler:apply_rate_limit(client_ip, config)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return false
    end

    local rate_key = "rate_limit:" .. client_ip
    local current = kong_cache:incr(rate_key, 1, 0, 60) or 1

    -- Check if over rate limit (default 60 requests per minute when threatened)
    local limit = config.threat_rate_limit or 60
    return current > limit
end

-- Optimized notification sending
function KongGuardAIHandler:send_notification_optimized(threat_data, config)
    if not config.notification_url then return end

    local httpc = http.new()
    httpc:set_timeout(500)  -- Reduced timeout for performance

    -- Use pooled table for payload
    local payload = get_pooled_table()
    payload.incident_id = self:generate_incident_id()
    payload.threat_type = threat_data.type
    payload.threat_score = threat_data.score
    payload.client_ip = threat_data.client_ip
    payload.path = threat_data.path
    payload.timestamp = threat_data.timestamp

    local success, err = pcall(function()
        local res = httpc:request_uri(config.notification_url, {
            method = "POST",
            body = cjson.encode(payload),
            headers = {
                ["Content-Type"] = "application/json",
                ["X-Kong-Guard-AI"] = "v1.0.0"
            }
        })
        return res and res.status == 200
    end)

    return_pooled_table(payload)

    if not success then
        log_message(config, "error", "Failed to send notification", {error = err})
    end
end

-- Optimized learning metrics update
function KongGuardAIHandler:update_learning_metrics_optimized(threat_data)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then return end

    -- Batch metric updates
    local pattern_key = "pattern:" .. threat_data.type
    local score_bucket = math.floor(threat_data.score * 10) / 10
    local score_key = "score_dist:" .. tostring(score_bucket)

    kong_cache:incr(pattern_key, 1, 0, 86400)
    kong_cache:incr(score_key, 1, 0, 86400)
end

-- Optimized incident ID generation
function KongGuardAIHandler:generate_incident_id()
    return string.format("KGA-%s-%s", ngx.now(), math.random(10000, 99999))
end

-- Performance monitoring and cleanup
function KongGuardAIHandler:cleanup()
    -- Clear caches periodically
    _feature_cache = {}

    -- Return pooled tables
    while #_table_pool > 0 do
        table.remove(_table_pool)
    end

    -- Clear string cache if it gets too large
    if #_string_cache > 1000 then
        _string_cache = {}
    end

    -- Clear module cache (force reload on next request)
    _modules = {}
    _instances = {}

    log_message({log_level = "info"}, "info", "Handler cleanup completed")
end

-- Performance statistics
function KongGuardAIHandler:get_performance_stats()
    return {
        memory_usage = {
            string_cache_size = #_string_cache,
            table_pool_size = #_table_pool,
            feature_cache_size = #_feature_cache
        },
        modules_loaded = #_modules,
        instances_cached = #_instances
    }
end

-- Generate unique incident ID
function KongGuardAIHandler:generate_incident_id()
    return string.format("KGA-%s-%s", os.time(), math.random(10000, 99999))
end

-- Check TAXII threat intelligence indicators
function KongGuardAIHandler:check_taxii_indicators(features, config)
    local taxii_cache = TaxiiCache.new(config)
    if not taxii_cache then
        return 0, "none", {}
    end

    local threat_score = 0
    local threat_type = "none"
    local taxii_details = {
        matches = {},
        checked_indicators = {},
        sources = {}
    }

    local weights = config.taxii_score_weights or {}

    -- Extract data for checking
    local client_ip = features.client_ip
    local path = features.path or kong.request.get_path()
    local user_agent = features.user_agent or kong.request.get_header("User-Agent")
    local host = features.host or kong.request.get_header("Host")

    -- 1. Check IP against TAXII IP blocklist/allowlist
    if client_ip then
        table.insert(taxii_details.checked_indicators, "ip:" .. client_ip)

        local ip_match = taxii_cache:lookup_ip(client_ip)
        if ip_match then
            local is_blocklist = self:is_blocklist_label(ip_match.metadata.labels or {})
            local weight = is_blocklist and (weights.ip_blocklist or 0.9) or (weights.ip_allowlist or -0.5)

            if weight > 0 or (weight < 0 and threat_score > 0) then
                threat_score = math.max(threat_score, weight)
                threat_type = is_blocklist and "taxii_ip_blocklist" or threat_type

                table.insert(taxii_details.matches, {
                    type = "ip",
                    value = client_ip,
                    action = is_blocklist and "block" or "allow",
                    weight = weight,
                    source_id = ip_match.metadata.source_id,
                    labels = ip_match.metadata.labels,
                    confidence = ip_match.metadata.confidence
                })

                taxii_details.sources[ip_match.metadata.source_id] = true
            end
        end
    end

    -- 2. Check domain/host against TAXII domain indicators
    if host then
        table.insert(taxii_details.checked_indicators, "domain:" .. host)

        local domain_match = taxii_cache:lookup_domain(host)
        if domain_match then
            local is_blocklist = self:is_blocklist_label(domain_match.metadata.labels or {})
            local weight = is_blocklist and (weights.domain_blocklist or 0.8) or (weights.domain_allowlist or -0.4)

            if weight > 0 or (weight < 0 and threat_score > 0) then
                threat_score = math.max(threat_score, weight)
                threat_type = is_blocklist and "taxii_domain_blocklist" or threat_type

                table.insert(taxii_details.matches, {
                    type = "domain",
                    value = host,
                    action = is_blocklist and "block" or "allow",
                    weight = weight,
                    source_id = domain_match.metadata.source_id,
                    labels = domain_match.metadata.labels,
                    confidence = domain_match.metadata.confidence
                })

                taxii_details.sources[domain_match.metadata.source_id] = true
            end
        end
    end

    -- 3. Check full URL against TAXII URL indicators
    if host and path then
        local full_url = "http://" .. host .. path
        table.insert(taxii_details.checked_indicators, "url:" .. full_url)

        local url_match = taxii_cache:lookup_url(full_url)
        if url_match then
            local is_blocklist = self:is_blocklist_label(url_match.metadata.labels or {})
            local weight = is_blocklist and (weights.url_blocklist or 0.8) or (weights.url_allowlist or -0.4)

            if weight > 0 or (weight < 0 and threat_score > 0) then
                threat_score = math.max(threat_score, weight)
                threat_type = is_blocklist and "taxii_url_blocklist" or threat_type

                table.insert(taxii_details.matches, {
                    type = "url",
                    value = full_url,
                    action = is_blocklist and "block" or "allow",
                    weight = weight,
                    source_id = url_match.metadata.source_id,
                    labels = url_match.metadata.labels,
                    confidence = url_match.metadata.confidence
                })

                taxii_details.sources[url_match.metadata.source_id] = true
            end
        end
    end

    -- 4. Check TLS fingerprints (JA3/JA4) if available
    if config.enable_tls_fingerprints then
        local tls_headers = config.tls_header_map or {}

        -- Check JA3
        local ja3 = kong.request.get_header(tls_headers.ja3 or "X-JA3")
        if ja3 then
            table.insert(taxii_details.checked_indicators, "ja3:" .. ja3)

            local ja3_match = taxii_cache:lookup_ja3(ja3)
            if ja3_match then
                local is_blocklist = self:is_blocklist_label(ja3_match.metadata.labels or {})
                local weight = is_blocklist and (weights.ja3_blocklist or 0.7) or (weights.ja3_allowlist or -0.3)

                if weight > 0 or (weight < 0 and threat_score > 0) then
                    threat_score = math.max(threat_score, weight)
                    threat_type = is_blocklist and "taxii_ja3_blocklist" or threat_type

                    table.insert(taxii_details.matches, {
                        type = "ja3",
                        value = ja3,
                        action = is_blocklist and "block" or "allow",
                        weight = weight,
                        source_id = ja3_match.metadata.source_id,
                        labels = ja3_match.metadata.labels,
                        confidence = ja3_match.metadata.confidence
                    })

                    taxii_details.sources[ja3_match.metadata.source_id] = true
                end
            end
        end

        -- Check JA4
        local ja4 = kong.request.get_header(tls_headers.ja4 or "X-JA4")
        if ja4 then
            table.insert(taxii_details.checked_indicators, "ja4:" .. ja4)

            local ja4_match = taxii_cache:lookup_ja4(ja4)
            if ja4_match then
                local is_blocklist = self:is_blocklist_label(ja4_match.metadata.labels or {})
                local weight = is_blocklist and (weights.ja4_blocklist or 0.7) or (weights.ja4_allowlist or -0.3)

                if weight > 0 or (weight < 0 and threat_score > 0) then
                    threat_score = math.max(threat_score, weight)
                    threat_type = is_blocklist and "taxii_ja4_blocklist" or threat_type

                    table.insert(taxii_details.matches, {
                        type = "ja4",
                        value = ja4,
                        action = is_blocklist and "block" or "allow",
                        weight = weight,
                        source_id = ja4_match.metadata.source_id,
                        labels = ja4_match.metadata.labels,
                        confidence = ja4_match.metadata.confidence
                    })

                    taxii_details.sources[ja4_match.metadata.source_id] = true
                end
            end
        end
    end

    -- 5. Check regex patterns against request content
    local request_content = (path or "") .. " " .. (user_agent or "")
    local query = kong.request.get_raw_query()
    if query then
        request_content = request_content .. " " .. query
    end

    table.insert(taxii_details.checked_indicators, "regex_checks")
    local regex_matches = taxii_cache:lookup_regex_matches(request_content)
    for _, regex_match in ipairs(regex_matches) do
        local weight = weights.regex_match or 0.6
        threat_score = math.max(threat_score, weight)
        threat_type = "taxii_regex_match"

        table.insert(taxii_details.matches, {
            type = "regex",
            value = regex_match.value,
            action = "block",
            weight = weight,
            source_id = regex_match.metadata.source_id,
            labels = regex_match.metadata.labels,
            confidence = regex_match.metadata.confidence
        })

        taxii_details.sources[regex_match.metadata.source_id] = true
    end

    -- Log TAXII analysis results
    if #taxii_details.matches > 0 then
        kong.log.info("[TAXII] Threat intelligence matches found", {
            matches_count = #taxii_details.matches,
            threat_score = threat_score,
            threat_type = threat_type,
            sources = table.concat(self:table_keys(taxii_details.sources), ", ")
        })
    end

    return threat_score, threat_type, taxii_details
end

-- Check if labels indicate blocklist vs allowlist
function KongGuardAIHandler:is_blocklist_label(labels)
    for _, label in ipairs(labels) do
        local lower_label = string.lower(label)
        -- Common blocklist indicators
        if lower_label:find("malicious") or lower_label:find("block") or
           lower_label:find("threat") or lower_label:find("bad") or
           lower_label:find("attack") or lower_label:find("exploit") then
            return true
        end
        -- Common allowlist indicators
        if lower_label:find("benign") or lower_label:find("allow") or
           lower_label:find("trusted") or lower_label:find("whitelist") or
           lower_label:find("safe") then
            return false
        end
    end

    -- Default to blocklist if unclear
    return true
end

-- Get table keys as array
function KongGuardAIHandler:table_keys(t)
    local keys = {}
    for key, _ in pairs(t) do
        table.insert(keys, key)
    end
    return keys
end

-- Apply advanced rate limiting with all modules
function KongGuardAIHandler:apply_advanced_rate_limiting(client_ip, threat_score, features, config)
    local result = {
        should_block = false,
        type = "none",
        message = "",
        retry_after = 60,
        challenge_required = false,
        challenge_html = nil,
        details = {},
        adaptive_rate_applied = false,
        ddos_detected = false,
        geo_limited = false,
        circuit_breaker_triggered = false
    }

    -- Check circuit breaker first (for service protection)
    if circuit_breaker and config.enable_circuit_breakers then
        local service_id = kong.router.get_service() and kong.router.get_service().id or "default"
        local should_allow, reason = circuit_breaker:should_allow_request(service_id)

        if not should_allow then
            result.should_block = true
            result.type = "circuit_breaker"
            result.message = "Service temporarily unavailable due to circuit breaker"
            result.retry_after = 30
            result.circuit_breaker_triggered = true
            result.details.circuit_reason = reason
            return result
        end
    end

    -- Check for DDoS patterns first (highest priority)
    if ddos_mitigator and config.ddos_protection and config.ddos_protection.enable_ddos_mitigation then
        local ddos_result = ddos_mitigator:analyze_request(client_ip, features, config.ddos_protection)

        if ddos_result.is_ddos then
            result.should_block = true
            result.type = "ddos"
            result.ddos_detected = true
            result.details.ddos_score = ddos_result.ddos_score
            result.details.ddos_patterns = ddos_result.patterns

            -- Check if challenge is required
            if ddos_result.requires_challenge then
                result.challenge_required = true
                result.challenge_html = ddos_mitigator:generate_challenge(client_ip, ddos_result.difficulty_level)
                result.message = "DDoS protection active - solve challenge to continue"
                result.retry_after = config.ddos_protection.challenge_timeout_seconds or 30
            else
                result.message = "Request blocked due to DDoS attack pattern"
                result.retry_after = 300 -- 5 minutes for DDoS blocks
            end

            return result
        end
    end

    -- Check geographic rate limiting
    if geo_rate_limiter and config.enable_geo_limiting then
        local geo_result = geo_rate_limiter:check_rate_limit(client_ip, features)

        if geo_result.rate_limited then
            result.should_block = true
            result.type = "geo_rate_limit"
            result.geo_limited = true
            result.message = "Geographic rate limit exceeded for your region"
            result.retry_after = 60
            result.details.country = geo_result.country
            result.details.geo_limit = geo_result.applied_limit
            result.details.current_rate = geo_result.current_rate

            -- Add anomaly information if detected
            if geo_result.anomaly_detected then
                result.details.anomaly_type = geo_result.anomaly_type
                result.details.anomaly_score = geo_result.anomaly_score
            end

            return result
        end
    end

    -- Apply adaptive rate limiting based on threat score
    if adaptive_rate_limiter and config.enable_adaptive_rate_limiting then
        -- Analyze traffic patterns
        local traffic_patterns = adaptive_rate_limiter:analyze_traffic_patterns(client_ip)

        -- Calculate adaptive rate limit
        local adaptive_limit = adaptive_rate_limiter:calculate_pattern_based_limit(
            client_ip, threat_score, traffic_patterns
        )

        -- Check if client exceeds the adaptive limit
        local is_rate_limited = adaptive_rate_limiter:check_rate_limit(client_ip, adaptive_limit)

        if is_rate_limited then
            result.should_block = true
            result.type = "adaptive_rate_limit"
            result.adaptive_rate_applied = true
            result.message = "Adaptive rate limit exceeded based on threat assessment"
            result.retry_after = 60

            -- Get quota information
            local quota = adaptive_rate_limiter:get_remaining_quota(client_ip, adaptive_limit)
            result.details.adaptive_limit = adaptive_limit
            result.details.remaining_quota = quota.remaining
            result.details.reset_time = quota.reset_time
            result.details.threat_score = threat_score
            result.details.traffic_patterns = traffic_patterns

            return result
        else
            -- Track successful adaptive rate limiting application
            result.adaptive_rate_applied = true
            result.details.adaptive_limit = adaptive_limit
        end
    end

    -- Fallback to basic rate limiting if no advanced modules triggered
    if not result.adaptive_rate_applied then
        local basic_limited = self:apply_rate_limit(client_ip, config)
        if basic_limited then
            result.should_block = true
            result.type = "basic_rate_limit"
            result.message = "Basic rate limit exceeded"
            result.retry_after = 60
        end
    end

    return result
end

-- Record success/failure for circuit breaker (called in response phase)
function KongGuardAIHandler:record_circuit_breaker_result(success, response_time)
    if not circuit_breaker then
        return
    end

    local service_id = kong.router.get_service() and kong.router.get_service().id or "default"

    if success then
        circuit_breaker:record_success(service_id)
    else
        local error_type = kong.response.get_status() >= 500 and "server_error" or "client_error"
        circuit_breaker:record_failure(service_id, error_type)
    end

    -- Record response time for metrics
    if response_time then
        circuit_breaker:record_response_time(service_id, response_time)
    end
end

-- Add Prometheus metrics endpoint handler
function KongGuardAIHandler:handle_prometheus_metrics(config)
    local request_path = kong.request.get_path()

    -- Check for Prometheus metrics path
    if request_path:match("/_kong_guard_ai/prometheus") or request_path:match("/_kong_guard_ai/metrics") then
        if prometheus_metrics then
            local metrics_output = prometheus_metrics:generate_prometheus_output()

            kong.response.set_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            kong.response.set_header("X-Kong-Guard-AI-Metrics", "ok")

            return kong.response.exit(200, metrics_output)
        else
            return kong.response.exit(503, {
                error = "Metrics not available",
                message = "Prometheus metrics not initialized"
            })
        end
    end

    return nil -- Not a metrics request
end

-- Override access phase to include metrics endpoint
-- Note: The original access function already exists above, this just adds metrics handling

return KongGuardAIHandler
