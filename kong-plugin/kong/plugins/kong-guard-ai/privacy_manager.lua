--- Privacy Manager Module for Kong Guard AI
-- Provides comprehensive privacy compliance features including PII detection,
-- data anonymization, consent management, and GDPR/CCPA compliance.

local _M = {}
local mt = { __index = _M }

-- Dependencies
local kong = kong
local ngx = ngx
local cjson = require("cjson.safe")
local string = string
local math = math
local os = os

-- Constants
local PII_PATTERNS = {
    email = {
        pattern = "[a-zA-Z0-9._%%+-]+@[a-zA-Z0-9.-]+%.[a-zA-Z]{2,}",
        description = "Email address pattern"
    },
    phone = {
        pattern = "%+?[%d%s%-%(%)]{10,}",
        description = "Phone number pattern"
    },
    credit_card = {
        pattern = "%d{4}%s?%d{4}%s?%d{4}%s?%d{4}",
        description = "Credit card number pattern"
    },
    ssn = {
        pattern = "%d{3}%-%d{2}%-%d{4}",
        description = "Social Security Number pattern"
    },
    ip_address = {
        pattern = "%d+%.%d+%.%d+%.%d+",
        description = "IP address pattern"
    },
    name = {
        pattern = "[A-Z][a-z]+%s+[A-Z][a-z]+",
        description = "Full name pattern"
    },
    address = {
        pattern = "%d+[%s%a]+%w+%s*,%s*%w+%s*%d{5}",
        description = "Street address pattern"
    }
}

local ANONYMIZATION_LEVELS = {
    MINIMAL = "minimal",    -- Mask sensitive parts
    STANDARD = "standard",  -- Hash sensitive data
    AGGRESSIVE = "aggressive"  -- Remove sensitive data entirely
}

--- Create a new privacy manager instance
-- @param config Configuration table with privacy settings
-- @return Privacy manager instance
function _M.new(config)
    if not config then
        return nil, "Configuration required for privacy manager"
    end

    local self = {
        -- Configuration
        config = config,

        -- PII detection patterns
        pii_patterns = PII_PATTERNS,

        -- Anonymization settings
        anonymization = {
            level = config.anonymization_level or ANONYMIZATION_LEVELS.STANDARD,
            salt = config.anonymization_salt or "kong-guard-ai-privacy",
            hash_function = config.hash_function or "sha256"
        },

        -- Consent management
        consent = {
            enabled = config.consent_tracking or false,
            storage = {},
            default_consent = false,
            consent_ttl = config.consent_ttl or 31536000  -- 1 year
        },

        -- Privacy metrics
        metrics = {
            pii_detected = 0,
            data_anonymized = 0,
            consent_checks = 0,
            privacy_violations = 0,
            gdpr_requests = 0,
            ccpa_requests = 0
        },

        -- Data processing cache
        processing_cache = {},
        cache_ttl = config.cache_ttl or 300,  -- 5 minutes

        -- Regulatory compliance
        compliance = {
            gdpr_enabled = config.gdpr_compliance or false,
            ccpa_enabled = config.ccpa_compliance or false,
            data_residency = config.data_residency or "us"
        }
    }

    return setmetatable(self, mt)
end

--- Initialize privacy manager
function _M:init()
    -- Initialize consent storage if enabled
    if self.consent.enabled then
        self:_init_consent_storage()
    end

    -- Set up cache cleanup
    local ok, err = ngx.timer.every(self.cache_ttl, function()
        self:_cleanup_cache()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize privacy cache cleanup: ", err)
    end

    kong.log.info("[kong-guard-ai] Privacy manager initialized")
end

--- Detect personally identifiable information (PII) in data
function _M:detect_pii(data, context)
    if not data then
        return {}, false
    end

    local detected_pii = {}
    local has_pii = false
    local data_string = ""

    -- Convert data to string for pattern matching
    if type(data) == "table" then
        data_string = cjson.encode(data) or ""
    elseif type(data) == "string" then
        data_string = data
    else
        data_string = tostring(data)
    end

    -- Check each PII type
    for pii_type, pattern_info in pairs(self.pii_patterns) do
        if self:_should_detect_pii_type(pii_type) then
            local matches = self:_find_pattern_matches(data_string, pattern_info.pattern)

            if #matches > 0 then
                detected_pii[pii_type] = {
                    count = #matches,
                    matches = matches,
                    pattern = pattern_info.description
                }
                has_pii = true
                self.metrics.pii_detected = self.metrics.pii_detected + 1
            end
        end
    end

    -- Log PII detection
    if has_pii then
        kong.log.info("[kong-guard-ai] PII detected: ", {
            types = self:_get_pii_types(detected_pii),
            context = context or "unknown",
            data_size = #data_string
        })
    end

    return detected_pii, has_pii
end

--- Check if PII type should be detected based on configuration
function _M:_should_detect_pii_type(pii_type)
    if not self.config.pii_detection_rules then
        return true  -- Detect all by default
    end

    for _, enabled_type in ipairs(self.config.pii_detection_rules) do
        if enabled_type == pii_type then
            return true
        end
    end

    return false
end

--- Find pattern matches in data
function _M:_find_pattern_matches(data, pattern)
    local matches = {}
    local start_pos = 1

    while true do
        local match_start, match_end = string.find(data, pattern, start_pos)
        if not match_start then
            break
        end

        local match = string.sub(data, match_start, match_end)
        table.insert(matches, match)

        start_pos = match_end + 1

        -- Limit matches to prevent excessive processing
        if #matches >= 10 then
            break
        end
    end

    return matches
end

--- Get list of detected PII types
function _M:_get_pii_types(detected_pii)
    local types = {}
    for pii_type, _ in pairs(detected_pii) do
        table.insert(types, pii_type)
    end
    return types
end

--- Anonymize data based on detected PII
function _M:anonymize_data(data, detected_pii, context)
    if not data or not detected_pii then
        return data
    end

    local anonymized_data = self:_deep_copy(data)
    local anonymized_count = 0

    -- Anonymize based on detected PII types
    for pii_type, pii_info in pairs(detected_pii) do
        for _, match in ipairs(pii_info.matches) do
            anonymized_data = self:_anonymize_value(anonymized_data, match, pii_type)
            anonymized_count = anonymized_count + 1
        end
    end

    if anonymized_count > 0 then
        self.metrics.data_anonymized = self.metrics.data_anonymized + anonymized_count

        kong.log.debug("[kong-guard-ai] Data anonymized: ", {
            pii_types = self:_get_pii_types(detected_pii),
            anonymized_count = anonymized_count,
            context = context or "unknown"
        })
    end

    return anonymized_data
end

--- Anonymize a specific value in data
function _M:_anonymize_value(data, original_value, pii_type)
    if type(data) == "string" then
        return self:_anonymize_string(data, original_value, pii_type)
    elseif type(data) == "table" then
        return self:_anonymize_table(data, original_value, pii_type)
    else
        return data
    end
end

--- Anonymize string data
function _M:_anonymize_string(data, original_value, pii_type)
    if self.anonymization.level == ANONYMIZATION_LEVELS.AGGRESSIVE then
        -- Remove sensitive data entirely
        return string.gsub(data, original_value:gsub("([^%w])", "%%%1"), "[REDACTED]")
    elseif self.anonymization.level == ANONYMIZATION_LEVELS.STANDARD then
        -- Hash sensitive data
        local hashed_value = self:_hash_value(original_value)
        return string.gsub(data, original_value:gsub("([^%w])", "%%%1"), hashed_value)
    else
        -- Minimal: Mask sensitive parts
        return self:_mask_value(data, original_value, pii_type)
    end
end

--- Anonymize table data
function _M:_anonymize_table(data, original_value, pii_type)
    for key, value in pairs(data) do
        if type(value) == "string" and string.find(value, original_value, 1, true) then
            data[key] = self:_anonymize_string(value, original_value, pii_type)
        elseif type(value) == "table" then
            data[key] = self:_anonymize_table(value, original_value, pii_type)
        end
    end
    return data
end

--- Hash a value for anonymization
function _M:_hash_value(value)
    -- Simple hash for demonstration
    -- In production, use proper cryptographic hashing
    local hash = 0
    local salt = self.anonymization.salt

    for i = 1, #value do
        hash = (hash * 31 + value:byte(i)) % 1000000
    end

    for i = 1, #salt do
        hash = (hash * 31 + salt:byte(i)) % 1000000
    end

    return string.format("HASH-%06d", hash)
end

--- Mask a value for minimal anonymization
function _M:_mask_value(data, original_value, pii_type)
    if pii_type == "email" then
        -- Mask email: user@domain.com -> u***@d***.com
        return string.gsub(data, "([^@]+)@([^.]+)%.(.+)", function(user, domain, tld)
            return string.sub(user, 1, 1) .. string.rep("*", #user - 1) .. "@" ..
                   string.sub(domain, 1, 1) .. string.rep("*", #domain - 1) .. "." .. tld
        end)
    elseif pii_type == "phone" then
        -- Mask phone: +1234567890 -> +***4567890
        return string.gsub(data, "(%+?%d+)(%d{3})(%d+)", function(prefix, middle, last)
            return prefix .. string.rep("*", #middle) .. last
        end)
    elseif pii_type == "credit_card" then
        -- Mask credit card: 1234567890123456 -> ****5678
        return string.gsub(data, "(%d%d%d%d)%d+(%d%d%d%d)", function(first, last)
            return string.rep("*", #first) .. last
        end)
    else
        -- Generic masking: show first and last character
        return string.gsub(data, original_value:gsub("([^%w])", "%%%1"),
            function(match)
                if #match <= 2 then
                    return string.rep("*", #match)
                else
                    return string.sub(match, 1, 1) .. string.rep("*", #match - 2) .. string.sub(match, -1)
                end
            end)
    end
end

--- Check user consent for data processing
function _M:check_consent(user_id, purpose, context)
    if not self.consent.enabled then
        return true  -- Consent not required
    end

    self.metrics.consent_checks = self.metrics.consent_checks + 1

    local consent_key = user_id .. ":" .. purpose
    local consent_record = self.consent.storage[consent_key]

    if not consent_record then
        -- No consent record found
        kong.log.debug("[kong-guard-ai] No consent record found: ", {
            user_id = user_id,
            purpose = purpose,
            context = context
        })
        return self.consent.default_consent
    end

    -- Check if consent is still valid
    if ngx.now() - consent_record.timestamp > self.consent.consent_ttl then
        -- Consent expired
        self.consent.storage[consent_key] = nil
        return self.consent.default_consent
    end

    return consent_record.consent_given
end

--- Validate consent for request processing (called from handler)
function _M:validate_consent(client_ip, config)
    -- For GDPR/CCPA, we need to check if this is a known user
    -- In a real implementation, this would look up the user by IP or session
    -- For now, we'll assume anonymous users have default consent

    local result = {
        valid = true,
        details = {
            consent_checked = false,
            user_identified = false,
            consent_type = "default"
        }
    }

    -- Check if we have user identification
    local user_id = self:_identify_user_from_request(client_ip, config)
    if user_id then
        result.details.user_identified = true
        result.details.consent_checked = true

        -- Check consent for data processing
        local consent_given = self:check_consent(user_id, "data_processing", {
            client_ip = client_ip,
            source = "request_handler"
        })

        result.valid = consent_given
        result.details.consent_type = consent_given and "explicit" or "denied"
        result.details.user_id = user_id
    else
        -- Anonymous user - use default consent
        result.valid = self.consent.default_consent
        result.details.consent_type = "anonymous_default"
    end

    return result
end

--- Identify user from request (helper for consent validation)
function _M:_identify_user_from_request(client_ip, config)
    -- In a real implementation, this would:
    -- 1. Check session cookies
    -- 2. Check authentication headers
    -- 3. Look up user by IP in a user database
    -- For now, return nil (anonymous user)
    return nil
end

--- Grant or revoke user consent
function _M:set_consent(user_id, purpose, consent_given, context)
    if not self.consent.enabled then
        return false, "Consent tracking not enabled"
    end

    local consent_key = user_id .. ":" .. purpose

    self.consent.storage[consent_key] = {
        user_id = user_id,
        purpose = purpose,
        consent_given = consent_given,
        timestamp = ngx.now(),
        context = context,
        ip_address = ngx.var.remote_addr,
        user_agent = ngx.var.http_user_agent
    }

    kong.log.info("[kong-guard-ai] Consent ", consent_given and "granted" or "revoked", ": ", {
        user_id = user_id,
        purpose = purpose,
        context = context
    })

    return true
end

--- Process data with privacy compliance
function _M:process_data(data, context)
    if not data then
        return data, {}
    end

    local processing_result = {
        pii_detected = false,
        data_anonymized = false,
        consent_validated = false,
        processing_time = ngx.now()
    }

    -- Detect PII
    local detected_pii, has_pii = self:detect_pii(data, context)
    processing_result.pii_detected = has_pii
    processing_result.detected_pii_types = has_pii and self:_get_pii_types(detected_pii) or {}

    -- Check consent if PII detected
    if has_pii and context.user_id then
        local consent_given = self:check_consent(context.user_id, "data_processing", context)
        processing_result.consent_validated = true
        processing_result.consent_given = consent_given

        if not consent_given then
            kong.log.warn("[kong-guard-ai] Data processing blocked due to lack of consent: ", {
                user_id = context.user_id,
                context = context
            })
            processing_result.processing_blocked = true
            return nil, processing_result
        end
    end

    -- Anonymize data if configured
    local processed_data = data
    if self.config.data_anonymization and has_pii then
        processed_data = self:anonymize_data(data, detected_pii, context)
        processing_result.data_anonymized = true
    end

    processing_result.processing_time = ngx.now() - processing_result.processing_time

    return processed_data, processing_result
end

--- Handle GDPR data subject requests
function _M:handle_gdpr_request(request_type, user_id, context)
    if not self.compliance.gdpr_enabled then
        return false, "GDPR compliance not enabled"
    end

    self.metrics.gdpr_requests = self.metrics.gdpr_requests + 1

    local request_handlers = {
        right_to_be_forgotten = self._handle_gdpr_data_deletion,
        data_portability = self._handle_gdpr_data_portability,
        consent_withdrawal = self._handle_gdpr_consent_withdrawal,
        access_request = self._handle_gdpr_access_request,
        rectification = self._handle_gdpr_rectification,
        restriction = self._handle_gdpr_restriction,
        objection = self._handle_gdpr_objection
    }

    local handler = request_handlers[request_type]
    if not handler then
        return false, "Unknown GDPR request type: " .. request_type
    end

    return handler(self, user_id, context)
end

--- Handle comprehensive GDPR data deletion (Right to be Forgotten)
function _M:_handle_gdpr_data_deletion(user_id, context)
    kong.log.info("[kong-guard-ai] Processing GDPR Right to be Forgotten request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local deletion_result = {
        user_id = user_id,
        request_type = "right_to_be_forgotten",
        timestamp = ngx.now(),
        data_deleted = {},
        consent_revoked = false,
        audit_logged = false
    }

    -- 1. Revoke all consents for the user
    local consent_revoked = self:_revoke_all_user_consents(user_id, context)
    deletion_result.consent_revoked = consent_revoked

    -- 2. Find and delete user data from various sources
    local data_sources = self:_find_user_data_sources(user_id)
    for _, source in ipairs(data_sources) do
        local deleted = self:_delete_data_from_source(source, user_id, context)
        if deleted then
            table.insert(deletion_result.data_deleted, source)
        end
    end

    -- 3. Anonymize any remaining references
    local anonymized = self:_anonymize_user_references(user_id, context)
    deletion_result.references_anonymized = anonymized

    -- 4. Log the deletion for audit purposes
    local audit_result = self:_log_gdpr_action("data_deletion", user_id, deletion_result, context)
    deletion_result.audit_logged = audit_result.success

    -- 5. Schedule follow-up verification
    self:_schedule_deletion_verification(user_id, deletion_result)

    return true, deletion_result
end

--- Handle GDPR data portability request
function _M:_handle_gdpr_data_portability(user_id, context)
    kong.log.info("[kong-guard-ai] Processing GDPR Data Portability request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local export_result = {
        user_id = user_id,
        request_type = "data_portability",
        timestamp = ngx.now(),
        data_exported = {},
        export_formats = {"json", "csv"},
        download_links = {}
    }

    -- 1. Collect user data from all sources
    local user_data = self:_collect_user_data(user_id, context)
    export_result.data_exported = user_data

    -- 2. Format data for export
    local export_formats = self:_format_data_for_export(user_data, context.format or "json")
    export_result.formatted_data = export_formats

    -- 3. Generate secure download links
    local download_links = self:_generate_secure_download_links(user_id, export_formats, context)
    export_result.download_links = download_links

    -- 4. Log the export
    self:_log_gdpr_action("data_export", user_id, export_result, context)

    -- 5. Set expiration for download links (typically 30 days)
    self:_schedule_download_link_expiration(user_id, download_links)

    return true, export_result
end

--- Handle GDPR consent withdrawal
function _M:_handle_gdpr_consent_withdrawal(user_id, context)
    kong.log.info("[kong-guard-ai] Processing GDPR Consent Withdrawal: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local withdrawal_result = {
        user_id = user_id,
        request_type = "consent_withdrawal",
        timestamp = ngx.now(),
        consents_revoked = {},
        notification_sent = false
    }

    -- 1. Identify all consent records for the user
    local user_consents = self:_get_user_consents(user_id)

    -- 2. Revoke each consent
    for purpose, consent_record in pairs(user_consents) do
        self:set_consent(user_id, purpose, false, context)
        table.insert(withdrawal_result.consents_revoked, purpose)
    end

    -- 3. Stop all data processing for this user
    local processing_stopped = self:_stop_user_data_processing(user_id, context)
    withdrawal_result.processing_stopped = processing_stopped

    -- 4. Send confirmation notification
    local notification_sent = self:_send_consent_withdrawal_notification(user_id, withdrawal_result, context)
    withdrawal_result.notification_sent = notification_sent

    -- 5. Log the withdrawal
    self:_log_gdpr_action("consent_withdrawal", user_id, withdrawal_result, context)

    return true, withdrawal_result
end

--- Handle GDPR access request
function _M:_handle_gdpr_access_request(user_id, context)
    kong.log.info("[kong-guard-ai] Processing GDPR Access Request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local access_result = {
        user_id = user_id,
        request_type = "access_request",
        timestamp = ngx.now(),
        data_inventory = {},
        processing_activities = {},
        consent_status = {}
    }

    -- 1. Provide data inventory
    access_result.data_inventory = self:_get_user_data_inventory(user_id)

    -- 2. List processing activities
    access_result.processing_activities = self:_get_user_processing_activities(user_id)

    -- 3. Show consent status
    access_result.consent_status = self:_get_user_consent_status(user_id)

    -- 4. Include data sources and recipients
    access_result.data_recipients = self:_get_data_recipients(user_id)
    access_result.retention_periods = self:_get_data_retention_periods(user_id)

    -- 5. Log the access request
    self:_log_gdpr_action("access_request", user_id, access_result, context)

    return true, access_result
end

--- Handle GDPR rectification request
function _M:_handle_gdpr_rectification(user_id, context)
    -- Implementation for data correction/rectification
    local rectification_data = context.rectification_data
    if not rectification_data then
        return false, "Rectification data not provided"
    end

    kong.log.info("[kong-guard-ai] Processing GDPR Rectification Request: ", {
        user_id = user_id,
        fields_to_rectify = rectification_data,
        timestamp = ngx.now()
    })

    -- Update user data across all systems
    local updated = self:_update_user_data(user_id, rectification_data, context)

    -- Log the rectification
    self:_log_gdpr_action("rectification", user_id, {
        updated_fields = rectification_data,
        success = updated
    }, context)

    return updated, updated and "Data rectified successfully" or "Failed to rectify data"
end

--- Handle GDPR restriction request
function _M:_handle_gdpr_restriction(user_id, context)
    local restriction_type = context.restriction_type or "general"
    local duration = context.duration_days or 30

    kong.log.info("[kong-guard-ai] Processing GDPR Restriction Request: ", {
        user_id = user_id,
        restriction_type = restriction_type,
        duration_days = duration,
        timestamp = ngx.now()
    })

    -- Implement data processing restriction
    local restricted = self:_restrict_data_processing(user_id, restriction_type, duration, context)

    -- Log the restriction
    self:_log_gdpr_action("restriction", user_id, {
        restriction_type = restriction_type,
        duration_days = duration,
        success = restricted
    }, context)

    return restricted, restricted and "Data processing restricted" or "Failed to restrict data processing"
end

--- Handle GDPR objection request
function _M:_handle_gdpr_objection(user_id, context)
    local objection_type = context.objection_type or "general"

    kong.log.info("[kong-guard-ai] Processing GDPR Objection Request: ", {
        user_id = user_id,
        objection_type = objection_type,
        timestamp = ngx.now()
    })

    -- Stop processing for the specified purpose
    local objection_result = self:_process_data_objection(user_id, objection_type, context)

    -- Log the objection
    self:_log_gdpr_action("objection", user_id, objection_result, context)

    return objection_result.success, objection_result.message
end

--- Handle CCPA consumer rights requests
function _M:handle_ccpa_request(request_type, user_id, context)
    if not self.compliance.ccpa_enabled then
        return false, "CCPA compliance not enabled"
    end

    self.metrics.ccpa_requests = self.metrics.ccpa_requests + 1

    local request_handlers = {
        do_not_sell = self._handle_ccpa_do_not_sell,
        do_not_share = self._handle_ccpa_do_not_share,
        data_deletion = self._handle_ccpa_data_deletion,
        data_access = self._handle_ccpa_data_access,
        opt_out = self._handle_ccpa_opt_out,
        limit_use = self._handle_ccpa_limit_use
    }

    local handler = request_handlers[request_type]
    if not handler then
        return false, "Unknown CCPA request type: " .. request_type
    end

    return handler(self, user_id, context)
end

--- Handle CCPA Do Not Sell request
function _M:_handle_ccpa_do_not_sell(user_id, context)
    kong.log.info("[kong-guard-ai] Processing CCPA Do Not Sell request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local result = {
        user_id = user_id,
        request_type = "do_not_sell",
        timestamp = ngx.now(),
        sale_opt_out = false,
        data_sharing_restricted = false
    }

    -- 1. Opt out from data sales
    result.sale_opt_out = self:_opt_out_data_sales(user_id, context)

    -- 2. Restrict data sharing for commercial purposes
    result.data_sharing_restricted = self:_restrict_commercial_sharing(user_id, context)

    -- 3. Update consent records
    self:set_consent(user_id, "data_sales", false, context)
    self:set_consent(user_id, "commercial_sharing", false, context)

    -- 4. Log the request
    self:_log_ccpa_action("do_not_sell", user_id, result, context)

    return true, result
end

--- Handle CCPA Do Not Share request
function _M:_handle_ccpa_do_not_share(user_id, context)
    kong.log.info("[kong-guard-ai] Processing CCPA Do Not Share request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local result = {
        user_id = user_id,
        request_type = "do_not_share",
        timestamp = ngx.now(),
        sharing_opt_out = false,
        third_party_restricted = false
    }

    -- 1. Opt out from data sharing
    result.sharing_opt_out = self:_opt_out_data_sharing(user_id, context)

    -- 2. Restrict third-party data sharing
    result.third_party_restricted = self:_restrict_third_party_sharing(user_id, context)

    -- 3. Update consent records
    self:set_consent(user_id, "third_party_sharing", false, context)
    self:set_consent(user_id, "data_broker_sharing", false, context)

    -- 4. Log the request
    self:_log_ccpa_action("do_not_share", user_id, result, context)

    return true, result
end

--- Handle CCPA data deletion request
function _M:_handle_ccpa_data_deletion(user_id, context)
    kong.log.info("[kong-guard-ai] Processing CCPA Data Deletion request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    -- Use automated deletion workflow
    local data_deletion_workflow = require("kong.plugins.kong-guard-ai.data_deletion_workflow")
    local workflow_config = {
        privacy_config = self.config,
        audit_config = self.config.audit_config or {},
        regulatory_config = self.config.regulatory_config or {}
    }

    local workflow_manager = data_deletion_workflow.new(workflow_config)
    local workflow_id, workflow = workflow_manager:start_deletion_workflow(user_id, "ccpa", context)

    return true, {
        workflow_id = workflow_id,
        message = "Data deletion workflow started",
        status = "in_progress",
        estimated_completion = "24-48 hours"
    }
end

--- Handle CCPA data access request
function _M:_handle_ccpa_data_access(user_id, context)
    kong.log.info("[kong-guard-ai] Processing CCPA Data Access request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local result = {
        user_id = user_id,
        request_type = "data_access",
        timestamp = ngx.now(),
        personal_info = {},
        data_sources = {},
        collection_practices = {}
    }

    -- 1. Collect personal information collected in last 12 months
    result.personal_info = self:_collect_ccpa_personal_info(user_id)

    -- 2. Identify data sources
    result.data_sources = self:_get_ccpa_data_sources(user_id)

    -- 3. Describe collection practices
    result.collection_practices = self:_get_ccpa_collection_practices(user_id)

    -- 4. Include business purposes
    result.business_purposes = self:_get_ccpa_business_purposes()

    -- 5. Log the access request
    self:_log_ccpa_action("data_access", user_id, result, context)

    return true, result
end

--- Handle CCPA opt-out request
function _M:_handle_ccpa_opt_out(user_id, context)
    local opt_out_type = context.opt_out_type or "general"

    kong.log.info("[kong-guard-ai] Processing CCPA Opt-Out request: ", {
        user_id = user_id,
        opt_out_type = opt_out_type,
        timestamp = ngx.now()
    })

    local result = {
        user_id = user_id,
        request_type = "opt_out",
        opt_out_type = opt_out_type,
        timestamp = ngx.now(),
        opt_out_successful = false
    }

    -- Process opt-out based on type
    if opt_out_type == "sale" then
        result.opt_out_successful = self:_opt_out_data_sales(user_id, context)
    elseif opt_out_type == "share" then
        result.opt_out_successful = self:_opt_out_data_sharing(user_id, context)
    elseif opt_out_type == "process" then
        result.opt_out_successful = self:_opt_out_data_processing(user_id, context)
    else
        -- General opt-out
        result.opt_out_successful = self:_general_opt_out(user_id, context)
    end

    -- Log the opt-out
    self:_log_ccpa_action("opt_out", user_id, result, context)

    return result.opt_out_successful, result
end

--- Handle CCPA limit use request
function _M:_handle_ccpa_limit_use(user_id, context)
    kong.log.info("[kong-guard-ai] Processing CCPA Limit Use request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    local result = {
        user_id = user_id,
        request_type = "limit_use",
        timestamp = ngx.now(),
        use_limited = false,
        limited_purposes = {}
    }

    -- 1. Identify sensitive data uses to limit
    local sensitive_uses = self:_identify_sensitive_data_uses(user_id)

    -- 2. Limit the identified uses
    for _, use in ipairs(sensitive_uses) do
        local limited = self:_limit_data_use(user_id, use, context)
        if limited then
            table.insert(result.limited_purposes, use)
        end
    end

    result.use_limited = #result.limited_purposes > 0

    -- 3. Log the limitation
    self:_log_ccpa_action("limit_use", user_id, result, context)

    return result.use_limited, result
end

--- Handle data deletion (Right to be Forgotten)
function _M:_handle_data_deletion(user_id, context)
    kong.log.info("[kong-guard-ai] GDPR data deletion request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    -- Use automated deletion workflow
    local data_deletion_workflow = require("kong.plugins.kong-guard-ai.data_deletion_workflow")
    local workflow_config = {
        privacy_config = self.config,
        audit_config = self.config.audit_config or {},
        regulatory_config = self.config.regulatory_config or {}
    }

    local workflow_manager = data_deletion_workflow.new(workflow_config)
    local workflow_id, workflow = workflow_manager:start_deletion_workflow(user_id, "gdpr", context)

    return true, {
        workflow_id = workflow_id,
        message = "Data deletion workflow started",
        status = "in_progress",
        estimated_completion = "24-48 hours"
    }
end

--- Handle data export (Data Portability)
function _M:_handle_data_export(user_id, context)
    -- In a real implementation, this would:
    -- 1. Collect all user data
    -- 2. Format for export
    -- 3. Provide secure download
    -- 4. Log the export

    kong.log.info("[kong-guard-ai] GDPR data export request: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    -- Placeholder for actual data export logic
    return true, "Data export request processed"
end

--- Handle consent withdrawal
function _M:_handle_consent_withdrawal(user_id, context)
    -- Withdraw consent for all purposes
    local purposes = {"data_processing", "data_sharing", "marketing", "analytics"}

    for _, purpose in ipairs(purposes) do
        self:set_consent(user_id, purpose, false, context)
    end

    kong.log.info("[kong-guard-ai] GDPR consent withdrawal: ", {
        user_id = user_id,
        context = context,
        timestamp = ngx.now()
    })

    return true, "Consent withdrawn for all purposes"
end

--- Initialize consent storage
function _M:_init_consent_storage()
    -- In a real implementation, this would connect to a database
    -- For now, we use in-memory storage
    self.consent.storage = {}
    kong.log.info("[kong-guard-ai] Consent storage initialized")
end

--- Deep copy a table
function _M:_deep_copy(obj)
    if type(obj) ~= "table" then
        return obj
    end

    local copy = {}
    for k, v in pairs(obj) do
        copy[k] = self:_deep_copy(v)
    end

    return copy
end

--- Clean up processing cache
function _M:_cleanup_cache()
    local current_time = ngx.now()
    local cleaned = 0

    for key, entry in pairs(self.processing_cache) do
        if current_time - entry.timestamp > self.cache_ttl then
            self.processing_cache[key] = nil
            cleaned = cleaned + 1
        end
    end

    if cleaned > 0 then
        kong.log.debug("[kong-guard-ai] Cleaned ", cleaned, " cache entries")
    end
end

--- Get privacy compliance statistics
function _M:get_stats()
    return {
        pii_detection = {
            pii_detected = self.metrics.pii_detected,
            data_anonymized = self.metrics.data_anonymized
        },
        consent_management = {
            consent_checks = self.metrics.consent_checks,
            consent_records = self:_count_consent_records()
        },
        regulatory_compliance = {
            gdpr_requests = self.metrics.gdpr_requests,
            ccpa_requests = self.metrics.ccpa_requests,
            privacy_violations = self.metrics.privacy_violations
        },
        configuration = {
            anonymization_level = self.anonymization.level,
            consent_enabled = self.consent.enabled,
            gdpr_enabled = self.compliance.gdpr_enabled,
            ccpa_enabled = self.compliance.ccpa_enabled
        },
        cache = {
            cache_entries = self:_count_cache_entries(),
            cache_ttl = self.cache_ttl
        }
    }
end

--- Count consent records
function _M:_count_consent_records()
    local count = 0
    for _ in pairs(self.consent.storage) do
        count = count + 1
    end
    return count
end

--- Count cache entries
function _M:_count_cache_entries()
    local count = 0
    for _ in pairs(self.processing_cache) do
        count = count + 1
    end
    return count
end

--- Validate privacy compliance
function _M:validate_compliance()
    local issues = {}

    -- Check configuration consistency
    if self.compliance.gdpr_enabled and not self.config.data_anonymization then
        table.insert(issues, "GDPR enabled but data anonymization disabled")
    end

    if self.compliance.ccpa_enabled and not self.consent.enabled then
        table.insert(issues, "CCPA enabled but consent tracking disabled")
    end

    if self.config.data_anonymization and not self.config.pii_detection then
        table.insert(issues, "Data anonymization enabled but PII detection disabled")
    end

    return #issues == 0, issues
end

--- Helper functions for GDPR compliance

--- Revoke all user consents
function _M:_revoke_all_user_consents(user_id, context)
    local purposes = {"data_processing", "data_sharing", "marketing", "analytics", "profiling"}
    local revoked_count = 0

    for _, purpose in ipairs(purposes) do
        local consent_key = user_id .. ":" .. purpose
        if self.consent.storage[consent_key] then
            self.consent.storage[consent_key] = nil
            revoked_count = revoked_count + 1
        end
    end

    kong.log.info("[kong-guard-ai] Revoked ", revoked_count, " consents for user: ", user_id)
    return revoked_count > 0
end

--- Find user data sources
function _M:_find_user_data_sources(user_id)
    -- In a real implementation, this would query databases, logs, etc.
    -- For now, return mock data sources
    return {
        "user_database",
        "analytics_logs",
        "audit_logs",
        "consent_records",
        "processing_history"
    }
end

--- Delete data from source
function _M:_delete_data_from_source(source, user_id, context)
    -- Mock implementation - in reality would delete from actual data stores
    kong.log.info("[kong-guard-ai] Deleting user data from ", source, " for user: ", user_id)
    return true
end

--- Anonymize user references
function _M:_anonymize_user_references(user_id, context)
    -- Mock implementation
    kong.log.info("[kong-guard-ai] Anonymizing user references for: ", user_id)
    return true
end

--- Log GDPR action
function _M:_log_gdpr_action(action_type, user_id, details, context)
    -- Mock audit logging
    kong.log.info("[kong-guard-ai] GDPR Action Logged: ", {
        action_type = action_type,
        user_id = user_id,
        details = details,
        context = context,
        timestamp = ngx.now()
    })
    return {success = true}
end

--- Schedule deletion verification
function _M:_schedule_deletion_verification(user_id, deletion_result)
    -- Mock scheduling
    kong.log.info("[kong-guard-ai] Scheduled deletion verification for user: ", user_id)
end

--- Collect user data for export
function _M:_collect_user_data(user_id, context)
    -- Mock data collection
    return {
        personal_info = {name = "John Doe", email = "john@example.com"},
        consent_history = {},
        processing_history = {},
        data_sources = {}
    }
end

--- Format data for export
function _M:_format_data_for_export(user_data, format)
    if format == "json" then
        return {json = cjson.encode(user_data)}
    elseif format == "csv" then
        return {csv = "mock,csv,data"}
    end
    return {json = cjson.encode(user_data)}
end

--- Generate secure download links
function _M:_generate_secure_download_links(user_id, export_formats, context)
    -- Mock download link generation
    return {
        json_link = "/api/privacy/download/" .. user_id .. "/data.json?token=mock_token",
        csv_link = "/api/privacy/download/" .. user_id .. "/data.csv?token=mock_token"
    }
end

--- Schedule download link expiration
function _M:_schedule_download_link_expiration(user_id, download_links)
    -- Mock expiration scheduling
    kong.log.info("[kong-guard-ai] Scheduled download link expiration for user: ", user_id)
end

--- Get user consents
function _M:_get_user_consents(user_id)
    local user_consents = {}
    for key, record in pairs(self.consent.storage) do
        if record.user_id == user_id then
            user_consents[record.purpose] = record
        end
    end
    return user_consents
end

--- Stop user data processing
function _M:_stop_user_data_processing(user_id, context)
    -- Mock implementation
    kong.log.info("[kong-guard-ai] Stopped data processing for user: ", user_id)
    return true
end

--- Send consent withdrawal notification
function _M:_send_consent_withdrawal_notification(user_id, withdrawal_result, context)
    -- Mock notification
    kong.log.info("[kong-guard-ai] Sent consent withdrawal notification for user: ", user_id)
    return true
end

--- Get user data inventory
function _M:_get_user_data_inventory(user_id)
    -- Mock data inventory
    return {
        {category = "personal_info", fields = {"name", "email", "phone"}, source = "user_database"},
        {category = "consent_data", fields = {"consent_history"}, source = "consent_store"},
        {category = "processing_logs", fields = {"access_logs", "processing_history"}, source = "audit_logs"}
    }
end

--- Get user processing activities
function _M:_get_user_processing_activities(user_id)
    -- Mock processing activities
    return {
        {purpose = "authentication", legal_basis = "contract", retention = "account_active"},
        {purpose = "analytics", legal_basis = "consent", retention = "2_years"},
        {purpose = "marketing", legal_basis = "consent", retention = "withdrawal"}
    }
end

--- Get user consent status
function _M:_get_user_consent_status(user_id)
    local consents = self:_get_user_consents(user_id)
    local status = {}

    for purpose, record in pairs(consents) do
        status[purpose] = {
            granted = record.consent_given,
            timestamp = record.timestamp,
            expires = record.timestamp + self.consent.consent_ttl
        }
    end

    return status
end

--- Get data recipients
function _M:_get_data_recipients(user_id)
    -- Mock recipients
    return {"analytics_provider", "marketing_platform", "cloud_storage"}
end

--- Get data retention periods
function _M:_get_data_retention_periods(user_id)
    -- Mock retention periods
    return {
        personal_info = "account_active_plus_2_years",
        consent_data = "7_years",
        audit_logs = "7_years"
    }
end

--- Update user data
function _M:_update_user_data(user_id, rectification_data, context)
    -- Mock data update
    kong.log.info("[kong-guard-ai] Updated user data for: ", user_id)
    return true
end

--- Restrict data processing
function _M:_restrict_data_processing(user_id, restriction_type, duration, context)
    -- Mock restriction
    kong.log.info("[kong-guard-ai] Restricted data processing for user: ", user_id)
    return true
end

--- Process data objection
function _M:_process_data_objection(user_id, objection_type, context)
    -- Mock objection processing
    return {
        success = true,
        message = "Data processing objection processed",
        objection_type = objection_type
    }
end

--- Helper functions for CCPA compliance

--- Opt out from data sales
function _M:_opt_out_data_sales(user_id, context)
    -- Mock opt-out
    kong.log.info("[kong-guard-ai] Opted out from data sales for user: ", user_id)
    return true
end

--- Restrict commercial sharing
function _M:_restrict_commercial_sharing(user_id, context)
    -- Mock restriction
    kong.log.info("[kong-guard-ai] Restricted commercial sharing for user: ", user_id)
    return true
end

--- Log CCPA action
function _M:_log_ccpa_action(action_type, user_id, details, context)
    -- Mock audit logging
    kong.log.info("[kong-guard-ai] CCPA Action Logged: ", {
        action_type = action_type,
        user_id = user_id,
        details = details,
        context = context,
        timestamp = ngx.now()
    })
    return {success = true}
end

--- Opt out from data sharing
function _M:_opt_out_data_sharing(user_id, context)
    -- Mock opt-out
    kong.log.info("[kong-guard-ai] Opted out from data sharing for user: ", user_id)
    return true
end

--- Restrict third-party sharing
function _M:_restrict_third_party_sharing(user_id, context)
    -- Mock restriction
    kong.log.info("[kong-guard-ai] Restricted third-party sharing for user: ", user_id)
    return true
end

--- Find CCPA personal information
function _M:_find_ccpa_personal_info(user_id)
    -- Mock data sources
    return {"user_profile", "purchase_history", "browsing_data", "device_info"}
end

--- Delete CCPA data from source
function _M:_delete_ccpa_data_from_source(source, user_id, context)
    -- Mock deletion
    kong.log.info("[kong-guard-ai] Deleted CCPA data from ", source, " for user: ", user_id)
    return true
end

--- Verify CCPA deletion
function _M:_verify_ccpa_deletion(user_id, deleted_sources)
    -- Mock verification
    return #deleted_sources > 0
end

--- Collect CCPA personal information
function _M:_collect_ccpa_personal_info(user_id)
    -- Mock personal info collection
    return {
        identifiers = {email = "user@example.com", phone = "+1234567890"},
        characteristics = {age = 30, gender = "prefer_not_to_say"},
        commercial_info = {purchase_history = "various_items"},
        internet_activity = {browsing_history = "website_visits"},
        geolocation = {location_data = "city_state"},
        sensory_data = {},
        professional_info = {job_title = "developer"},
        education_info = {education_level = "bachelors"},
        inferences = {interests = ["technology", "privacy"]}
    }
end

--- Get CCPA data sources
function _M:_get_ccpa_data_sources(user_id)
    -- Mock data sources
    return {
        {source = "website", collected = "2023-01-15", categories = {"identifiers", "internet_activity"}},
        {source = "mobile_app", collected = "2023-02-20", categories = {"geolocation", "device_info"}},
        {source = "customer_service", collected = "2023-03-10", categories = {"professional_info"}}
    }
end

--- Get CCPA collection practices
function _M:_get_ccpa_collection_practices(user_id)
    -- Mock collection practices
    return {
        automatic_collection = true,
        manual_collection = false,
        third_party_collection = true,
        data_broker_collection = false
    }
end

--- Get CCPA business purposes
function _M:_get_ccpa_business_purposes()
    -- Mock business purposes
    return {
        "providing_services",
        "analytics",
        "security",
        "debugging",
        "advertising",
        "marketing"
    }
end

--- Opt out from data processing
function _M:_opt_out_data_processing(user_id, context)
    -- Mock opt-out
    kong.log.info("[kong-guard-ai] Opted out from data processing for user: ", user_id)
    return true
end

--- General opt-out
function _M:_general_opt_out(user_id, context)
    -- Mock general opt-out
    kong.log.info("[kong-guard-ai] General opt-out for user: ", user_id)
    return true
end

--- Identify sensitive data uses
function _M:_identify_sensitive_data_uses(user_id)
    -- Mock sensitive uses
    return {"profiling", "targeted_advertising", "data_sharing"}
end

--- Limit data use
function _M:_limit_data_use(user_id, use_type, context)
    -- Mock limitation
    kong.log.info("[kong-guard-ai] Limited data use '", use_type, "' for user: ", user_id)
    return true
end

--- Cleanup resources
function _M:cleanup()
    -- Clear caches
    self.processing_cache = {}
    self.consent.storage = {}

    kong.log.info("[kong-guard-ai] Privacy manager cleanup completed")
end

return _M
