-- Compliance and Privacy Configuration Schema
-- Extracted from schema.lua for better modularity and maintainability

local _M = {}

--- Get compliance and privacy configuration schema fields
-- @return table configuration schema fields for compliance
function _M.get_fields()
    return {
        -- GDPR Compliance Configuration
        {
            enable_gdpr_compliance = {
                type = "boolean",
                default = false,
                description = "Enable GDPR compliance features"
            }
        },
        {
            gdpr_config = {
                type = "record",
                fields = {
                    {
                        data_retention_days = {
                            type = "integer",
                            default = 30,
                            between = {1, 2555}, -- 7 years max
                            description = "Data retention period in days"
                        }
                    },
                    {
                        enable_consent_management = {
                            type = "boolean",
                            default = true,
                            description = "Enable consent management"
                        }
                    },
                    {
                        consent_cookie_name = {
                            type = "string",
                            default = "kong_guard_ai_consent",
                            description = "Name of consent tracking cookie"
                        }
                    },
                    {
                        enable_right_to_be_forgotten = {
                            type = "boolean",
                            default = true,
                            description = "Enable right to be forgotten requests"
                        }
                    },
                    {
                        data_subject_request_endpoint = {
                            type = "string",
                            default = "/gdpr/data-subject-request",
                            description = "Endpoint for data subject requests"
                        }
                    }
                }
            }
        },
        -- CCPA Compliance Configuration
        {
            enable_ccpa_compliance = {
                type = "boolean",
                default = false,
                description = "Enable CCPA compliance features"
            }
        },
        {
            ccpa_config = {
                type = "record",
                fields = {
                    {
                        enable_opt_out = {
                            type = "boolean",
                            default = true,
                            description = "Enable opt-out of data sale"
                        }
                    },
                    {
                        opt_out_endpoint = {
                            type = "string",
                            default = "/ccpa/opt-out",
                            description = "Endpoint for opt-out requests"
                        }
                    },
                    {
                        privacy_policy_url = {
                            type = "string",
                            description = "URL to privacy policy"
                        }
                    }
                }
            }
        },
        -- SOC2 Compliance Configuration
        {
            enable_soc2_compliance = {
                type = "boolean",
                default = false,
                description = "Enable SOC2 compliance features"
            }
        },
        {
            soc2_config = {
                type = "record",
                fields = {
                    {
                        enable_detailed_audit_logs = {
                            type = "boolean",
                            default = true,
                            description = "Enable detailed audit logging for SOC2"
                        }
                    },
                    {
                        audit_log_retention_days = {
                            type = "integer",
                            default = 365,
                            between = {90, 2555},
                            description = "Audit log retention period in days"
                        }
                    },
                    {
                        enable_data_encryption = {
                            type = "boolean",
                            default = true,
                            description = "Enable data encryption at rest"
                        }
                    },
                    {
                        encryption_algorithm = {
                            type = "string",
                            default = "AES-256-GCM",
                            one_of = {"AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"},
                            description = "Encryption algorithm for data at rest"
                        }
                    }
                }
            }
        },
        -- HIPAA Compliance Configuration
        {
            enable_hipaa_compliance = {
                type = "boolean",
                default = false,
                description = "Enable HIPAA compliance features"
            }
        },
        {
            hipaa_config = {
                type = "record",
                fields = {
                    {
                        enable_phi_detection = {
                            type = "boolean",
                            default = true,
                            description = "Enable PHI (Protected Health Information) detection"
                        }
                    },
                    {
                        phi_anonymization_level = {
                            type = "string",
                            default = "full",
                            one_of = {"minimal", "standard", "full"},
                            description = "Level of PHI anonymization"
                        }
                    },
                    {
                        enable_breach_notification = {
                            type = "boolean",
                            default = true,
                            description = "Enable automatic breach notifications"
                        }
                    },
                    {
                        breach_notification_endpoint = {
                            type = "string",
                            description = "Endpoint for breach notifications"
                        }
                    }
                }
            }
        },
        -- PCI-DSS Compliance Configuration
        {
            enable_pci_compliance = {
                type = "boolean",
                default = false,
                description = "Enable PCI-DSS compliance features"
            }
        },
        {
            pci_config = {
                type = "record",
                fields = {
                    {
                        enable_card_data_detection = {
                            type = "boolean",
                            default = true,
                            description = "Enable credit card data detection"
                        }
                    },
                    {
                        card_data_masking_level = {
                            type = "string",
                            default = "full",
                            one_of = {"minimal", "standard", "full"},
                            description = "Level of card data masking"
                        }
                    },
                    {
                        enable_pci_logging = {
                            type = "boolean",
                            default = true,
                            description = "Enable PCI-specific audit logging"
                        }
                    },
                    {
                        cardholder_data_retention_days = {
                            type = "integer",
                            default = 90,
                            between = {1, 365},
                            description = "Cardholder data retention period"
                        }
                    }
                }
            }
        },
        -- Privacy Configuration
        {
            privacy_config = {
                type = "record",
                fields = {
                    {
                        enable_pii_detection = {
                            type = "boolean",
                            default = true,
                            description = "Enable PII detection"
                        }
                    },
                    {
                        pii_detection_patterns = {
                            type = "array",
                            elements = {type = "string"},
                            default = {"email", "phone", "ssn", "credit_card", "ip_address"},
                            description = "PII patterns to detect"
                        }
                    },
                    {
                        anonymization_method = {
                            type = "string",
                            default = "hash",
                            one_of = {"mask", "hash", "encrypt", "redact"},
                            description = "Method for anonymizing PII"
                        }
                    },
                    {
                        anonymization_key = {
                            type = "string",
                            description = "Key for PII anonymization (required for hash/encrypt)"
                        }
                    }
                }
            }
        },
        -- Data Loss Prevention
        {
            enable_dlp = {
                type = "boolean",
                default = false,
                description = "Enable Data Loss Prevention"
            }
        },
        {
            dlp_config = {
                type = "record",
                fields = {
                    {
                        sensitive_data_patterns = {
                            type = "array",
                            elements = {type = "string"},
                            description = "Custom patterns for sensitive data detection"
                        }
                    },
                    {
                        dlp_action = {
                            type = "string",
                            default = "block",
                            one_of = {"log", "block", "quarantine", "encrypt"},
                            description = "Action to take when sensitive data is detected"
                        }
                    },
                    {
                        enable_content_inspection = {
                            type = "boolean",
                            default = true,
                            description = "Enable deep content inspection"
                        }
                    }
                }
            }
        }
    }
end

--- Get compliance defaults
-- @return table default configuration values  
function _M.get_defaults()
    return {
        enable_gdpr_compliance = false,
        gdpr_config = {
            data_retention_days = 30,
            enable_consent_management = true,
            consent_cookie_name = "kong_guard_ai_consent",
            enable_right_to_be_forgotten = true,
            data_subject_request_endpoint = "/gdpr/data-subject-request"
        },
        enable_ccpa_compliance = false,
        ccpa_config = {
            enable_opt_out = true,
            opt_out_endpoint = "/ccpa/opt-out"
        },
        enable_soc2_compliance = false,
        soc2_config = {
            enable_detailed_audit_logs = true,
            audit_log_retention_days = 365,
            enable_data_encryption = true,
            encryption_algorithm = "AES-256-GCM"
        },
        enable_hipaa_compliance = false,
        hipaa_config = {
            enable_phi_detection = true,
            phi_anonymization_level = "full",
            enable_breach_notification = true
        },
        enable_pci_compliance = false,
        pci_config = {
            enable_card_data_detection = true,
            card_data_masking_level = "full",
            enable_pci_logging = true,
            cardholder_data_retention_days = 90
        },
        privacy_config = {
            enable_pii_detection = true,
            pii_detection_patterns = {"email", "phone", "ssn", "credit_card", "ip_address"},
            anonymization_method = "hash"
        },
        enable_dlp = false,
        dlp_config = {
            dlp_action = "block",
            enable_content_inspection = true
        }
    }
end

--- Get compliance framework requirements
-- @return table compliance framework details
function _M.get_compliance_frameworks()
    return {
        gdpr = {
            name = "General Data Protection Regulation",
            jurisdiction = "EU",
            required_features = {"consent_management", "right_to_be_forgotten", "data_retention"},
            max_retention_days = 2555, -- 7 years
            requires_encryption = true
        },
        ccpa = {
            name = "California Consumer Privacy Act",
            jurisdiction = "California, US",
            required_features = {"opt_out", "privacy_policy", "data_disclosure"},
            max_retention_days = 365,
            requires_encryption = false
        },
        soc2 = {
            name = "Service Organization Control 2",
            jurisdiction = "Global",
            required_features = {"audit_logs", "data_encryption", "access_controls"},
            min_retention_days = 365,
            requires_encryption = true
        },
        hipaa = {
            name = "Health Insurance Portability and Accountability Act",
            jurisdiction = "US",
            required_features = {"phi_detection", "breach_notification", "audit_logs"},
            min_retention_days = 2190, -- 6 years
            requires_encryption = true
        },
        pci_dss = {
            name = "Payment Card Industry Data Security Standard",
            jurisdiction = "Global",
            required_features = {"card_data_detection", "encryption", "secure_storage"},
            max_retention_days = 365,
            requires_encryption = true
        }
    }
end

--- Validate compliance configuration
-- @param config table configuration to validate
-- @return boolean true if valid
-- @return string error message if invalid
function _M.validate_config(config)
    if not config then
        return false, "Configuration is required"
    end
    
    -- Validate GDPR configuration
    if config.enable_gdpr_compliance and config.gdpr_config then
        local gdpr = config.gdpr_config
        if gdpr.data_retention_days and gdpr.data_retention_days > 2555 then
            return false, "GDPR data retention cannot exceed 7 years (2555 days)"
        end
        
        if gdpr.enable_consent_management and not gdpr.consent_cookie_name then
            return false, "consent_cookie_name is required when consent management is enabled"
        end
    end
    
    -- Validate HIPAA configuration
    if config.enable_hipaa_compliance and config.hipaa_config then
        local hipaa = config.hipaa_config
        if hipaa.enable_breach_notification and not hipaa.breach_notification_endpoint then
            return false, "breach_notification_endpoint is required when breach notification is enabled"
        end
    end
    
    -- Validate PCI configuration  
    if config.enable_pci_compliance and config.pci_config then
        local pci = config.pci_config
        if pci.cardholder_data_retention_days and pci.cardholder_data_retention_days > 365 then
            return false, "PCI cardholder data retention cannot exceed 365 days"
        end
    end
    
    -- Validate privacy configuration
    if config.privacy_config then
        local privacy = config.privacy_config
        if privacy.anonymization_method and (privacy.anonymization_method == "hash" or privacy.anonymization_method == "encrypt") then
            if not privacy.anonymization_key then
                return false, "anonymization_key is required for hash or encrypt methods"
            end
        end
    end
    
    -- Check for conflicting compliance requirements
    local enabled_frameworks = {}
    if config.enable_gdpr_compliance then table.insert(enabled_frameworks, "gdpr") end
    if config.enable_ccpa_compliance then table.insert(enabled_frameworks, "ccpa") end
    if config.enable_soc2_compliance then table.insert(enabled_frameworks, "soc2") end
    if config.enable_hipaa_compliance then table.insert(enabled_frameworks, "hipaa") end
    if config.enable_pci_compliance then table.insert(enabled_frameworks, "pci_dss") end
    
    if #enabled_frameworks > 1 then
        -- Validate compatibility between frameworks
        local frameworks = _M.get_compliance_frameworks()
        for i = 1, #enabled_frameworks do
            for j = i + 1, #enabled_frameworks do
                local fw1 = frameworks[enabled_frameworks[i]]
                local fw2 = frameworks[enabled_frameworks[j]]
                
                -- Check retention requirements compatibility
                if fw1.max_retention_days and fw2.min_retention_days then
                    if fw1.max_retention_days < fw2.min_retention_days then
                        return false, string.format("Conflicting retention requirements between %s and %s",
                            enabled_frameworks[i], enabled_frameworks[j])
                    end
                end
            end
        end
    end
    
    return true
end

return _M