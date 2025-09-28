local _M = {}

-- Kong Guard AI Compliance Reporter Module
-- Handles automated compliance reporting, monitoring, and regulatory requirements

local cjson = require("cjson.safe")
local pl_stringx = require("pl.stringx")
local pl_tablex = require("pl.tablex")
local pl_file = require("pl.file")
local pl_path = require("pl.path")
local pl_date = require("pl.date")
local uuid = require("resty.uuid")

-- Dependencies
local logger = require("kong.plugins.kong-guard-ai.audit_logger")
local privacy_manager = require("kong.plugins.kong-guard-ai.privacy_manager")
local retention_manager = require("kong.plugins.kong-guard-ai.retention_manager")

-- Module constants
local REPORT_TYPES = {
    GDPR = "gdpr",
    SECURITY_AUDIT = "security_audit",
    DATA_PROCESSING = "data_processing",
    PRIVACY_AUDIT = "privacy_audit",
    COMPLIANCE_STATUS = "compliance_status"
}

local OUTPUT_FORMATS = {
    JSON = "json",
    CSV = "csv",
    PDF = "pdf",
    HTML = "html"
}

local COMPLIANCE_FRAMEWORKS = {
    GDPR = "gdpr",
    CCPA = "ccpa",
    SOC2 = "soc2",
    HIPAA = "hipaa",
    PCI_DSS = "pci_dss"
}

-- Initialize compliance reporter
function _M.init_worker()
    -- Initialize scheduled reporting
    ngx.timer.every(3600, _M._scheduled_report_check) -- Check every hour
end

-- Generate compliance report
function _M.generate_report(report_type, config, options)
    options = options or {}

    local report_id = uuid.generate()
    local timestamp = ngx.time()
    local report_data = {
        report_id = report_id,
        report_type = report_type,
        generated_at = timestamp,
        period_start = options.period_start or (timestamp - 2592000), -- 30 days ago
        period_end = options.period_end or timestamp,
        framework = options.framework or "general",
        format = options.format or OUTPUT_FORMATS.JSON
    }

    -- Generate report based on type
    if report_type == REPORT_TYPES.GDPR then
        report_data.content = _M._generate_gdpr_report(config, options)
    elseif report_type == REPORT_TYPES.SECURITY_AUDIT then
        report_data.content = _M._generate_security_audit_report(config, options)
    elseif report_type == REPORT_TYPES.DATA_PROCESSING then
        report_data.content = _M._generate_data_processing_report(config, options)
    elseif report_type == REPORT_TYPES.PRIVACY_AUDIT then
        report_data.content = _M._generate_privacy_audit_report(config, options)
    elseif report_type == REPORT_TYPES.COMPLIANCE_STATUS then
        report_data.content = _M._generate_compliance_status_report(config, options)
    else
        return nil, "Unknown report type: " .. report_type
    end

    -- Add metadata
    report_data.metadata = {
        total_records = #report_data.content.records or 0,
        compliance_score = _M._calculate_compliance_score(report_data.content),
        violations_count = _M._count_violations(report_data.content),
        recommendations = _M._generate_recommendations(report_data.content, report_type)
    }

    -- Format output
    local formatted_report, err = _M._format_report(report_data, options.format)
    if err then
        return nil, "Failed to format report: " .. err
    end

    -- Store report if requested
    if options.store_report ~= false then
        _M._store_report(report_data, config)
    end

    -- Log report generation
    logger.log_event("compliance_report_generated", {
        report_id = report_id,
        report_type = report_type,
        records_count = report_data.metadata.total_records,
        compliance_score = report_data.metadata.compliance_score
    }, config)

    return formatted_report, nil
end

-- Generate GDPR compliance report
function _M._generate_gdpr_report(config, options)
    local report = {
        framework = COMPLIANCE_FRAMEWORKS.GDPR,
        records = {},
        summary = {
            total_data_subjects = 0,
            data_processing_activities = 0,
            consent_records = 0,
            data_deletion_requests = 0,
            privacy_violations = 0
        }
    }

    -- Get privacy audit data
    local privacy_audit = privacy_manager.get_privacy_audit_data(config, options.period_start, options.period_end)

    -- Process data subject records
    for _, record in ipairs(privacy_audit.data_subjects or {}) do
        table.insert(report.records, {
            type = "data_subject",
            subject_id = record.subject_id,
            data_types = record.data_types,
            processing_purposes = record.processing_purposes,
            consent_status = record.consent_status,
            last_activity = record.last_activity,
            gdpr_compliant = _M._check_gdpr_compliance(record)
        })
    end

    -- Process consent records
    for _, record in ipairs(privacy_audit.consent_records or {}) do
        table.insert(report.records, {
            type = "consent",
            subject_id = record.subject_id,
            consent_type = record.consent_type,
            granted_at = record.granted_at,
            expires_at = record.expires_at,
            withdrawn_at = record.withdrawn_at,
            gdpr_compliant = record.withdrawn_at == nil or record.granted_at < record.withdrawn_at
        })
    end

    -- Process data deletion requests
    for _, record in ipairs(privacy_audit.deletion_requests or {}) do
        table.insert(report.records, {
            type = "deletion_request",
            subject_id = record.subject_id,
            requested_at = record.requested_at,
            completed_at = record.completed_at,
            status = record.status,
            gdpr_compliant = record.completed_at ~= nil
        })
    end

    -- Update summary
    report.summary.total_data_subjects = #privacy_audit.data_subjects
    report.summary.consent_records = #privacy_audit.consent_records
    report.summary.data_deletion_requests = #privacy_audit.deletion_requests
    report.summary.privacy_violations = _M._count_gdpr_violations(report.records)

    return report
end

-- Generate security audit report
function _M._generate_security_audit_report(config, options)
    local report = {
        framework = "security_audit",
        records = {},
        summary = {
            total_threats = 0,
            blocked_requests = 0,
            rate_limited_requests = 0,
            security_incidents = 0,
            audit_events = 0
        }
    }

    -- Get audit events
    local audit_events = logger.get_audit_events(config, options.period_start, options.period_end, {"security_events"})

    -- Process security events
    for _, event in ipairs(audit_events) do
        table.insert(report.records, {
            type = "security_event",
            event_id = event.event_id,
            event_type = event.event_type,
            severity = event.severity,
            source_ip = event.source_ip,
            user_agent = event.user_agent,
            threat_score = event.threat_score,
            action_taken = event.action_taken,
            timestamp = event.timestamp
        })
    end

    -- Get threat statistics
    local threat_stats = _M._get_threat_statistics(config, options.period_start, options.period_end)

    -- Update summary
    report.summary.total_threats = threat_stats.total_threats
    report.summary.blocked_requests = threat_stats.blocked_requests
    report.summary.rate_limited_requests = threat_stats.rate_limited_requests
    report.summary.security_incidents = threat_stats.security_incidents
    report.summary.audit_events = #audit_events

    return report
end

-- Generate data processing report
function _M._generate_data_processing_report(config, options)
    local report = {
        framework = "data_processing",
        records = {},
        summary = {
            total_requests = 0,
            data_processed_gb = 0,
            pii_detected = 0,
            data_anonymized = 0,
            retention_compliant = 0
        }
    }

    -- Get data processing audit
    local processing_audit = _M._get_data_processing_audit(config, options.period_start, options.period_end)

    -- Process data processing records
    for _, record in ipairs(processing_audit.records or {}) do
        table.insert(report.records, {
            type = "data_processing",
            request_id = record.request_id,
            endpoint = record.endpoint,
            method = record.method,
            data_size_bytes = record.data_size_bytes,
            pii_detected = record.pii_detected,
            anonymized = record.anonymized,
            retention_days = record.retention_days,
            processing_time_ms = record.processing_time_ms,
            timestamp = record.timestamp
        })
    end

    -- Update summary
    report.summary.total_requests = #processing_audit.records
    report.summary.data_processed_gb = processing_audit.total_data_gb
    report.summary.pii_detected = processing_audit.pii_detected_count
    report.summary.data_anonymized = processing_audit.anonymized_count
    report.summary.retention_compliant = processing_audit.retention_compliant_count

    return report
end

-- Generate privacy audit report
function _M._generate_privacy_audit_report(config, options)
    local report = {
        framework = COMPLIANCE_FRAMEWORKS.GDPR,
        records = {},
        summary = {
            pii_detection_accuracy = 0,
            anonymization_effectiveness = 0,
            consent_compliance_rate = 0,
            data_retention_compliance = 0,
            privacy_violations = 0
        }
    }

    -- Get privacy audit data
    local privacy_audit = privacy_manager.get_privacy_audit_data(config, options.period_start, options.period_end)

    -- Process PII detection results
    for _, detection in ipairs(privacy_audit.pii_detections or {}) do
        table.insert(report.records, {
            type = "pii_detection",
            detection_id = detection.detection_id,
            data_type = detection.data_type,
            confidence_score = detection.confidence_score,
            anonymization_applied = detection.anonymization_applied,
            compliance_status = detection.compliance_status,
            timestamp = detection.timestamp
        })
    end

    -- Process anonymization results
    for _, anonymization in ipairs(privacy_audit.anonymizations or {}) do
        table.insert(report.records, {
            type = "anonymization",
            record_id = anonymization.record_id,
            original_data_type = anonymization.original_data_type,
            anonymization_method = anonymization.anonymization_method,
            effectiveness_score = anonymization.effectiveness_score,
            timestamp = anonymization.timestamp
        })
    end

    -- Calculate privacy metrics
    report.summary.pii_detection_accuracy = _M._calculate_pii_detection_accuracy(privacy_audit)
    report.summary.anonymization_effectiveness = _M._calculate_anonymization_effectiveness(privacy_audit)
    report.summary.consent_compliance_rate = _M._calculate_consent_compliance_rate(privacy_audit)
    report.summary.data_retention_compliance = _M._calculate_retention_compliance(privacy_audit)
    report.summary.privacy_violations = _M._count_privacy_violations(privacy_audit)

    return report
end

-- Generate compliance status report
function _M._generate_compliance_status_report(config, options)
    local report = {
        framework = "compliance_status",
        records = {},
        summary = {
            overall_compliance_score = 0,
            gdpr_compliance = 0,
            ccpa_compliance = 0,
            security_compliance = 0,
            data_protection_compliance = 0,
            active_violations = 0,
            critical_issues = 0
        }
    }

    -- Check each compliance framework
    local frameworks = {COMPLIANCE_FRAMEWORKS.GDPR, COMPLIANCE_FRAMEWORKS.CCPA}

    for _, framework in ipairs(frameworks) do
        if config.regulatory_config[string.lower(framework) .. "_compliance"] then
            local compliance_check = _M._check_framework_compliance(framework, config, options)
            table.insert(report.records, compliance_check)
        end
    end

    -- Check security compliance
    local security_check = _M._check_security_compliance(config, options)
    table.insert(report.records, security_check)

    -- Check data protection compliance
    local data_protection_check = _M._check_data_protection_compliance(config, options)
    table.insert(report.records, data_protection_check)

    -- Calculate overall scores
    report.summary.overall_compliance_score = _M._calculate_overall_compliance_score(report.records)
    report.summary.gdpr_compliance = _M._get_framework_score(report.records, COMPLIANCE_FRAMEWORKS.GDPR)
    report.summary.ccpa_compliance = _M._get_framework_score(report.records, COMPLIANCE_FRAMEWORKS.CCPA)
    report.summary.security_compliance = security_check.compliance_score
    report.summary.data_protection_compliance = data_protection_check.compliance_score
    report.summary.active_violations = _M._count_active_violations(report.records)
    report.summary.critical_issues = _M._count_critical_issues(report.records)

    return report
end

-- Check GDPR compliance
function _M._check_gdpr_compliance(record)
    -- Check consent validity
    if record.consent_status ~= "granted" then
        return false
    end

    -- Check data processing purposes
    if not record.processing_purposes or #record.processing_purposes == 0 then
        return false
    end

    -- Check data retention
    local retention_days = record.retention_days or 0
    if retention_days > 2555 then -- 7 years max
        return false
    end

    return true
end

-- Count GDPR violations
function _M._count_gdpr_violations(records)
    local violations = 0
    for _, record in ipairs(records) do
        if record.type == "data_subject" and not record.gdpr_compliant then
            violations = violations + 1
        elseif record.type == "consent" and not record.gdpr_compliant then
            violations = violations + 1
        elseif record.type == "deletion_request" and not record.gdpr_compliant then
            violations = violations + 1
        end
    end
    return violations
end

-- Get threat statistics
function _M._get_threat_statistics(config, period_start, period_end)
    -- This would integrate with the main threat detection system
    -- For now, return mock data structure
    return {
        total_threats = 0,
        blocked_requests = 0,
        rate_limited_requests = 0,
        security_incidents = 0
    }
end

-- Get data processing audit
function _M._get_data_processing_audit(config, period_start, period_end)
    -- This would integrate with request processing logs
    -- For now, return mock data structure
    return {
        records = {},
        total_data_gb = 0,
        pii_detected_count = 0,
        anonymized_count = 0,
        retention_compliant_count = 0
    }
end

-- Calculate compliance score
function _M._calculate_compliance_score(content)
    if not content or not content.records then
        return 0
    end

    local total_records = #content.records
    if total_records == 0 then
        return 100
    end

    local compliant_records = 0
    for _, record in ipairs(content.records) do
        if record.compliance_status == "compliant" or record.gdpr_compliant == true then
            compliant_records = compliant_records + 1
        end
    end

    return math.floor((compliant_records / total_records) * 100)
end

-- Count violations
function _M._count_violations(content)
    if not content or not content.records then
        return 0
    end

    local violations = 0
    for _, record in ipairs(content.records) do
        if record.compliance_status == "violation" or record.gdpr_compliant == false then
            violations = violations + 1
        end
    end
    return violations
end

-- Generate recommendations
function _M._generate_recommendations(content, report_type)
    local recommendations = {}

    if report_type == REPORT_TYPES.GDPR then
        if content.summary.privacy_violations > 0 then
            table.insert(recommendations, "Review and update data processing consent mechanisms")
        end
        if content.summary.data_deletion_requests > 0 then
            table.insert(recommendations, "Implement automated data deletion workflows")
        end
    elseif report_type == REPORT_TYPES.SECURITY_AUDIT then
        if content.summary.blocked_requests > 100 then
            table.insert(recommendations, "Review threat detection rules to reduce false positives")
        end
        if content.summary.security_incidents > 0 then
            table.insert(recommendations, "Implement additional security monitoring and alerting")
        end
    end

    return recommendations
end

-- Format report output
function _M._format_report(report_data, format)
    if format == OUTPUT_FORMATS.JSON then
        return cjson.encode(report_data), nil
    elseif format == OUTPUT_FORMATS.CSV then
        return _M._format_csv_report(report_data), nil
    elseif format == OUTPUT_FORMATS.HTML then
        return _M._format_html_report(report_data), nil
    else
        return nil, "Unsupported format: " .. format
    end
end

-- Format CSV report
function _M._format_csv_report(report_data)
    local csv_lines = {"Report ID,Type,Timestamp,Compliance Score,Violations"}

    table.insert(csv_lines, string.format("%s,%s,%s,%d,%d",
        report_data.report_id,
        report_data.report_type,
        os.date("%Y-%m-%d %H:%M:%S", report_data.generated_at),
        report_data.metadata.compliance_score,
        report_data.metadata.violations_count
    ))

    return table.concat(csv_lines, "\n")
end

-- Format HTML report
function _M._format_html_report(report_data)
    local html = [[
<!DOCTYPE html>
<html>
<head>
    <title>Kong Guard AI Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { background: #e8f4f8; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .recommendations { background: #fff3cd; padding: 15px; margin: 20px 0; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Kong Guard AI Compliance Report</h1>
        <p><strong>Report ID:</strong> ]] .. report_data.report_id .. [[</p>
        <p><strong>Type:</strong> ]] .. report_data.report_type .. [[</p>
        <p><strong>Generated:</strong> ]] .. os.date("%Y-%m-%d %H:%M:%S", report_data.generated_at) .. [[</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Compliance Score:</strong> ]] .. report_data.metadata.compliance_score .. [[%</p>
        <p><strong>Total Records:</strong> ]] .. report_data.metadata.total_records .. [[</p>
        <p><strong>Violations:</strong> ]] .. report_data.metadata.violations_count .. [[</p>
    </div>

    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
]]

    for _, rec in ipairs(report_data.metadata.recommendations) do
        html = html .. "<li>" .. rec .. "</li>\n"
    end

    html = html .. [[
        </ul>
    </div>
</body>
</html>
]]

    return html
end

-- Store report
function _M._store_report(report_data, config)
    local storage_path = config.audit_config.audit_storage_path or "/var/log/kong-guard-ai/reports"
    local filename = string.format("%s_%s_%s.json",
        report_data.report_type,
        os.date("%Y%m%d_%H%M%S", report_data.generated_at),
        report_data.report_id
    )

    local filepath = pl_path.join(storage_path, filename)

    -- Ensure directory exists
    pl_path.mkdir(pl_path.dirname(filepath))

    -- Write report
    local success, err = pl_file.write(filepath, cjson.encode(report_data))
    if not success then
        ngx.log(ngx.ERR, "Failed to store compliance report: ", err)
    end

    return success, err
end

-- Scheduled report check
function _M._scheduled_report_check()
    -- This would be called by the timer to check for scheduled reports
    -- Implementation would check configuration for scheduled report settings
    -- and generate reports as needed
end

-- Check framework compliance
function _M._check_framework_compliance(framework, config, options)
    -- Mock compliance check - would implement actual checks
    return {
        framework = framework,
        compliance_score = 85,
        status = "partial",
        violations = {"Missing data processing records", "Incomplete consent tracking"},
        last_checked = ngx.time()
    }
end

-- Check security compliance
function _M._check_security_compliance(config, options)
    return {
        framework = "security",
        compliance_score = 90,
        status = "good",
        violations = {},
        last_checked = ngx.time()
    }
end

-- Check data protection compliance
function _M._check_data_protection_compliance(config, options)
    return {
        framework = "data_protection",
        compliance_score = 88,
        status = "good",
        violations = {"Some encryption not implemented"},
        last_checked = ngx.time()
    }
end

-- Calculate overall compliance score
function _M._calculate_overall_compliance_score(records)
    if #records == 0 then
        return 100
    end

    local total_score = 0
    for _, record in ipairs(records) do
        total_score = total_score + (record.compliance_score or 0)
    end

    return math.floor(total_score / #records)
end

-- Get framework score
function _M._get_framework_score(records, framework)
    for _, record in ipairs(records) do
        if record.framework == framework then
            return record.compliance_score or 0
        end
    end
    return 0
end

-- Count active violations
function _M._count_active_violations(records)
    local count = 0
    for _, record in ipairs(records) do
        count = count + (#record.violations or 0)
    end
    return count
end

-- Count critical issues
function _M._count_critical_issues(records)
    local count = 0
    for _, record in ipairs(records) do
        for _, violation in ipairs(record.violations or {}) do
            if string.find(violation:lower(), "critical") then
                count = count + 1
            end
        end
    end
    return count
end

-- Privacy audit helper functions
function _M._calculate_pii_detection_accuracy(audit_data)
    -- Mock calculation
    return 95
end

function _M._calculate_anonymization_effectiveness(audit_data)
    -- Mock calculation
    return 92
end

function _M._calculate_consent_compliance_rate(audit_data)
    -- Mock calculation
    return 98
end

function _M._calculate_retention_compliance(audit_data)
    -- Mock calculation
    return 96
end

function _M._count_privacy_violations(audit_data)
    -- Mock calculation
    return 2
end

return _M
