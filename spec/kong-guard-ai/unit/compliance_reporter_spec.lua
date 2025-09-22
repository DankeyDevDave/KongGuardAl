describe("Kong Guard AI Compliance Reporter", function()
    local compliance_reporter = require("kong.plugins.kong-guard-ai.compliance_reporter")
    local cjson = require("cjson.safe")

    -- Mock configuration
    local mock_config = {
        compliance_config = {
            enable_gdpr_compliance = true,
            enable_audit_logging = true,
            enable_data_retention = true
        },
        privacy_config = {
            data_anonymization = true,
            pii_detection = true,
            consent_tracking = true,
            pii_detection_rules = {"email", "phone", "credit_card"},
            anonymization_level = "standard"
        },
        audit_config = {
            audit_log_level = "standard",
            audit_retention_days = 90,
            audit_encryption = true,
            audit_events = {"security_events", "config_changes", "access_events"},
            audit_storage_backend = "local"
        },
        retention_policies = {
            threat_data_retention_days = 30,
            user_data_retention_days = 90,
            log_retention_days = 365,
            audit_retention_days = 2555,
            cleanup_schedule = "daily",
            secure_deletion = true
        },
        regulatory_config = {
            gdpr_compliance = true,
            ccpa_compliance = false,
            soc2_compliance = false,
            data_residency = "us",
            breach_notification_enabled = true,
            breach_notification_emails = {"security@company.com"}
        }
    }

    describe("generate_report()", function()
        it("should generate a GDPR compliance report", function()
            local report, err = compliance_reporter.generate_report("gdpr", mock_config, {
                period_start = ngx.time() - 2592000, -- 30 days ago
                period_end = ngx.time(),
                format = "json"
            })

            assert.is_nil(err)
            assert.is_not_nil(report)

            -- Parse JSON report
            local report_data = cjson.decode(report)
            assert.is_not_nil(report_data)
            assert.equal("gdpr", report_data.report_type)
            assert.is_not_nil(report_data.content)
            assert.is_not_nil(report_data.metadata)
        end)

        it("should generate a security audit report", function()
            local report, err = compliance_reporter.generate_report("security_audit", mock_config, {
                period_start = ngx.time() - 604800, -- 7 days ago
                period_end = ngx.time(),
                format = "json"
            })

            assert.is_nil(err)
            assert.is_not_nil(report)

            local report_data = cjson.decode(report)
            assert.equal("security_audit", report_data.report_type)
            assert.is_not_nil(report_data.content.summary)
        end)

        it("should generate a data processing report", function()
            local report, err = compliance_reporter.generate_report("data_processing", mock_config, {
                period_start = ngx.time() - 86400, -- 1 day ago
                period_end = ngx.time(),
                format = "json"
            })

            assert.is_nil(err)
            assert.is_not_nil(report)

            local report_data = cjson.decode(report)
            assert.equal("data_processing", report_data.report_type)
            assert.is_not_nil(report_data.content.summary)
        end)

        it("should generate a privacy audit report", function()
            local report, err = compliance_reporter.generate_report("privacy_audit", mock_config, {
                period_start = ngx.time() - 2592000,
                period_end = ngx.time(),
                format = "json"
            })

            assert.is_nil(err)
            assert.is_not_nil(report)

            local report_data = cjson.decode(report)
            assert.equal("privacy_audit", report_data.report_type)
            assert.is_not_nil(report_data.content.summary)
        end)

        it("should generate a compliance status report", function()
            local report, err = compliance_reporter.generate_report("compliance_status", mock_config, {
                format = "json"
            })

            assert.is_nil(err)
            assert.is_not_nil(report)

            local report_data = cjson.decode(report)
            assert.equal("compliance_status", report_data.report_type)
            assert.is_not_nil(report_data.content.summary)
        end)

        it("should return error for unknown report type", function()
            local report, err = compliance_reporter.generate_report("unknown_type", mock_config)

            assert.is_nil(report)
            assert.is_not_nil(err)
            assert.matches("Unknown report type", err)
        end)

        it("should format report as CSV", function()
            local report, err = compliance_reporter.generate_report("gdpr", mock_config, {
                format = "csv"
            })

            assert.is_nil(err)
            assert.is_not_nil(report)
            assert.matches("Report ID,", report)
        end)

        it("should format report as HTML", function()
            local report, err = compliance_reporter.generate_report("gdpr", mock_config, {
                format = "html"
            })

            assert.is_nil(err)
            assert.is_not_nil(report)
            assert.matches("<!DOCTYPE html>", report)
            assert.matches("Kong Guard AI Compliance Report", report)
        end)

        it("should return error for unsupported format", function()
            local report, err = compliance_reporter.generate_report("gdpr", mock_config, {
                format = "xml"
            })

            assert.is_nil(report)
            assert.is_not_nil(err)
            assert.matches("Unsupported format", err)
        end)
    end)

    describe("_generate_gdpr_report()", function()
        it("should generate GDPR report structure", function()
            local report = compliance_reporter._generate_gdpr_report(mock_config, {
                period_start = ngx.time() - 2592000,
                period_end = ngx.time()
            })

            assert.is_not_nil(report)
            assert.equal("gdpr", report.framework)
            assert.is_table(report.records)
            assert.is_table(report.summary)
            assert.is_number(report.summary.total_data_subjects)
            assert.is_number(report.summary.consent_records)
            assert.is_number(report.summary.data_deletion_requests)
        end)
    end)

    describe("_generate_security_audit_report()", function()
        it("should generate security audit report structure", function()
            local report = compliance_reporter._generate_security_audit_report(mock_config, {
                period_start = ngx.time() - 604800,
                period_end = ngx.time()
            })

            assert.is_not_nil(report)
            assert.equal("security_audit", report.framework)
            assert.is_table(report.records)
            assert.is_table(report.summary)
            assert.is_number(report.summary.total_threats)
            assert.is_number(report.summary.blocked_requests)
            assert.is_number(report.summary.audit_events)
        end)
    end)

    describe("_generate_data_processing_report()", function()
        it("should generate data processing report structure", function()
            local report = compliance_reporter._generate_data_processing_report(mock_config, {
                period_start = ngx.time() - 86400,
                period_end = ngx.time()
            })

            assert.is_not_nil(report)
            assert.equal("data_processing", report.framework)
            assert.is_table(report.records)
            assert.is_table(report.summary)
            assert.is_number(report.summary.total_requests)
            assert.is_number(report.summary.data_processed_gb)
            assert.is_number(report.summary.pii_detected)
        end)
    end)

    describe("_generate_privacy_audit_report()", function()
        it("should generate privacy audit report structure", function()
            local report = compliance_reporter._generate_privacy_audit_report(mock_config, {
                period_start = ngx.time() - 2592000,
                period_end = ngx.time()
            })

            assert.is_not_nil(report)
            assert.equal("gdpr", report.framework)
            assert.is_table(report.records)
            assert.is_table(report.summary)
            assert.is_number(report.summary.pii_detection_accuracy)
            assert.is_number(report.summary.anonymization_effectiveness)
            assert.is_number(report.summary.consent_compliance_rate)
        end)
    end)

    describe("_generate_compliance_status_report()", function()
        it("should generate compliance status report structure", function()
            local report = compliance_reporter._generate_compliance_status_report(mock_config, {})

            assert.is_not_nil(report)
            assert.equal("compliance_status", report.framework)
            assert.is_table(report.records)
            assert.is_table(report.summary)
            assert.is_number(report.summary.overall_compliance_score)
            assert.is_number(report.summary.gdpr_compliance)
            assert.is_number(report.summary.security_compliance)
        end)
    end)

    describe("_check_gdpr_compliance()", function()
        it("should return true for compliant data subject", function()
            local record = {
                consent_status = "granted",
                processing_purposes = {"marketing", "analytics"},
                retention_days = 365
            }

            local compliant = compliance_reporter._check_gdpr_compliance(record)
            assert.is_true(compliant)
        end)

        it("should return false for non-compliant data subject", function()
            local record = {
                consent_status = "denied",
                processing_purposes = {},
                retention_days = 3000 -- Exceeds 7 year limit
            }

            local compliant = compliance_reporter._check_gdpr_compliance(record)
            assert.is_false(compliant)
        end)
    end)

    describe("_calculate_compliance_score()", function()
        it("should calculate compliance score correctly", function()
            local content = {
                records = {
                    {compliance_status = "compliant"},
                    {compliance_status = "compliant"},
                    {compliance_status = "violation"},
                    {gdpr_compliant = true},
                    {gdpr_compliant = false}
                }
            }

            local score = compliance_reporter._calculate_compliance_score(content)
            assert.equal(60, score) -- 3 out of 5 compliant
        end)

        it("should return 100 for empty records", function()
            local content = {records = {}}
            local score = compliance_reporter._calculate_compliance_score(content)
            assert.equal(100, score)
        end)

        it("should return 0 for nil content", function()
            local score = compliance_reporter._calculate_compliance_score(nil)
            assert.equal(0, score)
        end)
    end)

    describe("_count_violations()", function()
        it("should count violations correctly", function()
            local content = {
                records = {
                    {compliance_status = "compliant"},
                    {compliance_status = "violation"},
                    {compliance_status = "violation"},
                    {gdpr_compliant = true},
                    {gdpr_compliant = false}
                }
            }

            local violations = compliance_reporter._count_violations(content)
            assert.equal(3, violations) -- 2 violations + 1 gdpr non-compliant
        end)

        it("should return 0 for no violations", function()
            local content = {
                records = {
                    {compliance_status = "compliant"},
                    {gdpr_compliant = true}
                }
            }

            local violations = compliance_reporter._count_violations(content)
            assert.equal(0, violations)
        end)
    end)

    describe("_generate_recommendations()", function()
        it("should generate GDPR recommendations", function()
            local content = {
                summary = {
                    privacy_violations = 5,
                    data_deletion_requests = 3
                }
            }

            local recommendations = compliance_reporter._generate_recommendations(content, "gdpr")
            assert.is_table(recommendations)
            assert.is_true(#recommendations > 0)
        end)

        it("should generate security audit recommendations", function()
            local content = {
                summary = {
                    blocked_requests = 150,
                    security_incidents = 2
                }
            }

            local recommendations = compliance_reporter._generate_recommendations(content, "security_audit")
            assert.is_table(recommendations)
            assert.is_true(#recommendations > 0)
        end)
    end)

    describe("_calculate_overall_compliance_score()", function()
        it("should calculate average compliance score", function()
            local records = {
                {compliance_score = 80},
                {compliance_score = 90},
                {compliance_score = 70}
            }

            local score = compliance_reporter._calculate_overall_compliance_score(records)
            assert.equal(80, score) -- Average of 80, 90, 70
        end)

        it("should return 100 for empty records", function()
            local score = compliance_reporter._calculate_overall_compliance_score({})
            assert.equal(100, score)
        end)
    end)

    describe("_get_framework_score()", function()
        it("should return framework compliance score", function()
            local records = {
                {framework = "gdpr", compliance_score = 85},
                {framework = "ccpa", compliance_score = 90}
            }

            local gdpr_score = compliance_reporter._get_framework_score(records, "gdpr")
            local ccpa_score = compliance_reporter._get_framework_score(records, "ccpa")
            local unknown_score = compliance_reporter._get_framework_score(records, "unknown")

            assert.equal(85, gdpr_score)
            assert.equal(90, ccpa_score)
            assert.equal(0, unknown_score)
        end)
    end)

    describe("_count_active_violations()", function()
        it("should count total violations across frameworks", function()
            local records = {
                {violations = {"Missing consent", "Data breach"}},
                {violations = {"Incomplete audit"}},
                {violations = {}}
            }

            local count = compliance_reporter._count_active_violations(records)
            assert.equal(3, count)
        end)
    end)

    describe("_count_critical_issues()", function()
        it("should count critical violations", function()
            local records = {
                {violations = {"Critical: Data breach detected", "Minor issue"}},
                {violations = {"Critical security vulnerability"}},
                {violations = {"Normal violation"}}
            }

            local count = compliance_reporter._count_critical_issues(records)
            assert.equal(2, count)
        end)
    end)
end)
