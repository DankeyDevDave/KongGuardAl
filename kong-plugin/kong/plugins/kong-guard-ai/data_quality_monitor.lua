--- Data Quality Monitoring Module for Kong Guard AI
-- Monitors data quality metrics, detects anomalies, and provides quality assessments

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local math = math
local table = table

-- Quality dimensions
local QUALITY_DIMENSIONS = {
    ACCURACY = "accuracy",
    COMPLETENESS = "completeness",
    CONSISTENCY = "consistency",
    TIMELINESS = "timeliness",
    VALIDITY = "validity",
    UNIQUENESS = "uniqueness"
}

-- Quality metrics
local QUALITY_METRICS = {
    -- Accuracy metrics
    error_rate = {dimension = QUALITY_DIMENSIONS.ACCURACY, threshold = 0.05},
    validation_errors = {dimension = QUALITY_DIMENSIONS.ACCURACY, threshold = 0.10},

    -- Completeness metrics
    null_values = {dimension = QUALITY_DIMENSIONS.COMPLETENESS, threshold = 0.20},
    missing_fields = {dimension = QUALITY_DIMENSIONS.COMPLETENESS, threshold = 0.15},

    -- Consistency metrics
    format_inconsistencies = {dimension = QUALITY_DIMENSIONS.CONSISTENCY, threshold = 0.10},
    value_inconsistencies = {dimension = QUALITY_DIMENSIONS.CONSISTENCY, threshold = 0.08},

    -- Timeliness metrics
    data_age = {dimension = QUALITY_DIMENSIONS.TIMELINESS, threshold = 86400}, -- 24 hours
    processing_delay = {dimension = QUALITY_DIMENSIONS.TIMELINESS, threshold = 300}, -- 5 minutes

    -- Validity metrics
    invalid_formats = {dimension = QUALITY_DIMENSIONS.VALIDITY, threshold = 0.12},
    constraint_violations = {dimension = QUALITY_DIMENSIONS.VALIDITY, threshold = 0.05},

    -- Uniqueness metrics
    duplicate_records = {dimension = QUALITY_DIMENSIONS.UNIQUENESS, threshold = 0.05},
    duplicate_values = {dimension = QUALITY_DIMENSIONS.UNIQUENESS, threshold = 0.10}
}

-- Quality assessment levels
local QUALITY_LEVELS = {
    EXCELLENT = {min_score = 95, label = "Excellent", color = "green"},
    GOOD = {min_score = 85, label = "Good", color = "blue"},
    FAIR = {min_score = 70, label = "Fair", color = "yellow"},
    POOR = {min_score = 50, label = "Poor", color = "orange"},
    CRITICAL = {min_score = 0, label = "Critical", color = "red"}
}

--- Create a new data quality monitor instance
function _M.new(config)
    local self = {
        config = config or {},
        quality_metrics = {},
        quality_history = {},
        anomaly_detection = {},
        quality_profiles = {},
        alerts = {},
        enable_anomaly_detection = config.enable_anomaly_detection or false,
        alert_thresholds = config.alert_thresholds or {},
        monitoring_window = config.monitoring_window or 3600, -- 1 hour
        retention_days = config.retention_days or 30
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the quality monitor
function _M:init()
    -- Set up periodic quality assessment
    local ok, err = ngx.timer.every(300, function() -- Every 5 minutes
        self:_perform_quality_assessment()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize quality assessment: ", err)
    end

    -- Set up cleanup of old quality data
    local ok2, err2 = ngx.timer.every(3600, function() -- Every hour
        self:_cleanup_old_quality_data()
    end)

    if not ok2 then
        kong.log.err("[kong-guard-ai] Failed to initialize quality cleanup: ", err2)
    end

    kong.log.info("[kong-guard-ai] Data quality monitor initialized")
end

--- Monitor data quality for a request/response
function _M:monitor_data_quality(data, context, data_type)
    if not data then
        return {}
    end

    local quality_check = {
        data_id = context.data_id or ngx.md5(cjson.encode(data)),
        timestamp = ngx.now(),
        data_type = data_type or "unknown",
        metrics = {},
        issues = {},
        recommendations = {}
    }

    -- Perform quality checks based on data type
    if data_type == "request" then
        quality_check.metrics = self:_check_request_quality(data, context)
    elseif data_type == "response" then
        quality_check.metrics = self:_check_response_quality(data, context)
    elseif data_type == "user_data" then
        quality_check.metrics = self:_check_user_data_quality(data, context)
    else
        quality_check.metrics = self:_check_generic_data_quality(data, context)
    end

    -- Calculate overall quality score
    quality_check.overall_score = self:_calculate_overall_quality_score(quality_check.metrics)

    -- Identify quality issues
    quality_check.issues = self:_identify_quality_issues(quality_check.metrics)

    -- Generate recommendations
    quality_check.recommendations = self:_generate_quality_recommendations(quality_check.issues)

    -- Store quality metrics
    self:_store_quality_metrics(quality_check)

    -- Check for anomalies
    if self.enable_anomaly_detection then
        quality_check.anomalies = self:_detect_quality_anomalies(quality_check)
    end

    -- Generate alerts if needed
    self:_check_quality_alerts(quality_check)

    kong.log.debug("[kong-guard-ai] Data quality monitored: ", {
        data_id = quality_check.data_id,
        overall_score = quality_check.overall_score,
        issues_count = #quality_check.issues
    })

    return quality_check
end

--- Check request data quality
function _M:_check_request_quality(data, context)
    local metrics = {}

    -- Check for required fields
    metrics.missing_fields = self:_check_missing_fields(data, {"method", "path"})

    -- Check data format validity
    metrics.invalid_formats = self:_check_format_validity(data)

    -- Check for null/empty values
    metrics.null_values = self:_check_null_values(data)

    -- Check data consistency
    metrics.consistency_issues = self:_check_data_consistency(data, context)

    -- Check timeliness
    metrics.timeliness_score = self:_check_timeliness(context.timestamp, ngx.now())

    return metrics
end

--- Check response data quality
function _M:_check_response_quality(data, context)
    local metrics = {}

    -- Check response format
    metrics.format_validity = self:_check_response_format(data)

    -- Check data completeness
    metrics.completeness_score = self:_check_data_completeness(data)

    -- Check for error responses
    metrics.error_rate = self:_check_error_rate(data, context)

    -- Check response time
    metrics.response_timeliness = self:_check_response_timeliness(context.processing_time)

    -- Check data consistency with request
    if context.request_data then
        metrics.request_response_consistency = self:_check_request_response_consistency(context.request_data, data)
    end

    return metrics
end

--- Check user data quality
function _M:_check_user_data_quality(data, context)
    local metrics = {}

    -- Check PII data quality
    metrics.pii_quality = self:_check_pii_data_quality(data)

    -- Check data uniqueness
    metrics.uniqueness_score = self:_check_data_uniqueness(data)

    -- Check data accuracy
    metrics.accuracy_score = self:_check_data_accuracy(data)

    -- Check consent data quality
    if data.consent_data then
        metrics.consent_quality = self:_check_consent_data_quality(data.consent_data)
    end

    -- Check data retention compliance
    metrics.retention_compliance = self:_check_retention_compliance(data, context)

    return metrics
end

--- Check generic data quality
function _M:_check_generic_data_quality(data, context)
    local metrics = {}

    -- Basic quality checks
    metrics.completeness = self:_calculate_completeness(data)
    metrics.validity = self:_calculate_validity(data)
    metrics.consistency = self:_calculate_consistency(data)

    return metrics
end

--- Quality check helper functions

function _M:_check_missing_fields(data, required_fields)
    local missing = {}
    for _, field in ipairs(required_fields) do
        if not data[field] then
            table.insert(missing, field)
        end
    end
    return {
        count = #missing,
        fields = missing,
        percentage = #missing / #required_fields
    }
end

function _M:_check_format_validity(data)
    local invalid = {}

    -- Check email format
    if data.email and not string.match(data.email, "^[%w._-]+@[%w._-]+%.[%w]+$") then
        table.insert(invalid, "email")
    end

    -- Check phone format
    if data.phone and not string.match(data.phone, "^%+?[%d%s%-%(%)]+$") then
        table.insert(invalid, "phone")
    end

    -- Check date format
    if data.date and not string.match(data.date, "^%d%d%d%d%-%d%d%-%d%d$") then
        table.insert(invalid, "date")
    end

    return {
        count = #invalid,
        fields = invalid,
        percentage = #invalid / self:_count_table_fields(data)
    }
end

function _M:_check_null_values(data)
    local null_count = 0
    local total_fields = 0

    local function check_table(tbl)
        for key, value in pairs(tbl) do
            total_fields = total_fields + 1
            if value == nil or value == "" then
                null_count = null_count + 1
            elseif type(value) == "table" then
                check_table(value)
            end
        end
    end

    check_table(data)

    return {
        count = null_count,
        total_fields = total_fields,
        percentage = total_fields > 0 and null_count / total_fields or 0
    }
end

function _M:_check_data_consistency(data, context)
    local inconsistencies = {}

    -- Check for conflicting values
    if data.start_date and data.end_date and data.start_date > data.end_date then
        table.insert(inconsistencies, "start_date after end_date")
    end

    -- Check for logical inconsistencies
    if data.age and (data.age < 0 or data.age > 150) then
        table.insert(inconsistencies, "invalid age value")
    end

    return {
        count = #inconsistencies,
        issues = inconsistencies
    }
end

function _M:_check_timeliness(data_timestamp, current_timestamp)
    local age = current_timestamp - (data_timestamp or current_timestamp)
    local max_age = QUALITY_METRICS.data_age.threshold

    return {
        age_seconds = age,
        within_threshold = age <= max_age,
        score = math.max(0, 100 - (age / max_age) * 100)
    }
end

function _M:_check_response_format(data)
    -- Check if response is properly formatted
    local is_valid = true
    local issues = {}

    if type(data) ~= "table" then
        is_valid = false
        table.insert(issues, "response is not a valid object")
    end

    return {
        is_valid = is_valid,
        issues = issues
    }
end

function _M:_check_data_completeness(data)
    local total_fields = self:_count_table_fields(data)
    local filled_fields = 0

    for _, value in pairs(data) do
        if value ~= nil and value ~= "" then
            filled_fields = filled_fields + 1
        end
    end

    return {
        total_fields = total_fields,
        filled_fields = filled_fields,
        completeness_percentage = total_fields > 0 and (filled_fields / total_fields) * 100 or 100
    }
end

function _M:_check_error_rate(data, context)
    -- Check for error indicators in response
    local has_error = false
    local error_indicators = {"error", "Error", "ERROR", "exception", "Exception"}

    if type(data) == "table" then
        for _, indicator in ipairs(error_indicators) do
            if data[indicator] then
                has_error = true
                break
            end
        end
    end

    return {
        has_error = has_error,
        error_rate = has_error and 1.0 or 0.0
    }
end

function _M:_check_response_timeliness(processing_time)
    local max_time = QUALITY_METRICS.processing_delay.threshold

    return {
        processing_time_ms = processing_time,
        within_threshold = processing_time <= max_time,
        score = math.max(0, 100 - (processing_time / max_time) * 100)
    }
end

function _M:_check_request_response_consistency(request_data, response_data)
    -- Check if response is consistent with request
    local consistency_score = 100

    -- Simple consistency checks
    if request_data.method == "GET" and type(response_data) ~= "table" then
        consistency_score = consistency_score - 20
    end

    return {
        score = consistency_score,
        is_consistent = consistency_score >= 80
    }
end

function _M:_check_pii_data_quality(data)
    -- Check quality of PII data
    local pii_fields = {"email", "phone", "ssn", "credit_card", "name", "address"}
    local pii_quality = {}

    for _, field in ipairs(pii_fields) do
        if data[field] then
            pii_quality[field] = self:_assess_pii_field_quality(data[field], field)
        end
    end

    return pii_quality
end

function _M:_assess_pii_field_quality(value, field_type)
    if field_type == "email" then
        return string.match(value, "^[%w._-]+@[%w._-]+%.[%w]+$") and 100 or 0
    elseif field_type == "phone" then
        return string.match(value, "^%+?[%d%s%-%(%)]{10,}$") and 100 or 0
    elseif field_type == "ssn" then
        return string.match(value, "^%d{3}%-%d{2}%-%d{4}$") and 100 or 0
    else
        return value and #tostring(value) > 0 and 100 or 0
    end
end

function _M:_check_data_uniqueness(data)
    -- Check for duplicate values in data
    local values_seen = {}
    local duplicates = {}

    local function check_duplicates(tbl, path)
        for key, value in pairs(tbl) do
            local current_path = path and (path .. "." .. key) or key

            if type(value) == "table" then
                check_duplicates(value, current_path)
            else
                local value_key = tostring(value)
                if values_seen[value_key] then
                    table.insert(duplicates, {
                        field = current_path,
                        value = value,
                        duplicate_of = values_seen[value_key]
                    })
                else
                    values_seen[value_key] = current_path
                end
            end
        end
    end

    check_duplicates(data)

    return {
        duplicate_count = #duplicates,
        duplicates = duplicates,
        uniqueness_score = math.max(0, 100 - (#duplicates * 10))
    }
end

function _M:_check_data_accuracy(data)
    -- Basic accuracy checks
    local accuracy_score = 100
    local issues = {}

    -- Check for obviously invalid values
    if data.age and (data.age < 0 or data.age > 150) then
        accuracy_score = accuracy_score - 20
        table.insert(issues, "invalid age value")
    end

    if data.salary and data.salary < 0 then
        accuracy_score = accuracy_score - 20
        table.insert(issues, "negative salary value")
    end

    return {
        score = accuracy_score,
        issues = issues
    }
end

function _M:_check_consent_data_quality(consent_data)
    local quality_score = 100
    local issues = {}

    -- Check consent record completeness
    if not consent_data.purpose then
        quality_score = quality_score - 15
        table.insert(issues, "missing consent purpose")
    end

    if not consent_data.timestamp then
        quality_score = quality_score - 15
        table.insert(issues, "missing consent timestamp")
    end

    -- Check consent validity
    if consent_data.expires_at and ngx.now() > consent_data.expires_at then
        quality_score = quality_score - 25
        table.insert(issues, "expired consent")
    end

    return {
        score = quality_score,
        issues = issues
    }
end

function _M:_check_retention_compliance(data, context)
    -- Check if data retention policies are being followed
    local compliance_score = 100

    if context.created_at then
        local data_age = ngx.now() - context.created_at
        local max_age = context.retention_days and (context.retention_days * 24 * 60 * 60) or (365 * 24 * 60 * 60) -- 1 year default

        if data_age > max_age then
            compliance_score = 0
        elseif data_age > (max_age * 0.8) then
            compliance_score = 50
        end
    end

    return {
        score = compliance_score,
        within_retention = compliance_score > 0
    }
end

function _M:_calculate_completeness(data)
    return self:_check_data_completeness(data).completeness_percentage
end

function _M:_calculate_validity(data)
    local format_check = self:_check_format_validity(data)
    return 100 - (format_check.percentage * 100)
end

function _M:_calculate_consistency(data)
    local consistency_check = self:_check_data_consistency(data, {})
    return 100 - (consistency_check.count * 10)
end

function _M:_calculate_overall_quality_score(metrics)
    local total_score = 0
    local metric_count = 0

    for _, metric in pairs(metrics) do
        if type(metric) == "table" and metric.score then
            total_score = total_score + metric.score
            metric_count = metric_count + 1
        elseif type(metric) == "number" then
            total_score = total_score + metric
            metric_count = metric_count + 1
        end
    end

    return metric_count > 0 and (total_score / metric_count) or 100
end

function _M:_identify_quality_issues(metrics)
    local issues = {}

    for metric_name, metric in pairs(metrics) do
        if QUALITY_METRICS[metric_name] then
            local threshold = QUALITY_METRICS[metric_name].threshold
            local value = metric.percentage or metric.score or metric.count or 0

            if metric_name:match("error") or metric_name:match("invalid") or metric_name:match("missing") then
                if value > threshold then
                    table.insert(issues, {
                        metric = metric_name,
                        severity = "high",
                        value = value,
                        threshold = threshold,
                        description = string.format("%s exceeds threshold (%.2f > %.2f)", metric_name, value, threshold)
                    })
                end
            elseif metric_name:match("score") or metric_name:match("percentage") then
                if value < threshold then
                    table.insert(issues, {
                        metric = metric_name,
                        severity = "medium",
                        value = value,
                        threshold = threshold,
                        description = string.format("%s below threshold (%.2f < %.2f)", metric_name, value, threshold)
                    })
                end
            end
        end
    end

    return issues
end

function _M:_generate_quality_recommendations(issues)
    local recommendations = {}

    for _, issue in ipairs(issues) do
        if issue.metric:match("missing") then
            table.insert(recommendations, "Implement data validation to prevent missing required fields")
        elseif issue.metric:match("invalid") then
            table.insert(recommendations, "Add format validation for data inputs")
        elseif issue.metric:match("error") then
            table.insert(recommendations, "Review error handling and logging mechanisms")
        elseif issue.metric:match("completeness") then
            table.insert(recommendations, "Implement data completeness checks and alerts")
        elseif issue.metric:match("consistency") then
            table.insert(recommendations, "Add data consistency validation rules")
        end
    end

    -- Remove duplicates
    local unique_recommendations = {}
    for _, rec in ipairs(recommendations) do
        unique_recommendations[rec] = true
    end

    local final_recommendations = {}
    for rec in pairs(unique_recommendations) do
        table.insert(final_recommendations, rec)
    end

    return final_recommendations
end

function _M:_store_quality_metrics(quality_check)
    local data_id = quality_check.data_id

    if not self.quality_metrics[data_id] then
        self.quality_metrics[data_id] = {}
    end

    table.insert(self.quality_metrics[data_id], quality_check)

    -- Limit history to prevent unbounded growth
    if #self.quality_metrics[data_id] > 100 then
        table.remove(self.quality_metrics[data_id], 1)
    end
end

function _M:_detect_quality_anomalies(quality_check)
    local anomalies = {}

    -- Compare with historical data
    local history = self.quality_metrics[quality_check.data_id] or {}
    if #history < 5 then
        return anomalies -- Need minimum history for anomaly detection
    end

    -- Calculate baseline from recent history
    local recent_scores = {}
    for i = #history - 4, #history - 1 do
        table.insert(recent_scores, history[i].overall_score)
    end

    local baseline_avg = self:_calculate_average(recent_scores)
    local baseline_std = self:_calculate_standard_deviation(recent_scores, baseline_avg)

    -- Check for anomalies
    local score_diff = math.abs(quality_check.overall_score - baseline_avg)
    if score_diff > (baseline_std * 2) then
        table.insert(anomalies, {
            type = "quality_score_anomaly",
            severity = score_diff > (baseline_std * 3) and "high" or "medium",
            description = string.format("Quality score deviation: %.2f (baseline: %.2f ± %.2f)",
                quality_check.overall_score, baseline_avg, baseline_std),
            current_value = quality_check.overall_score,
            baseline = baseline_avg,
            threshold = baseline_std * 2
        })
    end

    return anomalies
end

function _M:_check_quality_alerts(quality_check)
    -- Check if quality issues require alerts
    if #quality_check.issues > 0 then
        local alert = {
            alert_id = ngx.md5(quality_check.data_id .. quality_check.timestamp),
            data_id = quality_check.data_id,
            timestamp = quality_check.timestamp,
            severity = "medium",
            issues = quality_check.issues,
            recommendations = quality_check.recommendations,
            quality_score = quality_check.overall_score
        }

        -- Determine severity based on quality score and issues
        if quality_check.overall_score < 50 or #quality_check.issues > 3 then
            alert.severity = "high"
        elseif quality_check.overall_score < 70 or #quality_check.issues > 1 then
            alert.severity = "medium"
        else
            alert.severity = "low"
        end

        table.insert(self.alerts, alert)

        kong.log.warn("[kong-guard-ai] Quality alert generated: ", {
            alert_id = alert.alert_id,
            severity = alert.severity,
            issues_count = #quality_check.issues,
            quality_score = quality_check.overall_score
        })
    end
end

function _M:_perform_quality_assessment()
    -- Perform periodic quality assessment across all monitored data
    local assessment = {
        timestamp = ngx.now(),
        total_data_points = 0,
        average_quality_score = 0,
        quality_distribution = {},
        top_issues = {},
        recommendations = {}
    }

    local total_score = 0
    local issue_counts = {}

    for data_id, metrics in pairs(self.quality_metrics) do
        if #metrics > 0 then
            local latest = metrics[#metrics]
            assessment.total_data_points = assessment.total_data_points + 1
            total_score = total_score + latest.overall_score

            -- Count issues
            for _, issue in ipairs(latest.issues) do
                issue_counts[issue.metric] = (issue_counts[issue.metric] or 0) + 1
            end
        end
    end

    if assessment.total_data_points > 0 then
        assessment.average_quality_score = total_score / assessment.total_data_points
    end

    -- Get top issues
    local sorted_issues = {}
    for metric, count in pairs(issue_counts) do
        table.insert(sorted_issues, {metric = metric, count = count})
    end

    table.sort(sorted_issues, function(a, b) return a.count > b.count end)

    for i = 1, math.min(5, #sorted_issues) do
        table.insert(assessment.top_issues, sorted_issues[i])
    end

    -- Store assessment
    if not self.quality_history then
        self.quality_history = {}
    end
    table.insert(self.quality_history, assessment)

    -- Limit history
    if #self.quality_history > 100 then
        table.remove(self.quality_history, 1)
    end

    kong.log.info("[kong-guard-ai] Quality assessment completed: ", {
        data_points = assessment.total_data_points,
        average_score = string.format("%.2f", assessment.average_quality_score),
        top_issues = #assessment.top_issues
    })
end

--- Utility functions

function _M:_count_table_fields(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

function _M:_calculate_average(values)
    if #values == 0 then return 0 end

    local sum = 0
    for _, value in ipairs(values) do
        sum = sum + value
    end

    return sum / #values
end

function _M:_calculate_standard_deviation(values, mean)
    if #values <= 1 then return 0 end

    local sum_squared_diff = 0
    for _, value in ipairs(values) do
        local diff = value - mean
        sum_squared_diff = sum_squared_diff + (diff * diff)
    end

    return math.sqrt(sum_squared_diff / (#values - 1))
end

function _M:_cleanup_old_quality_data()
    local current_time = ngx.now()
    local retention_seconds = self.retention_days * 24 * 60 * 60
    local cleaned = 0

    -- Clean quality metrics
    for data_id, metrics in pairs(self.quality_metrics) do
        local filtered_metrics = {}
        for _, metric in ipairs(metrics) do
            if current_time - metric.timestamp <= retention_seconds then
                table.insert(filtered_metrics, metric)
            end
        end

        if #filtered_metrics == 0 then
            self.quality_metrics[data_id] = nil
            cleaned = cleaned + 1
        else
            self.quality_metrics[data_id] = filtered_metrics
        end
    end

    -- Clean alerts
    local filtered_alerts = {}
    for _, alert in ipairs(self.alerts) do
        if current_time - alert.timestamp <= retention_seconds then
            table.insert(filtered_alerts, alert)
        end
    end
    self.alerts = filtered_alerts

    if cleaned > 0 then
        kong.log.info("[kong-guard-ai] Cleaned up ", cleaned, " old quality records")
    end
end

--- Get quality assessment for data
function _M:get_quality_assessment(data_id, time_range)
    local metrics = self.quality_metrics[data_id]
    if not metrics then
        return nil
    end

    if time_range then
        local current_time = ngx.now()
        metrics = {}
        for _, metric in ipairs(self.quality_metrics[data_id]) do
            if current_time - metric.timestamp <= time_range then
                table.insert(metrics, metric)
            end
        end
    end

    if #metrics == 0 then
        return nil
    end

    -- Calculate assessment
    local assessment = {
        data_id = data_id,
        total_checks = #metrics,
        latest_score = metrics[#metrics].overall_score,
        average_score = 0,
        trend = "stable",
        issues_summary = {},
        recommendations = {}
    }

    local total_score = 0
    for _, metric in ipairs(metrics) do
        total_score = total_score + metric.overall_score

        -- Aggregate issues
        for _, issue in ipairs(metric.issues) do
            assessment.issues_summary[issue.metric] = (assessment.issues_summary[issue.metric] or 0) + 1
        end
    end

    assessment.average_score = total_score / #metrics

    -- Determine trend
    if #metrics >= 2 then
        local recent_avg = 0
        local older_avg = 0

        for i = #metrics - 2, #metrics do
            if metrics[i] then
                recent_avg = recent_avg + metrics[i].overall_score
            end
        end
        recent_avg = recent_avg / 3

        for i = 1, math.min(3, #metrics - 3) do
            older_avg = older_avg + metrics[i].overall_score
        end
        older_avg = older_avg / math.min(3, #metrics - 3)

        if recent_avg > older_avg + 5 then
            assessment.trend = "improving"
        elseif recent_avg < older_avg - 5 then
            assessment.trend = "declining"
        end
    end

    return assessment
end

--- Get overall quality statistics
function _M:get_quality_statistics()
    local stats = {
        total_data_points = self:_count_table_fields(self.quality_metrics),
        total_alerts = #self.alerts,
        average_quality_score = 0,
        quality_distribution = {},
        top_issues = {},
        recent_assessments = #self.quality_history
    }

    -- Calculate average quality score
    local total_score = 0
    local score_count = 0

    for _, metrics in pairs(self.quality_metrics) do
        for _, metric in ipairs(metrics) do
            total_score = total_score + metric.overall_score
            score_count = score_count + 1
        end
    end

    if score_count > 0 then
        stats.average_quality_score = total_score / score_count
    end

    -- Get quality distribution
    for _, level in pairs(QUALITY_LEVELS) do
        stats.quality_distribution[level.label] = 0
    end

    for _, metrics in pairs(self.quality_metrics) do
        if #metrics > 0 then
            local latest_score = metrics[#metrics].overall_score
            for _, level in pairs(QUALITY_LEVELS) do
                if latest_score >= level.min_score then
                    stats.quality_distribution[level.label] = stats.quality_distribution[level.label] + 1
                    break
                end
            end
        end
    end

    return stats
end

return _M