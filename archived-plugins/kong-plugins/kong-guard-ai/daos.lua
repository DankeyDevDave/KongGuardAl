-- Kong Guard AI Plugin DAOs (Data Access Objects)
-- This module defines custom database entities for incident storage and analytics

local typedefs = require "kong.db.schema.typedefs"

-- Incident entity schema for storing security incidents
local incidents = {
  name = "kong_guard_ai_incidents",
  primary_key = { "id" },
  fields = {
    {
      id = {
        type = "uuid",
        default = function() return utils.uuid() end
      }
    },
    {
      created_at = typedefs.auto_timestamp_s,
    },
    {
      updated_at = typedefs.auto_timestamp_s,
    },
    {
      incident_type = {
        type = "string",
        required = true,
        description = "Type of security incident (e.g., rate_limit_exceeded, ip_blacklist_violation)"
      }
    },
    {
      severity = {
        type = "string",
        required = true,
        one_of = { "low", "medium", "high", "critical" },
        default = "medium",
        description = "Incident severity level"
      }
    },
    {
      client_ip = {
        type = "string",
        required = true,
        description = "Client IP address that triggered the incident"
      }
    },
    {
      service_id = {
        type = "foreign",
        reference = "services",
        description = "Associated Kong service ID"
      }
    },
    {
      route_id = {
        type = "foreign",
        reference = "routes",
        description = "Associated Kong route ID"
      }
    },
    {
      consumer_id = {
        type = "foreign",
        reference = "consumers",
        description = "Associated Kong consumer ID"
      }
    },
    {
      request_method = {
        type = "string",
        description = "HTTP method of the request"
      }
    },
    {
      request_path = {
        type = "string",
        description = "Request path that triggered the incident"
      }
    },
    {
      request_headers = {
        type = "map",
        keys = { type = "string" },
        values = { type = "string" },
        description = "Relevant request headers"
      }
    },
    {
      response_status = {
        type = "integer",
        between = { 100, 599 },
        description = "HTTP response status code"
      }
    },
    {
      evidence = {
        type = "map",
        keys = { type = "string" },
        values = { type = "string" },
        description = "Additional evidence data for the incident"
      }
    },
    {
      action_taken = {
        type = "string",
        one_of = { "blocked", "rate_limited", "logged_only", "remediation_applied" },
        default = "logged_only",
        description = "Action taken in response to the incident"
      }
    },
    {
      remediation_id = {
        type = "string",
        description = "ID of applied remediation action"
      }
    },
    {
      false_positive = {
        type = "boolean",
        default = false,
        description = "Whether this incident was marked as a false positive"
      }
    },
    {
      resolved_at = {
        type = "timestamp",
        description = "When the incident was resolved"
      }
    },
    {
      resolved_by = {
        type = "string",
        description = "Who or what resolved the incident"
      }
    }
  }
}

-- Analytics entity for storing aggregated metrics
local analytics = {
  name = "kong_guard_ai_analytics",
  primary_key = { "id" },
  fields = {
    {
      id = {
        type = "uuid",
        default = function() return utils.uuid() end
      }
    },
    {
      created_at = typedefs.auto_timestamp_s,
    },
    {
      updated_at = typedefs.auto_timestamp_s,
    },
    {
      metric_type = {
        type = "string",
        required = true,
        one_of = { "request_rate", "error_rate", "anomaly_score", "threat_level" },
        description = "Type of metric being recorded"
      }
    },
    {
      time_window = {
        type = "string",
        required = true,
        one_of = { "1m", "5m", "15m", "1h", "6h", "24h" },
        description = "Time window for the metric aggregation"
      }
    },
    {
      client_ip = {
        type = "string",
        description = "Client IP (for per-IP metrics)"
      }
    },
    {
      service_id = {
        type = "foreign",
        reference = "services",
        description = "Associated Kong service ID"
      }
    },
    {
      route_id = {
        type = "foreign",
        reference = "routes",
        description = "Associated Kong route ID"
      }
    },
    {
      metric_value = {
        type = "number",
        required = true,
        description = "The computed metric value"
      }
    },
    {
      baseline_value = {
        type = "number",
        description = "Historical baseline for comparison"
      }
    },
    {
      threshold_value = {
        type = "number",
        description = "Threshold that triggers alerts"
      }
    },
    {
      anomaly_detected = {
        type = "boolean",
        default = false,
        description = "Whether this metric triggered an anomaly alert"
      }
    }
  }
}

-- Remediation actions entity for tracking automated responses
local remediations = {
  name = "kong_guard_ai_remediations",
  primary_key = { "id" },
  fields = {
    {
      id = {
        type = "uuid",
        default = function() return utils.uuid() end
      }
    },
    {
      created_at = typedefs.auto_timestamp_s,
    },
    {
      updated_at = typedefs.auto_timestamp_s,
    },
    {
      incident_id = {
        type = "foreign",
        reference = "kong_guard_ai_incidents",
        required = true,
        description = "Associated incident that triggered this remediation"
      }
    },
    {
      remediation_type = {
        type = "string",
        required = true,
        one_of = { "rate_limit", "ip_block", "request_termination", "acl_restriction", "route_modification" },
        description = "Type of remediation action"
      }
    },
    {
      target_entity_type = {
        type = "string",
        required = true,
        one_of = { "consumer", "service", "route", "global" },
        description = "Kong entity type targeted by remediation"
      }
    },
    {
      target_entity_id = {
        type = "string",
        description = "ID of the Kong entity being modified"
      }
    },
    {
      configuration = {
        type = "map",
        keys = { type = "string" },
        values = { type = "string" },
        description = "Remediation configuration parameters"
      }
    },
    {
      status = {
        type = "string",
        required = true,
        one_of = { "pending", "applied", "failed", "rolled_back" },
        default = "pending",
        description = "Current status of the remediation"
      }
    },
    {
      applied_at = {
        type = "timestamp",
        description = "When the remediation was successfully applied"
      }
    },
    {
      rolled_back_at = {
        type = "timestamp",
        description = "When the remediation was rolled back"
      }
    },
    {
      admin_api_response = {
        type = "map",
        keys = { type = "string" },
        values = { type = "string" },
        description = "Response from Kong Admin API when applying remediation"
      }
    },
    {
      auto_rollback_at = {
        type = "timestamp",
        description = "Scheduled time for automatic rollback"
      }
    },
    {
      confirmed_by_operator = {
        type = "boolean",
        default = false,
        description = "Whether an operator has confirmed this remediation"
      }
    }
  }
}

-- Return the DAOs for registration
return {
  incidents,
  analytics,
  remediations
}
