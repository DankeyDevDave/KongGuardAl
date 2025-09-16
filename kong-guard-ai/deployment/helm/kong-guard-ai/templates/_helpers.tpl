{{/*
Expand the name of the chart.
*/}}
{{- define "kong-guard-ai.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kong-guard-ai.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kong-guard-ai.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kong-guard-ai.labels" -}}
helm.sh/chart: {{ include "kong-guard-ai.chart" . }}
{{ include "kong-guard-ai.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kong-guard-ai.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kong-guard-ai.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kong-guard-ai.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kong-guard-ai.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL fullname
*/}}
{{- define "kong-guard-ai.postgresql.fullname" -}}
{{- if .Values.postgresql.enabled }}
{{- include "postgresql.primary.fullname" .Subcharts.postgresql }}
{{- else }}
{{- .Values.kong.env.pg_host }}
{{- end }}
{{- end }}

{{/*
PostgreSQL secret name
*/}}
{{- define "kong-guard-ai.postgresql.secretName" -}}
{{- if .Values.postgresql.enabled }}
{{- include "postgresql.secretName" .Subcharts.postgresql }}
{{- else }}
{{- printf "%s-postgresql" (include "kong-guard-ai.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Redis fullname
*/}}
{{- define "kong-guard-ai.redis.fullname" -}}
{{- if .Values.redis.enabled }}
{{- include "redis.fullname" .Subcharts.redis }}
{{- end }}
{{- end }}

{{/*
Kong Guard AI plugin configuration
*/}}
{{- define "kong-guard-ai.plugin.config" -}}
{{- with .Values.kongGuardAI.config }}
dry_run_mode: {{ .dry_run_mode | default true }}
threat_threshold: {{ .threat_threshold | default 8.0 }}
max_processing_time_ms: {{ .max_processing_time_ms | default 10 }}
enable_rate_limiting_detection: {{ .enable_rate_limiting_detection | default true }}
rate_limit_threshold: {{ .rate_limit_threshold | default 150 }}
rate_limit_window_seconds: {{ .rate_limit_window_seconds | default 60 }}
enable_payload_analysis: {{ .enable_payload_analysis | default true }}
max_payload_size: {{ .max_payload_size | default 262144 }}
enable_auto_blocking: {{ .enable_auto_blocking | default false }}
block_duration_seconds: {{ .block_duration_seconds | default 1800 }}
enable_rate_limiting_response: {{ .enable_rate_limiting_response | default true }}
enable_config_rollback: {{ .enable_config_rollback | default false }}
ai_gateway_enabled: {{ .ai_gateway_enabled | default false }}
ai_gateway_model: {{ .ai_gateway_model | default "gpt-4o-mini" }}
ai_analysis_threshold: {{ .ai_analysis_threshold | default 6.0 }}
ai_timeout_ms: {{ .ai_timeout_ms | default 3000 }}
enable_notifications: {{ .enable_notifications | default true }}
notification_threshold: {{ .notification_threshold | default 7.0 }}
admin_api_enabled: {{ .admin_api_enabled | default false }}
admin_api_timeout_ms: {{ .admin_api_timeout_ms | default 3000 }}
log_level: {{ .log_level | default "info" }}
enable_learning: {{ .enable_learning | default false }}
learning_sample_rate: {{ .learning_sample_rate | default 0.01 }}
{{- if .ip_whitelist }}
ip_whitelist:
{{- range .ip_whitelist }}
  - {{ . | quote }}
{{- end }}
{{- end }}
{{- if .ip_blacklist }}
ip_blacklist:
{{- range .ip_blacklist }}
  - {{ . | quote }}
{{- end }}
{{- end }}
{{- if .suspicious_patterns }}
suspicious_patterns:
{{- range .suspicious_patterns }}
  - {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Environment-specific configuration override
*/}}
{{- define "kong-guard-ai.environment.config" -}}
{{- $env := .Values.environment }}
{{- if hasKey $env .Values.global.environment }}
{{- $envConfig := index $env .Values.global.environment }}
{{- if $envConfig }}
{{- toYaml $envConfig }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create secret data
*/}}
{{- define "kong-guard-ai.secret.data" -}}
{{- if .Values.secrets.aiApiKey }}
ai-api-key: {{ .Values.secrets.aiApiKey | b64enc }}
{{- end }}
{{- if .Values.secrets.slackWebhookUrl }}
slack-webhook-url: {{ .Values.secrets.slackWebhookUrl | b64enc }}
{{- end }}
{{- if .Values.secrets.emailSmtpPassword }}
email-smtp-password: {{ .Values.secrets.emailSmtpPassword | b64enc }}
{{- end }}
{{- if .Values.secrets.externalLogApiKey }}
external-log-api-key: {{ .Values.secrets.externalLogApiKey | b64enc }}
{{- end }}
{{- if .Values.secrets.adminApiKey }}
admin-api-key: {{ .Values.secrets.adminApiKey | b64enc }}
{{- end }}
{{- end }}
