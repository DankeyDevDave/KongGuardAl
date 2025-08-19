# Kong Guard AI - Autonomous API Threat Response Agent

An advanced Kong plugin that provides real-time, AI-driven API threat monitoring, incident classification, and automated remediation for Kong Gateway 3.x+.

## 🏗️ Architecture Overview

Kong Guard AI is built as a native Kong plugin following Kong's best practices for performance and extensibility. The plugin architecture consists of several modular components:

### Core Components

```
kong-guard-ai/
├── kong/
│   └── plugins/
│       └── kong-guard-ai/
│           ├── handler.lua       # Main plugin lifecycle handler
│           ├── schema.lua        # Configuration schema
│           ├── detector.lua      # Threat detection engine
│           ├── responder.lua     # Automated response system
│           ├── notifier.lua      # Notification system
│           └── ai_gateway.lua    # AI Gateway integration
└── kong-plugin-kong-guard-ai-0.1.0-1.rockspec  # LuaRocks package
```

### Plugin Lifecycle Hooks

The plugin implements Kong's standard lifecycle phases:

1. **`init_worker`** - Initialize threat detection models and shared memory
2. **`access`** - Real-time traffic analysis and threat detection (<10ms)
3. **`header_filter`** - Response header analysis for upstream anomalies
4. **`response`** - Full response analysis and pattern learning
5. **`log`** - Incident logging and notification triggering

## 🔧 Technical Architecture

### Performance Design
- **Sub-10ms latency** under 5,000+ RPS per node
- **Stateless design** using Kong's shared memory and cache
- **Async notifications** to prevent blocking request processing
- **Efficient pattern matching** with compiled regex patterns
- **Smart caching** to avoid duplicate AI analyses

### Threat Detection Engine (`detector.lua`)

Implements multi-layer threat detection:

- **IP Reputation Analysis** - Whitelist/blacklist checking and repeat offender tracking
- **Rate Limiting Detection** - DDoS and abuse pattern identification
- **Payload Analysis** - SQL injection, XSS, and injection attack detection
- **Behavioral Analysis** - Anomalous request pattern detection
- **AI-Powered Analysis** - Advanced threat detection via Kong AI Gateway

### Automated Response System (`responder.lua`)

Provides graduated response capabilities:

- **Blocking** - Immediate request rejection with custom error responses
- **Rate Limiting** - Dynamic rate limit application via Admin API
- **Monitoring** - Enhanced logging and tracking for suspicious activity
- **Config Rollback** - Automatic Kong configuration rollback for critical threats
- **Header Modification** - Security header injection and sanitization

### Notification System (`notifier.lua`)

Multi-channel alert delivery:

- **Slack Integration** - Rich threat notifications with threat details
- **Email Notifications** - SMTP-based email alerts (configurable)
- **Webhook Delivery** - Custom webhook endpoints for integration
- **External Logging** - Integration with log aggregation systems

### AI Gateway Integration (`ai_gateway.lua`)

Advanced AI-powered threat analysis:

- **LLM-Based Detection** - Use GPT-4, Claude, or other models via Kong AI Gateway
- **Behavioral Analysis** - AI-powered anomaly detection
- **Payload Analysis** - Deep content analysis for complex attacks
- **Feedback Loop** - Operator feedback for continuous learning

## 📋 Configuration Schema

The plugin supports comprehensive configuration through Kong's standard schema system:

### Core Settings
- `dry_run_mode` - Testing mode (logs but doesn't block)
- `threat_threshold` - Threat level threshold for responses (1-10)
- `max_processing_time_ms` - Performance limit enforcement

### Detection Settings
- `enable_rate_limiting_detection` - Rate-based threat detection
- `enable_ip_reputation` - IP whitelist/blacklist checking
- `enable_payload_analysis` - Request payload inspection
- `suspicious_patterns` - Custom regex patterns for threat detection

### AI Gateway Settings
- `ai_gateway_enabled` - Enable AI-powered analysis
- `ai_gateway_model` - AI model selection (GPT-4, Claude, etc.)
- `ai_analysis_threshold` - Threat level for triggering AI analysis

### Response Settings
- `enable_auto_blocking` - Automatic IP blocking
- `enable_rate_limiting_response` - Dynamic rate limiting
- `enable_config_rollback` - Automatic configuration rollback
- `block_duration_seconds` - Duration for blocking threats

### Notification Settings
- `slack_webhook_url` - Slack integration endpoint
- `email_smtp_server` - Email notification configuration
- `webhook_urls` - Custom webhook endpoints

## 🚀 Installation

### Prerequisites
- Kong Gateway 3.x+ (OSS or Enterprise)
- LuaRocks package manager
- Lua 5.1+ runtime

### Install via LuaRocks

```bash
# Build and install the plugin
cd kong-guard-ai
luarocks make

# Install from package
luarocks install kong-plugin-kong-guard-ai-0.1.0-1.rockspec
```

### Enable Plugin in Kong

Add the plugin to your Kong configuration:

```yaml
# kong.conf
plugins = bundled,kong-guard-ai
```

Or via environment variable:

```bash
export KONG_PLUGINS=bundled,kong-guard-ai
```

### Configure Plugin

#### Via Kong Admin API

```bash
curl -X POST http://localhost:8001/plugins \
  --data "name=kong-guard-ai" \
  --data "config.dry_run_mode=false" \
  --data "config.threat_threshold=7.0" \
  --data "config.enable_notifications=true" \
  --data "config.slack_webhook_url=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

#### Via Declarative Configuration

```yaml
# kong.yml
plugins:
- name: kong-guard-ai
  config:
    dry_run_mode: false
    threat_threshold: 7.0
    enable_notifications: true
    slack_webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    ai_gateway_enabled: true
    ai_gateway_model: "gpt-4"
    enable_auto_blocking: true
    block_duration_seconds: 3600
```

## 🛡️ Security Features

### Real-Time Threat Detection
- SQL injection pattern matching
- Cross-site scripting (XSS) detection
- Command injection identification
- Path traversal detection
- Rate limiting violation detection
- IP reputation checking

### Automated Response Actions
- Immediate request blocking
- Dynamic rate limiting
- IP address blocking
- Configuration rollback
- Response sanitization

### AI-Powered Analysis
- Advanced payload analysis
- Behavioral anomaly detection
- Context-aware threat assessment
- Continuous learning from feedback

## 📊 Monitoring and Metrics

The plugin provides comprehensive monitoring capabilities:

### Built-in Endpoints
- `/_guard_ai/status` - Plugin health and status
- `/_guard_ai/metrics` - Performance and threat metrics

### Metrics Available
- Total threats detected
- Response actions taken
- Processing time statistics
- AI analysis metrics
- Notification delivery status

### Integration with Kong Analytics
- Compatible with Kong's built-in analytics
- Exports to Prometheus, Datadog, etc.
- Custom log integration support

## 🔧 Development and Testing

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourorg/kong-guard-ai
cd kong-guard-ai

# Install development dependencies
luarocks install busted
luarocks install kong

# Run tests
busted spec/
```

### Docker Development Environment

```bash
# Start Kong with plugin
docker-compose up -d

# Test plugin functionality
curl -X GET http://localhost:8000/test \
  -H "X-Test-Attack: <script>alert('xss')</script>"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

Apache 2.0 License - see LICENSE file for details.

## 🙏 Acknowledgments

- Kong Inc. for the excellent Kong Gateway platform
- Kong community for plugin development best practices
- Security research community for threat intelligence