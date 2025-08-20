# Kong Guard AI - Enhanced AI Gateway Integration

## Overview

The Enhanced AI Gateway Integration provides production-ready LLM-powered threat analysis with comprehensive multi-model support, intelligent cost optimization, and advanced behavioral analytics.

## Key Features

### 🤖 Multi-Model AI Support
- **GPT-4 Turbo**: Advanced reasoning for complex threat analysis
- **Claude 3 Sonnet**: Superior contextual understanding and behavioral analysis  
- **Gemini 1.5 Pro**: Cost-effective analysis with excellent performance
- **Automatic Failover**: Seamless switching between models for reliability

### 🎯 Intelligent Analysis Types
- **Standard Threat Detection**: Basic injection and attack pattern analysis
- **Behavioral Analysis**: Session-based anomaly detection and automation identification
- **Payload Analysis**: Deep inspection of request payloads for sophisticated attacks
- **Contextual Assessment**: Multi-dimensional analysis incorporating historical data

### 💰 Cost Optimization
- **Risk-Based Sampling**: Analyze 100% of high-risk, 50% of medium-risk, 10% of low-risk requests
- **Intelligent Caching**: TTL-based caching with analysis-type specific expiration
- **Daily Cost Limits**: Configurable spending caps with automatic throttling
- **Model Selection**: Optimal model routing based on analysis requirements and cost

### 🔄 Continuous Learning
- **Feedback Collection**: Security analyst feedback integration
- **False Positive/Negative Tracking**: Automated learning from outcomes
- **Model Performance Monitoring**: Real-time reliability and latency tracking
- **Adaptive Improvements**: Dynamic optimization based on historical performance

## Configuration

### Basic Setup

```json
{
  "ai_gateway_enabled": true,
  "ai_gpt4_enabled": true,
  "ai_claude_enabled": true,
  "openai_api_key": "sk-...",
  "anthropic_api_key": "sk-ant-...",
  "ai_cost_optimization_enabled": true,
  "ai_max_daily_cost": 100.0
}
```

### Model-Specific Configuration

```json
{
  "openai_endpoint": "https://api.openai.com/v1/chat/completions",
  "anthropic_endpoint": "https://api.anthropic.com/v1/messages", 
  "gemini_endpoint": "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
  "ai_timeout_ms": 10000,
  "ai_ssl_verify": true
}
```

### Advanced Analysis Settings

```json
{
  "ai_analysis_threshold": 6.0,
  "ai_comprehensive_analysis_threshold": 8.0,
  "ai_behavioral_analysis_enabled": true,
  "ai_payload_analysis_enabled": true,
  "ai_contextual_analysis_enabled": false
}
```

### Cost Control Configuration

```json
{
  "ai_low_risk_sampling_rate": 0.1,
  "ai_medium_risk_sampling_rate": 0.5, 
  "ai_high_risk_sampling_rate": 1.0,
  "ai_cache_enabled": true,
  "ai_cache_ttl_seconds": 300,
  "ai_payload_size_limit": 2048
}
```

## Analysis Types

### 1. Standard Threat Detection
- **Trigger**: Threat level 6-7, basic suspicious patterns
- **Model**: Most cost-effective available (usually Gemini)
- **Focus**: SQL injection, XSS, command injection, path traversal
- **Response Time**: ~2 seconds
- **Cost**: Low ($0.001-0.003 per analysis)

### 2. Behavioral Analysis  
- **Trigger**: Automation indicators, session anomalies
- **Model**: Claude (best behavioral understanding)
- **Focus**: Bot detection, credential stuffing, session hijacking
- **Response Time**: ~2-3 seconds
- **Cost**: Medium ($0.002-0.005 per analysis)

### 3. Payload Analysis
- **Trigger**: Complex payloads, obfuscation detected
- **Model**: GPT-4 (superior pattern recognition)
- **Focus**: Advanced injection techniques, encoding evasion
- **Response Time**: ~3-4 seconds  
- **Cost**: High ($0.005-0.010 per analysis)

### 4. Contextual Assessment
- **Trigger**: Threat level 8+, multi-stage attacks
- **Model**: Claude or GPT-4 (comprehensive reasoning)
- **Focus**: APT indicators, business logic attacks, threat actor profiling
- **Response Time**: ~5-7 seconds
- **Cost**: Highest ($0.010-0.020 per analysis)

## Performance Optimization

### Caching Strategy
- **Threat Analysis**: 5-minute TTL for standard patterns
- **Behavioral Analysis**: 10-minute TTL for user patterns  
- **Payload Analysis**: 3-minute TTL for payload signatures
- **Cache Size**: 1,000 responses (configurable)

### Model Selection Algorithm
1. **Risk Assessment**: Calculate threat level and confidence
2. **Analysis Type**: Determine required analysis complexity
3. **Model Health**: Check model availability and error rates
4. **Cost Consideration**: Select most cost-effective suitable model
5. **Failover**: Automatic fallback to backup models

### Sampling Rules
```
Low Risk (threat level 1-4):    10% sampling
Medium Risk (threat level 5-7): 50% sampling  
High Risk (threat level 8-10):  100% sampling
```

## Security and Privacy

### Data Sanitization
- **PII Redaction**: Automatic removal of sensitive data patterns
- **Payload Limits**: Maximum 2KB sent to AI for analysis
- **Encoding Detection**: Handle URL, HTML, Unicode encoding
- **Credit Card Masking**: Replace CC numbers with XXXX-XXXX-XXXX-XXXX

### API Security
- **SSL Verification**: Enforced by default for all model endpoints
- **API Key Rotation**: Support for key rotation without downtime
- **Request Signing**: Optional request signing for enhanced security
- **Rate Limiting**: Built-in protection against API abuse

## Monitoring and Metrics

### Model Performance Metrics
- **Success Rate**: Percentage of successful API calls
- **Average Latency**: Response time tracking per model
- **Error Count**: Failed request tracking with categorization
- **Cost Tracking**: Real-time cost monitoring per model
- **Reliability Score**: Calculated availability and performance score

### Analysis Effectiveness Metrics
- **False Positive Rate**: Tracking via feedback loop
- **False Negative Rate**: Outcome-based learning
- **Threat Detection Accuracy**: Analyst-verified results
- **Cost Efficiency**: Cost per genuine threat detected

### Health Monitoring
- **Model Health Checks**: Every 5 minutes (configurable)
- **Endpoint Availability**: Automatic failover on failures
- **Performance Thresholds**: Alerts on latency or error rate issues
- **Daily Cost Tracking**: Spending alerts and throttling

## Feedback and Learning

### Analyst Feedback Integration
```bash
# Submit feedback on AI analysis
curl -X POST /api/ai-feedback \
  -H "Content-Type: application/json" \
  -d '{
    "analysis_id": "abc123",
    "analyst_verdict": "false_positive",
    "threat_category": "sql_injection",
    "confidence": 0.9,
    "notes": "Legitimate SQL query in application parameter"
  }'
```

### Automated Learning
- **Outcome Tracking**: Monitor blocked/allowed request outcomes
- **Pattern Recognition**: Identify recurring false positive patterns
- **Model Adjustment**: Adjust confidence thresholds based on feedback
- **Performance Optimization**: Improve model selection algorithms

## Deployment Considerations

### Production Setup
1. **Start with Dry Run**: Enable logging but no blocking initially
2. **Conservative Thresholds**: Begin with high AI analysis thresholds (8.0+)
3. **Monitor Costs**: Set low daily limits initially ($10-20)
4. **Single Model**: Start with one model, add others gradually
5. **Gradual Rollout**: Increase sampling rates as confidence grows

### Scaling Recommendations
- **High Traffic**: Reduce sampling rates for low/medium risk
- **Cost Sensitive**: Use Gemini primarily, GPT-4 for critical only
- **Security Critical**: Enable comprehensive analysis for all threats
- **Performance Critical**: Increase cache TTL, reduce analysis scope

### Troubleshooting

#### Common Issues
1. **High Latency**: Check model selection, increase cache TTL
2. **High Costs**: Review sampling rates, adjust thresholds
3. **False Positives**: Enable feedback collection, adjust confidence
4. **Model Failures**: Verify API keys, check endpoint availability

#### Debug Mode
```json
{
  "log_level": "debug",
  "ai_metrics_collection_enabled": true,
  "ai_cost_tracking_enabled": true
}
```

## API Reference

### Analysis Request Format
```json
{
  "request_context": {
    "method": "POST",
    "path": "/api/users",
    "headers": {...},
    "body": "...",
    "client_ip": "192.168.1.100"
  },
  "threat_result": {
    "threat_type": "sql_injection",
    "threat_level": 7.5,
    "confidence": 0.85
  },
  "analysis_type": "payload_focused"
}
```

### Analysis Response Format
```json
{
  "threat_validated": true,
  "threat_type": "sql_injection_blind",
  "threat_level": 8.2,
  "confidence": 0.92,
  "sophistication_level": "advanced",
  "attack_vectors": ["time_based_blind", "error_based"],
  "recommended_action": "block",
  "explanation": "Detected time-based blind SQL injection with sleep() function",
  "analysis_metadata": {
    "model_used": "GPT4",
    "analysis_type": "payload_focused", 
    "latency_ms": 2341,
    "timestamp": 1703097600
  }
}
```

## License

This enhanced AI Gateway integration is part of Kong Guard AI and follows the same licensing terms as the parent project.

## Support

For issues, feature requests, or deployment assistance:
- Create an issue in the Kong Guard AI repository
- Include relevant configuration and log snippets
- Specify model versions and analysis types used
- Provide cost and performance impact details