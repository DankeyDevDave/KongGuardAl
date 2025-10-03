# Kong Guard AI FastAPI Implementation

Auto-generated FastAPI implementation from Kong Guard AI plugin Lua codebase.

## Overview

This FastAPI application provides a RESTful API interface for the Kong Guard AI plugin, offering comprehensive threat detection, analysis, and automated remediation capabilities for Kong Gateway deployments.

## Features

- **Real-time Threat Detection**: Monitor and detect API threats including SQL injection, XSS, rate limiting violations
- **AI-Powered Analysis**: Integration with AI models for deep threat analysis
- **Incident Management**: Track and manage security incidents with full lifecycle support
- **Performance Monitoring**: Real-time metrics and performance dashboards
- **Automated Remediation**: Automatic IP blocking, rate limiting, and threat mitigation
- **Comprehensive Analytics**: Detailed reporting and analytics dashboards

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/kong-guard-ai
cd kong-guard-ai/fastapi-generated

# Set environment variables
cp .env.example .env
# Edit .env with your configuration

# Start all services
docker-compose up -d

# Check health
curl http://localhost:8000/health
```

### Manual Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql+asyncpg://user:pass@localhost/kongguard"
export REDIS_URL="redis://localhost:6379/0"
export KONG_ADMIN_URL="http://localhost:8001"

# Run database migrations
alembic upgrade head

# Start the application
uvicorn app.main:app --reload --port 8000
```

## API Documentation

Once running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI Spec**: http://localhost:8000/openapi.json

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql+asyncpg://kong:kong@localhost:5432/kongguard

# Redis Cache
REDIS_URL=redis://localhost:6379/0

# Kong Integration
KONG_ADMIN_URL=http://localhost:8001
KONG_API_KEY=your-kong-api-key

# AI Gateway (Optional)
AI_GATEWAY_ENABLED=false
AI_GATEWAY_ENDPOINT=https://ai.gateway.example.com
AI_GATEWAY_API_KEY=your-ai-api-key
AI_GATEWAY_MODEL=gpt-4o-mini

# Security
SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# CORS
CORS_ORIGINS=["http://localhost:3000", "https://app.example.com"]

# Monitoring
ENABLE_METRICS=true
ENABLE_TRACING=false
```

### Plugin Configuration

The plugin configuration can be managed via the API:

```bash
# Get current configuration
curl -X GET http://localhost:8000/v1/config \
  -H "Authorization: Bearer $TOKEN"

# Update configuration
curl -X PUT http://localhost:8000/v1/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "dry_run_mode": false,
    "threat_threshold": 7.0,
    "enable_auto_blocking": true
  }'
```

## API Endpoints

### Configuration Management
- `GET /v1/config` - Get current configuration
- `PUT /v1/config` - Update complete configuration
- `PATCH /v1/config` - Partial configuration update
- `POST /v1/config/validate` - Validate configuration
- `POST /v1/config/reset` - Reset to defaults

### Threat Detection
- `GET /v1/threats` - List detected threats
- `GET /v1/threats/{id}` - Get threat details
- `POST /v1/threats/{id}/analyze` - Trigger AI analysis
- `POST /v1/threats/{id}/mitigate` - Manual mitigation
- `GET /v1/threats/statistics/summary` - Threat statistics

### Incident Management
- `GET /v1/incidents` - List incidents
- `POST /v1/incidents` - Create incident
- `GET /v1/incidents/{id}` - Get incident details
- `PATCH /v1/incidents/{id}` - Update incident

### Analytics & Reporting
- `GET /v1/analytics/dashboard` - Dashboard data
- `GET /v1/analytics/reports` - List reports
- `POST /v1/analytics/reports` - Generate report

### Monitoring
- `GET /health` - Health check
- `GET /v1/monitoring/health` - Detailed health status
- `GET /v1/monitoring/metrics` - Performance metrics

### Remediation
- `GET /v1/remediation/ip-blacklist` - Get blacklist
- `POST /v1/remediation/ip-blacklist` - Add to blacklist
- `DELETE /v1/remediation/ip-blacklist/{ip}` - Remove from blacklist
- `GET /v1/remediation/rate-limits` - Get rate limit rules
- `POST /v1/remediation/rate-limits` - Create rate limit rule

## Authentication

The API supports multiple authentication methods:

### JWT Bearer Token
```bash
curl -X GET http://localhost:8000/v1/threats \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### API Key
```bash
curl -X GET http://localhost:8000/v1/threats \
  -H "X-API-Key: $API_KEY"
```

### OAuth 2.0
Configure OAuth 2.0 with your identity provider for production deployments.

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_threats.py
```

### Code Quality

```bash
# Format code
black app/ tests/

# Lint code
flake8 app/ tests/

# Type checking
mypy app/
```

### Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1
```

## Monitoring & Observability

### Prometheus Metrics

Metrics are exposed at `/monitoring/metrics` in Prometheus format:

- Request rate and latency
- Threat detection rate
- AI analysis performance
- Resource utilization

### Grafana Dashboards

Pre-configured dashboards available at http://localhost:3000:

- Kong Guard AI Overview
- Threat Analysis Dashboard
- Performance Metrics
- Incident Tracking

Default credentials: admin/admin

### Health Checks

```bash
# Basic health check
curl http://localhost:8000/health

# Detailed health status
curl http://localhost:8000/v1/monitoring/health
```

## Production Deployment

### Security Considerations

1. **Enable HTTPS**: Use TLS certificates in production
2. **Secure Secrets**: Use environment variables or secret management
3. **Rate Limiting**: Configure appropriate rate limits
4. **CORS**: Restrict CORS origins to trusted domains
5. **Authentication**: Implement proper authentication/authorization

### Scaling

```yaml
# docker-compose.override.yml for scaling
services:
  kong-guard-api:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

### Performance Tuning

1. **Database Connection Pool**: Adjust `SQLALCHEMY_POOL_SIZE`
2. **Redis Cache**: Configure appropriate TTLs
3. **Worker Processes**: Set based on CPU cores
4. **Request Timeout**: Adjust `REQUEST_TIMEOUT`

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check DATABASE_URL environment variable
   - Ensure PostgreSQL is running
   - Verify network connectivity

2. **Kong Integration Error**
   - Verify KONG_ADMIN_URL is correct
   - Check Kong Admin API is accessible
   - Validate API key/credentials

3. **AI Gateway Timeout**
   - Increase AI_TIMEOUT_MS
   - Check network latency
   - Verify API key is valid

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
export DEBUG=true
uvicorn app.main:app --log-level debug
```

## Migration from Lua Plugin

This FastAPI implementation maintains compatibility with the original Kong Lua plugin:

1. **Configuration**: All plugin configurations are preserved
2. **API Compatibility**: Response formats match original implementation
3. **Database Schema**: Compatible with existing data
4. **Kong Integration**: Seamless integration with Kong Gateway

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

Apache License 2.0 - See LICENSE file for details

## Support

Maintained by DankeyDevDave (https://github.com/DankeyDevDave)

- Documentation: https://github.com/DankeyDevDave/KongGuardAI/tree/main/docs
- Issues: https://github.com/DankeyDevDave/KongGuardAI/issues
- Contact: Open an issue or reach out via the GitHub profile above

## Acknowledgments

Auto-generated from Kong Guard AI Lua plugin using advanced code analysis and OpenAPI generation tools.