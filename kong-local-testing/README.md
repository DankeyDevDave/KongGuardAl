# Kong Local Testing Environment 🚀

A comprehensive, production-ready Kong Gateway testing and evaluation environment for local development.

## Features ✨

- **Multiple Deployment Modes**
  - Kong with PostgreSQL database
  - Kong DB-less (declarative) mode
  - Side-by-side comparison

- **Pre-configured Services**
  - HTTPBin - HTTP request/response testing
  - Echo Server - Request echo and debugging
  - MockBin - API mocking service
  - Redis - Caching layer

- **Monitoring & Observability**
  - Prometheus metrics collection
  - Grafana dashboards
  - pgAdmin for database management
  - Redis Commander for cache inspection

- **Testing Tools**
  - Automated API test suite
  - Performance benchmarking
  - Load testing scenarios
  - Web-based testing dashboard

- **Management**
  - CLI management script
  - Web dashboard
  - Kong Manager GUI
  - Docker Compose profiles

## Quick Start 🏃‍♂️

### Prerequisites

- Docker & Docker Compose
- macOS/Linux (Windows WSL2 supported)
- 4GB+ available RAM
- Ports 8000-8002, 9000-9001, 3000, 5432, 6379, 8080-8083, 9090 available

### Installation

1. Clone or copy the kong-local-testing directory
2. Navigate to the directory:
```bash
cd kong-local-testing
```

3. Start Kong with default configuration:
```bash
./scripts/kong-manager.sh start
```

4. Open the dashboard:
```bash
open dashboard.html
# Or visit: file:///path/to/kong-local-testing/dashboard.html
```

## Usage Guide 📖

### Starting Different Configurations

```bash
# Default setup (Kong DB mode + services)
./scripts/kong-manager.sh start

# Full setup (all services + monitoring + tools)
./scripts/kong-manager.sh start full

# DB-less mode only
./scripts/kong-manager.sh start dbless

# With monitoring stack
./scripts/kong-manager.sh start monitoring

# Minimal setup (Kong + HTTPBin only)
./scripts/kong-manager.sh start minimal
```

### Service URLs

| Service | URL | Description |
|---------|-----|-------------|
| Kong Proxy (DB) | http://localhost:8000 | Main gateway proxy |
| Kong Admin API (DB) | http://localhost:8001 | Admin API for configuration |
| Kong Manager | http://localhost:8002 | Web UI for Kong |
| Kong Proxy (DB-less) | http://localhost:9000 | DB-less mode proxy |
| Kong Admin (DB-less) | http://localhost:9001 | DB-less admin API |
| HTTPBin | http://localhost:8080 | HTTP testing service |
| Echo Server | http://localhost:8081 | Request echo service |
| MockBin | http://localhost:8082 | API mocking service |
| PostgreSQL | localhost:5432 | Kong database |
| Redis | localhost:6379 | Cache layer |
| Prometheus | http://localhost:9090 | Metrics collection |
| Grafana | http://localhost:3000 | Dashboards (admin/admin123) |
| pgAdmin | http://localhost:5050 | DB management (admin@kong.local/admin123) |
| Redis Commander | http://localhost:8083 | Redis UI |

### Testing APIs

#### Through Kong Proxy

```bash
# HTTPBin through Kong
curl http://localhost:8000/httpbin/get
curl -X POST http://localhost:8000/httpbin/post -d '{"test":"data"}'

# Echo server through Kong
curl http://localhost:8000/echo

# MockBin through Kong
curl http://localhost:8000/mock/request
```

#### Run Automated Tests

```bash
# Run functional tests
./scripts/api-tests.sh test

# Run performance benchmark
./scripts/api-tests.sh benchmark

# Run load tests
./scripts/api-tests.sh load

# Run all tests
./scripts/api-tests.sh all
```

### Managing Services

#### Add a New Service

```bash
curl -X POST http://localhost:8001/services \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-service",
    "url": "http://example.com"
  }'
```

#### Add a Route

```bash
curl -X POST http://localhost:8001/services/my-service/routes \
  -H "Content-Type: application/json" \
  -d '{
    "paths": ["/my-path"],
    "methods": ["GET", "POST"]
  }'
```

#### Enable a Plugin

```bash
curl -X POST http://localhost:8001/services/my-service/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "rate-limiting",
    "config": {
      "minute": 20,
      "hour": 500
    }
  }'
```

### Plugin Examples

#### Rate Limiting
```bash
curl -X POST http://localhost:8001/plugins \
  -d "name=rate-limiting" \
  -d "config.minute=10" \
  -d "config.policy=local"
```

#### Authentication (API Key)
```bash
# Enable key-auth on a service
curl -X POST http://localhost:8001/services/{service}/plugins \
  -d "name=key-auth"

# Create a consumer
curl -X POST http://localhost:8001/consumers \
  -d "username=test-user"

# Create an API key
curl -X POST http://localhost:8001/consumers/test-user/key-auth \
  -d "key=secret-api-key"

# Use the API key
curl http://localhost:8000/path \
  -H "apikey: secret-api-key"
```

#### CORS
```bash
curl -X POST http://localhost:8001/services/{service}/plugins \
  -d "name=cors" \
  -d "config.origins=*" \
  -d "config.methods=GET,POST,PUT,DELETE" \
  -d "config.headers=Accept,Content-Type,Authorization"
```

#### Request Transformer
```bash
curl -X POST http://localhost:8001/services/{service}/plugins \
  -d "name=request-transformer" \
  -d "config.add.headers=X-Custom-Header:value" \
  -d "config.add.querystring=api_key:secret"
```

### Monitoring

#### View Metrics
1. Open Prometheus: http://localhost:9090
2. Query examples:
   - `kong_http_requests_total` - Total HTTP requests
   - `kong_latency_bucket` - Latency distribution
   - `kong_bandwidth_total` - Bandwidth usage

#### Grafana Dashboards
1. Open Grafana: http://localhost:3000
2. Login: admin/admin123
3. Import Kong dashboard from Grafana marketplace

### Troubleshooting

#### Check Service Status
```bash
./scripts/kong-manager.sh status
```

#### View Logs
```bash
# Kong logs
docker-compose logs -f kong-db

# Specific service logs
./scripts/kong-manager.sh logs kong-db
./scripts/kong-manager.sh logs httpbin
```

#### Reset Everything
```bash
# Stop and remove all containers and volumes
./scripts/kong-manager.sh clean

# Start fresh
./scripts/kong-manager.sh start
```

#### Common Issues

**Port Already in Use**
```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>
```

**Kong Won't Start**
```bash
# Check database migrations
docker-compose run --rm kong-migration kong migrations bootstrap

# Check configuration
docker-compose config
```

**Can't Access Services**
```bash
# Check Docker network
docker network ls
docker network inspect kong-local-testing_kong-test-net

# Test connectivity
docker exec kong-gateway-db curl http://httpbin:80
```

## Advanced Configuration 🔧

### Custom Declarative Config (DB-less)

Edit `configs/kong-declarative.yml` to modify:
- Services and routes
- Plugins
- Consumers
- Upstreams

Then restart DB-less mode:
```bash
docker-compose restart kong-dbless
```

### Environment Variables

Create `.env` file for custom settings:
```env
KONG_VERSION=3.8.0
POSTGRES_VERSION=13
REDIS_VERSION=7-alpine
KONG_LICENSE_DATA=<your-enterprise-license>
```

### Docker Compose Profiles

- `default` - Basic Kong setup
- `monitoring` - Add Prometheus & Grafana
- `tools` - Add pgAdmin & Redis Commander
- `dbless` - Enable DB-less mode

Use profiles:
```bash
docker-compose --profile monitoring up -d
docker-compose --profile tools --profile monitoring up -d
```

## Testing Scenarios 🧪

### Security Testing

```bash
# SQL Injection attempt
curl "http://localhost:8000/httpbin/get?id=1' OR '1'='1"

# XSS attempt
curl "http://localhost:8000/httpbin/post" \
  -d "data=<script>alert('XSS')</script>"

# Large payload (test size limits)
dd if=/dev/zero bs=1M count=11 | curl -X POST http://localhost:8000/httpbin/post \
  -H "Content-Type: application/octet-stream" \
  --data-binary @-
```

### Performance Testing

```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8000/httpbin/get

# Using curl in parallel
for i in {1..100}; do
  curl http://localhost:8000/httpbin/get &
done
wait
```

### Load Testing

```bash
# Gradual load increase
for rate in 1 10 50 100 200; do
  echo "Testing with $rate req/s"
  ab -n 1000 -c $rate http://localhost:8000/httpbin/get
  sleep 5
done
```

## Best Practices 💡

1. **Development Workflow**
   - Use DB mode for development (easier to modify)
   - Use DB-less mode for CI/CD (reproducible)
   - Version control your `kong-declarative.yml`

2. **Performance**
   - Monitor with Prometheus/Grafana
   - Set appropriate cache sizes
   - Use connection pooling

3. **Security**
   - Always enable authentication in production
   - Use rate limiting to prevent abuse
   - Enable CORS appropriately
   - Regularly update Kong version

4. **Testing**
   - Automate tests with the provided scripts
   - Test both positive and negative scenarios
   - Benchmark before production deployment

## License 📄

This testing environment is provided as-is for evaluation and testing purposes.

## Support 🤝

For Kong-specific questions:
- [Kong Documentation](https://docs.konghq.com)
- [Kong Community](https://discuss.konghq.com)
- [Kong GitHub](https://github.com/Kong/kong)

---

Built with ❤️ for the Kong community