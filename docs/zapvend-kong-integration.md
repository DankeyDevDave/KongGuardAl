# ZapVend + Kong Integration Guide

## Overview

This guide explains how to configure your ZapVend electricity token vending application to route through Kong API Gateway for enhanced security, rate limiting, and API management.

## Architecture

```
[Client] → [Kong Gateway :18000] → [ZapVend Backend :8000]
                ↓
         [Kong Guard AI Plugin]
                ↓
         [Security & Rate Limiting]
```

## Integration Options

### Option 1: ZapVend Running Locally (Recommended for Development)

If ZapVend is running directly on your machine (not in Docker):

1. **Start ZapVend locally:**
   ```bash
   cd /Users/jacques/DevFolder/zapvend_new/elec-token-vending-original
   # Start your FastAPI backend
   python main.py # or uvicorn main:app --reload --port 8000
   ```

2. **Configure Kong to route to local ZapVend:**
   ```bash
   cd /Users/jacques/DevFolder/KongGuardAI
   chmod +x configure-zapvend-kong.sh
   ./configure-zapvend-kong.sh
   ```

### Option 2: ZapVend in Docker (Production-like)

1. **Modify ZapVend's docker-compose.yml to join Kong network:**
   ```yaml
   networks:
     app-network:
       external: true
       name: kongguardai_kong-net
   ```

2. **Start ZapVend with Kong network:**
   ```bash
   cd /Users/jacques/DevFolder/zapvend_new/elec-token-vending-original
   docker compose up -d
   ```

3. **Configure Kong routes:**
   ```bash
   cd /Users/jacques/DevFolder/KongGuardAI
   # Edit configure-zapvend-kong.sh to use Docker service name
   # Change: ZAPVEND_BACKEND_URL="http://elec-vending-backend:8000"
   ./configure-zapvend-kong.sh
   ```

## Kong Route Configuration

### Routes Created

| Route | Kong Path | Backend Path | Purpose |
|-------|-----------|--------------|---------|
| API | `/zapvend/api/*` | `/api/*` | API endpoints |
| Auth | `/zapvend/auth/*` | `/auth/*` | Authentication |
| Frontend | `/zapvend/*` | `/*` | Static files/UI |

### Applied Plugins

1. **Kong Guard AI** - AI-powered threat detection
2. **CORS** - Cross-origin resource sharing
3. **Rate Limiting** - 100 req/min, 1000 req/hour
4. **Request Size Limiting** - Max 10MB payloads
5. **Security Headers** - HSTS, XSS Protection, etc.

## Testing the Integration

### 1. Health Check
```bash
# Direct to ZapVend (if accessible)
curl http://localhost:8000/health

# Via Kong
curl http://localhost:18000/zapvend/api/health
```

### 2. API Endpoints
```bash
# Get meters (requires auth)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:18000/zapvend/api/meters

# Create token purchase
curl -X POST http://localhost:18000/zapvend/api/electricity/purchase \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "meter_number": "12345",
    "amount": 100.00
  }'
```

### 3. Test Security Features

```bash
# Test SQL injection protection (should be blocked)
curl "http://localhost:18000/zapvend/api/meters?id=1' OR '1'='1"

# Test rate limiting (run multiple times quickly)
for i in {1..150}; do
  curl http://localhost:18000/zapvend/api/health
done
```

## Monitoring in Konga UI

1. Open Konga: http://localhost:1337
2. Navigate to **Services** → **zapvend-backend**
3. View:
   - Routes configuration
   - Active plugins
   - Request analytics
   - Error logs

## Environment Variables for ZapVend

Update your ZapVend `.env` to work with Kong:

```env
# API Configuration
API_BASE_URL=http://localhost:18000/zapvend
CORS_ORIGINS=http://localhost:18000,http://localhost:3000

# If using authentication
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/electricity_vending
```

## Frontend Configuration

If ZapVend has a separate frontend:

### For React/Next.js
```javascript
// .env or config.js
REACT_APP_API_URL=http://localhost:18000/zapvend/api
NEXT_PUBLIC_API_URL=http://localhost:18000/zapvend/api
```

### For API calls
```javascript
// Use Kong proxy URL
const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:18000/zapvend/api';

fetch(`${API_BASE}/meters`, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});
```

## Troubleshooting

### 1. Connection Refused
```bash
# Check if ZapVend is running
curl http://localhost:8000/health

# Check Kong can reach ZapVend
docker exec kong-gateway curl http://host.docker.internal:8000/health
```

### 2. CORS Issues
```bash
# Test CORS headers
curl -I -X OPTIONS http://localhost:18000/zapvend/api/health \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: GET"
```

### 3. Authentication Issues
```bash
# Check if auth headers are passed through
curl -v http://localhost:18000/zapvend/api/protected \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 4. View Kong Logs
```bash
docker logs kong-gateway -f --tail 100
```

## Production Deployment

### 1. Use Environment-Specific Config
```bash
# Production configuration
ZAPVEND_BACKEND_URL="http://zapvend-backend-service:8000"
KONG_PROXY_URL="https://api.yourdomain.com"
```

### 2. Enable HTTPS
- Configure Kong with SSL certificates
- Update CORS origins to HTTPS URLs
- Enable HSTS headers

### 3. Configure Authentication
Consider adding:
- JWT plugin for token validation
- Key-Auth plugin for API keys
- OAuth2 plugin for third-party auth

### 4. Add Monitoring
- Enable Prometheus plugin
- Configure logging plugins
- Set up alerts for errors/threats

## Security Best Practices

1. **Never expose backend directly** - Always route through Kong
2. **Use rate limiting** - Prevent abuse and DDoS
3. **Enable Kong Guard AI** - AI-powered threat detection
4. **Implement authentication** - Protect sensitive endpoints
5. **Use HTTPS in production** - Encrypt all traffic
6. **Monitor and log** - Track all API access
7. **Regular updates** - Keep Kong and plugins updated

## Quick Commands

```bash
# View all services
curl -s http://localhost:18001/services | jq

# View ZapVend routes
curl -s http://localhost:18001/services/zapvend-backend/routes | jq

# View active plugins
curl -s http://localhost:18001/services/zapvend-backend/plugins | jq

# Remove a plugin
curl -X DELETE http://localhost:18001/plugins/{plugin-id}

# Update service URL
curl -X PATCH http://localhost:18001/services/zapvend-backend \
  -H "Content-Type: application/json" \
  -d '{"url": "http://new-backend:8000"}'
```

## Support

- Kong Documentation: https://docs.konghq.com
- Kong Guard AI: Check plugin logs in Kong Gateway
- ZapVend Issues: Check backend logs and database connectivity