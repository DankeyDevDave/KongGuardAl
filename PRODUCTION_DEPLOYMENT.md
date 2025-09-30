# Production Deployment Guide

## Current Fix: WebSocket Configuration

### What Changed
- **WebSocket URL**: Updated from `ws://localhost:8000/ws` to `ws://localhost:18002/ws`
- **Files Modified**:
  - `dashboard/src/app/page.tsx` (line 22)
  - `dashboard/src/hooks/useRealtimeDashboard.ts` (line 55)
  - Added handlers for `connection`, `ai_thinking`, and `threat_analysis` message types

### Production Deployment Steps

#### 1. On Your Local Machine (Mac)

```bash
# Commit the changes
cd /Users/jacques/DevFolder/KongGuardAI
git add dashboard/src/app/page.tsx dashboard/src/hooks/useRealtimeDashboard.ts
git commit -m "fix: update WebSocket port configuration for production

- Changed WebSocket URL from port 8000 to 18002
- Added proper message handlers for real-time threat analysis
- Fixed dashboard connectivity with WebSocket backend

Co-authored-by: factory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>"

# Push to GitHub
git push origin main
```

#### 2. On Production Server (192.168.0.228)

```bash
# SSH into production
ssh root@192.168.0.228

# Navigate to the correct directory (check both locations)
cd /opt/KongGuardAI  # or cd /opt/kong-guard-ai

# Pull latest changes
git pull origin main

# Stop existing services
docker-compose down

# Rebuild dashboard with new WebSocket configuration
docker-compose build dashboard

# Start services
docker-compose up -d

# Check service status
docker-compose ps

# View dashboard logs to confirm WebSocket connection
docker-compose logs -f dashboard

# View WebSocket backend logs
docker-compose logs -f ai-service
```

#### 3. Production Environment Configuration

**Important**: Check your production `docker-compose.yml` for port mappings:

```yaml
# Dashboard should be accessible on production port (e.g., 3000)
dashboard:
  ports:
    - "3000:3000"

# WebSocket backend should be on port 18002
ai-service:
  ports:
    - "18002:18002"
  environment:
    - PORT=18002
```

#### 4. Verification Steps

```bash
# On production server:

# 1. Check if WebSocket service is running
curl http://localhost:18002/

# Expected response:
# {"service":"Kong Guard AI - Real-Time Threat Analysis","status":"operational",...}

# 2. Test WebSocket connection (if python3-websockets is installed)
python3 << 'EOF'
import asyncio
import websockets

async def test():
    async with websockets.connect('ws://localhost:18002/ws') as ws:
        msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
        print(f"✅ Connected: {msg[:100]}")

asyncio.run(test())
EOF

# 3. Check dashboard accessibility
curl http://localhost:3000/

# 4. View service logs
docker-compose logs --tail=50 dashboard
docker-compose logs --tail=50 ai-service
```

#### 5. Firewall Configuration (if needed)

If you need external access to the dashboard:

```bash
# On production server:
ufw allow 3000/tcp comment "Kong Guard AI Dashboard"
ufw allow 18002/tcp comment "Kong Guard AI WebSocket"
ufw status
```

#### 6. Nginx Reverse Proxy (Recommended for Production)

If you want to expose the dashboard through a domain:

```nginx
# /etc/nginx/sites-available/kongguard-dashboard
server {
    listen 80;
    server_name dashboard.yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket endpoint
    location /ws {
        proxy_pass http://localhost:18002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable and restart nginx:
```bash
ln -s /etc/nginx/sites-available/kongguard-dashboard /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

### Production Environment Variables

Make sure your production `.env` file has:

```bash
# AI Service Configuration
GEMINI_API_KEY=your_production_key_here
OPENAI_API_KEY=your_production_key_here
ANTHROPIC_API_KEY=your_production_key_here

# WebSocket Configuration
WEBSOCKET_PORT=18002

# Dashboard Configuration
DASHBOARD_PORT=3000
```

### Troubleshooting

#### WebSocket Connection Failed
```bash
# Check if service is running
docker ps | grep ai-service

# Check service logs
docker-compose logs ai-service | tail -50

# Restart service
docker-compose restart ai-service
```

#### Dashboard Not Loading
```bash
# Check Next.js logs
docker-compose logs dashboard | tail -50

# Rebuild dashboard
docker-compose build --no-cache dashboard
docker-compose up -d dashboard
```

#### Port Conflicts
```bash
# Check what's using port 18002
lsof -i :18002

# Check what's using port 3000
lsof -i :3000
```

### Rollback Procedure

If something goes wrong:

```bash
# On production server
cd /opt/KongGuardAI

# Revert to previous commit
git log --oneline -5
git checkout <previous-commit-hash>

# Rebuild and restart
docker-compose down
docker-compose build dashboard
docker-compose up -d
```

### Production Monitoring

```bash
# Monitor all services
docker-compose logs -f --tail=100

# Monitor specific service
docker-compose logs -f dashboard
docker-compose logs -f ai-service

# Check resource usage
docker stats
```

### Next Steps

1. ✅ Commit changes locally
2. ✅ Push to GitHub
3. ✅ SSH to production
4. ✅ Pull changes
5. ✅ Rebuild services
6. ✅ Test WebSocket connectivity
7. ✅ Monitor logs for errors

### Production Checklist

- [ ] Changes committed and pushed to GitHub
- [ ] SSH access to production server verified
- [ ] Production directory identified (/opt/KongGuardAI or /opt/kong-guard-ai)
- [ ] Docker Compose configuration reviewed
- [ ] Environment variables configured
- [ ] Services stopped gracefully
- [ ] Changes pulled from GitHub
- [ ] Dashboard rebuilt with new configuration
- [ ] Services started successfully
- [ ] WebSocket connectivity tested
- [ ] Dashboard accessible
- [ ] Real-time data flowing
- [ ] Logs checked for errors
- [ ] Firewall rules updated (if needed)
- [ ] SSL/TLS configured (if applicable)
- [ ] Monitoring in place

### Support

If you encounter issues during deployment:

1. Check service logs: `docker-compose logs <service-name>`
2. Verify network connectivity: `docker network inspect kongguardai_kong-net`
3. Check environment variables: `docker-compose config`
4. Review this guide's troubleshooting section

---

**Last Updated**: September 30, 2025
**Version**: Post-WebSocket Fix
