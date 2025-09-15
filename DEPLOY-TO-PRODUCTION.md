# 🚀 Deploy Kong Guard AI to Production (192.168.0.228)

## Step-by-Step Deployment Guide

### From Your Mac:

#### Step 1: Transfer Files
```bash
# Replace 'username' with your actual username on the production server
./transfer-to-production.sh username
```

This will:
- Package all necessary files
- Transfer them to the production server
- Extract them to `/opt/kong-guard-ai`

#### Step 2: SSH to Production Server
```bash
ssh username@192.168.0.228
```

### On Production Server (192.168.0.228):

#### Step 3: Navigate to Project
```bash
cd /opt/kong-guard-ai
```

#### Step 4: Run Deployment Script
```bash
./production-deployment-package.sh
```

When prompted:
1. Enter your domain name (e.g., `example.com`)
2. Authenticate with Cloudflare (browser will open)
3. Wait for all services to deploy

#### Step 5: Configure API Keys
```bash
# Edit the .env file
nano .env

# Add your API keys:
OPENAI_API_KEY=sk-your-actual-key-here
ANTHROPIC_API_KEY=sk-ant-your-actual-key-here

# Save and exit (Ctrl+X, Y, Enter)

# Restart services
docker-compose -f docker-compose.production.yml restart
```

## ✅ Deployment Complete!

### Access Your Services:

#### Local Network (192.168.0.x):
- Dashboard: http://192.168.0.228:8080
- Grafana: http://192.168.0.228:3000
- Kong Admin: http://192.168.0.228:8001
- Konga UI: http://192.168.0.228:1337

#### Internet via Cloudflare:
- Dashboard: https://kong.yourdomain.com
- Grafana: https://grafana.yourdomain.com
- Kong Admin: https://admin.yourdomain.com
- Konga UI: https://konga.yourdomain.com

### Configure Zero Trust Access:

1. Go to https://one.dash.cloudflare.com/
2. Navigate to **Access** → **Applications**
3. Click **Add an application** → **Self-hosted**
4. For each hostname, configure:
   - Application domain: `kong.yourdomain.com`
   - Policy name: "Authorized Users"
   - Include: Your email or domain
   - Session duration: 24 hours

## 🔍 Verify Everything is Working

### Check Services:
```bash
# On production server
docker-compose -f docker-compose.production.yml ps

# Should show all services as "Up"
```

### Check Cloudflare Tunnel:
```bash
sudo systemctl status cloudflared

# Should show "active (running)"
```

### Test Access:
```bash
# From your Mac
curl https://kong.yourdomain.com

# Should redirect to Cloudflare Access login
```

## 📊 Monitor Your Deployment

### View Logs:
```bash
# All services
docker-compose -f docker-compose.production.yml logs -f

# Specific service
docker-compose -f docker-compose.production.yml logs -f grafana

# Cloudflare tunnel
sudo journalctl -u cloudflared -f
```

### Check Metrics:
- Open Grafana: https://grafana.yourdomain.com
- Login: admin / KongGuard2024!
- View Kong Guard AI dashboard

## 🆘 Troubleshooting

### Services not starting?
```bash
# Check logs
docker-compose -f docker-compose.production.yml logs [service-name]

# Restart specific service
docker-compose -f docker-compose.production.yml restart [service-name]
```

### Cloudflare tunnel not working?
```bash
# Check tunnel status
cloudflared tunnel list
cloudflared tunnel info kong-guard-ai

# Restart tunnel
sudo systemctl restart cloudflared

# Check DNS
dig kong.yourdomain.com
```

### Can't connect to Ollama on Mac?
```bash
# On your Mac, ensure Ollama is accessible:
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# From production server, test connection:
curl http://192.168.0.84:11434/api/tags
```

## 🔐 Security Checklist

- [ ] Changed default passwords in `.env`
- [ ] Configured Zero Trust policies for all endpoints
- [ ] Restricted admin endpoints to specific users
- [ ] Enabled 2FA on Cloudflare account
- [ ] Set appropriate session durations
- [ ] Reviewed firewall rules on production server

---

**That's it!** Your Kong Guard AI is now deployed on production with secure global access via Cloudflare Zero Trust! 🎉