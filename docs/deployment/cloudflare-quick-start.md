# Cloudflare Zero Trust - Quick Start Guide

## 5-Minute Setup for Kong Guard AI Dashboard

### 1 **On Production Server (192.168.0.228)**

```bash
# Install cloudflared
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Login to Cloudflare
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create kong-guard-ai

# Get tunnel ID (save this!)
cloudflared tunnel list
```

### 2 **Create Config File**

Create `~/.cloudflared/config.yml`:

```yaml
tunnel: YOUR_TUNNEL_ID_HERE
credentials-file: /home/user/.cloudflared/YOUR_TUNNEL_ID_HERE.json

ingress:
  # Main Dashboard
  - hostname: kong.yourdomain.com
    service: http://localhost:8080
    
  # Grafana
  - hostname: grafana.yourdomain.com
    service: http://localhost:3000
    
  - service: http_status:404
```

### 3 **Add DNS Records**

```bash
# Automatic DNS setup
cloudflared tunnel route dns kong-guard-ai kong.yourdomain.com
cloudflared tunnel route dns kong-guard-ai grafana.yourdomain.com
```

### 4 **Start Tunnel**

```bash
# Run as service
sudo cloudflared service install
sudo systemctl start cloudflared
sudo systemctl enable cloudflared

# Check status
sudo systemctl status cloudflared
```

### 5 **Configure Access (Zero Trust Dashboard)**

1. Go to: https://one.dash.cloudflare.com/
2. Access → Applications → Add application → Self-hosted
3. Configure:
   - **Application domain**: kong.yourdomain.com
   - **Name**: Kong Guard AI
   - **Policy**: 
     - Allow emails: your-email@domain.com
     - Or: Allow email domain: @yourcompany.com

## Access Your Dashboard

From anywhere in the world:
- Dashboard: **https://kong.yourdomain.com**
- Grafana: **https://grafana.yourdomain.com**

First-time access:
1. Navigate to URL
2. Enter your email
3. Check email for verification code
4. Access granted for 24 hours

## Security Features

 **No exposed ports** - Everything through Cloudflare  
 **Email verification** - Every user authenticated  
 **Session control** - Automatic logout after 24h  
 **Access logs** - Full audit trail in Zero Trust  
 **DDoS protection** - Cloudflare's network protection  
 **SSL/TLS** - Automatic HTTPS everywhere  

## Mobile Access

1. Visit https://kong.yourdomain.com on mobile
2. Complete email verification
3. Save to home screen for app-like experience

## Troubleshooting

### Tunnel not connecting?
```bash
# Check tunnel status
cloudflared tunnel info kong-guard-ai

# View logs
sudo journalctl -u cloudflared -f

# Test connection
curl -I http://localhost:8080
```

### DNS not working?
```bash
# Verify DNS records
dig kong.yourdomain.com

# Should show:
# kong.yourdomain.com. CNAME YOUR_TUNNEL_ID.cfargotunnel.com.
```

### Access denied?
- Check Zero Trust policy configuration
- Verify email is in allowed list
- Check session hasn't expired

## Quick Commands

```bash
# Restart tunnel
sudo systemctl restart cloudflared

# Stop tunnel
sudo systemctl stop cloudflared

# View tunnel metrics
cloudflared tunnel metrics kong-guard-ai

# Update tunnel
cloudflared update
```

## Pro Tips

1. **Multiple Users**: Add team members in Zero Trust → Users
2. **Service Tokens**: For API access without browser auth
3. **Bypass for localhost**: Access locally without auth at 192.168.0.228:8080
4. **Webhook notifications**: Set up alerts for access events
5. **Country restrictions**: Limit access to specific countries

---

**That's it!** Your Kong Guard AI dashboard is now securely accessible from anywhere via Cloudflare Zero Trust! 