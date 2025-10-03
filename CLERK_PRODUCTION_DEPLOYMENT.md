# Clerk Authentication - Production Deployment Guide

**Date**: September 30, 2025  
**Production URL**: https://YOUR_PRODUCTION_DOMAIN/  
**Maintainer**: DankeyDevDave (https://github.com/DankeyDevDave)  
**Server**: root@192.168.0.228  
**Deployment Status**: ✅ Committed to GitHub, Ready for Production

> Replace `YOUR_PRODUCTION_DOMAIN` with your live dashboard host when following the steps below.

---

## Overview

The Kong Guard AI dashboard now includes Clerk authentication with route protection. All dashboard routes require authentication before access.

### What Was Added

1. **Clerk SDK Integration**
   - Package: `@clerk/nextjs@6.33.1`
   - Middleware: `dashboard/src/middleware.ts`
   - Layout: Updated with ClerkProvider

2. **Route Protection**
   - All routes protected by default
   - Unauthenticated users redirected to Clerk sign-in
   - Sign In/Sign Up modals
   - User profile button for authenticated users

3. **Authentication Flow**
   - User visits dashboard → Redirected to Clerk if not authenticated
   - After sign-in → Redirected back to dashboard
   - User button displays profile and sign-out options

---

## CRITICAL: Production vs Test Keys

### Current Local Setup (TEST MODE)
Your local development uses **TEST** keys:
```bash
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_d2lzZS1tdWxlLTEyLmNsZXJrLmFjY291bnRzLmRldiQ
CLERK_SECRET_KEY=sk_test_FFspqyezhp9EJhPNnsUEEPkHWKje9p2K3NhApYMYeL
```

### Production Requires PRODUCTION Keys
**You MUST obtain separate production keys from Clerk Dashboard:**

1. Go to: https://dashboard.clerk.com/
2. Switch to **Production** instance (top left dropdown)
3. Navigate to: **API Keys** section
4. Copy your production keys:
   - `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...`
   - `CLERK_SECRET_KEY=sk_live_...`

---

## Clerk Dashboard Configuration

### Before Deployment - Configure Production Instance

1. **Add Authorized Domain**
   - Go to Clerk Dashboard → Production Instance → **Configure** → **Domains**
   - Add: `YOUR_PRODUCTION_DOMAIN`
   - Add: `https://YOUR_PRODUCTION_DOMAIN` (with https)

2. **Configure Redirect URLs**
   - Sign-in redirect: `https://YOUR_PRODUCTION_DOMAIN/`
   - Sign-up redirect: `https://YOUR_PRODUCTION_DOMAIN/`
   - After sign-out: `https://YOUR_PRODUCTION_DOMAIN/`

3. **Enable Authentication Methods** (Optional)
   - Email/Password (enabled by default)
   - Social providers (Google, GitHub, etc.) if desired
   - Two-factor authentication (recommended for production)

---

## Production Deployment Steps

### Step 1: SSH to Production Server

```bash
ssh root@192.168.0.228
cd /opt/KongGuardAI
```

### Step 2: Pull Latest Changes

```bash
# Pull the latest code with Clerk integration
git pull origin main

# Verify you got the Clerk changes
git log --oneline -5
# Should show: "feat: add Clerk authentication to dashboard"
```

### Step 3: Create Production Environment File

**IMPORTANT**: Create `.env.local` with YOUR PRODUCTION KEYS

```bash
# Create production environment file
cat > dashboard/.env.local << 'EOF'
# Clerk Production Keys - Get from https://dashboard.clerk.com (Production instance)
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_YOUR_PRODUCTION_KEY_HERE
CLERK_SECRET_KEY=sk_live_YOUR_PRODUCTION_SECRET_HERE
EOF

# Verify the file was created
cat dashboard/.env.local
```

⚠️ **REPLACE** `pk_live_YOUR_PRODUCTION_KEY_HERE` and `sk_live_YOUR_PRODUCTION_SECRET_HERE` with your actual production keys from Clerk Dashboard!

### Step 4: Stop Current Dashboard

```bash
# Check what's currently running
docker ps | grep dashboard

# Stop the dashboard service
docker-compose -f docker-compose.dashboard.yml down
```

### Step 5: Rebuild Dashboard with Clerk

```bash
# Rebuild the dashboard image with new dependencies
docker-compose -f docker-compose.dashboard.yml build --no-cache kong-guard-dashboard

# This will:
# - Install @clerk/nextjs package
# - Include middleware.ts
# - Build with new layout.tsx
```

### Step 6: Start Dashboard

```bash
# Start the dashboard with environment variables
docker-compose -f docker-compose.dashboard.yml up -d

# Check if it started successfully
docker ps | grep dashboard
```

### Step 7: Verify Deployment

```bash
# Check logs for any errors
docker logs kong-guard-dashboard -f

# Look for:
# ✓ Compiled middleware
# ✓ Ready in Xms
# No Clerk-related errors
```

### Step 8: Test Authentication

1. **Open browser**: https://YOUR_PRODUCTION_DOMAIN/
2. **Expected**: Should redirect to Clerk sign-in page
3. **Sign in** with your account (or create one)
4. **Expected**: Redirected back to dashboard
5. **Verify**: User button appears in top-right header

---

## Alternative: Production Dockerfile Method

If using the production Dockerfile (`dashboard/Dockerfile.production`):

```bash
# Build production image with environment variables
cd /opt/KongGuardAI

docker build \
  -f dashboard/Dockerfile.production \
  -t kong-guard-dashboard:clerk \
  dashboard/

# Run with environment variables
docker run -d \
  --name kong-guard-dashboard \
  --network kongguardai_kong-net \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_YOUR_KEY \
  -e CLERK_SECRET_KEY=sk_live_YOUR_SECRET \
  kong-guard-dashboard:clerk
```

---

## Troubleshooting

### Issue: "Clerk: Missing publishable key"

**Cause**: Environment variables not loaded

**Solution**:
```bash
# Check if .env.local exists
ls -la dashboard/.env.local

# Verify variables are set
docker exec kong-guard-dashboard env | grep CLERK

# If empty, recreate .env.local and restart:
docker-compose -f docker-compose.dashboard.yml down
# Recreate .env.local (see Step 3)
docker-compose -f docker-compose.dashboard.yml up -d
```

### Issue: Redirects to localhost instead of production domain

**Cause**: Clerk dashboard not configured with production URL

**Solution**:
1. Go to Clerk Dashboard → Production Instance
2. Add `YOUR_PRODUCTION_DOMAIN` to authorized domains
3. Update redirect URLs to use `https://YOUR_PRODUCTION_DOMAIN`

### Issue: "Invalid publishable key" error

**Cause**: Using test keys instead of production keys

**Solution**:
1. Go to Clerk Dashboard
2. **Switch to Production instance** (top-left dropdown)
3. Copy production keys (should start with `pk_live_` and `sk_live_`)
4. Update `.env.local` with production keys
5. Restart dashboard container

### Issue: Build fails with Clerk errors

**Cause**: npm dependencies not installed properly

**Solution**:
```bash
# Rebuild without cache
docker-compose -f docker-compose.dashboard.yml build --no-cache kong-guard-dashboard

# If still fails, check build logs:
docker-compose -f docker-compose.dashboard.yml build kong-guard-dashboard 2>&1 | tee build.log
```

### Issue: Can't access dashboard after authentication

**Cause**: Network/port configuration issue

**Solution**:
```bash
# Check if dashboard is running
docker ps | grep dashboard

# Check logs for errors
docker logs kong-guard-dashboard --tail 100

# Verify port is accessible
curl http://localhost:3000/

# Check network connectivity
docker network inspect kongguardai_kong-net
```

---

## Security Checklist

Before going to production:

- [ ] Production Clerk keys obtained from Clerk Dashboard
- [ ] Test keys (pk_test_*, sk_test_*) **NOT** used in production
- [ ] `.env.local` file created with production keys
- [ ] `.env.local` **NOT** committed to git (should be in .gitignore)
- [ ] Clerk Dashboard configured with production domain
- [ ] Redirect URLs updated in Clerk Dashboard
- [ ] Authentication tested successfully
- [ ] User sign-up flow tested
- [ ] Sign-out functionality verified
- [ ] Dashboard routes protected (cannot access without auth)

---

## Rollback Procedure

If deployment fails or causes issues:

```bash
cd /opt/KongGuardAI

# Option 1: Revert to previous commit
git log --oneline -5  # Find previous commit hash
git checkout <previous-commit-hash>
docker-compose -f docker-compose.dashboard.yml build kong-guard-dashboard
docker-compose -f docker-compose.dashboard.yml up -d

# Option 2: Remove authentication temporarily
# Remove .env.local to disable Clerk
rm dashboard/.env.local
docker-compose -f docker-compose.dashboard.yml restart kong-guard-dashboard
```

---

## Post-Deployment Monitoring

```bash
# Monitor dashboard logs
docker logs -f kong-guard-dashboard

# Check authentication events
docker logs kong-guard-dashboard | grep -i clerk

# Monitor container health
docker stats kong-guard-dashboard

# Check memory and CPU usage
docker exec kong-guard-dashboard ps aux
```

---

## Next Steps After Deployment

1. **Test user sign-up flow** thoroughly
2. **Configure user roles** in Clerk Dashboard (if needed)
3. **Set up email notifications** for new user sign-ups
4. **Enable two-factor authentication** for admin users
5. **Monitor authentication logs** in Clerk Dashboard
6. **Set up alerts** for failed authentication attempts

---

## Support & Resources

- **Clerk Documentation**: https://clerk.com/docs
- **Clerk Dashboard**: https://dashboard.clerk.com/
- **Next.js + Clerk Guide**: https://clerk.com/docs/quickstarts/nextjs
- **Production Checklist**: https://clerk.com/docs/deployments/overview

---

**Deployment Prepared By**: Factory Droid AI Agent  
**Last Updated**: September 30, 2025  
**Status**: ✅ Ready for Production Deployment
