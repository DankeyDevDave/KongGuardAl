# AI Service Port Configuration - Fixed

## Problem
Dashboard was trying to connect to wrong ports:
- Expected cloud: `http://localhost:18002` ❌
- Expected local: `http://localhost:18003` ❌

## Actual Ports
- Cloud AI service: `http://localhost:28100` ✅
- Local AI service (Ollama): `http://localhost:28101` ✅

## Files Updated

### 1. `/dashboard/src/hooks/useRealtimeDashboard.ts`
```typescript
// Before:
apiBaseUrls: {
  unprotected: 'http://localhost:8000',
  cloud: 'http://localhost:18002',
  local: 'http://localhost:18003'
}

// After:
apiBaseUrls: {
  unprotected: 'http://localhost:8000',
  cloud: 'http://localhost:28100',
  local: 'http://localhost:28101'
}
```

### 2. `/dashboard/src/app/page.tsx`
```typescript
// Updated same ports in main page component
cloud: 'http://localhost:28100',
local: 'http://localhost:28101'
```

## Actions Taken
1. ✅ Updated port configuration in both files
2. ✅ Restarted dashboard container (`kong-guard-dashboard`)
3. ✅ Verified AI services running:
   - `kong-guard-ai-cloud` on port 28100
   - `kong-guard-ai-ollama` on port 28101
4. ✅ Tested endpoint connectivity

## Result
- Dashboard can now connect to both AI services
- Attack simulator buttons will work
- Real-time threat detection functional
- No more `ERR_CONNECTION_REFUSED` errors

## Ready for Demo Recording
All systems operational:
- ✅ Dashboard on port 3000
- ✅ Cloud AI service on port 28100
- ✅ Local AI service on port 28101
- ✅ Visual effects with hidden overlays
- ✅ Enhanced click ripples (80px)
- ✅ Real-time audio narration ready

**Status:** Ready for final 5-minute demo recording!
