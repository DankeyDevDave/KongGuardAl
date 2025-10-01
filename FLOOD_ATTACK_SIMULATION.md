# Flood Attack Simulation - Complete Implementation

**Author:** DankeyDevDave (Jacques Wainwright - Internet Persona)  
**Email:** dankeydevdave@gmail.com  
**Date:** 2025-01-30  
**Status:** ✅ COMPLETE

---

## Overview

The flood attack simulation feature enables realistic attack demonstrations for the Kong Guard AI hackathon demo video. This client-side simulation generates continuous attack traffic across all three protection tiers (unprotected, cloud, local) with configurable intensity and duration.

## Implementation Details

### Location
- **File:** `dashboard/src/hooks/useRealtimeDashboard.ts`
- **Function:** `launchAttackFlood`
- **Type:** Client-side simulation (no backend required)

### Configuration Options

```typescript
interface AttackFloodConfig {
  intensity: 'low' | 'medium' | 'high' | 'extreme'
  strategy: string  // Not used in simulation
  duration: number  // Seconds (converted to ms)
  targets: string[] // Not used in simulation
}
```

### Attack Generation Parameters

#### Intensity Levels
```typescript
const interval = {
  'low': 200ms,      // 5 requests/sec per tier = 15 total/sec
  'medium': 100ms,   // 10 requests/sec per tier = 30 total/sec
  'high': 50ms,      // 20 requests/sec per tier = 60 total/sec
  'extreme': 30ms    // 33 requests/sec per tier = 99 total/sec
}
```

#### Attack Types
Randomly distributed across 8 categories:
- `sql` - SQL injection attacks
- `xss` - Cross-site scripting
- `cmd_injection` - Command injection
- `path` - Path traversal
- `ldap_injection` - LDAP injection
- `business_logic` - Business logic attacks
- `ransomware` - Ransomware patterns
- `normal` - Legitimate traffic (20% of samples)

#### Latency Distribution
Realistic latency based on protection tier:
```typescript
unprotected: 1.5 - 3.5ms   // No AI processing overhead
local:       5 - 9ms       // Ollama local inference
cloud:       7 - 12ms      // OpenAI cloud API + network
```

#### Threat Scores
- **Normal traffic:** 0.0 - 0.3 (low threat)
- **Attack traffic:** 0.65 - 1.0 (high threat)
- **Confidence:** 0.75 - 1.0 (realistic AI confidence)

### Activity Log Integration

Each simulated attack generates an `ActivityLogEntry`:

```typescript
interface ActivityLogEntry {
  id: string                    // Unique: timestamp-tier-random
  timestamp: number              // Unix timestamp ms
  tier: 'unprotected' | 'cloud' | 'local'
  attackType: string             // One of 8 attack types
  latencyMs: number              // Realistic tier-based latency
  action: 'allowed' | 'blocked'  // Based on threat score + tier
  threatScore: number            // 0-1 confidence score
  confidence: number             // 0.75-1.0 AI confidence
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  path: string                   // Randomized API endpoint
}
```

### Metrics Updates

The simulation updates real-time metrics for each tier:
- **Total requests:** Incremented for each simulated attack
- **Blocked count:** When action = 'blocked'
- **Vulnerable count:** Unprotected tier only, non-normal attacks
- **Detection rate:** (blocked / total) * 100 for protected tiers
- **Success rate:** ((total - vulnerable) / total) * 100 for unprotected
- **Average latency:** Running average of tier latencies

### Visual Effects

#### Activity Log Display
- **Three columns:** Unprotected | Cloud Protected | Local Protected
- **Color coding:**
  - 🔴 Red "allowed" - Attack allowed through
  - ✅ Green "blocked" - Attack successfully blocked
- **Auto-scroll:** Newest entries at top
- **Limit:** 60 total entries (20 per tier)
- **Real-time updates:** New entries every interval

#### Metrics Bar
All metrics update in real-time during flood:
- Total requests counter
- Detection/success rates
- Average latency per tier
- Blocked/vulnerable counts

## Usage Examples

### Low Intensity (Demo Recording)
```typescript
await launchAttackFlood({
  intensity: 'low',
  strategy: 'sustained',
  duration: 30,  // 30 seconds
  targets: ['cloud', 'local']
})
// Generates: 5 req/sec × 3 tiers × 30s = 450 total requests
```

### High Intensity (Stress Test Visualization)
```typescript
await launchAttackFlood({
  intensity: 'high',
  strategy: 'blended',
  duration: 60,  // 1 minute
  targets: ['cloud', 'local']
})
// Generates: 20 req/sec × 3 tiers × 60s = 3,600 total requests
```

### Extreme Intensity (Maximum Load)
```typescript
await launchAttackFlood({
  intensity: 'extreme',
  strategy: 'escalation',
  duration: 120,  // 2 minutes
  targets: ['cloud', 'local']
})
// Generates: 33 req/sec × 3 tiers × 120s = 11,880 total requests
```

## Dashboard Integration

### Button Location
Enterprise Attack Scenarios panel → Launch Attack Flood

### User Flow
1. Click "Launch Attack Flood" button
2. Select intensity level (dropdown)
3. Set duration (slider: 10-300 seconds)
4. Click "Start Flood Attack"
5. Watch activity log fill with real-time entries
6. Observe metrics incrementing
7. Flood automatically stops after duration

### Console Output
```
🚀 Launching simulated attack flood: {
  intensity: 'medium',
  strategy: 'sustained',
  duration: 60,
  targets: ['cloud', 'local']
}
... (flood running) ...
✅ Attack flood completed: 1,800 requests simulated
```

## Technical Advantages

### Why Client-Side Simulation?

1. **No Backend Dependencies**
   - Doesn't require WebSocket service `/api/attack/flood` endpoint
   - Works even if AI services are down
   - Perfect for demo recording scenarios

2. **Deterministic Performance**
   - Guaranteed smooth playback
   - No network latency variables
   - Predictable memory usage

3. **Demo-Ready**
   - Activity log always looks active
   - Metrics update smoothly
   - No external API failures

4. **Resource Efficient**
   - No actual HTTP requests sent
   - No Kong Gateway load
   - No AI model invocations

### Comparison: Real vs. Simulated

| Feature | Real Flood | Simulated Flood |
|---------|-----------|-----------------|
| Backend required | ✅ Yes | ❌ No |
| Network traffic | ✅ Yes | ❌ No |
| AI invocations | ✅ Yes | ❌ No |
| Metrics recorded | ✅ DB | ✅ Memory |
| Activity log | ✅ Yes | ✅ Yes |
| Dashboard updates | ✅ Yes | ✅ Yes |
| Demo reliability | ⚠️ Variable | ✅ Perfect |
| Resource usage | 🔥 High | ✅ Minimal |

## Future Enhancements

### Phase 1: Hybrid Mode
Add optional backend integration for real attacks when available:

```typescript
// Try real backend first, fallback to simulation
try {
  const response = await fetch('/api/attack/flood', { ... })
  return await response.json()
} catch (error) {
  console.warn('Backend unavailable, using simulation')
  return simulateFlood(config)
}
```

### Phase 2: WebSocket Broadcasting
When real floods run, broadcast results to dashboard:

```python
# In app_with_websocket.py
await manager.broadcast({
  "type": "flood_attack_result",
  "tier": "cloud",
  "attack_type": "sql",
  "latency_ms": 8.3,
  "action": "blocked",
  "threat_score": 0.95
})
```

### Phase 3: Attack Pattern Recording
Save simulation patterns for replay:

```typescript
// Record pattern
const pattern = recordFloodPattern(config)
savePattern('demo-burst', pattern)

// Replay later
await replayFloodPattern('demo-burst')
```

## Testing Checklist

- [x] Low intensity generates ~15 req/sec
- [x] High intensity generates ~60 req/sec
- [x] Extreme intensity generates ~99 req/sec
- [x] Activity log displays all three tiers
- [x] Metrics update in real-time
- [x] Simulation stops after duration
- [x] Console logs start/end messages
- [x] No memory leaks (60 entry limit)
- [x] No backend errors (pure client-side)
- [x] Dashboard remains responsive

## Demo Recording Script

### Optimal Settings for 5-Minute Video
```typescript
// Scene: Attack flood demonstration
await launchAttackFlood({
  intensity: 'medium',   // Visible but not overwhelming
  strategy: 'sustained', // Consistent activity
  duration: 45,          // 45 seconds of activity
  targets: ['cloud', 'local']
})
```

**Visual Result:**
- Activity log scrolls smoothly
- Metrics increment visibly
- Mix of allowed (red) and blocked (green) entries
- Clear difference between protected/unprotected tiers
- Professional, demo-ready appearance

## Conclusion

The flood attack simulation provides a reliable, demo-ready solution for showcasing Kong Guard AI's real-time threat detection and activity logging capabilities. By simulating attack traffic client-side, we ensure smooth playback, predictable performance, and professional visual results perfect for hackathon demonstration videos.

---

**Status:** Ready for demo recording  
**Next Step:** Run `python3 hackathon_demo_recorder.py` and click flood attack during Scene 5  

✅ **IMPLEMENTATION COMPLETE**
