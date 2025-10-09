# Normal Traffic Incorrectly Counted as Blocked - Fix Summary

## Problem Description

Normal traffic was being incorrectly counted as "blocked" in the KongGuard AI dashboard metrics, leading to inflated detection rates and false statistics.

### Root Cause

The issue was in how the `blocked` status was determined when recording attack metrics. The system used a hardcoded threat score threshold (>= 0.7) to determine if traffic was blocked, **instead of using the actual `recommended_action` from the AI analysis**.

### Code Locations Affected

1. **`attack_flood_simulator.py:357`** - Primary issue
2. **`attack_comparison_engine.py:234`** - Secondary issue with similar logic

---

## The Fix

### Before (Incorrect Logic)

```python
# attack_flood_simulator.py (line 357)
blocked=result_data.get("threat_score", 0.0) >= 0.7,
```

**Problem:** This incorrectly marked traffic as blocked if threat_score >= 0.7, even if the AI recommended "allow" or "monitor" actions.

### After (Correct Logic)

```python
# attack_flood_simulator.py (lines 346-349, 361)
# Determine blocked status based on recommended_action, not just threat_score
recommended_action = result_data.get("recommended_action", "unknown")
is_blocked = recommended_action in ["block", "rate_limit"]

# ... later in AttackResult
action_taken=recommended_action,
blocked=is_blocked,
```

**Fix:** Now correctly uses the AI's `recommended_action` field to determine blocked status.

---

## Files Modified

### 1. `attack_flood_simulator.py`

**Changes:**
- Line 346-349: Added logic to extract `recommended_action` and determine `is_blocked` based on action type
- Line 360-361: Updated to use `recommended_action` and `is_blocked` variables instead of hardcoded threshold

**Impact:** All attack flood simulations now correctly reflect whether traffic was actually blocked vs. just having a high threat score.

### 2. `attack_comparison_engine.py`

**Changes:**
- Line 232-234: Changed from `threat_score >= 0.7 or recommended_action == "block"` to only use `recommended_action in ["block", "rate_limit"]`
- Line 239: Use `result_data.get("threat_score", 0.0)` directly instead of storing in variable
- Line 243: Use `recommended_action` variable directly

**Impact:** Attack comparison tests now accurately report blocked vs. allowed traffic across all tiers.

---

## How It Works Now

### Decision Flow

```
AI Analysis
    ↓
Generates: threat_score (0.0-1.0) + recommended_action (allow/monitor/rate_limit/block)
    ↓
Blocked Determination:
    if recommended_action in ["block", "rate_limit"]:
        blocked = True
    else:
        blocked = False  # Even if threat_score is high!
    ↓
Database Storage: attack_metrics.blocked = blocked
    ↓
Dashboard Metrics: Counts only truly blocked requests
```

### Example Scenarios

| Scenario | Threat Score | Recommended Action | Old Logic (Wrong) | New Logic (Correct) |
|----------|-------------|-------------------|-------------------|---------------------|
| Normal Traffic | 0.1 | allow | ❌ Not Blocked | ✅ Not Blocked |
| Suspicious but Safe | 0.75 | monitor | ❌ BLOCKED | ✅ Not Blocked |
| Rate Limited | 0.65 | rate_limit | ❌ Not Blocked | ✅ Blocked |
| Dangerous Attack | 0.95 | block | ✅ Blocked | ✅ Blocked |

---

## Testing

### Test Script

Created `test_normal_traffic_fix.py` to verify:

1. **Normal Traffic Tests:** Ensures legitimate requests are not marked as blocked
   - Normal GET requests
   - Normal POST requests
   - Health check requests

2. **Attack Detection Tests:** Ensures real attacks are still correctly blocked
   - SQL injection attacks
   - XSS attacks
   - Command injection

### Running the Test

```bash
# Make sure the AI service is running on port 18002
python test_normal_traffic_fix.py
```

Expected output:
```
✅ ALL TESTS PASSED!
Normal traffic is correctly classified and not counted as blocked.
```

---

## Impact on Metrics

### Dashboard Changes

After this fix, the dashboard will show:

- **Accurate Detection Rate:** Only counts requests where action was `block` or `rate_limit`
- **Correct Blocked Count:** Reflects actual enforcement actions, not just high threat scores
- **Proper False Positive Rate:** Normal traffic with high scores but `allow` action won't inflate blocked counts

### Example Before/After

**Before Fix (Incorrect):**
```
Total Requests: 100
Blocked: 45  (includes 20 normal traffic with threat_score > 0.7)
Detection Rate: 45%  ← WRONG
```

**After Fix (Correct):**
```
Total Requests: 100
Blocked: 25  (only actual block/rate_limit actions)
Detection Rate: 25%  ← CORRECT
```

---

## Verification Checklist

- [x] Fixed `attack_flood_simulator.py` blocked determination logic
- [x] Fixed `attack_comparison_engine.py` blocked determination logic
- [x] Created test script to verify normal traffic is not incorrectly blocked
- [x] Documented the changes and impact
- [ ] Run test script to confirm fix works
- [ ] Verify dashboard metrics update correctly
- [ ] Test with real attack flood simulation
- [ ] Check historical data interpretation (old data still has incorrect blocked flags)

---

## Future Improvements

### 1. Database Migration (Optional)

If historical data accuracy is important, consider running a migration to recalculate `blocked` status for existing records:

```sql
UPDATE attack_metrics 
SET blocked = CASE 
    WHEN action_taken IN ('block', 'rate_limit') THEN 1 
    ELSE 0 
END;
```

### 2. Add Validation

Consider adding validation to ensure `recommended_action` is always present:

```python
recommended_action = result_data.get("recommended_action")
if not recommended_action:
    logger.warning("Missing recommended_action in AI response")
    recommended_action = "monitor"  # Safe default
```

### 3. Enhanced Metrics

Add separate metrics to track:
- High threat score but allowed (suspicious but safe)
- Low threat score but blocked (policy-based blocks)
- Action breakdown (allow/monitor/rate_limit/block percentages)

---

## Related Files

- `/Users/jacques/DevFolder/KongGuardAI/attack_flood_simulator.py` - Main fix
- `/Users/jacques/DevFolder/KongGuardAI/attack_comparison_engine.py` - Secondary fix
- `/Users/jacques/DevFolder/KongGuardAI/ai-service/app.py` - AI analysis logic (unchanged but referenced)
- `/Users/jacques/DevFolder/KongGuardAI/test_normal_traffic_fix.py` - Verification test

---

## Notes

- The AI service's threat analysis logic was **not changed** - it already correctly returns both `threat_score` and `recommended_action`
- The issue was purely in how the metrics collection layer interpreted and stored the blocked status
- This fix ensures the system respects the AI's decision-making rather than applying arbitrary thresholds

---

## Conclusion

The fix ensures that **blocked status accurately reflects enforcement actions** rather than just threat scores. Normal traffic will no longer be incorrectly counted as blocked, even if it receives a moderate threat score for monitoring purposes.

The system now properly distinguishes between:
- **High threat but allowed** (monitoring, learning, false positive prevention)
- **Low threat but blocked** (policy enforcement, rate limiting)
- **Actual threats blocked** (the only case that should increment blocked counters)
