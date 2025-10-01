# Manual Demo Recording Script - Kong Guard AI
**5-Minute Hackathon Demo with Synchronized Voice Narration**

---

## Pre-Recording Setup

### ✅ Required Services Running
```bash
# Verify all services are up
docker ps --format "{{.Names}}\t{{.Status}}" | grep -E "(dashboard|websocket|ai-service)"

# Should show:
# kong-guard-dashboard        Up
# kong-guard-ai-websocket    Up (healthy)
# kong-guard-ai-cloud        Up (healthy)
# kong-guard-ai-ollama       Up (healthy)
```

### ✅ Open Dashboard
1. Browser: `http://localhost:3000`
2. Press `F11` for full-screen mode
3. Ensure WebSocket connected (green indicator top-right)

### ✅ Recording Setup
1. **Screen Recorder**: QuickTime/OBS Studio ready
2. **Resolution**: 1920x1080 or native display
3. **Audio**: System audio enabled (to capture voice narration)
4. **Script**: This document visible on second monitor
5. **Voice Files**: Demo recordings ready to play (optional)

---

## 🎬 Scene-by-Scene Recording Guide

### **SCENE 1: Overview & Status** 
**⏱️ Time: 0:00 - 0:30 (30 seconds)**  
**🎙️ Narration:** 21.2 seconds

> *"Welcome to Kong Guard AI, the first autonomous AI security agent built directly into Kong Gateway. Everything on screen is running live—our gateway, the Kong Guard AI plugin, and the AI co-pilot services that inspect every request in real time."*

#### Actions:
| Time | Action | Details |
|------|--------|---------|
| 0:00 | **START RECORDING** | Hit record, let dashboard settle |
| 0:02 | Hover | Move mouse to main "Kong Guard AI" title |
| 0:05 | Move | Pan to metrics bar at top |
| 0:08 | Hover | "Total Requests" tile (pause 2s) |
| 0:10 | Hover | "Threats Blocked" tile (pause 2s) |
| 0:12 | Hover | "Average Latency" tile (pause 2s) |
| 0:15 | Hold | Keep mouse over metrics area |
| 0:21 | Wait | Let narration finish |
| 0:30 | → Scene 2 | Transition smoothly |

**💡 Tips:**
- Smooth, deliberate mouse movements
- No clicks in this scene - observation only
- Let metrics display naturally

---

### **SCENE 2: Architecture Context**
**⏱️ Time: 0:30 - 1:15 (45 seconds)**  
**🎙️ Narration:** 21.9 seconds

> *"APIs face evolving attacks that signature rules miss. Manual triage can't keep pace. Kong Guard AI embeds agentic intelligence at the edge. The Lua plugin intercepts traffic, streams rich context to our AI engine, and gets millisecond verdicts—allow, rate-limit, or block—before the request hits an upstream service."*

#### Actions:
| Time | Action | Details |
|------|--------|---------|
| 0:30 | Pan left | Move to left Control Panel |
| 0:35 | Hover | WebSocket connection indicator (top-right) |
| 0:40 | Pan right | Move back to main dashboard area |
| 0:45 | Scroll | Gently scroll down to show threat feed |
| 0:50 | Scroll up | Return to top of dashboard |
| 0:55 | Center | Position mouse center-screen |
| 1:00 | Hold | Minimal movement during narration |
| 1:15 | → Scene 3 | Ready for interaction |

**💡 Tips:**
- Show the full dashboard layout
- No clicks - emphasize the architecture
- Slow, professional movements

---

### **SCENE 3: Attack Simulator** 🎯
**⏱️ Time: 1:15 - 2:00 (45 seconds)**  
**🎙️ Narration:** 22.5 seconds

> *"On the left is our attack simulator. I'll start with normal traffic to set a baseline: notice the low threat score. Now I trigger SQL injection, XSS, and a bursty DDoS. The AI analysis panel updates instantly, and the live feed shows each attempt with explained actions."*

#### Actions:
| Time | Action | Details |
|------|--------|---------|
| 1:15 | Move | Pan to left Control Panel |
| 1:18 | Hover | "Target Tier" dropdown (pause) |
| 1:20 | **CLICK** | Target Tier → **Select "Cloud AI Protection"** |
| 1:23 | Scroll | Scroll to "Quick Attack Tests" section |
| 1:25 | **CLICK** | **"Normal Traffic"** button (green Activity icon) |
| 1:28 | Watch | Observe metrics update (2 seconds) |
| 1:30 | **CLICK** | **"SQL Injection"** button (red Target icon) |
| 1:35 | Glance right | Look at threat feed updating |
| 1:38 | **CLICK** | **"XSS Attack"** button (orange Zap icon) |
| 1:43 | Watch | See AI analysis update |
| 1:46 | **CLICK** | **"Command Injection"** button (yellow AlertTriangle) |
| 1:50 | Pan right | Move to metrics area |
| 1:55 | Hover | Threat feed to show detection results |
| 2:00 | → Scene 4 | Prepare for flood attack |

**💡 Tips:**
- **Space clicks 3-5 seconds apart** - allows time to see results
- After each click, pause briefly to show visual feedback
- Watch the threat feed (right side) update after each attack
- Metrics counters should increment visibly

**🎯 Button Locations:**
- Normal Traffic: Green icon (Activity)
- SQL Injection: Red icon (Target)
- XSS Attack: Orange icon (Zap)
- Command Injection: Yellow icon (AlertTriangle)

---

### **SCENE 4: Full Demo Sequence** 🚀
**⏱️ Time: 2:00 - 3:00 (60 seconds)**  
**🎙️ Narration:** 23.5 seconds

> *"Let's run the full demo sequence. This cycles through normal requests and malicious payloads, including a zero-day variant we crafted specifically for the hackathon. As events stream in, the AI reasons about intent, escalates from monitor to rate limit, and blocks high-risk calls automatically—all under 100 milliseconds."*

#### Actions:
| Time | Action | Details |
|------|--------|---------|
| 2:00 | Scroll down | In Control Panel to "Attack Flood Control" |
| 2:03 | Hover | "Intensity" dropdown (red border area) |
| 2:05 | **CLICK** | Intensity → **Select "Medium (50 req/s)"** |
| 2:10 | Hover | "Strategy" dropdown |
| 2:12 | **CLICK** | Strategy → **Select "Blended Traffic"** |
| 2:17 | Hover | "Duration" input field |
| 2:19 | **CLICK** | Duration field → **Change to "30"** seconds |
| 2:24 | Hover | Red "LAUNCH ATTACK FLOOD" button (pause) |
| 2:27 | **CLICK** | **"LAUNCH ATTACK FLOOD"** button |
| 2:28 | Watch | Progress bar fills, "ATTACK ACTIVE" shows |
| 2:30-2:50 | Observe | Metrics update rapidly (20 seconds) |
| 2:35 | Pan right | Move to threat feed showing live updates |
| 2:45 | Hover | Metrics bar showing counters incrementing |
| 2:50 | Pan | AI Analysis section (if visible) |
| 2:55 | Center | Position for scene transition |
| 3:00 | → Scene 5 | Attack should be completing |

**💡 Tips:**
- **Critical**: Attack flood runs for 30 seconds - creates continuous activity
- Watch progress bar fill from 0% to 100%
- Metrics will update rapidly during this scene
- Threat feed scrolls with new detections
- This is the most dynamic scene - let the system work!

**🎯 Attack Flood Settings:**
- Intensity: Medium (50 req/s) - balanced load
- Strategy: Blended Traffic - mixes normal + attacks
- Duration: 30 seconds - fits scene timing perfectly

---

### **SCENE 5: AI Reasoning & Metrics** 🧠
**⏱️ Time: 3:00 - 3:45 (45 seconds)**  
**🎙️ Narration:** 19.7 seconds

> *"The thinking overlay reveals what the AI is checking—previous behavior, anomaly scores, and shared memory from earlier attacks. On the right, metrics confirm how many threats were blocked, how many were allowed, and that our latency budget stays under 10 milliseconds even during spikes."*

#### Actions:
| Time | Action | Details |
|------|--------|---------|
| 3:00 | Pan right | Move to right side of dashboard |
| 3:03 | Hover | "AI Analysis Engine" section (center) |
| 3:08 | Move up | Pan to metrics bar at top |
| 3:10 | Hover | "Threats Blocked" counter (pause 2s) |
| 3:15 | Hover | "Average Latency" display (pause 2s) |
| 3:20 | Pan | Move to threat distribution (if present) |
| 3:25 | Hover | Any threat severity indicators |
| 3:30 | Slow pan | Across full metrics area |
| 3:40 | Center | Prepare for controls scene |
| 3:45 | → Scene 6 | Transition to controls |

**💡 Tips:**
- Focus on the "thinking" aspect - show AI reasoning
- Highlight sub-10ms latency achievement
- Let viewers absorb the metrics
- No clicks - observation scene

---

### **SCENE 6: Developer Controls** ⚙️
**⏱️ Time: 3:45 - 4:15 (30 seconds)**  
**🎙️ Narration:** 16.3 seconds

> *"Operators stay in control with simple commands. I can inspect the swarm of security agents, review stored threat memories, and update enforcement policies without redeploying anything—this fits right into standard Kong Gateway workflows."*

#### Actions:
| Time | Action | Details |
|------|--------|---------|
| 3:45 | Pan | Move to mode toggle at top (if visible) |
| 3:50 | **CLICK** | Mode toggle → Switch between Monitor/Control/Hybrid modes |
| 3:55 | Hover | Control Panel header area |
| 4:00 | Scroll | Through available attack types (show variety) |
| 4:05 | Hover | Tier selection dropdown (emphasize control) |
| 4:10 | Pan | Return to main dashboard view |
| 4:15 | → Scene 7 | Prepare for closing |

**💡 Tips:**
- Show developer-friendly controls
- Emphasize ease of use
- Quick, confident movements
- Demonstrate operational control

---

### **SCENE 7: Closing** 🏁
**⏱️ Time: 4:15 - 4:45 (30 seconds)**  
**🎙️ Narration:** 23.1 seconds

> *"Kong Guard AI delivers 95 percent plus detection accuracy, sub–10 millisecond decisions, and autonomous protection ready for Kong Konnect. It's built to stop zero-day attacks before they reach your APIs. We're excited to share Kong Guard AI with the Kong Agentic AI Hackathon judges—thank you for watching."*

#### Actions:
| Time | Action | Details |
|------|--------|---------|
| 4:15 | Scroll up | Return to very top of dashboard |
| 4:18 | Center | Mouse on main "Kong Guard AI" title |
| 4:22 | Slow pan | Left to right across full dashboard (5 seconds) |
| 4:27 | Hover | Final metrics showing session summary |
| 4:32 | Center | Position mouse center-screen |
| 4:37 | Fade | Slowly move cursor to bottom-right corner |
| 4:40 | Hold | Keep steady position |
| 4:45 | **STOP RECORDING** | End of demo |

**💡 Tips:**
- Professional, confident closing
- Let the final stats shine
- Smooth fade-out of cursor
- Hold final frame for 2-3 seconds before stopping

---

## 🎯 Quick Reference - All Clicks

```
SCENE 3 - Attack Tests (4 clicks):
├─ 1:20 → Click "Target Tier" → Select "Cloud AI Protection"
├─ 1:25 → Click "Normal Traffic" button
├─ 1:30 → Click "SQL Injection" button
├─ 1:38 → Click "XSS Attack" button
└─ 1:46 → Click "Command Injection" button

SCENE 4 - Flood Attack (4 clicks):
├─ 2:05 → Click "Intensity" → Select "Medium (50 req/s)"
├─ 2:12 → Click "Strategy" → Select "Blended Traffic"
├─ 2:19 → Click "Duration" → Type "30"
└─ 2:27 → Click "LAUNCH ATTACK FLOOD" (BIG RED BUTTON)

SCENE 6 - Controls (1 click):
└─ 3:50 → Click "Mode Toggle" (optional)

TOTAL: 9 clicks across 5-minute demo
```

---

## 📋 Pre-Flight Checklist

### ✅ Before You Start:
- [ ] All Docker containers running and healthy
- [ ] Dashboard accessible at `http://localhost:3000`
- [ ] WebSocket connected (green indicator visible)
- [ ] Browser in full-screen mode (F11)
- [ ] Screen recorder ready (QuickTime/OBS)
- [ ] This script visible on second monitor
- [ ] Audio enabled for voice narration
- [ ] Clean browser (no extensions interfering)

### ✅ During Recording:
- [ ] Follow time markers precisely
- [ ] Pause 1-2 seconds before each click
- [ ] Space clicks 3-5 seconds apart
- [ ] Watch for visual feedback after clicks
- [ ] Keep mouse movements smooth and professional
- [ ] Monitor WebSocket connection status

### ✅ After Recording:
- [ ] Review video immediately
- [ ] Check all 7 scenes captured
- [ ] Verify audio sync (if narration recorded)
- [ ] Confirm video length: 4:45 - 5:00 minutes
- [ ] Check resolution: 1920x1080 or higher
- [ ] Export high quality: H.264, MP4

---

## 🚨 Troubleshooting During Recording

### If WebSocket Disconnects:
```bash
# Pause recording, fix issue
docker restart kong-guard-ai-websocket
# Wait 10 seconds for startup
# Resume from last successful scene
```

### If Attack Buttons Don't Respond:
- Check browser console (F12) for errors
- Verify AI services running: `docker ps | grep ai-service`
- WebSocket must be connected (check indicator)

### If Metrics Don't Update:
- WebSocket connection issue - check top-right indicator
- Restart WebSocket service if needed
- Can continue - visual flow still works

---

## 🎬 Professional Recording Tips

### Mouse Movement Guidelines:
1. **Smooth, deliberate** - No sudden jumps
2. **Telegraph actions** - Hover 1-2s before clicking
3. **Pause after clicks** - Show results (2-3s)
4. **Purposeful movement** - Every motion has intent
5. **Natural speed** - Not too slow, not rushed

### Timing Best Practices:
- **Before click**: Hover 1-2 seconds
- **Between clicks**: Wait 3-5 seconds
- **After critical actions**: Pause 2-3 seconds
- **Scene transitions**: Smooth, not abrupt

### Visual Presentation:
- Keep cursor visible at all times
- Avoid rapid back-and-forth movements
- Let animations complete before moving on
- Give viewers time to read text elements

---

## 📊 Expected Final Output

**Video Specifications:**
- **Duration**: 4:45 - 5:00 minutes
- **Resolution**: 1920x1080 (Full HD)
- **Format**: MP4 (H.264 codec)
- **Frame Rate**: 30 fps minimum
- **Audio**: AAC, 192 kbps (if narration included)
- **File Size**: ~30-50 MB expected

**Content Checklist:**
- ✅ All 7 scenes complete
- ✅ Voice narration synchronized
- ✅ 9 clicks executed correctly
- ✅ Metrics update visibly
- ✅ Attack flood demonstrates system
- ✅ Professional presentation quality
- ✅ No technical glitches visible
- ✅ Clear, smooth recording

---

## 🎤 Voice Narration Options

### Option 1: Simultaneous Recording (Recommended)
**Play voice files during screen recording:**
1. Open voice files in audio player
2. Start screen recording with system audio capture
3. Play each scene's voice file at correct timestamp
4. Recording captures both video + audio together
5. **Result**: Single file ready to submit

### Option 2: Post-Production Sync
**Record silent video, add audio later:**
1. Record video following script timing
2. Export video file
3. Import to video editor (iMovie/DaVinci Resolve)
4. Add voice narration files to timeline
5. Sync audio to video actions
6. Export final combined video
7. **Result**: More control, requires editing

---

## 🏆 Final Quality Check

Before submitting, verify:
- [ ] Total duration: 4:45 - 5:00 minutes ✅
- [ ] All clicks visible and successful ✅
- [ ] Metrics update during demo ✅
- [ ] Attack flood shows activity ✅
- [ ] Audio synchronized properly ✅
- [ ] No recording artifacts ✅
- [ ] Professional presentation ✅
- [ ] Video plays smoothly ✅

---

**🎬 You're ready to record! Take a deep breath, follow the script, and showcase Kong Guard AI!**

**Good luck with your hackathon submission! 🚀**
