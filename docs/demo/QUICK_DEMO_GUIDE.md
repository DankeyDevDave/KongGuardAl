# 🎬 Quick Demo Recording Guide

## One-Command Demo Recording

```bash
# Full hackathon demo with visual effects (RECOMMENDED)
./hackathon_demo_recorder.py --headed --screenshots --narrator-timing
```

## 📋 Pre-Recording Checklist

```bash
# 1. Start services
docker-compose -f docker-compose-presentation.yml up -d

# 2. Wait for services (30 seconds)
sleep 30

# 3. Verify dashboard
curl http://localhost:8080

# 4. Start recording
./hackathon_demo_recorder.py --headed --screenshots
```

## ⏱️ Expected Output

- **Duration**: 4 minutes 45 seconds
- **Video**: `demo_recordings/hackathon_demo_TIMESTAMP/video.webm`
- **Screenshots**: 17 PNG files in `screenshots/` folder
- **Timing Log**: `timing_log.json` with performance data

## 🎯 Scene Overview

| Scene | Time | Focus |
|-------|------|-------|
| 1. Overview | 0:00-0:30 | Dashboard status, metrics |
| 2. Architecture | 0:30-1:15 | Threat flow visualization |
| 3. Attack Simulator | 1:15-2:00 | SQL, XSS, DDoS demos |
| 4. Demo Sequence | 2:00-3:00 | Automated testing |
| 5. AI Reasoning | 3:00-3:45 | Analysis engine |
| 6. Dev Controls | 3:45-4:15 | Dashboard controls |
| 7. Closing | 4:15-4:45 | Final summary |

## 🎤 Voiceover Script

Use `demo-voiceover-script.md` for narration text that matches timing exactly.

## 🔧 Quick Troubleshooting

**Dashboard not loading?**
```bash
docker-compose -f docker-compose-presentation.yml restart
```

**Visual effects not working?**
- Check browser console (F12)
- Verify `demo_visual_effects.js` exists
- Try refreshing dashboard

**Test specific scenes?**
```bash
./hackathon_demo_recorder.py --scenes 1,2,3
```

## 📸 Screenshot List

1. `01_overview_status.png` - Dashboard connected
2. `01_metrics_tiles.png` - Metrics overview
3. `02_architecture_flow.png` - Flow diagram
4. `03_attack_simulator.png` - Simulator panel
5. `03_normal_traffic_result.png` - Normal request
6. `03_sql_injection_result.png` - SQL attack blocked
7. `03_xss_attack_result.png` - XSS attack blocked
8. `03_ddos_burst_result.png` - DDoS mitigation
9. `04_demo_sequence_start.png` - Demo start
10. `04_demo_sequence_mid.png` - Demo progress
11. `04_threat_feed_active.png` - Live feed
12. `05_ai_reasoning.png` - AI analysis
13. `05_threat_distribution.png` - Threat chart
14. `05_metrics_detail.png` - Detailed metrics
15. `06_dashboard_controls.png` - Controls
16. `07_closing_flow.png` - Final flow
17. `07_closing_overview.png` - Final overview

## 📹 Post-Production

1. **Video File**: Convert WebM to MP4 if needed
   ```bash
   ffmpeg -i video.webm -c:v libx264 -c:a aac demo.mp4
   ```

2. **Add Voiceover**: Use video editor to sync audio

3. **Final Export**: 1920x1080, MP4, 4:30-5:00 duration

## 🏆 Submission Checklist

- [ ] Video recorded (4:45 duration)
- [ ] Screenshots captured (17 files)
- [ ] Voiceover added and synced
- [ ] Final edit complete
- [ ] Export as MP4 (1920x1080)
- [ ] Upload to hackathon platform

## 📚 Full Documentation

- `HACKATHON_DEMO_RECORDER_README.md` - Complete guide
- `DEMO_RECORDING_IMPLEMENTATION.md` - Technical details
- `narrator_timing.json` - Timing configuration
- `demo-voiceover-script.md` - Narration text

---

**Ready to create your hackathon demo video in minutes!** 🎬✨
