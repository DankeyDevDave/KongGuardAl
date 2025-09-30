# 🎬 Hackathon Demo Recorder

Professional Playwright-based demo recording system with visual indicators and perfect narrator timing.

## 🌟 Features

### Visual Effects
- **Click Indicators**: Animated ripple effects on every click (Kong Guard AI branded)
- **Element Highlighting**: Pulsing glow effect before interactions
- **Progress Indicators**: On-screen scene badges showing "Scene X/7"
- **Screenshot Flash**: Visual feedback when screenshots are captured
- **Scene Progress Bar**: Real-time progress with timing information

### Automation
- **Narrator Timing Alignment**: Precise wait times matching voiceover script
- **Automatic Screenshots**: Captures 15-20 screenshots at key stages
- **Video Recording**: Full 1920x1080 WebM video output
- **Timing Analysis**: JSON log comparing planned vs actual timing

### Customization
- **Scene Selection**: Record specific scenes only for testing
- **Headed/Headless**: Choose visible browser or background recording
- **Configurable Timing**: Edit `narrator_timing.json` to adjust durations

## 🚀 Quick Start

### Prerequisites

```bash
# Install Python dependencies
pip install playwright

# Install browser engines
playwright install chromium
```

### Basic Usage

```bash
# Full demo recording with all features (RECOMMENDED)
./hackathon_demo_recorder.py --headed --screenshots --narrator-timing

# Quick test (first 3 scenes only)
./hackathon_demo_recorder.py --scenes 1,2,3

# Background recording (headless)
./hackathon_demo_recorder.py --headless
```

## 📋 Scene Structure

The demo follows the hackathon submission timing requirements:

| Scene | Title | Duration | Actions |
|-------|-------|----------|---------|
| 1 | Overview & Status | 0:00-0:30 (30s) | Show dashboard, metrics |
| 2 | Architecture Context | 0:30-1:15 (45s) | Explain flow, highlight visualization |
| 3 | Attack Simulator | 1:15-2:00 (45s) | Demo normal traffic, SQL, XSS, DDoS |
| 4 | Full Demo Sequence | 2:00-3:00 (60s) | Run automated demo |
| 5 | AI Reasoning | 3:00-3:45 (45s) | Show analysis engine, metrics |
| 6 | Developer Controls | 3:45-4:15 (30s) | Dashboard controls overview |
| 7 | Closing | 4:15-4:45 (30s) | Final impact, fade out |

**Total Duration**: 4 minutes 45 seconds (within hackathon 3-5 minute requirement)

## 📁 Output Structure

After recording, you'll find:

```
demo_recordings/hackathon_demo_20241230_143022/
├── video.webm                          # Main video recording
├── screenshots/
│   ├── 01_overview_status.png          # Dashboard status
│   ├── 01_metrics_tiles.png            # Metrics overview
│   ├── 02_architecture_flow.png        # Flow visualization
│   ├── 03_attack_simulator.png         # Simulator panel
│   ├── 03_normal_traffic_result.png    # Normal request
│   ├── 03_sql_injection_result.png     # SQL attack blocked
│   ├── 03_xss_attack_result.png        # XSS attack blocked
│   ├── 03_ddos_burst_result.png        # DDoS mitigation
│   ├── 04_demo_sequence_start.png      # Demo sequence
│   ├── 04_demo_sequence_mid.png        # Sequence in progress
│   ├── 04_threat_feed_active.png       # Live feed
│   ├── 05_ai_reasoning.png             # AI analysis
│   ├── 05_threat_distribution.png      # Threat breakdown
│   ├── 05_metrics_detail.png           # Detailed metrics
│   ├── 06_dashboard_controls.png       # Control panel
│   ├── 07_closing_flow.png             # Final flow
│   └── 07_closing_overview.png         # Final overview
└── timing_log.json                     # Timing analysis
```

## ⚙️ Configuration

### narrator_timing.json

Main configuration file defining:
- Scene titles and durations
- Narration text (for reference)
- Actions per scene (highlight, click, wait, screenshot)
- Brand colors and styling

Edit this file to:
- Adjust wait times for narration
- Add/remove screenshots
- Modify scene order
- Change visual styling

### demo_visual_effects.js

JavaScript injected into the browser for visual effects:
- Click ripple animations
- Element highlighting
- Progress indicators
- Screenshot flash effects

Customize for different visual styles.

## 🎯 Command Line Options

```bash
./hackathon_demo_recorder.py [OPTIONS]

Options:
  --headed              Run browser in headed mode (visible) [default]
  --headless            Run browser in headless mode (background)
  --screenshots         Capture screenshots at each stage [default]
  --no-screenshots      Disable screenshot capture
  --video               Record video [default]
  --no-video            Disable video recording (screenshots only)
  --narrator-timing     Use narrator timing from config [default]
  --config PATH         Path to timing config file [default: narrator_timing.json]
  --scenes NUMBERS      Comma-separated scene numbers (e.g., "1,3,5")
  -h, --help            Show help message
```

## 📊 Timing Analysis

The `timing_log.json` file contains:

```json
{
  "demo_info": { ... },
  "recording_date": "2024-09-30T14:30:22",
  "scenes": [
    {
      "scene_number": 1,
      "scene_title": "Overview & Status",
      "planned_duration": 30,
      "actual_duration": 31.2,
      "variance": 1.2
    },
    ...
  ],
  "total_planned": 285,
  "total_actual": 287.5,
  "total_variance": 2.5
}
```

Use this to:
- Verify timing accuracy
- Adjust narrator script
- Optimize scene durations

## 🎤 Narrator Alignment

The recorder creates perfect timing alignment with your voiceover:

1. **Record the demo** with `--narrator-timing`
2. **Review timing_log.json** to see actual durations
3. **Record voiceover** using the video as visual reference
4. **Use demo-voiceover-script.md** for narration text

Each scene has built-in wait times matching the narration duration.

## 🔧 Troubleshooting

### Dashboard Not Loading
```bash
# Verify services are running
docker-compose -f docker-compose-presentation.yml ps

# Check dashboard URL is accessible
curl http://localhost:8080
```

### Visual Effects Not Working
- Check browser console (F12) for JavaScript errors
- Verify `demo_visual_effects.js` exists in project root
- Try refreshing the dashboard before recording

### Screenshots Missing
- Ensure `--screenshots` flag is used (default)
- Check file permissions in demo_recordings folder
- Verify disk space available

### Timing Drift
- Expected variance: ±2-3 seconds total
- Network latency affects AI service calls
- Adjust wait times in `narrator_timing.json` if needed

## 🎓 Best Practices

1. **Test Run First**: Record scenes 1-2 only to verify setup
2. **Clean Environment**: Fresh browser, no extensions
3. **Stable Network**: Ensure AI services are responsive
4. **Review Screenshots**: Check quality before full recording
5. **Multiple Takes**: Record 2-3 times, pick best version

## 📹 Post-Production Tips

### Video Editing
- Use screenshots as slide transitions
- Add title cards between scenes
- Overlay metrics/statistics
- Add background music (low volume)

### Voiceover Recording
- Record in quiet environment
- Use `demo-voiceover-script.md` as script
- Match timing to video (use timing_log.json)
- Edit out breaths and pauses

### Final Output
- Export as MP4 (H.264) for compatibility
- 1920x1080 resolution
- Target 4:30-5:00 minutes
- Add Kong Guard AI branding/watermark

## 🏆 Hackathon Submission Checklist

- [ ] Record full demo (all 7 scenes)
- [ ] Verify video quality (1080p, clear visuals)
- [ ] Review all screenshots (15-20 total)
- [ ] Check timing (4:30-5:00 minutes)
- [ ] Add voiceover narration
- [ ] Test playback on different devices
- [ ] Export final video as MP4
- [ ] Upload to submission platform

## 🔗 Related Files

- `narrator_timing.json` - Scene timing configuration
- `demo_visual_effects.js` - Visual effects JavaScript
- `demo-voiceover-script.md` - Narration script
- `demo-recording-script.md` - Detailed scene guide
- `comprehensive-demo-guide.md` - Complete demo system documentation

---

**Ready to create your hackathon demo video!** 🎬✨
