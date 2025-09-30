# 🎬 Kong Guard AI - Hackathon Quick Reference

## One-Line Commands

```bash
# Interactive menu
./hackathon-prep.sh

# Record full demo
./hackathon-prep.sh --record-full

# Quick test
./hackathon-prep.sh --test-scene-1

# Check status
./hackathon-prep.sh --status

# Start services
./hackathon-prep.sh --start-services

# Convert to MP4
./hackathon-prep.sh --convert-mp4
```

## Menu Quick Navigation

| Key | Action |
|-----|--------|
| `1` | Demo Recording |
| `2` | Environment Setup |
| `3` | Configuration |
| `4` | Preparation Tasks |
| `5` | Post-Production |
| `9` | Quick Actions ⭐ |
| `B` | Go Back |
| `Q` | Quit |

## Common Workflows

### First Time Setup
```bash
./hackathon-prep.sh
# → 4 (Preparation)
# → 1 (Check dependencies)
# → 2 (Start services)
# → 1 (Start services)
```

### Record Demo
```bash
./hackathon-prep.sh --record-full
```

### Quick Full Workflow
```bash
./hackathon-prep.sh
# → 9 (Quick Actions)
# → 1 (Full Demo)
```

## Configuration File

Location: `hackathon-prep.config`

```bash
# Key settings
DEMO_MODE="headed"              # or "headless"
VIDEO_ENABLED="true"            # or "false"
SCREENSHOTS_ENABLED="true"      # or "false"
DASHBOARD_URL="http://localhost:8080"
```

## Output Structure

```
demo_recordings/hackathon_demo_TIMESTAMP/
├── video.webm                  # 4:45 video
├── screenshots/                # 17 PNG files
│   ├── 01_overview_status.png
│   └── ...
└── timing_log.json            # Timing data
```

## Quick Actions (Menu 9)

| # | Action | Description |
|---|--------|-------------|
| 1 | Full Demo | Start services + record + report |
| 2 | Quick Test | Test scene 1 (fast) |
| 3 | Status Check | Check all systems |
| 4 | Package | Generate report + convert MP4 |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Dashboard not accessible | Menu: 2 → 1 (Start services) |
| Playwright error | Menu: 4 → 2 (Install Playwright) |
| Low disk space | Menu: 5 → 5 (Clean recordings) |
| Recording failed | Menu: 7 (Troubleshooting) |

## Files

| File | Purpose |
|------|---------|
| `hackathon-prep.sh` | Main menu script |
| `hackathon-prep.config` | Configuration |
| `hackathon_demo_recorder.py` | Recording engine |
| `narrator_timing.json` | Scene timing |
| `demo_visual_effects.js` | Visual effects |

## Help

```bash
./hackathon-prep.sh --help      # Command help
./hackathon-prep.sh             # Interactive help
```

---

**Ready to record your hackathon demo!** 🎬🏆
