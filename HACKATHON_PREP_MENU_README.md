# 🎬 Hackathon Prep Menu - Interactive CLI

## Overview

`hackathon-prep.sh` provides a unified, menu-driven interface for all Kong Guard AI hackathon preparation tasks.

## Quick Start

```bash
# Launch interactive menu
./hackathon-prep.sh

# Or use direct commands
./hackathon-prep.sh --help
```

## Features

### 1. 🎬 Demo Recording
- Record full demo (all 7 scenes)
- Test specific scenes
- Custom scene selection
- Screenshot-only mode
- View/list recordings

### 2. 🔧 Environment Setup
- Start/stop all services
- Check service status
- Reset environment
- View logs

### 3. ⚙️ Configuration
- View/edit configuration
- Toggle video/screenshots
- Change demo mode (headed/headless)
- Edit narrator timing
- Reset to defaults

### 4. 📦 Preparation Tasks
- Check dependencies
- Install Playwright
- Test dashboard access
- Check disk space
- Test network connections

### 5. 📹 Post-Production
- Convert WebM to MP4
- Open recording folder
- Generate reports
- Clean old recordings

### 6. 📋 Checklists
- Pre-recording checklist
- Post-recording checklist
- Submission checklist

### 7. 🔍 Troubleshooting
- Common issues and solutions
- Diagnostic information
- Quick fixes

### 8. 📚 Documentation
- List available documentation
- Quick links to guides

### 9. 🚀 Quick Actions
- Full demo workflow (one command)
- Quick test (scene 1 only)
- Status check (all systems)
- Package recording

## Command Line Usage

```bash
# Interactive menu (default)
./hackathon-prep.sh

# Direct commands
./hackathon-prep.sh --record-full        # Record full demo
./hackathon-prep.sh --test-scene-1       # Test scene 1
./hackathon-prep.sh --start-services     # Start services
./hackathon-prep.sh --stop-services      # Stop services
./hackathon-prep.sh --status             # Check status
./hackathon-prep.sh --convert-mp4        # Convert to MP4
./hackathon-prep.sh --clean              # Clean old recordings
./hackathon-prep.sh --help               # Show help
```

## Configuration

Edit `hackathon-prep.config` to customize:

```bash
# Demo settings
DEMO_MODE="headed"              # headed or headless
VIDEO_ENABLED="true"            # true or false
SCREENSHOTS_ENABLED="true"      # true or false
NARRATOR_TIMING="true"          # true or false

# Dashboard
DASHBOARD_URL="http://localhost:8080"

# Docker
DOCKER_COMPOSE_FILE="config/docker/docker-compose-presentation.yml"

# Video conversion
VIDEO_QUALITY="high"            # high, medium, or low
FFMPEG_PRESET="slow"            # slow, medium, fast, ultrafast
FFMPEG_CRF="18"                 # 18=high, 23=medium, 28=low

# Cleanup
AUTO_CLEANUP_DAYS=7             # Keep recordings for X days
KEEP_LAST_N_RECORDINGS=3        # Always keep N most recent

# Display
USE_COLORS="true"               # Enable colored output
SHOW_PROGRESS="true"            # Show progress indicators
```

## Menu Navigation

- **Numbers (1-9)**: Select menu options
- **B**: Go back to previous menu
- **Q**: Quit
- **0**: View settings

## Helper Scripts

The menu uses modular helper scripts in `scripts/hackathon/`:

- `demo-helpers.sh` - Recording functions
- `env-helpers.sh` - Environment management

## Quick Actions Workflow

### Full Demo (Option 9.1)
1. Checks/starts services
2. Records full demo
3. Generates report
4. Shows summary

### Quick Test (Option 9.2)
- Tests scene 1 only (fast validation)
- Headless mode
- Great for CI/CD

### Status Check (Option 9.3)
- Checks all dependencies
- Checks all services
- Checks disk space

### Package Recording (Option 9.4)
- Generates detailed report
- Converts WebM to MP4
- Ready for submission

## Examples

### First Time Setup
```bash
./hackathon-prep.sh
# Select: 4 (Preparation Tasks)
# Select: 1 (Check dependencies)
# Select: 2 (Install Playwright if needed)
# Select: B (Back)
# Select: 2 (Environment Setup)
# Select: 1 (Start all services)
```

### Record Demo
```bash
./hackathon-prep.sh --record-full
# Or interactively:
# Select: 1 (Demo Recording)
# Select: 1 (Record full demo)
```

### Quick Test
```bash
./hackathon-prep.sh --test-scene-1
# Or interactively:
# Select: 9 (Quick Actions)
# Select: 2 (Quick Test)
```

### Convert to MP4
```bash
./hackathon-prep.sh --convert-mp4
# Or interactively:
# Select: 5 (Post-Production)
# Select: 1 (Convert last WebM to MP4)
```

## Troubleshooting

### Dashboard not accessible
```bash
./hackathon-prep.sh
# Select: 2 (Environment Setup)
# Select: 3 (Check service status)
# If needed: 1 (Start all services)
```

### Playwright errors
```bash
./hackathon-prep.sh
# Select: 4 (Preparation Tasks)
# Select: 2 (Install Playwright)
```

### Low disk space
```bash
./hackathon-prep.sh
# Select: 5 (Post-Production)
# Select: 5 (Clean old recordings)
```

## Features

### ✅ Color-Coded Output
- 🟢 Green: Success messages
- 🟡 Yellow: Warnings
- 🔴 Red: Errors
- 🔵 Cyan: Info messages

### ✅ Status Icons
- ✓ Success
- ✗ Error
- ⚠ Warning
- ℹ Information

### ✅ Smart Defaults
- Loads configuration from file
- Falls back to sensible defaults
- Remembers your preferences

### ✅ Safety Features
- Confirms destructive operations
- Validates before execution
- Graceful error handling

## Integration

The menu integrates with:
- `hackathon_demo_recorder.py` - Main recorder
- `narrator_timing.json` - Timing configuration
- `demo_visual_effects.js` - Visual effects
- Docker Compose files - Services
- Existing shell scripts - Utilities

## Benefits

1. **No Command Memorization**: Navigate by menu
2. **Consistent Interface**: All operations standardized
3. **Safe Operations**: Validation and confirmations
4. **Configurable**: Persistent preferences
5. **Efficient**: Quick actions for common tasks
6. **Professional**: Polished interface
7. **Help Built-in**: Documentation integrated

## Advanced Usage

### Custom Configuration
```bash
# Create custom config
cp hackathon-prep.config my-custom.config
# Edit settings
nano my-custom.config
# Use custom config
CONFIG_FILE=my-custom.config ./hackathon-prep.sh
```

### Automation Scripts
```bash
#!/bin/bash
# Automated workflow
./hackathon-prep.sh --start-services
sleep 30
./hackathon-prep.sh --record-full
./hackathon-prep.sh --convert-mp4
./hackathon-prep.sh --stop-services
```

### CI/CD Integration
```bash
# In CI pipeline
./hackathon-prep.sh --test-scene-1
if [ $? -eq 0 ]; then
    echo "Demo recording working!"
else
    echo "Demo recording failed!"
    exit 1
fi
```

## Files

### Main Files
- `hackathon-prep.sh` - Main menu script
- `hackathon-prep.config` - Configuration file

### Helper Scripts
- `scripts/hackathon/demo-helpers.sh` - Recording functions
- `scripts/hackathon/env-helpers.sh` - Environment functions

### Related Files
- `hackathon_demo_recorder.py` - Recording script
- `narrator_timing.json` - Timing config
- `demo_visual_effects.js` - Visual effects

## Tips

1. **First Run**: Check dependencies (Option 4.1)
2. **Before Recording**: Start services (Option 2.1)
3. **Test First**: Use quick test (Option 9.2)
4. **Save Time**: Use quick actions (Option 9)
5. **Stay Organized**: Clean old recordings (Option 5.5)

## Support

For issues or questions:
1. Check Troubleshooting (Option 7)
2. View Documentation (Option 8)
3. Check Configuration (Option 0)

---

**Ready to prep for your hackathon submission!** 🎬🏆
