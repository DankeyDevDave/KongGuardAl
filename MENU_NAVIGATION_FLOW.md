# 🗺️ Kong Guard AI - Menu Navigation Flow Diagram

## 📁 Main Menu File
**File**: `hackathon-prep.sh` (719 lines)

---

## 🎯 Main Menu Structure

```
┌─────────────────────────────────────────────────────────────┐
│                  KONG GUARD AI                               │
│              Hackathon Preparation Menu                      │
│                                                              │
│  File: hackathon-prep.sh                                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                     MAIN MENU                                │
│  Function: show_main_menu()                                 │
├─────────────────────────────────────────────────────────────┤
│  1. 🎬 Demo Recording                                       │
│  2. 🔧 Environment Setup                                    │
│  3. ⚙️  Configuration                                       │
│  4. 📦 Preparation Tasks                                    │
│  5. 📹 Post-Production                                      │
│  6. 📋 Checklists                                           │
│  7. 🔍 Troubleshooting                                      │
│  8. 📚 Documentation                                        │
│  9. 🚀 Quick Actions                                        │
│  0. ⚙️  Settings                                            │
│  Q. Quit                                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Detailed Menu Flow

### 1️⃣ Demo Recording Menu
**Function**: `demo_recording_menu()`

```
┌────────────────────────────────────────┐
│    🎬 DEMO RECORDING                   │
│    Function: demo_recording_menu()     │
├────────────────────────────────────────┤
│  1. Record full demo (all 7 scenes)   │
│     └─► record_full_demo()            │
│                                        │
│  2. Test scenes (1,2,3 only)          │
│     └─► test_scenes("1,2,3")          │
│                                        │
│  3. Custom scenes (specify)            │
│     └─► test_scenes($user_input)      │
│                                        │
│  4. Screenshot mode only               │
│     └─► record_full_demo()            │
│         (video disabled)               │
│                                        │
│  5. View last recording                │
│     └─► show_last_recording()         │
│                                        │
│  6. List all recordings                │
│     └─► list_recordings()             │
│                                        │
│  B. Back to main menu                  │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

**Called Functions**:
- `record_full_demo()` → `scripts/hackathon/demo-helpers.sh`
- `test_scenes()` → `scripts/hackathon/demo-helpers.sh`
- `show_last_recording()` → `scripts/hackathon/demo-helpers.sh`
- `list_recordings()` → `scripts/hackathon/demo-helpers.sh`

---

### 2️⃣ Environment Setup Menu
**Function**: `environment_setup_menu()`

```
┌────────────────────────────────────────┐
│    🔧 ENVIRONMENT SETUP                │
│    Function: environment_setup_menu()  │
├────────────────────────────────────────┤
│  1. Start all services                 │
│     └─► start_services()               │
│                                        │
│  2. Stop all services                  │
│     └─► stop_services()                │
│                                        │
│  3. Check service status               │
│     └─► check_services_status()        │
│                                        │
│  4. Reset environment                  │
│     └─► reset_environment()            │
│                                        │
│  5. View logs                          │
│     └─► view_logs("all")               │
│                                        │
│  B. Back to main menu                  │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

**Called Functions**:
- `start_services()` → `scripts/hackathon/env-helpers.sh`
- `stop_services()` → `scripts/hackathon/env-helpers.sh`
- `check_services_status()` → `scripts/hackathon/env-helpers.sh`
- `reset_environment()` → `scripts/hackathon/env-helpers.sh`
- `view_logs()` → `scripts/hackathon/env-helpers.sh`

---

### 3️⃣ Configuration Menu
**Function**: `configuration_menu()`

```
┌────────────────────────────────────────┐
│    ⚙️  CONFIGURATION                   │
│    Function: configuration_menu()      │
├────────────────────────────────────────┤
│  1. View current configuration         │
│     └─► cat hackathon-prep.config      │
│                                        │
│  2. Edit configuration file            │
│     └─► $EDITOR hackathon-prep.config  │
│                                        │
│  3. Toggle video recording             │
│     └─► sed -i VIDEO_ENABLED=...       │
│                                        │
│  4. Toggle screenshots                 │
│     └─► sed -i SCREENSHOTS_ENABLED=... │
│                                        │
│  5. Change demo mode (headed/headless) │
│     └─► sed -i DEMO_MODE=...           │
│                                        │
│  6. Edit narrator timing               │
│     └─► $EDITOR narrator_timing.json   │
│                                        │
│  7. Reset to defaults                  │
│     └─► rm hackathon-prep.config       │
│                                        │
│  B. Back to main menu                  │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

**Config File**: `hackathon-prep.config` (55 lines)  
**Timing Config**: `narrator_timing.json` (305 lines)

---

### 4️⃣ Preparation Tasks Menu
**Function**: `preparation_tasks_menu()`

```
┌────────────────────────────────────────┐
│    📦 PREPARATION TASKS                │
│    Function: preparation_tasks_menu()  │
├────────────────────────────────────────┤
│  1. Check dependencies                 │
│     └─► check_dependencies()           │
│                                        │
│  2. Install Playwright                 │
│     └─► pip install playwright         │
│         playwright install chromium    │
│                                        │
│  3. Test dashboard access              │
│     └─► check_dashboard_access()       │
│                                        │
│  4. Check disk space                   │
│     └─► check_disk_space()             │
│                                        │
│  5. Test network connections           │
│     └─► test_connections()             │
│                                        │
│  B. Back to main menu                  │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

**Called Functions**:
- `check_dependencies()` → `scripts/hackathon/env-helpers.sh`
- `check_dashboard_access()` → `scripts/hackathon/env-helpers.sh`
- `check_disk_space()` → `scripts/hackathon/env-helpers.sh`
- `test_connections()` → `scripts/hackathon/env-helpers.sh`

---

### 5️⃣ Post-Production Menu
**Function**: `post_production_menu()`

```
┌────────────────────────────────────────┐
│    📹 POST-PRODUCTION                  │
│    Function: post_production_menu()    │
├────────────────────────────────────────┤
│  1. Convert last WebM to MP4           │
│     └─► convert_to_mp4("")             │
│                                        │
│  2. Convert specific file              │
│     └─► convert_to_mp4($file)          │
│                                        │
│  3. Open last recording folder         │
│     └─► open_last_recording()          │
│                                        │
│  4. Generate recording report          │
│     └─► generate_report("")            │
│                                        │
│  5. Clean old recordings               │
│     └─► clean_old_recordings($days)    │
│                                        │
│  B. Back to main menu                  │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

**Called Functions**:
- `convert_to_mp4()` → `scripts/hackathon/demo-helpers.sh`
- `open_last_recording()` → `scripts/hackathon/demo-helpers.sh`
- `generate_report()` → `scripts/hackathon/demo-helpers.sh`
- `clean_old_recordings()` → `scripts/hackathon/demo-helpers.sh`

---

### 6️⃣ Checklists Menu
**Function**: `checklists_menu()`

```
┌────────────────────────────────────────┐
│    📋 HACKATHON CHECKLISTS             │
│    Function: checklists_menu()         │
├────────────────────────────────────────┤
│  Display Only (No sub-menu):          │
│                                        │
│  □ PRE-RECORDING CHECKLIST             │
│    - Services running                  │
│    - Dashboard accessible              │
│    - Disk space >1GB                   │
│    - Playwright installed              │
│    - Configuration reviewed            │
│                                        │
│  □ POST-RECORDING CHECKLIST            │
│    - Video file exists                 │
│    - All 17 screenshots                │
│    - Timing log generated              │
│    - Video quality reviewed            │
│    - Convert to MP4                    │
│                                        │
│  □ SUBMISSION CHECKLIST                │
│    - Video length 4:30-5:00 min        │
│    - Add voiceover narration           │
│    - Export final MP4                  │
│    - Test playback                     │
│    - Upload to platform                │
│                                        │
│  [Press Enter to continue]             │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

---

### 7️⃣ Troubleshooting Menu
**Function**: `troubleshooting_menu()`

```
┌────────────────────────────────────────┐
│    🔍 TROUBLESHOOTING                  │
│    Function: troubleshooting_menu()    │
├────────────────────────────────────────┤
│  Display Only (No sub-menu):          │
│                                        │
│  Common Issues:                        │
│                                        │
│  1. Dashboard not accessible           │
│     → Check services                   │
│     → Start services                   │
│                                        │
│  2. Playwright errors                  │
│     → Install/reinstall Playwright     │
│                                        │
│  3. Recording fails                    │
│     → Check dependencies               │
│     → View logs                        │
│                                        │
│  4. Video not created                  │
│     → Ensure VIDEO_ENABLED=true        │
│     → Check disk space                 │
│                                        │
│  [Press Enter to continue]             │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

---

### 8️⃣ Documentation Menu
**Function**: `documentation_menu()`

```
┌────────────────────────────────────────┐
│    📚 DOCUMENTATION                    │
│    Function: documentation_menu()      │
├────────────────────────────────────────┤
│  Available Documentation:              │
│                                        │
│  ✓ Main README                         │
│    File: README.md                     │
│                                        │
│  ✓ Test Results                        │
│    File: TEST_RESULTS_SUCCESS.md       │
│                                        │
│  ✓ Video Recording Guide               │
│    File: VIDEO_RECORDING_CONFIRMED.md  │
│                                        │
│  ✓ Timing Configuration                │
│    File: narrator_timing.json          │
│                                        │
│  ✓ Visual Effects                      │
│    File: demo_visual_effects.js        │
│                                        │
│  [Press Enter to continue]             │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

---

### 9️⃣ Quick Actions Menu
**Function**: `quick_actions_menu()`

```
┌────────────────────────────────────────┐
│    🚀 QUICK ACTIONS                    │
│    Function: quick_actions_menu()      │
├────────────────────────────────────────┤
│  1. Full Demo                          │
│     (start services + record + report) │
│     └─► check_services_status()        │
│         start_services()               │
│         record_full_demo()             │
│         generate_report()              │
│                                        │
│  2. Quick Test (scene 1 only)          │
│     └─► test_scenes("1")               │
│                                        │
│  3. Status Check (all systems)         │
│     └─► check_dependencies()           │
│         check_services_status()        │
│         check_disk_space()             │
│                                        │
│  4. Package Last Recording             │
│     (report + convert)                 │
│     └─► generate_report("")            │
│         convert_to_mp4("")             │
│                                        │
│  B. Back to main menu                  │
└────────────────────────────────────────┘
         │
         ▼
   [Main Menu]
```

---

### 0️⃣ Settings Menu
**Function**: `settings_menu()`

```
┌────────────────────────────────────────┐
│    ⚙️  SETTINGS                        │
│    Function: settings_menu()           │
├────────────────────────────────────────┤
│  (Configuration alias)                 │
│  → Calls configuration_menu()          │
└────────────────────────────────────────┘
         │
         ▼
   [Configuration Menu]
```

---

## 📂 File Structure Map

```
Kong Guard AI Project
│
├── hackathon-prep.sh (Main CLI Menu - 719 lines)
│   ├── show_header()
│   ├── show_main_menu()
│   ├── demo_recording_menu()
│   ├── environment_setup_menu()
│   ├── configuration_menu()
│   ├── preparation_tasks_menu()
│   ├── post_production_menu()
│   ├── checklists_menu()
│   ├── troubleshooting_menu()
│   ├── documentation_menu()
│   ├── quick_actions_menu()
│   └── settings_menu()
│
├── hackathon-prep.config (Configuration - 55 lines)
│   ├── DEMO_MODE
│   ├── VIDEO_ENABLED
│   ├── SCREENSHOTS_ENABLED
│   ├── NARRATOR_TIMING
│   └── ... (30+ config options)
│
├── scripts/hackathon/
│   ├── demo-helpers.sh (Recording Functions - 279 lines)
│   │   ├── record_full_demo()
│   │   ├── test_scenes()
│   │   ├── show_last_recording()
│   │   ├── list_recordings()
│   │   ├── convert_to_mp4()
│   │   ├── generate_report()
│   │   └── clean_old_recordings()
│   │
│   └── env-helpers.sh (Environment Functions - 287 lines)
│       ├── start_services()
│       ├── stop_services()
│       ├── check_services_status()
│       ├── reset_environment()
│       ├── view_logs()
│       ├── check_dependencies()
│       ├── check_dashboard_access()
│       ├── check_disk_space()
│       └── test_connections()
│
├── hackathon_demo_recorder.py (Python Recorder - 508 lines)
├── narrator_timing.json (Scene Timing - 305 lines)
├── demo_visual_effects.js (Visual Effects - 431 lines)
└── generate_scene_voice.py (Voice Generator - 404 lines)
```

---

## 🔄 Command-Line Arguments

The menu can also be invoked with command-line arguments:

```bash
# Direct commands (bypasses menu)
./hackathon-prep.sh --record-full      # Record full demo
./hackathon-prep.sh --test-scene-1     # Test Scene 1
./hackathon-prep.sh --screenshots      # Screenshots only
./hackathon-prep.sh --convert-mp4      # Convert last recording
./hackathon-prep.sh --status           # System status check
./hackathon-prep.sh --help             # Show help
```

---

## 🎯 Function Call Flow

### Example: Full Demo Recording

```
User selects: Main Menu > 1 (Demo Recording) > 1 (Record full demo)

Flow:
1. show_main_menu()
   └─► User input: 1
2. demo_recording_menu()
   └─► User input: 1
3. record_full_demo("headed", "true", "true")
   └─► Located in: scripts/hackathon/demo-helpers.sh
4. Calls: python3 hackathon_demo_recorder.py --headed --screenshots
5. Python script executes:
   └─► Loads: narrator_timing.json
   └─► Injects: demo_visual_effects.js
   └─► Captures: video + 17 screenshots
6. generate_report()
   └─► Creates: RECORDING_REPORT.txt
7. Returns to: demo_recording_menu()
8. User presses Enter
9. Returns to: demo_recording_menu()
```

---

## 📊 Menu Statistics

| Menu | Options | Has Sub-menu | Function File |
|------|---------|--------------|---------------|
| Main Menu | 11 | Yes | hackathon-prep.sh |
| Demo Recording | 6 | No | hackathon-prep.sh |
| Environment Setup | 5 | No | hackathon-prep.sh |
| Configuration | 7 | No | hackathon-prep.sh |
| Preparation Tasks | 5 | No | hackathon-prep.sh |
| Post-Production | 5 | No | hackathon-prep.sh |
| Checklists | 0 (display) | No | hackathon-prep.sh |
| Troubleshooting | 0 (display) | No | hackathon-prep.sh |
| Documentation | 0 (display) | No | hackathon-prep.sh |
| Quick Actions | 4 | No | hackathon-prep.sh |
| Settings | 0 (alias) | Yes → Config | hackathon-prep.sh |

**Total Interactive Options**: 43  
**Total Menu Functions**: 11  
**Helper Script Functions**: 20+

---

## 🎨 Visual Menu Tree

```
KONG GUARD AI
    │
    ├─ 1. Demo Recording
    │   ├─ 1. Record full demo
    │   ├─ 2. Test scenes (1,2,3)
    │   ├─ 3. Custom scenes
    │   ├─ 4. Screenshot mode
    │   ├─ 5. View last recording
    │   └─ 6. List recordings
    │
    ├─ 2. Environment Setup
    │   ├─ 1. Start services
    │   ├─ 2. Stop services
    │   ├─ 3. Check status
    │   ├─ 4. Reset environment
    │   └─ 5. View logs
    │
    ├─ 3. Configuration
    │   ├─ 1. View config
    │   ├─ 2. Edit config
    │   ├─ 3. Toggle video
    │   ├─ 4. Toggle screenshots
    │   ├─ 5. Change mode
    │   ├─ 6. Edit timing
    │   └─ 7. Reset defaults
    │
    ├─ 4. Preparation Tasks
    │   ├─ 1. Check dependencies
    │   ├─ 2. Install Playwright
    │   ├─ 3. Test dashboard
    │   ├─ 4. Check disk space
    │   └─ 5. Test connections
    │
    ├─ 5. Post-Production
    │   ├─ 1. Convert to MP4
    │   ├─ 2. Convert specific
    │   ├─ 3. Open folder
    │   ├─ 4. Generate report
    │   └─ 5. Clean old
    │
    ├─ 6. Checklists [Display]
    ├─ 7. Troubleshooting [Display]
    ├─ 8. Documentation [Display]
    │
    ├─ 9. Quick Actions
    │   ├─ 1. Full Demo
    │   ├─ 2. Quick Test
    │   ├─ 3. Status Check
    │   └─ 4. Package Recording
    │
    ├─ 0. Settings → [Configuration]
    │
    └─ Q. Quit
```

---

## 🏗️ Architecture Summary

### Main Components

1. **Main CLI**: `hackathon-prep.sh` (719 lines)
   - Entry point
   - Menu navigation
   - User interaction

2. **Helper Scripts**: `scripts/hackathon/`
   - `demo-helpers.sh` (279 lines) - Recording functions
   - `env-helpers.sh` (287 lines) - Environment functions

3. **Python Scripts**:
   - `hackathon_demo_recorder.py` (508 lines) - Core recorder
   - `generate_scene_voice.py` (404 lines) - Voice generation

4. **Configuration**:
   - `hackathon-prep.config` (55 lines) - Runtime config
   - `narrator_timing.json` (305 lines) - Scene timing

5. **Assets**:
   - `demo_visual_effects.js` (431 lines) - Visual effects

**Total Lines of Code**: ~2,993 lines  
**Total Files**: 7 main files  
**Total Functions**: 40+ functions

---

**Created**: 2024-09-30  
**Menu System**: Interactive CLI with 11 menus and 43+ options  
**Status**: Complete and production-ready ✅
