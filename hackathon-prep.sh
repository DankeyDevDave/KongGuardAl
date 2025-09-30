#!/bin/bash
# Kong Guard AI - Hackathon Preparation Menu
# Interactive CLI for all hackathon preparation tasks

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration file
CONFIG_FILE="hackathon-prep.config"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo "⚠️  Configuration file not found: $CONFIG_FILE"
    echo "Creating default configuration..."
    cat > "$CONFIG_FILE" << 'EOF'
# Kong Guard AI - Hackathon Preparation Configuration
DEMO_MODE="headed"
VIDEO_ENABLED="true"
SCREENSHOTS_ENABLED="true"
NARRATOR_TIMING="true"
DASHBOARD_URL="http://localhost:8080"
DASHBOARD_LOCAL_PATH="visualization/index.html"
DOCKER_COMPOSE_FILE="config/docker/docker-compose-presentation.yml"
DOCKER_COMPOSE_FALLBACK="docker-compose.yml"
OUTPUT_DIR="demo_recordings"
SCREENSHOTS_DIR="screenshots"
VIDEO_QUALITY="high"
FFMPEG_PRESET="slow"
FFMPEG_CRF="18"
VIDEO_CODEC="libx264"
AUDIO_CODEC="aac"
AUTO_CLEANUP_DAYS=7
KEEP_LAST_N_RECORDINGS=3
SERVICE_STARTUP_WAIT=30
HEALTH_CHECK_RETRIES=3
HEALTH_CHECK_INTERVAL=5
USE_COLORS="true"
SHOW_PROGRESS="true"
VERBOSE_MODE="false"
PYTHON_CMD="python3"
PLAYWRIGHT_BROWSERS="chromium"
RECORDING_TIMEOUT=600
RECORDER_SCRIPT="hackathon_demo_recorder.py"
TIMING_CONFIG="narrator_timing.json"
VISUAL_EFFECTS="demo_visual_effects.js"
ENABLE_NOTIFICATIONS="false"
SOUND_ENABLED="false"
EOF
    source "$CONFIG_FILE"
    echo "✓ Configuration created: $CONFIG_FILE"
fi

# Colors
if [[ "$USE_COLORS" == "true" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

# Helper functions
echo_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Load helper scripts
HELPERS_DIR="scripts/hackathon"
if [[ -d "$HELPERS_DIR" ]]; then
    [[ -f "$HELPERS_DIR/demo-helpers.sh" ]] && source "$HELPERS_DIR/demo-helpers.sh"
    [[ -f "$HELPERS_DIR/env-helpers.sh" ]] && source "$HELPERS_DIR/env-helpers.sh"
fi

# Header
show_header() {
    clear
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║     ${CYAN}KONG GUARD AI${NC}${BOLD} - HACKATHON PREPARATION MENU          ║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Main Menu
show_main_menu() {
    show_header

    echo -e "${BOLD}1.${NC} 🎬 Demo Recording"
    echo -e "${BOLD}2.${NC} 🔧 Environment Setup"
    echo -e "${BOLD}3.${NC} ⚙️  Configuration"
    echo -e "${BOLD}4.${NC} 📦 Preparation Tasks"
    echo -e "${BOLD}5.${NC} 📹 Post-Production"
    echo -e "${BOLD}6.${NC} 📋 Checklists"
    echo -e "${BOLD}7.${NC} 🔍 Troubleshooting"
    echo -e "${BOLD}8.${NC} 📚 Documentation"
    echo -e "${BOLD}9.${NC} 🚀 Quick Actions"
    echo -e "${BOLD}0.${NC} ⚙️  Settings"
    echo ""
    echo -e "${BOLD}Q.${NC} Quit"
    echo ""
}

# 1. Demo Recording Menu
demo_recording_menu() {
    while true; do
        show_header
        echo -e "${BOLD}🎬 DEMO RECORDING${NC}"
        echo ""
        echo -e "${BOLD}1.${NC} Record full demo (all 7 scenes)"
        echo -e "${BOLD}2.${NC} Test scenes (1,2,3 only)"
        echo -e "${BOLD}3.${NC} Custom scenes (specify)"
        echo -e "${BOLD}4.${NC} Screenshot mode only"
        echo -e "${BOLD}5.${NC} View last recording"
        echo -e "${BOLD}6.${NC} List all recordings"
        echo ""
        echo -e "${BOLD}B.${NC} Back to main menu"
        echo ""

        read -p "Select option: " option

        case $option in
            1)
                echo ""
                record_full_demo "$DEMO_MODE" "$VIDEO_ENABLED" "$SCREENSHOTS_ENABLED"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                test_scenes "1,2,3"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                read -p "Enter scene numbers (e.g., 1,3,5): " scenes
                test_scenes "$scenes"
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                record_full_demo "$DEMO_MODE" "false" "true"
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                show_last_recording
                read -p "Press Enter to continue..."
                ;;
            6)
                echo ""
                list_recordings
                read -p "Press Enter to continue..."
                ;;
            [Bb])
                return
                ;;
            *)
                echo_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# 2. Environment Setup Menu
environment_setup_menu() {
    while true; do
        show_header
        echo -e "${BOLD}🔧 ENVIRONMENT SETUP${NC}"
        echo ""
        echo -e "${BOLD}1.${NC} Start all services"
        echo -e "${BOLD}2.${NC} Stop all services"
        echo -e "${BOLD}3.${NC} Check service status"
        echo -e "${BOLD}4.${NC} Reset environment"
        echo -e "${BOLD}5.${NC} View logs"
        echo ""
        echo -e "${BOLD}B.${NC} Back to main menu"
        echo ""

        read -p "Select option: " option

        case $option in
            1)
                echo ""
                start_services
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                stop_services
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                check_services_status
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                reset_environment
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                view_logs "all"
                read -p "Press Enter to continue..."
                ;;
            [Bb])
                return
                ;;
            *)
                echo_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# 3. Configuration Menu
configuration_menu() {
    while true; do
        show_header
        echo -e "${BOLD}⚙️  CONFIGURATION${NC}"
        echo ""
        echo -e "${BOLD}1.${NC} View current configuration"
        echo -e "${BOLD}2.${NC} Edit configuration file"
        echo -e "${BOLD}3.${NC} Toggle video recording"
        echo -e "${BOLD}4.${NC} Toggle screenshots"
        echo -e "${BOLD}5.${NC} Change demo mode (headed/headless)"
        echo -e "${BOLD}6.${NC} Edit narrator timing"
        echo -e "${BOLD}7.${NC} Reset to defaults"
        echo ""
        echo -e "${BOLD}B.${NC} Back to main menu"
        echo ""

        read -p "Select option: " option

        case $option in
            1)
                echo ""
                cat "$CONFIG_FILE"
                read -p "Press Enter to continue..."
                ;;
            2)
                ${EDITOR:-nano} "$CONFIG_FILE"
                source "$CONFIG_FILE"
                echo_success "Configuration reloaded"
                sleep 1
                ;;
            3)
                if [[ "$VIDEO_ENABLED" == "true" ]]; then
                    sed -i.bak 's/VIDEO_ENABLED="true"/VIDEO_ENABLED="false"/' "$CONFIG_FILE"
                    VIDEO_ENABLED="false"
                    echo_info "Video recording disabled"
                else
                    sed -i.bak 's/VIDEO_ENABLED="false"/VIDEO_ENABLED="true"/' "$CONFIG_FILE"
                    VIDEO_ENABLED="true"
                    echo_info "Video recording enabled"
                fi
                sleep 1
                ;;
            4)
                if [[ "$SCREENSHOTS_ENABLED" == "true" ]]; then
                    sed -i.bak 's/SCREENSHOTS_ENABLED="true"/SCREENSHOTS_ENABLED="false"/' "$CONFIG_FILE"
                    SCREENSHOTS_ENABLED="false"
                    echo_info "Screenshots disabled"
                else
                    sed -i.bak 's/SCREENSHOTS_ENABLED="false"/SCREENSHOTS_ENABLED="true"/' "$CONFIG_FILE"
                    SCREENSHOTS_ENABLED="true"
                    echo_info "Screenshots enabled"
                fi
                sleep 1
                ;;
            5)
                if [[ "$DEMO_MODE" == "headed" ]]; then
                    sed -i.bak 's/DEMO_MODE="headed"/DEMO_MODE="headless"/' "$CONFIG_FILE"
                    DEMO_MODE="headless"
                    echo_info "Switched to headless mode"
                else
                    sed -i.bak 's/DEMO_MODE="headless"/DEMO_MODE="headed"/' "$CONFIG_FILE"
                    DEMO_MODE="headed"
                    echo_info "Switched to headed mode"
                fi
                sleep 1
                ;;
            6)
                ${EDITOR:-nano} "$TIMING_CONFIG"
                echo_success "Timing configuration updated"
                sleep 1
                ;;
            7)
                rm -f "$CONFIG_FILE"
                echo_info "Configuration reset. Restart script to regenerate."
                read -p "Press Enter to continue..."
                exit 0
                ;;
            [Bb])
                return
                ;;
            *)
                echo_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# 4. Preparation Tasks Menu
preparation_tasks_menu() {
    while true; do
        show_header
        echo -e "${BOLD}📦 PREPARATION TASKS${NC}"
        echo ""
        echo -e "${BOLD}1.${NC} Check dependencies"
        echo -e "${BOLD}2.${NC} Install Playwright"
        echo -e "${BOLD}3.${NC} Test dashboard access"
        echo -e "${BOLD}4.${NC} Check disk space"
        echo -e "${BOLD}5.${NC} Test network connections"
        echo ""
        echo -e "${BOLD}B.${NC} Back to main menu"
        echo ""

        read -p "Select option: " option

        case $option in
            1)
                echo ""
                check_dependencies
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                echo_info "Installing Playwright..."
                pip install playwright
                playwright install chromium
                echo_success "Playwright installed"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                check_dashboard_access
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                check_disk_space
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                test_connections
                read -p "Press Enter to continue..."
                ;;
            [Bb])
                return
                ;;
            *)
                echo_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# 5. Post-Production Menu
post_production_menu() {
    while true; do
        show_header
        echo -e "${BOLD}📹 POST-PRODUCTION${NC}"
        echo ""
        echo -e "${BOLD}1.${NC} Convert last WebM to MP4"
        echo -e "${BOLD}2.${NC} Convert specific file"
        echo -e "${BOLD}3.${NC} Open last recording folder"
        echo -e "${BOLD}4.${NC} Generate recording report"
        echo -e "${BOLD}5.${NC} Clean old recordings"
        echo ""
        echo -e "${BOLD}B.${NC} Back to main menu"
        echo ""

        read -p "Select option: " option

        case $option in
            1)
                echo ""
                convert_to_mp4 ""
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                read -p "Enter WebM file path: " file
                convert_to_mp4 "$file"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                open_last_recording
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                generate_report ""
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                read -p "Delete recordings older than how many days? [$AUTO_CLEANUP_DAYS]: " days
                days=${days:-$AUTO_CLEANUP_DAYS}
                clean_old_recordings "$days"
                read -p "Press Enter to continue..."
                ;;
            [Bb])
                return
                ;;
            *)
                echo_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# 6. Checklists Menu
checklists_menu() {
    show_header
    echo -e "${BOLD}📋 HACKATHON CHECKLISTS${NC}"
    echo ""

    echo -e "${BOLD}PRE-RECORDING CHECKLIST:${NC}"
    echo "□ Services running (check with: Environment Setup > Check Status)"
    echo "□ Dashboard accessible at $DASHBOARD_URL"
    echo "□ Disk space >1GB available"
    echo "□ Playwright installed"
    echo "□ Configuration reviewed"
    echo ""

    echo -e "${BOLD}POST-RECORDING CHECKLIST:${NC}"
    echo "□ Video file exists (demo_recordings/*/video.webm)"
    echo "□ All 17 screenshots captured"
    echo "□ Timing log generated"
    echo "□ Video quality reviewed"
    echo "□ Convert to MP4 if needed"
    echo ""

    echo -e "${BOLD}SUBMISSION CHECKLIST:${NC}"
    echo "□ Video length 4:30-5:00 minutes"
    echo "□ Add voiceover narration"
    echo "□ Export final video as MP4"
    echo "□ Test playback on different devices"
    echo "□ Upload to hackathon platform"
    echo ""

    read -p "Press Enter to continue..."
}

# 7. Troubleshooting Menu
troubleshooting_menu() {
    show_header
    echo -e "${BOLD}🔍 TROUBLESHOOTING${NC}"
    echo ""

    echo -e "${BOLD}Common Issues:${NC}"
    echo ""
    echo "1. Dashboard not accessible"
    echo "   → Check services: Environment Setup > Check Status"
    echo "   → Start services: Environment Setup > Start Services"
    echo ""
    echo "2. Playwright errors"
    echo "   → Install/reinstall: Preparation Tasks > Install Playwright"
    echo ""
    echo "3. Recording fails"
    echo "   → Check dependencies: Preparation Tasks > Check Dependencies"
    echo "   → View logs: Environment Setup > View Logs"
    echo ""
    echo "4. Video not created"
    echo "   → Ensure VIDEO_ENABLED=true in configuration"
    echo "   → Check disk space: Preparation Tasks > Check Disk Space"
    echo ""

    read -p "Press Enter to continue..."
}

# 8. Documentation Menu
documentation_menu() {
    show_header
    echo -e "${BOLD}📚 DOCUMENTATION${NC}"
    echo ""

    local docs=(
        "README.md:Main README"
        "TEST_RESULTS_SUCCESS.md:Test Results"
        "VIDEO_RECORDING_CONFIRMED.md:Video Recording Guide"
        "narrator_timing.json:Timing Configuration"
        "demo_visual_effects.js:Visual Effects"
    )

    echo "Available Documentation:"
    echo ""

    for doc in "${docs[@]}"; do
        IFS=':' read -r file desc <<< "$doc"
        if [[ -f "$file" ]]; then
            echo -e "${GREEN}✓${NC} $desc ($file)"
        else
            echo -e "${RED}✗${NC} $desc ($file) - not found"
        fi
    done

    echo ""
    read -p "Press Enter to continue..."
}

# 9. Quick Actions Menu
quick_actions_menu() {
    while true; do
        show_header
        echo -e "${BOLD}🚀 QUICK ACTIONS${NC}"
        echo ""
        echo -e "${BOLD}1.${NC} Full Demo (start services + record + report)"
        echo -e "${BOLD}2.${NC} Quick Test (scene 1 only, headless)"
        echo -e "${BOLD}3.${NC} Status Check (all systems)"
        echo -e "${BOLD}4.${NC} Package Last Recording (report + convert)"
        echo ""
        echo -e "${BOLD}B.${NC} Back to main menu"
        echo ""

        read -p "Select option: " option

        case $option in
            1)
                echo ""
                echo_info "Running full demo workflow..."
                check_services_status || start_services
                record_full_demo "$DEMO_MODE" "$VIDEO_ENABLED" "$SCREENSHOTS_ENABLED"
                generate_report ""
                echo_success "Full demo workflow complete!"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                test_scenes "1"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                check_dependencies
                echo ""
                check_services_status
                echo ""
                check_disk_space
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                generate_report ""
                convert_to_mp4 ""
                echo_success "Recording packaged!"
                read -p "Press Enter to continue..."
                ;;
            [Bb])
                return
                ;;
            *)
                echo_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# 0. Settings Menu
settings_menu() {
    show_header
    echo -e "${BOLD}⚙️  CURRENT SETTINGS${NC}"
    echo ""
    echo -e "Demo Mode:          ${BOLD}$DEMO_MODE${NC}"
    echo -e "Video Enabled:      ${BOLD}$VIDEO_ENABLED${NC}"
    echo -e "Screenshots:        ${BOLD}$SCREENSHOTS_ENABLED${NC}"
    echo -e "Narrator Timing:    ${BOLD}$NARRATOR_TIMING${NC}"
    echo -e "Dashboard URL:      ${BOLD}$DASHBOARD_URL${NC}"
    echo -e "Output Directory:   ${BOLD}$OUTPUT_DIR${NC}"
    echo -e "Video Quality:      ${BOLD}$VIDEO_QUALITY${NC}"
    echo -e "Python Command:     ${BOLD}$PYTHON_CMD${NC}"
    echo ""
    echo "Edit settings in Configuration menu or edit $CONFIG_FILE directly"
    echo ""
    read -p "Press Enter to continue..."
}

# Command line arguments
handle_cli_args() {
    case "$1" in
        --record-full)
            record_full_demo "$DEMO_MODE" "$VIDEO_ENABLED" "$SCREENSHOTS_ENABLED"
            exit 0
            ;;
        --test-scene-1)
            test_scenes "1"
            exit 0
            ;;
        --start-services)
            start_services
            exit 0
            ;;
        --stop-services)
            stop_services
            exit 0
            ;;
        --status)
            check_services_status
            check_dependencies
            exit 0
            ;;
        --convert-mp4)
            convert_to_mp4 ""
            exit 0
            ;;
        --clean)
            clean_old_recordings "$AUTO_CLEANUP_DAYS"
            exit 0
            ;;
        --help|-h)
            echo "Kong Guard AI - Hackathon Prep Menu"
            echo ""
            echo "Usage: $0 [option]"
            echo ""
            echo "Options:"
            echo "  (no args)          Show interactive menu"
            echo "  --record-full      Record full demo"
            echo "  --test-scene-1     Test scene 1 only"
            echo "  --start-services   Start all services"
            echo "  --stop-services    Stop all services"
            echo "  --status           Check status"
            echo "  --convert-mp4      Convert last WebM to MP4"
            echo "  --clean            Clean old recordings"
            echo "  --help             Show this help"
            exit 0
            ;;
        "")
            # No args, show menu
            return 0
            ;;
        *)
            echo_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
}

# Main function
main() {
    # Handle CLI arguments
    if [[ $# -gt 0 ]]; then
        handle_cli_args "$@"
    fi

    # Interactive menu
    while true; do
        show_main_menu

        read -p "Select option: " option

        case $option in
            1) demo_recording_menu ;;
            2) environment_setup_menu ;;
            3) configuration_menu ;;
            4) preparation_tasks_menu ;;
            5) post_production_menu ;;
            6) checklists_menu ;;
            7) troubleshooting_menu ;;
            8) documentation_menu ;;
            9) quick_actions_menu ;;
            0) settings_menu ;;
            [Qq])
                echo ""
                echo_success "Thanks for using Kong Guard AI Hackathon Prep!"
                echo ""
                exit 0
                ;;
            *)
                echo_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Run main function
main "$@"
