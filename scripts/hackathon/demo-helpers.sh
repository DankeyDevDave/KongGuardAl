#!/bin/bash
# Demo Recording Helper Functions

# Record full demo
record_full_demo() {
    local mode="${1:-$DEMO_MODE}"
    local video="${2:-$VIDEO_ENABLED}"
    local screenshots="${3:-$SCREENSHOTS_ENABLED}"
    
    echo_info "Starting full demo recording..."
    echo_info "Mode: $mode | Video: $video | Screenshots: $screenshots"
    
    local cmd="$PYTHON_CMD $RECORDER_SCRIPT"
    [[ "$mode" == "headed" ]] && cmd="$cmd --headed" || cmd="$cmd --headless"
    [[ "$video" == "true" ]] && cmd="$cmd --video" || cmd="$cmd --no-video"
    [[ "$screenshots" == "true" ]] && cmd="$cmd --screenshots" || cmd="$cmd --no-screenshots"
    [[ "$NARRATOR_TIMING" == "true" ]] && cmd="$cmd --narrator-timing"
    
    echo_info "Running: $cmd"
    eval "$cmd"
    
    if [[ $? -eq 0 ]]; then
        echo_success "Demo recording completed successfully!"
        show_last_recording
        return 0
    else
        echo_error "Demo recording failed!"
        return 1
    fi
}

# Test specific scenes
test_scenes() {
    local scenes="${1:-1,2,3}"
    
    echo_info "Testing scenes: $scenes"
    
    local cmd="$PYTHON_CMD $RECORDER_SCRIPT --headless --scenes $scenes"
    
    eval "$cmd"
    
    if [[ $? -eq 0 ]]; then
        echo_success "Scene test completed!"
        return 0
    else
        echo_error "Scene test failed!"
        return 1
    fi
}

# Show last recording
show_last_recording() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        echo_warning "No recordings directory found"
        return 1
    fi
    
    local last_dir=$(ls -td "$OUTPUT_DIR"/hackathon_demo_* 2>/dev/null | head -1)
    
    if [[ -z "$last_dir" ]]; then
        echo_warning "No recordings found"
        return 1
    fi
    
    echo_info "Last recording: $last_dir"
    echo ""
    
    # Show contents
    if [[ -d "$last_dir" ]]; then
        echo "Contents:"
        ls -lh "$last_dir" | tail -n +2
        
        # Count files
        local video_count=$(find "$last_dir" -name "*.webm" -type f | wc -l | tr -d ' ')
        local screenshot_count=$(find "$last_dir/$SCREENSHOTS_DIR" -name "*.png" -type f 2>/dev/null | wc -l | tr -d ' ')
        
        echo ""
        echo_info "Videos: $video_count | Screenshots: $screenshot_count"
        
        # Show timing log if exists
        if [[ -f "$last_dir/timing_log.json" ]]; then
            echo_info "Timing log available: $last_dir/timing_log.json"
        fi
    fi
}

# List all recordings
list_recordings() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        echo_warning "No recordings directory found"
        return 1
    fi
    
    local recordings=($(ls -td "$OUTPUT_DIR"/hackathon_demo_* 2>/dev/null))
    
    if [[ ${#recordings[@]} -eq 0 ]]; then
        echo_warning "No recordings found"
        return 1
    fi
    
    echo_info "Found ${#recordings[@]} recording(s):"
    echo ""
    
    local i=1
    for dir in "${recordings[@]}"; do
        local timestamp=$(basename "$dir" | sed 's/hackathon_demo_//')
        local size=$(du -sh "$dir" 2>/dev/null | cut -f1)
        local video_count=$(find "$dir" -name "*.webm" -type f | wc -l | tr -d ' ')
        local screenshot_count=$(find "$dir" -name "*.png" -type f 2>/dev/null | wc -l | tr -d ' ')
        
        echo "[$i] $timestamp | Size: $size | Videos: $video_count | Screenshots: $screenshot_count"
        ((i++))
    done
}

# Convert WebM to MP4
convert_to_mp4() {
    local input_file="$1"
    
    if [[ -z "$input_file" ]]; then
        # Find last WebM file
        input_file=$(find "$OUTPUT_DIR" -name "*.webm" -type f | sort -r | head -1)
    fi
    
    if [[ -z "$input_file" || ! -f "$input_file" ]]; then
        echo_error "No WebM file found"
        return 1
    fi
    
    local output_file="${input_file%.webm}.mp4"
    
    echo_info "Converting: $input_file"
    echo_info "Output: $output_file"
    echo_info "Quality: $VIDEO_QUALITY (CRF $FFMPEG_CRF, preset $FFMPEG_PRESET)"
    
    if ! command_exists ffmpeg; then
        echo_error "ffmpeg not installed. Install with: brew install ffmpeg"
        return 1
    fi
    
    ffmpeg -i "$input_file" \
        -c:v "$VIDEO_CODEC" \
        -preset "$FFMPEG_PRESET" \
        -crf "$FFMPEG_CRF" \
        -c:a "$AUDIO_CODEC" \
        -y \
        "$output_file"
    
    if [[ $? -eq 0 ]]; then
        local input_size=$(du -h "$input_file" | cut -f1)
        local output_size=$(du -h "$output_file" | cut -f1)
        echo_success "Conversion complete!"
        echo_info "WebM: $input_size | MP4: $output_size"
        echo_info "Saved: $output_file"
        return 0
    else
        echo_error "Conversion failed!"
        return 1
    fi
}

# Clean old recordings
clean_old_recordings() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        echo_warning "No recordings directory found"
        return 0
    fi
    
    local days="${1:-$AUTO_CLEANUP_DAYS}"
    
    if [[ "$days" -eq 0 ]]; then
        echo_info "Auto-cleanup disabled (AUTO_CLEANUP_DAYS=0)"
        return 0
    fi
    
    echo_info "Cleaning recordings older than $days days..."
    
    local count=0
    while IFS= read -r -d '' dir; do
        rm -rf "$dir"
        echo_info "Removed: $(basename "$dir")"
        ((count++))
    done < <(find "$OUTPUT_DIR" -maxdepth 1 -type d -name "hackathon_demo_*" -mtime "+$days" -print0)
    
    if [[ $count -eq 0 ]]; then
        echo_info "No old recordings to clean"
    else
        echo_success "Cleaned $count recording(s)"
    fi
    
    # Keep last N recordings
    local recordings=($(ls -td "$OUTPUT_DIR"/hackathon_demo_* 2>/dev/null))
    local total=${#recordings[@]}
    
    if [[ $total -gt $KEEP_LAST_N_RECORDINGS ]]; then
        local to_remove=$((total - KEEP_LAST_N_RECORDINGS))
        echo_info "Keeping last $KEEP_LAST_N_RECORDINGS recordings, removing $to_remove old ones..."
        
        for ((i=KEEP_LAST_N_RECORDINGS; i<total; i++)); do
            rm -rf "${recordings[$i]}"
            echo_info "Removed: $(basename "${recordings[$i]}")"
        done
    fi
}

# Generate recording report
generate_report() {
    local recording_dir="${1:-$(ls -td "$OUTPUT_DIR"/hackathon_demo_* 2>/dev/null | head -1)}"
    
    if [[ -z "$recording_dir" || ! -d "$recording_dir" ]]; then
        echo_error "No recording directory found"
        return 1
    fi
    
    local report_file="$recording_dir/RECORDING_REPORT.txt"
    
    echo_info "Generating report: $report_file"
    
    {
        echo "=========================================="
        echo "KONG GUARD AI - RECORDING REPORT"
        echo "=========================================="
        echo ""
        echo "Recording: $(basename "$recording_dir")"
        echo "Generated: $(date)"
        echo ""
        echo "FILES:"
        echo "------"
        ls -lh "$recording_dir" | tail -n +2
        echo ""
        
        if [[ -d "$recording_dir/$SCREENSHOTS_DIR" ]]; then
            echo "SCREENSHOTS:"
            echo "------------"
            ls -lh "$recording_dir/$SCREENSHOTS_DIR" | tail -n +2
            echo ""
        fi
        
        if [[ -f "$recording_dir/timing_log.json" ]]; then
            echo "TIMING ANALYSIS:"
            echo "----------------"
            cat "$recording_dir/timing_log.json"
            echo ""
        fi
        
        echo "SUMMARY:"
        echo "--------"
        local video_count=$(find "$recording_dir" -name "*.webm" -type f | wc -l | tr -d ' ')
        local screenshot_count=$(find "$recording_dir/$SCREENSHOTS_DIR" -name "*.png" -type f 2>/dev/null | wc -l | tr -d ' ')
        local total_size=$(du -sh "$recording_dir" | cut -f1)
        
        echo "Videos: $video_count"
        echo "Screenshots: $screenshot_count"
        echo "Total Size: $total_size"
        echo ""
        echo "=========================================="
    } > "$report_file"
    
    echo_success "Report generated: $report_file"
    cat "$report_file"
}

# Open last recording in Finder/Explorer
open_last_recording() {
    local last_dir=$(ls -td "$OUTPUT_DIR"/hackathon_demo_* 2>/dev/null | head -1)
    
    if [[ -z "$last_dir" ]]; then
        echo_warning "No recordings found"
        return 1
    fi
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$last_dir"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "$last_dir" 2>/dev/null || nautilus "$last_dir" 2>/dev/null
    fi
    
    echo_success "Opened: $last_dir"
}
