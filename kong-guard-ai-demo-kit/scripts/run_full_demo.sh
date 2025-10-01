#!/usr/bin/env bash
set -euo pipefail

# Config
VOICE_NAME=${VOICE_NAME:-Gacrux}
OUTPUT_VOICE_DIR=${OUTPUT_VOICE_DIR:-demo_recordings/voiceovers}
HEADED=${HEADED:-true}
SCREENSHOTS=${SCREENSHOTS:-true}
VIDEO=${VIDEO:-false}

echo "== Kong Guard AI – Full Demo =="
echo "Voice: $VOICE_NAME"
echo "Headed: $HEADED  Screenshots: $SCREENSHOTS  Video: $VIDEO"
echo ""

# 1) Generate voiceovers (requires GEMINI_API_KEY and google-genai)
if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  echo "!! GEMINI_API_KEY not set. Skipping voice generation."
else
  echo "[1/4] Generating narration with Gemini..."
  python3 generate_scene_voice.py --voice "$VOICE_NAME" --all --output "$OUTPUT_VOICE_DIR" || echo "Voice generation skipped or partial."
fi

# 2) Ensure services are up (assumes docker compose from earlier pack)
echo "[2/4] Starting local stack (if present)..."
if [[ -f "docker-compose.yml" ]]; then
  docker compose up -d
  sleep 5
else
  echo "No docker-compose.yml found. Make sure Gateway + service are running."
fi

# 3) Record the demo in headed or headless mode
echo "[3/4] Recording browser demo..."
python3 hackathon_demo_recorder.py   ${HEADED:+--headed} ${SCREENSHOTS:+--screenshots} ${VIDEO:+--video}   --narrator-timing

# 4) Mux audio with the newest webm, if any
echo "[4/4] Post processing..."
LAST_WEBM=$(ls -t demo_recordings/*/*.webm 2>/dev/null | head -n1 || true)
LAST_TIMING=$(ls -t demo_recordings/*/timing_log.json 2>/dev/null | head -n1 || true)
if [[ -n "$LAST_WEBM" && -n "$LAST_TIMING" && -d "$OUTPUT_VOICE_DIR" ]]; then
  echo "Muxing voice with: $LAST_WEBM"
  # naive concat in scene order
  TMP_LIST=$(mktemp)
  for f in $(ls "$OUTPUT_VOICE_DIR"/scene_*.wav 2>/dev/null | sort -V); do
    echo "file '$f'" >> "$TMP_LIST"
  done
  if command -v ffmpeg >/dev/null 2>&1; then
    ffmpeg -y -f concat -safe 0 -i "$TMP_LIST" -c copy /tmp/voice_track.wav
    ffmpeg -y -i "$LAST_WEBM" -i /tmp/voice_track.wav -c:v copy -c:a aac -shortest "${LAST_WEBM%.webm}_narrated.mp4"
    echo "Created: ${LAST_WEBM%.webm}_narrated.mp4"
  else
    echo "ffmpeg not found; skipping mux."
  fi
else
  echo "No video+voice to mux; check recordings and voiceovers."
fi

echo "Done."
