# Kong Guard AI – Demo Kit

## One‑liner
```bash
# Optional: install deps
pip install -U playwright google-genai fastapi uvicorn httpx redis python-dotenv
python -m playwright install --with-deps chromium

# Run demo
bash scripts/run_full_demo.sh
```

## Prereqs
- Python 3.11+
- `pip install playwright google-genai`
- `python -m playwright install --with-deps chromium`
- Optional: `ffmpeg` if you want narrated MP4 output
- Optional: GEMINI_API_KEY for voice generation

## Files
- `narrator_timing.json` – scene list + durations + narration
- `demo_visual_effects.js` – overlay, progress, screenshot flash, highlights
- `scripts/run_full_demo.sh` – glue: TTS → stack → record → mux

## Tips
- Change the dashboard URL in `narrator_timing.json` to your live dashboard.
- If you skip voice generation, the recorder still runs scenes and captures screenshots.
- Use `HEADED=false VIDEO=true` envs to record headless WebM with Playwright if preferred.
