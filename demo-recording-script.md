# Kong Guard AI – Screen Recording Step Guide

This walkthrough mirrors the live attack dashboard (`visualization/index.html`) to ensure every highlight aligns with the actual UI components.

## Pre-Flight Checklist
- Start services: `docker-compose -f docker-compose-presentation.yml up -d`.
- Confirm Kong Guard AI plugin health: `curl http://localhost:8001/status` and Kong Admin UI plugin list.
- Open the attack dashboard at `http://localhost:8080` and refresh to clear prior events.
- Prepare two supporting terminals:
  1. **Attack Simulator:** ready for `./scripts/simulate-attacks.sh`.
  2. **Metrics Monitor (optional):** `watch "curl -s http://localhost:8001/_guard_ai/metrics | jq"`.
- Disable notifications, set recorder to 1080p30, and verify microphone input.

## Scene 1 · Overview & Status (0:00 – 0:30)
1. Begin on the dashboard header showing the "🟢 Connected" badge; toggle network/click to demonstrate live state if desired.
2. Hover over the six metric tiles (`Total Requests`, `Threats Blocked`, `Safe Requests`, `Current RPS`, `Avg Latency`, `AI Accuracy`).
3. Cut briefly to Terminal: run `docker-compose ps` to confirm services, then return to the dashboard.

## Scene 2 · Architecture Context (0:30 – 1:15)
1. Switch to the architecture slide from `PRESENTATION_GUIDE.md` (or preloaded graphic) and point out the client → Kong → AI → decision flow.
2. Return to the dashboard and highlight the "Threat Flow Visualization" section to mirror the same path in real-time.

## Scene 3 · Attack Simulator Showcase (1:15 – 2:00)
1. Focus on the "🎯 Attack Simulator" card.
2. Click `Normal Traffic` to establish baseline activity (observe low threat score in feed).
3. Trigger `SQL Injection`, `XSS Attack`, and `DDoS Burst` buttons with ~3 second spacing.
4. Point to updates in `AI Analysis Engine` (threat distribution bars) and scroll the `Live Threat Feed` to show new entries.

## Scene 4 · Full Demo Sequence (2:00 – 3:00)
1. Press `🎬 Run Demo Sequence` to launch the scripted pattern.
2. Alternate between Terminal output (`./scripts/simulate-attacks.sh`) and dashboard events to show real traffic correlation.
3. Zoom on any high-threat event card to showcase method, path, threat score, action, and IP.

## Scene 5 · AI Reasoning & Metrics (3:00 – 3:45)
1. Capture the `🧠 AI Analysis Engine` overlay when reasoning spinner appears; pause to read the status text.
2. Highlight the `Threat Distribution` bars adjusting live.
3. Show the metrics terminal for JSON output, then cross-reference matching values on the dashboard tiles.

## Scene 6 · Developer Controls (3:45 – 4:15)
1. Run commands like `/swarm-status detailed` or `/kong-security threats` (from demo scripts) to display agent coordination.
2. Show a snippet of the plugin configuration (`kong-plugin/kong/plugins/kong-guard-ai/schema.lua` or admin API example) to demonstrate manageability.

## Scene 7 · Closing Metrics & CTA (4:15 – 4:45)
1. Return to the top of the dashboard; linger on the `Threat Flow Visualization` animation.
2. Overlay a slide with key metrics (95%+ accuracy, <10 ms latency, multi-provider AI support).
3. End on the dashboard header as audio/video fades out.

## Post-Recording Tasks
- Trim to 4:30–5:00 minutes, normalize audio, and export at 1080p.
- Review playback to confirm all dashboard elements are visible and synchronized.
- Upload privately/unlisted, gather the share link, and prepare it for the submission form.
