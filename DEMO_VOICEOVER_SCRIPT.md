# Kong Guard AI – Demo Voiceover Script

Timing aligns with `DEMO_RECORDING_SCRIPT.md`. Pause slightly between sections to match on-screen transitions.

## 0:00 – 0:30 · Opening & Context
"Welcome to Kong Guard AI, the first autonomous AI security agent built directly into Kong Gateway. Everything on screen is running live—our gateway, the Kong Guard AI plugin, and the AI co-pilot services that inspect every request in real time."

## 0:30 – 1:15 · Problem & Architecture
"APIs face evolving attacks that signature rules miss. Manual triage can’t keep pace. Kong Guard AI embeds agentic intelligence at the edge. The Lua plugin intercepts traffic, streams rich context to our AI engine, and gets millisecond verdicts—allow, rate-limit, or block—before the request hits an upstream service."

## 1:15 – 2:00 · Attack Simulator Overview
"On the left is our attack simulator. I’ll start with normal traffic to set a baseline: notice the low threat score. Now I trigger SQL injection, XSS, and a bursty DDoS. The AI analysis panel updates instantly, and the live feed shows each attempt with explained actions."

## 2:00 – 3:00 · Full Demo Sequence
"Let’s run the full demo sequence. This cycles through normal requests and malicious payloads, including a zero-day variant we crafted specifically for the hackathon. As events stream in, the AI reasons about intent, escalates from monitor to rate limit, and blocks high-risk calls automatically—all under 100 milliseconds." 

## 3:00 – 3:45 · Reasoning & Metrics
"The thinking overlay reveals what the AI is checking—previous behavior, anomaly scores, and shared memory from earlier attacks. On the right, metrics confirm how many threats were blocked, how many were allowed, and that our latency budget stays under 10 milliseconds even during spikes." 

## 3:45 – 4:15 · Developer Controls
"Operators stay in control with simple commands. I can inspect the swarm of security agents, review stored threat memories, and update enforcement policies without redeploying anything—this fits right into standard Kong Gateway workflows." 

## 4:15 – 4:45 · Closing Impact
"Kong Guard AI delivers 95 percent plus detection accuracy, sub–10 millisecond decisions, and autonomous protection ready for Kong Konnect. It’s built to stop zero-day attacks before they reach your APIs. We’re excited to share Kong Guard AI with the Kong Agentic AI Hackathon judges—thank you for watching." 
