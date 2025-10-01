# Kong Guard AI - Video Script

**Duration**: 7-9 minutes  
**Format**: Code walkthrough + live demos  
**Presenter**: DankeyDevDave

---

## 🎬 Scene 1: Introduction (60 seconds)

### Visual: Terminal + README.md

**Script**:
> "Hello! I'm DankeyDevDave, and this is Kong Guard AI - an autonomous API threat detection and response system built for the Kong Agentic AI Hackathon 2025.
>
> Kong Guard AI transforms your Kong Gateway into an intelligent, self-healing security system that autonomously detects, classifies, and responds to API threats in real-time.
>
> What makes this unique? It combines multi-tier detection - pattern matching, ML models, and LLM analysis - all embedded directly in Kong Gateway with under 10 milliseconds of latency.
>
> Let me show you how it works."

**Actions**:
- Show README.md title
- Scroll through architecture diagram
- Highlight key stats (90% cache hit, <10ms latency)

---

## 🎬 Scene 2: Architecture Overview (90 seconds)

### Visual: docker-compose.yml + Architecture

**Script**:
> "The system architecture is built on four key components:
>
> First, Kong Gateway - the entry point for all API traffic. Every request flows through our custom Lua plugin.
>
> Second, the AI Service layer - I've implemented multi-provider support with automatic failover. OpenAI, Gemini, Groq, and local Ollama models. If one provider fails or hits quota limits, we automatically switch to another.
>
> Third, the Machine Learning models - three specialized models working together: anomaly detection using Isolation Forest, attack classification with Random Forest, and feature extraction with 70+ engineered features.
>
> Fourth, the caching layer - this is crucial. We achieve 90% cache hit rates through intelligent multi-tier caching with HMAC-SHA256 signatures to prevent cache poisoning attacks.
>
> Let me show you the plugin in action."

**Actions**:
- Open docker-compose.yml
- Show services list
- Open architecture diagram
- Highlight each component

---

## 🎬 Scene 3: Kong Plugin Loaded (60 seconds)

### Visual: Terminal - Kong Admin API

**Script**:
> "First, let's verify Kong Gateway is running and our plugin is loaded."

```bash
# Show Kong version
curl http://localhost:18001 | jq '.version'

# Show plugin loaded
curl http://localhost:18001 | jq '.plugins.available_on_server."kong-guard-ai"'

# Show plugin enabled
curl http://localhost:18001/plugins | jq '.data[] | {name, enabled}'
```

**Script**:
> "Perfect! Kong Guard AI plugin is loaded and active. Now let's look at the threat detection logic."

---

## 🎬 Scene 4: Plugin Code Walkthrough (120 seconds)

### Visual: handler.lua

**Script**:
> "The plugin's intelligence is in the handler. Let me walk you through the threat detection pipeline.
>
> When a request arrives, we first check the signature cache - if we've seen this exact threat pattern before, we block it immediately. That's our fastest path at under 1 millisecond.
>
> If not cached, we extract features from the request - URL patterns, header anomalies, payload characteristics. We pass these through our ML models which give us an initial threat score.
>
> For high-confidence threats, we're done. But for ambiguous requests, we leverage LLM analysis. The AI provides reasoning - not just a score, but an explanation of WHY something is suspicious.
>
> Finally, the policy engine decides the action based on per-endpoint configuration. Should we block? Challenge with CAPTCHA? Or just log in dry-run mode?
>
> And here's the key innovation - every decision includes comprehensive response headers so developers can see exactly what happened and why."

**Actions**:
- Open kong-plugin/kong/plugins/kong-guard-ai/handler.lua
- Scroll through access() function
- Highlight:
  - Cache lookup
  - ML model integration  
  - LLM analysis
  - Policy decisions
  - Response headers

---

## 🎬 Scene 5: Security Hardening Features (120 seconds)

### Visual: Security module files

**Script**:
> "Now let me show you the production-ready security hardening I've implemented.
>
> First, the Provider Circuit Breaker. This tracks quota usage across all LLM providers - requests per minute, tokens per day, cost per provider. When OpenAI hits its limit, we automatically failover to Gemini. When that's exhausted, we switch to Groq. The system never goes down.
>
> Second, PII Scrubbing - GDPR and POPIA compliant. Before sending ANY data to LLM providers, we scrub 10+ types of PII: emails, phone numbers, credit cards, API keys. IP addresses are hashed for correlation without exposure.
>
> Third, the Policy Engine - per-endpoint security policies. Your admin endpoints can have aggressive blocking at 0.5 threat score, while public APIs can be more permissive at 0.8. All configured via JSON, no code changes needed.
>
> Fourth, Cache Signature Validation - every cache entry is HMAC-SHA256 signed and version-bound. This prevents cache poisoning attacks. If someone tries to inject a malicious cache entry, the signature validation catches it.
>
> Fifth, the Feedback System with trust-weighted operator consensus. Not all security analysts are equal - senior analysts' feedback carries 2x weight compared to junior analysts.
>
> And finally, comprehensive response headers including dry-run mode. You can test new policies in production without blocking real traffic."

**Actions**:
- Open provider_circuit_breaker.py
- Show quota tracking code
- Open pii_scrubber.py  
- Show PII patterns
- Open policy_engine.py
- Show policy examples
- Open intelligent_cache_v2.py
- Show HMAC signing
- Open response_headers.py
- Show 14 header types

---

## 🎬 Scene 6: Authorship Protection (60 seconds)

### Visual: LICENSE file

**Script**:
> "One unique aspect of this project - I'm submitting under my online persona 'DankeyDevDave' while maintaining full legal protection.
>
> I've enhanced the LICENSE with pseudonymous copyright protection. Sections 9 through 12 establish:
> - Legal validity under the Berne Convention and US Copyright Act
> - Proof of authorship through hackathon submission records and GPG-signed commits
> - DMCA enforcement procedures
> - Dual contact system - public persona for collaborations, private legal channel through Kong Inc.
>
> This ensures I maintain copyright protection and enforcement rights while preserving my privacy publicly."

**Actions**:
- Open LICENSE
- Scroll to Section 9
- Highlight key legal framework
- Show Section 10 (Enforcement)
- Show authorship verification

---

## 🎬 Scene 7: Documentation Quality (60 seconds)

### Visual: docs/ folder

**Script**:
> "Professional documentation is crucial. I've created:
>
> A comprehensive technical whitepaper - 50 pages covering architecture, security, performance, and competitive analysis.
>
> SECURITY.md with vulnerability reporting and DMCA contact information.
>
> Operational runbooks for 8 common failure scenarios - from provider degradation to cache poisoning to false positive spikes.
>
> An authorship protection guide explaining the legal strategy.
>
> And example policy configurations for common use cases.
>
> Everything a production team needs to deploy and operate this system."

**Actions**:
- Open docs/ folder
- Show file list
- Open RUNBOOK_OPERATIONAL_GUIDE.md
- Scroll through sections
- Open AUTHORSHIP_PROTECTION_GUIDE.md
- Show table of contents

---

## 🎬 Scene 8: Live AI Service (60 seconds)

### Visual: Terminal - AI Service

**Script**:
> "Let me show you the AI services are actually running and responding."

```bash
# Check AI service health
curl http://localhost:28100/health | jq '.'

# Show it's alive and configured
docker ps --filter "name=kong-guard-ai" --format "table {{.Names}}\t{{.Status}}"
```

**Script**:
> "Both cloud and local AI services are healthy and ready to analyze threats. The multi-provider approach ensures we always have an AI backend available."

---

## 🎬 Scene 9: Business Value (45 seconds)

### Visual: Whitepaper - Economic Impact section

**Script**:
> "What's the business value?
>
> 90% reduction in LLM costs through intelligent caching.
> 80% reduction in false positives versus traditional WAFs.
> Under 10 milliseconds of latency - 5 to 20 times faster than external WAF solutions.
> Zero downtime deployment - the plugin integrates directly into Kong with no additional infrastructure.
>
> For e-commerce, financial services, SaaS platforms - this provides enterprise-grade security without the enterprise-grade complexity or cost."

**Actions**:
- Show whitepaper business value section
- Highlight cost savings
- Show performance metrics

---

## 🎬 Scene 10: Conclusion & Call to Action (30 seconds)

### Visual: README.md contact section

**Script**:
> "Kong Guard AI demonstrates how agentic AI can transform API security - from reactive alerting to autonomous threat response. 
>
> The code is production-ready, the documentation is comprehensive, and the security hardening makes it enterprise-deployable.
>
> I'm DankeyDevDave, this was built for the Kong Agentic AI Hackathon 2025. 
>
> For questions or collaboration: dankeydevdave@gmail.com
>
> Thank you for watching, and thank you to the judges for your consideration!"

**Actions**:
- Show README header
- Show contact information
- Show GitHub repo URL
- Fade out

---

## 🎯 Recording Checklist

### Before Recording ✅
- [ ] Close unnecessary apps
- [ ] Clear notifications
- [ ] Prepare terminal windows
- [ ] Open files in editor
- [ ] Test microphone
- [ ] Check screen resolution (1080p minimum)
- [ ] Quiet environment

### Files to Have Open ✅
1. README.md
2. LICENSE (Section 9-12)
3. kong-plugin/kong/plugins/kong-guard-ai/handler.lua
4. provider_circuit_breaker.py
5. pii_scrubber.py
6. policy_engine.py
7. intelligent_cache_v2.py
8. response_headers.py
9. SECURITY.md
10. docs/RUNBOOK_OPERATIONAL_GUIDE.md
11. KONG_GUARD_AI_TECHNICAL_WHITEPAPER.md

### Terminal Commands Ready ✅
```bash
# Kong version
curl -s http://localhost:18001 | jq '.version'

# Plugin loaded
curl -s http://localhost:18001 | jq '.plugins.available_on_server."kong-guard-ai"'

# AI service health
curl -s http://localhost:28100/health | jq '.'

# Docker status
docker ps --format "table {{.Names}}\t{{.Status}}"
```

---

## 🎥 Recording Tips

1. **Pace**: Speak slowly and clearly
2. **Pauses**: Pause between scenes for easier editing
3. **Zoom**: Use Cmd+Plus to zoom text when showing code
4. **Highlighting**: Use mouse/cursor to point at important code
5. **Timing**: Stay under 9 minutes total
6. **Energy**: Sound excited but professional
7. **Retakes**: Record in segments, easier to redo one scene than entire video

---

## 🚀 Alternative: Quick Demo Script (5 min)

If you want a shorter version:

1. **Intro** (30s)
2. **Show Kong + Plugin Loaded** (60s)
3. **Code Walkthrough - handler.lua** (90s)
4. **Security Modules Overview** (90s)
5. **Conclusion** (30s)

**Total**: 5 minutes, focuses on core innovation

---

**Ready to record!** 🎬

**Recommended Approach**: Record scene-by-scene, then stitch together. Easier to fix one bad scene than re-record entire video.

**Good luck!** 🚀
