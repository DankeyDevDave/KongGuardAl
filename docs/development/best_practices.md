# Project Best Practices

## 1. Project Purpose
Autonomous API Threat Response Agent for Kong Gateway. The core is a high‑priority Kong plugin (Lua/OpenResty) that detects API threats (SQLi, XSS, path traversal, DDoS patterns, credential stuffing, anomalies), scores risk, and applies graduated responses (block, rate limit, monitor). A lightweight dashboard (static HTML) and Playwright E2E tests validate the end‑to‑end behavior. An optional FastAPI management plane is scaffolded for configuration, analytics, and incident workflows.

## 2. Project Structure
- Root
  - docker/, docker-compose*.yml, scripts/: Local orchestration of Kong, demo APIs, and tooling.
  - kong-dashboard.html: Static testing dashboard used by Playwright tests.
  - tests/e2e/: Playwright test suite covering status checks, normal traffic, attacks, plugin management, and UI.
  - package.json, playwright.config.ts: Node/Playwright tooling and config.
  - README*.md, docs/: Operational docs, demos, and runbooks.
- Kong plugin(s)
  - kong-plugin/kong/plugins/kong-guard-ai/
    - handler.lua: Main plugin lifecycle (init_worker, access, log), threat scoring, responses, notifications.
    - schema.lua: Plugin config schema (thresholds, patterns, logging, admin integration, ML toggles, etc.).
    - Dependencies: lua-resty-http, ngx.shared DICT, Kong PDK.
  - plugins/kong-guard-ai/ (legacy/placeholder): Older skeleton; do not extend here. Prefer the kong-plugin/ implementation.
- fastapi-generated/ (scaffold)
  - app/main.py, app/api/v1/*, app/models/schemas.py: Management API skeleton. Some imports (app.core.*) are intentionally missing; treat as a reference design.
- Other environment assets
  - kong/, kong-guard-ai/, kong-local-testing/: Additional docs, configs, and local testing environments.

Guidance
- Treat kong-plugin/kong/plugins/kong-guard-ai as authoritative for runtime behavior.
- Keep dashboard and E2E tests aligned with Kong ports used in docker-compose (default tests assume 18000 proxy, 18001 admin, 18085 demo).

## 3. Test Strategy
- Framework: Playwright (@playwright/test)
  - Config: fullyParallel true; in CI workers=1, retries=2; trace on first retry; screenshots/videos on failure; json + html reporters.
  - Web server: python3 -m http.server 8080 serves the project root for kong-dashboard.html.
- Structure & Naming
  - tests/e2e/*.spec.ts with numeric prefixes (01-…05-…) to group scenarios.
  - tests/e2e/utils/test-helpers.ts centralizes UI operations and assertions (DashboardHelpers).
- Organization & Philosophy
  - E2E/UI tests validate integration with a live Kong stack; avoid mocking network at the browser layer.
  - Tests are independent; avoid ordering dependencies; numeric prefixes are organizational, not hard ordering.
  - Prefer explicit waits and state checks over fixed timeouts (see waitForServicesOnline, waitForResponse).
- Conventions
  - Use semantic locators and stable IDs/classes in kong-dashboard.html (e.g., #kong-status, .response-area.show).
  - Use helpers for repeated actions: clickTestButton, getStatValue, checkThreatBlocked, updateConfiguration.
  - Keep assertions resilient to variability (e.g., allow some rate-limit blocks during bursts).
- Mocking Guidelines
  - Prefer using the real docker-compose stack. If mocking is necessary, do it via backend endpoints or fixtures rather than DOM hacks.
- Unit vs Integration
  - E2E coverage is primary. Consider adding Lua unit/spec tests (busted) for detection utilities and schema validation, and Python tests for FastAPI when that layer becomes active.
- Coverage Expectations
  - Cover: dashboard load/status, normal traffic, common attack flows, plugin enable/config paths, UI interactions/styling toggles.

## 4. Code Style
- Lua (Kong Plugin)
  - Lifecycle: init_worker for one-time setup (precompute, cache init), access for detection and response decisions, log for notifications/metrics.
  - Non-blocking: Avoid synchronous external I/O in access; use ngx.timer.at for async notifications and background tasks.
  - Shared state: Use ngx.shared.kong_cache (or dedicated DICT) for counters, rate windows, and temporary blocks with TTLs.
  - Logging: Gate by config log_level; use kong.log.[debug|info|warn|err|crit]; never log secrets or full payloads.
  - Errors: Fail closed for critical checks; sanitize responses; always return via kong.response.exit for enforcement.
  - Configuration: Validate with schema.lua using defaults, between, one_of, arrays; prefer secure defaults; keep backward compatibility.
  - Performance: Keep hot paths simple; precompile/prepare patterns in init_worker; exit early on dry_run/whitelist.
  - Naming: handler.lua, schema.lua; functions verbs (extract_features, detect_threat); constants UPPER_SNAKE_CASE where appropriate.
- TypeScript (Playwright)
  - Use test.describe, test.beforeEach; centralize helpers; keep selectors stable and semantic.
  - Prefer expect with built-in retries; use waitForSelector/waitForFunction over raw timeouts; keep timeouts generous on CI.
- Python (FastAPI scaffold)
  - Type hints and Pydantic models (schemas.py) for I/O; clean separation via routers/services when implemented.
  - Middlewares for cross-cutting concerns (rate limit, error handling) as shown in main.py; structured logging.

## 5. Common Patterns
- Detection & Scoring
  - Layered approach: rate signals, pattern checks (SQLi/XSS), behavioral features, and optional anomaly score.
  - Feature extraction into a plain table; keep request context on kong.ctx.plugin for later phases.
- Rate & State Management
  - Per-IP counters via ngx.shared with windowed TTL keys (e.g., rate:<ip>:<window>), increment with expiry.
- Responses
  - Graduated actions: block above block_threshold; rate limit above rate_limit_threshold; info-only in dry_run.
  - Centralize response messaging; ensure consistent structure for audits.
- Notifications
  - Use resty.http with small timeouts; queue via ngx.timer.at; guard against failures; do not block request path.
- Configuration Endpoints (dashboard expectations)
  - Admin API routes: /kong-guard-ai/status and /kong-guard-ai/incidents are referenced by the dashboard; if not implemented server-side, return clear error JSON in the UI.
- Logging Conventions
  - Respect config.log_level; log_threats/log_requests/log_decisions provide verbosity control.

## 6. Do's and Don'ts
- Do
  - Use init_worker for initialization and precomputation; keep access fast.
  - Validate all config via schema.lua; provide safe defaults.
  - Sanitize logs and error outputs; avoid leaking request data.
  - Prefer ngx.shared DICT with TTLs for counters/flags; avoid unbounded growth.
  - Make Playwright tests robust with explicit waits and helper utilities.
  - Keep ports, routes, and plugin names in tests consistent with docker-compose and Kong config.
  - Document assumptions (e.g., /test upstream, ports 18000/18001/18085).
- Don't
  - Block in access() with network calls; avoid long regex on large bodies.
  - Store large payloads or PII in shared dict or logs.
  - Introduce breaking config changes without schema migration strategy.
  - Depend on test ordering or timing without explicit synchronization.

## 7. Tools & Dependencies
- Kong Plugin (Lua)
  - Kong 3.8.x; lua-resty-http; OpenResty/ngx; Kong PDK.
  - Packaging via rockspec in kong-plugin/.
- Node/Playwright
  - Node 20+; @playwright/test ^1.48.0; reporters: html, list, json.
  - Scripts: npm test, test:ui, test:debug, test:headed, test:report, test:codegen.
- Python (FastAPI, optional management plane)
  - FastAPI, Pydantic; requirements.txt under fastapi-generated/; intended for a separate service.
- Local Run
  - Bring up Kong stack via docker-compose (see README*.md). Ensure proxy/admin/demo ports match dashboard/test expectations.
  - Serve dashboard and run E2E: npm install; npx playwright install; npm test (Playwright auto-starts a local web server on :8080).

## 8. Other Notes
- Multiple plugin directories exist; extend runtime behavior in kong-plugin/kong/plugins/kong-guard-ai, not plugins/kong-guard-ai.
- fastapi-generated/ is a scaffold; some modules (app.core.*) are placeholders. Treat as design guidance unless completed.
- Dashboard assumes:
  - Kong Proxy: http://localhost:18000
  - Kong Admin: http://localhost:18001
  - Demo API: http://localhost:18085
- If implementing dashboard-referenced endpoints (/kong-guard-ai/status, /kong-guard-ai/incidents), keep JSON stable and concise for UI parsing.
- Prefer DB-less and stateless patterns for performance; ensure behavior scales horizontally.
- Aim for sub-10ms added latency; profile hot paths before adding heavy features (e.g., AI calls guarded by thresholds and caching).
