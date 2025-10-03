# Kong Guard AI - Playwright Test Suite

## Overview
Comprehensive end-to-end test suite for the Kong Guard AI Dashboard using Playwright.

## Test Coverage

### 1. Status Checks (`01-status-checks.spec.ts`)
- Dashboard loading and title verification
- Service status indicators (Kong, Admin API, Plugin, Demo API)
- Port information display
- Auto-refresh functionality
- Configuration section
- Plugin loading verification

### 2. Normal Traffic (`02-normal-traffic.spec.ts`)
- Normal request handling
- Burst request testing (10 requests)
- Statistics updates (total requests, success rate, response time)
- Sequential request handling
- Results history management
- Clear results functionality

### 3. Attack Simulations (`03-attack-simulations.spec.ts`)
- SQL Injection detection and blocking
- XSS attack detection and blocking
- Path traversal attack detection
- DDoS simulation and rate limiting
- Malformed headers detection
- Attack payload display
- Threat level indicators
- Statistics accumulation

### 4. Plugin Management (`04-plugin-management.spec.ts`)
- Plugin status checking
- Blocked IPs viewing
- Metrics viewing
- Incidents viewing
- Plugin enabling/configuration
- Configuration updates
- Error handling

### 5. UI Interactions (`05-ui-interactions.spec.ts`)
- Responsive layout testing
- Color scheme and styling
- Hover effects
- Animation verification
- Result formatting
- Keyboard navigation
- Scroll handling
- Result ordering

## Setup

### Prerequisites
- Node.js 20+
- Docker and Docker Compose
- Kong stack running (ports 18000, 18001)

### Installation
```bash
# Install dependencies
npm install

# Install Playwright browsers
npx playwright install
```

### Configuration
The test suite expects:
- Kong Proxy: `http://localhost:18000`
- Kong Admin: `http://localhost:18001`
- Dashboard: `http://localhost:8080/kong-dashboard.html`

## Running Tests

### Local Development
```bash
# Run all tests
npm test

# Run with UI mode
npm run test:ui

# Run in headed mode (see browser)
npm run test:headed

# Run with debug mode
npm run test:debug

# Run specific test file
npx playwright test tests/e2e/01-status-checks.spec.ts

# Run specific test
npx playwright test -g "should send normal request"
```

### Generate Tests
```bash
# Open Playwright codegen to record new tests
npm run test:codegen
```

### View Reports
```bash
# After running tests, view HTML report
npm run test:report
```

## CI/CD Integration

Tests run automatically on:
- Push to `main` or `develop` branches
- Pull requests
- Manual workflow dispatch

GitHub Actions workflow:
- Sets up Kong stack with Docker Compose
- Runs all Playwright tests
- Uploads test reports as artifacts
- Captures screenshots/videos on failure

## Test Structure

```
tests/
└── e2e/
    ├── utils/
    │ └── test-helpers.ts # Shared helper functions
    ├── 01-status-checks.spec.ts # Service status tests
    ├── 02-normal-traffic.spec.ts # Normal request tests
    ├── 03-attack-simulations.spec.ts # Security tests
    ├── 04-plugin-management.spec.ts # Plugin config tests
    └── 05-ui-interactions.spec.ts # UI/UX tests
```

## Helper Functions

The `DashboardHelpers` class provides:
- `waitForServicesOnline()` - Wait for all services to be ready
- `getResponseData()` - Parse response from dashboard
- `checkServiceStatus()` - Check if a service is online
- `clickTestButton()` - Click test buttons and wait for response
- `getStatValue()` - Get statistics values
- `checkThreatBlocked()` - Verify threat was blocked
- `updateConfiguration()` - Update dashboard configuration

## Debugging

### View browser during tests
```bash
npx playwright test --headed --workers=1
```

### Debug specific test
```bash
npx playwright test --debug -g "test name"
```

### Trace viewer
```bash
# Tests create traces on retry
npx playwright show-trace trace.zip
```

### Screenshots
Failed tests automatically capture screenshots in `test-results/` directory.

## Best Practices

1. **Test Independence**: Each test should be independent and not rely on others
2. **Wait Strategies**: Use proper wait conditions instead of fixed timeouts
3. **Assertions**: Use Playwright's built-in assertions for auto-retry
4. **Cleanup**: Tests should clean up after themselves
5. **Parallel Execution**: Tests are designed to run in parallel

## Troubleshooting

### Services not online
- Ensure Docker Compose stack is running: `docker compose up -d`
- Check services: `docker ps`
- Verify ports: 18000, 18001, 18085

### Tests timing out
- Increase timeout in `playwright.config.ts`
- Check if services are responding
- Review network conditions

### Flaky tests
- Add more specific wait conditions
- Check for race conditions
- Use `test.slow()` for longer operations

## Contributing

When adding new tests:
1. Follow existing naming conventions
2. Add to appropriate test file or create new one
3. Update this README with new coverage
4. Ensure tests are independent
5. Add proper assertions and error handling