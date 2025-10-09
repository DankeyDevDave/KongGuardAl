# Kong Guard AI Makefile
# Provides convenient targets for development, testing, and auditing

.PHONY: help install-dev audit audit-live audit-quick clean test

# Default target
help:
	@echo "Kong Guard AI Development Commands"
	@echo "=================================="
	@echo ""
	@echo "Development:"
	@echo "  install-dev     Install development dependencies"
	@echo "  test           Run test suite"
	@echo "  clean          Clean build artifacts and caches"
	@echo ""
	@echo "Audit & Testing:"
	@echo "  audit          Run full automated audit (10 clicks per attack)"
	@echo "  audit-quick    Run quick audit (3 clicks per attack)"
	@echo "  audit-live     Run audit with live markdown output"
	@echo ""
	@echo "Docker Management:"
	@echo "  docker-up      Start all services with docker-compose"
	@echo "  docker-down    Stop all services"
	@echo "  docker-logs    Show logs from all services"
	@echo ""
	@echo "Presentation:"
	@echo "  present        Start live presentation with reveal-md"
	@echo "  present-matrix Start presentation focused on attack matrix"

# Development setup
install-dev:
	@echo "Installing development dependencies..."
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt
	@echo "Development environment ready!"

# Testing
test:
	@echo "Running test suite..."
	.venv/bin/python -m pytest tests/ -v

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	rm -f coverage.xml
	@echo "Cleanup complete!"

# Docker management
docker-up:
	@echo "Starting Kong Guard AI stack..."
	docker compose -f docker-compose.consolidated.yml up -d
	@echo "Stack started! Dashboard: http://localhost:3000"

docker-down:
	@echo "Stopping Kong Guard AI stack..."
	docker compose -f docker-compose.consolidated.yml down
	@echo "Stack stopped!"

docker-logs:
	@echo "Showing logs from all services..."
	docker compose -f docker-compose.consolidated.yml logs -f

# Audit commands
audit: docker-up
	@echo "Running full automated audit..."
	sleep 10  # Wait for services to start
	.venv/bin/python scripts/auto_audit_runner.py \
		--clicks 10 \
		--tiers unprotected,cloud,local \
		--matrix docs/demo-attack-matrix.md \
		--report-dir docs/audit/runs \
		--goals docs/audit/goals.yaml \
		--live-md docs/audit/live/audit-live.md
	@echo "Audit complete! Check docs/audit/runs/ for results."

audit-quick: docker-up
	@echo "Running quick audit..."
	sleep 10  # Wait for services to start
	.venv/bin/python scripts/auto_audit_runner.py \
		--clicks 3 \
		--tiers unprotected,cloud,local \
		--matrix docs/demo-attack-matrix.md \
		--report-dir docs/audit/runs \
		--goals docs/audit/goals.yaml
	@echo "Quick audit complete!"

audit-live: docker-up
	@echo "Running audit with live output..."
	sleep 10  # Wait for services to start
	.venv/bin/python scripts/auto_audit_runner.py \
		--clicks 10 \
		--tiers unprotected,cloud,local \
		--matrix docs/demo-attack-matrix.md \
		--report-dir docs/audit/runs \
		--goals docs/audit/goals.yaml \
		--live-md docs/audit/live/audit-live.md
	@echo "Live audit complete! Check docs/audit/live/audit-live.md"

# Presentation commands
present:
	@echo "Starting live presentation..."
	@echo "Opening http://localhost:1948/docs/demo-attack-matrix.md"
	npx reveal-md docs/demo-attack-matrix.md -w --port 1948

present-matrix:
	@echo "Starting attack matrix presentation..."
	@echo "Opening http://localhost:1949/docs/demo-attack-matrix.md"
	npx reveal-md docs/demo-attack-matrix.md -w --port 1949 --theme simple

# Health check
health:
	@echo "Checking service health..."
	@echo "Kong Gateway:"
	@curl -s http://localhost:28080/ || echo "  ❌ Kong Gateway not responding"
	@echo "Cloud AI Service:"
	@curl -s http://localhost:28100/ | head -c 100 || echo "  ❌ Cloud AI not responding"
	@echo "Local AI Service:"
	@curl -s http://localhost:28101/ | head -c 100 || echo "  ❌ Local AI not responding"
	@echo "WebSocket Service:"
	@curl -s http://localhost:18002/ | head -c 100 || echo "  ❌ WebSocket not responding"
	@echo "Dashboard:"
	@curl -s http://localhost:3000/ | head -c 100 || echo "  ❌ Dashboard not responding"

# Full development workflow
dev-setup: install-dev docker-up
	@echo "Development environment ready!"
	@echo "Dashboard: http://localhost:3000"
	@echo "Run 'make audit' to test the system"

# CI/CD targets
ci-gates:
	@echo "Running CI/CD quality gates..."
	.venv/bin/python scripts/ci_gates.py --goals docs/audit/goals.yaml --report docs/audit/runs/latest.json --summary

ci-audit: install-dev docker-up
	@echo "Running CI audit..."
	sleep 10  # Wait for services to start
	.venv/bin/python scripts/auto_audit_runner.py \
		--clicks 3 \
		--tiers unprotected,cloud,local \
		--matrix docs/demo-attack-matrix.md \
		--report-dir docs/audit/runs \
		--goals docs/audit/goals.yaml \
		--live-md docs/audit/live/audit-live.md
	.venv/bin/python scripts/ci_gates.py --goals docs/audit/goals.yaml --report docs/audit/runs/latest.json
	@echo "CI audit complete!"

# Development workflow targets
dev-test: ci-audit
	@echo "Development testing complete"

dev-clean:
	docker-compose down -v
	rm -rf docs/audit/runs/*.json docs/audit/runs/*.csv

# Production deployment preparation
deploy-prep: dev-clean ci-audit
	@echo "Production deployment preparation complete!"
	@echo "All tests passed and audit completed successfully."
