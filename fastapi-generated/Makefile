.PHONY: help install dev test lint format clean docker-up docker-down migrate docs

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
DOCKER_COMPOSE := docker-compose
PROJECT_NAME := kong-guard-ai

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)Kong Guard AI FastAPI - Available Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install dependencies
	@echo "$(GREEN)Installing dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

dev: ## Run development server
	@echo "$(GREEN)Starting development server...$(NC)"
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test: ## Run tests with coverage
	@echo "$(GREEN)Running tests...$(NC)"
	pytest tests/ -v --cov=app --cov-report=term-missing --cov-report=html

test-unit: ## Run unit tests only
	@echo "$(GREEN)Running unit tests...$(NC)"
	pytest tests/unit/ -v

test-integration: ## Run integration tests
	@echo "$(GREEN)Running integration tests...$(NC)"
	pytest tests/integration/ -v

lint: ## Run linting checks
	@echo "$(GREEN)Running linters...$(NC)"
	flake8 app/ tests/
	mypy app/
	black --check app/ tests/

format: ## Format code with black
	@echo "$(GREEN)Formatting code...$(NC)"
	black app/ tests/
	isort app/ tests/

clean: ## Clean up generated files
	@echo "$(GREEN)Cleaning up...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info

docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(NC)"
	docker build -t $(PROJECT_NAME):latest .

docker-up: ## Start all services with Docker Compose
	@echo "$(GREEN)Starting services...$(NC)"
	$(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)Services started!$(NC)"
	@echo "API: http://localhost:8000"
	@echo "Docs: http://localhost:8000/docs"
	@echo "Grafana: http://localhost:3000 (admin/admin)"
	@echo "Prometheus: http://localhost:9090"

docker-down: ## Stop all Docker Compose services
	@echo "$(YELLOW)Stopping services...$(NC)"
	$(DOCKER_COMPOSE) down

docker-logs: ## Show Docker Compose logs
	$(DOCKER_COMPOSE) logs -f

docker-clean: ## Clean Docker resources
	@echo "$(YELLOW)Cleaning Docker resources...$(NC)"
	$(DOCKER_COMPOSE) down -v
	docker system prune -f

migrate: ## Run database migrations
	@echo "$(GREEN)Running database migrations...$(NC)"
	alembic upgrade head

migrate-create: ## Create new migration
	@echo "$(GREEN)Creating new migration...$(NC)"
	@read -p "Enter migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"

migrate-rollback: ## Rollback last migration
	@echo "$(YELLOW)Rolling back migration...$(NC)"
	alembic downgrade -1

db-reset: ## Reset database
	@echo "$(RED)Resetting database...$(NC)"
	alembic downgrade base
	alembic upgrade head

docs: ## Generate documentation
	@echo "$(GREEN)Generating documentation...$(NC)"
	mkdocs build

docs-serve: ## Serve documentation locally
	@echo "$(GREEN)Serving documentation...$(NC)"
	mkdocs serve

validate: ## Validate OpenAPI specification
	@echo "$(GREEN)Validating OpenAPI spec...$(NC)"
	openapi-spec-validator docs/openapi.yaml

generate-client: ## Generate client SDK
	@echo "$(GREEN)Generating client SDK...$(NC)"
	openapi-generator generate -i docs/openapi.yaml -g python -o client-sdk/

benchmark: ## Run performance benchmarks
	@echo "$(GREEN)Running benchmarks...$(NC)"
	locust -f tests/performance/locustfile.py --headless -u 100 -r 10 -t 60s

security-scan: ## Run security scan
	@echo "$(GREEN)Running security scan...$(NC)"
	bandit -r app/
	safety check

monitoring-up: ## Start monitoring stack
	@echo "$(GREEN)Starting monitoring...$(NC)"
	docker-compose -f docker-compose.monitoring.yml up -d

monitoring-down: ## Stop monitoring stack
	@echo "$(YELLOW)Stopping monitoring...$(NC)"
	docker-compose -f docker-compose.monitoring.yml down

setup: install migrate ## Complete setup
	@echo "$(GREEN)Setup complete!$(NC)"

run-prod: ## Run in production mode
	@echo "$(GREEN)Starting production server...$(NC)"
	gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

health-check: ## Check service health
	@echo "$(GREEN)Checking health...$(NC)"
	@curl -s http://localhost:8000/health | jq '.' || echo "$(RED)Service not responding$(NC)"

api-test: ## Test API endpoints
	@echo "$(GREEN)Testing API endpoints...$(NC)"
	@bash scripts/test-api.sh

version: ## Show version
	@echo "$(GREEN)Kong Guard AI FastAPI v1.0.0$(NC)"

.DEFAULT_GOAL := help
