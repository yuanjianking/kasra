# =============================================================================
# Kasra — Enterprise Makefile
# =============================================================================
# Usage:
#   make install        Install Python dependencies
#   make dev            Install with dev dependencies
#   make build          Build wheel and docker image
#   make test           Run test suite
#   make lint           Run ruff linter
#   make typecheck      Run mypy type checking
#   make docker         Build Docker image
#   make docker-push    Build and push to registry
#   make up             Start development stack
#   make up-prod        Start production stack
#   make down           Stop all services
#   make logs           Follow logs
#   make migrate        Run database migrations
#   make backup         Backup database
#   make restore        Restore database from backup
#   make clean          Remove build artifacts
#   make security       Run security scanning
# =============================================================================

# ── Project Configuration ─────────────────────────────────────────────────────
APP_NAME        := kasra
APP_VERSION     := $(shell grep -E "^__version__" app/__init__.py | awk -F'"' '{print $$2}')
DOCKER_REGISTRY ?= ghcr.io/kasra-security
DOCKER_IMAGE    := $(DOCKER_REGISTRY)/$(APP_NAME):$(APP_VERSION)
DOCKER_IMAGE_LATEST := $(DOCKER_REGISTRY)/$(APP_NAME):latest
PYTHON          := python3
PIP             := pip3
POETRY          := $(shell command -v poetry 2>/dev/null || echo "")
RUFF            := ruff
MYPY            := mypy
PYTEST          := python -m pytest
COVERAGE        := coverage
NODE            := node
NPM             := npm

# ── Colors ────────────────────────────────────────────────────────────────────
BLUE   := \033[34m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
RESET  := \033[0m

.PHONY: all install dev build test lint typecheck docker docker-push \
        up up-prod down logs shell migrate backup restore clean security \
        check format help

all: check test build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "$(BLUE)%-20s$(RESET) %s\n", $$1, $$2}'

# ── Python Dependencies ───────────────────────────────────────────────────────

install: ## Install production dependencies
	$(PIP) install -e .
	@echo "$(GREEN)✓ Production dependencies installed$(RESET)"

dev: ## Install development dependencies
	$(PIP) install -e ".[dev]"
	$(PIP) install pytest-cov watchdog
	@echo "$(GREEN)✓ Dev dependencies installed$(RESET)"

install-all: dev ## Install all dependencies (prod + dev)
	$(PIP) install -e ".[postgres]"
	@echo "$(GREEN)✓ All dependencies installed$(RESET)"

# ── Testing ───────────────────────────────────────────────────────────────────

test: ## Run test suite with coverage
	$(PYTEST) tests/ -v --tb=short --cov=app --cov-report=term-missing --cov-report=html:coverage_html
	@echo "$(GREEN)✓ Tests complete$(RESET)"

test-quick: ## Run tests without coverage (faster)
	$(PYTEST) tests/ -v --tb=short -x
	@echo "$(GREEN)✓ Quick tests passed$(RESET)"

test-integration: ## Run integration tests only
	$(PYTEST) tests/test_integration.py -v --tb=short
	@echo "$(GREEN)✓ Integration tests passed$(RESET)"

test-watch: ## Run tests on file changes
	$(PYTEST) tests/ -f

# ── Linting & Formatting ──────────────────────────────────────────────────────

lint: ## Run ruff linter on all Python files
	$(RUFF) check app/ tests/ --select=E,F,I,N,W,S
	@echo "$(GREEN)✓ Lint passed$(RESET)"

lint-fix: ## Auto-fix lint issues
	$(RUFF) check app/ tests/ --fix
	@echo "$(GREEN)✓ Lint fixes applied$(RESET)"

format: ## Format code with ruff
	$(RUFF) format app/ tests/ --check
	@echo "$(GREEN)✓ Format check passed$(RESET)"

format-fix: ## Auto-format code
	$(RUFF) format app/ tests/
	@echo "$(GREEN)✓ Formatted$(RESET)"

typecheck: ## Run mypy type checking
	$(MYPY) app/ --python-version 3.11
	@echo "$(GREEN)✓ Type check passed$(RESET)"

check: lint format typecheck ## Run all checks (lint + format + typecheck)

# ── Build ─────────────────────────────────────────────────────────────────────

build: ## Build Python wheel
	$(PIP) install build
	python -m build --wheel
	@echo "$(GREEN)✓ Wheel built: dist/$(APP_NAME)-$(APP_VERSION)-py3-none-any.whl$(RESET)"

docker: ## Build Docker image (production stage)
	docker build --target production -t $(DOCKER_IMAGE) .
	docker tag $(DOCKER_IMAGE) $(DOCKER_IMAGE_LATEST)
	@echo "$(GREEN)✓ Docker image built: $(DOCKER_IMAGE)$(RESET)"

docker-dev: ## Build Docker image (development stage)
	docker build --target development -t $(APP_NAME):dev .
	@echo "$(GREEN)✓ Docker dev image built: $(APP_NAME):dev$(RESET)"

docker-push: docker ## Build and push Docker image to registry
	docker push $(DOCKER_IMAGE)
	docker push $(DOCKER_IMAGE_LATEST)
	@echo "$(GREEN)✓ Docker image pushed: $(DOCKER_IMAGE)$(RESET)"

# ── Docker Compose ────────────────────────────────────────────────────────────

up: ## Start development stack
	docker compose up -d
	@echo "$(GREEN)✓ Development stack started$(RESET)"

up-prod: ## Start production stack (with PostgreSQL)
	@echo "Enter POSTGRES_PASSWORD: "; \
	docker compose --profile production up -d
	@echo "$(GREEN)✓ Production stack started$(RESET)"

up-monitoring: ## Start monitoring stack (Prometheus + Grafana)
	docker compose --profile monitoring up -d
	@echo "$(GREEN)✓ Monitoring stack started$(RESET)"

down: ## Stop all services
	docker compose down
	@echo "$(GREEN)✓ Services stopped$(RESET)"

logs: ## Follow all logs
	docker compose logs -f

logs-kasra: ## Follow Kasra app logs only
	docker compose logs -f kasra

# ── Database Migrations ───────────────────────────────────────────────────────

migrate: ## Run Alembic database migrations
	alembic upgrade head
	@echo "$(GREEN)✓ Migrations up to date$(RESET)"

migrate-check: ## Check pending migrations
	alembic check
	@echo "$(GREEN)✓ Migration check complete$(RESET)"

migrate-auto: ## Auto-generate a new migration
	@read -p "Migration name: " name; \
	alembic revision --autogenerate -m "$$name"
	@echo "$(GREEN)✓ Migration generated$(RESET)"

migrate-downgrade: ## Rollback last migration
	alembic downgrade -1
	@echo "$(GREEN)✓ Last migration rolled back$(RESET)"

# ── Backups ───────────────────────────────────────────────────────────────────

backup: ## Backup database
	sudo bash deploy/scripts/backup.sh
	@echo "$(GREEN)✓ Backup complete$(RESET)"

restore: ## Restore database from backup
	@read -p "Backup file path: " path; \
	sudo bash deploy/scripts/restore.sh "$$path"
	@echo "$(GREEN)✓ Restore complete$(RESET)"

# ── Security Scanning ─────────────────────────────────────────────────────────

security: ## Run security scanning
	# Scan dependencies for known vulnerabilities
	$(PIP) install safety 2>/dev/null; \
	safety check --full-report || true
	# Scan source code with bandit
	$(PIP) install bandit 2>/dev/null; \
	bandit -r app/ -ll -x tests/ || true
	# Scan with ruff security rules
	$(RUFF) check app/ --select=S
	@echo "$(GREEN)✓ Security scan complete$(RESET)"

# ── Cleaning ──────────────────────────────────────────────────────────────────

clean: ## Clean up build artifacts
	rm -rf build/ dist/ *.egg-info/ .coverage coverage_html/
	rm -rf .pytest_cache/ .ruff_cache/ .mypy_cache/ __pycache__/
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -type f -delete
	@echo "$(GREEN)✓ Cleaned up$(RESET)"

clean-all: clean ## Full clean including data and node_modules
	rm -rf data/ frontend/node_modules/ frontend/dist/
	rm -rf .venv/
	@echo "$(GREEN)✓ Full clean complete$(RESET)"

# ── Development Helpers ───────────────────────────────────────────────────────

shell: ## Open Python shell with app context
	$(PYTHON) -c "from app.database import SessionLocal; from app.models import *; print('Kasra shell ready')"

serve: ## Run development server with hot-reload
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8080 --log-level debug

serve-prod: ## Run production server
	uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers $$(nproc) --log-level info

version: ## Show app version
	@echo "$(APP_NAME) v$(APP_VERSION)"

ci: lint format typecheck test ## Run all CI checks (lint + format + typecheck + test)
