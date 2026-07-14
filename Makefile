# ============================================================================
# Kasra — Makefile
# ============================================================================

.PHONY: dev test build clean logs help

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

dev: ## Start all containers
	docker compose up -d

build: ## Build Docker images
	docker compose build

build-frontend: ## Build frontend
	cd frontend && npm run build

test: ## Run app tests
	python -m pytest tests/ -q

test-sdk: ## Run SDK tests
	python -m pytest ../kasra-sdk/tests/ -q

test-integration: ## Run integration tests
	python -m pytest integration_tests/ -q

test-all: test-sdk test test-integration ## All tests

logs: ## Container logs
	docker compose logs -f

down: ## Stop
	docker compose down

clean: ## Clean volumes
	docker compose down -v

shell: ## DB shell
	docker compose exec postgres psql -U kasra -d kasra
