.PHONY: help build up down restart logs shell test test-fast test-metrics test-coverage cache-prepare enrich train cv ablation clean health jupyter stats doctor

COMPOSE := $(shell if command -v docker-compose >/dev/null 2>&1; then echo docker-compose; else echo docker compose; fi)

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "CTI Recommender - Makefile Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ==============================================================================
# BUILD & START
# ==============================================================================

docker-check: ## Verify Docker daemon is running
	@docker info >/dev/null 2>&1 || (echo "✗ Docker daemon is not running." && echo "  Start Docker Desktop, then rerun this command." && exit 1)

build: docker-check ## Build Docker image
	@echo "Building Docker image..."
	@$(COMPOSE) build

up: build ## Start services (production mode)
	@echo "Starting services..."
	@$(COMPOSE) up -d
	@echo "✓ Services started at http://localhost:8000"

dev: build ## Start services (development mode with hot-reload)
	@echo "Starting development services..."
	@$(COMPOSE) -f docker-compose.dev.yml up -d api-dev
	@echo "✓ Development server started at http://localhost:8000"
	@echo "  (Source code mounted, auto-reload enabled)"

down: ## Stop all services
	@echo "Stopping services..."
	@$(COMPOSE) down
	@$(COMPOSE) -f docker-compose.dev.yml down 2>/dev/null || true
	@echo "✓ Services stopped"

restart: ## Restart services
	@$(COMPOSE) restart
	@echo "✓ Services restarted"

# ==============================================================================
# MONITORING
# ==============================================================================

logs: ## View logs (follows in real-time)
	@$(COMPOSE) logs -f api || $(COMPOSE) -f docker-compose.dev.yml logs -f api-dev

status: ## Check container status
	@echo "Container Status:"
	@$(COMPOSE) ps
	@$(COMPOSE) -f docker-compose.dev.yml ps 2>/dev/null || true

doctor: ## Run local environment diagnostics (docker, compose, db)
	@echo "Running local diagnostics..."
	@set -e; \
	fail=0; \
	if docker info >/dev/null 2>&1; then \
		echo "✓ Docker daemon: running"; \
	else \
		echo "✗ Docker daemon: not running"; \
		fail=1; \
	fi; \
	if $(COMPOSE) -f docker-compose.yml config >/dev/null 2>&1; then \
		echo "✓ Compose (prod): valid"; \
	else \
		echo "✗ Compose (prod): invalid"; \
		fail=1; \
	fi; \
	if $(COMPOSE) -f docker-compose.dev.yml config >/dev/null 2>&1; then \
		echo "✓ Compose (dev): valid"; \
	else \
		echo "✗ Compose (dev): invalid"; \
		fail=1; \
	fi; \
	if [ -f data/cve_database.db ]; then \
		echo "✓ Database file: present (data/cve_database.db)"; \
	else \
		echo "✗ Database file: missing (data/cve_database.db)"; \
		fail=1; \
	fi; \
	if [ $$fail -eq 0 ]; then \
		echo "✓ Diagnostics passed"; \
	else \
		echo "✗ Diagnostics failed"; \
		exit 1; \
	fi

stats: ## Show resource usage
	@docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" \
		$$(docker ps --filter "name=cti-" --format "{{.Names}}")

health: ## Check API health
	@curl -sf http://localhost:8000/health && echo "\n✓ API is healthy" || echo "✗ API is not responding"

# ==============================================================================
# DEVELOPMENT
# ==============================================================================

shell: ## Open interactive shell in container
	@$(COMPOSE) exec api bash || $(COMPOSE) -f docker-compose.dev.yml exec api-dev bash

jupyter: ## Start Jupyter notebook server
	@echo "Starting Jupyter notebook..."
	@$(COMPOSE) -f docker-compose.dev.yml up -d jupyter
	@echo "✓ Jupyter available at http://localhost:8888"

# ==============================================================================
# TESTING
# ==============================================================================

cache-prepare: ## Prepare required cache artifacts before tests
	@echo "Preparing cache for test suite..."
	@$(COMPOSE) -f docker-compose.dev.yml run --rm test-runner \
		python scripts/prepare_test_cache.py --max-cves 30000 --min-size 1000000

test: cache-prepare ## Run all tests
	@echo "Running all tests..."
	@$(COMPOSE) -f docker-compose.dev.yml run --rm test-runner pytest tests/ -v --tb=short

test-fast: cache-prepare ## Run new tests only (99 tests, ~1 second)
	@echo "Running new tests (healthcare, CV, ablation)..."
	@$(COMPOSE) -f docker-compose.dev.yml run --rm test-runner \
		pytest tests/test_healthcare_mapper.py \
		       tests/test_cross_validation.py \
		       tests/test_ablation_study.py -v

test-metrics: cache-prepare ## Run evaluation metrics tests
	@$(COMPOSE) -f docker-compose.dev.yml run --rm test-runner \
		pytest tests/test_evaluation_metrics.py -v

test-coverage: cache-prepare ## Run tests with coverage report
	@$(COMPOSE) -f docker-compose.dev.yml run --rm test-runner \
		pytest tests/ --cov=src --cov-report=html --cov-report=term

# ==============================================================================
# SCRIPTS
# ==============================================================================

enrich: ## Run CVE enrichment with healthcare mapping
	@echo "Running CVE enrichment..."
	@$(COMPOSE) run --rm api python scripts/enrich_cves.py

train: ## Train LTR model
	@echo "Training LTR model..."
	@$(COMPOSE) run --rm api python scripts/train_ltr.py

cv: ## Run 5-fold cross-validation
	@echo "Running cross-validation..."
	@$(COMPOSE) run --rm api python scripts/cross_validation.py

ablation: ## Run ablation study (7 feature variants)
	@echo "Running ablation study..."
	@$(COMPOSE) run --rm api python scripts/analyze/ablation_study.py

temporal: ## Run temporal validation
	@echo "Running temporal validation..."
	@$(COMPOSE) run --rm api python scripts/temporal_validation.py

evaluate: ## Evaluate leakage-free performance
	@echo "Evaluating model..."
	@$(COMPOSE) run --rm api python scripts/evaluate_leakage_free.py

report: ## Generate evaluation report
	@echo "Generating report..."
	@$(COMPOSE) run --rm api python scripts/generate_report.py

# ==============================================================================
# DATABASE
# ==============================================================================

db-status: ## Check database status
	@$(COMPOSE) run --rm api python scripts/check_db_status.py

db-backup: ## Backup database to host
	@echo "Backing up database..."
	@docker cp cti-recommender-api:/app/data/cve_database.db ./backup_$$(date +%Y%m%d_%H%M%S).db
	@echo "✓ Backup complete"

db-shell: ## Open SQLite shell
	@$(COMPOSE) run --rm api sqlite3 /app/data/cve_database.db

# ==============================================================================
# CLEANUP
# ==============================================================================

clean: ## Clean up containers and volumes
	@echo "Cleaning up..."
	@$(COMPOSE) down -v
	@$(COMPOSE) -f docker-compose.dev.yml down -v 2>/dev/null || true
	@echo "✓ Cleanup complete"

clean-cache: ## Clean Python cache files
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✓ Python cache cleaned"

clean-all: clean clean-cache ## Clean everything including Docker images
	@docker system prune -a -f
	@echo "✓ Complete cleanup done"

# ==============================================================================
# QUICK START (for examiners/reviewers)
# ==============================================================================

demo: build ## Quick demo: build, start, test (for thesis examiners)
	@echo "=========================================="
	@echo "CTI Recommender - Quick Demo"
	@echo "=========================================="
	@echo ""
	@echo "[1/4] Building Docker image..."
	@$(COMPOSE) build
	@echo ""
	@echo "[2/4] Starting services..."
	@$(COMPOSE) up -d
	@sleep 3
	@echo ""
	@echo "[3/4] Running health check..."
	@curl -sf http://localhost:8000/health && echo "\n✓ API is healthy" || echo "✗ API failed"
	@echo ""
	@echo "[4/4] Running tests (99 tests)..."
	@$(COMPOSE) -f docker-compose.dev.yml run --rm test-runner \
		pytest tests/test_healthcare_mapper.py \
		       tests/test_cross_validation.py \
		       tests/test_ablation_study.py -v
	@echo ""
	@echo "=========================================="
	@echo "✓ Demo complete!"
	@echo "  API:    http://localhost:8000"
	@echo "  Docs:   http://localhost:8000/docs"
	@echo "  Logs:   make logs"
	@echo "=========================================="

install-deps: ## Install local development dependencies (optional)
	@pip install -r requirements.txt

# ==============================================================================
# ALIASES
# ==============================================================================

start: up ## Alias for 'up'
stop: down ## Alias for 'down'
tests: test ## Alias for 'test'
