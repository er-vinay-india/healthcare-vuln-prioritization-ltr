.PHONY: help build up down restart logs shell test test-fast enrich train cv ablation clean health jupyter stats

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "CTI Recommender - Makefile Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ==============================================================================
# BUILD & START
# ==============================================================================

build: ## Build Docker image
	@echo "Building Docker image..."
	@docker-compose build

up: build ## Start services (production mode)
	@echo "Starting services..."
	@docker-compose up -d
	@echo "✓ Services started at http://localhost:8000"

dev: build ## Start services (development mode with hot-reload)
	@echo "Starting development services..."
	@docker-compose -f docker-compose.dev.yml up -d api-dev
	@echo "✓ Development server started at http://localhost:8000"
	@echo "  (Source code mounted, auto-reload enabled)"

down: ## Stop all services
	@echo "Stopping services..."
	@docker-compose down
	@docker-compose -f docker-compose.dev.yml down 2>/dev/null || true
	@echo "✓ Services stopped"

restart: ## Restart services
	@docker-compose restart
	@echo "✓ Services restarted"

# ==============================================================================
# MONITORING
# ==============================================================================

logs: ## View logs (follows in real-time)
	@docker-compose logs -f api || docker-compose -f docker-compose.dev.yml logs -f api-dev

status: ## Check container status
	@echo "Container Status:"
	@docker-compose ps
	@docker-compose -f docker-compose.dev.yml ps 2>/dev/null || true

stats: ## Show resource usage
	@docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" \
		$$(docker ps --filter "name=cti-" --format "{{.Names}}")

health: ## Check API health
	@curl -sf http://localhost:8000/health && echo "\n✓ API is healthy" || echo "✗ API is not responding"

# ==============================================================================
# DEVELOPMENT
# ==============================================================================

shell: ## Open interactive shell in container
	@docker-compose exec api bash || docker-compose -f docker-compose.dev.yml exec api-dev bash

jupyter: ## Start Jupyter notebook server
	@echo "Starting Jupyter notebook..."
	@docker-compose -f docker-compose.dev.yml up -d jupyter
	@echo "✓ Jupyter available at http://localhost:8888"

# ==============================================================================
# TESTING
# ==============================================================================

test: ## Run all tests
	@echo "Running all tests..."
	@docker-compose -f docker-compose.dev.yml run --rm test-runner pytest tests/ -v --tb=short

test-fast: ## Run new tests only (99 tests, ~1 second)
	@echo "Running new tests (healthcare, CV, ablation)..."
	@docker-compose -f docker-compose.dev.yml run --rm test-runner \
		pytest tests/test_healthcare_mapper.py \
		       tests/test_cross_validation.py \
		       tests/test_ablation_study.py -v

test-metrics: ## Run evaluation metrics tests
	@docker-compose -f docker-compose.dev.yml run --rm test-runner \
		pytest tests/test_evaluation_metrics.py -v

test-coverage: ## Run tests with coverage report
	@docker-compose -f docker-compose.dev.yml run --rm test-runner \
		pytest tests/ --cov=src --cov-report=html --cov-report=term

# ==============================================================================
# SCRIPTS
# ==============================================================================

enrich: ## Run CVE enrichment with healthcare mapping
	@echo "Running CVE enrichment..."
	@docker-compose run --rm api python scripts/enrich_cves.py

train: ## Train LTR model
	@echo "Training LTR model..."
	@docker-compose run --rm api python scripts/train_ltr.py

cv: ## Run 5-fold cross-validation
	@echo "Running cross-validation..."
	@docker-compose run --rm api python scripts/cross_validation.py

ablation: ## Run ablation study (7 feature variants)
	@echo "Running ablation study..."
	@docker-compose run --rm api python scripts/analyze/ablation_study.py

temporal: ## Run temporal validation
	@echo "Running temporal validation..."
	@docker-compose run --rm api python scripts/temporal_validation.py

evaluate: ## Evaluate leakage-free performance
	@echo "Evaluating model..."
	@docker-compose run --rm api python scripts/evaluate_leakage_free.py

report: ## Generate evaluation report
	@echo "Generating report..."
	@docker-compose run --rm api python scripts/generate_report.py

# ==============================================================================
# DATABASE
# ==============================================================================

db-status: ## Check database status
	@docker-compose run --rm api python scripts/check_db_status.py

db-backup: ## Backup database to host
	@echo "Backing up database..."
	@docker cp cti-recommender-api:/app/data/cve_database.db ./backup_$$(date +%Y%m%d_%H%M%S).db
	@echo "✓ Backup complete"

db-shell: ## Open SQLite shell
	@docker-compose run --rm api sqlite3 /app/data/cve_database.db

# ==============================================================================
# CLEANUP
# ==============================================================================

clean: ## Clean up containers and volumes
	@echo "Cleaning up..."
	@docker-compose down -v
	@docker-compose -f docker-compose.dev.yml down -v 2>/dev/null || true
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
	@docker-compose build
	@echo ""
	@echo "[2/4] Starting services..."
	@docker-compose up -d
	@sleep 3
	@echo ""
	@echo "[3/4] Running health check..."
	@curl -sf http://localhost:8000/health && echo "\n✓ API is healthy" || echo "✗ API failed"
	@echo ""
	@echo "[4/4] Running tests (99 tests)..."
	@docker-compose -f docker-compose.dev.yml run --rm test-runner \
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
