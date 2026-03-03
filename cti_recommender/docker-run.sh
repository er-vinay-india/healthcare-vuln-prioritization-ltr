#!/bin/bash
# Docker Helper Script - CTI Recommender
# Simplifies common Docker operations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Help message
show_help() {
    cat << EOF
CTI Recommender - Docker Helper Script

USAGE:
    ./docker-run.sh [COMMAND] [OPTIONS]

COMMANDS:
    build           Build Docker image
    start           Start services (production)
    start-dev       Start services (development mode with hot-reload)
    stop            Stop all services
    restart         Restart services
    logs            View logs (default: follow mode)
    status          Check container status
    shell           Open interactive shell in container
    test            Run all tests
    test-fast       Run new tests only (99 tests)
    enrich          Run CVE enrichment script
    train           Train LTR model
    cv              Run cross-validation
    ablation        Run ablation study
    clean           Clean up containers and volumes
    clean-all       Clean everything including images
    backup-db       Backup database
    jupyter         Start Jupyter notebook server
    health          Check API health
    stats           Show resource usage

EXAMPLES:
    ./docker-run.sh build          # Build image
    ./docker-run.sh start-dev      # Start in dev mode
    ./docker-run.sh test-fast      # Run 99 new tests
    ./docker-run.sh logs           # Follow logs
    ./docker-run.sh shell          # Interactive bash
    ./docker-run.sh enrich         # Enrich CVEs
    ./docker-run.sh health         # Check if API is healthy

EOF
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
}

# Build image
build() {
    print_info "Building Docker image..."
    docker-compose build
    print_success "Build complete!"
}

# Start services (production)
start() {
    print_info "Starting services in production mode..."
    docker-compose up -d
    print_success "Services started!"
    print_info "API available at: http://localhost:8000"
    print_info "Check status with: ./docker-run.sh status"
}

# Start services (development)
start_dev() {
    print_info "Starting services in development mode..."
    docker-compose -f docker-compose.dev.yml up -d api-dev
    print_success "Development services started!"
    print_info "API available at: http://localhost:8000 (with hot-reload)"
    print_info "View logs with: ./docker-run.sh logs"
}

# Stop services
stop() {
    print_info "Stopping services..."
    docker-compose down
    docker-compose -f docker-compose.dev.yml down 2>/dev/null || true
    print_success "Services stopped!"
}

# Restart services
restart() {
    print_info "Restarting services..."
    docker-compose restart
    print_success "Services restarted!"
}

# View logs
logs() {
    print_info "Showing logs (Ctrl+C to exit)..."
    if docker ps | grep -q cti-recommender-dev; then
        docker-compose -f docker-compose.dev.yml logs -f api-dev
    else
        docker-compose logs -f api
    fi
}

# Check status
status() {
    echo "Container Status:"
    docker-compose ps
    echo ""
    docker-compose -f docker-compose.dev.yml ps 2>/dev/null || true
}

# Interactive shell
shell() {
    print_info "Opening interactive shell..."
    if docker ps | grep -q cti-recommender-api; then
        docker-compose exec api bash
    elif docker ps | grep -q cti-recommender-dev; then
        docker-compose -f docker-compose.dev.yml exec api-dev bash
    else
        print_error "No running container found. Start services first."
        exit 1
    fi
}

# Run all tests
test_all() {
    print_info "Running all tests..."
    docker-compose -f docker-compose.dev.yml run --rm test-runner pytest tests/ -v --tb=short
}

# Run new tests only (fast)
test_fast() {
    print_info "Running new tests (99 tests)..."
    docker-compose -f docker-compose.dev.yml run --rm test-runner \
        pytest tests/test_healthcare_mapper.py \
               tests/test_cross_validation.py \
               tests/test_ablation_study.py -v
}

# Run enrichment
enrich() {
    print_info "Running CVE enrichment..."
    docker-compose run --rm api python scripts/enrich_cves.py
    print_success "Enrichment complete!"
}

# Train model
train() {
    print_info "Training LTR model..."
    docker-compose run --rm api python scripts/train_ltr.py
    print_success "Training complete!"
}

# Cross-validation
cv() {
    print_info "Running cross-validation..."
    docker-compose run --rm api python scripts/cross_validation.py
    print_success "Cross-validation complete!"
}

# Ablation study
ablation() {
    print_info "Running ablation study..."
    docker-compose run --rm api python scripts/analyze/ablation_study.py
    print_success "Ablation study complete!"
}

# Clean up
clean() {
    print_info "Cleaning up containers and volumes..."
    docker-compose down -v
    docker-compose -f docker-compose.dev.yml down -v 2>/dev/null || true
    print_success "Cleanup complete!"
}

# Clean everything
clean_all() {
    print_info "WARNING: This will remove all Docker images, containers, and volumes!"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        docker-compose down -v
        docker-compose -f docker-compose.dev.yml down -v 2>/dev/null || true
        docker system prune -a -f
        print_success "Complete cleanup done!"
    else
        print_info "Cleanup cancelled."
    fi
}

# Backup database
backup_db() {
    print_info "Backing up database..."
    backup_file="backup_$(date +%Y%m%d_%H%M%S).db"
    
    if docker ps | grep -q cti-recommender; then
        docker cp cti-recommender-api:/app/data/cve_database.db "./$backup_file"
        print_success "Database backed up to: $backup_file"
    else
        print_error "Container not running. Start services first."
        exit 1
    fi
}

# Start Jupyter
jupyter() {
    print_info "Starting Jupyter notebook server..."
    docker-compose -f docker-compose.dev.yml up -d jupyter
    print_success "Jupyter started!"
    print_info "Access at: http://localhost:8888"
}

# Health check
health() {
    print_info "Checking API health..."
    if curl -sf http://localhost:8000/health > /dev/null; then
        response=$(curl -s http://localhost:8000/health)
        print_success "API is healthy: $response"
    else
        print_error "API is not responding"
        exit 1
    fi
}

# Resource stats
stats() {
    print_info "Container resource usage:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" \
        $(docker ps --filter "name=cti-" --format "{{.Names}}")
}

# Main script
main() {
    check_docker
    
    case "$1" in
        build)
            build
            ;;
        start)
            start
            ;;
        start-dev)
            start_dev
            ;;
        stop)
            stop
            ;;
        restart)
            restart
            ;;
        logs)
            logs
            ;;
        status)
            status
            ;;
        shell)
            shell
            ;;
        test)
            test_all
            ;;
        test-fast)
            test_fast
            ;;
        enrich)
            enrich
            ;;
        train)
            train
            ;;
        cv)
            cv
            ;;
        ablation)
            ablation
            ;;
        clean)
            clean
            ;;
        clean-all)
            clean_all
            ;;
        backup-db)
            backup_db
            ;;
        jupyter)
            jupyter
            ;;
        health)
            health
            ;;
        stats)
            stats
            ;;
        help|--help|-h)
            show_help
            ;;
        "")
            print_error "No command specified"
            echo ""
            show_help
            exit 1
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
