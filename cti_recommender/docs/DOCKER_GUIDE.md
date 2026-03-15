# Docker Setup Guide - CTI Recommender

**Complete guide for running the CTI Recommender system in Docker**

---

## 📦 Quick Start (5 Minutes)

### Command Shortcuts (Recommended)

Use the project shortcuts for the fastest bootstrap:

```bash
# Full demo run (build + start + validation)
make demo

# Or step-by-step
make build
make up
make health
make test-fast
```

You can also use the helper script:

```bash
chmod +x docker-run.sh
./docker-run.sh build
./docker-run.sh start
./docker-run.sh health
./docker-run.sh test-fast
```

For available commands:

```bash
make help
./docker-run.sh help
```

### 1. Prerequisites

Ensure you have Docker installed:
```bash
docker --version  # Should be 20.10+
docker-compose --version  # Should be 2.0+
```

**Install Docker:**
- **macOS/Windows:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- **Linux:** 
  ```bash
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  ```

### 2. Build & Run (Production)

```bash
# Build the image
docker-compose build

# Start the service
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f api
```

**Access the API:** http://localhost:8000

**Verify it's working:**
```bash
curl http://localhost:8000/health
# Should return: {"status":"healthy"}
```

### 3. Stop Services

```bash
# Stop containers
docker-compose down

# Stop and remove volumes (⚠️ deletes data)
docker-compose down -v
```

---

## 🛠️ Development Mode

For active development with hot-reload:

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# View logs in real-time
docker-compose -f docker-compose.dev.yml logs -f api-dev

# Stop development environment
docker-compose -f docker-compose.dev.yml down
```

**Features:**
- ✅ Auto-reload on code changes
- ✅ Debug logging enabled
- ✅ Source code mounted as volumes
- ✅ Jupyter notebook available on port 8888

---

## 🧪 Running Tests in Docker

### Option 1: One-time Test Run

```bash
docker-compose -f docker-compose.dev.yml run --rm test-runner
```

### Option 2: Interactive Testing

```bash
# Start a test shell
docker-compose -f docker-compose.dev.yml run --rm test-runner bash

# Inside container:
pytest tests/test_healthcare_mapper.py -v
pytest tests/test_evaluation_metrics.py -v
pytest tests/ -v --tb=short  # All tests
```

### Option 3: Test Specific Files

```bash
# Healthcare mapper tests (59 tests)
docker-compose -f docker-compose.dev.yml run --rm test-runner \
    pytest tests/test_healthcare_mapper.py -v

# Evaluation metrics tests (31 tests)
docker-compose -f docker-compose.dev.yml run --rm test-runner \
    pytest tests/test_evaluation_metrics.py -v

# Cross-validation tests (16 tests)
docker-compose -f docker-compose.dev.yml run --rm test-runner \
    pytest tests/test_cross_validation.py -v

# All new tests (99 tests)
docker-compose -f docker-compose.dev.yml run --rm test-runner \
    pytest tests/test_healthcare_mapper.py \
           tests/test_cross_validation.py \
           tests/test_ablation_study.py -v
```

---

## 📊 Running Scripts in Docker

### Data Enrichment

```bash
# Enrich CVEs with healthcare mapping
docker-compose run --rm api python scripts/data/enrich_cves.py

# Check database status
docker-compose run --rm api python scripts/ops/check_db_status.py
```

### Model Training

```bash
# Train LTR model
docker-compose run --rm api python scripts/training/train_ltr.py

# Run cross-validation
docker-compose run --rm api python scripts/training/cross_validation.py

# Run ablation study
docker-compose run --rm api python scripts/analyze/ablation_study.py
```

### Evaluation

```bash
# Evaluate leakage-free performance
docker-compose run --rm api python scripts/evaluation/evaluate_leakage_free.py

# Temporal validation
docker-compose run --rm api python scripts/training/temporal_validation.py

# Generate report
docker-compose run --rm api python scripts/evaluation/generate_report.py
```

---

## 📓 Jupyter Notebooks in Docker

### Start Jupyter Server

```bash
docker-compose -f docker-compose.dev.yml up jupyter
```

**Access Jupyter:** http://localhost:8888

**Available notebooks:**
- `Model_Training_And_Evaluation.ipynb`
- `Advanced_Models_GraphBased.ipynb`
- `CVE_Prioritization_Final.ipynb`
- `Feature_Engineering.ipynb`
- `EDA_Analysis.ipynb`

---

## 🗄️ Database Access

### Connect to SQLite Database

```bash
# Interactive SQL shell
docker-compose run --rm api sqlite3 /app/data/cve_database.db

# Example queries:
.tables
SELECT COUNT(*) FROM cves;
SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1;
.quit
```

### Backup Database

```bash
# Backup to host
docker-compose run --rm api sqlite3 /app/data/cve_database.db ".backup /app/data/backup.db"

# Copy from container
docker cp cti-recommender-api:/app/data/cve_database.db ./backup_$(date +%Y%m%d).db
```

### Restore Database

```bash
# Copy backup into container
docker cp ./backup.db cti-recommender-api:/app/data/cve_database.db

# Restart service
docker-compose restart api
```

---

## 🔧 Troubleshooting

### Issue: Container won't start

**Check logs:**
```bash
docker-compose logs api
```

**Common fixes:**
```bash
# Rebuild from scratch
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Issue: Port 8000 already in use

```bash
lsof -ti:8000 | xargs kill -9
```

### Issue: Permission denied errors

**Fix ownership:**
```bash
# On host machine
sudo chown -R $(whoami):$(whoami) data/ logs/ models/ cache/
```

### Issue: Database locked

**Solution:**
```bash
# Stop all containers
docker-compose down

# Remove stale lock files
rm -f data/*.db-journal data/*.db-wal

# Restart
docker-compose up -d
```

### Issue: Port already in use

**Find and kill process:**
```bash
# Find process using port 8000
lsof -ti:8000 | xargs kill -9

# Or change port in docker-compose.yml
# ports:
#   - "8001:8000"  # Changed from 8000:8000
```

### Issue: Out of disk space

**Clean up Docker:**
```bash
# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Full cleanup (⚠️ removes everything)
docker system prune -a --volumes
```

---

## 🚀 Production Deployment

### Using docker-compose (recommended)

```bash
# Build production image
docker-compose build

# Start in detached mode
docker-compose up -d

# View logs
docker-compose logs -f api

# Scale (if needed)
docker-compose up -d --scale api=3
```

### Using Docker directly

```bash
# Build image
docker build -t cti-recommender:latest .

# Run container
docker run -d \
  --name cti-recommender \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/models:/app/models \
  -v $(pwd)/logs:/app/logs \
  -e LOG_LEVEL=INFO \
  cti-recommender:latest

# Check logs
docker logs -f cti-recommender
```

### Environment Variables

Create `.env` file:
```env
LOG_LEVEL=INFO
DATABASE_PATH=/app/data/cve_database.db
API_HOST=0.0.0.0
API_PORT=8000
STRUCTURED_LOGGING=true
```

Use it:
```bash
docker-compose --env-file .env up -d
```

---

## 📝 Common Tasks Cheat Sheet

```bash
# ============================================================================
# BUILD & START
# ============================================================================
docker-compose build                          # Build image
docker-compose up -d                          # Start (production)
docker-compose -f docker-compose.dev.yml up  # Start (development)

# ============================================================================
# MONITORING
# ============================================================================
docker-compose ps                             # List containers
docker-compose logs -f api                    # Follow logs
docker-compose top                            # Show running processes
docker stats cti-recommender-api              # Resource usage

# ============================================================================
# TESTING
# ============================================================================
docker-compose run --rm test-runner          # Run all tests
docker-compose run --rm test-runner bash     # Interactive test shell

# ============================================================================
# SCRIPTS
# ============================================================================
docker-compose run --rm api python scripts/data/enrich_cves.py
docker-compose run --rm api python scripts/training/train_ltr.py
docker-compose run --rm api python scripts/training/cross_validation.py

# ============================================================================
# DATABASE
# ============================================================================
docker-compose run --rm api sqlite3 /app/data/cve_database.db
docker cp cti-recommender-api:/app/data/cve_database.db ./backup.db

# ============================================================================
# CLEANUP
# ============================================================================
docker-compose down                          # Stop containers
docker-compose down -v                       # Stop + remove volumes
docker system prune -a                       # Clean everything
```

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  Docker Host                        │
│                                                     │
│  ┌───────────────────────────────────────────┐     │
│  │         cti-recommender-api               │     │
│  │                                           │     │
│  │  Port 8000 → FastAPI Server              │     │
│  │  - src/api/main.py                       │     │
│  │  - Health checks every 30s               │     │
│  │  - Auto-restart on failure               │     │
│  │                                           │     │
│  │  Mounted Volumes:                        │     │
│  │  ├─ data/   (SQLite database)           │     │
│  │  ├─ models/ (Trained models)            │     │
│  │  ├─ logs/   (Application logs)          │     │
│  │  └─ cache/  (API responses)             │     │
│  └───────────────────────────────────────────┘     │
│                                                     │
│  ┌───────────────────────────────────────────┐     │
│  │         cti-jupyter (dev only)            │     │
│  │                                           │     │
│  │  Port 8888 → Jupyter Lab                 │     │
│  │  - Interactive notebooks                 │     │
│  │  - Data exploration                      │     │
│  └───────────────────────────────────────────┘     │
│                                                     │
│  ┌───────────────────────────────────────────┐     │
│  │      test-runner (on-demand)              │     │
│  │                                           │     │
│  │  Runs pytest suite:                      │     │
│  │  - 99 new tests (HealthcareMapper, CV)  │     │
│  │  - 31 evaluation metric tests            │     │
│  │  - Full integration tests                │     │
│  └───────────────────────────────────────────┘     │
│                                                     │
│  Network: cti-network (bridge)                     │
└─────────────────────────────────────────────────────┘
```

---

## 📚 File Structure

```
cti_recommender/
├── Dockerfile                 # Multi-stage production build
├── docker-compose.yml         # Production configuration
├── docker-compose.dev.yml     # Development with hot-reload
├── .dockerignore              # Files excluded from build
├── requirements.txt           # Python dependencies
│
├── src/                       # Application code (mounted in dev)
├── tests/                     # Test suite (99+ tests)
├── scripts/                   # Utility scripts
├── notebooks/                 # Jupyter notebooks
│
└── data/                      # Persisted data (volume)
    ├── cve_database.db        # SQLite database
    ├── config/                # Configuration files
    └── healthcare_breaches.json
```

---

## 🎓 For Thesis Examiners

**To run the complete system:**

```bash
# 1. Clone repository
git clone <repo-url>
cd cti_recommender

# 2. Build Docker image
docker-compose build

# 3. Start services
docker-compose up -d

# 4. Verify API is running
curl http://localhost:8000/health

# 5. Run all tests (99 tests, ~1 second)
docker-compose run --rm test-runner pytest tests/test_healthcare_mapper.py \
    tests/test_cross_validation.py tests/test_ablation_study.py -v

# 6. View results
docker-compose logs api
```

**Expected output:**
- API: `{"status": "healthy"}` at http://localhost:8000/health
- Tests: `99 passed in 0.76s` ✅
- Database: 226,320 CVEs with healthcare enrichments

---

## 🔐 Security Notes

1. **Non-root user:** Container runs as `appuser` (UID 1000)
2. **Read-only source in production:** Code is copied, not mounted
3. **Health checks:** Automatic restart on failure
4. **No secrets in image:** Use environment variables or Docker secrets

---

## 📊 Resource Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 4 GB
- Disk: 10 GB

**Recommended (for training):**
- CPU: 4+ cores
- RAM: 8+ GB
- Disk: 20 GB

**Check resource usage:**
```bash
docker stats cti-recommender-api
```

---

## 🆘 Getting Help

**Check logs:**
```bash
docker-compose logs -f api
```

**Interactive debugging:**
```bash
docker-compose run --rm api bash
# Inside container:
python scripts/ops/check_db_status.py
pytest tests/ -v
```

**Restart from scratch:**
```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

---

## ✅ Verification Checklist

- [ ] Docker and Docker Compose installed
- [ ] `.dockerignore` file exists
- [ ] `docker-compose build` completes without errors
- [ ] `docker-compose up -d` starts container
- [ ] `curl http://localhost:8000/health` returns `{"status":"healthy"}`
- [ ] `docker-compose run --rm test-runner` shows 99 tests passing
- [ ] Database accessible at `data/cve_database.db`
- [ ] Logs visible in `logs/` directory

---

**Last Updated:** March 1, 2026  
**Docker Version:** 24.0+  
**Python Version:** 3.14  
**Test Coverage:** 99 tests, 100% passing ✅
