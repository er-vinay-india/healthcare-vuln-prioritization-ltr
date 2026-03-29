# 🐳 Docker Quick Start

**Get the CTI Recommender running in 5 minutes**

---

## Option 1: Using Makefile (Easiest)

```bash
# One command to build, start, and test:
make demo

# Or step by step:
make build        # Build image
make up           # Start services
make health       # Check if working
make test-fast    # Run 99 tests (~1 second)
```

**Available commands:** `make help`

---

## Option 2: Using Helper Script

```bash
# Make script executable
chmod +x docker-run.sh

# Build and start
./docker-run.sh build
./docker-run.sh start

# Check health
./docker-run.sh health

# Run tests
./docker-run.sh test-fast
```

**All commands:** `./docker-run.sh help`

---

## Option 3: Using Docker Compose Directly

```bash
# Build
docker-compose build

# Start
docker-compose up -d

# Check health
curl http://localhost:8000/health

# Run tests
docker-compose -f docker-compose.dev.yml run --rm test-runner \
    pytest tests/test_healthcare_mapper.py \
           tests/test_cross_validation.py \
           tests/test_ablation_study.py -v
```

---

## Verify Everything Works

```bash
# 1. API is running
curl http://localhost:8000/health
# Should return: {"status":"healthy"}

# 2. Run tests
make test-fast
# Should show: 99 passed in ~0.76s

# 3. Check database
make db-status
# Should show: 226,320 CVEs
```

---

## Common Tasks

```bash
# Development mode (hot-reload)
make dev
make logs

# Run scripts
make enrich       # Enrich CVEs with healthcare mapping
make train        # Train LTR model
make cv           # Cross-validation
make ablation     # Ablation study

# Jupyter notebooks
make jupyter
# Access at: http://localhost:8888

# Database backup
make db-backup

# View logs
make logs

# Stop everything
make down
```

---

**Complete validation in one command:**

```bash
make demo
```

This will:
1. ✅ Build the Docker image
2. ✅ Start the API server
3. ✅ Verify health check passes
4. ✅ Run 99 tests (healthcare mapper, cross-validation, ablation study)

**Expected output:** All tests passing, API healthy

---

## Troubleshooting

**Port 8000 already in use:**
```bash
# Find and kill process
lsof -ti:8000 | xargs kill -9
```

**Need to rebuild from scratch:**
```bash
make clean
make build
make up
```

**Container won't start:**
```bash
make logs  # Check error messages
```

---

## File Structure

```
.
├── Dockerfile                  # Production build
├── docker-compose.yml          # Production config
├── docker-compose.dev.yml      # Development config
├── Makefile                    # Quick commands
├── docker-run.sh               # Helper script
├── DOCKER_GUIDE.md             # Full documentation
└── QUICKSTART_DOCKER.md        # This file
```

---

## Next Steps

- **Full documentation:** See [DOCKER_GUIDE.md](DOCKER_GUIDE.md)
- **API docs:** http://localhost:8000/docs (after starting)
- **Development:** See [DEVELOPMENT.md](docs/DEVELOPMENT.md)
- **General docs:** See [README.md](README.md)

---

**Questions?** Check `make help` or `./docker-run.sh help`
