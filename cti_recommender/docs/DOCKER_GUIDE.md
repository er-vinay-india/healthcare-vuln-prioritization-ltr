# Docker Guide

**Last Updated:** March 2026

Use this if you want to run the project through Docker instead of a local Python environment.

## Quick Start

```bash
docker-compose build
docker-compose up -d
curl http://localhost:8000/health
```

If the repository Makefile is preferred:

```bash
make build
make up
make health
```

## Useful Commands

### View status and logs

```bash
docker-compose ps
docker-compose logs -f api
```

### Stop services

```bash
docker-compose down
```

### Run tests

```bash
docker-compose -f docker-compose.dev.yml run --rm test-runner
```

### Run a script inside Docker

```bash
docker-compose run --rm api python scripts/data/enrich_cves.py
docker-compose run --rm api python scripts/training/train_ltr.py
```

## Development Mode

```bash
docker-compose -f docker-compose.dev.yml up -d
docker-compose -f docker-compose.dev.yml logs -f api-dev
```

## Common Issues

### Container does not start

```bash
docker-compose logs api
docker-compose build --no-cache
docker-compose up -d
```

### Port 8000 already in use

```bash
lsof -ti:8000 | xargs kill -9
```

### Database locked

```bash
docker-compose down
rm -f data/*.db-journal data/*.db-wal
docker-compose up -d
```

### Out of disk space

```bash
docker image prune -a
docker volume prune
```

## When To Read Other Docs

- `QUICKSTART.md` for local non-Docker setup
- `DEVELOPMENT.md` for code changes
- `ARCHITECTURE.md` for system structure

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
