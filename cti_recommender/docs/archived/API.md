# CTI Recommender - Deployment & Development Guide

## Quick Start (Docker)

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 10GB disk space

### 1. Setup Environment

```bash
# Clone repository
git clone <repository-url>
cd cti_recommender

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Build and Run

```bash
# Build Docker image
docker-compose build

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f api

# Verify health
curl http://localhost:8000/health
```

### 3. Access API

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

##  Installation (Development)

### Local Setup

```bash
# Create virtual environment
python3.14 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup configuration
cp .env.example .env

# Install package in editable mode
pip install -e .
```

### Install New Dependencies

```bash
# Update requirements.txt first, then:
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Configuration

### Environment Variables

Key settings in `.env`:

```bash
# API Keys
NVD_API_KEY=your_key_here

# Logging
LOG_LEVEL=INFO
STRUCTURED_LOGGING=true

# Model
USE_PRUNED_MODEL=true

# Database
DATABASE_PATH=data/cve_database.db
```

### Volumes

Docker volumes for persistence:
- `./data` - CVE database
- `./models` - Trained ML models
- `./logs` - Application logs
- `./cache` - API response cache (organized by source)

## [TEST] Testing

### Run Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=src --cov-report=html

# Specific test file
pytest tests/test_api.py -v

# Docker environment
docker-compose exec api pytest
```

### Manual API Testing

```bash
# Get recommendations
curl -X POST http://localhost:8000/api/v1/recommendations \
  -H "Content-Type: application/json" \
  -d '{"limit": 20, "healthcare_only": true}'

# Get CVE details
curl http://localhost:8000/api/v1/cve/CVE-2024-1234

# Get statistics
curl http://localhost:8000/api/v1/stats
```

## Monitoring

### Logs

```bash
# View API logs
docker-compose logs -f api

# Search logs
docker-compose logs api | grep ERROR

# Export logs
docker-compose logs api > api.log
```

### Health Checks

```bash
# Docker health status
docker ps

# API health endpoint
curl http://localhost:8000/health | jq

# Database check
docker-compose exec api sqlite3 data/cve_database.db "SELECT COUNT(*) FROM cves;"
```

## Data Pipeline

### Refresh CVE Database

```bash
# Run in Docker
docker-compose exec api python scripts/data/refresh_cves.py

# Or locally
python scripts/data/refresh_cves.py
```

### Enrich CVEs

```bash
# Full enrichment
docker-compose exec api python scripts/data/enrich_cves.py

# Validation only
docker-compose exec api python scripts/data/enrich_cves.py --validate-only
```

### Retrain Model

```bash
# Train pruned model
docker-compose exec api python scripts/train_ltr_pruned.py

# Temporal validation
docker-compose exec api python scripts/temporal_validation_pruned.py
```

##  Troubleshooting

### Common Issues

**1. Port Already in Use**
```bash
# Change port in docker-compose.yml or .env
ports:
  - "8080:8000"  # Use 8080 instead
```

**2. Database Locked**
```bash
# Stop all containers
docker-compose down

# Remove stale locks
rm data/*.db-shm data/*.db-wal

# Restart
docker-compose up -d
```

**3. Out of Memory**
```bash
# Increase Docker memory limit
# Docker Desktop > Settings > Resources > Memory: 4GB+
```

**4. Model Not Found**
```bash
# Check model files exist
ls -lh models/

# Retrain if missing
python scripts/train_ltr_pruned.py
```

### Debug Mode

```bash
# Enable debug logging
echo "LOG_LEVEL=DEBUG" >> .env

# Restart with debug
docker-compose down
docker-compose up

# Check detailed logs
docker-compose logs -f api
```

## Production Deployment

### Performance Tuning

```yaml
# docker-compose.yml
services:
  api:
    environment:
      - API_WORKERS=4  # CPU cores
      - STRUCTURED_LOGGING=true
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
```

### Reverse Proxy (Nginx)

```nginx
# nginx.conf
upstream cti_api {
    server api:8000;
}

server {
    listen 80;
    server_name cti.example.com;

    location / {
        proxy_pass http://cti_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### SSL/TLS

```bash
# Generate certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout ssl/key.pem -out ssl/cert.pem -days 365

# Update nginx.conf for HTTPS
```

## API Documentation

Once running, visit:
- **Interactive Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

##  Security

### Best Practices

1. **Never commit .env file**
2. **Use secrets management in production**
3. **Enable HTTPS in production**
4. **Regularly update dependencies**
5. **Run as non-root user** (already configured)
6. **Implement rate limiting**
7. **Monitor for security updates**

### Dependency Updates

```bash
# Check outdated packages
pip list --outdated

# Update specific package
pip install --upgrade xgboost

# Update all (carefully)
pip install --upgrade -r requirements.txt
```

##  Support

For issues:
1. Check logs: `docker-compose logs -f`
2. Verify configuration: `.env` file
3. Review documentation
4. Open GitHub issue

##  License

[Your License Here]
