# Deployment Guide

Complete guide for deploying the CVE Prioritization API.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Deployment](#docker-deployment)
3. [Production Deployment](#production-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Monitoring & Maintenance](#monitoring--maintenance)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 2GB RAM minimum
- 5GB disk space

### 1. Build and Run

```bash
# Clone repository
git clone <repository-url>
cd cti_recommender

# Ensure database and model exist
ls data/cve_database.db
ls models/ltr_model_conf_weighted.pkl

# Build and start
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f api

# Test
curl http://localhost:8000/health
```

### 2. Stop and Clean Up

```bash
# Stop services
docker-compose down

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

---

## Docker Deployment

### Build Docker Image

```bash
# Build image
docker build -t cve-recommender:latest .

# Check image size
docker images | grep cve-recommender

# Run container
docker run -d \
  --name cve-api \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/models:/app/models \
  -e LOG_LEVEL=INFO \
  cve-recommender:latest

# View logs
docker logs -f cve-api

# Stop container
docker stop cve-api
docker rm cve-api
```

### Docker Compose (Recommended)

```bash
# Start services
docker-compose up -d

# Scale API workers
docker-compose up -d --scale api=3

# View logs
docker-compose logs -f api

# Restart service
docker-compose restart api

# Update and restart
docker-compose pull
docker-compose up -d
```

### Environment Variables

Create `.env` file:

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
API_RELOAD=false

# Database
DATABASE_PATH=/app/data/cve_database.db

# Model
MODEL_PATH=/app/models/ltr_model_conf_weighted.pkl

# Logging
LOG_LEVEL=INFO
STRUCTURED_LOGGING=true

# Optional: Authentication
API_KEY_ENABLED=false
API_KEY_SECRET=your-secret-key-here
```

Use with docker-compose:

```bash
docker-compose --env-file .env up -d
```

---

## Production Deployment

### 1. Optimize Docker Image

**Multi-stage build** (already configured):
- Builder stage: 1.2GB
- Runtime stage: 500MB
- Final image: ~600MB

**Further optimization:**

```dockerfile
# Use Alpine for smaller size (optional)
FROM python:3.14-alpine

# Or use distroless for security
FROM gcr.io/distroless/python3:latest
```

### 2. Security Hardening

**a) Run as non-root user** (already configured):

```dockerfile
USER appuser
```

**b) Add security scanning:**

```bash
# Scan for vulnerabilities
docker scan cve-recommender:latest

# Use Trivy
trivy image cve-recommender:latest
```

**c) Enable TLS:**

```yaml
# docker-compose.yml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./ssl/cert.pem:/etc/nginx/ssl/cert.pem
      - ./ssl/key.pem:/etc/nginx/ssl/key.pem
      - ./nginx.conf:/etc/nginx/nginx.conf
```

**nginx.conf:**

```nginx
server {
    listen 443 ssl;
    server_name api.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    location / {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. High Availability Setup

**Load balancing with multiple workers:**

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  api:
    image: cve-recommender:latest
    deploy:
      replicas: 4
      restart_policy:
        condition: on-failure
        max_attempts: 3
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
```

**Deploy:**

```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 4. Database Optimization

**Use PostgreSQL for production** (optional upgrade from SQLite):

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: cve_db
      POSTGRES_USER: cve_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    
  api:
    depends_on:
      - postgres
    environment:
      DATABASE_URL: postgresql://cve_user:${DB_PASSWORD}@postgres:5432/cve_db

volumes:
  postgres_data:
```

---

## Kubernetes Deployment

### 1. Create Kubernetes Manifests

**deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cve-recommender
  labels:
    app: cve-recommender
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cve-recommender
  template:
    metadata:
      labels:
        app: cve-recommender
    spec:
      containers:
      - name: api
        image: cve-recommender:latest
        ports:
        - containerPort: 8000
        env:
        - name: API_WORKERS
          value: "4"
        - name: LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: data
          mountPath: /app/data
        - name: models
          mountPath: /app/models
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: cve-data-pvc
      - name: models
        persistentVolumeClaim:
          claimName: cve-models-pvc
```

**service.yaml:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: cve-recommender-service
spec:
  selector:
    app: cve-recommender
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
```

**ingress.yaml:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cve-recommender-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: cve-api-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: cve-recommender-service
            port:
              number: 80
```

### 2. Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace cve-recommender

# Apply manifests
kubectl apply -f k8s/deployment.yaml -n cve-recommender
kubectl apply -f k8s/service.yaml -n cve-recommender
kubectl apply -f k8s/ingress.yaml -n cve-recommender

# Check status
kubectl get pods -n cve-recommender
kubectl get svc -n cve-recommender
kubectl logs -f deployment/cve-recommender -n cve-recommender

# Scale deployment
kubectl scale deployment/cve-recommender --replicas=5 -n cve-recommender
```

---

## Monitoring & Maintenance

### 1. Health Checks

```bash
# Docker
curl http://localhost:8000/health

# Kubernetes
kubectl exec -it <pod-name> -- curl localhost:8000/health
```

### 2. Log Management

**Docker logs:**

```bash
# View logs
docker-compose logs -f api

# Export logs
docker-compose logs api > api-logs.txt

# Log rotation (in docker-compose.yml)
services:
  api:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

**Centralized logging with ELK:**

```yaml
services:
  elasticsearch:
    image: elasticsearch:8.5.0
  
  logstash:
    image: logstash:8.5.0
    
  kibana:
    image: kibana:8.5.0
    ports:
      - "5601:5601"
```

### 3. Metrics & Monitoring

**Prometheus + Grafana:**

```yaml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
  
  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

**prometheus.yml:**

```yaml
scrape_configs:
  - job_name: 'cve-api'
    static_configs:
      - targets: ['api:8000']
```

### 4. Backup Strategy

**Database backup:**

```bash
# Backup SQLite database
docker exec cti-recommender-api sqlite3 /app/data/cve_database.db ".backup '/app/data/backup.db'"

# Copy backup out
docker cp cti-recommender-api:/app/data/backup.db ./backups/cve_db_$(date +%Y%m%d).db

# Automated daily backups
crontab -e
# Add: 0 2 * * * /path/to/backup-script.sh
```

**backup-script.sh:**

```bash
#!/bin/bash
BACKUP_DIR="/backups/cve_db"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup
docker exec cti-recommender-api sqlite3 /app/data/cve_database.db ".backup '/tmp/backup.db'"
docker cp cti-recommender-api:/tmp/backup.db $BACKUP_DIR/cve_db_$DATE.db

# Compress
gzip $BACKUP_DIR/cve_db_$DATE.db

# Remove old backups (keep last 30 days)
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete
```

### 5. Updates & Rollbacks

```bash
# Update to new version
docker pull cve-recommender:v2.0
docker-compose up -d

# Rollback if needed
docker-compose down
docker tag cve-recommender:v1.0 cve-recommender:latest
docker-compose up -d
```

---

## Troubleshooting

### Common Issues

#### 1. Container Won't Start

```bash
# Check logs
docker-compose logs api

# Common causes:
# - Missing database file
# - Missing model file
# - Port already in use

# Solutions:
# 1. Verify files exist
ls data/cve_database.db models/ltr_model_conf_weighted.pkl

# 2. Check port availability
lsof -i :8000

# 3. Check permissions
docker-compose exec api ls -la /app/data
```

#### 2. API Returns 500 Errors

```bash
# Check logs for stack traces
docker-compose logs -f api | grep ERROR

# Common causes:
# - Database connection failed
# - Model loading failed
# - Feature engineering error

# Debug inside container
docker-compose exec api bash
python -c "from src.api.main import app; print('OK')"
```

#### 3. Slow Performance

```bash
# Check resource usage
docker stats cti-recommender-api

# Increase workers
# In docker-compose.yml:
environment:
  - API_WORKERS=8

# Or scale containers
docker-compose up -d --scale api=4
```

#### 4. Database Locked

```bash
# SQLite is single-writer
# Solution: Use PostgreSQL for production
# Or reduce concurrent requests
```

### Performance Tuning

**1. Optimize workers:**

```python
# Rule of thumb: workers = (2 × CPU cores) + 1
workers = (2 * 4) + 1  # 9 workers for 4 cores
```

**2. Add Redis caching:**

```yaml
services:
  redis:
    image: redis:alpine
    
  api:
    depends_on:
      - redis
    environment:
      - REDIS_URL=redis://redis:6379
```

**3. Use gunicorn with uvicorn workers:**

```bash
CMD ["gunicorn", "src.api.main:app", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000"]
```

---

## CI/CD Pipeline

### GitHub Actions Example

**.github/workflows/deploy.yml:**

```yaml
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: docker build -t cve-recommender:${{ github.sha }} .
      
      - name: Run tests
        run: docker run cve-recommender:${{ github.sha }} pytest tests/
      
      - name: Push to registry
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker tag cve-recommender:${{ github.sha }} username/cve-recommender:latest
          docker push username/cve-recommender:latest
      
      - name: Deploy to production
        run: |
          ssh ${{ secrets.PROD_SERVER }} "cd /opt/cti_recommender && docker-compose pull && docker-compose up -d"
```

---

## Maintenance Checklist

### Daily
- [ ] Check API health endpoint
- [ ] Monitor error logs
- [ ] Check resource usage (CPU, memory, disk)

### Weekly
- [ ] Review application logs
- [ ] Check backup integrity
- [ ] Update CVE database if needed

### Monthly
- [ ] Update Docker images
- [ ] Review and optimize database
- [ ] Performance benchmarking
- [ ] Security vulnerability scan

---

## Support

- **Documentation**: `docs/`
- **API Docs**: http://localhost:8000/docs
- **Issues**: GitHub Issues
- **Logs**: `docker-compose logs -f api`
