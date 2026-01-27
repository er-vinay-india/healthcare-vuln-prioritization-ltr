# CVE Prioritization API

FastAPI REST API for vulnerability scoring and recommendations.

## Quick Start

### 1. Start the API Server

```bash
# Development mode (with auto-reload)
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 2. Access Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

---

## API Endpoints

### Core Endpoints

#### `GET /health`
Health check with database statistics.

```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "database_status": "connected",
  "total_cves": 226320,
  "model_loaded": true
}
```

---

#### `POST /api/v1/predict`
Score a list of CVE IDs.

```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '["CVE-2024-1234", "CVE-2023-5678"]'
```

Response:
```json
{
  "predictions": {
    "CVE-2024-1234": 0.8547,
    "CVE-2023-5678": 0.6231
  },
  "count": 2
}
```

---

#### `GET /api/v1/top_cves`
Get top-K ranked CVEs with filtering.

**Query Parameters:**
- `limit` (1-100): Number of CVEs to return (default: 20)
- `date_start` (YYYY-MM-DD): Filter by published date
- `date_end` (YYYY-MM-DD): Filter by published date
- `healthcare_only` (bool): Only healthcare-relevant CVEs
- `kev_only` (bool): Only KEV CVEs
- `min_cvss` (0-10): Minimum CVSS score

```bash
curl "http://localhost:8000/api/v1/top_cves?limit=10&healthcare_only=true&min_cvss=7.0"
```

Response:
```json
{
  "top_cves": [
    {
      "rank": 1,
      "cve_id": "CVE-2024-1234",
      "score": 0.9521,
      "cvss": 9.8,
      "epss_score": 0.8234,
      "kev_flag": true,
      "is_healthcare": true,
      "label": 3,
      "published": "2024-01-15T00:00:00",
      "description": "Critical vulnerability in healthcare system..."
    }
  ],
  "count": 10,
  "total_candidates": 145,
  "filters": {
    "healthcare_only": true,
    "min_cvss": 7.0
  }
}
```

---

#### `POST /api/v1/explain`
Get SHAP-based explanation for a CVE prediction.

```bash
curl -X POST "http://localhost:8000/api/v1/explain?cve_id=CVE-2024-1234"
```

Response:
```json
{
  "cve_id": "CVE-2024-1234",
  "prediction_score": 0.9521,
  "top_3_features": [
    {"feature": "kev_flag", "contribution": 0.3245},
    {"feature": "cvss_norm", "contribution": 0.2156},
    {"feature": "epss_score", "contribution": 0.1823}
  ],
  "feature_contributions": {
    "kev_flag": 0.3245,
    "cvss_norm": 0.2156,
    ...
  },
  "feature_values": {
    "kev_flag": 1,
    "cvss_norm": 0.98,
    ...
  },
  "cve_details": {
    "cvss": 9.8,
    "kev_flag": true,
    "is_healthcare": true,
    "label": 3
  }
}
```

---

#### `GET /api/v1/stats`
Get database statistics.

```bash
curl http://localhost:8000/api/v1/stats
```

Response:
```json
{
  "total_cves": 226320,
  "epss_coverage": 226320,
  "kev_count": 1156,
  "healthcare_count": 124723,
  "label_distribution": {
    "0": 82021,
    "1": 138432,
    "2": 5333,
    "3": 534
  },
  "cvss_stats": {
    "average": 6.75,
    "min": 0.0,
    "max": 10.0
  }
}
```

---

### Legacy Endpoints

#### `POST /api/v1/recommendations`
Get recommendations (legacy format, use `/top_cves` instead).

#### `GET /api/v1/cve/{cve_id}`
Get detailed CVE information.

```bash
curl http://localhost:8000/api/v1/cve/CVE-2024-1234
```

---

## Testing

### Run Test Script

```bash
# Start API server first
uvicorn src.api.main:app --reload

# In another terminal, run tests
python scripts/test_api.py
```

### Manual Testing with curl

```bash
# Health check
curl http://localhost:8000/health

# Get top 5 healthcare CVEs
curl "http://localhost:8000/api/v1/top_cves?limit=5&healthcare_only=true"

# Score specific CVEs
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '["CVE-2024-0001", "CVE-2024-0002"]'

# Explain a prediction
curl -X POST "http://localhost:8000/api/v1/explain?cve_id=CVE-2024-0001"
```

---

## Python Client Example

```python
import requests

BASE_URL = "http://localhost:8000"

# Get top CVEs
response = requests.get(
    f"{BASE_URL}/api/v1/top_cves",
    params={
        'limit': 20,
        'healthcare_only': True,
        'min_cvss': 7.0
    }
)
top_cves = response.json()

print(f"Top {len(top_cves['top_cves'])} CVEs:")
for cve in top_cves['top_cves']:
    print(f"  {cve['rank']}. {cve['cve_id']}: {cve['score']:.4f}")

# Score specific CVEs
cve_ids = ["CVE-2024-1234", "CVE-2023-5678"]
response = requests.post(
    f"{BASE_URL}/api/v1/predict",
    json=cve_ids
)
predictions = response.json()['predictions']

print(f"\nPredictions:")
for cve_id, score in predictions.items():
    print(f"  {cve_id}: {score:.4f}")

# Explain a prediction
response = requests.post(
    f"{BASE_URL}/api/v1/explain",
    params={'cve_id': 'CVE-2024-1234'}
)
explanation = response.json()

print(f"\nExplanation for {explanation['cve_id']}:")
print(f"  Score: {explanation['prediction_score']:.4f}")
print("  Top features:")
for feat in explanation['top_3_features']:
    print(f"    - {feat['feature']}: {feat['contribution']:.4f}")
```

---

## Configuration

Set environment variables or use `config/settings.py`:

```bash
# Database
export DATABASE_PATH=data/cve_database.db

# Model
export MODEL_PATH=models/ltr_model_conf_weighted.pkl

# API Server
export API_HOST=0.0.0.0
export API_PORT=8000
export API_WORKERS=4

# Logging
export LOG_LEVEL=INFO
```

---

## Performance

- **Latency**: <100ms p95 for `/predict` and `/top_cves`
- **Throughput**: ~100 requests/second (single worker)
- **Caching**: Model loaded once at startup
- **Database**: SQLite with 226K CVEs, indexed for fast queries

---

## Production Deployment

### Docker

```bash
docker build -t cve-recommender-api .
docker run -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/models:/app/models \
  cve-recommender-api
```

### Systemd Service

```ini
[Unit]
Description=CVE Recommender API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/cti_recommender
Environment="PATH=/opt/cti_recommender/venv/bin"
ExecStart=/opt/cti_recommender/venv/bin/uvicorn src.api.main:app \
  --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## Monitoring

### Health Check Endpoint

```bash
# Kubernetes liveness/readiness probe
curl -f http://localhost:8000/health || exit 1
```

### Metrics

Add Prometheus metrics (TODO):
```python
from prometheus_client import Counter, Histogram

request_count = Counter('api_requests_total', 'Total requests')
request_latency = Histogram('api_request_duration_seconds', 'Request latency')
```

---

## Troubleshooting

### API Won't Start

```bash
# Check if port is in use
lsof -i :8000

# Check model file exists
ls -lh models/ltr_model_conf_weighted.pkl

# Check database exists
ls -lh data/cve_database.db
```

### Import Errors

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Slow Responses

- Check database size: `du -h data/cve_database.db`
- Increase API workers: `--workers 8`
- Add database indexes if needed

---

## Next Steps

- [ ] Add authentication (API keys)
- [ ] Add rate limiting
- [ ] Add request/response caching
- [ ] Add Prometheus metrics
- [ ] Add batch prediction endpoint
- [ ] Add WebSocket support for streaming
