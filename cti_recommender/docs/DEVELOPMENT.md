# Development Guide

**Last Updated:** March 2026

This guide is for contributors who want to change or debug the project.

## Setup

```bash
git clone https://github.com/er-vinay-india/cti-recommender.git
cd cti_recommender

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov black flake8 mypy
```

## Main Areas

- `src/core/` - database, ingestion, core logic
- `src/features/` - feature and label generation
- `src/models/` - ranking and graph models
- `src/evaluation/` - metrics and evaluation helpers
- `src/api/` - serving layer
- `scripts/` - executable entrypoints
- `tests/` - automated tests

## Typical Workflow

### 1. Make changes

Work in `src/`, `scripts/`, and `tests/`.

### 2. Run tests

```bash
pytest
pytest --cov=src --cov-report=term-missing
```

### 3. Run code quality checks

```bash
black src/ scripts/ tests/
flake8 src/ scripts/ tests/ --max-line-length=100
mypy src/ --ignore-missing-imports
```

### 4. Commit

Use simple commit prefixes such as:
- `feat:`
- `fix:`
- `refactor:`
- `docs:`
- `test:`
- `chore:`

## Development Notes

- Prefer changes in `src/` over notebook-only logic.
- Add or update tests for behavior changes.
- Keep scripts thin and move reusable logic into modules.
- Use logging instead of `print()` in application code.

## Useful Commands

```bash
# Run one test file
pytest tests/test_some_file.py -v

# Run one test
pytest tests/test_some_file.py::test_name -v

# Open the SQLite database
sqlite3 data/cve_database.db
```

## When To Read Other Docs

- `ARCHITECTURE.md` for structure and data flow
- `DOCKER_GUIDE.md` for container-based development
- `RANKING_LOGIC.md` for score interpretation
    results = list(executor.map(process_cve, cve_ids))
```

### Caching

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def fetch_epss_score(cve_id: str) -> float:
    """Cached EPSS score fetching."""
    # Expensive API call
    pass
```

---

## Common Development Tasks

### Add New Feature to LTR Model

1. **Add feature extraction** in `src/core/ltr.py`:
```python
def extract_features(self, df: pd.DataFrame) -> np.ndarray:
    # Add new feature
    df['new_feature'] = df['some_column'].apply(transform_function)
    
    # Include in feature list
    features = [
        'recency_score',
        'cvss_normalized',
        'new_feature',  # Add here
        # ... other features
    ]
```

2. **Update feature count:**
```python
# Update n_features constant
N_FEATURES = 15  # Was 14
```

3. **Add tests:**
```python
def test_new_feature():
    """Test new feature extraction."""
    pass
```

4. **Retrain model:**
```bash
python scripts/training/train_ltr.py
```

### Update Database Schema

1. **Update schema** in `src/core/cve_database.py`
2. **Delete old database:** `rm data/cve_database.db`
3. **Re-run enrichment:** `python scripts/data/enrich_cves.py --years 1`
4. **Update tests:** Modify `tests/conftest.py` fixtures

### Add New API Endpoint

1. **Add endpoint** in `src/api/main.py`:
```python
@app.get("/api/v1/new_endpoint")
def new_endpoint(param: str):
    """New endpoint description."""
    # Implementation
    return {"result": "data"}
```

2. **Add tests** in `tests/test_api_endpoints.py`
3. **Update** `docs/DOCKER_GUIDE.md` (and `docs/archived/archive_README.md` if needed)

---

## Troubleshooting Development Issues

### Issue: Import Errors

```bash
# Ensure src/ is in Python path
export PYTHONPATH="${PYTHONPATH}:/path/to/cti_recommender"

# Or use relative imports
from ..core import module
```

### Issue: Database Lock

```bash
# Check for running processes
ps aux | grep python

# Kill if necessary
pkill -f "python scripts"
```

### Issue: Tests Failing

```bash
# Clear pytest cache
rm -rf .pytest_cache

# Run with verbose output
pytest -vv

# Run single test for debugging
pytest tests/test_file.py::test_name -s
```

---

## Release Process

### 1. Update Version

Update version in:
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/QUICKSTART.md`
- `docs/DEVELOPMENT.md`

### 2. Run Full Test Suite

```bash
pytest --cov=src --cov-report=term
```

### 3. Update Documentation

- Update `CHANGELOG.md` (if exists)
- Review all documentation files
- Update API documentation

### 4. Create Release Tag

```bash
git tag -a v2.0.0 -m "Release version 2.0.0"
git push origin v2.0.0
```

### 5. Build Docker Image

```bash
docker build -t cti-recommender:2.0.0 .
docker tag cti-recommender:2.0.0 cti-recommender:latest
```

---

## Additional Resources

- **Git workflow:** https://guides.github.com/introduction/flow/
- **Python testing:** https://docs.pytest.org/
- **Code style:** https://pep8.org/
- **Type hints:** https://docs.python.org/3/library/typing.html

---

## Getting Help

- **Team chat:** [Slack/Discord channel]
- **Email:** [maintainer-email]
- **GitHub Issues:** For bugs and feature requests

---

Happy coding! [RUN]
