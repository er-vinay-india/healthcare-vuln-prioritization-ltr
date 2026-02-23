# Development Guide

**Last Updated:** 2026-01-17  
**Version:** 2.0.0

---

## Development Environment Setup

### Prerequisites

- Python 3.10+ (3.14 recommended)
- Git
- Virtual environment tool (venv, conda, pyenv)
- SQLite3
- (Optional) Docker for containerized development

### Initial Setup

```bash
# Clone repository
git clone https://github.com/er-vinay-india/cti-recommender.git
cd cti_recommender

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies (testing, linting)
pip install pytest pytest-cov black flake8 mypy
```

---

## Project Structure

```
cti_recommender/
├── src/                          # Source code
│   ├── core/                     # Core modules
│   │   ├── cve_database.py      # Database management
│   │   ├── cti_recommender.py   # Scoring engine
│   │   └── ltr.py               # LTR model
│   ├── enrichment/              # Enrichment modules
│   │   ├── attack_mapper.py     # ATT&CK mapping
│   │   ├── chpl_matcher.py      # CHPL matching
│   │   ├── kev_checker.py       # KEV checking
│   │   └── epss_fetcher.py      # EPSS fetching
│   ├── analysis/                # Analysis modules
│   │   ├── data_quality.py      # Validation
│   │   └── healthcare_mapping.py # Healthcare detection
│   ├── models/                  # Pydantic schemas
│   │   └── schemas.py
│   ├── utils/                   # Utilities
│   │   ├── api_client.py        # API client
│   │   └── logging_config.py    # Logging
│   └── api/                     # REST API
│       └── main.py
├── scripts/                     # Executable scripts
│   ├── enrich_cves.py          # Main enrichment
│   ├── train_ltr.py            # Training
│   ├── temporal_validation.py  # Validation
│   └── analyze/                # Analysis scripts
├── tests/                       # Unit tests
├── notebooks/                   # Jupyter notebooks
├── config/                      # Configuration
├── data/                        # Data files
├── models/                      # Trained models
└── docs/                        # Documentation
```

---

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

Edit files in `src/`, `scripts/`, or `tests/`

### 3. Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test
pytest tests/test_attack_mapping.py -v
```

### 4. Code Quality Checks

```bash
# Format code
black src/ scripts/ tests/

# Lint code
flake8 src/ scripts/ tests/ --max-line-length=100

# Type checking
mypy src/ --ignore-missing-imports
```

### 5. Commit Changes

```bash
git add .
git commit -m "feat: your feature description"
```

**Commit message format:**
- `feat:` - New feature
- `fix:` - Bug fix
- `refactor:` - Code refactoring
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `chore:` - Maintenance tasks

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
# Create Pull Request on GitHub
```

---

## Database Schema

### Core Tables

**cves:**
```sql
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    published TEXT NOT NULL,
    modified TEXT NOT NULL,
    description TEXT,
    cvss REAL
);
```

**enrichments:**
```sql
CREATE TABLE enrichments (
    cve_id TEXT PRIMARY KEY,
    in_kev INTEGER DEFAULT 0,
    kev_date_added TEXT,
    epss_score REAL,
    is_healthcare INTEGER DEFAULT 0,
    chpl_product_name TEXT,
    chpl_vendor TEXT,
    attack_techniques TEXT,
    attack_tactics TEXT,
    attack_technique_count INTEGER DEFAULT 0,
    curated_label INTEGER,
    healthcare_vendor_flag INTEGER DEFAULT 0,
    label INTEGER DEFAULT 0,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);
```

### Database Access

```python
from src.core.cve_database import CVEDatabase

# Initialize database
db = CVEDatabase()

# Query CVEs
results = db.conn.execute("SELECT * FROM cves LIMIT 10").fetchall()

# Always close connection
db.conn.close()
```

---

## Adding New Features

### 1. Create New Module

Example: Adding a new enrichment source

**File:** `src/enrichment/new_source.py`

```python
"""Module for enriching CVEs with NewSource data."""

import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


class NewSourceEnricher:
    """Enrich CVEs with NewSource data."""
    
    def __init__(self):
        """Initialize the enricher."""
        self.cache = {}
        logger.info("NewSourceEnricher initialized")
    
    def enrich_cve(self, cve_id: str) -> Dict[str, any]:
        """
        Enrich a single CVE with NewSource data.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
        
        Returns:
            Dictionary with enrichment data
        """
        # Check cache
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        # Fetch from API
        data = self._fetch_from_api(cve_id)
        
        # Cache result
        self.cache[cve_id] = data
        
        return data
    
    def _fetch_from_api(self, cve_id: str) -> Dict[str, any]:
        """Fetch data from NewSource API."""
        # Implementation here
        pass
```

### 2. Add Unit Tests

**File:** `tests/test_new_source.py`

```python
"""Tests for NewSource enricher."""

import pytest
from src.enrichment.new_source import NewSourceEnricher


def test_enricher_initialization():
    """Test enricher initializes correctly."""
    enricher = NewSourceEnricher()
    assert enricher.cache == {}


def test_enrich_cve():
    """Test CVE enrichment."""
    enricher = NewSourceEnricher()
    result = enricher.enrich_cve("CVE-2024-1234")
    
    assert isinstance(result, dict)
    assert "field1" in result
    assert "field2" in result


def test_caching():
    """Test result caching."""
    enricher = NewSourceEnricher()
    
    # First call
    result1 = enricher.enrich_cve("CVE-2024-1234")
    
    # Second call (should use cache)
    result2 = enricher.enrich_cve("CVE-2024-1234")
    
    assert result1 == result2
    assert "CVE-2024-1234" in enricher.cache
```

### 3. Integrate into Pipeline

**File:** `scripts/enrich_cves.py`

```python
from src.enrichment.new_source import NewSourceEnricher

# In main enrichment loop
enricher = NewSourceEnricher()

for cve_id in cve_ids:
    data = enricher.enrich_cve(cve_id)
    # Store in database
```

### 4. Update Documentation

- Add to `docs/API.md` if adding API endpoints
- Update `README.md` features list
- Add to this development guide if introducing new patterns

---

## Testing Guidelines

### Test Structure

```python
import pytest
from src.module import function_to_test


class TestFunctionName:
    """Tests for function_to_test()."""
    
    def test_normal_case(self):
        """Test with valid input."""
        result = function_to_test("valid_input")
        assert result == "expected_output"
    
    def test_edge_case(self):
        """Test with edge case."""
        result = function_to_test("")
        assert result is None
    
    def test_error_case(self):
        """Test error handling."""
        with pytest.raises(ValueError):
            function_to_test(invalid_input)


@pytest.fixture
def sample_data():
    """Fixture providing sample test data."""
    return {
        "cve_id": "CVE-2024-1234",
        "cvss": 9.8
    }


def test_with_fixture(sample_data):
    """Test using fixture."""
    result = function_to_test(sample_data)
    assert result is not None
```

### Running Tests

```bash
# All tests
pytest

# Specific file
pytest tests/test_attack_mapping.py

# Specific test
pytest tests/test_attack_mapping.py::test_technique_mapping -v

# With coverage
pytest --cov=src --cov-report=html

# View coverage report
open htmlcov/index.html
```

---

## Code Style Guidelines

### Python Style (PEP 8)

- **Line length:** 100 characters max
- **Indentation:** 4 spaces (no tabs)
- **Imports:** Standard library -> Third-party -> Local
- **Naming:**
  - Classes: `PascalCase`
  - Functions/variables: `snake_case`
  - Constants: `UPPER_SNAKE_CASE`

### Documentation

Every module, class, and public function should have a docstring:

```python
def calculate_score(cve_data: Dict[str, any]) -> float:
    """
    Calculate priority score for a CVE.
    
    Args:
        cve_data: Dictionary with CVE attributes (cvss, kev, epss, etc.)
    
    Returns:
        Priority score between 0 and 1
    
    Raises:
        ValueError: If required fields are missing
    
    Example:
        >>> data = {"cvss": 9.8, "in_kev": 1, "epss_score": 0.85}
        >>> score = calculate_score(data)
        >>> print(f"Score: {score:.2f}")
        Score: 0.92
    """
    # Implementation
    pass
```

### Type Hints

Always use type hints for function signatures:

```python
from typing import List, Dict, Optional, Tuple

def fetch_cves(
    years: int = 1,
    filter_healthcare: bool = False
) -> List[Dict[str, any]]:
    """Fetch CVEs with type-safe parameters."""
    pass

def parse_cve(cve_data: Dict[str, any]) -> Optional[CVE]:
    """Parse CVE data, returning None if invalid."""
    pass
```

---

## Debugging

### Logging

Use structured logging instead of `print()`:

```python
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Info logging
logger.info("Processing CVEs", extra={"count": 1000, "source": "NVD"})

# Warning logging
logger.warning("CVSS missing", extra={"cve_id": "CVE-2024-1234"})

# Error logging
logger.error("API failed", extra={"status_code": 500, "url": api_url})
```

### Interactive Debugging

```python
# Add breakpoint in code
import pdb; pdb.set_trace()

# Or use Python 3.7+
breakpoint()
```

**PDB Commands:**
- `n` - Next line
- `s` - Step into function
- `c` - Continue execution
- `p variable` - Print variable
- `l` - List code around current line
- `h` - Help

### Database Inspection

```bash
# Open database
sqlite3 data/cve_database.db

# Common queries
.schema cves
.schema enrichments
SELECT COUNT(*) FROM cves;
SELECT * FROM cves WHERE cvss > 9.0 LIMIT 10;
SELECT COUNT(*) FROM enrichments WHERE in_kev = 1;
```

---

## Performance Optimization

### Database Queries

**Use indexes:**
```python
# Add index for frequently queried columns
cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_kev ON enrichments(in_kev)")
```

**Batch operations:**
```python
# Bad: Multiple inserts
for cve in cves:
    cursor.execute("INSERT INTO cves VALUES (?, ?)", (cve.id, cve.cvss))

# Good: Batch insert
cursor.executemany("INSERT INTO cves VALUES (?, ?)", 
                   [(cve.id, cve.cvss) for cve in cves])
```

### Parallel Processing

```python
from concurrent.futures import ThreadPoolExecutor

def process_cve(cve_id: str) -> Dict:
    # Enrichment logic
    pass

# Process in parallel
with ThreadPoolExecutor(max_workers=4) as executor:
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
python scripts/train_ltr.py
```

### Update Database Schema

1. **Update schema** in `src/core/cve_database.py`
2. **Delete old database:** `rm data/cve_database.db`
3. **Re-run enrichment:** `python scripts/enrich_cves.py --years 1`
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
3. **Update** `docs/API.md`

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
- `ARCHITECTURE_GUIDE.md`
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
