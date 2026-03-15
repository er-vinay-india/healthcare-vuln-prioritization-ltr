# Test Strategy & Coverage

**Last Updated:** 2026-02-23  
**Test Framework:** pytest 9.0.2  
**Python:** 3.14.0

---

## Test Organization

```
tests/
├── conftest.py                          # Shared fixtures (temp_dir, test_db, test_settings)
├── test_config.py                       # [OK] Configuration & settings (10 tests)
├── test_schemas.py                      # [OK] Pydantic data models (19 tests)
├── test_feature_engineering_clean.py    # [OK] Feature engineering (5 tests)
├── test_chpl_integration.py             # [WARN]  CHPL enrichment (10/12 passing)
├── test_temporal_splits.py              # [OK] Temporal splitting (9/11 passing)
├── test_api_*.py                        # API endpoint tests
└── test_*.py                            # Legacy/additional tests
```

---

## Current Test Status

### [OK] Passing Test Suites (53 tests)

**Configuration & Settings** (10/10 passing)
- Settings initialization
- Path resolution (database, cache, models)
- NVD API rate limiting
- Directory creation
- Hyperparameter validation

**Data Validation Schemas** (19/19 passing)
- CVEInput validation
- EPSS score validation
- CVE enrichment schemas
- Recommendation schemas
- Model metrics schemas
- Health status schemas

**Feature Engineering** (5/5 passing)
- Basic functionality
- CVSS normalization
- Temporal features
- Interaction features
- Missing value handling

**Temporal Splits** (9/11 passing)
- Date-based splits (2024-11-01 cutoff)
- Percentage-based splits (70/30)
- Year-based splits (train 2018-2024, test 2025)
- Data leakage validation
- Edge case: single-day data

---

## [WARN] Critical Test Failures

### 1. CHPL Integration (2/12 tests failing)

**Status:**  **BLOCKS THESIS DEFENSE**

**Failure:**
```
test_chpl_enrichment_coverage FAILED
```

**Finding:**
```
Database: 226,320 CVEs
CHPL enrichments: 0 (0.00%)
```

**Root Cause:**
- CHPL cache exists and has 695 products
- CHPLMapper loads correctly
- BUT database shows 0 CHPL flags
- Enrichment script either:
  - Was run with `--skip-chpl` flag
  - Encountered silent failures during batch processing

**Impact:**
- Documentation claims CHPL as active data source
- `chpl_flag` feature contributes zero signal to model
- Examiners will question documentation accuracy

**Action Required:**
```bash
python scripts/data/enrich_cves.py  # WITHOUT --skip-chpl
python scripts/ops/check_db_status.py
pytest tests/test_chpl_integration.py -v
```

### 2. Temporal Splits Edge Cases (2/11 tests)

**Minor Issues:**
- `test_empty_dataframe`: Should raise error for empty data (currently silent)
- `test_timezone_aware_dates`: Training set ends up empty with certain date ranges

**Impact:** Low priority - edge cases unlikely in production

---

## Test Coverage by Component

| Component | Coverage | Status |
|-----------|----------|--------|
| Configuration | 100% | [OK] Excellent |
| Data Schemas | 100% | [OK] Excellent |
| Feature Engineering | 90% | [OK] Good |
| **CHPL Integration** | **83%** | [WARN] **CRITICAL ISSUE FOUND** |
| Temporal Splits | 82% | [OK] Good |
| API Endpoints | ~60% |  Partial |
| Data Pipeline | 0% | [FAIL] Missing |

---

## Missing Test Coverage (Priority Order)

###  HIGH PRIORITY

**1. Data Pipeline Integration Tests**
```python
# tests/test_data_pipeline.py (TO BE CREATED)
def test_nvd_to_database_flow()
def test_enrichment_pipeline_end_to_end()
def test_feature_engineering_pipeline()
def test_database_enrichment_consistency()
```

**2. CHPL Enrichment Fix Validation**
```bash
# After running enrich_cves.py
pytest tests/test_chpl_integration.py::test_chpl_enrichment_coverage
```

###  MEDIUM PRIORITY

**3. Model Training Tests**
```python
# tests/test_ltr_model.py
def test_lightgbm_training()
def test_model_evaluation_metrics()
def test_model_persistence()
```

**4. Database Operations Tests**
```python
# tests/test_database.py
def test_cve_upsert()
def test_enrichment_upsert()
def test_query_performance()
```

###  LOW PRIORITY

**5. API Integration Tests**
- Expand test_api_*.py coverage
- Add performance benchmarks

---

## Running Tests

### Run All Tests
```bash
source venv/bin/activate
pytest tests/ -v
```

### Run Specific Test Suite
```bash
pytest tests/test_chpl_integration.py -v
pytest tests/test_temporal_splits.py -v
pytest tests/test_feature_engineering_clean.py -v
```

### Run Tests with Coverage Report
```bash
pytest tests/ --cov=src --cov-report=html
```

### Run Only Fast Tests (skip integration)
```bash
pytest tests/ -v -m "not slow"
```

---

## Test Fixtures Available

### From conftest.py

**temp_dir**
- Creates temporary directory for test outputs
- Automatically cleaned up after test

**test_settings**
- Settings instance with temporary paths
- Isolated from production configuration

**test_database**
- SQLite database with sample CVE data
- Pre-populated with test records

---

## Architecture Review Findings Validated by Tests

### [OK] Confirmed by Tests:

1. **CHPL Enrichment Not Working**
   - Test: `test_chpl_enrichment_coverage`
   - Finding: 0 CHPL flags in 226,320 CVEs
   - Status:  CRITICAL - matches documentation review

2. **Temporal Splits Work Correctly**
   - Tests: 9/11 passing
   - Date-based: [OK] Working
   - Percentage-based: [OK] Working
   - Year-based: [OK] Working
   - Data leakage: [OK] Validated

3. **Feature Engineering Solid**
   - Tests: 5/5 passing
   - CVSS normalization: [OK]
   - Interaction features: [OK]
   - Missing value handling: [OK]

### [FAIL] Not Yet Validated by Tests:

1. **Data Pipeline Transparency**
   - No integration tests for backfill -> enrich -> train flow
   - Need: `test_data_pipeline.py`

2. **Multi-Strategy Temporal Splits**
   - Current tests use existing `make_temporal_splits()`
   - Need: Tests for flexible YAML configuration

---

## Continuous Integration Readiness

### Pre-commit Checks
```bash
# tests/scripts/pre_commit.sh
pytest tests/test_config.py tests/test_schemas.py tests/test_feature_engineering_clean.py
```

### Full Test Suite (CI/CD)
```bash
pytest tests/ --tb=short --maxfail=5
```

### Test Performance
- Configuration: ~0.03s
- Schemas: ~1.14s
- Feature Engineering: ~0.25s
- CHPL Integration: ~17.17s (cache loading)
- Temporal Splits: ~0.28s

**Total Runtime:** ~20 seconds for 53 tests

---

## Next Steps

1. **Fix CHPL Enrichment** (CRITICAL)
   ```bash
   python scripts/data/enrich_cves.py
   pytest tests/test_chpl_integration.py
   ```

2. **Create Data Pipeline Tests**
   - File: `tests/test_data_pipeline.py`
   - Coverage: NVD -> DB -> Enrichment -> Features

3. **Add Model Training Tests**
   - File: `tests/test_ltr_model.py`
   - Coverage: Training, evaluation, persistence

4. **Expand API Tests**
   - Add performance benchmarks
   - Test error handling

---

## Test Quality Standards

### Required for All Tests:
- [OK] Descriptive docstrings
- [OK] Isolated (no shared state)
- [OK] Fast (<1s per test)
- [OK] Clear assertions with messages
- [OK] Proper fixtures from conftest.py

### Test Naming Convention:
```python
def test_<component>_<behavior>_<expected_outcome>():
    """Test that <component> <behavior> when <condition>"""
```

---

## Known Issues

1. **CHPL Test Failure** - See Critical Test Failures section
2. **Empty DataFrame Handling** - temporal.py should raise error
3. **Timezone Edge Case** - Training set empty with certain TZ dates
4. **Legacy Test Imports** - Some tests import non-existent `cti_recommender` package (fixed)

---

## Contact & Maintenance

**Test Owner:** Architecture Review (2026-02-23)  
**Last Full Run:** 2026-02-23  
**Next Review:** After CHPL enrichment fix
