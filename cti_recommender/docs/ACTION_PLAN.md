# Action Plan: Production Hardening (Phase 6)
**Date:** January 27, 2026  
**Status:** Ready to Execute  
**Timeline:** 2 weeks (80 hours total)  
**Priority:** HIGH

Based on [PROJECT_REVIEW_2026.md](PROJECT_REVIEW_2026.md) analysis, this document provides a concrete, step-by-step execution plan.

---

## 🎯 Phase 6 Overview

**Goal:** Make the system production-ready for deployment

**Success Criteria:**
- ✅ All feature engineering in modules (0 inline code)
- ✅ Working API with 3+ endpoints
- ✅ Test coverage ≥80%
- ✅ Docker deployment ready
- ✅ Zero TODO stubs in production code

---

## 📋 Task Breakdown

### **Task 6.1: Migrate Feature Engineering** (2 hours)
**Priority:** HIGH | **Difficulty:** Easy | **Blocking:** No

**Current Problem:**
- 38 lines of feature engineering code inline in notebook (lines 130-167)
- Located in: `notebooks/CVE_Prioritization_Final.ipynb`
- Should be in: `src/features/engineering.py`

**Steps:**
1. ✅ Read current inline code from notebook
2. ✅ Design `create_all_features(df: pd.DataFrame) -> pd.DataFrame` function
3. ✅ Implement function in `src/features/engineering.py`
4. ✅ Add type hints and docstrings
5. ✅ Update notebook to call `create_all_features(df)`
6. ✅ Test notebook execution
7. ✅ Commit changes

**Acceptance Criteria:**
- Notebook has 0 lines of inline feature engineering
- Function handles all 12 features correctly
- All tests pass

**Files to Modify:**
- `src/features/engineering.py` (add function)
- `notebooks/CVE_Prioritization_Final.ipynb` (replace inline code)

---

### **Task 6.2: Clean Up TODO Stubs** (4 hours)
**Priority:** HIGH | **Difficulty:** Medium | **Blocking:** No

**Current Problem:**
- 21 TODO stubs scattered across modules
- Functions declared but not implemented
- Creates confusion and false expectations

**Steps:**
1. ✅ List all TODO locations (grep search)
2. ✅ Categorize: [Implement Now | Implement Later | Remove]
3. ✅ For "Implement Now" (critical path):
   - `src/data/preprocessing.py`: Clean/filter functions
   - `src/evaluation/comparison.py`: Model comparison
4. ✅ For "Implement Later" (non-critical):
   - Add detailed TODO comments with requirements
   - Create GitHub issues
5. ✅ For "Remove" (not needed):
   - Delete stub functions
   - Remove from `__init__.py` exports
6. ✅ Update documentation
7. ✅ Commit changes

**Acceptance Criteria:**
- Zero TODO stubs in `src/core/`, `src/models/`, `src/features/`
- All remaining TODOs have detailed plans
- Documentation reflects actual capabilities

**Files to Review:**
```
src/evaluation/significance.py      (3 TODOs - Wilcoxon, Bonferroni, pairwise)
src/evaluation/comparison.py        (4 TODOs - comparison framework)
src/data/preprocessing.py           (2 TODOs - cleaning/filtering)
src/data/loader.py                  (1 TODO - date queries)
src/models/ltr.py                   (1 TODO - CV logic)
src/models/baselines.py             (1 TODO - EPSS baseline)
src/utils/temporal.py               (3 TODOs - leakage check, engineering, grouping)
src/utils/config.py                 (4 TODOs - config management)
src/evaluation/metrics.py           (2 TODOs - temporal eval, comprehensive)
```

---

### **Task 6.3: Implement FastAPI Endpoints** (8 hours)
**Priority:** HIGH | **Difficulty:** Hard | **Blocking:** Yes (for deployment)

**Current Problem:**
- `src/api/main.py` is skeleton only
- No endpoints implemented
- Blocking production deployment

**Steps:**

#### Step 1: Core Inference (3 hours)
```python
# Implement these endpoints:
POST /api/v1/predict
  - Input: List of CVE IDs
  - Output: Scores + rankings
  
GET /api/v1/top_cves
  - Query params: limit, date_range, sector
  - Output: Top-K CVEs with details

POST /api/v1/explain
  - Input: CVE ID
  - Output: SHAP values, feature contributions
```

#### Step 2: Infrastructure (2 hours)
- Add Pydantic models for request/response
- Implement error handling
- Add logging middleware
- Health check endpoint (`/health`)

#### Step 3: Authentication (2 hours)
- API key authentication
- Rate limiting (100 req/hour per key)
- Usage tracking

#### Step 4: Documentation (1 hour)
- Swagger/OpenAPI auto-generated docs
- Example curl commands
- Python client example

**Acceptance Criteria:**
- All 3 endpoints working
- Swagger docs at `/docs`
- Authentication enforced
- <100ms p95 latency for `/predict`

**Files to Create/Modify:**
- `src/api/main.py` (implement endpoints)
- `src/api/models.py` (Pydantic schemas)
- `src/api/auth.py` (authentication)
- `src/api/README.md` (API documentation)
- `tests/test_api.py` (API tests)

---

### **Task 6.4: Add Comprehensive Tests** (8 hours)
**Priority:** HIGH | **Difficulty:** Medium | **Blocking:** Yes (for production)

**Current Problem:**
- Test coverage ~40% (estimated)
- Missing tests for new modular functions
- No integration tests

**Steps:**

#### Step 1: Unit Tests (4 hours)
```
tests/
├── test_features/
│   ├── test_labeling.py          (NEW - test build_weak_labels)
│   └── test_engineering.py       (NEW - test create_all_features)
├── test_models/
│   ├── test_ltr.py               (EXPAND - add confidence weighting tests)
│   └── test_baselines.py         (NEW - test all baselines)
├── test_evaluation/
│   └── test_metrics.py           (EXPAND - test NDCG edge cases)
└── test_utils/
    └── test_temporal.py          (NEW - test temporal splits)
```

#### Step 2: Integration Tests (2 hours)
```python
# Test full pipeline
def test_end_to_end_pipeline():
    # Load data → Features → Train → Predict → Evaluate
    
def test_temporal_validation():
    # No data leakage in temporal splits
    
def test_api_endpoints():
    # FastAPI integration tests
```

#### Step 3: Property-Based Tests (1 hour)
```python
# Use Hypothesis for invariants
@given(rankings=st.lists(st.floats()))
def test_ndcg_monotonicity(rankings):
    # Higher scores → higher NDCG
```

#### Step 4: Coverage Report (1 hour)
- Run pytest with coverage
- Generate HTML report
- Add coverage badge to README

**Acceptance Criteria:**
- Coverage ≥80% for `src/` modules
- All critical paths tested
- CI/CD integration ready

**Commands:**
```bash
# Run tests
pytest tests/ -v --cov=src --cov-report=html

# Check coverage
coverage report
```

---

### **Task 6.5: Docker Deployment** (4 hours)
**Priority:** MEDIUM | **Difficulty:** Easy | **Blocking:** No

**Current Problem:**
- No containerization
- Manual deployment steps
- Environment inconsistencies

**Steps:**

#### Step 1: Create Dockerfile (1 hour)
```dockerfile
# Multi-stage build
FROM python:3.14-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.14-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY src/ src/
COPY models/ models/
COPY data/ data/
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Step 2: Docker Compose (1 hour)
```yaml
# docker-compose.yml
services:
  api:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./models:/app/models
      - ./data:/app/data
    environment:
      - MODEL_PATH=/app/models/ltr_model_conf_weighted.pkl
  
  postgres:
    image: postgres:15
    # Migrate SQLite → PostgreSQL for production
```

#### Step 3: Health Checks (1 hour)
- Implement `/health` endpoint
- Docker healthcheck configuration
- Graceful shutdown

#### Step 4: Documentation (1 hour)
- Deployment guide
- Environment variables
- Scaling instructions

**Acceptance Criteria:**
- `docker build` succeeds
- `docker-compose up` runs API
- Health checks passing
- <500MB image size

**Files to Create:**
- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `docs/DEPLOYMENT.md`

---

### **Task 6.6: Remove Duplicate Code** (2 hours)
**Priority:** MEDIUM | **Difficulty:** Easy | **Blocking:** No

**Current Problem:**
- `src/core/ltr.py` and `src/models/ltr.py` both implement LambdaRank
- Confusion about which to use
- Maintenance burden

**Steps:**
1. ✅ Compare both implementations
2. ✅ Choose canonical version (`src/models/ltr.py` - newer, better)
3. ✅ Update all imports to use `src.models.ltr`
4. ✅ Delete `src/core/ltr.py`
5. ✅ Update documentation
6. ✅ Run all tests
7. ✅ Commit changes

**Acceptance Criteria:**
- Only one LTR implementation exists
- All imports updated
- Tests pass

**Files to Modify:**
- Delete: `src/core/ltr.py`
- Update imports in: `scripts/`, notebooks if any reference old path

---

## 📅 Execution Timeline (2 Weeks)

### **Week 1: Code Quality & Modularization**

**Monday (6h)**
- Task 6.1: Migrate feature engineering (2h)
- Task 6.6: Remove duplicate LTR code (2h)
- Task 6.2: Start TODO cleanup - categorization (2h)

**Tuesday (6h)**
- Task 6.2: Implement critical TODOs (4h)
- Task 6.2: Remove non-critical stubs (2h)

**Wednesday (6h)**
- Task 6.4: Unit tests for features module (3h)
- Task 6.4: Unit tests for models module (3h)

**Thursday (6h)**
- Task 6.4: Unit tests for evaluation module (2h)
- Task 6.4: Integration tests (2h)
- Task 6.4: Generate coverage report (2h)

**Friday (4h)**
- Code review and refactoring
- Documentation updates
- Week 1 demo

### **Week 2: API & Deployment**

**Monday (8h)**
- Task 6.3: Implement core API endpoints (3h)
- Task 6.3: Add infrastructure (error handling, logging) (2h)
- Task 6.3: Authentication & rate limiting (3h)

**Tuesday (4h)**
- Task 6.3: API documentation (1h)
- Task 6.4: API integration tests (2h)
- Bug fixes and polish (1h)

**Wednesday (4h)**
- Task 6.5: Create Dockerfile (1h)
- Task 6.5: Docker Compose setup (1h)
- Task 6.5: Health checks (1h)
- Task 6.5: Deployment documentation (1h)

**Thursday (4h)**
- End-to-end testing
- Performance benchmarking
- Security audit

**Friday (4h)**
- Final code review
- Documentation review
- Phase 6 completion report
- Deploy to staging

---

## 🎯 Quick Start (Start Now)

### **Immediate Next Steps (Today)**

#### 1. Feature Engineering Migration (30 min)
```bash
# Start with Task 6.1
cd /Users/vinayksharma/AirDnd/cti_recommender

# 1. Extract inline feature code from notebook
# 2. Create function in src/features/engineering.py
# 3. Update notebook to use function
# 4. Test and commit
```

#### 2. TODO Audit (30 min)
```bash
# List all TODOs
grep -r "TODO\|FIXME" src/ --include="*.py" > docs/todo_audit.txt

# Categorize each:
# - [IMPLEMENT] = Critical for Phase 6
# - [LATER] = Post-production
# - [REMOVE] = Not needed
```

#### 3. Setup Testing Infrastructure (30 min)
```bash
# Install test dependencies
pip install pytest pytest-cov hypothesis

# Create test structure
mkdir -p tests/{test_features,test_models,test_evaluation,test_api}

# Run existing tests to establish baseline
pytest tests/ -v --cov=src
```

---

## 📊 Success Metrics

### Code Quality
- [ ] 0 lines of inline feature engineering
- [ ] 0 TODO stubs in core modules
- [ ] Test coverage ≥80%
- [ ] All type hints present

### API Functionality
- [ ] 3+ endpoints implemented
- [ ] Swagger docs available
- [ ] Authentication working
- [ ] <100ms p95 latency

### Deployment Readiness
- [ ] Docker build succeeds
- [ ] Health checks passing
- [ ] Deployment guide complete
- [ ] Staging environment running

---

## 🚨 Risk Assessment

### High Risk
1. **API Performance** - Risk: Slow inference
   - Mitigation: Cache model predictions, use async endpoints
   
2. **Test Coverage** - Risk: Can't reach 80%
   - Mitigation: Focus on critical paths first, defer edge cases

### Medium Risk
1. **TODO Implementation** - Risk: TODOs more complex than expected
   - Mitigation: Remove instead of implement if too costly
   
2. **Docker Size** - Risk: Image too large
   - Mitigation: Multi-stage build, minimize dependencies

### Low Risk
1. **Feature Engineering** - Risk: Breaking changes
   - Mitigation: Simple refactor, well-tested
   
2. **Duplicate Code Removal** - Risk: Missing imports
   - Mitigation: Grep search for all usages

---

## 📋 Checklist (Use This Daily)

### Daily Standup Questions
- [ ] What did I complete yesterday?
- [ ] What will I work on today?
- [ ] Any blockers?
- [ ] Am I on track with the timeline?

### Before Each Commit
- [ ] All tests passing (`pytest tests/`)
- [ ] No linting errors (`ruff check src/`)
- [ ] Type checking clean (`mypy src/`)
- [ ] Documentation updated

### Before Pull Request
- [ ] Coverage report shows increase
- [ ] All CI checks green
- [ ] Reviewer assigned
- [ ] Linked to issue/task

---

## 🎓 Learning Resources

### FastAPI
- [Official Tutorial](https://fastapi.tiangolo.com/tutorial/)
- [Testing Guide](https://fastapi.tiangolo.com/tutorial/testing/)
- [Deployment](https://fastapi.tiangolo.com/deployment/)

### Testing
- [pytest documentation](https://docs.pytest.org/)
- [Coverage.py](https://coverage.readthedocs.io/)
- [Hypothesis](https://hypothesis.readthedocs.io/)

### Docker
- [Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)

---

## 🎯 Phase 6 Completion Criteria

### Definition of Done
- ✅ All 6 tasks completed
- ✅ Test coverage ≥80%
- ✅ API deployed to staging
- ✅ Documentation complete
- ✅ Code reviewed and merged
- ✅ Demo to stakeholders

### Deliverables
1. ✅ Modular feature engineering code
2. ✅ Production-ready FastAPI application
3. ✅ Comprehensive test suite
4. ✅ Docker deployment setup
5. ✅ API documentation (Swagger)
6. ✅ Deployment guide

---

## 🚀 What's Next (Phase 7)?

After Phase 6 completion, we'll move to **Phase 7: Advanced Models**

**Preview:**
- Integrate RGCN (graph neural network)
- Implement DiffusionRank
- Create ensemble method
- GPU optimization (XGBoost GPU)
- Advanced models notebook

**But first:** Complete Phase 6 and get to production! 🎯

---

**Ready to start?** Begin with Task 6.1 (Feature Engineering Migration) - it's the easiest and provides immediate value!
