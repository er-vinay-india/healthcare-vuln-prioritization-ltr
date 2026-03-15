# CTI Recommender - Architecture Analysis & Action Plan

**Date:** 2026-02-26  
**Analysis Type:** Database Architecture, Caching Layer, and Data Quality

---

## Executive Summary

### Current State Analysis

**Database:** 226,320 CVEs across 3 tables (`cves`, `enrichments`, `fetch_log`)  
**Critical Finding:** Several enrichment columns are 100% NULL despite having code to populate them  
**Root Cause:** Enrichment pipeline not extracting all available fields from API responses and mappers

---

## 1. CURRENT ARCHITECTURE

### 1.1 Database Layer (SQLite)

```
┌─────────────────────────────────────────────────────────────┐
│                     SQLite Database                         │
├─────────────────────────────────────────────────────────────┤
│ cves (226,320 records)                                      │
│   - cve_id, published, modified, description                │
│   - cvss, cvss_vector, cwe, raw_json                        │
├─────────────────────────────────────────────────────────────┤
│ enrichments (226,320 records)                               │
│   - kev_flag, epss_score, epss_percentile, epss_date        │
│   - is_healthcare, healthcare_score, curated_severity       │
│   - attack_flag, chpl_flag, label                           │
├─────────────────────────────────────────────────────────────┤
│ fetch_log (tracking table)                                  │
│   - fetch_date, start_date, end_date, cve_count, status     │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Caching Layer (File-Based)

**Location:** `cache/` directory  
**Purpose:** Store raw API responses to avoid repeated API calls  
**Strategy:** Hybrid (persistent + daily caches)

```
cache/
├── nvd/                    # NVD CVE Data
│   ├── nvd_30d.pkl.gz     
│   ├── nvd_7d.pkl.gz      
│   └── nvd_enhanced_phase1.pkl.gz
├── epss/                   # EPSS Exploit Probability Scores
│   ├── epss_2026-01-17.json       (daily cache, 1-day TTL)
│   └── epss_persistent.json       (permanent cache, NEVER expires)
├── kev/                    # CISA Known Exploited Vulnerabilities
│   └── kev_catalog.pkl.gz         (cached catalog)
├── attack/                 # MITRE ATT&CK Techniques
│   └── attack_techniques.pkl.gz   (static reference data)
└── chpl/                   # Health IT Certified Products
    ├── chpl_products.json  
    └── chpl_products.pkl.gz
```

**Key Points:**
- **Raw API responses are stored in cache files (JSON/pickle)**
- **Only processed/enriched data goes to SQLite database**
- **No duplicate storage of raw API responses in database**
- **Two-tier caching:** Daily (expires) + Persistent (never expires)

### 1.3 Third-Party API Integrations

| API Source | Data Type | Fetch Strategy | Caching | Rate Limiting |
|------------|-----------|----------------|---------|---------------|
| **NVD** (NIST) | CVE details, CVSS, CWE | Incremental (date ranges) | File-based (.pkl.gz) | Yes (0.6s delay) |
| **EPSS** (FIRST.org) | Exploit probability scores | Bulk batch (100 CVEs/batch) | Persistent JSON + Daily | Yes (0.5s delay) |
| **KEV** (CISA) | Known exploited vulnerabilities | Full catalog fetch | File-based (.pkl.gz) | No |
| **ATT&CK** (MITRE) | Technique mappings | Static reference data | File-based (.pkl.gz) | No (once) |
| **CHPL** (ONC) | Certified health IT products | Full catalog fetch | JSON + pickle | Yes |

**Fetch Modes:**
- **Batch:** EPSS (100 CVEs per request)
- **On-the-fly:** None currently (all pre-fetched)
- **Incremental:** NVD (date-based ranges)
- **Full catalog:** KEV, CHPL, ATT&CK

---

## 2. DATA QUALITY ISSUES - CRITICAL FINDINGS

### 2.1 NULL Column Analysis (226,320 total records)

| Column | NULL Count | NULL % | Expected Behavior |
|--------|-----------|--------|-------------------|
| `epss_date` | **226,320** | **100%** ⚠️ | Should contain date from EPSS API |
| `healthcare_score` | **226,320** | **100%** ⚠️ | Should contain 0-1 relevance score |
| `curated_severity` | **226,268** | **99.99%** ⚠️ | Should contain severity for curated CVEs |
| `epss_score` | **0** | **0%** ✅ | Correctly populated |
| `kev_flag` | **0** | **0%** ✅ | Correctly populated (1,178 KEV CVEs) |
| `is_healthcare` | **0** | **0%** ✅ | Correctly populated (124,753 healthcare) |

### 2.2 Root Cause Analysis

#### Issue 1: `epss_date` is 100% NULL
**Location:** [scripts/data/enrich_cves.py](scripts/data/enrich_cves.py#L316-L320)

```python
# CURRENT CODE (BROKEN) - Line 316-320
batch_df['epss_score'] = batch_df['cve_id'].apply(
    lambda cve: epss_scores.get(cve, {}).get('epss_score', 0.0)
)
batch_df['epss_percentile'] = batch_df['cve_id'].apply(
    lambda cve: epss_scores.get(cve, {}).get('percentile', 0.0)
)
# ❌ Missing: epss_date extraction!
```

**EPSS API Response Structure:**
```json
{
  "CVE-2023-12345": {
    "epss_score": 0.00832,
    "percentile": 0.71234,
    "date": "2026-02-26"  ← This field is NOT being extracted!
  }
}
```

**Fix Required:** Extract `date` field and store in `epss_date` column.

---

#### Issue 2: `healthcare_score` is 100% NULL
**Location:** [scripts/data/enrich_cves.py](scripts/data/enrich_cves.py#L323-L326)

```python
# CURRENT CODE (BROKEN) - Line 323-326
batch_df['is_healthcare'] = batch_df.apply(
    lambda row: int(detect_healthcare_relevance({'description': row['description']}, healthcare_mapper)),
    axis=1
)
# ❌ Only storing boolean flag, not the numerical score!
```

**Available but Unused:**  
The `HealthcareMapper` class has `get_healthcare_score()` method that returns a 0-1 score, but enrichment script only uses boolean detection.

**Fix Required:** Call `healthcare_mapper.get_healthcare_score()` and store result.

---

#### Issue 3: `curated_severity` is 99.99% NULL
**Location:** [scripts/data/enrich_cves.py](scripts/data/enrich_cves.py#L360-L368)

```python
# CURRENT CODE (INCOMPLETE)
batch_df['is_curated'] = batch_df['cve_id'].apply(
    lambda cve_id: int(curated_dataset.is_curated(cve_id))
).astype(int)
# ❌ Only checking if curated, not extracting severity!
```

**Available but Unused:**  
The `curated_dataset.get_breach_info(cve_id)` returns full breach info including severity, but only boolean flag is stored.

**Fix Required:** Extract `severity` field from breach info for curated CVEs.

---

## 3. PROPOSED ARCHITECTURAL IMPROVEMENTS

### 3.1 Option A: Keep Current Architecture (Recommended for Now)

**Rationale:**
- File-based caching is working well for raw API data
- SQLite is efficient for processed/queried data
- Clean separation of concerns: cache = raw, database = enriched
- No need to store duplicate raw JSON in database

**Required Changes:**
- ✅ Fix enrichment pipeline to extract all fields (epss_date, healthcare_score, curated_severity)
- ✅ Add validation tests to ensure all fields populated
- ✅ No schema changes needed (columns already exist!)

**Pros:**
- Minimal changes, low risk
- Preserves working cache system
- Notebooks continue working without changes

**Cons:**
- Raw API data still in files (not queryable via SQL)
- Cache invalidation requires file operations

---

### 3.2 Option B: Add Raw Data Tables (Future Enhancement)

**Proposal:** Add dedicated raw data tables for each API source

```sql
CREATE TABLE raw_epss_responses (
    cve_id TEXT PRIMARY KEY,
    epss_score REAL,
    percentile REAL,
    epss_date TEXT,
    raw_json TEXT,
    fetched_at TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE TABLE raw_nvd_responses (
    cve_id TEXT PRIMARY KEY,
    raw_json TEXT,
    fetched_at TIMESTAMP,
    last_modified TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE TABLE raw_chpl_products (
    product_id TEXT PRIMARY KEY,
    vendor TEXT,
    product_name TEXT,
    certification_date TEXT,
    raw_json TEXT,
    fetched_at TIMESTAMP
);
```

**Migration Strategy:**
1. Create new tables (backwards compatible)
2. Populate from existing cache files
3. Update fetchers to write to both cache files AND database
4. Migrate incrementally (dual-write during transition)
5. Eventually deprecate file cache (optional)

**Pros:**
- Single source of truth (database)
- SQL-queryable raw data
- Better auditability (timestamps, versioning)
- Easier cache invalidation (UPDATE queries)

**Cons:**
- Database size increases significantly
- More complex migration
- Potential performance impact on write operations
- Notebooks might need updates if they access cache files directly

**Recommendation:** Consider for Phase 2 (future), not immediate priority

---

## 4. ACTION PLAN - IMMEDIATE FIXES

### Phase 1: Fix Data Quality Issues (PRIORITY 1)

#### Task 1.1: Fix EPSS Date Extraction
**File:** [scripts/data/enrich_cves.py](scripts/data/enrich_cves.py)  
**Change:**
```python
# Add after line 320
batch_df['epss_date'] = batch_df['cve_id'].apply(
    lambda cve: epss_scores.get(cve, {}).get('date', None)
)
```

**Impact:** 
- Column `epss_date` will be populated with actual dates
- Enables temporal analysis of EPSS score changes
- No breaking changes

---

#### Task 1.2: Fix Healthcare Score Extraction
**File:** [scripts/data/enrich_cves.py](scripts/data/enrich_cves.py)  
**Change:**
```python
# Add after line 326
batch_df['healthcare_score'] = batch_df['description'].apply(
    lambda desc: healthcare_mapper.get_healthcare_score(desc) if pd.notna(desc) else 0.0
)
```

**Impact:**
- Column `healthcare_score` will contain 0-1 relevance scores
- More granular healthcare relevance (not just boolean)
- Better ranking/prioritization
- No breaking changes (is_healthcare flag still works)

---

#### Task 1.3: Fix Curated Severity Extraction
**File:** [scripts/data/enrich_cves.py](scripts/data/enrich_cves.py)  
**Change:**
```python
# Modify lines 360-368
batch_df['is_curated'] = batch_df['cve_id'].apply(
    lambda cve_id: int(curated_dataset.is_curated(cve_id))
).astype(int)

# ADD NEW CODE:
batch_df['curated_severity'] = batch_df['cve_id'].apply(
    lambda cve_id: curated_dataset.get_breach_info(cve_id).get('severity', None)
    if curated_dataset.is_curated(cve_id) else None
)
```

**Impact:**
- Column `curated_severity` populated for ~52 curated CVEs
- Enables severity-based filtering for high-confidence cases
- No breaking changes

---

#### Task 1.4: Update Enrichment Record Building
**File:** [scripts/data/enrich_cves.py](scripts/data/enrich_cves.py) (lines 380-395)  
**Change:** Add missing fields to enrichment record dict
```python
enrichment_records.append({
    'cve_id': row['cve_id'],
    'kev_flag': row['kev_flag'],
    'epss_score': row['epss_score'],
    'epss_percentile': row.get('epss_percentile', 0.0),
    'epss_date': row.get('epss_date', None),  # ← ADD THIS
    'is_healthcare': row['is_healthcare'],
    'healthcare_score': row.get('healthcare_score', 0.0),  # ← ADD THIS
    'is_curated': row['is_curated'],
    'curated_severity': row.get('curated_severity', None),  # ← ADD THIS
    'attack_flag': row.get('attack_flag', 0),
    'attack_technique_count': row.get('attack_technique_count', 0),
    'chpl_flag': row.get('chpl_flag', 0),
    'label': row['label']
})
```

---

### Phase 2: Create Test Suite (PRIORITY 2)

#### Task 2.1: Data Validation Tests
**New File:** `tests/test_enrichment_data_quality.py`

```python
def test_epss_date_not_null():
    """Verify epss_date is populated when epss_score exists"""
    db = CVEDatabase()
    result = db.conn.execute("""
        SELECT COUNT(*) FROM enrichments 
        WHERE epss_score IS NOT NULL AND epss_date IS NULL
    """).fetchone()[0]
    assert result == 0, f"Found {result} records with epss_score but NULL epss_date"

def test_healthcare_score_range():
    """Verify healthcare_score is in valid range [0, 1]"""
    db = CVEDatabase()
    result = db.conn.execute("""
        SELECT COUNT(*) FROM enrichments 
        WHERE healthcare_score < 0 OR healthcare_score > 1
    """).fetchone()[0]
    assert result == 0, f"Found {result} records with invalid healthcare_score"

def test_curated_severity_populated():
    """Verify curated CVEs have severity"""
    db = CVEDatabase()
    result = db.conn.execute("""
        SELECT COUNT(*) FROM enrichments 
        WHERE is_curated = 1 AND curated_severity IS NULL
    """).fetchone()[0]
    # Allow some to be NULL (not all curated entries may have severity)
    assert result < 10, f"Too many curated CVEs missing severity: {result}"
```

---

#### Task 2.2: Cross-Check All Records Test
**New File:** `tests/test_enrichment_comprehensive.py`

```python
def test_all_records_comprehensive():
    """Comprehensive data quality check across ALL 226,320 records"""
    db = CVEDatabase()
    
    # Get full dataset
    df = pd.read_sql("""
        SELECT e.*, c.description 
        FROM enrichments e 
        JOIN cves c ON e.cve_id = c.cve_id
    """, db.conn)
    
    issues = []
    
    # Check 1: EPSS scores should have dates
    epss_no_date = df[(df['epss_score'] > 0) & (df['epss_date'].isna())]
    if len(epss_no_date) > 0:
        issues.append(f"EPSS: {len(epss_no_date)} records have score but no date")
    
    # Check 2: Healthcare flags should align with scores
    healthcare_mismatch = df[
        ((df['is_healthcare'] == 1) & (df['healthcare_score'] <= 0.3)) |
        ((df['is_healthcare'] == 0) & (df['healthcare_score'] > 0.3))
    ]
    if len(healthcare_mismatch) > 0:
        issues.append(f"Healthcare: {len(healthcare_mismatch)} flag/score mismatches")
    
    # Check 3: Curated CVEs should have severity
    curated_no_severity = df[(df['is_curated'] == 1) & (df['curated_severity'].isna())]
    if len(curated_no_severity) > 5:  # Allow some tolerance
        issues.append(f"Curated: {len(curated_no_severity)} missing severity")
    
    assert len(issues) == 0, "\n".join(issues)
```

---

### Phase 3: Re-run Enrichment (PRIORITY 3)

**Command:**
```bash
# Backup current database first
cp data/cve_database.db data/cve_database_backup_$(date +%Y%m%d).db

# Run enrichment with fixed code (test on small batch first)
python scripts/data/enrich_cves.py --limit 1000 --dry-run

# If dry-run looks good, run on full dataset
python scripts/data/enrich_cves.py --batch-size 5000

# Validate results
python -m pytest tests/test_enrichment_data_quality.py -v
```

**Estimated Time:** 
- Small batch (1,000 CVEs): ~2 minutes
- Full dataset (226,320 CVEs): ~60-90 minutes (EPSS API batching)

---

## 5. IMPACT ANALYSIS

### 5.1 Changes to Existing Code

| Component | Files Modified | Impact | Breaking Changes |
|-----------|---------------|--------|------------------|
| Enrichment Pipeline | `scripts/data/enrich_cves.py` | Add 3 field extractions | **None** ✅ |
| Database Schema | None | No schema changes needed | **None** ✅ |
| Notebooks | None | All column names unchanged | **None** ✅ |
| Cache Layer | None | No changes to caching | **None** ✅ |
| API Clients | None | No changes to fetchers | **None** ✅ |

**Guarantee:** No column name changes, no breaking changes to notebooks!

---

### 5.2 Data Changes After Fix

**Before:**
```sql
SELECT cve_id, epss_score, epss_date, healthcare_score, curated_severity 
FROM enrichments LIMIT 5;

CVE-2025-9999 | 0.00063 | NULL | NULL | NULL
CVE-2025-9998 | 0.00032 | NULL | NULL | NULL
```

**After:**
```sql
SELECT cve_id, epss_score, epss_date, healthcare_score, curated_severity 
FROM enrichments LIMIT 5;

CVE-2025-9999 | 0.00063 | 2026-02-26 | 0.15 | NULL
CVE-2025-9998 | 0.00032 | 2026-02-26 | 0.72 | NULL
```

---

### 5.3 Notebook Compatibility

**Existing Notebooks** (will continue working):
```python
# This code in notebooks remains unchanged
df = load_cves_from_db()
df[df['is_healthcare'] == 1]  # Still works
df[df['kev_flag'] == 1]       # Still works
df['epss_score'].mean()       # Still works
```

**New Capabilities Unlocked:**
```python
# NEW: Temporal EPSS analysis (now possible!)
df['epss_date'] = pd.to_datetime(df['epss_date'])
df.groupby('epss_date')['epss_score'].mean().plot()

# NEW: Granular healthcare ranking
df.sort_values('healthcare_score', ascending=False).head(20)

# NEW: Curated severity filtering
df[df['curated_severity'] == 'Critical']
```

---

## 6. RISK ASSESSMENT

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Data loss during re-enrichment | Low | High | Database backup before running |
| EPSS API rate limiting | Medium | Medium | Use existing batch delays (0.5s) |
| Enrichment takes too long | Low | Low | Run in batches, use persistent cache |
| Breaking notebook code | **Very Low** | High | No column name changes guaranteed |
| Missing test coverage | Medium | Medium | Comprehensive test suite beforehand |

---

## 7. TESTING STRATEGY

### 7.1 Unit Tests (Before Deployment)
- ✅ Test EPSS date extraction logic
- ✅ Test healthcare score calculation
- ✅ Test curated severity extraction
- ✅ Test enrichment record building

### 7.2 Integration Tests (After Fix)
- ✅ Run on 100 CVE sample
- ✅ Verify no NULL values for populated fields
- ✅ Cross-check with cache files
- ✅ Validate score ranges (0-1 for healthcare_score)

### 7.3 Regression Tests (Notebooks)
- ✅ Run existing notebook cells
- ✅ Verify all plots still render
- ✅ Check model training still works
- ✅ Ensure API endpoints return same structure

---

## 8. LONG-TERM RECOMMENDATIONS

### 8.1 Monitoring & Observability
- Add data quality metrics dashboard
- Track NULL percentages per column over time
- Alert on sudden drops in field population rates
- Log API fetch success/failure rates

### 8.2 Documentation
- Document expected NULL rates for each column
- Add data dictionary with field descriptions
- Create troubleshooting guide for enrichment failures
- Document cache refresh procedures

### 8.3 Future Enhancements (Not Immediate)
- Consider raw data tables (Option B) for Phase 2
- Implement incremental enrichment (only new CVEs)
- Add enrichment timestamps for debugging
- Create admin UI for cache management

---

## 9. DECISION MATRIX

| Option | Complexity | Risk | Time to Implement | Impact on Notebooks | Recommended? |
|--------|-----------|------|-------------------|---------------------|--------------|
| **Fix enrichment pipeline only** | Low | Low | 2-4 hours | None | ✅ **YES** (Phase 1) |
| **Add raw data tables** | High | Medium | 2-3 days | Minimal | ⏸️ Future (Phase 2) |
| **Rewrite cache layer** | High | High | 1-2 weeks | High | ❌ Not recommended |
| **Do nothing** | None | High | 0 | None | ❌ Data quality issues persist |

---

## 10. IMPLEMENTATION TIMELINE

### Week 1 (Immediate)
- [x] Complete architecture analysis (this document)
- [ ] Implement fixes to `enrich_cves.py`
- [ ] Write comprehensive test suite
- [ ] Test on 1,000 CVE sample

### Week 2
- [ ] Backup production database
- [ ] Run full enrichment (226,320 CVEs)
- [ ] Validate results with tests
- [ ] Verify notebooks still work

### Week 3 (Validation)
- [ ] Run regression tests on all notebooks
- [ ] Document changes in CHANGELOG
- [ ] Update API documentation if needed
- [ ] Monitor for issues

### Future (Phase 2 - Optional)
- [ ] Design raw data table schema
- [ ] Implement migration from file cache to DB
- [ ] Add cache management UI
- [ ] Deprecate file-based cache (optional)

---

## 11. SUMMARY & NEXT STEPS

### Current Problems Identified ✅
1. **`epss_date` is 100% NULL** - EPSS API returns date but enrichment ignores it
2. **`healthcare_score` is 100% NULL** - HealthcareMapper returns score but enrichment ignores it
3. **`curated_severity` is 99.99% NULL** - Curated dataset has severity but enrichment ignores it

### Root Cause ✅
**Enrichment pipeline (`scripts/data/enrich_cves.py`) is not extracting all available fields from API responses and mapper outputs.**

### Solution ✅
**Fix enrichment pipeline to extract 3 missing fields - NO database schema changes needed!**

### Impact ✅
- ✅ No breaking changes to notebooks
- ✅ No column name changes
- ✅ No API changes
- ✅ Unlocks new analytical capabilities

### Recommended Path Forward ✅
**Proceed with Phase 1 fixes immediately - architectural overhaul (raw data tables) can wait for Phase 2.**

---

**Questions for Discussion:**

1. ✅ **Approve Phase 1 fixes?** (Low risk, high value)
2. ⏸️ **Timeline for Phase 2 raw data tables?** (Future consideration)
3. ✅ **Preferred enrichment batch size?** (Current: 5,000 CVEs/batch)
4. ✅ **Acceptable enrichment duration?** (60-90 min for full dataset)

---

**Document Status:** Ready for Review  
**Next Action:** Implement Phase 1 fixes after approval
