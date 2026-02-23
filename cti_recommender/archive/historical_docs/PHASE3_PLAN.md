# Phase 3 Implementation Plan

## Research Objective Completion Checklist

### [OK] COMPLETED (Phase 1-2)
- [x] NVD data collection (226,320 CVEs, 2018-2025)
- [x] CISA KEV integration (1,161 CVEs)
- [x] Healthcare identification (125,606 CVEs)
- [x] Multi-level labeling (0-5 scale)
- [x] Feature engineering (15 features)
- [x] XGBoost LTR model (NDCG@10=1.0)
- [x] Production recommender API

### [WARN] MISSING (Phase 3 - CRITICAL)
- [ ] **MITRE ATT&CK mapping** (Research Objective #1)
- [ ] **CHPL medical device flags** (Research Objective #2)
- [ ] **Fix EPSS scores** (Currently 0 in database)
- [ ] **Link curated dataset** (52 CVEs not flagged)
- [ ] **Ablation study** (Research Objective #4)
- [ ] **Temporal analysis** (Research Question #3)

---

## Phase 3: Task Breakdown

### Task 3.1: Fix EPSS Integration (30 min)
**Problem:** EPSS API called but 0 scores saved to database  
**Priority:** HIGH (affects model features)

**Steps:**
1. Debug why EPSS scores = 0 in enrichments table
2. Check EPSS cache: `data_cache/epss_*.pkl`
3. Re-run enrichment with EPSS fix
4. Validate: Should have ~177K CVEs with EPSS > 0

**Expected:** 78% coverage (~177K CVEs with EPSS scores)

---

### Task 3.2: MITRE ATT&CK Integration (2-3 hours)
**Research Gap:** "Few works robustly map CVEs to ATT&CK techniques"  
**Priority:** HIGH (core research contribution)

**Implementation:**
```python
# src/analysis/attack_mapper.py
class AttackMapper:
    def __init__(self):
        # Load ATT&CK Enterprise matrix
        # Parse techniques, tactics, procedures
        
    def map_cve_to_techniques(self, description, cwe_ids):
        # 1. Keyword matching (technique names/aliases)
        # 2. CWE-to-CAPEC-to-ATT&CK mapping
        # 3. Return matched technique IDs
```

**Integration points:**
- `scripts/enrich_cves.py` - Add ATT&CK mapping step
- Database: Add `attack_techniques` TEXT column (JSON array)
- Features: `attack_technique_count`, `attack_tactic_diversity`

**Expected:** 15-20% of CVEs mapped to ATT&CK techniques

---

### Task 3.3: CHPL Medical Device Flags (1-2 hours)
**Research Objective:** "Identify healthcare scope using vendor/product heuristics"  
**Priority:** MEDIUM (enhances healthcare detection)

**Implementation:**
```python
# src/analysis/chpl_mapper.py
class CHPLMapper:
    def __init__(self, api_key):
        # Fetch CHPL certified products
        # Cache vendor/product lists
        
    def check_chpl_match(self, cve_description, cpe_list):
        # Match against 6,900 CHPL products
        # Return True if medical device
```

**Previous work found:** Code exists in `archive/` from earlier implementation  
**Action:** Port to new structure, integrate into enrichment pipeline

**Expected:** 500-1,000 CVEs flagged as certified medical devices

---

### Task 3.4: Link Curated Dataset (30 min)
**Current:** 52 curated healthcare breaches exist but `is_curated=0` for all CVEs  
**Priority:** MEDIUM (improves training labels)

**Steps:**
1. Load `data/healthcare_breaches.json`
2. Update enrichments: `is_curated=1` for 52 CVEs
3. Update labels: Some may become L4/L5

**Expected:** 52 CVEs flagged, potential label upgrades

---

### Task 3.5: Ablation Study (1 hour)
**Research Objective:** "Evaluate using ablation studies"  
**Priority:** HIGH (validates research contribution)

**Experiments:**
```python
# Compare model variants
1. Baseline: CVSS only
2. + KEV flags
3. + Healthcare detection
4. + EPSS scores
5. + ATT&CK mapping
6. + CHPL flags
7. Full model (all features)

# Metrics per variant
- NDCG@10
- Precision@20
- Healthcare recall
```

**Outputs:**
- `outputs/ablation_results.csv`
- Feature importance comparison
- Performance delta analysis

---

### Task 3.6: Temporal Analysis (2 hours)
**Research Question:** "How does multi-source scoring improve recommendations?"  
**Priority:** MEDIUM (research paper material)

**Analysis:**
1. **Exploit timeline:** KEV date - CVE publish date
2. **Zero-day detection:** CVEs exploited before public disclosure
3. **Trend analysis:** Healthcare CVEs by year/quarter
4. **Vendor response time:** Patch availability patterns

**Outputs:**
- `notebooks/temporal_analysis.ipynb`
- Visualization: Exploit timeline distributions
- Key findings for paper

---

## Execution Order

### Week 1: Critical Fixes
1. [OK] Task 3.1: Fix EPSS (30 min) - **DO FIRST**
2. [OK] Task 3.4: Link curated dataset (30 min)
3. [OK] Task 3.2: ATT&CK integration (3 hours)

### Week 2: Enhancements
4. [OK] Task 3.3: CHPL integration (2 hours)
5. [OK] Task 3.5: Ablation study (1 hour)
6. [OK] Task 3.6: Temporal analysis (2 hours)

---

## Success Criteria

### Data Completeness
- EPSS: ~177K CVEs with scores (78% coverage)
- ATT&CK: ~45K CVEs mapped (20% coverage)
- CHPL: ~1K CVEs flagged (medical devices)
- Curated: 52 CVEs linked

### Research Validation
- Ablation study shows each feature contribution
- ATT&CK mapping demonstrates novel contribution
- Temporal analysis reveals exploit patterns
- Model performance maintained/improved after additions

### Publication Ready
- All research objectives addressed
- Comprehensive evaluation completed
- Novel contributions validated
- Reproducible results documented

---

## Estimated Total Time: 8-10 hours

**Priority Order for Today:**
1. Fix EPSS (critical model feature)
2. ATT&CK integration (core research gap)
3. Ablation study (validates contribution)

**Recommendation:** Start with EPSS fix, then ATT&CK integration.
