# Codebase Refactoring Plan
## Technical Debt Analysis & Consolidation Strategy

**Created:** 2026-01-17  
**Goal:** Eliminate adhoc scripts, consolidate database schema, streamline workflows

---

## 🔍 Phase 1: Issues Identified

### A. Database Schema Problems

#### ❌ Current Issues:
1. **Incremental Column Addition**: `attack_technique_count` added via ALTER TABLE migration in runtime
2. **Missing Columns on Creation**: Schema created minimal, then expanded later
3. **Migration Code in Production**: Try/except ALTER TABLE in `_create_tables()` (line 94)

#### ✅ Solution:
- Create complete schema upfront with ALL columns
- Remove migration code from `cve_database.py`
- Add proper migration script IF needed for existing DBs (one-time use)

**Files Affected:**
- `src/core/cve_database.py` (lines 57-130)
- `tests/conftest.py` (test fixtures need update)

---

### B. Adhoc "Fix" Scripts (Should be eliminated)

| Script | Purpose | Problem | Solution |
|--------|---------|---------|----------|
| `fix_healthcare_flags.py` | Re-run healthcare detection | Retroactive fix | Integrate into `enrich_cves.py` |
| `fix_epss_scores.py` | Fix missing EPSS data | Retroactive fix | Integrate into `enrich_cves.py` |
| `recalculate_labels.py` | Recompute labels | Retroactive fix | Integrate into `enrich_cves.py` |
| `link_curated_dataset.py` | Link curated CVEs | One-time sync | Part of enrichment pipeline |
| `apply_attack_mappings.py` | Add ATT&CK data | Retroactive fix | Integrate into `enrich_cves.py` |
| `apply_chpl_mappings.py` | Add CHPL data | Retroactive fix | Integrate into `enrich_cves.py` |
| `rescore_weights.py` | Recalculate scores | Weight tuning test | Archive or integrate into validation |

**Impact:** 7 scripts eliminated → 1 comprehensive enrichment script

---

### C. Duplicate/Similar Scripts

| Category | Scripts | Issue | Solution |
|----------|---------|-------|----------|
| **Training** | `train_ltr_model.py`<br>`train_ltr_pruned.py` | Two versions of same functionality | Keep pruned, remove base |
| **Validation** | `temporal_validation.py`<br>`temporal_validation_pruned.py` | Two versions | Keep pruned, remove base |
| **Analysis** | Multiple coverage/feature analysis scripts | Overlapping functionality | Consolidate into unified analysis module |

**Impact:** ~4 scripts eliminated

---

### D. Workflow Inefficiencies

#### Current Workflow (Fragmented):
```
1. refresh_cves.py       → Fetch CVEs from NVD
2. enrich_cves.py        → Partial enrichment (EPSS, KEV)
3. fix_epss_scores.py    → Fix missing EPSS
4. fix_healthcare_flags.py → Add healthcare flags
5. apply_attack_mappings.py → Add ATT&CK data
6. apply_chpl_mappings.py → Add CHPL data
7. link_curated_dataset.py → Link curated CVEs
8. recalculate_labels.py → Compute final labels
9. train_ltr_model.py    → Train model
```

#### Proposed Workflow (Streamlined):
```
1. refresh_cves.py          → Fetch CVEs from NVD
2. enrich_cves_complete.py  → ALL enrichments in one pass
   ├─ EPSS scores
   ├─ KEV flags
   ├─ Healthcare detection
   ├─ ATT&CK mappings
   ├─ CHPL mappings
   └─ Curated dataset linking
3. train_ltr_pruned.py      → Train model (single version)
4. recommend_cves.py        → Generate recommendations
```

**Impact:** 9 steps → 4 steps

---

## 📋 Phase 2: Consolidation Plan

### Phase 2.1: Database Schema Fix ⚡
**Priority:** Critical  
**Risk:** Low (well-tested schema)  
**Time:** 30 mins

**Actions:**
1. Update `src/core/cve_database.py`:
   - Add ALL columns in initial CREATE TABLE (including `attack_technique_count`)
   - Remove ALTER TABLE migration code
   - Clean up comments

2. Update `tests/conftest.py`:
   - Match test fixtures to new schema

3. Test:
   - Delete test database, run tests
   - Verify all columns present on fresh creation
   - Commit

**Files Modified:**
- `src/core/cve_database.py`
- `tests/conftest.py`

---

### Phase 2.2: Enrichment Pipeline Consolidation 🔄
**Priority:** High  
**Risk:** Medium (complex logic)  
**Time:** 2 hours

**Actions:**
1. Create `scripts/enrich_cves_complete.py`:
   - Copy base from `enrich_cves.py`
   - Integrate healthcare detection (from `fix_healthcare_flags.py`)
   - Integrate ATT&CK mapping (from `apply_attack_mappings.py`)
   - Integrate CHPL mapping (from `apply_chpl_mappings.py`)
   - Integrate curated dataset linking (from `link_curated_dataset.py`)
   - Integrate label calculation (from `recalculate_labels.py`)
   - Add `--skip-*` flags for selective enrichment

2. Test incremental enrichment:
   - Run on small sample (100 CVEs)
   - Verify all enrichments applied
   - Check database state
   - Run full enrichment
   - Commit

3. Archive old scripts:
   - Move to `archive/adhoc_scripts/`
   - Add README explaining why archived

**Files Created:**
- `scripts/enrich_cves_complete.py`

**Files Archived:**
- `scripts/fix_healthcare_flags.py`
- `scripts/fix_epss_scores.py`
- `scripts/recalculate_labels.py`
- `scripts/link_curated_dataset.py`
- `scripts/apply_attack_mappings.py`
- `scripts/apply_chpl_mappings.py`

---

### Phase 2.3: Training Script Cleanup 🧹
**Priority:** Medium  
**Risk:** Low  
**Time:** 15 mins

**Actions:**
1. Rename `train_ltr_pruned.py` → `train_ltr.py`
2. Archive `train_ltr_model.py` → `archive/adhoc_scripts/`
3. Update references in docs
4. Test training pipeline
5. Commit

**Files Modified:**
- `scripts/train_ltr_pruned.py` (renamed)

**Files Archived:**
- `scripts/train_ltr_model.py`

---

### Phase 2.4: Validation Script Cleanup 🧹
**Priority:** Medium  
**Risk:** Low  
**Time:** 15 mins

**Actions:**
1. Rename `temporal_validation_pruned.py` → `temporal_validation.py`
2. Archive old `temporal_validation.py` → `archive/adhoc_scripts/`
3. Update references
4. Test validation
5. Commit

**Files Modified:**
- `scripts/temporal_validation_pruned.py` (renamed)

**Files Archived:**
- `scripts/temporal_validation.py` (old version)

---

### Phase 2.5: Analysis Scripts Consolidation 📊
**Priority:** Low  
**Risk:** Low  
**Time:** 1 hour

**Actions:**
1. Review analysis scripts:
   - `analyze_coverage.py`
   - `analyze_cve_medical_terms.py`
   - `feature_correlation.py`
   - `ablation_study.py`
   - `show_enrichment_stats.py`

2. Consolidate into `scripts/analyze/`:
   - `coverage_analysis.py`
   - `feature_analysis.py`
   - `model_analysis.py` (ablation, stats)

3. Test all analysis functions
4. Commit

**Files Reorganized:**
- Create `scripts/analyze/` directory
- Move/consolidate analysis scripts

---

### Phase 2.6: Documentation Update 📝
**Priority:** High  
**Risk:** None  
**Time:** 30 mins

**Actions:**
1. Update `README.md`:
   - Remove references to archived scripts
   - Update workflow documentation
   - Simplify quick start guide

2. Update `ARCHITECTURE_GUIDE.md`:
   - Document consolidated enrichment pipeline
   - Update database schema documentation

3. Create `MIGRATION_GUIDE.md`:
   - For users with existing databases
   - How to apply schema updates

4. Commit

---

## 📊 Impact Summary

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Scripts in `scripts/`** | 24 | 12 | -50% |
| **Workflow Steps** | 9 | 4 | -56% |
| **Adhoc Fix Scripts** | 7 | 0 | -100% |
| **Duplicate Scripts** | 4 | 0 | -100% |
| **Database Migrations in Code** | 1 | 0 | -100% |
| **Lines of Code** | ~8000 | ~6000 | -25% |

---

## ✅ Testing Strategy

### After Each Phase:
1. **Unit Tests:** `pytest tests/` (49/53 passing target)
2. **Smoke Tests:** Run key workflows on small dataset
3. **Integration Tests:** Full pipeline on 1000 CVEs
4. **Database Validation:** Check schema, counts, data integrity

### Before Final Commit:
1. Full test suite
2. End-to-end workflow test
3. Docker build and run
4. Documentation review

---

## 🎯 Success Criteria

- [ ] All adhoc "fix_*" scripts archived
- [ ] Single comprehensive enrichment pipeline
- [ ] No ALTER TABLE in production code
- [ ] All tests passing (49/53 minimum)
- [ ] Documentation updated
- [ ] Docker build succeeds
- [ ] <30 minute fresh setup time

---

## 📅 Execution Timeline

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| 2.1 - Schema Fix | 30 min | None |
| 2.2 - Enrichment | 2 hours | Phase 2.1 |
| 2.3 - Training | 15 min | Phase 2.2 |
| 2.4 - Validation | 15 min | Phase 2.2 |
| 2.5 - Analysis | 1 hour | Phase 2.2 |
| 2.6 - Docs | 30 min | All previous |
| **Total** | **~5 hours** | Sequential |

---

## 🚀 Let's Begin!

Ready to start with **Phase 2.1: Database Schema Fix**?
