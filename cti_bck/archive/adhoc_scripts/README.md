# Archived Adhoc Scripts

**Date Archived:** 2026-01-17  
**Reason:** Consolidated into main enrichment pipeline  
**Refactoring Phase:** Phase 2.2 - Enrichment Pipeline Consolidation

---

## Why These Scripts Were Archived

These scripts were created as **adhoc fixes** to retroactively add missing enrichment data to the database. They were necessary during development when the enrichment pipeline was incomplete, but are now obsolete because:

1. **Main enrichment pipeline now includes ALL enrichments**
2. **No need for retroactive fixes** - fresh enrichments include everything
3. **Reduced maintenance burden** - one script instead of seven
4. **Simplified workflow** - 4 steps instead of 9

---

## Archived Scripts

### `fix_healthcare_flags.py`
**Purpose:** Retroactively add healthcare flags to existing CVEs  
**Now Integrated:** `scripts/enrich_cves.py` - healthcare detection via `HealthcareMapper`

### `fix_epss_scores.py`
**Purpose:** Fix missing EPSS scores from incomplete enrichment  
**Now Integrated:** `scripts/enrich_cves.py` - EPSS fetching via `EPSSFetcher`

### `recalculate_labels.py`
**Purpose:** Recompute multi-level labels after enrichment changes  
**Now Integrated:** `scripts/enrich_cves.py` - label calculation via `compute_multi_level_labels()`

### `link_curated_dataset.py`
**Purpose:** Link healthcare breach CVEs to enrichments table  
**Now Integrated:** `scripts/enrich_cves.py` - curated dataset via `HealthcareCuratedDataset`

### `apply_attack_mappings.py`
**Purpose:** Add ATT&CK technique mappings to CVEs  
**Now Integrated:** `scripts/enrich_cves.py` - ATT&CK mapping via `AttackMapper` (use `--skip-attack` to disable)

### `apply_chpl_mappings.py`
**Purpose:** Add CHPL (Certified Health IT Product List) flags  
**Now Integrated:** `scripts/enrich_cves.py` - CHPL mapping via `CHPLMapper` (use `--skip-chpl` to disable)

### `rescore_weights.py`
**Purpose:** Experimental script for weight calibration testing  
**Status:** Not part of main workflow - kept for reference

---

## Migration Guide

### Old Workflow (9 Steps):
```bash
# Step 1: Fetch CVEs
python scripts/refresh_cves.py

# Step 2-8: Multiple enrichment scripts (adhoc fixes)
python scripts/enrich_cves.py          # Partial enrichment (KEV, EPSS)
python scripts/fix_epss_scores.py      # Fix EPSS
python scripts/fix_healthcare_flags.py # Add healthcare flags
python scripts/apply_attack_mappings.py --live
python scripts/apply_chpl_mappings.py  # Add CHPL flags
python scripts/link_curated_dataset.py # Link curated data
python scripts/recalculate_labels.py   # Compute labels

# Step 9: Train model
python scripts/train_ltr_pruned.py
```

### New Workflow (4 Steps):
```bash
# Step 1: Fetch CVEs
python scripts/refresh_cves.py

# Step 2: Complete enrichment (ALL in one pass)
python scripts/enrich_cves.py
# Includes: KEV, EPSS, healthcare, ATT&CK, CHPL, curated, labels

# Step 3: Train model
python scripts/train_ltr.py

# Step 4: Generate recommendations
python scripts/recommend_cves.py
```

---

## Using the New Enrichment Script

### Basic usage:
```bash
python scripts/enrich_cves.py
```

### With options:
```bash
# Test on small sample
python scripts/enrich_cves.py --limit 1000

# Skip ATT&CK mapping (if mapper unavailable)
python scripts/enrich_cves.py --skip-attack

# Skip CHPL mapping (if API unavailable)
python scripts/enrich_cves.py --skip-chpl

# Dry run (show plan without changes)
python scripts/enrich_cves.py --dry-run

# Validate existing enrichment
python scripts/enrich_cves.py --validate-only
```

---

## When to Use These Archived Scripts

**Short answer: Never.**

These scripts are preserved for:
- **Historical reference** - understand how the system evolved
- **Debugging** - if you need to inspect old enrichment logic
- **Emergency recovery** - if main pipeline fails and you need targeted fixes

For normal operations, use `scripts/enrich_cves.py` which includes all functionality.

---

## Technical Details

### What Changed

**Before (adhoc scripts):**
- Healthcare detection: Separate `fix_healthcare_flags.py`
- ATT&CK mapping: Separate `apply_attack_mappings.py`
- CHPL mapping: Separate `apply_chpl_mappings.py`
- Label calculation: Separate `recalculate_labels.py`
- Curated linking: Separate `link_curated_dataset.py`

**After (consolidated pipeline):**
- All enrichments in `scripts/enrich_cves.py`
- Batch processing for efficiency
- Transactional safety (rollback on error)
- Progress tracking and validation
- Optional components (--skip-* flags)

### Database Schema

All enrichment fields are now created upfront in the database schema:
- `kev_flag` - KEV catalog membership
- `epss_score`, `epss_percentile` - EPSS scores
- `is_healthcare`, `healthcare_score` - Healthcare relevance
- `attack_flag`, `attack_technique_count` - ATT&CK mappings
- `chpl_flag` - CHPL product matching
- `is_curated`, `curated_severity` - Curated breach data
- `label` - Multi-level priority label (0-5)

No retroactive column additions needed!

---

## References

- **Refactoring Plan:** `REFACTORING_PLAN.md`
- **Main Enrichment Script:** `scripts/enrich_cves.py`
- **Architecture Guide:** `ARCHITECTURE_GUIDE.md`
- **Phase 2.2 Commit:** [Git commit reference]

---

## Questions?

If you need to use these archived scripts or have questions about the consolidation, refer to:
1. `REFACTORING_PLAN.md` - Complete consolidation strategy
2. `scripts/enrich_cves.py` - Source code with all functionality
3. Git history - Trace evolution of enrichment pipeline
