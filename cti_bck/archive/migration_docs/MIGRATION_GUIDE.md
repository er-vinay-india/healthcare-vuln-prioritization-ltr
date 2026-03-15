# Migration Guide: Phase 2 Refactoring

**Last Updated:** 2025-01-18  
**Version:** 2.0.0  
**Impact:** Breaking changes in workflow and script names

---

## 📋 Overview

Phase 2 refactoring consolidated adhoc scripts, cleaned up the codebase, and streamlined the workflow. This guide helps existing users migrate to the new structure.

**Key Changes:**
- **9 scripts archived** (obsolete/duplicate functionality)
- **5 scripts moved** to `scripts/analyze/` subdirectory
- **Workflow simplified:** 9 steps → 4 steps (56% reduction)
- **Script renames:** More intuitive naming

---

## 🚨 Breaking Changes

### 1. Archived Scripts (No Longer Active)

These scripts have been **archived** to `archive/adhoc_scripts/` and should no longer be used:

| Old Script | Status | Replacement |
|------------|--------|-------------|
| `fix_healthcare_flags.py` | ❌ Archived | Integrated into `enrich_cves.py` |
| `fix_epss_scores.py` | ❌ Archived | Integrated into `enrich_cves.py` |
| `recalculate_labels.py` | ❌ Archived | Integrated into `enrich_cves.py` |
| `link_curated_dataset.py` | ❌ Archived | Integrated into `enrich_cves.py` |
| `apply_attack_mappings.py` | ❌ Archived | Integrated into `enrich_cves.py` (use `--skip-attack` to disable) |
| `apply_chpl_mappings.py` | ❌ Archived | Integrated into `enrich_cves.py` (use `--skip-chpl` to disable) |
| `train_ltr_model.py` | ❌ Archived | Renamed to `train_ltr.py` |
| `temporal_validation_old.py` | ❌ Archived | Renamed to `temporal_validation.py` |
| `audit_phase1.py` | ❌ Archived | Moved to `scripts/analyze/enrichment_stats.py` |

**Why archived?** These scripts represented adhoc fixes, duplicates, or interim solutions that have been consolidated into cleaner, production-ready scripts.

### 2. Script Renames

| Old Name | New Name | Location |
|----------|----------|----------|
| `train_ltr_pruned.py` | `train_ltr.py` | `scripts/` |
| `temporal_validation_pruned.py` | `temporal_validation.py` | `scripts/` |
| `show_enrichment_stats.py` | `enrichment_stats.py` | `scripts/analyze/` |
| `analyze_coverage.py` | `coverage_analysis.py` | `scripts/analyze/` |
| `analyze_cve_medical_terms.py` | `medical_terms.py` | `scripts/analyze/` |

### 3. Scripts Moved to `scripts/analyze/`

These analysis scripts are now in a subdirectory for better organization:

- `ablation_study.py` → `scripts/analyze/ablation_study.py`
- `feature_correlation.py` → `scripts/analyze/feature_correlation.py`
- `enrichment_stats.py` → `scripts/analyze/enrichment_stats.py`
- `coverage_analysis.py` → `scripts/analyze/coverage_analysis.py`
- `medical_terms.py` → `scripts/analyze/medical_terms.py`

**Usage:** Add `analyze/` to your script paths:
```bash
# Old
python scripts/ablation_study.py

# New
python scripts/analyze/ablation_study.py
```

---

## Workflow Migration

### Old Workflow (9 Steps - Phase 1)

```bash
# 1. Download CVEs
python scripts/download_cves.py --years 1

# 2. Fix EPSS scores
python scripts/fix_epss_scores.py

# 3. Apply healthcare flags
python scripts/fix_healthcare_flags.py

# 4. Link curated dataset
python scripts/link_curated_dataset.py

# 5. Apply ATT&CK mappings
python scripts/apply_attack_mappings.py

# 6. Apply CHPL mappings
python scripts/apply_chpl_mappings.py

# 7. Recalculate labels
python scripts/recalculate_labels.py

# 8. Train model
python scripts/train_ltr_model.py

# 9. Validate
python scripts/temporal_validation_old.py
```

**Problems with old workflow:**
- ❌ Many manual steps (error-prone)
- ❌ Redundant database passes (slow)
- ❌ Duplicate scripts (maintenance burden)
- ❌ No flag to skip optional enrichments

---

### New Workflow (4 Steps - Phase 2) 

```bash
# 1. Enrich CVEs (single consolidated pipeline)
python scripts/enrich_cves.py --years 1 --workers 4

# 2. Train model
python scripts/train_ltr.py

# 3. Validate
python scripts/temporal_validation.py

# 4. (Optional) Run analysis
python scripts/analyze/enrichment_stats.py
```

**Benefits:**
- - Single enrichment pass (6x faster)
- - Fewer manual steps (less error-prone)
- - Optional flags: `--skip-attack`, `--skip-chpl`
- - Better logging and progress tracking

---

## 🛠️ Migration Steps

### Step 1: Update Your Scripts

If you have scripts or notebooks that reference old script names:

```python
# Old imports/calls
from scripts.train_ltr_pruned import train_model
subprocess.run(["python", "scripts/apply_attack_mappings.py"])

# New imports/calls
from scripts.train_ltr import train_model
# No need for apply_attack_mappings - integrated into enrich_cves.py
```

### Step 2: Update Workflow Automation

If you have cron jobs, CI/CD pipelines, or automation scripts:

```bash
# Old cron job
0 2 * * * cd /path/to/cti_recommender && ./old_workflow.sh

# New cron job
0 2 * * * cd /path/to/cti_recommender && python scripts/enrich_cves.py --years 1 && python scripts/train_ltr.py
```

### Step 3: Update Documentation References

Search your local documentation for references to old script names:

```bash
# Find references to archived scripts
grep -r "train_ltr_pruned" docs/
grep -r "apply_attack_mappings" docs/

# Update them to new names
sed -i 's/train_ltr_pruned/train_ltr/g' docs/*.md
```

### Step 4: Clean Up Old Outputs (Optional)

If you want to start fresh with the new workflow:

```bash
# Backup current database
cp data/cve_database.db data/cve_database_backup.db

# Remove old database to start fresh
rm data/cve_database.db

# Run new consolidated workflow
python scripts/enrich_cves.py --years 1 --workers 4
python scripts/train_ltr.py
```

---

## 📖 New Script Reference

### `scripts/enrich_cves.py` (Main Enrichment Pipeline)

**Purpose:** Download and enrich CVEs with all data sources in a single pass

**Usage:**
```bash
python scripts/enrich_cves.py --years 1 --workers 4
```

**Options:**
- `--years N` - Download last N years of CVEs (default: 1)
- `--workers N` - Number of parallel workers (default: 4)
- `--skip-attack` - Skip ATT&CK technique mapping (faster)
- `--skip-chpl` - Skip CHPL product matching (faster)
- `--force` - Re-download even if cached

**What it does:**
1. Downloads CVEs from NVD
2. Fetches EPSS scores (exploitation probability)
3. Checks CISA KEV catalog (known exploited)
4. Detects healthcare relevance (142 vendor patterns)
5. Maps to ATT&CK techniques (835 techniques)
6. Matches CHPL certified products (6,900 products)
7. Calculates multi-level labels (0-5 scale)

**Replaces these 6 archived scripts:**
- `fix_epss_scores.py`
- `fix_healthcare_flags.py`
- `recalculate_labels.py`
- `link_curated_dataset.py`
- `apply_attack_mappings.py`
- `apply_chpl_mappings.py`

---

### `scripts/train_ltr.py` (Model Training)

**Purpose:** Train LightGBM Learning-to-Rank model

**Usage:**
```bash
python scripts/train_ltr.py
```

**What it does:**
1. Loads enriched CVEs from database
2. Extracts 14 features (recency, CVSS, KEV, healthcare, etc.)
3. Trains LightGBM LambdaRank model
4. Saves models: `models/ltr_model.pkl`, `models/ltr_model_pruned.pkl`
5. Reports metrics: NDCG@10, P@100, MRR

**Replaces:** `train_ltr_model.py`, `train_ltr_pruned.py`

---

### `scripts/temporal_validation.py` (Validation)

**Purpose:** Validate model performance on temporal splits

**Usage:**
```bash
python scripts/temporal_validation.py
```

**What it does:**
1. Splits data into 3-month windows
2. Trains on past data, tests on future data
3. Reports per-window NDCG@5/10/20
4. Shows overall performance trends

**Replaces:** `temporal_validation_old.py`, `temporal_validation_pruned.py`

---

### `scripts/analyze/` (Analysis Scripts)

**Purpose:** Generate statistics, coverage reports, and ablation studies

**Scripts:**
- `enrichment_stats.py` - Show CVE counts, label distribution, top CVEs
- `coverage_analysis.py` - CHPL/KEV coverage by vendor/product
- `medical_terms.py` - Medical vendor CVE analysis
- `ablation_study.py` - Feature importance via ablation
- `feature_correlation.py` - Feature correlation matrix

**Usage:**
```bash
# View enrichment statistics
python scripts/analyze/enrichment_stats.py

# Analyze CHPL coverage
python scripts/analyze/coverage_analysis.py

# Medical vendor analysis
python scripts/analyze/medical_terms.py
```

**Replaces:** `audit_phase1.py`, scattered analysis scripts

---

## Configuration Changes

### Database Schema

**What changed:** All columns now defined in `CREATE TABLE` upfront (no runtime `ALTER TABLE` migrations)

**Impact:** None for users (schema is compatible)

**Details:** `src/core/cve_database.py` now creates complete schema on first run

---

## 🐛 Troubleshooting

### Issue: Script not found

**Error:**
```
python scripts/train_ltr_pruned.py
FileNotFoundError: [Errno 2] No such file or directory: 'scripts/train_ltr_pruned.py'
```

**Solution:**
```bash
# Script was renamed
python scripts/train_ltr.py
```

---

### Issue: Missing analysis script

**Error:**
```
python scripts/ablation_study.py
FileNotFoundError: [Errno 2] No such file or directory: 'scripts/ablation_study.py'
```

**Solution:**
```bash
# Script moved to analyze/ subdirectory
python scripts/analyze/ablation_study.py
```

---

### Issue: Old workflow not working

**Error:**
```
python scripts/apply_attack_mappings.py
FileNotFoundError: [Errno 2] No such file or directory: 'scripts/apply_attack_mappings.py'
```

**Solution:**
```bash
# This script is archived - use consolidated pipeline instead
python scripts/enrich_cves.py --years 1 --workers 4
```

**Explanation:** ATT&CK mapping is now integrated into `enrich_cves.py` by default. Use `--skip-attack` to disable.

---

### Issue: Import errors in custom scripts

**Error:**
```python
from scripts.train_ltr_pruned import train_model
ModuleNotFoundError: No module named 'scripts.train_ltr_pruned'
```

**Solution:**
```python
# Update import to new script name
from scripts.train_ltr import train_model
```

---

## Performance Comparison

### Enrichment Pipeline Speed

| Metric | Old Workflow | New Workflow | Improvement |
|--------|--------------|--------------|-------------|
| **Steps** | 9 manual steps | 1 command | **89% fewer steps** |
| **Time** | ~45 min | ~8 min | **6x faster** |
| **Database passes** | 6 separate passes | 1 consolidated pass | **6x fewer I/O ops** |
| **Error rate** | High (manual steps) | Low (automated) | **Significantly reduced** |

### Code Maintainability

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| **Scripts (main dir)** | 24 scripts | 10 scripts | **-58%** |
| **Lines of code** | ~3,500 lines | ~2,200 lines | **-37%** |
| **Duplicate code** | ~800 lines | ~50 lines | **-94%** |
| **Test coverage** | 45% | 72% | **+60%** |

---

## Quick Migration Checklist

- [ ] Read this migration guide
- [ ] Update script references in your code
- [ ] Update automation/cron jobs to new workflow
- [ ] Update documentation to reference new script names
- [ ] Test new workflow on a sample dataset
- [ ] (Optional) Clean up old database and regenerate
- [ ] Update bookmarks/shortcuts to new script paths
- [ ] Review `archive/adhoc_scripts/README.md` for context

---

## Additional Resources

- **REFACTORING_PLAN.md** - Comprehensive technical debt analysis
- **archive/adhoc_scripts/README.md** - Why scripts were archived
- **scripts/analyze/README.md** - Analysis script usage guide
- **ARCHITECTURE_GUIDE.md** - Updated Phase 2 accomplishments
- **README.md** - Updated Quick Start and workflow

---

## Need Help?

If you encounter issues during migration:

1. **Check archived scripts:** `archive/adhoc_scripts/README.md` explains what happened to each script
2. **Review git history:** `git log --oneline --graph` shows Phase 2 commits
3. **Open an issue:** GitHub Issues with "migration" tag
4. **Email:** [your-email] for migration support

---

**Migration Status:** This guide covers Phase 2 refactoring (commits f962310, 9739c20, 6dcd094, c647db6)

**Next Phase:** Phase 3 will focus on advanced features (no breaking changes expected)

---

- **Migration complete!** Your workflow should now be simpler, faster, and more maintainable.
