# README Corrections - VERIFIED DATA

**Date:** March 8, 2026  
**Source:** Direct database queries + evaluation outputs  
**Status:** ✅ All numbers verified against actual data

---

## Summary of Changes

### ❌ FAKE DATA (Previous README)

| Metric | FAKE Value | Reality |
|--------|------------|---------|
| **Total CVEs** | 176,332 | **226,320 CVEs** |
| **Date Range** | 2015-2025 | **2018-2025** |
| **Healthcare Coverage** | 98K CVEs (55.5%) | **822 CVEs (0.36%)** |
| **NDCG@10** | 1.0000 | **0.203** (production) |
| **Precision@20** | 1.0000 | **0.220** (production) |
| **Features** | 16 features | **27 features** (production) |

---

## ✅ VERIFIED ACTUAL DATA

### Dataset Statistics (from database)

```sql
-- Query: SELECT COUNT(*), MIN(published), MAX(published) FROM cves;
Total CVEs: 226,320
Date range: 2018-01-01 to 2025-12-31
```

**Year-by-year breakdown:**
- 2018: 18,154 CVEs
- 2019: 18,938 CVEs
- 2020: 19,222 CVEs
- 2021: 21,950 CVEs
- 2022: 26,431 CVEs
- 2023: 30,949 CVEs
- 2024: 40,704 CVEs
- 2025: 49,972 CVEs

**Train/Test Split:**
- Training: 2018-2024 = 176,348 CVEs
- Test: 2025 = 49,972 CVEs

### Data Enrichment Coverage (from enrichments table)

| Source | CVE Count | Coverage % | Notes |
|--------|-----------|------------|-------|
| **NVD** | 226,320 | 100.0% | Base data |
| **EPSS** | 226,320 | 100.0% | Exploitation probability |
| **CISA KEV** | 1,179 | 0.52% | Known exploited |
| **MITRE ATT&CK** | 83,574 | 36.9% | Adversarial techniques |
| **CHPL** | 5,107 | 2.26% | Healthcare certifications |
| **Healthcare Flags** | 822 | 0.36% | ⚠️ NOT 55.5%! |

### Model Performance (from outputs/production_comparison_20260303_124625.csv)

**Production Model (27 leakage-free features):**
- NDCG@5: 0.187 (vs CVSS 0.142, +31.7%)
- NDCG@10: 0.203 (vs CVSS 0.156, +30.1%)
- **NDCG@20: 0.220** (vs CVSS 0.171, **+28.7%**)
- NDCG@50: 0.251 (vs CVSS 0.201, +24.9%)

**Healthcare-Specific Performance:**
- Precision@20: 0.342 (vs CVSS 0.185, +84.9%)
- Recall@50: 0.428 (vs CVSS 0.267, +60.3%)
- NDCG@20: 0.276 (vs CVSS 0.194, +42.3%)

**Retrospective Model (47 features with KEV/EPSS - temporal leakage):**
- NDCG@20: 0.990 (⚠️ NOT production performance!)
- CVSS baseline: 0.890
- Improvement: +11.2%

### Feature Set (27 production features)

**Source:** CHAPTER5_FIX_RECOMMENDATIONS.md

1. **CVSS Metrics (6)**: cvss_score, attack_vector, privilege_required, user_interaction, scope, impact_score
2. **Temporal (2)**: days_since_published, is_recent
3. **Vendor (3)**: vendor_exploitation_history, vendor_patch_velocity, affected_product_count
4. **CWE Patterns (4)**: cwe_id, cwe_category, cwe_top25_flag, historical_cwe_exploitation_rate
5. **Description NLP (5)**: description_length, contains_rce_keywords, contains_privilege_keywords, technical_complexity_score, attack_surface_indicators
6. **ATT&CK Mappings (4)**: attack_technique_count, attack_tactic_count, has_initial_access, has_privilege_escalation
7. **Healthcare Context (2)**: is_healthcare, chpl_certified_flag
8. **Interaction Terms (1)**: healthcare_x_cvss

**Excluded (temporal leakage):** kev_flag, epss_score, epss_percentile

---

## Critical Insight: Production vs Retrospective Models

### Why the huge gap?

**Retrospective:** NDCG@20 = 0.990 (uses KEV/EPSS as features)  
**Production:** NDCG@20 = 0.220 (leakage-free features only)  
**Gap:** 0.770 points (77.8% difference)

### This gap exists because:

1. **Temporal leakage:** Retrospective models "cheat" by using exploitation evidence (KEV/EPSS) that doesn't exist when a CVE is first published
2. **Production reality:** Real-world systems must rank CVEs IMMEDIATELY at publication time
3. **Cold-start problem:** No exploitation data exists for new CVEs
4. **Sparse healthcare flags:** Only 0.36% of CVEs have healthcare context (not 55.5%)

### For your thesis abstract:

✅ **Use production model numbers:** NDCG@20 = 0.220, +28.7% improvement  
❌ **Don't use retrospective:** NDCG@20 = 0.990 (temporal leakage, not realistic)

---

## Verification Queries Used

```bash
# Total CVEs and date range
sqlite3 data/cve_database.db "SELECT COUNT(*), MIN(published), MAX(published) FROM cves;"
# Result: 226320|2018-01-01T00:29:00.213|2025-12-31T23:15:42.413

# Year-by-year breakdown
sqlite3 data/cve_database.db "SELECT strftime('%Y', published) as year, COUNT(*) FROM cves GROUP BY year ORDER BY year;"

# Enrichment coverage
sqlite3 data/cve_database.db "SELECT 
  COUNT(*) as total,
  SUM(kev_flag) as kev_count,
  SUM(is_healthcare) as healthcare_count,
  SUM(attack_flag) as attack_count,
  SUM(chpl_flag) as chpl_count,
  SUM(CASE WHEN epss_score IS NOT NULL THEN 1 ELSE 0 END) as epss_count,
  ROUND(100.0 * SUM(is_healthcare) / COUNT(*), 2) as healthcare_pct
FROM enrichments;"
# Result: 226320|1179|822|83574|5107|226320|0.36
```

---

## Files Updated

1. **README.md** - All sections corrected with verified data
   - Key Results table
   - Data Enrichment Coverage table
   - Feature Engineering section
   - Performance Metrics section
   - Train/Test Split numbers

---

## Remaining Action Items for Your Thesis

1. **Update abstract** with production model numbers (NDCG@20 = 0.220, +28.7%)
2. **Emphasize weak supervision** methodology in abstract (KEV=2, ATT&CK/Healthcare=1)
3. **Mention dataset scale** accurately (226,320 CVEs, 2018-2025)
4. **Highlight healthcare coverage** realistically (822 CVEs = 0.36%, not 55.5%)
5. **Add LambdaMART precision** (not just "LambdaRank" - it's LightGBM LambdaMART)
6. **Include temporal validation** strategy to show rigor
7. **Acknowledge retrospective vs production** gap to show methodological sophistication

---

## Why This Matters for Thesis Defense

**Examiners will:**
1. ✅ Check if numbers are internally consistent
2. ✅ Verify dataset scale claims against standard benchmarks
3. ✅ Question "too perfect" metrics (NDCG=1.0 raises red flags)
4. ✅ Test understanding of temporal leakage issues
5. ✅ Ask why healthcare coverage is different from claims

**With corrected data you can:**
1. ✅ Defend all numbers with database queries
2. ✅ Show methodological rigor (avoiding leakage)
3. ✅ Demonstrate realistic performance expectations
4. ✅ Explain the gap between retrospective and production models
5. ✅ Highlight stronger healthcare-specific performance (+42.3% vs +28.7% overall)
