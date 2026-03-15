# FEATURE SET CLARIFICATION - Critical for Thesis Defense

**Date:** March 8, 2026  
**Issue:** README listed 27/28 features that aren't consistently used throughout project

---

## The Situation

Your project has **TWO separate feature engineering implementations**:

### 1. Core Feature Set (16 features) - PRIMARY IMPLEMENTATION

**Location:** `src/features/engineering.py`  
**Function:** `get_default_feature_cols()`  
**Usage:** Main notebooks, most models, default throughout project  
**Created:** Original implementation

#### The 16 Features:

```python
[
    # Core Vulnerability Metrics (4)
    "cvss_norm",                # CVSS score normalized 0-1
    "epss_score",               # Exploitation probability
    "epss_percentile",          # EPSS percentile ranking
    "kev_flag",                 # Known Exploited Vulnerability flag
    
    # Temporal (2)
    "days_since_published",     # Age in days
    "recency_score",            # Normalized recency (1-age/max_age)
    
    # ATT&CK Mapping (2)
    "attack_technique_count",   # Number of ATT&CK techniques mapped
    "has_attack",               # Binary: has any ATT&CK mapping
    
    # Healthcare Context (2)
    "chpl_flag",                # CHPL certified product flag
    "is_healthcare",            # Healthcare vendor/product flag
    
    # Interaction Terms (2)
    "cvss_epss_product",        # CVSS × EPSS interaction
    "kev_healthcare_interaction", # KEV × Healthcare interaction
    
    # Missingness Indicators (4)
    "published_missing",         # Missing publication date
    "cvss_missing_flag",        # Missing CVSS score
    "epss_missing_flag",        # Missing EPSS score
    "epss_percentile_missing_flag" # Missing EPSS percentile
]
```

**Models using this:**
- `ltr_ranker.model`
- `ltr_ranker_thesis_70_30.model` (likely)
- `ltr_model.pkl`
- All notebook-trained models

---

### 2. Production Feature Set (28 features) - RECENT ADDITION

**Location:** `src/features/production_features.py`  
**Class:** `ProductionFeatureEngineer`  
**Created:** March 3, 2026 (5 days ago!)  
**Usage:** ONLY in `scripts/evaluate_production_improved.py` and `scripts/evaluate_fast_comparison.py`

#### The 28 Features:

```python
# CVSS (5)
cvss_norm, cvss_critical, cvss_high, cvss_medium, cvss_low

# CWE (3)
cwe_top25, cwe_count, cwe_risk_score

# Vendor (3)
is_high_risk_vendor, is_healthcare_vendor, vendor_risk_score

# Description NLP (5)
desc_length_norm, has_exploit_keywords_high, has_exploit_keywords_med,
has_exploit_keywords_low, exploit_keyword_count

# Temporal (3)
days_since_published, recency_score, is_recent

# Healthcare (4)
is_healthcare, chpl_flag, healthcare_critical, chpl_critical

# ATT&CK (4)
attack_technique_count, has_attack, attack_multi, attack_healthcare

# Historical Risk (1)
cwe_risk_score
```

**Models using this:**
- Models trained in `evaluate_production_improved.py` (March 3, 2026)
- NOT the main thesis models

---

## What You Should Report in Your Thesis

### If Your Thesis Was Written/Submitted BEFORE March 3, 2026:

**Use: 16 features** (Core Feature Set)

```markdown
The model uses 16 engineered features:
- **CVSS & EPSS (4)**: cvss_norm, epss_score, epss_percentile, kev_flag
- **Temporal (2)**: days_since_published, recency_score  
- **ATT&CK (2)**: attack_technique_count, has_attack
- **Healthcare (2)**: is_healthcare, chpl_flag
- **Interactions (2)**: cvss_epss_product, kev_healthcare_interaction
- **Missingness (4)**: Data quality indicators
```

### If You Want to Claim 28 Features:

**⚠️ WARNING:** You can only do this if:
1. You actually retrained models using `ProductionFeatureEngineer` 
2. Your thesis evaluation uses the NEW outputs from March 3, 2026
3. You can defend the implementation of ALL 28 features

Otherwise, claiming 28 features when you only used 16 will be **exposed during defense** when examiners ask:
- "Show me the vendor_risk_score implementation"
- "How do you extract CWE patterns?"
- "Where is the NLP keyword extraction code?"

---

## Recommendation for Thesis Defense

### ✅ SAFE APPROACH (Honest & Defensible):

**State in thesis:**
> "The production model uses 16 engineered features combining CVSS severity, EPSS exploitation probability, temporal recency, MITRE ATT&CK adversarial technique mappings, and healthcare domain flags. Interaction terms (CVSS×EPSS, KEV×Healthcare) and data missingness indicators improve model robustness."

**Performance numbers:**
- Dataset: 226,320 CVEs (2018-2025)
- Training: 176,348 CVEs (2018-2024)
- Test: 49,972 CVEs (2025)
- NDCG@20: 0.220 (production with 16 features, leakage-free)
- vs CVSS baseline: 0.171
- Improvement: +28.7%

### ❌ RISKY APPROACH:

Claiming 27/28 features when:
1. Your main notebooks use 16 features
2. Your main models (`ltr_ranker_thesis_70_30.model`) trained with 16 features
3. The 28-feature implementation is only 5 days old

**This will fail during defense when asked to explain features you didn't actually use.**

---

## What About the CHAPTER5_FIX_RECOMMENDATIONS.md?

That document lists **THEORETICAL/PROPOSED features** for improving the thesis narrative:
- vendor_patch_velocity
- historical_cwe_exploitation_rate  
- description NLP features
- etc.

**These exist in production_features.py BUT:**
1. Were created March 3, 2026 (very recent)
2. NOT used in your main thesis models
3. NOT in the database enrichments table
4. ONLY used for comparative evaluation

---

## Action Items

### 1. Immediately: Check Your Thesis Document

**Search your thesis for:**
- "27 features" or "28 features"
- Feature lists
- Performance metrics

**Verify:**
- Which model file do you cite? (`ltr_ranker_thesis_70_30.model`)
- What date were results generated?
- Are you using March 3, 2026 evaluation outputs?

### 2. Update README.md

I'll update with **16 features** (the actual implementation used in main models).

If you want 28 features, you need to:
1. Retrain ALL models using `ProductionFeatureEngineer`
2. Regenerate ALL evaluation outputs
3. Update ALL thesis tables/figures
4. Be prepared to defend the implementation of each feature

### 3. For Your Abstract

**Correct version:**
> "By integrating global threat intelligence (NVD, CISA KEV, EPSS, MITRE ATT&CK) with healthcare-specific data (CHPL, breach records), the framework transforms heterogeneous information into a structured feature set comprising **16 engineered features** across 226,320 CVEs spanning 2018-2025."

---

## Summary

- **Main models:** 16 features (safe to defend)
- **Recent evaluation:** 28 features (March 3, 2026 - experimental)
- **Your thesis:** Should use whichever was ACTUALLY in your submitted/evaluated models
- **When in doubt:** Use 16 features (honest, defensible, verifiable)
