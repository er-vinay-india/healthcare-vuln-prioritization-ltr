# Quick Reference: NULL Columns Fix

## 🎯 THE ISSUE (In 30 Seconds)

**Problem:** 3 columns are 100% NULL in your database:
- `epss_date` (226,320 NULL / 100%)
- `healthcare_score` (226,320 NULL / 100%)  
- `curated_severity` (226,268 NULL / 99.99%)

**Root Cause:** Enrichment script extracts `epss_score` but ignores `epss_date` from same API response. Similar issue for healthcare and curated data.

**Solution:** Add 6 lines of code to extract the missing fields. NO database changes needed!

---

## 🔧 THE FIX (Copy-Paste Ready)

### File: `scripts/data/enrich_cves.py`

#### Fix 1: After line 320, add:
```python
batch_df['epss_date'] = batch_df['cve_id'].apply(
    lambda cve: epss_scores.get(cve, {}).get('date', None)
)
```

#### Fix 2: After line 326, add:
```python
batch_df['healthcare_score'] = batch_df['description'].apply(
    lambda desc: healthcare_mapper.get_healthcare_score(desc) if pd.notna(desc) else 0.0
)
```

#### Fix 3: After line 368, add:
```python
batch_df['curated_severity'] = batch_df['cve_id'].apply(
    lambda cve_id: curated_dataset.get_breach_info(cve_id).get('severity', None)
    if curated_dataset.is_curated(cve_id) else None
)
```

#### Fix 4: In enrichment_records.append() (lines 380-395), add 3 fields:
```python
enrichment_records.append({
    'cve_id': row['cve_id'],
    'kev_flag': row['kev_flag'],
    'epss_score': row['epss_score'],
    'epss_percentile': row.get('epss_percentile', 0.0),
    'epss_date': row.get('epss_date', None),                    # ← ADD THIS
    'is_healthcare': row['is_healthcare'],
    'healthcare_score': row.get('healthcare_score', 0.0),       # ← ADD THIS
    'is_curated': row['is_curated'],
    'curated_severity': row.get('curated_severity', None),      # ← ADD THIS
    'attack_flag': row.get('attack_flag', 0),
    'attack_technique_count': row.get('attack_technique_count', 0),
    'chpl_flag': row.get('chpl_flag', 0),
    'label': row['label']
})
```

---

## ⚡ RUN IT

```bash
# 1. Backup database
cp data/cve_database.db data/cve_database_backup_$(date +%Y%m%d).db

# 2. Test on small sample first
python scripts/data/enrich_cves.py --limit 1000

# 3. Check looks good
sqlite3 data/cve_database.db "SELECT epss_date, healthcare_score FROM enrichments LIMIT 5;"

# 4. Run full enrichment
python scripts/data/enrich_cves.py --batch-size 5000

# 5. Validate with tests
python -m pytest tests/test_enrichment_data_quality.py -v
```

**Time:** ~60-90 minutes for 226,320 CVEs

---

## 📊 ARCHITECTURE Q&A

### Q: "Why only 3 tables in database?"
**A:** By design! Database stores processed data only. Raw API responses cached in files.

### Q: "Where is raw API data stored?"
**A:** File-based cache:
```
cache/
├── nvd/*.pkl.gz         (NVD CVE data)
├── epss/*.json          (EPSS scores - persistent + daily)
├── kev/*.pkl.gz         (CISA KEV catalog)
├── attack/*.pkl.gz      (MITRE ATT&CK)
└── chpl/*.json          (Health IT certified products)
```

### Q: "Should we add raw data tables?"
**A:** Not now. File caching works well. Consider as Phase 2 (months out).

### Q: "Are API calls batch or on-the-fly?"
**A:** **Batch!** 
- EPSS: 100 CVEs per request
- NVD: Incremental date ranges
- KEV/ATT&CK/CHPL: Full catalog fetch, then cached

### Q: "Will notebooks break?"
**A:** **NO!** Zero column name changes. All existing code still works.

---

## ✅ CHECKLIST

- [x] Analysis complete (this doc)
- [ ] Apply code fixes (6 lines)
- [ ] Backup database
- [ ] Test on 1,000 CVEs
- [ ] Run full enrichment (226K CVEs)
- [ ] Validate with pytest
- [ ] Test existing notebooks
- [ ] Mark complete ✨

---

## 📚 Full Documentation

- **[ARCHITECTURE_SUMMARY.md](ARCHITECTURE_SUMMARY.md)** - Executive summary (this is for stakeholders)
- **[ARCHITECTURE_ANALYSIS.md](ARCHITECTURE_ANALYSIS.md)** - Full technical analysis (11 sections)
- **[test_enrichment_data_quality.py](../tests/test_enrichment_data_quality.py)** - Unit tests
- **[test_enrichment_comprehensive.py](../tests/test_enrichment_comprehensive.py)** - Full scan tests

---

## 🎯 Bottom Line

**Current State:** File caching works fine. Database has 3 columns with 100% NULL due to enrichment bug.

**Solution:** Fix enrichment script (6 lines). NO architectural overhaul needed.

**Impact:** Zero breaking changes. Unlocks new analytical capabilities.

**Next Step:** Implement fixes and re-run enrichment.

---

**Questions?** See [ARCHITECTURE_ANALYSIS.md](ARCHITECTURE_ANALYSIS.md) for detailed answers.
