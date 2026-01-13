# Changelog

All notable changes to this project are documented here. This file is intended
for internal traceability of experiments and major code changes.

## 2026-01-13 — Active development snapshot
- Commit `9183963` — project scaffold and initial files
- Commit `f175862` — added CI badge, created GitHub repo https://github.com/er-vinay-india/cti-recommender
- Commit `55120cd` — added LightGBM learning-to-rank prototype (`cti_recommender/ltr.py`), tests, and requirements
- Implemented CHPL fetching and caching; persisted `data/processed/CHPL_products.parquet`
- Implemented ATT&CK technique fetching and simple CVE→ATT&CK mapping (`attack_flag`)
- Grid-search tuning completed for `w_chpl` and `w_attack` with evaluation artifacts in `outputs/`
- LTR prototype run and artifacts saved to `outputs/` and `models/ltr_model.pkl`

---

(Keep appending entries here as development proceeds.)
