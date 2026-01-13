# Research Context — Vulnerability Recommender (Healthcare)

Saved: 2026-01-13

## 1. Literature summary
- Early computing incidents (Levy, Ware, Creeper, Morris Worm) highlighted human-driven misuse and the need for structured security controls.
- Standardization efforts: CVE system (circa 1999), NVD launch (2005), and CVSS formalization introduced consistent identifiers and severity scoring.
- Cyber Threat Intelligence (CTI) and attacker-behaviour frameworks (e.g., MITRE ATT&CK) matured from 2012 onward and are widely used to contextualize adversary TTPs.
- Recent studies analyze NVD metadata (CVSS trends, disclosure patterns) but often rely on single-source data and thus may lack real-world threat relevance.
- CISA KEV catalog is a strong signal of exploited vulnerabilities but is frequently used in isolation.
- ATT&CK is useful for mapping behaviour/TTPs; few works robustly map CVEs to ATT&CK techniques and even fewer fuse ATT&CK with NVD+KEV for prioritization.
- Multi-source CTI aggregation (e.g., MultiKG) improves feed quality, but methods focusing specifically on vulnerability prioritisation and sector-specific ranking (healthcare) are limited.

## 2. Identified gaps
- Existing research typically depends on single-source vulnerability data (primarily NVD). 
- Multi-factor scoring approaches (e.g., V-Score) improve assessment but often omit ATT&CK mappings and sector-specific tailoring. 
- There is limited or no prior work that fuses NVD, KEV, and ATT&CK to build a healthcare-specific vulnerability ranking.
- ML approaches have not been widely applied to joint, multi-source CVE ranking that includes behavioural (ATT&CK) and exploit-validated (KEV) signals.

## 3. Research questions
1. How can NVD, CISA KEV, and MITRE ATT&CK datasets be combined effectively? 
2. What features/factors best indicate healthcare-relevant vulnerabilities (e.g., CPE-based mapping, vendor/product criticality, CVSS components, ATT&CK coverage)?
3. How does multi-source scoring (including CVSS) improve actionable recommendations for healthcare stakeholders?

## 4. Aim & objectives
**Aim:** Develop a data-driven, healthcare-focused vulnerability recommender that integrates NVD, CISA KEV, and MITRE ATT&CK to produce a prioritized ranking of vulnerabilities by recency, exploit validation, and attacker behaviour.

**Objectives:**
- Gather and prepare data from NVD, CISA KEV, and MITRE ATT&CK (clean, normalize, and persist). 
- Identify healthcare scope using CPE-to-sector mapping and product/vendor heuristics. 
- Engineer multi-source features and implement a recommender (weighted heuristic baseline and optional learning-to-rank ML model). 
- Evaluate using precision@K, NDCG, and ablation studies; tailor evaluation to healthcare-relevant metrics where possible.

## 5. Short-term implementation notes
- Use chunked NVD fetch (120-day chunks) and pagination to reliably collect historical CVEs. 
- Normalize NVD to extract `published`, `last_modified`, `cvss_v3_base_score`, `cvss_v3_vector`, and English descriptions. 
- Flag KEV membership and save both Parquet and CSV for portability. 
- Plan to create a `build_healthcare_features(...)` helper and `build_weighted_score(...)` baseline in `cti_recommender/cti_recommender.py`.

---

## CHPL fetcher & usage ✅

- Implemented `fetch_chpl_products` and `get_chpl_cached` in `cti_recommender/cti_recommender.py` to obtain CHPL product and vendor lists.
- Usage: set your CHPL API key in the environment variable `CHPL_API_KEY` (e.g., `export CHPL_API_KEY="<your_key>"`) and run `python cti_recommender/healthcare_local.py` from the repository root; outputs saved to `data/processed/CHPL_products.parquet` (and CSV fallback).
- The CHPL data is used to compute a `chpl_flag` in `build_healthcare_features(...)` (exact-match signals), and `build_weighted_score(...)` now supports `w_chpl` weight to include CHPL signals in ranking.
- A one-time run using the key you provided successfully fetched CHPL products: **6,900** entries were retrieved. Artifacts saved:
  - Cache: `data_cache/chpl_products.pkl.gz`
  - Processed: `data/processed/CHPL_products.parquet`
  - Raw page dumps (for debugging): `data_cache/chpl_v3_search_page_*.json`
  Re-scored NVD (4,979 CVEs) with CHPL signals and saved outputs to `outputs/` (e.g., `top_scored.csv`, `top20.csv`). Performed a weight grid search over `w_chpl` (0.00–0.20); best weight by precision@20 is **w_chpl = 0.10** (precision@20 = **0.85**). Grid results and summary saved as `outputs/weight_grid_chpl.csv` and `outputs/eval_grid_chpl.txt`.

- ATT&CK integration: added `fetch_attack_techniques` and `get_attack_cached` to pull MITRE ATT&CK Enterprise techniques (enterprise-attack.json) and persist to `data/processed/ATTACK_techniques.parquet`. Implemented a first-pass heuristic mapping that sets `attack_flag` when a technique *name* or *alias* appears in the CVE `description_en`; this `attack_flag` is included in `build_healthcare_features(...)` and used by `build_weighted_score(...)` via `w_attack`. Unit tests were added in `cti_recommender/tests/test_attack_mapping.py` to validate matching behavior.

  - Quick evaluation: enabling ATT&CK mapping (with baseline `w_attack=0.05`) increases `precision@20` for `attack_flag` in our top-20 list (example run saved as `outputs/attack_integration_report.txt` and top-20 CSVs `outputs/top20_before_attack.csv` / `outputs/top20_after_attack.csv`). See outputs for the precise deltas and top-20 changes.

If you'd like, I can: (a) add an initial `CPE_HEALTHCARE_MAPPING.csv` placeholder, (b) implement the `build_healthcare_features` prototype, or (c) draft the evaluation plan and the first baseline weights for the heuristic scorer.
