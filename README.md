# cti-recommender

A simple, data-driven vulnerability recommender focused on healthcare use-cases. It combines signals from NVD, CISA KEV, CHPL, and MITRE ATT&CK to produce a weighted-priority ranking of CVEs.

Quickstart
----------
- Create and activate a Python venv (recommended).
- Install dependencies: `pip install -r cti_recommender/requirements.txt` (if present).
- Run the local ETL: `python cti_recommender/healthcare_local.py` (sets up `data/processed/*`).
- Run tests: `PYTHONPATH=. pytest -q`.

Repository layout
-----------------
- `cti_recommender/` — core code for fetchers, feature engineering and scoring.
- `data/` — raw and processed data (not committed by default).
- `data_cache/` — local caches for external fetches.
- `outputs/` — saved scoring artifacts and evaluation outputs.

CI
--
[![Python CI](https://github.com/er-vinay-india/cti-recommender/actions/workflows/python-ci.yml/badge.svg)](https://github.com/er-vinay-india/cti-recommender/actions/workflows/python-ci.yml)

License
-------
MIT — see `LICENSE`.
