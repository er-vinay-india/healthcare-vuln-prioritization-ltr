import pandas as pd
from pathlib import Path
from src.core.ltr import run_end_to_end


def test_ltr_smoke(tmp_path: Path):
    # small synthetic dataset
    nvd = pd.DataFrame([
        {'cve_id': 'CVE-1', 'published': '2025-01-01Z', 'description_en': 'Epic system vuln', 'cvss': 9.0},
        {'cve_id': 'CVE-2', 'published': '2025-01-01Z', 'description_en': 'Generic vuln', 'cvss': 5.0},
        {'cve_id': 'CVE-3', 'published': '2025-01-02Z', 'description_en': 'Spear-phishing attack', 'cvss': 7.0},
    ])
    kev = pd.DataFrame([{'cve_id': 'CVE-1'}])
    # build features and run end-to-end (small)
    run_end_to_end(nvd, kev_df=kev, chpl_df=None, attack_df=None, out_dir=tmp_path)
    assert (tmp_path / 'top_scored_ltr.csv').exists()
    assert (tmp_path / 'ltr_eval_summary.txt').exists()
