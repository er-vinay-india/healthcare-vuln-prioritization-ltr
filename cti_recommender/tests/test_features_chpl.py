import pandas as pd
from datetime import datetime, timezone
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cti_recommender import build_healthcare_features


def test_chpl_flag_matches_description():
    now = datetime.now(timezone.utc).isoformat()
    nvd_df = pd.DataFrame([
        {"cve_id": "CVE-000-1", "published": now, "description_en": "This vulnerability affects Epic Systems EHR."}
    ])
    chpl_df = pd.DataFrame([{"product": "Epic Systems", "developer": "Epic", "raw": {}}])

    out = build_healthcare_features(nvd_df, chpl_df=chpl_df)
    assert "chpl_flag" in out.columns
    assert int(out.loc[0, "chpl_flag"]) == 1


def test_chpl_flag_not_set_for_nonmatching():
    now = datetime.now(timezone.utc).isoformat()
    nvd_df = pd.DataFrame([
        {"cve_id": "CVE-000-2", "published": now, "description_en": "This vulnerability affects an unrelated product."}
    ])
    chpl_df = pd.DataFrame([{"product": "Epic Systems", "developer": "Epic", "raw": {}}])

    out = build_healthcare_features(nvd_df, chpl_df=chpl_df)
    assert "chpl_flag" in out.columns
    assert int(out.loc[0, "chpl_flag"]) == 0
