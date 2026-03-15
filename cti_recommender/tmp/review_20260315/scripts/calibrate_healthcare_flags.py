#!/usr/bin/env python3
"""Compute healthcare flag prevalence with current logic (no DB writes)."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import settings
from src.core.cti_recommender import build_healthcare_features


def main() -> None:
    conn = sqlite3.connect(settings.get_database_path())
    try:
        df = pd.read_sql(
            "SELECT cve_id, published, description, cvss FROM cves WHERE cve_id IS NOT NULL",
            conn,
        )
        out = build_healthcare_features(df, add_epss=False, include_osint=True)

        print(f"rows {len(out)}")
        print(f"pattern_flag {int(out['healthcare_pattern_flag'].sum())}")
        print(f"osint_flag {int(out['healthcare_osint_flag'].sum())}")
        print(f"is_healthcare {int(out['is_healthcare'].sum())}")
        print(f"is_healthcare_pct {round(out['is_healthcare'].mean() * 100, 2)}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
