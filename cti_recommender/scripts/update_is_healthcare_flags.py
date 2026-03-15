#!/usr/bin/env python3
"""Recompute and persist enrichments.is_healthcare using latest feature logic."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import settings
from src.core.cti_recommender import build_healthcare_features

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)


def main() -> int:
    db_path = settings.get_database_path()
    conn = sqlite3.connect(db_path)

    try:
        before_total = conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        before_hc = conn.execute("SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1").fetchone()[0]

        cves = pd.read_sql(
            """
            SELECT cve_id, published, description, cvss
            FROM cves
            WHERE cve_id IS NOT NULL
            """,
            conn,
        )

        if cves.empty:
            logger.warning("No CVEs found; no update performed")
            return 0

        features = build_healthcare_features(cves, add_epss=False, include_osint=True)
        updates = features[["cve_id", "is_healthcare"]].copy()
        updates["is_healthcare"] = pd.to_numeric(
            updates["is_healthcare"], errors="coerce"
        ).fillna(0).astype(int)

        current = pd.read_sql("SELECT cve_id, is_healthcare FROM enrichments", conn)
        merged = updates.merge(current, on="cve_id", how="inner", suffixes=("_new", "_old"))
        changed = int(
            (
                merged["is_healthcare_new"]
                != merged["is_healthcare_old"].fillna(0).astype(int)
            ).sum()
        )

        cursor = conn.cursor()
        cursor.execute("BEGIN TRANSACTION")
        cursor.executemany(
            "UPDATE enrichments SET is_healthcare = ? WHERE cve_id = ?",
            [(int(row.is_healthcare), str(row.cve_id)) for row in updates.itertuples(index=False)],
        )
        conn.commit()

        after_total = conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        after_hc = conn.execute("SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1").fetchone()[0]

        logger.info(f"DB: {db_path}")
        logger.info(f"Rows in enrichments: {before_total:,} -> {after_total:,}")
        logger.info(f"Healthcare flagged: {before_hc:,} -> {after_hc:,}")
        logger.info(f"Rows with changed is_healthcare: {changed:,}")
        return 0
    except Exception as exc:
        conn.rollback()
        logger.exception(f"Failed to recompute is_healthcare flags: {exc}")
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
