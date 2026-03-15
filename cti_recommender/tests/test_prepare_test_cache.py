import sqlite3
from pathlib import Path

from scripts.data.prepare_test_cache import seed_epss_cache_from_db


def _create_db_with_enrichments(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE enrichments (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL,
                epss_percentile REAL,
                epss_date TEXT
            )
            """
        )
        cur.executemany(
            "INSERT INTO enrichments (cve_id, epss_score, epss_percentile, epss_date) VALUES (?, ?, ?, ?)",
            [
                ("CVE-2023-0001", 0.9, 0.99, "2026-03-14"),
                ("CVE-2023-0002", 0.2, 0.80, "2026-03-14"),
                ("CVE-2023-0003", 0.0, 0.10, None),
            ],
        )
        conn.commit()


def test_seed_epss_cache_from_db_writes_only_valid_rows(tmp_path: Path):
    db_path = tmp_path / "cve_database.db"
    cache_path = tmp_path / "cache" / "epss" / "epss_persistent.json"
    _create_db_with_enrichments(db_path)

    written = seed_epss_cache_from_db(db_path, cache_path)

    assert written == 2
    assert cache_path.exists()
    assert cache_path.stat().st_size > 0


def test_seed_epss_cache_from_db_missing_db_returns_zero(tmp_path: Path):
    db_path = tmp_path / "missing.db"
    cache_path = tmp_path / "cache" / "epss" / "epss_persistent.json"

    written = seed_epss_cache_from_db(db_path, cache_path)

    assert written == 0
    assert not cache_path.exists()
