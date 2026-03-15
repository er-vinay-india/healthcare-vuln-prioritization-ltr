#!/usr/bin/env python3
"""Prepare mandatory cache artifacts before running test suite.

This script ensures required cache directories exist and pre-populates
EPSS persistent cache to a minimum size threshold expected by tests.
"""

import argparse
import sqlite3
import sys
from pathlib import Path
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.epss_fetcher import EPSSFetcher


REQUIRED_CACHE_DIRS = [
    Path("cache/epss"),
    Path("cache/kev"),
    Path("cache/attack"),
    Path("cache/chpl"),
    Path("cache/nvd"),
]

EPSS_HEALTHCHECK_URL = "https://api.first.org/data/v1/epss"


def ensure_directories() -> None:
    for cache_dir in REQUIRED_CACHE_DIRS:
        cache_dir.mkdir(parents=True, exist_ok=True)


def load_cve_ids(db_path: Path, max_cves: int) -> list[str]:
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cve_id FROM cves ORDER BY cve_id DESC LIMIT ?",
            (max_cves,),
        )
        return [row[0] for row in cursor.fetchall()]


def check_epss_connectivity(timeout_seconds: int = 15) -> None:
    try:
        response = requests.get(
            EPSS_HEALTHCHECK_URL,
            params={"cve": "CVE-2023-4863"},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
    except Exception as exc:
        raise RuntimeError(
            "EPSS API unreachable. Start network/VPN access, then rerun cache preparation."
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare cache required for test suite")
    parser.add_argument("--db-path", default="data/cve_database.db", help="Path to CVE SQLite database")
    parser.add_argument("--max-cves", type=int, default=30000, help="Maximum CVEs to use for EPSS warmup")
    parser.add_argument("--min-size", type=int, default=1_000_000, help="Minimum EPSS persistent cache size in bytes")
    args = parser.parse_args()

    ensure_directories()

    persistent_path = Path("cache/epss/epss_persistent.json")
    if persistent_path.exists() and persistent_path.stat().st_size >= args.min_size:
        size_mb = persistent_path.stat().st_size / (1024 * 1024)
        print(f"[OK] EPSS cache already warm ({size_mb:.2f} MB)")
        return 0

    check_epss_connectivity()

    cve_ids = load_cve_ids(Path(args.db_path), args.max_cves)
    if not cve_ids:
        raise RuntimeError("No CVEs found in database to warm EPSS cache")

    print(f"[INFO] Warming EPSS cache using {len(cve_ids):,} CVEs...")
    fetcher = EPSSFetcher()
    fetcher.fetch_epss_bulk(cve_ids, use_cache=True, show_progress=True, fail_fast=True)

    if not persistent_path.exists():
        raise RuntimeError("EPSS persistent cache was not created")

    size = persistent_path.stat().st_size
    size_mb = size / (1024 * 1024)
    if size < args.min_size:
        raise RuntimeError(
            f"EPSS persistent cache too small after warmup: {size_mb:.2f} MB "
            f"(required >= {args.min_size / (1024 * 1024):.2f} MB)"
        )

    print(f"[OK] EPSS cache ready ({size_mb:.2f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
