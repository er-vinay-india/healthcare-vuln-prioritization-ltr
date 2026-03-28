"""
Pipeline utility functions for the CTI Recommender ingestion workflow.

These functions were extracted from STEP_1 notebook to keep the notebook
focused on workflow orchestration rather than implementation details.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pandas as pd
import requests

from src.core.cve_database import CVEDatabase
from src.core import cti_recommender
from src.core.epss_fetcher import EPSSFetcher
from src.core.healthcare_curated import HealthcareCuratedDataset
from src.analysis.healthcare_mapping import HealthcareMapper
from src.analysis.attack_mapper import AttackMapper
from src.analysis.chpl_mapper import CHPLMapper
from config.settings import settings


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def check_current_status(project_root: Path) -> None:
    """Display comprehensive status of database and cache."""
    print("=" * 80)
    print("CURRENT DATA STATUS")
    print("=" * 80)

    db_path = project_root / "data" / "cve_database.db"
    if db_path.exists():
        db_size = db_path.stat().st_size / (1024 ** 2)
        print(f"\n[STATS] Database: {db_path}")
        print(f"   Size: {db_size:.2f} MB")

        db = CVEDatabase(db_path)
        cursor = db.conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM cves")
        cve_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM enrichments")
        enrichment_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE kev_flag = 1")
        kev_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE chpl_flag = 1")
        chpl_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1")
        healthcare_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE attack_flag = 1")
        attack_count = cursor.fetchone()[0]
        cursor.execute("SELECT MIN(published), MAX(published) FROM cves")
        date_range = cursor.fetchone()

        print(f"   Total CVEs: {cve_count:,}")
        print(f"   Enriched: {enrichment_count:,}")
        print(f"   Date range: {date_range[0]} to {date_range[1]}")
        print(f"\n   Enrichment Signals:")
        print(f"      KEV (exploited): {kev_count:,}")
        print(f"      CHPL certified:  {chpl_count:,}")
        print(f"      Healthcare:      {healthcare_count:,}")
        print(f"      ATT&CK mapped:   {attack_count:,}")

        db.conn.close()
    else:
        print(f"\n[WARN]  Database not found: {db_path}")

    print(f"\n Cache Directories:")
    for cache_dir in ["cache/nvd", "cache/epss", "cache/kev", "cache/attack", "cache/chpl"]:
        cache_path = project_root / cache_dir
        if cache_path.exists():
            files = list(cache_path.glob("*"))
            total_size = sum(f.stat().st_size for f in files if f.is_file()) / (1024 ** 2)
            print(f"   {cache_dir}: {len(files)} files ({total_size:.2f} MB)")
        else:
            print(f"   {cache_dir}: Not found")

    print(f"\n Enhanced Features (for Model Training):")
    features_path = project_root / "outputs" / "features" / "features_enhanced_latest.csv"
    if features_path.exists():
        features_size = features_path.stat().st_size / (1024 ** 2)
        features_df = pd.read_csv(features_path, nrows=1)
        feature_count = len(features_df.columns)
        print(f"   features_enhanced_latest.csv: {feature_count} features ({features_size:.1f} MB)")
        print(f"   [OK] Enhanced features ready for STEP_2 & STEP_3")
    else:
        print(f"   features_enhanced_latest.csv: Not found")
        print(f"   [INFO] Run apply_enhanced_features.py after STEP_2 to generate")

    print("\n" + "=" * 80)


# ---------------------------------------------------------------------------
# Reset helpers
# ---------------------------------------------------------------------------

def reset_database(project_root: Path, confirm: bool = False) -> None:
    """Delete and recreate the CVE database."""
    if not confirm:
        print("[WARN]  Set confirm=True to actually delete the database")
        return
    db_path = project_root / "data" / "cve_database.db"
    if db_path.exists():
        db_path.unlink()
        print(f"[OK] Deleted database: {db_path}")
    db = CVEDatabase(db_path)
    db.conn.close()
    print("[OK] Created fresh database")


def reset_cache(project_root: Path, cache_type: str = "all", confirm: bool = False) -> None:
    """Clear one or all cache directories.

    Args:
        cache_type: 'all', 'nvd', 'epss', 'kev', 'attack', or 'chpl'
    """
    if not confirm:
        print("[WARN]  Set confirm=True to actually delete cache")
        return
    cache_dirs = {
        "nvd": "cache/nvd",
        "epss": "cache/epss",
        "kev": "cache/kev",
        "attack": "cache/attack",
        "chpl": "cache/chpl",
    }
    dirs_to_clear = cache_dirs.values() if cache_type == "all" else [cache_dirs[cache_type]]
    for cache_dir in dirs_to_clear:
        cache_path = project_root / cache_dir
        if cache_path.exists():
            shutil.rmtree(cache_path)
            cache_path.mkdir(parents=True, exist_ok=True)
            print(f"[OK] Cleared: {cache_dir}")


def reset_all(project_root: Path, confirm: bool = False) -> None:
    """Reset database AND all caches."""
    if not confirm:
        print("[WARN]  Set confirm=True to reset everything")
        return
    reset_database(project_root, confirm=True)
    reset_cache(project_root, cache_type="all", confirm=True)
    print("\n[OK] Complete reset finished")


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def fetch_cves_by_date(
    project_root: Path,
    start_date: str,
    end_date: str,
    api_key: str | None = None,
) -> pd.DataFrame:
    """Fetch CVEs from NVD for a date range and upsert into the database.

    Args:
        project_root: Workspace root Path
        start_date: Start date string YYYY-MM-DD
        end_date:   End date string   YYYY-MM-DD
        api_key:    NVD API key (falls back to NVD_API_KEY env var)

    Returns:
        DataFrame of fetched CVEs, or empty DataFrame on no results.
    """
    if api_key is None:
        api_key = os.environ.get("NVD_API_KEY")

    print(f"\n{'=' * 80}")
    print(f"FETCHING CVEs: {start_date} to {end_date}")
    print(f"{'=' * 80}")
    print("[OK] Using NVD API key" if api_key else "[WARN]  No API key — slower rate limit (6 s/request)")

    df = cti_recommender.fetch_nvd_date_range(
        start_date=start_date, end_date=end_date, api_key=api_key
    )
    if df.empty:
        print("[WARN]  No CVEs found for this date range")
        return df

    print(f"\n[OK] Fetched {len(df):,} CVEs")

    db_path = project_root / "data" / "cve_database.db"
    db = CVEDatabase(db_path)
    count = db.upsert_cves(df)
    db.log_fetch(
        start_date=start_date, end_date=end_date,
        cve_count=count, fetch_type="manual", status="success",
    )
    db.conn.close()

    print(f"[OK] Inserted {count:,} CVEs into database")
    print(f"{'=' * 80}\n")
    return df


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def enrich_all_cves(project_root: Path) -> None:
    """Run the full 6-step enrichment pipeline (KEV → EPSS → HC → Curated → ATT&CK → CHPL)."""
    db_path = project_root / "data" / "cve_database.db"
    db = CVEDatabase(db_path)

    print("=" * 80)
    print("ENRICHMENT PIPELINE")
    print("=" * 80)

    df = db.query_cves()
    print(f"\n[STATS] Total CVEs to enrich: {len(df):,}")

    # 1 — KEV
    print("\n[1/6] Fetching CISA KEV catalog...")
    try:
        response = requests.get(settings.KEV_CATALOG_URL, timeout=settings.KEV_TIMEOUT)
        response.raise_for_status()
        kev_cves = {v["cveID"] for v in response.json().get("vulnerabilities", [])}
        print(f"   [OK] Loaded {len(kev_cves):,} KEV CVEs")
        kev_df = pd.DataFrame({
            "cve_id": [c for c in kev_cves if c in set(df["cve_id"])],
            "kev_flag": 1,
        })
        db.upsert_enrichments(kev_df)
        print(f"   [OK] Flagged {len(kev_df):,} CVEs as KEV-listed")
    except Exception as e:
        print(f"   [WARN]  KEV fetch failed: {e}")

    # 2 — EPSS
    print("\n[2/6] Fetching EPSS scores...")
    try:
        epss_fetcher = EPSSFetcher()
        enriched = epss_fetcher.enrich_dataframe(df[["cve_id"]].copy())
        epss_df = enriched[["cve_id", "epss_score", "epss_percentile"]]
        db.upsert_enrichments(epss_df)
        print(f"   [OK] Added EPSS scores for {int((epss_df['epss_score'] > 0).sum()):,} CVEs")
    except Exception as e:
        print(f"   [WARN]  EPSS fetch failed: {e}")

    # 3 — Healthcare mapping
    print("\n[3/6] Healthcare keyword mapping...")
    try:
        mapper = HealthcareMapper()
        enriched = mapper.enrich_dataframe(df, description_col="description")
        hc_df = enriched[["cve_id", "is_healthcare", "healthcare_score"]]
        db.upsert_enrichments(hc_df)
        print(f"   [OK] Flagged {int(hc_df['is_healthcare'].sum()):,} healthcare-related CVEs")
    except Exception as e:
        print(f"   [WARN]  Healthcare mapping failed: {e}")

    # 4 — Curated breaches
    print("\n[4/6] Curated healthcare breach mapping...")
    try:
        curated_ds = HealthcareCuratedDataset()
        enriched = curated_ds.enrich_dataframe(df[["cve_id"]].copy())
        curated_df = enriched[["cve_id", "is_curated", "curated_severity"]]
        db.upsert_enrichments(curated_df)
        print(f"   [OK] Flagged {int(curated_df['is_curated'].sum()):,} curated breach CVEs")
    except Exception as e:
        print(f"   [WARN]  Curated breach enrichment failed: {e}")

    # 5 — ATT&CK
    print("\n[5/6] MITRE ATT&CK mapping...")
    try:
        attack_mapper = AttackMapper()
        attack_rows = [
            {"cve_id": row["cve_id"],
             "attack_flag": attack_mapper.map_cve_to_techniques(row.get("description", "")).get("attack_flag", 0)}
            for _, row in df.iterrows()
        ]
        attack_df = pd.DataFrame(attack_rows)
        db.upsert_enrichments(attack_df[attack_df["attack_flag"] == 1])
        print(f"   [OK] Mapped {int(attack_df['attack_flag'].sum()):,} CVEs to ATT&CK techniques")
    except Exception as e:
        print(f"   [WARN]  ATT&CK mapping failed: {e}")

    # 6 — CHPL
    print("\n[6/6] CHPL certified products mapping...")
    try:
        chpl_mapper = CHPLMapper()
        chpl_rows = [
            {"cve_id": row["cve_id"], "chpl_flag": 1}
            for _, row in df.iterrows()
            if chpl_mapper.check_chpl_match(
                description=row.get("description", ""),
                cpe_list=row.get("cpe_list", ""),
            ).get("chpl_flag")
        ]
        if chpl_rows:
            db.upsert_enrichments(pd.DataFrame(chpl_rows))
        print(f"   [OK] Flagged {len(chpl_rows):,} CHPL-related CVEs")
    except Exception as e:
        print(f"   [WARN]  CHPL mapping failed: {e}")

    db.conn.close()
    print("\n" + "=" * 80)
    print("[OK] ENRICHMENT COMPLETE")
    print("=" * 80)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_data_quality(project_root: Path) -> None:
    """Print a comprehensive data quality report for the CVE database."""
    db_path = project_root / "data" / "cve_database.db"
    db = CVEDatabase(db_path)
    cursor = db.conn.cursor()

    print("=" * 80)
    print("DATA QUALITY VALIDATION")
    print("=" * 80)

    cursor.execute("SELECT COUNT(*) FROM cves")
    total_cves = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM enrichments")
    enriched_cves = cursor.fetchone()[0]

    print(f"\n[STATS] Coverage:")
    print(f"   Total CVEs: {total_cves:,}")
    print(f"   Enriched:   {enriched_cves:,} ({enriched_cves / total_cves * 100:.1f}%)")

    print(f"\n[TARGET] Enrichment Signals:")
    signals = [
        ("KEV (exploited)", "kev_flag"),
        ("Healthcare-related", "is_healthcare"),
        ("ATT&CK mapped", "attack_flag"),
        ("CHPL certified", "chpl_flag"),
        ("Curated breaches", "is_curated"),
    ]
    for label, field in signals:
        cursor.execute(f"SELECT COUNT(*) FROM enrichments WHERE {field} = 1")
        count = cursor.fetchone()[0]
        pct = (count / enriched_cves * 100) if enriched_cves > 0 else 0
        print(f"   {label:30s} {count:6,} ({pct:5.2f}%)")

    cursor.execute("SELECT COUNT(*) FROM enrichments WHERE epss_score IS NOT NULL")
    epss_count = cursor.fetchone()[0]
    epss_pct = (epss_count / enriched_cves * 100) if enriched_cves > 0 else 0
    print(f"   {'EPSS scores':30s} {epss_count:6,} ({epss_pct:5.2f}%)")

    print(f"\n High-Value CVEs (multiple signals):")
    multi_queries = [
        ("KEV + Healthcare", "kev_flag = 1 AND is_healthcare = 1"),
        ("CHPL + Healthcare", "chpl_flag = 1 AND is_healthcare = 1"),
        ("ATT&CK + Healthcare", "attack_flag = 1 AND is_healthcare = 1"),
        ("KEV + ATT&CK + Healthcare", "kev_flag = 1 AND attack_flag = 1 AND is_healthcare = 1"),
    ]
    for label, where in multi_queries:
        cursor.execute(f"SELECT COUNT(*) FROM enrichments WHERE {where}")
        print(f"   {label}: {cursor.fetchone()[0]:,}")

    cursor.execute("""
        SELECT strftime('%Y', published) as year, COUNT(*) as count
        FROM cves GROUP BY year ORDER BY year DESC LIMIT 10
    """)
    print(f"\n CVE Distribution by Year (last 10):")
    for year, count in cursor.fetchall():
        print(f"   {year}: {count:,}")

    cursor.execute("""
        SELECT
            CASE
                WHEN cvss >= 9.0 THEN 'Critical (9.0-10.0)'
                WHEN cvss >= 7.0 THEN 'High (7.0-8.9)'
                WHEN cvss >= 4.0 THEN 'Medium (4.0-6.9)'
                ELSE 'Low (0.0-3.9)'
            END as severity,
            COUNT(*) as count
        FROM cves
        WHERE cvss IS NOT NULL
        GROUP BY severity
        ORDER BY MIN(cvss) DESC
    """)
    print(f"\n[WARN]  CVSS Severity Distribution:")
    for severity, count in cursor.fetchall():
        pct = count / total_cves * 100
        print(f"   {severity:25s} {count:6,} ({pct:5.2f}%)")

    db.conn.close()
    print("\n" + "=" * 80)
    print("[OK] VALIDATION COMPLETE")
    print("=" * 80)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_enriched_data(
    project_root: Path,
    output_path: Path | None = None,
) -> pd.DataFrame:
    """Export the full enriched CVE dataset to a CSV file.

    Args:
        project_root: Workspace root Path
        output_path:  Destination CSV path; defaults to outputs/ with timestamp

    Returns:
        DataFrame that was exported.
    """
    if output_path is None:
        output_path = (
            project_root / "outputs"
            / f"enriched_cves_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

    db_path = project_root / "data" / "cve_database.db"
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        """
        SELECT
            c.*,
            e.kev_flag, e.epss_score, e.epss_percentile,
            e.is_healthcare, e.healthcare_score,
            e.attack_flag, e.attack_technique_count,
            e.chpl_flag, e.is_curated, e.label
        FROM cves c
        LEFT JOIN enrichments e ON c.cve_id = e.cve_id
        """,
        conn,
    )
    conn.close()
    df.to_csv(output_path, index=False)
    print(f"[OK] Exported {len(df):,} CVEs to: {output_path}")
    return df
