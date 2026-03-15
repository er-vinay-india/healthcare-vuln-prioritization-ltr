#!/usr/bin/env python
"""
Enrich CVE database with KEV, EPSS, healthcare flags, and multi-level labels
"""

import os
import sys
from pathlib import Path
import pandas as pd
import requests
import time
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase
from src.core.epss_fetcher import EPSSFetcher
from src.core.healthcare_curated import HealthcareCuratedDataset
from src.core.multi_level_labels import compute_multi_level_labels
from src.analysis.healthcare_mapping import HealthcareMapper
from src.analysis.attack_mapper import AttackMapper
from src.analysis.chpl_mapper import CHPLMapper
from config.settings import settings

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)


def fetch_kev_catalog() -> set:
    """
    Fetch CISA KEV catalog and return set of CVE IDs
    
    Returns:
        Set of CVE IDs in the KEV catalog
    """
    logger.info("Fetching CISA KEV catalog...")
    
    url = settings.KEV_CATALOG_URL
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        kev_data = response.json()
        
        kev_cves = {vuln['cveID'] for vuln in kev_data.get('vulnerabilities', [])}
        logger.info(f"[OK] Loaded {len(kev_cves):,} CVEs from KEV catalog")
        return kev_cves
        
    except Exception as e:
        logger.error(f"Failed to fetch KEV catalog: {e}")
        return set()


def fetch_epss_bulk(cve_ids: list, batch_size: int = 100) -> dict:
    """
    Fetch EPSS scores for multiple CVEs in batches
    
    Args:
        cve_ids: List of CVE IDs to fetch scores for
        batch_size: Number of CVEs per batch (max 100 for bulk API)
    
    Returns:
        Dictionary mapping CVE ID to EPSS score
    """
    if batch_size <= 0:
        raise ValueError(f"batch_size must be > 0, got {batch_size}")

    if not cve_ids:
        logger.warning("No CVE IDs provided for EPSS fetch; skipping EPSS fetch phase")
        return {}

    logger.info(f"Fetching EPSS scores for {len(cve_ids):,} CVEs...")
    
    epss_fetcher = EPSSFetcher()
    epss_scores = {}
    
    # Process in batches
    total_batches = (len(cve_ids) + batch_size - 1) // batch_size
    
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        batch_num = i // batch_size + 1
        
        try:
            # Fetch batch
            result = epss_fetcher.fetch_epss_bulk(batch, fail_fast=True)
            
            if isinstance(result, pd.DataFrame) and not result.empty:
                batch_scores = dict(zip(result['cve_id'], result['epss']))
                epss_scores.update(batch_scores)
            elif isinstance(result, dict):
                epss_scores.update(result)
                
            if batch_num % 10 == 0:
                logger.info(f"  Processed {batch_num}/{total_batches} batches ({len(epss_scores):,} scores)")
            
            # Rate limiting (be nice to FIRST.org API)
            time.sleep(0.5)
            
        except Exception as e:
            logger.error(f"Failed to fetch batch {batch_num}: {e}")
            raise RuntimeError(
                f"EPSS fetch failed at batch {batch_num}/{total_batches}. "
                "Stopping immediately (fail-fast mode)."
            ) from e
    
    coverage_pct = (len(epss_scores) / len(cve_ids) * 100) if cve_ids else 0.0
    logger.info(f"[OK] Fetched {len(epss_scores):,} EPSS scores ({coverage_pct:.1f}% coverage)")
    return epss_scores


def _safe_pct(count: int, total: int) -> float:
    return (count / total * 100.0) if total > 0 else 0.0


def detect_healthcare_relevance(cve_data: dict, healthcare_mapper: HealthcareMapper) -> bool:
    """
    Detect if CVE is healthcare-relevant based on description and vendors
    
    Args:
        cve_data: Dictionary with 'description' and optionally 'vendors' keys
        healthcare_mapper: HealthcareMapper instance
    
    Returns:
        True if healthcare-relevant, False otherwise
    """
    description = cve_data.get('description', '')
    
    # Check description for healthcare keywords
    if healthcare_mapper.check_healthcare_keyword(description):
        return True
    
    # Check vendor names if available
    vendors = cve_data.get('vendors', [])
    if isinstance(vendors, str):
        vendors = [vendors]
    
    for vendor in vendors:
        if healthcare_mapper.check_vendor_match(vendor):
            return True
    
    return False


def validate_enrichment(db: CVEDatabase):
    """
    Validate enrichment results - CHECK FOR ALL-ZERO FEATURES!
    
    Args:
        db: CVEDatabase instance
    """
    logger.info("="*70)
    logger.info(" ENRICHMENT VALIDATION")
    logger.info("="*70)
    
    query = '''
    SELECT 
        COUNT(*) as total,
        SUM(kev_flag) as kev_count,
        SUM(CASE WHEN epss_score > 0 THEN 1 ELSE 0 END) as epss_count,
        SUM(is_healthcare) as healthcare_count,
        SUM(is_curated) as curated_count,
        SUM(chpl_flag) as chpl_count,
        SUM(attack_flag) as attack_count,
        AVG(epss_score) as avg_epss,
        MAX(epss_score) as max_epss
    FROM enrichments
    '''
    
    result = db.conn.execute(query).fetchone()
    
    total = int(result[0] or 0)
    kev_count = int(result[1] or 0)
    epss_count = int(result[2] or 0)
    healthcare_count = int(result[3] or 0)
    curated_count = int(result[4] or 0)
    chpl_count = int(result[5] or 0)
    attack_count = int(result[6] or 0)
    avg_epss = float(result[7] or 0.0)
    max_epss = float(result[8] or 0.0)

    logger.info("Enrichment Coverage:")
    logger.info(f"  Total CVEs: {total:,}")
    logger.info(f"  KEV: {kev_count:,} ({_safe_pct(kev_count, total):.1f}%)")
    logger.info(f"  EPSS: {epss_count:,} ({_safe_pct(epss_count, total):.1f}%)")
    logger.info(f"  Healthcare: {healthcare_count:,} ({_safe_pct(healthcare_count, total):.1f}%)")
    logger.info(f"  Curated: {curated_count:,} ({_safe_pct(curated_count, total):.1f}%)")
    logger.info(f"  CHPL: {chpl_count:,} ({_safe_pct(chpl_count, total):.1f}%)")
    logger.info(f"  ATT&CK: {attack_count:,} ({_safe_pct(attack_count, total):.1f}%)")
    logger.info("EPSS Statistics:")
    logger.info(f"  Average: {avg_epss:.4f}")
    logger.info(f"  Maximum: {max_epss:.4f}")

    if total == 0:
        logger.warning("No enrichment records found to validate")
        return False
    
    # Critical checks
    issues = []
    if epss_count == 0:
        issues.append(" CRITICAL: EPSS has 0 CVEs! Feature is useless!")
    elif epss_count < total * 0.5:
        issues.append(f"[WARN]  WARNING: EPSS coverage is low ({_safe_pct(epss_count, total):.1f}%)")
    
    if healthcare_count > total * 0.7:
        issues.append(f"[WARN]  WARNING: Healthcare coverage seems high ({_safe_pct(healthcare_count, total):.1f}%) - check for false positives")
    
    if issues:
        logger.warning("[WARN]  Issues Found:")
        for issue in issues:
            logger.warning(f"  {issue}")
        return False
    else:
        logger.info("[OK] Validation passed!")
        return True


def enrich_database(batch_size: int = 5000, limit: int = None, dry_run: bool = False, skip_epss: bool = False, skip_attack: bool = False, skip_chpl: bool = False):
    """
    Enrich all CVEs in database with KEV, EPSS, healthcare, ATT&CK, CHPL, curated flags, and labels
    
    Args:
        batch_size: Number of CVEs to process at once
        limit: Optional limit for testing (None = process all)
        dry_run: If True, show plan without making changes
        skip_epss: Skip EPSS fetching (use existing EPSS data from database)
        skip_attack: Skip ATT&CK mapping (useful if mapper unavailable)
        skip_chpl: Skip CHPL mapping (useful if API unavailable)
    """
    
    if batch_size <= 0:
        raise ValueError(f"batch_size must be > 0, got {batch_size}")

    logger.info("="*70)
    if dry_run:
        logger.info(" CVE DATABASE ENRICHMENT - DRY RUN MODE")
    else:
        logger.info("CVE DATABASE ENRICHMENT PIPELINE")
    logger.info("="*70)

    db = CVEDatabase()
    try:
        curated_dataset = HealthcareCuratedDataset()
        healthcare_mapper = HealthcareMapper()

        attack_mapper = None
        if not skip_attack:
            try:
                attack_mapper = AttackMapper()
                logger.info("[OK] ATT&CK mapper initialized")
            except Exception as e:
                logger.warning(f"ATT&CK mapper unavailable: {e}")
                skip_attack = True

        chpl_mapper = None
        if not skip_chpl:
            try:
                chpl_mapper = CHPLMapper()
                if chpl_mapper.products_df is None or len(chpl_mapper.products_df) == 0:
                    logger.warning("CHPL data unavailable - skipping CHPL mapping")
                    skip_chpl = True
                    chpl_mapper = None
                else:
                    logger.info(f"[OK] CHPL mapper initialized with {len(chpl_mapper.products_df):,} products")
            except Exception as e:
                logger.warning(f"CHPL mapper unavailable: {e}")
                skip_chpl = True

        stats = db.get_statistics()
        total_cves = stats['total_cves']

        if limit:
            total_cves = min(total_cves, limit)
            logger.info(f"Processing {total_cves:,} CVEs (limited for testing)")
        else:
            logger.info(f"Processing {total_cves:,} CVEs")

        kev_cves = fetch_kev_catalog()

        logger.info(f"\nLoading CVEs from database...")
        query = "SELECT cve_id, description, cvss FROM cves ORDER BY cve_id DESC"
        if limit:
            query += f" LIMIT {limit}"

        cves_df = pd.read_sql_query(query, db.conn)
        logger.info(f"[OK] Loaded {len(cves_df):,} CVEs")

        required_columns = {'cve_id', 'description', 'cvss'}
        missing_columns = required_columns - set(cves_df.columns)
        if missing_columns:
            raise ValueError(f"CVE query missing required columns: {sorted(missing_columns)}")

        if cves_df.empty:
            logger.warning("No CVEs returned by query; skipping enrichment run")
            return

        logger.info("="*70)
        logger.info("PHASE 1: FETCHING EPSS SCORES")
        logger.info("="*70)

        if skip_epss:
            logger.info("[SKIP] EPSS fetching skipped - using existing EPSS data from database")
            epss_scores = {}
        elif dry_run:
            logger.info(f"[DRY RUN] Would fetch EPSS for {len(cves_df):,} CVEs")
            logger.info(f"  Estimated time: {len(cves_df)/100*1.5/60:.1f} minutes")
            logger.info(f"  Storage: ~{len(cves_df)*0.2:.1f} KB in persistent cache")
            return
        else:
            epss_scores = fetch_epss_bulk(cves_df['cve_id'].tolist())
            epss_coverage = _safe_pct(len(epss_scores), len(cves_df))
            logger.info(f"\n[OK] EPSS Fetch Complete: {len(epss_scores):,}/{len(cves_df):,} CVEs ({epss_coverage:.1f}%)")
            if epss_coverage < 50:
                logger.warning(f"[WARN]  Low EPSS coverage ({epss_coverage:.1f}%) - many CVEs may not be in EPSS database")

        logger.info("="*70)
        logger.info("PHASE 2: PROCESSING CVEs")
        logger.info("="*70)

        logger.info(f"\nProcessing CVEs in batches of {batch_size:,}...")

        total_batches = (len(cves_df) + batch_size - 1) // batch_size
        enrichment_records = []

        for batch_idx in range(0, len(cves_df), batch_size):
            batch_df = cves_df.iloc[batch_idx:batch_idx + batch_size].copy()
            batch_num = batch_idx // batch_size + 1

            batch_df['kev_flag'] = batch_df['cve_id'].isin(kev_cves).astype(int)

            if skip_epss:
                batch_df['epss_score'] = None
                batch_df['epss_percentile'] = None
                batch_df['epss_date'] = None
            else:
                batch_df['epss_score'] = batch_df['cve_id'].apply(
                    lambda cve: epss_scores.get(cve, {}).get('epss_score', 0.0)
                )
                batch_df['epss_percentile'] = batch_df['cve_id'].apply(
                    lambda cve: epss_scores.get(cve, {}).get('percentile', 0.0)
                )
                batch_df['epss_date'] = batch_df['cve_id'].apply(
                    lambda cve: epss_scores.get(cve, {}).get('date', None)
                )

            batch_df['is_healthcare'] = batch_df.apply(
                lambda row: int(detect_healthcare_relevance({'description': row['description']}, healthcare_mapper)),
                axis=1
            )
            batch_df['healthcare_score'] = batch_df['description'].apply(
                lambda desc: healthcare_mapper.get_healthcare_score(desc) if pd.notna(desc) else 0.0
            )

            if attack_mapper:
                batch_df['attack_flag'] = 0
                batch_df['attack_technique_count'] = 0
                for idx, row in batch_df.iterrows():
                    result = attack_mapper.map_cve_to_techniques(row['description'])
                    batch_df.at[idx, 'attack_flag'] = result['attack_flag']
                    batch_df.at[idx, 'attack_technique_count'] = result['technique_count']
            else:
                batch_df['attack_flag'] = 0
                batch_df['attack_technique_count'] = 0

            if chpl_mapper:
                batch_df['chpl_flag'] = 0
                for idx, row in batch_df.iterrows():
                    is_match, _ = chpl_mapper.map_cve_to_chpl(row['description'] or '')
                    batch_df.at[idx, 'chpl_flag'] = 1 if is_match else 0
            else:
                batch_df['chpl_flag'] = 0

            batch_df['is_curated'] = batch_df['cve_id'].apply(
                lambda cve_id: int(curated_dataset.is_curated(cve_id))
            ).astype(int)
            batch_df['curated_severity'] = batch_df['cve_id'].apply(
                lambda cve_id: curated_dataset.get_breach_info(cve_id).get('severity', None)
                if curated_dataset.is_curated(cve_id) else None
            )

            batch_df['curated_exploited'] = batch_df['cve_id'].apply(
                lambda cve_id: int(curated_dataset.get_breach_info(cve_id).get('exploited_in_wild', False))
                if curated_dataset.is_curated(cve_id) else 0
            ).astype(int)

            batch_df = compute_multi_level_labels(batch_df)

            for _, row in batch_df.iterrows():
                enrichment_records.append({
                    'cve_id': row['cve_id'],
                    'kev_flag': row['kev_flag'],
                    'epss_score': row['epss_score'],
                    'epss_percentile': row.get('epss_percentile', 0.0),
                    'epss_date': row.get('epss_date', None),
                    'is_healthcare': row['is_healthcare'],
                    'healthcare_score': row.get('healthcare_score', 0.0),
                    'is_curated': row['is_curated'],
                    'curated_severity': row.get('curated_severity', None),
                    'attack_flag': row.get('attack_flag', 0),
                    'attack_technique_count': row.get('attack_technique_count', 0),
                    'chpl_flag': row.get('chpl_flag', 0),
                    'label': row['label']
                })

            logger.info(
                f"  Batch {batch_num}/{total_batches} - Processed {len(batch_df):,} CVEs "
                + f"(KEV: {batch_df['kev_flag'].sum()}, Healthcare: {batch_df['is_healthcare'].sum()}, "
                + f"Curated: {batch_df['is_curated'].sum()}, ATT&CK: {batch_df.get('attack_flag', pd.Series([0])).sum()}, "
                + f"CHPL: {batch_df.get('chpl_flag', pd.Series([0])).sum()})"
            )

        logger.info("="*70)
        logger.info("PHASE 3: SAVING TO DATABASE")
        logger.info("="*70)

        logger.info(f"\nPreparing to upsert {len(enrichment_records):,} enrichment records...")
        enrichments_df = pd.DataFrame(enrichment_records)

        epss_in_records = int((enrichments_df['epss_score'] > 0).sum())
        logger.info(f"  Records with EPSS scores: {epss_in_records:,} ({_safe_pct(epss_in_records, len(enrichments_df)):.1f}%)")
        logger.info(f"  Records with KEV flag: {enrichments_df['kev_flag'].sum():,}")
        logger.info(f"  Records with Healthcare flag: {enrichments_df['is_healthcare'].sum():,}")

        try:
            db.conn.execute("BEGIN TRANSACTION")
            db.upsert_enrichments(enrichments_df)
            db.conn.commit()
            logger.info("[OK] Database transaction committed successfully")
        except Exception as e:
            db.conn.rollback()
            logger.exception(f"[FAIL] Database transaction failed, rolled back: {e}")
            raise

        logger.info("="*70)
        logger.info("ENRICHMENT SUMMARY")
        logger.info("="*70)

        final_stats = db.get_statistics()
        total_after_run = int(final_stats.get('total_cves', 0) or 0)
        logger.info(f"Total CVEs enriched in this run: {len(enrichment_records):,}", extra={'total_enriched': len(enrichment_records)})
        logger.info(f"Database KEV-flagged CVEs: {final_stats['kev_count']:,} ({_safe_pct(int(final_stats['kev_count']), total_after_run):.1f}%)", extra={'kev_count': final_stats['kev_count']})
        logger.info(f"Database healthcare-relevant CVEs: {final_stats['healthcare_count']:,} ({_safe_pct(int(final_stats['healthcare_count']), total_after_run):.1f}%)", extra={'healthcare_count': final_stats['healthcare_count']})
        logger.info(f"Database curated breach CVEs: {final_stats['curated_count']:,} ({_safe_pct(int(final_stats['curated_count']), total_after_run):.1f}%)", extra={'curated_count': final_stats['curated_count']})

        enriched_df = pd.DataFrame(enrichment_records)
        label_counts = enriched_df['label'].value_counts().sort_index(ascending=False)

        logger.info("Label Distribution:")
        label_names = {
            5: "Critical",
            4: "High",
            3: "Medium",
            2: "Low",
            1: "Informational",
            0: "Irrelevant"
        }

        for label in range(5, -1, -1):
            count = int(label_counts.get(label, 0))
            pct = _safe_pct(count, len(enrichment_records))
            bar = "█" * int(pct / 2)
            logger.info(f"  L{label} ({label_names[label]:>13}): {count:>6,} ({pct:>5.1f}%) {bar}")

        logger.info("="*70)
        logger.info("Enrichment pipeline complete!")
    finally:
        db.close()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Enrich CVE database with KEV, EPSS, healthcare flags, and labels")
    parser.add_argument('--batch-size', type=int, default=5000, help='Batch size for processing (default: 5000)')
    parser.add_argument('--limit', type=int, help='Limit number of CVEs to process (for testing)')
    parser.add_argument('--dry-run', action='store_true', help='Show plan without making changes')
    parser.add_argument('--validate-only', action='store_true', help='Only validate existing enrichment')
    parser.add_argument('--skip-epss', action='store_true', help='Skip EPSS fetching (use existing EPSS data)')
    parser.add_argument('--skip-attack', action='store_true', help='Skip ATT&CK mapping')
    parser.add_argument('--skip-chpl', action='store_true', help='Skip CHPL mapping')
    
    args = parser.parse_args()

    try:
        if args.validate_only:
            db = CVEDatabase()
            try:
                validate_enrichment(db)
            finally:
                db.close()
        else:
            enrich_database(
                batch_size=args.batch_size,
                limit=args.limit,
                dry_run=args.dry_run,
                skip_epss=args.skip_epss,
                skip_attack=args.skip_attack,
                skip_chpl=args.skip_chpl
            )
        return 0
    except Exception:
        logger.exception("CVE enrichment pipeline failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
