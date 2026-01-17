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
    
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        kev_data = response.json()
        
        kev_cves = {vuln['cveID'] for vuln in kev_data.get('vulnerabilities', [])}
        logger.info(f"✓ Loaded {len(kev_cves):,} CVEs from KEV catalog")
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
            result = epss_fetcher.fetch_epss_bulk(batch)
            
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
            logger.warning(f"Failed to fetch batch {batch_num}: {e}")
            continue
    
    logger.info(f"✓ Fetched {len(epss_scores):,} EPSS scores ({len(epss_scores)/len(cve_ids)*100:.1f}% coverage)")
    return epss_scores


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
    logger.info("🔍 ENRICHMENT VALIDATION")
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
    
    logger.info("Enrichment Coverage:")
    logger.info(f"  Total CVEs: {result[0]:,}")
    logger.info(f"  KEV: {result[1]:,} ({result[1]/result[0]*100:.1f}%)")
    logger.info(f"  EPSS: {result[2]:,} ({result[2]/result[0]*100:.1f}%)")
    logger.info(f"  Healthcare: {result[3]:,} ({result[3]/result[0]*100:.1f}%)")
    logger.info(f"  Curated: {result[4]:,} ({result[4]/result[0]*100:.1f}%)")
    logger.info(f"  CHPL: {result[5]:,} ({result[5]/result[0]*100:.1f}%)")
    logger.info(f"  ATT&CK: {result[6]:,} ({result[6]/result[0]*100:.1f}%)")
    logger.info("EPSS Statistics:")
    logger.info(f"  Average: {result[7]:.4f}")
    logger.info(f"  Maximum: {result[8]:.4f}")
    
    # Critical checks
    issues = []
    if result[2] == 0:
        issues.append("🔴 CRITICAL: EPSS has 0 CVEs! Feature is useless!")
    elif result[2] < result[0] * 0.5:
        issues.append(f"⚠️  WARNING: EPSS coverage is low ({result[2]/result[0]*100:.1f}%)")
    
    if result[3] > result[0] * 0.7:
        issues.append(f"⚠️  WARNING: Healthcare coverage seems high ({result[3]/result[0]*100:.1f}%) - check for false positives")
    
    if issues:
        logger.warning("⚠️  Issues Found:")
        for issue in issues:
            logger.warning(f"  {issue}")
        return False
    else:
        logger.info("✅ Validation passed!")
        return True


def enrich_database(batch_size: int = 5000, limit: int = None, dry_run: bool = False):
    """
    Enrich all CVEs in database with KEV, EPSS, healthcare, curated flags, and labels
    
    Args:
        batch_size: Number of CVEs to process at once
        limit: Optional limit for testing (None = process all)
        dry_run: If True, show plan without making changes
    """
    
    logger.info("="*70)
    if dry_run:
        logger.info("🔍 CVE DATABASE ENRICHMENT - DRY RUN MODE")
    else:
        logger.info("CVE DATABASE ENRICHMENT PIPELINE")
    logger.info("="*70)
    
    # Initialize components
    db = CVEDatabase()
    curated_dataset = HealthcareCuratedDataset()
    healthcare_mapper = HealthcareMapper()
    
    # Get database stats
    stats = db.get_statistics()
    total_cves = stats['total_cves']
    
    if limit:
        total_cves = min(total_cves, limit)
        logger.info(f"Processing {total_cves:,} CVEs (limited for testing)")
    else:
        logger.info(f"Processing {total_cves:,} CVEs")
    
    # Step 1: Fetch KEV catalog
    kev_cves = fetch_kev_catalog()
    
    # Step 2: Query CVEs from database
    logger.info(f"\nLoading CVEs from database...")
    query = "SELECT cve_id, description, cvss FROM cves ORDER BY cve_id DESC"
    if limit:
        query += f" LIMIT {limit}"
    
    cves_df = pd.read_sql_query(query, db.conn)
    logger.info(f"✓ Loaded {len(cves_df):,} CVEs")
    
    # =================================================================
    # PHASE 1: FETCH ALL EPSS DATA (SEPARATE FROM PROCESSING)
    # =================================================================
    logger.info("="*70)
    logger.info("PHASE 1: FETCHING EPSS SCORES")
    logger.info("="*70)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would fetch EPSS for {len(cves_df):,} CVEs")
        logger.info(f"  Estimated time: {len(cves_df)/100*1.5/60:.1f} minutes")
        logger.info(f"  Storage: ~{len(cves_df)*0.2:.1f} KB in persistent cache")
        db.close()
        return
    
    epss_scores = fetch_epss_bulk(cves_df['cve_id'].tolist())
    
    # Verify EPSS fetch completeness
    epss_coverage = len(epss_scores) / len(cves_df) * 100
    logger.info(f"\n✓ EPSS Fetch Complete: {len(epss_scores):,}/{len(cves_df):,} CVEs ({epss_coverage:.1f}%)")
    
    if epss_coverage < 50:
        logger.warning(f"⚠️  Low EPSS coverage ({epss_coverage:.1f}%) - many CVEs may not be in EPSS database")
    
    # =================================================================
    # PHASE 2: PROCESS CVEs AND PREPARE ENRICHMENT DATA
    # =================================================================
    logger.info("="*70)
    logger.info("PHASE 2: PROCESSING CVEs")
    logger.info("="*70)
    
    # Step 4: Process CVEs in batches
    logger.info(f"\nProcessing CVEs in batches of {batch_size:,}...")
    
    total_batches = (len(cves_df) + batch_size - 1) // batch_size
    enrichment_records = []
    
    for batch_idx in range(0, len(cves_df), batch_size):
        batch_df = cves_df.iloc[batch_idx:batch_idx + batch_size].copy()
        batch_num = batch_idx // batch_size + 1
        
        # Add KEV flags
        batch_df['kev_flag'] = batch_df['cve_id'].isin(kev_cves).astype(int)
        
        # Add EPSS scores - extract from dict properly
        batch_df['epss_score'] = batch_df['cve_id'].apply(
            lambda cve: epss_scores.get(cve, {}).get('epss_score', 0.0)
        )
        batch_df['epss_percentile'] = batch_df['cve_id'].apply(
            lambda cve: epss_scores.get(cve, {}).get('percentile', 0.0)
        )
        
        # Add healthcare flags
        batch_df['is_healthcare'] = batch_df.apply(
            lambda row: int(detect_healthcare_relevance({'description': row['description']}, healthcare_mapper)),
            axis=1
        )
        
        # Add curated flags
        batch_df['is_curated'] = batch_df['cve_id'].apply(
            lambda cve_id: int(curated_dataset.is_curated(cve_id))
        ).astype(int)
        
        # Add curated exploited flag
        batch_df['curated_exploited'] = batch_df['cve_id'].apply(
            lambda cve_id: int(curated_dataset.get_breach_info(cve_id).get('exploited_in_wild', False))
            if curated_dataset.is_curated(cve_id) else 0
        ).astype(int)
        
        # Compute multi-level labels
        batch_df = compute_multi_level_labels(batch_df)
        
        # Prepare enrichment records
        for _, row in batch_df.iterrows():
            enrichment_records.append({
                'cve_id': row['cve_id'],
                'kev_flag': row['kev_flag'],
                'epss_score': row['epss_score'],
                'epss_percentile': row.get('epss_percentile', 0.0),
                'is_healthcare': row['is_healthcare'],
                'is_curated': row['is_curated'],
                'label': row['label']
            })
        
        logger.info(f"  Batch {batch_num}/{total_batches} - Processed {len(batch_df):,} CVEs " +
                   f"(KEV: {batch_df['kev_flag'].sum()}, Healthcare: {batch_df['is_healthcare'].sum()}, " +
                   f"Curated: {batch_df['is_curated'].sum()})")
    
    # =================================================================
    # PHASE 3: SAVE TO DATABASE (TRANSACTIONAL)
    # =================================================================
    logger.info("="*70)
    logger.info("PHASE 3: SAVING TO DATABASE")
    logger.info("="*70)
    
    logger.info(f"\nPreparing to upsert {len(enrichment_records):,} enrichment records...")
    enrichments_df = pd.DataFrame(enrichment_records)
    
    # Validate data before saving
    epss_in_records = (enrichments_df['epss_score'] > 0).sum()
    logger.info(f"  Records with EPSS scores: {epss_in_records:,} ({epss_in_records/len(enrichments_df)*100:.1f}%)")
    logger.info(f"  Records with KEV flag: {enrichments_df['kev_flag'].sum():,}")
    logger.info(f"  Records with Healthcare flag: {enrichments_df['is_healthcare'].sum():,}")
    
    # Save with transaction safety
    try:
        db.conn.execute("BEGIN TRANSACTION")
        db.upsert_enrichments(enrichments_df)
        db.conn.commit()
        logger.info("✓ Database transaction committed successfully")
    except Exception as e:
        db.conn.rollback()
        logger.error(f"❌ Database transaction failed, rolled back: {e}")
        raise
    
    # Step 6: Print final statistics
    logger.info("="*70)
    logger.info("ENRICHMENT SUMMARY")
    logger.info("="*70)
    
    final_stats = db.get_statistics()
    logger.info(f"Total CVEs enriched: {len(enrichment_records):,}", extra={'total_enriched': len(enrichment_records)})
    logger.info(f"KEV-flagged CVEs: {final_stats['kev_count']:,} ({final_stats['kev_count']/len(enrichment_records)*100:.1f}%)", extra={'kev_count': final_stats['kev_count']})
    logger.info(f"Healthcare-relevant CVEs: {final_stats['healthcare_count']:,} ({final_stats['healthcare_count']/len(enrichment_records)*100:.1f}%)", extra={'healthcare_count': final_stats['healthcare_count']})
    logger.info(f"Curated breach CVEs: {final_stats['curated_count']:,} ({final_stats['curated_count']/len(enrichment_records)*100:.1f}%)", extra={'curated_count': final_stats['curated_count']})
    
    # Label distribution
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
        count = label_counts.get(label, 0)
        pct = count / len(enrichment_records) * 100 if len(enrichment_records) > 0 else 0
        bar = "█" * int(pct / 2)
        logger.info(f"  L{label} ({label_names[label]:>13}): {count:>6,} ({pct:>5.1f}%) {bar}")
    
    logger.info("="*70)
    
    db.close()
    logger.info("Enrichment pipeline complete!")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enrich CVE database with KEV, EPSS, healthcare flags, and labels")
    parser.add_argument('--batch-size', type=int, default=5000, help='Batch size for processing (default: 5000)')
    parser.add_argument('--limit', type=int, help='Limit number of CVEs to process (for testing)')
    parser.add_argument('--dry-run', action='store_true', help='Show plan without making changes')
    parser.add_argument('--validate-only', action='store_true', help='Only validate existing enrichment')
    
    args = parser.parse_args()
    
    if args.validate_only:
        db = CVEDatabase()
        validate_enrichment(db)
        db.close()
    else:
        enrich_database(batch_size=args.batch_size, limit=args.limit, dry_run=args.dry_run)
