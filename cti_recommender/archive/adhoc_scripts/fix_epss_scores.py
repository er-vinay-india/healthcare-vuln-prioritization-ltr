#!/usr/bin/env python3
"""
Investigate and fix EPSS scores using cached data.
Check why EPSS = 0 in database despite enrichment running.
DRY RUN mode available for testing on small sample.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pandas as pd
from src.core.cve_database import CVEDatabase

def check_epss_cache():
    """Check what EPSS data we have cached."""
    print("="*70)
    print("EPSS CACHE INVESTIGATION")
    print("="*70)
    
    cache_path = Path(__file__).parent.parent / 'data_cache' / 'epss' / 'epss_2026-01-17.json'
    
    if not cache_path.exists():
        print("[FAIL] No EPSS cache found!")
        return None
    
    with open(cache_path) as f:
        epss_data = json.load(f)
    
    print(f"\nEPSS cache contains {len(epss_data):,} CVEs")
    print(f"Sample entries:")
    for cve_id, data in list(epss_data.items())[:3]:
        print(f"  {cve_id}: {data}")
    
    return epss_data

def update_epss_from_cache(dry_run=True, limit=100):
    """Update EPSS scores from cached data."""
    print("\n" + "="*70)
    if dry_run:
        print(f"EPSS UPDATE - DRY RUN (limit={limit})")
    else:
        print("EPSS UPDATE - LIVE RUN")
    print("="*70)
    
    # Load cache
    epss_data = check_epss_cache()
    if not epss_data:
        print("Cannot proceed without cache")
        return
    
    # Get CVEs that need EPSS scores
    db = CVEDatabase()
    
    query = f"""
        SELECT e.cve_id 
        FROM enrichments e
        WHERE (e.epss_score IS NULL OR e.epss_score = 0)
        LIMIT {limit if dry_run else 999999}
    """
    
    df = pd.read_sql_query(query, db.conn)
    print(f"\nCVEs needing EPSS update: {len(df):,}")
    
    if len(df) == 0:
        print("[OK] No CVEs need EPSS updates!")
        db.close()
        return
    
    # Update from cache
    updated = 0
    not_in_cache = 0
    
    for _, row in df.iterrows():
        cve_id = row['cve_id']
        
        if cve_id in epss_data:
            epss_info = epss_data[cve_id]
            
            # Extract EPSS fields
            if isinstance(epss_info, dict):
                epss_score = float(epss_info.get('epss', 0))
                epss_percentile = float(epss_info.get('percentile', 0))
                epss_date = epss_info.get('date', '2026-01-17')
            else:
                # Legacy format?
                epss_score = float(epss_info) if epss_info else 0.0
                epss_percentile = 0.0
                epss_date = '2026-01-17'
            
            if not dry_run:
                db.conn.execute("""
                    UPDATE enrichments 
                    SET epss_score = ?,
                        epss_percentile = ?,
                        epss_date = ?
                    WHERE cve_id = ?
                """, (epss_score, epss_percentile, epss_date, cve_id))
            
            updated += 1
        else:
            not_in_cache += 1
    
    if not dry_run:
        db.conn.commit()
        print(f"\n[OK] Updated {updated:,} CVEs with EPSS scores")
    else:
        print(f"\n[STATS] DRY RUN: Would update {updated:,} CVEs")
    
    print(f"[WARN]  {not_in_cache:,} CVEs not in EPSS cache")
    
    # Sample check
    if updated > 0:
        sample = db.conn.execute("""
            SELECT cve_id, epss_score, epss_percentile 
            FROM enrichments 
            WHERE epss_score > 0 
            LIMIT 5
        """).fetchall()
        
        print(f"\nSample EPSS scores:")
        for cve_id, score, percentile in sample:
            print(f"  {cve_id}: EPSS={score:.4f}, Percentile={percentile:.2f}")
    
    db.close()
    print("="*70)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true', help='Run live update (not dry run)')
    parser.add_argument('--limit', type=int, default=100, help='Limit for dry run')
    args = parser.parse_args()
    
    update_epss_from_cache(dry_run=not args.live, limit=args.limit)
