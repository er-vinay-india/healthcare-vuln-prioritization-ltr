#!/usr/bin/env python3
"""
Update database EPSS scores from existing cache (NO API calls)
Fast operation to load cached EPSS data into database
"""
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase
from tqdm import tqdm

def update_epss_from_cache():
    """Load EPSS from persistent cache and update database"""
    
    print("="*70)
    print("UPDATE DATABASE EPSS FROM CACHE")
    print("="*70)
    
    # Load cache
    cache_path = Path("cache/epss/epss_persistent.json")
    if not cache_path.exists():
        print(f"ERROR: Cache file not found: {cache_path}")
        return False
    
    print(f"\nLoading cache: {cache_path}")
    with open(cache_path, 'r') as f:
        epss_cache = json.load(f)
    
    print(f"✓ Loaded {len(epss_cache):,} EPSS records from cache")
    print(f"  Cache size: {cache_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    # Connect to database
    db = CVEDatabase()
    
    # Get all CVE IDs from database
    cursor = db.conn.cursor()
    cursor.execute("SELECT cve_id FROM enrichments")
    db_cves = [row[0] for row in cursor.fetchall()]
    
    print(f"\n✓ Database has {len(db_cves):,} enrichment records")
    
    # Match cache to database
    matched = set(db_cves) & set(epss_cache.keys())
    print(f"✓ {len(matched):,} CVEs match between cache and database ({len(matched)/len(db_cves)*100:.1f}%)")
    
    # Prepare update records
    updates = []
    for cve_id in matched:
        epss_data = epss_cache[cve_id]
        updates.append((
            epss_data.get('epss_score', 0.0),
            epss_data.get('percentile', 0.0),
            epss_data.get('date'),
            cve_id
        ))
    
    print(f"\nPreparing to update {len(updates):,} records...")
    
    # Batch update
    batch_size = 5000
    total_batches = (len(updates) + batch_size - 1) // batch_size
    
    print(f"Updating in {total_batches} batches of {batch_size:,}...")
    
    cursor = db.conn.cursor()
    for i in tqdm(range(0, len(updates), batch_size), desc="Updating EPSS"):
        batch = updates[i:i+batch_size]
        cursor.executemany("""
            UPDATE enrichments 
            SET epss_score = ?, 
                epss_percentile = ?,
                epss_date = ?
            WHERE cve_id = ?
        """, batch)
        db.conn.commit()
    
    print(f"\n✓ Updated {len(updates):,} EPSS records in database")
    
    # Verify update
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN epss_score > 0 THEN 1 ELSE 0 END) as has_epss,
            AVG(epss_score) as avg_epss,
            MAX(epss_score) as max_epss
        FROM enrichments
    """)
    
    total, has_epss, avg_epss, max_epss = cursor.fetchone()
    
    print(f"\n{"="*70}")
    print("POST-UPDATE VERIFICATION:")
    print(f"{"="*70}")
    print(f"Total enrichments: {total:,}")
    print(f"With EPSS > 0: {has_epss:,} ({has_epss/total*100:.1f}%)")
    print(f"Average EPSS: {avg_epss:.5f}")
    print(f"Max EPSS: {max_epss:.5f}")
    
    if has_epss == 0:
        print("\n❌ ERROR: Still no EPSS data after update!")
        return False
    elif has_epss < total * 0.5:
        print(f"\n⚠️  WARNING: Low EPSS coverage ({has_epss/total*100:.1f}%)")
        return True
    else:
        print(f"\n✓ SUCCESS: EPSS data loaded ({has_epss/total*100:.1f}% coverage)")
        return True

if __name__ == "__main__":
    success = update_epss_from_cache()
    sys.exit(0 if success else 1)
