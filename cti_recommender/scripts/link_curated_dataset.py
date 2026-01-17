#!/usr/bin/env python3
"""
Quick script to link curated healthcare dataset to enrichments table.
No API calls - just DB updates using existing healthcare_breaches.json.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
from src.core.cve_database import CVEDatabase

def link_curated_dataset():
    """Flag curated CVEs in enrichments table."""
    print("="*70)
    print("LINKING CURATED DATASET (NO API CALLS)")
    print("="*70)
    
    # Load curated dataset
    curated_path = Path(__file__).parent.parent / 'data' / 'healthcare_breaches.json'
    with open(curated_path) as f:
        data = json.load(f)
    
    breaches = data['breaches']
    print(f"\nLoaded {len(breaches)} curated healthcare breaches")
    
    # Connect to database
    db = CVEDatabase()
    
    # Update enrichments table
    updated = 0
    not_found = []
    
    for breach in breaches:
        cve_id = breach['cve_id']
        
        # Check if CVE exists in database
        result = db.conn.execute(
            "SELECT COUNT(*) FROM cves WHERE cve_id = ?", 
            (cve_id,)
        ).fetchone()
        
        if result[0] == 0:
            not_found.append(cve_id)
            continue
        
        # Update enrichments
        db.conn.execute("""
            UPDATE enrichments 
            SET is_curated = 1,
                curated_severity = ?
            WHERE cve_id = ?
        """, (breach['severity'], cve_id))
        
        updated += 1
    
    db.conn.commit()
    db.close()
    
    print(f"\n✅ Updated {updated} CVEs with curated flags")
    if not_found:
        print(f"⚠️  {len(not_found)} CVEs not found in database:")
        for cve in not_found[:10]:
            print(f"    {cve}")
        if len(not_found) > 10:
            print(f"    ... and {len(not_found) - 10} more")
    
    print("="*70)

if __name__ == "__main__":
    link_curated_dataset()
