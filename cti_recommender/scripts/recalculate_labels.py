#!/usr/bin/env python3
"""
Recalculate multi-level labels using existing enrichment data.
No API calls - just recompute labels based on KEV/EPSS/healthcare/curated flags already in DB.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.core.cve_database import CVEDatabase
from src.core.multi_level_labels import compute_multi_level_labels

def recalculate_labels(batch_size=10000):
    """Recalculate labels using existing enrichment data."""
    db = CVEDatabase()
    
    # Get total count
    total = db.conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
    print(f"Recalculating labels for {total:,} CVEs...")
    print("Using existing enrichment data - no API calls!\n")
    
    offset = 0
    updated_count = 0
    label_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    
    while offset < total:
        # Fetch batch with all enrichment data
        query = f"""
        SELECT 
            e.cve_id,
            e.kev_flag,
            e.epss_score,
            e.is_healthcare,
            e.is_curated,
            c.cvss
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        LIMIT {batch_size} OFFSET {offset}
        """
        df = pd.read_sql_query(query, db.conn)
        
        # Compute labels
        df = compute_multi_level_labels(df)
        
        # Update database
        for _, row in df.iterrows():
            db.conn.execute(
                "UPDATE enrichments SET label = ? WHERE cve_id = ?",
                (int(row['label']), row['cve_id'])
            )
            label_counts[int(row['label'])] += 1
        
        db.conn.commit()
        updated_count += len(df)
        offset += batch_size
        
        print(f"Progress: {updated_count:,}/{total:,} ({100*updated_count/total:.1f}%)")
    
    db.close()
    
    print(f"\n✅ Complete! Recalculated labels for {updated_count:,} CVEs")
    print("\nLabel Distribution:")
    for label in sorted(label_counts.keys(), reverse=True):
        count = label_counts[label]
        pct = 100 * count / total
        print(f"  L{label}: {count:,} ({pct:.1f}%)")

if __name__ == "__main__":
    recalculate_labels()
