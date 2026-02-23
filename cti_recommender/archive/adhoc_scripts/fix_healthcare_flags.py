#!/usr/bin/env python3
"""
Quick script to fix healthcare flags using existing data in database.
No API calls needed - just re-run healthcare detection on descriptions we already have.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.core.cve_database import CVEDatabase
from src.analysis.healthcare_mapping import HealthcareMapper

def fix_healthcare_flags(batch_size=10000):
    """Update healthcare flags using existing CVE descriptions."""
    db = CVEDatabase()
    mapper = HealthcareMapper()
    
    # Get total count
    total = db.conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    print(f"Fixing healthcare flags for {total:,} CVEs...")
    print("Using existing descriptions - no API calls needed!\n")
    
    offset = 0
    updated_count = 0
    healthcare_count = 0
    
    while offset < total:
        # Fetch batch of CVEs
        query = f"""
        SELECT cve_id, description 
        FROM cves 
        LIMIT {batch_size} OFFSET {offset}
        """
        df = pd.read_sql_query(query, db.conn)
        
        # Detect healthcare relevance
        df['is_healthcare'] = df['description'].apply(
            lambda desc: 1 if mapper.check_healthcare_keyword(str(desc)) or 
                              mapper.check_vendor_match(str(desc)) or 
                              mapper.check_product_match(str(desc)) else 0
        )
        
        # Update database directly
        for _, row in df.iterrows():
            db.conn.execute(
                "UPDATE enrichments SET is_healthcare = ? WHERE cve_id = ?",
                (row['is_healthcare'], row['cve_id'])
            )
            if row['is_healthcare']:
                healthcare_count += 1
        
        db.conn.commit()
        updated_count += len(df)
        offset += batch_size
        
        print(f"Progress: {updated_count:,}/{total:,} ({100*updated_count/total:.1f}%) - "
              f"Healthcare CVEs found: {healthcare_count:,}")
    
    db.close()
    
    print(f"\n[OK] Complete! Updated {updated_count:,} CVEs")
    print(f"Healthcare-relevant CVEs: {healthcare_count:,} ({100*healthcare_count/total:.2f}%)")

if __name__ == "__main__":
    fix_healthcare_flags()
