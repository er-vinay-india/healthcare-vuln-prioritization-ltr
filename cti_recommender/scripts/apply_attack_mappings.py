#!/usr/bin/env python3
"""
Apply ATT&CK mappings to CVEs using cached ATT&CK matrix.
No external API calls - uses local cache only.
Supports dry run mode for testing on limited sample.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pandas as pd
from src.core.cve_database import CVEDatabase
from src.analysis.attack_mapper import AttackMapper

def apply_attack_mappings(dry_run=True, limit=100):
    """Apply ATT&CK technique mappings to CVEs."""
    print("="*70)
    if dry_run:
        print(f"ATT&CK MAPPING - DRY RUN (limit={limit})")
    else:
        print("ATT&CK MAPPING - LIVE RUN")
    print("="*70)
    
    # Initialize mapper
    mapper = AttackMapper()
    
    # Connect to database
    db = CVEDatabase()
    
    # Get CVEs to process
    query = f"""
        SELECT e.cve_id, c.description
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE c.description IS NOT NULL
        LIMIT {limit if dry_run else 999999}
    """
    
    df = pd.read_sql_query(query, db.conn)
    print(f"\nProcessing {len(df):,} CVEs...")
    
    # Apply mappings
    mapped_count = 0
    technique_counts = {}
    
    for idx, row in df.iterrows():
        cve_id = row['cve_id']
        description = row['description']
        
        # Map to ATT&CK techniques
        result = mapper.map_cve_to_techniques(description)
        
        if result['attack_flag']:
            mapped_count += 1
            
            # Update database
            if not dry_run:
                techniques_json = json.dumps(result['techniques'])
                db.conn.execute("""
                    UPDATE enrichments
                    SET attack_flag = ?,
                        attack_technique_count = ?,
                        attack_techniques = ?
                    WHERE cve_id = ?
                """, (
                    result['attack_flag'],
                    result['technique_count'],
                    techniques_json,
                    cve_id
                ))
            
            # Track technique distribution
            for tech in result['techniques']:
                technique_counts[tech] = technique_counts.get(tech, 0) + 1
        
        # Progress
        if (idx + 1) % 1000 == 0:
            print(f"  Processed {idx+1:,}/{len(df):,} ({100*(idx+1)/len(df):.1f}%) - Mapped: {mapped_count:,}")
    
    if not dry_run:
        db.conn.commit()
    
    # Results
    print(f"\n" + "="*70)
    print("RESULTS")
    print("="*70)
    
    if dry_run:
        print(f"DRY RUN: Would map {mapped_count:,} / {len(df):,} CVEs ({100*mapped_count/len(df):.1f}%)")
    else:
        print(f"✅ Mapped {mapped_count:,} / {len(df):,} CVEs ({100*mapped_count/len(df):.1f}%)")
    
    # Top techniques
    print(f"\nTop 10 most matched techniques:")
    sorted_techs = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
    for tech_id, count in sorted_techs[:10]:
        info = mapper.get_technique_info(tech_id)
        print(f"  {tech_id}: {count:,} CVEs - {info.get('name', 'Unknown')}")
    
    db.close()
    print("="*70)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true', help='Run live update (not dry run)')
    parser.add_argument('--limit', type=int, default=100, help='Limit for dry run')
    args = parser.parse_args()
    
    apply_attack_mappings(dry_run=not args.live, limit=args.limit)
