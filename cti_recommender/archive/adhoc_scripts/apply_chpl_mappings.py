#!/usr/bin/env python3
"""
Apply CHPL (Certified Health IT Product List) mappings to CVE database.
Identifies CVEs affecting certified medical devices and health IT products.
Uses cached CHPL data - fetches from API once if cache empty, then reuses cache.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
from datetime import datetime
from src.core.cve_database import CVEDatabase
from src.analysis.chpl_mapper import CHPLMapper

def apply_chpl_mappings(dry_run=True, limit=100):
    """
    Apply CHPL mappings to CVE database.
    
    Args:
        dry_run: If True, only analyze sample without DB updates
        limit: Number of CVEs to process (None = all)
    
    Returns:
        dict: Statistics about mapping results
    """
    print("\n" + "="*70)
    print(f"{'DRY RUN - ' if dry_run else ''}CHPL MAPPING APPLICATION")
    print("="*70)
    
    # Initialize
    db = CVEDatabase()
    mapper = CHPLMapper()
    
    if mapper.products_df is None or len(mapper.products_df) == 0:
        print("\n❌ No CHPL data available - cannot proceed")
        return None
    
    # Get CVEs to process
    if dry_run:
        print(f"\nFetching {limit} sample CVEs for testing...")
        cursor = db.conn.cursor()
        cursor.execute("SELECT cve_id, description FROM cves LIMIT ?", (limit,))
        cves = cursor.fetchall()
    else:
        print("\nFetching all CVEs from database...")
        cursor = db.conn.cursor()
        cursor.execute("SELECT cve_id, description FROM cves")
        cves = cursor.fetchall()
    
    total = len(cves)
    print(f"Processing {total:,} CVEs\n")
    
    # Process CVEs
    matched_count = 0
    match_types = {}
    
    if not dry_run:
        db.conn.execute("BEGIN TRANSACTION")
    
    try:
        for i, (cve_id, description) in enumerate(cves, 1):
            if i % 1000 == 0:
                print(f"  Progress: {i:,}/{total:,} ({i/total*100:.1f}%)")
            
            # Map to CHPL products
            is_match, match_info = mapper.map_cve_to_chpl(description or '')
            
            if is_match:
                matched_count += 1
                
                # Track match types
                for match_type in match_info['match_types']:
                    match_types[match_type] = match_types.get(match_type, 0) + 1
                
                if not dry_run:
                    # Update database
                    db.conn.execute("""
                        UPDATE enrichments
                        SET chpl_flag = 1,
                            updated_at = ?
                        WHERE cve_id = ?
                    """, (datetime.now(), cve_id))
        
        if not dry_run:
            db.conn.commit()
            print("\n✓ Database updated successfully")
        else:
            print("\n✓ Dry run completed (no database changes)")
    
    except Exception as e:
        if not dry_run:
            db.conn.rollback()
        print(f"\n❌ Error during processing: {e}")
        raise
    
    # Print statistics
    print("\n" + "="*70)
    print("MAPPING STATISTICS")
    print("="*70)
    print(f"Total CVEs processed:    {total:,}")
    print(f"CHPL matches:            {matched_count:,} ({matched_count/total*100:.1f}%)")
    print(f"No CHPL match:           {total-matched_count:,} ({(total-matched_count)/total*100:.1f}%)")
    
    if match_types:
        print("\nMatch Type Breakdown:")
        for match_type, count in sorted(match_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {match_type:20s}: {count:,}")
    
    # Show sample matches if dry run
    if dry_run and matched_count > 0:
        print("\nSample CHPL Matches:")
        sample_count = 0
        for cve_id, description in cves:
            is_match, match_info = mapper.map_cve_to_chpl(description or '')
            if is_match and sample_count < 5:
                print(f"\n  {cve_id}")
                print(f"    Description: {description[:100]}...")
                print(f"    Matched: {match_info['match_types']}")
                sample_count += 1
    
    print("\n" + "="*70)
    
    return {
        'total': total,
        'matched': matched_count,
        'match_types': match_types,
        'dry_run': dry_run
    }

def main():
    parser = argparse.ArgumentParser(description='Apply CHPL mappings to CVE database')
    parser.add_argument('--live', action='store_true', help='Apply to full database (default: dry run on 100 CVEs)')
    parser.add_argument('--limit', type=int, help='Number of CVEs to process in dry run (default: 100)')
    
    args = parser.parse_args()
    
    if args.live:
        print("\n🚀 LIVE MODE - Will update database")
        response = input("Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled.")
            return
        
        apply_chpl_mappings(dry_run=False, limit=None)
    else:
        limit = args.limit or 100
        print(f"\n🧪 DRY RUN MODE - Testing on {limit} CVEs (no database changes)")
        apply_chpl_mappings(dry_run=True, limit=limit)

if __name__ == '__main__':
    main()
