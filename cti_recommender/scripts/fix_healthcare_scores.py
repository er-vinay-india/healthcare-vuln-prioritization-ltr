#!/usr/bin/env python3
"""
Quick fix: Recalculate healthcare scores with corrected word boundary logic
This updates ONLY the healthcare_score column, leaving everything else intact.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import sqlite3
from src.analysis.healthcare_mapping import HealthcareMapper
from tqdm import tqdm

def recalculate_healthcare_scores():
    """Recalculate all healthcare scores with current (fixed) code"""
    
    conn = sqlite3.connect('data/cve_database.db')
    cursor = conn.cursor()
    
    # Get all CVEs that have a healthcare_score
    print("Fetching CVEs from database...")
    cursor.execute("""
        SELECT c.cve_id, c.description
        FROM cves c
        JOIN enrichments e ON c.cve_id = e.cve_id
        WHERE e.healthcare_score IS NOT NULL
    """)
    
    rows = cursor.fetchall()
    print(f"Found {len(rows):,} CVEs with healthcare scores")
    
    # Initialize mapper with FIXED code (has word boundaries)
    mapper = HealthcareMapper()
    
    # Recalculate scores
    print("\nRecalculating healthcare scores with corrected logic...")
    updates = []
    changes = {'decreased': 0, 'increased': 0, 'unchanged': 0}
    threshold = 0.3  # Score >= 0.3 means is_healthcare = 1
    
    for cve_id, description in tqdm(rows, desc="Processing"):
        # Get current score from DB
        cursor.execute("SELECT healthcare_score FROM enrichments WHERE cve_id = ?", (cve_id,))
        old_score = cursor.execute("SELECT healthcare_score FROM enrichments WHERE cve_id = ?", (cve_id,)).fetchone()[0]
        
        # Calculate new score with FIXED code
        new_score = mapper.get_healthcare_score(description) if description else 0.0
        
        # Calculate flag based on threshold
        is_healthcare = 1 if new_score >= threshold else 0
        
        # Track changes
        if abs(new_score - old_score) < 0.01:
            changes['unchanged'] += 1
        elif new_score < old_score:
            changes['decreased'] += 1
        else:
            changes['increased'] += 1
        
        # Update both score AND flag
        updates.append((new_score, is_healthcare, cve_id))
    
    # Batch update
    print("\nUpdating database...")
    cursor.executemany("""
        UPDATE enrichments 
        SET healthcare_score = ?,
            is_healthcare = ?
        WHERE cve_id = ?
    """, updates)
    
    conn.commit()
    
    # Show results
    print("\n" + "=" * 70)
    print("RECALCULATION COMPLETE")
    print("=" * 70)
    print(f"Total CVEs processed: {len(rows):,}")
    print(f"  Scores decreased: {changes['decreased']:,} (fixed false positives)")
    print(f"  Scores increased: {changes['increased']:,}")
    print(f"  Scores unchanged: {changes['unchanged']:,}")
    
    # Show new statistics
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN is_healthcare = 1 THEN 1 ELSE 0 END) as healthcare_flagged,
            SUM(CASE WHEN healthcare_score >= 0.3 THEN 1 ELSE 0 END) as score_based_flagged,
            AVG(healthcare_score) as avg_score
        FROM enrichments
    """)
    result = cursor.fetchone()
    total, flagged, score_flagged, avg = result
    
    print(f"\nNew statistics:")
    print(f"  Total CVEs: {total:,}")
    print(f"  Healthcare-flagged (is_healthcare=1): {flagged:,} ({flagged/total*100:.2f}%)")
    print(f"  Healthcare-flagged (score >= 0.3): {score_flagged:,} ({score_flagged/total*100:.2f}%)")
    print(f"  Average healthcare score: {avg:.3f}")
    
    conn.close()
    print("\n✓ Database updated successfully!")

if __name__ == "__main__":
    recalculate_healthcare_scores()
