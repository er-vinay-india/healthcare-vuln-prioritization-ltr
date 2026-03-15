#!/usr/bin/env python3
"""
Analyze why CVEs are flagged as healthcare-related
Provides transparency on the healthcare mapping logic
"""

import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.analysis.healthcare_mapping import HealthcareMapper, HEALTHCARE_KEYWORDS
import sqlite3

def analyze_healthcare_flags(num_samples=20):
    """Show exactly why CVEs are flagged as healthcare-related"""
    
    conn = sqlite3.connect(project_root / 'data' / 'cve_database.db')
    cursor = conn.cursor()
    
    # Get sample healthcare-flagged CVEs with different scores
    # Focus on score 0.5 since 98% of flags are this score (vendor-only matches)
    cursor.execute("""
    SELECT c.cve_id, c.description, e.healthcare_score
    FROM cves c  
    JOIN enrichments e ON c.cve_id = e.cve_id
    WHERE e.is_healthcare = 1 AND e.healthcare_score = 0.5
    ORDER BY RANDOM()
    LIMIT ?
    """, (num_samples,))
    
    results = cursor.fetchall()
    mapper = HealthcareMapper()
    
    print("=" * 120)
    print(f"HEALTHCARE CLASSIFICATION TRANSPARENCY REPORT ({len(results)} samples)")
    print("=" * 120)
    print(f"\nScoring Logic:")
    print(f"  • Vendor match: +0.5 points")
    print(f"  • Product match: +0.3 points")
    print(f"  • Keyword match: +0.2 points")
    print(f"  • Threshold: >0.3 = flagged as healthcare")
    print("=" * 120)
    
    score_counts = {}
    reason_counts = {'vendor': 0, 'product': 0, 'keyword': 0}
    
    for cve_id, desc, score in results:
        score_counts[score] = score_counts.get(score, 0) + 1
        
        print(f"\n{cve_id} | Score: {score}")
        print(f"  Description: {desc[:150]}...")
        
        # Check what matched
        desc_lower = desc.lower() if desc else ""
        reasons = []
        
        # Vendor match (0.5 points)
        vendor_match = mapper.check_vendor_match(desc)
        if vendor_match:
            reasons.append(f"Vendor '{vendor_match}'")
            reason_counts['vendor'] += 1
        
        # Product match (0.3 points)
        if mapper.check_product_match(desc):
            reasons.append("Product keywords")
            reason_counts['product'] += 1
        
        # Keyword match (0.2 points)
        matched_keywords = [kw for kw in HEALTHCARE_KEYWORDS if kw.lower() in desc_lower]
        if matched_keywords:
            reasons.append(f"Keywords: {', '.join(matched_keywords[:3])}")
            reason_counts['keyword'] += 1
        
        print(f"  ✓ Matched: {' + '.join(reasons)}")
    
    # Summary statistics
    print("\n" + "=" * 120)
    print("SUMMARY STATISTICS")
    print("=" * 120)
    print(f"\nScore Distribution in sample:")
    for score in sorted(score_counts.keys(), reverse=True):
        count = score_counts[score]
        pct = (count / len(results)) * 100
        print(f"  Score {score}: {count:2d} CVEs ({pct:5.1f}%)")
    
    print(f"\nMatch Reasons:")
    for reason, count in reason_counts.items():
        pct = (count / len(results)) * 100
        print(f"  {reason.title()}: {count:2d} ({pct:5.1f}%)")
    
    # Get full database statistics
    cursor.execute("SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1")
    total_healthcare = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM enrichments")
    total_cves = cursor.fetchone()[0]
    
    print(f"\nDatabase Totals:")
    print(f"  Total CVEs: {total_cves:,}")
    print(f"  Flagged as healthcare: {total_healthcare:,} ({total_healthcare/total_cves*100:.2f}%)")
    
    conn.close()
    
    print("\n" + "=" * 120)
    print("[INFO] To adjust sensitivity, modify thresholds in src/analysis/healthcare_mapping.py")
    print("=" * 120)

if __name__ == "__main__":
    analyze_healthcare_flags(num_samples=30)
