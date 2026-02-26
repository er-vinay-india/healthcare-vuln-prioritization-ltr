#!/usr/bin/env python3
"""Quick test to check false positive CVEs"""

from src.analysis.healthcare_mapping import HealthcareMapper
import sqlite3

# Connect to database
conn = sqlite3.connect('data/cve_database.db')
cursor = conn.cursor()

# Get 5 CVEs with score 0.5
cursor.execute("""
SELECT c.cve_id, c.description, e.healthcare_score
FROM cves c
JOIN enrichments e ON c.cve_id = e.cve_id
WHERE e.healthcare_score >= 0.45 AND e.healthcare_score <= 0.55
LIMIT 5
""")

rows = cursor.fetchall()
mapper = HealthcareMapper()

print("Testing CVEs with healthcare_score = 0.5")
print("=" * 80)

for cve_id, description, db_score in rows:
    calc_score = mapper.get_healthcare_score(description)
    vendor = mapper.check_vendor_match(description)
    product = mapper.check_product_match(description)
    keyword = mapper.check_healthcare_keyword(description)
    
    print(f"\n{cve_id} (DB score: {db_score})")
    print(f"Description: {description[:150]}...")
    print(f"Calculated score: {calc_score}")
    print(f"  Vendor: {vendor}, Product: {product}, Keyword: {keyword}")
    
    if calc_score != db_score:
        print(f"  ⚠️  MISMATCH: DB has {db_score} but calculation gives {calc_score}")

conn.close()
