#!/usr/bin/env python3
"""Diagnose EPSS data in database"""
import sqlite3

conn = sqlite3.connect('data/cve_database.db')
cursor = conn.cursor()

print("=" * 80)
print("EPSS DATA DIAGNOSTIC")
print("=" * 80)

# Check schema
cursor.execute("PRAGMA table_info(enrichments)")
schema = cursor.fetchall()
epss_cols = [col for col in schema if 'epss' in col[1].lower()]
print(f"\nEPSS-related columns: {[col[1] for col in epss_cols]}")

# Overall stats
cursor.execute("""
SELECT 
    COUNT(*) as total,
    COUNT(epss_score) as non_null,
    SUM(CASE WHEN epss_score = 0.0 THEN 1 ELSE 0 END) as zeros,
    SUM(CASE WHEN epss_score > 0.0 THEN 1 ELSE 0 END) as positive,
    MIN(epss_score) as min_val,
    MAX(epss_score) as max_val
FROM enrichments
""")

total, non_null, zeros, positive, min_val, max_val = cursor.fetchone()

print(f"\nTotal enrichment records: {total:,}")
print(f"Non-NULL epss_score: {non_null:,}")
print(f"Zero values (0.0): {zeros:,}")
print(f"Positive values (>0): {positive:,}")
print(f"Min value: {min_val}")
print(f"Max value: {max_val}")

# Sample some records
print(f"\n{'='*80}")
print("SAMPLE RECORDS (first 10):")
print(f"{'='*80}")
cursor.execute("SELECT cve_id, epss_score, epss_percentile FROM enrichments LIMIT 10")
for row in cursor.fetchall():
    print(f"  {row[0]}: score={row[1]}, percentile={row[2]}")

# If there are positive values, show them
if positive > 0:
    print(f"\n{'='*80}")
    print("POSITIVE EPSS SCORES (first 10):")
    print(f"{'='*80}")
    cursor.execute("""
    SELECT cve_id, epss_score, epss_percentile 
    FROM enrichments 
    WHERE epss_score > 0 
    LIMIT 10
    """)
    for row in cursor.fetchall():
        print(f"  {row[0]}: score={row[1]}, percentile={row[2]}")

conn.close()
