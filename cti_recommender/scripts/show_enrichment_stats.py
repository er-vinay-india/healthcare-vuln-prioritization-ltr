#!/usr/bin/env python
"""Show enrichment summary and sample high-priority CVEs"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase
import pandas as pd

db = CVEDatabase()
stats = db.get_statistics()

print('\n' + '='*70)
print('DATABASE ENRICHMENT SUMMARY')
print('='*70)
print(f'\nTotal CVEs: {stats["total_cves"]:,}')
print(f'Date Range: {stats["date_range"][0][:10]} to {stats["date_range"][1][:10]}')
print(f'CVEs with CVSS: {stats["cves_with_cvss"]:,} ({stats["cves_with_cvss"]/stats["total_cves"]*100:.1f}%)')
print(f'\nEnrichments:')
print(f'  • KEV-flagged: {stats["kev_count"]:,}')
print(f'  • Healthcare-relevant: {stats["healthcare_count"]:,}')
print(f'  • Curated breaches: {stats["curated_count"]:,}')

# Get label distribution
query = '''
    SELECT label, COUNT(*) as count 
    FROM enrichments 
    GROUP BY label 
    ORDER BY label DESC
'''
label_df = pd.read_sql_query(query, db.conn)

print(f'\nLabel Distribution:')
label_names = {5: 'Critical', 4: 'High', 3: 'Medium', 2: 'Low', 1: 'Informational', 0: 'Irrelevant'}
for _, row in label_df.iterrows():
    label = int(row['label'])
    count = int(row['count'])
    pct = count / stats['total_cves'] * 100
    bar = '█' * int(pct / 2)
    print(f'  L{label} ({label_names[label]:>13}): {count:>7,} ({pct:>5.1f}%) {bar}')

# Sample high-priority CVEs
print(f'\n' + '='*70)
print('SAMPLE HIGH-PRIORITY CVEs (Label 3+)')
print('='*70)
sample_query = '''
    SELECT c.cve_id, c.cvss, e.epss_score, e.kev_flag, e.is_healthcare, e.label
    FROM cves c
    JOIN enrichments e ON c.cve_id = e.cve_id
    WHERE e.label >= 3
    ORDER BY e.label DESC, e.epss_score DESC
    LIMIT 20
'''
sample_df = pd.read_sql_query(sample_query, db.conn)
print(sample_df.to_string(index=False))

print('\n' + '='*70 + '\n')

db.close()
