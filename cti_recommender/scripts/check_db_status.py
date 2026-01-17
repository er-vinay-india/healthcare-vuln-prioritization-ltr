#!/usr/bin/env python3
"""Check database status after CHPL mapping."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase

db = CVEDatabase()
cursor = db.conn.cursor()

print('='*70)
print('DATABASE STATUS AFTER CHPL MAPPING')
print('='*70)

# Check enrichment signals
cursor.execute('SELECT COUNT(*) FROM enrichments WHERE kev_flag = 1')
kev = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1')
healthcare = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM enrichments WHERE attack_flag = 1')
attack = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM enrichments WHERE chpl_flag = 1')
chpl = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM enrichments WHERE is_curated = 1')
curated = cursor.fetchone()[0]

print(f'\n📊 Multi-Source Coverage:')
print(f'   KEV (exploited):              {kev:,}')
print(f'   Healthcare-related:           {healthcare:,}')
print(f'   ATT&CK mapped:                {attack:,}')
print(f'   CHPL certified products:      {chpl:,}')
print(f'   Curated breaches:             {curated:,}')

print(f'\n🎯 Multi-signal CVEs:')
cursor.execute('SELECT COUNT(*) FROM enrichments WHERE kev_flag = 1 AND is_healthcare = 1')
kev_healthcare = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM enrichments WHERE chpl_flag = 1 AND is_healthcare = 1')
chpl_healthcare = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM enrichments WHERE attack_flag = 1 AND is_healthcare = 1')
attack_healthcare = cursor.fetchone()[0]

print(f'   KEV + Healthcare:             {kev_healthcare:,}')
print(f'   CHPL + Healthcare:            {chpl_healthcare:,}')
print(f'   ATT&CK + Healthcare:          {attack_healthcare:,}')

print('\n' + '='*70)
print('✅ Phase 3 Complete - Ready for next steps')
print('='*70)
