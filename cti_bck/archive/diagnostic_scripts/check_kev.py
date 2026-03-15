import sqlite3

conn = sqlite3.connect('data/cve_database.db')
cursor = conn.cursor()

# Check EPSS data details
cursor.execute("""
SELECT 
    COUNT(*) as total,
    COUNT(CASE WHEN epss_score IS NOT NULL AND epss_score > 0 THEN 1 END) as has_nonzero_epss,
    COUNT(CASE WHEN epss_score = 0.0 THEN 1 END) as is_zero,
    COUNT(CASE WHEN epss_score < 0.01 AND epss_score > 0 THEN 1 END) as below_001_nonzero,
    COUNT(CASE WHEN epss_score > 0.5 THEN 1 END) as above_05,
    ROUND(MAX(epss_score), 4) as max_epss,
    ROUND(AVG(CASE WHEN epss_score > 0 THEN epss_score END), 4) as avg_nonzero_epss
FROM enrichments
""")

row = cursor.fetchone()
total, has_nonzero, is_zero, below_001, above_05, max_epss, avg_nonzero = row

print("=" * 70)
print("EPSS Distribution Check:")
print("=" * 70)
print(f"  Total records: {total:,}")
print(f"  EPSS = 0: {is_zero:,} ({is_zero/total*100:.1f}%)")
print(f"  EPSS > 0: {has_nonzero:,} ({has_nonzero/total*100:.1f}%)")
if has_nonzero > 0:
    print(f"  EPSS 0 < x < 0.01: {below_001:,} ({below_001/has_nonzero*100:.1f}% of non-zero)")
    print(f"  EPSS > 0.5: {above_05:,} ({above_05/has_nonzero*100:.1f}% of non-zero)")
    print(f"  Max EPSS: {max_epss}")
    print(f"  Avg (non-zero): {avg_nonzero}")

# Check ATT&CK data - look at technique count not just flag
cursor.execute("""
SELECT 
    COUNT(*) as total,
    COUNT(CASE WHEN attack_flag = 1 THEN 1 END) as has_attack_flag,
    COUNT(CASE WHEN attack_technique_count > 0 THEN 1 END) as has_techniques,
    MAX(attack_technique_count) as max_techniques,
    ROUND(AVG(CASE WHEN attack_technique_count > 0 THEN attack_technique_count END), 2) as avg_techniques
FROM enrichments
""")

row = cursor.fetchone()
total, has_flag, has_techniques, max_tech, avg_tech = row
print(f"\n" + "=" * 70)
print("ATT&CK Mapping Check:")
print("=" * 70)
print(f"  Total records: {total:,}")
print(f"  attack_flag = 1: {has_flag:,} ({has_flag/total*100:.2f}%)")
print(f"  Has techniques (count > 0): {has_techniques:,} ({has_techniques/total*100:.2f}%)")
if has_techniques > 0:
    print(f"  Max techniques: {max_tech}")
    print(f"  Avg techniques (when > 0): {avg_tech}")

# Sample some ATT&CK mapped CVEs
cursor.execute("""
SELECT c.cve_id, e.attack_technique_count, c.cvss
FROM cves c
JOIN enrichments e ON c.cve_id = e.cve_id
WHERE e.attack_technique_count > 0
ORDER BY e.attack_technique_count DESC
LIMIT 5
""")

print(f"\n  Sample CVEs with ATT&CK mappings:")
for row in cursor.fetchall():
    print(f"    {row[0]}: {row[1]} techniques, CVSS {row[2]}")

conn.close()
