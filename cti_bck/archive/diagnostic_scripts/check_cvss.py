import sqlite3

conn = sqlite3.connect('data/cve_database.db')
cursor = conn.cursor()

print("=" * 60)
print("CVSS SEVERITY DISTRIBUTION ANALYSIS")
print("=" * 60)

# CVSS distribution by severity bands
cursor.execute("""
SELECT 
    CASE 
        WHEN cvss >= 9.0 THEN 'Critical (9.0-10.0)'
        WHEN cvss >= 7.0 THEN 'High (7.0-8.9)'
        WHEN cvss >= 4.0 THEN 'Medium (4.0-6.9)'
        WHEN cvss > 0 THEN 'Low (0.1-3.9)'
        ELSE 'None/Unknown'
    END as severity,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM cves), 2) as percentage
FROM cves
GROUP BY severity
ORDER BY MIN(cvss) DESC NULLS LAST
""")

print("\nCVSS Severity Distribution:")
print("-" * 60)
print(f"{'Severity Band':<25} {'Count':>12} {'Percentage':>12}")
print("-" * 60)

results = cursor.fetchall()
for row in results:
    print(f"{row[0]:<25} {row[1]:>12,} {row[2]:>11.2f}%")

# CVSS statistics
cursor.execute("""
SELECT 
    COUNT(*) as total,
    COUNT(cvss) as has_cvss,
    ROUND(AVG(cvss), 2) as avg_cvss,
    ROUND(MIN(cvss), 2) as min_cvss,
    ROUND(MAX(cvss), 2) as max_cvss
FROM cves
""")

print("\n" + "=" * 60)
print("CVSS Statistics:")
print("-" * 60)
total, has_cvss, avg_cvss, min_cvss, max_cvss = cursor.fetchone()
print(f"Total CVEs: {total:,}")
print(f"With CVSS scores: {has_cvss:,} ({has_cvss/total*100:.2f}%)")
print(f"Missing CVSS: {total-has_cvss:,} ({(total-has_cvss)/total*100:.2f}%)")
print(f"\nCVSS Range: {min_cvss} - {max_cvss}")
print(f"Mean CVSS: {avg_cvss}")

# Year-by-year CVSS averages
cursor.execute("""
SELECT 
    strftime('%Y', published) as year,
    COUNT(*) as total,
    COUNT(cvss) as has_cvss,
    ROUND(AVG(cvss), 2) as avg_cvss
FROM cves
WHERE published IS NOT NULL
GROUP BY year
ORDER BY year
""")

print("\n" + "=" * 60)
print("CVSS Trends by Year:")
print("-" * 60)
print(f"{'Year':<6} {'Total CVEs':>12} {'With CVSS':>12} {'Avg CVSS':>10}")
print("-" * 60)

for row in cursor.fetchall():
    year, total_year, has_cvss_year, avg_cvss_year = row
    print(f"{year:<6} {total_year:>12,} {has_cvss_year:>12,} {avg_cvss_year:>10}")

conn.close()
