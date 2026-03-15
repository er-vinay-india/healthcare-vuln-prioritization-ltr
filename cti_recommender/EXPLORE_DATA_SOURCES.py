"""
Explore Available Data Sources for Additional Feature Engineering
==================================================================

This script examines what raw data is available in our data sources
to identify opportunities for additional feature extraction.
"""

import sqlite3
import pandas as pd
import json
from pathlib import Path

print("="*80)
print("DATA SOURCE EXPLORATION FOR FEATURE ENGINEERING")
print("="*80)

# 1. Check SQLite database tables and columns
print("\n[1] DATABASE SCHEMA ANALYSIS")
print("-" * 80)
conn = sqlite3.connect('cache/cve_database.db')

# Get all table names
tables = pd.read_sql_query(
    "SELECT name FROM sqlite_master WHERE type='table'", 
    conn
)
print(f"\nAvailable tables ({len(tables)}):")
for table in tables['name']:
    print(f"  - {table}")
    
    # Get column info for each table
    columns = pd.read_sql_query(f"PRAGMA table_info({table})", conn)
    print(f"    Columns: {', '.join(columns['name'].tolist())}")
    
    # Get row count
    count = pd.read_sql_query(f"SELECT COUNT(*) as cnt FROM {table}", conn)['cnt'][0]
    print(f"    Records: {count:,}")
    print()

# 2. Sample data from each enrichment table
print("\n[2] ENRICHMENT DATA SAMPLES")
print("-" * 80)

# ATTACK data
print("\n2.1 ATT&CK Techniques (sample):")
attack_sample = pd.read_sql_query("""
    SELECT technique_id, technique_name, tactic, data_sources, platforms
    FROM attack_techniques
    LIMIT 3
""", conn)
print(attack_sample.to_string())

# CHPL data
print("\n2.2 CHPL Devices (sample):")
chpl_sample = pd.read_sql_query("""
    SELECT product_classification, vendor, 
           product_code, fda_class, panel_type
    FROM chpl_products
    LIMIT 3
""", conn)
print(chpl_sample.to_string())

# CVE metadata
print("\n2.3 CVE Detailed Fields (sample):")
cve_sample = pd.read_sql_query("""
    SELECT id, description, cwe_ids, cvss_version, cvss_score,
           cvss_vector, attack_vector, attack_complexity,
           privileges_required, user_interaction, scope,
           confidentiality_impact, integrity_impact, availability_impact
    FROM cves
    WHERE cwe_ids IS NOT NULL
    LIMIT 2
""", conn)
for col in cve_sample.columns:
    print(f"  {col}: {cve_sample[col].iloc[0] if len(cve_sample) > 0 else 'N/A'}")
print()

# 3. Analyze what features we're NOT using yet
print("\n[3] UNTAPPED FEATURE OPPORTUNITIES")
print("-" * 80)

# CVE fields not currently used
print("\n3.1 NVD/CVE Fields Available (not all used):")
cve_columns = pd.read_sql_query("PRAGMA table_info(cves)", conn)
print("Currently available CVE columns:")
for col in cve_columns['name']:
    print(f"  - {col}")

# ATT&CK dimensions
print("\n3.2 ATT&CK Enrichment Opportunities:")
attack_cols = pd.read_sql_query("PRAGMA table_info(attack_techniques)", conn)
print("ATT&CK technique attributes:")
for col in attack_cols['name']:
    print(f"  - {col}")

# Check for reference/source data
print("\n3.3 CVE References/Sources:")
ref_check = pd.read_sql_query("""
    SELECT COUNT(*) as total,
           SUM(CASE WHEN description LIKE '%github%' THEN 1 ELSE 0 END) as github_refs,
           SUM(CASE WHEN description LIKE '%exploit%' THEN 1 ELSE 0 END) as exploit_refs,
           SUM(CASE WHEN description LIKE '%patch%' THEN 1 ELSE 0 END) as patch_refs
    FROM cves
""", conn)
print(ref_check.to_string())

# 4. Feature extraction ideas based on available data
print("\n[4] RECOMMENDED NEW FEATURES")
print("-" * 80)

recommendations = {
    "CVSS Vector Decomposition": [
        "Attack Vector (Network/Adjacent/Local/Physical)",
        "Attack Complexity (Low/High)",
        "Privileges Required (None/Low/High)",
        "User Interaction (None/Required)",
        "Scope (Unchanged/Changed)",
        "Impact Triad (C/I/A as separate features)"
    ],
    
    "CWE Intelligence": [
        "Is CWE in Top 25 Most Dangerous (binary)",
        "CWE category (e.g., injection, auth, crypto)",
        "Number of CWEs associated (multi-weakness indicator)",
        "CWE parent chain depth (abstraction level)"
    ],
    
    "ATT&CK Enrichment": [
        "Kill chain position (early=recon vs late=impact)",
        "Number of detection data sources required",
        "Platform diversity (cross-platform = more dangerous)",
        "Tactic count (multi-stage attack indicator)",
        "Has 'Defense Evasion' tactic (stealth indicator)"
    ],
    
    "CHPL/Healthcare Intelligence": [
        "FDA device class (I/II/III - higher = more critical)",
        "Medical device category (imaging, life-support, diagnostic)",
        "Number of affected CHPL products",
        "Device criticality score (life-support > monitoring)",
        "CHPL vendor reputation (breach history)"
    ],
    
    "Vendor/Product Signals": [
        "Vendor risk score (historical exploit frequency)",
        "Product age/maturity indicator",
        "Is high-profile vendor (Microsoft, Cisco, etc.)",
        "Product category (OS, network, application, IoT)"
    ],
    
    "Description NLP Features": [
        "Exploitation keyword density (RCE, bypass, etc.)",
        "Action verb count (execute, escalate, bypass)",
        "Complexity indicators (simple vs complex exploit)",
        "Mention of authentication/authorization",
        "Weaponization signals (PoC, exploit, wild)"
    ],
    
    "Temporal/Historical Patterns": [
        "Days since last vendor CVE (vendor cadence)",
        "CVE ID pattern (year-month based seasonality)",
        "Similar CVE exploit history (CWE-based lookup)",
        "Vendor's average time-to-patch (if available)"
    ]
}

for category, features in recommendations.items():
    print(f"\n{category}:")
    for feat in features:
        print(f"  ✓ {feat}")

# 5. External enrichment possibilities
print("\n[5] EXTERNAL ENRICHMENT OPPORTUNITIES")
print("-" * 80)
external = {
    "Exploit-DB/GitHub": "PoC exploit availability",
    "Vendor Advisories": "Official patch release dates",
    "Social Media": "Discussion volume on Twitter/Reddit",
    "Shodan/Censys": "Internet-exposed vulnerable systems count",
    "Vulners/VulnDB": "Additional exploit intelligence",
    "MITRE CWE DB": "CWE parent relationships and abstraction"
}

for source, value in external.items():
    print(f"  • {source}: {value}")

conn.close()

print("\n" + "="*80)
print("SUMMARY: Focus on CHPL/Healthcare and CVSS decomposition for quick wins")
print("="*80)
