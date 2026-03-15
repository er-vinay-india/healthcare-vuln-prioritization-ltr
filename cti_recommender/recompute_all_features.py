#!/usr/bin/env python3
"""
STEP_3 Standalone: Compute and Store All 37 Enhanced Features
This script bypasses notebook caching issues
"""

import sys
from pathlib import Path
import pandas as pd
from tqdm import tqdm

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.core.cve_database import CVEDatabase
from src.features.enhanced_features import EnhancedFeatureExtractor, get_enhanced_feature_columns

print("="*80)
print("STANDALONE FEATURE COMPUTATION - ALL 37 FEATURES")
print("="*80)

# 1. Connect to database
print("\n[1/5] Connecting to database...")
db = CVEDatabase()
print(f"  ✓ Connected")

# 2. Load CVE data
print("\n[2/5] Loading CVE data...")
query = """
SELECT 
    c.cve_id,
    c.cvss,
    c.cvss_vector,
    c.cwe,
    c.description,
    e.kev_flag,
    e.is_healthcare
FROM cves c
LEFT JOIN enrichments e ON c.cve_id = e.cve_id
WHERE c.cvss IS NOT NULL
ORDER BY c.cve_id
"""
df = pd.read_sql(query, db.conn)
print(f"  ✓ Loaded {len(df):,} CVEs")

# 3. Compute features
print("\n[3/5] Computing all 37 enhanced features...")
extractor = EnhancedFeatureExtractor()
enhanced_df = extractor.extract_all_features(df, include_nlp=True)

# Verify all features were created
expected_features = get_enhanced_feature_columns()
created = [f for f in expected_features if f in enhanced_df.columns]
print(f"  ✓ Created {len(created)}/{len(expected_features)} features")

if len(created) < len(expected_features):
    missing = [f for f in expected_features if f not in enhanced_df.columns]
    print(f"  ✗ Missing: {missing}")
    sys.exit(1)

# 4. Update database
print("\n[4/5] Updating database...")
cursor = db.conn.cursor()

# Build UPDATE statement
set_clause = ", ".join([f"{col} = ?" for col in expected_features])
update_sql = f"UPDATE enrichments SET {set_clause} WHERE cve_id = ?"

batch_size = 1000
total_updated = 0
errors = 0

for i in tqdm(range(0, len(enhanced_df), batch_size), desc="Updating"):
    batch = enhanced_df.iloc[i:i+batch_size]
    
    for _, row in batch.iterrows():
        try:
            values = [row.get(col, None) for col in expected_features]
            values.append(row['cve_id'])
            cursor.execute(update_sql, values)
            total_updated += 1
        except Exception as e:
            errors += 1
            if errors < 10:
                print(f"Error updating {row['cve_id']}: {e}")
    
    db.conn.commit()

print(f"  ✓ Updated {total_updated:,} CVEs")
print(f"  Errors: {errors}")

# 5. Verify
print("\n[5/5] Verifying database...")
verify_query = """
SELECT COUNT(*) as total,
       COUNT(cvss_score_derived) as has_cvss_derived,
       COUNT(cvss_severity_category) as has_cvss_category,
       COUNT(cwe_is_crypto) as has_cwe_crypto,
       COUNT(desc_has_sqli) as has_desc_sqli,
       COUNT(ultimate_risk) as has_ultimate_risk
FROM enrichments
WHERE cve_id IN (SELECT cve_id FROM cves WHERE cvss IS NOT NULL)
"""
verify_df = pd.read_sql(verify_query, db.conn)
print(f"\n  Verification (of {verify_df['total'][0]:,} CVEs):")
for col in verify_df.columns:
    if col != 'total':
        count = verify_df[col][0]
        pct = (count / verify_df['total'][0] * 100) if verify_df['total'][0] > 0 else 0
        status = "✓" if count > 0 else "✗"
        print(f"    {status} {col}: {count:,} ({pct:.1f}%)")

db.close()

print("\n" + "="*80)
print("COMPLETE - All 37 enhanced features computed and stored!")
print("="*80)
print("\nNext steps:")
print("  1. Run STEP_4_Feature_Engineering_Labels.ipynb to regenerate CSV")
print("  2. Run STEP_5_Model_Training_And_Evaluation.ipynb to retrain model")
print("  3. Model should now use all 53 features (16 basic + 37 enhanced)")
