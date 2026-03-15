"""
Regenerate features CSV from database with ALL 53 features (16 basic + 37 enhanced)
This ensures STEP_5 uses the latest data with fixed CWE features
"""

import pandas as pd
from pathlib import Path
from src.core.cve_database import CVEDatabase
from src.features.labeling import build_weak_labels

print("="*80)
print("REGENERATING FEATURES CSV FROM DATABASE")
print("="*80)

# Connect to database
db = CVEDatabase()

# SQL to load ALL 53 features (cast timestamps as text to avoid SQLite parsing issues)
query = """
SELECT 
    c.cve_id,
    CAST(c.published AS TEXT) as published,
    CAST(c.modified AS TEXT) as modified,
    c.cvss,
    c.cvss_vector,
    c.cwe,
    c.description,
    -- Basic enrichments (10 features)
    e.kev_flag,
    e.epss_score,
    e.epss_percentile,
    e.is_healthcare,
    e.healthcare_score,
    e.attack_flag,
    e.attack_technique_count,
    e.chpl_flag,
    e.is_curated,
    e.curated_severity,
    -- CVSS Decomposition (10 features)
    e.cvss_av,
    e.cvss_ac,
    e.cvss_pr,
    e.cvss_ui,
    e.cvss_s,
    e.cvss_c,
    e.cvss_i,
    e.cvss_a,
    e.cvss_score_derived,
    e.cvss_severity_category,
    -- CWE Intelligence (8 features)
    e.cwe_is_top25,
    e.cwe_is_injection,
    e.cwe_is_crypto,
    e.cwe_is_access_control,
    e.cwe_is_input_validation,
    e.cwe_is_memory_corruption,
    e.cwe_category,
    e.cwe_severity_score,
    -- Description NLP (10 features)
    e.desc_has_rce,
    e.desc_has_auth_bypass,
    e.desc_has_priv_esc,
    e.desc_has_sqli,
    e.desc_has_xss,
    e.desc_has_dos,
    e.desc_has_buffer_overflow,
    e.desc_has_path_traversal,
    e.desc_has_csrf,
    e.desc_has_xxe,
    -- Vendor Features (3 features)
    e.vendor_is_high_risk,
    e.vendor_is_healthcare,
    e.vendor_risk_score,
    -- Interaction Features (6 features)
    e.ultimate_risk,
    e.critical_exploitable,
    e.network_accessible,
    e.auth_not_required,
    e.high_impact_network,
    e.healthcare_critical
FROM cves c
LEFT JOIN enrichments e ON c.cve_id = e.cve_id
WHERE c.cvss IS NOT NULL
ORDER BY c.published DESC
"""

print("\n[1/4] Loading data from database...")
df = pd.read_sql(query, db.conn)
# Convert timestamps after loading to avoid SQLite parsing issues
df['published'] = pd.to_datetime(df['published'], errors='coerce')
df['modified'] = pd.to_datetime(df['modified'], errors='coerce')
db.close()
print(f"  ✓ Loaded {len(df):,} CVEs")

# Build weak labels
print("\n[2/4] Building weak labels...")
df_labeled = build_weak_labels(df)
print(f"  ✓ Labels created")
print(f"    - Mean label: {df_labeled['soft_label'].mean():.2f}")
print(f"    - Mean confidence: {df_labeled['label_confidence'].mean():.3f}")

# Verify features
all_features = [
    # Basic (10)
    'kev_flag', 'epss_score', 'epss_percentile', 
    'is_healthcare', 'healthcare_score',
    'attack_flag', 'attack_technique_count',
    'chpl_flag', 'is_curated', 'curated_severity',
    # CVSS (10)
    'cvss_av', 'cvss_ac', 'cvss_pr', 'cvss_ui', 'cvss_s',
    'cvss_c', 'cvss_i', 'cvss_a', 'cvss_score_derived', 'cvss_severity_category',
    # CWE (8)
    'cwe_is_top25', 'cwe_is_injection', 'cwe_is_crypto',
    'cwe_is_access_control', 'cwe_is_input_validation',
    'cwe_is_memory_corruption', 'cwe_category', 'cwe_severity_score',
    # NLP (10)
    'desc_has_rce', 'desc_has_auth_bypass', 'desc_has_priv_esc',
    'desc_has_sqli', 'desc_has_xss', 'desc_has_dos',
    'desc_has_buffer_overflow', 'desc_has_path_traversal',
    'desc_has_csrf', 'desc_has_xxe',
    # Vendor (3)
    'vendor_is_high_risk', 'vendor_is_healthcare', 'vendor_risk_score',
    # Interaction (6)
    'ultimate_risk', 'critical_exploitable', 'network_accessible',
    'auth_not_required', 'high_impact_network', 'healthcare_critical'
]

print("\n[3/4] Verifying feature quality...")
missing_features = [f for f in all_features if f not in df_labeled.columns]
if missing_features:
    print(f"  ✗ WARNING: Missing features: {missing_features}")
else:
    print(f"  ✓ All {len(all_features)} features present")

# Check for zero-variance features
zero_variance = []
for feat in all_features:
    if df_labeled[feat].nunique() <= 1:
        zero_variance.append(feat)

if zero_variance:
    print(f"  ✗ WARNING: Zero-variance features: {zero_variance}")
else:
    print(f"  ✓ No zero-variance features")

# Check data quality
good_features = sum(1 for f in all_features if df_labeled[f].nunique() > 1 and (df_labeled[f].fillna(0) != 0).sum() > len(df)*0.01)
print(f"  ✓ Features with >1% non-zero data: {good_features}/{len(all_features)}")

# Save CSV
print("\n[4/4] Saving CSV...")
output_dir = Path('outputs/features')
output_dir.mkdir(parents=True, exist_ok=True)

# Use today's date
timestamp = pd.Timestamp.now().strftime('%Y%m%d')
output_file = output_dir / f'features_with_labels_{timestamp}.csv'

# Delete old file with same name if exists
if output_file.exists():
    output_file.unlink()
    print(f"  ✓ Deleted old file: {output_file.name}")

df_labeled.to_csv(output_file, index=False)
size_mb = output_file.stat().st_size / (1024*1024)

print(f"  ✓ Saved: {output_file.name}")
print(f"    - Rows: {len(df_labeled):,}")
print(f"    - Columns: {len(df_labeled.columns)}")
print(f"    - Size: {size_mb:.1f} MB")

print("\n" + "="*80)
print("✅ CSV REGENERATED SUCCESSFULLY")
print("="*80)
print("\nNext step:")
print("  Run STEP_5_Model_Training_And_Evaluation.ipynb")
print("  It will automatically load the latest CSV")
print("="*80)
