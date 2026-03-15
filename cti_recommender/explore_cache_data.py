"""
Explore cached data sources for additional feature enrichment.
"""

import pandas as pd
import pickle
import gzip
import json

print("="*80)
print("EXPLORING CACHED DATA SOURCES")
print("="*80)

# 1. NVD Data (CVE descriptions, vendors)
print("\n[1] NVD DATA")
print("-" * 80)
try:
    with gzip.open('cache/nvd/nvd_enhanced_phase1.pkl.gz', 'rb') as f:
        nvd_data = pickle.load(f)
    print(f"Records: {len(nvd_data)}")
    if len(nvd_data) > 0:
        sample = nvd_data[0] if isinstance(nvd_data, list) else nvd_data.iloc[0]
        print(f"Type: {type(nvd_data)}")
        if isinstance(nvd_data, pd.DataFrame):
            print(f"Columns: {nvd_data.columns.tolist()}")
            print("\nSample row:")
            print(nvd_data[['id', 'description']].head(2) if 'description' in nvd_data.columns else nvd_data.head(2))
        else:
            print(f"Sample keys: {sample.keys() if hasattr(sample, 'keys') else 'N/A'}")
except Exception as e:
    print(f"Error: {e}")

# 2. CHPL Data (device classes, FDA classification)
print("\n[2] CHPL DATA")
print("-" * 80)
try:
    with open('cache/chpl/chpl_products.json', 'r') as f:
        chpl_data = json.load(f)
    print(f"Records: {len(chpl_data) if isinstance(chpl_data, list) else 'N/A'}")
    if isinstance(chpl_data, list) and len(chpl_data) > 0:
        sample = chpl_data[0]
        print(f"Sample keys: {list(sample.keys())[:15]}")
        print("\nSample record:")
        for key in list(sample.keys())[:10]:
            print(f"  {key}: {sample[key]}")
    elif isinstance(chpl_data, dict):
        print(f"Top-level keys: {list(chpl_data.keys())}")
except Exception as e:
    print(f"Error: {e}")

# 3. ATT&CK Data (tactics, techniques)
print("\n[3] ATT&CK DATA")
print("-" * 80)
try:
    with gzip.open('cache/attack/attack_techniques.pkl.gz', 'rb') as f:
        attack_data = pickle.load(f)
    print(f"Records: {len(attack_data)}")
    if isinstance(attack_data, pd.DataFrame):
        print(f"Columns: {attack_data.columns.tolist()}")
        print("\nSample techniques:")
        print(attack_data[['technique_id', 'technique_name', 'tactic']].head(3) if 'tactic' in attack_data.columns else attack_data.head(3))
    elif isinstance(attack_data, dict):
        print(f"Top keys: {list(attack_data.keys())[:10]}")
    elif isinstance(attack_data, list) and len(attack_data) > 0:
        sample = attack_data[0]
        print(f"Sample type: {type(sample)}")
        if hasattr(sample, 'keys'):
            print(f"Sample keys: {list(sample.keys())}")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*80)
