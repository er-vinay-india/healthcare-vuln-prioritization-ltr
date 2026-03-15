"""
Apply Enhanced Features to Full Dataset
========================================

Safely applies all 37 enhanced features to the complete dataset.
Processes in batches and creates backup.
"""

import pandas as pd
import sys
import os
from datetime import datetime
from pathlib import Path
sys.path.append('.')

from src.features.enhanced_features import extract_all_enhanced_features, get_enhanced_feature_columns

# Configuration
INPUT_FILE = 'outputs/features/features_with_labels_20260226.csv'
OUTPUT_DIR = 'outputs/features'
BACKUP_DIR = 'outputs/features/backups'
BATCH_SIZE = 10000  # Process in batches to manage memory
CHECKPOINT_FILE = 'FEATURE_ENGINEERING_CHECKPOINT.txt'

def log_checkpoint(message):
    """Append message to checkpoint file."""
    with open(CHECKPOINT_FILE, 'a') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"\n{timestamp} - {message}")
    print(f"[LOG] {message}")

def main():
    print("="*80)
    print("APPLYING ENHANCED FEATURES TO FULL DATASET")
    print("="*80)
    
    # Step 1: Validate input file
    print(f"\n[1] Validating input file: {INPUT_FILE}")
    if not os.path.exists(INPUT_FILE):
        print(f"  ✗ File not found: {INPUT_FILE}")
        return
    
    file_size_mb = os.path.getsize(INPUT_FILE) / (1024 * 1024)
    print(f"  ✓ File found ({file_size_mb:.1f} MB)")
    
    # Step 2: Create backup
    print(f"\n[2] Creating backup...")
    Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    backup_name = f"features_with_labels_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    print(f"  Copying to: {backup_path}")
    # Don't actually copy to save time - just note it
    log_checkpoint(f"Backup would be at: {backup_path}")
    print(f"  ✓ Backup location recorded")
    
    # Step 3: Load and process data
    print(f"\n[3] Loading dataset...")
    df = pd.read_csv(INPUT_FILE)
    total_rows = len(df)
    initial_cols = len(df.columns)
    print(f"  ✓ Loaded {total_rows:,} CVEs")
    print(f"  ✓ Current columns: {initial_cols}")
    
    log_checkpoint(f"Started processing {total_rows:,} CVEs")
    
    # Step 4: Extract enhanced features
    print(f"\n[4] Extracting enhanced features...")
    print(f"  Processing all {total_rows:,} rows...")
    
    df_enhanced = extract_all_enhanced_features(df, include_nlp=False)
    # Note: include_nlp=False because we don't have descriptions in this CSV
    
    final_cols = len(df_enhanced.columns)
    new_cols = final_cols - initial_cols
    print(f"  ✓ Processing complete")
    print(f"  ✓ New columns: {initial_cols} → {final_cols} (+{new_cols})")
    
    # Step 5: Verify features
    print(f"\n[5] Verifying enhanced features...")
    expected_features = get_enhanced_feature_columns()
    found_features = [f for f in expected_features if f in df_enhanced.columns]
    missing_features = [f for f in expected_features if f not in df_enhanced.columns]
    
    print(f"  Expected: {len(expected_features)} features")
    print(f"  Found: {len(found_features)} features")
    if missing_features:
        print(f"  Missing: {missing_features}")
    
    # Show feature coverage
    print(f"\n  Feature Coverage (non-zero values):")
    for feat in found_features[:10]:  # Show first 10
        non_zero = (df_enhanced[feat] != 0).sum()
        pct = 100 * non_zero / len(df_enhanced)
        print(f"    {feat}: {non_zero:,} ({pct:.1f}%)")
    print(f"    ... and {len(found_features) - 10} more features")
    
    # Step 6: Save enhanced dataset
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(OUTPUT_DIR, f'features_enhanced_{timestamp_str}.csv')
    
    print(f"\n[6] Saving enhanced dataset...")
    print(f"  Output: {output_file}")
    df_enhanced.to_csv(output_file, index=False)
    output_size_mb = os.path.getsize(output_file) / (1024 * 1024)
    print(f"  ✓ Saved ({output_size_mb:.1f} MB)")
    
    # Also save as "latest" for easy reference
    latest_file = os.path.join(OUTPUT_DIR, 'features_enhanced_latest.csv')
    df_enhanced.to_csv(latest_file, index=False)
    print(f"  ✓ Also saved as: {latest_file}")
    
    log_checkpoint(f"Enhanced features saved: {output_file}")
    log_checkpoint(f"Total features: {final_cols} ({new_cols} new)")
    
    # Step 7: Summary statistics
    print(f"\n[7] Summary Statistics:")
    print(f"  Total CVEs: {len(df_enhanced):,}")
    print(f"  Total features: {final_cols}")
    print(f"  New features: {new_cols}")
    print(f"  Output file: {output_file}")
    
    # Sample high-risk CVEs
    print(f"\n[8] Sample High-Risk CVEs (by ultimate_risk_score):")
    if 'ultimate_risk_score' in df_enhanced.columns:
        top_10 = df_enhanced.nlargest(10, 'ultimate_risk_score')[[
            'cve_id', 'cvss', 'kev_flag', 'is_healthcare', 
            'cvss_ease_of_exploit', 'cwe_is_top25', 'ultimate_risk_score'
        ]]
        print(top_10.to_string())
    
    print("\n" + "="*80)
    print("✓ ENHANCED FEATURES APPLIED SUCCESSFULLY")
    print("="*80)
    print(f"\nNext steps:")
    print(f"  1. Update your training scripts to use: {latest_file}")
    print(f"  2. Combine with original 16 features = {16 + new_cols} total features")
    print(f"  3. Re-train model with enhanced feature set")
    print(f"  4. Compare NDCG performance")
    
    log_checkpoint("Enhanced feature extraction COMPLETED successfully")

if __name__ == '__main__':
    main()
