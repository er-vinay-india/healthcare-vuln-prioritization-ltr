#!/usr/bin/env python
"""Run Phase 1 Data Quality Audit

This script performs comprehensive data quality checks and audits the current
top-20 recommendations for healthcare relevance.
"""
from pathlib import Path
import sys

import pandas as pd

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.analysis.data_quality import generate_quality_report
from src.analysis.healthcare_mapping import HealthcareMapper, analyze_healthcare_coverage
from src.core import cti_recommender as cr


def main():
    print("\n" + "="*80)
    print("PHASE 1: DATA QUALITY & VALIDATION AUDIT")
    print("="*80 + "\n")
    
    # Load datasets
    print(" Loading datasets...")
    
    # Load NVD
    try:
        nvd_df = cr.get_nvd_cached()
        print(f"  [OK] NVD: {len(nvd_df)} CVEs loaded")
    except Exception as e:
        print(f"  [X] NVD: Failed to load - {e}")
        nvd_df = None
    
    # Load KEV
    try:
        kev_df = cr.get_kev_cached()
        print(f"  [OK] KEV: {len(kev_df)} entries loaded")
    except Exception as e:
        print(f"  [X] KEV: Failed to load - {e}")
        kev_df = None
    
    # Load CHPL
    try:
        chpl_df = cr.get_chpl_cached()
        print(f"  [OK] CHPL: {len(chpl_df)} products loaded")
    except Exception as e:
        print(f"  [X] CHPL: Failed to load - {e}")
        chpl_df = None
    
    # Load ATT&CK
    try:
        attack_df = cr.get_attack_cached()
        print(f"  [OK] ATT&CK: {len(attack_df)} techniques loaded")
    except Exception as e:
        print(f"  [X] ATT&CK: Failed to load - {e}")
        attack_df = None
    
    # Load top-20 recommendations
    try:
        top20_df = pd.read_csv('outputs/top20.csv')
        print(f"  [OK] Top-20: {len(top20_df)} recommendations loaded")
    except Exception as e:
        print(f"  [X] Top-20: Failed to load - {e}")
        top20_df = None
    
    print("\n" + "-"*80 + "\n")
    
    # Run data quality checks
    if nvd_df is not None:
        reports = generate_quality_report(
            nvd_df=nvd_df,
            kev_df=kev_df,
            chpl_df=chpl_df,
            attack_df=attack_df,
            top_recommendations=top20_df,
            output_path=Path('outputs/phase1_quality_report.txt')
        )
        
        # Enhanced healthcare mapping analysis
        print("\n" + "="*80)
        print("ENHANCED HEALTHCARE MAPPING ANALYSIS")
        print("="*80 + "\n")
        
        mapper = HealthcareMapper()
        
        # Analyze NVD coverage
        print("Analyzing NVD dataset with enhanced healthcare mapping...")
        nvd_coverage = analyze_healthcare_coverage(nvd_df, mapper)
        
        print(f"\n[STATS] Healthcare Coverage in NVD:")
        print(f"  Total CVEs: {nvd_coverage['total_cves']}")
        print(f"  Healthcare flagged: {nvd_coverage['healthcare_flagged']} ({nvd_coverage['healthcare_flagged']/nvd_coverage['total_cves']*100:.1f}%)")
        print(f"  Vendor matches: {nvd_coverage['vendor_matches']}")
        print(f"  Product matches: {nvd_coverage['product_matches']}")
        print(f"  Keyword matches: {nvd_coverage['keyword_matches']}")
        print(f"  Avg healthcare score: {nvd_coverage['avg_healthcare_score']:.3f}")
        
        if nvd_coverage['top_vendors']:
            print(f"\n  Top healthcare vendors in dataset:")
            for vendor, count in list(nvd_coverage['top_vendors'].items())[:5]:
                print(f"    • {vendor}: {count} CVEs")
        
        # Analyze top-20 with enhanced mapping
        if top20_df is not None:
            print("\n" + "-"*80)
            print("Re-analyzing top-20 with enhanced healthcare mapping...\n")
            
            top20_enriched = mapper.enrich_dataframe(
                top20_df, 
                description_col='description' if 'description' in top20_df.columns else 'description_en'
            )
            
            print("[TARGET] Top-20 Healthcare Relevance (Enhanced):")
            print(f"  Healthcare flagged: {top20_enriched['is_healthcare'].sum()}/20")
            print(f"  Vendor matches: {top20_enriched['healthcare_vendor'].notna().sum()}/20")
            print(f"  Product matches: {top20_enriched['healthcare_product'].sum()}/20")
            print(f"  Avg healthcare score: {top20_enriched['healthcare_score'].mean():.3f}")
            
            # Save enriched top-20
            top20_enriched.to_csv('outputs/top20_enriched.csv', index=False)
            print(f"\n  [OK] Saved enriched top-20 to outputs/top20_enriched.csv")
            
            # Show detailed breakdown
            print("\n Detailed Top-20 Breakdown:")
            print(f"  {'Rank':<5} {'CVE ID':<18} {'CVSS':<6} {'KEV':<5} {'HC Score':<9} {'Vendor'}")
            print("  " + "-"*70)
            
            for idx, row in top20_enriched.head(20).iterrows():
                cve_id = row['cve_id']
                cvss = row.get('cvss', 0)
                kev = '[OK]' if row.get('kev_flag', 0) else '[X]'
                hc_score = row.get('healthcare_score', 0)
                vendor = row.get('healthcare_vendor', 'None')[:15] if pd.notna(row.get('healthcare_vendor')) else 'None'
                
                print(f"  {idx+1:<5} {cve_id:<18} {cvss:<6.1f} {kev:<5} {hc_score:<9.3f} {vendor}")
        
        print("\n" + "="*80)
        print("PHASE 1 AUDIT COMPLETE")
        print("="*80)
        print("\n[OK] Quality report saved to: outputs/phase1_quality_report.txt")
        print("[OK] Healthcare mapping saved to: data/config/healthcare_mapping.csv")
        print("[OK] Enriched top-20 saved to: outputs/top20_enriched.csv")
        
        # Summary recommendations
        print("\n" + "="*80)
        print("RECOMMENDATIONS FOR NEXT STEPS")
        print("="*80)
        
        total_issues = sum(len(r.errors) + len(r.warnings) for r in reports.values() if hasattr(r, 'errors'))
        
        if total_issues > 0:
            print(f"\n[WARN]  Found {total_issues} data quality issues that should be addressed")
            print("   • Review outputs/phase1_quality_report.txt for details")
            print("   • Consider data cleaning before proceeding to ML training")
        
        if top20_enriched is not None:
            hc_precision = top20_enriched['is_healthcare'].sum() / 20
            if hc_precision < 0.50:
                print(f"\n[WARN]  Healthcare precision is low ({hc_precision:.1%})")
                print("   • Consider adjusting scoring weights")
                print("   • Review and refine healthcare mapping patterns")
            elif hc_precision >= 0.85:
                print(f"\n[OK] Healthcare precision looks good ({hc_precision:.1%})")
                print("   • Ready to proceed with LTR model training")
        
        print("\n Next Phase:")
        print("   Phase 2: Improve labeling strategy")
        print("   • Add EPSS scores for exploit probability")
        print("   • Create curated positive examples")
        print("   • Implement multi-level labels")
        
        print("\n")
        
    else:
        print("[FAIL] Cannot proceed without NVD dataset")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
