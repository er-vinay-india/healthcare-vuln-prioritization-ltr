#!/usr/bin/env python3
"""
Analyze current CHPL data coverage vs full healthcare ecosystem.
Identifies gaps and suggests additional data sources.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.chpl_fetcher import CHPLFetcher
from src.core.cve_database import CVEDatabase

def analyze_coverage():
    """Analyze what healthcare technology data we have vs what we need."""
    
    print("\n" + "="*70)
    print("HEALTHCARE TECHNOLOGY DATA COVERAGE ANALYSIS")
    print("="*70)
    
    # Current CHPL data
    fetcher = CHPLFetcher()
    chpl_df = fetcher.get_chpl_data()
    
    print("\n✅ CURRENT DATA (CHPL ONC-Certified Products):")
    print(f"   Total Products: {len(chpl_df):,}")
    print(f"   Unique Vendors: {chpl_df['developer'].apply(lambda x: x.get('name', '') if isinstance(x, dict) else str(x)).nunique()}")
    print("   Coverage: EHR systems, certified health IT")
    print("   Examples: Epic, Cerner, MEDITECH, athenahealth")
    
    # What's missing
    print("\n❌ MISSING DATA (Not in CHPL):")
    print("\n1. FDA-Registered Medical Devices (~10,000+ products):")
    print("   - Patient monitors (Philips, GE, Medtronic)")
    print("   - Infusion pumps (BD, Baxter, Hospira)")
    print("   - Ventilators (Medtronic, Dräger)")
    print("   - Imaging systems (GE, Siemens, Philips)")
    print("   - Surgical robots (Intuitive Surgical)")
    print("   - Implantable devices (Medtronic, Boston Scientific)")
    
    print("\n2. Medical Imaging & PACS Systems (~2,000+ products):")
    print("   - GE Healthcare imaging systems")
    print("   - Siemens Healthineers")
    print("   - Philips Medical Systems")
    print("   - Fujifilm Medical Systems")
    print("   - Canon Medical")
    
    print("\n3. Laboratory Information Systems (~1,000+ products):")
    print("   - Roche Diagnostics")
    print("   - Abbott Laboratories")
    print("   - Siemens Healthineers")
    print("   - Beckman Coulter")
    
    print("\n4. Medical IoT & Connected Devices (~5,000+ products):")
    print("   - Remote patient monitoring")
    print("   - Wearable medical devices")
    print("   - Connected insulin pumps")
    print("   - Telehealth platforms")
    
    # Check current CVE coverage
    db = CVEDatabase()
    cursor = db.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cves WHERE description LIKE '%medical%' OR description LIKE '%health%'")
    medical_cves = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1")
    healthcare_flagged = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM enrichments WHERE chpl_flag = 1")
    chpl_flagged = cursor.fetchone()[0]
    
    print("\n" + "="*70)
    print("CVE DATABASE COVERAGE:")
    print("="*70)
    print(f"Total CVEs with 'medical/health' keywords: {medical_cves:,}")
    print(f"CVEs flagged as healthcare-related:        {healthcare_flagged:,}")
    print(f"CVEs mapped to CHPL products:              {chpl_flagged:,}")
    
    # Recommendations
    print("\n" + "="*70)
    print("RECOMMENDATIONS FOR BETTER COVERAGE:")
    print("="*70)
    print("\n1. ✅ CHPL Data (DONE):")
    print("   Source: ONC Certified Health IT Product List API")
    print("   Status: 706 products cached")
    
    print("\n2. 🔄 FDA Medical Device Database (RECOMMENDED):")
    print("   Source: FDA GUDID (Global Unique Device ID)")
    print("   API: https://accessgudid.nlm.nih.gov/")
    print("   Coverage: ~2M medical devices")
    print("   Focus: Extract top manufacturers & device types")
    print("   Estimated useful: ~5,000 products")
    
    print("\n3. 🔄 Healthcare Vendor List (RECOMMENDED):")
    print("   Source: Manual curation from:")
    print("   - Top medical device manufacturers")
    print("   - Major healthcare software vendors")
    print("   - Medical imaging companies")
    print("   - Known healthcare technology brands")
    print("   Estimated: ~500 key vendors/products")
    
    print("\n4. 🔄 CPE Healthcare Filter (OPTIONAL):")
    print("   Source: NVD CPE dictionary")
    print("   Filter: Healthcare-related CPEs from CVE database")
    print("   Extract unique vendors/products mentioned in CVEs")
    
    print("\n" + "="*70)
    print("IMPACT ESTIMATE:")
    print("="*70)
    print(f"Current coverage:  706 products (~3-5% of ecosystem)")
    print(f"With FDA GUDID:    ~5,706 products (~25-30% coverage)")
    print(f"With vendor list:  ~6,206 products (~35-40% coverage)")
    print("\n🎯 Target: 6,000+ products for comprehensive research coverage")
    print("="*70)

if __name__ == '__main__':
    analyze_coverage()
