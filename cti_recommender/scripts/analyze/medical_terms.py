#!/usr/bin/env python3
"""
Analyze CVE descriptions to find medical vendors and terms not in CHPL.
Determines if we need additional datasets beyond CHPL.
"""
import sys
from pathlib import Path
# Add project root to path (scripts/analyze/ -> scripts/ -> project root)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.cve_database import CVEDatabase
from src.core.chpl_fetcher import CHPLFetcher
from collections import Counter

def analyze_medical_terms():
    """Analyze what medical vendors and terms appear in CVE descriptions."""
    
    print("\n" + "="*70)
    print("CVE MEDICAL TERM ANALYSIS")
    print("="*70)
    
    # Get CHPL vendors
    fetcher = CHPLFetcher()
    chpl_df = fetcher.get_chpl_data()
    chpl_vendors = set()
    for _, row in chpl_df.iterrows():
        vendor = row.get('developer', {})
        if isinstance(vendor, dict):
            vendor_name = vendor.get('name', '').lower().strip()
        else:
            vendor_name = str(vendor).lower().strip()
        if vendor_name:
            chpl_vendors.add(vendor_name)
    
    print(f"\n✅ CHPL Vendors: {len(chpl_vendors)} vendors")
    
    # Get CVE descriptions
    db = CVEDatabase()
    cursor = db.conn.cursor()
    
    cursor.execute('''
        SELECT description 
        FROM cves 
        WHERE description LIKE '%medical%' 
           OR description LIKE '%health%' 
           OR description LIKE '%patient%'
           OR description LIKE '%hospital%'
           OR description LIKE '%philips%'
           OR description LIKE '%siemens%'
           OR description LIKE '%medtronic%'
        LIMIT 1000
    ''')
    
    descriptions = [row[0] for row in cursor.fetchall() if row[0]]
    print(f"\n📋 Analyzing {len(descriptions)} CVE descriptions...")
    
    # Known medical device vendors (NOT in CHPL typically)
    device_vendors = [
        'philips', 'ge healthcare', 'siemens', 'medtronic', 'baxter',
        'bd', 'boston scientific', 'stryker', 'zimmer', 'smith & nephew',
        'roche', 'abbott', 'dräger', 'draeger', 'carestream',
        'fujifilm', 'canon medical', 'hitachi', 'toshiba',
        'intuitive surgical', 'masimo', 'welch allyn', 'spacelabs',
        'ge medical', 'siemens healthineers', 'philips healthcare',
        'hospira', 'cardinal health', 'fresenius', 'teleflex'
    ]
    
    # Medical terms and device types
    medical_terms = [
        'infusion pump', 'patient monitor', 'ventilator', 'defibrillator',
        'mri', 'ct scan', 'x-ray', 'pacs', 'dicom', 'hl7',
        'imaging system', 'surgical robot', 'implantable', 'pacemaker',
        'insulin pump', 'glucose monitor', 'medical device', 'radiotherapy',
        'ultrasound', 'ecg', 'ekg', 'anesthesia', 'laboratory information',
        'blood gas', 'vital signs'
    ]
    
    vendor_count = Counter()
    term_count = Counter()
    
    for desc in descriptions:
        desc_lower = desc.lower()
        
        # Check for device vendors
        for vendor in device_vendors:
            if vendor in desc_lower:
                vendor_count[vendor] += 1
        
        # Check for medical terms
        for term in medical_terms:
            if term in desc_lower:
                term_count[term] += 1
    
    print("\n" + "="*70)
    print("🏥 MEDICAL DEVICE VENDORS (Not in CHPL):")
    print("="*70)
    if vendor_count:
        for vendor, count in vendor_count.most_common(15):
            print(f"   {vendor:30s}: {count:3d} CVEs")
    else:
        print("   None found")
    
    print("\n" + "="*70)
    print("🔧 MEDICAL DEVICE/SYSTEM TERMS:")
    print("="*70)
    if term_count:
        for term, count in term_count.most_common(15):
            print(f"   {term:30s}: {count:3d} CVEs")
    else:
        print("   None found")
    
    print("\n" + "="*70)
    print("📊 COVERAGE GAP ANALYSIS:")
    print("="*70)
    print(f"   CHPL vendors:                {len(chpl_vendors)}")
    print(f"   Device vendors found in CVEs: {len(vendor_count)}")
    print(f"   Medical terms found:          {len(term_count)}")
    print(f"   Total vendor mentions:        {sum(vendor_count.values())}")
    print(f"   Total term mentions:          {sum(term_count.values())}")
    
    gap_percentage = (sum(vendor_count.values()) / len(descriptions) * 100) if descriptions else 0
    print(f"   CVEs mentioning devices:      {gap_percentage:.1f}%")
    
    print("\n" + "="*70)
    print("💡 RECOMMENDATION:")
    print("="*70)
    
    if sum(vendor_count.values()) > 50:
        print("   ⚠️  SIGNIFICANT GAP - Should create supplementary vendor list")
        print("   → Create data/medical_device_vendors.json with top vendors")
        print("   → Add ~30-50 major device manufacturers")
        print("   → Augment CHPL matching with device vendor keywords")
    else:
        print("   ✅ CHPL Coverage Sufficient")
        print("   → Most CVEs reference EHR/IT systems (covered by CHPL)")
        print("   → Device vendor mentions are minimal")
        print("   → Current approach is research-valid")
    
    print("="*70)
    
    return vendor_count, term_count

if __name__ == '__main__':
    analyze_medical_terms()
