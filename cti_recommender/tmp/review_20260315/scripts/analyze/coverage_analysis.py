#!/usr/bin/env python3
"""
Analyze current CHPL data coverage vs full healthcare ecosystem.
Identifies gaps and suggests additional data sources.
"""
import sys
from pathlib import Path
# Add project root to path (scripts/analyze/ -> scripts/ -> project root)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.chpl_fetcher import CHPLFetcher
from src.core.cve_database import CVEDatabase

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

def analyze_coverage():
    """Analyze what healthcare technology data we have vs what we need."""
    
    logger.info("="*70)
    logger.info("HEALTHCARE TECHNOLOGY DATA COVERAGE ANALYSIS")
    logger.info("="*70)
    
    # Current CHPL data
    fetcher = CHPLFetcher()
    chpl_df = fetcher.get_chpl_data()
    
    unique_vendors = chpl_df['developer'].apply(lambda x: x.get('name', '') if isinstance(x, dict) else str(x)).nunique()
    logger.info("[OK] CURRENT DATA (CHPL ONC-Certified Products):")
    logger.info(f"   Total Products: {len(chpl_df):,}", extra={'product_count': len(chpl_df)})
    logger.info(f"   Unique Vendors: {unique_vendors}", extra={'vendor_count': unique_vendors})
    logger.info("   Coverage: EHR systems, certified health IT")
    logger.info("   Examples: Epic, Cerner, MEDITECH, athenahealth")
    
    # What's missing
    logger.info("[FAIL] MISSING DATA (Not in CHPL):")
    logger.info("")
    logger.info("1. FDA-Registered Medical Devices (~10,000+ products):")
    logger.info("   - Patient monitors (Philips, GE, Medtronic)")
    logger.info("   - Infusion pumps (BD, Baxter, Hospira)")
    logger.info("   - Ventilators (Medtronic, Dräger)")
    logger.info("   - Imaging systems (GE, Siemens, Philips)")
    logger.info("   - Surgical robots (Intuitive Surgical)")
    logger.info("   - Implantable devices (Medtronic, Boston Scientific)")
    
    logger.info("")
    logger.info("2. Medical Imaging & PACS Systems (~2,000+ products):")
    logger.info("   - GE Healthcare imaging systems")
    logger.info("   - Siemens Healthineers")
    logger.info("   - Philips Medical Systems")
    logger.info("   - Fujifilm Medical Systems")
    logger.info("   - Canon Medical")
    
    logger.info("")
    logger.info("3. Laboratory Information Systems (~1,000+ products):")
    logger.info("   - Roche Diagnostics")
    logger.info("   - Abbott Laboratories")
    logger.info("   - Siemens Healthineers")
    logger.info("   - Beckman Coulter")
    
    logger.info("")
    logger.info("4. Medical IoT & Connected Devices (~5,000+ products):")
    logger.info("   - Remote patient monitoring")
    logger.info("   - Wearable medical devices")
    logger.info("   - Connected insulin pumps")
    logger.info("   - Telehealth platforms")
    
    # Check current CVE coverage
    db = CVEDatabase()
    cursor = db.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cves WHERE description LIKE '%medical%' OR description LIKE '%health%'")
    medical_cves = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1")
    healthcare_flagged = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM enrichments WHERE chpl_flag = 1")
    chpl_flagged = cursor.fetchone()[0]
    
    logger.info("="*70)
    logger.info("CVE DATABASE COVERAGE:")
    logger.info("="*70)
    logger.info(f"Total CVEs with 'medical/health' keywords: {medical_cves:,}", extra={'medical_cves': medical_cves})
    logger.info(f"CVEs flagged as healthcare-related:        {healthcare_flagged:,}", extra={'healthcare_flagged': healthcare_flagged})
    logger.info(f"CVEs mapped to CHPL products:              {chpl_flagged:,}", extra={'chpl_flagged': chpl_flagged})
    
    # Recommendations
    logger.info("="*70)
    logger.info("RECOMMENDATIONS FOR BETTER COVERAGE:")
    logger.info("="*70)
    logger.info("")
    logger.info("1. [OK] CHPL Data (DONE):")
    logger.info("   Source: ONC Certified Health IT Product List API")
    logger.info("   Status: 706 products cached")
    
    logger.info("")
    logger.info("2. FDA Medical Device Database (RECOMMENDED):")
    logger.info("   Source: FDA GUDID (Global Unique Device ID)")
    logger.info("   API: https://accessgudid.nlm.nih.gov/")
    logger.info("   Coverage: ~2M medical devices")
    logger.info("   Focus: Extract top manufacturers & device types")
    logger.info("   Estimated useful: ~5,000 products")
    
    logger.info("")
    logger.info("3. Healthcare Vendor List (RECOMMENDED):")
    logger.info("   Source: Manual curation from:")
    logger.info("   - Top medical device manufacturers")
    logger.info("   - Major healthcare software vendors")
    logger.info("   - Medical imaging companies")
    logger.info("   - Known healthcare technology brands")
    logger.info("   Estimated: ~500 key vendors/products")
    
    logger.info("")
    logger.info("4. CPE Healthcare Filter (OPTIONAL):")
    logger.info("   Source: NVD CPE dictionary")
    logger.info("   Filter: Healthcare-related CPEs from CVE database")
    logger.info("   Extract unique vendors/products mentioned in CVEs")
    
    logger.info("="*70)
    logger.info("IMPACT ESTIMATE:")
    logger.info("="*70)
    logger.info("Current coverage:  706 products (~3-5% of ecosystem)")
    logger.info("With FDA GUDID:    ~5,706 products (~25-30% coverage)")
    logger.info("With vendor list:  ~6,206 products (~35-40% coverage)")
    logger.info("Target: 6,000+ products for comprehensive research coverage")
    logger.info("="*70)

if __name__ == '__main__':
    analyze_coverage()
