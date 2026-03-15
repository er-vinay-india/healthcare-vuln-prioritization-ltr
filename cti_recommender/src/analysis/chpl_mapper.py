#!/usr/bin/env python3
"""
CHPL (Certified Health IT Product List) mapper for CVEs.
Uses smart caching - fetches from API once if needed, then uses cache.
Identifies CVEs affecting certified medical devices and health IT products.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import re
from typing import Dict, Set
from src.core.chpl_fetcher import CHPLFetcher

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class CHPLMapper:
    """Maps CVEs to CHPL certified health IT products using cached data."""
    
    def __init__(self):
        """Load CHPL product data - uses cache or fetches if needed."""
        try:
            fetcher = CHPLFetcher()
            self.products_df = fetcher.get_chpl_data()
        except Exception:
            logger.exception("Failed to load CHPL data")
            self.products_df = None
            return

        if self.products_df is None or len(self.products_df) == 0:
            logger.warning("No CHPL data available")
            self.products_df = None
            return

        logger.info(f"Loaded {len(self.products_df)} CHPL certified products")

        # Build lookup structures
        self._build_lookups()
    
    def _build_lookups(self):
        """Build efficient lookup structures for product/vendor matching."""
        self.vendor_names = set()
        self.product_names = set()
        self.product_patterns = []
        
        for _, row in self.products_df.iterrows():
            # Extract vendor name
            vendor = row.get('developer', {})
            if isinstance(vendor, dict):
                vendor_name = vendor.get('name', '').lower().strip()
            else:
                vendor_name = str(vendor).lower().strip()
            
            if vendor_name and len(vendor_name) > 3:  # Min 4 chars
                self.vendor_names.add(vendor_name)
            
            # Extract product name
            product = row.get('product', '')
            if isinstance(product, dict):
                product_name = product.get('name', '')
            else:
                product_name = str(product)
            product_name = product_name.lower().strip()
            
            if product_name and len(product_name) > 2:
                self.product_names.add(product_name)
                
                # Create regex pattern for matching
                pattern = r'\b' + re.escape(product_name) + r'\b'
                self.product_patterns.append(re.compile(pattern, re.IGNORECASE))
        
        logger.info(f"Built lookups: {len(self.vendor_names)} vendors, {len(self.product_names)} products")
    
    def check_chpl_match(self, description: str, cpe_list: str = None) -> Dict:
        """
        Check if CVE matches CHPL certified products.
        
        Args:
            description: CVE description text
            cpe_list: Optional CPE list (comma-separated)
        
        Returns:
            Dict with chpl_flag and matched product info
        """
        if self.products_df is None or not description:
            return {'chpl_flag': 0, 'matched_products': []}

        description_lower = description.lower()
        matched = []
        
        # Check vendor names
        for vendor in self.vendor_names:
            if len(vendor) > 4 and vendor in description_lower:  # Min 5 chars to avoid false positives
                matched.append(f"vendor:{vendor}")
                if len(matched) >= 5:  # Limit matches
                    break
        
        # Check product names with patterns
        if not matched:
            for pattern in self.product_patterns[:1000]:  # Limit to first 1000 patterns for speed
                if pattern.search(description):
                    matched.append(f"product:{pattern.pattern}")
                    if len(matched) >= 3:
                        break
        
        return {
            'chpl_flag': 1 if matched else 0,
            'matched_products': matched[:3]  # Keep top 3
        }
    
    def map_cve_to_chpl(self, description: str, cpe_list: str = None):
        """
        Map CVE to CHPL products (wrapper for check_chpl_match).
        
        Args:
            description: CVE description
            cpe_list: Optional CPE list
        
        Returns:
            Tuple of (is_match: bool, match_info: dict)
        """
        result = self.check_chpl_match(description, cpe_list)
        return (
            result['chpl_flag'] == 1,
            {
                'match_types': result['matched_products'],
                'chpl_flag': result['chpl_flag']
            }
        )

if __name__ == "__main__":
    # Test the mapper
    mapper = CHPLMapper()
    
    # Test cases
    test_cases = [
        "Vulnerability in Epic EHR system allows unauthorized access",
        "SQL injection in Cerner Millennium PowerChart",
        "Buffer overflow in medical device firmware",
        "XSS vulnerability in healthcare portal",
        "Remote code execution in patient management system"
    ]
    
    print("\n" + "="*70)
    print("CHPL MAPPER TEST")
    print("="*70)
    
    for desc in test_cases:
        result = mapper.check_chpl_match(desc)
        print(f"\nDescription: {desc}")
        print(f"  CHPL Match: {result['chpl_flag']}")
        if result['matched_products']:
            print(f"  Matched: {result['matched_products']}")
