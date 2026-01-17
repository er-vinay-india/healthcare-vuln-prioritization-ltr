#!/usr/bin/env python3
"""
CHPL (Certified Health IT Product List) fetcher with smart caching.
Strategy: Check cache first → If empty, fetch from API once → Save to cache → Use cached data
Never calls API twice for same data.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import os
import json
import gzip
import pickle
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class CHPLFetcher:
    """Fetches CHPL data with intelligent caching."""
    
    def __init__(self, api_key=None):
        """Initialize with optional API key."""
        self.api_key = api_key or os.getenv('CHPL_API_KEY')
        self.cache_dir = Path(__file__).parent.parent / 'data_cache'
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / 'chpl_products.pkl.gz'
        self.json_cache = self.cache_dir / 'chpl_products.json'
    
    def get_chpl_data(self, force_refresh=False):
        """
        Get CHPL data - checks cache first, fetches if needed.
        
        Args:
            force_refresh: Force API fetch even if cache exists
        
        Returns:
            DataFrame with CHPL products
        """
        # Step 1: Check cache
        if not force_refresh and self._cache_exists() and self._cache_valid():
            print("✓ Loading CHPL data from cache (no API call)")
            return self._load_cache()
        
        # Step 2: Cache empty/invalid - fetch from API
        print("⚠ Cache empty/invalid - fetching from CHPL API (ONE TIME)")
        df = self._fetch_from_api()
        
        # Step 3: Save to cache immediately
        if df is not None and len(df) > 0:
            self._save_cache(df)
            print(f"✓ Cached {len(df)} products for future use")
        
        return df
    
    def _cache_exists(self):
        """Check if cache file exists and has data."""
        if not self.cache_file.exists():
            return False
        
        try:
            with gzip.open(self.cache_file, 'rb') as f:
                df = pickle.load(f)
            return isinstance(df, pd.DataFrame) and len(df) > 0
        except:
            return False
    
    def _cache_valid(self):
        """Check if cache is recent (less than 30 days old)."""
        if not self.cache_file.exists():
            return False
        
        cache_age_days = (datetime.now().timestamp() - self.cache_file.stat().st_mtime) / 86400
        return cache_age_days < 30
    
    def _load_cache(self):
        """Load data from cache."""
        try:
            with gzip.open(self.cache_file, 'rb') as f:
                df = pickle.load(f)
            print(f"  Loaded {len(df)} products from cache")
            return df
        except Exception as e:
            print(f"  Error loading cache: {e}")
            return None
    
    def _fetch_from_api(self):
        """Fetch CHPL data from API."""
        if not self.api_key:
            print("  ❌ No CHPL API key found (set CHPL_API_KEY env var)")
            print("  Using mock data for testing...")
            return self._create_mock_data()
        
        try:
            # CHPL API v3 search endpoint
            url = "https://chpl.healthit.gov/rest/search/v3"
            headers = {'API-Key': self.api_key}
            params = {
                'pageNumber': 0,
                'pageSize': 100,  # Max per page
                'certificationStatuses': 'Active'
            }
            
            all_products = []
            page = 0
            
            print(f"  Fetching from CHPL API...")
            
            while True:
                params['pageNumber'] = page
                response = requests.get(url, headers=headers, params=params, timeout=30)
                
                if response.status_code != 200:
                    print(f"  API error: {response.status_code}")
                    break
                
                data = response.json()
                results = data.get('results', [])
                
                if not results:
                    break
                
                all_products.extend(results)
                print(f"  Page {page+1}: {len(results)} products (total: {len(all_products)})")
                
                # Check if more pages
                if len(results) < params['pageSize']:
                    break
                
                page += 1
                
                # Safety limit
                if page >= 100:
                    print(f"  Reached page limit, stopping")
                    break
            
            if all_products:
                df = pd.DataFrame(all_products)
                return df
            else:
                print("  No products fetched, using mock data")
                return self._create_mock_data()
        
        except Exception as e:
            print(f"  API fetch error: {e}")
            print("  Using mock data...")
            return self._create_mock_data()
    
    def _create_mock_data(self):
        """Create mock CHPL data for testing without API."""
        mock_products = [
            {'developer': {'name': 'Epic Systems'}, 'product': {'name': 'EpicCare'}, 'version': '2023'},
            {'developer': {'name': 'Cerner'}, 'product': {'name': 'Millennium'}, 'version': '2023'},
            {'developer': {'name': 'Allscripts'}, 'product': {'name': 'Sunrise'}, 'version': '2023'},
            {'developer': {'name': 'eClinicalWorks'}, 'product': {'name': 'eCW'}, 'version': '11.0'},
            {'developer': {'name': 'NextGen Healthcare'}, 'product': {'name': 'NextGen Office'}, 'version': '5.9'},
            {'developer': {'name': 'athenahealth'}, 'product': {'name': 'athenaOne'}, 'version': '2023'},
            {'developer': {'name': 'GE Healthcare'}, 'product': {'name': 'Centricity'}, 'version': '12.0'},
            {'developer': {'name': 'Philips'}, 'product': {'name': 'IntelliSpace'}, 'version': '8.0'},
        ]
        print(f"  Created mock data: {len(mock_products)} products")
        return pd.DataFrame(mock_products)
    
    def _save_cache(self, df):
        """Save DataFrame to cache."""
        try:
            # Save as pickle (compressed)
            with gzip.open(self.cache_file, 'wb') as f:
                pickle.dump(df, f)
            
            # Also save as JSON for inspection
            df.to_json(self.json_cache, orient='records', indent=2)
            
            print(f"  ✓ Saved to cache: {self.cache_file}")
        except Exception as e:
            print(f"  ⚠ Cache save error: {e}")

if __name__ == "__main__":
    print("="*70)
    print("CHPL FETCHER - SMART CACHING")
    print("="*70)
    
    fetcher = CHPLFetcher()
    
    # First call - will fetch if cache empty
    print("\n1st call - checking cache...")
    df1 = fetcher.get_chpl_data()
    print(f"Result: {len(df1) if df1 is not None else 0} products")
    
    # Second call - should use cache (no API call)
    print("\n2nd call - should use cache...")
    df2 = fetcher.get_chpl_data()
    print(f"Result: {len(df2) if df2 is not None else 0} products")
    
    print("\n✓ Demonstrated: Check cache first → Fetch once → Use cached data")
