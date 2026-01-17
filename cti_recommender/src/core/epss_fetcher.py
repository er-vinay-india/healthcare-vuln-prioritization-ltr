"""
EPSS (Exploit Prediction Scoring System) Fetcher
Integrates FIRST.org EPSS API to provide exploit probability scores (0-1)
for CVEs, filling gaps from missing CVSS scores and enhancing prioritization.
"""

import requests
import pandas as pd
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# EPSS API Configuration
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
CACHE_DIR = Path("data_cache/epss")
CACHE_EXPIRY_DAYS = 1  # EPSS updates daily

class EPSSFetcher:
    """Fetches and caches EPSS scores from FIRST.org API"""
    
    def __init__(self, cache_dir: Path = CACHE_DIR):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CTI-Healthcare-Recommender/1.0',
            'Accept': 'application/json'
        })
    
    def _get_cache_path(self, date: str = None) -> Path:
        """Get cache file path for specific date or today"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
        return self.cache_dir / f"epss_{date}.json"
    
    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache exists and is less than 1 day old"""
        if not cache_path.exists():
            return False
        
        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        return cache_age < timedelta(days=CACHE_EXPIRY_DAYS)
    
    def fetch_epss_bulk(self, cve_list: List[str], use_cache: bool = True) -> Dict[str, dict]:
        """
        Fetch EPSS scores for multiple CVEs in bulk
        
        Args:
            cve_list: List of CVE IDs (e.g., ['CVE-2023-12345', ...])
            use_cache: Whether to use cached data
        
        Returns:
            Dict mapping CVE ID to {epss_score, percentile, date}
        """
        cache_path = self._get_cache_path()
        
        # Try cache first
        if use_cache and self._is_cache_valid(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    cached_data = json.load(f)
                
                # Filter for requested CVEs
                result = {cve: cached_data[cve] for cve in cve_list if cve in cached_data}
                
                if len(result) >= len(cve_list) * 0.9:  # 90% hit rate
                    print(f"[EPSS] Loaded {len(result)}/{len(cve_list)} CVEs from cache")
                    return result
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[EPSS] Cache read error: {e}")
        
        # Fetch from API
        print(f"[EPSS] Fetching scores for {len(cve_list)} CVEs from API...")
        
        result = {}
        batch_size = 100  # EPSS API limit per request
        
        for i in range(0, len(cve_list), batch_size):
            batch = cve_list[i:i + batch_size]
            batch_result = self._fetch_batch(batch)
            result.update(batch_result)
            
            # Rate limiting: 1 request per second
            if i + batch_size < len(cve_list):
                time.sleep(1)
        
        # Save to cache
        try:
            with open(cache_path, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"[EPSS] Cached {len(result)} CVE scores")
        except IOError as e:
            print(f"[EPSS] Cache write error: {e}")
        
        return result
    
    def _fetch_batch(self, cve_batch: List[str]) -> Dict[str, dict]:
        """Fetch EPSS scores for a batch of CVEs"""
        try:
            # Build query parameters: ?cve=CVE-2023-1,CVE-2023-2,...
            cve_param = ','.join(cve_batch)
            params = {'cve': cve_param}
            
            response = self.session.get(EPSS_API_BASE, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse response
            result = {}
            if 'data' in data:
                for item in data['data']:
                    cve_id = item.get('cve')
                    if cve_id:
                        result[cve_id] = {
                            'epss_score': float(item.get('epss', 0)),
                            'percentile': float(item.get('percentile', 0)),
                            'date': item.get('date', '')
                        }
            
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[EPSS] API error for batch: {e}")
            return {}
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            print(f"[EPSS] Parse error: {e}")
            return {}
    
    def enrich_dataframe(self, df: pd.DataFrame, cve_column: str = 'cve_id') -> pd.DataFrame:
        """
        Add EPSS scores to a DataFrame containing CVE IDs
        
        Args:
            df: DataFrame with CVE IDs
            cve_column: Name of column containing CVE IDs
        
        Returns:
            DataFrame with added columns: epss_score, epss_percentile
        """
        if cve_column not in df.columns:
            print(f"[EPSS] Warning: Column '{cve_column}' not found")
            df['epss_score'] = 0.0
            df['epss_percentile'] = 0.0
            return df
        
        # Get unique CVEs
        cve_list = df[cve_column].dropna().unique().tolist()
        
        if not cve_list:
            print("[EPSS] No CVEs to enrich")
            df['epss_score'] = 0.0
            df['epss_percentile'] = 0.0
            return df
        
        # Fetch scores
        epss_data = self.fetch_epss_bulk(cve_list)
        
        # Map to DataFrame
        df['epss_score'] = df[cve_column].map(
            lambda cve: epss_data.get(cve, {}).get('epss_score', 0.0)
        )
        df['epss_percentile'] = df[cve_column].map(
            lambda cve: epss_data.get(cve, {}).get('percentile', 0.0)
        )
        
        # Report coverage
        coverage = (df['epss_score'] > 0).sum() / len(df) * 100
        print(f"[EPSS] Enriched {len(df)} rows, {coverage:.1f}% coverage")
        
        return df
    
    def get_high_risk_cves(self, threshold: float = 0.5) -> List[str]:
        """
        Get list of CVEs with EPSS score above threshold
        
        Args:
            threshold: EPSS score threshold (0-1), default 0.5 (high exploitation risk)
        
        Returns:
            List of high-risk CVE IDs
        """
        cache_path = self._get_cache_path()
        
        if not self._is_cache_valid(cache_path):
            print("[EPSS] No recent cache available, fetch CVEs first")
            return []
        
        try:
            with open(cache_path, 'r') as f:
                epss_data = json.load(f)
            
            high_risk = [
                cve for cve, data in epss_data.items()
                if data.get('epss_score', 0) >= threshold
            ]
            
            print(f"[EPSS] Found {len(high_risk)} CVEs with score >= {threshold}")
            return high_risk
            
        except (json.JSONDecodeError, IOError) as e:
            print(f"[EPSS] Error reading cache: {e}")
            return []


def fetch_epss_scores(cve_list: List[str], use_cache: bool = True) -> Dict[str, dict]:
    """
    Convenience function to fetch EPSS scores
    
    Args:
        cve_list: List of CVE IDs
        use_cache: Whether to use cached data
    
    Returns:
        Dict mapping CVE ID to {epss_score, percentile, date}
    """
    fetcher = EPSSFetcher()
    return fetcher.fetch_epss_bulk(cve_list, use_cache=use_cache)


if __name__ == "__main__":
    # Test with sample CVEs
    test_cves = [
        'CVE-2023-0669',  # Recent high-profile
        'CVE-2021-44228',  # Log4Shell (known high EPSS)
        'CVE-2023-12345',  # Likely not found
    ]
    
    print("Testing EPSS Fetcher...")
    fetcher = EPSSFetcher()
    scores = fetcher.fetch_epss_bulk(test_cves, use_cache=False)
    
    print("\nResults:")
    for cve, data in scores.items():
        print(f"{cve}: EPSS={data['epss_score']:.4f}, Percentile={data['percentile']:.2f}%")
    
    # Test DataFrame enrichment
    df = pd.DataFrame({'cve_id': test_cves})
    df_enriched = fetcher.enrich_dataframe(df)
    print("\nEnriched DataFrame:")
    print(df_enriched)
