"""
EPSS (Exploit Prediction Scoring System) Fetcher
Integrates FIRST.org EPSS API to provide exploit probability scores (0-1)
for CVEs, filling gaps from missing CVSS scores and enhancing prioritization.
"""

import pandas as pd
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Import centralized configuration and logging
try:
    from config.settings import settings
    from src.utils.logging_config import get_logger
    from src.utils.api_client import get_epss_client
    logger = get_logger(__name__)
    USE_RESILIENT_CLIENT = True
except ImportError:
    # Fallback for standalone usage
    import requests
    import logging
    logger = logging.getLogger(__name__)
    settings = None
    USE_RESILIENT_CLIENT = False

class EPSSFetcher:
    """Fetches and caches EPSS scores from FIRST.org API"""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        # Use centralized settings if available
        if cache_dir is None and settings:
            self.cache_dir = settings.get_cache_dir() / "epss"
            self.api_base = settings.EPSS_API_BASE
        elif cache_dir is None:
            self.cache_dir = Path("cache/epss")
            self.api_base = "https://api.first.org/data/v1/epss"
        else:
            self.cache_dir = Path(cache_dir)
            self.api_base = "https://api.first.org/data/v1/epss"
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.persistent_cache_path = self.cache_dir / "epss_persistent.json"
        
        # Use ResilientAPIClient if available
        if USE_RESILIENT_CLIENT:
            self.client = get_epss_client()
            logger.info("EPSS Fetcher initialized with ResilientAPIClient", 
                       extra={"cache_dir": str(self.cache_dir)})
        else:
            # Fallback to requests
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'CTI-Healthcare-Recommender/1.0',
                'Accept': 'application/json'
            })
            logger.info("EPSS Fetcher initialized", 
                       extra={"cache_dir": str(self.cache_dir)})
        
        self._log_cache_stats()
    
    def _get_cache_path(self, date: Optional[str] = None) -> Path:
        """Get cache file path for specific date or today"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
        return self.cache_dir / f"epss_{date}.json"
    
    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache exists and is less than 1 day old"""
        if not cache_path.exists():
            return False
        
        cache_expiry_days = settings.CACHE_EXPIRY_DAYS if settings else 1
        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        return cache_age < timedelta(days=cache_expiry_days)
    
    def _log_cache_stats(self) -> None:
        """Log statistics about cached EPSS data"""
        persistent_data = self._load_persistent_cache()
        logger.info("Persistent cache statistics", 
                   extra={"cve_count": len(persistent_data)})
        
        if persistent_data:
            scores = [v['epss_score'] for v in persistent_data.values()]
            logger.info("EPSS score statistics", extra={
                "min_score": min(scores),
                "max_score": max(scores),
                "avg_score": sum(scores)/len(scores)
            })
    
    def _load_persistent_cache(self) -> Dict[str, dict]:
        """Load persistent cache that never expires"""
        if not self.persistent_cache_path.exists():
            return {}
        
        try:
            with open(self.persistent_cache_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Persistent cache read error", extra={"error": str(e)})
            return {}
    
    def _save_persistent_cache(self, data: Dict[str, dict]) -> None:
        """Save to persistent cache (append, never delete)"""
        existing = self._load_persistent_cache()
        existing.update(data)  # Merge new data
        
        try:
            with open(self.persistent_cache_path, 'w') as f:
                json.dump(existing, f, indent=2)
            logger.info("Persistent cache updated", 
                       extra={"total_cves": len(existing)})
        except IOError as e:
            logger.warning("Persistent cache write error", 
                          extra={"error": str(e)})
    
    def fetch_epss_bulk(self, cve_list: List[str], use_cache: bool = True, show_progress: bool = True) -> Dict[str, dict]:
        """
        Fetch EPSS scores for multiple CVEs in bulk
        
        Args:
            cve_list: List of CVE IDs (e.g., ['CVE-2023-12345', ...])
            use_cache: Whether to use cached data
            show_progress: Whether to show progress updates
        
        Returns:
            Dict mapping CVE ID to {epss_score, percentile, date}
        """
        logger.info("Starting bulk EPSS fetch", extra={"cve_count": len(cve_list)})
        
        # Try persistent cache first (NEVER expires)
        result = {}
        if use_cache:
            persistent_data = self._load_persistent_cache()
            result = {cve: persistent_data[cve] for cve in cve_list if cve in persistent_data}
            
            if result:
                cache_hit_rate = len(result) / len(cve_list) * 100
                logger.info("Cache hit", extra={
                    "cached": len(result),
                    "total": len(cve_list),
                    "hit_rate": f"{cache_hit_rate:.1f}%"
                })
                
                if cache_hit_rate >= 95:  # 95% hit rate is good enough
                    logger.info("Using cached data (>95% hit rate)")
                    return result
        
        # Determine what we need to fetch
        cves_to_fetch = [cve for cve in cve_list if cve not in result]
        logger.info("Need to fetch from API", extra={"count": len(cves_to_fetch)})
        
        if not cves_to_fetch:
            return result
        
        # Estimate time
        batch_size = 100
        num_batches = (len(cves_to_fetch) + batch_size - 1) // batch_size
        estimated_time = num_batches * 1.5  # 1 sec per batch + overhead
        logger.info("Batch fetch estimation", extra={
            "num_batches": num_batches,
            "estimated_minutes": f"{estimated_time/60:.1f}"
        })
        
        # Fetch from API with progress
        fetched_count = 0
        start_time = time.time()
        checkpoint_interval = 50  # Save progress every 50 batches (~5000 CVEs)
        
        for i in range(0, len(cves_to_fetch), batch_size):
            batch = cves_to_fetch[i:i + batch_size]
            batch_num = i // batch_size + 1
            
            batch_result = self._fetch_batch(batch)
            result.update(batch_result)
            fetched_count += len(batch_result)
            
            # Checkpoint: Save progress incrementally to prevent data loss
            if batch_num % checkpoint_interval == 0:
                new_data = {k: v for k, v in result.items() if k in cves_to_fetch}
                self._save_persistent_cache(new_data)
                logger.info("Checkpoint saved", extra={
                    "batch": batch_num,
                    "total_batches": num_batches
                })
            
            # Progress logging
            if show_progress and (batch_num % 10 == 0 or batch_num == num_batches):
                elapsed = time.time() - start_time
                progress_pct = batch_num / num_batches * 100
                rate = fetched_count / elapsed if elapsed > 0 else 0
                eta = (len(cves_to_fetch) - fetched_count) / rate if rate > 0 else 0
                logger.info("Batch progress", extra={
                    "batch": batch_num,
                    "total_batches": num_batches,
                    "progress_pct": f"{progress_pct:.1f}%",
                    "fetched": fetched_count,
                    "rate_cves_per_sec": f"{rate:.1f}",
                    "eta_minutes": f"{eta/60:.1f}"
                })
            
            # Rate limiting: 1 request per second
            if i + batch_size < len(cves_to_fetch):
                time.sleep(1)
        
        # Save to persistent cache (final save)
        if fetched_count > 0:
            new_data = {k: v for k, v in result.items() if k in cves_to_fetch}
            self._save_persistent_cache(new_data)
            logger.info("Final cache save", extra={"new_cves": len(new_data)})
        
        # Final statistics
        elapsed_total = time.time() - start_time
        success_rate = len(result) / len(cve_list) * 100
        logger.info("Bulk fetch completed", extra={
            "duration_minutes": f"{elapsed_total/60:.1f}",
            "success_count": len(result),
            "total_requested": len(cve_list),
            "success_rate": f"{success_rate:.1f}%"
        })
        
        if len(result) < len(cve_list):
            missing = len(cve_list) - len(result)
            logger.warning("Missing CVEs", extra={
                "missing_count": missing,
                "reason": "not in EPSS database"
            })
        
        return result
    
    def _fetch_batch(self, cve_batch: List[str]) -> Dict[str, dict]:
        """Fetch EPSS scores for a batch of CVEs"""
        try:
            # Build query parameters: ?cve=CVE-2023-1,CVE-2023-2,...
            cve_param = ','.join(cve_batch)
            params = {'cve': cve_param}
            
            # Use ResilientAPIClient if available
            if USE_RESILIENT_CLIENT:
                data = self.client.get('/epss', params=params, timeout=30)
            else:
                response = self.session.get(self.api_base, params=params, timeout=30)
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
            
        except Exception as e:
            logger.warning("API error for batch", extra={"error": str(e)})
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
            logger.warning(f"Column not found: {cve_column}")
            df['epss_score'] = 0.0
            df['epss_percentile'] = 0.0
            return df
        
        # Get unique CVEs
        cve_list = df[cve_column].dropna().unique().tolist()
        
        if not cve_list:
            logger.warning("No CVEs to enrich")
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
        logger.info("Enriched DataFrame", extra={
            "rows": len(df),
            "coverage": f"{coverage:.1f}%"
        })
        
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
            logger.warning("No recent cache available, fetch CVEs first")
            return []
        
        try:
            with open(cache_path, 'r') as f:
                epss_data = json.load(f)
            
            high_risk = [
                cve for cve, data in epss_data.items()
                if data.get('epss_score', 0) >= threshold
            ]
            
            logger.info("Found high-risk CVEs", extra={
                "count": len(high_risk),
                "threshold": threshold
            })
            return high_risk
            
        except (json.JSONDecodeError, IOError) as e:
            logger.error("Error reading cache", extra={"error": str(e)})
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
    
    logger.info("Testing EPSS Fetcher...")
    fetcher = EPSSFetcher()
    scores = fetcher.fetch_epss_bulk(test_cves, use_cache=False)
    
    logger.info("\nResults:")
    for cve, data in scores.items():
        logger.info(f"{cve}: EPSS={data['epss_score']:.4f}, Percentile={data['percentile']:.2f}%")
    
    # Test DataFrame enrichment
    df = pd.DataFrame({'cve_id': test_cves})
    df_enriched = fetcher.enrich_dataframe(df)
    logger.info(f"\nEnriched DataFrame:\n{df_enriched}")
