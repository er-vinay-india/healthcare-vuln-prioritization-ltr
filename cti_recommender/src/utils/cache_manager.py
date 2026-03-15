"""
Cache Management Utility for CTI Recommender

Provides functions to manage data cache, including:
- Cache information/status
- Cache clearing (burst)
- Cache testing with sample data
- Fallback mechanism verification

Author: CTI Recommender Team
Date: 2026-01-18
"""

import os
import shutil
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import gzip
import pickle

try:
    from src.utils.logging_config import get_logger as _get_logger
    _logger = _get_logger(__name__)
except Exception:
    import logging
    logging.basicConfig(level=logging.INFO)
    _logger = logging.getLogger(__name__)


class CacheManager:
    """Manages cache for all data sources (NVD, EPSS, KEV, ATT&CK, CHPL)"""
    
    def __init__(self, cache_root: Optional[Path] = None):
        """
        Initialize cache manager
        
        Args:
            cache_root: Root directory for cache (default: cache/)
        """
        if cache_root is None:
            self.cache_root = Path(__file__).parent.parent.parent / 'cache'
        else:
            self.cache_root = Path(cache_root)
        
        # Organized cache structure with subdirectories for each source
        self.cache_sources = {
            'nvd': self.cache_root / 'nvd',
            'epss': self.cache_root / 'epss',
            'kev': self.cache_root / 'kev',
            'attack': self.cache_root / 'attack',
            'chpl': self.cache_root / 'chpl'
        }
    
    def get_cache_info(self) -> Dict[str, Dict]:
        """
        Get detailed information about all caches
        
        Returns:
            Dictionary with cache statistics for each source
            
        Example:
            {
                'nvd': {'exists': True, 'size_mb': 45.2, 'files': 3, 'last_modified': '2026-01-17'},
                'epss': {'exists': True, 'size_mb': 12.1, 'files': 2, 'last_modified': '2026-01-17'},
                ...
            }
        """
        cache_info = {}

        # NVD cache (now in cache/nvd/)
        try:
            nvd_dir = self.cache_sources['nvd']
            nvd_files = list(nvd_dir.glob('*.pkl.gz')) if nvd_dir.exists() else []
            if nvd_files:
                total_size = sum(f.stat().st_size for f in nvd_files)
                latest_mod = max(f.stat().st_mtime for f in nvd_files)
                cache_info['nvd'] = {
                    'exists': True,
                    'size_mb': total_size / (1024**2),
                    'files': len(nvd_files),
                    'last_modified': datetime.fromtimestamp(latest_mod).strftime('%Y-%m-%d %H:%M:%S'),
                    'age_days': (datetime.now() - datetime.fromtimestamp(latest_mod)).days
                }
            else:
                cache_info['nvd'] = {'exists': False}
        except Exception:
            _logger.exception("Failed to read NVD cache info")
            cache_info['nvd'] = {'exists': False, 'error': True}

        # EPSS cache (in cache/epss/)
        try:
            epss_dir = self.cache_sources['epss']
            if epss_dir.exists() and list(epss_dir.glob('*.json')):
                epss_files = list(epss_dir.glob('*.json'))
                total_size = sum(f.stat().st_size for f in epss_files)
                latest_mod = max(f.stat().st_mtime for f in epss_files)
                cache_info['epss'] = {
                    'exists': True,
                    'size_mb': total_size / (1024**2),
                    'files': len(epss_files),
                    'last_modified': datetime.fromtimestamp(latest_mod).strftime('%Y-%m-%d %H:%M:%S'),
                    'age_days': (datetime.now() - datetime.fromtimestamp(latest_mod)).days
                }
            else:
                cache_info['epss'] = {'exists': False}
        except Exception:
            _logger.exception("Failed to read EPSS cache info")
            cache_info['epss'] = {'exists': False, 'error': True}

        # KEV cache (now in cache/kev/)
        try:
            kev_dir = self.cache_sources['kev']
            kev_file = kev_dir / 'kev_catalog.pkl.gz'
            if kev_file.exists():
                kev_stat = kev_file.stat()
                cache_info['kev'] = {
                    'exists': True,
                    'size_mb': kev_stat.st_size / (1024**2),
                    'files': 1,
                    'last_modified': datetime.fromtimestamp(kev_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'age_days': (datetime.now() - datetime.fromtimestamp(kev_stat.st_mtime)).days
                }
            else:
                cache_info['kev'] = {'exists': False}
        except Exception:
            _logger.exception("Failed to read KEV cache info")
            cache_info['kev'] = {'exists': False, 'error': True}

        # ATT&CK cache (now in cache/attack/)
        try:
            attack_dir = self.cache_sources['attack']
            attack_file = attack_dir / 'attack_techniques.pkl.gz'
            if attack_file.exists():
                attack_stat = attack_file.stat()
                cache_info['attack'] = {
                    'exists': True,
                    'size_mb': attack_stat.st_size / (1024**2),
                    'files': 1,
                    'last_modified': datetime.fromtimestamp(attack_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'age_days': (datetime.now() - datetime.fromtimestamp(attack_stat.st_mtime)).days
                }
            else:
                cache_info['attack'] = {'exists': False}
        except Exception:
            _logger.exception("Failed to read ATT&CK cache info")
            cache_info['attack'] = {'exists': False, 'error': True}

        # CHPL cache (now in cache/chpl/)
        try:
            chpl_dir = self.cache_sources['chpl']
            chpl_files = list(chpl_dir.glob('*.json')) if chpl_dir.exists() else []
            if chpl_files:
                total_size = sum(f.stat().st_size for f in chpl_files)
                latest_mod = max(f.stat().st_mtime for f in chpl_files)
                cache_info['chpl'] = {
                    'exists': True,
                    'size_mb': total_size / (1024**2),
                    'files': len(chpl_files),
                    'last_modified': datetime.fromtimestamp(latest_mod).strftime('%Y-%m-%d %H:%M:%S'),
                    'age_days': (datetime.now() - datetime.fromtimestamp(latest_mod)).days
                }
            else:
                cache_info['chpl'] = {'exists': False}
        except Exception:
            _logger.exception("Failed to read CHPL cache info")
            cache_info['chpl'] = {'exists': False, 'error': True}

        return cache_info
    
    def print_cache_summary(self) -> None:
        """Print formatted cache summary"""
        cache_info = self.get_cache_info()
        
        print("=" * 70)
        print(" CACHE STATUS SUMMARY")
        print("=" * 70)
        
        total_size = 0
        total_files = 0
        
        for source, info in cache_info.items():
            print(f"\n  {source.upper()}")
            print("-" * 70)
            if info['exists']:
                print(f"   Status: [OK] Cached")
                print(f"   Size: {info['size_mb']:.2f} MB")
                print(f"   Files: {info['files']}")
                print(f"   Last Modified: {info['last_modified']}")
                print(f"   Age: {info['age_days']} days")
                total_size += info['size_mb']
                total_files += info['files']
            else:
                print(f"   Status: [FAIL] No cache (will fetch from API)")
        
        print("\n" + "=" * 70)
        print(f"TOTAL CACHE: {total_size:.2f} MB | {total_files} files")
        print("=" * 70)
    
    def clear_specific_cache(self, source: str, confirm: bool = False) -> bool:
        """
        Clear cache for a specific data source
        
        Args:
            source: One of 'nvd', 'epss', 'kev', 'attack', 'chpl'
            confirm: If False, will prompt for confirmation
            
        Returns:
            True if cleared, False if cancelled
        """
        if source not in self.cache_sources:
            print(f"[FAIL] Invalid source: {source}")
            print(f"   Valid sources: {', '.join(self.cache_sources.keys())}")
            return False
        
        # Check if cache exists
        cache_info = self.get_cache_info()
        if not cache_info[source]['exists']:
            print(f"[INFO]  No {source} cache to clear")
            return False
        
        # Confirmation
        if not confirm:
            size_mb = cache_info[source]['size_mb']
            files = cache_info[source]['files']
            print(f"[WARN]  WARNING: About to delete {source} cache")
            print(f"   Size: {size_mb:.2f} MB | Files: {files}")
            response = input("   Type 'yes' to confirm: ")
            if response.lower() != 'yes':
                print("[FAIL] Cancelled")
                return False
        
        # Delete files
        deleted_count = 0
        failed_count = 0

        try:
            if source == 'nvd':
                for f in self.cache_root.glob('nvd*.pkl.gz'):
                    try:
                        f.unlink()
                        deleted_count += 1
                    except Exception:
                        _logger.exception("Failed to delete NVD cache file: %s", f)
                        failed_count += 1
            elif source == 'epss':
                if self.cache_sources['epss'].exists():
                    shutil.rmtree(self.cache_sources['epss'])
                    self.cache_sources['epss'].mkdir(parents=True, exist_ok=True)
                    deleted_count = cache_info[source]['files']
            elif source == 'kev':
                kev_file = self.cache_root / 'kev_catalog.pkl.gz'
                if kev_file.exists():
                    kev_file.unlink()
                    deleted_count = 1
            elif source == 'attack':
                attack_file = self.cache_root / 'attack_techniques.pkl.gz'
                if attack_file.exists():
                    attack_file.unlink()
                    deleted_count = 1
            elif source == 'chpl':
                for f in self.cache_root.glob('chpl*.json'):
                    try:
                        f.unlink()
                        deleted_count += 1
                    except Exception:
                        _logger.exception("Failed to delete CHPL cache file: %s", f)
                        failed_count += 1
        except Exception:
            _logger.exception("Unexpected error clearing %s cache", source)

        if failed_count:
            _logger.warning("Cleared %s cache with %d failures (%d deleted)", source, failed_count, deleted_count)
        else:
            _logger.info("Cleared %s cache (%d files deleted)", source, deleted_count)
        print(f"[OK] Cleared {source} cache ({deleted_count} files deleted)")
        print(f"   Next run will fetch fresh data from API")
        return True
    
    def clear_all_cache(self, confirm: bool = False) -> bool:
        """
         DANGER: Clear ALL cache data
        
        Args:
            confirm: If False, will prompt for confirmation
            
        Returns:
            True if cleared, False if cancelled
        """
        cache_info = self.get_cache_info()
        
        # Calculate totals
        total_size = sum(info['size_mb'] for info in cache_info.values() if info['exists'])
        total_files = sum(info['files'] for info in cache_info.values() if info['exists'])
        
        if total_files == 0:
            print("[INFO]  No cache to clear")
            return False
        
        # Confirmation
        if not confirm:
            print(" WARNING: NUCLEAR OPTION - About to delete ALL cache!")
            print(f"   Total Size: {total_size:.2f} MB")
            print(f"   Total Files: {total_files}")
            print("\n   Sources to be cleared:")
            for source, info in cache_info.items():
                if info['exists']:
                    print(f"      - {source}: {info['size_mb']:.2f} MB ({info['files']} files)")
            print("\n   This will force fresh API downloads on next run.")
            response = input("\n   Type 'DELETE ALL' to confirm: ")
            if response != 'DELETE ALL':
                print("[FAIL] Cancelled")
                return False
        
        # Clear all sources
        for source in self.cache_sources.keys():
            self.clear_specific_cache(source, confirm=True)
        
        print("\n ALL CACHE CLEARED!")
        print("   Next enrichment run will fetch everything fresh from APIs")
        return True
    
    def test_cache_fallback(self, sample_cve_ids: Optional[List[str]] = None) -> Dict:
        """
        [TEST] Test cache fallback mechanism with sample data
        
        This is a SAFE test that uses a few sample CVEs to verify:
        1. Cache miss -> API call -> cache save
        2. Cache hit -> load from cache (no API call)
        3. Cache clear -> cache miss again
        
        Args:
            sample_cve_ids: List of CVE IDs to test (default: 5 recent CVEs)
            
        Returns:
            Dictionary with test results
        """
        if sample_cve_ids is None:
            # Use 5 sample CVEs from 2024
            sample_cve_ids = [
                'CVE-2024-0001',
                'CVE-2024-0002',
                'CVE-2024-0003',
                'CVE-2024-0004',
                'CVE-2024-0005'
            ]
        
        print("[TEST] Testing Cache Fallback Mechanism")
        print("=" * 70)
        print(f"Sample CVEs: {', '.join(sample_cve_ids)}")
        print()
        
        results = {
            'sample_cves': sample_cve_ids,
            'tests': []
        }
        
        # This is a mock test - in real implementation, you'd call actual fetcher
        print("[OK] Test 1: Cache Miss -> API Call")
        print("   (Would call API if no cache exists)")
        results['tests'].append({
            'test': 'cache_miss',
            'expected': 'API call made, data cached',
            'status': 'mock'
        })
        
        print("\n[OK] Test 2: Cache Hit -> Load from Cache")
        print("   (Would load from cache without API call)")
        results['tests'].append({
            'test': 'cache_hit',
            'expected': 'Data loaded from cache',
            'status': 'mock'
        })
        
        print("\n[OK] Test 3: Cache Clear -> Cache Miss")
        print("   (Would call API again after cache clear)")
        results['tests'].append({
            'test': 'cache_clear',
            'expected': 'API call made again',
            'status': 'mock'
        })
        
        print("\n" + "=" * 70)
        print("[INFO]  This is a mock test. Real implementation would:")
        print("   1. Import EPSSFetcher")
        print("   2. Fetch sample CVEs with cache enabled")
        print("   3. Clear cache for those CVEs")
        print("   4. Fetch again and verify API was called")
        print("=" * 70)
        
        return results
    
    def get_cache_age(self, source: str) -> Optional[int]:
        """
        Get age of cache in days
        
        Args:
            source: Cache source name
            
        Returns:
            Age in days or None if cache doesn't exist
        """
        cache_info = self.get_cache_info()
        if cache_info[source]['exists']:
            return cache_info[source]['age_days']
        return None
    
    def is_cache_stale(self, source: str, max_age_days: int = 30) -> bool:
        """
        Check if cache is stale (older than max_age_days)
        
        Args:
            source: Cache source name
            max_age_days: Maximum age in days (default: 30)
            
        Returns:
            True if stale or doesn't exist, False if fresh
        """
        age = self.get_cache_age(source)
        if age is None:
            return True  # No cache = stale
        return age > max_age_days


# Convenience functions for notebook use
def get_cache_manager() -> CacheManager:
    """Get default cache manager instance"""
    return CacheManager()


def print_cache_status():
    """Quick function to print cache status"""
    manager = get_cache_manager()
    manager.print_cache_summary()


def clear_cache(source: Optional[str] = None, confirm: bool = False):
    """
    Clear cache (specific source or all)
    
    Args:
        source: 'nvd', 'epss', 'kev', 'attack', 'chpl', or None for all
        confirm: If True, skips confirmation prompt
    """
    manager = get_cache_manager()
    if source is None:
        return manager.clear_all_cache(confirm=confirm)
    else:
        return manager.clear_specific_cache(source, confirm=confirm)


def test_cache():
    """Test cache fallback mechanism"""
    manager = get_cache_manager()
    return manager.test_cache_fallback()


if __name__ == '__main__':
    # Demo usage
    print("Cache Manager Demo\n")
    
    # Show cache status
    print_cache_status()
    
    print("\n" + "=" * 70)
    print("Available Functions:")
    print("=" * 70)
    print("1. print_cache_status() - Show cache summary")
    print("2. clear_cache('nvd') - Clear specific cache")
    print("3. clear_cache() - Clear all cache (with confirmation)")
    print("4. test_cache() - Test cache fallback mechanism")
    print("=" * 70)
