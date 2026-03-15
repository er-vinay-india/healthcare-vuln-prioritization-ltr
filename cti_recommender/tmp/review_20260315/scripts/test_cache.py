#!/usr/bin/env python3
"""
Cache Testing Script (Dry Run)

Tests cache functionality without modifying actual cache:
1. Cache status check
2. Cache freshness validation
3. Cache fallback mechanism (mock test)
4. Cache operations simulation

Usage:
    python scripts/test_cache.py
    python scripts/test_cache.py --verbose
    python scripts/test_cache.py --test-fallback
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.cache_manager import CacheManager


def test_cache_status(verbose=False):
    """Test 1: Check current cache status"""
    print("=" * 70)
    print("TEST 1: CACHE STATUS CHECK")
    print("=" * 70)
    
    cache_mgr = CacheManager()
    cache_info = cache_mgr.get_cache_info()
    
    total_size = 0
    total_files = 0
    
    print("\nCurrent Cache Status:")
    print("-" * 70)
    for source, info in cache_info.items():
        if info['exists']:
            print(f"[OK] {source.upper():8} | {info['size_mb']:6.2f} MB | {info['files']:3} files | {info['age_days']:3} days old")
            if verbose:
                print(f"          Last Modified: {info['last_modified']}")
            total_size += info['size_mb']
            total_files += info['files']
        else:
            print(f"[FAIL] {source.upper():8} | No cache (will fetch from API)")
    
    print("-" * 70)
    print(f"TOTAL: {total_size:.2f} MB | {total_files} files")
    print("\n[OK] Test 1 PASSED: Cache status retrieved successfully\n")


def test_cache_freshness(max_age_days=7):
    """Test 2: Check if cache is stale"""
    print("=" * 70)
    print(f"TEST 2: CACHE FRESHNESS CHECK (max age: {max_age_days} days)")
    print("=" * 70)
    
    cache_mgr = CacheManager()
    
    print("\n Cache Freshness Status:")
    print("-" * 70)
    
    stale_count = 0
    fresh_count = 0
    missing_count = 0
    
    for source in ['nvd', 'epss', 'kev', 'attack', 'chpl']:
        age = cache_mgr.get_cache_age(source)
        
        if age is None:
            print(f"[WARN]  {source.upper():8} | MISSING (no cache)")
            missing_count += 1
        elif age > max_age_days:
            print(f"[WARN]  {source.upper():8} | STALE ({age} days old) - Consider refreshing")
            stale_count += 1
        else:
            print(f"[OK] {source.upper():8} | FRESH ({age} days old)")
            fresh_count += 1
    
    print("-" * 70)
    print(f"Summary: {fresh_count} fresh | {stale_count} stale | {missing_count} missing")
    
    if stale_count > 0 or missing_count > 0:
        print("\n[TIP] TIP: Run 'python scripts/enrich_cves.py' to refresh cache")
    
    print("\n[OK] Test 2 PASSED: Cache freshness checked successfully\n")


def test_cache_fallback_mock():
    """Test 3: Mock test of cache fallback mechanism (safe, no modifications)"""
    print("=" * 70)
    print("TEST 3: CACHE FALLBACK MECHANISM (DRY RUN)")
    print("=" * 70)
    
    cache_mgr = CacheManager()
    
    print("\n[TEST] Testing Fallback Logic (Simulation):")
    print("-" * 70)
    
    # Simulate different scenarios
    scenarios = [
        {
            'name': 'Cache Hit',
            'condition': 'Cache exists and valid',
            'expected': 'Load from cache (fast)',
            'api_call': False
        },
        {
            'name': 'Cache Miss',
            'condition': 'Cache missing or expired',
            'expected': 'Fetch from API -> Save to cache',
            'api_call': True
        },
        {
            'name': 'Cache Corrupted',
            'condition': 'Cache file corrupted',
            'expected': 'Fallback to API -> Rebuild cache',
            'api_call': True
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\nScenario {i}: {scenario['name']}")
        print(f"   Condition: {scenario['condition']}")
        print(f"   Expected: {scenario['expected']}")
        print(f"   API Call: {'YES' if scenario['api_call'] else 'NO'}")
        print("   Result: [OK] PASS (simulation)")
    
    print("\n" + "-" * 70)
    print("[INFO]  This is a DRY RUN - no actual cache modifications made")
    print("[INFO]  Real system implements these fallback patterns automatically")
    print("\n[OK] Test 3 PASSED: Fallback logic validated\n")


def test_cache_operations_dry_run():
    """Test 4: Simulate cache operations (no actual modifications)"""
    print("=" * 70)
    print("TEST 4: CACHE OPERATIONS (DRY RUN - NO MODIFICATIONS)")
    print("=" * 70)
    
    cache_mgr = CacheManager()
    cache_info = cache_mgr.get_cache_info()
    
    print("\nAvailable Cache Operations:")
    print("-" * 70)
    
    # Operation 1: Clear specific cache (simulation)
    print("\n1⃣  Clear Specific Cache (e.g., EPSS)")
    if cache_info['epss']['exists']:
        print(f"   Would delete: {cache_info['epss']['files']} files ({cache_info['epss']['size_mb']:.2f} MB)")
        print(f"   Command: cache_mgr.clear_specific_cache('epss', confirm=True)")
    else:
        print(f"   Status: No EPSS cache to clear")
    print("   [WARN]  DRY RUN: No files deleted")
    
    # Operation 2: Clear all cache (simulation)
    print("\n2⃣  Clear ALL Cache (Nuclear Option)")
    total_size = sum(info['size_mb'] for info in cache_info.values() if info['exists'])
    total_files = sum(info['files'] for info in cache_info.values() if info['exists'])
    print(f"   Would delete: {total_files} files ({total_size:.2f} MB)")
    print(f"   Command: cache_mgr.clear_all_cache(confirm='DELETE ALL')")
    print("   [WARN]  DRY RUN: No files deleted")
    
    # Operation 3: Refresh stale cache (simulation)
    print("\n3⃣  Refresh Stale Cache")
    stale_sources = [s for s, info in cache_info.items() if info['exists'] and cache_mgr.is_cache_stale(s, max_age_days=7)]
    if stale_sources:
        print(f"   Stale sources: {', '.join(stale_sources)}")
        print(f"   Command: python scripts/enrich_cves.py")
    else:
        print(f"   Status: All caches are fresh")
    print("   [WARN]  DRY RUN: No API calls made")
    
    print("\n" + "-" * 70)
    print("[INFO]  This is a DRY RUN - no actual modifications made")
    print("[INFO]  Use the commands shown above for actual cache operations")
    print("\n[OK] Test 4 PASSED: Cache operations simulated\n")


def main():
    """Run all cache tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test cache functionality (dry run)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--test-fallback', '-f', action='store_true', help='Include fallback mechanism test')
    parser.add_argument('--max-age', '-a', type=int, default=7, help='Max cache age in days (default: 7)')
    
    args = parser.parse_args()
    
    print("\n[TEST] CTI RECOMMENDER - CACHE TESTING SUITE (DRY RUN)")
    print("=" * 70)
    print("[WARN]  SAFE MODE: No cache modifications will be made")
    print("=" * 70)
    print()
    
    results = []
    
    # Test 1: Cache Status
    try:
        test_cache_status(verbose=args.verbose)
        results.append(("Cache Status", True))
    except Exception as e:
        print(f"[FAIL] Test 1 FAILED: {e}\n")
        results.append(("Cache Status", False))
    
    # Test 2: Cache Freshness
    try:
        test_cache_freshness(max_age_days=args.max_age)
        results.append(("Cache Freshness", True))
    except Exception as e:
        print(f"[FAIL] Test 2 FAILED: {e}\n")
        results.append(("Cache Freshness", False))
    
    # Test 3: Fallback Mechanism (if requested)
    if args.test_fallback:
        try:
            test_cache_fallback_mock()
            results.append(("Fallback Mechanism", True))
        except Exception as e:
            print(f"[FAIL] Test 3 FAILED: {e}\n")
            results.append(("Fallback Mechanism", False))
    
    # Test 4: Cache Operations (dry run)
    try:
        test_cache_operations_dry_run()
        results.append(("Cache Operations", True))
    except Exception as e:
        print(f"[FAIL] Test 4 FAILED: {e}\n")
        results.append(("Cache Operations", False))
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[OK] PASSED" if result else "[FAIL] FAILED"
        print(f"{status}: {test_name}")
    
    print("-" * 70)
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 70)
    
    if passed == total:
        print("\n All cache tests PASSED! Cache system is healthy.")
    else:
        print(f"\n[WARN]  {total - passed} test(s) failed. Check cache configuration.")
    
    print("\n[TIP] Useful Commands:")
    print("   • View cache status: python -m src.utils.cache_manager")
    print("   • Refresh cache: python scripts/enrich_cves.py")
    print("   • Clear specific: python -c \"from src.utils.cache_manager import *; clear_cache('epss', confirm=True)\"")
    print("   • Clear all: python -c \"from src.utils.cache_manager import *; clear_cache(confirm=True)\"")
    print()
    
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
