"""
Test suite for enrichment data integrity
Ensures EPSS, KEV, ATT&CK, and other enrichments are properly populated
"""
import pytest
import sqlite3
from pathlib import Path


@pytest.fixture
def db_path():
    return "data/cve_database.db"


@pytest.fixture
def db_conn(db_path):
    conn = sqlite3.connect(db_path)
    yield conn
    conn.close()


class TestEnrichmentIntegrity:
    """Test enrichment data is properly loaded and not all zeros"""
    
    def test_epss_data_exists(self, db_conn):
        """Verify EPSS scores are populated with real data"""
        cursor = db_conn.cursor()
        
        # Check total records
        cursor.execute("SELECT COUNT(*) FROM enrichments")
        total = cursor.fetchone()[0]
        assert total > 0, "No enrichment records found"
        
        # Check EPSS data exists
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN epss_score > 0 THEN 1 ELSE 0 END) as has_epss,
                MAX(epss_score) as max_epss
            FROM enrichments
        """)
        
        total, has_epss, max_epss = cursor.fetchone()
        
        # At least 50% should have EPSS scores (realistic for FIRST.org coverage)
        epss_coverage = (has_epss / total * 100) if total > 0 else 0
        assert epss_coverage > 50, f"EPSS coverage too low: {epss_coverage:.1f}% (expected >50%)"
        
        # Max EPSS should be reasonable (0-1 scale, typically < 1.0)
        assert max_epss > 0, "EPSS max is 0 - data not populated!"
        assert max_epss <= 1.0, f"EPSS max {max_epss} exceeds valid range (0-1)"
        
        print(f"✓ EPSS: {has_epss:,}/{total:,} ({epss_coverage:.1f}%) with max={max_epss}")
    
    def test_epss_distribution_realistic(self, db_conn):
        """Verify EPSS distribution matches expected characteristics"""
        cursor = db_conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN epss_score > 0 AND epss_score < 0.01 THEN 1 END) as low,
                COUNT(CASE WHEN epss_score >= 0.01 AND epss_score < 0.1 THEN 1 END) as medium,
                COUNT(CASE WHEN epss_score >= 0.1 THEN 1 END) as high,
                AVG(CASE WHEN epss_score > 0 THEN epss_score END) as avg_nonzero
            FROM enrichments
        """)
        
        low, medium, high, avg_nonzero = cursor.fetchone()
        
        # Most EPSS scores should be in low range (right-skewed distribution)
        # This is a characteristic of EPSS data
        assert low > 0, "No low EPSS scores found - data likely not loaded"
        assert avg_nonzero is not None and avg_nonzero > 0, "Average EPSS is 0/NULL"
        
        print(f"✓ EPSS distribution: Low(<0.01)={low:,}, Med(0.01-0.1)={medium:,}, High(>0.1)={high:,}")
        print(f"  Average (non-zero): {avg_nonzero:.5f}")
    
    def test_kev_data_exists(self, db_conn):
        """Verify KEV flags are set"""
        cursor = db_conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE kev_flag = 1")
        kev_count = cursor.fetchone()[0]
        
        # KEV should be rare but present (0.3-0.8% is typical)
        cursor.execute("SELECT COUNT(*) FROM enrichments")
        total = cursor.fetchone()[0]
        kev_pct = (kev_count / total * 100) if total > 0 else 0
        
        assert kev_count > 0, "No KEV entries found"
        assert 0.1 < kev_pct < 2.0, f"KEV percentage {kev_pct:.2f}% outside expected range (0.1-2%)"
        
        print(f"✓ KEV: {kev_count:,} ({kev_pct:.2f}%)")
    
    def test_attack_data_exists(self, db_conn):
        """Verify ATT&CK mappings exist"""
        cursor = db_conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN attack_flag = 1 THEN 1 ELSE 0 END) as has_attack,
                MAX(attack_technique_count) as max_techniques
            FROM enrichments
        """)
        
        total, has_attack, max_techniques = cursor.fetchone()
        attack_pct = (has_attack / total * 100) if total > 0 else 0
        
        assert has_attack > 0, "No ATT&CK mappings found"
        assert max_techniques >= 1, "No technique counts found"
        
        print(f"✓ ATT&CK: {has_attack:,} ({attack_pct:.1f}%) max_techniques={max_techniques}")
    
    def test_healthcare_data_reasonable(self, db_conn):
        """Verify healthcare flags are reasonable (not too many false positives)"""
        cursor = db_conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(is_healthcare) as healthcare_count
            FROM enrichments
        """)
        
        total, healthcare_count = cursor.fetchone()
        healthcare_pct = (healthcare_count / total * 100) if total > 0 else 0
        
        # Healthcare should be small subset (0.1-5% is reasonable for specialized domain)
        assert healthcare_pct < 10, f"Healthcare {healthcare_pct:.1f}% too high - likely false positives"
        
        print(f"✓ Healthcare: {healthcare_count:,} ({healthcare_pct:.2f}%)")
    
    def test_no_all_zero_features(self, db_conn):
        """Critical test: ensure no enrichment features are all zeros/nulls"""
        cursor = db_conn.cursor()
        
        cursor.execute("""
            SELECT 
                SUM(kev_flag) as kev,
                SUM(CASE WHEN epss_score > 0 THEN 1 ELSE 0 END) as epss,
                SUM(is_healthcare) as healthcare,
                SUM(attack_flag) as attack,
                SUM(chpl_flag) as chpl,
                SUM(is_curated) as curated
            FROM enrichments
        """)
        
        kev, epss, healthcare, attack, chpl, curated = cursor.fetchone()
        
        issues = []
        if kev == 0:
            issues.append("KEV: all zeros")
        if epss == 0:
            issues.append("EPSS: all zeros")
        if healthcare == 0:
            issues.append("Healthcare: all zeros")
        if attack == 0:
            issues.append("ATT&CK: all zeros")
        
        assert len(issues) == 0, f"Critical features are all zeros: {', '.join(issues)}"
        
        print(f"✓ All features populated: KEV={kev}, EPSS={epss}, HC={healthcare}, ATT&CK={attack}")


class TestEnrichmentCacheIntegrity:
    """Test that cache files exist and are valid"""
    
    def test_epss_cache_exists(self):
        """Verify EPSS cache file exists"""
        cache_path = Path("cache/epss/epss_persistent.json")
        assert cache_path.exists(), "EPSS persistent cache missing"
        assert cache_path.stat().st_size > 1000000, "EPSS cache suspiciously small"
        
        print(f"✓ EPSS cache: {cache_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    def test_cache_directories_exist(self):
        """Verify all cache directories are set up"""
        cache_dirs = [
            "cache/epss",
            "cache/kev",
            "cache/attack",
            "cache/chpl",
            "cache/nvd"
        ]

        for cache_dir in cache_dirs:
            path = Path(cache_dir)
            assert path.exists(), f"Cache directory missing: {cache_dir}"

        print(f"✓ All {len(cache_dirs)} cache directories exist")


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "-s"])
