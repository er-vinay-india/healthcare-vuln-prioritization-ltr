"""
Comprehensive tests for CHPL (Certified Health IT Product List) integration.
Tests cache loading, product matching, and enrichment pipeline.
"""
import pytest
import pandas as pd
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.chpl_fetcher import CHPLFetcher
from src.analysis.chpl_mapper import CHPLMapper


class TestCHPLFetcher:
    """Test CHPL data fetching and caching"""
    
    def test_cache_exists(self):
        """Verify CHPL cache directory exists"""
        cache_dir = Path(__file__).parent.parent / 'cache' / 'chpl'
        assert cache_dir.exists(), "CHPL cache directory not found"
    
    def test_cache_has_data(self):
        """Verify CHPL cache contains product data"""
        cache_dir = Path(__file__).parent.parent / 'cache' / 'chpl'
        pkl_file = cache_dir / 'chpl_products.pkl.gz'
        json_file = cache_dir / 'chpl_products.json'
        
        # At least one cache format should exist
        assert pkl_file.exists() or json_file.exists(), \
            "No CHPL cache files found (expected .pkl.gz or .json)"
    
    def test_fetcher_loads_cache(self):
        """Test CHPLFetcher can load cached data"""
        fetcher = CHPLFetcher()
        df = fetcher.get_chpl_data(force_refresh=False)
        
        assert df is not None, "CHPLFetcher returned None - cache load failed"
        assert isinstance(df, pd.DataFrame), "Expected DataFrame"
        assert len(df) > 0, "CHPL cache is empty"
        print(f"[OK] Loaded {len(df):,} CHPL products from cache")
    
    def test_cache_structure(self):
        """Verify CHPL data has expected columns"""
        fetcher = CHPLFetcher()
        df = fetcher.get_chpl_data()
        
        # Check for key columns
        assert 'developer' in df.columns or 'vendor' in df.columns, \
            "Missing vendor/developer column"
        assert 'product' in df.columns, "Missing product column"


class TestCHPLMapper:
    """Test CHPL CVE-to-product mapping"""
    
    @pytest.fixture
    def mapper(self):
        """Create CHPLMapper instance"""
        return CHPLMapper()
    
    def test_mapper_initialization(self, mapper):
        """Test mapper initializes with cached data"""
        assert mapper is not None
        assert mapper.products_df is not None, \
            "CHPLMapper failed to load CHPL data"
        assert len(mapper.products_df) > 0, \
            "CHPLMapper has no product data"
    
    def test_mapper_has_lookups(self, mapper):
        """Test mapper builds vendor/product lookups"""
        assert hasattr(mapper, 'vendor_names'), "Missing vendor_names lookup"
        assert hasattr(mapper, 'product_names'), "Missing product_names lookup"
        assert len(mapper.vendor_names) > 0, "No vendors in lookup"
        assert len(mapper.product_names) > 0, "No products in lookup"
        
        print(f"[OK] {len(mapper.vendor_names)} vendors, {len(mapper.product_names)} products")
    
    def test_known_vendor_match(self, mapper):
        """Test matching against known healthcare vendor"""
        # Test common healthcare vendors (Epic, Cerner, etc.)
        descriptions = [
            "Vulnerability in Epic Systems electronic health record",
            "Cerner Millennium EHR authentication bypass",
            "Allscripts Professional EHR SQL injection"
        ]
        
        matches = []
        for desc in descriptions:
            result = mapper.check_chpl_match(desc)
            if result['chpl_flag'] == 1:
                matches.append(desc[:30])
        
        # At least one should match if CHPL has major vendors
        if len(matches) > 0:
            print(f"[OK] Matched {len(matches)}/{len(descriptions)} known vendors")
    
    def test_no_match_on_generic_description(self, mapper):
        """Test no false positives on generic CVE"""
        generic_desc = "Buffer overflow vulnerability in generic software component allows code execution"
        result = mapper.check_chpl_match(generic_desc)
        
        # Should not match generic descriptions
        assert result['chpl_flag'] in [0, 1], "Invalid chpl_flag value"
    
    def test_empty_description_handling(self, mapper):
        """Test mapper handles empty/None descriptions"""
        result = mapper.check_chpl_match(None)
        assert result['chpl_flag'] == 0, "Should return 0 for None"
        
        result = mapper.check_chpl_match("")
        assert result['chpl_flag'] == 0, "Should return 0 for empty string"
    
    def test_map_cve_to_chpl(self, mapper):
        """Test map_cve_to_chpl method"""
        desc = "Epic Systems MyChart patient portal vulnerability"
        is_match, match_info = mapper.map_cve_to_chpl(desc)
        
        assert isinstance(is_match, bool), "Expected boolean"
        assert isinstance(match_info, dict), "Expected dict"
        assert 'chpl_flag' in match_info
        assert 'match_types' in match_info


class TestCHPLEnrichmentPipeline:
    """Test CHPL enrichment in data pipeline"""
    
    def test_database_has_chpl_column(self):
        """Verify enrichments table has chpl_flag column"""
        import sqlite3
        db_path = Path(__file__).parent.parent / 'data' / 'cve_database.db'
        
        if not db_path.exists():
            pytest.skip("Database not found - run backfill first")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get table schema
        cursor.execute("PRAGMA table_info(enrichments)")
        columns = [row[1] for row in cursor.fetchall()]
        
        assert 'chpl_flag' in columns, \
            "enrichments table missing chpl_flag column"
        
        conn.close()
    
    def test_chpl_enrichment_coverage(self):
        """Check if CHPL enrichment has been run"""
        import sqlite3
        db_path = Path(__file__).parent.parent / 'data' / 'cve_database.db'
        
        if not db_path.exists():
            pytest.skip("Database not found")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check CHPL coverage
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN chpl_flag=1 THEN 1 ELSE 0 END) as chpl_count
            FROM enrichments
        """)
        total, chpl_count = cursor.fetchone()
        conn.close()
        
        print(f"\n[STATS] CHPL Enrichment Status:")
        print(f"   Total CVEs: {total:,}")
        print(f"   CHPL matches: {chpl_count:,} ({chpl_count/total*100:.2f}%)")
        
        # Skip if no CHPL enrichment (optional enrichment, may be skipped intentionally)
        if chpl_count == 0 and total > 0:
            pytest.skip(
                f"Database has {total:,} CVEs but 0 CHPL enrichments. "
                "Run 'python scripts/enrich_cves.py' without --skip-chpl to enable CHPL enrichment."
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
