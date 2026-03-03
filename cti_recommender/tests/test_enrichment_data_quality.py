"""
Data Quality Tests for CVE Enrichment

Tests to ensure all enrichment fields are properly populated with valid data.
These tests should PASS after fixing the enrichment pipeline.
"""

import pytest
import pandas as pd
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase


@pytest.fixture
def db():
    """Get database connection"""
    database = CVEDatabase()
    yield database
    database.close()


class TestEPSSDataQuality:
    """Tests for EPSS enrichment data quality"""
    
    def test_epss_date_not_null_when_score_exists(self, db):
        """Verify epss_date is populated when epss_score exists"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE epss_score IS NOT NULL 
            AND epss_score > 0 
            AND epss_date IS NULL
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} records with epss_score but NULL epss_date. "
            f"The enrichment pipeline should extract the 'date' field from EPSS API responses."
        )
    
    def test_epss_date_format_valid(self, db):
        """Verify epss_date is in valid date format"""
        df = pd.read_sql("""
            SELECT epss_date FROM enrichments 
            WHERE epss_date IS NOT NULL 
            LIMIT 100
        """, db.conn)
        
        if len(df) == 0:
            pytest.fail("No epss_date values found to validate format")
        
        # Try to parse dates
        try:
            pd.to_datetime(df['epss_date'], errors='raise')
        except Exception as e:
            pytest.fail(f"Invalid date format in epss_date: {e}")
    
    def test_epss_score_range(self, db):
        """Verify epss_score is in valid range [0, 1]"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE epss_score < 0 OR epss_score > 1
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} records with invalid epss_score (outside 0-1 range)"
        )
    
    def test_epss_percentile_range(self, db):
        """Verify epss_percentile is in valid range [0, 1]"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE epss_percentile < 0 OR epss_percentile > 1
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} records with invalid epss_percentile (outside 0-1 range)"
        )


class TestHealthcareDataQuality:
    """Tests for healthcare enrichment data quality"""
    
    def test_healthcare_score_not_null(self, db):
        """Verify healthcare_score is populated (can be 0, but not NULL)"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE healthcare_score IS NULL
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} records with NULL healthcare_score. "
            f"The enrichment pipeline should call healthcare_mapper.get_healthcare_score()."
        )
    
    def test_healthcare_score_range(self, db):
        """Verify healthcare_score is in valid range [0, 1]"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE healthcare_score < 0 OR healthcare_score > 1
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} records with invalid healthcare_score (outside 0-1 range)"
        )
    
    def test_healthcare_flag_score_consistency(self, db):
        """Verify is_healthcare flag aligns with healthcare_score threshold (0.3)"""
        # NOTE: This test is informational only - old is_healthcare flag may use different logic
        # than new healthcare_score field. Some mismatches are expected.
        
        # Check: is_healthcare=1 should have score > 0.3
        result1 = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE is_healthcare = 1 AND healthcare_score <= 0.3
        """).fetchone()[0]
        
        # Check: is_healthcare=0 should have score <= 0.3
        result2 = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE is_healthcare = 0 AND healthcare_score > 0.3
        """).fetchone()[0]
        
        mismatches = result1 + result2
        
        # Allow up to 5% mismatch between old flag and new score (different logic)
        total = db.conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        mismatch_pct = (mismatches / total * 100) if total > 0 else 0
        
        assert mismatch_pct <= 5.0, (
            f"FAIL: Found {mismatches:,} ({mismatch_pct:.2f}%) mismatches between is_healthcare flag and healthcare_score. "
            f"(Flag=1 but score<=0.3: {result1:,}, Flag=0 but score>0.3: {result2:,}). "
            f"Expected <= 5% mismatch due to different scoring logic."
        )
    
    def test_healthcare_count_reasonable(self, db):
        """Verify healthcare CVE count is reasonable (not 0%, not 100%)"""
        total, healthcare = db.conn.execute("""
            SELECT COUNT(*), SUM(is_healthcare) FROM enrichments
        """).fetchone()
        
        healthcare_pct = (healthcare / total * 100) if total > 0 else 0
        
        assert 0.1 < healthcare_pct < 5.0, (
            f"WARN: Healthcare percentage seems unusual: {healthcare_pct:.1f}% "
            f"({healthcare:,}/{total:,}). Expected 0.1-5.0%."
        )


class TestCuratedDataQuality:
    """Tests for curated dataset enrichment data quality"""
    
    def test_curated_severity_populated_when_curated(self, db):
        """Verify curated CVEs have severity populated (with tolerance for missing data)"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE is_curated = 1 AND curated_severity IS NULL
        """).fetchone()[0]
        
        # Allow up to 10 curated CVEs to be missing severity
        # (some curated entries may not have this field)
        assert result < 10, (
            f"FAIL: Too many curated CVEs missing severity: {result:,}. "
            f"Expected < 10 missing."
        )
    
    def test_curated_severity_valid_values(self, db):
        """Verify curated_severity contains valid severity levels"""
        valid_severities = {'critical', 'high', 'medium', 'low', 'informational'}
        
        df = pd.read_sql("""
            SELECT DISTINCT LOWER(curated_severity) as curated_severity FROM enrichments 
            WHERE curated_severity IS NOT NULL
        """, db.conn)
        
        invalid = set(df['curated_severity']) - valid_severities
        
        assert len(invalid) == 0, (
            f"FAIL: Found invalid curated_severity values: {invalid}. "
            f"Valid values (case-insensitive): {valid_severities}"
        )
    
    def test_non_curated_have_null_severity(self, db):
        """Verify non-curated CVEs have NULL curated_severity"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE is_curated = 0 AND curated_severity IS NOT NULL
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} non-curated CVEs with curated_severity set. "
            f"Only curated CVEs should have this field."
        )


class TestEnrichmentCompleteness:
    """Tests for overall enrichment completeness"""
    
    def test_all_cves_have_enrichment_record(self, db):
        """Verify every CVE in cves table has corresponding enrichment record"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM cves c
            LEFT JOIN enrichments e ON c.cve_id = e.cve_id
            WHERE e.cve_id IS NULL
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} CVEs without enrichment records"
        )
    
    def test_kev_flag_coverage(self, db):
        """Verify KEV flag is set for reasonable number of CVEs"""
        total, kev_count = db.conn.execute("""
            SELECT COUNT(*), SUM(kev_flag) FROM enrichments
        """).fetchone()
        
        kev_pct = (kev_count / total * 100) if total > 0 else 0
        
        # KEV catalog typically has 1000-2000 CVEs out of 200k+ total
        assert 0.3 < kev_pct < 2.0, (
            f"WARN: KEV percentage seems unusual: {kev_pct:.2f}% "
            f"({kev_count:,}/{total:,}). Expected 0.3-2.0%."
        )
    
    def test_attack_technique_count_range(self, db):
        """Verify attack_technique_count is reasonable"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE attack_technique_count < 0 OR attack_technique_count > 50
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} records with invalid attack_technique_count "
            f"(negative or > 50)"
        )
    
    def test_label_valid_range(self, db):
        """Verify label is in valid range [0, 5]"""
        result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments 
            WHERE label < 0 OR label > 5
        """).fetchone()[0]
        
        assert result == 0, (
            f"FAIL: Found {result:,} records with invalid label (outside 0-5 range)"
        )


class TestDataStatistics:
    """Statistical tests to verify enrichment makes sense"""
    
    def test_epss_statistics_reasonable(self, db):
        """Verify EPSS score statistics are in expected ranges"""
        # First check if EPSS data exists
        count_result = db.conn.execute("""
            SELECT COUNT(*) FROM enrichments WHERE epss_score > 0
        """).fetchone()[0]
        
        if count_result == 0:
            # EPSS data not populated (enrichment may have been run with --skip-epss)
            pytest.skip("EPSS data not populated - run enrichment without --skip-epss")
        
        stats = db.conn.execute("""
            SELECT 
                AVG(epss_score) as avg_score,
                MIN(epss_score) as min_score,
                MAX(epss_score) as max_score
            FROM enrichments
            WHERE epss_score > 0
        """).fetchone()
        
        avg_score, min_score, max_score = stats
        
        # EPSS scores are typically low (most CVEs have < 0.1 probability)
        assert 0 <= avg_score <= 0.3, (
            f"WARN: Average EPSS score unusual: {avg_score:.4f}. Expected 0-0.3."
        )
        assert 0 <= min_score <= max_score <= 1, (
            f"FAIL: EPSS score range invalid: min={min_score}, max={max_score}"
        )
    
    def test_label_distribution_reasonable(self, db):
        """Verify label distribution follows expected pattern (most CVEs = low priority)"""
        df = pd.read_sql("""
            SELECT label, COUNT(*) as count 
            FROM enrichments 
            GROUP BY label
            ORDER BY label DESC
        """, db.conn)
        
        # Most CVEs should be low priority (labels 0-2)
        low_priority = df[df['label'].isin([0, 1, 2])]['count'].sum()
        high_priority = df[df['label'].isin([4, 5])]['count'].sum()
        total = df['count'].sum()
        
        low_pct = (low_priority / total * 100) if total > 0 else 0
        high_pct = (high_priority / total * 100) if total > 0 else 0
        
        assert low_pct > 50, (
            f"WARN: Low priority CVEs should be majority. Found {low_pct:.1f}% "
            f"(expected > 50%)"
        )
        assert high_pct < 20, (
            f"WARN: Too many high priority CVEs: {high_pct:.1f}% (expected < 20%)"
        )


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])
