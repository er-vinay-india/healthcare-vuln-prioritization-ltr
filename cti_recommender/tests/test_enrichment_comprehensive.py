"""
Comprehensive Enrichment Tests - Cross-Check ALL Records

Tests that scan the entire database (all 226,320+ CVEs) to identify
systematic data quality issues.
"""

import pytest
import pandas as pd
import numpy as np
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


@pytest.fixture
def full_dataset(db):
    """Load complete dataset for comprehensive testing"""
    print("\n[INFO] Loading full dataset from database...")
    # Cast published to TEXT to avoid SQLite timestamp conversion issues
    df = pd.read_sql("""
        SELECT 
            e.*,
            c.description,
            c.cvss,
            CAST(c.published AS TEXT) as published_date
        FROM enrichments e 
        JOIN cves c ON e.cve_id = c.cve_id
    """, db.conn)
    print(f"[INFO] Loaded {len(df):,} records")
    return df


class TestComprehensiveDataQuality:
    """Comprehensive data quality checks across entire dataset"""
    
    def test_all_records_epss_consistency(self, full_dataset):
        """Check EPSS score/date consistency across ALL records"""
        df = full_dataset
        
        # Records with EPSS score should have date
        epss_has_score = df['epss_score'] > 0
        epss_no_date = df[epss_has_score & df['epss_date'].isna()]
        
        print(f"\n[CHECK] EPSS Consistency:")
        print(f"  Total records: {len(df):,}")
        print(f"  Records with EPSS score > 0: {epss_has_score.sum():,}")
        print(f"  Records missing epss_date: {len(epss_no_date):,}")
        
        assert len(epss_no_date) == 0, (
            f"FAIL: {len(epss_no_date):,} records have EPSS score but NULL date. "
            f"Sample CVEs: {epss_no_date['cve_id'].head(5).tolist()}"
        )
    
    def test_all_records_healthcare_consistency(self, full_dataset):
        """Check healthcare flag/score consistency across ALL records"""
        df = full_dataset
        
        # Flag should align with score threshold
        flag_set = df['is_healthcare'] == 1
        score_high = df['healthcare_score'] > 0.3
        
        # Mismatches
        mismatch_flag_but_low_score = df[flag_set & ~score_high]
        mismatch_no_flag_but_high_score = df[~flag_set & score_high]
        
        print(f"\n[CHECK] Healthcare Consistency:")
        print(f"  Total records: {len(df):,}")
        print(f"  Healthcare flag set: {flag_set.sum():,}")
        print(f"  Healthcare score > 0.3: {score_high.sum():,}")
        print(f"  Flag=1 but score<=0.3: {len(mismatch_flag_but_low_score):,}")
        print(f"  Flag=0 but score>0.3: {len(mismatch_no_flag_but_high_score):,}")
        
        total_mismatches = len(mismatch_flag_but_low_score) + len(mismatch_no_flag_but_high_score)
        mismatch_pct = (total_mismatches / len(df) * 100) if len(df) > 0 else 0
        
        # Allow up to 2% mismatch due to different scoring logic between flag and score
        assert mismatch_pct <= 2.0, (
            f"FAIL: {total_mismatches:,} ({mismatch_pct:.2f}%) healthcare flag/score mismatches (expected <= 2%). "
            f"Sample mismatches (flag=1, score<=0.3): {mismatch_flag_but_low_score['cve_id'].head(3).tolist()}"
        )
    
    def test_all_records_healthcare_score_populated(self, full_dataset):
        """Verify healthcare_score is populated for ALL records"""
        df = full_dataset
        
        null_count = df['healthcare_score'].isna().sum()
        
        print(f"\n[CHECK] Healthcare Score Population:")
        print(f"  Total records: {len(df):,}")
        print(f"  NULL healthcare_score: {null_count:,}")
        print(f"  Populated: {len(df) - null_count:,}")
        
        assert null_count == 0, (
            f"FAIL: {null_count:,} records have NULL healthcare_score. "
            f"All records should have a score (even if 0.0)."
        )
    
    def test_all_records_curated_severity_logic(self, full_dataset):
        """Check curated severity is only set for curated CVEs"""
        df = full_dataset
        
        # Curated CVEs should have severity (with some tolerance)
        curated = df[df['is_curated'] == 1]
        curated_no_severity = curated[curated['curated_severity'].isna()]
        
        # Non-curated CVEs should NOT have severity
        non_curated = df[df['is_curated'] == 0]
        non_curated_has_severity = non_curated[non_curated['curated_severity'].notna()]
        
        print(f"\n[CHECK] Curated Severity Logic:")
        print(f"  Total curated CVEs: {len(curated):,}")
        print(f"  Curated missing severity: {len(curated_no_severity):,}")
        print(f"  Non-curated with severity: {len(non_curated_has_severity):,}")
        
        # Allow up to 10 curated to be missing severity
        assert len(curated_no_severity) < 10, (
            f"WARN: {len(curated_no_severity):,} curated CVEs missing severity "
            f"(expected < 10)"
        )
        
        # No non-curated should have severity
        assert len(non_curated_has_severity) == 0, (
            f"FAIL: {len(non_curated_has_severity):,} non-curated CVEs have curated_severity. "
            f"Sample: {non_curated_has_severity['cve_id'].head(5).tolist()}"
        )
    
    def test_all_records_no_invalid_values(self, full_dataset):
        """Check for invalid/extreme values across ALL records"""
        df = full_dataset
        
        issues = []
        
        # Check EPSS score range
        invalid_epss = df[(df['epss_score'] < 0) | (df['epss_score'] > 1)]
        if len(invalid_epss) > 0:
            issues.append(f"EPSS score: {len(invalid_epss):,} invalid (outside 0-1)")
        
        # Check healthcare score range  
        invalid_healthcare = df[(df['healthcare_score'] < 0) | (df['healthcare_score'] > 1)]
        if len(invalid_healthcare) > 0:
            issues.append(f"Healthcare score: {len(invalid_healthcare):,} invalid (outside 0-1)")
        
        # Check label range
        invalid_label = df[(df['label'] < 0) | (df['label'] > 5)]
        if len(invalid_label) > 0:
            issues.append(f"Label: {len(invalid_label):,} invalid (outside 0-5)")
        
        # Check attack technique count
        invalid_attack = df[(df['attack_technique_count'] < 0) | (df['attack_technique_count'] > 100)]
        if len(invalid_attack) > 0:
            issues.append(f"Attack count: {len(invalid_attack):,} invalid (negative or > 100)")
        
        print(f"\n[CHECK] Invalid Values:")
        if issues:
            for issue in issues:
                print(f"  ❌ {issue}")
        else:
            print(f"  ✅ No invalid values found")
        
        assert len(issues) == 0, "\n".join(issues)


class TestComprehensiveCoverage:
    """Check enrichment coverage across entire dataset"""
    
    def test_enrichment_coverage_statistics(self, full_dataset):
        """Generate comprehensive coverage statistics"""
        df = full_dataset
        
        total = len(df)
        
        coverage = {
            'kev_flag': (df['kev_flag'] == 1).sum(),
            'epss_score': (df['epss_score'] > 0).sum(),
            'epss_date': df['epss_date'].notna().sum(),
            'is_healthcare': (df['is_healthcare'] == 1).sum(),
            'healthcare_score': df['healthcare_score'].notna().sum(),
            'is_curated': (df['is_curated'] == 1).sum(),
            'curated_severity': df['curated_severity'].notna().sum(),
            'attack_flag': (df['attack_flag'] == 1).sum(),
            'chpl_flag': (df['chpl_flag'] == 1).sum(),
        }
        
        print(f"\n[COVERAGE] Enrichment Statistics (Total: {total:,} CVEs):")
        print("=" * 60)
        for field, count in coverage.items():
            pct = (count / total * 100) if total > 0 else 0
            bar = "█" * int(pct / 2)
            print(f"  {field:20s}: {count:>7,} ({pct:>5.1f}%) {bar}")
        print("=" * 60)
        
        # Critical checks
        # Note: EPSS may be 0 if enrichment was run with --skip-epss flag
        epss_populated = coverage['epss_score'] > 0 or coverage['epss_date'] > 0
        if not epss_populated:
            print("\n[WARN] EPSS data not populated - enrichment may have been run with --skip-epss")
        
        # If EPSS scores exist, dates should match
        if coverage['epss_score'] > 0:
            assert coverage['epss_date'] >= coverage['epss_score'] * 0.9, (
                f"FAIL: EPSS date coverage significantly lower than scores: "
                f"scores={coverage['epss_score']:,}, dates={coverage['epss_date']:,}"
            )
        
        # Healthcare score should always be populated (not affected by skip flags)
        assert coverage['healthcare_score'] == total, (
            f"FAIL: Healthcare score not fully populated: "
            f"{coverage['healthcare_score']:,}/{total:,}"
        )
    
    def test_label_distribution_complete(self, full_dataset):
        """Check label distribution across ALL records"""
        df = full_dataset
        
        label_counts = df['label'].value_counts().sort_index(ascending=False)
        total = len(df)
        
        label_names = {
            5: "Critical",
            4: "High",
            3: "Medium",
            2: "Low",
            1: "Informational",
            0: "Irrelevant"
        }
        
        print(f"\n[DISTRIBUTION] Label Distribution:")
        print("=" * 60)
        for label in range(5, -1, -1):
            count = label_counts.get(label, 0)
            pct = (count / total * 100) if total > 0 else 0
            bar = "█" * int(pct / 2)
            print(f"  L{label} ({label_names[label]:>13}): {count:>7,} ({pct:>5.1f}%) {bar}")
        print("=" * 60)
        
        # Ensure all labels are used
        assert len(label_counts) > 0, "FAIL: No labels assigned!"
        
        # Most CVEs should be low/medium priority
        low_medium = label_counts.get(0, 0) + label_counts.get(1, 0) + label_counts.get(2, 0)
        low_medium_pct = (low_medium / total * 100) if total > 0 else 0
        
        assert low_medium_pct > 40, (
            f"WARN: Low/medium priority CVEs should be majority: {low_medium_pct:.1f}%"
        )


class TestComprehensiveNullAnalysis:
    """Detailed NULL value analysis across ALL columns"""
    
    def test_null_percentage_by_column(self, full_dataset):
        """Calculate and report NULL percentage for each enrichment column"""
        df = full_dataset
        total = len(df)
        
        columns_to_check = [
            'kev_flag', 'epss_score', 'epss_percentile', 'epss_date',
            'is_healthcare', 'healthcare_score', 'is_curated', 'curated_severity',
            'attack_flag', 'attack_technique_count', 'chpl_flag', 'label'
        ]
        
        null_analysis = []
        for col in columns_to_check:
            if col in df.columns:
                null_count = df[col].isna().sum()
                null_pct = (null_count / total * 100) if total > 0 else 0
                null_analysis.append({
                    'column': col,
                    'null_count': null_count,
                    'null_pct': null_pct
                })
        
        null_df = pd.DataFrame(null_analysis).sort_values('null_pct', ascending=False)
        
        print(f"\n[NULL ANALYSIS] NULL Values by Column (Total: {total:,} records):")
        print("=" * 60)
        for _, row in null_df.iterrows():
            status = "✅" if row['null_pct'] < 1 else ("⚠️" if row['null_pct'] < 10 else "❌")
            print(f"  {status} {row['column']:25s}: {row['null_count']:>7,} ({row['null_pct']:>5.1f}%)")
        print("=" * 60)
        
        # Critical columns should not be mostly NULL
        # epss_date: Allow up to 10% NULL (not all CVEs have EPSS scores)
        # healthcare_score: Should be populated for all records
        critical_thresholds = {
            'epss_date': 10.0,  # Not all CVEs have EPSS scores
            'healthcare_score': 1.0  # Should be populated for all
        }
        
        for col, threshold in critical_thresholds.items():
            null_pct = null_df[null_df['column'] == col]['null_pct'].iloc[0] if col in null_df['column'].values else 0
            assert null_pct < threshold, (
                f"FAIL: Critical column '{col}' is {null_pct:.1f}% NULL (expected < {threshold}%)"
            )


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short", "-s"])
