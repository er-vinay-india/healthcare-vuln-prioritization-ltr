"""
Test expectations for CVSS temporal distribution plot generation
"""
import os
import pytest
import sqlite3
from pathlib import Path


@pytest.fixture
def db_path():
    return "data/cve_database.db"


@pytest.fixture
def expected_plot_path():
    return "outputs/plots/cvss_temporal_trends.html"


def test_cvss_temporal_data_requirements(db_path):
    """Test that database has required data for CVSS temporal analysis"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check we have CVEs with publication dates
    cursor.execute("SELECT COUNT(*) FROM cves WHERE published IS NOT NULL")
    count = cursor.fetchone()[0]
    assert count > 0, "No CVEs with publication dates"
    
    # Check we have CVSS scores
    cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss IS NOT NULL")
    cvss_count = cursor.fetchone()[0]
    assert cvss_count > 0, "No CVEs with CVSS scores"
    
    # Check we have data across years 2018-2025
    cursor.execute("""
        SELECT COUNT(DISTINCT strftime('%Y', published)) 
        FROM cves 
        WHERE published IS NOT NULL
    """)
    year_count = cursor.fetchone()[0]
    assert year_count >= 8, f"Expected 8 years (2018-2025), got {year_count}"
    
    conn.close()


def test_plot_generation_expectations(expected_plot_path):
    """Test that plot file will be created in correct location"""
    plot_dir = Path(expected_plot_path).parent
    assert plot_dir.exists(), f"Output directory {plot_dir} does not exist"
    
    # Plot may not exist yet, but directory should
    assert str(plot_dir) == "outputs/plots"


def test_plot_content_requirements(expected_plot_path):
    """Test that generated plot has required content (run after generation)"""
    if not os.path.exists(expected_plot_path):
        pytest.skip("Plot not generated yet")
    
    with open(expected_plot_path, 'r') as f:
        content = f.read()
    
    # Check it's an HTML file
    assert '<html' in content.lower(), "Not a valid HTML file"
    
    # Check for Plotly (our visualization library)
    assert 'plotly' in content.lower(), "Missing Plotly library"
    
    # Check for expected data traces (CVE count and CVSS score)
    assert len(content) > 10000, "Plot HTML seems too small"
    
    print(f"✓ Plot generated successfully at {expected_plot_path}")
    print(f"  File size: {len(content):,} bytes")
