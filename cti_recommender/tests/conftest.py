"""Pytest configuration and shared fixtures"""
import pytest
import tempfile
from pathlib import Path
from datetime import datetime
import sqlite3

from config.settings import Settings


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_settings(temp_dir):
    """Create test settings with temporary paths"""
    return Settings(
        DATABASE_PATH=temp_dir / "test.db",
        CACHE_DIR=temp_dir / "cache",
        LOG_DIR=temp_dir / "logs",
        MODEL_DIR=temp_dir / "models"
    )


@pytest.fixture
def test_database(temp_dir):
    """Create test database with sample data"""
    db_path = temp_dir / "test.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            published TIMESTAMP,
            modified TIMESTAMP,
            description TEXT,
            cvss REAL,
            cvss_vector TEXT,
            cwe TEXT,
            raw_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE enrichments (
            cve_id TEXT PRIMARY KEY,
            kev_flag INTEGER DEFAULT 0,
            epss_score REAL,
            epss_percentile REAL,
            epss_date TEXT,
            is_healthcare INTEGER DEFAULT 0,
            is_curated INTEGER DEFAULT 0,
            curated_severity TEXT,
            healthcare_score REAL,
            attack_flag INTEGER DEFAULT 0,
            attack_technique_count INTEGER DEFAULT 0,
            chpl_flag INTEGER DEFAULT 0,
            label INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
        )
    """)
    
    # Insert sample CVEs
    cursor.execute("""
        INSERT INTO cves (cve_id, published, modified, description, cvss, cvss_vector, cwe, raw_json) 
        VALUES 
        ('CVE-2024-1234', '2024-01-15 10:00:00', '2024-01-16 10:00:00', 
         'Test vulnerability in healthcare system', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 
         'CWE-120', '{}'),
        ('CVE-2024-5678', '2024-01-20 10:00:00', '2024-01-21 10:00:00', 
         'Another test vulnerability', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 
         'CWE-79', '{}')
    """)
    
    # Insert enrichments with all columns
    cursor.execute("""
        INSERT INTO enrichments (cve_id, kev_flag, epss_score, epss_percentile, epss_date, 
                                is_healthcare, is_curated, curated_severity, healthcare_score,
                                attack_flag, attack_technique_count, chpl_flag, label) 
        VALUES 
        ('CVE-2024-1234', 1, 0.78, 0.95, '2024-01-15', 1, 1, 'critical', 0.9, 1, 3, 1, 4),
        ('CVE-2024-5678', 0, 0.45, 0.75, '2024-01-20', 1, 0, NULL, 0.6, 0, 0, 0, 3)
    """)
    
    conn.commit()
    conn.close()
    
    yield db_path


@pytest.fixture
def sample_cve_data():
    """Sample CVE data for testing"""
    return {
        'cve_id': 'CVE-2024-1234',
        'published': datetime(2024, 1, 15),
        'modified': datetime(2024, 1, 16),
        'description': 'Buffer overflow in XYZ application',
        'cvss': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'cwe': 'CWE-120'
    }


@pytest.fixture
def sample_epss_data():
    """Sample EPSS data for testing"""
    return {
        'cve_id': 'CVE-2024-1234',
        'epss_score': 0.78,
        'percentile': 0.95,
        'date': '2024-01-15'
    }


@pytest.fixture
def sample_enrichment():
    """Sample enrichment data for testing"""
    return {
        'cve_id': 'CVE-2024-1234',
        'kev_flag': True,
        'epss_score': 0.78,
        'is_healthcare': True,
        'is_curated': False,
        'attack_technique_count': 2,
        'label': 4
    }


@pytest.fixture
def mock_xgboost_model():
    """Mock XGBoost model for testing"""
    from unittest.mock import Mock
    
    model = Mock()
    model.predict.return_value = [0.95, 0.85, 0.75]
    return model


@pytest.fixture(scope="session")
def test_config():
    """Test configuration for integration tests"""
    return {
        'database': 'test_cve.db',
        'log_level': 'DEBUG',
        'timeout': 5
    }
