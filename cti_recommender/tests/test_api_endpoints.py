"""Unit tests for FastAPI endpoints"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock
import pandas as pd

from src.api.main import app


client = TestClient(app)


class TestRootEndpoints:
    """Tests for root and health endpoints"""
    
    def test_root_endpoint(self):
        """Test root endpoint returns service info"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "version" in data
        assert data["status"] == "operational"
    
    @patch('src.api.main.get_database')
    def test_health_check_healthy(self, mock_db):
        """Test health check when all systems operational"""
        # Mock database responses
        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            (226320,),  # total_cves
            (214316,),  # enriched_cves
            ("2024-01-15 10:00:00",)  # last_update
        ]
        
        mock_conn = Mock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_db_instance = Mock()
        mock_db_instance.conn = mock_conn
        mock_db.return_value = mock_db_instance
        
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert "total_cves" in data
    
    @patch('src.api.main.get_database')
    def test_health_check_degraded(self, mock_db):
        """Test health check when database issues exist"""
        # Mock database error
        mock_db.side_effect = Exception("Database connection failed")
        
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["database_connected"] is False


class TestStatisticsEndpoint:
    """Tests for statistics endpoint"""
    
    @patch('src.api.main.get_database')
    def test_get_statistics(self, mock_db):
        """Test statistics retrieval"""
        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            (226320,),  # total_cves
            (214316,),  # epss_coverage
            (1161,),    # kev_count
            (124753,),  # healthcare_count
            (8.5, 0.0, 10.0),  # cvss_stats
        ]
        mock_cursor.fetchall.return_value = [
            (4, 1716),
            (3, 4128),
            (2, 164778)
        ]
        
        mock_conn = Mock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_db_instance = Mock()
        mock_db_instance.conn = mock_conn
        mock_db.return_value = mock_db_instance
        
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_cves" in data
        assert "label_distribution" in data
        assert "cvss_stats" in data


class TestCVEEndpoints:
    """Tests for CVE-specific endpoints"""
    
    @patch('src.api.main.get_database')
    def test_get_cve_details_found(self, mock_db):
        """Test CVE details retrieval - found"""
        mock_cursor = Mock()
        mock_row = {
            'cve_id': 'CVE-2024-1234',
            'cvss': 9.8,
            'description': 'Test vulnerability',
            'kev_flag': 1,
            'epss_score': 0.78
        }
        mock_cursor.fetchone.return_value = mock_row
        
        mock_conn = Mock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_db_instance = Mock()
        mock_db_instance.conn = mock_conn
        mock_db.return_value = mock_db_instance
        
        response = client.get("/api/v1/cve/CVE-2024-1234")
        assert response.status_code == 200
        data = response.json()
        assert data['cve_id'] == 'CVE-2024-1234'
    
    @patch('src.api.main.get_database')
    def test_get_cve_details_not_found(self, mock_db):
        """Test CVE details retrieval - not found"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        
        mock_conn = Mock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_db_instance = Mock()
        mock_db_instance.conn = mock_conn
        mock_db.return_value = mock_db_instance
        
        response = client.get("/api/v1/cve/CVE-9999-9999")
        assert response.status_code == 404


class TestRecommendationsEndpoint:
    """Tests for recommendations endpoint"""
    
    @patch('src.api.main.load_model')
    @patch('src.api.main.get_database')
    @patch('src.api.main.prepare_features')
    def test_get_recommendations_success(self, mock_prepare, mock_db, mock_model):
        """Test successful recommendations generation"""
        # Mock database query
        mock_df = pd.DataFrame({
            'cve_id': ['CVE-2024-1', 'CVE-2024-2'],
            'cvss': [9.8, 8.5],
            'kev_flag': [1, 0],
            'epss_score': [0.8, 0.5],
            'is_healthcare': [1, 1],
            'is_curated': [0, 0],
            'attack_technique_count': [2, 1],
            'label': [4, 3],
            'published_str': ['2024-01-15', '2024-01-16'],
            'description': ['Test CVE 1', 'Test CVE 2']
        })
        
        mock_conn = Mock()
        mock_conn.cursor.return_value = Mock()
        
        mock_db_instance = Mock()
        mock_db_instance.conn = mock_conn
        
        # Mock pandas read_sql_query
        with patch('pandas.read_sql_query', return_value=mock_df):
            mock_db.return_value = mock_db_instance
            
            # Mock model
            mock_model_instance = Mock()
            mock_model_instance.predict.return_value = [0.95, 0.85]
            mock_model.return_value = (mock_model_instance, None)
            
            # Mock feature preparation
            mock_prepare.return_value = [[1, 0.8], [0, 0.5]]
            
            response = client.post("/api/v1/recommendations", json={
                "limit": 2,
                "healthcare_only": True
            })
            
            assert response.status_code == 200
            data = response.json()
            assert len(data) <= 2
    
    def test_recommendations_invalid_request(self):
        """Test recommendations with invalid request"""
        response = client.post("/api/v1/recommendations", json={
            "limit": 0  # Invalid: must be >= 1
        })
        assert response.status_code == 422  # Validation error


class TestAPIDocumentation:
    """Tests for API documentation"""
    
    def test_openapi_schema(self):
        """Test OpenAPI schema is accessible"""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert "paths" in schema
    
    def test_swagger_ui(self):
        """Test Swagger UI is accessible"""
        response = client.get("/docs")
        assert response.status_code == 200
    
    def test_redoc_ui(self):
        """Test ReDoc UI is accessible"""
        response = client.get("/redoc")
        assert response.status_code == 200
