"""Integration tests for FastAPI endpoints"""
import pytest
from fastapi.testclient import TestClient
import json
from datetime import datetime, timedelta

from src.api.main import app


@pytest.fixture
def client():
    """Create FastAPI test client"""
    return TestClient(app)


class TestHealthEndpoint:
    """Test /health endpoint"""
    
    def test_health_check_returns_200(self, client):
        """Test health endpoint returns 200 OK"""
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_health_check_returns_json(self, client):
        """Test health endpoint returns JSON"""
        response = client.get("/health")
        assert response.headers["content-type"] == "application/json"
    
    def test_health_check_has_status(self, client):
        """Test health response has status field"""
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        # API can return: healthy, degraded, or unhealthy
        assert data["status"] in ["healthy", "degraded", "unhealthy"]


class TestStatisticsEndpoint:
    """Test /api/v1/stats endpoint"""
    
    def test_statistics_returns_200(self, client):
        """Test statistics endpoint returns 200 OK"""
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
    
    def test_statistics_returns_counts(self, client):
        """Test statistics includes expected counts"""
        response = client.get("/api/v1/stats")
        data = response.json()
        
        # Check for expected fields
        expected_fields = ['total_cves', 'kev_count', 'healthcare_count']
        for field in expected_fields:
            assert field in data
            assert isinstance(data[field], int)
            assert data[field] >= 0


class TestPredictEndpoint:
    """Test POST /api/v1/predict endpoint"""
    
    def test_predict_returns_200_for_valid_input(self, client):
        """Test predict endpoint with valid CVE IDs"""
        # Use real CVE IDs that should exist in the database
        payload = {
            "cve_ids": ["CVE-2024-0001", "CVE-2024-0002"]
        }
        response = client.post("/api/v1/predict", json=payload)
        
        # Should return 200 or 404 if CVEs don't exist
        assert response.status_code in [200, 404]
    
    def test_predict_returns_scores(self, client):
        """Test predict endpoint returns priority scores"""
        payload = {
            "cve_ids": ["CVE-2024-0001"]
        }
        response = client.post("/api/v1/predict", json=payload)
        
        if response.status_code == 200:
            data = response.json()
            assert "predictions" in data
            assert "count" in data
            assert isinstance(data["predictions"], dict)
            
            # Check format: {"predictions": {"CVE-ID": score}, "count": N}
            if len(data["predictions"]) > 0:
                cve_id = list(data["predictions"].keys())[0]
                score = data["predictions"][cve_id]
                assert isinstance(score, (int, float))
    
    def test_predict_rejects_empty_list(self, client):
        """Test predict endpoint rejects empty CVE ID list"""
        payload = {"cve_ids": []}
        response = client.post("/api/v1/predict", json=payload)
        assert response.status_code in [400, 422]
    
    def test_predict_rejects_invalid_format(self, client):
        """Test predict endpoint rejects invalid CVE ID format"""
        payload = {"cve_ids": ["INVALID-FORMAT"]}
        response = client.post("/api/v1/predict", json=payload)
        # Might return 400 for invalid format or 404 for not found
        assert response.status_code in [400, 404, 422]
    
    def test_predict_handles_missing_cves(self, client):
        """Test predict endpoint handles non-existent CVE IDs"""
        payload = {"cve_ids": ["CVE-9999-99999"]}
        response = client.post("/api/v1/predict", json=payload)
        # Should return 404 or empty predictions
        assert response.status_code in [200, 404]


class TestTopCVEsEndpoint:
    """Test GET /api/v1/top_cves endpoint"""
    
    def test_top_cves_returns_200(self, client):
        """Test top CVEs endpoint returns 200 OK"""
        response = client.get("/api/v1/top_cves")
        assert response.status_code == 200
    
    def test_top_cves_returns_list(self, client):
        """Test top CVEs endpoint returns list of CVEs"""
        response = client.get("/api/v1/top_cves")
        data = response.json()
        
        assert "top_cves" in data or isinstance(data, list)
        
        cve_list = data["top_cves"] if "top_cves" in data else data
        assert isinstance(cve_list, list)
    
    def test_top_cves_respects_limit(self, client):
        """Test top CVEs endpoint respects limit parameter"""
        limit = 5
        response = client.get(f"/api/v1/top_cves?limit={limit}")
        data = response.json()
        
        cve_list = data.get("top_cves", data)
        assert len(cve_list) <= limit
    
    def test_top_cves_filters_by_min_cvss(self, client):
        """Test top CVEs endpoint filters by minimum CVSS"""
        response = client.get("/api/v1/top_cves?min_cvss=7.0")
        
        if response.status_code == 200:
            data = response.json()
            cve_list = data.get("top_cves", data)
            
            # All returned CVEs should have CVSS >= 7.0
            for cve in cve_list:
                if "cvss" in cve:
                    assert cve["cvss"] >= 7.0
    
    def test_top_cves_filters_by_kev(self, client):
        """Test top CVEs endpoint filters KEV-only"""
        response = client.get("/api/v1/top_cves?kev_only=true")
        
        if response.status_code == 200:
            data = response.json()
            cve_list = data.get("top_cves", data)
            
            # All returned CVEs should be KEV-listed
            for cve in cve_list:
                if "kev_flag" in cve:
                    assert cve["kev_flag"] in [1, True, "true"]
    
    def test_top_cves_filters_by_healthcare(self, client):
        """Test top CVEs endpoint filters healthcare-only"""
        response = client.get("/api/v1/top_cves?healthcare_only=true")
        
        if response.status_code == 200:
            data = response.json()
            cve_list = data.get("top_cves", data)
            
            # All returned CVEs should be healthcare-relevant
            for cve in cve_list:
                if "is_healthcare" in cve:
                    assert cve["is_healthcare"] in [1, True, "true"]
    
    def test_top_cves_filters_by_date_range(self, client):
        """Test top CVEs endpoint filters by date range"""
        start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        response = client.get(f"/api/v1/top_cves?start_date={start_date}")
        
        if response.status_code == 200:
            data = response.json()
            cve_list = data.get("top_cves", data)
            
            # All CVEs should be within date range
            for cve in cve_list:
                if "published" in cve:
                    pub_date = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
                    assert pub_date >= datetime.fromisoformat(start_date)
    
    def test_top_cves_sorted_by_priority(self, client):
        """Test that CVEs are sorted by priority score"""
        response = client.get("/api/v1/top_cves?limit=10")
        
        if response.status_code == 200:
            data = response.json()
            cve_list = data.get("top_cves", data)
            
            if len(cve_list) > 1:
                # Check if sorted in descending order by priority_score
                scores = [cve.get("priority_score", 0) for cve in cve_list if "priority_score" in cve]
                if len(scores) > 1:
                    assert scores == sorted(scores, reverse=True), "CVEs not sorted by priority"
    
    def test_top_cves_combined_filters(self, client):
        """Test combining multiple filters"""
        response = client.get(
            "/api/v1/top_cves?limit=5&min_cvss=7.0&kev_only=true&healthcare_only=true"
        )
        
        if response.status_code == 200:
            data = response.json()
            cve_list = data.get("top_cves", data)
            
            assert len(cve_list) <= 5
            
            for cve in cve_list:
                if "cvss" in cve:
                    assert cve["cvss"] >= 7.0
                if "kev_flag" in cve:
                    assert cve["kev_flag"] in [1, True, "true"]
                if "is_healthcare" in cve:
                    assert cve["is_healthcare"] in [1, True, "true"]
    
    def test_top_cves_invalid_limit_returns_error(self, client):
        """Test invalid limit parameter"""
        response = client.get("/api/v1/top_cves?limit=-1")
        assert response.status_code in [400, 422]
    
    def test_top_cves_invalid_date_format_returns_error(self, client):
        """Test invalid date format"""
        response = client.get("/api/v1/top_cves?start_date=invalid-date")
        assert response.status_code in [400, 422]


class TestExplainEndpoint:
    """Test POST /api/v1/explain endpoint"""
    
    def test_explain_returns_200_for_valid_input(self, client):
        """Test explain endpoint with valid CVE ID"""
        payload = {"cve_id": "CVE-2024-0001"}
        response = client.post("/api/v1/explain", json=payload)
        
        # Should return 200 or 404 if CVE doesn't exist
        assert response.status_code in [200, 404]
    
    def test_explain_returns_feature_contributions(self, client):
        """Test explain endpoint returns feature contributions"""
        payload = {"cve_id": "CVE-2024-0001"}
        response = client.post("/api/v1/explain", json=payload)
        
        if response.status_code == 200:
            data = response.json()
            
            # Should have explanation data
            assert "cve_id" in data
            assert "explanation" in data or "feature_contributions" in data or "shap_values" in data
    
    def test_explain_rejects_missing_cve_id(self, client):
        """Test explain endpoint rejects missing CVE ID"""
        payload = {}
        response = client.post("/api/v1/explain", json=payload)
        assert response.status_code == 422  # Unprocessable Entity
    
    def test_explain_handles_nonexistent_cve(self, client):
        """Test explain endpoint handles non-existent CVE"""
        payload = {"cve_id": "CVE-9999-99999"}
        response = client.post("/api/v1/explain", json=payload)
        assert response.status_code == 404
    
    def test_explain_invalid_cve_format(self, client):
        """Test explain endpoint with invalid CVE format"""
        payload = {"cve_id": "INVALID"}
        response = client.post("/api/v1/explain", json=payload)
        assert response.status_code in [400, 404, 422]


class TestCORSHeaders:
    """Test CORS configuration"""
    
    def test_cors_headers_present(self, client):
        """Test that CORS headers are present"""
        response = client.options("/api/v1/top_cves")
        
        # Check for CORS headers
        assert "access-control-allow-origin" in response.headers
    
    def test_cors_allows_methods(self, client):
        """Test that CORS allows required methods"""
        response = client.options("/api/v1/predict")
        
        if "access-control-allow-methods" in response.headers:
            allowed_methods = response.headers["access-control-allow-methods"]
            assert "POST" in allowed_methods


class TestErrorHandling:
    """Test error handling across endpoints"""
    
    def test_404_for_invalid_endpoint(self, client):
        """Test 404 for non-existent endpoint"""
        response = client.get("/api/v1/nonexistent")
        assert response.status_code == 404
    
    def test_405_for_wrong_method(self, client):
        """Test 405 for wrong HTTP method"""
        response = client.post("/api/v1/stats")  # Should be GET
        assert response.status_code == 405
    
    def test_422_for_invalid_json(self, client):
        """Test 422 for malformed JSON"""
        response = client.post(
            "/api/v1/predict",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


class TestRateLimiting:
    """Test rate limiting (if implemented)"""
    
    @pytest.mark.skip(reason="Rate limiting not yet implemented")
    def test_rate_limit_enforced(self, client):
        """Test that rate limiting is enforced"""
        # Make many rapid requests
        for _ in range(100):
            response = client.get("/api/v1/top_cves")
            if response.status_code == 429:  # Too Many Requests
                break
        else:
            pytest.fail("Rate limiting not enforced")


class TestPerformance:
    """Test API performance"""
    
    def test_top_cves_responds_quickly(self, client):
        """Test that top CVEs endpoint responds in reasonable time"""
        import time
        
        start = time.time()
        response = client.get("/api/v1/top_cves?limit=100")
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 5.0, f"Response took {elapsed:.2f}s, expected < 5s"
    
    def test_predict_responds_quickly(self, client):
        """Test that predict endpoint responds in reasonable time"""
        import time
        
        payload = {
            "cve_ids": [f"CVE-2024-{i:04d}" for i in range(1, 11)]  # 10 CVEs
        }
        
        start = time.time()
        response = client.post("/api/v1/predict", json=payload)
        elapsed = time.time() - start
        
        # Should respond quickly even if CVEs don't exist
        assert elapsed < 5.0, f"Response took {elapsed:.2f}s, expected < 5s"


class TestResponseFormat:
    """Test response format consistency"""
    
    def test_all_responses_are_json(self, client):
        """Test that all endpoints return JSON"""
        endpoints = [
            ("/health", "GET"),
            ("/api/v1/stats", "GET"),
            ("/api/v1/top_cves", "GET"),
        ]
        
        for endpoint, method in endpoints:
            if method == "GET":
                response = client.get(endpoint)
            else:
                response = client.post(endpoint, json={})
            
            if response.status_code < 500:  # Don't check server errors
                assert "application/json" in response.headers.get("content-type", "")
    
    def test_error_responses_have_detail(self, client):
        """Test that error responses include detail field"""
        response = client.post("/api/v1/predict", json={"cve_ids": []})
        
        if response.status_code >= 400:
            data = response.json()
            assert "detail" in data or "message" in data or "error" in data
