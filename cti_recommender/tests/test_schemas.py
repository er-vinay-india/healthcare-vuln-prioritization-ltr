"""Unit tests for Pydantic validation schemas"""
import pytest
from datetime import datetime
from pydantic import ValidationError

from src.models.schemas import (
    CVEInput,
    EPSSScore,
    CVEEnrichment,
    CVERecommendation,
    ModelMetrics,
    HealthStatus,
    RecommendationRequest
)


class TestCVEInput:
    """Tests for CVEInput schema"""
    
    def test_valid_cve_input(self):
        """Test valid CVE input"""
        cve = CVEInput(
            cve_id="CVE-2024-1234",
            published=datetime(2024, 1, 15),
            modified=datetime(2024, 1, 16),
            description="Buffer overflow vulnerability",
            cvss=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.cvss == 9.8
    
    def test_invalid_cve_id_format(self):
        """Test invalid CVE ID format"""
        with pytest.raises(ValidationError) as exc_info:
            CVEInput(
                cve_id="INVALID-2024-1234",
                published=datetime.now(),
                modified=datetime.now(),
                description="Test description"
            )
        assert "Invalid CVE ID format" in str(exc_info.value)
    
    def test_cvss_out_of_range(self):
        """Test CVSS score validation"""
        with pytest.raises(ValidationError):
            CVEInput(
                cve_id="CVE-2024-1234",
                published=datetime.now(),
                modified=datetime.now(),
                description="Test description",
                cvss=11.0  # Invalid: > 10
            )
    
    def test_short_description(self):
        """Test description length validation"""
        with pytest.raises(ValidationError):
            CVEInput(
                cve_id="CVE-2024-1234",
                published=datetime.now(),
                modified=datetime.now(),
                description="Short"  # Too short
            )
    
    def test_reserved_description(self):
        """Test placeholder description rejection"""
        with pytest.raises(ValidationError) as exc_info:
            CVEInput(
                cve_id="CVE-2024-1234",
                published=datetime.now(),
                modified=datetime.now(),
                description="** RESERVED ** This CVE has been reserved"
            )
        assert "placeholder text" in str(exc_info.value)


class TestEPSSScore:
    """Tests for EPSSScore schema"""
    
    def test_valid_epss_score(self):
        """Test valid EPSS score"""
        epss = EPSSScore(
            cve_id="CVE-2024-1234",
            epss_score=0.78,
            percentile=0.95,
            date="2024-01-15"
        )
        assert epss.epss_score == 0.78
        assert epss.percentile == 0.95
    
    def test_epss_score_out_of_range(self):
        """Test EPSS score validation"""
        with pytest.raises(ValidationError):
            EPSSScore(
                cve_id="CVE-2024-1234",
                epss_score=1.5,  # Invalid: > 1.0
                percentile=0.95,
                date="2024-01-15"
            )


class TestCVEEnrichment:
    """Tests for CVEEnrichment schema"""
    
    def test_valid_enrichment(self):
        """Test valid CVE enrichment"""
        enrichment = CVEEnrichment(
            cve_id="CVE-2024-1234",
            cvss=9.8,
            kev_flag=True,
            epss_score=0.78,
            is_healthcare=True,
            label=4
        )
        assert enrichment.label == 4
        assert enrichment.kev_flag is True
    
    def test_invalid_label(self):
        """Test label validation"""
        with pytest.raises(ValidationError):
            CVEEnrichment(
                cve_id="CVE-2024-1234",
                label=6  # Invalid: > 5
            )
    
    def test_default_values(self):
        """Test default values"""
        enrichment = CVEEnrichment(
            cve_id="CVE-2024-1234",
            label=2
        )
        assert enrichment.kev_flag is False
        assert enrichment.attack_technique_count == 0


class TestCVERecommendation:
    """Tests for CVERecommendation schema"""
    
    def test_valid_recommendation(self):
        """Test valid recommendation"""
        rec = CVERecommendation(
            cve_id="CVE-2024-1234",
            rank=1,
            score=0.95,
            cvss=9.8,
            epss_score=0.78,
            kev_flag=True,
            is_healthcare=True,
            label=4
        )
        assert rec.rank == 1
        assert rec.score == 0.95
    
    def test_invalid_rank(self):
        """Test rank validation"""
        with pytest.raises(ValidationError):
            CVERecommendation(
                cve_id="CVE-2024-1234",
                rank=0,  # Invalid: < 1
                score=0.95,
                label=4
            )


class TestModelMetrics:
    """Tests for ModelMetrics schema"""
    
    def test_valid_metrics(self):
        """Test valid model metrics"""
        metrics = ModelMetrics(
            model_name="ltr_ranker_pruned",
            version="1.0.0",
            ndcg_10=0.7674,
            precision_100=1.0,
            num_features=14,
            training_samples=226320,
            hyperparameters={"max_depth": 5, "eta": 0.05}
        )
        assert metrics.ndcg_10 == 0.7674
        assert metrics.num_features == 14
    
    def test_invalid_ndcg(self):
        """Test NDCG validation"""
        with pytest.raises(ValidationError):
            ModelMetrics(
                model_name="test",
                version="1.0",
                ndcg_10=1.5,  # Invalid: > 1.0
                num_features=14,
                training_samples=1000
            )


class TestHealthStatus:
    """Tests for HealthStatus schema"""
    
    def test_valid_health_status(self):
        """Test valid health status"""
        status = HealthStatus(
            status="healthy",
            version="1.0.0",
            database_connected=True,
            model_loaded=True,
            total_cves=226320
        )
        assert status.status == "healthy"
        assert status.database_connected is True
    
    def test_default_timestamp(self):
        """Test timestamp auto-generation"""
        status = HealthStatus(
            status="healthy",
            version="1.0.0"
        )
        assert isinstance(status.timestamp, datetime)


class TestRecommendationRequest:
    """Tests for RecommendationRequest schema"""
    
    def test_valid_request(self):
        """Test valid recommendation request"""
        req = RecommendationRequest(
            limit=20,
            healthcare_only=True,
            min_cvss=7.0
        )
        assert req.limit == 20
        assert req.healthcare_only is True
    
    def test_limit_validation(self):
        """Test limit bounds"""
        with pytest.raises(ValidationError):
            RecommendationRequest(limit=0)  # Too low
        
        with pytest.raises(ValidationError):
            RecommendationRequest(limit=2000)  # Too high
    
    def test_default_values(self):
        """Test default request values"""
        req = RecommendationRequest()
        assert req.limit == 20
        assert req.healthcare_only is False
        assert req.kev_only is False
