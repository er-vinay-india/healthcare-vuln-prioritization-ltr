"""
Pydantic Data Models and Validation Schemas
Ensures data integrity throughout the pipeline
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict
import re


class CVEInput(BaseModel):
    """Validated CVE input data from NVD API"""
    
    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-1234)")
    published: datetime = Field(..., description="Publication date")
    modified: datetime = Field(..., description="Last modification date")
    description: str = Field(..., min_length=10, description="Vulnerability description")
    cvss: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS base score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    cwe: Optional[str] = Field(None, description="CWE identifier")
    raw_json: Optional[str] = Field(None, description="Original JSON from NVD")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2024-1234",
                "published": "2024-01-15T10:30:00",
                "modified": "2024-01-16T14:20:00",
                "description": "Buffer overflow in XYZ application allows remote code execution",
                "cvss": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": "CWE-120"
            }
        }
    )
    
    @field_validator('cve_id')
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        """Validate CVE ID format"""
        pattern = r'^CVE-\d{4}-\d{4,}$'
        if not re.match(pattern, v):
            raise ValueError(f"Invalid CVE ID format: {v}. Expected format: CVE-YYYY-NNNN")
        return v.upper()
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Validate description is not placeholder text"""
        placeholder_patterns = [
            "** RESERVED **",
            "** REJECT **",
            "*** UNSUPPORTED WHEN",
        ]
        for pattern in placeholder_patterns:
            if pattern in v.upper():
                raise ValueError(f"Description contains placeholder text: {pattern}")
        return v


class EPSSScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) score data"""
    
    cve_id: str = Field(..., description="CVE identifier")
    epss_score: float = Field(..., ge=0.0, le=1.0, description="EPSS probability score")
    percentile: float = Field(..., ge=0.0, le=1.0, description="Percentile rank")
    date: str = Field(..., description="Score date (YYYY-MM-DD)")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2024-1234",
                "epss_score": 0.78,
                "percentile": 0.95,
                "date": "2024-01-15"
            }
        }
    )


class CVEEnrichment(BaseModel):
    """Enriched CVE data with all computed features"""
    
    cve_id: str
    
    # Core vulnerability data
    cvss: Optional[float] = Field(None, ge=0.0, le=10.0)
    published: Optional[datetime] = None
    description: Optional[str] = None
    
    # Enrichment flags
    kev_flag: bool = Field(default=False, description="CISA KEV catalog membership")
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS score")
    epss_percentile: Optional[float] = Field(None, ge=0.0, le=1.0)
    is_healthcare: bool = Field(default=False, description="Healthcare sector relevance")
    is_curated: bool = Field(default=False, description="Curated breach dataset membership")
    
    # ATT&CK mapping
    attack_flag: bool = Field(default=False)
    attack_technique_count: int = Field(default=0, ge=0)
    
    # CHPL mapping
    chpl_flag: bool = Field(default=False)
    
    # Multi-level label
    label: int = Field(..., ge=0, le=5, description="Priority label (0=lowest, 5=highest)")
    
    # Metadata
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2024-1234",
                "cvss": 9.8,
                "published": "2024-01-15T10:30:00",
                "kev_flag": True,
                "epss_score": 0.78,
                "is_healthcare": True,
                "label": 4
            }
        }
    )
    
    @field_validator('label')
    @classmethod
    def validate_label(cls, v: int) -> int:
        """Validate label is within valid range"""
        if v not in range(6):
            raise ValueError(f"Label must be 0-5, got: {v}")
        return v


class CVERecommendation(BaseModel):
    """CVE recommendation output from ranking model"""
    
    cve_id: str
    rank: int = Field(..., ge=1, description="Ranking position")
    score: float = Field(..., description="Model prediction score")
    
    # Key features for explainability
    cvss: Optional[float] = Field(None, ge=0.0, le=10.0)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    kev_flag: bool = False
    is_healthcare: bool = False
    label: int = Field(..., ge=0, le=5)
    
    # Additional context
    description: Optional[str] = None
    published: Optional[datetime] = None
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2024-1234",
                "rank": 1,
                "score": 0.95,
                "cvss": 9.8,
                "epss_score": 0.78,
                "kev_flag": True,
                "is_healthcare": True,
                "label": 4,
                "description": "Critical RCE vulnerability",
                "published": "2024-01-15T10:30:00"
            }
        }
    )


class ModelMetrics(BaseModel):
    """Model performance metrics"""
    
    model_name: str = Field(..., description="Model identifier")
    version: str = Field(..., description="Model version")
    
    # Performance metrics
    ndcg_5: Optional[float] = Field(None, ge=0.0, le=1.0, description="NDCG@5")
    ndcg_10: Optional[float] = Field(None, ge=0.0, le=1.0, description="NDCG@10")
    ndcg_20: Optional[float] = Field(None, ge=0.0, le=1.0, description="NDCG@20")
    precision_100: Optional[float] = Field(None, ge=0.0, le=1.0, description="P@100")
    
    # Training metadata
    num_features: int = Field(..., ge=1)
    training_samples: int = Field(..., ge=1)
    training_time_seconds: Optional[float] = Field(None, ge=0.0)
    trained_at: Optional[datetime] = None
    
    # Hyperparameters
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "model_name": "ltr_ranker_pruned",
                "version": "1.0.0",
                "ndcg_10": 0.7674,
                "precision_100": 1.0,
                "num_features": 14,
                "training_samples": 226320,
                "training_time_seconds": 45.2,
                "hyperparameters": {
                    "max_depth": 5,
                    "min_child_weight": 5,
                    "eta": 0.05
                }
            }
        }
    )


class RecommendationRequest(BaseModel):
    """Request for CVE recommendations"""
    
    limit: int = Field(default=20, ge=1, le=1000, description="Number of recommendations")
    healthcare_only: bool = Field(default=False, description="Filter to healthcare-relevant CVEs")
    min_cvss: Optional[float] = Field(None, ge=0.0, le=10.0, description="Minimum CVSS score")
    kev_only: bool = Field(default=False, description="Filter to KEV catalog CVEs")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "limit": 20,
                "healthcare_only": True,
                "min_cvss": 7.0,
                "kev_only": False
            }
        }
    )


class HealthStatus(BaseModel):
    """API health check response"""
    
    status: str = Field(..., description="Service status: healthy, degraded, unhealthy")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Component health
    database_connected: bool = True
    model_loaded: bool = True
    
    # Statistics
    total_cves: Optional[int] = None
    enriched_cves: Optional[int] = None
    last_update: Optional[datetime] = None
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "timestamp": "2024-01-15T10:30:00",
                "database_connected": True,
                "model_loaded": True,
                "total_cves": 226320,
                "enriched_cves": 214316
            }
        }
    )


class BatchEnrichmentRequest(BaseModel):
    """Request for batch CVE enrichment"""
    
    cve_ids: List[str] = Field(..., min_length=1, max_length=1000)
    force_refresh: bool = Field(default=False, description="Force refresh cached data")
    
    @field_validator('cve_ids')
    @classmethod
    def validate_cve_ids(cls, v: List[str]) -> List[str]:
        """Validate all CVE IDs"""
        pattern = r'^CVE-\d{4}-\d{4,}$'
        for cve_id in v:
            if not re.match(pattern, cve_id):
                raise ValueError(f"Invalid CVE ID format: {cve_id}")
        return [cve.upper() for cve in v]


class EnrichmentResult(BaseModel):
    """Result of CVE enrichment operation"""
    
    cve_id: str
    success: bool
    enrichment: Optional[CVEEnrichment] = None
    error: Optional[str] = None
    cached: bool = Field(default=False, description="Result from cache")
