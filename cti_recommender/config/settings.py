"""
Centralized Configuration Management for CTI Recommender
Uses Pydantic BaseSettings for environment variable management
"""
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file"""
    
    # ============================================================================
    # PROJECT PATHS
    # ============================================================================
    PROJECT_ROOT: Path = Path(__file__).parent.parent
    
    # ============================================================================
    # DATABASE CONFIGURATION
    # ============================================================================
    DATABASE_PATH: Path = Path("data/cve_database.db")
    DATABASE_TIMEOUT: int = 30  # seconds
    DATABASE_CHECK_SAME_THREAD: bool = False  # For multi-threading
    
    # ============================================================================
    # API CONFIGURATION
    # ============================================================================
    # NVD API
    NVD_API_KEY: Optional[str] = None
    NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT_WITH_KEY: float = 0.6  # seconds between requests (50 req/30s)
    NVD_RATE_LIMIT_NO_KEY: float = 6.0    # seconds between requests (5 req/30s)
    NVD_TIMEOUT: int = 30
    
    # EPSS API (FIRST.org)
    EPSS_API_BASE: str = "https://api.first.org/data/v1/epss"
    EPSS_TIMEOUT: int = 30
    EPSS_BATCH_SIZE: int = 100
    EPSS_RATE_LIMIT: float = 1.0  # seconds between requests
    
    # CISA KEV Catalog
    KEV_CATALOG_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    KEV_TIMEOUT: int = 30
    
    # ============================================================================
    # CACHING CONFIGURATION
    # ============================================================================
    CACHE_DIR: Path = Path("cache")
    EPSS_CACHE_DIR: Path = Path("cache/epss")
    EPSS_CACHE_EXPIRY_DAYS: int = 1
    EPSS_PERSISTENT_CACHE: str = "epss_persistent.json"
    
    # ============================================================================
    # MODEL CONFIGURATION
    # ============================================================================
    MODEL_DIR: Path = Path("models")
    MODEL_PATH: Path = Path("models/ltr_ranker.model")
    MODEL_PRUNED_PATH: Path = Path("models/ltr_ranker_pruned.model")
    SCALER_PATH: Path = Path("models/scaler.pkl")
    
    # XGBoost hyperparameters
    XGBOOST_OBJECTIVE: str = "rank:ndcg"
    XGBOOST_ETA: float = 0.05
    XGBOOST_MAX_DEPTH: int = 5
    XGBOOST_MIN_CHILD_WEIGHT: int = 5
    XGBOOST_SUBSAMPLE: float = 0.8
    XGBOOST_COLSAMPLE_BYTREE: float = 0.8
    XGBOOST_ALPHA: float = 0.1  # L1 regularization
    XGBOOST_LAMBDA: float = 2.0  # L2 regularization
    XGBOOST_NUM_BOOST_ROUND: int = 200
    
    # ============================================================================
    # LOGGING CONFIGURATION
    # ============================================================================
    LOG_LEVEL: str = "INFO"
    LOG_DIR: Path = Path("logs")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5
    STRUCTURED_LOGGING: bool = False  # JSON format for production
    
    # ============================================================================
    # FEATURE ENGINEERING
    # ============================================================================
    BASELINE_DATE: str = "2018-01-01"
    RECENT_THRESHOLD_DAYS: int = 2500
    
    # Feature thresholds
    CVSS_CRITICAL_THRESHOLD: float = 9.0
    EPSS_HIGH_THRESHOLD: float = 0.1
    EPSS_VERY_HIGH_THRESHOLD: float = 0.5
    
    # ============================================================================
    # DATA PATHS
    # ============================================================================
    DATA_DIR: Path = Path("data")
    OUTPUTS_DIR: Path = Path("outputs")
    CURATED_DATA_PATH: Path = Path("data/curated_healthcare_breaches.json")
    HEALTHCARE_MAPPING_PATH: Path = Path("data/config/healthcare_mapping.csv")
    
    # ============================================================================
    # VALIDATION & TESTING
    # ============================================================================
    MIN_CVSS_SCORE: float = 0.0
    MAX_CVSS_SCORE: float = 10.0
    MIN_EPSS_SCORE: float = 0.0
    MAX_EPSS_SCORE: float = 1.0
    VALID_LABEL_VALUES: tuple = (0, 1, 2, 3, 4, 5)
    
    # ============================================================================
    # API SERVER (FastAPI)
    # ============================================================================
    API_TITLE: str = "CTI Healthcare Recommender API"
    API_VERSION: str = "1.0.0"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 4
    API_RELOAD: bool = False  # Enable in development
    
    # ============================================================================
    # RETRY & RESILIENCE
    # ============================================================================
    MAX_RETRIES: int = 3
    RETRY_BACKOFF_FACTOR: float = 1.0  # Exponential backoff: 1, 2, 4 seconds
    RETRY_STATUS_CODES: tuple = (429, 500, 502, 503, 504)
    
    # ============================================================================
    # PIPELINE CONFIGURATION
    # ============================================================================
    DEFAULT_FETCH_DAYS: int = 7
    ENRICHMENT_CHECKPOINT_INTERVAL: int = 50  # Save progress every N batches
    
    # ============================================================================
    # MONITORING & OBSERVABILITY
    # ============================================================================
    ENABLE_METRICS: bool = False
    METRICS_PORT: int = 9090
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )
    
    def get_database_path(self) -> Path:
        """Get absolute database path"""
        if self.DATABASE_PATH.is_absolute():
            return self.DATABASE_PATH
        return self.PROJECT_ROOT / self.DATABASE_PATH
    
    def get_cache_dir(self) -> Path:
        """Get absolute cache directory path"""
        if self.CACHE_DIR.is_absolute():
            return self.CACHE_DIR
        return self.PROJECT_ROOT / self.CACHE_DIR
    
    def get_log_dir(self) -> Path:
        """Get absolute log directory path"""
        if self.LOG_DIR.is_absolute():
            return self.LOG_DIR
        return self.PROJECT_ROOT / self.LOG_DIR
    
    def get_model_path(self, pruned: bool = False) -> Path:
        """Get absolute model path"""
        model_path = self.MODEL_PRUNED_PATH if pruned else self.MODEL_PATH
        if model_path.is_absolute():
            return model_path
        return self.PROJECT_ROOT / model_path
    
    def ensure_directories(self):
        """Create all necessary directories"""
        dirs_to_create = [
            self.get_database_path().parent,
            self.get_cache_dir(),
            self.EPSS_CACHE_DIR if self.EPSS_CACHE_DIR.is_absolute() else self.PROJECT_ROOT / self.EPSS_CACHE_DIR,
            self.get_log_dir(),
            self.MODEL_DIR if self.MODEL_DIR.is_absolute() else self.PROJECT_ROOT / self.MODEL_DIR,
            self.OUTPUTS_DIR if self.OUTPUTS_DIR.is_absolute() else self.PROJECT_ROOT / self.OUTPUTS_DIR,
        ]
        
        for directory in dirs_to_create:
            directory.mkdir(parents=True, exist_ok=True)
    
    def get_nvd_rate_limit(self) -> float:
        """Get appropriate NVD API rate limit based on API key availability"""
        return self.NVD_RATE_LIMIT_WITH_KEY if self.NVD_API_KEY else self.NVD_RATE_LIMIT_NO_KEY


# Global settings instance
settings = Settings()

# Ensure all directories exist
settings.ensure_directories()
