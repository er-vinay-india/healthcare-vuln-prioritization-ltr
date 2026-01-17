"""
FastAPI REST API for CTI Healthcare Recommender
Provides endpoints for vulnerability recommendations and data enrichment
"""
from datetime import datetime
from typing import List, Optional
import pickle
from pathlib import Path
import sqlite3

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

from config import settings
from src.models.schemas import (
    CVERecommendation,
    RecommendationRequest,
    HealthStatus,
    ModelMetrics,
    BatchEnrichmentRequest,
    EnrichmentResult
)
from src.core.cve_database import CVEDatabase
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="AI-powered vulnerability prioritization for healthcare organizations",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
_model = None
_scaler = None
_db = None


def get_database() -> CVEDatabase:
    """Dependency: Get database connection"""
    global _db
    if _db is None:
        _db = CVEDatabase(db_path=settings.get_database_path())
    return _db


def load_model():
    """Load trained model and scaler"""
    global _model, _scaler
    
    if _model is None:
        model_path = settings.get_model_path(pruned=True)
        
        if not model_path.exists():
            logger.error(f"Model not found: {model_path}")
            raise RuntimeError(f"Model file not found: {model_path}")
        
        try:
            import xgboost as xgb
            _model = xgb.Booster()
            _model.load_model(str(model_path))
            logger.info(f"Loaded model from {model_path}")
            
            # Try to load scaler if exists
            scaler_path = settings.PROJECT_ROOT / settings.SCALER_PATH
            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    _scaler = pickle.load(f)
                logger.info(f"Loaded scaler from {scaler_path}")
            else:
                logger.warning("Scaler not found, will use unscaled features")
                
        except Exception as e:
            logger.error(f"Failed to load model: {e}", exc_info=True)
            raise RuntimeError(f"Failed to load model: {e}")
    
    return _model, _scaler


@app.on_event("startup")
async def startup_event():
    """Initialize resources on startup"""
    logger.info("Starting CTI Recommender API...")
    
    try:
        # Load model
        load_model()
        logger.info("✓ Model loaded successfully")
        
        # Connect to database
        db = get_database()
        logger.info("✓ Database connected successfully")
        
        logger.info(f"API server ready at http://{settings.API_HOST}:{settings.API_PORT}")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}", exc_info=True)
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global _db
    logger.info("Shutting down CTI Recommender API...")
    
    if _db:
        _db.close()
        logger.info("✓ Database connection closed")


@app.get("/", response_model=dict)
async def root():
    """Root endpoint"""
    return {
        "service": "CTI Healthcare Recommender API",
        "version": settings.API_VERSION,
        "status": "operational",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthStatus)
async def health_check(db: CVEDatabase = Depends(get_database)):
    """
    Health check endpoint
    Returns service status and statistics
    """
    try:
        # Check database connection
        cursor = db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        total_cves = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE epss_score IS NOT NULL")
        enriched_cves = cursor.fetchone()[0]
        
        cursor.execute("SELECT MAX(updated_at) FROM enrichments")
        last_update = cursor.fetchone()[0]
        
        # Check model
        model_loaded = _model is not None
        
        # Determine overall status
        database_ok = total_cves > 0
        status = "healthy" if (database_ok and model_loaded) else "degraded"
        
        return HealthStatus(
            status=status,
            version=settings.API_VERSION,
            database_connected=database_ok,
            model_loaded=model_loaded,
            total_cves=total_cves,
            enriched_cves=enriched_cves,
            last_update=datetime.fromisoformat(last_update) if last_update else None
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return HealthStatus(
            status="unhealthy",
            version=settings.API_VERSION,
            database_connected=False,
            model_loaded=_model is not None
        )


@app.post("/api/v1/recommendations", response_model=List[CVERecommendation])
async def get_recommendations(
    request: RecommendationRequest,
    db: CVEDatabase = Depends(get_database)
):
    """
    Get top CVE recommendations based on LTR model
    
    Args:
        request: Recommendation request parameters
        
    Returns:
        List of ranked CVE recommendations
    """
    try:
        model, scaler = load_model()
        
        # Build query with filters
        query = """
        SELECT 
            e.cve_id,
            e.kev_flag,
            e.epss_score,
            e.is_healthcare,
            e.is_curated,
            e.attack_technique_count,
            e.label,
            c.cvss,
            CAST(c.published AS TEXT) as published_str,
            c.description
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE c.cvss IS NOT NULL
        """
        
        conditions = []
        params = []
        
        if request.healthcare_only:
            conditions.append("e.is_healthcare = 1")
        
        if request.min_cvss is not None:
            conditions.append("c.cvss >= ?")
            params.append(request.min_cvss)
        
        if request.kev_only:
            conditions.append("e.kev_flag = 1")
        
        if conditions:
            query += " AND " + " AND ".join(conditions)
        
        query += " ORDER BY e.label DESC, c.cvss DESC LIMIT ?"
        params.append(min(request.limit * 5, 5000))  # Get more for ranking
        
        df = pd.read_sql_query(query, db.conn, params=params)
        
        if df.empty:
            raise HTTPException(status_code=404, detail="No CVEs found matching criteria")
        
        # Prepare features (same as training)
        features_df = prepare_features(df)
        
        # Get predictions
        import xgboost as xgb
        dmatrix = xgb.DMatrix(features_df)
        scores = model.predict(dmatrix)
        
        # Sort by score and take top N
        top_indices = np.argsort(scores)[::-1][:request.limit]
        
        # Build recommendations
        recommendations = []
        for rank, idx in enumerate(top_indices, start=1):
            row = df.iloc[idx]
            recommendations.append(CVERecommendation(
                cve_id=row['cve_id'],
                rank=rank,
                score=float(scores[idx]),
                cvss=float(row['cvss']) if pd.notna(row['cvss']) else None,
                epss_score=float(row['epss_score']) if pd.notna(row['epss_score']) else None,
                kev_flag=bool(row['kev_flag']),
                is_healthcare=bool(row['is_healthcare']),
                label=int(row['label']),
                description=row['description'][:200] if pd.notna(row['description']) else None,
                published=datetime.fromisoformat(row['published_str']) if pd.notna(row['published_str']) else None
            ))
        
        logger.info(f"Generated {len(recommendations)} recommendations", extra={
            "healthcare_only": request.healthcare_only,
            "min_cvss": request.min_cvss,
            "total_candidates": len(df)
        })
        
        return recommendations
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Recommendation generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/api/v1/cve/{cve_id}", response_model=dict)
async def get_cve_details(cve_id: str, db: CVEDatabase = Depends(get_database)):
    """
    Get detailed information for a specific CVE
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
        
    Returns:
        CVE details with enrichment data
    """
    try:
        query = """
        SELECT 
            c.cve_id,
            CAST(c.published AS TEXT) as published,
            CAST(c.modified AS TEXT) as modified,
            c.description,
            c.cvss,
            c.cvss_vector,
            c.cwe,
            e.kev_flag,
            e.epss_score,
            e.epss_percentile,
            e.is_healthcare,
            e.is_curated,
            e.attack_technique_count,
            e.label
        FROM cves c
        LEFT JOIN enrichments e ON c.cve_id = e.cve_id
        WHERE c.cve_id = ?
        """
        
        # Use row_factory for dict results
        db.conn.row_factory = sqlite3.Row
        cursor = db.conn.cursor()
        cursor.execute(query, (cve_id.upper(),))
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")
        
        # Convert Row to dict
        result = {key: row[key] for key in row.keys()}
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CVE lookup failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/api/v1/stats", response_model=dict)
async def get_statistics(db: CVEDatabase = Depends(get_database)):
    """
    Get database statistics
    
    Returns:
        Statistics about CVE database
    """
    try:
        stats = {}
        cursor = db.conn.cursor()
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cves")
        stats['total_cves'] = cursor.fetchone()[0]
        
        # Enrichment stats
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE epss_score IS NOT NULL")
        stats['epss_coverage'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE kev_flag = 1")
        stats['kev_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1")
        stats['healthcare_count'] = cursor.fetchone()[0]
        
        # Label distribution
        cursor.execute("""
            SELECT label, COUNT(*) as count 
            FROM enrichments 
            GROUP BY label 
            ORDER BY label DESC
        """)
        stats['label_distribution'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # CVSS stats
        cursor.execute("""
            SELECT 
                AVG(cvss) as avg_cvss,
                MIN(cvss) as min_cvss,
                MAX(cvss) as max_cvss
            FROM cves
            WHERE cvss IS NOT NULL
        """)
        row = cursor.fetchone()
        stats['cvss_stats'] = {
            'average': round(row[0], 2) if row[0] else None,
            'min': row[1],
            'max': row[2]
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Statistics retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Prepare features for model inference (matches training)
    
    Args:
        df: DataFrame with CVE data
        
    Returns:
        Feature DataFrame with correct column names
    """
    features = pd.DataFrame({
        'kev_flag': df['kev_flag'],
        'epss_score': df['epss_score'].fillna(0.0),
        'is_healthcare': df['is_healthcare'],
        'is_curated': df['is_curated'],
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
        'cvss': df['cvss'].fillna(0.0),
    })
    
    # Engineered features
    features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
    features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
    features['attack_multi'] = (features['attack_technique_count'] > 1).astype(int)
    features['attack_count_x_healthcare'] = features['attack_technique_count'] * features['is_healthcare']
    
    # Recency features
    df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
    
    return features


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=settings.API_WORKERS,
        reload=settings.API_RELOAD,
        log_level=settings.LOG_LEVEL.lower()
    )
