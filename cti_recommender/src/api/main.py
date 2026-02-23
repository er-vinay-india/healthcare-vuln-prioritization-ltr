"""
FastAPI REST API for CTI Healthcare Recommender
Provides endpoints for vulnerability recommendations and data enrichment
"""
from datetime import datetime, timezone
from typing import List, Optional
import pickle
from pathlib import Path
import sqlite3
from contextlib import asynccontextmanager
import warnings

from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from pydantic import BaseModel

from config import settings
from src.models.schemas import (
    CVERecommendation,
    RecommendationRequest,
    PredictRequest,
    HealthStatus,
    ModelMetrics,
    BatchEnrichmentRequest,
    EnrichmentResult
)
from src.core.cve_database import CVEDatabase
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Global state
_model = None
_scaler = None
_db = None
_rate_limit_state = {}


class ExplainRequest(BaseModel):
    """Request body for explanation endpoint."""
    cve_id: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources using FastAPI lifespan API."""
    logger.info("Starting CTI Recommender API...")

    try:
        load_model()
        logger.info("✓ Model loaded successfully")

        get_database()
        logger.info("✓ Database connected successfully")
        logger.info(f"API server ready at http://{settings.API_HOST}:{settings.API_PORT}")
    except Exception as e:
        logger.error(f"Startup failed: {e}", exc_info=True)
        raise

    yield

    global _db
    logger.info("Shutting down CTI Recommender API...")
    if _db:
        _db.close()
        logger.info("✓ Database connection closed")


# Initialize FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="AI-powered vulnerability prioritization for healthcare organizations",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=".*Unknown file format.*", category=UserWarning)
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
async def health_check():
    """
    Health check endpoint
    Returns service status and statistics
    """
    try:
        db = get_database()
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


def _cors_options_response():
    """Standard OPTIONS response for endpoints when preflight headers are not provided."""
    return JSONResponse(
        status_code=200,
        content={"ok": True},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        },
    )


@app.options("/api/v1/top_cves")
async def options_top_cves():
    return _cors_options_response()


@app.options("/api/v1/predict")
async def options_predict():
    return _cors_options_response()


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


@app.post("/api/v1/predict", response_model=dict)
async def predict_scores(
    request: PredictRequest,
    db: CVEDatabase = Depends(get_database)
):
    """
    Score a list of CVE IDs using the trained LTR model.
    
    Args:
        request: PredictRequest with list of CVE identifiers
        
    Returns:
        Dictionary mapping CVE IDs to scores
    """
    try:
        model, scaler = load_model()
        
        cve_ids = request.cve_ids
        
        # Query CVEs from database
        placeholders = ','.join('?' * len(cve_ids))
        query = f"""
        SELECT 
            e.cve_id,
            c.cvss,
            datetime(c.published) as published,
            e.epss_score,
            e.epss_percentile,
            e.kev_flag,
            e.attack_technique_count,
            e.chpl_flag,
            e.is_healthcare
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE UPPER(e.cve_id) IN ({placeholders})
        """
        
        df = pd.read_sql_query(query, db.conn, params=[cve.upper() for cve in cve_ids])
        
        if df.empty:
            raise HTTPException(status_code=404, detail="No CVEs found")
        
        # Create features using modular function
        from src.features.engineering import create_all_features
        
        FEATURE_COLS = [
            'cvss_norm', 'epss_score', 'epss_percentile', 'kev_flag',
            'days_since_published', 'recency_score', 'attack_technique_count',
            'has_attack', 'chpl_flag', 'is_healthcare',
            'cvss_epss_product', 'kev_healthcare_interaction'
        ]
        
        df = create_all_features(df, FEATURE_COLS)
        
        # Get predictions using LightGBM
        import lightgbm as lgb
        X = df[FEATURE_COLS].values
        
        # Load LightGBM model if not already loaded
        model_path = Path("models/ltr_model_conf_weighted.pkl")
        if model_path.exists():
            with open(model_path, 'rb') as f:
                lgb_model = pickle.load(f)
            scores = lgb_model.predict(X)
        else:
            raise HTTPException(status_code=500, detail="Model not found")
        
        # Build response
        result = {
            cve_id: float(score) 
            for cve_id, score in zip(df['cve_id'].values, scores)
        }
        
        logger.info(f"Scored {len(result)} CVEs")
        return {"predictions": result, "count": len(result)}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Prediction failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/api/v1/top_cves", response_model=dict)
async def get_top_cves(
    limit: int = Query(20, ge=1, le=100, description="Number of top CVEs to return"),
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    date_start: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    date_end: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    healthcare_only: bool = Query(False, description="Only healthcare-relevant CVEs"),
    kev_only: bool = Query(False, description="Only KEV CVEs"),
    min_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="Minimum CVSS score"),
    request: Request = None,
    db: CVEDatabase = Depends(get_database)
):
    """
    Get top-K ranked CVEs with filtering options.
    
    Query params:
        limit: Number of CVEs to return (1-100)
        date_start: Filter CVEs published after this date
        date_end: Filter CVEs published before this date  
        healthcare_only: Only include healthcare-relevant CVEs
        kev_only: Only include KEV CVEs
        min_cvss: Minimum CVSS score threshold
        
    Returns:
        Top-K CVEs with scores and details
    """
    try:
        # Lightweight in-memory rate limiting for this expensive endpoint.
        # Keeps normal usage unaffected while preventing request storms.
        if request is not None and limit < 100:
            client_key = request.client.host if request.client else "unknown"
            now = datetime.now(timezone.utc).timestamp()
            window_seconds = 60
            max_requests = 80

            key = (client_key, "top_cves")
            history = _rate_limit_state.get(key, [])
            history = [ts for ts in history if (now - ts) <= window_seconds]

            if len(history) >= max_requests:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")

            history.append(now)
            _rate_limit_state[key] = history

        model, scaler = load_model()

        # Backward-compatible query param handling
        effective_start = start_date or date_start
        effective_end = end_date or date_end

        # Validate date formats explicitly
        if effective_start:
            try:
                datetime.fromisoformat(effective_start)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_date format. Use YYYY-MM-DD")

        if effective_end:
            try:
                datetime.fromisoformat(effective_end)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_date format. Use YYYY-MM-DD")
        
        # Build query with filters
        query = """
        SELECT 
            e.cve_id,
            c.cvss,
            datetime(c.published) as published,
            c.description,
            e.epss_score,
            e.epss_percentile,
            e.kev_flag,
            e.attack_technique_count,
            e.chpl_flag,
            e.is_healthcare,
            e.label
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE 1=1
        """
        
        params = []
        
        if effective_start:
            query += " AND c.published >= ?"
            params.append(effective_start)
        
        if effective_end:
            query += " AND c.published <= ?"
            params.append(effective_end)
        
        if healthcare_only:
            query += " AND e.is_healthcare = 1"
        
        if kev_only:
            query += " AND e.kev_flag = 1"
        
        if min_cvss is not None:
            query += " AND c.cvss >= ?"
            params.append(min_cvss)
        
        query += " LIMIT ?"
        params.append(min(limit * 10, 10000))  # Get more for ranking
        
        df = pd.read_sql_query(query, db.conn, params=params)
        
        if df.empty:
            raise HTTPException(status_code=404, detail="No CVEs found matching criteria")
        
        # Create features and score
        from src.features.engineering import create_all_features
        
        FEATURE_COLS = [
            'cvss_norm', 'epss_score', 'epss_percentile', 'kev_flag',
            'days_since_published', 'recency_score', 'attack_technique_count',
            'has_attack', 'chpl_flag', 'is_healthcare',
            'cvss_epss_product', 'kev_healthcare_interaction'
        ]
        
        df = create_all_features(df, FEATURE_COLS)
        
        # Get predictions
        model_path = Path("models/ltr_model_conf_weighted.pkl")
        with open(model_path, 'rb') as f:
            lgb_model = pickle.load(f)
        
        X = df[FEATURE_COLS].values
        df['ltr_score'] = lgb_model.predict(X)
        
        # Sort by score and take top K
        top_df = df.nlargest(limit, 'ltr_score')
        
        # Build response
        results = []
        for rank, (_, row) in enumerate(top_df.iterrows(), start=1):
            published_iso = None
            if pd.notna(row['published']):
                published_ts = pd.to_datetime(row['published'], errors='coerce', utc=True)
                if pd.notna(published_ts):
                    published_iso = published_ts.tz_convert(None).isoformat()

            results.append({
                'rank': rank,
                'cve_id': row['cve_id'],
                'score': float(row['ltr_score']),
                'cvss': float(row['cvss']) if pd.notna(row['cvss']) else None,
                'epss_score': float(row['epss_score']) if pd.notna(row['epss_score']) else None,
                'kev_flag': bool(row['kev_flag']),
                'is_healthcare': bool(row['is_healthcare']),
                'label': int(row['label']) if pd.notna(row['label']) else None,
                'published': published_iso,
                'description': row['description'][:200] if pd.notna(row['description']) else None
            })
        
        logger.info(f"Returned top {len(results)} CVEs (filters: healthcare={healthcare_only}, kev={kev_only})")
        
        return {
            'top_cves': results,
            'count': len(results),
            'total_candidates': len(df),
            'filters': {
                'date_start': effective_start,
                'date_end': effective_end,
                'healthcare_only': healthcare_only,
                'kev_only': kev_only,
                'min_cvss': min_cvss
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Top CVEs retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.post("/api/v1/explain", response_model=dict)
async def explain_prediction(
    request: ExplainRequest,
    db: CVEDatabase = Depends(get_database)
):
    """
    Get SHAP-based explanation for a CVE prediction.
    
    Args:
        cve_id: CVE identifier
        
    Returns:
        Feature contributions and explanations
    """
    try:
        # Query CVE
        query = """
        SELECT 
            e.cve_id,
            c.cvss,
            datetime(c.published) as published,
            c.description,
            e.epss_score,
            e.epss_percentile,
            e.kev_flag,
            e.attack_technique_count,
            e.chpl_flag,
            e.is_healthcare,
            e.label
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE UPPER(e.cve_id) = ?
        """
        
        cve_id = request.cve_id
        df = pd.read_sql_query(query, db.conn, params=[cve_id.upper()])
        
        if df.empty:
            raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")
        
        # Create features
        from src.features.engineering import create_all_features
        
        FEATURE_COLS = [
            'cvss_norm', 'epss_score', 'epss_percentile', 'kev_flag',
            'days_since_published', 'recency_score', 'attack_technique_count',
            'has_attack', 'chpl_flag', 'is_healthcare',
            'cvss_epss_product', 'kev_healthcare_interaction'
        ]
        
        df = create_all_features(df, FEATURE_COLS)
        
        # Get model prediction
        model_path = Path("models/ltr_model_conf_weighted.pkl")
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        X = df[FEATURE_COLS].values
        score = model.predict(X)[0]
        
        # Compute SHAP values (if shap available)
        try:
            import shap
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X)
            
            # Build explanation
            feature_importance = {
                feat: float(shap_val)
                for feat, shap_val in zip(FEATURE_COLS, shap_values[0])
            }
            
            # Sort by absolute importance
            sorted_features = sorted(
                feature_importance.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )
            
            explanation = {
                'cve_id': cve_id.upper(),
                'prediction_score': float(score),
                'feature_contributions': dict(sorted_features),
                'top_3_features': [
                    {'feature': feat, 'contribution': float(val)}
                    for feat, val in sorted_features[:3]
                ],
                'feature_values': {
                    feat: float(df[feat].values[0])
                    for feat in FEATURE_COLS
                },
                'cve_details': {
                    'cvss': float(df['cvss'].values[0]) if pd.notna(df['cvss'].values[0]) else None,
                    'kev_flag': bool(df['kev_flag'].values[0]),
                    'is_healthcare': bool(df['is_healthcare'].values[0]),
                    'label': int(df['label'].values[0]) if pd.notna(df['label'].values[0]) else None
                }
            }
            
        except ImportError:
            # Fallback: Use feature importance from model
            feature_importance = dict(zip(FEATURE_COLS, model.feature_importances_))
            
            explanation = {
                'cve_id': cve_id.upper(),
                'prediction_score': float(score),
                'feature_importance': feature_importance,
                'note': 'SHAP not available, showing feature importance instead',
                'feature_values': {
                    feat: float(df[feat].values[0])
                    for feat in FEATURE_COLS
                },
                'cve_details': {
                    'cvss': float(df['cvss'].values[0]) if pd.notna(df['cvss'].values[0]) else None,
                    'kev_flag': bool(df['kev_flag'].values[0]),
                    'is_healthcare': bool(df['is_healthcare'].values[0]),
                    'label': int(df['label'].values[0]) if pd.notna(df['label'].values[0]) else None
                }
            }
        
        logger.info(f"Explained prediction for {cve_id}")
        return explanation
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Explanation failed: {e}", exc_info=True)
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
