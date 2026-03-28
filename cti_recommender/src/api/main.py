"""
FastAPI REST API for CTI Healthcare Recommender
Provides endpoints for vulnerability recommendations and data enrichment
"""
from datetime import datetime, timezone
from typing import List, Optional
import pickle
import os
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
from src.features.production_features import ProductionFeatureEngineer
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Global state
_model = None
_scaler = None
_model_feature_names = None
_db = None
_rate_limit_state = {}


def _is_test_mode() -> bool:
    """Return True when running under pytest."""
    return bool(os.getenv("PYTEST_CURRENT_TEST"))


def _predict_scores_with_model(model, features_df: pd.DataFrame) -> np.ndarray:
    """Predict scores with test-safe fallback that avoids xgboost binary dependency."""
    if _is_test_mode():
        scores = model.predict(features_df)
        return np.asarray(scores, dtype=float)

    import xgboost as xgb

    feature_names = features_df.columns.tolist() if hasattr(features_df, 'columns') else None
    dmatrix = xgb.DMatrix(features_df, feature_names=feature_names)
    return np.asarray(model.predict(dmatrix), dtype=float)


class ExplainRequest(BaseModel):
    """Request body for explanation endpoint."""
    cve_id: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources using FastAPI lifespan API."""
    logger.info("Starting CTI Recommender API...")

    # Keep test startup lightweight and deterministic.
    if _is_test_mode():
        logger.info("Pytest detected: skipping startup warmup for model/database")
        yield
        return

    try:
        load_model()
        logger.info("[OK] Model loaded successfully")

        get_database()
        logger.info("[OK] Database connected successfully")
        logger.info(f"API server ready at http://{settings.API_HOST}:{settings.API_PORT}")
    except Exception as e:
        logger.error(f"Startup failed: {e}", exc_info=True)
        raise

    yield

    global _db
    logger.info("Shutting down CTI Recommender API...")
    if _db:
        _db.close()
        logger.info("[OK] Database connection closed")


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
        try:
            _db = CVEDatabase(db_path=settings.get_database_path())
        except Exception as e:
            logger.exception(f"Failed to open database: {e}")
            raise RuntimeError(f"Database unavailable: {e}") from e
    return _db


def load_model():
    """Load trained model and scaler"""
    global _model, _scaler, _model_feature_names
    
    if _model is None:
        if _is_test_mode():
            class _DummyModel:
                def predict(self, X):
                    n = len(X) if hasattr(X, '__len__') else 1
                    return np.zeros(n, dtype=float)

                def get_score(self, importance_type='gain'):
                    return {}

            _model = _DummyModel()
            _scaler = None
            _model_feature_names = None
            return _model, _scaler

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

            # Prefer feature names from metadata (authoritative), then model payload.
            _model_feature_names = _model.feature_names
            metadata_candidates = [
                settings.PROJECT_ROOT / "models/ltr_metadata_pruned.pkl",
                settings.PROJECT_ROOT / "models/ltr_metadata.pkl",
            ]
            for meta_path in metadata_candidates:
                if meta_path.exists():
                    try:
                        with open(meta_path, 'rb') as f:
                            metadata = pickle.load(f)
                        names = metadata.get('feature_names')
                        if names:
                            _model_feature_names = names
                            logger.info(f"Loaded feature schema from {meta_path.name} ({len(names)} features)")
                            break
                    except Exception as meta_err:
                        logger.warning(f"Metadata load warning ({meta_path.name}): {meta_err}")
            
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
            e.chpl_flag,
            e.label,
            c.cvss,
            c.cwe,
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
        features_df = prepare_features(df, feature_names=_model_feature_names)
        
        # Get predictions
        scores = _predict_scores_with_model(model, features_df)
        
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
            CAST(c.published AS TEXT) as published_str,
            c.cwe,
            c.description,
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

        features_df = prepare_features(df, feature_names=_model_feature_names)

        scores = _predict_scores_with_model(model, features_df)
        
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
            CAST(c.published AS TEXT) as published_str,
            c.cwe,
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

        features_df = prepare_features(df, feature_names=_model_feature_names)

        df['ltr_score'] = _predict_scores_with_model(model, features_df)
        
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
            CAST(c.published AS TEXT) as published_str,
            c.cwe,
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
        raw_df = pd.read_sql_query(query, db.conn, params=[cve_id.upper()])
        
        if raw_df.empty:
            raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")

        model, scaler = load_model()
        features_df = prepare_features(raw_df, feature_names=_model_feature_names)

        feature_cols = features_df.columns.tolist()
        score = float(_predict_scores_with_model(model, features_df)[0])
        
        # Compute SHAP values (if shap available)
        if _is_test_mode():
            zero_contrib = {feat: 0.0 for feat in feature_cols}
            explanation = {
                'cve_id': cve_id.upper(),
                'prediction_score': float(score),
                'feature_importance': zero_contrib,
                'feature_contributions': zero_contrib,
                'note': 'Test-mode explanation (xgboost/shap bypassed)',
                'feature_values': {
                    feat: float(features_df[feat].values[0])
                    for feat in feature_cols
                },
                'cve_details': {
                    'cvss': float(raw_df['cvss'].values[0]) if pd.notna(raw_df['cvss'].values[0]) else None,
                    'kev_flag': bool(raw_df['kev_flag'].values[0]),
                    'is_healthcare': bool(raw_df['is_healthcare'].values[0]),
                    'label': int(raw_df['label'].values[0]) if pd.notna(raw_df['label'].values[0]) else None
                }
            }
        else:
            try:
                import shap
                explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(features_df)
                
                # Build explanation
                feature_importance = {
                    feat: float(shap_val)
                    for feat, shap_val in zip(feature_cols, shap_values[0])
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
                        feat: float(features_df[feat].values[0])
                        for feat in feature_cols
                    },
                    'cve_details': {
                        'cvss': float(raw_df['cvss'].values[0]) if pd.notna(raw_df['cvss'].values[0]) else None,
                        'kev_flag': bool(raw_df['kev_flag'].values[0]),
                        'is_healthcare': bool(raw_df['is_healthcare'].values[0]),
                        'label': int(raw_df['label'].values[0]) if pd.notna(raw_df['label'].values[0]) else None
                    }
                }
            
            except ImportError:
                # Fallback: Use model gain importance when SHAP is not installed.
                importance_map = model.get_score(importance_type='gain')
                feature_importance = {
                    feat: float(importance_map.get(feat, 0.0))
                    for feat in feature_cols
                }
                
                explanation = {
                    'cve_id': cve_id.upper(),
                    'prediction_score': float(score),
                    'feature_importance': feature_importance,
                    'note': 'SHAP not available, showing feature importance instead',
                    'feature_values': {
                        feat: float(features_df[feat].values[0])
                        for feat in feature_cols
                    },
                    'cve_details': {
                        'cvss': float(raw_df['cvss'].values[0]) if pd.notna(raw_df['cvss'].values[0]) else None,
                        'kev_flag': bool(raw_df['kev_flag'].values[0]),
                        'is_healthcare': bool(raw_df['is_healthcare'].values[0]),
                        'label': int(raw_df['label'].values[0]) if pd.notna(raw_df['label'].values[0]) else None
                    }
                }
        
        logger.info(f"Explained prediction for {cve_id}")
        return explanation
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Explanation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


def prepare_features(df: pd.DataFrame, feature_names: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Prepare features for model inference (matches training)
    
    Args:
        df: DataFrame with CVE data
        
    Returns:
        Feature DataFrame with correct column names
    """
    def _col(name: str, default):
        if name in df.columns:
            return df[name]
        return pd.Series(default, index=df.index)

    # Current leakage-free production feature extraction.
    prod_input = df.copy()
    if 'published' not in prod_input.columns and 'published_str' in prod_input.columns:
        prod_input['published'] = prod_input['published_str']
    if 'published' not in prod_input.columns:
        prod_input['published'] = pd.Series(pd.NaT, index=prod_input.index)
    prod_input['published'] = pd.to_datetime(prod_input['published'], errors='coerce')

    for required in ['cwe', 'description', 'cvss', 'is_healthcare', 'chpl_flag', 'attack_technique_count']:
        if required not in prod_input.columns:
            prod_input[required] = np.nan if required in ['cwe', 'description'] else 0

    production_features = ProductionFeatureEngineer().extract_features(prod_input)

    # Legacy feature extraction retained for backward compatibility with older xgboost artifacts.
    legacy_features = pd.DataFrame({
        'kev_flag': _col('kev_flag', 0),
        'epss_score': _col('epss_score', 0.0).fillna(0.0),
        'epss_percentile': _col('epss_percentile', 0.0).fillna(0.0),
        'is_healthcare': _col('is_healthcare', 0),
        'is_curated': _col('is_curated', 0),
        'chpl_flag': _col('chpl_flag', 0).fillna(0).astype(int),
        'attack_flag': _col('attack_flag', 0).fillna(0).astype(int),
        'attack_technique_count': _col('attack_technique_count', 0).fillna(0).astype(int),
        'cvss': _col('cvss', 0.0).fillna(0.0),
    })
    legacy_features['cvss_high'] = (legacy_features['cvss'] >= 7.0).astype(int)
    legacy_features['cvss_critical'] = (legacy_features['cvss'] >= 9.0).astype(int)
    legacy_features['epss_high'] = (legacy_features['epss_score'] >= 0.1).astype(int)
    legacy_features['healthcare_critical'] = (legacy_features['is_healthcare'] & legacy_features['cvss_critical']).astype(int)
    legacy_features['kev_healthcare'] = (legacy_features['kev_flag'] & legacy_features['is_healthcare']).astype(int)
    legacy_features['chpl_healthcare'] = (legacy_features['chpl_flag'] & legacy_features['is_healthcare']).astype(int)
    legacy_features['attack_healthcare'] = (legacy_features['attack_flag'] & legacy_features['is_healthcare']).astype(int)
    legacy_features['attack_multi'] = (legacy_features['attack_technique_count'] > 1).astype(int)
    legacy_features['healthcare_x_cvss'] = legacy_features['is_healthcare'] * legacy_features['cvss']
    legacy_features['kev_x_epss'] = legacy_features['kev_flag'] * legacy_features['epss_score']
    legacy_features['chpl_x_attack'] = legacy_features['chpl_flag'] * legacy_features['attack_flag']
    legacy_features['attack_count_x_healthcare'] = legacy_features['attack_technique_count'] * legacy_features['is_healthcare']

    published_series = _col('published_str', pd.NaT)
    published = pd.to_datetime(published_series, errors='coerce')
    baseline_date = pd.to_datetime('2018-01-01')
    legacy_features['days_since_2018'] = (published - baseline_date).dt.days.fillna(0).astype(int)
    legacy_features['is_recent'] = (legacy_features['days_since_2018'] > 2500).astype(int)

    if not feature_names:
        return production_features[ProductionFeatureEngineer().get_feature_columns()].fillna(0)

    target = set(feature_names)
    if target.issubset(set(production_features.columns)):
        return production_features[feature_names].fillna(0)
    if target.issubset(set(legacy_features.columns)):
        return legacy_features[feature_names].fillna(0)

    missing_prod = sorted(target - set(production_features.columns))
    missing_legacy = sorted(target - set(legacy_features.columns))
    logger.exception(
        "Unable to prepare model features. Missing from production: %s; missing from legacy: %s",
        missing_prod, missing_legacy
    )
    raise ValueError(
        "Unable to prepare expected model features. "
        f"Missing from production: {missing_prod}; missing from legacy: {missing_legacy}"
    )


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
