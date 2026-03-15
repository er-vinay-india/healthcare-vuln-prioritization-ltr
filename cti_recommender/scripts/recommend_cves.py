#!/usr/bin/env python3
"""
Healthcare CVE Recommender - Production interface for ranking CVEs by healthcare relevance.
Uses trained LTR model to score and recommend high-priority vulnerabilities.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
import xgboost as xgb
import pickle
from datetime import datetime, timedelta

from src.core.cve_database import CVEDatabase
from src.features.production_features import ProductionFeatureEngineer

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class HealthcareCVERecommender:
    """Recommender system for healthcare CVEs using trained LTR model."""
    
    def __init__(self, model_path=None, metadata_path=None):
        """Initialize recommender with trained model."""
        model_dir = Path(__file__).parent.parent / 'models'
        if model_path is None:
            # Prefer pruned model if present, then fallback to legacy artifact.
            pruned_model = model_dir / 'ltr_ranker_pruned.model'
            legacy_model = model_dir / 'ltr_ranker.model'
            model_path = pruned_model if pruned_model.exists() else legacy_model

        if metadata_path is None:
            pruned_meta = model_dir / 'ltr_metadata_pruned.pkl'
            legacy_meta = model_dir / 'ltr_metadata.pkl'
            if pruned_meta.exists():
                metadata_path = pruned_meta
            elif legacy_meta.exists():
                metadata_path = legacy_meta
        
        # Load model
        self.model = xgb.Booster()
        try:
            self.model.load_model(str(model_path))
        except Exception:
            logger.exception("Failed to load model artifact: %s", model_path)
            raise
        
        # Load metadata
        self.metadata = {}
        if metadata_path is not None and Path(metadata_path).exists():
            try:
                with open(metadata_path, 'rb') as f:
                    self.metadata = pickle.load(f)
            except Exception:
                logger.exception("Failed to load model metadata: %s", metadata_path)
                raise

        model_feature_names = self.model.feature_names or []
        self.feature_names = self.metadata.get('feature_names') or model_feature_names
        self.scaler = self.metadata.get('scaler', None)
        self.production_engineer = ProductionFeatureEngineer()

        if self.metadata.get('training_date'):
            logger.info(f"Loaded model trained on {self.metadata['training_date'][:10]}")
        if self.metadata.get('metrics', {}).get('ndcg_10') is not None:
            logger.info(
                f"Model performance: NDCG@10 = {self.metadata['metrics']['ndcg_10']:.4f}",
                extra={'ndcg_10': self.metadata['metrics']['ndcg_10']}
            )
        if self.scaler is not None:
            logger.info("Feature scaler loaded for inference")
        logger.info(f"Loaded model artifact: {Path(model_path).name}")

    def _prepare_legacy_features(self, df):
        """Build legacy feature set for backward compatibility with old artifacts."""
        def _col(name, default):
            if name in df.columns:
                return df[name]
            return pd.Series(default, index=df.index)

        features = pd.DataFrame({
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

        # Engineered features
        features['cvss_high'] = (features['cvss'] >= 7.0).astype(int)
        features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
        features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
        features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
        features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
        features['chpl_healthcare'] = (features['chpl_flag'] & features['is_healthcare']).astype(int)
        features['attack_healthcare'] = (features['attack_flag'] & features['is_healthcare']).astype(int)
        features['attack_multi'] = (features['attack_technique_count'] > 1).astype(int)
        features['healthcare_x_cvss'] = features['is_healthcare'] * features['cvss']
        features['kev_x_epss'] = features['kev_flag'] * features['epss_score']
        features['chpl_x_attack'] = features['chpl_flag'] * features['attack_flag']
        features['attack_count_x_healthcare'] = features['attack_technique_count'] * features['is_healthcare']

        # Recency
        published_series = df['published_str'] if 'published_str' in df.columns else _col('published', pd.NaT)
        published = pd.to_datetime(published_series, errors='coerce')
        baseline_date = pd.to_datetime('2018-01-01')
        features['days_since_2018'] = (published - baseline_date).dt.days.fillna(0).astype(int)
        features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)

        if self.scaler is not None:
            continuous_cols = [
                'cvss', 'epss_score', 'epss_percentile', 'attack_technique_count',
                'healthcare_x_cvss', 'kev_x_epss', 'attack_count_x_healthcare', 'days_since_2018'
            ]
            scaled_cols = [c for c in continuous_cols if c in features.columns]
            if scaled_cols:
                features[scaled_cols] = self.scaler.transform(features[scaled_cols])

        return features

    def _prepare_production_features(self, df):
        """Build current production features from leakage-free feature engineer."""
        prepared = df.copy()
        if 'published' not in prepared.columns and 'published_str' in prepared.columns:
            prepared['published'] = prepared['published_str']
        if 'published' not in prepared.columns:
            prepared['published'] = pd.Series(pd.NaT, index=prepared.index)
        prepared['published'] = pd.to_datetime(prepared['published'], errors='coerce')

        for col in ['cwe', 'description', 'cvss', 'is_healthcare', 'chpl_flag', 'attack_technique_count']:
            if col not in prepared.columns:
                prepared[col] = np.nan if col in ['cwe', 'description'] else 0

        engineered = self.production_engineer.extract_features(prepared)
        return engineered
    
    def prepare_features(self, df):
        """Extract features from CVE dataframe using model-driven schema selection."""
        production_features = self._prepare_production_features(df)
        legacy_features = self._prepare_legacy_features(df)

        if not self.feature_names:
            # Safe default when model metadata is unavailable.
            self.feature_names = self.production_engineer.get_feature_columns()

        target_features = set(self.feature_names)
        if target_features.issubset(set(production_features.columns)):
            return production_features[self.feature_names].fillna(0)
        if target_features.issubset(set(legacy_features.columns)):
            return legacy_features[self.feature_names].fillna(0)

        missing_from_prod = sorted(target_features - set(production_features.columns))
        missing_from_legacy = sorted(target_features - set(legacy_features.columns))
        raise ValueError(
            "Unable to prepare model features. "
            f"Missing from production features: {missing_from_prod}. "
            f"Missing from legacy features: {missing_from_legacy}."
        )
    
    def recommend(self, df, top_k=50):
        """Recommend top-K CVEs from dataframe."""
        # Prepare features
        X = self.prepare_features(df)
        
        # Predict scores
        dmatrix = xgb.DMatrix(X, feature_names=self.feature_names)
        scores = self.model.predict(dmatrix)
        
        # Add scores to dataframe
        df = df.copy()
        df['model_score'] = scores
        
        # Sort by score (descending) and return top K
        df_ranked = df.sort_values('model_score', ascending=False).head(top_k)
        
        return df_ranked
    
    def recommend_from_db(self, days_back=30, top_k=50, min_cvss=0.0):
        """Recommend recent CVEs from database."""
        db = CVEDatabase()
        
        # Get recent CVEs
        cutoff_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')
        
        query = """
        SELECT 
            e.cve_id,
            e.kev_flag,
            e.epss_score,
            e.epss_percentile,
            e.is_healthcare,
            e.is_curated,
            e.chpl_flag,
            e.attack_flag,
            e.attack_technique_count,
            e.label,
            c.cvss,
            c.cwe,
            CAST(c.published AS TEXT) as published_str,
            c.description
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE c.published >= ?
          AND c.cvss >= ?
        ORDER BY c.published DESC
        """
        
        try:
            df = pd.read_sql_query(query, db.conn, params=[cutoff_date, min_cvss])
        except Exception:
            logger.exception("Failed to load CVEs for recommendation")
            raise
        finally:
            db.close()
        
        if len(df) == 0:
            logger.warning(f"No CVEs found in last {days_back} days with CVSS >= {min_cvss}", 
                         extra={'days_back': days_back, 'min_cvss': min_cvss})
            return pd.DataFrame()
        
        logger.info(f"Analyzing {len(df):,} CVEs from last {days_back} days...", 
                   extra={'cve_count': len(df), 'days_back': days_back})
        
        # Get recommendations
        recommendations = self.recommend(df, top_k=top_k)
        
        return recommendations

def main() -> int:
    """Demo: Recommend recent healthcare CVEs."""
    logger.info("="*70)
    logger.info("HEALTHCARE CVE RECOMMENDER")
    logger.info("="*70)
    
    try:
        # Initialize recommender
        recommender = HealthcareCVERecommender()

        # Get recommendations for last 30 days
        logger.info("Top 20 healthcare CVEs from last 30 days:")
        logger.info("="*70)

        recommendations = recommender.recommend_from_db(days_back=30, top_k=20, min_cvss=7.0)

        if len(recommendations) > 0:
            # Display recommendations
            display_cols = ['cve_id', 'cvss', 'model_score', 'kev_flag', 'is_healthcare', 'label', 'published_str']
            logger.info(f"\n{recommendations[display_cols].to_string(index=False)}")

            # Summary statistics
            logger.info("="*70)
            logger.info("Summary:")
            logger.info(f"  Total analyzed: {len(recommendations):,}", extra={'total': len(recommendations)})
            logger.info(f"  Healthcare CVEs: {recommendations['is_healthcare'].sum()}", extra={'healthcare_count': int(recommendations['is_healthcare'].sum())})
            logger.info(f"  KEV-flagged: {recommendations['kev_flag'].sum()}", extra={'kev_count': int(recommendations['kev_flag'].sum())})
            logger.info(f"  Avg CVSS: {recommendations['cvss'].mean():.1f}", extra={'avg_cvss': recommendations['cvss'].mean()})
            logger.info(f"  Avg Model Score: {recommendations['model_score'].mean():.2f}", extra={'avg_score': recommendations['model_score'].mean()})

        logger.info("="*70)
        return 0
    except Exception:
        logger.exception("Healthcare CVE recommendation run failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
