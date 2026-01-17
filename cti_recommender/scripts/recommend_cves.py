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
        if model_path is None:
            model_dir = Path(__file__).parent.parent / 'models'
            model_path = model_dir / 'ltr_ranker.model'
            metadata_path = model_dir / 'ltr_metadata.pkl'
        
        # Load model
        self.model = xgb.Booster()
        self.model.load_model(str(model_path))
        
        # Load metadata
        with open(metadata_path, 'rb') as f:
            self.metadata = pickle.load(f)
        
        self.feature_names = self.metadata['feature_names']
        self.scaler = self.metadata.get('scaler', None)
        
        logger.info(f"Loaded model trained on {self.metadata['training_date'][:10]}")
        logger.info(f"Model performance: NDCG@10 = {self.metadata['metrics']['ndcg_10']:.4f}", 
                   extra={'ndcg_10': self.metadata['metrics']['ndcg_10']})
        if self.scaler is not None:
            logger.info("Feature scaler loaded for inference")
        else:
            logger.warning("⚠️  Warning: No scaler found in metadata (old model?)")
    
    def prepare_features(self, df):
        """Extract features from CVE dataframe (same as training)."""
        features = pd.DataFrame({
            'kev_flag': df['kev_flag'],
            'epss_score': df['epss_score'].fillna(0.0),
            'epss_percentile': df['epss_percentile'].fillna(0.0),
            'is_healthcare': df['is_healthcare'],
            'is_curated': df['is_curated'],
            'chpl_flag': df['chpl_flag'].fillna(0).astype(int),
            'attack_flag': df['attack_flag'].fillna(0).astype(int),
            'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
            'cvss': df['cvss'].fillna(0.0),
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
        if 'published_str' in df.columns:
            df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
            baseline_date = pd.to_datetime('2018-01-01')
            features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
            features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
        else:
            features['days_since_2018'] = 0
            features['is_recent'] = 0
        
        # Apply same scaling as training
        if self.scaler is not None:
            continuous_cols = ['cvss', 'epss_score', 'epss_percentile', 'attack_technique_count',
                             'healthcare_x_cvss', 'kev_x_epss', 'attack_count_x_healthcare', 'days_since_2018']
            features[continuous_cols] = self.scaler.transform(features[continuous_cols])
        
        return features[self.feature_names]
    
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
            CAST(c.published AS TEXT) as published_str,
            c.description
        FROM enrichments e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE c.published >= ?
          AND c.cvss >= ?
        ORDER BY c.published DESC
        """
        
        df = pd.read_sql_query(query, db.conn, params=[cutoff_date, min_cvss])
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

def main():
    """Demo: Recommend recent healthcare CVEs."""
    logger.info("="*70)
    logger.info("HEALTHCARE CVE RECOMMENDER")
    logger.info("="*70)
    
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

if __name__ == "__main__":
    main()
