"""
Bootstrap Ensemble Model for Uncertainty-aware Ranking

Uses query-level bootstrapping with LambdaRank for risk-aware CVE prioritization.
"""
import numpy as np
import pandas as pd
import lightgbm as lgb
from typing import List, Tuple, Dict, Callable


class BootstrapEnsemble:
    """Bootstrap ensemble of LambdaRank models."""
    
    def __init__(self, K: int = 5, seed: int = 42):
        self.K = K
        self.seed = seed
        self.models: List[lgb.Booster] = []
        self.best_lambda = 0.25
    
    def train(self, train_df: pd.DataFrame, feature_cols: List[str],
              prepare_ranking_data: Callable, verbose: bool = True) -> Dict[str, float]:
        """Train K bootstrapped LambdaRank models."""
        
        self.models = []
        groups = train_df['published_week'].unique()
        
        for k in range(self.K):
            np.random.seed(self.seed + k)
            sampled_groups = np.random.choice(groups, size=len(groups), replace=True)
            bootstrap_df = pd.concat([train_df[train_df['published_week'] == g] for g in sampled_groups])
            
            X, y, w, g, _ = prepare_ranking_data(bootstrap_df, feature_cols)
            ds = lgb.Dataset(X, label=y, weight=w, group=g)
            
            params = {
                'objective': 'lambdarank',
                'metric': 'ndcg',
                'ndcg_eval_at': [10],
                'num_leaves': 15,
                'learning_rate': 0.1,
                'verbose': -1,
                'seed': self.seed + k
            }
            
            model = lgb.train(params, ds, num_boost_round=30)
            self.models.append(model)
            
            if verbose:
                print(f"  Model {k+1}/{self.K} trained", flush=True)
        
        return {'num_models': len(self.models)}
    
    def predict(self, df: pd.DataFrame, feature_cols: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """Get predictions with uncertainty."""
        X = df[feature_cols].values
        
        all_preds = []
        for model in self.models:
            pred = model.predict(X)
            all_preds.append(pred)
        
        all_preds = np.array(all_preds)
        mean_scores = all_preds.mean(axis=0)
        std_scores = all_preds.std(axis=0)
        
        return mean_scores, std_scores
    
    def predict_risk_aware(self, df: pd.DataFrame, feature_cols: List[str],
                           lambda_val: float = None) -> np.ndarray:
        """Get risk-averse predictions: mean - lambda * std."""
        if lambda_val is None:
            lambda_val = self.best_lambda
        
        mean_scores, std_scores = self.predict(df, feature_cols)
        return mean_scores - lambda_val * std_scores
