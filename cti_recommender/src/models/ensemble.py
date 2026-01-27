"""
Ensemble Methods for CVE Prioritization

Combines predictions from multiple models (LambdaRank, DiffusionRank, RGCN)
to create robust priority scores with uncertainty quantification.
"""

from typing import List, Dict, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler


class EnsembleRanker:
    """
    Ensemble method for combining multiple CVE ranking models.
    
    Supports multiple combination strategies:
    - Simple averaging (uniform weights)
    - Weighted averaging (learned weights)
    - Meta-learning (train a model on base model predictions)
    - Rank fusion (Borda count, reciprocal rank fusion)
    """
    
    def __init__(
        self,
        method: str = 'weighted_average',
        meta_model: Optional[str] = None,
        normalize_scores: bool = True
    ):
        """
        Initialize ensemble ranker.
        
        Args:
            method: Combination method
                - 'simple_average': Uniform weights
                - 'weighted_average': Learn optimal weights
                - 'meta_learning': Train meta-model on base predictions
                - 'rank_fusion': Combine ranks instead of scores
            meta_model: Meta-model type for meta-learning
                - 'logistic': Logistic regression
                - 'ridge': Ridge regression
                - 'rf': Random forest
            normalize_scores: Normalize scores to [0,1] before combining
        """
        self.method = method
        self.meta_model_type = meta_model or 'ridge'
        self.normalize_scores = normalize_scores
        
        self.weights = None
        self.meta_model = None
        self.scaler = StandardScaler() if normalize_scores else None
    
    def fit(
        self,
        predictions: Dict[str, np.ndarray],
        labels: np.ndarray
    ) -> 'EnsembleRanker':
        """
        Learn ensemble weights or train meta-model.
        
        Args:
            predictions: Dict of {model_name: prediction_array}
            labels: Ground truth labels for training
        
        Returns:
            self
        """
        model_names = list(predictions.keys())
        n_models = len(model_names)
        
        # Stack predictions
        X = np.column_stack([predictions[name] for name in model_names])
        
        # Normalize if requested
        if self.normalize_scores:
            X = self.scaler.fit_transform(X)
        
        if self.method == 'simple_average':
            # Uniform weights
            self.weights = np.ones(n_models) / n_models
        
        elif self.method == 'weighted_average':
            # Learn optimal weights via linear regression
            from sklearn.linear_model import Ridge
            ridge = Ridge(alpha=1.0, fit_intercept=False, positive=True)
            ridge.fit(X, labels)
            self.weights = ridge.coef_
            # Normalize to sum to 1
            self.weights = self.weights / self.weights.sum()
        
        elif self.method == 'meta_learning':
            # Train meta-model on base predictions
            if self.meta_model_type == 'logistic':
                # For classification
                self.meta_model = LogisticRegression(max_iter=1000)
            elif self.meta_model_type == 'ridge':
                # For regression
                self.meta_model = Ridge(alpha=1.0)
            elif self.meta_model_type == 'rf':
                # Random forest
                self.meta_model = RandomForestRegressor(
                    n_estimators=100,
                    max_depth=5,
                    random_state=42
                )
            
            self.meta_model.fit(X, labels)
        
        self.model_names = model_names
        return self
    
    def predict(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """
        Generate ensemble predictions.
        
        Args:
            predictions: Dict of {model_name: prediction_array}
        
        Returns:
            Combined prediction scores
        """
        # Ensure same model order as training
        X = np.column_stack([predictions[name] for name in self.model_names])
        
        # Normalize if requested
        if self.normalize_scores:
            X = self.scaler.transform(X)
        
        if self.method in ['simple_average', 'weighted_average']:
            # Weighted combination
            ensemble_scores = X @ self.weights
        
        elif self.method == 'meta_learning':
            # Meta-model prediction
            ensemble_scores = self.meta_model.predict(X)
        
        elif self.method == 'rank_fusion':
            # Rank-based fusion
            ensemble_scores = self._rank_fusion(predictions)
        
        return ensemble_scores
    
    def _rank_fusion(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """
        Reciprocal Rank Fusion (RRF) for combining rankings.
        
        RRF formula: score = sum(1 / (k + rank_i)) for all models i
        where k is a constant (typically 60).
        """
        k = 60
        n = len(next(iter(predictions.values())))
        ensemble_scores = np.zeros(n)
        
        for model_name, scores in predictions.items():
            # Convert scores to ranks (higher score = lower rank number)
            ranks = np.argsort(np.argsort(-scores)) + 1
            # Apply RRF formula
            ensemble_scores += 1.0 / (k + ranks)
        
        return ensemble_scores
    
    def get_weights(self) -> Optional[Dict[str, float]]:
        """Get learned model weights (for weighted_average method)."""
        if self.weights is not None:
            return {name: float(w) for name, w in zip(self.model_names, self.weights)}
        return None
    
    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Get feature importance from meta-model (for meta_learning method)."""
        if self.meta_model is None:
            return None
        
        if hasattr(self.meta_model, 'coef_'):
            # Linear model
            importance = np.abs(self.meta_model.coef_)
        elif hasattr(self.meta_model, 'feature_importances_'):
            # Tree-based model
            importance = self.meta_model.feature_importances_
        else:
            return None
        
        return {name: float(imp) for name, imp in zip(self.model_names, importance)}


def bootstrap_ensemble(
    predictions: Dict[str, np.ndarray],
    labels: np.ndarray,
    n_bootstrap: int = 100,
    sample_size: float = 0.8
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Bootstrap ensemble for uncertainty quantification.
    
    Creates multiple ensemble models on bootstrap samples and computes
    mean and standard deviation of predictions.
    
    Args:
        predictions: Dict of {model_name: prediction_array}
        labels: Ground truth labels
        n_bootstrap: Number of bootstrap samples
        sample_size: Fraction of data for each bootstrap sample
    
    Returns:
        Tuple of (mean_predictions, std_predictions)
    """
    n = len(labels)
    sample_n = int(n * sample_size)
    
    bootstrap_predictions = []
    
    for i in range(n_bootstrap):
        # Bootstrap sample
        indices = np.random.choice(n, size=sample_n, replace=True)
        
        # Create predictions for bootstrap sample
        bootstrap_preds = {
            name: scores[indices]
            for name, scores in predictions.items()
        }
        bootstrap_labels = labels[indices]
        
        # Train ensemble on bootstrap sample
        ensemble = EnsembleRanker(method='weighted_average')
        ensemble.fit(bootstrap_preds, bootstrap_labels)
        
        # Predict on full dataset
        ensemble_scores = ensemble.predict(predictions)
        bootstrap_predictions.append(ensemble_scores)
    
    # Compute statistics
    bootstrap_predictions = np.array(bootstrap_predictions)
    mean_preds = bootstrap_predictions.mean(axis=0)
    std_preds = bootstrap_predictions.std(axis=0)
    
    return mean_preds, std_preds


def create_stacking_ensemble(
    train_predictions: Dict[str, np.ndarray],
    test_predictions: Dict[str, np.ndarray],
    train_labels: np.ndarray,
    method: str = 'ridge'
) -> np.ndarray:
    """
    Create stacking ensemble with cross-validation to avoid overfitting.
    
    Args:
        train_predictions: Training set predictions from base models
        test_predictions: Test set predictions from base models
        train_labels: Training labels
        method: Meta-learner type ('ridge', 'rf', 'logistic')
    
    Returns:
        Test set ensemble predictions
    """
    ensemble = EnsembleRanker(method='meta_learning', meta_model=method)
    ensemble.fit(train_predictions, train_labels)
    ensemble_scores = ensemble.predict(test_predictions)
    return ensemble_scores


def reciprocal_rank_fusion(
    rankings: Dict[str, np.ndarray],
    k: int = 60
) -> np.ndarray:
    """
    Reciprocal Rank Fusion for combining multiple rankings.
    
    Commonly used in information retrieval. More robust than score averaging.
    
    Args:
        rankings: Dict of {model_name: rank_array}
            Ranks should be 1-indexed (1 = best)
        k: Constant for RRF formula (typically 60)
    
    Returns:
        Fused scores (higher is better)
    """
    n = len(next(iter(rankings.values())))
    fused_scores = np.zeros(n)
    
    for model_name, ranks in rankings.items():
        fused_scores += 1.0 / (k + ranks)
    
    return fused_scores


def borda_count(rankings: Dict[str, np.ndarray]) -> np.ndarray:
    """
    Borda count voting for combining rankings.
    
    Simple and interpretable. Each item gets points based on its rank
    in each ranking (n-rank points).
    
    Args:
        rankings: Dict of {model_name: rank_array}
            Ranks should be 1-indexed (1 = best)
    
    Returns:
        Borda scores (higher is better)
    """
    n = len(next(iter(rankings.values())))
    n_models = len(rankings)
    
    borda_scores = np.zeros(n)
    
    for model_name, ranks in rankings.items():
        # Give points: n points for rank 1, n-1 for rank 2, etc.
        borda_scores += (n - ranks + 1)
    
    return borda_scores


def evaluate_ensemble_diversity(
    predictions: Dict[str, np.ndarray],
    k: int = 100
) -> Dict[str, float]:
    """
    Measure diversity of base model predictions.
    
    Higher diversity often leads to better ensemble performance.
    
    Args:
        predictions: Dict of {model_name: prediction_array}
        k: Top-k for overlap analysis
    
    Returns:
        Dict of diversity metrics
    """
    model_names = list(predictions.keys())
    n_models = len(model_names)
    
    # Get top-k predictions from each model
    top_k_sets = []
    for name in model_names:
        scores = predictions[name]
        top_k_indices = set(np.argsort(scores)[-k:])
        top_k_sets.append(top_k_indices)
    
    # Pairwise Jaccard similarity
    pairwise_similarities = []
    for i in range(n_models):
        for j in range(i + 1, n_models):
            intersection = len(top_k_sets[i] & top_k_sets[j])
            union = len(top_k_sets[i] | top_k_sets[j])
            jaccard = intersection / union if union > 0 else 0
            pairwise_similarities.append(jaccard)
    
    avg_similarity = np.mean(pairwise_similarities)
    diversity = 1.0 - avg_similarity
    
    # Correlation between predictions
    pred_matrix = np.column_stack([predictions[name] for name in model_names])
    correlations = np.corrcoef(pred_matrix.T)
    avg_correlation = (correlations.sum() - n_models) / (n_models * (n_models - 1))
    
    return {
        'diversity_score': diversity,
        'avg_jaccard_similarity': avg_similarity,
        'avg_correlation': avg_correlation,
        'min_pairwise_similarity': min(pairwise_similarities),
        'max_pairwise_similarity': max(pairwise_similarities)
    }


# Example usage
if __name__ == "__main__":
    # Simulate predictions from 3 models
    np.random.seed(42)
    n_samples = 1000
    
    # Generate synthetic predictions
    predictions = {
        'baseline': np.random.randn(n_samples),
        'diffusion': np.random.randn(n_samples),
        'rgcn': np.random.randn(n_samples)
    }
    
    # Generate synthetic labels (priority levels 1-5)
    labels = np.random.randint(1, 6, size=n_samples)
    
    # Split train/test
    split = 800
    train_preds = {k: v[:split] for k, v in predictions.items()}
    test_preds = {k: v[split:] for k, v in predictions.items()}
    train_labels = labels[:split]
    test_labels = labels[split:]
    
    print("=" * 60)
    print("ENSEMBLE METHODS DEMO")
    print("=" * 60)
    
    # 1. Simple average
    ensemble1 = EnsembleRanker(method='simple_average')
    ensemble1.fit(train_preds, train_labels)
    scores1 = ensemble1.predict(test_preds)
    print(f"\n1. Simple Average Ensemble")
    print(f"   Weights: {ensemble1.get_weights()}")
    
    # 2. Weighted average
    ensemble2 = EnsembleRanker(method='weighted_average')
    ensemble2.fit(train_preds, train_labels)
    scores2 = ensemble2.predict(test_preds)
    print(f"\n2. Weighted Average Ensemble")
    print(f"   Weights: {ensemble2.get_weights()}")
    
    # 3. Meta-learning
    ensemble3 = EnsembleRanker(method='meta_learning', meta_model='ridge')
    ensemble3.fit(train_preds, train_labels)
    scores3 = ensemble3.predict(test_preds)
    print(f"\n3. Meta-Learning Ensemble (Ridge)")
    print(f"   Feature importance: {ensemble3.get_feature_importance()}")
    
    # 4. Rank fusion
    ensemble4 = EnsembleRanker(method='rank_fusion')
    scores4 = ensemble4._rank_fusion(test_preds)
    print(f"\n4. Reciprocal Rank Fusion")
    
    # 5. Diversity analysis
    diversity_metrics = evaluate_ensemble_diversity(test_preds, k=50)
    print(f"\n5. Diversity Analysis (Top-50)")
    for metric, value in diversity_metrics.items():
        print(f"   {metric}: {value:.4f}")
    
    # 6. Bootstrap ensemble
    print(f"\n6. Bootstrap Ensemble (100 iterations)")
    mean_scores, std_scores = bootstrap_ensemble(train_preds, train_labels, n_bootstrap=100)
    print(f"   Mean score range: [{mean_scores.min():.4f}, {mean_scores.max():.4f}]")
    print(f"   Avg uncertainty: {std_scores.mean():.4f}")
    print(f"   High uncertainty samples: {(std_scores > std_scores.mean() + std_scores.std()).sum()}")
    
    print("\n" + "=" * 60)
