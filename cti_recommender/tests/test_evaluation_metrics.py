"""
Test Suite for Evaluation Metrics

Tests all ranking evaluation metrics to ensure correctness and robustness.
"""

import pytest
import numpy as np
import pandas as pd
from src.evaluation.metrics import (
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    compute_ap_at_k,
    compute_ranking_metrics,
    evaluate_ranking
)


class TestPrecisionAtK:
    """Test Precision@K metric."""
    
    def test_perfect_ranking(self):
        """Test Precision@K with perfect ranking."""
        y_true = np.array([3, 3, 2, 1, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        # Top-3: all relevant (labels >= 2)
        assert precision_at_k(y_true, y_pred, k=3) == 1.0
        
    def test_partial_precision(self):
        """Test Precision@K with partial relevance."""
        y_true = np.array([3, 2, 1, 0, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7, 0.6, 0.5])
        
        # Top-3: 2 relevant, 1 not
        assert precision_at_k(y_true, y_pred, k=3) == 2/3
        
    def test_no_relevant(self):
        """Test Precision@K when no relevant items in top-K."""
        y_true = np.array([0, 0, 0, 3, 3, 2])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        # Top-3: all non-relevant
        assert precision_at_k(y_true, y_pred, k=3) == 0.0
        
    def test_empty_array(self):
        """Test Precision@K with empty input."""
        y_true = np.array([])
        y_pred = np.array([])
        
        assert precision_at_k(y_true, y_pred, k=5) == 0.0
        
    def test_k_larger_than_array(self):
        """Test Precision@K when K > array length."""
        y_true = np.array([3, 2, 1])
        y_pred = np.array([1.0, 0.9, 0.8])
        
        # K=10 but only 3 items: should evaluate all 3
        precision = precision_at_k(y_true, y_pred, k=10)
        assert precision == 2/3  # 2 relevant out of 3
        
    def test_custom_threshold(self):
        """Test Precision@K with custom relevance threshold."""
        y_true = np.array([3, 3, 2, 2, 1, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7, 0.6, 0.5])
        
        # Threshold = 3 (only label 3 is relevant)
        precision = precision_at_k(y_true, y_pred, k=4, threshold=3)
        assert precision == 2/4  # 2 items with label 3 in top-4


class TestRecallAtK:
    """Test Recall@K metric."""
    
    def test_perfect_recall(self):
        """Test Recall@K with perfect ranking."""
        y_true = np.array([3, 3, 2, 1, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        # 3 relevant items total (labels >= 2), all in top-3
        assert recall_at_k(y_true, y_pred, k=3) == 1.0
        
    def test_partial_recall(self):
        """Test Recall@K with partial retrieval."""
        y_true = np.array([3, 3, 2, 1, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        # 3 relevant items total, only 2 in top-2
        assert np.isclose(recall_at_k(y_true, y_pred, k=2), 2/3)
        
    def test_zero_recall(self):
        """Test Recall@K when no relevant items in top-K."""
        y_true = np.array([0, 0, 0, 3, 3, 2])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        # 3 relevant items total, none in top-3
        assert recall_at_k(y_true, y_pred, k=3) == 0.0
        
    def test_no_relevant_items_exist(self):
        """Test Recall@K when no relevant items exist in dataset."""
        y_true = np.array([0, 0, 0, 1, 1, 1])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        # No items with label >= 2
        assert recall_at_k(y_true, y_pred, k=3, threshold=2) == 0.0
        
    def test_empty_array(self):
        """Test Recall@K with empty input."""
        y_true = np.array([])
        y_pred = np.array([])
        
        assert recall_at_k(y_true, y_pred, k=5) == 0.0
        
    def test_all_relevant_retrieved_before_k(self):
        """Test Recall@K when all relevant items appear before K."""
        y_true = np.array([3, 2, 0, 0, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7, 0.6, 0.5])
        
        # 2 relevant items, both in top-3
        assert recall_at_k(y_true, y_pred, k=3) == 1.0
        assert recall_at_k(y_true, y_pred, k=5) == 1.0  # Still 100% at k=5
        
    def test_custom_threshold(self):
        """Test Recall@K with custom relevance threshold."""
        y_true = np.array([3, 3, 2, 2, 1, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7, 0.6, 0.5])
        
        # Threshold = 3 (only 2 items with label 3)
        recall = recall_at_k(y_true, y_pred, k=3, threshold=3)
        assert recall == 1.0  # Both label-3 items in top-3


class TestNDCGAtK:
    """Test NDCG@K metric."""
    
    def test_perfect_ranking(self):
        """Test NDCG@K with perfect ranking."""
        y_true = np.array([3, 2, 1, 0])
        y_pred = np.array([4.0, 3.0, 2.0, 1.0])  # Perfect order
        
        # Perfect ranking should give NDCG@4 = 1.0
        ndcg = ndcg_at_k(y_true, y_pred, k=4)
        assert np.isclose(ndcg, 1.0)
        
    def test_reverse_ranking(self):
        """Test NDCG@K with worst possible ranking."""
        y_true = np.array([3, 2, 1, 0])
        y_pred = np.array([1.0, 2.0, 3.0, 4.0])  # Reverse order
        
        # Worst ranking should give low NDCG
        ndcg = ndcg_at_k(y_true, y_pred, k=4)
        assert ndcg < 0.7  # Should be significantly below 1.0
        
    def test_empty_array(self):
        """Test NDCG@K with empty input."""
        y_true = np.array([])
        y_pred = np.array([])
        
        assert ndcg_at_k(y_true, y_pred, k=5) == 0.0
        
    def test_no_relevance(self):
        """Test NDCG@K when all items have zero relevance."""
        y_true = np.array([0, 0, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7])
        
        # No relevant items → NDCG = 0
        ndcg = ndcg_at_k(y_true, y_pred, k=4)
        assert ndcg == 0.0


class TestComputeAPAtK:
    """Test Average Precision@K (MAP component)."""
    
    def test_perfect_ap(self):
        """Test AP@K with all relevant items at top."""
        y_true = np.array([3, 3, 2, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.2, 0.1])
        
        # All relevant (>=2) at top → AP = 1.0
        ap = compute_ap_at_k(y_true, y_pred, k=5)
        assert ap == 1.0
        
    def test_partial_ap(self):
        """Test AP@K with scattered relevant items."""
        y_true = np.array([3, 0, 2, 0, 1])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7, 0.6])
        
        # Relevant at positions 1 and 3
        ap = compute_ap_at_k(y_true, y_pred, k=5)
        # AP = (1/1 + 2/3) / 2 = 0.8333
        assert np.isclose(ap, 0.8333, atol=0.01)
        
    def test_no_relevant(self):
        """Test AP@K when no relevant items."""
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7])
        
        # No items with label >= 2
        ap = compute_ap_at_k(y_true, y_pred, k=4, threshold=2)
        assert ap == 0.0


class TestComputeRankingMetrics:
    """Test comprehensive compute_ranking_metrics function."""
    
    def test_returns_all_metrics(self):
        """Test that all metrics are computed and returned."""
        y_true = np.array([3, 3, 2, 1, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        metrics = compute_ranking_metrics(y_true, y_pred, k=3)
        
        assert 'NDCG@3' in metrics
        assert 'Precision@3' in metrics
        assert 'Recall@3' in metrics
        assert 'MAP@3' in metrics
        
    def test_metric_values_correct(self):
        """Test that metric values are correctly computed."""
        y_true = np.array([3, 3, 2, 1, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        metrics = compute_ranking_metrics(y_true, y_pred, k=3)
        
        # Verify individual metrics
        assert metrics['Precision@3'] == 1.0  # All top-3 are relevant
        assert metrics['Recall@3'] == 1.0  # All 3 relevant items in top-3
        assert metrics['NDCG@3'] > 0.9  # Should be high
        assert metrics['MAP@3'] > 0  # Should be positive
        
    def test_multiple_k_values(self):
        """Test metrics at different K values."""
        y_true = np.array([3, 3, 2, 1, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.3, 0.2, 0.1])
        
        metrics_5 = compute_ranking_metrics(y_true, y_pred, k=5)
        metrics_10 = compute_ranking_metrics(y_true, y_pred, k=10)
        
        # Precision and Recall should change with K
        assert 'NDCG@5' in metrics_5
        assert 'NDCG@10' in metrics_10


class TestEvaluateRanking:
    """Test grouped evaluation function."""
    
    def test_grouped_evaluation(self):
        """Test evaluation across multiple groups."""
        # Create sample data with groups
        df = pd.DataFrame({
            'published_week': ['2024-01'] * 5 + ['2024-02'] * 5,
            'soft_label': [3, 2, 1, 0, 0, 3, 3, 2, 1, 0],
            'score': [1.0, 0.9, 0.8, 0.7, 0.6, 1.0, 0.9, 0.8, 0.7, 0.6]
        })
        
        results = evaluate_ranking(
            df,
            score_col='score',
            label_col='soft_label',
            group_col='published_week',
            k_values=[3, 5]
        )
        
        # Should return metrics for both K values
        assert 'NDCG@3' in results
        assert 'NDCG@5' in results
        assert 'P@3' in results
        assert 'P@5' in results
        assert 'R@3' in results  # NEW: Recall@K
        assert 'R@5' in results  # NEW: Recall@K
        assert 'MAP@3' in results
        assert 'MAP@5' in results
        
    def test_skips_small_groups(self):
        """Test that groups with <2 items are skipped."""
        df = pd.DataFrame({
            'published_week': ['2024-01', '2024-02', '2024-03'],
            'soft_label': [3, 2, 1],
            'score': [1.0, 0.9, 0.8]
        })
        
        results = evaluate_ranking(
            df,
            score_col='score',
            group_col='published_week',
            k_values=[3]
        )
        
        # All groups have <2 items, should still return but with 0 values
        assert results['NDCG@3'] == 0.0
        
    def test_returns_averages(self):
        """Test that results are averaged across groups."""
        df = pd.DataFrame({
            'published_week': ['2024-01'] * 4 + ['2024-02'] * 4,
            'soft_label': [3, 2, 0, 0, 2, 2, 0, 0],
            'score': [1.0, 0.9, 0.8, 0.7, 1.0, 0.9, 0.8, 0.7]
        })
        
        results = evaluate_ranking(
            df,
            score_col='score',
            k_values=[2]
        )
        
        # Should return averaged metrics
        assert 0 <= results['NDCG@2'] <= 1.0
        assert 0 <= results['P@2'] <= 1.0
        assert 0 <= results['R@2'] <= 1.0


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_all_same_scores(self):
        """Test when all predictions have same score."""
        y_true = np.array([3, 2, 1, 0])
        y_pred = np.array([0.5, 0.5, 0.5, 0.5])
        
        # Should not crash
        precision = precision_at_k(y_true, y_pred, k=2)
        recall = recall_at_k(y_true, y_pred, k=2)
        ndcg = ndcg_at_k(y_true, y_pred, k=2)
        
        assert 0 <= precision <= 1.0
        assert 0 <= recall <= 1.0
        assert 0 <= ndcg <= 1.0
        
    def test_single_item(self):
        """Test with single item."""
        y_true = np.array([3])
        y_pred = np.array([1.0])
        
        metrics = compute_ranking_metrics(y_true, y_pred, k=1)
        
        assert metrics['Precision@1'] == 1.0
        assert metrics['Recall@1'] == 1.0
        
    def test_all_zeros(self):
        """Test with all zero labels."""
        y_true = np.array([0, 0, 0, 0])
        y_pred = np.array([1.0, 0.9, 0.8, 0.7])
        
        metrics = compute_ranking_metrics(y_true, y_pred, k=2, threshold=1)
        
        # No relevant items
        assert metrics['Precision@2'] == 0.0
        assert metrics['Recall@2'] == 0.0
        assert metrics['NDCG@2'] == 0.0


class TestMetricConsistency:
    """Test consistency between metrics."""
    
    def test_precision_recall_relationship(self):
        """Test relationship between Precision and Recall."""
        y_true = np.array([3, 3, 2, 1, 0, 0])  # 3 relevant items
        y_pred = np.array([1.0, 0.9, 0.8, 0.7, 0.6, 0.5])
        
        # At k=3 with perfect ranking:
        # Precision@3 = 3/3 = 1.0
        # Recall@3 = 3/3 = 1.0
        precision = precision_at_k(y_true, y_pred, k=3)
        recall = recall_at_k(y_true, y_pred, k=3)
        
        assert precision == 1.0
        assert recall == 1.0
        
    def test_recall_increases_with_k(self):
        """Test that Recall typically increases with larger K."""
        y_true = np.array([3, 0, 0, 2, 0, 0])  # 2 relevant items
        y_pred = np.array([1.0, 0.9, 0.8, 0.7, 0.6, 0.5])
        
        recall_2 = recall_at_k(y_true, y_pred, k=2)
        recall_4 = recall_at_k(y_true, y_pred, k=4)
        recall_6 = recall_at_k(y_true, y_pred, k=6)
        
        # Recall should not decrease as K increases
        assert recall_4 >= recall_2
        assert recall_6 >= recall_4


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
