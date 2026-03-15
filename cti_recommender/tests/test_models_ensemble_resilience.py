"""Coverage tests for ensemble model utilities."""
from __future__ import annotations

import numpy as np


def _sample_predictions():
    return {
        "m1": np.array([0.1, 0.8, 0.2, 0.7]),
        "m2": np.array([0.2, 0.7, 0.3, 0.6]),
        "m3": np.array([0.3, 0.6, 0.4, 0.5]),
    }


def test_ensemble_ranker_simple_average_fit_predict_and_weights():
    from src.models.ensemble import EnsembleRanker

    preds = _sample_predictions()
    labels = np.array([0.0, 1.0, 0.0, 1.0])

    ens = EnsembleRanker(method="simple_average", normalize_scores=False)
    ens.fit(preds, labels)
    out = ens.predict(preds)
    weights = ens.get_weights()

    assert out.shape == (4,)
    assert weights is not None
    assert abs(sum(weights.values()) - 1.0) < 1e-8


def test_ensemble_ranker_weighted_average_normalized_predicts():
    from src.models.ensemble import EnsembleRanker

    preds = _sample_predictions()
    labels = np.array([0.0, 1.0, 0.0, 1.0])

    ens = EnsembleRanker(method="weighted_average", normalize_scores=True)
    ens.fit(preds, labels)
    out = ens.predict(preds)

    assert out.shape == (4,)
    assert ens.weights is not None
    assert np.isfinite(out).all()


def test_ensemble_ranker_meta_learning_paths_and_feature_importance():
    from src.models.ensemble import EnsembleRanker

    preds = _sample_predictions()
    labels = np.array([0.0, 1.0, 0.0, 1.0])

    ens_ridge = EnsembleRanker(method="meta_learning", meta_model="ridge")
    ens_ridge.fit(preds, labels)
    out_ridge = ens_ridge.predict(preds)
    imp_ridge = ens_ridge.get_feature_importance()

    ens_rf = EnsembleRanker(method="meta_learning", meta_model="rf")
    ens_rf.fit(preds, labels)
    out_rf = ens_rf.predict(preds)
    imp_rf = ens_rf.get_feature_importance()

    ens_log = EnsembleRanker(method="meta_learning", meta_model="logistic")
    ens_log.fit(preds, labels.astype(int))
    out_log = ens_log.predict(preds)

    assert out_ridge.shape == (4,)
    assert out_rf.shape == (4,)
    assert out_log.shape == (4,)
    assert imp_ridge is not None
    assert imp_rf is not None


def test_ensemble_ranker_rank_fusion_path():
    from src.models.ensemble import EnsembleRanker

    preds = _sample_predictions()
    labels = np.array([0.0, 1.0, 0.0, 1.0])

    ens = EnsembleRanker(method="rank_fusion", normalize_scores=False)
    ens.fit(preds, labels)
    out = ens.predict(preds)

    assert out.shape == (4,)
    assert (out > 0).all()


def test_bootstrap_ensemble_returns_mean_and_std():
    from src.models.ensemble import bootstrap_ensemble

    preds = _sample_predictions()
    labels = np.array([0.0, 1.0, 0.0, 1.0])

    mean_preds, std_preds = bootstrap_ensemble(preds, labels, n_bootstrap=5, sample_size=0.75)

    assert mean_preds.shape == (4,)
    assert std_preds.shape == (4,)
    assert (std_preds >= 0).all()


def test_stacking_rrf_borda_and_diversity_utilities():
    from src.models.ensemble import (
        borda_count,
        create_stacking_ensemble,
        evaluate_ensemble_diversity,
        reciprocal_rank_fusion,
    )

    train_preds = _sample_predictions()
    test_preds = {
        "m1": np.array([0.4, 0.5, 0.6]),
        "m2": np.array([0.3, 0.6, 0.5]),
        "m3": np.array([0.2, 0.7, 0.4]),
    }
    train_labels = np.array([0.0, 1.0, 0.0, 1.0])

    stack_scores = create_stacking_ensemble(train_preds, test_preds, train_labels, method="ridge")
    assert stack_scores.shape == (3,)

    rankings = {
        "m1": np.array([1, 2, 3]),
        "m2": np.array([2, 1, 3]),
        "m3": np.array([1, 3, 2]),
    }
    rrf = reciprocal_rank_fusion(rankings, k=60)
    borda = borda_count(rankings)
    diversity = evaluate_ensemble_diversity(train_preds, k=2)

    assert rrf.shape == (3,)
    assert borda.shape == (3,)
    assert set(diversity.keys()) == {
        "diversity_score",
        "avg_jaccard_similarity",
        "avg_correlation",
        "min_pairwise_similarity",
        "max_pairwise_similarity",
    }
