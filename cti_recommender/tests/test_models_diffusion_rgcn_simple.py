"""Coverage tests for diffusion_rank and rgcn_simple modules."""
from __future__ import annotations

from unittest.mock import patch

import networkx as nx
import numpy as np
import torch


def test_diffusion_rank_empty_graph_and_uniform_seed_fallback():
    from src.models.diffusion_rank import diffusion_rank

    empty = nx.Graph()
    assert diffusion_rank(empty, {}) == {}

    g = nx.Graph()
    g.add_edge("A", "B", weight=1.0)
    scores = diffusion_rank(g, {}, alpha=0.85, max_iter=30, tol=1e-9)

    assert set(scores.keys()) == {"A", "B"}
    assert all(v >= 0 for v in scores.values())
    assert abs(sum(scores.values()) - 1.0) < 1e-6


def test_diffusion_rank_seeded_and_batch_paths():
    from src.models.diffusion_rank import batch_diffusion_rank, diffusion_rank

    g = nx.Graph()
    g.add_edge("A", "B", weight=2.0)
    g.add_edge("B", "C", weight=1.0)

    seeded = diffusion_rank(g, {"A": 1.0}, alpha=0.85, max_iter=100, tol=1e-8)
    assert seeded["A"] > seeded["C"]

    batches = batch_diffusion_rank(g, [{"A": 1.0}, {"C": 1.0}], alpha=0.85, max_iter=50, tol=1e-7)
    assert len(batches) == 2
    assert batches[0]["A"] != batches[1]["A"]


def test_personalized_pagerank_fallback_to_custom_impl():
    from src.models.diffusion_rank import personalized_pagerank

    g = nx.Graph()
    g.add_edge("A", "B", weight=1.0)

    with patch("networkx.pagerank", side_effect=RuntimeError("boom")):
        scores = personalized_pagerank(g, {"A": 1.0}, alpha=0.85)

    assert set(scores.keys()) == {"A", "B"}


def test_evaluate_diffusion_quality_metrics():
    from src.models.diffusion_rank import evaluate_diffusion_quality

    g = nx.Graph()
    g.add_nodes_from(["A", "B", "C"])
    scores = {"A": 0.8, "B": 0.15, "C": 0.05}
    labels = {"A": 3, "B": 1, "C": 0}

    metrics = evaluate_diffusion_quality(g, scores, labels, k=2)

    assert set(metrics.keys()) == {"precision_at_k", "avg_label", "coverage"}
    assert 0 <= metrics["precision_at_k"] <= 1


def test_simple_rgcn_forward_and_trainer_fit_paths():
    from src.models.rgcn_simple import SimpleRGCN, SimpleRGCNTrainer

    model = SimpleRGCN(num_features=3, hidden_channels=8, num_layers=2, num_relations=2, dropout=0.0)

    x = torch.tensor([[0.1, 0.2, 0.3], [0.2, 0.3, 0.4], [0.3, 0.4, 0.5]], dtype=torch.float32)
    edge_index = torch.tensor([[0, 1, 1, 2], [1, 0, 2, 1]], dtype=torch.long)
    edge_type = torch.tensor([0, 1, 0, 1], dtype=torch.long)

    out = model(x, edge_index, edge_type)
    assert out.shape == (3,)

    trainer = SimpleRGCNTrainer(model, learning_rate=0.01, weight_decay=0.0)
    y = torch.tensor([0.0, 1.0, 2.0], dtype=torch.float32)
    train_mask = torch.tensor([True, True, False])
    val_mask = torch.tensor([False, False, True])

    history = trainer.fit(
        x,
        edge_index,
        edge_type,
        y,
        train_mask,
        val_mask,
        epochs=4,
        early_stopping_patience=2,
        verbose=False,
    )

    assert "train_loss" in history and "val_loss" in history
    assert len(history["train_loss"]) >= 1


def test_train_simple_rgcn_scaffold_and_outputs():
    from src.models.rgcn_simple import train_simple_rgcn

    cve_features = np.array(
        [
            [0.1, 0.2, 0.3],
            [0.2, 0.3, 0.4],
            [0.3, 0.4, 0.5],
            [0.4, 0.5, 0.6],
        ],
        dtype=np.float32,
    )
    cve_to_cwe = {0: [1], 1: [2], 2: [3], 3: [0]}
    cve_labels = np.array([0.0, 1.0, 2.0, 1.0], dtype=np.float32)
    train_idx = np.array([0, 1, 2])
    val_idx = np.array([3])

    model, trainer, history = train_simple_rgcn(
        cve_features,
        cve_to_cwe,
        cve_labels,
        train_idx,
        val_idx,
        hidden_channels=8,
        num_layers=2,
        dropout=0.0,
        learning_rate=0.01,
        epochs=3,
        early_stopping_patience=2,
        verbose=False,
    )

    assert model is not None
    assert trainer is not None
    assert len(history["train_loss"]) >= 1
