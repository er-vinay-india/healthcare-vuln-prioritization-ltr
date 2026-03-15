"""Coverage tests for diffusion and graph ranking model modules."""
from __future__ import annotations

import numpy as np
import pandas as pd
import torch


def test_denoising_mlp_forward_shape():
    from src.models.diffusion_imputer import DenoisingMLP

    model = DenoisingMLP(input_dim=3, hidden_dim=8, num_layers=2)
    x = torch.randn(4, 3)
    noisy_y = torch.randn(4, 1)
    t = torch.rand(4, 1)

    out = model(x, noisy_y, t)
    assert tuple(out.shape) == (4, 1)


def test_diffusion_rank_imputer_train_and_predict_paths():
    from src.models.diffusion_imputer import DiffusionRankImputer

    df = pd.DataFrame(
        {
            "f1": [0.1, 0.2, 0.3, 0.4],
            "f2": [1.0, 1.2, 1.4, 1.6],
            "soft_label": [0.0, 1.0, 2.0, 3.0],
        }
    )

    imputer = DiffusionRankImputer(input_dim=2, hidden_dim=16, num_layers=2, lr=1e-3, device="cpu")
    stats = imputer.train_quick(df, ["f1", "f2"], epochs=2, verbose=False)

    mean_scores, uncertainty = imputer.predict(df, ["f1", "f2"], num_samples=3)

    assert len(stats["losses"]) == 2
    assert stats["final_loss"] == stats["losses"][-1]
    assert mean_scores.shape == (4,)
    assert uncertainty.shape == (4,)
    assert np.all(mean_scores >= 0)
    assert np.all(mean_scores <= 3)


def test_extract_vendor_from_description_patterns_and_fallbacks():
    from src.models.rgcn_ranker import extract_vendor_from_description

    assert extract_vendor_from_description("Microsoft before 1.2 allows X") == "microsoft"
    assert extract_vendor_from_description("Issue in OpenSSL version 3.0") == "openssl"
    assert extract_vendor_from_description("Acme allows remote code execution") == "acme"
    assert extract_vendor_from_description("") == "unknown_vendor"
    assert extract_vendor_from_description(np.nan) == "unknown_vendor"


def test_simple_rgcn_forward_handles_empty_and_nonempty_edges():
    from src.models.rgcn_ranker import SimpleRGCN

    model = SimpleRGCN(cve_dim=3, vendor_dim=3, hidden_dim=8, output_dim=1, num_layers=2)
    cve = torch.randn(3, 3)
    vendor = torch.randn(2, 3)

    empty_edges = torch.empty((2, 0), dtype=torch.long)
    out_empty = model(cve, vendor, empty_edges, empty_edges)
    assert tuple(out_empty.shape) == (3, 1)

    c2v = torch.tensor([[0, 1, 2], [0, 1, 0]], dtype=torch.long)
    v2c = torch.tensor([[0, 1, 0], [0, 1, 2]], dtype=torch.long)
    out_edges = model(cve, vendor, c2v, v2c)
    assert tuple(out_edges.shape) == (3, 1)


def test_rgcn_ranker_build_graph_train_then_infer_unknown_vendor():
    from src.models.rgcn_ranker import RGCNRanker

    train_df = pd.DataFrame(
        {
            "description": [
                "Acme before 1.0 vulnerability",
                "Beta allows privilege escalation",
                "Acme through 2.0 issue",
            ],
            "f1": [0.1, 0.2, 0.3],
            "f2": [1.0, 1.1, 1.2],
            "soft_label": [0.0, 1.0, 2.0],
        }
    )

    ranker = RGCNRanker(cve_dim=2, hidden_dim=8, num_layers=2, lr=1e-3, device="cpu")
    cve_t, vendor_t, c2v, v2c, vendors = ranker._build_graph(train_df, ["f1", "f2"], is_train=True)

    assert cve_t.shape[0] == len(train_df)
    assert vendor_t.shape[1] == 2
    assert c2v.shape[1] == len(train_df)
    assert len(vendors) == len(train_df)

    infer_df = pd.DataFrame(
        {
            "description": ["CompletelyNewVendor before 3.0 bug"],
            "f1": [0.4],
            "f2": [1.3],
            "soft_label": [1.0],
        }
    )
    cve_inf, vendor_inf, c2v_inf, v2c_inf, _ = ranker._build_graph(infer_df, ["f1", "f2"], is_train=False)

    assert cve_inf.shape[0] == 1
    assert vendor_inf.shape[0] == vendor_t.shape[0]
    assert c2v_inf.shape[1] == 1
    assert v2c_inf.shape[1] == 1


def test_rgcn_ranker_train_and_predict_quick_paths():
    from src.models.rgcn_ranker import RGCNRanker

    df = pd.DataFrame(
        {
            "description": [
                "Acme before 1.0 vulnerability",
                "Beta allows privilege escalation",
                "Acme through 2.0 issue",
                "Beta before 4.2 denial of service",
            ],
            "f1": [0.1, 0.2, 0.3, 0.4],
            "f2": [1.0, 1.1, 1.2, 1.3],
            "soft_label": [0.0, 1.0, 2.0, 1.0],
        }
    )

    ranker = RGCNRanker(cve_dim=2, hidden_dim=8, num_layers=2, lr=1e-3, device="cpu")
    stats = ranker.train_quick(df, ["f1", "f2"], epochs=1, verbose=False)
    scores = ranker.predict(df, ["f1", "f2"])

    assert len(stats["losses"]) == 1
    assert stats["final_loss"] == stats["losses"][-1]
    assert scores.shape == (len(df),)
