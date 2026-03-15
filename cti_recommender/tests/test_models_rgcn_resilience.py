"""Coverage tests for src.models.rgcn with lightweight stubs."""
from __future__ import annotations

from unittest.mock import patch

import numpy as np
import torch
import torch.nn as nn


class _DummyRGCNModel(nn.Module):
    def __init__(self, in_features: int = 3):
        super().__init__()
        self.linear = nn.Linear(in_features, 1)

    def forward(self, x, edge_index, edge_type):
        return self.linear(x).squeeze(-1)


class _FakePredictModel:
    def eval(self):
        return self

    def to(self, _device):
        return self

    def __call__(self, x, edge_index, edge_type):
        # Deterministic pseudo-score independent of edges.
        return x.sum(dim=1)


class _TinyModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(2, 1)

    def forward(self, x, edge_index, edge_type):
        return self.linear(x).squeeze(-1)


def test_prepare_rgcn_data_builds_tensors_edges_and_masks():
    from src.models.rgcn import prepare_rgcn_data

    features = np.array([[1.0, 0.0], [0.5, 0.1], [0.2, 0.3]], dtype=np.float32)
    cve_to_cwe = {0: [1], 1: [2]}
    labels = np.array([0.0, 1.0, 2.0], dtype=np.float32)

    x, edge_index, edge_type, y, train_mask, val_mask, test_mask = prepare_rgcn_data(
        cve_features=features,
        cve_to_cwe=cve_to_cwe,
        cve_labels=labels,
        train_idx=np.array([0, 1]),
        val_idx=np.array([2]),
        test_idx=np.array([], dtype=int),
        normalize_features=False,
        verbose=False,
    )

    assert tuple(x.shape) == (3, 2)
    assert edge_index.shape[0] == 2
    assert len(edge_type) == edge_index.shape[1]
    assert tuple(y.shape) == (3,)
    assert train_mask.sum().item() == 2
    assert val_mask.sum().item() == 1
    assert test_mask.sum().item() == 0


def test_prepare_rgcn_data_no_edges_creates_self_loops():
    from src.models.rgcn import prepare_rgcn_data

    features = np.array([[1.0], [2.0]], dtype=np.float32)
    labels = np.array([0.0, 1.0], dtype=np.float32)

    x, edge_index, edge_type, *_ = prepare_rgcn_data(
        cve_features=features,
        cve_to_cwe={},
        cve_labels=labels,
        train_idx=np.array([0]),
        normalize_features=False,
        verbose=False,
    )

    assert tuple(x.shape) == (2, 1)
    assert edge_index.shape[1] == 2
    assert edge_type.shape[0] == 2


def test_trainer_fit_fullbatch_runs_and_records_history():
    from src.models.rgcn import CVERGCNTrainer

    model = _DummyRGCNModel(in_features=2)
    trainer = CVERGCNTrainer(model=model, learning_rate=0.01, device="cpu", use_minibatch=False)

    x = torch.tensor([[0.1, 0.2], [0.3, 0.4], [0.5, 0.6]], dtype=torch.float32)
    edge_index = torch.tensor([[0, 1, 1, 2], [1, 0, 2, 1]], dtype=torch.long)
    edge_type = torch.tensor([0, 1, 0, 1], dtype=torch.long)
    y = torch.tensor([0.0, 1.0, 2.0], dtype=torch.float32)
    train_mask = torch.tensor([True, True, False])
    val_mask = torch.tensor([False, False, True])

    history = trainer.fit(
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        y=y,
        train_mask=train_mask,
        val_mask=val_mask,
        epochs=3,
        early_stopping_patience=2,
        verbose=False,
    )

    assert "train_loss" in history
    assert "val_loss" in history
    assert len(history["train_loss"]) >= 1


def test_fit_minibatch_falls_back_to_fullbatch_when_neighborloader_unavailable():
    from src.models import rgcn as mod

    model = _DummyRGCNModel(in_features=2)
    trainer = mod.CVERGCNTrainer(model=model, learning_rate=0.01, device="cpu", use_minibatch=True)

    x = torch.tensor([[0.1, 0.2], [0.3, 0.4]], dtype=torch.float32)
    edge_index = torch.tensor([[0, 1], [1, 0]], dtype=torch.long)
    edge_type = torch.tensor([0, 1], dtype=torch.long)
    y = torch.tensor([0.0, 1.0], dtype=torch.float32)
    train_mask = torch.tensor([True, False])
    val_mask = torch.tensor([False, True])

    with patch.object(mod, "NeighborLoader", side_effect=RuntimeError("missing pyg-lib")), \
         patch.object(trainer, "_fit_fullbatch", return_value={"train_loss": [1.0], "val_loss": [1.0]}) as fb:
        hist = trainer._fit_minibatch(
            x=x,
            edge_index=edge_index,
            edge_type=edge_type,
            y=y,
            train_mask=train_mask,
            val_mask=val_mask,
            epochs=2,
            early_stopping_patience=1,
            verbose=False,
        )

    fb.assert_called_once()
    assert hist["train_loss"] == [1.0]


def test_fast_rgcn_inference_batches_and_returns_predictions():
    from src.models.rgcn import fast_rgcn_inference

    model = _FakePredictModel()
    train_features = np.array([[1.0, 0.0], [0.5, 0.5], [0.2, 0.8]], dtype=np.float32)
    test_features = np.array([[0.1, 0.2], [0.2, 0.3], [0.4, 0.1]], dtype=np.float32)

    train_cve_to_cwe = {0: [1], 1: [2], 2: [0]}
    test_to_train_neighbors = {0: [0, 1], 1: [2], 2: [1]}

    preds = fast_rgcn_inference(
        model=model,
        train_features=train_features,
        test_features=test_features,
        train_cve_to_cwe=train_cve_to_cwe,
        test_to_train_neighbors=test_to_train_neighbors,
        batch_size=2,
        device="cpu",
    )

    assert preds.shape == (3,)
    assert np.isfinite(preds).all()


def test_fast_rgcn_inference_handles_batches_with_no_neighbors():
    from src.models.rgcn import fast_rgcn_inference

    model = _FakePredictModel()
    train_features = np.array([[0.9, 0.1]], dtype=np.float32)
    test_features = np.array([[0.1, 0.2], [0.3, 0.4]], dtype=np.float32)

    preds = fast_rgcn_inference(
        model=model,
        train_features=train_features,
        test_features=test_features,
        train_cve_to_cwe={},
        test_to_train_neighbors={},
        batch_size=1,
        device="cpu",
    )

    assert preds.shape == (2,)
    assert np.isfinite(preds).all()


def test_trainer_init_forces_cpu_when_mps_requested():
    from src.models import rgcn as mod

    model = _DummyRGCNModel(in_features=2)
    with patch.object(mod.logger, "warning") as warn:
        trainer = mod.CVERGCNTrainer(model=model, device="mps", use_minibatch=False)

    assert str(trainer.device) == "cpu"
    warn.assert_called_once()


def test_trainer_evaluate_and_predict_with_mask():
    from src.models.rgcn import CVERGCNTrainer

    model = _TinyModel()
    trainer = CVERGCNTrainer(model=model, learning_rate=0.01, device="cpu", use_minibatch=False)

    x = torch.tensor([[1.0, 2.0], [3.0, 4.0]], dtype=torch.float32)
    edge_index = torch.zeros((2, 0), dtype=torch.long)
    edge_type = torch.zeros(0, dtype=torch.long)
    y = torch.tensor([3.0, 7.0], dtype=torch.float32)
    mask = torch.tensor([True, False])

    loss, preds = trainer.evaluate(x, edge_index, edge_type, y, mask)
    masked_preds = trainer.predict(x, edge_index, edge_type, mask)

    assert isinstance(loss, float)
    assert preds.shape == (1,)
    assert masked_preds.shape == (1,)


def test_train_rgcn_model_orchestrates_prepare_and_fit():
    from src.models import rgcn as mod

    x = torch.zeros((2, 2), dtype=torch.float32)
    edge_index = torch.zeros((2, 0), dtype=torch.long)
    edge_type = torch.zeros(0, dtype=torch.long)
    y = torch.zeros(2, dtype=torch.float32)
    train_mask = torch.tensor([True, False])
    val_mask = torch.tensor([False, True])
    test_mask = torch.tensor([False, False])

    with patch.object(
        mod,
        "prepare_rgcn_data",
        return_value=(x, edge_index, edge_type, y, train_mask, val_mask, test_mask),
    ) as prep, patch.object(mod.CVERGCNTrainer, "fit", return_value={"train_loss": [0.1], "val_loss": [0.2]}) as fit:
        model, trainer, history = mod.train_rgcn_model(
            cve_features=np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32),
            cve_to_cwe={},
            cve_labels=np.array([0.0, 1.0], dtype=np.float32),
            train_idx=np.array([0]),
            val_idx=np.array([1]),
            test_idx=np.array([], dtype=int),
            hidden_channels=4,
            num_layers=1,
            epochs=1,
            early_stopping_patience=1,
            device="cpu",
            verbose=False,
            use_minibatch=False,
            batch_size=2,
        )

    prep.assert_called_once()
    fit.assert_called_once()
    assert isinstance(model, mod.RGCNPrioritizer)
    assert isinstance(trainer, mod.CVERGCNTrainer)
    assert history["train_loss"] == [0.1]
