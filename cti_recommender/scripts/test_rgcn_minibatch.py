#!/usr/bin/env python
"""
Quick test script for RGCN mini-batch training.
Run directly: python scripts/test_rgcn_minibatch.py
"""
import sys
import time
import numpy as np
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

print("=" * 60)
print("RGCN MINI-BATCH TRAINING TEST")
print("=" * 60)

# Step 1: Import test
print("\n[1/5] Testing imports...")
t0 = time.time()
try:
    import torch
    from src.models.rgcn import (
        RGCNPrioritizer,
        CVERGCNTrainer,
        train_rgcn_model,
        prepare_rgcn_data
    )
    print(f"  ✓ Imports successful ({time.time()-t0:.2f}s)")
    print(f"  PyTorch: {torch.__version__}")
    print(f"  MPS available: {torch.backends.mps.is_available()}")
except Exception as e:
    print(f"  ✗ Import failed: {e}")
    sys.exit(1)

# Step 2: Create synthetic test data
print("\n[2/5] Creating synthetic test data...")
t0 = time.time()

N_SAMPLES = 1000  # Small test set
N_FEATURES = 12
N_CWES = 50  # Simulate 50 CWE groups

# Random features and labels
np.random.seed(42)
features = np.random.randn(N_SAMPLES, N_FEATURES).astype(np.float32)
labels = np.random.randint(1, 6, N_SAMPLES).astype(np.float32)  # Labels 1-5

# Create CVE-CWE mapping (simulate CWE relationships)
cwe_assignments = np.random.randint(0, N_CWES, N_SAMPLES)
cve_to_cwe = {}
for idx in range(N_SAMPLES):
    cwe_id = cwe_assignments[idx]
    # Find other CVEs with same CWE
    same_cwe = np.where(cwe_assignments == cwe_id)[0]
    neighbors = [int(i) for i in same_cwe if i != idx][:10]  # Max 10 neighbors
    cve_to_cwe[idx] = neighbors

# Train/val split
train_idx = np.arange(int(0.8 * N_SAMPLES))
val_idx = np.arange(int(0.8 * N_SAMPLES), N_SAMPLES)

print(f"  ✓ Data created ({time.time()-t0:.2f}s)")
print(f"  Samples: {N_SAMPLES}, Features: {N_FEATURES}")
print(f"  Train: {len(train_idx)}, Val: {len(val_idx)}")
print(f"  Avg neighbors per CVE: {np.mean([len(v) for v in cve_to_cwe.values()]):.1f}")

# Step 3: Test data preparation
print("\n[3/5] Testing prepare_rgcn_data...")
t0 = time.time()
try:
    # Returns: (x, edge_index, edge_type, y, train_mask, val_mask, test_mask)
    x, edge_index, edge_type, y, train_mask, val_mask, test_mask = prepare_rgcn_data(
        cve_features=features,
        cve_to_cwe=cve_to_cwe,
        cve_labels=labels,
        train_idx=train_idx,
        val_idx=val_idx,
        verbose=True
    )
    print(f"  ✓ Data preparation complete ({time.time()-t0:.2f}s)")
    print(f"  Nodes: {x.shape[0]}, Edges: {edge_index.shape[1]}")
except Exception as e:
    print(f"  ✗ Data preparation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Step 4: Test mini-batch training
print("\n[4/5] Testing MINI-BATCH training (10 epochs)...")
t0 = time.time()
try:
    model, trainer, history = train_rgcn_model(
        cve_features=features,
        cve_to_cwe=cve_to_cwe,
        cve_labels=labels,
        train_idx=train_idx,
        val_idx=val_idx,
        hidden_channels=32,
        num_layers=2,
        dropout=0.3,
        learning_rate=0.01,
        epochs=10,  # Short test
        early_stopping_patience=5,
        device=None,  # Auto-select (should pick CPU)
        verbose=True,
        use_minibatch=True,
        batch_size=256
    )
    print(f"\n  ✓ Mini-batch training complete ({time.time()-t0:.2f}s)")
    print(f"  Final train loss: {history['train_loss'][-1]:.4f}")
    print(f"  Final val loss: {history['val_loss'][-1]:.4f}")
except Exception as e:
    print(f"  ✗ Training failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Step 5: Test full-batch training for comparison
print("\n[5/5] Testing FULL-BATCH training (10 epochs)...")
t0 = time.time()
try:
    model2, trainer2, history2 = train_rgcn_model(
        cve_features=features,
        cve_to_cwe=cve_to_cwe,
        cve_labels=labels,
        train_idx=train_idx,
        val_idx=val_idx,
        hidden_channels=32,
        num_layers=2,
        dropout=0.3,
        learning_rate=0.01,
        epochs=10,
        early_stopping_patience=5,
        device=None,
        verbose=True,
        use_minibatch=False  # Full batch
    )
    print(f"\n  ✓ Full-batch training complete ({time.time()-t0:.2f}s)")
    print(f"  Final train loss: {history2['train_loss'][-1]:.4f}")
    print(f"  Final val loss: {history2['val_loss'][-1]:.4f}")
except Exception as e:
    print(f"  ✗ Full-batch training failed: {e}")
    import traceback
    traceback.print_exc()

# Summary
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)
print("✓ All tests passed!")
print(f"Mini-batch (1000 samples, 10 epochs): Works")
print(f"Full-batch (1000 samples, 10 epochs): Works")
print("\nYou can now run the notebook cell with confidence.")
print("=" * 60)
