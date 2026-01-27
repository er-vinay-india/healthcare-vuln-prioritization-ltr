#!/usr/bin/env python
"""Production-like RGCN test (32K samples, 100 epochs)."""
import sys, os, time

# CRITICAL: Set thread limits BEFORE importing PyTorch to avoid macOS segfaults
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'

import numpy as np
sys.path.insert(0, '.')

# Set PyTorch threads after import
import torch
torch.set_num_threads(1)

print('Testing with PRODUCTION-like data (32K samples, 100 epochs)...')
print('='*60)
print(f'PyTorch threads: {torch.get_num_threads()}')

from src.models.rgcn import train_rgcn_model

# Simulate production-sized data
N = 32000
features = np.random.randn(N, 12).astype(np.float32)
labels = np.random.randint(1, 6, N).astype(np.float32)

# CWE mapping (mimics real distribution)
cwe_ids = np.random.randint(0, 200, N)
cve_to_cwe = {}
for i in range(N):
    same_cwe = np.where(cwe_ids == cwe_ids[i])[0]
    cve_to_cwe[i] = [int(j) for j in same_cwe if j != i][:10]

train_idx = np.arange(int(0.8 * N))
val_idx = np.arange(int(0.8 * N), N)

print(f'Samples: {N:,}, Train: {len(train_idx):,}')
print(f'Starting training...\n')
t0 = time.time()

model, trainer, history = train_rgcn_model(
    cve_features=features,
    cve_to_cwe=cve_to_cwe,
    cve_labels=labels,
    train_idx=train_idx,
    val_idx=val_idx,
    hidden_channels=64,
    epochs=100,
    use_minibatch=True,
    batch_size=1024,
    verbose=True
)

print(f'\n✓ DONE in {time.time()-t0:.1f}s')
print(f'Final train loss: {history["train_loss"][-1]:.4f}')
