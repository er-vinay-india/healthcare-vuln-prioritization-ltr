#!/usr/bin/env python
"""Safe RGCN test - avoids segfaults on macOS."""
import sys
import os

# Disable MPS to avoid Apple Silicon crashes
os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'

import time
import numpy as np

sys.path.insert(0, '.')

print('='*60)
print('SAFE RGCN TEST (avoids macOS segfaults)')
print('='*60)

# Import PyTorch first and set thread limits
import torch
torch.set_num_threads(1)  # Reduce threading issues

print(f'PyTorch: {torch.__version__}')
print(f'Threads: {torch.get_num_threads()}')

# Smaller test to avoid memory issues
N = 5000  # Start small
print(f'\nTest 1: Small scale ({N:,} samples)')
print('-'*40)

from src.models.rgcn import train_rgcn_model

# Generate synthetic data
np.random.seed(42)
features = np.random.randn(N, 12).astype(np.float32)
labels = np.random.randint(1, 6, N).astype(np.float32)

# Simple CWE mapping
cwe_ids = np.random.randint(0, 50, N)
cve_to_cwe = {}
for i in range(N):
    same_cwe = np.where(cwe_ids == cwe_ids[i])[0]
    cve_to_cwe[i] = [int(j) for j in same_cwe if j != i][:5]

train_idx = np.arange(int(0.8 * N))
val_idx = np.arange(int(0.8 * N), N)

print(f'Samples: {N:,}')
print(f'Train: {len(train_idx):,}, Val: {len(val_idx):,}')

t0 = time.time()
try:
    model, trainer, history = train_rgcn_model(
        cve_features=features,
        cve_to_cwe=cve_to_cwe,
        cve_labels=labels,
        train_idx=train_idx,
        val_idx=val_idx,
        hidden_channels=32,  # Smaller model
        epochs=20,           # Fewer epochs
        use_minibatch=True,
        batch_size=512,
        verbose=True
    )
    print(f'\n✓ Test 1 PASSED in {time.time()-t0:.1f}s')
    print(f'Final loss: {history["train_loss"][-1]:.4f}')
    
except Exception as e:
    print(f'\n✗ Test 1 FAILED: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)

# If small test passes, try larger
print('\n' + '='*60)
print('Test 2: Medium scale (15K samples)')
print('-'*40)

N = 15000
features = np.random.randn(N, 12).astype(np.float32)
labels = np.random.randint(1, 6, N).astype(np.float32)

cwe_ids = np.random.randint(0, 100, N)
cve_to_cwe = {}
for i in range(N):
    same_cwe = np.where(cwe_ids == cwe_ids[i])[0]
    cve_to_cwe[i] = [int(j) for j in same_cwe if j != i][:5]

train_idx = np.arange(int(0.8 * N))
val_idx = np.arange(int(0.8 * N), N)

print(f'Samples: {N:,}')

t0 = time.time()
try:
    model, trainer, history = train_rgcn_model(
        cve_features=features,
        cve_to_cwe=cve_to_cwe,
        cve_labels=labels,
        train_idx=train_idx,
        val_idx=val_idx,
        hidden_channels=64,
        epochs=30,
        use_minibatch=True,
        batch_size=1024,
        verbose=True
    )
    print(f'\n✓ Test 2 PASSED in {time.time()-t0:.1f}s')
    
except Exception as e:
    print(f'\n✗ Test 2 FAILED: {e}')

print('\n' + '='*60)
print('TESTS COMPLETE')
print('='*60)
