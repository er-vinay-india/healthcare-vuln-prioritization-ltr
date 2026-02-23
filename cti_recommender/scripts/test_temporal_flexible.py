#!/usr/bin/env python
"""
Quick test of flexible temporal split implementation
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.experiment_config import load_config
from src.utils.temporal import make_temporal_splits_flexible
from dataclasses import asdict
import pandas as pd

# Load config
cfg = load_config('default')

# Create sample data (2018-2025)
dates = pd.date_range('2018-01-01', '2025-12-31', freq='W')
df = pd.DataFrame({
    'cve_id': [f'CVE-{i:05d}' for i in range(len(dates))],
    'published': dates,
    'label': [1] * len(dates)
})

print('='*70)
print('FLEXIBLE TEMPORAL SPLIT TESTING')
print('='*70)
print(f'Sample data: {len(df):,} CVEs (2018-2025)\n')

# Test 1: Date-based (default)
print('='*70)
print('Strategy 1: DATE-BASED (current default)')
print('='*70)
train, val, test = make_temporal_splits_flexible(df, cfg.temporal_splits, 'published')
assert len(train) + len(val) + len(test) == len(df)
print('✅ Date-based split works!\n')

# Test 2: Percentage-based (70/15/15)
print('='*70)
print('Strategy 2: PERCENTAGE-BASED (70/15/15 split)')
print('='*70)
# Convert to dict and modify strategy
temp_config = asdict(cfg.temporal_splits)
temp_config['strategy'] = 'percentage'
train, val, test = make_temporal_splits_flexible(df, temp_config, 'published')
assert len(train) + len(val) + len(test) == len(df)
assert abs(len(train)/len(df) - 0.70) < 0.01  # Within 1%
print('✅ Percentage-based split works!\n')

# Test 3: Year-based (2018-2024 train, 2025 test)
print('='*70)
print('Strategy 3: YEAR-BASED (train 2018-2024, test 2025)')
print('='*70)
temp_config = asdict(cfg.temporal_splits)
temp_config['strategy'] = 'year_based'
train, val, test = make_temporal_splits_flexible(df, temp_config, 'published')
test_years = pd.to_datetime(test['published']).dt.year.unique()
train_years = pd.to_datetime(train['published']).dt.year.unique()
assert 2025 in test_years and 2025 not in train_years
print('✅ Year-based split works!\n')

print('='*70)
print('✅ ALL 3 TEMPORAL SPLIT STRATEGIES VALIDATED!')
print('='*70)
print('\nUsage in notebooks:')
print('  from src.utils.temporal import make_temporal_splits_flexible')
print('  train, val, test = make_temporal_splits_flexible(df, cfg.temporal_splits)')
print('\nTo switch strategies, edit config/experiments/default.yaml:')
print('  temporal_splits:')
print('    strategy: date | percentage | year_based')

