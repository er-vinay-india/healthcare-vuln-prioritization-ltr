#!/usr/bin/env python3
"""Test updated EnhancedFeatureExtractor"""

from src.features.enhanced_features import EnhancedFeatureExtractor, get_enhanced_feature_columns

# Test imports
print("✓ Code compiles successfully")

# Check feature list
cols = get_enhanced_feature_columns()
print(f"✓ Feature columns: {len(cols)}")
print('\nExpected 37 enhanced features:')
for i, col in enumerate(cols, 1):
    print(f'  {i:2d}. {col}')

# Test extractor initialization
extractor = EnhancedFeatureExtractor()
print('\n✓ Extractor initialized successfully')
