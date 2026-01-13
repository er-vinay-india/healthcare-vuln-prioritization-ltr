"""Learning-to-rank prototype using LightGBM (LambdaRank)

This module provides utilities to build a simple training dataset from our
existing engineered features, train a LightGBM ranker, and evaluate using
precision@K and NDCG.
"""
from __future__ import annotations

import os
from pathlib import Path
import pickle
from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import lightgbm as lgb


def _label_from_signals(df: pd.DataFrame) -> pd.Series:
    """Weak supervision labeling:
    - label=2 if KEV membership
    - label=1 if chpl_flag==1 or attack_flag==1
    - label=0 otherwise
    """
    lab = pd.Series(0, index=df.index, dtype=int)
    if 'kev_flag' in df.columns:
        lab[df['kev_flag'] == 1] = 2
    mask = ((df.get('chpl_flag', 0) == 1) | (df.get('attack_flag', 0) == 1)) & (lab == 0)
    lab[mask] = 1
    return lab


def build_ltr_features(nvd_df: pd.DataFrame, kev_df: pd.DataFrame = None, chpl_df: pd.DataFrame = None, attack_df: pd.DataFrame = None, patterns: List[str] = None) -> pd.DataFrame:
    """Return a feature DataFrame with required training columns.

    Columns include: cve_id, label, group (e.g., day or week bucket), features [...]
    """
    from cti_recommender import cti_recommender as cr

    df = cr.build_healthcare_features(nvd_df.copy(), kev_df=kev_df, chpl_df=chpl_df, patterns=patterns, attack_df=attack_df)

    # create label
    df['label'] = _label_from_signals(df)

    # group by published date bucket (e.g., YYYY-MM-DD) to create ranking groups
    df['published_day'] = pd.to_datetime(df['published'], errors='coerce').dt.strftime('%Y-%m-%d').fillna('unknown')

    # features to use
    feature_cols = ['recency_score', 'cvss_norm', 'kev_flag', 'attack_flag', 'is_healthcare', 'chpl_flag']
    for c in feature_cols:
        if c not in df.columns:
            df[c] = 0

    return df[['cve_id', 'label', 'published_day'] + feature_cols]


def _group_to_lgb_dataset(df: pd.DataFrame, feature_cols: List[str]) -> Tuple[lgb.Dataset, List[int]]:
    # order by group then by label descending for stability
    df_sorted = df.sort_values(by=['published_day', 'label'], ascending=[True, False]).reset_index(drop=True)
    group_sizes = df_sorted.groupby('published_day').size().tolist()
    X = df_sorted[feature_cols].values
    y = df_sorted['label'].values
    dset = lgb.Dataset(X, label=y, group=group_sizes)
    return dset, group_sizes


def train_ltr(df: pd.DataFrame, feature_cols: List[str], model_path: Path = Path('models/ltr_model.pkl')) -> lgb.Booster:
    os.makedirs(model_path.parent, exist_ok=True)
    dset, groups = _group_to_lgb_dataset(df, feature_cols)

    params = {
        'objective': 'lambdarank',
        'metric': 'ndcg',
        'ndcg_eval_at': [5, 10, 20],
        'learning_rate': 0.05,
        'num_leaves': 31,
        'min_data_in_leaf': 20,
        'verbose': -1,
    }

    # simple train with no holdout; small num_boost_round for speed in prototype
    booster = lgb.train(params, dset, num_boost_round=200)

    # save model
    with open(model_path, 'wb') as f:
        pickle.dump(booster, f)
    return booster


def predict_and_eval(booster: lgb.Booster, df: pd.DataFrame, feature_cols: List[str], ks: List[int] = [5,10,20]) -> Tuple[pd.DataFrame, dict]:
    # Apply model and compute precision@K and ndcg@K per group then macro-average
    df_sorted = df.copy().reset_index(drop=True)
    X = df_sorted[feature_cols].values
    preds = booster.predict(X)
    df_sorted['score_ltr'] = preds

    # Evaluate per group
    metrics = {f'precision@{k}': [] for k in ks}
    metrics.update({f'ndcg@{k}': [] for k in ks})

    for grp, sub in df_sorted.groupby('published_day'):
        sub = sub.sort_values(by='score_ltr', ascending=False)
        labels = sub['label'].values
        for k in ks:
            topk = labels[:k]
            # precision@k: consider label>0 as relevant
            prec = (topk > 0).sum() / float(min(k, len(labels))) if len(labels) > 0 else 0.0
            metrics[f'precision@{k}'].append(prec)
            # simple NDCG@k
            dcg = 0.0
            for i, rel in enumerate(topk):
                dcg += (2**rel - 1) / np.log2(i + 2)
            # ideal DCG
            ideal = np.sort(labels)[::-1][:k]
            idcg = 0.0
            for i, rel in enumerate(ideal):
                idcg += (2**rel - 1) / np.log2(i + 2)
            ndcg = (dcg / idcg) if idcg > 0 else 0.0
            metrics[f'ndcg@{k}'].append(ndcg)

    summary = {k: float(np.mean(v)) for k, v in metrics.items()}
    return df_sorted, summary


def run_end_to_end(nvd_df: pd.DataFrame, kev_df: pd.DataFrame = None, chpl_df: pd.DataFrame = None, attack_df: pd.DataFrame = None, out_dir: Path = Path('outputs')) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = build_ltr_features(nvd_df, kev_df=kev_df, chpl_df=chpl_df, attack_df=attack_df)
    feature_cols = ['recency_score', 'cvss_norm', 'kev_flag', 'attack_flag', 'is_healthcare', 'chpl_flag']

    # simple train-test split by date groups when there are enough groups,
    # otherwise do a random row-wise split to ensure we have both train and test.
    groups = df['published_day'].unique().tolist()
    if len(groups) >= 2:
        train_groups, test_groups = train_test_split(groups, test_size=0.2, random_state=42)
        train_df = df[df['published_day'].isin(train_groups)]
        test_df = df[df['published_day'].isin(test_groups)]
    else:
        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)

    model = train_ltr(train_df, feature_cols)

    # evaluate
    preds, summary = predict_and_eval(model, test_df, feature_cols)

    # save artifacts
    preds.to_csv(out_dir / 'top_scored_ltr.csv', index=False)
    # top20 overall
    preds.sort_values(by='score_ltr', ascending=False).head(20).to_csv(out_dir / 'top20_ltr.csv', index=False)

    with open(out_dir / 'ltr_eval_summary.txt', 'w') as f:
        f.write('\n'.join([f'{k}: {v:.4f}' for k, v in summary.items()]))

    # persist model
    os.makedirs('models', exist_ok=True)
    with open('models/ltr_model.pkl', 'wb') as f:
        pickle.dump(model, f)

    print('LTR training + eval complete. Summary:')
    print(summary)
