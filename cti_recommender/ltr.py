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

    # group by published date bucket (e.g., YYYY-WW) to create ranking groups
    df['published_week'] = pd.to_datetime(df['published'], errors='coerce').dt.strftime('%Y-%U').fillna('unknown')

    # features to use
    feature_cols = ['recency_score', 'cvss_norm', 'kev_flag', 'attack_flag', 'is_healthcare', 'chpl_flag']
    for c in feature_cols:
        if c not in df.columns:
            df[c] = 0

    return df[['cve_id', 'label', 'published_week'] + feature_cols]


def _group_to_lgb_dataset(df: pd.DataFrame, feature_cols: List[str]) -> Tuple[lgb.Dataset, List[int]]:
    # order by group then by label descending for stability
    df_sorted = df.sort_values(by=['published_week', 'label'], ascending=[True, False]).reset_index(drop=True)
    group_sizes = df_sorted.groupby('published_week').size().tolist()
    X = df_sorted[feature_cols].values
    y = df_sorted['label'].values
    dset = lgb.Dataset(X, label=y, group=group_sizes)
    return dset, group_sizes


def tune_ltr(df: pd.DataFrame, feature_cols: List[str], param_grid: dict, cv_folds: int = 3) -> dict:
    """Tune hyperparameters using manual CV."""
    
    best_params = None
    best_score = -np.inf
    best_num_boost = 100
    
    # Use StratifiedKFold on labels
    from sklearn.model_selection import StratifiedKFold
    cv_splitter = StratifiedKFold(n_splits=min(cv_folds, len(df['label'].unique())), shuffle=True, random_state=42)
    y_labels = df['label'].values
    
    # Grid search over params
    from itertools import product
    keys = param_grid.keys()
    values = param_grid.values()
    for combo in product(*values):
        params = dict(zip(keys, combo))
        params.update({
            'objective': 'lambdarank',
            'metric': 'ndcg',
            'ndcg_eval_at': [5, 10, 20],
            'verbose': -1,
        })
        
        scores = []
        for train_idx, val_idx in cv_splitter.split(df, y_labels):
            train_df = df.iloc[train_idx]
            val_df = df.iloc[val_idx]
            
            train_dset, _ = _group_to_lgb_dataset(train_df, feature_cols)
            val_dset, _ = _group_to_lgb_dataset(val_df, feature_cols)
            
            booster = lgb.train(params, train_dset, num_boost_round=500, valid_sets=[val_dset], 
                               callbacks=[lgb.early_stopping(50), lgb.log_evaluation(0)])
            scores.append(booster.best_score['valid_0']['ndcg@20'])
        
        mean_ndcg20 = np.mean(scores)
        
        if mean_ndcg20 > best_score:
            best_score = mean_ndcg20
            best_params = params.copy()
            best_num_boost = 500  # approximate
    
    best_params['num_boost_round'] = best_num_boost
    print(f'Best params: {best_params}, NDCG@20: {best_score:.4f}')
    return best_params


def train_ltr(df: pd.DataFrame, feature_cols: List[str], params: dict = None, model_path: Path = Path('models/ltr_model.pkl')) -> lgb.Booster:
    os.makedirs(model_path.parent, exist_ok=True)
    dset, groups = _group_to_lgb_dataset(df, feature_cols)

    if params is None:
        params = {
            'objective': 'lambdarank',
            'metric': 'ndcg',
            'ndcg_eval_at': [5, 10, 20],
            'learning_rate': 0.05,
            'num_leaves': 31,
            'min_data_in_leaf': 20,
            'verbose': -1,
        }
    else:
        params = params.copy()
        params.setdefault('objective', 'lambdarank')
        params.setdefault('metric', 'ndcg')
        params.setdefault('ndcg_eval_at', [5, 10, 20])
        params.setdefault('verbose', -1)

    num_boost = params.pop('num_boost_round', 200)

    booster = lgb.train(params, dset, num_boost_round=num_boost)

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

    for grp, sub in df_sorted.groupby('published_week'):
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

    groups = df['published_week'].unique().tolist()
    if len(groups) >= 2:
        train_groups, test_groups = train_test_split(groups, test_size=0.2, random_state=42)
        train_df = df[df['published_week'].isin(train_groups)]
        test_df = df[df['published_week'].isin(test_groups)]
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


def run_tuned_end_to_end(nvd_df: pd.DataFrame, kev_df: pd.DataFrame = None, chpl_df: pd.DataFrame = None, attack_df: pd.DataFrame = None, out_dir: Path = Path('outputs')) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = build_ltr_features(nvd_df, kev_df=kev_df, chpl_df=chpl_df, attack_df=attack_df)
    feature_cols = ['recency_score', 'cvss_norm', 'kev_flag', 'attack_flag', 'is_healthcare', 'chpl_flag']

    groups = df['published_week'].unique().tolist()
    if len(groups) >= 2:
        train_groups, test_groups = train_test_split(groups, test_size=0.2, random_state=42)
        train_df = df[df['published_week'].isin(train_groups)]
        test_df = df[df['published_week'].isin(test_groups)]
    else:
        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)

    param_grid = {
        'learning_rate': [0.01, 0.05, 0.1],
        'num_leaves': [20, 31, 50],
        'min_data_in_leaf': [10, 20, 50],
    }
    
    best_params = tune_ltr(train_df, feature_cols, param_grid, cv_folds=3)
    
    # Train final model with best params on train
    model = train_ltr(train_df, feature_cols, best_params, model_path=Path('models/ltr_tuned_model.pkl'))
    
    # Evaluate on test
    preds, summary = predict_and_eval(model, test_df, feature_cols)

    # save artifacts
    preds.to_csv(out_dir / 'top_scored_ltr_tuned.csv', index=False)
    preds.sort_values(by='score_ltr', ascending=False).head(20).to_csv(out_dir / 'top20_ltr_tuned.csv', index=False)

    with open(out_dir / 'ltr_tuned_eval_summary.txt', 'w') as f:
        f.write('\n'.join([f'{k}: {v:.4f}' for k, v in summary.items()]))
        f.write(f'\nBest params: {best_params}\n')

    print('LTR tuned training + eval complete. Summary:')
    print(summary)


def run_ablation_study(nvd_df: pd.DataFrame, kev_df: pd.DataFrame = None, chpl_df: pd.DataFrame = None, attack_df: pd.DataFrame = None, out_dir: Path = Path('outputs')) -> None:
    """Run ablation study by removing one feature at a time and evaluating LTR performance."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = build_ltr_features(nvd_df, kev_df=kev_df, chpl_df=chpl_df, attack_df=attack_df)
    feature_cols_base = ['recency_score', 'cvss_norm', 'kev_flag', 'attack_flag', 'is_healthcare', 'chpl_flag']

    groups = df['published_week'].unique().tolist()
    if len(groups) >= 2:
        train_groups, test_groups = train_test_split(groups, test_size=0.2, random_state=42)
        train_df = df[df['published_week'].isin(train_groups)]
        test_df = df[df['published_week'].isin(test_groups)]
    else:
        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)

    results = {}
    for i, feat in enumerate(feature_cols_base):
        feature_cols = [f for f in feature_cols_base if f != feat]
        model = train_ltr(train_df, feature_cols)
        preds, summary = predict_and_eval(model, test_df, feature_cols)
        results[f'without_{feat}'] = summary

    # Full model
    model = train_ltr(train_df, feature_cols_base)
    preds, summary = predict_and_eval(model, test_df, feature_cols_base)
    results['full'] = summary

    # Save results
    with open(out_dir / 'ablation_results.txt', 'w') as f:
        for key, val in results.items():
            f.write(f'{key}: {val}\n')

    print('Ablation study complete.')
    for key, val in results.items():
        print(f'{key}: NDCG@20={val.get("ndcg@20", 0):.4f}')
