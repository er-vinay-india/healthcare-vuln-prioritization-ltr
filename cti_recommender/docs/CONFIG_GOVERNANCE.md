# Configuration Governance

## Ownership boundaries

- **Runtime configuration (`config/settings.py`)** owns operational values loaded from environment variables or `.env`.
  - Examples: API keys, API host/port, cache paths, DB path, logging, retries, monitoring.
- **Experiment configuration (`config/experiments/*.yaml` via `config/experiment_config.py`)** owns ML/experiment behavior.
  - Examples: sampling sizes, RGCN hyperparameters, evaluation `k_values`, feature engineering toggles, temporal split strategy.

## Precedence

1. **Environment variables** (highest precedence for runtime settings)
2. **Selected experiment profile YAML** (`debug.yaml` or `production.yaml`)
3. **`default.yaml` experiment base** (lowest precedence)

This means runtime values are never duplicated into experiment YAML. Experiment profile values override `default.yaml` only within the experiment domain.

## Deprecations removed

The following stale experiment keys were removed from `default.yaml`:

- `feature_engineering.feature_cols`
- `feature_engineering.similarity_features`

Use these active keys instead:

- `data.feature_cols`
- `data.similarity_features`

## Validation gate

Run the audit locally:

```bash
python cti_recommender/scripts/ops/config_audit.py
```

The audit fails on:

- unknown/unused experiment YAML keys
- duplicated ownership keys between runtime settings and experiment schema
