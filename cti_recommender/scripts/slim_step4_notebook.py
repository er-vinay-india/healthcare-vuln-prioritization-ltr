"""Slim STEP_4 notebook: replace inline function defs with src/ imports."""
import json

NB = 'notebooks/STEP_4_All_Models_Training.ipynb'

with open(NB) as f:
    nb = json.load(f)

cells = nb['cells']

def find_cell(cell_id):
    for i, c in enumerate(cells):
        if c.get('id') == cell_id:
            return i
    raise KeyError(cell_id)


# ----------------------------------------------------------------
# Cell a0c24c4a: trace_event / trace_stage_done / register_artifact
# Keep all config code; remove 3 inline function defs; add RunTracker
# ----------------------------------------------------------------
idx = find_cell('a0c24c4a')
cells[idx]['source'] = [
    "# Project imports (separated from setup cell to avoid startup hangs)\n",
    "from src.models.ltr import train_lambdarank, save_model, get_default_ltr_params\n",
    "from src.models.baselines import compute_cvss_only_scores, compute_heuristic_scores\n",
    "from src.utils.notebook_helpers import save_plot, save_dataframe, display_sample, setup_notebook_output\n",
    "from config.experiment_config import get_config\n",
    "\n",
    "# Configure notebook display\n",
    "setup_notebook_output()\n",
    "\n",
    "# Load experiment configuration\n",
    "exp_cfg = get_config()\n",
    "\n",
    "# Config-driven temporal split ratios\n",
    "split_cfg = exp_cfg.temporal_splits.percentage_split\n",
    "TRAIN_RATIO = float(split_cfg.get('train', 0.70))\n",
    "VAL_RATIO   = float(split_cfg.get('val',   0.15))\n",
    "TEST_RATIO  = float(split_cfg.get('test',  0.15))\n",
    "\n",
    "# Config-driven ranking evaluation cutoffs\n",
    "EVAL_K_VALUES = sorted({int(k) for k in exp_cfg.evaluation.k_values if int(k) > 0})\n",
    "if not EVAL_K_VALUES:\n",
    "    EVAL_K_VALUES = [10, 20, 100]\n",
    "\n",
    "# Config-driven year-based cutoff\n",
    "year_split_cfg = exp_cfg.temporal_splits.year_split\n",
    "test_years = sorted(int(y) for y in year_split_cfg.get('test_years', [2025]))\n",
    "thesis_test_start_year = test_years[0] if test_years else 2025\n",
    "THESIS_CUTOFF_DATE = pd.Timestamp(f'{thesis_test_start_year - 1}-12-31', tz='UTC')\n",
    "\n",
    "print(f'[OK] Config profile: {exp_cfg._profile}')\n",
    "print(f'[OK] Split ratios (train/val/test): {TRAIN_RATIO:.2f}/{VAL_RATIO:.2f}/{TEST_RATIO:.2f}')\n",
    "print(f'[OK] Evaluation k-values: {EVAL_K_VALUES}')\n",
    "print(f'[OK] Thesis cutoff date: {THESIS_CUTOFF_DATE.date()}')\n",
    "\n",
    "# Traceability setup — implementation in src/utils/run_tracker.py\n",
    "RUN_ID = f\"step4_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}\"\n",
    "TRACE_LOG_DIR = project_root / 'logs' / 'runs' / RUN_ID\n",
    "TRACE_LOG_DIR.mkdir(parents=True, exist_ok=True)\n",
    "\n",
    "from src.utils.run_tracker import RunTracker\n",
    "_tracker = RunTracker(run_id=RUN_ID, log_dir=TRACE_LOG_DIR,\n",
    "                      notebook='STEP_4_All_Models_Training.ipynb')\n",
    "\n",
    "# Expose tracker state and add notebook-level manifest fields\n",
    "_tracker.manifest.update({\n",
    "    'config_profile': getattr(exp_cfg, '_profile', 'unknown'),\n",
    "    'split_ratios': {'train': TRAIN_RATIO, 'val': VAL_RATIO, 'test': TEST_RATIO},\n",
    "    'eval_k_values': EVAL_K_VALUES,\n",
    "})\n",
    "RUN_MANIFEST      = _tracker.manifest\n",
    "RUN_MANIFEST_FILE = _tracker.manifest_file\n",
    "TRACE_LOG_FILE    = _tracker.trace_file\n",
    "\n",
    "# Module-level aliases so all downstream cells work unchanged\n",
    "trace_event       = _tracker.trace_event\n",
    "trace_stage_done  = _tracker.trace_stage_done\n",
    "register_artifact = _tracker.register_artifact\n",
    "\n",
    "trace_stage_done(\n",
    "    'notebook_start',\n",
    "    status='ok',\n",
    "    profile=getattr(exp_cfg, '_profile', 'unknown'),\n",
    ")\n",
    "print(f'[OK] Trace run id: {RUN_ID}')\n",
    "print(f'[OK] Trace log:    {TRACE_LOG_FILE}')\n",
    "print(f'[OK] Run manifest: {RUN_MANIFEST_FILE}')\n",
]

# ----------------------------------------------------------------
# Cell 2bcff0d7: create_temporal_splits / fit_categorical_mapping /
#               apply_categorical_mapping
# Remove 3 function defs; add imports; keep all the rest unchanged
# ----------------------------------------------------------------
idx = find_cell('2bcff0d7')
original = ''.join(cells[idx]['source'])

# Extract everything after the last function definition block
# The function block ends at the first non-def, non-indented line that
# starts with a call:  "train_df, val_df, test_df = create_temporal_splits("
split_marker = "train_df, val_df, test_df = create_temporal_splits("
before, after = original.split(split_marker, 1)

new_call = (
    "from src.features.engineering import fit_categorical_mapping, apply_categorical_mapping\n"
    "from src.utils.temporal import make_temporal_splits_flexible as _make_splits\n"
    "\n"
    "# Implementations are in src/features/engineering.py and src/utils/temporal.py\n"
    "train_df, val_df, test_df = _make_splits(\n"
    "    df,\n"
    "    config={'strategy': 'percentage', 'percentage_split':\n"
    "            {'train': TRAIN_RATIO, 'val': VAL_RATIO, 'test': TEST_RATIO}},\n"
    "    date_col='published',\n"
    ")\n"
)
new_src = new_call + after
cells[idx]['source'] = new_src.splitlines(keepends=True)

# ----------------------------------------------------------------
# Cell 2167505b: compute_ranking_metrics_inline
# Remove function def; add import; keep all the rest unchanged
# ----------------------------------------------------------------
idx = find_cell('2167505b')
original = ''.join(cells[idx]['source'])

old_func = (
    "\ndef compute_ranking_metrics_inline(y_true, scores, k_values):\n"
    "    from sklearn.metrics import ndcg_score, average_precision_score\n"
    "    metrics = {}\n"
    "    sorted_idx = np.argsort(-scores)\n"
    "    y_arr = y_true.values if hasattr(y_true, 'values') else y_true\n"
    "    for k in k_values:\n"
    "        tk = y_arr[sorted_idx[:k]]\n"
    "        metrics[f'Precision@{k}'] = float((tk >= 2).sum() / k)\n"
    "        total_rel = int((y_arr >= 2).sum())\n"
    "        metrics[f'Recall@{k}'] = float((tk >= 2).sum() / total_rel) if total_rel > 0 else 0.0\n"
    "    for k in k_values:\n"
    "        try:\n"
    "            metrics[f'NDCG@{k}'] = float(ndcg_score([y_arr], [scores], k=k))\n"
    "        except Exception:\n"
    "            metrics[f'NDCG@{k}'] = 0.0\n"
    "    try:\n"
    "        y_bin = (y_arr >= 2).astype(int)\n"
    "        metrics['MAP'] = float(average_precision_score(y_bin, scores))\n"
    "    except Exception:\n"
    "        metrics['MAP'] = 0.0\n"
    "    return metrics\n"
)
replacement = (
    "\n# compute_flat_ranking_metrics is in src/evaluation/metrics.py\n"
    "from src.evaluation.metrics import compute_flat_ranking_metrics as compute_ranking_metrics_inline\n"
)
if old_func in original:
    new_src = original.replace(old_func, replacement)
    cells[idx]['source'] = new_src.splitlines(keepends=True)
    print('[OK] Replaced compute_ranking_metrics_inline')
else:
    print('[WARN] compute_ranking_metrics_inline pattern not matched — skipped')

# ----------------------------------------------------------------
# Cell 50809df6: per_group_ndcg
# Remove function def + sklearn import; add src import; keep rest
# ----------------------------------------------------------------
idx = find_cell('50809df6')
original = ''.join(cells[idx]['source'])

old_block = (
    "from sklearn.metrics import ndcg_score\n"
    "\n"
    "\ndef per_group_ndcg(df_in, score_col, label_col='soft_label', group_col='published_week', k=20):\n"
    "    rows = []\n"
    "    for g, part in df_in.groupby(group_col):\n"
    "        if len(part) < 2:\n"
    "            continue\n"
    "        y = part[label_col].values\n"
    "        if (y >= 2).sum() == 0:\n"
    "            continue\n"
    "        s = part[score_col].values\n"
    "        kk = min(k, len(part))\n"
    "        try:\n"
    "            v = float(ndcg_score([y], [s], k=kk))\n"
    "            rows.append((g, v))\n"
    "        except Exception:\n"
    "            continue\n"
    "    return pd.DataFrame(rows, columns=['group', 'ndcg'])\n"
)
replacement = (
    "# per_group_ndcg is in src/evaluation/metrics.py\n"
    "from src.evaluation.metrics import per_group_ndcg\n"
)
if old_block in original:
    new_src = original.replace(old_block, replacement)
    cells[idx]['source'] = new_src.splitlines(keepends=True)
    print('[OK] Replaced per_group_ndcg')
elif 'def per_group_ndcg' in original:
    print('[WARN] per_group_ndcg pattern has minor whitespace diff — check manually')
else:
    print('[WARN] per_group_ndcg not found in cell 50809df6')

with open(NB, 'w') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'\n[OK] Wrote {NB}')
import subprocess
result = subprocess.run(['wc', '-l', NB], capture_output=True, text=True)
print(result.stdout.strip())
