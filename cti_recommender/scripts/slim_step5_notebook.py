"""Slim STEP_5 notebook: replace inline function defs with src/ imports."""
import json

NB = 'notebooks/STEP_5_Model_Comparison_And_Evaluation.ipynb'

with open(NB) as f:
    nb = json.load(f)

cells = nb['cells']

def find_cell(cell_id):
    for i, c in enumerate(cells):
        if c.get('id') == cell_id:
            return i
    raise KeyError(cell_id)


# ----------------------------------------------------------------
# Cell 067ebfc4: per_group_ndcg (returns np.array, uses GROUP_COL)
# Replace the 8-line definition with a 3-line adapter that delegates
# to the canonical implementation in src/evaluation/metrics.py.
# ----------------------------------------------------------------
idx = find_cell('067ebfc4')
original = ''.join(cells[idx]['source'])

old_block = (
    "from src.evaluation.metrics import ndcg_at_k\n"
    "\n"
    "def per_group_ndcg(df_in, score_col, k=20):\n"
    "    scores = []\n"
    "    for _, g in df_in.groupby(GROUP_COL):\n"
    "        if len(g) >= 2 and g[LABEL_COL].sum() > 0:\n"
    "            scores.append(ndcg_at_k(g[LABEL_COL].values, g[score_col].values, k))\n"
    "    return np.array(scores)\n"
)
replacement = (
    "# per_group_ndcg (DataFrame variant) lives in src/evaluation/metrics.py\n"
    "from src.evaluation.metrics import per_group_ndcg as _per_group_ndcg_df\n"
    "\n"
    "# Local adapter: returns numpy array of per-group NDCG values (needed for Wilcoxon)\n"
    "def per_group_ndcg(df_in, score_col, k=20):\n"
    "    return _per_group_ndcg_df(df_in, score_col=score_col,\n"
    "                              label_col=LABEL_COL, group_col=GROUP_COL, k=k)['ndcg'].values\n"
)
if old_block in original:
    new_src = original.replace(old_block, replacement)
    cells[idx]['source'] = new_src.splitlines(keepends=True)
    print('[OK] Replaced per_group_ndcg in cell 067ebfc4')
else:
    print('[WARN] per_group_ndcg block not matched in 067ebfc4 — skipped')

# ----------------------------------------------------------------
# Cell 6e348b3d: cliffs_delta + per_group_ndcg (DataFrame version)
# Both now live in src/ — replace with imports.
# ----------------------------------------------------------------
idx = find_cell('6e348b3d')
original = ''.join(cells[idx]['source'])

old_funcs = (
    "def cliffs_delta(x, y):\n"
    "    x = np.asarray(x)\n"
    "    y = np.asarray(y)\n"
    "    if len(x) == 0 or len(y) == 0:\n"
    "        return np.nan\n"
    "    gt = sum((xi > yj) for xi in x for yj in y)\n"
    "    lt = sum((xi < yj) for xi in x for yj in y)\n"
    "    return (gt - lt) / (len(x) * len(y))\n"
    "\n"
    "\n"
    "def per_group_ndcg(df_in, score_col, label_col='soft_label', group_col='published_week', k=20):\n"
    "    out = []\n"
    "    for g, part in df_in.groupby(group_col):\n"
    "        if len(part) < 2:\n"
    "            continue\n"
    "        y = part[label_col].values\n"
    "        if (y >= 2).sum() == 0:\n"
    "            continue\n"
    "        s = part[score_col].values\n"
    "        kk = min(k, len(part))\n"
    "        try:\n"
    "            from sklearn.metrics import ndcg_score\n"
    "            out.append((g, float(ndcg_score([y], [s], k=kk))))\n"
    "        except Exception:\n"
    "            continue\n"
    "    return pd.DataFrame(out, columns=['group', 'ndcg'])\n"
)
replacement = (
    "# Implementations moved to src/ modules\n"
    "from src.evaluation.significance import cliffs_delta\n"
    "from src.evaluation.metrics import per_group_ndcg\n"
)
if old_funcs in original:
    new_src = original.replace(old_funcs, replacement)
    cells[idx]['source'] = new_src.splitlines(keepends=True)
    print('[OK] Replaced cliffs_delta + per_group_ndcg in cell 6e348b3d')
else:
    print('[WARN] cliffs_delta/per_group_ndcg block not matched in 6e348b3d — skipped')

with open(NB, 'w') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'\n[OK] Wrote {NB}')
import subprocess
result = subprocess.run(['wc', '-l', NB], capture_output=True, text=True)
print(result.stdout.strip())
