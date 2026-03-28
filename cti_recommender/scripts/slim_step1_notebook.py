"""Slim STEP_1 notebook: replace function-definition cells with import+call stubs."""
import json

NB = 'notebooks/STEP_1_Data_Ingestion_Pipeline.ipynb'

with open(NB) as f:
    nb = json.load(f)

cells = nb['cells']

def find_cell(cell_id):
    for i, c in enumerate(cells):
        if c.get('id') == cell_id:
            return i
    raise KeyError(cell_id)

# ----- Setup cell: slim imports, add pipeline_utils import -----
idx = find_cell('b0a018b1')
cells[idx]['source'] = [
    "import sys\n",
    "import os\n",
    "import sqlite3\n",
    "from pathlib import Path\n",
    "import pandas as pd\n",
    "from datetime import datetime, timezone, timedelta\n",
    "from dotenv import load_dotenv\n",
    "import warnings\n",
    "warnings.filterwarnings('ignore')\n",
    "\n",
    "# Load environment variables\n",
    "load_dotenv()\n",
    "\n",
    "# Add project root to path\n",
    "project_root = Path.cwd().parent if 'notebooks' in str(Path.cwd()) else Path.cwd()\n",
    "sys.path.insert(0, str(project_root))\n",
    "\n",
    "# Pipeline functions (ingestion, enrichment, validation, reset)\n",
    "# Full implementations are in src/utils/pipeline_utils.py\n",
    "from src.utils.pipeline_utils import (\n",
    "    check_current_status,\n",
    "    reset_database, reset_cache, reset_all,\n",
    "    fetch_cves_by_date,\n",
    "    enrich_all_cves,\n",
    "    validate_data_quality,\n",
    "    export_enriched_data,\n",
    ")\n",
    "from config.settings import settings\n",
    "\n",
    "print(f'[OK] Project root: {project_root}')\n",
    "print(f'[OK] Database path: {settings.get_database_path()}')\n",
    "print('[OK] Imports successful')\n",
]

# ----- Section 2: check_current_status definition → one-liner call -----
idx = find_cell('b08c4cd9')
cells[idx]['source'] = [
    "# See: src/utils/pipeline_utils.check_current_status\n",
    "check_current_status(project_root)\n",
]

# ----- Section 3: reset functions definition → comment + examples -----
idx = find_cell('42d22f89')
cells[idx]['source'] = [
    "# Reset functions are in src/utils/pipeline_utils.py\n",
    "# Uncomment to run:\n",
    "# reset_database(project_root, confirm=True)\n",
    "# reset_cache(project_root, cache_type='epss', confirm=True)\n",
    "# reset_all(project_root, confirm=True)\n",
    "\n",
    "print('Reset functions loaded. Use with confirm=True to execute.')\n",
]

# ----- Section 4: fetch function definition → preview + usage hint -----
idx = find_cell('4c90b099')
cells[idx]['source'] = [
    "# See: src/utils/pipeline_utils.fetch_cves_by_date\n",
    "\n",
    "end_date = datetime.now(timezone.utc)\n",
    "start_date = end_date - timedelta(days=30)\n",
    "\n",
    "print(f\"Ready to fetch CVEs from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}\")\n",
    "print(\"\\nTo fetch, run:\")\n",
    "print(f\"df = fetch_cves_by_date(project_root, '{start_date.strftime('%Y-%m-%d')}', '{end_date.strftime('%Y-%m-%d')}')\")\n",
]

# ----- Section 5: enrich_all_cves definition → one-liner hint -----
idx = find_cell('75eca415')
cells[idx]['source'] = [
    "# See: src/utils/pipeline_utils.enrich_all_cves\n",
    "# Runs steps: KEV, EPSS, Healthcare, Curated, ATT&CK, CHPL\n",
    "print('Enrichment pipeline loaded. Run: enrich_all_cves(project_root)')\n",
]

# ----- Section 6: validate_data_quality definition → call -----
idx = find_cell('ed296919')
cells[idx]['source'] = [
    "# See: src/utils/pipeline_utils.validate_data_quality\n",
    "validate_data_quality(project_root)\n",
]

# ----- Section 8: export_enriched_data definition → comment -----
idx = find_cell('7f403e16')
cells[idx]['source'] = [
    "# See: src/utils/pipeline_utils.export_enriched_data\n",
    "# Uncomment to export:\n",
    "# export_enriched_data(project_root)\n",
]

with open(NB, 'w') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'[OK] Wrote {NB}')

# Verify
with open(NB) as f:
    nb2 = json.load(f)
for c in nb2['cells']:
    if c['cell_type'] == 'code':
        s = ''.join(c['source'])
        print(f"  id={c.get('id','?')} | {s[:60].replace(chr(10),' ')}")
