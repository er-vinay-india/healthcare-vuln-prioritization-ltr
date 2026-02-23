#!/usr/bin/env python3
"""
Clear outputs from Jupyter notebooks to reduce file size
"""
import json
import sys
from pathlib import Path

def clear_notebook_outputs(notebook_path):
    """Clear all cell outputs from a notebook"""
    with open(notebook_path, 'r') as f:
        nb = json.load(f)
    
    cells_cleared = 0
    for cell in nb['cells']:
        if cell['cell_type'] == 'code':
            if cell.get('outputs') or cell.get('execution_count'):
                cell['outputs'] = []
                cell['execution_count'] = None
                cells_cleared += 1
    
    with open(notebook_path, 'w') as f:
        json.dump(nb, f, indent=1)
    
    return cells_cleared

if __name__ == '__main__':
    notebooks = [
        'notebooks/CVE_Prioritization_Final.ipynb',
        'notebooks/CVE_Prioritization_Advanced.ipynb'
    ]
    
    for nb_path in notebooks:
        path = Path(nb_path)
        if path.exists():
            print(f"Clearing outputs from: {nb_path}")
            cleared = clear_notebook_outputs(path)
            print(f"  ✓ Cleared {cleared} code cells")
            
            # Check new size
            with open(path) as f:
                lines = len(f.readlines())
            print(f"  ✓ New size: {lines:,} lines\n")
        else:
            print(f"  ⚠️  Not found: {nb_path}\n")
