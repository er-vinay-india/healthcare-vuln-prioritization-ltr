#!/usr/bin/env python3
"""
Create detailed migration mapping for notebook refactoring
"""
import json
from pathlib import Path
from typing import List, Dict

def analyze_cell(cell: Dict, cell_num: int) -> Dict:
    """Extract key information from a cell"""
    source = ''.join(cell.get('source', []))
    first_line = source.split('\n')[0][:80] if source else ''
    
    # Detect cell purpose
    purpose = 'unknown'
    if cell['cell_type'] == 'markdown':
        if source.startswith('##'):
            purpose = 'section_header'
        else:
            purpose = 'documentation'
    elif cell['cell_type'] == 'code':
        source_lower = source.lower()
        if 'import ' in source:
            purpose = 'imports'
        elif 'def ' in source:
            purpose = 'function_definition'
        elif any(kw in source_lower for kw in ['plot', 'fig.show', 'px.', 'plt.']):
            purpose = 'visualization'
        elif 'train' in source_lower or 'fit' in source_lower:
            purpose = 'model_training'
        elif 'evaluate' in source_lower or 'metric' in source_lower:
            purpose = 'evaluation'
        elif 'load' in source_lower or 'read' in source_lower:
            purpose = 'data_loading'
        elif any(kw in source_lower for kw in ['feature', 'engineer']):
            purpose = 'feature_engineering'
        else:
            purpose = 'analysis'
    
    return {
        'cell_num': cell_num,
        'type': cell['cell_type'],
        'purpose': purpose,
        'lines': len(cell.get('source', [])),
        'first_line': first_line,
        'has_functions': 'def ' in source,
        'has_classes': 'class ' in source,
        'content_preview': source[:200].replace('\n', ' ')
    }

def create_migration_map(nb_path: str, notebook_name: str):
    """Analyze notebook and categorize cells for migration"""
    with open(nb_path) as f:
        nb = json.load(f)
    
    cells_info = []
    for i, cell in enumerate(nb['cells']):
        cells_info.append(analyze_cell(cell, i + 1))
    
    return {
        'notebook': notebook_name,
        'total_cells': len(cells_info),
        'code_cells': len([c for c in cells_info if c['type'] == 'code']),
        'markdown_cells': len([c for c in cells_info if c['type'] == 'markdown']),
        'cells': cells_info
    }

def generate_mapping_markdown(advanced_map: Dict, final_map: Dict) -> str:
    """Generate migration mapping document"""
    
    md = ["# Notebook Migration Mapping",
          "",
          "**Date**: 2026-02-23",
          "**Status**: Migration Plan",
          "",
          "---",
          "",
          "## Summary",
          "",
          f"- **CVE_Prioritization_Advanced.ipynb**: {advanced_map['total_cells']} cells "
          f"({advanced_map['code_cells']} code, {advanced_map['markdown_cells']} markdown)",
          f"- **CVE_Prioritization_Final.ipynb**: {final_map['total_cells']} cells "
          f"({final_map['code_cells']} code, {final_map['markdown_cells']} markdown)",
          "",
          "---",
          "",
          "## CVE_Prioritization_Advanced.ipynb → New Notebooks",
          "",
          "| Cell # | Type | Purpose | Content | → Destination | Status |",
          "|--------|------|---------|---------|---------------|--------|"]
    
    # Categorize cells for Advanced notebook
    for cell in advanced_map['cells']:
        dest = categorize_cell_destination(cell)
        status = "✅" if cell['type'] in ['code', 'markdown'] else "⚠️"
        
        md.append(
            f"| {cell['cell_num']} | {cell['type'][:4]} | "
            f"{cell['purpose'][:15]} | {cell['first_line'][:40]} | "
            f"{dest} | {status} |"
        )
    
    md.extend(["", "", "## CVE_Prioritization_Final.ipynb → New Notebooks", "",
               "| Cell # | Type | Purpose | Content | → Destination | Status |",
               "|--------|------|---------|---------|---------------|--------|"])
    
    # Categorize cells for Final notebook
    for cell in final_map['cells']:
        dest = categorize_cell_destination(cell)
        status = "✅" if cell['type'] in ['code', 'markdown'] else "⚠️"
        
        md.append(
            f"| {cell['cell_num']} | {cell['type'][:4]} | "
            f"{cell['purpose'][:15]} | {cell['first_line'][:40]} | "
            f"{dest} | {status} |"
        )
    
    md.extend(["", "", "---", "",
               "## Destination Notebooks", "",
               "1. **Data_Ingestion_Pipeline.ipynb** ✅ Already created",
               "2. **EDA_Analysis.ipynb** - Data loading, visualizations, quality checks",
               "3. **Feature_Engineering.ipynb** - Feature extraction, label construction",
               "4. **Model_Training_And_Evaluation.ipynb** - Training, evaluation, comparison", "",
               "---", "",
               "## Verification Checklist", "",
               "- [ ] All cells accounted for in mapping",
               "- [ ] All functions preserved (notebook or module)",
               "- [ ] All imports present in new notebooks",
               "- [ ] No duplicate content across notebooks",
               "- [ ] Logical flow maintained",
               "- [ ] External outputs configured for plots"])
    
    return '\n'.join(md)

def categorize_cell_destination(cell: Dict) -> str:
    """Determine which new notebook a cell should go to"""
    purpose = cell['purpose']
    content = cell['content_preview'].lower()
    
    # Imports go to the notebook where they're used
    if purpose == 'imports':
        if 'plotly' in content or 'matplotlib' in content:
            return "2_EDA_Analysis"
        elif 'lightgbm' in content or 'xgboost' in content:
            return "4_Model_Training"
        else:
            return "2_EDA_Analysis"  # Default for setup
    
    # Section headers
    if purpose == 'section_header':
        if any(kw in content for kw in ['eda', 'exploration', 'visualization', 'distribution']):
            return "2_EDA_Analysis"
        elif any(kw in content for kw in ['feature', 'label', 'engineering']):
            return "3_Feature_Engineering"
        elif any(kw in content for kw in ['train', 'model', 'evaluation', 'comparison']):
            return "4_Model_Training"
        else:
            return "2_EDA_Analysis"
    
    # Code cells by purpose
    if purpose == 'data_loading':
        return "2_EDA_Analysis"
    elif purpose == 'visualization':
        return "2_EDA_Analysis"
    elif purpose == 'feature_engineering':
        return "3_Feature_Engineering"
    elif purpose in ['model_training', 'evaluation']:
        return "4_Model_Training"
    elif purpose == 'function_definition':
        # Check if it should go to module instead
        if cell['has_functions']:
            return "→ src/module (refactor)"
        return "3_Feature_Engineering"
    else:
        return "2_EDA_Analysis"  # Default

if __name__ == '__main__':
    # Analyze both notebooks
    advanced_map = create_migration_map(
        'notebooks/CVE_Prioritization_Advanced.ipynb',
        'CVE_Prioritization_Advanced'
    )
    
    final_map = create_migration_map(
        'notebooks/CVE_Prioritization_Final.ipynb',
        'CVE_Prioritization_Final'
    )
    
    # Generate mapping document
    mapping_md = generate_mapping_markdown(advanced_map, final_map)
    
    # Save to file
    output_path = Path('docs/NOTEBOOK_MIGRATION_MAP.md')
    output_path.write_text(mapping_md)
    
    print(f"✓ Migration mapping created: {output_path}")
    print(f"\nSummary:")
    print(f"  Advanced: {advanced_map['total_cells']} cells")
    print(f"  Final: {final_map['total_cells']} cells")
    print(f"  Total to migrate: {advanced_map['total_cells'] + final_map['total_cells']} cells")
