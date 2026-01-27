#!/usr/bin/env python3
"""
Model Comparison Script

Executes the advanced models notebook and generates a comprehensive
performance comparison report.

Usage:
    python scripts/compare_models.py [--output-dir outputs/]

Author: Vinayk Sharma
Date: January 27, 2026
"""

import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import nbformat
from nbconvert.preprocessors import ExecutePreprocessor
import pandas as pd


def execute_notebook(notebook_path: Path, output_path: Path = None, timeout: int = 3600):
    """
    Execute a Jupyter notebook and optionally save the output.
    
    Args:
        notebook_path: Path to input notebook
        output_path: Path to save executed notebook (optional)
        timeout: Cell execution timeout in seconds
        
    Returns:
        Executed notebook object
    """
    print(f"📖 Reading notebook: {notebook_path}")
    with open(notebook_path, 'r') as f:
        nb = nbformat.read(f, as_version=4)
    
    print(f"🏃 Executing notebook (timeout={timeout}s)...")
    print(f"   Total cells: {len(nb.cells)}")
    
    ep = ExecutePreprocessor(timeout=timeout, kernel_name='python3')
    
    start_time = time.time()
    try:
        ep.preprocess(nb, {'metadata': {'path': str(notebook_path.parent)}})
        execution_time = time.time() - start_time
        print(f"✅ Notebook executed successfully in {execution_time:.1f}s")
    except Exception as e:
        print(f"❌ Notebook execution failed: {e}")
        raise
    
    # Save executed notebook
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            nbformat.write(nb, f)
        print(f"💾 Saved executed notebook to: {output_path}")
    
    return nb


def extract_results_from_notebook(nb):
    """
    Extract performance metrics from executed notebook cells.
    
    Args:
        nb: Executed notebook object
        
    Returns:
        Dictionary with extracted results
    """
    results = {
        'baseline': {},
        'diffusion': {},
        'rgcn': {},
        'ensemble': {},
        'metadata': {
            'execution_date': datetime.now().isoformat(),
            'cells_executed': len([c for c in nb.cells if c.cell_type == 'code']),
        }
    }
    
    # Look for cells with performance metrics
    for cell in nb.cells:
        if cell.cell_type == 'code' and 'outputs' in cell:
            for output in cell.outputs:
                if 'text' in output:
                    text = output['text']
                    # Parse NDCG/Precision metrics
                    if 'NDCG@' in text or 'Precision@' in text:
                        # Extract metrics (simplified parser)
                        for line in text.split('\n'):
                            if ':' in line:
                                metric, value = line.split(':', 1)
                                metric = metric.strip()
                                try:
                                    value = float(value.strip())
                                    # Categorize by model
                                    if 'Baseline' in cell.source:
                                        results['baseline'][metric] = value
                                    elif 'DiffusionRank' in cell.source:
                                        results['diffusion'][metric] = value
                                    elif 'RGCN' in cell.source:
                                        results['rgcn'][metric] = value
                                    elif 'Ensemble' in cell.source:
                                        results['ensemble'][metric] = value
                                except ValueError:
                                    continue
    
    return results


def generate_comparison_report(results: dict, output_path: Path):
    """
    Generate a comprehensive comparison report.
    
    Args:
        results: Performance metrics dictionary
        output_path: Path to save report
    """
    print(f"📊 Generating comparison report...")
    
    report = f"""# Model Comparison Results

**Execution Date:** {results['metadata']['execution_date']}  
**Cells Executed:** {results['metadata']['cells_executed']}

---

## Performance Summary

### Baseline (LambdaRank)
{format_metrics_table(results.get('baseline', {}))}

### DiffusionRank
{format_metrics_table(results.get('diffusion', {}))}

### RGCN
{format_metrics_table(results.get('rgcn', {}))}

### Ensemble
{format_metrics_table(results.get('ensemble', {}))}

---

## Key Findings

1. **Best Model:** TBD (analyze metrics above)
2. **Improvement over Baseline:** TBD
3. **Recommended for Production:** TBD

---

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(report)
    
    print(f"✅ Report saved to: {output_path}")


def format_metrics_table(metrics: dict) -> str:
    """Format metrics as markdown table."""
    if not metrics:
        return "_No metrics available_"
    
    table = "| Metric | Value |\n|--------|-------|\n"
    for metric, value in sorted(metrics.items()):
        table += f"| {metric} | {value:.4f} |\n"
    
    return table


def main():
    parser = argparse.ArgumentParser(description='Compare CVE prioritization models')
    parser.add_argument(
        '--notebook',
        type=Path,
        default=project_root / 'notebooks' / 'CVE_Prioritization_Advanced.ipynb',
        help='Path to notebook'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=project_root / 'outputs',
        help='Output directory for results'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=3600,
        help='Cell execution timeout (seconds)'
    )
    parser.add_argument(
        '--skip-execution',
        action='store_true',
        help='Skip notebook execution (use existing results)'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("CVE PRIORITIZATION - MODEL COMPARISON")
    print("=" * 70)
    print()
    
    # Execute notebook
    executed_nb_path = args.output_dir / 'CVE_Prioritization_Advanced_executed.ipynb'
    
    if not args.skip_execution:
        nb = execute_notebook(
            notebook_path=args.notebook,
            output_path=executed_nb_path,
            timeout=args.timeout
        )
        
        # Extract results
        print()
        print("📈 Extracting performance metrics...")
        results = extract_results_from_notebook(nb)
        
        # Save results as JSON
        results_json_path = args.output_dir / 'model_comparison_results.json'
        with open(results_json_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to: {results_json_path}")
    else:
        print("⏭️  Skipping notebook execution (--skip-execution)")
        # Load existing results
        results_json_path = args.output_dir / 'model_comparison_results.json'
        if results_json_path.exists():
            with open(results_json_path, 'r') as f:
                results = json.load(f)
        else:
            print("❌ No existing results found")
            return 1
    
    # Generate report
    print()
    report_path = args.output_dir / 'model_comparison_final.md'
    generate_comparison_report(results, report_path)
    
    print()
    print("=" * 70)
    print("✅ MODEL COMPARISON COMPLETE")
    print("=" * 70)
    print()
    print(f"📁 Outputs:")
    print(f"   - Executed notebook: {executed_nb_path}")
    print(f"   - Results JSON: {results_json_path}")
    print(f"   - Comparison report: {report_path}")
    print()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
