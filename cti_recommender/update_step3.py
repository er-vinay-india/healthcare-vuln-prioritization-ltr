#!/usr/bin/env python3
import json

with open('notebooks/STEP_3_Feature_Engineering_Labels.ipynb', 'r') as f:
    nb = json.load(f)

descriptions = {
    "## 6. Label Diagnostics": "Analyze the distribution, confidence scores, and quality metrics of constructed weak labels.",
    "## 7. Feature Correlations with Labels": "Compute Pearson correlations between all 53 features and weak labels to identify predictive signal strength.",
    "## 8. Label Quality Analysis": "Evaluate label reliability, multi-signal CVE analysis, and confidence-weighted label quality metrics.",
    "## 9. Save Processed Features": "Export labeled CVE dataset and feature matrix as reusable CSV artifacts for STEP_4 model training.",
    "## 10. Feature Summary Statistics": "Generate descriptive statistics, heatmaps, and comprehensive summaries of feature distributions and engineering results."
}

updated_count = 0
for cell in nb['cells']:
    if cell.get('cell_type') == 'markdown':
        source = cell.get('source', [])
        if isinstance(source, list) and len(source) > 0:
            first_line = source[0].rstrip('\n')
            
            for key, desc in descriptions.items():
                if key in first_line:
                    cell['source'] = [
                        key + "\n",
                        "\n",
                        desc
                    ]
                    updated_count += 1
                    print(f"✓ Updated: {key}")
                    break

with open('notebooks/STEP_3_Feature_Engineering_Labels.ipynb', 'w') as f:
    json.dump(nb, f, indent=1)

print(f"\nTotal sections updated: {updated_count}")
