# Research Methodology: Development of a Healthcare-Focused Vulnerability Recommender System

## Project Overview
This project develops a data-driven recommender system for prioritizing cybersecurity vulnerabilities in healthcare contexts. Leveraging multiple threat intelligence sources—National Vulnerability Database (NVD), CISA Known Exploited Vulnerabilities (KEV), MITRE ATT&CK Enterprise techniques, and Certified Health IT Product List (CHPL)—the system integrates features for recency, severity, exploitability, and healthcare relevance. A Learning-to-Rank (LTR) model using LightGBM (LambdaRank) ranks vulnerabilities based on weak supervision labels derived from these sources. The goal is to produce actionable rankings for healthcare stakeholders, emphasizing vulnerabilities likely to impact medical devices, EHR systems, and related infrastructure.

The project evolved from a baseline heuristic scorer to an AI-enhanced system, with iterative additions of data sources, feature engineering, and machine learning. Key metrics include precision@K and NDCG@K for ranking quality, evaluated on held-out test sets. All code is implemented in Python, with reproducible caching and modular design for scalability.

## Data Preparation
Data preparation was foundational, ensuring reliability, freshness, and integration across heterogeneous sources. We adopted a modular ETL (Extract, Transform, Load) approach with caching to handle API rate limits, data volatility, and computational efficiency.

### Extraction and Caching Strategy
- **Sources and APIs**: Data is fetched from REST APIs (NVD v2.0, CHPL /search/v3) and static files (CISA KEV CSV, MITRE ATT&CK JSON). APIs require authentication (e.g., CHPL API-Key header) and pagination to retrieve large datasets.
- **Caching Mechanism**: A TTL-based (Time-To-Live) cache using gzipped pandas pickles stores raw and processed data in `data_cache/` and `data/processed/`. Validity checks prevent redundant fetches, with manual refreshes for updates. Raw API responses are logged for debugging (e.g., CHPL pages saved as JSON).
- **Error Handling and Resilience**: HTTP sessions with retries (up to 3 attempts, exponential backoff) handle transient failures. Fallback endpoints and header variants were implemented for CHPL due to initial API inconsistencies.
- **Volume and Scope**: Initial tests used small windows (30 days, ~5k CVEs); expansions fetched ~17k CVEs over 4 years. Data is normalized to consistent schemas (e.g., CVE IDs, descriptions, timestamps).

### Transformation and Integration
- **Normalization**: Raw JSON/CSV data is flattened into pandas DataFrames with standardized columns (e.g., `cve_id`, `published`, `description_en`, `cvss_v3_base_score`). Missing values are handled via coercion and defaults.
- **Deduplication and Cleaning**: Duplicate CVE IDs are removed; text fields are lowercased for matching. Timestamps are parsed with timezone awareness.
- **Integration**: DataFrames are merged on `cve_id` for feature engineering. External references (e.g., ATT&CK's CAPEC links) are extracted for enrichment.
- **Insights**: This preparation reduced fetch times by 90% via caching and ensured data consistency across sources. Challenges included API key management and date parsing failures in large fetches, leading to 'unknown' groupings in LTR.

## Deep Insights into Added Components
Each component was added iteratively, with feature engineering, evaluation, and tuning. Insights focus on rationale, implementation, performance impacts, and limitations.

### 1. NVD Data Integration (Core Vulnerability Feed)
- **Purpose**: Provides baseline CVE metadata (IDs, descriptions, CVSS scores, publication dates) for scoring.
- **Implementation**: Fetched via chunked API calls (120-day windows) to avoid timeouts. Features include `recency_score` (exponential decay over 180 days) and `cvss_norm` (score/10).
- **Insights**: Recency captures temporal urgency (e.g., recent exploits are prioritized). CVSS provides severity grounding. Performance: Baseline NDCG@20 ~0.623. Limitations: API limits (2k/page) and missing fields (e.g., some CVEs lack descriptions). Expansion to 17k CVEs improved coverage but introduced grouping issues due to date parsing.

### 2. CISA KEV Integration (Exploited Vulnerabilities Signal)
- **Purpose**: Flags actively exploited CVEs for high-priority labeling.
- **Implementation**: CSV fetch with column normalization. Merged on `cve_id` to add `kev_flag` (binary). Weighted at 0.35 in scoring.
- **Insights**: KEV provides ground truth for exploitability, boosting precision@20 by ~10% in tuned models. Weak supervision uses KEV as label=2. Ablation showed removing KEV drops NDCG@20 by 0.1, highlighting its criticality. Limitations: Static list (~1.5k entries) may lag; no temporal decay.

### 3. MITRE ATT&CK Integration (Tactic-Technique Mapping)
- **Purpose**: Maps CVEs to adversarial techniques for contextual relevance.
- **Implementation**: JSON fetch from MITRE CTI repo (~835 techniques). Substring matching on names/aliases (>=4 chars) in descriptions. Added CAPEC IDs from external_references for broader coverage (36 techniques linked).
- **Insights**: Enhances healthcare focus by flagging technique-related exploits (e.g., "process injection"). Tuning w_attack=0.05 improved rankings. Ablation: Removing ATT&CK reduces NDCG@20 minimally, but qualitative analysis shows better attack-aware prioritization. Limitations: Noisy matches (e.g., short keywords); future fuzzy matching could reduce false positives. Improved mapping increased attack_flag to 33.8% of CVEs.

### 4. CHPL Integration (Healthcare Product Matching)
- **Purpose**: Identifies vulnerabilities in certified health IT products.
- **Implementation**: API fetch (~6.9k products) with paging. Substring matching on product/developer names in descriptions. Weighted at 0.08 post-tuning.
- **Insights**: Provides domain-specific signals, boosting healthcare relevance. Grid search optimized weights, improving precision@20. Ablation: CHPL removal affects ~5% of rankings, validating its niche value. Limitations: Exact matching misses variants; API key required. Challenges: Initial 400 errors resolved by correct header usage.

### 5. LightGBM Learning-to-Rank (LTR) Model
- **Purpose**: Learns ranking from weak labels instead of heuristics.
- **Implementation**: LambdaRank objective with NDCG@20 metric. Features: recency, CVSS, KEV/ATT&CK/CHPL flags. Labels: KEV=2, others=1, none=0. Grouped by publication week for ranking contexts.
- **Insights**: Hyperparameter tuning (learning_rate=0.01, num_leaves=20, min_data_in_leaf=10) via CV achieved NDCG@20 ~0.623. Ablation confirmed all features contribute equally. Weak labels enable unsupervised learning from signals. Limitations: Small groups limit CV; future work could use larger datasets or semantic embeddings. Performance matches heuristics but is more adaptable.

## Workflow Description
The end-to-end workflow is modular and reproducible, implemented in Python scripts (`cti_recommender.py`, `ltr.py`, `healthcare_local.py`).

1. **Data Fetching**: Use cached fetchers for NVD, KEV, CHPL, ATT&CK. Refresh if TTL expired.
2. **Feature Engineering**: Call `build_healthcare_features()` to add recency, CVSS, flags via substring matching.
3. **Labeling (LTR)**: Generate weak labels from signals; group by time buckets.
4. **Training/Evaluation**: Train LightGBM on features; evaluate precision/NDCG per group.
5. **Tuning**: Grid search hyperparameters/CV; ablate features.
6. **Scoring and Output**: Compute weighted scores; save top-K CSVs and summaries.
7. **Iteration**: Refine based on metrics (e.g., adjust weights, add data).

This workflow ensures auditable, scalable processing, with outputs in `outputs/` and models in `models/`.

## Progress Summary and Future Directions
Progress includes baseline scoring (NDCG@20=0.623), component integrations, LTR prototype, and tuning. Key insights: Weak signals enable effective ranking; caching/data expansion improves robustness. Challenges: API dependencies, grouping limits. Future: Semantic matching, larger datasets, deployment.

This methodology demonstrates a rigorous, iterative approach to building AI-enhanced cybersecurity tools for healthcare.