#  Knowledge Transfer Guide - CTI Recommender System
**Easy Explanation for Quick Learning | Exam Ready Guide**

---

##  Table of Contents (Index)
1. [What is this project? (Kya hai yeh?)](#1-what-is-this-project)
2. [Why we need this? (Kyun chahiye?)](#2-why-we-need-this)
3. [How it works? (Kaise kaam karta hai?)](#3-how-it-works)
4. [Key Components (Main parts)](#4-key-components)
5. [Complete Workflow (Poora process)](#5-complete-workflow)
6. [Important Terms (Yaad rakhne wale words)](#6-important-terms)
7. [Exam Questions & Answers](#7-exam-questions--answers)

---

## 1. What is this project? (Kya hai yeh?)

### Simple Answer:
**यह एक Smart Security System है जो hospitals को बताता है कि कौनसी vulnerabilities (कमजोरियां) पहले fix करनी चाहिए।**

### Detailed Answer:
- **Name:** CTI Healthcare Vulnerability Recommender
- **Type:** Machine Learning + Cybersecurity System
- **Target Users:** Healthcare organizations (hospitals, clinics)
- **Main Goal:** Prioritize vulnerabilities (कौनसी security problem पहले solve करें)

### Real-Life Example (याद रखने का तरीका):
```
सोचो तुम्हारे पास 1000 homework questions हैं:
- कुछ easy हैं (low priority)
- कुछ difficult और important हैं (high priority)
- कुछ exam में 100% आएंगे (critical priority)

यह system वही करता है - 226,000 security problems में से सबसे important ones को top पर लाता है!
```

### Memory Technique:
**CTI = "Choose The Important"** vulnerabilities first! [TARGET]

---

## 2. Why we need this? (Kyun chahiye?)

### The Problem (Samasya):

**Traditional System (पुराना तरीका):**
```
सिर्फ CVSS score देखते थे (0-10 number)
Problem: यह बताता नहीं कि actually hackers attack करेंगे या नहीं!

Example:
CVE-2024-1234: CVSS = 9.8 (बहुत high)
लेकिन: कोई hacker attack नहीं कर रहा (not exploited)
```

**Our Solution (हमारा तरीका):**
```
6 sources से data लेते हैं:
1. NVD - सभी CVEs की list
2. CISA KEV - जो actually exploit हो रहे हैं
3. EPSS - exploitation probability (% chance)
4. Healthcare patterns - medical devices में है?
5. ATT&CK - hackers कौनसी techniques use करेंगे
6. CHPL - certified medical products

Result: Smart priority score! [RUN]
```

### Memory Technique:
**Think: "न्यूज़ में सुनो = पहले fix करो"** (If in news/exploited = Fix first)

---

## 3. How it works? (Kaise kaam karta hai?)

### Simple 4-Step Process:

```
Step 1: DATA COLLECTION (Data इकठ्ठा करो)
        ↓
Step 2: ENRICHMENT (Extra info add करो)
        ↓
Step 3: TRAINING (Machine को सिखाओ)
        ↓
Step 4: PREDICTION (Priority बताओ)
```

### Detailed Explanation:

#### Step 1: Data Collection 
```python
# Script: enrich_cves.py
# What it does:
- NVD से last 1 year के CVEs download करता है
- Total: ~226,320 CVEs (2018-2025)
- Time: ~8 minutes

Memory trick: "Download करो, जैसे songs download करते हो"
```

#### Step 2: Enrichment 
```python
# Same script: enrich_cves.py
# What it adds:

1. EPSS Score (0-1)
   - Exploitation probability
   - Example: 0.85 = 85% chance of attack
   - याद रखो: "EPSS = Exam Pass Success Score" (high = dangerous)

2. KEV Check (0/1)
   - CISA Known Exploited Vulnerabilities
   - 1 = already being exploited by hackers
   - याद रखो: "KEV = Known Evil Vulnerability"

3. Healthcare Flag (0/1)
   - Medical device/vendor?
   - Example: Philips, Siemens, Medtronic
   - याद रखो: "Hospital में use hota hai = 1"

4. ATT&CK Techniques
   - Which hacker techniques apply?
   - Example: "Remote Code Execution", "Privilege Escalation"
   - याद रखो: "ATT&CK = Attacker's Technique & Tactics"

5. CHPL Products
   - Certified healthcare IT products
   - 706 products matched
   - याद रखो: "CHPL = Certified Healthcare Product List"

6. Label (0-5)
   - Final priority level
   - 0 = Low, 5 = Emergency
   - याद रखो: "5 = पांच alarm!" 
```

#### Step 3: Training 
```python
# Script: train_ltr.py
# What it does:

Uses LightGBM (Learning to Rank) algorithm
- Input: 14 features (recency, CVSS, KEV, healthcare, etc.)
- Output: Trained model (.pkl file)
- Performance: NDCG@10 = 0.77 (77% accurate)

Memory trick:
"LTR = Learning To Rank (सीखो कि कैसे rank करें)"
```

#### Step 4: Prediction [TARGET]
```python
# Uses trained model
# For new CVE:
1. Extract 14 features
2. Pass through model
3. Get priority score
4. Sort by score
5. Top 20 = Fix first!

Memory trick: "Top 20 = First 20 homework questions करो"
```

---

## 4. Key Components (Main Parts)

### A. Database (SQLite) 

**2 Main Tables:**

**Table 1: cves**
```sql
cve_id       | published | modified | description | cvss
CVE-2024-123 | 2024-01-15| 2024-01-16| Buffer overflow | 9.8

Memory: "CVE = CVE की basic details"
```

**Table 2: enrichments**
```sql
cve_id | in_kev | epss | is_healthcare | label
CVE-123|   1    | 0.85 |      1        |  5

Memory: "Enrichment = Extra masala add kiya!"
```

### B. Scripts (Executable Files) 

**Main 4 Scripts:**

1. **enrich_cves.py** 
   - Purpose: Download + Enrich CVEs
   - Time: ~8 min
   - याद रखो: "Enrich = Ameer banana (add features)"

2. **train_ltr.py**
   - Purpose: Train ML model
   - Time: ~2 min
   - याद रखो: "Train = Machine ko sikhana"

3. **temporal_validation.py**
   - Purpose: Test model accuracy
   - Time: ~5 min
   - याद रखो: "Validation = Exam देना (test karna)"

4. **analyze/** (5 scripts)
   - enrichment_stats.py - Statistics dekho
   - coverage_analysis.py - Coverage check
   - medical_terms.py - Medical vendors
   - ablation_study.py - Feature importance
   - feature_correlation.py - Features ka relation

### C. Source Code (src/) 

**Structure:**
```
src/
├── core/              # Main logic
│   ├── cve_database.py      # Database operations
│   ├── cti_recommender.py   # Scoring engine
│   └── ltr.py               # ML model
├── enrichment/        # Data enrichment
│   ├── attack_mapper.py     # ATT&CK mapping
│   ├── chpl_matcher.py      # CHPL matching
│   ├── kev_checker.py       # KEV checking
│   └── epss_fetcher.py      # EPSS fetching
└── analysis/          # Analysis tools
    └── healthcare_mapping.py # Healthcare detection
```

**Memory Technique:**
```
src/core = दिल (Heart - main logic)
src/enrichment = पेट (Stomach - digestion/processing)
src/analysis = दिमाग (Brain - analysis)
```

---

## 5. Complete Workflow (Poora Process)

### Workflow Diagram (Visual Memory):
```
1. [Download CVEs from NVD]
        ↓
2. [Check KEV - already exploited?]
        ↓
3. [Fetch EPSS - exploitation chance?]
        ↓
4. [Detect healthcare relevance]
        ↓
5. [Map ATT&CK techniques]
        ↓
6. [Match CHPL products]
        ↓
7. [Calculate label (0-5)]
        ↓
8. [Store in database]
        ↓
9. [Train LTR model]
        ↓
10. [Predict top priorities]
```

### Command Flow (Actual Commands):
```bash
# Step 1: Enrich (सबसे पहला काम)
python scripts/data/enrich_cves.py --years 1 --workers 4

# Step 2: Train (Model को सिखाओ)
python scripts/training/train_ltr.py

# Step 3: Validate (Test करो)
python scripts/training/temporal_validation.py

# Step 4: Analyze (Results देखो)
python scripts/analyze/enrichment_stats.py
```

---

## 6. Important Terms (Yaad Rakhne Wale Words)

### A. Security Terms

**CVE (Common Vulnerabilities and Exposures)**
- Unique ID for security bugs
- Format: CVE-YYYY-NNNNN
- Example: CVE-2024-1234
- **याद रखो:** "CVE = Certificate of Vulnerability Entry"

**CVSS (Common Vulnerability Scoring System)**
- Score 0-10
- 9.0-10.0 = Critical
- 7.0-8.9 = High
- 4.0-6.9 = Medium
- 0.1-3.9 = Low
- **याद रखो:** "CVSS = सवाल की difficulty level (out of 10)"

**KEV (Known Exploited Vulnerabilities)**
- CISA's list of actively exploited CVEs
- 1,460+ entries
- **याद रखो:** "KEV = Known Evil (already happening!)"

**EPSS (Exploit Prediction Scoring System)**
- Probability score (0-1)
- Predicts exploitation likelihood
- **याद रखो:** "EPSS = Exam probability (कितना % chance है)"

**ATT&CK (Adversarial Tactics, Techniques & Common Knowledge)**
- Framework of hacker techniques
- 835 techniques total
- **याद रखो:** "ATT&CK = Attacker's playbook"

**CHPL (Certified Health Product List)**
- FDA certified medical products
- 6,900+ products
- **याद रखो:** "CHPL = Certificate wale hospital products"

### B. ML Terms

**LTR (Learning to Rank)**
- ML algorithm for ranking
- Like Google search results
- **याद रखो:** "LTR = Learning To Rank (कौन first, कौन last)"

**NDCG@10 (Normalized Discounted Cumulative Gain)**
- Measures ranking quality
- 0.77 = 77% accurate
- **याद रखो:** "NDCG = Number Denoting Correctness Grade"

**Features (फीचर्स)**
- Input variables for ML model
- 14 features total
- Example: recency, CVSS, KEV flag
- **याद रखो:** "Features = पहचान के लक्षण (identifying marks)"

**Label (लेबल)**
- Target variable (0-5)
- 0 = Low priority
- 5 = Emergency
- **याद रखो:** "Label = Priority tag"

### C. Architecture Terms

**Enrichment (एनरिचमेंट)**
- Adding extra information
- Like adding spices to food
- **याद रखो:** "Enrich = अमीर बनाना (add value)"

**Temporal Validation**
- Testing with time-based splits
- Train on past, test on future
- **याद रखो:** "Temporal = समय के साथ test"

**Ablation Study**
- Remove 1 feature at a time
- See impact on accuracy
- **याद रखो:** "Ablation = एक-एक करके हटाना"

---

## 7. Exam Questions & Answers

### Q1: What is the main purpose of CTI Recommender?
**Answer:**
CTI Recommender is a healthcare vulnerability prioritization system that uses machine learning to rank CVEs based on multiple data sources (NVD, KEV, EPSS, ATT&CK, CHPL). It helps hospitals decide which security vulnerabilities to fix first, reducing risk and optimizing resource allocation.

**Key Points:**
- 6 data sources integrated
- LightGBM LTR algorithm
- 226,320 CVEs in database
- NDCG@10 = 0.77 accuracy
- Targets healthcare organizations

---

### Q2: Explain the enrichment pipeline.
**Answer:**
The enrichment pipeline (enrich_cves.py) is a single-pass process that:

1. **Downloads CVEs** from NVD API (last N years)
2. **Fetches EPSS scores** (exploitation probability)
3. **Checks CISA KEV** (known exploited vulnerabilities)
4. **Detects healthcare relevance** (142 vendor patterns)
5. **Maps ATT&CK techniques** (835 adversary tactics)
6. **Matches CHPL products** (6,900 certified devices)
7. **Calculates labels** (0-5 priority scale)
8. **Stores in SQLite database**

**Time:** ~8 minutes for 1 year of CVEs
**Workflow:** 9 steps -> 4 steps (56% faster than old approach)

---

### Q3: What are the key features used in the ML model?
**Answer:**
The LTR model uses **14 features**:

**1-4: Temporal Features**
- Recency score (newer = higher priority)
- Days since published
- Days since modified
- Age in days

**5-8: Risk Features**
- CVSS score (0-10)
- EPSS score (0-1)
- KEV flag (0/1)
- Label (0-5)

**9-12: Healthcare Features**
- Healthcare flag (0/1)
- CHPL vendor match (0/1)
- CHPL product match (0/1)
- Healthcare vendor flag (0/1)

**13-14: Threat Intelligence**
- ATT&CK technique count
- ATT&CK tactic diversity

**याद रखो:** "TRACE HHH TA" (Temporal, Risk, Attack, Coverage, Exploit + Healthcare)

---

### Q4: How does the system differ from traditional CVSS-based prioritization?
**Answer:**

**Traditional (CVSS-only):**
- Single metric (0-10 score)
- Doesn't consider exploitation
- Ignores healthcare context
- Static scoring

**Our System (Multi-source LTR):**
- 6 authoritative sources
- Real-time exploitation data (KEV, EPSS)
- Healthcare-specific patterns
- ML-based dynamic ranking

**Result:** +27.5% NDCG improvement vs baseline

**Example:**
```
CVE-2024-1234:
- CVSS: 9.8 (Critical)
- EPSS: 0.001 (0.1% chance)
- KEV: No
- Healthcare: No
-> Traditional: #1 priority
-> Our System: #523 priority (low actual risk)
```

---

### Q5: Explain the database schema.
**Answer:**

**Two main tables:**

**Table 1: cves (Basic CVE data)**
```sql
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,      -- CVE-2024-1234
    published TEXT NOT NULL,       -- 2024-01-15
    modified TEXT NOT NULL,        -- 2024-01-16
    description TEXT,              -- Vulnerability description
    cvss REAL                      -- 9.8
);
```

**Table 2: enrichments (Enhanced data)**
```sql
CREATE TABLE enrichments (
    cve_id TEXT PRIMARY KEY,
    in_kev INTEGER DEFAULT 0,           -- 0/1 (CISA KEV)
    kev_date_added TEXT,                -- Date added to KEV
    epss_score REAL,                    -- 0.0-1.0
    is_healthcare INTEGER DEFAULT 0,    -- 0/1
    chpl_product_name TEXT,             -- Product name
    chpl_vendor TEXT,                   -- Vendor name
    attack_techniques TEXT,             -- T1059.001, T1190
    attack_tactics TEXT,                -- Initial Access, Execution
    attack_technique_count INTEGER,     -- Number of techniques
    curated_label INTEGER,              -- Manually labeled (if any)
    healthcare_vendor_flag INTEGER,     -- 0/1
    label INTEGER DEFAULT 0,            -- 0-5 (final priority)
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);
```

**Memory:** "cves = basic info, enrichments = masala"

---

### Q6: What is temporal validation and why is it important?
**Answer:**

**Temporal Validation:**
- Split data by time (not randomly)
- Train on past data (e.g., Jan-Mar)
- Test on future data (e.g., Apr-Jun)
- Simulates real-world usage

**Why Important?**
1. **Prevents data leakage** (no future info in training)
2. **Tests real deployment** (will it work next month?)
3. **Shows time-based trends** (is model deteriorating?)

**Our Results:**
- 3-month windows
- NDCG@5/10/20 per window
- Average NDCG@10 = 0.77

**याद रखो:** "Temporal = टाइम मशीन test (past से सीखो, future में test करो)"

---

### Q7: What optimizations were done in Phase 2?
**Answer:**

**Phase 2 Refactoring (Jan 2026):**

**1. Enrichment Consolidation**
- Before: 6 separate scripts (9 steps)
- After: 1 unified script (4 steps)
- Result: 6x faster, 56% fewer steps

**2. Script Cleanup**
- Before: 24 scripts in main directory
- After: 10 scripts + 5 in analyze/
- Result: 58% reduction

**3. Database Standardization**
- Removed runtime ALTER TABLE migrations
- All columns in CREATE TABLE upfront
- Cleaner schema, no migration issues

**4. Documentation Cleanup**
- Archived 15 historical documents
- Created final-state docs (QUICKSTART, DEVELOPMENT, API)
- Focus on "what it is" vs "what changed"

**Impact:** Maintainability improved by ~60%

---

### Q8: How would you explain the system to a non-technical person?
**Answer:**

**Simple Analogy:**

"Imagine you have 1000 homework problems to solve, but you only have time for 20 today.

**Old way (CVSS):** Sort by difficulty (1-10 marks)
- Problem: A 10-mark question might not be in the exam!

**Our way (CTI Recommender):** Smart sorting
- Check past papers (KEV) - has this appeared before?
- Ask seniors (EPSS) - what's the probability it'll come?
- Check syllabus (Healthcare) - is it relevant to your course?
- Check teacher's hints (ATT&CK) - what topics are emphasized?
- Check solved examples (CHPL) - are there reference solutions?

**Result:** You solve the RIGHT 20 problems that will actually help you score, not just the hardest ones!"

---

### Q9: What are the data sources and their roles?
**Answer:**

| Source | Role | Data Size | Update Frequency |
|--------|------|-----------|------------------|
| **NVD** | Base CVE data | 226,320 CVEs | Daily |
| **CISA KEV** | Known exploited vulns | 1,460 entries | Weekly |
| **EPSS** | Exploitation probability | All CVEs | Daily |
| **Healthcare Patterns** | Medical device detection | 142 patterns | Static |
| **ATT&CK** | Hacker techniques | 835 techniques | Monthly |
| **CHPL** | Certified products | 6,900 products | Weekly |

**Memory Trick (NEK-HAC):**
- **N**VD - Base data
- **E**PSS - Probability
- **K**EV - Known exploits
- **H**ealthcare - Domain
- **A**TT&CK - Techniques
- **C**HPL - Products

---

### Q10: What would you improve next?
**Answer:**

**Phase 3 Roadmap:**

1. **Enhanced ATT&CK weighting**
   - Not all techniques equally dangerous
   - Weight by technique severity

2. **Temporal trend analysis**
   - Track vulnerability patterns over time
   - Predict emerging threats

3. **Vendor risk scoring**
   - Aggregate CVEs by vendor
   - Create vendor security rankings

4. **Real-time updates**
   - API endpoints for live data
   - Automated daily enrichment

5. **Scanner integration**
   - Integrate with Nessus, Qualys
   - Map scan results to priorities

---

## 8. Quick Revision (Last Minute याद करने के लिए)

### 30-Second Pitch:
```
CTI Recommender = Smart vulnerability prioritization for healthcare

- Input: 226K CVEs from 6 sources
- Process: ML-based ranking (LightGBM LTR)
- Output: Top 20 priority CVEs
- Accuracy: NDCG@10 = 0.77
- Benefit: Fix what matters, reduce risk
```

### Key Numbers (Must Remember):
- **226,320** CVEs in database
- **6** data sources (NVD, KEV, EPSS, Healthcare, ATT&CK, CHPL)
- **14** features for ML model
- **0.77** NDCG@10 accuracy
- **4** main scripts (enrich, train, validate, analyze)
- **2** database tables (cves, enrichments)
- **0-5** label scale (Low to Emergency)
- **142** healthcare vendor patterns
- **835** ATT&CK techniques
- **1,460** KEV entries
- **6,900** CHPL products

### Architecture in 5 Points:
1. **Database:** SQLite (cves + enrichments tables)
2. **Enrichment:** 6-source data integration
3. **Training:** LightGBM LTR algorithm
4. **Validation:** Temporal split testing
5. **Analysis:** 5 analysis scripts

### Workflow in 4 Steps:
1. **Enrich** -> python scripts/data/enrich_cves.py
2. **Train** -> python scripts/training/train_ltr.py
3. **Validate** -> python scripts/training/temporal_validation.py
4. **Analyze** -> python scripts/analyze/*.py

---

## 9. Hindi Memory Tricks (याद रखने की तरकीब)

### For 6 Data Sources:
**"नई एक केवी है और चाल"**
- **नई** = NVD (नया data)
- **एक** = EPSS (एक्स्प्लॉइट की संभावना)
- **केवी** = KEV (known evil)
- **है** = Healthcare (हॉस्पिटल)
- **और** = ATT&CK (और techniques)
- **चाल** = CHPL (चालू products)

### For 14 Features:
**"समय का खतरा है अटैक"**
- **समय** = Temporal (4 features)
- **का** = Ka (of)
- **खतरा** = Risk (4 features: CVSS, EPSS, KEV, Label)
- **है** = Healthcare (4 features)
- **अटैक** = ATT&CK (2 features)

### For Workflow:
**"डाउनलोड, सजाओ, सिखाओ, दिखाओ"**
- **डाउनलोड** = Download CVEs
- **सजाओ** = Enrich (decorate with features)
- **सिखाओ** = Train model
- **दिखाओ** = Show results

---

## 10. Common Mistakes to Avoid (Galtiyan)

### [FAIL] Wrong Answers:

1. **"It only uses CVSS scores"**
   - - Correct: Uses 6 data sources including CVSS

2. **"It's just for hospitals"**
   - - Correct: Designed for healthcare but applicable to any domain

3. **"Random forest algorithm"**
   - - Correct: LightGBM (Learning to Rank)

4. **"1000 CVEs"**
   - - Correct: 226,320 CVEs

5. **"Train on future data"**
   - - Correct: Temporal validation (train on past, test on future)

---

## Final Tips for Exam [TARGET]

### If asked about:

**Purpose:** "Healthcare vulnerability prioritization using ML"

**Data:** "226K CVEs from 6 sources (NVD, KEV, EPSS, Healthcare, ATT&CK, CHPL)"

**Algorithm:** "LightGBM Learning to Rank (LTR)"

**Performance:** "NDCG@10 = 0.77 (77% accurate)"

**Workflow:** "Enrich -> Train -> Validate -> Analyze (4 steps)"

**Key Innovation:** "Multi-source intelligence vs single CVSS score"

**Impact:** "+27.5% improvement over baseline, 58% code reduction in Phase 2"

---

## Practice Questions (Khud se karke dekho):

1. Draw the system architecture diagram
2. Explain enrichment pipeline in 2 minutes
3. List all 6 data sources with examples
4. Describe temporal validation
5. What are the 14 features?
6. Database schema (2 tables)
7. Phase 2 improvements
8. Why better than CVSS-only?

---

**अब तुम तैयार हो! All the best for your exam! [RUN]**

**Remember:** Confidence + Clear explanation = Good marks!

**Last minute revision:** Read sections 7 (Q&A) and 8 (Quick Revision) again before exam.

---

**Created:** 2026-01-17  
**Purpose:** Exam preparation guide  
**Time to read:** 30-45 minutes  
**Time to revise:** 10 minutes
