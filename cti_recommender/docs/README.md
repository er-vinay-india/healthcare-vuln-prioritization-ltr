# Documentation Index

**Last Updated:** February 2026  
**Project Version:** 3.0.0 (Multi-Notebook Architecture)

---

## 🏗️ Architecture Diagrams

Visual representations of the system architecture:

| Diagram | Description | View |
|---------|-------------|------|
| **Project Architecture** | Complete system with notebooks + modules | [SVG](diagrams/project_architecture.svg) |
| **Notebook Pipeline** | 5-stage analysis workflow | [SVG](diagrams/notebook_pipeline.svg) |
| **Data Pipeline** | Data ingestion to evaluation | [SVG](diagrams/data_pipeline.svg) |
| **Evaluation Strategies** | Three evaluation approaches | [SVG](diagrams/evaluation_strategies.svg) |
| **LTR Model** | LambdaMART architecture | [SVG](diagrams/ltr_model.svg) |

> 📝 SVG files are the primary view; Mermaid source (.mmd) is kept in the same folder for edits.

---

## 📚 Core Documentation

### Getting Started
- **[Quick Start Guide](QUICKSTART.md)** - Installation and 5-minute setup
- **[Main README](../README.md)** - Project overview, architecture, results

### Technical Guides
- **[Development Guide](DEVELOPMENT.md)** - Developer setup and contribution
- **[API Documentation](API.md)** - REST API and deployment (if applicable)
- **[Scoring Explanation](SCORING_EXPLANATION.md)** - Weak supervision + confidence weighting

### Research & Analysis
- **[Research Context](RESEARCH_CONTEXT.md)** - Literature review and academic background
- **[Project Review](PROJECT_REVIEW_2026.md)** - Current status and roadmap
- **[Examiner Brief](EXAMINER_BRIEF.md)** - Project summary for evaluation

---

## 📓 Notebook Documentation

The project uses a **5-notebook pipeline** for modularity and clarity:

| Notebook | Purpose | Outputs |
|----------|---------|---------|
| **1. Data Ingestion** | Fetch NVD/KEV/EPSS/ATT&CK/CHPL | SQLite DB (176K CVEs) |
| **2. EDA Analysis** | Exploratory data analysis | Visualizations + insights |
| **3. Feature Engineering** | Extract 16 features + labels | `features_with_labels.csv` |
| **4. Model Training** | LambdaMART + 3 eval strategies | Trained models + metrics |
| **5. Advanced Models** | DiffusionRank, RGCN, ensembles | Advanced comparisons |

**See notebooks in:** [`../notebooks/`](../notebooks/)

---

## 📁 Documentation Structure

```
docs/
├── README.md                    # This file - documentation index
├── QUICKSTART.md               # Installation & setup
├── DEVELOPMENT.md              # Developer guide
├── API.md                      # API documentation
├── SCORING_EXPLANATION.md      # Methodology details
├── RESEARCH_CONTEXT.md         # Literature review
├── PROJECT_REVIEW_2026.md      # Project status
├── EXAMINER_BRIEF.md           # Thesis evaluation summary
├── EXAMINER_PRESENTATION.md    # Presentation notes
├── KT_GUIDE.md                 # Knowledge transfer
├── GPU_SETUP.md                # GPU acceleration setup
│
├── diagrams/                   # 🎨 Architecture diagrams (Mermaid)
│   ├── project_architecture.mmd
│   ├── notebook_pipeline.mmd
│   ├── data_pipeline.mmd
│   ├── evaluation_strategies.mmd
│   └── ltr_model.mmd
│
├── guides/                     # 📖 Detailed guides
│   └── ARCHITECTURE_GUIDE.md   # System architecture details
│

---

## 🎯 Key Documents by Use Case

### I want to...

**...get started quickly**  
→ [QUICKSTART.md](QUICKSTART.md) - 5-minute installation and first run

**...understand the project**  
→ [Main README](../README.md) - Overview, architecture, results

**...run the analysis**  
→ Start with notebooks: `Data_Ingestion` → `EDA` → `Feature_Engineering` → `Model_Training`

**...contribute code**  
→ [DEVELOPMENT.md](DEVELOPMENT.md) - Dev environment, testing, code standards

**...understand the methodology**  
→ [SCORING_EXPLANATION.md](SCORING_EXPLANATION.md) - Weak supervision, confidence weighting

**...see the research background**  
→ [RESEARCH_CONTEXT.md](RESEARCH_CONTEXT.md) - Literature review, problem statement

**...present to thesis committee**  
→ [EXAMINER_BRIEF.md](EXAMINER_BRIEF.md) - Project summary and results

---

## 📦 Data Sources

- **NVD API**: https://nvd.nist.gov/developers - CVE database
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog - Exploited CVEs
- **EPSS**: https://www.first.org/epss/ - Exploit prediction scores
- **MITRE ATT&CK**: https://attack.mitre.org/ - Adversary tactics
- **CHPL**: https://chpl.healthit.gov/ - Healthcare IT products

---

## 📝 Document Updates

**Recent Changes (Feb 2026):**
- ✅ Updated to multi-notebook architecture (5 notebooks)
- ✅ Added three evaluation strategies (temporal + K-fold)
- ✅ Archived migration documents (not production yet)
- ✅ Created new Mermaid diagrams for current architecture
- ✅ Updated README with actual project structure

**Archived Documents:**
- Migration guides (moved to `archive/migration_docs/`)
- Old single-notebook references
- Development artifacts not relevant for final submission

---

## 🤝 Contributing

See [DEVELOPMENT.md](DEVELOPMENT.md) for contribution guidelines.

---

**Need help?** Open an issue or check existing documentation above.
- **LightGBM**: https://lightgbm.readthedocs.io/
- **Learning to Rank**: https://en.wikipedia.org/wiki/Learning_to_rank

---

## Version History

| Version | Date | Status | Documentation |
|---------|------|--------|---------------|
| **2.0.0** | 2026-01-17 | Current | Phase 2 complete - Refactoring & consolidation |
| 1.0.0 | 2025-12-15 | Archived | Phase 1 - Data quality & validation |

---

## Getting Help

- **GitHub Issues**: https://github.com/er-vinay-india/cti-recommender/issues
- **Email**: [your-email]
- **Documentation**: You're looking at it! 📚

---

## Document Maintenance

### Last Review: 2026-01-17

**Reviewed by:** System architect  
**Status:** Up-to-date with Phase 2 refactoring  
**Next review:** After Phase 3 completion

---

- Start with [QUICKSTART.md](QUICKSTART.md) for installation and basic usage.
