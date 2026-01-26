# Documentation Index

**Last Updated:** 2026-01-26  
**CTI Recommender Version:** 2.0.0

---

## Architecture Diagrams

| Diagram | Description |
|---------|-------------|
| [Project Architecture](diagrams/project_architecture.svg) | System components and data flow |
| [Data Pipeline](diagrams/data_pipeline.svg) | End-to-end processing pipeline |
| [LTR Model](diagrams/ltr_model.svg) | Learning-to-Rank model structure |
| [Examiner Flowchart](diagrams/examiner_flowchart.svg) | High-level system overview |

> Mermaid source files available in [diagrams/](diagrams/)

---

## Quick Access

### Getting Started
- **[Quick Start Guide](QUICKSTART.md)** - Installation and basic usage (5-minute setup)
- **[README](../README.md)** - Project overview, features, and current performance

### Technical Documentation
- **[API Documentation](API.md)** - REST API endpoints, Docker deployment, and usage examples
- **[Development Guide](DEVELOPMENT.md)** - Developer setup, coding standards, and contribution guidelines
- **[Architecture Guide](guides/ARCHITECTURE_GUIDE.md)** - System architecture, completed implementations, and technical stack

### Reference
- **[Migration Guide](guides/MIGRATION_GUIDE.md)** - Guide for upgrading from Phase 1 to Phase 2
- **[Research Context](RESEARCH_CONTEXT.md)** - Literature review, research gaps, and academic context

---

## Documentation Structure

```
docs/
├── README.md                    # This file - documentation index
├── QUICKSTART.md               # Installation & basic usage
├── API.md                      # REST API & Docker deployment
├── DEVELOPMENT.md              # Development guide
├── RESEARCH_CONTEXT.md         # Research background
├── diagrams/                   # Architecture diagrams (PNG, SVG, Mermaid)
│   ├── project_architecture.*
│   ├── data_pipeline.*
│   ├── ltr_model.*
│   └── examiner_flowchart.*
├── guides/                     # Technical guides
│   ├── ARCHITECTURE_GUIDE.md
│   └── MIGRATION_GUIDE.md
└── reports/                    # Generated analysis reports
```

---

## Key Documents by Use Case

### I want to...

**...get started quickly**
→ [QUICKSTART.md](QUICKSTART.md) - Step-by-step installation and first run

**...use the REST API**
→ [API.md](API.md) - API endpoints, Docker setup, Swagger UI

**...contribute code**
→ [DEVELOPMENT.md](DEVELOPMENT.md) - Dev environment, testing, code style

**...understand the architecture**
→ [ARCHITECTURE_GUIDE.md](../ARCHITECTURE_GUIDE.md) - System design, modules, completed implementations

**...migrate from older version**
→ [MIGRATION_GUIDE.md](../MIGRATION_GUIDE.md) - Breaking changes, script renames, workflow updates

**...understand the research**
→ [RESEARCH_CONTEXT.md](RESEARCH_CONTEXT.md) - Literature review, problem statement, research gaps

---

## External Resources

### Data Sources
- **NVD API**: https://nvd.nist.gov/developers
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **MITRE ATT&CK**: https://attack.mitre.org/
- **CHPL**: https://chpl.healthit.gov/

### Related Projects
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
