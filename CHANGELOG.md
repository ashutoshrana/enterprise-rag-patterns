# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-04-11

### Added

**Core modules:**
- `context.py` — `ContextEnvelope` and `ContextSource` for context assembly across multiple source systems
- `session.py` — `SessionState` for cross-channel continuity (web, voice, messaging, dashboard)
- `policy.py` — `ActionPolicy` and `EscalationRule` for workflow-safe action boundaries and human escalation
- `compliance.py` — FERPA-aware context governance:
  - `StudentIdentityScope` — defines retrieval boundary per student and institution
  - `FERPAContextPolicy` — two-layer enforcement (pre-filter + category authorization)
  - `AuditRecord` — structured 34 CFR § 99.32 disclosure logging
  - `make_enrollment_advisor_policy` — factory for the most common higher-education RAG use case

**Documentation:**
- `docs/architecture.md` — layered architecture overview with design principles
- `docs/implementation-note-01.md` — cross-channel continuity problem and solution
- `docs/implementation-note-02.md` — FERPA boundaries in retrieval-augmented generation
- `docs/articles/production-grade-rag-in-regulated-enterprise-environments.md`
- `docs/case-study-anonymized.md` — anonymized production deployment notes

**Examples:**
- `examples/context-pipeline.yaml` — declarative context assembly reference
- `examples/ferpa_rag_pipeline.py` — complete runnable FERPA-compliant four-layer RAG pipeline

**Project infrastructure:**
- `CITATION.cff` — enables GitHub "Cite this repository" button
- `CONTRIBUTING.md` — contribution guidance
- `GOVERNANCE.md` — project governance model
- `ROADMAP.md` — near-term development direction
- `pyproject.toml` — setuptools build configuration with keywords, classifiers, and optional dependency groups
- GitHub Actions CI: pytest (Python 3.10–3.12), ruff lint, mypy type check
- Issue templates: bug report, feature request
- 85 passing tests covering all public module APIs
