# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.1] — 2026-04-13

### Added
- `integrations/langchain_lcel.py`: `FERPAFilterRunnable` — LangChain LCEL step that makes FERPA filtering an explicit `Runnable` in the `|` pipe chain. Supports per-request scope injection via `RunnableConfig["metadata"]["ferpa_scope"]`. Closes #25.
- `integrations/langchain_lcel.py`: `make_ferpa_chain()` — factory that wires `retriever | FERPAFilterRunnable | prompt | llm [| output_parser]` in one call.
- `integrations/__init__.py`: exports `FERPAFilterRunnable`, `make_ferpa_chain`

### Fixed
- `integrations/llama_index_workflow.py`: ruff format fix (whitespace normalization)

---

## [0.4.0] — 2026-04-12

### Added
- `integrations/maf.py`: `FERPAAgentMiddleware` — Microsoft Agent Framework (MAF) middleware intercepting agent tool-call messages, applying FERPA identity-scope filtering, emitting 34 CFR § 99.32 audit records. MAF is the enterprise-ready successor to AutoGen and Semantic Kernel (released 2026).
- `integrations/llama_index_workflow.py`: `FERPAWorkflowStep` + `FERPAFilterEvent` — LlamaIndex 0.12+ event-driven Workflow step enforcing FERPA scoping between retrieval and synthesis steps. Compatible with `llama-index-core>=0.12.0` (current: 0.14.20).
- New `[maf]` optional dependency: `microsoft-agent-framework>=1.0.0`

### Changed
- Bumped ecosystem compatibility pins:
  - `llama-index-core`: `>=0.10.0` → `>=0.12.0` (LlamaIndex 0.14.20 current)
  - `haystack-ai`: `>=2.0.0` → `>=2.20.0` (Haystack 2.27.0 current)
  - `pinecone`: `>=3.0.0` → `>=5.0.0` (Pinecone 8.1.2 current; v5 required for async API)
  - `weaviate-client`: `>=4.0.0` → `>=4.10.0` (Weaviate 4.20.5 current)
  - `chromadb`: `>=0.5.0` → `>=1.0.0` (ChromaDB 1.5.7 current; v1.0 is GA)
- `integrations/__init__.py`: exports `FERPAAgentMiddleware`, `FERPAWorkflowStep`, `FERPAFilterEvent`
- `pyproject.toml`: version bumped to 0.4.0; `[all]` extra now includes `[maf]`

---

## [0.3.0] — 2026-04-12

### Added
- Enhanced CI: coverage reporting (Codecov), ruff format check, build-check job, pip cache, concurrency cancellation
- Automation: PR auto-labeler, stale bot, Conventional Commits PR title check, first-contributor welcome bot
- Dependabot; CODEOWNERS; SECURITY.md; pre-commit config; automated release notes
- `integrations/langchain.py`: `FERPAComplianceCallbackHandler` — LangChain callback handler intercepting `on_retriever_end`, applying identity-scope filtering in-place, emitting 34 CFR § 99.32 audit records
- LangChain added as `[langchain]` optional dependency (`langchain-core>=0.3.0`)
- ADRs: `docs/adr/004-pydantic-v2-data-models.md`
- README: badge row, FERPA pipeline ASCII diagram, ecosystem integration table, 60-second quickstart, regulations table, BibTeX citation
- GitHub Discussions enabled; 22 standardized labels (type/*, priority/*, status/*, area/*); milestones v0.3.0 + v1.0.0

---

## [0.2.0] - 2026-04-11

### Added

**Vector store filter adapters** (`src/enterprise_rag_patterns/vector_stores/`):
- `base.py` — `ComplianceFilter` dataclass and `VectorStoreFilterAdapter` ABC; portable filter specification for compliance-scoped vector queries
- `pinecone_adapter.py` — `PineconeComplianceFilter`: builds Pinecone v8 metadata filter dict (`$and` / `$eq` / `$in`) for FERPA/HIPAA scoping
- `weaviate_adapter.py` — `WeaviateComplianceFilter`: builds Weaviate v4 `Filter` object using `Filter.by_property().equal()` and `&` combinator; lazy import
- `qdrant_adapter.py` — `QdrantComplianceFilter`: builds Qdrant `Filter` with `FieldCondition` / `MatchValue` / `MatchAny`; lazy import
- `chroma_adapter.py` — `ChromaComplianceFilter`: builds ChromaDB `where` dict with `$and` / `$eq` / `$in` operators

**Framework integrations** (`src/enterprise_rag_patterns/integrations/`):
- `llama_index.py` — `FERPANodePostprocessor`: LlamaIndex `BaseNodePostprocessor` enforcing student identity scoping; emits 34 CFR § 99.32 audit log entries
- `haystack.py` — `FERPAHaystackFilter`: Haystack 2.x `@component` filtering documents on `meta["student_id"]` and `meta["institution_id"]`; lazy import with `_make_haystack_component()` for pipeline serialisation

**GDPR regulation module** (`src/enterprise_rag_patterns/regulations/`):
- `gdpr.py` — GDPR Article 17 RAG-layer erasure patterns: `ErasureRequest`, `ErasureAuditRecord`, `GDPRRAGPolicy`; supports `filter_for_subject`, `record_erasure`, and `to_log_entry`
- `__init__.py` — exports all GDPR symbols

**Async compliance** (`src/enterprise_rag_patterns/async_compliance.py`):
- `async_filter_retrieved_documents` — async wrapper for `FERPAContextPolicy.filter_retrieved_documents`
- `async_record_access` — async wrapper for `FERPAContextPolicy.record_access`
- Async-wrapper pattern: `await asyncio.sleep(0)` yields to event loop then delegates to synchronous implementation — compatible with all async AI frameworks

**Tests**:
- `tests/test_vector_store_adapters.py` — full coverage of all four adapters; verifies filter structure without real vector store connections
- `tests/test_gdpr.py` — covers `ErasureRequest`, `GDPRRAGPolicy.filter_for_subject`, `record_erasure`, `to_log_entry`
- `tests/test_integrations.py` — covers `FERPAHaystackFilter` and `FERPANodePostprocessor` with duck-typed stubs; no framework import required
- `tests/test_async_compliance.py` — covers `async_filter_retrieved_documents` and `async_record_access` via `asyncio.run`

**Open-source contribution infrastructure**:
- `CONTRIBUTING.md` — comprehensive guide: dev setup, how to add adapters/regulations/integrations, PR checklist with regulatory citation requirement
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1
- `ECOSYSTEM.md` — compatibility matrix for vector stores, frameworks, and regulations
- `.github/ISSUE_TEMPLATE/new-vector-store.md` — issue template for new vector store adapters
- `.github/ISSUE_TEMPLATE/new-regulation.md` — issue template for new regulation modules
- `.github/ISSUE_TEMPLATE/new-framework-integration.md` — issue template for new framework integrations

**Package configuration**:
- `pyproject.toml` — version bumped to `0.2.0`; added optional dependency groups: `llama-index`, `haystack`, `pinecone`, `weaviate`, `qdrant`, `chromadb`, `all`

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
