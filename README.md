# enterprise-rag-patterns

[![CI](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml/badge.svg)](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)
[![Python](https://img.shields.io/pypi/pyversions/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)

---

## The problem this solves

Standard RAG implementations retrieve documents and pass them directly to an LLM — with no enforcement of who is allowed to see what. In regulated environments (higher education, healthcare, financial services, government), this creates a structural compliance failure: a student receives another student's records, a patient's ePHI leaks into an unrelated clinical query, prompt injection hides in a retrieved document, and no audit log is produced.

This library provides the **missing compliance layer** — a cross-industry framework of pre-filters, identity scopes, risk assessors, and audit records that enforce regulatory requirements at the retrieval layer, before any document reaches the LLM context window.

**Regulations covered:** FERPA · HIPAA · GDPR · NIST AI RMF · OWASP LLM Top 10

---

## Architecture

```
Session Token
     │
     ▼
StudentIdentityScope
(student_id + institution_id + authorized_categories + disclosure_reason)
     │
     ├─ Vector Store Pre-filter ──────────────────────────────────┐
     │   student_id + institution_id + categories checked here   │
     │   Only authorized documents enter the ranking stage       │
     │                                                            │
     ├─ Policy Layer Filter (defense-in-depth) ──────────────────┤
     │   Application-level identity re-check                     │
     │   Blocks any document that escaped the vector filter      │
     │                                                            │
     ├─ Audit Record ─────────────────────────────────────────────┤
     │   34 CFR § 99.32 Disclosure Log                           │
     │   Emitted before LLM sees any document                    │
     │                                                            │
     └─ LLM Context (authorized documents only) ─────────────────┘
```

**Why pre-filter, not post-filter?** Post-filtering is a UI concern, not a compliance control — the LLM has already processed the unauthorized record. FERPA and HIPAA require that disclosure not occur, not that unauthorized data be hidden after the fact. See [docs/adr/](./docs/adr/) for the full architecture decision record.

---

## Installation

```bash
pip install enterprise-rag-patterns
```

With framework extras:

```bash
pip install 'enterprise-rag-patterns[langchain]'
pip install 'enterprise-rag-patterns[llama-index]'
pip install 'enterprise-rag-patterns[haystack]'
```

---

## 60-second example

```python
from enterprise_rag_patterns.compliance import (
    StudentIdentityScope,
    RecordCategory,
    FERPAContextPolicy,
    DisclosureReason,
)

# Build a verified scope from your session token — never from user input
scope = StudentIdentityScope(
    student_id="stu_001",
    institution_id="univ_abc",
    requesting_user_id="advisor_007",
    authorized_categories={RecordCategory.ACADEMIC_RECORD},
    disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
)
policy = FERPAContextPolicy(scope=scope)

# Your retriever returns docs — filter before the LLM sees them
safe_docs = policy.filter_retrieved_documents(
    retrieved_docs,
    student_id_field="student_id",
    institution_id_field="institution_id",
    category_field="category",
)

# Emit a 34 CFR § 99.32 disclosure log entry
audit = policy.record_access(categories_accessed={RecordCategory.ACADEMIC_RECORD})
print(audit.to_log_entry())
# → {"record_id": "...", "student_id": "stu_001", "regulation": "FERPA",
#    "categories": ["academic_record"], "permitted": true, "timestamp": "..."}
```

See the `examples/` directory for complete runnable pipelines:

| Example | Regulation | What it shows |
|---------|------------|---------------|
| [`ferpa_rag_pipeline.py`](./examples/ferpa_rag_pipeline.py) | FERPA | Four-layer FERPA-compliant pipeline |
| [`05_hipaa_rag_pipeline.py`](./examples/05_hipaa_rag_pipeline.py) | HIPAA | Minimum-necessary ePHI filter + SHA-256 tamper-evidence |
| [`06_owasp_security_scan.py`](./examples/06_owasp_security_scan.py) | OWASP LLM01/LLM02 | PII redaction + prompt injection scan |
| [`07_soc2_cbac_pipeline.py`](./examples/07_soc2_cbac_pipeline.py) | SOC 2 Type II | Multi-tenant CBAC: tenant isolation, confidentiality tiers, role-based access |
| [`08_nist_ai_rmf_assessment.py`](./examples/08_nist_ai_rmf_assessment.py) | NIST AI RMF | MAP/MEASURE/MANAGE risk assessment + incident recording |

---

## Framework integrations

| Framework | Integration Class | Install Extra |
|-----------|------------------|---------------|
| LangChain | `FERPAComplianceCallbackHandler` | `[langchain]` |
| LlamaIndex | `FERPANodePostprocessor` | `[llama-index]` |
| Haystack 2.x | `FERPAHaystackFilter` | `[haystack]` |
| Pinecone | `PineconeComplianceFilter` | `[pinecone]` |
| Weaviate | `WeaviateComplianceFilter` | `[weaviate]` |
| Qdrant | `QdrantComplianceFilter` | `[qdrant]` |
| ChromaDB | `ChromaComplianceFilter` | `[chromadb]` |

---

## Cross-industry compliance coverage

| Regulation / Framework | Status | Primary Sector | RAG Controls |
|------------------------|--------|----------------|--------------|
| FERPA (34 CFR § 99) | ✅ Implemented | Education | Identity scoping, 34 CFR § 99.32 audit log |
| GDPR (Articles 17, 32) | ✅ Implemented | EU / Global | Right-to-erasure, data subject rights |
| HIPAA (45 CFR §§ 164.312, 164.502) | ✅ Implemented | Healthcare | ePHI minimum-necessary, audit controls |
| NIST AI RMF 1.0 + AI 600-1 | ✅ Implemented | All sectors | MAP/MEASURE/MANAGE risk assessment |
| OWASP LLM Top 10 (2025) | ✅ Implemented | Software / AI | LLM01 injection, LLM02 PII disclosure |
| SOC 2 Type II | ✅ Implemented | SaaS / Enterprise | Tenant isolation, CBAC, CC7.2 audit log |
| GLBA (16 CFR § 314) | 🗓 Planned | Financial services | Customer record safeguards |
| EU AI Act | 🗓 Planned | EU / Global | Article 12 tamper-evident audit logs |

### Four-layer defense-in-depth model

```
Layer 0: Query-time security    → OWASP (PII redaction, injection scanning)
Layer 1: Identity scoping       → FERPA / HIPAA (namespace + metadata filter)
Layer 2: Compliance filtering   → FERPA / HIPAA / GDPR (document-level rules)
Layer 3: Risk assessment + audit→ NIST AI RMF / HIPAA (structured audit records)
```

See [`docs/architecture.md`](./docs/architecture.md) for the full layered model.

---

## Repository structure

```
src/enterprise_rag_patterns/
├── compliance.py               # FERPA identity scoping + 34 CFR § 99.32 audit
├── context.py                  # Multi-source context envelope assembly
├── session.py                  # Cross-channel session continuity
├── policy.py                   # Escalation and action-boundary policy objects
├── async_compliance.py         # Async wrappers for asyncio/FastAPI environments
├── regulations/
│   ├── gdpr.py                 # GDPR Article 17 right-to-erasure patterns
│   ├── hipaa.py                # HIPAA ePHI minimum-necessary + audit (NEW)
│   ├── nist_ai_rmf.py          # NIST AI RMF 1.0 + AI 600-1 risk assessment
│   ├── owasp_llm.py            # OWASP LLM Top 10 (2025) — LLM01/LLM02
│   └── soc2.py                 # SOC 2 Type II CBAC — CC6.1/CC6.6/C1.1/CC7.2 (NEW)
├── vector_stores/
│   ├── pinecone_adapter.py     # PineconeComplianceFilter + namespace isolation
│   ├── weaviate_adapter.py     # WeaviateComplianceFilter
│   ├── qdrant_adapter.py       # QdrantComplianceFilter
│   └── chroma_adapter.py       # ChromaComplianceFilter
└── integrations/
    ├── langchain.py            # FERPAComplianceCallbackHandler (LangChain 0.3+)
    ├── langchain_lcel.py       # FERPAFilterRunnable + make_ferpa_chain (LCEL)
    ├── llama_index.py          # FERPANodePostprocessor (LlamaIndex)
    ├── llama_index_workflow.py # FERPAWorkflowStep (LlamaIndex 0.12+ Workflows)
    ├── haystack.py             # FERPAHaystackFilter (Haystack 2.x)
    └── maf.py                  # FERPAAgentMiddleware (Microsoft Agent Framework)
docs/
├── architecture.md             # Four-layer defense-in-depth model
├── adr/                        # Architecture decision records
└── implementation-note-*.md    # Implementation notes
examples/
└── ferpa_rag_pipeline.py       # Complete runnable FERPA-compliant pipeline
```

---

## Published notes

- [Implementation Note 01](./docs/implementation-note-01.md) — Cross-channel continuity problem and solution
- [Implementation Note 02](./docs/implementation-note-02.md) — FERPA boundaries in retrieval-augmented generation
- [Production-Grade RAG in Regulated Enterprise Environments](./docs/articles/production-grade-rag-in-regulated-enterprise-environments.md)

---

## Near-term roadmap

- `regulations/eu_ai_act.py` — EU AI Act Article 12 tamper-evident audit log with cryptographic signing
- `regulations/glba.py` — GLBA Safeguards Rule financial record access controls
- `integrations/crewai.py` — CrewAI policy-gated tool wrapper
- Async vector store adapters for FastAPI/asyncio environments
- ECOSYSTEM.md: compatibility matrix with current ecosystem versions

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines and [GOVERNANCE.md](./GOVERNANCE.md) for the governance model. Run `pytest tests/ -v` to verify your changes before opening a pull request.

---

## Citation

If you use these patterns in research or production, please cite:

```bibtex
@software{rana2026erp,
  author    = {Rana, Ashutosh},
  title     = {enterprise-rag-patterns: FERPA-compliant retrieval-augmented generation patterns},
  year      = {2026},
  url       = {https://github.com/ashutoshrana/enterprise-rag-patterns},
  license   = {MIT}
}
```

Or use GitHub's "Cite this repository" button above (reads `CITATION.cff`).

---

## Part of the enterprise AI patterns trilogy

| Library | Focus | Compliance |
|---------|-------|-----------|
| **enterprise-rag-patterns** | What to retrieve | FERPA, HIPAA, GDPR, NIST AI RMF, OWASP LLM |
| [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) | What agents may do | FERPA, HIPAA, GLBA policy enforcement |
| [integration-automation-patterns](https://github.com/ashutoshrana/integration-automation-patterns) | How data flows | Event-driven enterprise integration |

---

## License

MIT — see [LICENSE](LICENSE).
