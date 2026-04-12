# enterprise-rag-patterns

[![CI](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml/badge.svg)](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)
[![Python](https://img.shields.io/pypi/pyversions/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)

---

## The problem this solves

Standard RAG implementations retrieve documents and pass them directly to an LLM — with no enforcement of who is allowed to see what. In regulated environments (higher education, healthcare, financial services), this creates a structural compliance failure: a student can receive another student's records, a financial aid record can leak into an enrollment query, and no disclosure log is produced. This library provides the missing layer — an identity-scoped pre-filter that restricts what enters the LLM context window based on verified session identity, authorized record categories, and institution, with every access producing a 34 CFR § 99.32-compliant audit record before any generation occurs.

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

See [`examples/ferpa_rag_pipeline.py`](./examples/ferpa_rag_pipeline.py) for a complete runnable pipeline.

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

## Regulations supported

| Regulation | Status | Scope |
|------------|--------|-------|
| FERPA (34 CFR § 99) | Implemented | Student education records, disclosure log |
| GDPR Art. 17 | Implemented | Right to erasure, data subject scope |
| HIPAA (45 CFR § 164) | Planned | PHI access control and audit |
| GLBA (16 CFR § 314) | Planned | Customer financial record safeguards |

---

## Repository structure

```
src/enterprise_rag_patterns/
├── compliance.py        # FERPA-scoped pre-filter + 34 CFR § 99.32 audit log
├── context.py           # Context envelope and source assembly patterns
├── session.py           # Cross-channel session continuity scaffolding
└── policy.py            # Escalation and action-boundary policy objects
docs/
├── architecture.md
├── implementation-note-01.md   # Cross-channel continuity problem and solution
├── implementation-note-02.md   # FERPA boundaries in retrieval-augmented generation
├── articles/
├── adr/                        # Architecture decision records
└── case-study-anonymized.md
examples/
├── context-pipeline.yaml
└── ferpa_rag_pipeline.py       # Complete runnable FERPA-compliant pipeline
```

---

## Published notes

- [Implementation Note 01](./docs/implementation-note-01.md) — Cross-channel continuity problem and solution
- [Implementation Note 02](./docs/implementation-note-02.md) — FERPA boundaries in retrieval-augmented generation
- [Production-Grade RAG in Regulated Enterprise Environments](./docs/articles/production-grade-rag-in-regulated-enterprise-environments.md)

---

## Near-term roadmap

- Add architecture decision records for cross-channel continuity
- Publish a reference event flow for system-of-record synchronization
- Add policy examples for human escalation thresholds
- Document anonymized implementation lessons from production-style operating environments
- HIPAA and GLBA compliance module implementations

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

| Library | Focus | Regulation |
|---------|-------|-----------|
| **enterprise-rag-patterns** | What to retrieve | FERPA identity-scoped RAG |
| [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) | What agents may do | FERPA, HIPAA, GLBA policy enforcement |
| [integration-automation-patterns](https://github.com/ashutoshrana/integration-automation-patterns) | How data flows | Event-driven enterprise integration |

---

## License

MIT — see [LICENSE](LICENSE).
