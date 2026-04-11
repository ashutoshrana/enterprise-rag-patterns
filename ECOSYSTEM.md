# Ecosystem Coverage

This document maps all verified integrations, adapters, and regulation modules in `enterprise-rag-patterns`. Use it to understand what is production-ready, what is in-progress, and where to contribute.

---

## Vector Store Adapters

| Vector Store | Status | Adapter Class | Min Version | Notes |
|---|---|---|---|---|
| Pinecone | ✅ Implemented | `PineconeComplianceFilter` | `pinecone>=3.0.0` | `$and` filter dict; serverless + pod index compatible |
| Weaviate | ✅ Implemented | `WeaviateComplianceFilter` | `weaviate-client>=4.0.0` | v4 client API; `Filter.by_property()` chaining |
| Qdrant | ✅ Implemented | `QdrantComplianceFilter` | `qdrant-client>=1.9.0` | `Filter(must=[FieldCondition(...)])` with `MatchAny` for categories |
| ChromaDB | ✅ Implemented | `ChromaComplianceFilter` | `chromadb>=0.5.0` | `{"$and": [...]}` where-filter dict |
| PGVector | 🔲 Planned | — | `psycopg2>=2.9` | SQL WHERE clause builder; [contribute →](../../issues/new?template=new-vector-store.md) |
| OpenSearch | 🔲 Planned | — | `opensearch-py>=2.4` | [contribute →](../../issues/new?template=new-vector-store.md) |
| Redis VSS | 🔲 Planned | — | `redis>=5.0` | [contribute →](../../issues/new?template=new-vector-store.md) |

**Adding a new vector store adapter:** see [CONTRIBUTING.md — Adding a Vector Store](CONTRIBUTING.md#adding-a-vector-store-adapter).

---

## Framework Integrations

| Framework | Status | Integration Class | Regulation | Notes |
|---|---|---|---|---|
| LlamaIndex | ✅ Implemented | `FERPANodePostprocessor` | FERPA | NodePostprocessor for `QueryEngine` pipeline |
| Haystack 2.x | ✅ Implemented | `FERPAHaystackFilter` | FERPA | `@component`-compatible; lazy haystack import |
| LangChain | ✅ Implemented | `FERPAComplianceCallbackHandler` | FERPA | `BaseCallbackHandler` on `on_retriever_end` |
| CrewAI | ✅ via regulated-ai-governance | `EnterpriseActionGuard` | FERPA/HIPAA/GLBA | See [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) |
| AutoGen (AG2) | ✅ via regulated-ai-governance | `AutoGenGovernedAgent` | FERPA/HIPAA/GLBA | See [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) |
| Semantic Kernel | ✅ via regulated-ai-governance | `GovernedKernelPlugin` | FERPA/HIPAA/GLBA | See [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) |
| DSPy | 🔲 Planned | — | — | [contribute →](../../issues/new?template=new-framework-integration.md) |
| Pydantic AI | 🔲 Planned | — | — | [contribute →](../../issues/new?template=new-framework-integration.md) |

---

## Regulation Modules (RAG Layer)

| Regulation | Status | Module | Key Classes | Notes |
|---|---|---|---|---|
| FERPA (34 CFR Part 99) | ✅ Implemented | `compliance.py` | `FERPAContextPolicy`, `StudentIdentityScope`, `AuditRecord` | Full two-layer enforcement + 34 CFR § 99.32 audit |
| GDPR Art. 17 (erasure) | ✅ Implemented | `regulations/gdpr.py` | `GDPRRAGPolicy`, `ErasureRequest`, `ErasureAuditRecord` | Erasure tracking at the RAG retrieval layer |
| HIPAA (45 CFR § 164) | ✅ via regulated-ai-governance | — | `make_hipaa_treating_provider_policy()` | Agent-layer PHI access control |
| GLBA (16 CFR § 314) | ✅ via regulated-ai-governance | — | `make_glba_loan_officer_policy()` | Agent-layer NNPI access control |
| CCPA | ✅ via regulated-ai-governance | — | `make_ccpa_consumer_policy()` | Agent-layer consumer data rights |
| SOC 2 Type II | ✅ via regulated-ai-governance | — | `SOC2AuditControl` | Audit control assertions |
| GDPR full | 🔲 Planned | `regulations/gdpr_full.py` | — | Full DSAR workflow, data minimisation, retention; [contribute →](../../issues/new?template=new-regulation.md) |
| FERPA GLBA overlap | 🔲 Planned | — | — | Student financial data at degree-granting institutions |

---

## Async Support

| Feature | Status | Module | Notes |
|---|---|---|---|
| Async filter | ✅ Implemented | `async_compliance.py` | `async_filter_retrieved_documents()` |
| Async audit | ✅ Implemented | `async_compliance.py` | `async_record_access()` |
| Async vector store adapters | 🔲 Planned | `vector_stores/async_*.py` | asyncio-native adapters for Weaviate/Qdrant async clients |

---

## Cloud Provider Examples

| Cloud | Examples | Status |
|---|---|---|
| AWS Bedrock + OpenSearch | `examples/aws_bedrock_ferpa.py` | 🔲 Planned |
| Azure OpenAI + Azure AI Search | `examples/azure_openai_ferpa.py` | 🔲 Planned |
| GCP Vertex AI + Matching Engine | `examples/gcp_vertex_ferpa.py` | 🔲 Planned |
| OpenAI + Pinecone (cloud-agnostic) | `examples/openai_pinecone_ferpa.py` | 🔲 Planned |

---

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and PR guidelines.

Open issues: [github.com/ashutoshrana/enterprise-rag-patterns/issues](https://github.com/ashutoshrana/enterprise-rag-patterns/issues)

Related repos in the trilogy:
- [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) — agent-layer policy enforcement
- [integration-automation-patterns](https://github.com/ashutoshrana/integration-automation-patterns) — enterprise event/sync patterns
