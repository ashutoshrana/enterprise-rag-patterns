# Getting Started — enterprise-rag-patterns

This guide walks from a bare Python environment to a running FERPA-compliant RAG pipeline in under 10 minutes.

---

## 1. Install

```bash
pip install enterprise-rag-patterns
```

For framework integrations, add the relevant extra:

```bash
pip install 'enterprise-rag-patterns[langchain]'    # LangChain / LCEL
pip install 'enterprise-rag-patterns[haystack]'     # Haystack 2.x
pip install 'enterprise-rag-patterns[llama-index]'  # LlamaIndex
pip install 'enterprise-rag-patterns[pinecone]'     # Pinecone vector store
pip install 'enterprise-rag-patterns[chromadb]'     # ChromaDB vector store
pip install 'enterprise-rag-patterns[qdrant]'       # Qdrant vector store
pip install 'enterprise-rag-patterns[weaviate]'     # Weaviate vector store
```

Or install `ferpa-haystack` for the standalone Haystack component:

```bash
pip install ferpa-haystack
```

---

## 2. Core concepts

### The pre-filter pattern

Standard RAG pipelines pass all retrieved documents to the LLM. In regulated environments, this is structurally wrong: the LLM context window becomes the unauthorized disclosure.

```
UNSAFE (default):
  Query → Retriever → LLM (sees all docs, including unauthorized ones)

SAFE (this library):
  Query → Retriever → [PRE-FILTER] → LLM (only authorized docs)
```

The pre-filter runs *before* the LLM ever sees a document. This satisfies FERPA 34 CFR §99.31(a)(1) ("legitimate educational interest"), HIPAA 45 CFR §164.502 ("minimum necessary"), and equivalent regulations requiring that disclosure not occur — not merely that unauthorized data be hidden from the UI.

### Document metadata

Documents must carry identity metadata at ingest time. The filter checks this metadata:

```python
doc = {
    "content": "Alice Johnson — GPA: 3.85, Major: Computer Science",
    "metadata": {
        "student_id": "stu_001",
        "institution_id": "univ_abc",
        "category": "academic_record",  # RecordCategory enum value
    }
}
```

Documents without identity metadata (course catalogues, policy handbooks) pass through unchanged — they are shared knowledge-base content.

---

## 3. Quickstart: FERPA filter

```python
from enterprise_rag_patterns.compliance import (
    StudentIdentityScope,
    RecordCategory,
    FERPAContextPolicy,
    DisclosureReason,
)

# Define who the authorized user is and what they may see
scope = StudentIdentityScope(
    student_id="stu_001",
    institution_id="univ_abc",
    requesting_user_id="advisor_007",
    authorized_categories={
        RecordCategory.ACADEMIC_RECORD,
        RecordCategory.FINANCIAL_AID,
    },
    disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
)

policy = FERPAContextPolicy(scope=scope)

# Assume `retrieved_docs` is a list of dicts from your vector store
safe_docs = policy.filter_retrieved_documents(
    retrieved_docs,
    student_id_field="student_id",
    institution_id_field="institution_id",
    category_field="category",
)

# Emit a 34 CFR §99.32 disclosure log entry
audit = policy.record_access(categories_accessed={RecordCategory.ACADEMIC_RECORD})
print(audit.to_log_entry())
# [FERPA_DISCLOSURE] student_id='stu_001' institution_id='univ_abc'
# requesting_user_id='advisor_007' categories_disclosed=['academic_record']
```

---

## 4. LangChain integration

```python
from enterprise_rag_patterns.integrations.langchain import FERPAComplianceCallbackHandler
from langchain_community.vectorstores import Chroma
from langchain_openai import ChatOpenAI

handler = FERPAComplianceCallbackHandler(
    student_id="stu_001",
    institution_id="univ_abc",
    requesting_user_id="advisor_007",
    authorized_categories={"academic_record"},
    audit_sink=lambda rec: write_to_compliance_db(rec),
)

llm = ChatOpenAI(model="gpt-4o", callbacks=[handler])
retriever = vectorstore.as_retriever()
chain = retriever | llm

result = chain.invoke("What is Alice's current GPA?")
```

---

## 5. Haystack 2.x integration

Use the standalone package for a Haystack-native component:

```bash
pip install ferpa-haystack
```

```python
from haystack_integrations.components.filters.ferpa_filter import FERPAMetadataFilter
from haystack import Pipeline

pipeline = Pipeline()
pipeline.add_component("embedder", text_embedder)
pipeline.add_component("retriever", vector_store_retriever)
pipeline.add_component("ferpa_filter", FERPAMetadataFilter(
    student_id="stu_001",
    institution_id="univ_abc",
    authorized_categories=["academic_record", "financial_aid"],
    requesting_user_id="advisor_007",
))
pipeline.add_component("llm", openai_generator)

pipeline.connect("embedder.embedding", "retriever.query_embedding")
pipeline.connect("retriever.documents", "ferpa_filter.documents")
pipeline.connect("ferpa_filter.documents", "llm.documents")

result = pipeline.run({"embedder": {"text": "What is Alice's GPA?"}})
```

---

## 6. HIPAA filter

```python
from enterprise_rag_patterns.regulations.hipaa import (
    HIPAAContextPolicy,
    PHICategory,
    PatientIdentityScope,
)

scope = PatientIdentityScope(
    patient_id="pat_001",
    covered_entity_id="hospital_abc",
    requesting_user_id="dr_jones",
    authorized_phi_categories={PHICategory.CLINICAL_NOTE, PHICategory.LAB_RESULT},
    treatment_relationship=True,
)

policy = HIPAAContextPolicy(scope=scope)
safe_docs = policy.filter_retrieved_documents(
    retrieved_docs,
    patient_id_field="patient_id",
    covered_entity_field="covered_entity_id",
    phi_category_field="phi_category",
)
audit = policy.record_access(categories_accessed={PHICategory.CLINICAL_NOTE})
```

---

## 7. Multi-regulation pipeline

Use `FilterPipeline` to chain multiple compliance layers:

```python
from enterprise_rag_patterns.pipeline import FilterPipeline

pipeline = FilterPipeline()
pipeline.add_filter("ferpa", ferpa_policy)
pipeline.add_filter("hipaa", hipaa_policy)
pipeline.add_filter("owasp", owasp_scanner)

result = pipeline.run(retrieved_docs)
# result.approved_docs   → safe to send to LLM
# result.denied_docs     → with denial reason per regulation
# result.audit_records   → one record per regulation layer
```

---

## 8. Async support

All filters support async use for FastAPI:

```python
from enterprise_rag_patterns.async_compliance import AsyncFERPAContextPolicy

async def handle_query(query: str, student_id: str):
    policy = AsyncFERPAContextPolicy(scope=make_scope(student_id))
    docs = await retriever.aretrieve(query)
    safe_docs = await policy.afilter_retrieved_documents(docs)
    return await llm.agenerate(safe_docs)
```

---

## 9. Example files

The `examples/` directory contains 50 runnable scripts covering every sector and regulation. Good starting points:

| File | What it shows |
|------|---------------|
| `01_basic_ferpa_filter.py` | Minimal FERPA filter |
| `03_langchain_handler.py` | Full LangChain FERPA chain |
| `05_hipaa_rag_pipeline.py` | HIPAA PHI minimum-necessary |
| `08_nist_ai_rmf_assessment.py` | NIST AI RMF risk assessment |
| `50_rag_security_auditor.py` | Full RAG security audit |

Run any example:

```bash
python examples/01_basic_ferpa_filter.py
```

---

## 10. Running tests

```bash
pip install pytest
pytest tests/ -v
```

1,901 tests, all passing. Zero external dependencies required for the test suite.

---

## See also

- [API Reference](./api-reference.md)
- [Regulation Coverage](./regulations.md)
- [Architecture Decision Records](./adr/)
- [Integration with regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) — for agent-level governance on top of retrieval-level filtering
