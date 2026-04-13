# Implementation Note 02: FERPA Boundaries in Retrieval-Augmented Generation

Most RAG tutorials stop at retrieval quality. A standard RAG walkthrough asks: how well does the system find relevant documents? That is the right question for a demo.

In a FERPA-regulated environment, it is the wrong first question. The right first question is: what records may this system retrieve, for whom, and under what conditions?

This note documents the design principles behind FERPA-aware RAG architecture. The implementation is in `src/enterprise_rag_patterns/compliance.py`. A working example is in `examples/ferpa_rag_pipeline.py`.

---

## What FERPA requires, concisely

FERPA (20 U.S.C. § 1232g; implementing regulations at 34 CFR Part 99) grants students rights over their education records held by institutions receiving federal funding. The key operational requirements for AI systems are:

**1. Access control at the record level (not just the system level)**
Authenticating a user into the system is insufficient. Access must be controlled at the individual record level, scoped to the student and record type.

**2. Legitimate educational interest required (34 CFR § 99.31(a)(1))**
A school official may access student records only when there is a legitimate educational interest in doing so. AI agents acting as school officials must have this purpose defined before retrieval begins — not inferred during the interaction.

**3. Disclosure records required (34 CFR § 99.32)**
Institutions must maintain a record of each request for access to education records and the stated reason. In a RAG pipeline, this means audit logging is not optional. Every retrieval that touches protected records must generate a tamper-evident audit entry.

**4. Student-scoped retrieval required**
The retrieval query that feeds the LLM context window must be constrained to the records of the specific student whose session is active. A pipeline that retrieves the top-k most relevant records across all students, then filters by relevance, does not satisfy FERPA. The boundary filter must be applied before retrieval ranking, not after.

---

## Where standard RAG architectures fail under FERPA

### Problem 1: The relevance-before-identity pattern

Most vector search implementations rank by semantic similarity across the entire index, then return the top-k results. If the index contains records from many students, a query about "missed coursework" may retrieve semantically relevant records from multiple students — ranked by relevance, not by identity.

A FERPA-compliant pipeline must apply a metadata filter (`student_id = X AND institution_id = Y`) as a pre-filter, before semantic ranking. This is supported by all major vector databases (Pinecone, Weaviate, Chroma, pgvector) via metadata filtering, but requires explicit implementation at design time.

### Problem 2: Cross-institution contamination

Multi-institution deployments — a platform serving multiple universities from shared infrastructure — must enforce institution-level data isolation. A session authenticated for institution A must not surface records tagged to institution B, even if the records are semantically relevant.

This boundary is easy to miss when a shared knowledge base contains institution-agnostic content (policy documents, course catalogs, general FAQs) alongside institution-specific student records. The policy layer must classify each document at index time and enforce boundaries at retrieval time.

### Problem 3: Prompt-layer filtering is insufficient

A common pattern is to retrieve broadly and then add a system prompt instruction such as "Only discuss information relevant to [student name]." This does not satisfy FERPA. The records have already entered the LLM context window. The filter must prevent records from entering context in the first place — not attempt to suppress them afterward.

### Problem 4: No audit trail

A RAG pipeline that retrieves records without logging who accessed what, when, and why does not satisfy 34 CFR § 99.32. Audit logging in enterprise RAG is architecturally different from application logging — it must be correlated to the specific student, the retrieval query hash, and the workflow context, and must be available to students on request.

---

## Design rules for FERPA-compliant RAG

### Rule 1: Identity scope before retrieval

Establish the `StudentIdentityScope` — student, institution, authorized record categories, legitimate educational interest reason — before the retrieval query is constructed. The scope is an input to the retrieval function, not a filter applied to its output.

```python
from enterprise_rag_patterns.compliance import (
    StudentIdentityScope, RecordCategory, DisclosureReason
)

scope = StudentIdentityScope(
    student_id="S-12345",
    institution_id="acme-univ",
    requesting_user_id="agent:enrollment_advisor",
    authorized_categories={RecordCategory.ACADEMIC_RECORD},
    disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
)
```

### Rule 2: Apply metadata filter at the vector store level

Pass the student_id and institution_id as metadata filters to the vector store query, not as post-retrieval filters. This prevents ineligible records from ranking or appearing in results.

```python
# Example with metadata-filtered vector store query
results = vector_store.similarity_search(
    query=user_query,
    filter={
        "student_id": scope.student_id,
        "institution_id": scope.institution_id,
    },
    k=5,
)
```

### Rule 3: Pass results through the policy layer before context assembly

After retrieval and before the results are assembled into the context envelope, pass them through `FERPAContextPolicy.filter_retrieved_documents()`. This catches any documents that bypassed the vector store filter and enforces category-level authorization.

```python
from enterprise_rag_patterns.compliance import FERPAContextPolicy

policy = FERPAContextPolicy(scope=scope, audit_sink=audit_logger)
safe_docs = policy.filter_retrieved_documents(raw_results)
# Only safe_docs enter the ContextEnvelope
```

### Rule 4: Log every access to protected records

After each successful retrieval of protected records, call `policy.record_access()` with the categories accessed and workflow context. Store audit records durably — not in rotated application logs, but in a store accessible to students and institutional auditors.

```python
audit = policy.record_access(
    categories_accessed=[RecordCategory.ACADEMIC_RECORD],
    workflow_context="enrollment advisor: graduation audit query",
    query_hash=sha256_of_query,
)
# audit.to_log_entry() produces a structured log line for institutional systems
```

### Rule 5: Scope escalation requires explicit re-authorization

If a workflow step requires access to a record category not in the initial scope, the scope must be explicitly upgraded with a new legitimate educational interest reason. The system must not silently expand the retrieval scope mid-session.

---

## Architecture pattern summary

```
[User / Agent Request]
        |
        v
[Identity Scope Construction]  ← Define student, institution, authorized categories
        |
        v
[Vector Store Query]           ← Apply metadata filter (student_id + institution_id)
        |
        v
[FERPAContextPolicy.filter()]  ← Second-layer enforcement, category authorization
        |
        v
[Audit Record Creation]        ← 34 CFR § 99.32 compliance, durable storage
        |
        v
[Context Envelope Assembly]    ← Only authorized, filtered documents enter LLM context
        |
        v
[LLM Generation]
```

---

## Multi-tenant deployment note

In deployments serving multiple institutions from shared infrastructure, institution boundary enforcement requires two additional steps beyond the retrieval filter:

1. **Index-time tagging:** Every document in the vector index must be tagged with its originating institution at ingest time. Documents without an institution tag should be classified as `institution_id = "shared"` for non-PII knowledge base content.

2. **Session-level institution binding:** The session must bind to a single institution at authentication time. A session authenticated for institution A must not be reused for institution B within the same session context.

---

## Reference

- FERPA statute: 20 U.S.C. § 1232g
- FERPA regulations: 34 CFR Part 99
- Key provisions: § 99.3 (definitions), § 99.31 (legitimate educational interest), § 99.32 (record of disclosures)
- Implementation: [`src/enterprise_rag_patterns/compliance.py`](../src/enterprise_rag_patterns/compliance.py)
- Working example: [`examples/ferpa_rag_pipeline.py`](../examples/ferpa_rag_pipeline.py)
