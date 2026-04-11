# FERPA Compliance in RAG Pipelines: Five Rules Your Enterprise System Probably Breaks

*Originally published on dev.to / Hashnode. Cross-posted here for reference.*

---

You've deployed a RAG (Retrieval-Augmented Generation) pipeline to help students at your university. A student asks about their enrollment status. The LLM gives a confident, accurate answer. Everything looks great.

Then your compliance officer reads the audit log and flags a problem: the context window that produced that answer contained records from three different students — not just the one making the request.

Your RAG pipeline passed every functional test. And it violated FERPA on every single query.

This isn't a hypothetical. It's the default behavior of every general-purpose vector store retrieval system when deployed in a regulated education environment without identity-scoped filtering.

Here are the five FERPA rules that enterprise RAG systems routinely break — and exactly how to fix them.

---

## Rule 1: Similarity alone is not an access control mechanism

The most common RAG architecture retrieves the top-k most semantically similar documents to a query. The problem: semantic similarity has nothing to do with identity authorization.

When a student asks "What are my transfer requirements?", a cosine-similarity search returns the most semantically similar documents in the entire vector store — which may include transfer requirement documents from other students' advising sessions, academic records uploaded during a different student's session, or documents tagged with a different institution entirely.

**What FERPA requires**: 34 CFR § 99.10 gives students the right to inspect their own education records. 34 CFR § 99.30 prohibits disclosure to third parties without consent. "Third party" in this context includes other students. One student's query is a disclosure risk for every other student whose records are in the same vector store.

**The fix**: Filter before retrieval, not after. Apply an identity predicate at the vector store query layer so only documents with matching `student_id` and `institution_id` metadata are eligible for ranking.

```python
from enterprise_rag_patterns.compliance import FERPAContextPolicy, StudentIdentityScope
from enterprise_rag_patterns.vector_stores.pinecone_adapter import PineconeComplianceFilter

scope = StudentIdentityScope(
    student_id="stu-alice",
    institution_id="univ-east",
    authorized_categories={RecordCategory.ACADEMIC_RECORD, RecordCategory.FINANCIAL_RECORD},
)

adapter = PineconeComplianceFilter()
query_filter = adapter.build_filter(scope)
# → {"$and": [{"student_id": {"$eq": "stu-alice"}}, {"institution_id": {"$eq": "univ-east"}}, ...]}

results = index.query(vector=embedding, filter=query_filter, top_k=5)
```

The filter goes into the vector store query — not applied as a post-processing step on results. A post-processing step lets non-authorized documents travel the network and enter your application process. The boundary must be enforced at retrieval time.

---

## Rule 2: Cross-institution contamination is almost guaranteed with shared indexes

Multi-institution deployments routinely share a single vector store across institutions to reduce infrastructure cost. This is an architectural decision that creates a structural FERPA violation unless institution-level metadata filtering is enforced on every single query.

The failure mode is subtle. Documents from Institution A and Institution B share a semantic space. A query for "financial aid appeal process" may return documents from multiple institutions — and if your metadata filter only checks `student_id` but not `institution_id`, a student at one institution can receive documents that originated at another.

**What FERPA requires**: Education records are institution-specific. 34 CFR § 99.1 defines "educational agency or institution" as the unit with the obligation. Cross-institution disclosure is a disclosure to a third party and requires consent under § 99.30.

**The fix**: Always include both `student_id` AND `institution_id` in your compliance filter. Treat them as a compound key. Never query on student_id alone in a multi-institution deployment.

```python
# Wrong: single-institution assumption
filter = {"student_id": {"$eq": "stu-alice"}}

# Right: compound identity predicate
filter = {
    "$and": [
        {"student_id": {"$eq": "stu-alice"}},
        {"institution_id": {"$eq": "univ-east"}},
        {"category": {"$in": ["academic_record", "financial_record"]}},
    ]
}
```

---

## Rule 3: Shared knowledge base documents break the identity boundary

Not every document in your RAG store is student-specific. Institutional knowledge — course catalogs, policy documents, advising guides, financial aid handbooks — is legitimately shared across all students.

The trap: if you enforce a strict `student_id = X` filter on every document in the store, you also filter out the shared knowledge base. Your system then produces answers based only on that student's personal records, with no institutional context.

**The pattern**: Distinguish between identity-scoped documents and institution-level shared documents at ingestion time. Tag every document with its access category:

```python
# Student-specific record — must be identity-filtered
{"student_id": "stu-alice", "institution_id": "univ-east", "category": "academic_record"}

# Institution-level knowledge — accessible to all students at that institution
{"student_id": "__shared__", "institution_id": "univ-east", "category": "policy_document"}
```

Your compliance filter then becomes:

```python
filter = {
    "$or": [
        {
            "$and": [
                {"student_id": {"$eq": "stu-alice"}},
                {"institution_id": {"$eq": "univ-east"}},
            ]
        },
        {
            "$and": [
                {"student_id": {"$eq": "__shared__"}},
                {"institution_id": {"$eq": "univ-east"}},
            ]
        },
    ]
}
```

This is what `enterprise-rag-patterns` calls a `StudentIdentityScope` with `authorized_categories` — the scope governs which identity-owned categories are accessible, while shared documents are accessible by virtue of institution membership.

---

## Rule 4: You must log every disclosure — not every query

RAG systems generate a large volume of retrieval operations. A naive compliance implementation logs every query event, which produces enormous audit trails that are expensive to store and difficult to search.

But 34 CFR § 99.32 doesn't require logging every query. It requires logging every *disclosure* — specifically, every time education records are disclosed to a party other than the student themselves or a school official with legitimate educational interest.

**The practical implication**: For a student-facing system, retrievals within the student's own authorized scope are not disclosures requiring § 99.32 logging. The disclosure log requirement triggers when records cross an identity boundary — staff accessing student records, third-party integrations receiving student data, or cross-student queries (which should never happen but must be caught and logged when attempted).

**The fix**: Structured audit records with a `permitted` flag and a `denial_reason` when boundaries are violated:

```python
from enterprise_rag_patterns.compliance import FERPAContextPolicy, RecordCategory

policy = FERPAContextPolicy(identity_scope=scope)
record = policy.record_access(
    action="read_academic_record",
    categories_accessed=[RecordCategory.ACADEMIC_RECORD],
    context={"query_id": "q-001", "agent": "enrollment-advisor"},
)
# GovernanceAuditRecord with regulation, actor_id, action_name, permitted, timestamp
# → Write to compliance database, not application log
```

Write audit records to a durable compliance store — not your application log. Application logs rotate. Compliance audit trails under FERPA must be retained for as long as the education records themselves are retained.

---

## Rule 5: GDPR erasure requests break RAG — structurally

If your RAG system serves users covered by GDPR (EU students, international students at EU institutions, or any deployment with EU data subjects), you have a structural problem that vector stores were not designed to solve.

Article 17 of GDPR gives data subjects the right to erasure. When a student requests deletion of their data, you must:

1. Delete their records from the source database
2. Remove their document vectors from the vector store
3. Rebuild any affected index structures
4. Confirm deletion within 30 days

Point 3 is the architectural challenge. Most vector stores don't natively support "delete all vectors where metadata.student_id = X and then rebuild the affected portion of the HNSW index." You either delete individual vectors (if you have the vector IDs) or you rebuild the index from scratch.

**The pattern**: Track vector IDs by student identity at ingestion time. Store the mapping `student_id → [vector_id_1, vector_id_2, ...]` in a relational database alongside the FERPA disclosure log. When an erasure request arrives, use that mapping to target precise deletions.

```python
from enterprise_rag_patterns.regulations.gdpr import GDPRRAGPolicy, ErasureRequest

policy = GDPRRAGPolicy()
request = ErasureRequest(subject_id="stu-alice", regulation="GDPR")

# Filter retrieval results to exclude the subject's data
remaining = policy.filter_for_subject(
    documents=retrieved_docs,
    subject_id_field="student_id",
)

# After deletion from source + vector store:
audit = policy.record_erasure(
    request=request,
    removed_count=len(retrieved_docs) - len(remaining),
    index_rebuilt=True,
)
# → ErasureAuditRecord with timestamp, documents_removed, index_rebuilt
```

---

## The architecture that satisfies all five rules

```
Student query (with verified session token)
    │
    ▼
StudentIdentityScope — build compound filter (student_id + institution_id + categories)
    │
    ▼
Vector Store Query — filter applied AT query time, not post-retrieval
    │
    ▼
Compliance Filter — second-pass check on returned documents (defence in depth)
    │
    ▼
Audit Record — structured GovernanceAuditRecord → compliance database
    │
    ▼
LLM Context Assembly — only authorized documents enter context window
```

Two enforcement layers: the vector store filter (fast, removes unauthorized documents before they travel across the network) and the application-layer compliance filter (catches anything that slips through, satisfies defence-in-depth requirements for regulated environments).

The session token supplies `student_id` and `institution_id` — these values must come from the verified authentication system, never from user-supplied input in the query.

---

## Implementation

All patterns described here are implemented in [`enterprise-rag-patterns`](https://github.com/ashutoshrana/enterprise-rag-patterns):

```bash
pip install enterprise-rag-patterns
```

Adapters for Pinecone, Weaviate, Qdrant, and ChromaDB are included. LlamaIndex and Haystack integrations drop in as node postprocessors and pipeline components respectively.

The companion library [`regulated-ai-governance`](https://github.com/ashutoshrana/regulated-ai-governance) provides the policy enforcement and audit layer for AI agents operating across FERPA, HIPAA, GLBA, GDPR, CCPA, and SOC 2 environments.

---

*These patterns are drawn from production deployments in higher-education enterprise AI systems. The implementation is open-source under MIT.*
