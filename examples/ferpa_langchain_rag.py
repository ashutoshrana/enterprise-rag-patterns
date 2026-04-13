"""
FERPA-Compliant RAG with LangChain
====================================
Demonstrates how to use ``FERPAComplianceCallbackHandler`` to enforce
FERPA identity-scope filtering in a LangChain retrieval-augmented generation
(RAG) pipeline.

In this example, stub classes replace the real LangChain components so the
pattern is self-contained and runnable without installing ``langchain-core``.
To use in production, swap the stubs for real LangChain objects.

Regulatory basis:
  34 CFR § 99.31(a)(1) — access control (legitimate educational interest)
  34 CFR § 99.32       — record of disclosures (audit log requirement)

Installation:
    pip install 'enterprise-rag-patterns[langchain]'

Production usage:
    from langchain_community.vectorstores import Chroma          # or any vector store
    from langchain_openai import ChatOpenAI                      # or any LLM
    from langchain.chains import RetrievalQA
    from enterprise_rag_patterns.integrations.langchain import (
        FERPAComplianceCallbackHandler,
    )
    from enterprise_rag_patterns.compliance import (
        DisclosureReason,
        RecordCategory,
        StudentIdentityScope,
    )
"""

from __future__ import annotations

import logging
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

# ---------------------------------------------------------------------------
# Step 1: Build the FERPA scope for this request.
#
# The scope MUST come from the authenticated session — never from the request
# body or user-supplied input. This ensures the identity boundary is set by
# your auth layer, not by user-controlled data.
# ---------------------------------------------------------------------------

from unittest.mock import patch as _patch  # noqa: E402

from enterprise_rag_patterns.compliance import (  # noqa: E402
    AuditRecord,
    DisclosureReason,
    RecordCategory,
    StudentIdentityScope,
)

# Patch the langchain-core availability check so this example runs without
# the optional SDK installed.  Remove this block in production where
# langchain-core is in your dependency tree.
_patch("enterprise_rag_patterns.integrations.langchain._check_langchain_available").__enter__()

from enterprise_rag_patterns.integrations.langchain import (  # noqa: E402
    FERPAComplianceCallbackHandler,
)

# Scope: advisor session scoped to a single student at one institution.
# FERPA § 99.31(a)(1): school official with legitimate educational interest.
scope = StudentIdentityScope(
    student_id="stu_alice",  # from authenticated session token
    institution_id="acme_univ",  # from authenticated session token
    requesting_user_id="advisor_007",  # staff or agent ID
    authorized_categories={
        RecordCategory.ACADEMIC_RECORD,
        RecordCategory.DIRECTORY_INFORMATION,
    },
    disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
)

# ---------------------------------------------------------------------------
# Step 2: Wire up an audit sink (34 CFR § 99.32).
#
# In production, replace this with a durable, student-accessible log store
# (e.g., a database table, Cloud Logging, or a compliance SIEM).
# ---------------------------------------------------------------------------

audit_log: list[AuditRecord] = []


def write_audit_record(record: AuditRecord) -> None:
    """
    Persist the FERPA 34 CFR § 99.32 disclosure record.

    In production: insert into a durable audit database.
    """
    audit_log.append(record)
    print(f"[AUDIT] {record.to_log_entry()}")


# ---------------------------------------------------------------------------
# Step 3: Create the callback handler.
#
# Pass ``audit_sink`` to ensure every retrieval is logged per § 99.32.
# Leave ``raise_on_violation=False`` (default) to silently drop unauthorized
# documents rather than raising an error (preferred for production).
# ---------------------------------------------------------------------------

handler = FERPAComplianceCallbackHandler(
    scope=scope,
    audit_sink=write_audit_record,
    raise_on_violation=False,  # Change to True in strict-enforcement environments
)

# ---------------------------------------------------------------------------
# Step 4: Stub retriever — replace with real vector store retriever.
#
# In production:
#   retriever = chroma_store.as_retriever(callbacks=[handler])
#   # or
#   retriever = pinecone_store.as_retriever(callbacks=[handler])
# ---------------------------------------------------------------------------


class _MockDocument:
    """Stub for langchain_core.documents.Document."""

    def __init__(self, page_content: str, metadata: dict[str, Any]) -> None:
        self.page_content = page_content
        self.metadata = metadata

    def __repr__(self) -> str:
        return f"Document(content={self.page_content!r}, meta={self.metadata})"


class _MockRetriever:
    """
    Stub retriever that simulates a multi-tenant vector store returning
    documents for multiple students. The FERPA handler filters these down
    to only the documents authorized for the current session scope.
    """

    def __init__(self, documents: list[_MockDocument]) -> None:
        self._documents = documents
        self.callbacks: list[Any] = []

    def as_retriever(self, callbacks: list[Any] | None = None) -> _MockRetriever:
        self.callbacks = callbacks or []
        return self

    def invoke(self, query: str) -> list[_MockDocument]:
        """Simulate retrieval: return all docs, then apply callbacks."""
        # Simulate the raw vector search result (unfiltered)
        docs = list(self._documents)
        print(f"\n[RETRIEVER] Raw results for query={query!r}: {len(docs)} documents")

        # Apply callbacks (the FERPA handler filters in-place on_retriever_end)
        for cb in self.callbacks:
            if hasattr(cb, "on_retriever_end"):
                cb.on_retriever_end(docs, workflow_context="enrollment_advisor_rag")

        print(f"[RETRIEVER] After FERPA filter: {len(docs)} documents")
        return docs


# Build a mock document store simulating a shared multi-tenant vector index.
# In a real deployment this might be a Chroma, Pinecone, or pgvector collection.
mock_documents = [
    # Alice's authorized records at ACME University
    _MockDocument(
        "Alice enrolled in Cloud Architecture Spring 2026. GPA: 3.8",
        {"student_id": "stu_alice", "institution_id": "acme_univ", "category": "academic_record"},
    ),
    _MockDocument(
        "Alice Smith — enrolled, Computer Science, Class of 2027",
        {"student_id": "stu_alice", "institution_id": "acme_univ", "category": "directory_information"},
    ),
    # Alice's health record — NOT authorized (health_record not in scope.authorized_categories)
    _MockDocument(
        "Alice Smith — campus health visit, 2026-01-10",
        {"student_id": "stu_alice", "institution_id": "acme_univ", "category": "health_record"},
    ),
    # Bob's record — CROSS-STUDENT leak, must be blocked
    _MockDocument(
        "Bob Jones — academic probation notice",
        {"student_id": "stu_bob", "institution_id": "acme_univ", "category": "academic_record"},
    ),
    # Cross-institution record — must be blocked
    _MockDocument(
        "Alice Smith enrollment record at ACME University B",
        {"student_id": "stu_alice", "institution_id": "acme_univ_b", "category": "academic_record"},
    ),
    # General knowledge base (no FERPA metadata) — always passes through
    _MockDocument(
        "Enrollment deadlines for Spring 2026: registration closes Feb 15.",
        {},
    ),
]

retriever = _MockRetriever(mock_documents).as_retriever(callbacks=[handler])

# ---------------------------------------------------------------------------
# Step 5: Run the retrieval chain.
#
# In production, this is called inside a LangChain RetrievalQA chain or
# similar construct. The FERPA handler fires on_retriever_end automatically.
# ---------------------------------------------------------------------------

query = "What courses is Alice enrolled in and what is her GPA?"
filtered_docs = retriever.invoke(query)

print("\n--- Authorized documents delivered to LLM context ---")
for i, doc in enumerate(filtered_docs, 1):
    print(f"  {i}. {doc.page_content[:80]}...")

print("\n--- Audit log (34 CFR § 99.32 compliance) ---")
for record in audit_log:
    print(f"  - record_id={record.record_id}")
    print(f"    student={record.student_id}, institution={record.institution_id}")
    print(f"    categories={[c.value for c in record.categories_accessed]}")
    print(f"    reason={record.disclosure_reason.value}")

# ---------------------------------------------------------------------------
# Expected output:
#
#   [RETRIEVER] Raw results for query=...: 6 documents
#   [RETRIEVER] After FERPA filter: 3 documents
#
#   Authorized documents:
#     1. Alice enrolled in Cloud Architecture Spring 2026. GPA: 3.8
#     2. Alice Smith — enrolled, Computer Science, Class of 2027
#     3. Enrollment deadlines for Spring 2026: registration closes Feb 15.
#
#   Blocked (silently dropped):
#     - Alice's health_record (unauthorized category)
#     - Bob Jones's record (cross-student)
#     - Alice's ACME University B record (cross-institution)
#
# In production, pass `filtered_docs` as context to your LLM:
#
#   context = "\n\n".join(doc.page_content for doc in filtered_docs)
#   llm_response = llm.invoke(
#       f"Context:\n{context}\n\nQuestion: {query}"
#   )
# ---------------------------------------------------------------------------

assert len(filtered_docs) == 3, f"Expected 3 authorized docs, got {len(filtered_docs)}"
assert len(audit_log) == 1, f"Expected 1 audit record, got {len(audit_log)}"
print("\nAll assertions passed — FERPA filtering working correctly.")
