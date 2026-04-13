"""
ferpa_rag_pipeline.py — FERPA-Compliant RAG Pipeline Reference Implementation

Demonstrates context.py + session.py + policy.py + compliance.py working
together as a complete FERPA-aware retrieval pipeline.

Scenario: An enrollment advisor AI agent answering a student's question about
their academic standing. The student's records are in a shared vector store
alongside records from other students and shared knowledge base articles.
The pipeline enforces four FERPA requirements:

  1. Session is bound to a specific student + institution before retrieval
  2. Vector store query applies metadata pre-filter (student_id + institution_id)
  3. FERPAContextPolicy applies category-level authorization as a second layer
  4. Every access to protected records generates a 34 CFR § 99.32 audit entry

Run:
    python examples/ferpa_rag_pipeline.py

This example uses a mock vector store and LLM. Replace with your actual
retrieval and generation implementations.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

from enterprise_rag_patterns.compliance import (
    AuditRecord,
    FERPAContextPolicy,
    RecordCategory,
    make_enrollment_advisor_policy,
)
from enterprise_rag_patterns.context import ContextEnvelope, ContextSource
from enterprise_rag_patterns.session import SessionState

# ---------------------------------------------------------------------------
# Mock document store — replace with your actual vector store
# ---------------------------------------------------------------------------

MOCK_DOCUMENTS = [
    {
        "doc_id": "doc-001",
        "student_id": "S-12345",
        "institution_id": "acme-univ",
        "record_category": "academic_record",
        "content": "Student S-12345 has completed 42 of 120 required credits. GPA: 3.4.",
    },
    {
        "doc_id": "doc-002",
        "student_id": "S-99999",  # Different student — will be blocked
        "institution_id": "acme-univ",
        "record_category": "academic_record",
        "content": "Student S-99999 is on academic probation.",
    },
    {
        "doc_id": "doc-003",
        "student_id": "S-12345",
        "institution_id": "acme-univ-b",  # Different institution — will be blocked
        "record_category": "academic_record",
        "content": "ACME University B program records for S-12345 (separate institution).",
    },
    {
        "doc_id": "doc-004",  # No student_id — shared knowledge base, safe to include
        "institution_id": "acme-univ",
        "content": "The BS Business Administration program requires 120 total credits.",
    },
    {
        "doc_id": "doc-005",
        "student_id": "S-12345",
        "institution_id": "acme-univ",
        "record_category": "financial_record",  # Not in authorized_categories — will be blocked
        "content": "Outstanding balance: $2,400.",
    },
]


def mock_vector_search(query: str, student_id: str, institution_id: str) -> list[dict]:
    """
    Mock vector store with metadata pre-filtering.

    In production, use your vector store's native metadata filter:

    Pinecone:   filter={"student_id": {"$eq": student_id}, "institution_id": ...}
    Weaviate:   where filter on student_id and institution_id properties
    pgvector:   WHERE metadata->>'student_id' = $1 AND metadata->>'institution_id' = $2
    Chroma:     where={"$and": [{"student_id": student_id}, {"institution_id": institution_id}]}

    Apply the filter BEFORE semantic ranking — not as a post-processing step.
    """
    return [
        doc
        for doc in MOCK_DOCUMENTS
        if doc.get("student_id") in (student_id, None) and doc.get("institution_id") == institution_id
    ]


def mock_llm_generate(context_text: str, user_query: str) -> str:
    """Mock LLM — replace with your actual generation call."""
    return (
        "Based on the available records: you have completed 42 of 120 required credits "
        "(GPA: 3.4). The BS Business Administration program requires 120 total credits. "
        "You have approximately 78 credits remaining."
    )


# ---------------------------------------------------------------------------
# Audit sink — replace with your durable audit store
# ---------------------------------------------------------------------------

_audit_log: list[AuditRecord] = []


def collect_audit(record: AuditRecord) -> None:
    """In-memory audit sink for this example. Use a durable store in production."""
    _audit_log.append(record)
    print(f"  [AUDIT] {record.to_log_entry()[:120]}...")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


@dataclass
class EnrollmentAdvisorPipeline:
    """
    FERPA-compliant RAG pipeline for enrollment advisor use cases.

    Demonstrates the four-layer enforcement model:
      1. Session binding — student + institution bound at session start
      2. Vector store pre-filter — metadata filter before semantic ranking
      3. Policy layer filter — category authorization + cross-institution block
      4. Audit logging — 34 CFR § 99.32 compliance
    """

    session: SessionState
    ferpa_policy: FERPAContextPolicy

    def run(self, user_query: str) -> dict:
        """Run one query through the FERPA-compliant pipeline."""

        # Step 1: Hash the query for the audit trail (log the hash, not the query)
        query_hash = hashlib.sha256(user_query.encode()).hexdigest()

        # Step 2: Retrieve from vector store with metadata pre-filter
        raw_docs = mock_vector_search(
            query=user_query,
            student_id=self.ferpa_policy.scope.student_id,
            institution_id=self.ferpa_policy.scope.institution_id,
        )

        # Step 3: Apply FERPA policy filter (second enforcement layer)
        safe_docs = self.ferpa_policy.filter_retrieved_documents(raw_docs)

        # Step 4: Log the access (34 CFR § 99.32)
        categories = list({RecordCategory(doc["record_category"]) for doc in safe_docs if "record_category" in doc})
        audit = self.ferpa_policy.record_access(
            categories_accessed=categories,
            workflow_context="enrollment_advisor: graduation status query",
            query_hash=query_hash,
        )

        # Step 5: Assemble context envelope (only safe_docs enter)
        context = ContextEnvelope(
            session_id=self.session.session_id,
            channel=self.session.primary_channel,
            sources=[ContextSource(name="student_records", freshness_seconds=300)],
        )
        for doc in safe_docs:
            context.add_fact(doc["doc_id"], doc["content"])

        # Step 6: Generate response
        context_text = "\n".join(doc["content"] for doc in safe_docs)
        response = mock_llm_generate(context_text, user_query)

        return {
            "response": response,
            "context_docs": [doc["doc_id"] for doc in safe_docs],
            "docs_blocked": len(raw_docs) - len(safe_docs),
            "audit_record_id": audit.record_id,
        }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def main() -> None:
    print("=== FERPA-Compliant RAG Pipeline — Reference Example ===\n")

    # Bind session to student + institution at authentication time
    session = SessionState(
        session_id=str(uuid.uuid4()),
        primary_channel="web_chat",
    )
    session.register_channel("web_chat")
    session.add_checkpoint("authenticated")

    # Build FERPA policy for this student + advisor
    # Authorizes: academic_record + directory_information only
    policy = make_enrollment_advisor_policy(
        student_id="S-12345",
        institution_id="acme-univ",
        advisor_id="agent:enrollment_advisor",
        audit_sink=collect_audit,
    )

    pipeline = EnrollmentAdvisorPipeline(session=session, ferpa_policy=policy)

    user_query = "How many credits do I have left to graduate?"
    print(f"Query: {user_query}\n")

    result = pipeline.run(user_query)

    print(f"\nResponse:\n  {result['response']}")
    print(f"\nDocuments included in context: {result['context_docs']}")
    print(f"Documents blocked by FERPA policy: {result['docs_blocked']}")
    print(f"Audit record ID: {result['audit_record_id']}")
    print(f"\nAudit log entries: {len(_audit_log)}")


if __name__ == "__main__":
    main()
