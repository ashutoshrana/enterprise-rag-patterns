"""
Example 04 — LangChain LCEL chain with FERPA filtering (enterprise-rag-patterns)

Demonstrates ``FERPAFilterRunnable`` as an explicit step in a LangChain LCEL
pipeline. The filter is visible in the chain, traceable in LangSmith, and
accepts per-request scope injection via ``RunnableConfig``.

Requires: pip install 'enterprise-rag-patterns[langchain]'

Run: python examples/04_lcel_ferpa_chain.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Minimal stubs so this example runs without a live LangChain install.
# Replace with real langchain_core imports in production.
# ---------------------------------------------------------------------------


@dataclass
class FakeDocument:
    page_content: str
    metadata: dict[str, Any] = field(default_factory=dict)


class FakeRetriever:
    """Simulates a vector store retriever returning mixed student records."""

    def invoke(self, query: Any, config: Any = None) -> list[FakeDocument]:
        return [
            FakeDocument(
                "Alice enrolled in CS101",
                {"student_id": "alice", "institution_id": "univ_a", "category": "academic_record"},
            ),
            FakeDocument(
                "Bob enrolled in MATH201",
                {"student_id": "bob", "institution_id": "univ_a", "category": "academic_record"},
            ),
            FakeDocument(
                "Alice financial aid: $12,000 grant",
                {"student_id": "alice", "institution_id": "univ_a", "category": "financial_record"},
            ),
            FakeDocument(
                "Shared course catalog",
                {},  # No student_id — shared knowledge base content; passes through
            ),
        ]


# ---------------------------------------------------------------------------
# FERPA setup
# ---------------------------------------------------------------------------

from enterprise_rag_patterns.compliance import RecordCategory, StudentIdentityScope
from enterprise_rag_patterns.integrations.langchain_lcel import FERPAFilterRunnable

audit_log: list[str] = []

# Alice is allowed to see her own academic record, not financial records
alice_scope = StudentIdentityScope(
    student_id="alice",
    institution_id="univ_a",
    authorized_categories={RecordCategory.ACADEMIC_RECORD},
)

ferpa_filter = FERPAFilterRunnable(
    scope=alice_scope,
    audit_sink=lambda rec: audit_log.append(
        f"[AUDIT {datetime.now(timezone.utc).strftime('%H:%M:%S')}] "
        f"student={rec.student_id} docs={rec.documents_retrieved} "
        f"categories={rec.categories_accessed}"
    ),
)

# ---------------------------------------------------------------------------
# Simulate an LCEL chain: retriever | ferpa_filter | (prompt | llm skipped)
# ---------------------------------------------------------------------------

retriever = FakeRetriever()

print("=" * 60)
print("Example 04 — LCEL chain with FERPAFilterRunnable")
print("=" * 60)

# Simulate the retrieval step
raw_docs = retriever.invoke("What courses am I enrolled in?")
print(f"\n[Retriever] Returned {len(raw_docs)} documents (including other students)")

# FERPA filter step — only Alice's academic records pass
filtered_docs = ferpa_filter(raw_docs)
print(f"[FERPA filter] Retained {len(filtered_docs)} authorized documents:")
for doc in filtered_docs:
    meta = doc.metadata
    if meta:
        print(
            f"  ✓ student={meta.get('student_id', 'shared')} "
            f"category={meta.get('category', 'none')} | {doc.page_content[:60]}"
        )
    else:
        print(f"  ✓ (shared knowledge base) | {doc.page_content[:60]}")

print("\n[Audit log]")
for entry in audit_log:
    print(f"  {entry}")

# ---------------------------------------------------------------------------
# Per-request scope injection via RunnableConfig
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("Per-request scope injection (Bob's context)")
print("=" * 60)

bob_scope = StudentIdentityScope(
    student_id="bob",
    institution_id="univ_a",
    authorized_categories={RecordCategory.ACADEMIC_RECORD},
)

bob_docs = ferpa_filter(
    raw_docs,
    config={"metadata": {"ferpa_scope": bob_scope}},  # RunnableConfig override
)
print(f"[FERPA filter] Bob: {len(bob_docs)} authorized documents")
for doc in bob_docs:
    print(f"  ✓ {doc.page_content[:60]}")

print("\nDone. In production, replace FakeRetriever with a vector store retriever")
print("and complete the chain: retriever | ferpa_filter.as_runnable() | prompt | llm")
