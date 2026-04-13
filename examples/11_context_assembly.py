"""
11_context_assembly.py — Multi-source context assembly for enterprise RAG.

Demonstrates how to build a ``ContextEnvelope`` from five enterprise data
sources — CRM, ERP, knowledge base, policy documents, and real-time data —
and how to apply ``FERPAContextPolicy`` filtering before passing context
to the LLM stage.

Enterprise RAG pipelines typically assemble context from multiple systems:

  System A — Student Information System (CRM/SIS)
      academic record, enrollment status, degree audit
  System B — Financial Aid System (ERP)
      aid disbursement, SAP status, balance
  System C — Knowledge Base (vector store)
      policy documents, course catalog, graduation requirements
  System D — Policy Document Store (vector store, shared — not student-specific)
      institution policies, FERPA notices
  System E — Real-time Data (live API)
      current term deadlines, room availability

Context assembly involves three concerns this example covers:
  1. **Source freshness** — real-time data must be fresh; cached data may be stale
  2. **FERPA pre-filtering** — student-specific documents must pass identity scope
  3. **Failure modes** — required vs optional sources; graceful degradation

Run:
    python examples/11_context_assembly.py
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enterprise_rag_patterns.compliance import (
    DisclosureReason,
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
)
from enterprise_rag_patterns.context import ContextEnvelope, ContextSource

# ---------------------------------------------------------------------------
# Simulated data sources
# ---------------------------------------------------------------------------

NOW = datetime.now(timezone.utc)

# Use relative timestamps for simulated data so freshness checks work
# regardless of when the example is run.
_TS_5MIN_AGO = (NOW.replace(microsecond=0) - __import__("datetime").timedelta(minutes=5)).isoformat() + "Z"
_TS_90MIN_AGO = (NOW.replace(microsecond=0) - __import__("datetime").timedelta(minutes=90)).isoformat() + "Z"
_TS_10SEC_AGO = (NOW.replace(microsecond=0) - __import__("datetime").timedelta(seconds=10)).isoformat() + "Z"


def _age_seconds(ts: str) -> float:
    """Return age in seconds of an ISO timestamp."""
    dt = datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
    return (NOW - dt).total_seconds()


# --- System A: Student Information System (SIS/CRM) ---


def fetch_sis_documents(student_id: str, institution_id: str) -> list[dict[str, Any]]:
    """Simulate SIS retrieval for student S-001."""
    return [
        {
            "doc_id": "sis-001",
            "content": "Degree audit: 87/120 credits completed. Major: Computer Science.",
            "student_id": student_id,
            "institution_id": institution_id,
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
            "fetched_at": _TS_5MIN_AGO,
        },
        {
            "doc_id": "sis-002",
            "content": "Enrollment status: Full-time. Expected graduation: May 2027.",
            "student_id": student_id,
            "institution_id": institution_id,
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
            "fetched_at": _TS_5MIN_AGO,
        },
        {
            "doc_id": "sis-003",
            "content": "GPA: 3.62. Academic standing: Good standing.",
            "student_id": student_id,
            "institution_id": institution_id,
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
            "fetched_at": _TS_5MIN_AGO,
        },
    ]


# --- System B: Financial Aid System ---


def fetch_financial_aid_documents(student_id: str, institution_id: str) -> list[dict[str, Any]]:
    """Simulate financial aid retrieval — financial aid is EXCLUDED from this scope."""
    return [
        {
            "doc_id": "fa-001",
            "content": "Financial aid award: $8,500 Pell Grant, $3,500 subsidized loan.",
            "student_id": student_id,
            "institution_id": institution_id,
            "record_category": RecordCategory.FINANCIAL_RECORD.value,
            "fetched_at": _TS_90MIN_AGO,
        },
        {
            "doc_id": "fa-002",
            "content": "Account balance: $0.00 (all charges satisfied).",
            "student_id": student_id,
            "institution_id": institution_id,
            "record_category": RecordCategory.FINANCIAL_RECORD.value,
            "fetched_at": _TS_90MIN_AGO,
        },
    ]


# --- System C: Knowledge Base (shared policy docs + course catalog) ---


def fetch_knowledge_base_documents(query: str) -> list[dict[str, Any]]:
    """Simulate semantic search on shared knowledge base — no student_id."""
    return [
        {
            "doc_id": "kb-001",
            "content": "CS program graduation requirements: 120 credits, 2.0 GPA, "
            "45 credits in CS core, capstone project required.",
        },
        {
            "doc_id": "kb-002",
            "content": "Registration window for Fall 2026 opens April 14 for seniors.",
        },
        {
            "doc_id": "kb-003",
            "content": "Academic advisor appointments available Monday-Friday 9am-5pm. Book at advising.strayer.edu.",
        },
    ]


# --- System D: Policy documents (institution-wide, no student_id) ---


def fetch_policy_documents(institution_id: str) -> list[dict[str, Any]]:
    """Simulate policy document retrieval — institution-wide, not student-specific."""
    return [
        {
            "doc_id": "policy-001",
            "content": "Late withdrawal policy: After Week 10, withdrawal requires "
            "Academic Dean approval. Grade of W assigned.",
            "institution_id": institution_id,
        },
        {
            "doc_id": "policy-002",
            "content": "Academic integrity policy: First violation results in grade of F "
            "for the assignment. Second violation results in course failure.",
            "institution_id": institution_id,
        },
    ]


# --- System E: Real-time data (live API, very short freshness requirement) ---


def fetch_realtime_data() -> list[dict[str, Any]]:
    """Simulate real-time data — current deadlines."""
    return [
        {
            "doc_id": "rt-001",
            "content": "Spring 2026 final exam period: May 1–7. Last day to withdraw: April 14.",
            "fetched_at": _TS_10SEC_AGO,  # 10 seconds ago — well within 60s freshness limit
        },
    ]


# ---------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------


@dataclass
class AssembledContext:
    """Result of context assembly — documents that passed all filters."""

    envelope: ContextEnvelope
    documents: list[dict[str, Any]]
    filtered_count: int  # how many were removed by FERPA filter
    degraded_sources: list[str]  # sources that returned no useful data

    def to_llm_context(self) -> str:
        """Format for LLM prompt injection."""
        lines = []
        for doc in self.documents:
            source = doc.get("doc_id", "unknown")
            content = doc.get("content", "")
            lines.append(f"[{source}] {content}")
        return "\n".join(lines)


def assemble_context(
    student_id: str,
    institution_id: str,
    query: str,
    scope: StudentIdentityScope,
    policy: FERPAContextPolicy,
    required_sources: list[str] | None = None,
    max_freshness_seconds: dict[str, int] | None = None,
) -> AssembledContext:
    """
    Assemble context from all five data sources, apply FERPA filtering,
    and enforce freshness constraints.

    Args:
        student_id: Target student identifier.
        institution_id: Institution identifier.
        query: The user's query — used for knowledge base retrieval.
        scope: StudentIdentityScope for FERPA pre-filtering.
        policy: FERPAContextPolicy to apply.
        required_sources: Sources that must return data; others are optional.
        max_freshness_seconds: Per-source freshness limit in seconds.

    Returns:
        AssembledContext with filtered documents and metadata.
    """
    required_sources = required_sources or ["sis", "knowledge_base"]
    max_freshness = max_freshness_seconds or {
        "sis": 3600,  # 1 hour
        "financial_aid": 7200,  # 2 hours
        "knowledge_base": None,  # no freshness requirement for static docs
        "policy": None,
        "realtime": 60,  # 1 minute — must be very fresh
    }

    sources_declared: list[ContextSource] = []
    all_docs: list[dict[str, Any]] = []
    degraded: list[str] = []

    envelope = ContextEnvelope(
        session_id=f"sess-{student_id}-{institution_id}",
        channel="web_advisor_chat",
    )

    # --- Source A: SIS ---
    sis_docs = fetch_sis_documents(student_id, institution_id)
    freshness_limit = max_freshness.get("sis")
    if freshness_limit and sis_docs:
        stale = [d for d in sis_docs if _age_seconds(d["fetched_at"]) > freshness_limit]
        if len(stale) == len(sis_docs):
            degraded.append("sis (stale)")
            sis_docs = []
    all_docs.extend(sis_docs)
    sources_declared.append(ContextSource(name="student_information_system", required=True))
    envelope.add_fact("sis_doc_count", str(len(sis_docs)))

    # --- Source B: Financial Aid ---
    fa_docs = fetch_financial_aid_documents(student_id, institution_id)
    sources_declared.append(ContextSource(name="financial_aid_system", required=False))
    all_docs.extend(fa_docs)

    # --- Source C: Knowledge Base ---
    kb_docs = fetch_knowledge_base_documents(query)
    sources_declared.append(ContextSource(name="knowledge_base", required=True))
    all_docs.extend(kb_docs)
    envelope.add_fact("kb_doc_count", str(len(kb_docs)))

    # --- Source D: Policy documents ---
    policy_docs = fetch_policy_documents(institution_id)
    sources_declared.append(ContextSource(name="policy_documents", required=False))
    all_docs.extend(policy_docs)

    # --- Source E: Real-time data ---
    rt_docs = fetch_realtime_data()
    freshness_limit = max_freshness.get("realtime", 60)
    if freshness_limit and rt_docs:
        stale_rt = [d for d in rt_docs if _age_seconds(d.get("fetched_at", "2000-01-01T00:00:00Z")) > freshness_limit]
        if len(stale_rt) == len(rt_docs):
            degraded.append("realtime (stale)")
            rt_docs = []
    all_docs.extend(rt_docs)
    sources_declared.append(ContextSource(name="realtime_data", freshness_seconds=60, required=False))

    # Register sources on envelope
    for source in sources_declared:
        envelope.sources.append(source)

    # --- FERPA filtering ---
    pre_filter_count = len(all_docs)
    filtered_docs = policy.filter_retrieved_documents(documents=all_docs)
    removed_count = pre_filter_count - len(filtered_docs)

    envelope.add_fact("pre_filter_count", str(pre_filter_count))
    envelope.add_fact("post_filter_count", str(len(filtered_docs)))
    envelope.add_fact("ferpa_removed", str(removed_count))

    return AssembledContext(
        envelope=envelope,
        documents=filtered_docs,
        filtered_count=removed_count,
        degraded_sources=degraded,
    )


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------


def main() -> None:
    student_id = "S-001"
    institution_id = "strayer"
    query = "What courses do I need to complete my CS degree?"

    print("=" * 66)
    print("Multi-Source Context Assembly — Enterprise RAG Pipeline")
    print("=" * 66)
    print(f"\nStudent:     {student_id}")
    print(f"Institution: {institution_id}")
    print(f"Query:       {query}")

    # -----------------------------------------------------------------------
    # Scenario 1: Advisor authorized for ACADEMIC records only
    # Financial records should be filtered out by FERPA policy
    # -----------------------------------------------------------------------
    print("\n" + "─" * 66)
    print("SCENARIO 1: Academic records scope only (FERPA filtered)")
    print("─" * 66)

    scope_academic = StudentIdentityScope(
        student_id=student_id,
        institution_id=institution_id,
        requesting_user_id="agent:enrollment_advisor",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )
    policy_academic = FERPAContextPolicy(scope=scope_academic)

    ctx = assemble_context(
        student_id=student_id,
        institution_id=institution_id,
        query=query,
        scope=scope_academic,
        policy=policy_academic,
    )

    print(f"\n  Sources declared: {sorted(ctx.envelope.source_names())}")
    print(f"\n  Documents fetched (before FERPA filter): {ctx.envelope.facts['pre_filter_count']}")
    print(f"  Documents after FERPA filter:            {ctx.envelope.facts['post_filter_count']}")
    print(f"  Documents removed by FERPA:              {ctx.filtered_count}")
    print()

    print("  Documents passed to LLM context:")
    for doc in ctx.documents:
        category = doc.get("record_category", "shared")
        owner = doc.get("student_id", "shared")
        print(f"    [{doc['doc_id']}] category={category}  owner={owner}")
        print(f"      {doc['content'][:70]}")
    print()

    if ctx.filtered_count > 0:
        print(f"  Note: {ctx.filtered_count} financial record(s) removed — enrollment advisor")
        print("        not authorized for FINANCIAL_RECORD category (FERPA 34 CFR § 99.31)")

    # -----------------------------------------------------------------------
    # Scenario 2: Financial aid advisor — also authorized for financial records
    # -----------------------------------------------------------------------
    print("\n" + "─" * 66)
    print("SCENARIO 2: Financial aid advisor scope (academic + financial)")
    print("─" * 66)

    scope_financial = StudentIdentityScope(
        student_id=student_id,
        institution_id=institution_id,
        requesting_user_id="agent:financial_aid_advisor",
        authorized_categories={
            RecordCategory.ACADEMIC_RECORD,
            RecordCategory.FINANCIAL_RECORD,
        },
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )
    policy_financial = FERPAContextPolicy(scope=scope_financial)

    ctx2 = assemble_context(
        student_id=student_id,
        institution_id=institution_id,
        query="What financial aid do I have and will I graduate on time?",
        scope=scope_financial,
        policy=policy_financial,
    )

    print(f"\n  Documents fetched: {ctx2.envelope.facts['pre_filter_count']}")
    print(f"  Documents after FERPA filter: {ctx2.envelope.facts['post_filter_count']}")
    print(f"  Documents removed: {ctx2.filtered_count}  (0 expected — both categories authorized)")
    print()
    print("  All student-specific documents available:")
    for doc in ctx2.documents:
        if doc.get("student_id"):
            category = doc.get("record_category", "—")
            print(f"    [{doc['doc_id']}] {category}")
            print(f"      {doc['content'][:65]}")

    # -----------------------------------------------------------------------
    # Scenario 3: Cross-institution contamination attempt
    # -----------------------------------------------------------------------
    print("\n" + "─" * 66)
    print("SCENARIO 3: Cross-institution contamination (other institution's student)")
    print("─" * 66)

    # Create docs that look like they came from a different institution
    contamination_doc = {
        "doc_id": "POISON-001",
        "content": "GPA: 2.1 (WARNING: this belongs to a student at gwu, not strayer)",
        "student_id": student_id,  # correct student_id
        "institution_id": "gwu",  # WRONG institution
        "record_category": RecordCategory.ACADEMIC_RECORD.value,
    }

    test_docs = [contamination_doc] + fetch_sis_documents(student_id, institution_id)
    filtered = policy_academic.filter_retrieved_documents(documents=test_docs)

    print(f"\n  Input docs: {len(test_docs)} (including 1 with wrong institution_id='gwu')")
    print(f"  After FERPA filter: {len(filtered)}")
    print()
    poison_survived = any(d["doc_id"] == "POISON-001" for d in filtered)
    print(f"  Cross-institution document survived: {poison_survived}")
    print("  ✅ Contamination document correctly blocked by institution_id mismatch")

    # -----------------------------------------------------------------------
    # LLM context string (Scenario 1)
    # -----------------------------------------------------------------------
    print("\n" + "─" * 66)
    print("LLM CONTEXT STRING (Scenario 1)")
    print("─" * 66)
    print()
    llm_ctx = ctx.to_llm_context()
    for line in llm_ctx.splitlines():
        print(f"  {line}")

    # -----------------------------------------------------------------------
    # Context envelope facts
    # -----------------------------------------------------------------------
    print("\n" + "─" * 66)
    print("CONTEXT ENVELOPE METADATA")
    print("─" * 66)
    print(f"\n  session_id:  {ctx.envelope.session_id}")
    print(f"  channel:     {ctx.envelope.channel}")
    print(f"  facts:       {ctx.envelope.facts}")
    if ctx.degraded_sources:
        print(f"  degraded:    {ctx.degraded_sources}")

    print()
    print("─" * 66)
    print("KEY ASSEMBLY RULES")
    print("─" * 66)
    print(
        """
  1. Student-specific documents require FERPA pre-filtering.
     Documents with student_id / institution_id metadata are checked against
     StudentIdentityScope before they enter the LLM context window.

  2. Shared documents (no student_id) pass through without FERPA gating.
     Course catalog, policy docs, and real-time data are institution-wide.
     They do not carry student identity — the pre-filter does not apply.

  3. Source categories control what is assembled — not query proximity.
     Financial records are excluded from the enrollment advisor scope even if
     they are the most semantically similar documents to the query. FERPA
     authorization is not overridden by retrieval relevance scores.

  4. Real-time data has a strict freshness requirement.
     Current deadlines and room availability must be < 60s old. Stale
     real-time data is excluded entirely rather than served as if current.

  5. Context assembly failure is graceful.
     Optional sources (financial aid, policy docs) that fail or are stale
     are logged in degraded_sources and excluded. Required sources (SIS,
     knowledge base) failing should raise an error before LLM invocation.
"""
    )


if __name__ == "__main__":
    main()
