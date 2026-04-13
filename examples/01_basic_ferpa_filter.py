"""
01_basic_ferpa_filter.py — Basic FERPA document filtering with FERPAContextPolicy.

Demonstrates how to use FERPAContextPolicy.filter_retrieved_documents() to
enforce FERPA boundaries before retrieved documents enter an LLM context window.

Run:
    python examples/01_basic_ferpa_filter.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enterprise_rag_patterns.compliance import (
    DisclosureReason,
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
)


def main() -> None:
    # --- Build an identity scope for student_001 at inst_abc ---
    scope = StudentIdentityScope(
        student_id="student_001",
        institution_id="inst_abc",
        requesting_user_id="advisor:portal_agent",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )

    policy = FERPAContextPolicy(scope=scope)

    # --- 5 mock documents with different identity/category combinations ---
    documents = [
        {
            # PASS: correct student + institution + authorized category
            "doc_id": "doc-1",
            "content": "GPA: 3.8, Major: Computer Science",
            "student_id": "student_001",
            "institution_id": "inst_abc",
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
        },
        {
            # FAIL: wrong student
            "doc_id": "doc-2",
            "content": "GPA: 3.2, Major: Biology",
            "student_id": "student_999",
            "institution_id": "inst_abc",
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
        },
        {
            # FAIL: wrong institution (cross-institution contamination)
            "doc_id": "doc-3",
            "content": "Enrollment status: Part-time",
            "student_id": "student_001",
            "institution_id": "inst_xyz",
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
        },
        {
            # FAIL: unauthorized category (financial record not in scope)
            "doc_id": "doc-4",
            "content": "Outstanding balance: $2,400",
            "student_id": "student_001",
            "institution_id": "inst_abc",
            "record_category": RecordCategory.FINANCIAL_RECORD.value,
        },
        {
            # PASS: no identity fields — treated as shared knowledge-base content
            "doc_id": "doc-5",
            "content": "Course registration opens the first Monday of each semester.",
        },
    ]

    print("=" * 60)
    print("FERPA Context Policy — Basic Filtering Demo")
    print("=" * 60)
    print(f"\nScope: student={scope.student_id!r}  institution={scope.institution_id!r}")
    print(f"Authorized categories: {[c.value for c in scope.authorized_categories]}")
    print(f"\nDocuments before filtering: {len(documents)}")

    safe_docs = policy.filter_retrieved_documents(documents)

    print(f"Documents after filtering:  {len(safe_docs)}")

    # Determine outcome for each original document
    safe_ids = {d["doc_id"] for d in safe_docs}

    print("\nPer-document outcomes:")
    print("-" * 60)
    expected = {
        "doc-1": ("PASS", "correct student + institution + authorized category"),
        "doc-2": ("FAIL", "wrong student_id (student_999 != student_001)"),
        "doc-3": ("FAIL", "wrong institution_id (inst_xyz != inst_abc)"),
        "doc-4": ("FAIL", "unauthorized record_category (financial_record)"),
        "doc-5": ("PASS", "no identity fields — shared knowledge-base content"),
    }
    for doc in documents:
        doc_id = doc["doc_id"]
        outcome = "PASS" if doc_id in safe_ids else "FAIL"
        reason = expected[doc_id][1]
        marker = "✓" if outcome == "PASS" else "✗"
        print(f"  {marker} {doc_id}: {outcome} — {reason}")

    print("\nSafe documents passed to LLM context:")
    for doc in safe_docs:
        print(f"  [{doc['doc_id']}] {doc['content']}")

    # Generate an audit record
    audit = policy.record_access(
        categories_accessed=[RecordCategory.ACADEMIC_RECORD],
        workflow_context="enrollment_status_check",
    )
    print("\nFERPA audit record (34 CFR § 99.32):")
    print(" ", audit.to_log_entry())

    print("\nDone.")


if __name__ == "__main__":
    main()
