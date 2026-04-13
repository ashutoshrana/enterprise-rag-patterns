"""
02_multi_student_isolation.py — Multi-student isolation with FERPAContextPolicy.

Demonstrates that two students' scopes are completely isolated: filtering for
student A never leaks documents belonging to student B, and vice versa.

Run:
    python examples/02_multi_student_isolation.py
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


def build_policy(student_id: str, institution_id: str) -> FERPAContextPolicy:
    scope = StudentIdentityScope(
        student_id=student_id,
        institution_id=institution_id,
        requesting_user_id="system:advisor_agent",
        authorized_categories={
            RecordCategory.ACADEMIC_RECORD,
            RecordCategory.DIRECTORY_INFORMATION,
        },
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )
    return FERPAContextPolicy(scope=scope)


def main() -> None:
    institution = "inst_abc"

    # 6 documents: 3 per student
    documents = [
        {
            "doc_id": "A-1",
            "content": "Alice GPA: 3.9",
            "student_id": "alice",
            "institution_id": institution,
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
        },
        {
            "doc_id": "A-2",
            "content": "Alice major: Computer Science",
            "student_id": "alice",
            "institution_id": institution,
            "record_category": RecordCategory.DIRECTORY_INFORMATION.value,
        },
        {
            "doc_id": "A-3",
            "content": "Alice financial aid balance: $5,000",
            "student_id": "alice",
            "institution_id": institution,
            "record_category": RecordCategory.FINANCIAL_RECORD.value,  # not in scope
        },
        {
            "doc_id": "B-1",
            "content": "Bob GPA: 3.5",
            "student_id": "bob",
            "institution_id": institution,
            "record_category": RecordCategory.ACADEMIC_RECORD.value,
        },
        {
            "doc_id": "B-2",
            "content": "Bob major: Biology",
            "student_id": "bob",
            "institution_id": institution,
            "record_category": RecordCategory.DIRECTORY_INFORMATION.value,
        },
        {
            "doc_id": "B-3",
            "content": "Bob disciplinary note: warning issued",
            "student_id": "bob",
            "institution_id": institution,
            "record_category": RecordCategory.DISCIPLINARY_RECORD.value,  # not in scope
        },
    ]

    policy_alice = build_policy("alice", institution)
    policy_bob = build_policy("bob", institution)

    alice_docs = policy_alice.filter_retrieved_documents(documents)
    bob_docs = policy_bob.filter_retrieved_documents(documents)

    alice_ids = {d["doc_id"] for d in alice_docs}
    bob_ids = {d["doc_id"] for d in bob_docs}

    # Verify no cross-contamination
    alice_bob_leak = alice_ids & {"B-1", "B-2", "B-3"}
    bob_alice_leak = bob_ids & {"A-1", "A-2", "A-3"}
    assert not alice_bob_leak, f"LEAK: Alice scope returned Bob's docs: {alice_bob_leak}"
    assert not bob_alice_leak, f"LEAK: Bob scope returned Alice's docs: {bob_alice_leak}"

    # Display results as a table
    print("=" * 68)
    print("FERPA Multi-Student Isolation Demo")
    print("=" * 68)
    print(f"\nInstitution: {institution}")
    print("Authorized categories: academic_record, directory_information\n")

    header = f"{'Doc ID':<8} {'Owner':<8} {'Category':<25} {'Alice scope':<14} {'Bob scope'}"
    print(header)
    print("-" * 68)

    cat_short = {
        RecordCategory.ACADEMIC_RECORD.value: "academic_record",
        RecordCategory.DIRECTORY_INFORMATION.value: "directory_info",
        RecordCategory.FINANCIAL_RECORD.value: "financial_record",
        RecordCategory.DISCIPLINARY_RECORD.value: "disciplinary_record",
    }

    for doc in documents:
        doc_id = doc["doc_id"]
        owner = doc["student_id"]
        cat = cat_short.get(doc.get("record_category", ""), doc.get("record_category", ""))
        alice_result = "PASS" if doc_id in alice_ids else "FAIL"
        bob_result = "PASS" if doc_id in bob_ids else "FAIL"
        alice_marker = "✓" if alice_result == "PASS" else "✗"
        bob_marker = "✓" if bob_result == "PASS" else "✗"
        print(f"  {doc_id:<6} {owner:<8} {cat:<25} {alice_marker} {alice_result:<12} {bob_marker} {bob_result}")

    print("\nCross-contamination check:")
    print(f"  Alice scope contains Bob docs:  {alice_ids & {'B-1', 'B-2', 'B-3'} or 'none'}")
    print(f"  Bob scope contains Alice docs:  {bob_ids & {'A-1', 'A-2', 'A-3'} or 'none'}")
    print("\nAll assertions passed — no cross-student leakage detected.")
    print("\nDone.")


if __name__ == "__main__":
    main()
