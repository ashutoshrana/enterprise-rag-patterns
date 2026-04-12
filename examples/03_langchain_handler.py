"""
03_langchain_handler.py — FERPAComplianceCallbackHandler integration.

Demonstrates how FERPAComplianceCallbackHandler intercepts retriever results
and applies FERPA filtering in-place, without requiring langchain-core to be
installed (the handler is instantiated inside a try/except ImportError block).

Duck-typed mock Document objects are used so no real LangChain retriever is needed.

Run:
    python examples/03_langchain_handler.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enterprise_rag_patterns.compliance import (
    DisclosureReason,
    RecordCategory,
    StudentIdentityScope,
)


class MockDocument:
    """
    Duck-typed stand-in for langchain_core.documents.Document.

    FERPAComplianceCallbackHandler only requires that each document expose
    a `.metadata` dict — nothing else is needed.
    """

    def __init__(self, page_content: str, metadata: dict) -> None:
        self.page_content = page_content
        self.metadata = metadata

    def __repr__(self) -> str:
        return f"MockDocument(content={self.page_content!r}, metadata={self.metadata})"


def main() -> None:
    print("=" * 64)
    print("FERPAComplianceCallbackHandler — LangChain Integration Demo")
    print("=" * 64)

    scope = StudentIdentityScope(
        student_id="stu_007",
        institution_id="strayer",
        requesting_user_id="advisor:enrollment_bot",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )

    # Patch the availability check before import so the handler can be
    # instantiated without langchain-core, letting us demonstrate the
    # filtering logic directly regardless of whether the SDK is installed.
    import enterprise_rag_patterns.integrations.langchain as lc_module

    _langchain_available = True
    try:
        import langchain_core.callbacks  # noqa: F401
    except ImportError:
        _langchain_available = False
        print(
            "\nlangchain-core is not installed — patching availability check "
            "to demonstrate filtering logic without the SDK.\n"
        )
        lc_module._check_langchain_available = lambda: None  # type: ignore[attr-defined]

    from enterprise_rag_patterns.integrations.langchain import (
        FERPAComplianceCallbackHandler,
    )

    audit_log: list[str] = []

    def capture_audit(record) -> None:  # type: ignore[type-arg]
        audit_log.append(record.to_log_entry())

    handler = FERPAComplianceCallbackHandler(
        scope=scope,
        # The langchain integration stores category under "category" key by default
        category_field="category",
        audit_sink=capture_audit,
    )

    # Mock documents as they would arrive from a LangChain retriever
    documents = [
        MockDocument(
            "Enrolled in CSCI-401, grade: A",
            {
                "student_id": "stu_007",
                "institution_id": "strayer",
                "category": RecordCategory.ACADEMIC_RECORD.value,
            },
        ),
        MockDocument(
            "Outstanding tuition balance: $1,800",
            {
                "student_id": "stu_007",
                "institution_id": "strayer",
                "category": RecordCategory.FINANCIAL_RECORD.value,  # not authorized
            },
        ),
        MockDocument(
            "Different student's transcript",
            {
                "student_id": "stu_999",  # wrong student
                "institution_id": "strayer",
                "category": RecordCategory.ACADEMIC_RECORD.value,
            },
        ),
        MockDocument(
            "Semester calendar: registration opens Jan 15.",
            {},  # no identity fields — shared content, passes through
        ),
    ]

    print(f"\nScope: student={scope.student_id!r}  institution={scope.institution_id!r}")
    print(f"Documents before on_retriever_end(): {len(documents)}")

    # Show before state
    print("\nBefore filtering:")
    for i, doc in enumerate(documents):
        print(f"  [{i}] {doc.page_content!r}  meta={doc.metadata}")

    # Call the handler — mutates list in-place
    handler.on_retriever_end(documents)

    print(f"\nDocuments after on_retriever_end(): {len(documents)}")
    print("\nAfter filtering (in-place mutation):")
    for i, doc in enumerate(documents):
        print(f"  [{i}] {doc.page_content!r}  meta={doc.metadata}")

    if audit_log:
        print("\nFERPA audit entries emitted (34 CFR § 99.32):")
        for entry in audit_log:
            print(f"  {entry}")
    else:
        print("\nNo protected categories in retained documents — no audit entry generated.")

    print("\nDone.")


if __name__ == "__main__":
    main()
