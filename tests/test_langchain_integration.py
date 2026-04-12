"""
Tests for FERPAComplianceCallbackHandler (LangChain integration).

Uses duck-typed stubs — langchain-core is NOT required to run these tests.
The handler's lazy import check is bypassed via monkeypatching so we can
test filtering behaviour without the optional SDK dependency.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from enterprise_rag_patterns.compliance import (
    AuditRecord,
    DisclosureReason,
    RecordCategory,
    StudentIdentityScope,
)
from enterprise_rag_patterns.integrations.langchain import FERPAComplianceCallbackHandler

# ---------------------------------------------------------------------------
# Stub: duck-typed LangChain Document (no SDK needed)
# ---------------------------------------------------------------------------


class MockDocument:
    """Minimal duck-typed stub for langchain_core.documents.Document."""

    def __init__(self, page_content: str, metadata: dict[str, Any]) -> None:
        self.page_content = page_content
        self.metadata = metadata

    def __repr__(self) -> str:
        return f"MockDocument(metadata={self.metadata!r})"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_scope(
    student_id: str = "stu_001",
    institution_id: str = "inst_abc",
    categories: set[RecordCategory] | None = None,
) -> StudentIdentityScope:
    return StudentIdentityScope(
        student_id=student_id,
        institution_id=institution_id,
        requesting_user_id="advisor_007",
        authorized_categories=categories or {RecordCategory.ACADEMIC_RECORD},
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )


def _make_handler(
    scope: StudentIdentityScope | None = None,
    raise_on_violation: bool = False,
    audit_sink: Any = None,
) -> FERPAComplianceCallbackHandler:
    """Construct handler with langchain-core import check patched out."""
    with patch("enterprise_rag_patterns.integrations.langchain._check_langchain_available"):
        return FERPAComplianceCallbackHandler(
            scope=scope or _make_scope(),
            raise_on_violation=raise_on_violation,
            audit_sink=audit_sink,
        )


# ---------------------------------------------------------------------------
# Identity filtering tests
# ---------------------------------------------------------------------------


class TestIdentityFiltering:
    def test_allows_authorized_documents(self) -> None:
        handler = _make_handler()
        docs = [
            MockDocument(
                "Grade report",
                {"student_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"},
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 1

    def test_blocks_cross_student_documents(self) -> None:
        handler = _make_handler()
        docs = [
            MockDocument(
                "Other student", {"student_id": "stu_999", "institution_id": "inst_abc", "category": "academic_record"}
            ),
            MockDocument(
                "Own record", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 1
        assert docs[0].metadata["student_id"] == "stu_001"

    def test_blocks_cross_institution_documents(self) -> None:
        handler = _make_handler()
        docs = [
            MockDocument(
                "Other inst", {"student_id": "stu_001", "institution_id": "inst_xyz", "category": "academic_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 0

    def test_shared_knowledge_passes_through(self) -> None:
        """Documents without student/institution identifiers pass as shared KB content."""
        handler = _make_handler()
        docs = [MockDocument("General policy doc", {})]
        handler.on_retriever_end(docs)
        assert len(docs) == 1

    def test_empty_document_list(self) -> None:
        handler = _make_handler()
        docs: list[MockDocument] = []
        handler.on_retriever_end(docs)
        assert len(docs) == 0

    def test_mixed_batch_filters_correctly(self) -> None:
        handler = _make_handler()
        docs = [
            MockDocument("Own", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"}),
            MockDocument(
                "Other student", {"student_id": "stu_002", "institution_id": "inst_abc", "category": "academic_record"}
            ),
            MockDocument(
                "Other inst", {"student_id": "stu_001", "institution_id": "inst_xyz", "category": "academic_record"}
            ),
            MockDocument("Shared KB", {}),
        ]
        handler.on_retriever_end(docs)
        # Only own record + shared KB should remain
        assert len(docs) == 2
        remaining_students = {d.metadata.get("student_id") for d in docs}
        assert remaining_students == {"stu_001", None}


# ---------------------------------------------------------------------------
# Category authorization tests
# ---------------------------------------------------------------------------


class TestCategoryFiltering:
    def test_blocks_unauthorized_category(self) -> None:
        handler = _make_handler(scope=_make_scope(categories={RecordCategory.ACADEMIC_RECORD}))
        docs = [
            MockDocument(
                "Health record", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "health_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 0

    def test_allows_authorized_category(self) -> None:
        handler = _make_handler(scope=_make_scope(categories={RecordCategory.ACADEMIC_RECORD}))
        docs = [
            MockDocument(
                "Transcript", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 1

    def test_allows_directory_information_always(self) -> None:
        """FERPA: directory_information is always permitted regardless of scope."""
        handler = _make_handler(scope=_make_scope(categories={RecordCategory.ACADEMIC_RECORD}))
        docs = [
            MockDocument(
                "Dir info", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "directory_information"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 1

    def test_blocks_multiple_unauthorized_categories(self) -> None:
        handler = _make_handler(scope=_make_scope(categories={RecordCategory.ACADEMIC_RECORD}))
        docs = [
            MockDocument(
                "Health", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "health_record"}
            ),
            MockDocument(
                "Disciplinary",
                {"student_id": "stu_001", "institution_id": "inst_abc", "category": "disciplinary_record"},
            ),
            MockDocument(
                "Academic", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 1
        assert docs[0].metadata["category"] == "academic_record"


# ---------------------------------------------------------------------------
# raise_on_violation mode
# ---------------------------------------------------------------------------


class TestRaiseOnViolation:
    def test_raises_when_unauthorized_document_blocked(self) -> None:
        handler = _make_handler(raise_on_violation=True)
        docs = [
            MockDocument(
                "Other student", {"student_id": "stu_999", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        with pytest.raises(ValueError, match="FERPA violation"):
            handler.on_retriever_end(docs)

    def test_does_not_raise_when_all_authorized(self) -> None:
        handler = _make_handler(raise_on_violation=True)
        docs = [
            MockDocument("Own", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"}),
        ]
        # Should not raise
        handler.on_retriever_end(docs)
        assert len(docs) == 1

    def test_does_not_raise_in_default_mode(self) -> None:
        handler = _make_handler(raise_on_violation=False)
        docs = [
            MockDocument(
                "Other", {"student_id": "stu_999", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        # Should silently drop, not raise
        handler.on_retriever_end(docs)
        assert len(docs) == 0


# ---------------------------------------------------------------------------
# Audit sink tests
# ---------------------------------------------------------------------------


class TestAuditSink:
    def test_audit_sink_receives_record_for_category_access(self) -> None:
        audit_log: list[AuditRecord] = []
        handler = _make_handler(audit_sink=audit_log.append)
        docs = [
            MockDocument(
                "Transcript", {"student_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(audit_log) == 1
        record = audit_log[0]
        assert record.student_id == "stu_001"
        assert record.institution_id == "inst_abc"
        assert RecordCategory.ACADEMIC_RECORD in record.categories_accessed

    def test_audit_sink_not_called_for_shared_kb_only(self) -> None:
        """No audit record for docs that have no FERPA category."""
        audit_log: list[AuditRecord] = []
        handler = _make_handler(audit_sink=audit_log.append)
        docs = [MockDocument("Shared policy", {})]
        handler.on_retriever_end(docs)
        assert len(audit_log) == 0

    def test_audit_sink_not_called_when_all_filtered(self) -> None:
        """No audit record when all docs are blocked (nothing actually accessed)."""
        audit_log: list[AuditRecord] = []
        handler = _make_handler(audit_sink=audit_log.append)
        docs = [
            MockDocument(
                "Other", {"student_id": "stu_999", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(audit_log) == 0


# ---------------------------------------------------------------------------
# No-op handler methods
# ---------------------------------------------------------------------------


class TestNoopHandlers:
    """All non-retriever callback methods must be callable without raising."""

    def _handler(self) -> FERPAComplianceCallbackHandler:
        return _make_handler()

    def test_on_llm_start(self) -> None:
        self._handler().on_llm_start()

    def test_on_llm_end(self) -> None:
        self._handler().on_llm_end()

    def test_on_chain_start(self) -> None:
        self._handler().on_chain_start()

    def test_on_chain_end(self) -> None:
        self._handler().on_chain_end()

    def test_on_tool_start(self) -> None:
        self._handler().on_tool_start()

    def test_on_tool_end(self) -> None:
        self._handler().on_tool_end()

    def test_on_retriever_start(self) -> None:
        self._handler().on_retriever_start()

    def test_on_retriever_error(self) -> None:
        self._handler().on_retriever_error()


# ---------------------------------------------------------------------------
# Custom field name configuration
# ---------------------------------------------------------------------------


class TestCustomFieldNames:
    def test_custom_student_id_field(self) -> None:
        with patch("enterprise_rag_patterns.integrations.langchain._check_langchain_available"):
            handler = FERPAComplianceCallbackHandler(
                scope=_make_scope(),
                student_id_field="learner_id",
            )
        docs = [
            MockDocument(
                "Record", {"learner_id": "stu_001", "institution_id": "inst_abc", "category": "academic_record"}
            ),
            MockDocument(
                "Other", {"learner_id": "stu_999", "institution_id": "inst_abc", "category": "academic_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 1
        assert docs[0].metadata["learner_id"] == "stu_001"

    def test_custom_category_field(self) -> None:
        with patch("enterprise_rag_patterns.integrations.langchain._check_langchain_available"):
            handler = FERPAComplianceCallbackHandler(
                scope=_make_scope(categories={RecordCategory.ACADEMIC_RECORD}),
                category_field="doc_type",
            )
        docs = [
            MockDocument(
                "Academic", {"student_id": "stu_001", "institution_id": "inst_abc", "doc_type": "academic_record"}
            ),
            MockDocument(
                "Health", {"student_id": "stu_001", "institution_id": "inst_abc", "doc_type": "health_record"}
            ),
        ]
        handler.on_retriever_end(docs)
        assert len(docs) == 1
        assert docs[0].metadata["doc_type"] == "academic_record"


# ---------------------------------------------------------------------------
# ImportError path
# ---------------------------------------------------------------------------


def test_raises_import_error_when_langchain_missing() -> None:
    """Handler __init__ must raise ImportError with install instructions if langchain-core absent."""
    import builtins

    real_import = builtins.__import__

    def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "langchain_core.callbacks":
            raise ImportError("No module named 'langchain_core'")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(ImportError, match="langchain-core"):
            FERPAComplianceCallbackHandler(scope=_make_scope())
