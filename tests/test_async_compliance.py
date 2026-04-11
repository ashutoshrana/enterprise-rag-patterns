"""
Tests for enterprise_rag_patterns.async_compliance.

Verifies that async wrappers preserve filtering behaviour
and return correct types for async LLM framework compatibility.
"""

from __future__ import annotations

import asyncio

from enterprise_rag_patterns.async_compliance import (
    async_filter_retrieved_documents,
    async_record_access,
)
from enterprise_rag_patterns.compliance import (
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
)

DOCS = [
    {"doc_id": "own", "student_id": "S-1", "institution_id": "inst-a", "record_category": "academic_record"},
    {"doc_id": "other-student", "student_id": "S-2", "institution_id": "inst-a", "record_category": "academic_record"},
    {"doc_id": "shared-kb", "institution_id": "inst-a"},
]


def _policy() -> FERPAContextPolicy:
    scope = StudentIdentityScope(
        student_id="S-1",
        institution_id="inst-a",
        requesting_user_id="agent",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )
    return FERPAContextPolicy(scope=scope)


class TestAsyncFilterRetrievedDocuments:
    def test_returns_list(self) -> None:
        result = asyncio.run(async_filter_retrieved_documents(_policy(), DOCS))
        assert isinstance(result, list)

    def test_blocks_cross_student(self) -> None:
        result = asyncio.run(async_filter_retrieved_documents(_policy(), DOCS))
        ids = [d["doc_id"] for d in result]
        assert "other-student" not in ids

    def test_keeps_own_doc(self) -> None:
        result = asyncio.run(async_filter_retrieved_documents(_policy(), DOCS))
        ids = [d["doc_id"] for d in result]
        assert "own" in ids

    def test_keeps_shared_kb(self) -> None:
        result = asyncio.run(async_filter_retrieved_documents(_policy(), DOCS))
        ids = [d["doc_id"] for d in result]
        assert "shared-kb" in ids

    def test_empty_input(self) -> None:
        result = asyncio.run(async_filter_retrieved_documents(_policy(), []))
        assert result == []


class TestAsyncRecordAccess:
    def test_returns_audit_record(self) -> None:
        record = asyncio.run(
            async_record_access(_policy(), "read_transcript", categories_accessed=[RecordCategory.ACADEMIC_RECORD])
        )
        assert record is not None

    def test_audit_record_has_timestamp(self) -> None:
        record = asyncio.run(
            async_record_access(_policy(), "read_transcript", categories_accessed=[RecordCategory.ACADEMIC_RECORD])
        )
        assert hasattr(record, "access_timestamp") or hasattr(record, "timestamp") or hasattr(record, "accessed_at")
