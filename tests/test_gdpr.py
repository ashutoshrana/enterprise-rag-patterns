"""
Tests for enterprise_rag_patterns.regulations.gdpr.

Verifies erasure request tracking and GDPR-layer RAG compliance patterns.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from enterprise_rag_patterns.regulations.gdpr import (
    ErasureAuditRecord,
    ErasureRequest,
    GDPRRAGPolicy,
)


@pytest.fixture()
def erasure_request() -> ErasureRequest:
    return ErasureRequest(
        subject_id="user-42",
        request_id="req-001",
        requested_at=datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc),
    )


@pytest.fixture()
def policy() -> GDPRRAGPolicy:
    return GDPRRAGPolicy()


@pytest.fixture()
def documents() -> list[dict]:
    return [
        {"doc_id": "d1", "subject_id": "user-42", "content": "personal note"},
        {"doc_id": "d2", "subject_id": "user-99", "content": "other user doc"},
        {"doc_id": "d3", "content": "shared knowledge base article"},
        {"doc_id": "d4", "subject_id": "user-42", "content": "another personal doc"},
    ]


# ---------------------------------------------------------------------------
# ErasureRequest
# ---------------------------------------------------------------------------


class TestErasureRequest:
    def test_defaults(self, erasure_request: ErasureRequest) -> None:
        assert erasure_request.regulation == "GDPR"
        assert erasure_request.subject_id == "user-42"

    def test_fields(self, erasure_request: ErasureRequest) -> None:
        assert erasure_request.request_id == "req-001"
        assert erasure_request.requested_at.year == 2026


# ---------------------------------------------------------------------------
# GDPRRAGPolicy.filter_for_subject
# ---------------------------------------------------------------------------


class TestFilterForSubject:
    def test_removes_matching_docs(self, policy: GDPRRAGPolicy, documents: list[dict]) -> None:
        result = policy.filter_for_subject(documents, subject_id="user-42")
        doc_ids = [d["doc_id"] for d in result]
        assert "d1" not in doc_ids
        assert "d4" not in doc_ids

    def test_keeps_other_subjects(self, policy: GDPRRAGPolicy, documents: list[dict]) -> None:
        result = policy.filter_for_subject(documents, subject_id="user-42")
        doc_ids = [d["doc_id"] for d in result]
        assert "d2" in doc_ids

    def test_keeps_docs_without_subject_field(self, policy: GDPRRAGPolicy, documents: list[dict]) -> None:
        result = policy.filter_for_subject(documents, subject_id="user-42")
        doc_ids = [d["doc_id"] for d in result]
        assert "d3" in doc_ids

    def test_correct_count(self, policy: GDPRRAGPolicy, documents: list[dict]) -> None:
        result = policy.filter_for_subject(documents, subject_id="user-42")
        assert len(result) == 2  # d2 + d3

    def test_custom_field_name(self, policy: GDPRRAGPolicy) -> None:
        docs = [
            {"user": "alice", "text": "alice's doc"},
            {"user": "bob", "text": "bob's doc"},
        ]
        result = policy.filter_for_subject(docs, subject_id="alice", subject_id_field="user")
        assert len(result) == 1
        assert result[0]["user"] == "bob"


# ---------------------------------------------------------------------------
# GDPRRAGPolicy.record_erasure
# ---------------------------------------------------------------------------


class TestRecordErasure:
    def test_returns_audit_record(self, policy: GDPRRAGPolicy, erasure_request: ErasureRequest) -> None:
        record = policy.record_erasure(erasure_request, removed_count=2, index_rebuilt=True)
        assert isinstance(record, ErasureAuditRecord)

    def test_counts(self, policy: GDPRRAGPolicy, erasure_request: ErasureRequest) -> None:
        record = policy.record_erasure(erasure_request, removed_count=3, index_rebuilt=False)
        assert record.documents_removed == 3
        assert record.index_rebuilt is False

    def test_subject_id_propagated(self, policy: GDPRRAGPolicy, erasure_request: ErasureRequest) -> None:
        record = policy.record_erasure(erasure_request, removed_count=1, index_rebuilt=True)
        assert record.subject_id == "user-42"

    def test_request_id_propagated(self, policy: GDPRRAGPolicy, erasure_request: ErasureRequest) -> None:
        record = policy.record_erasure(erasure_request, removed_count=1, index_rebuilt=True)
        assert record.request_id == "req-001"


# ---------------------------------------------------------------------------
# ErasureAuditRecord.to_log_entry
# ---------------------------------------------------------------------------


class TestErasureAuditRecordToLogEntry:
    def test_returns_dict(self, policy: GDPRRAGPolicy, erasure_request: ErasureRequest) -> None:
        record = policy.record_erasure(erasure_request, removed_count=2, index_rebuilt=True)
        entry = record.to_log_entry()
        assert isinstance(entry, dict)

    def test_required_fields(self, policy: GDPRRAGPolicy, erasure_request: ErasureRequest) -> None:
        record = policy.record_erasure(erasure_request, removed_count=2, index_rebuilt=True)
        entry = record.to_log_entry()
        for key in ("request_id", "subject_id", "documents_removed", "index_rebuilt", "completed_at", "regulation"):
            assert key in entry, f"Missing key: {key}"

    def test_json_serialisable(self, policy: GDPRRAGPolicy, erasure_request: ErasureRequest) -> None:
        import json

        record = policy.record_erasure(erasure_request, removed_count=0, index_rebuilt=False)
        entry = record.to_log_entry()
        # Should not raise
        json.dumps(entry)
