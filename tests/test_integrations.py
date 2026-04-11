"""
Tests for enterprise_rag_patterns.integrations.

Uses duck-typed stubs — no haystack-ai or llama-index-core required.
"""

from __future__ import annotations

from typing import Any

import pytest

from enterprise_rag_patterns.compliance import RecordCategory, StudentIdentityScope
from enterprise_rag_patterns.integrations.haystack import FERPAHaystackFilter
from enterprise_rag_patterns.integrations.llama_index import FERPANodePostprocessor

# ---------------------------------------------------------------------------
# Stubs (duck-typed, no external imports)
# ---------------------------------------------------------------------------


class _FakeDocument:
    """Duck-typed Haystack Document stub."""

    def __init__(self, meta: dict[str, Any]) -> None:
        self.meta = meta
        self.content = "stub content"


class _FakeNode:
    """Duck-typed LlamaIndex BaseNode stub."""

    def __init__(self, metadata: dict[str, Any]) -> None:
        self.metadata = metadata
        self.text = "stub node text"
        self.node_id = "stub-id"


# ---------------------------------------------------------------------------
# FERPAHaystackFilter
# ---------------------------------------------------------------------------


@pytest.fixture()
def haystack_filter() -> FERPAHaystackFilter:
    return FERPAHaystackFilter()


@pytest.fixture()
def haystack_docs() -> list[_FakeDocument]:
    return [
        _FakeDocument({"student_id": "S-1", "institution_id": "inst-a", "category": "academic_record"}),
        _FakeDocument({"student_id": "S-2", "institution_id": "inst-a", "category": "academic_record"}),
        _FakeDocument({"student_id": "S-1", "institution_id": "inst-b", "category": "academic_record"}),
        _FakeDocument({"institution_id": "inst-a"}),  # shared KB — no student_id
        _FakeDocument({"student_id": "S-1", "institution_id": "inst-a", "category": "disciplinary_record"}),
    ]


Docs = list[_FakeDocument]  # local alias to keep signatures short


class TestFERPAHaystackFilter:
    def test_returns_dict_with_key(self, haystack_filter: FERPAHaystackFilter, haystack_docs: Docs) -> None:
        result = haystack_filter.run(haystack_docs, student_id="S-1", institution_id="inst-a")
        assert "filtered_documents" in result

    def test_blocks_cross_student(self, haystack_filter: FERPAHaystackFilter, haystack_docs: Docs) -> None:
        result = haystack_filter.run(haystack_docs, student_id="S-1", institution_id="inst-a")
        metas = [d.meta for d in result["filtered_documents"]]
        assert not any(m.get("student_id") == "S-2" for m in metas)

    def test_blocks_cross_institution(self, haystack_filter: FERPAHaystackFilter, haystack_docs: Docs) -> None:
        result = haystack_filter.run(haystack_docs, student_id="S-1", institution_id="inst-a")
        metas = [d.meta for d in result["filtered_documents"]]
        assert not any(m.get("institution_id") == "inst-b" for m in metas)

    def test_passes_shared_kb_doc(self, haystack_filter: FERPAHaystackFilter, haystack_docs: Docs) -> None:
        result = haystack_filter.run(haystack_docs, student_id="S-1", institution_id="inst-a")
        metas = [d.meta for d in result["filtered_documents"]]
        assert any("student_id" not in m for m in metas)

    def test_category_filter(self, haystack_filter: FERPAHaystackFilter, haystack_docs: Docs) -> None:
        result = haystack_filter.run(
            haystack_docs,
            student_id="S-1",
            institution_id="inst-a",
            permitted_categories={"academic_record"},
        )
        metas = [d.meta for d in result["filtered_documents"]]
        assert not any(m.get("category") == "disciplinary_record" for m in metas)

    def test_no_category_filter_when_none(self, haystack_filter: FERPAHaystackFilter, haystack_docs: Docs) -> None:
        result = haystack_filter.run(
            haystack_docs, student_id="S-1", institution_id="inst-a", permitted_categories=None
        )
        metas = [d.meta for d in result["filtered_documents"]]
        # disciplinary_record should pass through when no category filter
        assert any(m.get("category") == "disciplinary_record" for m in metas)

    def test_empty_input(self, haystack_filter: FERPAHaystackFilter) -> None:
        result = haystack_filter.run([], student_id="S-1", institution_id="inst-a")
        assert result["filtered_documents"] == []


# ---------------------------------------------------------------------------
# FERPANodePostprocessor
# ---------------------------------------------------------------------------


@pytest.fixture()
def postprocessor() -> FERPANodePostprocessor:
    scope = StudentIdentityScope(
        student_id="S-1",
        institution_id="inst-a",
        requesting_user_id="agent",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )
    return FERPANodePostprocessor(scope=scope)


@pytest.fixture()
def llama_nodes() -> list[_FakeNode]:
    return [
        _FakeNode({"student_id": "S-1", "institution_id": "inst-a"}),
        _FakeNode({"student_id": "S-2", "institution_id": "inst-a"}),
        _FakeNode({"student_id": "S-1", "institution_id": "inst-b"}),
        _FakeNode({}),  # shared KB node
    ]


Nodes = list[_FakeNode]  # local alias


class TestFERPANodePostprocessor:
    def test_blocks_cross_student(self, postprocessor: FERPANodePostprocessor, llama_nodes: Nodes) -> None:
        result = postprocessor.postprocess_nodes(llama_nodes)  # type: ignore[arg-type]
        metas = [n.metadata for n in result]
        assert not any(m.get("student_id") == "S-2" for m in metas)

    def test_blocks_cross_institution(self, postprocessor: FERPANodePostprocessor, llama_nodes: Nodes) -> None:
        result = postprocessor.postprocess_nodes(llama_nodes)  # type: ignore[arg-type]
        metas = [n.metadata for n in result]
        assert not any(m.get("institution_id") == "inst-b" for m in metas)

    def test_passes_own_node(self, postprocessor: FERPANodePostprocessor, llama_nodes: Nodes) -> None:
        result = postprocessor.postprocess_nodes(llama_nodes)  # type: ignore[arg-type]
        metas = [n.metadata for n in result]
        assert any(m.get("student_id") == "S-1" and m.get("institution_id") == "inst-a" for m in metas)

    def test_passes_shared_kb(self, postprocessor: FERPANodePostprocessor, llama_nodes: Nodes) -> None:
        result = postprocessor.postprocess_nodes(llama_nodes)  # type: ignore[arg-type]
        metas = [n.metadata for n in result]
        assert any(not m.get("student_id") for m in metas)

    def test_empty_input(self, postprocessor: FERPANodePostprocessor) -> None:
        result = postprocessor.postprocess_nodes([])  # type: ignore[arg-type]
        assert result == []
