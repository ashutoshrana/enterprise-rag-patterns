"""
Tests for PineconeNamespaceIsolation (vector_stores/pinecone_adapter.py).

Verifies defense-in-depth: namespace (Layer 1) + metadata filter (Layer 2).
Uses duck-typed stubs — no pinecone SDK required.
Async tests use asyncio.run().
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from enterprise_rag_patterns.vector_stores.base import ComplianceFilter
from enterprise_rag_patterns.vector_stores.pinecone_adapter import PineconeNamespaceIsolation

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def scope_with_categories() -> ComplianceFilter:
    return ComplianceFilter(
        student_id="stu-001",
        institution_id="strayer",
        permitted_categories={"academic_record", "financial_record"},
        regulation="FERPA",
    )


@pytest.fixture()
def scope_no_categories() -> ComplianceFilter:
    return ComplianceFilter(
        student_id="stu-002",
        institution_id="purdue",
        permitted_categories=set(),
        regulation="FERPA",
    )


@pytest.fixture()
def isolator() -> PineconeNamespaceIsolation:
    return PineconeNamespaceIsolation(index_host="my-idx.svc.us-east1.pinecone.io")


# ---------------------------------------------------------------------------
# namespace_for
# ---------------------------------------------------------------------------


class TestNamespaceFor:
    def test_default_uses_institution_id(self, isolator: PineconeNamespaceIsolation) -> None:
        assert isolator.namespace_for("strayer") == "strayer"

    def test_default_uses_institution_id_purdue(self, isolator: PineconeNamespaceIsolation) -> None:
        assert isolator.namespace_for("purdue") == "purdue"

    def test_custom_resolver(self) -> None:
        isolator = PineconeNamespaceIsolation(
            index_host="host",
            namespace_resolver=lambda inst: f"ns_{inst.upper()}",
        )
        assert isolator.namespace_for("strayer") == "ns_STRAYER"

    def test_custom_resolver_normalization(self) -> None:
        isolator = PineconeNamespaceIsolation(
            index_host="host",
            namespace_resolver=lambda inst: inst.replace("-", "_"),
        )
        assert isolator.namespace_for("univ-a") == "univ_a"


# ---------------------------------------------------------------------------
# build_metadata_filter — Layer 2
# ---------------------------------------------------------------------------


class TestBuildMetadataFilter:
    def test_student_id_only_when_no_categories(
        self, isolator: PineconeNamespaceIsolation, scope_no_categories: ComplianceFilter
    ) -> None:
        f = isolator.build_metadata_filter(scope_no_categories)
        # No $and when only student_id clause
        assert "student_id" in f
        assert f["student_id"] == {"$eq": "stu-002"}

    def test_and_clause_with_categories(
        self, isolator: PineconeNamespaceIsolation, scope_with_categories: ComplianceFilter
    ) -> None:
        f = isolator.build_metadata_filter(scope_with_categories)
        assert "$and" in f
        clauses = f["$and"]
        assert len(clauses) == 2

    def test_student_id_clause_present(
        self, isolator: PineconeNamespaceIsolation, scope_with_categories: ComplianceFilter
    ) -> None:
        f = isolator.build_metadata_filter(scope_with_categories)
        clauses = f["$and"]
        student_clause = next((c for c in clauses if "student_id" in c), None)
        assert student_clause is not None
        assert student_clause["student_id"] == {"$eq": "stu-001"}

    def test_category_clause_sorted(
        self, isolator: PineconeNamespaceIsolation, scope_with_categories: ComplianceFilter
    ) -> None:
        f = isolator.build_metadata_filter(scope_with_categories)
        clauses = f["$and"]
        cat_clause = next((c for c in clauses if "category" in c), None)
        assert cat_clause is not None
        assert cat_clause["category"]["$in"] == sorted(scope_with_categories.permitted_categories)

    def test_institution_id_not_in_filter(
        self, isolator: PineconeNamespaceIsolation, scope_with_categories: ComplianceFilter
    ) -> None:
        """institution_id is enforced at namespace layer, not metadata filter."""
        f = isolator.build_metadata_filter(scope_with_categories)
        import json

        serialized = json.dumps(f)
        assert "institution_id" not in serialized
        assert "strayer" not in serialized

    def test_custom_field_names(self) -> None:
        isolator = PineconeNamespaceIsolation(
            index_host="host",
            student_id_field="sid",
            category_field="rec_type",
        )
        scope = ComplianceFilter(
            student_id="stu-x",
            institution_id="inst-y",
            permitted_categories={"transcript"},
            regulation="FERPA",
        )
        f = isolator.build_metadata_filter(scope)
        clauses = f["$and"]
        assert any("sid" in c for c in clauses)
        assert any("rec_type" in c for c in clauses)


# ---------------------------------------------------------------------------
# query_sync
# ---------------------------------------------------------------------------


class TestQuerySync:
    def test_calls_index_query_with_namespace_and_filter(
        self, isolator: PineconeNamespaceIsolation, scope_with_categories: ComplianceFilter
    ) -> None:
        mock_index = MagicMock()
        mock_index.query.return_value = {"matches": []}
        vec = [0.1, 0.2, 0.3]

        isolator.query_sync(mock_index, vector=vec, scope=scope_with_categories, top_k=5)

        mock_index.query.assert_called_once()
        call_kwargs = mock_index.query.call_args.kwargs
        assert call_kwargs["namespace"] == "strayer"  # institution_id is namespace
        assert call_kwargs["top_k"] == 5
        assert call_kwargs["include_metadata"] is True
        assert call_kwargs["vector"] == vec

    def test_filter_in_sync_call_has_student_id(
        self, isolator: PineconeNamespaceIsolation, scope_with_categories: ComplianceFilter
    ) -> None:
        mock_index = MagicMock()
        mock_index.query.return_value = {"matches": []}

        isolator.query_sync(mock_index, vector=[0.1], scope=scope_with_categories)

        call_kwargs = mock_index.query.call_args.kwargs
        import json

        f = json.dumps(call_kwargs["filter"])
        assert "stu-001" in f

    def test_cross_institution_uses_different_namespace(self, isolator: PineconeNamespaceIsolation) -> None:
        scope_a = ComplianceFilter(
            student_id="s1", institution_id="inst-a", permitted_categories=set(), regulation="FERPA"
        )
        scope_b = ComplianceFilter(
            student_id="s2", institution_id="inst-b", permitted_categories=set(), regulation="FERPA"
        )
        mock_index = MagicMock()
        mock_index.query.return_value = {"matches": []}

        isolator.query_sync(mock_index, vector=[0.1], scope=scope_a)
        ns_a = mock_index.query.call_args.kwargs["namespace"]

        isolator.query_sync(mock_index, vector=[0.1], scope=scope_b)
        ns_b = mock_index.query.call_args.kwargs["namespace"]

        assert ns_a != ns_b  # institutions map to different namespaces


# ---------------------------------------------------------------------------
# async_query
# ---------------------------------------------------------------------------


class TestAsyncQuery:
    def test_async_query_calls_index_asyncio(
        self, isolator: PineconeNamespaceIsolation, scope_with_categories: ComplianceFilter
    ) -> None:
        mock_response = {"matches": [{"id": "v1", "score": 0.9}]}
        mock_idx = AsyncMock()
        mock_idx.query = AsyncMock(return_value=mock_response)

        # Create a proper async context manager mock
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_idx)
        cm.__aexit__ = AsyncMock(return_value=None)

        mock_pc = MagicMock()
        mock_pc.IndexAsyncio.return_value = cm

        result = asyncio.run(isolator.async_query(mock_pc, vector=[0.1, 0.2], scope=scope_with_categories, top_k=3))

        mock_pc.IndexAsyncio.assert_called_once_with(host="my-idx.svc.us-east1.pinecone.io")
        mock_idx.query.assert_called_once()
        call_kwargs = mock_idx.query.call_args.kwargs
        assert call_kwargs["namespace"] == "strayer"
        assert call_kwargs["top_k"] == 3
        assert call_kwargs["include_metadata"] is True
        assert result == mock_response

    def test_async_query_namespace_isolation(self, isolator: PineconeNamespaceIsolation) -> None:
        """Different institutions produce different namespaces in async queries."""
        scope_inst_x = ComplianceFilter(
            student_id="s1", institution_id="inst-x", permitted_categories=set(), regulation="FERPA"
        )
        scope_inst_y = ComplianceFilter(
            student_id="s2", institution_id="inst-y", permitted_categories=set(), regulation="FERPA"
        )

        namespaces_used: list[str] = []

        async def mock_query(**kwargs: Any) -> dict[str, Any]:
            namespaces_used.append(kwargs.get("namespace", ""))
            return {"matches": []}

        async def run_both() -> None:
            for scope in (scope_inst_x, scope_inst_y):
                mock_idx = AsyncMock()
                mock_idx.query = mock_query  # type: ignore[assignment]
                cm = MagicMock()
                cm.__aenter__ = AsyncMock(return_value=mock_idx)
                cm.__aexit__ = AsyncMock(return_value=None)
                mock_pc = MagicMock()
                mock_pc.IndexAsyncio.return_value = cm
                await isolator.async_query(mock_pc, vector=[0.1], scope=scope)

        asyncio.run(run_both())
        assert len(namespaces_used) == 2
        assert namespaces_used[0] != namespaces_used[1]
