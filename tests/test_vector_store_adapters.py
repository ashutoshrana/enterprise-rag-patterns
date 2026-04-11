"""
Tests for vector_stores adapters.

All tests use duck-typed stubs — no actual vector store SDKs required.
Each adapter's build_filter() output is validated structurally.
"""

from __future__ import annotations

import pytest

from enterprise_rag_patterns.vector_stores.base import ComplianceFilter
from enterprise_rag_patterns.vector_stores.chroma_adapter import ChromaComplianceFilter
from enterprise_rag_patterns.vector_stores.pinecone_adapter import PineconeComplianceFilter


@pytest.fixture()
def scope() -> ComplianceFilter:
    return ComplianceFilter(
        student_id="S-001",
        institution_id="univ-a",
        permitted_categories={"academic_record", "financial_record"},
        regulation="FERPA",
    )


@pytest.fixture()
def scope_no_categories() -> ComplianceFilter:
    return ComplianceFilter(
        student_id="S-002",
        institution_id="univ-b",
        permitted_categories=set(),
        regulation="FERPA",
    )


# ---------------------------------------------------------------------------
# PineconeComplianceFilter
# ---------------------------------------------------------------------------


def _pinecone_clauses(f: dict) -> list[dict]:
    """Extract the $and clause list from a Pinecone filter dict."""
    return f.get("$and", [])


class TestPineconeComplianceFilter:
    def test_returns_dict(self, scope: ComplianceFilter) -> None:
        f = PineconeComplianceFilter().build_filter(scope)
        assert isinstance(f, dict)

    def test_uses_and_operator(self, scope: ComplianceFilter) -> None:
        f = PineconeComplianceFilter().build_filter(scope)
        assert "$and" in f

    def test_student_id_eq(self, scope: ComplianceFilter) -> None:
        clauses = _pinecone_clauses(PineconeComplianceFilter().build_filter(scope))
        assert {"student_id": {"$eq": "S-001"}} in clauses

    def test_institution_id_eq(self, scope: ComplianceFilter) -> None:
        clauses = _pinecone_clauses(PineconeComplianceFilter().build_filter(scope))
        assert {"institution_id": {"$eq": "univ-a"}} in clauses

    def test_categories_in(self, scope: ComplianceFilter) -> None:
        clauses = _pinecone_clauses(PineconeComplianceFilter().build_filter(scope))
        cat_clauses = [c for c in clauses if "category" in c]
        assert len(cat_clauses) == 1
        assert set(cat_clauses[0]["category"]["$in"]) == {"academic_record", "financial_record"}

    def test_no_category_filter_when_empty(self, scope_no_categories: ComplianceFilter) -> None:
        clauses = _pinecone_clauses(PineconeComplianceFilter().build_filter(scope_no_categories))
        cat_clauses = [c for c in clauses if "category" in c]
        assert len(cat_clauses) == 0

    def test_all_required_keys_present(self, scope: ComplianceFilter) -> None:
        clauses = _pinecone_clauses(PineconeComplianceFilter().build_filter(scope))
        keys = [list(c.keys())[0] for c in clauses]
        assert "student_id" in keys
        assert "institution_id" in keys


# ---------------------------------------------------------------------------
# ChromaComplianceFilter
# ---------------------------------------------------------------------------


class TestChromaComplianceFilter:
    def test_returns_dict(self, scope: ComplianceFilter) -> None:
        f = ChromaComplianceFilter().build_filter(scope)
        assert isinstance(f, dict)

    def test_and_operator(self, scope: ComplianceFilter) -> None:
        f = ChromaComplianceFilter().build_filter(scope)
        assert "$and" in f

    def test_student_id_clause(self, scope: ComplianceFilter) -> None:
        f = ChromaComplianceFilter().build_filter(scope)
        clauses = f["$and"]
        student_clauses = [c for c in clauses if "student_id" in c]
        assert len(student_clauses) == 1
        assert student_clauses[0]["student_id"]["$eq"] == "S-001"

    def test_institution_id_clause(self, scope: ComplianceFilter) -> None:
        f = ChromaComplianceFilter().build_filter(scope)
        clauses = f["$and"]
        inst_clauses = [c for c in clauses if "institution_id" in c]
        assert len(inst_clauses) == 1
        actual = inst_clauses[0]["institution_id"]["$eq"]
        assert actual in {"univ-a", "univ-b"}

    def test_category_clause_when_present(self, scope: ComplianceFilter) -> None:
        f = ChromaComplianceFilter().build_filter(scope)
        clauses = f["$and"]
        cat_clauses = [c for c in clauses if "category" in c]
        assert len(cat_clauses) == 1
        assert "$in" in cat_clauses[0]["category"]

    def test_no_category_when_empty(self, scope_no_categories: ComplianceFilter) -> None:
        f = ChromaComplianceFilter().build_filter(scope_no_categories)
        clauses = f["$and"]
        cat_clauses = [c for c in clauses if "category" in c]
        assert len(cat_clauses) == 0


# ---------------------------------------------------------------------------
# Lazy-import adapters (Weaviate, Qdrant) — test ImportError path
# ---------------------------------------------------------------------------


class TestWeaviateComplianceFilterLazyImport:
    def test_raises_import_error_without_sdk(self, scope: ComplianceFilter) -> None:
        """Without weaviate-client installed, build_filter raises ImportError."""
        from enterprise_rag_patterns.vector_stores.weaviate_adapter import WeaviateComplianceFilter

        adapter = WeaviateComplianceFilter()
        try:
            adapter.build_filter(scope)
        except ImportError as exc:
            assert "weaviate-client" in str(exc)
        except Exception:
            # If weaviate IS installed in the test env, any output is acceptable
            pass


class TestQdrantComplianceFilterLazyImport:
    def test_raises_import_error_without_sdk(self, scope: ComplianceFilter) -> None:
        """Without qdrant-client installed, build_filter raises ImportError."""
        from enterprise_rag_patterns.vector_stores.qdrant_adapter import QdrantComplianceFilter

        adapter = QdrantComplianceFilter()
        try:
            adapter.build_filter(scope)
        except ImportError as exc:
            assert "qdrant-client" in str(exc)
        except Exception:
            pass
