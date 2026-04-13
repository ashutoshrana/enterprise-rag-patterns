"""Tests for PGVectorComplianceFilter and PGVectorSQLAlchemyFilter."""

from __future__ import annotations

import pytest

from enterprise_rag_patterns.vector_stores.base import ComplianceFilter
from enterprise_rag_patterns.vector_stores.pgvector_adapter import (
    PGVectorComplianceFilter,
    PGVectorSQLAlchemyFilter,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope(
    student_id: str = "S-001",
    institution_id: str = "acme-univ",
    categories: set[str] | None = None,
) -> ComplianceFilter:
    return ComplianceFilter(
        student_id=student_id,
        institution_id=institution_id,
        permitted_categories=categories or set(),
    )


# ===========================================================================
# PGVectorComplianceFilter — JSON metadata column (default)
# ===========================================================================


class TestPGVectorComplianceFilterJSONColumn:
    def _adapter(self) -> PGVectorComplianceFilter:
        return PGVectorComplianceFilter()

    def test_returns_tuple_of_str_and_list(self) -> None:
        where_sql, params = self._adapter().build_filter(_scope())
        assert isinstance(where_sql, str)
        assert isinstance(params, list)

    def test_student_id_clause_json(self) -> None:
        where_sql, params = self._adapter().build_filter(_scope(student_id="S-002"))
        assert "metadata->>'student_id'" in where_sql
        assert "S-002" in params

    def test_institution_id_clause_json(self) -> None:
        where_sql, params = self._adapter().build_filter(_scope(institution_id="acme-univ-b"))
        assert "metadata->>'institution_id'" in where_sql
        assert "acme-univ-b" in params

    def test_no_category_clause_when_empty(self) -> None:
        where_sql, params = self._adapter().build_filter(_scope(categories=set()))
        assert "category" not in where_sql

    def test_category_clause_when_provided(self) -> None:
        where_sql, params = self._adapter().build_filter(
            _scope(categories={"academic_record", "directory_information"})
        )
        assert "metadata->>'category'" in where_sql
        assert "= ANY(%s)" in where_sql
        # categories are sorted in params
        cat_param = params[-1]
        assert sorted(["academic_record", "directory_information"]) == cat_param

    def test_params_order_student_institution_category(self) -> None:
        where_sql, params = self._adapter().build_filter(
            _scope(student_id="S-001", institution_id="acme-univ", categories={"academic_record"})
        )
        assert params[0] == "S-001"
        assert params[1] == "acme-univ"
        assert params[2] == ["academic_record"]

    def test_exactly_two_params_no_category(self) -> None:
        _, params = self._adapter().build_filter(_scope())
        assert len(params) == 2

    def test_exactly_three_params_with_category(self) -> None:
        _, params = self._adapter().build_filter(_scope(categories={"x", "y"}))
        assert len(params) == 3

    def test_clauses_joined_with_and(self) -> None:
        where_sql, _ = self._adapter().build_filter(_scope())
        assert " AND " in where_sql

    def test_custom_metadata_column_name(self) -> None:
        adapter = PGVectorComplianceFilter(metadata_column_name="doc_meta")
        where_sql, _ = adapter.build_filter(_scope())
        assert "doc_meta->>'student_id'" in where_sql

    def test_custom_field_names(self) -> None:
        adapter = PGVectorComplianceFilter(
            student_id_field="learner_id",
            institution_id_field="org_id",
            category_field="doc_type",
        )
        where_sql, _ = adapter.build_filter(_scope(categories={"transcript"}))
        assert "learner_id" in where_sql
        assert "org_id" in where_sql
        assert "doc_type" in where_sql


# ===========================================================================
# PGVectorComplianceFilter — Normalised columns
# ===========================================================================


class TestPGVectorComplianceFilterNormalisedColumns:
    def _adapter(self) -> PGVectorComplianceFilter:
        return PGVectorComplianceFilter(use_json_column=False)

    def test_no_jsonb_arrow_operator(self) -> None:
        where_sql, _ = self._adapter().build_filter(_scope())
        assert "->>" not in where_sql

    def test_student_id_direct_column(self) -> None:
        where_sql, params = self._adapter().build_filter(_scope(student_id="S-003"))
        assert "student_id = %s" in where_sql
        assert "S-003" in params

    def test_institution_id_direct_column(self) -> None:
        where_sql, params = self._adapter().build_filter(_scope(institution_id="johns_hopkins"))
        assert "institution_id = %s" in where_sql
        assert "johns_hopkins" in params

    def test_category_any_clause(self) -> None:
        where_sql, params = self._adapter().build_filter(_scope(categories={"financial_aid"}))
        assert "category = ANY(%s)" in where_sql
        assert ["financial_aid"] in params

    def test_no_category_without_categories(self) -> None:
        where_sql, _ = self._adapter().build_filter(_scope())
        assert "category" not in where_sql


# ===========================================================================
# PGVectorComplianceFilter — asyncpg placeholders
# ===========================================================================


class TestPGVectorComplianceFilterAsyncpg:
    def _adapter(self) -> PGVectorComplianceFilter:
        return PGVectorComplianceFilter()

    def test_asyncpg_uses_dollar_placeholders(self) -> None:
        where_sql, _ = self._adapter().build_asyncpg_filter(_scope())
        assert "$1" in where_sql
        assert "$2" in where_sql
        assert "%s" not in where_sql

    def test_asyncpg_params_list(self) -> None:
        _, params = self._adapter().build_asyncpg_filter(_scope(student_id="S-001", institution_id="acme-univ"))
        assert params[0] == "S-001"
        assert params[1] == "acme-univ"

    def test_asyncpg_category_dollar_placeholder(self) -> None:
        where_sql, params = self._adapter().build_asyncpg_filter(_scope(categories={"academic_record"}))
        assert "$3" in where_sql
        assert "::text[]" in where_sql
        assert params[2] == ["academic_record"]

    def test_asyncpg_normalised_columns(self) -> None:
        adapter = PGVectorComplianceFilter(use_json_column=False)
        where_sql, _ = adapter.build_asyncpg_filter(_scope())
        assert "student_id = $1" in where_sql
        assert "institution_id = $2" in where_sql

    def test_asyncpg_no_category_two_params(self) -> None:
        _, params = self._adapter().build_asyncpg_filter(_scope())
        assert len(params) == 2


# ===========================================================================
# PGVectorSQLAlchemyFilter — without sqlalchemy installed
# ===========================================================================


class TestPGVectorSQLAlchemyFilterInit:
    def test_requires_metadata_or_columns(self) -> None:
        with pytest.raises(ValueError, match="metadata_column"):
            PGVectorSQLAlchemyFilter()

    def test_requires_both_student_and_institution_columns(self) -> None:
        with pytest.raises(ValueError):
            PGVectorSQLAlchemyFilter(student_id_column=object())

    def test_metadata_column_alone_is_valid(self) -> None:
        adapter = PGVectorSQLAlchemyFilter(metadata_column=object())
        assert adapter is not None

    def test_both_normalised_columns_valid(self) -> None:
        adapter = PGVectorSQLAlchemyFilter(
            student_id_column=object(),
            institution_id_column=object(),
        )
        assert adapter is not None


class TestPGVectorSQLAlchemyFilterWithSQLAlchemy:
    """Tests that actually invoke SQLAlchemy if available; skip otherwise."""

    def _try_import(self) -> None:
        pytest.importorskip("sqlalchemy", reason="sqlalchemy not installed")

    def _make_mock_jsonb_column(self) -> object:
        """Return a mock column that supports __getitem__ and as_string()."""
        from unittest.mock import MagicMock

        col = MagicMock()
        # Simulate: col["key"].as_string() == "value"
        col.__getitem__ = MagicMock(return_value=MagicMock())
        return col

    def test_build_filter_with_metadata_column_returns_expression(self) -> None:
        self._try_import()
        # Use a real SQLAlchemy JSONB column
        from sqlalchemy import Column, MetaData, String, Table

        meta = MetaData()
        docs = Table(
            "documents",
            meta,
            Column("metadata", String),  # simple column for test
        )
        adapter = PGVectorSQLAlchemyFilter(
            student_id_column=docs.c.metadata,
            institution_id_column=docs.c.metadata,
        )
        # Just verify it doesn't crash — normalised mode with same column
        filter_expr = adapter.build_filter(_scope())
        assert filter_expr is not None

    def test_build_filter_normalised_columns(self) -> None:
        self._try_import()
        from sqlalchemy import Column, MetaData, String, Table

        meta = MetaData()
        docs = Table(
            "documents",
            meta,
            Column("student_id", String),
            Column("institution_id", String),
            Column("category", String),
        )
        adapter = PGVectorSQLAlchemyFilter(
            student_id_column=docs.c.student_id,
            institution_id_column=docs.c.institution_id,
            category_column=docs.c.category,
        )
        filter_expr = adapter.build_filter(_scope(categories={"academic_record"}))
        assert filter_expr is not None
        # Compile to verify it produces valid SQL
        from sqlalchemy.dialects import sqlite

        compiled = str(filter_expr.compile(dialect=sqlite.dialect()))
        assert "student_id" in compiled
        assert "institution_id" in compiled

    def test_raises_import_error_without_sqlalchemy(self) -> None:
        """Simulate missing sqlalchemy — skip if it's installed."""
        import sys

        if "sqlalchemy" in sys.modules:
            pytest.skip("sqlalchemy is installed; cannot test ImportError path")

        adapter = PGVectorSQLAlchemyFilter(metadata_column=object())
        with pytest.raises(ImportError, match="sqlalchemy"):
            adapter.build_filter(_scope())


# ===========================================================================
# PGVectorComplianceFilter — query construction integration
# ===========================================================================


class TestPGVectorQueryConstruction:
    """Verify that the produced WHERE fragment embeds cleanly into SELECT queries."""

    def test_embeds_in_psycopg2_style_query(self) -> None:
        adapter = PGVectorComplianceFilter()
        where_sql, params = adapter.build_filter(
            _scope(student_id="S-001", institution_id="acme-univ", categories={"academic_record"})
        )
        query = f"SELECT id, content FROM documents WHERE {where_sql} ORDER BY embedding <=> %s LIMIT 5"
        all_params = params + ["[0.1, 0.2, ...]"]
        assert "metadata->>'student_id' = %s" in query
        assert len(all_params) == 4  # student, institution, categories, embedding

    def test_category_param_is_sorted_list(self) -> None:
        adapter = PGVectorComplianceFilter()
        _, params = adapter.build_filter(_scope(categories={"zzz", "aaa", "mmm"}))
        assert params[-1] == ["aaa", "mmm", "zzz"]

    def test_cross_institution_isolation(self) -> None:
        """Filters for two different students / institutions produce different params."""
        adapter = PGVectorComplianceFilter()
        _, params_a = adapter.build_filter(_scope(student_id="S-001", institution_id="acme-univ"))
        _, params_b = adapter.build_filter(_scope(student_id="S-002", institution_id="acme-univ-b"))
        assert params_a[0] != params_b[0]
        assert params_a[1] != params_b[1]
