"""
pgvector_adapter.py — pgvector / PostgreSQL compliance filter adapters.

PostgreSQL with the ``pgvector`` extension is the most common enterprise vector
store: organisations that already run PostgreSQL can add vector search without
adopting a new infrastructure component.

This module provides two adapters:

1. ``PGVectorComplianceFilter`` — produces SQL ``WHERE`` clause fragments and
   parameterised argument tuples for direct ``psycopg2`` / ``asyncpg`` queries.

2. ``PGVectorSQLAlchemyFilter`` — produces a ``sqlalchemy.sql.ColumnElement``
   (boolean expression) for use with SQLAlchemy ORM / Core queries.  This is the
   recommended adapter for FastAPI applications using SQLAlchemy sessions.

Both adapters support two common pgvector schema layouts:

**JSON metadata column** (most common)::

    CREATE TABLE documents (
        id         BIGSERIAL PRIMARY KEY,
        embedding  VECTOR(1536),
        metadata   JSONB NOT NULL DEFAULT '{}'
    );

    -- Query pattern (psycopg2 parameterised):
    SELECT ... FROM documents
    WHERE embedding <=> %s < 0.5
      AND metadata->>'student_id' = %s
      AND metadata->>'institution_id' = %s
      AND metadata->>'category' = ANY(%s);

**Normalised columns** (explicit schema)::

    CREATE TABLE documents (
        id             BIGSERIAL PRIMARY KEY,
        embedding      VECTOR(1536),
        student_id     TEXT NOT NULL,
        institution_id TEXT NOT NULL,
        category       TEXT
    );

Usage — psycopg2 (JSON metadata column)::

    from enterprise_rag_patterns.vector_stores.pgvector_adapter import PGVectorComplianceFilter
    from enterprise_rag_patterns.vector_stores.base import ComplianceFilter

    adapter = PGVectorComplianceFilter()
    where_sql, params = adapter.build_filter(ComplianceFilter(
        student_id="S-001",
        institution_id="acme-univ",
        permitted_categories={"academic_record", "directory_information"},
    ))
    cursor.execute(
        f"SELECT id, content FROM documents WHERE {where_sql} LIMIT 5",
        params,
    )

Usage — normalised columns::

    adapter = PGVectorComplianceFilter(use_json_column=False)
    where_sql, params = adapter.build_filter(...)
    # Produces direct column comparisons: student_id = %s AND ...

Usage — SQLAlchemy::

    from enterprise_rag_patterns.vector_stores.pgvector_adapter import PGVectorSQLAlchemyFilter

    adapter = PGVectorSQLAlchemyFilter(metadata_column=Document.metadata)
    filter_expr = adapter.build_filter(ComplianceFilter(
        student_id="S-001",
        institution_id="acme-univ",
        permitted_categories={"academic_record"},
    ))
    results = session.scalars(
        select(Document).where(filter_expr).limit(5)
    ).all()

Regulatory context:
    FERPA 34 CFR § 99.3 requires that retrieval be scoped to the authorised
    student's records at the vector index query layer — pre-filter semantics.
    SQL WHERE clauses applied before the ``<=>`` (cosine distance) ranking step
    satisfy this requirement; pgvector applies the filter before computing ANN
    distances when an index scan is used.
"""

from __future__ import annotations

from typing import Any

from .base import ComplianceFilter, VectorStoreFilterAdapter


class PGVectorComplianceFilter(VectorStoreFilterAdapter):
    """
    Builds a SQL ``WHERE`` clause fragment + parameterised arguments tuple.

    The returned tuple ``(where_sql, params)`` is designed for direct use with
    ``psycopg2`` or ``asyncpg``::

        where_sql, params = adapter.build_filter(scope)
        cursor.execute(
            f"SELECT id, content, metadata FROM documents "
            f"WHERE {where_sql} "
            f"ORDER BY embedding <=> %s LIMIT 10",
            params + (embedding_bytes,),
        )

    Attributes:
        use_json_column: When ``True`` (default), filters use JSONB arrow
            operators (``metadata->>'field' = %s``).  When ``False``, filters
            use direct column comparisons (``student_id = %s``).
        metadata_column_name: Name of the JSONB metadata column.  Only used
            when ``use_json_column=True``.  Default: ``"metadata"``.
        student_id_field: Metadata key / column name for student identifier.
        institution_id_field: Metadata key / column name for institution.
        category_field: Metadata key / column name for record category.
    """

    def __init__(
        self,
        use_json_column: bool = True,
        metadata_column_name: str = "metadata",
        student_id_field: str = "student_id",
        institution_id_field: str = "institution_id",
        category_field: str = "category",
    ) -> None:
        self._use_json = use_json_column
        self._meta = metadata_column_name
        self._student_field = student_id_field
        self._institution_field = institution_id_field
        self._category_field = category_field

    def build_filter(self, scope: ComplianceFilter) -> tuple[str, list[Any]]:
        """
        Build a SQL WHERE fragment and parameter list from *scope*.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A tuple ``(where_sql, params)`` where:
            - ``where_sql`` is a SQL boolean expression string (no leading
              ``WHERE`` keyword) suitable for embedding in a larger query.
            - ``params`` is a list of positional parameter values for
              ``cursor.execute(sql, params)``.

        Example (JSON column)::

            where_sql == (
                "metadata->>'student_id' = %s "
                "AND metadata->>'institution_id' = %s "
                "AND metadata->>'category' = ANY(%s)"
            )
            params == ["S-001", "acme-univ", ["academic_record"]]
        """
        clauses: list[str] = []
        params: list[Any] = []

        if self._use_json:
            clauses.append(f"{self._meta}->>'{self._student_field}' = %s")
            params.append(scope.student_id)
            clauses.append(f"{self._meta}->>'{self._institution_field}' = %s")
            params.append(scope.institution_id)
            if scope.permitted_categories:
                clauses.append(f"{self._meta}->>'{self._category_field}' = ANY(%s)")
                params.append(sorted(scope.permitted_categories))
        else:
            clauses.append(f"{self._student_field} = %s")
            params.append(scope.student_id)
            clauses.append(f"{self._institution_field} = %s")
            params.append(scope.institution_id)
            if scope.permitted_categories:
                clauses.append(f"{self._category_field} = ANY(%s)")
                params.append(sorted(scope.permitted_categories))

        return " AND ".join(clauses), params

    def build_asyncpg_filter(self, scope: ComplianceFilter) -> tuple[str, list[Any]]:
        """
        Build a SQL WHERE fragment using ``asyncpg`` ``$N`` placeholders.

        ``asyncpg`` uses positional ``$1``, ``$2``, … placeholders instead of
        ``%s``.  Start index defaults to 1 but can be offset for queries that
        already have earlier parameters (e.g. the embedding vector).

        Args:
            scope: Compliance filter.

        Returns:
            ``(where_sql, params)`` with ``$N``-style placeholders.
        """
        clauses: list[str] = []
        params: list[Any] = []
        idx = 1

        if self._use_json:
            clauses.append(f"{self._meta}->>'{self._student_field}' = ${idx}")
            params.append(scope.student_id)
            idx += 1
            clauses.append(f"{self._meta}->>'{self._institution_field}' = ${idx}")
            params.append(scope.institution_id)
            idx += 1
            if scope.permitted_categories:
                clauses.append(f"{self._meta}->>'{self._category_field}' = ANY(${idx}::text[])")
                params.append(sorted(scope.permitted_categories))
        else:
            clauses.append(f"{self._student_field} = ${idx}")
            params.append(scope.student_id)
            idx += 1
            clauses.append(f"{self._institution_field} = ${idx}")
            params.append(scope.institution_id)
            idx += 1
            if scope.permitted_categories:
                clauses.append(f"{self._category_field} = ANY(${idx}::text[])")
                params.append(sorted(scope.permitted_categories))

        return " AND ".join(clauses), params


class PGVectorSQLAlchemyFilter(VectorStoreFilterAdapter):
    """
    Builds a SQLAlchemy boolean filter expression for pgvector compliance scoping.

    This adapter is designed for applications using SQLAlchemy ORM or Core, the
    standard approach in FastAPI applications.

    Supports two schema styles:
    - **JSONB column**: filters on ``Model.metadata_col["field"].as_string()``
    - **Normalised columns**: filters on dedicated ``Model.student_id``, etc.

    Example (JSONB column)::

        from sqlalchemy.orm import DeclarativeBase
        from sqlalchemy import Column, Text
        from pgvector.sqlalchemy import Vector

        class Document(Base):
            __tablename__ = "documents"
            id = Column(Integer, primary_key=True)
            embedding = Column(Vector(1536))
            metadata = Column(JSONB)

        adapter = PGVectorSQLAlchemyFilter(metadata_column=Document.metadata)
        filter_expr = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="acme-univ",
            permitted_categories={"academic_record"},
        ))
        results = session.scalars(
            select(Document).where(filter_expr).limit(5)
        ).all()

    Example (normalised columns)::

        adapter = PGVectorSQLAlchemyFilter(
            student_id_column=Document.student_id,
            institution_id_column=Document.institution_id,
            category_column=Document.category,
        )

    Args:
        metadata_column: SQLAlchemy ``JSONB`` column expression.  Provide this
            OR the three ``*_column`` kwargs — not both.
        student_id_column: SQLAlchemy column expression for student_id.
        institution_id_column: SQLAlchemy column expression for institution_id.
        category_column: SQLAlchemy column expression for record category.
        student_id_key: Key name inside the JSONB column. Default ``"student_id"``.
        institution_id_key: Key name inside the JSONB column. Default ``"institution_id"``.
        category_key: Key name inside the JSONB column. Default ``"category"``.
    """

    def __init__(
        self,
        metadata_column: Any | None = None,
        student_id_column: Any | None = None,
        institution_id_column: Any | None = None,
        category_column: Any | None = None,
        student_id_key: str = "student_id",
        institution_id_key: str = "institution_id",
        category_key: str = "category",
    ) -> None:
        if metadata_column is None and (student_id_column is None or institution_id_column is None):
            raise ValueError(
                "Provide either metadata_column (JSONB) "
                "or student_id_column + institution_id_column (normalised columns)."
            )
        self._metadata_col = metadata_column
        self._student_col = student_id_column
        self._institution_col = institution_id_column
        self._category_col = category_column
        self._student_key = student_id_key
        self._institution_key = institution_id_key
        self._category_key = category_key

    def build_filter(self, scope: ComplianceFilter) -> Any:
        """
        Build a SQLAlchemy boolean filter expression from *scope*.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A ``sqlalchemy.sql.ColumnElement`` that can be passed to
            ``select(Model).where(filter_expr)``.

        Raises:
            ImportError: If ``sqlalchemy`` is not installed.
        """
        try:
            from sqlalchemy import and_, or_
        except ImportError as exc:
            raise ImportError(
                "sqlalchemy is required for PGVectorSQLAlchemyFilter. Install it with: pip install sqlalchemy>=2.0"
            ) from exc

        conditions: list[Any] = []

        if self._metadata_col is not None:
            # JSONB column: metadata['key'].as_string() == value
            conditions.append(self._metadata_col[self._student_key].as_string() == scope.student_id)
            conditions.append(self._metadata_col[self._institution_key].as_string() == scope.institution_id)
            if scope.permitted_categories:
                # metadata['category'].as_string() IN (...)
                cat_list = sorted(scope.permitted_categories)
                conditions.append(or_(*[self._metadata_col[self._category_key].as_string() == cat for cat in cat_list]))
        else:
            # Normalised columns
            conditions.append(self._student_col == scope.student_id)
            conditions.append(self._institution_col == scope.institution_id)
            if scope.permitted_categories and self._category_col is not None:
                conditions.append(self._category_col.in_(sorted(scope.permitted_categories)))

        return and_(*conditions)
