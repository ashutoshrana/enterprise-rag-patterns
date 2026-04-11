"""
chroma_adapter.py — ChromaDB where-filter adapter for FERPA/HIPAA compliance scoping.

Builds a ChromaDB ``where`` dict suitable for use with
``collection.query(where=...)``.

ChromaDB filter syntax (v1.5+):
  - Exact match:    {"key": {"$eq": "value"}}
  - Set membership: {"key": {"$in": ["a", "b"]}}
  - Logical AND:    {"$and": [{...}, {...}]}

See: https://docs.trychroma.com/guides#using-where-filters

No optional import is needed — ChromaDB filters are plain Python dicts.

Regulatory context:
  FERPA 34 CFR § 99.3: pre-filter retrieval to authorised student records;
  do not rely on post-hoc LLM output filtering to enforce access boundaries.
"""

from __future__ import annotations

from typing import Any

from .base import ComplianceFilter, VectorStoreFilterAdapter


class ChromaComplianceFilter(VectorStoreFilterAdapter):
    """
    Builds a ChromaDB ``where`` filter dict for compliance-scoped queries.

    The returned dict can be passed directly to ``collection.query(where=...)``.
    ChromaDB evaluates the filter on stored document metadata before returning
    results, providing pre-filter semantics.

    Example::

        adapter = ChromaComplianceFilter()
        f = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="strayer",
            permitted_categories={"academic_record", "directory_information"},
        ))
        results = collection.query(
            query_embeddings=[embedding],
            where=f,
            n_results=5,
        )
    """

    def build_filter(self, scope: ComplianceFilter) -> dict[str, Any]:
        """
        Build a ChromaDB ``$and`` where-filter dict from *scope*.

        Always includes student_id and institution_id exact-match clauses.
        When ``scope.permitted_categories`` is non-empty, a category ``$in``
        clause is appended.

        Metadata field names assumed: ``student_id``, ``institution_id``,
        ``category``.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A ``dict`` compatible with ``chromadb.Collection.query(where=...)``.
        """
        clauses: list[dict[str, Any]] = [
            {"student_id": {"$eq": scope.student_id}},
            {"institution_id": {"$eq": scope.institution_id}},
        ]

        if scope.permitted_categories:
            clauses.append({"category": {"$in": sorted(scope.permitted_categories)}})

        # ChromaDB requires $and to wrap a list; when there is only one clause
        # (no categories), wrap it anyway for structural consistency — ChromaDB
        # accepts $and with a single-element list.
        return {"$and": clauses}
