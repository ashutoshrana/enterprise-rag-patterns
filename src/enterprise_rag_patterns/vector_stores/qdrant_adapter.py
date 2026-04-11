"""
qdrant_adapter.py — Qdrant filter adapter for FERPA/HIPAA compliance scoping.

Builds a Qdrant ``Filter`` object using ``FieldCondition`` / ``MatchValue``
and ``MatchAny`` from ``qdrant_client.models``.

Qdrant filter reference (v1.17+):
  https://qdrant.tech/documentation/concepts/filtering/

The ``qdrant_client`` import is lazy (inside ``build_filter``) so this module
can be imported without the ``qdrant-client`` package installed.

Regulatory context:
  FERPA 34 CFR § 99.3: retrieval must be scoped to the authorised student's
  records at the index query layer — pre-filter, not post-filter.
"""

from __future__ import annotations

from typing import Any

from .base import ComplianceFilter, VectorStoreFilterAdapter


class QdrantComplianceFilter(VectorStoreFilterAdapter):
    """
    Builds a Qdrant ``Filter`` object for compliance-scoped queries.

    Uses ``qdrant_client.models.Filter``, ``FieldCondition``, ``MatchValue``,
    and ``MatchAny`` (for category set membership).  The returned object can be
    passed to ``qdrant_client.QdrantClient.search(query_filter=...)``.

    Lazy import: ``qdrant_client`` is imported inside ``build_filter`` so that
    the package can be installed without the Qdrant client.

    Example::

        adapter = QdrantComplianceFilter()
        f = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="strayer",
            permitted_categories={"academic_record", "directory_information"},
        ))
        results = client.search(
            collection_name="student_docs",
            query_vector=embedding,
            query_filter=f,
            limit=5,
        )
    """

    def build_filter(self, scope: ComplianceFilter) -> Any:
        """
        Build a Qdrant ``Filter`` object from *scope*.

        Creates a ``must`` clause list containing:
        1. ``FieldCondition(key="student_id", match=MatchValue(...))``
        2. ``FieldCondition(key="institution_id", match=MatchValue(...))``
        3. ``FieldCondition(key="category", match=MatchAny(any=[...]))``
           (only when ``scope.permitted_categories`` is non-empty).

        Metadata payload keys assumed: ``student_id``, ``institution_id``,
        ``category``.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A ``qdrant_client.models.Filter`` instance (typed as ``Any``).

        Raises:
            ImportError: If ``qdrant-client`` is not installed.
        """
        try:
            from qdrant_client.models import FieldCondition, Filter, MatchAny, MatchValue
        except ImportError as exc:
            raise ImportError(
                "qdrant-client is required for QdrantComplianceFilter. "
                "Install it with: pip install qdrant-client>=1.9.0"
            ) from exc

        must_conditions: list[Any] = [
            FieldCondition(key="student_id", match=MatchValue(value=scope.student_id)),
            FieldCondition(key="institution_id", match=MatchValue(value=scope.institution_id)),
        ]

        if scope.permitted_categories:
            must_conditions.append(
                FieldCondition(
                    key="category",
                    match=MatchAny(any=sorted(scope.permitted_categories)),
                )
            )

        return Filter(must=must_conditions)
