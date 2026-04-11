"""
pinecone_adapter.py — Pinecone metadata filter adapter for FERPA/HIPAA compliance scoping.

Builds a Pinecone-compatible filter dict suitable for use with
``pinecone.Index.query(filter=...)``.

Pinecone filter syntax reference (v8):
  - Exact match:   {"key": {"$eq": "value"}}
  - Set membership: {"key": {"$in": ["a", "b"]}}
  - Logical AND:   {"$and": [{...}, {...}]}

See: https://docs.pinecone.io/docs/metadata-filtering

Regulatory context:
  FERPA 34 CFR § 99.3: retrieval must be scoped to the authorised student's
  records at the index query layer, not post-hoc in application code.
"""

from __future__ import annotations

from typing import Any

from .base import ComplianceFilter, VectorStoreFilterAdapter


class PineconeComplianceFilter(VectorStoreFilterAdapter):
    """
    Builds a Pinecone metadata filter dict for FERPA/HIPAA compliance scoping.

    The produced dict can be passed directly to
    ``pinecone.Index.query(filter=...)`` or ``Index.upsert`` namespace queries.

    Pinecone executes the filter at the ANN search layer, so only vectors whose
    metadata matches the filter are considered — pre-filter semantics by default
    when ``serverless_index=True`` or when the index has metadata index enabled.

    Example::

        adapter = PineconeComplianceFilter()
        f = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="strayer",
            permitted_categories={"academic_record", "directory_information"},
        ))
        # f == {
        #     "$and": [
        #         {"student_id": {"$eq": "S-001"}},
        #         {"institution_id": {"$eq": "strayer"}},
        #         {"category": {"$in": ["academic_record", "directory_information"]}},
        #     ]
        # }
        index.query(vector=embedding, filter=f, top_k=10)
    """

    def build_filter(self, scope: ComplianceFilter) -> dict[str, Any]:
        """
        Build a Pinecone ``$and`` filter dict from *scope*.

        Always includes student_id and institution_id exact-match clauses.
        Adds a category ``$in`` clause when ``scope.permitted_categories`` is
        non-empty.  The metadata fields are assumed to be named ``student_id``,
        ``institution_id``, and ``category`` on each Pinecone vector — adjust
        the field names via subclassing if your index uses different names.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A ``dict`` compatible with ``pinecone.Index.query(filter=...)``.
        """
        clauses: list[dict[str, Any]] = [
            {"student_id": {"$eq": scope.student_id}},
            {"institution_id": {"$eq": scope.institution_id}},
        ]

        if scope.permitted_categories:
            clauses.append({"category": {"$in": sorted(scope.permitted_categories)}})

        return {"$and": clauses}
