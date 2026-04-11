"""
weaviate_adapter.py — Weaviate v4 filter adapter for FERPA/HIPAA compliance scoping.

Builds a Weaviate ``Filter`` object using the v4 client API:
  ``Filter.by_property("key").equal("value")``
combined with the ``&`` operator for logical AND.

Weaviate client v4 filter reference:
  https://weaviate.io/developers/weaviate/search/filters

The ``weaviate`` import is lazy (inside ``build_filter``) so this module can be
imported without the ``weaviate-client`` package installed.

Regulatory context:
  FERPA 34 CFR § 99.3: pre-filter retrieval to authorised student records before
  results enter the LLM context window.
"""

from __future__ import annotations

from typing import Any

from .base import ComplianceFilter, VectorStoreFilterAdapter


class WeaviateComplianceFilter(VectorStoreFilterAdapter):
    """
    Builds a Weaviate v4 ``Filter`` object for compliance-scoped queries.

    Uses the ``weaviate.classes.query.Filter`` fluent API introduced in the
    v4 Python client.  The returned object can be passed to ``collection.query``
    methods via the ``filters=`` keyword argument.

    Lazy import: ``weaviate`` is imported inside ``build_filter`` so that the
    package can be installed and imported without ``weaviate-client``.

    Example::

        adapter = WeaviateComplianceFilter()
        f = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="strayer",
            permitted_categories={"academic_record"},
        ))
        results = collection.query.near_text(
            query="degree requirements",
            filters=f,
            limit=5,
        )
    """

    def build_filter(self, scope: ComplianceFilter) -> Any:
        """
        Build a Weaviate v4 ``Filter`` object from *scope*.

        Combines student_id, institution_id, and (if present) category filters
        using the ``&`` operator.  Category membership is expressed as a disjunction
        (``|`` over ``equal``) since Weaviate v4 does not have a native ``$in``
        operator — each permitted category becomes an ``OR`` branch.

        Metadata property names assumed: ``student_id``, ``institution_id``,
        ``category``.  Adjust by subclassing if your schema differs.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A ``weaviate.classes.query.Filter`` object (typed as ``Any`` to
            avoid hard import at module level).

        Raises:
            ImportError: If ``weaviate-client`` is not installed.
        """
        try:
            from weaviate.classes.query import Filter
        except ImportError as exc:
            raise ImportError(
                "weaviate-client is required for WeaviateComplianceFilter. "
                "Install it with: pip install weaviate-client>=4.0.0"
            ) from exc

        combined: Any = Filter.by_property("student_id").equal(scope.student_id) & Filter.by_property(
            "institution_id"
        ).equal(scope.institution_id)

        if scope.permitted_categories:
            categories = sorted(scope.permitted_categories)
            # Build OR chain over individual equal() filters — Weaviate v4 has no native $in
            cat_filter: Any = Filter.by_property("category").equal(categories[0])
            for cat in categories[1:]:
                cat_filter = cat_filter | Filter.by_property("category").equal(cat)
            combined = combined & cat_filter

        return combined
