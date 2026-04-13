"""
base.py — Abstract base types for compliance-scoped vector store filter adapters.

Each vector store expresses metadata filters differently. This module provides a
common dataclass (ComplianceFilter) and abstract adapter interface so callers can
build a filter once and dispatch to any supported store without conditional logic
in application code.

Design principle: filter adapters are *pure functions wrapped in objects* — they
hold no mutable state and produce a new filter object on every call to
``build_filter``.

Regulatory context:
  FERPA 34 CFR § 99.3 requires that retrieval be scoped to records for which
  legitimate educational interest exists. Pre-filtering at the vector store layer
  (rather than post-filtering LLM output) is the preferred enforcement point; see
  docs/adr/001-pre-filter-not-post-filter.md for the architectural rationale.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ComplianceFilter:
    """
    Portable filter specification for compliance-scoped vector store queries.

    Instances are created once per retrieval request and passed to a
    ``VectorStoreFilterAdapter`` to produce a store-specific filter object.

    Attributes:
        student_id: Unique institutional identifier for the student whose
            records are being retrieved.  Used for exact-match filtering.
        institution_id: Identifier for the institution scoping this request.
            In multi-tenant deployments, prevents cross-institution record bleed.
        permitted_categories: Whitelist of record-category strings the caller is
            authorised to retrieve (e.g. ``{"academic_record", "directory_information"}``).
            When empty, no category filter is applied (use with caution — typically only
            appropriate for non-FERPA content collections).
        regulation: Identifier for the governing regulation, used for audit tagging.
            Defaults to ``"FERPA"``.
    """

    student_id: str
    institution_id: str
    permitted_categories: set[str] = field(default_factory=set)
    regulation: str = "FERPA"


class VectorStoreFilterAdapter(ABC):
    """
    Abstract base class for compliance-scoped vector store filter adapters.

    Subclasses translate a ``ComplianceFilter`` into the native filter format
    expected by a specific vector store.  All optional library imports must be
    lazy (inside ``build_filter``) so that the package can be imported without
    any vector store client installed.

    Example::

        adapter = PineconeComplianceFilter()
        f = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="acme-univ",
            permitted_categories={"academic_record"},
        ))
        index.query(vector=embedding, filter=f, top_k=5)
    """

    @abstractmethod
    def build_filter(self, scope: ComplianceFilter) -> Any:
        """
        Build a vector-store-native filter object from *scope*.

        Args:
            scope: The compliance scope specifying student, institution, and
                permitted record categories.

        Returns:
            A filter value in the format expected by the target vector store's
            query API.  The concrete return type depends on the adapter.
        """
        ...  # pragma: no cover
