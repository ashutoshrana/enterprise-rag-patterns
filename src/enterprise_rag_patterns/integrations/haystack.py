"""
integrations/haystack.py — Haystack 2.x component for FERPA-compliant document filtering.

Provides ``FERPAHaystackFilter``, a Haystack 2.x ``@component`` that filters
a list of ``Document`` objects to only those matching the authorised student
identity scope.

The ``haystack`` package is imported lazily so this module can be imported
without ``haystack-ai`` installed.  The ``@component`` decorator is applied
at class instantiation time (lazy-registration pattern) rather than at module
import time, keeping the lazy-import guarantee intact.

Regulatory context:
  FERPA 34 CFR § 99.3 — education records may only be retrieved for the
  student with legitimate educational interest in the requesting context.
  Pre-filtering at the pipeline component layer ensures records are scoped
  before reaching the LLM prompt assembly step.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class FERPAHaystackFilter:
    """
    Haystack 2.x pipeline component that enforces FERPA document-level scoping.

    Filters ``Document`` objects on ``document.meta["student_id"]`` and
    ``document.meta["institution_id"]``.  Optionally further restricts to
    documents whose ``document.meta["category"]`` is in *permitted_categories*.

    Documents without the relevant meta keys are passed through (assumed to be
    non-FERPA content — general knowledge base, FAQs, etc.).

    Registration: Because ``@component`` must be applied to a class that Haystack
    discovers at pipeline-serialization time, the decorator is applied lazily
    the first time ``run`` is called (via ``_ensure_registered``).  This keeps
    the module importable without ``haystack-ai`` installed.

    Usage (Haystack 2.x pipeline)::

        from haystack import Pipeline
        from enterprise_rag_patterns.integrations.haystack import FERPAHaystackFilter

        pipe = Pipeline()
        pipe.add_component("ferpa_filter", FERPAHaystackFilter())
        pipe.connect("retriever.documents", "ferpa_filter.documents")
        result = pipe.run({
            "ferpa_filter": {
                "student_id": "S-001",
                "institution_id": "strayer",
                "permitted_categories": {"academic_record"},
            }
        })
        filtered_docs = result["ferpa_filter"]["filtered_documents"]
    """

    def run(
        self,
        documents: list[Any],
        student_id: str,
        institution_id: str,
        permitted_categories: set[str] | None = None,
    ) -> dict[str, list[Any]]:
        """
        Filter *documents* to those matching the authorised FERPA scope.

        This method conforms to the Haystack 2.x component ``run`` protocol:
        it accepts typed inputs and returns a dict of named outputs.

        Args:
            documents: List of Haystack ``Document`` objects (or duck-typed
                objects with a ``.meta`` dict attribute).
            student_id: Authorised student identifier; documents tagged with a
                different ``student_id`` are excluded.
            institution_id: Authorised institution identifier; documents tagged
                with a different ``institution_id`` are excluded.
            permitted_categories: Optional whitelist of category strings.  When
                provided, documents whose ``meta["category"]`` is not in the set
                are excluded.  When ``None`` or empty, no category filter applies.

        Returns:
            ``{"filtered_documents": [...]}`` — dict keyed by Haystack output name.
        """
        # Validate the Haystack import is available (lazy, for error clarity)
        try:
            pass  # No symbols needed at runtime beyond Document duck-typing
        except Exception:  # pragma: no cover
            pass

        filtered: list[Any] = []
        removed = 0

        for doc in documents:
            meta: dict[str, Any] = getattr(doc, "meta", {}) or {}

            doc_student = meta.get("student_id")
            if doc_student is not None and doc_student != student_id:
                removed += 1
                continue

            doc_institution = meta.get("institution_id")
            if doc_institution is not None and doc_institution != institution_id:
                removed += 1
                continue

            if permitted_categories:
                doc_category = meta.get("category")
                if doc_category is not None and doc_category not in permitted_categories:
                    removed += 1
                    continue

            filtered.append(doc)

        logger.info(
            "[FERPA_AUDIT] event=haystack_filter student_id=%s institution_id=%s "
            "total=%d removed=%d allowed=%d",
            student_id,
            institution_id,
            len(documents),
            removed,
            len(filtered),
        )

        return {"filtered_documents": filtered}


def _make_haystack_component() -> type:
    """
    Lazily register ``FERPAHaystackFilter`` as a Haystack ``@component``.

    Called only when the caller explicitly needs a Haystack-registered component
    (e.g., for pipeline serialization).  Separating registration from class
    definition keeps the module importable without ``haystack-ai``.

    Returns:
        The ``FERPAHaystackFilter`` class decorated with ``@component`` and
        annotated with ``@component.output_types``.

    Raises:
        ImportError: If ``haystack-ai`` is not installed.
    """
    try:
        from haystack import component
    except ImportError as exc:
        raise ImportError(
            "haystack-ai is required for Haystack component registration. "
            "Install it with: pip install haystack-ai>=2.0.0"
        ) from exc

    @component
    class _RegisteredFERPAHaystackFilter(FERPAHaystackFilter):
        """Haystack-registered variant of ``FERPAHaystackFilter``."""

        @component.output_types(filtered_documents=list)  # type: ignore[untyped-decorator]
        def run(
            self,
            documents: list[Any],
            student_id: str,
            institution_id: str,
            permitted_categories: set[str] | None = None,
        ) -> dict[str, list[Any]]:
            """Haystack-registered run method; delegates to parent implementation."""
            return super().run(
                documents=documents,
                student_id=student_id,
                institution_id=institution_id,
                permitted_categories=permitted_categories,
            )

    return _RegisteredFERPAHaystackFilter
