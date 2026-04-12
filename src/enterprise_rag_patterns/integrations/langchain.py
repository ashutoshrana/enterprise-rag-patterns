"""
integrations/langchain.py — LangChain integration for FERPA-compliant RAG pipelines.

Provides ``FERPAComplianceCallbackHandler``, a LangChain ``BaseCallbackHandler``
(duck-typed, no hard SDK import at class-definition time) that intercepts
retriever results and applies StudentIdentityScope filtering before the
documents reach the LLM context window.

Two filtering layers are applied on every ``on_retriever_end`` event:
  1. **Identity pre-filter** — documents tagged with a different ``student_id``
     or ``institution_id`` than the authorized scope are removed.
  2. **Category authorization** — documents whose ``category`` field is not in
     the scope's ``authorized_categories`` are removed.

Regulatory basis:
  34 CFR § 99.31(a)(1) — access control (legitimate educational interest)
  34 CFR § 99.32       — record of disclosures (audit log requirement)

Installation::

    pip install 'enterprise-rag-patterns[langchain]'

Usage::

    from enterprise_rag_patterns.integrations.langchain import (
        FERPAComplianceCallbackHandler,
    )
    from enterprise_rag_patterns.compliance import (
        DisclosureReason,
        RecordCategory,
        StudentIdentityScope,
    )

    scope = StudentIdentityScope(
        student_id="stu_001",
        institution_id="inst_abc",
        requesting_user_id="advisor_007",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )
    handler = FERPAComplianceCallbackHandler(scope=scope)

    # Pass handler to a LangChain retriever or chain:
    retriever = vector_store.as_retriever(callbacks=[handler])
    docs = retriever.invoke("What is my enrollment status?")
    # docs contains only stu_001's academic records at inst_abc
"""

from __future__ import annotations

import logging
from typing import Any

from enterprise_rag_patterns.compliance import (
    AuditRecord,
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
)

logger = logging.getLogger(__name__)


def _check_langchain_available() -> None:
    """
    Verify langchain-core is installed and raise a clear ImportError if not.

    Called lazily at handler instantiation — not at module import — so that
    the package remains importable without the optional SDK dependency.
    """
    try:
        import langchain_core.callbacks  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "langchain-core is required for the LangChain integration. "
            "Install it with: pip install 'enterprise-rag-patterns[langchain]'"
        ) from exc


class FERPAComplianceCallbackHandler:
    """
    LangChain callback handler that enforces FERPA identity-scope filtering
    on retriever results before they enter the LLM context window.

    Implements the LangChain ``BaseCallbackHandler`` interface via duck typing
    so that the class can be defined and imported without ``langchain-core``
    installed.  The SDK availability check is deferred to ``__init__``.

    Two enforcement layers (matching ``FERPAContextPolicy``):
      1. Identity pre-filter: ``student_id`` + ``institution_id`` must match scope.
      2. Category authorization: ``category`` must be in scope's
         ``authorized_categories``.

    Documents without ``student_id`` / ``institution_id`` metadata are treated
    as non-FERPA shared knowledge-base content and are passed through unchanged.

    Regulatory basis: 34 CFR § 99.31(a)(1), § 99.32

    Args:
        scope: ``StudentIdentityScope`` defining the authorized student,
               institution, and record categories for this request.
        student_id_field: Document metadata key for the student identifier.
                          Default: ``"student_id"``
        institution_id_field: Document metadata key for the institution.
                              Default: ``"institution_id"``
        category_field: Document metadata key for the record category.
                        Default: ``"category"``
        audit_sink: Optional callable receiving each ``AuditRecord`` produced
                    by this handler (34 CFR § 99.32).  When ``None``, records
                    are emitted via ``logging`` only.
        raise_on_violation: If ``True``, raise ``ValueError`` when unauthorized
                            documents are detected.  If ``False`` (default),
                            silently drop unauthorized documents and log a
                            ``WARNING``.
    """

    def __init__(
        self,
        scope: StudentIdentityScope,
        student_id_field: str = "student_id",
        institution_id_field: str = "institution_id",
        category_field: str = "category",
        audit_sink: Any | None = None,
        raise_on_violation: bool = False,
    ) -> None:
        _check_langchain_available()
        self.policy = FERPAContextPolicy(scope=scope, audit_sink=audit_sink)
        self.student_id_field = student_id_field
        self.institution_id_field = institution_id_field
        self.category_field = category_field
        self.raise_on_violation = raise_on_violation

    # ------------------------------------------------------------------
    # Core LangChain event handler
    # ------------------------------------------------------------------

    def on_retriever_end(self, documents: list[Any], **kwargs: Any) -> None:
        """
        Intercept retriever results and apply FERPA filtering in-place.

        Called by the LangChain callback system immediately after a retriever
        returns results.  The ``documents`` list is mutated in-place so that
        downstream chain components see only the authorized subset.

        FERPA 34 CFR § 99.32: each disclosure must be logged.

        Args:
            documents: List of LangChain ``Document``-like objects (duck-typed;
                       must expose a ``.metadata`` dict attribute).
            **kwargs: Additional LangChain callback keyword arguments
                      (``run_id``, ``parent_run_id``, etc.).
        """
        original_count = len(documents)

        # Convert to the dict-based API expected by FERPAContextPolicy.
        # Inject "_idx" so we can map filtered results back to original objects.
        doc_dicts: list[dict[str, Any]] = [self._to_dict(doc, idx) for idx, doc in enumerate(documents)]

        filtered_dicts = self.policy.filter_retrieved_documents(
            doc_dicts,
            student_id_field=self.student_id_field,
            institution_id_field=self.institution_id_field,
            # FERPAContextPolicy uses "record_category" as its default field name;
            # we map our category_field value into "record_category" in _to_dict.
            category_field="record_category",
        )

        # Rebuild the filtered document list, preserving the original objects.
        retained_indices: set[int] = {
            int(d["_idx"])  # type: ignore[arg-type]
            for d in filtered_dicts
            if "_idx" in d
        }
        filtered_documents = [doc for idx, doc in enumerate(documents) if idx in retained_indices]

        removed = original_count - len(filtered_documents)

        if removed > 0 and self.raise_on_violation:
            raise ValueError(
                f"FERPA violation: {removed} unauthorized document(s) blocked for "
                f"student={self.policy.scope.student_id!r}, "
                f"institution={self.policy.scope.institution_id!r}. "
                "Check StudentIdentityScope.authorized_categories."
            )

        # Mutate the list in-place — LangChain passes the same list downstream.
        documents.clear()
        documents.extend(filtered_documents)

        # Emit FERPA 34 CFR § 99.32 audit record for any accessed categories.
        categories_accessed = self._extract_accessed_categories(filtered_documents)
        if categories_accessed:
            workflow_ctx = kwargs.get("workflow_context", "langchain_retriever")
            audit: AuditRecord = self.policy.record_access(
                categories_accessed=list(categories_accessed),
                workflow_context=str(workflow_ctx),
            )
            logger.info("FERPA audit: %s", audit.to_log_entry())

        if removed > 0:
            logger.warning(
                "[FERPA_AUDIT] event=langchain_filter student_id=%s institution_id=%s total=%d removed=%d allowed=%d",
                self.policy.scope.student_id,
                self.policy.scope.institution_id,
                original_count,
                removed,
                len(filtered_documents),
            )

    # ------------------------------------------------------------------
    # No-op handlers for other LangChain callback events
    # ------------------------------------------------------------------

    def on_llm_start(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LLM start event."""

    def on_llm_end(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LLM end event."""

    def on_chain_start(self, *args: Any, **kwargs: Any) -> None:
        """No-op: chain start event."""

    def on_chain_end(self, *args: Any, **kwargs: Any) -> None:
        """No-op: chain end event."""

    def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
        """No-op: tool start event."""

    def on_tool_end(self, *args: Any, **kwargs: Any) -> None:
        """No-op: tool end event."""

    def on_retriever_start(self, *args: Any, **kwargs: Any) -> None:
        """No-op: retriever start event."""

    def on_retriever_error(self, *args: Any, **kwargs: Any) -> None:
        """No-op: retriever error event."""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _to_dict(self, doc: Any, index: int = 0) -> dict[str, Any]:
        """
        Convert a LangChain Document-like object to a dict for FERPAContextPolicy.

        Maps the configured ``category_field`` to ``"record_category"`` (the
        field name expected by ``FERPAContextPolicy.filter_retrieved_documents``).
        Injects ``_idx`` so we can recover the original objects after filtering.
        """
        meta: dict[str, Any] = getattr(doc, "metadata", {}) or {}
        d: dict[str, Any] = {"_idx": index}
        if self.student_id_field in meta:
            d[self.student_id_field] = meta[self.student_id_field]
        if self.institution_id_field in meta:
            d[self.institution_id_field] = meta[self.institution_id_field]
        if self.category_field in meta:
            d["record_category"] = meta[self.category_field]
        return d

    def _extract_accessed_categories(self, documents: list[Any]) -> set[RecordCategory]:
        """Return the set of RecordCategory values present in the authorized documents."""
        categories: set[RecordCategory] = set()
        for doc in documents:
            meta: dict[str, Any] = getattr(doc, "metadata", {}) or {}
            raw = meta.get(self.category_field)
            if raw is not None:
                try:
                    categories.add(RecordCategory(raw))
                except ValueError:
                    pass  # Unknown category string — skip
        return categories
