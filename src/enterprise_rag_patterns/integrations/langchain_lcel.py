"""
integrations/langchain_lcel.py — LangChain LCEL (Runnable) integration.

Provides ``FERPAFilterRunnable``, a ``RunnableLambda``-based LCEL step that
enforces FERPA identity-scope filtering as an explicit step in a LangChain
Expression Language (LCEL) pipeline.

LangChain 0.3+ uses LCEL — the ``|`` pipe operator and ``Runnable`` interface —
as the primary chain-building API. Unlike the callback-based
``FERPAComplianceCallbackHandler``, this integration makes the FERPA filter
an explicit, visible step in the chain.

Installation::

    pip install 'enterprise-rag-patterns[langchain]'

Usage::

    from enterprise_rag_patterns.integrations.langchain_lcel import (
        FERPAFilterRunnable,
        make_ferpa_chain,
    )
    from enterprise_rag_patterns.compliance import StudentIdentityScope, RecordCategory

    scope = StudentIdentityScope(
        student_id="stu_001",
        institution_id="inst_abc",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )

    # Compose directly in LCEL chain:
    ferpa_filter = FERPAFilterRunnable(scope=scope)
    chain = retriever | ferpa_filter | prompt | llm | StrOutputParser()
    result = chain.invoke({"query": "What are my grades?"})

    # Or use the factory for the most common pattern:
    chain = make_ferpa_chain(retriever, prompt, llm, scope=scope)
"""

from __future__ import annotations

import asyncio
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
    """Verify langchain-core is installed."""
    try:
        import langchain_core.runnables  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "langchain-core is required for FERPAFilterRunnable. "
            "Install it with: pip install 'enterprise-rag-patterns[langchain]'"
        ) from exc


class FERPAFilterRunnable:
    """
    LangChain LCEL ``Runnable`` step that enforces FERPA identity-scope
    filtering on a list of ``Document`` objects.

    Designed for use in LangChain 0.3+ LCEL chains with the ``|`` operator.
    The scope can be set at instantiation time (static) or injected per-request
    via ``RunnableConfig`` metadata (dynamic).

    Two enforcement layers per invocation:
      1. Identity pre-filter: ``student_id`` + ``institution_id`` must match scope.
      2. Category authorization: ``category`` must be in ``authorized_categories``.

    Emits a 34 CFR § 99.32 audit record for each invocation.

    Args:
        scope: Default ``StudentIdentityScope``. Can be overridden per-request
               via ``RunnableConfig`` by setting ``config["metadata"]["ferpa_scope"]``.
        student_id_field: Metadata key for student ID. Default: ``"student_id"``.
        institution_id_field: Metadata key for institution. Default: ``"institution_id"``.
        category_field: Metadata key for record category. Default: ``"category"``.
        audit_sink: Optional callable receiving each ``AuditRecord``.
        raise_on_violation: If ``True``, raise on unauthorized documents.

    Example — LCEL chain::

        ferpa_filter = FERPAFilterRunnable(scope=scope)
        chain = retriever | ferpa_filter | prompt | llm | StrOutputParser()
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
        self._default_scope = scope
        self.student_id_field = student_id_field
        self.institution_id_field = institution_id_field
        self.category_field = category_field
        self.audit_sink = audit_sink
        self.raise_on_violation = raise_on_violation

    # ------------------------------------------------------------------
    # Runnable interface — __call__ makes this duck-compatible with
    # LangChain's RunnableLambda and allows use with the | operator
    # via RunnableLambda wrapping.
    # ------------------------------------------------------------------

    def __call__(
        self,
        documents: list[Any],
        config: dict[str, Any] | None = None,
    ) -> list[Any]:
        """
        Filter a list of LangChain ``Document`` objects, enforcing FERPA scope.

        Args:
            documents: List of ``Document``-like objects with ``.metadata`` dicts.
            config: Optional LangChain ``RunnableConfig`` dict. If
                    ``config["metadata"]["ferpa_scope"]`` is a
                    ``StudentIdentityScope``, it overrides the default scope.

        Returns:
            Filtered list of ``Document`` objects (only authorized documents).
        """
        scope = self._resolve_scope(config)
        policy = FERPAContextPolicy(scope=scope, audit_sink=self.audit_sink)

        original_count = len(documents)
        doc_dicts: list[dict[str, Any]] = [self._to_dict(doc, i) for i, doc in enumerate(documents)]
        filtered_dicts = policy.filter_retrieved_documents(
            doc_dicts,
            student_id_field=self.student_id_field,
            institution_id_field=self.institution_id_field,
            category_field="record_category",
        )
        retained_indices: set[int] = {int(str(d["_idx"])) for d in filtered_dicts if "_idx" in d}
        filtered_docs = [doc for i, doc in enumerate(documents) if i in retained_indices]
        removed = original_count - len(filtered_docs)

        if removed > 0:
            if self.raise_on_violation:
                raise ValueError(
                    f"FERPA: {removed} unauthorized document(s) blocked for "
                    f"student={scope.student_id!r}, institution={scope.institution_id!r}"
                )
            logger.warning(
                "[FERPA_AUDIT] lcel_filter student=%s removed=%d retained=%d",
                scope.student_id,
                removed,
                len(filtered_docs),
            )

        categories = self._extract_categories(filtered_docs)
        if categories:
            audit: AuditRecord = policy.record_access(
                categories_accessed=list(categories),
                workflow_context="langchain_lcel",
            )
            logger.info("FERPA audit (LCEL): %s", audit.to_log_entry())

        return filtered_docs

    def invoke(self, input: Any, config: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """
        LangChain ``Runnable.invoke``-compatible entry point.

        Allows ``FERPAFilterRunnable`` instances to be used directly in ``|``
        chains without explicitly calling ``.as_runnable()``.  LangChain coerces
        callables to ``RunnableLambda`` via ``__or__``/``__ror__``; exposing
        ``invoke()`` also satisfies the duck-typed ``Runnable`` protocol for
        frameworks that check for it.

        Args:
            input: List of ``Document``-like objects.
            config: Optional LangChain ``RunnableConfig``.

        Returns:
            Filtered list of documents.
        """
        return self.__call__(input, config)

    async def ainvoke(self, input: Any, config: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """
        Async LangChain ``Runnable.ainvoke``-compatible entry point.

        Runs the synchronous filter in a thread pool via
        ``asyncio.get_event_loop().run_in_executor`` so the event loop is not
        blocked during filtering.

        Args:
            input: List of ``Document``-like objects.
            config: Optional LangChain ``RunnableConfig``.

        Returns:
            Filtered list of documents.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.__call__, input, config)

    def as_runnable(self) -> Any:
        """
        Wrap this filter as a LangChain ``RunnableLambda`` for explicit
        LCEL integration.

        Returns a ``RunnableLambda`` that can be used in ``|`` chains.

        Example::

            chain = retriever | ferpa_filter.as_runnable() | prompt | llm
        """
        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError as exc:
            raise ImportError(
                "langchain-core required. Install: pip install 'enterprise-rag-patterns[langchain]'"
            ) from exc
        return RunnableLambda(self.__call__)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_scope(self, config: dict[str, Any] | None) -> StudentIdentityScope:
        """Extract per-request scope from RunnableConfig if present."""
        if config is None:
            return self._default_scope
        metadata = config.get("metadata") or {}
        override = metadata.get("ferpa_scope")
        if isinstance(override, StudentIdentityScope):
            return override
        return self._default_scope

    def _to_dict(self, doc: Any, index: int) -> dict[str, Any]:
        meta: dict[str, Any] = getattr(doc, "metadata", {}) or {}
        d: dict[str, Any] = {"_idx": index}
        if self.student_id_field in meta:
            d[self.student_id_field] = meta[self.student_id_field]
        if self.institution_id_field in meta:
            d[self.institution_id_field] = meta[self.institution_id_field]
        if self.category_field in meta:
            d["record_category"] = meta[self.category_field]
        return d

    def _extract_categories(self, documents: list[Any]) -> set[RecordCategory]:
        cats: set[RecordCategory] = set()
        for doc in documents:
            meta: dict[str, Any] = getattr(doc, "metadata", {}) or {}
            raw = meta.get(self.category_field)
            if raw is not None:
                try:
                    cats.add(RecordCategory(raw))
                except ValueError:
                    pass
        return cats


def make_ferpa_chain(
    retriever: Any,
    prompt: Any,
    llm: Any,
    scope: StudentIdentityScope,
    output_parser: Any | None = None,
    audit_sink: Any | None = None,
) -> Any:
    """
    Factory that builds a FERPA-compliant LCEL chain:
    ``retriever | ferpa_filter | prompt | llm [| output_parser]``.

    Args:
        retriever: Any LangChain retriever (``BaseRetriever``-compatible).
        prompt: LangChain ``ChatPromptTemplate`` or ``PromptTemplate``.
        llm: LangChain ``BaseLLM`` or ``BaseChatModel``.
        scope: ``StudentIdentityScope`` for this chain.
        output_parser: Optional output parser (e.g. ``StrOutputParser()``).
        audit_sink: Optional callable for 34 CFR § 99.32 audit records.

    Returns:
        A LangChain ``Runnable`` chain ready to ``.invoke()``.

    Example::

        chain = make_ferpa_chain(retriever, prompt, llm, scope=scope)
        answer = chain.invoke({"query": "What is my GPA?"})
    """
    try:
        from langchain_core.runnables import RunnableLambda
    except ImportError as exc:
        raise ImportError("langchain-core required. Install: pip install 'enterprise-rag-patterns[langchain]'") from exc

    ferpa_filter = FERPAFilterRunnable(scope=scope, audit_sink=audit_sink)
    chain: Any = retriever | RunnableLambda(ferpa_filter.__call__) | prompt | llm
    if output_parser is not None:
        chain = chain | output_parser
    return chain
