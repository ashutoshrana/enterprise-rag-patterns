"""
integrations/maf.py — Microsoft Agent Framework (MAF) integration.

Provides ``FERPAAgentMiddleware``, a MAF ``MiddlewareBase`` that intercepts
agent tool calls, applies FERPA identity-scope filtering on any retrieved
documents, and emits 34 CFR § 99.32 audit records.

Microsoft Agent Framework (MAF) is the enterprise-ready successor to AutoGen
and Semantic Kernel, released 2026. MAF uses a middleware pipeline architecture
for intercepting agent messages and tool calls.

Installation::

    pip install 'enterprise-rag-patterns[maf]'

Usage::

    from enterprise_rag_patterns.integrations.maf import FERPAAgentMiddleware
    from enterprise_rag_patterns.compliance import StudentIdentityScope, RecordCategory

    scope = StudentIdentityScope(
        student_id="stu_001",
        institution_id="inst_abc",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )
    middleware = FERPAAgentMiddleware(scope=scope)

    # Register with MAF agent runtime
    runtime = AgentRuntime(middlewares=[middleware])
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


def _check_maf_available() -> None:
    """Verify microsoft-agent-framework is installed."""
    try:
        import microsoft_agent_framework  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "microsoft-agent-framework is required for the MAF integration. "
            "Install it with: pip install 'enterprise-rag-patterns[maf]'"
        ) from exc


class FERPAAgentMiddleware:
    """
    Microsoft Agent Framework middleware enforcing FERPA identity-scope
    filtering on document retrieval tool calls.

    Implements MAF ``MiddlewareBase`` via duck typing so the class is importable
    without the MAF SDK installed. Dependency check is deferred to ``__init__``.

    Two enforcement layers per MAF message intercept:
      1. Identity pre-filter: ``student_id`` + ``institution_id`` must match scope.
      2. Category authorization: ``category`` must be in ``authorized_categories``.

    Emits a ``GovernanceAuditRecord`` per tool call (34 CFR § 99.32).

    Args:
        scope: ``StudentIdentityScope`` defining the authorized boundary.
        audit_sink: Optional callable receiving each ``AuditRecord``.
        raise_on_violation: If ``True``, raise on policy breach rather than drop.
    """

    def __init__(
        self,
        scope: StudentIdentityScope,
        audit_sink: Any | None = None,
        raise_on_violation: bool = False,
    ) -> None:
        _check_maf_available()
        self.policy = FERPAContextPolicy(scope=scope, audit_sink=audit_sink)
        self.raise_on_violation = raise_on_violation

    async def on_message(self, message: Any, next_handler: Any) -> Any:
        """
        Intercept agent messages. For tool result messages containing a
        ``documents`` payload, apply FERPA filtering before passing downstream.

        Args:
            message: MAF message object (duck-typed).
            next_handler: Callable to invoke the next middleware or handler.
        """
        # Tool result messages carry retrieved documents in message.payload
        payload = getattr(message, "payload", None) or {}
        documents = payload.get("documents") if isinstance(payload, dict) else None

        if documents is not None:
            original_count = len(documents)
            doc_dicts = [self._to_dict(d, i) for i, d in enumerate(documents)]
            filtered_dicts = self.policy.filter_retrieved_documents(doc_dicts)
            retained_indices = {int(str(d["_idx"])) for d in filtered_dicts if "_idx" in d}
            filtered_docs = [d for i, d in enumerate(documents) if i in retained_indices]
            removed = original_count - len(filtered_docs)

            if removed > 0:
                if self.raise_on_violation:
                    raise PermissionError(
                        f"FERPA: {removed} unauthorized document(s) blocked "
                        f"for student={self.policy.scope.student_id!r}"
                    )
                logger.warning(
                    "[FERPA_AUDIT] maf_middleware student=%s removed=%d retained=%d",
                    self.policy.scope.student_id,
                    removed,
                    len(filtered_docs),
                )

            # Mutate payload in-place
            if isinstance(payload, dict):
                payload["documents"] = filtered_docs

            # Emit 34 CFR § 99.32 audit record
            categories = self._extract_categories(filtered_docs)
            if categories:
                audit: AuditRecord = self.policy.record_access(
                    categories_accessed=list(categories),
                    workflow_context="maf_middleware",
                )
                logger.info("FERPA audit (MAF): %s", audit.to_log_entry())

        return await next_handler(message)

    def _to_dict(self, doc: Any, index: int) -> dict[str, Any]:
        meta: dict[str, Any] = getattr(doc, "metadata", {}) or {}
        d: dict[str, Any] = {"_idx": index}
        d.update(meta)
        return d

    def _extract_categories(self, documents: list[Any]) -> set[RecordCategory]:
        cats: set[RecordCategory] = set()
        for doc in documents:
            meta: dict[str, Any] = getattr(doc, "metadata", {}) or {}
            raw = meta.get("category") or meta.get("record_category")
            if raw is not None:
                try:
                    cats.add(RecordCategory(raw))
                except ValueError:
                    pass
        return cats
