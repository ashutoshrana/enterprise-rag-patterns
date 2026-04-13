"""
integrations/llama_index_workflow.py — LlamaIndex 0.12+ Workflow integration.

Provides ``FERPAWorkflowStep``, a LlamaIndex ``Step`` that enforces FERPA
identity-scope filtering inside a LlamaIndex ``Workflow``.

LlamaIndex 0.12+ uses an event-driven Workflow model (``@step`` decorator,
``StartEvent`` / ``StopEvent`` / custom ``Event`` types). This module adds
a typed ``FERPAFilterEvent`` that carries a ``StudentIdentityScope`` and a
``FERPAWorkflowStep`` that intercepts ``NodeWithScore`` lists in the workflow
before they enter the synthesis step.

Installation::

    pip install 'enterprise-rag-patterns[llama-index]'

Usage::

    from llama_index.core.workflow import Workflow, StartEvent, StopEvent
    from enterprise_rag_patterns.integrations.llama_index_workflow import (
        FERPAWorkflowStep,
        FERPAFilterEvent,
    )
    from enterprise_rag_patterns.compliance import StudentIdentityScope, RecordCategory

    scope = StudentIdentityScope(
        student_id="stu_001",
        institution_id="inst_abc",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )

    class EnrollmentWorkflow(Workflow):
        ferpa_step = FERPAWorkflowStep(scope=scope)

        @step
        async def retrieve(self, event: StartEvent) -> FERPAFilterEvent:
            nodes = await retriever.aretrieve(event.query)
            return FERPAFilterEvent(nodes=nodes)

        @step
        async def synthesize(self, event: StopEvent) -> StopEvent:
            response = await synthesizer.asynthesize(event.query, nodes=event.nodes)
            return StopEvent(result=str(response))
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


def _check_llama_index_available() -> None:
    """Verify llama-index-core >=0.12 is installed."""
    try:
        import llama_index.core.workflow  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "llama-index-core>=0.12.0 is required for FERPAWorkflowStep. "
            "Install it with: pip install 'enterprise-rag-patterns[llama-index]'"
        ) from exc


class FERPAFilterEvent:
    """
    LlamaIndex Workflow event carrying a list of nodes and an optional scope.

    Passed between the retrieval step and the synthesis step; allows the
    ``FERPAWorkflowStep`` to intercept and filter in-workflow.

    Args:
        nodes: List of ``NodeWithScore`` objects from the retriever.
        query: The original query string (passed through to synthesis).
        scope_override: Optional scope override; uses the step's scope if None.
    """

    def __init__(
        self,
        nodes: list[Any],
        query: str = "",
        scope_override: StudentIdentityScope | None = None,
    ) -> None:
        self.nodes = nodes
        self.query = query
        self.scope_override = scope_override


class FERPAWorkflowStep:
    """
    LlamaIndex Workflow step that enforces FERPA identity-scope filtering
    on a list of ``NodeWithScore`` objects emitted by the retrieval step.

    Implements the ``@step`` contract via duck typing; the class is usable
    as a workflow step by returning the filtered ``FERPAFilterEvent``.

    Args:
        scope: Default ``StudentIdentityScope`` for this step.
        audit_sink: Optional callable receiving ``AuditRecord`` per call.
        raise_on_violation: If ``True``, raise on any FERPA violation.
    """

    def __init__(
        self,
        scope: StudentIdentityScope,
        audit_sink: Any | None = None,
        raise_on_violation: bool = False,
    ) -> None:
        _check_llama_index_available()
        self._default_scope = scope
        self._audit_sink = audit_sink
        self._raise_on_violation = raise_on_violation

    async def __call__(self, event: FERPAFilterEvent) -> FERPAFilterEvent:
        """
        Filter nodes in the event, enforcing the FERPA identity scope.

        Returns the same ``FERPAFilterEvent`` with ``nodes`` replaced by
        the authorized subset.
        """
        scope = event.scope_override or self._default_scope
        policy = FERPAContextPolicy(scope=scope, audit_sink=self._audit_sink)

        nodes = event.nodes or []
        original_count = len(nodes)

        doc_dicts = [self._node_to_dict(n, i) for i, n in enumerate(nodes)]
        filtered_dicts = policy.filter_retrieved_documents(doc_dicts)
        retained_indices = {int(str(d["_idx"])) for d in filtered_dicts if "_idx" in d}
        filtered_nodes = [n for i, n in enumerate(nodes) if i in retained_indices]
        removed = original_count - len(filtered_nodes)

        if removed > 0:
            if self._raise_on_violation:
                raise PermissionError(f"FERPA: {removed} unauthorized node(s) blocked for student={scope.student_id!r}")
            logger.warning(
                "[FERPA_AUDIT] llama_index_workflow student=%s removed=%d retained=%d",
                scope.student_id,
                removed,
                len(filtered_nodes),
            )

        categories = self._extract_categories(filtered_nodes)
        if categories:
            audit: AuditRecord = policy.record_access(
                categories_accessed=list(categories),
                workflow_context="llama_index_workflow",
            )
            logger.info("FERPA audit (LlamaIndex Workflow): %s", audit.to_log_entry())

        event.nodes = filtered_nodes
        return event

    def _node_to_dict(self, node: Any, index: int) -> dict[str, Any]:
        """Extract metadata from a NodeWithScore into a dict for FERPAContextPolicy."""
        node_obj = getattr(node, "node", node)
        meta: dict[str, Any] = getattr(node_obj, "metadata", {}) or {}
        d: dict[str, Any] = {"_idx": index}
        d.update(meta)
        return d

    def _extract_categories(self, nodes: list[Any]) -> set[RecordCategory]:
        cats: set[RecordCategory] = set()
        for node in nodes:
            node_obj = getattr(node, "node", node)
            meta: dict[str, Any] = getattr(node_obj, "metadata", {}) or {}
            raw = meta.get("category") or meta.get("record_category")
            if raw is not None:
                try:
                    cats.add(RecordCategory(raw))
                except ValueError:
                    pass
        return cats
