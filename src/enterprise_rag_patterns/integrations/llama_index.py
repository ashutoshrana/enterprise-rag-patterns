"""
integrations/llama_index.py — LlamaIndex node postprocessor for FERPA compliance.

Provides ``FERPANodePostprocessor``, a LlamaIndex ``NodePostprocessor`` that
filters retrieved nodes to only those matching the authorised student identity
scope before they are assembled into the LLM context window.

The ``llama_index`` package is imported lazily so this module can be imported
without ``llama-index-core`` installed.

Regulatory context:
  34 CFR § 99.32 — FERPA requires institutions to maintain a record of each
  request for access to education records and the reason for access.  This
  postprocessor emits a structured audit entry for every filtering operation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..compliance import StudentIdentityScope

if TYPE_CHECKING:
    # Only for type-checking; not imported at runtime.
    pass

logger = logging.getLogger(__name__)


class FERPANodePostprocessor:
    """
    LlamaIndex ``BaseNodePostprocessor`` that enforces FERPA identity scoping.

    Filters a list of ``BaseNode`` objects returned by a retriever, retaining
    only nodes whose metadata matches the authorised ``StudentIdentityScope``.
    Nodes without ``student_id`` or ``institution_id`` metadata are passed
    through (assumed to be non-FERPA knowledge-base content).

    A lightweight audit log entry (34 CFR § 99.32) is emitted via the standard
    ``logging`` module after each filtering pass.

    Usage::

        from llama_index.core.query_engine import RetrieverQueryEngine
        from llama_index.core.retrievers import VectorIndexRetriever

        scope = StudentIdentityScope(
            student_id="S-001",
            institution_id="acme-univ",
            requesting_user_id="agent:advisor",
        )
        postprocessor = FERPANodePostprocessor(scope=scope)

        engine = RetrieverQueryEngine.from_args(
            retriever=retriever,
            node_postprocessors=[postprocessor],
        )

    Regulatory reference:
        34 CFR § 99.32 — Record of disclosures required.
    """

    def __init__(self, scope: StudentIdentityScope) -> None:
        """
        Initialise the postprocessor with an authorised identity scope.

        Args:
            scope: The ``StudentIdentityScope`` defining the student and
                institution whose records may be included in the context.
        """
        self.scope = scope

    # ------------------------------------------------------------------
    # LlamaIndex postprocessor protocol (duck-typed to avoid hard import)
    # ------------------------------------------------------------------

    def postprocess_nodes(
        self,
        nodes: list[Any],
        query_bundle: Any | None = None,
    ) -> list[Any]:
        """
        Filter *nodes* to only those authorised by ``self.scope``.

        Nodes are excluded if:
        - ``metadata["student_id"]`` is present and does not equal
          ``scope.student_id``.
        - ``metadata["institution_id"]`` is present and does not equal
          ``scope.institution_id``.

        Nodes without these metadata keys are passed through unchanged
        (non-FERPA content assumption).

        After filtering, a FERPA audit log entry is emitted at INFO level
        in accordance with 34 CFR § 99.32.

        Args:
            nodes: List of ``BaseNode``-compatible objects with a ``.metadata``
                dict attribute.
            query_bundle: Optional ``QueryBundle``; unused but required by the
                LlamaIndex postprocessor interface.

        Returns:
            Filtered list of nodes safe to include in LLM context.
        """
        filtered: list[Any] = []
        removed = 0

        for node in nodes:
            metadata: dict[str, Any] = getattr(node, "metadata", {}) or {}

            node_student = metadata.get("student_id")
            node_institution = metadata.get("institution_id")

            if node_student is not None and node_student != self.scope.student_id:
                removed += 1
                continue

            if node_institution is not None and node_institution != self.scope.institution_id:
                removed += 1
                continue

            filtered.append(node)

        # Emit 34 CFR § 99.32 audit record as structured log entry
        audit_entry = _build_audit_entry(
            student_id=self.scope.student_id,
            institution_id=self.scope.institution_id,
            requesting_user_id=self.scope.requesting_user_id,
            nodes_total=len(nodes),
            nodes_removed=removed,
            nodes_allowed=len(filtered),
        )
        logger.info("[FERPA_AUDIT] %s", audit_entry)

        return filtered


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_audit_entry(
    *,
    student_id: str,
    institution_id: str,
    requesting_user_id: str,
    nodes_total: int,
    nodes_removed: int,
    nodes_allowed: int,
) -> dict[str, Any]:
    """
    Build a GovernanceAuditRecord-style dict for FERPA 34 CFR § 99.32 logging.

    Deliberately a plain ``dict`` rather than an imported dataclass to avoid
    coupling this module to any external audit-record type.

    Args:
        student_id: Authorised student identifier.
        institution_id: Authorised institution identifier.
        requesting_user_id: Agent or user performing the retrieval.
        nodes_total: Total nodes before filtering.
        nodes_removed: Nodes excluded by FERPA scoping.
        nodes_allowed: Nodes passed through to LLM context.

    Returns:
        A ``dict`` with fields compatible with GovernanceAuditRecord.
    """
    return {
        "event": "ferpa_node_postprocessor",
        "regulation": "FERPA",
        "citation": "34 CFR § 99.32",
        "student_id": student_id,
        "institution_id": institution_id,
        "requesting_user_id": requesting_user_id,
        "nodes_total": nodes_total,
        "nodes_removed": nodes_removed,
        "nodes_allowed": nodes_allowed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
