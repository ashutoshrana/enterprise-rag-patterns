"""
async_compliance.py — Async wrappers for FERPA compliance policy methods.

Provides async versions of ``FERPAContextPolicy.filter_retrieved_documents``
and ``FERPAContextPolicy.record_access`` for use with async AI orchestration
frameworks (LangChain async chains, LlamaIndex async query engines, Haystack
async pipelines, CrewAI, AutoGen, etc.).

Async wrapper pattern
---------------------
The underlying compliance operations are CPU-bound (list filtering, dict
construction) and complete in microseconds — no actual I/O is involved.
However, async AI frameworks require that all pipeline components expose
an ``async def`` interface so they can be awaited in an event loop without
blocking.

The pattern used here is the minimal correct approach: ``await asyncio.sleep(0)``
yields control to the event loop (allowing other coroutines to run), then
delegates to the synchronous implementation.  This is preferable to
``asyncio.to_thread`` for pure-CPU operations that do not benefit from
thread-pool execution and where the synchronous path is already thread-safe.

Usage::

    policy = make_enrollment_advisor_policy(
        student_id="S-001",
        institution_id="strayer",
        advisor_id="agent:enrollment_advisor",
    )

    # In an async pipeline:
    safe_docs = await async_filter_retrieved_documents(
        policy, raw_docs, workflow_context="enrollment query"
    )
    audit = await async_record_access(
        policy,
        action="context_retrieval",
        categories_accessed=[RecordCategory.ACADEMIC_RECORD],
        workflow_context="enrollment query",
        query_hash=sha256_hash,
    )
"""

from __future__ import annotations

import asyncio
from typing import Any

from .compliance import AuditRecord, FERPAContextPolicy, RecordCategory


async def async_filter_retrieved_documents(
    policy: FERPAContextPolicy,
    documents: list[dict[str, Any]],
    student_id_field: str = "student_id",
    institution_id_field: str = "institution_id",
    category_field: str = "record_category",
) -> list[dict[str, Any]]:
    """
    Async wrapper for ``FERPAContextPolicy.filter_retrieved_documents``.

    Yields to the event loop once (``await asyncio.sleep(0)``) then delegates
    to the synchronous implementation.  Use this in async AI orchestration
    frameworks to avoid blocking the event loop during pipeline execution.

    The filtering logic is identical to the synchronous version:
    - Documents with a different ``student_id`` than ``policy.scope.student_id``
      are excluded.
    - Documents with a different ``institution_id`` are excluded when
      ``policy.block_cross_institution`` is ``True``.
    - Documents whose ``record_category`` is not authorised by the scope
      are excluded.

    Args:
        policy: The ``FERPAContextPolicy`` governing this retrieval.
        documents: List of retrieved document dicts.
        student_id_field: Key for student identity in each document.
        institution_id_field: Key for institution identity in each document.
        category_field: Key for record category in each document.

    Returns:
        Filtered list of documents safe to include in LLM context.

    Regulatory reference:
        FERPA 34 CFR § 99.3 — definition of education records and
        legitimate educational interest.
    """
    await asyncio.sleep(0)  # Yield to event loop; see module docstring for rationale.
    return policy.filter_retrieved_documents(
        documents=documents,
        student_id_field=student_id_field,
        institution_id_field=institution_id_field,
        category_field=category_field,
    )


async def async_record_access(
    policy: FERPAContextPolicy,
    action: str,
    categories_accessed: list[RecordCategory],
    workflow_context: str = "",
    query_hash: str = "",
) -> AuditRecord:
    """
    Async wrapper for ``FERPAContextPolicy.record_access``.

    Yields to the event loop once (``await asyncio.sleep(0)``) then delegates
    to the synchronous implementation, which creates and persists an
    ``AuditRecord`` via the policy's ``audit_sink``.

    The ``action`` parameter provides a semantic label for the operation
    (e.g., ``"context_retrieval"``, ``"advisor_query"``) that is stored in
    ``AuditRecord.workflow_context`` alongside the caller-supplied
    ``workflow_context`` string.

    Args:
        policy: The ``FERPAContextPolicy`` governing this retrieval.
        action: Semantic label for the access operation.
        categories_accessed: Which record categories were retrieved.
        workflow_context: Human-readable description of the workflow.
        query_hash: SHA-256 hash of the retrieval query.

    Returns:
        The created ``AuditRecord`` (also passed to ``policy.audit_sink`` if set).

    Regulatory reference:
        FERPA 34 CFR § 99.32 — Record of disclosures required.
    """
    await asyncio.sleep(0)  # Yield to event loop; see module docstring for rationale.
    full_context = f"{action}: {workflow_context}".strip(": ") if workflow_context else action
    return policy.record_access(
        categories_accessed=categories_accessed,
        workflow_context=full_context,
        query_hash=query_hash,
    )
