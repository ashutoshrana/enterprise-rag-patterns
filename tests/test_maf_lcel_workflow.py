"""
Tests for the v0.4.x integration additions:
  - FERPAAgentMiddleware     (integrations/maf.py)
  - FERPAWorkflowStep        (integrations/llama_index_workflow.py)
  - FERPAFilterEvent         (integrations/llama_index_workflow.py)
  - FERPAFilterRunnable      (integrations/langchain_lcel.py)
  - make_ferpa_chain         (integrations/langchain_lcel.py)

All framework SDKs (MAF, LlamaIndex, LangChain) are stubbed via sys.modules
so the tests run without any optional dependencies installed.
Async tests use asyncio.run() (no pytest-asyncio required).
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

from enterprise_rag_patterns.compliance import RecordCategory, StudentIdentityScope

# ---------------------------------------------------------------------------
# Stub optional framework modules BEFORE importing integration classes
# ---------------------------------------------------------------------------
#
# Each integration module does a lazy `import <sdk>` inside _check_*_available().
# Inserting MagicMock stubs into sys.modules means those checks pass without
# the real SDKs being installed.
# ---------------------------------------------------------------------------

for _mod in (
    "microsoft_agent_framework",
    "llama_index",
    "llama_index.core",
    "llama_index.core.workflow",
    "langchain_core",
    "langchain_core.runnables",
):
    sys.modules.setdefault(_mod, MagicMock())

# RunnableLambda stub: just wrap the callable so it is callable itself
_lc_runnables = sys.modules["langchain_core.runnables"]
_lc_runnables.RunnableLambda = lambda fn: fn  # type: ignore[assignment]

# Now import integration classes (availability checks will succeed)
from enterprise_rag_patterns.integrations.langchain_lcel import (  # noqa: E402
    FERPAFilterRunnable,
    make_ferpa_chain,
)
from enterprise_rag_patterns.integrations.llama_index_workflow import (  # noqa: E402
    FERPAFilterEvent,
    FERPAWorkflowStep,
)
from enterprise_rag_patterns.integrations.maf import FERPAAgentMiddleware  # noqa: E402

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def scope_s1() -> StudentIdentityScope:
    return StudentIdentityScope(
        student_id="S-1",
        institution_id="inst-a",
        requesting_user_id="agent",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )


@pytest.fixture()
def scope_s2() -> StudentIdentityScope:
    return StudentIdentityScope(
        student_id="S-2",
        institution_id="inst-a",
        requesting_user_id="agent",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _FakeDoc:
    """Duck-typed LangChain / MAF document stub."""

    def __init__(self, metadata: dict[str, Any]) -> None:
        self.metadata = metadata
        self.page_content = "stub"


class _FakeNode:
    """Duck-typed LlamaIndex NodeWithScore stub (direct node)."""

    def __init__(self, metadata: dict[str, Any]) -> None:
        self.metadata = metadata
        self.text = "stub"


class _FakeNodeWithScore:
    """Duck-typed LlamaIndex NodeWithScore with nested .node."""

    def __init__(self, metadata: dict[str, Any]) -> None:
        self.node = _FakeNode(metadata)
        self.score = 0.9


class _FakeMessage:
    """Duck-typed MAF message stub."""

    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        self.payload = payload or {}


# ---------------------------------------------------------------------------
# FERPAFilterEvent
# ---------------------------------------------------------------------------


class TestFERPAFilterEvent:
    def test_construction_minimal(self) -> None:
        nodes: list[Any] = [_FakeNode({"student_id": "S-1"})]
        event = FERPAFilterEvent(nodes=nodes)
        assert event.nodes is nodes
        assert event.query == ""
        assert event.scope_override is None

    def test_construction_full(self, scope_s1: StudentIdentityScope) -> None:
        nodes: list[Any] = []
        event = FERPAFilterEvent(nodes=nodes, query="GPA?", scope_override=scope_s1)
        assert event.query == "GPA?"
        assert event.scope_override is scope_s1


# ---------------------------------------------------------------------------
# FERPAWorkflowStep
# ---------------------------------------------------------------------------


class TestFERPAWorkflowStep:
    def test_construction(self, scope_s1: StudentIdentityScope) -> None:
        step = FERPAWorkflowStep(scope=scope_s1)
        assert step._default_scope is scope_s1

    def test_blocks_cross_student(self, scope_s1: StudentIdentityScope) -> None:
        step = FERPAWorkflowStep(scope=scope_s1)
        nodes: list[Any] = [
            _FakeNode({"student_id": "S-1", "institution_id": "inst-a"}),
            _FakeNode({"student_id": "S-2", "institution_id": "inst-a"}),
        ]
        event = FERPAFilterEvent(nodes=nodes)
        result = asyncio.run(step(event))
        assert len(result.nodes) == 1
        assert result.nodes[0].metadata["student_id"] == "S-1"

    def test_passes_shared_kb_node(self, scope_s1: StudentIdentityScope) -> None:
        step = FERPAWorkflowStep(scope=scope_s1)
        nodes: list[Any] = [
            _FakeNode({"student_id": "S-1", "institution_id": "inst-a"}),
            _FakeNode({}),  # no student_id → shared KB, should pass
        ]
        event = FERPAFilterEvent(nodes=nodes)
        result = asyncio.run(step(event))
        assert len(result.nodes) == 2

    def test_empty_nodes(self, scope_s1: StudentIdentityScope) -> None:
        step = FERPAWorkflowStep(scope=scope_s1)
        event = FERPAFilterEvent(nodes=[])
        result = asyncio.run(step(event))
        assert result.nodes == []

    def test_scope_override(self, scope_s1: StudentIdentityScope, scope_s2: StudentIdentityScope) -> None:
        # Step configured for S-1, but override gives S-2 scope
        step = FERPAWorkflowStep(scope=scope_s1)
        nodes: list[Any] = [
            _FakeNode({"student_id": "S-1", "institution_id": "inst-a"}),
            _FakeNode({"student_id": "S-2", "institution_id": "inst-a"}),
        ]
        event = FERPAFilterEvent(nodes=nodes, scope_override=scope_s2)
        result = asyncio.run(step(event))
        assert len(result.nodes) == 1
        assert result.nodes[0].metadata["student_id"] == "S-2"

    def test_raise_on_violation(self, scope_s1: StudentIdentityScope) -> None:
        step = FERPAWorkflowStep(scope=scope_s1, raise_on_violation=True)
        nodes: list[Any] = [
            _FakeNode({"student_id": "S-2", "institution_id": "inst-a"}),
        ]
        event = FERPAFilterEvent(nodes=nodes)
        with pytest.raises(PermissionError, match="FERPA"):
            asyncio.run(step(event))

    def test_node_with_score_unwrapped(self, scope_s1: StudentIdentityScope) -> None:
        """NodeWithScore objects with .node attribute are correctly unwrapped."""
        step = FERPAWorkflowStep(scope=scope_s1)
        nodes: list[Any] = [
            _FakeNodeWithScore({"student_id": "S-1", "institution_id": "inst-a"}),
            _FakeNodeWithScore({"student_id": "S-2", "institution_id": "inst-a"}),
        ]
        event = FERPAFilterEvent(nodes=nodes)
        result = asyncio.run(step(event))
        assert len(result.nodes) == 1

    def test_audit_sink_accepted(self, scope_s1: StudentIdentityScope) -> None:
        sink = MagicMock()
        step = FERPAWorkflowStep(scope=scope_s1, audit_sink=sink)
        nodes: list[Any] = [
            _FakeNode({"student_id": "S-1", "institution_id": "inst-a", "category": "academic_record"}),
        ]
        event = FERPAFilterEvent(nodes=nodes)
        result = asyncio.run(step(event))
        assert len(result.nodes) == 1


# ---------------------------------------------------------------------------
# FERPAAgentMiddleware
# ---------------------------------------------------------------------------


@pytest.fixture()
def middleware(scope_s1: StudentIdentityScope) -> FERPAAgentMiddleware:
    return FERPAAgentMiddleware(scope=scope_s1)


async def _next(msg: Any) -> Any:
    return msg


class TestFERPAAgentMiddleware:
    def test_construction(self, scope_s1: StudentIdentityScope) -> None:
        m = FERPAAgentMiddleware(scope=scope_s1)
        assert m.policy.scope is scope_s1
        assert m.raise_on_violation is False

    def test_filters_cross_student_documents(self, middleware: FERPAAgentMiddleware) -> None:
        docs = [
            _FakeDoc({"student_id": "S-1", "institution_id": "inst-a"}),
            _FakeDoc({"student_id": "S-2", "institution_id": "inst-a"}),
        ]
        message = _FakeMessage(payload={"documents": docs})
        asyncio.run(middleware.on_message(message, _next))
        assert len(message.payload["documents"]) == 1
        assert message.payload["documents"][0].metadata["student_id"] == "S-1"

    def test_passes_through_no_documents(self, middleware: FERPAAgentMiddleware) -> None:
        message = _FakeMessage(payload={"text": "hello"})
        result = asyncio.run(middleware.on_message(message, _next))
        assert result is message

    def test_passes_through_no_payload(self, middleware: FERPAAgentMiddleware) -> None:
        message = _FakeMessage(payload=None)
        result = asyncio.run(middleware.on_message(message, _next))
        assert result is message

    def test_passes_shared_kb_document(self, middleware: FERPAAgentMiddleware) -> None:
        docs = [
            _FakeDoc({"student_id": "S-1", "institution_id": "inst-a"}),
            _FakeDoc({}),  # no student_id → shared KB
        ]
        message = _FakeMessage(payload={"documents": docs})
        asyncio.run(middleware.on_message(message, _next))
        assert len(message.payload["documents"]) == 2

    def test_raise_on_violation(self, scope_s1: StudentIdentityScope) -> None:
        m = FERPAAgentMiddleware(scope=scope_s1, raise_on_violation=True)
        docs = [_FakeDoc({"student_id": "S-2", "institution_id": "inst-a"})]
        message = _FakeMessage(payload={"documents": docs})
        with pytest.raises(PermissionError, match="FERPA"):
            asyncio.run(m.on_message(message, _next))

    def test_empty_documents_list(self, middleware: FERPAAgentMiddleware) -> None:
        message = _FakeMessage(payload={"documents": []})
        asyncio.run(middleware.on_message(message, _next))
        assert message.payload["documents"] == []

    def test_next_handler_called(self, middleware: FERPAAgentMiddleware) -> None:
        called: list[Any] = []

        async def recording_next(msg: Any) -> Any:
            called.append(msg)
            return msg

        message = _FakeMessage(payload={"text": "hi"})
        asyncio.run(middleware.on_message(message, recording_next))
        assert called == [message]


# ---------------------------------------------------------------------------
# FERPAFilterRunnable
# ---------------------------------------------------------------------------


@pytest.fixture()
def runnable(scope_s1: StudentIdentityScope) -> FERPAFilterRunnable:
    return FERPAFilterRunnable(scope=scope_s1)


@pytest.fixture()
def mixed_docs() -> list[_FakeDoc]:
    return [
        _FakeDoc({"student_id": "S-1", "institution_id": "inst-a", "category": "academic_record"}),
        _FakeDoc({"student_id": "S-2", "institution_id": "inst-a", "category": "academic_record"}),
        _FakeDoc({}),  # shared KB
    ]


class TestFERPAFilterRunnable:
    def test_construction(self, scope_s1: StudentIdentityScope) -> None:
        r = FERPAFilterRunnable(scope=scope_s1)
        assert r._default_scope is scope_s1
        assert r.student_id_field == "student_id"
        assert r.institution_id_field == "institution_id"

    def test_filters_cross_student(self, runnable: FERPAFilterRunnable, mixed_docs: list[_FakeDoc]) -> None:
        result = runnable(mixed_docs)
        student_ids = [d.metadata.get("student_id") for d in result]
        assert "S-2" not in student_ids

    def test_passes_shared_kb(self, runnable: FERPAFilterRunnable, mixed_docs: list[_FakeDoc]) -> None:
        result = runnable(mixed_docs)
        assert any(not d.metadata.get("student_id") for d in result)

    def test_empty_input(self, runnable: FERPAFilterRunnable) -> None:
        assert runnable([]) == []

    def test_no_config_uses_default_scope(self, runnable: FERPAFilterRunnable, scope_s1: StudentIdentityScope) -> None:
        resolved = runnable._resolve_scope(None)
        assert resolved is scope_s1

    def test_config_scope_override(
        self,
        runnable: FERPAFilterRunnable,
        scope_s2: StudentIdentityScope,
    ) -> None:
        config = {"metadata": {"ferpa_scope": scope_s2}}
        resolved = runnable._resolve_scope(config)
        assert resolved is scope_s2

    def test_config_non_scope_value_falls_back(
        self, runnable: FERPAFilterRunnable, scope_s1: StudentIdentityScope
    ) -> None:
        config: dict[str, Any] = {"metadata": {"ferpa_scope": "not-a-scope"}}
        resolved = runnable._resolve_scope(config)
        assert resolved is scope_s1

    def test_config_without_metadata_falls_back(
        self, runnable: FERPAFilterRunnable, scope_s1: StudentIdentityScope
    ) -> None:
        config: dict[str, Any] = {}
        resolved = runnable._resolve_scope(config)
        assert resolved is scope_s1

    def test_raise_on_violation(self, scope_s1: StudentIdentityScope) -> None:
        r = FERPAFilterRunnable(scope=scope_s1, raise_on_violation=True)
        docs = [_FakeDoc({"student_id": "S-2", "institution_id": "inst-a"})]
        with pytest.raises(ValueError, match="FERPA"):
            r(docs)

    def test_scope_override_via_config(
        self,
        scope_s1: StudentIdentityScope,
        scope_s2: StudentIdentityScope,
    ) -> None:
        """Per-request scope injection blocks S-1 when override is S-2."""
        runnable = FERPAFilterRunnable(scope=scope_s1)
        docs = [
            _FakeDoc({"student_id": "S-1", "institution_id": "inst-a"}),
            _FakeDoc({"student_id": "S-2", "institution_id": "inst-a"}),
        ]
        config = {"metadata": {"ferpa_scope": scope_s2}}
        result = runnable(docs, config=config)
        student_ids = [d.metadata.get("student_id") for d in result]
        assert "S-1" not in student_ids
        assert "S-2" in student_ids

    def test_to_dict_maps_metadata(self, scope_s1: StudentIdentityScope) -> None:
        r = FERPAFilterRunnable(scope=scope_s1)
        doc = _FakeDoc({"student_id": "S-1", "institution_id": "inst-a", "category": "academic_record"})
        d = r._to_dict(doc, 0)
        assert d["_idx"] == 0
        assert d["student_id"] == "S-1"
        assert d["institution_id"] == "inst-a"
        # category maps to record_category for FERPAContextPolicy
        assert d["record_category"] == "academic_record"


# ---------------------------------------------------------------------------
# make_ferpa_chain
# ---------------------------------------------------------------------------


class TestMakeFerpaChain:
    def test_returns_chain(self, scope_s1: StudentIdentityScope) -> None:
        # All components duck-typed (MagicMock supports | operator)
        retriever = MagicMock()
        prompt = MagicMock()
        llm = MagicMock()
        chain = make_ferpa_chain(retriever, prompt, llm, scope=scope_s1)
        assert chain is not None

    def test_returns_chain_with_output_parser(self, scope_s1: StudentIdentityScope) -> None:
        retriever = MagicMock()
        prompt = MagicMock()
        llm = MagicMock()
        output_parser = MagicMock()
        chain = make_ferpa_chain(retriever, prompt, llm, scope=scope_s1, output_parser=output_parser)
        assert chain is not None

    def test_custom_audit_sink_propagated(self, scope_s1: StudentIdentityScope) -> None:
        sink = MagicMock()
        retriever = MagicMock()
        prompt = MagicMock()
        llm = MagicMock()
        # Should not raise; audit_sink is accepted without error
        chain = make_ferpa_chain(retriever, prompt, llm, scope=scope_s1, audit_sink=sink)
        assert chain is not None
