"""
dspy.py — DSPy integration: FERPA-scoped and HIPAA-scoped retriever modules.

Provides DSPy-native retrieval steps that enforce FERPA identity-scope filtering
and HIPAA minimum-necessary access control before retrieved passages reach the
LLM synthesis stage.

Compatible with DSPy ≥ 2.5.0 (Pydantic v2).

Installation:
    pip install enterprise-rag-patterns[dspy]

Usage — FERPA::

    import dspy
    from enterprise_rag_patterns.compliance import (
        FERPAContextPolicy, StudentIdentityScope, RecordCategory, DisclosureReason,
    )
    from enterprise_rag_patterns.integrations.dspy import FERPADSPyRetriever

    scope = StudentIdentityScope(
        student_id="S-001",
        institution_id="acme-univ",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )
    policy = FERPAContextPolicy(scope=scope)

    base_retriever = dspy.Retrieve(k=10)
    ferpa_retriever = FERPADSPyRetriever(retriever=base_retriever, policy=policy)

    class EnrollmentAdvisor(dspy.Module):
        def __init__(self):
            self.retrieve = ferpa_retriever
            self.generate = dspy.ChainOfThought("context, question -> answer")

        def forward(self, question):
            passages = self.retrieve(question)
            context = "\\n".join(passages.passages)
            return self.generate(context=context, question=question)

    advisor = EnrollmentAdvisor()
    response = advisor(question="What are my graduation requirements?")

Usage — HIPAA::

    from enterprise_rag_patterns.regulations.hipaa import (
        HIPAAContextPolicy, HIPAAAccessScope, HIPAAPurpose,
    )
    from enterprise_rag_patterns.integrations.dspy import HIPAADSPyRetriever

    scope = HIPAAAccessScope(
        patient_id="PAT-001",
        provider_id="prov-clinic-a",
        purpose=HIPAAPurpose.TREATMENT,
        permitted_phi_categories={"DiagnosisData", "MedicationData"},
    )
    policy = HIPAAContextPolicy(scope=scope)
    hipaa_retriever = HIPAADSPyRetriever(retriever=base_retriever, policy=policy)
"""

from __future__ import annotations

from typing import Any

from ..compliance import AuditRecord, FERPAContextPolicy, StudentIdentityScope


class _DSPyPassagesResult:
    """
    Minimal stand-in for ``dspy.Prediction`` when dspy is not installed.

    When dspy IS installed, the real retriever returns a ``dspy.Prediction``
    with a ``passages`` attribute.  This class provides the same interface
    so that ``FERPADSPyRetriever`` can be tested and used without the dspy
    dependency.
    """

    __slots__ = ("passages",)

    def __init__(self, passages: list[Any]) -> None:
        self.passages = passages


def _extract_passages(result: Any) -> list[Any]:
    """
    Normalise a retriever result to a list of passage objects.

    Handles:
    - ``dspy.Prediction`` with ``.passages`` attribute (list of strings or dicts)
    - Plain ``list`` (already a list of passages)
    - Any other object with a ``.passages`` attribute
    """
    if isinstance(result, list):
        return result
    if hasattr(result, "passages"):
        return list(result.passages)
    return []


def _passage_to_dict(passage: Any) -> dict[str, Any]:
    """Convert a passage to a dict for policy filtering."""
    if isinstance(passage, dict):
        return passage
    if isinstance(passage, str):
        return {"content": passage}
    # dspy.Example / object with attribute access
    return {
        "content": getattr(passage, "long_text", getattr(passage, "text", str(passage))),
        "student_id": getattr(passage, "student_id", None),
        "institution_id": getattr(passage, "institution_id", None),
        "record_category": getattr(passage, "record_category", None),
        "patient_id": getattr(passage, "patient_id", None),
        "phi_category": getattr(passage, "phi_category", None),
    }


class FERPADSPyRetriever:
    """
    DSPy ``Module`` wrapper that applies FERPA identity-scope filtering.

    Intercepts the underlying retriever's passages and runs them through
    ``FERPAContextPolicy.filter_retrieved_documents()``.  Passages that do not
    belong to the authorised student / institution / category set are removed
    before the response is returned to the caller.

    The module mimics the DSPy Module API — ``__call__`` / ``forward`` work
    identically to the wrapped retriever from the pipeline's perspective.

    ``FERPAContextPolicy`` uses ``self.scope`` (set at construction time) to
    evaluate each document.  Pass a new ``FERPAContextPolicy`` per request when
    serving multiple students concurrently.

    Args:
        retriever: Any DSPy ``Retrieve`` module or compatible callable.
        policy: Pre-configured ``FERPAContextPolicy`` containing the student
            identity scope and optional audit sink.
    """

    def __init__(
        self,
        retriever: Any,
        policy: FERPAContextPolicy,
    ) -> None:
        self._retriever = retriever
        self._policy = policy

    @property
    def scope(self) -> StudentIdentityScope:
        """The active ``StudentIdentityScope`` from the wrapped policy."""
        return self._policy.scope

    def forward(self, query: str, **kwargs: Any) -> _DSPyPassagesResult:
        """
        Retrieve passages and apply FERPA identity-scope filtering.

        Args:
            query: The retrieval query string.
            **kwargs: Additional keyword arguments forwarded to the retriever.

        Returns:
            A ``_DSPyPassagesResult`` with a ``passages`` attribute containing
            only the passages permitted by the FERPA scope.  Blocked passages are
            silently removed — consistent with FERPA's prohibition on disclosing
            which records were withheld (34 CFR § 99.12).
        """
        raw_result = self._retriever(query, **kwargs)
        raw_passages = _extract_passages(raw_result)
        doc_dicts = [_passage_to_dict(p) for p in raw_passages]

        filtered_docs = self._policy.filter_retrieved_documents(documents=doc_dicts)

        filtered_passages = _rebuild_passages(raw_passages, filtered_docs)
        return _DSPyPassagesResult(passages=filtered_passages)

    def __call__(self, query: str, **kwargs: Any) -> _DSPyPassagesResult:
        """Delegate to ``forward()`` — matches the DSPy Module ``__call__`` contract."""
        return self.forward(query, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate DSPy introspection to the wrapped retriever."""
        return getattr(self._retriever, name)

    def __repr__(self) -> str:
        return (
            f"FERPADSPyRetriever("
            f"student={self._policy.scope.student_id!r}, "
            f"institution={self._policy.scope.institution_id!r})"
        )


class HIPAADSPyRetriever:
    """
    DSPy ``Module`` wrapper that applies HIPAA minimum-necessary filtering.

    Intercepts the underlying retriever's results and runs them through
    ``HIPAAContextPolicy.filter_retrieved_documents()``, removing any ePHI
    documents outside the authorised patient / purpose / PHI-category boundary
    (45 CFR § 164.502(b)).

    Args:
        retriever: Any DSPy ``Retrieve`` module or compatible callable.
        policy: Pre-configured ``HIPAAContextPolicy`` containing the access
            scope and optional audit sink.
    """

    def __init__(
        self,
        retriever: Any,
        policy: Any,  # HIPAAContextPolicy — typed as Any to avoid circular import at module level
    ) -> None:
        self._retriever = retriever
        self._policy = policy

    def forward(self, query: str, **kwargs: Any) -> _DSPyPassagesResult:
        """
        Retrieve passages and apply HIPAA minimum-necessary filtering.

        Args:
            query: The retrieval query string.
            **kwargs: Additional keyword arguments forwarded to the retriever.

        Returns:
            A ``_DSPyPassagesResult`` with HIPAA-filtered passages.
        """
        raw_result = self._retriever(query, **kwargs)
        raw_passages = _extract_passages(raw_result)
        doc_dicts = [_passage_to_dict(p) for p in raw_passages]

        filtered_docs = self._policy.filter_retrieved_documents(documents=doc_dicts)

        filtered_passages = _rebuild_passages(raw_passages, filtered_docs)
        return _DSPyPassagesResult(passages=filtered_passages)

    def __call__(self, query: str, **kwargs: Any) -> _DSPyPassagesResult:
        return self.forward(query, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._retriever, name)

    def __repr__(self) -> str:
        return f"HIPAADSPyRetriever(policy={self._policy!r})"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _rebuild_passages(
    original: list[Any],
    filtered_dicts: list[dict[str, Any]],
) -> list[Any]:
    """
    Return original passage objects that survived filtering.

    Matches by content string to preserve the original passage type
    (string, dspy.Example, etc.) rather than returning plain dicts.
    Preserves order of original passages.
    """
    allowed_contents: set[str] = {str(d.get("content", "")) for d in filtered_dicts}
    return [p for p in original if str(_passage_to_dict(p).get("content", "")) in allowed_contents]


# ---------------------------------------------------------------------------
# Re-export AuditRecord for callers who use the audit_sink callback
# ---------------------------------------------------------------------------

__all__ = [
    "FERPADSPyRetriever",
    "HIPAADSPyRetriever",
    "_DSPyPassagesResult",
    "AuditRecord",
]
