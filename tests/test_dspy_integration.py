"""Tests for FERPADSPyRetriever and HIPAADSPyRetriever DSPy integrations."""

from __future__ import annotations

from typing import Any

from enterprise_rag_patterns.compliance import (
    DisclosureReason,
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
)
from enterprise_rag_patterns.integrations.dspy import (
    FERPADSPyRetriever,
    HIPAADSPyRetriever,
    _DSPyPassagesResult,
    _extract_passages,
    _passage_to_dict,
    _rebuild_passages,
)
from enterprise_rag_patterns.regulations.hipaa import (
    HIPAAAccessScope,
    HIPAAContextPolicy,
    HIPAAPurpose,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_STUDENT_ID = "S-001"
_INSTITUTION = "acme-univ"
_OTHER_STUDENT = "S-999"
_OTHER_INSTITUTION = "acme-univ-b"


def _scope(
    student_id: str = _STUDENT_ID,
    institution_id: str = _INSTITUTION,
    categories: set[RecordCategory] | None = None,
) -> StudentIdentityScope:
    return StudentIdentityScope(
        student_id=student_id,
        institution_id=institution_id,
        requesting_user_id="agent:enrollment_advisor",
        authorized_categories=categories or {RecordCategory.ACADEMIC_RECORD},
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )


def _policy(
    student_id: str = _STUDENT_ID,
    institution_id: str = _INSTITUTION,
    categories: set[RecordCategory] | None = None,
) -> FERPAContextPolicy:
    return FERPAContextPolicy(scope=_scope(student_id, institution_id, categories))


class FakeRetriever:
    """Stub retriever returning a fixed list of passages."""

    def __init__(self, passages: list[Any]) -> None:
        self._passages = passages

    def __call__(self, query: str, **kwargs: Any) -> _DSPyPassagesResult:
        return _DSPyPassagesResult(passages=self._passages)


# ---------------------------------------------------------------------------
# _DSPyPassagesResult
# ---------------------------------------------------------------------------


class TestDSPyPassagesResult:
    def test_has_passages_attribute(self) -> None:
        r = _DSPyPassagesResult(["a", "b"])
        assert r.passages == ["a", "b"]

    def test_empty_passages(self) -> None:
        r = _DSPyPassagesResult([])
        assert r.passages == []


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestExtractPassages:
    def test_list_returned_directly(self) -> None:
        docs = ["a", "b"]
        assert _extract_passages(docs) == docs

    def test_object_with_passages_attr(self) -> None:
        obj = _DSPyPassagesResult(["x", "y"])
        assert _extract_passages(obj) == ["x", "y"]

    def test_unknown_object_returns_empty(self) -> None:
        assert _extract_passages("not a list or prediction") == []


class TestPassageToDict:
    def test_dict_passthrough(self) -> None:
        doc = {"content": "hello", "student_id": "S-001"}
        assert _passage_to_dict(doc) == doc

    def test_string_becomes_content_dict(self) -> None:
        result = _passage_to_dict("hello world")
        assert result["content"] == "hello world"

    def test_object_with_text_attr(self) -> None:
        class FakeNode:
            text = "node text"
            student_id = "S-001"
            institution_id = "acme-univ"
            record_category = None
            patient_id = None
            phi_category = None

        result = _passage_to_dict(FakeNode())
        assert result["content"] == "node text"
        assert result["student_id"] == "S-001"


class TestRebuildPassages:
    def test_all_pass_through(self) -> None:
        originals = [{"content": "a"}, {"content": "b"}]
        filtered = [{"content": "a"}, {"content": "b"}]
        assert _rebuild_passages(originals, filtered) == originals

    def test_blocked_passage_removed(self) -> None:
        originals = [{"content": "a"}, {"content": "b"}]
        filtered = [{"content": "a"}]
        assert _rebuild_passages(originals, filtered) == [{"content": "a"}]

    def test_preserves_original_type(self) -> None:
        originals = ["string-passage"]
        filtered = [{"content": "string-passage"}]
        result = _rebuild_passages(originals, filtered)
        assert result == ["string-passage"]


# ---------------------------------------------------------------------------
# FERPADSPyRetriever — basic invocation
# ---------------------------------------------------------------------------


class TestFERPADSPyRetrieverBasic:
    def test_returns_passages_result(self) -> None:
        retriever = FakeRetriever([{"content": "data", "student_id": _STUDENT_ID, "institution_id": _INSTITUTION}])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("graduation requirements")
        assert isinstance(result, _DSPyPassagesResult)

    def test_forward_same_as_call(self) -> None:
        retriever = FakeRetriever([{"content": "data", "student_id": _STUDENT_ID, "institution_id": _INSTITUTION}])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        assert wrapped("q").passages == wrapped.forward("q").passages

    def test_scope_property(self) -> None:
        wrapped = FERPADSPyRetriever(retriever=FakeRetriever([]), policy=_policy())
        assert wrapped.scope.student_id == _STUDENT_ID
        assert wrapped.scope.institution_id == _INSTITUTION

    def test_repr_contains_student_and_institution(self) -> None:
        wrapped = FERPADSPyRetriever(retriever=FakeRetriever([]), policy=_policy())
        r = repr(wrapped)
        assert _STUDENT_ID in r
        assert _INSTITUTION in r


# ---------------------------------------------------------------------------
# FERPADSPyRetriever — FERPA filtering
# ---------------------------------------------------------------------------


class TestFERPADSPyRetrieverFiltering:
    def test_authorized_passage_passes_through(self) -> None:
        doc = {"content": "my record", "student_id": _STUDENT_ID, "institution_id": _INSTITUTION}
        retriever = FakeRetriever([doc])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        assert len(result.passages) == 1

    def test_wrong_student_blocked(self) -> None:
        doc = {"content": "other record", "student_id": _OTHER_STUDENT, "institution_id": _INSTITUTION}
        retriever = FakeRetriever([doc])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        assert len(result.passages) == 0

    def test_wrong_institution_blocked(self) -> None:
        doc = {"content": "cross-inst", "student_id": _STUDENT_ID, "institution_id": _OTHER_INSTITUTION}
        retriever = FakeRetriever([doc])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        assert len(result.passages) == 0

    def test_non_ferpa_content_passes_through(self) -> None:
        doc = {"content": "general policy doc"}  # no student_id or institution_id
        retriever = FakeRetriever([doc])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        assert len(result.passages) == 1

    def test_mixed_passages_filtered_correctly(self) -> None:
        docs = [
            {"content": "alice record", "student_id": _STUDENT_ID, "institution_id": _INSTITUTION},
            {"content": "bob record", "student_id": _OTHER_STUDENT, "institution_id": _INSTITUTION},
            {"content": "generic doc"},  # no FERPA tags — passes through
        ]
        retriever = FakeRetriever(docs)
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        contents = [_passage_to_dict(p)["content"] for p in result.passages]
        assert "alice record" in contents
        assert "bob record" not in contents
        assert "generic doc" in contents

    def test_empty_retriever_result(self) -> None:
        retriever = FakeRetriever([])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        assert result.passages == []

    def test_string_passages_pass_through(self) -> None:
        # String passages without FERPA metadata are treated as non-FERPA content
        retriever = FakeRetriever(["generic knowledge base entry"])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        assert len(result.passages) == 1

    def test_result_preserves_original_passage_type(self) -> None:
        doc = {"content": "my record", "student_id": _STUDENT_ID, "institution_id": _INSTITUTION}
        retriever = FakeRetriever([doc])
        wrapped = FERPADSPyRetriever(retriever=retriever, policy=_policy())
        result = wrapped("q")
        assert result.passages[0] is doc  # original dict, not a copy

    def test_cross_institution_isolation(self) -> None:
        """Two policies for different students must produce different results."""
        docs = [
            {"content": "alice-doc", "student_id": "S-001", "institution_id": "acme-univ"},
            {"content": "bob-doc", "student_id": "S-002", "institution_id": "acme-univ-b"},
        ]
        retriever = FakeRetriever(docs)
        policy_alice = _policy("S-001", "acme-univ")
        policy_bob = _policy("S-002", "acme-univ-b")

        result_alice = FERPADSPyRetriever(retriever=retriever, policy=policy_alice)("q")
        result_bob = FERPADSPyRetriever(retriever=retriever, policy=policy_bob)("q")

        contents_alice = {_passage_to_dict(p)["content"] for p in result_alice.passages}
        contents_bob = {_passage_to_dict(p)["content"] for p in result_bob.passages}
        assert contents_alice == {"alice-doc"}
        assert contents_bob == {"bob-doc"}


# ---------------------------------------------------------------------------
# FERPADSPyRetriever — attribute delegation
# ---------------------------------------------------------------------------


class TestFERPADSPyRetrieverDelegation:
    def test_getattr_delegates_to_retriever(self) -> None:
        class RetrieverWithAttr:
            k = 5

            def __call__(self, query: str, **kwargs: Any) -> _DSPyPassagesResult:
                return _DSPyPassagesResult([])

        wrapped = FERPADSPyRetriever(retriever=RetrieverWithAttr(), policy=_policy())
        assert wrapped.k == 5


# ---------------------------------------------------------------------------
# HIPAADSPyRetriever
# ---------------------------------------------------------------------------


def _hipaa_scope(
    patient_id: str = "PAT-001",
    covered_entity_id: str = "clinic-a",
    purpose: HIPAAPurpose = HIPAAPurpose.TREATMENT,
) -> HIPAAAccessScope:
    return HIPAAAccessScope(
        patient_id=patient_id,
        covered_entity_id=covered_entity_id,
        permitted_purposes=frozenset({purpose}),
        role="clinician",
        authorized_phi_categories=frozenset({"DiagnosisData", "MedicationData"}),
    )


def _hipaa_policy(patient_id: str = "PAT-001") -> HIPAAContextPolicy:
    return HIPAAContextPolicy(scope=_hipaa_scope(patient_id=patient_id))


class TestHIPAADSPyRetriever:
    def test_returns_passages_result(self) -> None:
        doc = {"content": "diagnosis notes", "patient_id": "PAT-001", "phi_category": "DiagnosisData"}
        retriever = FakeRetriever([doc])
        wrapped = HIPAADSPyRetriever(retriever=retriever, policy=_hipaa_policy())
        result = wrapped("patient symptoms")
        assert isinstance(result, _DSPyPassagesResult)

    def test_authorized_phi_passes_through(self) -> None:
        doc = {"content": "notes", "patient_id": "PAT-001", "phi_category": "DiagnosisData"}
        retriever = FakeRetriever([doc])
        wrapped = HIPAADSPyRetriever(retriever=retriever, policy=_hipaa_policy())
        result = wrapped("q")
        assert len(result.passages) == 1

    def test_wrong_patient_blocked(self) -> None:
        doc = {"content": "other notes", "patient_id": "PAT-999", "phi_category": "DiagnosisData"}
        retriever = FakeRetriever([doc])
        wrapped = HIPAADSPyRetriever(retriever=retriever, policy=_hipaa_policy())
        result = wrapped("q")
        assert len(result.passages) == 0

    def test_non_phi_content_passes_through(self) -> None:
        doc = {"content": "clinical guidelines"}  # no patient_id
        retriever = FakeRetriever([doc])
        wrapped = HIPAADSPyRetriever(retriever=retriever, policy=_hipaa_policy())
        result = wrapped("q")
        assert len(result.passages) == 1

    def test_call_delegates_to_forward(self) -> None:
        retriever = FakeRetriever([])
        wrapped = HIPAADSPyRetriever(retriever=retriever, policy=_hipaa_policy())
        assert wrapped("q").passages == wrapped.forward("q").passages

    def test_repr_is_string(self) -> None:
        wrapped = HIPAADSPyRetriever(retriever=FakeRetriever([]), policy=_hipaa_policy())
        assert isinstance(repr(wrapped), str)
