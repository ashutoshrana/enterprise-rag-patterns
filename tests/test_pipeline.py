"""Tests for FilterPipeline and PipelineResult."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from enterprise_rag_patterns.pipeline import FilterPipeline, PipelineResult

# ---------------------------------------------------------------------------
# Minimal stub that mimics a real filter result object
# ---------------------------------------------------------------------------


class _FilterResult:
    def __init__(
        self,
        decision: str,
        reason: str = "test reason",
        regulation_citation: str = "Test §1",
        requires_logging: bool = True,
    ):
        self.decision = decision
        self.reason = reason
        self.regulation_citation = regulation_citation
        self.requires_logging = requires_logging


def _make_filter(decision: str, reason: str = "test reason", citation: str = "Test §1", requires_logging: bool = True):
    """Return a simple callable that always returns the given decision."""

    def _filter(document: dict) -> _FilterResult:
        return _FilterResult(decision, reason, citation, requires_logging)

    return _filter


# ---------------------------------------------------------------------------
# PipelineResult unit tests
# ---------------------------------------------------------------------------


class TestPipelineResult:
    def test_is_approved_true(self):
        r = PipelineResult(decision="APPROVED", reason="ok", regulation_citation="", filter_name="pipeline")
        assert r.is_approved is True

    def test_is_approved_false_denied(self):
        r = PipelineResult(decision="DENIED", reason="blocked", regulation_citation="§1", filter_name="f")
        assert r.is_approved is False

    def test_passed_all_filters_alias(self):
        r = PipelineResult(decision="APPROVED", reason="ok", regulation_citation="", filter_name="pipeline")
        assert r.passed_all_filters is True

    def test_passed_all_filters_false(self):
        r = PipelineResult(decision="REQUIRES_HUMAN_REVIEW", reason="review", regulation_citation="§2", filter_name="f")
        assert r.passed_all_filters is False

    def test_requires_logging_default_true(self):
        r = PipelineResult(decision="DENIED", reason="x", regulation_citation="§1", filter_name="f")
        assert r.requires_logging is True

    def test_requires_logging_can_be_false(self):
        r = PipelineResult(
            decision="APPROVED", reason="ok", regulation_citation="", filter_name="pipeline", requires_logging=False
        )
        assert r.requires_logging is False


# ---------------------------------------------------------------------------
# FilterPipeline construction
# ---------------------------------------------------------------------------


class TestFilterPipelineConstruction:
    def test_empty_filters_raises(self):
        with pytest.raises(ValueError, match="at least one filter"):
            FilterPipeline([])

    def test_single_filter_len(self):
        p = FilterPipeline([_make_filter("APPROVED")])
        assert len(p) == 1

    def test_multiple_filters_len(self):
        p = FilterPipeline([_make_filter("APPROVED")] * 5)
        assert len(p) == 5

    def test_repr_contains_filter_name(self):
        def my_special_filter(doc):
            return _FilterResult("APPROVED")

        p = FilterPipeline([my_special_filter])
        assert "my_special_filter" in repr(p)

    def test_repr_format(self):
        p = FilterPipeline([_make_filter("APPROVED"), _make_filter("DENIED")])
        r = repr(p)
        assert r.startswith("FilterPipeline([")
        assert r.endswith("])")


# ---------------------------------------------------------------------------
# FilterPipeline.run — single filter
# ---------------------------------------------------------------------------


class TestFilterPipelineRunSingle:
    def test_single_approved_returns_approved(self):
        p = FilterPipeline([_make_filter("APPROVED")])
        result = p.run({"text": "hello"})
        assert result.decision == "APPROVED"
        assert result.is_approved is True
        assert result.filter_name == "pipeline"

    def test_single_denied_returns_denied(self):
        p = FilterPipeline([_make_filter("DENIED", reason="PII detected", citation="HIPAA §164.502")])
        result = p.run({"text": "SSN 123-45-6789"})
        assert result.decision == "DENIED"
        assert result.reason == "PII detected"
        assert result.regulation_citation == "HIPAA §164.502"
        assert result.is_approved is False

    def test_single_requires_review_does_not_block_by_default(self):
        p = FilterPipeline([_make_filter("REQUIRES_HUMAN_REVIEW")])
        result = p.run({})
        # With stop_on_requires_review=False, REQUIRES_HUMAN_REVIEW is not blocking,
        # so pipeline continues to end and returns APPROVED
        assert result.decision == "APPROVED"

    def test_single_requires_review_blocks_when_flag_set(self):
        p = FilterPipeline(
            [_make_filter("REQUIRES_HUMAN_REVIEW", reason="ambiguous", citation="Policy §5")],
            stop_on_requires_review=True,
        )
        result = p.run({})
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert result.reason == "ambiguous"


# ---------------------------------------------------------------------------
# FilterPipeline.run — two filters, ordering / short-circuit
# ---------------------------------------------------------------------------


class TestFilterPipelineShortCircuit:
    def test_first_denied_second_never_called(self):
        call_count = {"n": 0}

        def counting_filter(doc):
            call_count["n"] += 1
            return _FilterResult("APPROVED")

        p = FilterPipeline([_make_filter("DENIED"), counting_filter])
        result = p.run({})
        assert result.decision == "DENIED"
        assert call_count["n"] == 0, "Second filter should not have been called"

    def test_first_approved_second_denied_returns_second(self):
        p = FilterPipeline(
            [
                _make_filter("APPROVED"),
                _make_filter("DENIED", reason="second blocked", citation="GDPR Art.9"),
            ]
        )
        result = p.run({})
        assert result.decision == "DENIED"
        assert result.reason == "second blocked"
        assert result.regulation_citation == "GDPR Art.9"

    def test_all_approved_returns_approved(self):
        p = FilterPipeline(
            [
                _make_filter("APPROVED"),
                _make_filter("APPROVED"),
                _make_filter("APPROVED"),
            ]
        )
        result = p.run({"text": "safe content"})
        assert result.is_approved is True
        assert result.filter_name == "pipeline"
        assert result.requires_logging is False

    def test_requires_review_continues_when_flag_false(self):
        """REQUIRES_HUMAN_REVIEW mid-pipeline should not block when stop_on_requires_review=False."""
        call_count = {"n": 0}

        def second_filter(doc):
            call_count["n"] += 1
            return _FilterResult("APPROVED")

        p = FilterPipeline(
            [
                _make_filter("REQUIRES_HUMAN_REVIEW"),
                second_filter,
            ],
            stop_on_requires_review=False,
        )
        result = p.run({})
        assert result.decision == "APPROVED"
        assert call_count["n"] == 1, "Second filter must have been called"

    def test_requires_review_short_circuits_when_flag_true(self):
        call_count = {"n": 0}

        def second_filter(doc):
            call_count["n"] += 1
            return _FilterResult("APPROVED")

        p = FilterPipeline(
            [
                _make_filter("REQUIRES_HUMAN_REVIEW"),
                second_filter,
            ],
            stop_on_requires_review=True,
        )
        result = p.run({})
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert call_count["n"] == 0, "Second filter must NOT have been called"

    def test_requires_logging_propagated_from_filter_result(self):
        p = FilterPipeline([_make_filter("DENIED", requires_logging=False)])
        result = p.run({})
        assert result.requires_logging is False

    def test_requires_logging_defaults_true_when_attribute_missing(self):
        """If filter result has no requires_logging attribute, default to True."""

        class MinimalResult:
            decision = "DENIED"
            reason = "blocked"
            regulation_citation = "§X"
            # No requires_logging attribute

        def minimal_filter(doc):
            return MinimalResult()

        p = FilterPipeline([minimal_filter])
        result = p.run({})
        assert result.requires_logging is True


# ---------------------------------------------------------------------------
# FilterPipeline.filter_batch
# ---------------------------------------------------------------------------


class TestFilterBatch:
    def test_filter_batch_returns_one_result_per_document(self):
        p = FilterPipeline([_make_filter("APPROVED")])
        docs = [{}, {}, {}]
        results = p.filter_batch(docs)
        assert len(results) == 3

    def test_filter_batch_empty_list(self):
        p = FilterPipeline([_make_filter("APPROVED")])
        results = p.filter_batch([])
        assert results == []

    def test_filter_batch_mixed_results(self):
        decisions = ["APPROVED", "DENIED", "APPROVED"]
        idx = {"i": 0}

        def rotating_filter(doc):
            d = decisions[idx["i"] % len(decisions)]
            idx["i"] += 1
            return _FilterResult(d)

        p = FilterPipeline([rotating_filter])
        results = p.filter_batch([{}, {}, {}])
        assert [r.decision for r in results] == ["APPROVED", "DENIED", "APPROVED"]

    def test_filter_batch_all_denied(self):
        p = FilterPipeline([_make_filter("DENIED")])
        results = p.filter_batch([{"a": 1}, {"b": 2}])
        assert all(r.decision == "DENIED" for r in results)


# ---------------------------------------------------------------------------
# FilterPipeline.approved_only
# ---------------------------------------------------------------------------


class TestApprovedOnly:
    def test_approved_only_passes_all_when_all_approved(self):
        p = FilterPipeline([_make_filter("APPROVED")])
        docs = [{"id": 1}, {"id": 2}, {"id": 3}]
        result = p.approved_only(docs)
        assert result == docs

    def test_approved_only_removes_denied(self):
        decisions = iter(["APPROVED", "DENIED", "APPROVED"])

        def sequential_filter(doc):
            return _FilterResult(next(decisions))

        p = FilterPipeline([sequential_filter])
        docs = [{"id": 1}, {"id": 2}, {"id": 3}]
        result = p.approved_only(docs)
        assert len(result) == 2
        assert result[0]["id"] == 1
        assert result[1]["id"] == 3

    def test_approved_only_empty_input(self):
        p = FilterPipeline([_make_filter("APPROVED")])
        assert p.approved_only([]) == []

    def test_approved_only_all_denied_returns_empty(self):
        p = FilterPipeline([_make_filter("DENIED")])
        docs = [{"id": i} for i in range(5)]
        assert p.approved_only(docs) == []


# ---------------------------------------------------------------------------
# Top-level package import smoke test
# ---------------------------------------------------------------------------


class TestPackageImport:
    def test_import_from_package_init(self):
        from enterprise_rag_patterns import FilterPipeline as FP
        from enterprise_rag_patterns import PipelineResult as PR

        assert FP is FilterPipeline
        assert PR is PipelineResult

    def test_version_present(self):
        import enterprise_rag_patterns

        assert hasattr(enterprise_rag_patterns, "__version__")
        assert enterprise_rag_patterns.__version__ == "0.34.0"
