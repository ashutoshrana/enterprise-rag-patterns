"""
FilterPipeline — composable pre-filter chain for RAG pipelines.

Chains multiple filter callables and short-circuits on the first non-APPROVED
result, returning that result along with the filter that produced it.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Aggregated result from running all filters in the pipeline."""
    decision: str  # APPROVED / DENIED / REDACTED / REQUIRES_HUMAN_REVIEW
    reason: str
    regulation_citation: str
    filter_name: str  # which filter produced the decision
    requires_logging: bool = True

    @property
    def is_approved(self) -> bool:
        return self.decision == "APPROVED"

    @property
    def passed_all_filters(self) -> bool:
        return self.decision == "APPROVED"


class FilterPipeline:
    """
    Chains filter callables in order; short-circuits on first non-APPROVED result.

    Each filter callable must accept a single dict (the document) and return an
    object with at least: .decision (str), .reason (str), .regulation_citation (str).

    Usage::

        pipeline = FilterPipeline([
            FERPAComplianceFilter(...).filter,
            HIPAAPrivacyFilter(...).filter,
            CCPADataSubjectFilter(...).filter,
        ])
        result = pipeline.run(document)
        if not result.is_approved:
            logger.warning("Document blocked: %s", result.reason)
    """

    def __init__(
        self,
        filters: list[Callable],
        *,
        stop_on_requires_review: bool = False,
    ) -> None:
        """
        Args:
            filters: Ordered list of filter callables. Each receives a dict document
                     and returns an object with .decision / .reason / .regulation_citation.
            stop_on_requires_review: If True, treat REQUIRES_HUMAN_REVIEW the same as
                DENIED for short-circuit purposes. Default False (pipeline continues).
        """
        if not filters:
            raise ValueError("FilterPipeline requires at least one filter")
        self._filters = filters
        self._stop_on_requires_review = stop_on_requires_review

    def run(self, document: dict) -> PipelineResult:
        """
        Run all filters against document. Returns the first blocking result, or
        APPROVED if all filters pass.
        """
        for filter_fn in self._filters:
            result = filter_fn(document)
            decision = result.decision
            is_blocking = decision == "DENIED" or (
                self._stop_on_requires_review and decision == "REQUIRES_HUMAN_REVIEW"
            )
            if is_blocking:
                logger.debug(
                    "Document blocked by %s: %s (%s)",
                    filter_fn.__qualname__,
                    result.reason,
                    result.regulation_citation,
                )
                return PipelineResult(
                    decision=decision,
                    reason=result.reason,
                    regulation_citation=result.regulation_citation,
                    filter_name=filter_fn.__qualname__,
                    requires_logging=getattr(result, "requires_logging", True),
                )
        # All filters passed
        return PipelineResult(
            decision="APPROVED",
            reason="All filters passed",
            regulation_citation="",
            filter_name="pipeline",
            requires_logging=False,
        )

    def filter_batch(self, documents: list[dict]) -> list[PipelineResult]:
        """Run pipeline against a list of documents. Returns result for each."""
        return [self.run(doc) for doc in documents]

    def approved_only(self, documents: list[dict]) -> list[dict]:
        """Filter a list of documents, returning only those that pass all filters."""
        return [doc for doc in documents if self.run(doc).is_approved]

    def __len__(self) -> int:
        return len(self._filters)

    def __repr__(self) -> str:
        names = [getattr(f, "__qualname__", repr(f)) for f in self._filters]
        return f"FilterPipeline([{', '.join(names)}])"
