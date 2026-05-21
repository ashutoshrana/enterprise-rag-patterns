"""
OpenTelemetry observability for enterprise RAG compliance pipelines.

Instruments retrieval, filter decisions, and compliance outcomes with
GenAI semantic conventions (OpenTelemetry Semantic Conventions v1.26+).

Falls back to a no-op tracer when opentelemetry-sdk is not installed —
safe to import in environments without OTel.

Usage::

    from enterprise_rag_patterns.observability import RAGObservability

    obs = RAGObservability(service_name="enrollment-rag", regulation="FERPA")

    with obs.trace_retrieval(query, user_id="stu-001") as span:
        docs = pipeline.retrieve(query, scope=user_scope)
        obs.record_filter_decision(span, accepted=len(docs), rejected=n_filtered)
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

__all__ = ["RAGObservability", "FilterMetrics", "instrument_compliance"]


@dataclass
class FilterMetrics:
    """Accumulated metrics for one retrieval pass."""
    regulation: str
    user_id_hash: str
    query_hash: str
    documents_accepted: int = 0
    documents_rejected: int = 0
    filter_latency_ms: float = 0.0
    rejection_reasons: list[str] = field(default_factory=list)

    @property
    def rejection_rate(self) -> float:
        total = self.documents_accepted + self.documents_rejected
        return self.documents_rejected / total if total > 0 else 0.0


class _NoOpSpan:
    """Absorbs all span operations when OTel is not installed."""
    def set_attribute(self, *_: Any) -> None: ...
    def __enter__(self) -> "_NoOpSpan": return self
    def __exit__(self, *_: Any) -> None: ...


class RAGObservability:
    """
    OpenTelemetry instrumentation for RAG compliance pipelines.

    Emits spans following OTel GenAI semantic conventions plus custom
    compliance attributes (compliance.regulation, rag.filter.*).

    Metrics (when OTel SDK is present):
      rag.compliance.filter_decisions_total  — Counter by outcome + regulation
      rag.compliance.filter_latency_ms       — Histogram of filter latency
      rag.compliance.rejected_documents      — Histogram of per-pass rejections
      rag.compliance.escalations_total       — Counter of compliance escalations

    Args:
        service_name: OTel service.name resource attribute.
        regulation: Default compliance regulation (FERPA / HIPAA / GDPR / GLBA).
        otlp_endpoint: Optional OTLP gRPC endpoint for span export.

    Example::

        obs = RAGObservability(
            service_name="financial-aid-rag",
            regulation="FERPA",
            otlp_endpoint="http://otel-collector:4317",
        )
        with obs.trace_retrieval(query, user_id=student_id) as span:
            docs = retriever.retrieve(query)
            obs.record_filter_decision(span, accepted=len(docs), rejected=dropped)
    """

    _otel_available: bool = False

    def __init__(
        self,
        service_name: str = "enterprise-rag-pipeline",
        regulation: str = "FERPA",
        otlp_endpoint: str | None = None,
    ) -> None:
        self.service_name = service_name
        self.regulation = regulation
        self._tracer: Any = None
        self._counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._setup(otlp_endpoint)

    def _setup(self, otlp_endpoint: str | None) -> None:
        try:
            from opentelemetry import trace, metrics
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.resources import Resource

            resource = Resource.create({
                "service.name": self.service_name,
                "compliance.regulation": self.regulation,
            })
            tp = TracerProvider(resource=resource)
            if otlp_endpoint:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                from opentelemetry.sdk.trace.export import BatchSpanProcessor
                tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
            trace.set_tracer_provider(tp)
            self._tracer = trace.get_tracer(self.service_name)

            mp = MeterProvider(resource=resource)
            metrics.set_meter_provider(mp)
            meter = metrics.get_meter(self.service_name)

            self._counters["filter_decisions"] = meter.create_counter(
                "rag.compliance.filter_decisions_total",
                description="RAG filter decisions by outcome and regulation",
            )
            self._counters["escalations"] = meter.create_counter(
                "rag.compliance.escalations_total",
                description="Compliance escalations triggered",
            )
            self._histograms["filter_latency"] = meter.create_histogram(
                "rag.compliance.filter_latency_ms",
                unit="ms",
                description="Compliance filter evaluation latency",
            )
            self._histograms["rejected_docs"] = meter.create_histogram(
                "rag.compliance.rejected_documents",
                description="Documents rejected per retrieval pass",
            )
            RAGObservability._otel_available = True
        except ImportError:
            pass

    @contextmanager
    def trace_retrieval(
        self,
        query: str,
        user_id: str,
        regulation: str | None = None,
        operation: str = "rag.retrieval",
    ) -> Iterator[Any]:
        """
        Context manager wrapping one retrieval pass in an OTel span.

        Span attributes follow GenAI semantic conventions:
          gen_ai.operation.name, gen_ai.system,
          compliance.regulation, compliance.user_id_hash, rag.query_hash.

        PII safety: raw query and user_id are never stored — only SHA-256 hashes.
        """
        reg = regulation or self.regulation
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
        uid_hash = hashlib.sha256(user_id.encode()).hexdigest()[:16]

        if self._tracer and RAGObservability._otel_available:
            with self._tracer.start_as_current_span(operation) as span:
                span.set_attribute("gen_ai.operation.name", operation)
                span.set_attribute("gen_ai.system", "enterprise-rag-patterns")
                span.set_attribute("compliance.regulation", reg)
                span.set_attribute("compliance.user_id_hash", uid_hash)
                span.set_attribute("rag.query_hash", query_hash)
                yield span
        else:
            yield _NoOpSpan()

    def record_filter_decision(
        self,
        span: Any,
        accepted: int,
        rejected: int,
        rejection_reasons: list[str] | None = None,
        latency_ms: float | None = None,
        regulation: str | None = None,
    ) -> None:
        """Record filter outcome on the active span and increment metrics."""
        reg = regulation or self.regulation
        attrs = {"compliance.regulation": reg}
        if RAGObservability._otel_available:
            self._counters["filter_decisions"].add(accepted, {**attrs, "outcome": "accepted"})
            self._counters["filter_decisions"].add(rejected, {**attrs, "outcome": "rejected"})
            if latency_ms is not None:
                self._histograms["filter_latency"].record(latency_ms, attrs)
            if rejected > 0:
                self._histograms["rejected_docs"].record(rejected, attrs)
        if hasattr(span, "set_attribute"):
            span.set_attribute("rag.filter.accepted", accepted)
            span.set_attribute("rag.filter.rejected", rejected)
            if rejection_reasons:
                span.set_attribute("rag.filter.rejection_reasons", ",".join(rejection_reasons[:5]))

    def record_escalation(self, reason: str, regulation: str | None = None) -> None:
        """Increment escalation counter for compliance dashboards."""
        if RAGObservability._otel_available:
            self._counters["escalations"].add(1, {
                "compliance.regulation": regulation or self.regulation,
                "escalation.reason": reason,
            })


def instrument_compliance(regulation: str = "FERPA", service_name: str = "rag-pipeline") -> RAGObservability:
    """Convenience factory returning a configured RAGObservability instance."""
    return RAGObservability(service_name=service_name, regulation=regulation)
