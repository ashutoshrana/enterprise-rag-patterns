"""
regulations/nist_ai_rmf.py — NIST AI Risk Management Framework (AI RMF 1.0) patterns.

Provides RAG-pipeline-layer primitives aligned with the NIST AI RMF 1.0
(NIST AI 100-1, January 2023) and the NIST AI 600-1 Generative AI Profile.

The NIST AI RMF organises AI governance into four core functions:

  GOVERN  — Policies, accountability, culture; AI risk oversight.
  MAP     — Context, risk identification; problem framing.
  MEASURE — Analysis, assessment, benchmarking; risk quantification.
  MANAGE  — Prioritisation, response, monitoring; risk treatment.

For RAG pipelines, the most operative sub-categories are:

  MAP 1.6  — Map the risks associated with each data source and retrieval step.
  MEASURE 2.5 — Measure bias, toxicity, and accuracy on a per-query basis.
  MEASURE 2.6 — Evaluate system-level risks including retrieval hallucination rate.
  MANAGE 1.3 — Track and document all AI incidents and anomalies.
  GOVERN 1.1 — Establish policies for acceptable use of AI systems.

NIST AI 600-1 Generative AI Profile (July 2024)
------------------------------------------------
The Generative AI Profile maps 12 unique risks of generative AI to AI RMF
functions.  The risks most relevant to RAG pipelines are:

  GV-AI-001 — Data Privacy: PII leakage from retrieved context.
  GV-AI-002 — Confabulation: Retrieval-grounded hallucination.
  GV-AI-003 — Information Integrity: Retrieved document authenticity.
  GV-AI-007 — Data Poisoning: Adversarial manipulation of the knowledge base.

Usage
------

.. code-block:: python

    from enterprise_rag_patterns.regulations.nist_ai_rmf import (
        AIRMFRiskLevel,
        AIRMFRetrievalRisk,
        AIRMFAuditRecord,
        AIRMFRAGPolicy,
    )

    policy = AIRMFRAGPolicy(
        system_id="enrollment-advisor-v2",
        risk_level=AIRMFRiskLevel.HIGH,
        data_sources=["sis_database", "course_catalog", "financial_aid_db"],
    )

    risk = policy.assess_retrieval(
        query="What are John's outstanding financial obligations?",
        retrieved_docs=docs,
    )
    print(risk.to_log_entry())
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AIRMFRiskLevel(str, Enum):
    """
    NIST AI RMF risk tiers (NIST AI 100-1 §3.7).

    Based on likelihood and magnitude of harm; used to determine
    the intensity of AI risk management controls required.
    """

    MINIMAL = "minimal"
    """Low likelihood and magnitude of harm; standard monitoring."""

    LOW = "low"
    """Limited potential harm; basic controls required."""

    MEDIUM = "medium"
    """Significant potential harm; enhanced controls and documentation."""

    HIGH = "high"
    """High potential for harm to individuals or society; comprehensive controls."""

    CRITICAL = "critical"
    """Extreme harm potential; may require human-in-the-loop or discontinuation."""


class AIRMFFunction(str, Enum):
    """The four NIST AI RMF core functions."""

    GOVERN = "GOVERN"
    MAP = "MAP"
    MEASURE = "MEASURE"
    MANAGE = "MANAGE"


@dataclass(slots=True)
class AIRMFRetrievalRisk:
    """
    NIST AI RMF risk assessment result for a single RAG retrieval event.

    Captures MAP and MEASURE function findings for one query-retrieve cycle.

    Attributes:
        system_id: Identifier of the AI system being assessed.
        query_hash: SHA-256 hash of the query (for correlation without logging PII).
        risk_level: Assessed risk level for this retrieval.
        data_sources_accessed: Which knowledge base sources were queried.
        documents_retrieved: Number of documents returned.
        confabulation_risk: Estimated likelihood of hallucination (0.0–1.0).
            Calculated from query-document relevance scores if available.
        pii_exposure_risk: Estimated likelihood of PII leakage in context (0.0–1.0).
        relevant_rmf_controls: AI RMF sub-categories applicable to this event.
        timestamp_utc: ISO 8601 UTC timestamp.
        notes: Optional free-text assessment notes.
    """

    system_id: str
    query_hash: str
    risk_level: AIRMFRiskLevel
    data_sources_accessed: list[str]
    documents_retrieved: int
    confabulation_risk: float = 0.0
    pii_exposure_risk: float = 0.0
    relevant_rmf_controls: list[str] = field(default_factory=list)
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: str = ""

    def to_log_entry(self) -> str:
        """Serialize to a JSON log line for AI RMF audit storage."""
        return json.dumps(
            {
                "framework": "NIST_AI_RMF_1.0",
                "profile": "AI_600-1_GenAI",
                "event": "rag_retrieval_risk_assessment",
                "system_id": self.system_id,
                "query_hash": self.query_hash,
                "risk_level": self.risk_level,
                "data_sources_accessed": self.data_sources_accessed,
                "documents_retrieved": self.documents_retrieved,
                "confabulation_risk": round(self.confabulation_risk, 4),
                "pii_exposure_risk": round(self.pii_exposure_risk, 4),
                "relevant_rmf_controls": self.relevant_rmf_controls,
                "timestamp_utc": self.timestamp_utc,
                "notes": self.notes,
            },
            separators=(",", ":"),
        )


@dataclass
class AIRMFAuditRecord:
    """
    NIST AI RMF MANAGE function audit record for AI incident and anomaly tracking.

    Maps to MANAGE 1.3: Track and document all AI incidents, near-misses, and
    anomalies. Required for continuous monitoring and feedback into the MAP/MEASURE
    functions.

    Attributes:
        system_id: AI system identifier.
        incident_type: Category of incident (e.g. ``"retrieval_failure"``,
            ``"pii_exposure"``, ``"hallucination"``, ``"access_violation"``).
        severity: Incident severity (``"low"``, ``"medium"``, ``"high"``, ``"critical"``).
        description: Human-readable description of the incident.
        affected_users: Count of potentially affected users.
        remediation_applied: Whether automated remediation was applied.
        timestamp_utc: ISO 8601 UTC timestamp.
        rmf_function: AI RMF function most relevant to this incident.
    """

    system_id: str
    incident_type: str
    severity: str
    description: str
    affected_users: int = 0
    remediation_applied: bool = False
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    rmf_function: AIRMFFunction = AIRMFFunction.MANAGE

    def to_log_entry(self) -> str:
        """Serialize to JSON for MANAGE 1.3 incident log."""
        return json.dumps(
            {
                "framework": "NIST_AI_RMF_1.0",
                "rmf_function": self.rmf_function,
                "event": "ai_incident",
                "system_id": self.system_id,
                "incident_type": self.incident_type,
                "severity": self.severity,
                "description": self.description,
                "affected_users": self.affected_users,
                "remediation_applied": self.remediation_applied,
                "timestamp_utc": self.timestamp_utc,
            },
            separators=(",", ":"),
        )


class AIRMFRAGPolicy:
    """
    NIST AI RMF-aligned governance policy for RAG retrieval pipelines.

    Implements the MAP and MEASURE functions for a specific RAG deployment.
    Produces structured risk assessments and audit records for every retrieval
    event, supporting MANAGE function monitoring and feedback loops.

    This policy is not a compliance gate (documents are not blocked) — it is
    a risk measurement and observability layer that feeds into your AI risk
    register and incident management workflow.

    Args:
        system_id: Unique identifier for this AI system instance.
        risk_level: Baseline risk tier (determines alert thresholds).
        data_sources: List of knowledge base / data source identifiers.
        audit_sink: Optional callable receiving each ``AIRMFRetrievalRisk``.
        pii_fields: Document metadata field names that may contain PII.
            Used to calculate ``pii_exposure_risk``.
        confabulation_threshold: Minimum relevance score to consider a
            document well-grounded (default 0.7). Documents below this
            threshold increase confabulation risk estimate.
    """

    # AI RMF controls relevant to every RAG retrieval event
    _DEFAULT_CONTROLS = [
        "MAP 1.6 — Data source risk mapping",
        "MEASURE 2.5 — Bias and accuracy measurement",
        "MEASURE 2.6 — System-level risk evaluation",
        "AI-600-1 GV-AI-001 — Data privacy",
        "AI-600-1 GV-AI-002 — Confabulation",
    ]

    def __init__(
        self,
        system_id: str,
        risk_level: AIRMFRiskLevel = AIRMFRiskLevel.MEDIUM,
        data_sources: list[str] | None = None,
        audit_sink: Any | None = None,
        pii_fields: list[str] | None = None,
        confabulation_threshold: float = 0.7,
    ) -> None:
        self.system_id = system_id
        self.risk_level = risk_level
        self.data_sources = data_sources or []
        self._audit_sink = audit_sink
        self._pii_fields = pii_fields or ["student_id", "patient_id", "ssn", "email", "phone"]
        self._confab_threshold = confabulation_threshold

    def assess_retrieval(
        self,
        query: str,
        retrieved_docs: list[dict[str, Any]],
        relevance_scores: list[float] | None = None,
    ) -> AIRMFRetrievalRisk:
        """
        Produce a NIST AI RMF risk assessment for a RAG retrieval event.

        Args:
            query: The user query (hashed — never stored in plaintext).
            retrieved_docs: List of retrieved document dicts.
            relevance_scores: Optional list of float scores (0.0–1.0) from the
                vector store, one per document.  Used to estimate confabulation risk.

        Returns:
            ``AIRMFRetrievalRisk`` with risk scores and applicable controls.
        """
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]

        # Estimate PII exposure risk: fraction of docs containing PII fields
        pii_docs = sum(1 for doc in retrieved_docs if self._has_pii(doc))
        pii_risk = pii_docs / max(len(retrieved_docs), 1)

        # Estimate confabulation risk from relevance scores
        confab_risk = self._estimate_confabulation_risk(retrieved_docs, relevance_scores)

        # Elevate risk level if scores exceed thresholds
        effective_risk = self._elevate_risk(pii_risk, confab_risk)

        risk = AIRMFRetrievalRisk(
            system_id=self.system_id,
            query_hash=query_hash,
            risk_level=effective_risk,
            data_sources_accessed=list(self.data_sources),
            documents_retrieved=len(retrieved_docs),
            confabulation_risk=confab_risk,
            pii_exposure_risk=pii_risk,
            relevant_rmf_controls=list(self._DEFAULT_CONTROLS),
        )

        if self._audit_sink is not None:
            self._audit_sink(risk)

        return risk

    def record_incident(
        self,
        incident_type: str,
        severity: str,
        description: str,
        affected_users: int = 0,
        remediation_applied: bool = False,
    ) -> AIRMFAuditRecord:
        """
        Record a NIST AI RMF MANAGE 1.3 incident.

        Call this when a retrieval policy violation, PII exposure, or
        confabulation event is detected to feed the incident into the
        AI risk register.

        Returns:
            ``AIRMFAuditRecord`` suitable for AI incident management systems.
        """
        record = AIRMFAuditRecord(
            system_id=self.system_id,
            incident_type=incident_type,
            severity=severity,
            description=description,
            affected_users=affected_users,
            remediation_applied=remediation_applied,
        )
        return record

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _has_pii(self, doc: dict[str, Any]) -> bool:
        """Return True if the document contains any recognised PII fields."""
        return any(f in doc for f in self._pii_fields)

    def _estimate_confabulation_risk(
        self,
        docs: list[dict[str, Any]],
        scores: list[float] | None,
    ) -> float:
        """Estimate confabulation risk from relevance scores."""
        if not docs:
            return 0.0
        if scores is None or len(scores) != len(docs):
            # Without scores, use a heuristic: low doc count = higher risk
            return max(0.0, 1.0 - min(len(docs) / 3, 1.0)) * 0.5
        low_relevance = sum(1 for s in scores if s < self._confab_threshold)
        return low_relevance / len(scores)

    def _elevate_risk(self, pii_risk: float, confab_risk: float) -> AIRMFRiskLevel:
        """Elevate the effective risk level based on computed risk scores."""
        if pii_risk > 0.8 or confab_risk > 0.8:
            return AIRMFRiskLevel.CRITICAL
        if pii_risk > 0.5 or confab_risk > 0.5:
            if self.risk_level in (AIRMFRiskLevel.MEDIUM, AIRMFRiskLevel.LOW):
                return AIRMFRiskLevel.HIGH
        return self.risk_level
