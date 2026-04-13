"""
regulations/hipaa.py — HIPAA RAG-layer compliance patterns.

Provides the RAG-pipeline-layer primitives for HIPAA (Health Insurance
Portability and Accountability Act, 45 CFR Parts 160 and 164) compliance:
access control, audit logging, and minimum-necessary enforcement for
ePHI (electronic Protected Health Information) in retrieval pipelines.

**Scope**: RAG-layer patterns only.  This module is not a general-purpose
HIPAA compliance engine.  It addresses retrieval from systems containing ePHI
(EHR systems, clinical note stores, lab result databases) where RAG pipelines
must enforce access rules equivalent to the Privacy and Security Rules.

Relevant regulations
---------------------
- HIPAA Privacy Rule (45 CFR § 164.502(b)): Minimum necessary standard —
  only the minimum ePHI necessary to accomplish the intended purpose may be
  disclosed. Applies to every retrieval event.
- HIPAA Security Rule (45 CFR § 164.312(b)): Audit controls — hardware,
  software, and procedural mechanisms to record and examine activity in
  information systems containing ePHI.
- HIPAA Security Rule (45 CFR § 164.312(a)(1)): Access control — unique user
  identification, emergency access procedure, automatic logoff, encryption.
- HIPAA Breach Notification Rule (45 CFR § 164.400–414): Breaches involving
  RAG exposure of ePHI to unauthorized agents require notification within 60 days.

Minimum-necessary principle in RAG
-------------------------------------
The minimum-necessary standard (§ 164.502(b)) maps to RAG as follows:

  1. Query-time scoping: the retrieval query SHOULD carry the minimum data needed
     (e.g. patient ID, not full demographics) to retrieve relevant context.
  2. Result filtering: retrieved documents must be filtered to the minimum ePHI
     necessary for the task (treatment vs. payment vs. healthcare operations).
  3. Purpose classification: the RAG pipeline must classify the purpose of the
     request (treatment, payment, operations, research, etc.) and apply
     purpose-specific access rules.

Usage
------

.. code-block:: python

    from enterprise_rag_patterns.regulations.hipaa import (
        HIPAAAccessScope,
        HIPAAPurpose,
        HIPAAContextPolicy,
        HIPAAAuditRecord,
    )

    scope = HIPAAAccessScope(
        patient_id="PAT-0042",
        covered_entity_id="ACO-NORTHWEST",
        permitted_purposes={HIPAAPurpose.TREATMENT},
        role="attending_physician",
    )

    policy = HIPAAContextPolicy(scope=scope)
    filtered_docs = policy.filter_retrieved_documents(
        retrieved_docs,
        patient_id_field="patient_id",
        purpose_field="data_purpose",
    )
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class HIPAAPurpose(str, Enum):
    """
    HIPAA permissible purposes for ePHI disclosure (45 CFR § 164.502(a)).

    These correspond to the treatment-payment-operations (TPO) framework
    and additional permitted purposes.
    """

    TREATMENT = "treatment"
    """Direct patient care by healthcare providers."""

    PAYMENT = "payment"
    """Activities for payment or reimbursement of health care."""

    HEALTHCARE_OPERATIONS = "healthcare_operations"
    """Quality assessment, training, auditing, compliance activities."""

    RESEARCH = "research"
    """IRB-approved research with proper data use agreement."""

    PUBLIC_HEALTH = "public_health"
    """Public health activities (disease surveillance, adverse event reporting)."""

    EMERGENCY = "emergency"
    """Emergency access override — must be documented and reviewed post-access."""


@dataclass(slots=True)
class HIPAAAccessScope:
    """
    Defines the HIPAA access boundary for a single RAG retrieval session.

    Maps to the HIPAA minimum-necessary standard (45 CFR § 164.502(b)):
    a retrieval pipeline may only return ePHI that is the minimum necessary
    for the stated purpose.

    Attributes:
        patient_id: The patient's identifier (MRN, EHR ID, or de-identified
            surrogate). Used to scope vector queries.
        covered_entity_id: Identifier of the covered entity or business
            associate performing the retrieval.
        permitted_purposes: Set of HIPAA purposes authorized for this session.
            Most clinical queries should use {HIPAAPurpose.TREATMENT}.
        role: HIPAA role of the requester (e.g. ``"attending_physician"``,
            ``"care_coordinator"``, ``"billing_staff"``).
        authorized_phi_categories: Optional set of PHI category labels that
            may be retrieved. If empty, all PHI categories are permitted for
            the stated purpose.
    """

    patient_id: str
    covered_entity_id: str
    permitted_purposes: frozenset[HIPAAPurpose]
    role: str
    authorized_phi_categories: frozenset[str] = field(default_factory=frozenset)

    def permits_purpose(self, purpose: str) -> bool:
        """Return True if *purpose* is in the permitted purposes for this scope."""
        try:
            return HIPAAPurpose(purpose) in self.permitted_purposes
        except ValueError:
            return False


@dataclass
class HIPAAAuditRecord:
    """
    Structured 45 CFR § 164.312(b) audit record for a RAG retrieval event.

    HIPAA requires audit logs for every access to ePHI.  This record captures
    the minimum fields needed to satisfy both the Security Rule audit control
    requirement and to support breach investigation.

    Attributes:
        patient_id: Patient whose ePHI was accessed.
        covered_entity_id: Entity performing the access.
        role: HIPAA role of the requester.
        purpose: The stated HIPAA purpose for this access.
        documents_retrieved: Count of documents returned after filtering.
        documents_blocked: Count of documents blocked by minimum-necessary filter.
        phi_categories_accessed: Categories of PHI actually returned.
        timestamp_utc: ISO 8601 UTC timestamp of the access event.
        session_id: Correlation ID for the session or request.
        regulation_citation: HIPAA regulation citation for this record.
    """

    patient_id: str
    covered_entity_id: str
    role: str
    purpose: str
    documents_retrieved: int
    documents_blocked: int
    phi_categories_accessed: list[str]
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""
    regulation_citation: str = "HIPAA 45 CFR § 164.312(b)"

    def to_log_entry(self) -> str:
        """Serialize to a structured JSON log line for HIPAA audit storage."""
        return json.dumps(
            {
                "regulation": self.regulation_citation,
                "event": "rag_retrieval",
                "patient_id": self.patient_id,
                "covered_entity_id": self.covered_entity_id,
                "role": self.role,
                "purpose": self.purpose,
                "documents_retrieved": self.documents_retrieved,
                "documents_blocked": self.documents_blocked,
                "phi_categories_accessed": sorted(self.phi_categories_accessed),
                "timestamp_utc": self.timestamp_utc,
                "session_id": self.session_id,
            },
            separators=(",", ":"),
        )

    def content_hash(self) -> str:
        """
        SHA-256 hash of the audit record contents.

        Enables tamper-evidence: store the hash alongside the record in a
        separate immutable store (e.g. append-only log, hash chain) so that
        modification of the log entry can be detected.
        """
        return hashlib.sha256(self.to_log_entry().encode()).hexdigest()


class HIPAAContextPolicy:
    """
    HIPAA minimum-necessary enforcement policy for RAG retrieved documents.

    Applies the HIPAA minimum-necessary standard (45 CFR § 164.502(b)) to a
    list of retrieved documents.  Documents are retained only if:

    1. The ``patient_id`` field matches the authorized patient in the scope.
    2. The ``purpose`` field (if present) is an authorized HIPAA purpose.
    3. The PHI category (if present) is in the authorized categories list.

    Both access control decisions and audit records are emitted per the
    Security Rule audit control requirement (45 CFR § 164.312(b)).

    Args:
        scope: ``HIPAAAccessScope`` defining the authorized access boundary.
        audit_sink: Optional callable receiving each ``HIPAAAuditRecord``.
        session_id: Session or request correlation ID for audit records.
    """

    def __init__(
        self,
        scope: HIPAAAccessScope,
        audit_sink: Any | None = None,
        session_id: str = "",
    ) -> None:
        self._scope = scope
        self._audit_sink = audit_sink
        self._session_id = session_id

    def filter_retrieved_documents(
        self,
        documents: list[dict[str, Any]],
        patient_id_field: str = "patient_id",
        purpose_field: str = "data_purpose",
        phi_category_field: str = "phi_category",
    ) -> list[dict[str, Any]]:
        """
        Filter retrieved ePHI documents to the minimum necessary.

        Args:
            documents: List of document dicts with metadata fields.
            patient_id_field: Metadata key for patient identifier.
            purpose_field: Metadata key for the data use purpose.
            phi_category_field: Metadata key for PHI category label.

        Returns:
            Filtered list — only documents authorized for this scope.
        """
        filtered: list[dict[str, Any]] = []
        categories_seen: set[str] = set()

        for doc in documents:
            doc_patient = doc.get(patient_id_field)
            doc_purpose = doc.get(purpose_field)
            doc_category = doc.get(phi_category_field, "")

            # Layer 1: patient identity must match
            if doc_patient is not None and doc_patient != self._scope.patient_id:
                continue

            # Layer 2: purpose must be authorized (if present)
            if doc_purpose is not None and not self._scope.permits_purpose(str(doc_purpose)):
                continue

            # Layer 3: PHI category must be authorized (if non-empty allowed list)
            if self._scope.authorized_phi_categories and doc_category:
                if doc_category not in self._scope.authorized_phi_categories:
                    continue

            filtered.append(doc)
            if doc_category:
                categories_seen.add(doc_category)

        blocked = len(documents) - len(filtered)
        self._emit_audit(
            documents_retrieved=len(filtered),
            documents_blocked=blocked,
            phi_categories=list(categories_seen),
        )
        return filtered

    def _emit_audit(
        self,
        documents_retrieved: int,
        documents_blocked: int,
        phi_categories: list[str],
    ) -> None:
        if self._audit_sink is None:
            return
        purpose = next(iter(self._scope.permitted_purposes), HIPAAPurpose.TREATMENT)
        record = HIPAAAuditRecord(
            patient_id=self._scope.patient_id,
            covered_entity_id=self._scope.covered_entity_id,
            role=self._scope.role,
            purpose=purpose.value,
            documents_retrieved=documents_retrieved,
            documents_blocked=documents_blocked,
            phi_categories_accessed=phi_categories,
            session_id=self._session_id,
        )
        self._audit_sink(record)
