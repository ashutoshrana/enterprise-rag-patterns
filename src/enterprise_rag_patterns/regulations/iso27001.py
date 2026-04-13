"""
regulations/iso27001.py — ISO/IEC 27001:2022 ISMS access control for RAG.

Provides RAG-pipeline compliance controls aligned with ISO/IEC 27001:2022
(Information Security Management System — ISMS) Annex A controls.  ISO 27001
is the dominant international information security standard, covering 100+
countries and required by a majority of enterprise vendor procurement
processes globally.

**Scope**: RAG-layer access controls and audit logging.  This module addresses
the subset of Annex A controls that apply to retrieval pipelines serving
multi-tenant or classified information assets.

Relevant Annex A Controls
--------------------------

  **A.5.12** (Classification of Information):
    Information shall be classified according to legal requirements, sensitivity,
    and business criticality.  For RAG, this maps to labelling every retrievable
    document with an ISMS classification tier and enforcing those labels at
    retrieval time.

  **A.5.15** (Access Control):
    Processes controlling physical and logical access to information and other
    associated assets shall be established.  For RAG, this maps to enforcing
    per-organization tenant isolation so that subjects can only retrieve
    documents belonging to their authorized organization.

  **A.5.16** (Identity Management):
    The full lifecycle of identities shall be managed.  For RAG, this maps
    to requiring a verified ``subject_id`` for every retrieval event and
    logging it in the audit record.

  **A.5.34** (Privacy and Protection of PII):
    PII shall be protected in accordance with applicable legal requirements.
    For RAG, this maps to blocking SECRET-classified documents (which commonly
    contain PII) from subjects not authorized for that level.

  **A.8.2** (Privileged Access Rights):
    The allocation and use of privileged access rights shall be restricted
    and managed.  For RAG, this maps to requiring explicit elevated roles
    for documents at CONFIDENTIAL or SECRET classification.

  **A.8.12** (Data Leakage Prevention):
    Data leakage prevention measures shall be applied to systems processing
    sensitive information.  For RAG, this maps to blocking documents above
    the subject's maximum classification from entering the LLM context window.

  **A.8.15** (Logging):
    Logs that record activities, exceptions, faults, and other relevant events
    shall be produced, stored, protected, and analysed.  For RAG, this maps
    to emitting a structured ``ISMSAuditRecord`` for every retrieval event.

  **A.8.16** (Monitoring Activities):
    Networks, systems, and applications shall be monitored for anomalous
    behaviour.  For RAG, the audit stream feeds anomaly detection pipelines.

Defense-in-depth layer
------------------------
ISO 27001 controls sit at **Layer 2** of the four-layer compliance model:

    Layer 0: OWASP LLM01/LLM02    — PII redaction, injection scanning
    Layer 1: Identity scoping      — namespace + tenant isolation
    Layer 2: ISO 27001 ISMS CBAC   — classification × role enforcement  ←
    Layer 3: NIST AI RMF audit     — risk assessment, structured audit trail

Usage
------

.. code-block:: python

    from enterprise_rag_patterns.regulations.iso27001 import (
        ISMSAccessContext,
        ISMSClassification,
        ISMSContextPolicy,
        ISMSAuditRecord,
    )

    ctx = ISMSAccessContext(
        subject_id="user_abc",
        organization_id="org_acme",
        roles=frozenset({"analyst", "data_viewer"}),
        max_classification=ISMSClassification.CONFIDENTIAL,
        purpose="customer_support_query",
    )

    policy = ISMSContextPolicy(access_context=ctx, audit_sink=my_siem.emit)
    safe_docs = policy.filter_retrieved_documents(
        retrieved_docs,
        organization_id_field="organization_id",
        classification_field="classification",
        required_roles_field="required_roles",
    )

    audit = policy.last_audit_record
    if audit:
        print(audit.to_log_entry())
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class ISMSClassification(IntEnum):
    """
    ISO/IEC 27001:2022 information classification levels (Annex A.5.12).

    Ordered by sensitivity: a subject authorized for a level can access all
    documents at that level and below.

    Attributes:
        PUBLIC: Publicly available information — no access restriction.
        INTERNAL: Internal-use-only information (non-sensitive corporate content).
        CONFIDENTIAL: Business-confidential information (PII-adjacent, contracts,
            financial projections, customer data).
        SECRET: Highest sensitivity (security configurations, key material, critical
            personal data, regulatory data).  Requires explicitly elevated role
            authorization in addition to classification clearance.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3

    @classmethod
    def from_label(cls, label: str) -> ISMSClassification:
        """
        Parse a classification level from a case-insensitive string label.

        Args:
            label: One of ``"public"``, ``"internal"``, ``"confidential"``,
                ``"secret"`` (case-insensitive).

        Returns:
            Matching ``ISMSClassification``.

        Raises:
            ValueError: If *label* does not match any known classification level.
        """
        try:
            return cls[label.upper()]
        except KeyError:
            known = ", ".join(m.name.lower() for m in cls)
            raise ValueError(f"Unknown ISMS classification {label!r}. Known: {known}") from None


@dataclass(slots=True)
class ISMSAccessContext:
    """
    Defines the ISO 27001 ISMS access boundary for a single RAG retrieval session.

    Mirrors the A.5.15/A.5.16 access control model: a subject authenticates with
    a verified identity, carries a set of authorized roles, and is scoped to a
    single organization.  The retrieval layer enforces both organizational tenant
    isolation (A.5.15) and role-based document-level access (A.8.2).

    Attributes:
        subject_id: Unique identifier for the authenticated user or service
            principal (A.5.16 identity management).  Sourced from a verified
            OIDC token — never from user-supplied input.
        organization_id: Organization / tenant identifier.  Documents with a
            different organization ID are always blocked (A.5.15 access control).
        roles: Frozenset of role labels held by this subject.  Used to enforce
            role-based document-level access (A.8.2 privileged access rights).
        max_classification: The highest ``ISMSClassification`` this subject is
            authorized for.  Documents above this level are blocked (A.8.12 DLP).
        purpose: Descriptive purpose for this access session — logged in the
            A.8.15 audit record.
    """

    subject_id: str
    organization_id: str
    roles: frozenset[str]
    max_classification: ISMSClassification = ISMSClassification.INTERNAL
    purpose: str = ""

    def has_role(self, role: str) -> bool:
        """Return True if *role* is held by this subject."""
        return role in self.roles

    def may_access_classification(self, classification: ISMSClassification) -> bool:
        """Return True if this subject is authorized for *classification* and below."""
        return int(classification) <= int(self.max_classification)


@dataclass
class ISMSAuditRecord:
    """
    Structured ISO 27001 A.8.15 audit record for a RAG retrieval event.

    Attributes:
        subject_id: Authenticated subject identifier (A.5.16).
        organization_id: Organization scope for this access event (A.5.15).
        roles: Roles held by the subject at access time (A.8.2).
        max_classification: Highest classification authorized for this subject.
        purpose: Stated purpose of the retrieval session.
        documents_retrieved: Documents returned after ISMS filtering.
        documents_blocked: Documents blocked by ISMS controls.
        block_reasons: Counts per block reason (``"organization_mismatch"``,
            ``"classification_exceeded"``, ``"role_required"``).
        annex_a_controls: Annex A control identifiers applied.
        timestamp_utc: ISO 8601 UTC timestamp of the access event.
        session_id: Correlation ID for the session or request.
    """

    subject_id: str
    organization_id: str
    roles: list[str]
    max_classification: str
    purpose: str
    documents_retrieved: int
    documents_blocked: int
    block_reasons: dict[str, int] = field(default_factory=dict)
    annex_a_controls: list[str] = field(default_factory=list)
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""

    def to_log_entry(self) -> str:
        """Serialize to a structured JSON log line for SIEM / ISO 27001 audit storage."""
        return json.dumps(
            {
                "framework": "ISO_IEC_27001_2022",
                "annex_a_controls": sorted(self.annex_a_controls),
                "event": "rag_retrieval",
                "subject_id": self.subject_id,
                "organization_id": self.organization_id,
                "roles": sorted(self.roles),
                "max_classification": self.max_classification,
                "purpose": self.purpose,
                "documents_retrieved": self.documents_retrieved,
                "documents_blocked": self.documents_blocked,
                "block_reasons": self.block_reasons,
                "timestamp_utc": self.timestamp_utc,
                "session_id": self.session_id,
            },
            separators=(",", ":"),
        )

    def content_hash(self) -> str:
        """
        SHA-256 hash of the audit record for tamper-evidence (A.8.15 log protection).
        """
        return hashlib.sha256(self.to_log_entry().encode()).hexdigest()


class ISMSContextPolicy:
    """
    ISO/IEC 27001:2022 ISMS context-based access control (CBAC) policy for RAG.

    Three independent controls applied per document (defense-in-depth):

    1. **A.5.15 Organization isolation** — Block documents from other organizations.
    2. **A.5.12 / A.8.12 Classification** — Block documents above the subject's
       authorized maximum.  Unknown labels always blocked (fail-safe).
    3. **A.8.2 Role-based access** — Block documents whose ``required_roles``
       field lists no role held by the subject.

    Args:
        access_context: ``ISMSAccessContext`` defining subject, organization, roles,
            and maximum classification level.
        audit_sink: Optional callable receiving each ``ISMSAuditRecord``.
        session_id: Correlation ID included in audit records.
        annex_a_controls: Override the default Annex A control IDs in audit records.
            Default: ``["A.5.12", "A.5.15", "A.8.2", "A.8.15", "A.8.16"]``.
    """

    _DEFAULT_ANNEX_A_CONTROLS = ["A.5.12", "A.5.15", "A.8.2", "A.8.15", "A.8.16"]

    def __init__(
        self,
        access_context: ISMSAccessContext,
        audit_sink: Any | None = None,
        session_id: str = "",
        annex_a_controls: list[str] | None = None,
    ) -> None:
        self._ctx = access_context
        self._audit_sink = audit_sink
        self._session_id = session_id
        self._annex_a_controls = annex_a_controls or list(self._DEFAULT_ANNEX_A_CONTROLS)
        self._last_audit: ISMSAuditRecord | None = None

    @property
    def last_audit_record(self) -> ISMSAuditRecord | None:
        """The ``ISMSAuditRecord`` produced by the most recent filter call."""
        return self._last_audit

    def filter_retrieved_documents(
        self,
        documents: list[dict[str, Any]],
        organization_id_field: str = "organization_id",
        classification_field: str = "classification",
        required_roles_field: str = "required_roles",
    ) -> list[dict[str, Any]]:
        """
        Apply ISO 27001 ISMS CBAC to retrieved documents.

        Args:
            documents: List of document dicts (keys are metadata fields).
            organization_id_field: Key for the document organization ID.
            classification_field: Key for the classification label.
            required_roles_field: Key for required role labels.

        Returns:
            Documents that passed all three controls.
        """
        result: list[dict[str, Any]] = []
        block_reasons: dict[str, int] = {}

        for doc in documents:
            block = self._check_document(
                doc,
                organization_id_field=organization_id_field,
                classification_field=classification_field,
                required_roles_field=required_roles_field,
            )
            if block is None:
                result.append(doc)
            else:
                block_reasons[block] = block_reasons.get(block, 0) + 1

        blocked_total = sum(block_reasons.values())
        record = ISMSAuditRecord(
            subject_id=self._ctx.subject_id,
            organization_id=self._ctx.organization_id,
            roles=sorted(self._ctx.roles),
            max_classification=self._ctx.max_classification.name.lower(),
            purpose=self._ctx.purpose,
            documents_retrieved=len(result),
            documents_blocked=blocked_total,
            block_reasons=block_reasons,
            annex_a_controls=self._annex_a_controls,
            session_id=self._session_id,
        )
        self._last_audit = record
        if self._audit_sink is not None:
            self._audit_sink(record)

        return result

    def _check_document(
        self,
        doc: dict[str, Any],
        organization_id_field: str,
        classification_field: str,
        required_roles_field: str,
    ) -> str | None:
        # A.5.15: organization isolation
        doc_org = doc.get(organization_id_field)
        if doc_org is not None and doc_org != self._ctx.organization_id:
            return "organization_mismatch"

        # A.5.12 / A.8.12: classification enforcement
        classification_label = doc.get(classification_field)
        if classification_label is not None:
            try:
                doc_classification = ISMSClassification.from_label(str(classification_label))
            except ValueError:
                return "classification_exceeded"  # unknown label → fail-safe block
            if not self._ctx.may_access_classification(doc_classification):
                return "classification_exceeded"

        # A.8.2: role-based access
        required_roles_raw = doc.get(required_roles_field)
        if required_roles_raw is not None:
            required_roles = self._parse_roles(required_roles_raw)
            if required_roles and not any(self._ctx.has_role(r) for r in required_roles):
                return "role_required"

        return None

    @staticmethod
    def _parse_roles(roles_raw: Any) -> list[str]:
        if isinstance(roles_raw, str):
            return [r.strip() for r in roles_raw.split(",") if r.strip()]
        if isinstance(roles_raw, (list, tuple, frozenset, set)):
            return [str(r) for r in roles_raw]
        return []
