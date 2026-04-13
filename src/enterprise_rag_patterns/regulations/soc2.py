"""
regulations/soc2.py — SOC 2 Type II context-based access control (CBAC) for RAG.

Provides RAG-pipeline compliance controls aligned with the AICPA Trust Service
Criteria (TSC) as required for SOC 2 Type II audit opinions.  SOC 2 is the
dominant security assurance standard for SaaS, cloud, and enterprise software
vendors in the United States — required by roughly 65% of Fortune 500 vendor
contracts.

**Scope**: RAG-layer access controls and audit logging.  This module addresses
the subset of TSC that applies to retrieval pipelines serving multi-tenant or
confidential data stores.

Relevant Trust Service Criteria
---------------------------------

  **CC6.1** (Logical and Physical Access Controls):
    The entity implements logical access security software, infrastructure, and
    architectures over protected information assets to protect them from security
    events.  For RAG, this maps to scoping retrieval to documents within the
    authorized tenant boundary.

  **CC6.6** (Logical Access Security Measures):
    The entity implements controls to prevent unauthorized access including
    restricting access to production environments.  For RAG, this maps to
    enforcing role-based document-level access at the retrieval layer.

  **CC7.2** (System Monitoring):
    The entity monitors system components and the operation of controls to detect
    anomalies.  For RAG, this maps to emitting structured audit records for every
    retrieval event (access grant and deny) to enable anomaly detection.

  **C1.1 / C1.2** (Confidentiality):
    The entity identifies and maintains confidential information.  For RAG, this
    maps to enforcing confidentiality tier labels so that RESTRICTED and
    CONFIDENTIAL data are only accessible to explicitly authorized roles.

  **A1.2** (Availability):
    Capacity management procedures to support system availability.  This module
    supports availability monitoring via the audit stream.

Defense-in-depth layer
------------------------
SOC 2 controls sit at **Layer 2** of the four-layer compliance model:

    Layer 0: OWASP LLM01/LLM02    — PII redaction, injection scanning
    Layer 1: Identity scoping      — namespace + tenant isolation
    Layer 2: SOC 2 CBAC filter     — role × confidentiality tier enforcement  ←
    Layer 3: NIST AI RMF audit     — risk assessment, structured audit trail

Usage
------

.. code-block:: python

    from enterprise_rag_patterns.regulations.soc2 import (
        SOC2AccessContext,
        SOC2ConfidentialityTier,
        SOC2ContextPolicy,
        SOC2AuditRecord,
    )

    # Build from your verified session / OIDC token — never from user input
    ctx = SOC2AccessContext(
        subject_id="user_abc",
        tenant_id="org_acme",
        roles=frozenset({"analyst", "viewer"}),
        max_confidentiality_tier=SOC2ConfidentialityTier.CONFIDENTIAL,
    )

    policy = SOC2ContextPolicy(access_context=ctx)
    safe_docs = policy.filter_retrieved_documents(
        retrieved_docs,
        tenant_id_field="tenant_id",
        confidentiality_field="confidentiality_tier",
        required_roles_field="required_roles",
    )

    # CC7.2: emit structured access event for SIEM
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


class SOC2ConfidentialityTier(IntEnum):
    """
    Confidentiality classification tiers aligned with SOC 2 C1.1/C1.2.

    Ordered by sensitivity: a subject authorized for a tier can access all
    documents at that tier and below.

    Attributes:
        PUBLIC: Publicly available information — no access restriction.
        INTERNAL: Internal-use-only data (non-sensitive corporate content).
        CONFIDENTIAL: Business-confidential data (PII-adjacent, contracts,
            financial projections, customer data).
        RESTRICTED: Highest sensitivity (regulatory data, PHI-adjacent,
            security configurations, key material).  Requires explicit role
            authorization in addition to tier clearance.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @classmethod
    def from_label(cls, label: str) -> SOC2ConfidentialityTier:
        """
        Parse a tier from a case-insensitive string label.

        Args:
            label: One of ``"public"``, ``"internal"``, ``"confidential"``,
                ``"restricted"`` (case-insensitive).

        Returns:
            Matching ``SOC2ConfidentialityTier``.

        Raises:
            ValueError: If *label* does not match any known tier.
        """
        try:
            return cls[label.upper()]
        except KeyError:
            known = ", ".join(m.name.lower() for m in cls)
            raise ValueError(f"Unknown confidentiality tier {label!r}. Known: {known}") from None


@dataclass(slots=True)
class SOC2AccessContext:
    """
    Defines the SOC 2 access boundary for a single RAG retrieval session.

    Mirrors the CC6.1/CC6.6 logical access control model: a subject (user or
    service) authenticates, carries a set of authorized roles, and is scoped to
    a single tenant.  The retrieval layer enforces both tenant isolation and
    role-based document access.

    Attributes:
        subject_id: Unique identifier for the authenticated user or service
            principal.  Typically sourced from a verified OIDC token.
        tenant_id: Tenant / organization identifier.  Documents with a
            different tenant ID are always blocked (CC6.1 tenant isolation).
        roles: Frozenset of role labels held by this subject (e.g.
            ``{"analyst", "data_viewer"}``).  Used to enforce role-based
            document-level access.
        max_confidentiality_tier: The highest ``SOC2ConfidentialityTier`` this
            subject is authorized for.  Documents above this tier are blocked.
        purpose: Descriptive purpose for this access session — logged in the
            CC7.2 audit record (e.g. ``"customer_support_query"``).
    """

    subject_id: str
    tenant_id: str
    roles: frozenset[str]
    max_confidentiality_tier: SOC2ConfidentialityTier = SOC2ConfidentialityTier.INTERNAL
    purpose: str = ""

    def has_role(self, role: str) -> bool:
        """Return True if *role* is held by this subject."""
        return role in self.roles

    def may_access_tier(self, tier: SOC2ConfidentialityTier) -> bool:
        """Return True if this subject is authorized for *tier* and below."""
        return int(tier) <= int(self.max_confidentiality_tier)


@dataclass
class SOC2AuditRecord:
    """
    Structured SOC 2 CC7.2 audit record for a RAG retrieval event.

    Captures access control decisions for SIEM integration and SOC 2 Type II
    audit evidence.  Each filter call emits one record regardless of outcome
    (both access grants and denials are logged).

    Attributes:
        subject_id: Authenticated subject identifier.
        tenant_id: Tenant scope for this access event.
        roles: Roles held by the subject at access time.
        max_confidentiality_tier: Highest tier authorized for this subject.
        purpose: Stated purpose of the retrieval session.
        documents_retrieved: Documents returned after CBAC filtering.
        documents_blocked: Documents blocked by CBAC controls.
        block_reasons: Counts per block reason (``"tenant_mismatch"``,
            ``"tier_exceeded"``, ``"role_required"``).
        tsc_controls_applied: TSC control identifiers applied (e.g.
            ``["CC6.1", "CC6.6", "C1.1"]``).
        timestamp_utc: ISO 8601 UTC timestamp of the access event.
        session_id: Correlation ID for the session or request.
    """

    subject_id: str
    tenant_id: str
    roles: list[str]
    max_confidentiality_tier: str
    purpose: str
    documents_retrieved: int
    documents_blocked: int
    block_reasons: dict[str, int] = field(default_factory=dict)
    tsc_controls_applied: list[str] = field(default_factory=list)
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""

    def to_log_entry(self) -> str:
        """Serialize to a structured JSON log line for SIEM / SOC 2 audit storage."""
        return json.dumps(
            {
                "framework": "SOC2_TypeII",
                "tsc_controls": sorted(self.tsc_controls_applied),
                "event": "rag_retrieval",
                "subject_id": self.subject_id,
                "tenant_id": self.tenant_id,
                "roles": sorted(self.roles),
                "max_confidentiality_tier": self.max_confidentiality_tier,
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
        SHA-256 hash of the audit record contents for tamper-evidence.

        Store the hash in a separate immutable store to detect log tampering —
        satisfies SOC 2 CC7.2 anomaly-detection and integrity requirements.
        """
        return hashlib.sha256(self.to_log_entry().encode()).hexdigest()


class SOC2ContextPolicy:
    """
    SOC 2 Type II context-based access control (CBAC) policy for RAG pipelines.

    Applies three independent controls to each retrieved document:

    1. **CC6.1 Tenant isolation** — Block any document whose tenant ID does not
       match the authorized tenant in the access context.  This is the primary
       multi-tenancy guard; a bypass of this layer exposes cross-tenant data.

    2. **C1.1/C1.2 Confidentiality tier** — Block documents whose
       ``confidentiality_tier`` label exceeds the subject's authorized maximum.
       Uses ``SOC2ConfidentialityTier`` ordering (PUBLIC < INTERNAL <
       CONFIDENTIAL < RESTRICTED).

    3. **CC6.6 Role-based access** — If a document carries a
       ``required_roles`` field (a list or comma-separated string of role
       labels), block the document unless the subject holds at least one of
       those roles.

    All three controls are applied independently (defense-in-depth).  A
    document must pass all three to be included in the result.

    Args:
        access_context: ``SOC2AccessContext`` defining subject, tenant, roles,
            and maximum confidentiality tier.
        audit_sink: Optional callable receiving each ``SOC2AuditRecord``.
            Wire to your SIEM, append-only log, or security data lake.
        session_id: Correlation ID included in audit records.
        tsc_controls: Override the default list of TSC control IDs logged in
            audit records.  Default: ``["CC6.1", "CC6.6", "C1.1", "CC7.2"]``.
    """

    _DEFAULT_TSC_CONTROLS = ["CC6.1", "CC6.6", "C1.1", "CC7.2"]

    def __init__(
        self,
        access_context: SOC2AccessContext,
        audit_sink: Any | None = None,
        session_id: str = "",
        tsc_controls: list[str] | None = None,
    ) -> None:
        self._ctx = access_context
        self._audit_sink = audit_sink
        self._session_id = session_id
        self._tsc_controls = tsc_controls or list(self._DEFAULT_TSC_CONTROLS)
        self._last_audit: SOC2AuditRecord | None = None

    @property
    def last_audit_record(self) -> SOC2AuditRecord | None:
        """The ``SOC2AuditRecord`` produced by the most recent filter call."""
        return self._last_audit

    def filter_retrieved_documents(
        self,
        documents: list[dict[str, Any]],
        tenant_id_field: str = "tenant_id",
        confidentiality_field: str = "confidentiality_tier",
        required_roles_field: str = "required_roles",
    ) -> list[dict[str, Any]]:
        """
        Apply SOC 2 CBAC to retrieved documents.

        Three controls are applied in order; failing any single check blocks
        the document:

        - **CC6.1**: ``doc[tenant_id_field]`` must equal ``access_context.tenant_id``
          (or be absent — documents without a tenant field pass this check).
        - **C1.1**: ``doc[confidentiality_field]`` must be ≤
          ``access_context.max_confidentiality_tier``.  Unknown or unrecognised
          tier labels are always blocked regardless of the subject's tier (fail-safe:
          access to data of indeterminate classification is never granted).
        - **CC6.6**: ``doc[required_roles_field]``, if present, must have at
          least one role that the subject holds.

        An audit record is emitted for every call via the ``audit_sink``.

        Args:
            documents: List of document dicts (keys are metadata fields).
            tenant_id_field: Key used to look up the document tenant ID.
            confidentiality_field: Key used to look up the confidentiality tier.
            required_roles_field: Key used to look up required role labels.

        Returns:
            Documents that passed all three controls.
        """
        result: list[dict[str, Any]] = []
        block_reasons: dict[str, int] = {}

        for doc in documents:
            block = self._check_document(
                doc,
                tenant_id_field=tenant_id_field,
                confidentiality_field=confidentiality_field,
                required_roles_field=required_roles_field,
            )
            if block is None:
                result.append(doc)
            else:
                block_reasons[block] = block_reasons.get(block, 0) + 1

        blocked_total = sum(block_reasons.values())
        record = SOC2AuditRecord(
            subject_id=self._ctx.subject_id,
            tenant_id=self._ctx.tenant_id,
            roles=sorted(self._ctx.roles),
            max_confidentiality_tier=self._ctx.max_confidentiality_tier.name.lower(),
            purpose=self._ctx.purpose,
            documents_retrieved=len(result),
            documents_blocked=blocked_total,
            block_reasons=block_reasons,
            tsc_controls_applied=self._tsc_controls,
            session_id=self._session_id,
        )
        self._last_audit = record
        if self._audit_sink is not None:
            self._audit_sink(record)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_document(
        self,
        doc: dict[str, Any],
        tenant_id_field: str,
        confidentiality_field: str,
        required_roles_field: str,
    ) -> str | None:
        """
        Evaluate a single document against all three controls.

        Returns:
            ``None`` if the document passes, or a string reason code if blocked.
        """
        # CC6.1: tenant isolation
        doc_tenant = doc.get(tenant_id_field)
        if doc_tenant is not None and doc_tenant != self._ctx.tenant_id:
            return "tenant_mismatch"

        # C1.1: confidentiality tier
        tier_label = doc.get(confidentiality_field)
        if tier_label is not None:
            try:
                doc_tier = SOC2ConfidentialityTier.from_label(str(tier_label))
            except ValueError:
                # Unknown label → always block regardless of user tier (fail-safe:
                # never grant access to data of indeterminate classification).
                return "tier_exceeded"
            if not self._ctx.may_access_tier(doc_tier):
                return "tier_exceeded"

        # CC6.6: role-based access
        required_roles_raw = doc.get(required_roles_field)
        if required_roles_raw is not None:
            required_roles = self._parse_roles(required_roles_raw)
            if required_roles and not any(self._ctx.has_role(r) for r in required_roles):
                return "role_required"

        return None

    @staticmethod
    def _parse_roles(roles_raw: Any) -> list[str]:
        """Normalise roles field to a list of strings."""
        if isinstance(roles_raw, str):
            return [r.strip() for r in roles_raw.split(",") if r.strip()]
        if isinstance(roles_raw, (list, tuple, frozenset, set)):
            return [str(r) for r in roles_raw]
        return []
