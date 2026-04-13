"""
regulations/pci_dss.py — PCI DSS v4.0 access control and PAN masking for RAG.

Provides RAG-pipeline compliance controls aligned with PCI DSS v4.0 (Payment
Card Industry Data Security Standard).  PCI DSS is the mandatory security
standard for any organization that stores, processes, or transmits cardholder
data — enforced by the major card brands across all payment-adjacent vendors.

**Scope**: RAG-layer access controls, PAN masking, and audit logging.  This
module addresses the subset of PCI DSS v4.0 requirements that apply when RAG
pipelines retrieve context from systems containing cardholder data (CHD) or
sensitive authentication data (SAD) — for example, payment dispute systems,
fraud detection assistants, and financial operations tooling.

Relevant PCI DSS v4.0 Requirements
------------------------------------

  **Req 3.3 / 3.4** (Protect Stored Account Data):
    Primary Account Numbers (PAN) must be rendered unreadable anywhere they are
    stored, and masked when displayed so that only authorized personnel with a
    legitimate business need can see the full PAN.  For RAG, this maps to masking
    PAN patterns in document content before they enter the LLM context window.

  **Req 7.2** (Implement Access Control System):
    An access control system is in place that restricts access based on need to
    know and is set to deny-all unless specifically allowed.  For RAG, this maps
    to enforcing merchant-level tenant isolation.

  **Req 7.2.1** (Define Access Needs for Each Role):
    Only approved users with a documented business need may access cardholder
    data.  For RAG, this maps to blocking documents whose ``data_category`` field
    is ``CARDHOLDER_DATA`` or ``SENSITIVE_AUTH_DATA`` unless explicitly authorized.

  **Req 10.2.1** (Audit Log Events — Individual Access to CHD):
    Audit log events for all individual user access to cardholder data shall be
    captured.  For RAG, this maps to emitting a ``PCIAuditRecord`` for every call
    to ``filter_retrieved_documents``, regardless of outcome.

  **Req 10.3** (Protect Audit Logs):
    Audit logs shall be protected from destruction and unauthorized modifications.
    Satisfied by ``PCIAuditRecord.content_hash()`` — SHA-256 tamper-evidence hash
    for storage in a separate immutable store alongside the log entry.

Defense-in-depth layer
------------------------
PCI DSS controls sit at **Layer 2** of the four-layer compliance model:

    Layer 0: OWASP LLM01/LLM02    — PII redaction, injection scanning
    Layer 1: Identity scoping      — namespace + merchant isolation
    Layer 2: PCI DSS filter        — CHD category × PAN masking enforcement  ←
    Layer 3: NIST AI RMF audit     — risk assessment, structured audit trail

Usage
------

.. code-block:: python

    from enterprise_rag_patterns.regulations.pci_dss import (
        PCIAccessScope,
        PCIDataCategory,
        PCIContextPolicy,
        PCIAuditRecord,
    )

    scope = PCIAccessScope(
        merchant_id="merchant_acme",
        user_id="agent_fraud_007",
        roles=frozenset({"fraud_analyst"}),
        authorized_data_categories=frozenset({
            PCIDataCategory.CARDHOLDER_DATA,
            PCIDataCategory.TRANSACTION_DATA,
        }),
        business_justification="fraud_dispute_resolution",
    )

    policy = PCIContextPolicy(access_scope=scope, audit_sink=my_qsa_log.emit)
    safe_docs = policy.filter_retrieved_documents(retrieved_docs)

    print(f"PAN patterns masked: {policy.last_pan_masked_count}")
    print(policy.last_audit_record.to_log_entry())
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class PCIDataCategory(str, Enum):
    """
    PCI DSS v4.0 data categories for cardholder data environment (CDE) documents.

    Attributes:
        CARDHOLDER_DATA: PAN, cardholder name, expiry date, service code.
            Requires explicit authorization in ``authorized_data_categories``.
        SENSITIVE_AUTH_DATA: Full track data, CVV2/CVC2, PINs.  Must never be
            stored after authorization per Req 3.2; included to block retrieval
            when not authorized.
        TRANSACTION_DATA: Transaction records, authorization codes, amounts,
            timestamps.  Adjacent to CHD but not itself account data.
        NON_CHD: Documents not containing cardholder data — always permitted
            regardless of ``authorized_data_categories``.
    """

    CARDHOLDER_DATA = "cardholder_data"
    SENSITIVE_AUTH_DATA = "sensitive_auth_data"
    TRANSACTION_DATA = "transaction_data"
    NON_CHD = "non_chd"


# Req 3.4: PAN masking — matches 13–19 digit card numbers with optional spaces
# or hyphens between groups of 4 digits.  Word boundaries prevent false positives
# on longer numeric sequences (timestamps, IBANs, etc.).
_PAN_PATTERN: re.Pattern[str] = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")
_PAN_REPLACEMENT = "[PAN-MASKED]"

# Categories requiring explicit authorization (Req 7.2.1 need-to-know)
_RESTRICTED_CATEGORIES: frozenset[PCIDataCategory] = frozenset(
    {PCIDataCategory.CARDHOLDER_DATA, PCIDataCategory.SENSITIVE_AUTH_DATA}
)


@dataclass(slots=True)
class PCIAccessScope:
    """
    Defines the PCI DSS access boundary for a single RAG retrieval session.

    Maps to Req 7.2 / 7.2.1: each retrieval session must carry a verified
    identity, an authorized merchant scope, documented business justification,
    and an explicit set of data categories the subject is permitted to access.

    Attributes:
        merchant_id: Merchant or acquirer identifier.  Documents belonging to
            a different merchant are always blocked (Req 7.2 tenant isolation).
        user_id: Unique identifier for the authenticated user or service
            principal.  Required by Req 10.2.1 for individual CHD access logging.
        roles: Frozenset of role labels held by this subject.
        authorized_data_categories: Frozenset of ``PCIDataCategory`` values
            this subject may access.  ``CARDHOLDER_DATA`` and
            ``SENSITIVE_AUTH_DATA`` are blocked unless present here (Req 7.2.1).
        business_justification: Documented reason for this access session —
            required by Req 7.2.1 and recorded in every ``PCIAuditRecord``.
    """

    merchant_id: str
    user_id: str
    roles: frozenset[str]
    authorized_data_categories: frozenset[PCIDataCategory]
    business_justification: str

    def may_access_category(self, category: PCIDataCategory) -> bool:
        """
        Return True if this subject may access documents of *category*.

        Non-CHD documents are always permitted.  CARDHOLDER_DATA and
        SENSITIVE_AUTH_DATA require explicit presence in
        ``authorized_data_categories`` (Req 7.2.1 need-to-know).
        """
        if category == PCIDataCategory.NON_CHD:
            return True
        return category in self.authorized_data_categories


@dataclass
class PCIAuditRecord:
    """
    Structured PCI DSS Req 10.2.1 audit record for a RAG retrieval event.

    Attributes:
        merchant_id: Merchant scope for this access event (Req 7.2).
        user_id: Authenticated user or service principal (Req 10.2.1).
        roles: Roles held by the subject at access time.
        business_justification: Documented need-to-know justification (Req 7.2.1).
        documents_retrieved: Count of documents returned after PCI filtering.
        documents_blocked: Count of documents blocked by PCI controls.
        pan_masked_count: Number of PAN patterns masked across all retrieved
            documents (Req 3.4 — aggregate across the result set).
        pci_requirements_applied: Requirement identifiers applied.
        timestamp_utc: ISO 8601 UTC timestamp of the access event.
        session_id: Correlation ID for the session or request.
    """

    merchant_id: str
    user_id: str
    roles: list[str]
    business_justification: str
    documents_retrieved: int
    documents_blocked: int
    pan_masked_count: int
    pci_requirements_applied: list[str] = field(default_factory=list)
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""

    def to_log_entry(self) -> str:
        """Serialize to a structured JSON log line for PCI DSS / QSA audit storage."""
        return json.dumps(
            {
                "framework": "PCI_DSS_v4",
                "pci_requirements": sorted(self.pci_requirements_applied),
                "event": "rag_retrieval",
                "merchant_id": self.merchant_id,
                "user_id": self.user_id,
                "roles": sorted(self.roles),
                "business_justification": self.business_justification,
                "documents_retrieved": self.documents_retrieved,
                "documents_blocked": self.documents_blocked,
                "pan_masked_count": self.pan_masked_count,
                "timestamp_utc": self.timestamp_utc,
                "session_id": self.session_id,
            },
            separators=(",", ":"),
        )

    def content_hash(self) -> str:
        """
        SHA-256 hash of the audit record for tamper-evidence (Req 10.3).

        Store the hash in a separate immutable store alongside the log entry
        to detect unauthorized modification of audit logs.
        """
        return hashlib.sha256(self.to_log_entry().encode()).hexdigest()


class PCIContextPolicy:
    """
    PCI DSS v4.0 access control and PAN masking policy for RAG pipelines.

    Three controls applied per document plus PAN masking on passing documents:

    1. **Req 7.2 Merchant isolation** — Block documents from other merchants.
    2. **Req 7.2.1 Category need-to-know** — Block ``CARDHOLDER_DATA`` /
       ``SENSITIVE_AUTH_DATA`` documents unless explicitly authorized.  Unknown
       or absent category fields are treated as ``NON_CHD`` (permissive default
       — documents without a CDE label are outside PCI scope).
    3. **Req 3.4 PAN masking** — After filtering, replace PAN patterns
       (``\\b(?:\\d{4}[- ]?){3}\\d{4}\\b``) with ``[PAN-MASKED]`` in all
       string-valued fields of passing documents.

    A ``PCIAuditRecord`` is emitted per Req 10.2.1 for every call regardless
    of whether any documents were blocked or masked.

    Args:
        access_scope: ``PCIAccessScope`` defining merchant, user, authorized
            categories, and business justification.
        audit_sink: Optional callable receiving each ``PCIAuditRecord``.
        session_id: Correlation ID included in audit records.
        pci_requirements: Override the default PCI DSS requirement IDs in
            audit records.  Default: ``["Req 3.4", "Req 7.2", "Req 7.2.1", "Req 10.2.1"]``.
    """

    _DEFAULT_PCI_REQUIREMENTS = ["Req 3.4", "Req 7.2", "Req 7.2.1", "Req 10.2.1"]

    def __init__(
        self,
        access_scope: PCIAccessScope,
        audit_sink: Any | None = None,
        session_id: str = "",
        pci_requirements: list[str] | None = None,
    ) -> None:
        self._scope = access_scope
        self._audit_sink = audit_sink
        self._session_id = session_id
        self._pci_requirements = pci_requirements or list(self._DEFAULT_PCI_REQUIREMENTS)
        self._last_audit: PCIAuditRecord | None = None
        self._last_pan_masked_count: int = 0

    @property
    def last_audit_record(self) -> PCIAuditRecord | None:
        """The ``PCIAuditRecord`` produced by the most recent filter call."""
        return self._last_audit

    @property
    def last_pan_masked_count(self) -> int:
        """Total PAN patterns replaced during the most recent filter call (Req 3.4)."""
        return self._last_pan_masked_count

    def filter_retrieved_documents(
        self,
        documents: list[dict[str, Any]],
        merchant_id_field: str = "merchant_id",
        data_category_field: str = "data_category",
    ) -> list[dict[str, Any]]:
        """
        Apply PCI DSS v4.0 controls to retrieved documents.

        Processing order per document:
        1. Req 7.2 — merchant isolation check.
        2. Req 7.2.1 — data category need-to-know check.
        3. Req 3.4 — PAN masking on all string-valued fields of passing documents.

        A ``PCIAuditRecord`` is emitted via ``audit_sink`` for every call
        (Req 10.2.1), even when no documents are blocked or masked.

        Args:
            documents: List of document dicts.
            merchant_id_field: Key for the document merchant ID.
            data_category_field: Key for the data category label.

        Returns:
            Documents that passed merchant and category checks, with PAN
            patterns masked in all string-valued fields (Req 3.4).
        """
        result: list[dict[str, Any]] = []
        blocked_count = 0
        total_pan_masked = 0

        for doc in documents:
            block = self._check_document(doc, merchant_id_field, data_category_field)
            if block is not None:
                blocked_count += 1
                continue

            masked_doc, pan_count = self._mask_pan_in_document(doc)
            total_pan_masked += pan_count
            result.append(masked_doc)

        self._last_pan_masked_count = total_pan_masked

        record = PCIAuditRecord(
            merchant_id=self._scope.merchant_id,
            user_id=self._scope.user_id,
            roles=sorted(self._scope.roles),
            business_justification=self._scope.business_justification,
            documents_retrieved=len(result),
            documents_blocked=blocked_count,
            pan_masked_count=total_pan_masked,
            pci_requirements_applied=self._pci_requirements,
            session_id=self._session_id,
        )
        self._last_audit = record
        if self._audit_sink is not None:
            self._audit_sink(record)

        return result

    def _check_document(
        self,
        doc: dict[str, Any],
        merchant_id_field: str,
        data_category_field: str,
    ) -> str | None:
        # Req 7.2: merchant isolation
        doc_merchant = doc.get(merchant_id_field)
        if doc_merchant is not None and doc_merchant != self._scope.merchant_id:
            return "merchant_mismatch"

        # Req 7.2.1: data category need-to-know
        category_raw = doc.get(data_category_field)
        if category_raw is not None:
            try:
                category = PCIDataCategory(str(category_raw))
            except ValueError:
                category = PCIDataCategory.NON_CHD  # unknown → treat as non-CHD
            if not self._scope.may_access_category(category):
                return "category_not_authorized"

        return None

    @staticmethod
    def _mask_pan_in_document(doc: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """
        Replace PAN patterns in all top-level string-valued fields of *doc*.

        Returns a shallow copy with PAN patterns replaced and the substitution count.
        Callers needing deep masking of nested dicts/lists should pre-flatten their
        documents before passing to the policy.
        """
        masked: dict[str, Any] = {}
        total_count = 0
        for key, value in doc.items():
            if isinstance(value, str):
                new_value, n = _PAN_PATTERN.subn(_PAN_REPLACEMENT, value)
                masked[key] = new_value
                total_count += n
            else:
                masked[key] = value
        return masked, total_count
