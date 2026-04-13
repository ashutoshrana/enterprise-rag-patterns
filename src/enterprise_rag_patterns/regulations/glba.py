"""
regulations/glba.py — GLBA Safeguards Rule (16 CFR § 314) NPI access control for RAG.

Provides RAG-pipeline compliance controls aligned with the Gramm-Leach-Bliley Act
(15 U.S.C. § 6801) and its implementing Safeguards Rule (16 CFR Part 314), as
updated by the FTC's 2023 amendments.  GLBA applies to financial institutions —
banks, credit unions, insurance companies, securities firms, and any entity that
is "significantly engaged" in providing financial products or services to consumers.

**Scope**: RAG-layer access controls and audit logging.  This module addresses the
subset of Safeguards Rule controls that apply to retrieval pipelines serving
systems containing Nonpublic Personal Information (NPI) — for example, customer
service assistants, fraud detection tooling, and internal financial operations
chatbots.

Relevant Safeguards Rule Controls (16 CFR § 314)
-------------------------------------------------

  **§ 314.3** (Standards for Safeguarding Customer Information):
    Every covered financial institution must develop, implement, and maintain a
    comprehensive information security program.  For RAG, this maps to enforcing
    institution-level isolation so that NPI belonging to one institution cannot
    enter the context window of a retrieval session scoped to another institution.

  **§ 314.4(e)** (Implement Access Controls):
    Limit access to customer information to authorized users — permitting access
    only to those with a business need to know.  For RAG, this maps to purpose
    limitation: actors must declare and be authorized for the specific purpose
    (e.g. ``"customer_service"``, ``"fraud_detection"``) before NPI documents are
    returned.

  **§ 314.4(f)** (Encrypt Customer Information):
    Encrypt customer information in transit and at rest.  Encryption enforcement
    is handled at the infrastructure layer; this module contributes by ensuring NPI
    documents are never transmitted to unauthorized actors at the RAG layer.

  **§ 314.4(h)** (Monitor and Test):
    Continuously monitor and test the effectiveness of safeguards.  For RAG, this
    maps to emitting a structured ``GLBAAuditRecord`` for every retrieval event
    regardless of outcome — feeding monitoring and anomaly-detection pipelines.

  **§ 314.4(i)** (Oversee Service Providers):
    Oversee service providers with whom NPI is shared.  For RAG, this maps to
    role-based restrictions that prevent marketing-role actors from accessing
    transaction history or credit information outside their authorized purposes.

Defense-in-depth layer
------------------------
GLBA controls sit at **Layer 2** of the four-layer compliance model:

    Layer 0: OWASP LLM01/LLM02    — PII redaction, injection scanning
    Layer 1: Identity scoping      — namespace + institution isolation
    Layer 2: GLBA NPI filter       — institution × purpose × role enforcement  ←
    Layer 3: NIST AI RMF audit     — risk assessment, structured audit trail

Usage
------

.. code-block:: python

    from enterprise_rag_patterns.regulations.glba import (
        GLBAAccessContext,
        GLBAAccessScope,
        GLBAContextPolicy,
        GLBAAuditRecord,
        GLBADataCategory,
    )

    ctx = GLBAAccessContext(
        actor_id="agent_cs_001",
        actor_role="customer_service_rep",
        institution_id="bank_acme",
        purpose="customer_service",
        authorized_purposes=frozenset({"customer_service", "account_management"}),
    )

    policy = GLBAContextPolicy(access_context=ctx, audit_sink=my_audit_log.emit)
    safe_docs = policy.filter_retrieved_documents(retrieved_docs)

    audit = policy.last_audit_record
    if audit:
        print(audit.to_log_entry())
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class GLBADataCategory(str, Enum):
    """
    GLBA data categories for classifying documents by NPI sensitivity.

    Only ``NONPUBLIC_PERSONAL`` requires strict Safeguards Rule controls.
    All other categories are permitted by default subject to institution and
    purpose checks.

    Attributes:
        NONPUBLIC_PERSONAL: Nonpublic Personal Information (NPI) as defined by
            15 U.S.C. § 6809(4) — any information not publicly available that a
            financial institution collects or receives in connection with providing
            a financial product or service.  Requires strict purpose-limited access.
        ACCOUNT_DATA: Account numbers, balances, product details.  Sensitive but
            not NPI in all contexts; included for granular access control.
        TRANSACTION_HISTORY: Records of financial transactions — purchases, payments,
            transfers.  Restricted from marketing-role actors (§ 314.4(i)).
        CREDIT_INFORMATION: Credit scores, credit reports, loan terms.  Restricted
            from marketing-role actors (§ 314.4(i)).
        PUBLIC_INFORMATION: Publicly available information — not subject to
            Safeguards Rule controls.  Always permitted regardless of role or purpose.
    """

    NONPUBLIC_PERSONAL = "nonpublic_personal"
    ACCOUNT_DATA = "account_data"
    TRANSACTION_HISTORY = "transaction_history"
    CREDIT_INFORMATION = "credit_information"
    PUBLIC_INFORMATION = "public_information"


# Categories restricted from marketing actors (§ 314.4(i) service-provider oversight
# and § 314.4(e) need-to-know access controls)
_MARKETING_RESTRICTED_CATEGORIES: frozenset[GLBADataCategory] = frozenset(
    {GLBADataCategory.CREDIT_INFORMATION, GLBADataCategory.TRANSACTION_HISTORY}
)

# The sole NPI category requiring strict purpose + institution controls (§ 314.3)
_STRICT_NPI_CATEGORIES: frozenset[GLBADataCategory] = frozenset(
    {
        GLBADataCategory.NONPUBLIC_PERSONAL,
        GLBADataCategory.ACCOUNT_DATA,
        GLBADataCategory.TRANSACTION_HISTORY,
        GLBADataCategory.CREDIT_INFORMATION,
    }
)


@dataclass(slots=True)
class GLBAAccessContext:
    """
    Defines the GLBA Safeguards Rule access boundary for a single RAG retrieval session.

    Maps to 16 CFR § 314.4(e): every retrieval session must carry a verified
    actor identity, an authorized institution scope, a declared purpose, and an
    explicit set of purposes the actor is permitted to exercise.

    Attributes:
        actor_id: Unique identifier for the authenticated user or service principal.
            Required by § 314.4(h) for individual NPI access logging.
        actor_role: Role label for the actor (e.g. ``"customer_service_rep"``,
            ``"fraud_analyst"``, ``"marketing_analyst"``).  Used to enforce
            role-based restrictions on credit and transaction data (§ 314.4(i)).
        institution_id: Financial institution identifier.  Documents belonging
            to a different institution are always blocked (§ 314.3 isolation).
        purpose: The specific business purpose for this retrieval session
            (e.g. ``"customer_service"``, ``"fraud_detection"``, ``"marketing"``).
            Must be present in ``authorized_purposes`` to access NPI.
        authorized_purposes: Set of purposes this actor is authorized to exercise.
            NPI documents are blocked if ``purpose`` is not in this set (§ 314.4(e)).
    """

    actor_id: str
    actor_role: str
    institution_id: str
    purpose: str
    authorized_purposes: set[str]

    def has_authorized_purpose(self) -> bool:
        """Return True if the declared purpose is in the actor's authorized purposes."""
        return self.purpose in self.authorized_purposes

    def is_marketing_role(self) -> bool:
        """
        Return True if this actor's role is classified as a marketing role.

        Marketing roles are restricted from accessing credit information and
        transaction history per § 314.4(i) (oversee service providers).
        """
        return "marketing" in self.actor_role.lower()


@dataclass(slots=True)
class GLBAAccessScope:
    """
    Defines the GLBA access scope for a retrieval session — a lightweight
    alternative to ``GLBAAccessContext`` for systems that pre-validate purpose
    authorization externally and need only a scope-check helper.

    Attributes:
        institution_id: Financial institution identifier.
        actor_id: Unique identifier for the authenticated actor.
        authorized_purposes: Set of purposes this actor may exercise.
    """

    institution_id: str
    actor_id: str
    authorized_purposes: set[str]

    def permits(self, document: dict[str, Any], requested_purpose: str) -> bool:
        """
        Return True if this scope permits access to *document* for *requested_purpose*.

        Access is permitted when all of the following hold:
        1. The document's ``institution_id`` field (if present) matches ``self.institution_id``.
        2. *requested_purpose* is in ``self.authorized_purposes``.
        3. The document's ``data_category`` (if present) is not ``NONPUBLIC_PERSONAL``
           unless the requested purpose is authorized.

        Args:
            document: Document dict with optional ``institution_id`` and
                ``data_category`` metadata fields.
            requested_purpose: The purpose for which access is requested.

        Returns:
            ``True`` if the scope permits access; ``False`` otherwise.
        """
        # Institution isolation
        doc_institution = document.get("institution_id")
        if doc_institution is not None and doc_institution != self.institution_id:
            return False

        # Purpose authorization
        if requested_purpose not in self.authorized_purposes:
            return False

        # NPI category requires authorized purpose
        category_raw = document.get("data_category")
        if category_raw is not None:
            try:
                category = GLBADataCategory(str(category_raw))
            except ValueError:
                category = GLBADataCategory.PUBLIC_INFORMATION
            if category in _STRICT_NPI_CATEGORIES and requested_purpose not in self.authorized_purposes:
                return False

        return True


@dataclass
class GLBAAuditRecord:
    """
    Structured GLBA Safeguards Rule § 314.4(h) audit record for a RAG retrieval event.

    Attributes:
        actor_id: Authenticated actor identifier (§ 314.4(e) access control).
        actor_role: Role held by the actor at access time (§ 314.4(i)).
        institution_id: Institution scope for this access event (§ 314.3).
        purpose: Declared purpose for the retrieval session (§ 314.4(e)).
        authorized_purposes: Purposes authorized for this actor.
        documents_retrieved: Documents returned after GLBA filtering.
        documents_blocked: Documents blocked by GLBA controls.
        block_reasons: Counts per block reason (``"institution_mismatch"``,
            ``"purpose_not_authorized"``, ``"marketing_role_restricted"``).
        safeguards_controls: Safeguards Rule § references applied.
        timestamp_utc: ISO 8601 UTC timestamp of the access event.
        session_id: Correlation ID for the session or request.
    """

    actor_id: str
    actor_role: str
    institution_id: str
    purpose: str
    authorized_purposes: list[str]
    documents_retrieved: int
    documents_blocked: int
    block_reasons: dict[str, int] = field(default_factory=dict)
    safeguards_controls: list[str] = field(default_factory=list)
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""

    def to_log_entry(self) -> str:
        """Serialize to a structured JSON log line for GLBA / FTC audit storage."""
        return json.dumps(
            {
                "framework": "GLBA_16CFR314",
                "safeguards_controls": sorted(self.safeguards_controls),
                "event": "rag_retrieval",
                "actor_id": self.actor_id,
                "actor_role": self.actor_role,
                "institution_id": self.institution_id,
                "purpose": self.purpose,
                "authorized_purposes": sorted(self.authorized_purposes),
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
        SHA-256 hash of the audit record for tamper-evidence (§ 314.4(h) monitoring).

        Store the hash in a separate immutable store alongside the log entry
        to detect unauthorized modification of audit logs.
        """
        return hashlib.sha256(self.to_log_entry().encode()).hexdigest()


class GLBAContextPolicy:
    """
    GLBA Safeguards Rule (16 CFR § 314) NPI access control policy for RAG pipelines.

    Three independent controls applied per document (defense-in-depth):

    1. **§ 314.3 Institution isolation** — Block documents from other institutions.
    2. **§ 314.4(e) Purpose limitation** — Block NPI documents if the actor's
       declared purpose is not in their authorized purposes.
    3. **§ 314.4(i) Role-based restriction** — Block credit information and
       transaction history from marketing-role actors regardless of purpose.

    A ``GLBAAuditRecord`` is emitted per § 314.4(h) for every call to
    ``filter_retrieved_documents``, regardless of whether any documents were blocked.

    Args:
        access_context: ``GLBAAccessContext`` defining actor, institution, purpose,
            and authorized purposes.
        audit_sink: Optional callable receiving each ``GLBAAuditRecord``.
        session_id: Correlation ID included in audit records.
        safeguards_controls: Override the default § references in audit records.
            Default: ``["§314.3", "§314.4(e)", "§314.4(h)", "§314.4(i)"]``.
    """

    _DEFAULT_SAFEGUARDS_CONTROLS = ["§314.3", "§314.4(e)", "§314.4(h)", "§314.4(i)"]

    def __init__(
        self,
        access_context: GLBAAccessContext,
        audit_sink: Any | None = None,
        session_id: str = "",
        safeguards_controls: list[str] | None = None,
    ) -> None:
        self._ctx = access_context
        self._audit_sink = audit_sink
        self._session_id = session_id
        self._safeguards_controls = safeguards_controls or list(self._DEFAULT_SAFEGUARDS_CONTROLS)
        self._last_audit: GLBAAuditRecord | None = None

    @property
    def last_audit_record(self) -> GLBAAuditRecord | None:
        """The ``GLBAAuditRecord`` produced by the most recent filter call."""
        return self._last_audit

    def filter_retrieved_documents(
        self,
        documents: list[dict[str, Any]],
        institution_id_field: str = "institution_id",
        data_category_field: str = "data_category",
    ) -> list[dict[str, Any]]:
        """
        Apply GLBA Safeguards Rule controls to retrieved documents.

        Processing order per document:
        1. § 314.3 — institution isolation check.
        2. § 314.4(e) — purpose limitation check for NPI categories.
        3. § 314.4(i) — marketing role restriction for credit and transaction data.

        A ``GLBAAuditRecord`` is emitted via ``audit_sink`` for every call
        (§ 314.4(h)), even when no documents are blocked.

        Args:
            documents: List of document dicts (keys are metadata fields).
            institution_id_field: Key for the document institution ID.
            data_category_field: Key for the data category label.

        Returns:
            Documents that passed all three controls.
        """
        result: list[dict[str, Any]] = []
        block_reasons: dict[str, int] = {}

        for doc in documents:
            block = self._check_document(doc, institution_id_field, data_category_field)
            if block is None:
                result.append(doc)
            else:
                block_reasons[block] = block_reasons.get(block, 0) + 1

        blocked_total = sum(block_reasons.values())
        record = GLBAAuditRecord(
            actor_id=self._ctx.actor_id,
            actor_role=self._ctx.actor_role,
            institution_id=self._ctx.institution_id,
            purpose=self._ctx.purpose,
            authorized_purposes=sorted(self._ctx.authorized_purposes),
            documents_retrieved=len(result),
            documents_blocked=blocked_total,
            block_reasons=block_reasons,
            safeguards_controls=self._safeguards_controls,
            session_id=self._session_id,
        )
        self._last_audit = record
        if self._audit_sink is not None:
            self._audit_sink(record)

        return result

    def _check_document(
        self,
        doc: dict[str, Any],
        institution_id_field: str,
        data_category_field: str,
    ) -> str | None:
        # § 314.3: institution isolation
        doc_institution = doc.get(institution_id_field)
        if doc_institution is not None and doc_institution != self._ctx.institution_id:
            return "institution_mismatch"

        # Resolve data category
        category_raw = doc.get(data_category_field)
        if category_raw is None:
            return None  # no category label → outside GLBA scope, permit

        try:
            category = GLBADataCategory(str(category_raw))
        except ValueError:
            # Unknown category → treat as PUBLIC_INFORMATION (permissive)
            return None

        # PUBLIC_INFORMATION is always permitted
        if category == GLBADataCategory.PUBLIC_INFORMATION:
            return None

        # § 314.4(e): purpose limitation for all NPI categories
        if category in _STRICT_NPI_CATEGORIES and not self._ctx.has_authorized_purpose():
            return "purpose_not_authorized"

        # § 314.4(i): marketing role restriction for credit and transaction data
        if category in _MARKETING_RESTRICTED_CATEGORIES and self._ctx.is_marketing_role():
            return "marketing_role_restricted"

        return None
