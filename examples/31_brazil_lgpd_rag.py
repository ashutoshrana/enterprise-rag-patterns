"""
Brazil LGPD RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating under Brazil's Lei Geral de Proteção de Dados Pessoais
(LGPD, Law 13.709/2018).  Four independent filter layers run sequentially;
a document must pass all four to be returned to the caller.

Commercial use cases:

  +--------------------------------------------------+------------------------------------------+
  | Platform / Product                               | Applicable Regulation(s)                 |
  +--------------------------------------------------+------------------------------------------+
  | Brazilian e-commerce customer portals            | LGPD Art. 7 (legal basis), Art. 18 (DSR)|
  | Healthcare record retrieval systems              | LGPD Art. 11 (sensitive data)            |
  | HR and employee data platforms                   | LGPD Art. 6(III) (minimization)          |
  | Financial services analytics pipelines          | LGPD Art. 6(I) (purpose limitation)      |
  | Cross-border data sharing platforms              | LGPD Art. 33 (international transfers)   |
  | Government and public-sector data platforms      | LGPD Art. 15 (retention), Art. 18(VI)    |
  | Marketing automation systems                     | LGPD Art. 7(I) (consent)                 |
  | Customer service AI assistants                   | LGPD Art. 18 (data subject rights)       |
  +--------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — LGPDDataSubjectFilter (LGPD Art. 7, Art. 11, Art. 18)
      Controls access to personal data documents based on the requesting
      user's legal basis and relationship to the data subject.

      LGPD Art. 7 enumerates ten legal bases for processing personal data.
      Any processing activity—including retrieval—must be grounded in one
      of those bases: consent, legitimate interest, legal obligation,
      contract execution, vital interests, public task, or official
      authority.

      LGPD Art. 11 imposes heightened requirements for sensitive personal
      data (health, biometric, racial or ethnic origin, religious belief,
      trade union membership, sexual orientation, political opinion).
      Processing sensitive data requires either explicit consent from the
      data subject or grounding in a legal obligation.

      LGPD Art. 18 grants data subjects a comprehensive set of rights over
      their own personal data, including the right to access, correct, port,
      delete, and revoke consent.  A data subject always has the right to
      access their own personal data regardless of the processing legal
      basis used by the controller.

  Layer 2 — LGPDMinimizationFilter (LGPD Art. 6(I), Art. 6(III))
      Enforces the data minimization and purpose limitation principles that
      are foundational to the LGPD.

      LGPD Art. 6(I) (Purpose): Personal data must be processed for
      legitimate, specific, explicit, and informed purposes.  Processing
      for purposes incompatible with the original collection purpose is
      prohibited, unless the data subject provides new consent or another
      legal basis applies.

      LGPD Art. 6(III) (Necessity / Minimization): Processing must be
      limited to the minimum data necessary to achieve the stated purpose.
      Retrieval of documents containing data categories beyond those
      strictly necessary for the stated purpose is not permitted.

  Layer 3 — LGPDDataRetentionFilter (LGPD Art. 15, Art. 18(VI))
      Blocks access to data that has exceeded its lawful retention period or
      for which the data subject has exercised their right to erasure.

      LGPD Art. 15 specifies that personal data must be deleted after the
      processing purpose has been fulfilled, after the data subject revokes
      consent, or upon determination by the national authority.  Retention
      beyond those endpoints is unlawful.

      LGPD Art. 18(VI) grants data subjects the right to request deletion
      of unnecessary or excessive personal data or data processed in
      violation of the LGPD.  Once a deletion request is lodged, further
      access to the data should be restricted pending review, unless a legal
      override applies (e.g., ongoing litigation or regulatory investigation).

  Layer 4 — LGPDCrossBorderFilter (LGPD Art. 33)
      Controls cross-border data transfers at the retrieval layer.

      LGPD Art. 33 permits international transfer of personal data only to
      countries that provide an adequate level of data protection as
      determined by the Brazilian National Data Protection Authority (ANPD),
      or when an appropriate safeguard mechanism is in place, such as
      Standard Contractual Clauses (SCCs) or Binding Corporate Rules (BCRs).

      Countries currently recognised as providing adequate protection for
      LGPD purposes include Brazil itself (BR) and jurisdictions that have
      broadly equivalent frameworks: EU member states (EU), the United
      Kingdom (UK), and Switzerland (CH).  Requests from other jurisdictions
      require an LGPD-compliant transfer mechanism before personal data may
      be retrieved.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BrazilRole(Enum):
    DATA_SUBJECT = "DATA_SUBJECT"
    DATA_CONTROLLER = "DATA_CONTROLLER"
    DATA_PROCESSOR = "DATA_PROCESSOR"
    AUDITOR = "AUDITOR"
    REGULATOR = "REGULATOR"
    RESEARCHER = "RESEARCHER"


class Decision(Enum):
    PERMITTED = "PERMITTED"
    DENIED = "DENIED"
    REDACTED = "REDACTED"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BrazilRAGContext:
    """
    Carries all per-request attributes needed by the four LGPD filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    lgpd_legal_basis must be one of:
        "consent", "legitimate_interest", "legal_obligation", "contract",
        "vital_interests", "public_task", "official_authority", "none"

    authorized_data_categories is the set of data categories the requester
    is permitted to access for the stated processing_purpose.

    processing_purpose describes why the requester needs the data, e.g.:
        "customer_service", "fraud_detection", "marketing", "analytics",
        "legal_obligation", "research"

    requester_jurisdiction is an ISO 3166-1 alpha-2 country code, e.g.
        "BR" (Brazil), "DE" (Germany), "US" (United States).
    """

    user_id: str
    requester_role: BrazilRole
    requester_jurisdiction: str          # ISO 3166-1 alpha-2
    lgpd_legal_basis: str
    has_explicit_consent: bool
    requester_is_data_subject: bool
    authorized_data_categories: frozenset
    processing_purpose: str
    is_legal_hold: bool
    is_legal_override: bool
    has_lgpd_transfer_mechanism: bool    # SCC or binding corporate rules
    is_dpo: bool                         # Data Protection Officer


@dataclass(frozen=True)
class BrazilRAGDocument:
    """
    Immutable document descriptor carrying all attributes needed for LGPD
    compliance evaluation across the four filter layers.

    classification should be one of:
        "PERSONAL_DATA", "SENSITIVE_DATA", "PUBLIC", "ANONYMIZED"

    data_categories_present is the set of data categories in the document,
    e.g. frozenset({"financial", "health", "contact"}).

    compatible_purposes is the set of purposes the data was collected for.
    An empty frozenset means the data may be used for any purpose.

    data_subject_id identifies whose personal data the document contains;
    leave as an empty string if the document does not belong to a specific
    data subject.
    """

    document_id: str
    contains_personal_data: bool
    contains_sensitive_data: bool        # health, biometric, racial, religious, sexual, political
    data_categories_present: frozenset
    compatible_purposes: frozenset       # empty = any purpose
    retention_expired: bool
    data_subject_requested_deletion: bool
    classification: str
    data_subject_id: str


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: Decision
    reason: str
    regulation_citation: str

    @property
    def is_denied(self) -> bool:
        """True only when the decision is DENIED; REDACTED does not stop the pipeline."""
        return self.decision == Decision.DENIED


# ---------------------------------------------------------------------------
# Layer 1: LGPDDataSubjectFilter — Art. 7, Art. 11, Art. 18
# ---------------------------------------------------------------------------

class LGPDDataSubjectFilter:
    """
    Enforces LGPD legal-basis and data-subject-rights requirements.

    LGPD Art. 18 — Data subject always has the right to access their own
    personal data.  If the requester is the data subject, access is
    unconditionally permitted by this layer.

    LGPD Art. 7 — Processing of personal data (including retrieval) requires
    one of the enumerated legal bases.  Attempting to retrieve personal data
    without a valid legal basis results in a DENIED decision.

    LGPD Art. 11 — Sensitive personal data (health, biometric, racial or
    ethnic origin, religious belief, trade union membership, sexual
    orientation, political opinion) requires either explicit consent from
    the data subject or grounding in a legal obligation.  A valid Art. 7
    legal basis is insufficient on its own for sensitive data.
    """

    LAYER_NAME = "LGPD_DATA_SUBJECT_ART_7_11_18"

    _VALID_LEGAL_BASES = frozenset({
        "consent",
        "legitimate_interest",
        "legal_obligation",
        "contract",
        "vital_interests",
        "public_task",
        "official_authority",
    })

    def evaluate(
        self, context: BrazilRAGContext, document: BrazilRAGDocument
    ) -> FilterResult:
        """
        Evaluate LGPD data-subject rights and legal-basis requirements for
        access to the document.

        Evaluation order:
          1. Data subject self-access (Art. 18) — always permitted.
          2. No valid legal basis (Art. 7) — denied.
          3. Sensitive data without explicit consent or legal obligation (Art. 11) — denied.
          4. Otherwise — permitted.
        """
        # Non-personal data is not subject to LGPD access controls.
        if not document.contains_personal_data:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason="Document does not contain personal data — LGPD Art. 7/11 not applicable",
                regulation_citation="LGPD Art. 3",
            )

        # Art. 18: Data subject always has the right to access their own data.
        if context.requester_is_data_subject:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason=(
                    "LGPD Art. 18 — data subject right of access: requester is the "
                    "data subject and has unconditional access to their own personal data"
                ),
                regulation_citation="LGPD Art. 18",
            )

        # Art. 7: A valid legal basis is required for all other requesters.
        if context.lgpd_legal_basis not in self._VALID_LEGAL_BASES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    f"LGPD Art. 7 — no valid legal basis for personal data access: "
                    f"'{context.lgpd_legal_basis}' is not an enumerated LGPD legal basis"
                ),
                regulation_citation="LGPD Art. 7 — no valid legal basis for personal data access",
            )

        # Art. 11: Sensitive data requires explicit consent or legal obligation.
        if document.contains_sensitive_data:
            if not context.has_explicit_consent and context.lgpd_legal_basis != "legal_obligation":
                return FilterResult(
                    layer=self.LAYER_NAME,
                    decision=Decision.DENIED,
                    reason=(
                        "LGPD Art. 11 — explicit consent required for sensitive personal data: "
                        "document contains sensitive data (health, biometric, racial, religious, "
                        "sexual, or political) and no explicit consent or legal obligation exists"
                    ),
                    regulation_citation="LGPD Art. 11 — explicit consent required for sensitive personal data",
                )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason="LGPD Art. 7/11/18 — legal basis and data subject rights check passed",
            regulation_citation="LGPD Art. 7",
        )


# ---------------------------------------------------------------------------
# Layer 2: LGPDMinimizationFilter — Art. 6(I), Art. 6(III)
# ---------------------------------------------------------------------------

class LGPDMinimizationFilter:
    """
    Enforces LGPD data minimization (Art. 6(III)) and purpose limitation
    (Art. 6(I)) principles at the retrieval layer.

    LGPD Art. 6(III) (Necessity / Minimization): Processing must be limited
    to the minimum data necessary to achieve the stated purpose.  If a
    document contains data categories beyond those the requester is
    authorised to access, the retrieval is denied to prevent over-disclosure.

    LGPD Art. 6(I) (Purpose): Personal data must be processed for the
    specific purposes for which it was collected.  If the requester's stated
    processing purpose is not among the purposes for which the document's
    data was originally collected, access is denied unless the document
    imposes no purpose restriction (empty compatible_purposes set).
    """

    LAYER_NAME = "LGPD_MINIMIZATION_ART_6"

    def evaluate(
        self, context: BrazilRAGContext, document: BrazilRAGDocument
    ) -> FilterResult:
        """
        Evaluate data minimization and purpose limitation requirements.

        Evaluation order:
          1. Data category check (Art. 6(III)) — deny if unauthorized categories present.
          2. Purpose compatibility check (Art. 6(I)) — deny if purpose incompatible.
          3. Otherwise — permitted.
        """
        # Art. 6(III): Check whether document contains any unauthorized data category.
        unauthorized = document.data_categories_present - context.authorized_data_categories
        if unauthorized:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    f"LGPD Art. 6(III) — data minimization: document contains categories "
                    f"outside authorized scope: {sorted(unauthorized)}"
                ),
                regulation_citation=(
                    "LGPD Art. 6(III) — data minimization: document contains categories "
                    "outside authorized scope"
                ),
            )

        # Art. 6(I): Check purpose compatibility if the document declares compatible purposes.
        if document.compatible_purposes and (
            context.processing_purpose not in document.compatible_purposes
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    f"LGPD Art. 6(I) — purpose limitation: access purpose "
                    f"'{context.processing_purpose}' is incompatible with the "
                    f"data collection purposes {sorted(document.compatible_purposes)}"
                ),
                regulation_citation=(
                    "LGPD Art. 6(I) — purpose limitation: access purpose incompatible "
                    "with data collection purpose"
                ),
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason="LGPD Art. 6(I)/(III) — data minimization and purpose limitation check passed",
            regulation_citation="LGPD Art. 6(I) and Art. 6(III)",
        )


# ---------------------------------------------------------------------------
# Layer 3: LGPDDataRetentionFilter — Art. 15, Art. 18(VI)
# ---------------------------------------------------------------------------

class LGPDDataRetentionFilter:
    """
    Enforces LGPD data retention limits (Art. 15) and the data subject's
    right to erasure (Art. 18(VI)) at the retrieval layer.

    LGPD Art. 15: Personal data must be deleted or anonymised when the
    processing purpose has been fulfilled, the data retention period has
    expired, or the data subject revokes consent.  Retrieval of data that
    has exceeded its lawful retention period is prohibited, unless the
    retention is justified by a legal hold (e.g., ongoing litigation,
    regulatory investigation, or statutory record-keeping obligation).

    LGPD Art. 18(VI): Data subjects have the right to request deletion of
    unnecessary, excessive, or unlawfully processed personal data.  Once
    such a request is lodged, access to the document is restricted; the
    document is treated as REDACTED pending review and erasure unless a
    legal override applies (e.g., a court order or regulatory requirement
    preventing immediate deletion).
    """

    LAYER_NAME = "LGPD_DATA_RETENTION_ART_15_18"

    def evaluate(
        self, context: BrazilRAGContext, document: BrazilRAGDocument
    ) -> FilterResult:
        """
        Evaluate data retention and erasure-request requirements.

        Evaluation order:
          1. Retention expired without legal hold (Art. 15) — denied.
          2. Deletion requested without legal override (Art. 18(VI)) — redacted.
          3. Otherwise — permitted.
        """
        # Art. 15: Deny access to data whose retention period has expired,
        # unless a legal hold justifies continued retention.
        if document.retention_expired and not context.is_legal_hold:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    "LGPD Art. 15 — data retention period expired; right to erasure applies: "
                    "the document's retention period has expired and no legal hold is in place"
                ),
                regulation_citation=(
                    "LGPD Art. 15 — data retention period expired; right to erasure applies"
                ),
            )

        # Art. 18(VI): Redact documents for which the data subject has requested
        # deletion, unless a legal override (court order, regulatory requirement)
        # prevents immediate erasure.
        if document.data_subject_requested_deletion and not context.is_legal_override:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.REDACTED,
                reason=(
                    "LGPD Art. 18(VI) — data subject requested deletion; document redacted "
                    "pending erasure: the data subject has exercised their right to erasure "
                    "and no legal override is in place"
                ),
                regulation_citation=(
                    "LGPD Art. 18(VI) — data subject requested deletion; document redacted "
                    "pending erasure"
                ),
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason="LGPD Art. 15/18(VI) — retention and erasure request check passed",
            regulation_citation="LGPD Art. 15 and Art. 18(VI)",
        )


# ---------------------------------------------------------------------------
# Layer 4: LGPDCrossBorderFilter — Art. 33
# ---------------------------------------------------------------------------

class LGPDCrossBorderFilter:
    """
    Enforces LGPD cross-border data transfer requirements (Art. 33) at the
    retrieval layer.

    LGPD Art. 33 permits international transfer of personal data only when:
      (a) the destination country provides an adequate level of protection as
          recognised by the ANPD; or
      (b) an appropriate safeguard mechanism is in place, such as Standard
          Contractual Clauses (SCCs), Binding Corporate Rules (BCRs), or
          specific contractual clauses approved by the ANPD.

    Jurisdictions currently treated as providing adequate protection for the
    purpose of this pipeline:
      "BR" — Brazil (domestic, no transfer)
      "EU" — EU member states (GDPR, broadly equivalent)
      "UK" — United Kingdom (UK GDPR, post-Brexit adequacy)
      "CH" — Switzerland (Federal Act on Data Protection)

    Requests from all other jurisdictions require an LGPD-compliant transfer
    mechanism before personal data may be retrieved.  Non-personal data
    (PUBLIC, ANONYMIZED) is not subject to Art. 33 transfer controls.
    """

    LAYER_NAME = "LGPD_CROSS_BORDER_ART_33"

    _ADEQUATE_JURISDICTIONS = frozenset({"BR", "EU", "UK", "CH"})

    def evaluate(
        self, context: BrazilRAGContext, document: BrazilRAGDocument
    ) -> FilterResult:
        """
        Evaluate LGPD cross-border transfer requirements.

        Evaluation order:
          1. Non-personal data — always permitted (Art. 33 not applicable).
          2. Adequate jurisdiction (BR/EU/UK/CH) — permitted.
          3. Non-adequate jurisdiction with transfer mechanism — permitted.
          4. Non-adequate jurisdiction without mechanism — denied.
        """
        # Art. 33 applies only to personal data.
        if not document.contains_personal_data:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason="Document does not contain personal data — LGPD Art. 33 not applicable",
                regulation_citation="LGPD Art. 33",
            )

        # Requests from jurisdictions with adequate protection are permitted.
        if context.requester_jurisdiction in self._ADEQUATE_JURISDICTIONS:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason=(
                    f"LGPD Art. 33 — adequate protection: jurisdiction "
                    f"'{context.requester_jurisdiction}' provides adequate data protection"
                ),
                regulation_citation="LGPD Art. 33",
            )

        # Non-adequate jurisdiction: a transfer mechanism (SCC/BCR) is required.
        if not context.has_lgpd_transfer_mechanism:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    f"LGPD Art. 33 — cross-border transfer to non-adequate jurisdiction "
                    f"'{context.requester_jurisdiction}' requires SCCs or binding rules: "
                    "no LGPD-compliant transfer mechanism is in place"
                ),
                regulation_citation=(
                    "LGPD Art. 33 — cross-border transfer to non-adequate jurisdiction "
                    "requires SCCs or binding rules"
                ),
            )

        # Non-adequate jurisdiction with an approved transfer mechanism.
        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason=(
                f"LGPD Art. 33 — transfer mechanism in place: cross-border transfer to "
                f"'{context.requester_jurisdiction}' permitted via SCCs or binding corporate rules"
            ),
            regulation_citation="LGPD Art. 33",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class BrazilRAGAuditRecord:
    """
    Captures the full decision trail for a Brazil LGPD RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - LGPD Art. 37: Controllers and processors must maintain records of
        personal data processing operations.
      - LGPD Art. 38: The ANPD may request the impact report and processing
        records at any time; audit records support this obligation.
      - LGPD Art. 48: Breach and access-event notification obligations.

    All fields are populated at retrieval time; the timestamp uses the
    system clock and should be treated as UTC for regulatory record-keeping.
    """

    context: BrazilRAGContext
    documents_evaluated: int
    documents_permitted: int
    documents_denied: int
    documents_redacted: int
    filter_results: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "BRAZIL_LGPD_RAG_RETRIEVAL",
            "user_id": self.context.user_id,
            "requester_role": self.context.requester_role.value,
            "requester_jurisdiction": self.context.requester_jurisdiction,
            "lgpd_legal_basis": self.context.lgpd_legal_basis,
            "processing_purpose": self.context.processing_purpose,
            "documents_evaluated": self.documents_evaluated,
            "documents_permitted": self.documents_permitted,
            "documents_denied": self.documents_denied,
            "documents_redacted": self.documents_redacted,
            "filter_results": self.filter_results,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class BrazilLGPDRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms subject
    to Brazil's Lei Geral de Proteção de Dados Pessoais (LGPD, Law 13.709/2018).

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REDACTED results do not stop the
    pipeline — the document is included in the result set with a redaction
    marker.  Only documents that pass (or are redacted by) all four layers
    are returned to the caller.

    Layers in order:
      1. LGPDDataSubjectFilter     — Art. 7 legal basis, Art. 11 sensitive data, Art. 18 DSR
      2. LGPDMinimizationFilter    — Art. 6(I) purpose limitation, Art. 6(III) minimization
      3. LGPDDataRetentionFilter   — Art. 15 retention expiry, Art. 18(VI) erasure requests
      4. LGPDCrossBorderFilter     — Art. 33 cross-border transfer controls

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for LGPD Art. 37/38 record-keeping
    and Art. 48 breach/access notification obligations.
    """

    def __init__(self) -> None:
        self._layers = [
            LGPDDataSubjectFilter(),
            LGPDMinimizationFilter(),
            LGPDDataRetentionFilter(),
            LGPDCrossBorderFilter(),
        ]

    def retrieve(
        self,
        context: BrazilRAGContext,
        documents: List[BrazilRAGDocument],
    ) -> List[tuple]:
        """
        Return a list of (document, filter_results) tuples for all documents
        that pass or are redacted by all four filter layers.

        Documents denied on any layer are excluded from the result.  Each
        returned tuple contains the document and the list of per-layer
        FilterResult objects representing the evaluation trail.
        """
        permitted = []
        for doc in documents:
            layer_results: List[FilterResult] = []
            allow = True
            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(result)
                if result.is_denied:
                    allow = False
                    break
            if allow:
                permitted.append((doc, layer_results))
        return permitted

    def retrieve_with_audit(
        self,
        context: BrazilRAGContext,
        documents: List[BrazilRAGDocument],
    ) -> BrazilRAGAuditRecord:
        """
        Evaluate all documents and return a BrazilRAGAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support LGPD
        Art. 37/38 processing records and Art. 48 notification obligations.
        """
        documents_permitted = 0
        documents_denied = 0
        documents_redacted = 0
        all_filter_results: List[dict] = []

        for doc in documents:
            layer_results: List[dict] = []
            allow = True
            final_decision = Decision.PERMITTED

            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(
                    {
                        "layer": result.layer,
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "regulation_citation": result.regulation_citation,
                    }
                )
                if result.is_denied:
                    allow = False
                    final_decision = Decision.DENIED
                    break
                if result.decision == Decision.REDACTED:
                    final_decision = Decision.REDACTED

            if allow:
                if final_decision == Decision.REDACTED:
                    documents_redacted += 1
                else:
                    documents_permitted += 1
            else:
                documents_denied += 1

            all_filter_results.append(
                {
                    "document_id": doc.document_id,
                    "final_decision": final_decision.value,
                    "layer_results": layer_results,
                }
            )

        return BrazilRAGAuditRecord(
            context=context,
            documents_evaluated=len(documents),
            documents_permitted=documents_permitted,
            documents_denied=documents_denied,
            documents_redacted=documents_redacted,
            filter_results=all_filter_results,
        )


# ---------------------------------------------------------------------------
# Smoke test / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=" * 70)
    print("Brazil LGPD RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Shared documents
    # ------------------------------------------------------------------

    personal_doc = BrazilRAGDocument(
        document_id="doc-001-customer-contact",
        contains_personal_data=True,
        contains_sensitive_data=False,
        data_categories_present=frozenset({"contact", "financial"}),
        compatible_purposes=frozenset({"customer_service", "fraud_detection"}),
        retention_expired=False,
        data_subject_requested_deletion=False,
        classification="PERSONAL_DATA",
        data_subject_id="ds-001",
    )

    sensitive_doc = BrazilRAGDocument(
        document_id="doc-002-health-record",
        contains_personal_data=True,
        contains_sensitive_data=True,
        data_categories_present=frozenset({"health", "contact"}),
        compatible_purposes=frozenset({"healthcare", "insurance"}),
        retention_expired=False,
        data_subject_requested_deletion=False,
        classification="SENSITIVE_DATA",
        data_subject_id="ds-002",
    )

    expired_doc = BrazilRAGDocument(
        document_id="doc-003-expired-record",
        contains_personal_data=True,
        contains_sensitive_data=False,
        data_categories_present=frozenset({"contact"}),
        compatible_purposes=frozenset(),
        retention_expired=True,
        data_subject_requested_deletion=False,
        classification="PERSONAL_DATA",
        data_subject_id="ds-003",
    )

    deletion_requested_doc = BrazilRAGDocument(
        document_id="doc-004-deletion-requested",
        contains_personal_data=True,
        contains_sensitive_data=False,
        data_categories_present=frozenset({"contact", "financial"}),
        compatible_purposes=frozenset(),
        retention_expired=False,
        data_subject_requested_deletion=True,
        classification="PERSONAL_DATA",
        data_subject_id="ds-004",
    )

    public_doc = BrazilRAGDocument(
        document_id="doc-005-public-policy",
        contains_personal_data=False,
        contains_sensitive_data=False,
        data_categories_present=frozenset(),
        compatible_purposes=frozenset(),
        retention_expired=False,
        data_subject_requested_deletion=False,
        classification="PUBLIC",
        data_subject_id="",
    )

    all_documents = [
        personal_doc, sensitive_doc, expired_doc, deletion_requested_doc, public_doc
    ]

    # ------------------------------------------------------------------
    # Scenario 1: Brazilian data controller with valid consent (BR)
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: BR data controller, consent legal basis ---")
    ctx_br_controller = BrazilRAGContext(
        user_id="user-br-001",
        requester_role=BrazilRole.DATA_CONTROLLER,
        requester_jurisdiction="BR",
        lgpd_legal_basis="consent",
        has_explicit_consent=True,
        requester_is_data_subject=False,
        authorized_data_categories=frozenset({"contact", "financial", "health"}),
        processing_purpose="customer_service",
        is_legal_hold=False,
        is_legal_override=False,
        has_lgpd_transfer_mechanism=False,
        is_dpo=False,
    )
    pipeline = BrazilLGPDRAGPipeline()
    results = pipeline.retrieve(ctx_br_controller, all_documents)
    print(f"  Permitted documents: {[r[0].document_id for r in results]}")

    # ------------------------------------------------------------------
    # Scenario 2: Data subject accessing their own data
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Data subject self-access (Art. 18) ---")
    ctx_data_subject = BrazilRAGContext(
        user_id="ds-001",
        requester_role=BrazilRole.DATA_SUBJECT,
        requester_jurisdiction="BR",
        lgpd_legal_basis="none",          # Art. 18 bypasses legal basis check
        has_explicit_consent=False,
        requester_is_data_subject=True,
        authorized_data_categories=frozenset({"contact", "financial"}),
        processing_purpose="customer_service",
        is_legal_hold=False,
        is_legal_override=False,
        has_lgpd_transfer_mechanism=False,
        is_dpo=False,
    )
    results_ds = pipeline.retrieve(ctx_data_subject, [personal_doc])
    print(f"  Permitted documents: {[r[0].document_id for r in results_ds]}")

    # ------------------------------------------------------------------
    # Scenario 3: US requester without SCC — cross-border denied
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: US requester, no SCC — cross-border denied ---")
    ctx_us = BrazilRAGContext(
        user_id="user-us-001",
        requester_role=BrazilRole.DATA_PROCESSOR,
        requester_jurisdiction="US",
        lgpd_legal_basis="contract",
        has_explicit_consent=False,
        requester_is_data_subject=False,
        authorized_data_categories=frozenset({"contact", "financial"}),
        processing_purpose="customer_service",
        is_legal_hold=False,
        is_legal_override=False,
        has_lgpd_transfer_mechanism=False,
        is_dpo=False,
    )
    results_us = pipeline.retrieve(ctx_us, [personal_doc])
    print(f"  Permitted documents: {[r[0].document_id for r in results_us]}")

    # ------------------------------------------------------------------
    # Scenario 4: US requester WITH SCC — permitted
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: US requester, SCC in place — permitted ---")
    ctx_us_scc = BrazilRAGContext(
        user_id="user-us-002",
        requester_role=BrazilRole.DATA_PROCESSOR,
        requester_jurisdiction="US",
        lgpd_legal_basis="contract",
        has_explicit_consent=False,
        requester_is_data_subject=False,
        authorized_data_categories=frozenset({"contact", "financial"}),
        processing_purpose="customer_service",
        is_legal_hold=False,
        is_legal_override=False,
        has_lgpd_transfer_mechanism=True,
        is_dpo=False,
    )
    results_us_scc = pipeline.retrieve(ctx_us_scc, [personal_doc])
    print(f"  Permitted documents: {[r[0].document_id for r in results_us_scc]}")

    # ------------------------------------------------------------------
    # Scenario 5: Deletion-requested doc — redacted
    # ------------------------------------------------------------------
    print("\n--- Scenario 5: Data subject deletion request — document redacted ---")
    results_redact = pipeline.retrieve(ctx_br_controller, [deletion_requested_doc])
    print(f"  Returned (redacted) documents: {[r[0].document_id for r in results_redact]}")
    if results_redact:
        last_layer = results_redact[0][1][-1]
        print(f"  Retention layer decision: {last_layer.decision.value}")

    # ------------------------------------------------------------------
    # Audit record
    # ------------------------------------------------------------------
    print("\n--- Audit record (retrieve_with_audit) ---")
    audit = pipeline.retrieve_with_audit(ctx_br_controller, all_documents)
    log = audit.to_audit_log()
    print(json.dumps(
        {k: v for k, v in log.items() if k != "filter_results"},
        indent=2,
    ))
    print(f"  event: {log['event']}")
    print(f"  documents_evaluated: {log['documents_evaluated']}")
    print(f"  documents_permitted: {log['documents_permitted']}")
    print(f"  documents_denied: {log['documents_denied']}")
    print(f"  documents_redacted: {log['documents_redacted']}")
    print("\nSmoke test complete.")
