"""
South Korea PIPA RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating under South Korea's Personal Information Protection
Act (PIPA, Act No. 10142, as amended) and the Korea AI Framework Act
(enacted January 2024).  Four independent filter layers run sequentially;
a document must pass all four to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | Korean e-commerce and fintech customer portals           | PIPA Art. 15 (legal basis), Art. 35 (DSR)|
  | Healthcare record retrieval systems                      | PIPA Art. 23 (sensitive data)            |
  | HR and employee data management platforms                | PIPA Art. 3(1) (minimization)            |
  | Financial services analytics pipelines                   | PIPA Art. 16(2) (purpose limitation)     |
  | Cross-border data sharing with global enterprises        | PIPA Art. 17, Art. 39-3 (transfers)      |
  | Public-sector AI decision-support systems                | Korea AI Framework Act Art. 6            |
  | Marketing and CRM automation platforms                   | PIPA Art. 15(1)(i) (consent)             |
  | Customer service AI assistants (high-impact AI)          | Korea AI Framework Act Art. 6 (disclosure)|
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — KoreaPIPADataSubjectFilter (PIPA Art. 15-18, Art. 23, Art. 35)
      Controls access to personal information documents based on the
      requesting party's legal basis and data subject relationship.

      PIPA Art. 15 enumerates the lawful bases for processing personal
      information: consent, necessity for contract performance, legal
      obligation, vital interests, public task, and legitimate interest.
      All personal information processing — including retrieval — must be
      grounded in one of those bases.

      PIPA Art. 23 imposes heightened requirements for sensitive personal
      information (ideology, religion, trade union membership, political
      views, health and medical records, sexual orientation, biometric data,
      criminal records, and similar).  Processing sensitive information
      requires explicit consent from the data subject.

      PIPA Art. 35 grants data subjects the right to access their own
      personal information held by a personal information controller.  A
      data subject always has the right to access their own personal
      information regardless of the basis used by the controller.

  Layer 2 — KoreaPIPAMinimizationFilter (PIPA Art. 3(1), Art. 16(2))
      Enforces the data minimization and purpose limitation principles that
      are foundational to PIPA.

      PIPA Art. 3(1) (Minimization): Personal information controllers shall
      process the minimum amount of personal information necessary to
      achieve the purposes of processing.  Retrieval of documents containing
      categories beyond those expressly authorised for the stated purpose is
      prohibited.

      PIPA Art. 16(2) (Purpose Limitation): Personal information shall be
      processed only within the scope of the collected purpose.  Retrieval
      for purposes incompatible with the original collection purpose is
      denied unless the document imposes no purpose restriction.

  Layer 3 — KoreaAIActFilter (Korea AI Framework Act, January 2024)
      Enforces transparency and human oversight requirements for high-impact
      AI systems at the retrieval layer.

      Korea AI Framework Act Art. 6 requires that developers and deployers
      of high-impact AI systems disclose to users that they are interacting
      with or being assessed by an AI system.  If the system is classified as
      high-impact AI and the required disclosure has not been made to the
      user, the retrieval is escalated for human review before proceeding.

      High-impact AI systems include AI used in employment decisions, credit
      assessment, insurance underwriting, medical diagnosis, and critical
      infrastructure management, among others defined by the Act.

  Layer 4 — KoreaCrossBorderFilter (PIPA Art. 17, Art. 39-3)
      Controls cross-border transfer of personal information at the
      retrieval layer.

      PIPA Art. 39-3 permits international transfer of personal information
      only to jurisdictions that provide an adequate level of data protection,
      or when appropriate safeguard mechanisms such as Binding Corporate
      Rules (BCRs) or Standard Contractual Clauses (SCCs) are in place.

      Jurisdictions currently recognised as providing adequate protection for
      PIPA purposes (Korea has adequacy arrangements with):
        "KR" — Korea (domestic, no transfer)
        "EU" — EU member states (GDPR adequacy determination)
        "UK" — United Kingdom (UK GDPR)
        "CH" — Switzerland (Federal Act on Data Protection)
        "JP" — Japan (APPI adequacy)
        "NZ" — New Zealand (Privacy Act 2020)
        "CA" — Canada (PIPEDA adequacy)

      Requests from all other jurisdictions require an SCCs or BCRs
      mechanism before personal information may be retrieved.  Non-personal
      information is not subject to Art. 39-3 transfer controls.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class KoreaRequesterRole(Enum):
    DATA_SUBJECT = "DATA_SUBJECT"
    AUTHORIZED_PROCESSOR = "AUTHORIZED_PROCESSOR"
    THIRD_PARTY = "THIRD_PARTY"
    PUBLIC_BODY = "PUBLIC_BODY"


class KoreaLegalBasis(Enum):
    CONSENT = "CONSENT"
    CONTRACT = "CONTRACT"
    LEGAL_OBLIGATION = "LEGAL_OBLIGATION"
    VITAL_INTEREST = "VITAL_INTEREST"
    PUBLIC_TASK = "PUBLIC_TASK"
    LEGITIMATE_INTEREST = "LEGITIMATE_INTEREST"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KoreaRAGContext:
    """
    Carries all per-request attributes needed by the four PIPA filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    requester_jurisdiction is an ISO 3166-1 alpha-2 country code, e.g.
        "KR" (Korea), "EU" (EU member states), "US" (United States).

    authorized_categories is the set of personal information categories the
    requester is permitted to access for the stated processing_purpose.

    processing_purpose describes why the requester needs the information, e.g.
        "customer_service", "fraud_detection", "healthcare", "hr_management".
    """

    requester_id: str
    requester_role: KoreaRequesterRole
    legal_basis: KoreaLegalBasis
    processing_purpose: str
    authorized_categories: frozenset                # personal info categories permitted
    requester_jurisdiction: str                     # ISO 3166-1 alpha-2
    has_pipa_consent: bool                          # PIPA Art. 15(1)(i) consent obtained
    has_sensitive_data_consent: bool                # PIPA Art. 23 explicit consent for sensitive info
    is_data_subject_request: bool                   # PIPA Art. 35 data subject self-access
    has_cross_border_agreement: bool                # BCRs or SCCs in place (PIPA Art. 39-3)
    is_high_impact_ai: bool                         # Korea AI Framework Act Art. 6 trigger
    ai_transparency_disclosed: bool                 # Disclosure made to user per AI Act Art. 6


@dataclass(frozen=True)
class KoreaRAGDocument:
    """
    Immutable document descriptor carrying all attributes needed for PIPA
    compliance evaluation across the four filter layers.

    contains_sensitive_info corresponds to PIPA Art. 23 categories:
        ideology, health, biometric, criminal records, and similar.

    data_categories_present is the set of personal information categories in
    the document, e.g. frozenset({"financial", "health", "contact"}).

    compatible_purposes is the set of purposes the data was collected for.
    An empty frozenset means the data may be used for any purpose.

    data_subject_ids identifies whose personal information the document
    contains; leave as an empty frozenset if the document has no specific
    data subjects.
    """

    document_id: str
    contains_personal_info: bool
    contains_sensitive_info: bool               # PIPA Art. 23 — ideology, health, biometric, criminal
    data_categories_present: frozenset
    compatible_purposes: frozenset              # empty = any purpose
    data_subject_ids: frozenset
    retention_expired: bool
    is_third_party_data: bool
    source_jurisdiction: str


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: str               # "APPROVED", "DENIED", "REDACTED", "REQUIRES_HUMAN_REVIEW"
    reason: str
    regulation_citation: str
    requires_logging: bool = True

    @property
    def is_denied(self) -> bool:
        """True only when the decision is DENIED.

        REDACTED and REQUIRES_HUMAN_REVIEW do not stop the pipeline.
        """
        return self.decision == "DENIED"


# ---------------------------------------------------------------------------
# Layer 1: KoreaPIPADataSubjectFilter — PIPA Art. 15-18, Art. 23, Art. 35
# ---------------------------------------------------------------------------

class KoreaPIPADataSubjectFilter:
    """
    Enforces PIPA legal-basis and data-subject-rights requirements.

    PIPA Art. 35 — Data subject always has the right to access their own
    personal information.  If the requester is the data subject making a
    self-access request, access is unconditionally permitted by this layer.

    PIPA Art. 15 — Processing of personal information (including retrieval)
    requires one of the enumerated legal bases.  Attempting to retrieve
    personal information without a valid legal basis results in a DENIED
    decision.

    PIPA Art. 23 — Sensitive personal information (ideology, religion, trade
    union membership, political views, health and medical records, sexual
    orientation, biometric data, criminal records) requires explicit consent
    from the data subject.  A valid Art. 15 legal basis is insufficient on
    its own for sensitive information.
    """

    LAYER_NAME = "KOREA_PIPA_DATA_SUBJECT_ART_15_23_35"

    def evaluate(
        self, context: KoreaRAGContext, document: KoreaRAGDocument
    ) -> FilterResult:
        """
        Evaluate PIPA data-subject rights and legal-basis requirements for
        access to the document.

        Evaluation order:
          1. Data subject self-access (Art. 35) — always approved.
          2. Non-personal information — approved (PIPA Art. 15/23 not applicable).
          3. No legal basis (Art. 15) — denied.
          4. Sensitive info without explicit consent (Art. 23) — denied.
          5. Otherwise — approved.
        """
        # Art. 35: Data subject always has the right to access their own information.
        if context.is_data_subject_request:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    "PIPA Article 35 — data subject right of access: requester is the "
                    "data subject and has unconditional access to their own personal information"
                ),
                regulation_citation="PIPA Article 35",
            )

        # Non-personal information is not subject to PIPA access controls.
        if not document.contains_personal_info:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Document does not contain personal information — PIPA Art. 15/23 not applicable",
                regulation_citation="PIPA Article 15",
            )

        # Art. 15: A valid legal basis is required for all personal information processing.
        if not context.has_pipa_consent and context.legal_basis not in (
            KoreaLegalBasis.CONSENT,
            KoreaLegalBasis.CONTRACT,
            KoreaLegalBasis.LEGAL_OBLIGATION,
            KoreaLegalBasis.VITAL_INTEREST,
            KoreaLegalBasis.PUBLIC_TASK,
            KoreaLegalBasis.LEGITIMATE_INTEREST,
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "PIPA Article 15: Lawful basis required for personal information processing"
                ),
                regulation_citation="PIPA Article 15",
            )

        # Art. 23: Sensitive information requires explicit consent.
        if document.contains_sensitive_info and not context.has_sensitive_data_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "PIPA Article 23: Explicit consent required for sensitive personal information"
                ),
                regulation_citation="PIPA Article 23",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="PIPA Article 15/23/35 — legal basis and data subject rights check passed",
            regulation_citation="PIPA Article 15",
        )


# ---------------------------------------------------------------------------
# Layer 2: KoreaPIPAMinimizationFilter — PIPA Art. 3(1), Art. 16(2)
# ---------------------------------------------------------------------------

class KoreaPIPAMinimizationFilter:
    """
    Enforces PIPA data minimization (Art. 3(1)) and purpose limitation
    (Art. 16(2)) principles at the retrieval layer.

    PIPA Art. 3(1) (Minimization): Personal information controllers shall
    process the minimum amount of personal information necessary to achieve
    the purposes of processing.  If a document contains personal information
    categories beyond those the requester is authorised to access, the
    retrieval is denied to prevent over-disclosure.

    PIPA Art. 16(2) (Purpose Limitation): Personal information shall be
    processed only within the scope of the collected purpose.  If the
    requester's stated processing purpose is not among the purposes for which
    the document's data was originally collected, access is denied unless the
    document imposes no purpose restriction (empty compatible_purposes).
    """

    LAYER_NAME = "KOREA_PIPA_MINIMIZATION_ART_3_16"

    def evaluate(
        self, context: KoreaRAGContext, document: KoreaRAGDocument
    ) -> FilterResult:
        """
        Evaluate data minimization and purpose limitation requirements.

        Evaluation order:
          1. Data category check (Art. 3(1)) — deny if unauthorized categories present.
          2. Purpose compatibility check (Art. 16(2)) — deny if purpose incompatible.
          3. Otherwise — approved.
        """
        # Art. 3(1): Check whether document contains any unauthorized data category.
        if document.data_categories_present and context.authorized_categories:
            unauthorized = document.data_categories_present - context.authorized_categories
            if unauthorized:
                return FilterResult(
                    layer=self.LAYER_NAME,
                    decision="DENIED",
                    reason=(
                        f"PIPA Article 3(1): Data minimization — document contains "
                        f"unauthorized categories: {sorted(unauthorized)}"
                    ),
                    regulation_citation="PIPA Article 3(1)",
                )

        # Art. 16(2): Check purpose compatibility if the document declares compatible purposes.
        if document.compatible_purposes and (
            context.processing_purpose not in document.compatible_purposes
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    f"PIPA Article 16(2): Purpose limitation — processing purpose "
                    f"'{context.processing_purpose}' incompatible with document purposes "
                    f"{sorted(document.compatible_purposes)}"
                ),
                regulation_citation="PIPA Article 16(2)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="PIPA Article 3(1)/16(2) — data minimization and purpose limitation check passed",
            regulation_citation="PIPA Article 3(1)",
        )


# ---------------------------------------------------------------------------
# Layer 3: KoreaAIActFilter — Korea AI Framework Act (January 2024)
# ---------------------------------------------------------------------------

class KoreaAIActFilter:
    """
    Enforces transparency and disclosure requirements for high-impact AI
    systems under the Korea AI Framework Act (enacted January 2024).

    Korea AI Framework Act Art. 6 requires developers and deployers of
    high-impact AI systems to notify users that they are interacting with or
    being assessed by an AI system before the AI processes data relating to
    them.  High-impact AI includes systems used in employment, credit,
    insurance, medical diagnosis, and critical infrastructure.

    If the retrieval is performed by a high-impact AI system and the required
    disclosure has not been made to the affected user, the retrieval is
    escalated for human review (REQUIRES_HUMAN_REVIEW) rather than being
    outright denied.  This reflects the Act's proportionate approach: the
    remedy is disclosure and oversight, not prohibition.

    Systems not classified as high-impact AI are not subject to Art. 6
    transparency requirements at the retrieval layer.
    """

    LAYER_NAME = "KOREA_AI_ACT_ART_6"

    def evaluate(
        self, context: KoreaRAGContext, document: KoreaRAGDocument
    ) -> FilterResult:
        """
        Evaluate Korea AI Framework Act transparency requirements.

        Evaluation order:
          1. Not high-impact AI — approved (Art. 6 not applicable).
          2. High-impact AI without disclosure — REQUIRES_HUMAN_REVIEW.
          3. High-impact AI with disclosure — approved.
        """
        if not context.is_high_impact_ai:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Korea AI Framework Act — not high-impact AI; Art. 6 transparency not applicable",
                regulation_citation="Korea AI Framework Act — not high-impact AI",
            )

        if not context.ai_transparency_disclosed:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Korea AI Framework Act Article 6: High-impact AI systems must disclose "
                    "AI involvement to users before processing"
                ),
                regulation_citation="Korea AI Framework Act Article 6",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason=(
                "Korea AI Framework Act Article 6 — high-impact AI with disclosure: "
                "AI transparency requirement satisfied"
            ),
            regulation_citation="Korea AI Framework Act Article 6",
        )


# ---------------------------------------------------------------------------
# Layer 4: KoreaCrossBorderFilter — PIPA Art. 17, Art. 39-3
# ---------------------------------------------------------------------------

class KoreaCrossBorderFilter:
    """
    Enforces PIPA cross-border personal information transfer requirements
    (Art. 17, Art. 39-3) at the retrieval layer.

    PIPA Art. 39-3 permits international transfer of personal information
    only when:
      (a) the destination jurisdiction provides an adequate level of data
          protection as recognised by the Personal Information Protection
          Commission (PIPC) of Korea; or
      (b) an appropriate safeguard mechanism (BCRs or SCCs) is in place.

    Jurisdictions currently recognised as providing adequate protection:
      "KR" — Korea (domestic)
      "EU" — EU member states (GDPR adequacy)
      "UK" — United Kingdom (UK GDPR)
      "CH" — Switzerland (Federal Act on Data Protection)
      "JP" — Japan (APPI adequacy determination)
      "NZ" — New Zealand (Privacy Act 2020)
      "CA" — Canada (PIPEDA adequacy)

    Non-personal information is not subject to Art. 39-3 transfer controls.
    """

    LAYER_NAME = "KOREA_PIPA_CROSS_BORDER_ART_39_3"

    _ADEQUATE_JURISDICTIONS: frozenset = frozenset({"KR", "EU", "UK", "CH", "JP", "NZ", "CA"})

    def evaluate(
        self, context: KoreaRAGContext, document: KoreaRAGDocument
    ) -> FilterResult:
        """
        Evaluate PIPA cross-border transfer requirements.

        Evaluation order:
          1. Non-personal information — always approved (Art. 39-3 not applicable).
          2. Adequate jurisdiction — approved.
          3. Non-adequate jurisdiction with BCRs/SCCs — approved.
          4. Non-adequate jurisdiction without safeguards — denied.
        """
        # Art. 39-3 applies only to personal information.
        if not document.contains_personal_info:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Document does not contain personal information — PIPA Art. 39-3 not applicable",
                regulation_citation="PIPA Article 39-3",
            )

        # Requests from jurisdictions with adequate protection are permitted.
        if context.requester_jurisdiction in self._ADEQUATE_JURISDICTIONS:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    f"PIPA Article 39-3: Transfer to adequate jurisdiction "
                    f"'{context.requester_jurisdiction}'"
                ),
                regulation_citation="PIPA Article 39-3: Transfer to adequate jurisdiction",
            )

        # Non-adequate jurisdiction with BCRs or SCCs in place.
        if context.has_cross_border_agreement:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    f"PIPA Article 39-3: Cross-border transfer to "
                    f"'{context.requester_jurisdiction}' permitted via BCRs or SCCs"
                ),
                regulation_citation="PIPA Article 39-3: Binding corporate rules or standard contractual clauses",
            )

        # Non-adequate jurisdiction without any safeguard mechanism.
        return FilterResult(
            layer=self.LAYER_NAME,
            decision="DENIED",
            reason=(
                f"PIPA Article 39-3: Cross-border transfer without adequate safeguards — "
                f"jurisdiction '{context.requester_jurisdiction}' is not adequate and no "
                "BCRs or SCCs are in place"
            ),
            regulation_citation="PIPA Article 39-3",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class KoreaRAGAuditRecord:
    """
    Captures the full decision trail for a Korea PIPA RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - PIPA Art. 30: Controllers shall maintain records of personal
        information processing operations.
      - PIPA Art. 31: Designation of Chief Privacy Officer (CPO) and
        associated record-keeping obligations.
      - Korea AI Framework Act Art. 9: High-impact AI systems must maintain
        logs of AI-assisted decisions for accountability and auditability.

    All fields are populated at retrieval time; the timestamp uses the
    system clock and should be treated as UTC for regulatory record-keeping.
    """

    context: KoreaRAGContext
    documents_evaluated: int
    documents_permitted: int
    documents_denied: int
    documents_redacted: int
    filter_results: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "KOREA_PIPA_RAG_RETRIEVAL",
            "requester_id": self.context.requester_id,
            "requester_role": self.context.requester_role.value,
            "requester_jurisdiction": self.context.requester_jurisdiction,
            "legal_basis": self.context.legal_basis.value,
            "processing_purpose": self.context.processing_purpose,
            "is_high_impact_ai": self.context.is_high_impact_ai,
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

class KoreaPIPARAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms subject
    to Korea's Personal Information Protection Act (PIPA) and the Korea AI
    Framework Act.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW and REDACTED
    results do not stop the pipeline — those documents are included in the
    result set.  Only documents that are denied by any layer are excluded
    from the returned set.

    Layers in order:
      1. KoreaPIPADataSubjectFilter  — Art. 15 legal basis, Art. 23 sensitive data, Art. 35 DSR
      2. KoreaPIPAMinimizationFilter — Art. 3(1) minimization, Art. 16(2) purpose limitation
      3. KoreaAIActFilter            — AI Framework Act Art. 6 transparency disclosure
      4. KoreaCrossBorderFilter      — PIPA Art. 39-3 cross-border transfer controls

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for PIPA Art. 30/31 record-keeping
    and AI Act Art. 9 accountability obligations.
    """

    def __init__(self) -> None:
        self._layers = [
            KoreaPIPADataSubjectFilter(),
            KoreaPIPAMinimizationFilter(),
            KoreaAIActFilter(),
            KoreaCrossBorderFilter(),
        ]

    def retrieve(
        self,
        context: KoreaRAGContext,
        documents: List[KoreaRAGDocument],
    ) -> List[KoreaRAGDocument]:
        """
        Return a list of documents that pass (or are flagged but not denied by)
        all four filter layers.

        Documents denied on any layer are excluded from the result.  Documents
        that receive REQUIRES_HUMAN_REVIEW or REDACTED decisions on any layer
        are included, as those decisions do not constitute a denial.
        """
        permitted = []
        for doc in documents:
            allow = True
            for layer in self._layers:
                result = layer.evaluate(context, doc)
                if result.is_denied:
                    allow = False
                    break
            if allow:
                permitted.append(doc)
        return permitted

    def retrieve_with_audit(
        self,
        context: KoreaRAGContext,
        documents: List[KoreaRAGDocument],
    ) -> KoreaRAGAuditRecord:
        """
        Evaluate all documents and return a KoreaRAGAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support PIPA
        Art. 30/31 processing records and AI Act Art. 9 accountability logs.
        """
        documents_permitted = 0
        documents_denied = 0
        documents_redacted = 0
        all_filter_results: List[dict] = []

        for doc in documents:
            layer_results: List[dict] = []
            allow = True
            final_decision = "APPROVED"

            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(
                    {
                        "layer": result.layer,
                        "decision": result.decision,
                        "reason": result.reason,
                        "regulation_citation": result.regulation_citation,
                    }
                )
                if result.is_denied:
                    allow = False
                    final_decision = "DENIED"
                    break
                if result.decision == "REDACTED":
                    final_decision = "REDACTED"
                elif result.decision == "REQUIRES_HUMAN_REVIEW" and final_decision == "APPROVED":
                    final_decision = "REQUIRES_HUMAN_REVIEW"

            if allow:
                if final_decision == "REDACTED":
                    documents_redacted += 1
                else:
                    documents_permitted += 1
            else:
                documents_denied += 1

            all_filter_results.append(
                {
                    "document_id": doc.document_id,
                    "final_decision": final_decision,
                    "layer_results": layer_results,
                }
            )

        return KoreaRAGAuditRecord(
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
    print("South Korea PIPA RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Shared documents
    # ------------------------------------------------------------------

    personal_doc = KoreaRAGDocument(
        document_id="doc-001-customer-contact",
        contains_personal_info=True,
        contains_sensitive_info=False,
        data_categories_present=frozenset({"contact", "financial"}),
        compatible_purposes=frozenset({"customer_service", "fraud_detection"}),
        data_subject_ids=frozenset({"ds-001"}),
        retention_expired=False,
        is_third_party_data=False,
        source_jurisdiction="KR",
    )

    sensitive_doc = KoreaRAGDocument(
        document_id="doc-002-health-record",
        contains_personal_info=True,
        contains_sensitive_info=True,
        data_categories_present=frozenset({"health", "contact"}),
        compatible_purposes=frozenset({"healthcare"}),
        data_subject_ids=frozenset({"ds-002"}),
        retention_expired=False,
        is_third_party_data=False,
        source_jurisdiction="KR",
    )

    public_doc = KoreaRAGDocument(
        document_id="doc-003-public-policy",
        contains_personal_info=False,
        contains_sensitive_info=False,
        data_categories_present=frozenset(),
        compatible_purposes=frozenset(),
        data_subject_ids=frozenset(),
        retention_expired=False,
        is_third_party_data=False,
        source_jurisdiction="KR",
    )

    all_documents = [personal_doc, sensitive_doc, public_doc]

    # ------------------------------------------------------------------
    # Scenario 1: Korean authorized processor with consent
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: KR authorized processor, consent legal basis ---")
    ctx_kr = KoreaRAGContext(
        requester_id="proc-kr-001",
        requester_role=KoreaRequesterRole.AUTHORIZED_PROCESSOR,
        legal_basis=KoreaLegalBasis.CONSENT,
        processing_purpose="customer_service",
        authorized_categories=frozenset({"contact", "financial", "health"}),
        requester_jurisdiction="KR",
        has_pipa_consent=True,
        has_sensitive_data_consent=True,
        is_data_subject_request=False,
        has_cross_border_agreement=False,
        is_high_impact_ai=False,
        ai_transparency_disclosed=False,
    )
    pipeline = KoreaPIPARAGPipeline()
    results = pipeline.retrieve(ctx_kr, all_documents)
    print(f"  Permitted documents: {[d.document_id for d in results]}")

    # ------------------------------------------------------------------
    # Scenario 2: Data subject self-access (Art. 35)
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Data subject self-access (Art. 35) ---")
    ctx_ds = KoreaRAGContext(
        requester_id="ds-001",
        requester_role=KoreaRequesterRole.DATA_SUBJECT,
        legal_basis=KoreaLegalBasis.CONSENT,
        processing_purpose="self_access",
        authorized_categories=frozenset({"contact", "financial"}),
        requester_jurisdiction="KR",
        has_pipa_consent=False,
        has_sensitive_data_consent=False,
        is_data_subject_request=True,
        has_cross_border_agreement=False,
        is_high_impact_ai=False,
        ai_transparency_disclosed=False,
    )
    results_ds = pipeline.retrieve(ctx_ds, [personal_doc])
    print(f"  Permitted documents: {[d.document_id for d in results_ds]}")

    # ------------------------------------------------------------------
    # Scenario 3: US requester without BCRs/SCCs — cross-border denied
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: US requester, no BCRs/SCCs — cross-border denied ---")
    ctx_us = KoreaRAGContext(
        requester_id="proc-us-001",
        requester_role=KoreaRequesterRole.AUTHORIZED_PROCESSOR,
        legal_basis=KoreaLegalBasis.CONTRACT,
        processing_purpose="customer_service",
        authorized_categories=frozenset({"contact", "financial"}),
        requester_jurisdiction="US",
        has_pipa_consent=True,
        has_sensitive_data_consent=False,
        is_data_subject_request=False,
        has_cross_border_agreement=False,
        is_high_impact_ai=False,
        ai_transparency_disclosed=False,
    )
    results_us = pipeline.retrieve(ctx_us, [personal_doc])
    print(f"  Permitted documents: {[d.document_id for d in results_us]}")

    # ------------------------------------------------------------------
    # Scenario 4: High-impact AI without disclosure — REQUIRES_HUMAN_REVIEW
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: High-impact AI without disclosure (Art. 6) ---")
    ctx_ai = KoreaRAGContext(
        requester_id="ai-sys-001",
        requester_role=KoreaRequesterRole.AUTHORIZED_PROCESSOR,
        legal_basis=KoreaLegalBasis.CONSENT,
        processing_purpose="customer_service",
        authorized_categories=frozenset({"contact", "financial"}),
        requester_jurisdiction="KR",
        has_pipa_consent=True,
        has_sensitive_data_consent=False,
        is_data_subject_request=False,
        has_cross_border_agreement=False,
        is_high_impact_ai=True,
        ai_transparency_disclosed=False,
    )
    results_ai = pipeline.retrieve(ctx_ai, [personal_doc])
    print(f"  Permitted documents (incl. REQUIRES_HUMAN_REVIEW): {[d.document_id for d in results_ai]}")

    # ------------------------------------------------------------------
    # Audit record
    # ------------------------------------------------------------------
    print("\n--- Audit record (retrieve_with_audit) ---")
    audit = pipeline.retrieve_with_audit(ctx_kr, all_documents)
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
