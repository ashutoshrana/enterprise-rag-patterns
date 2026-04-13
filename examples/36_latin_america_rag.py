"""
Latin America RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating in the Latin American data-protection regulatory
environment.  Four independent filter layers run sequentially; a document
must pass all four to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | HR and payroll management platforms (Argentina)          | Argentina LPDP 25.326 + AAIP Res. 47/2018|
  | Healthcare data systems (Colombia)                       | Colombia Law 1581/2012 + Decree 1377/2013|
  | Fintech credit platforms (Chile)                         | Chile Law 19.628 + Law 21.719 (2024)     |
  | E-government portals (multi-jurisdiction)                | LPDP / Law 19.628 / Law 1581             |
  | Cross-border B2B data exchange platforms                 | Ibero-American Data Protection Network   |
  | EdTech platforms serving LatAm markets                   | LPDP Art. 12 / Law 19.628 Art. 4         |
  | Telemedicine platforms operating in AR/CL/CO             | LPDP Art. 7 / Law 19.628 Art. 2(g)      |
  | AI-driven credit scoring platforms                       | Chile Law 21.719 Art. 16 (automated)     |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — ArgentinaPersonalDataFilter
      (Argentina Personal Data Protection Law 25.326 + AAIP Resolution 47/2018)
      Controls access to personal data for controllers operating in Argentina
      or processing data of Argentine data subjects.

      Art. 7 restricts collection, use, or disclosure of sensitive personal
      data — including health data, biometric data, ethnic origin, political
      opinions, and religious beliefs — to situations where the data subject
      has provided express written consent.  Processing sensitive data without
      explicit consent is denied.

      Art. 5 requires prior informed consent from the data subject before any
      personal data processing.  Requests that satisfy neither consent nor
      legitimate interest — unless submitted by the data subject or a regulator
      — are denied.

      Art. 12 requires parental or guardian authorisation before processing
      personal data of minors.  Processing a minor's data without parental
      consent is denied.

      Data subjects have an unconditional right of access to their own personal
      data; data-subject role requests are approved immediately.

  Layer 2 — ChilePersonalDataFilter
      (Chile Personal Data Protection Law 19.628 + Law 21.719 (2024 reform))
      Controls access to personal data for controllers operating in Chile or
      processing data of Chilean data subjects.

      Art. 4 of Law 19.628 requires consent or a legal authorisation basis
      before any personal data processing.  Requests without consent and
      without legitimate interest — except data subjects and regulators —
      are denied.

      Art. 2(g) of Law 19.628 classifies a category of sensitive data whose
      processing requires the explicit consent of its owner.  Processing
      sensitive data without explicit consent is denied.

      Law 21.719 Art. 16 grants data subjects the right to obtain human
      review of automated decisions that produce significant effects on them.
      Automated decisions without a human-review pathway are escalated, not
      denied, so the pipeline continues with a REQUIRES_HUMAN_REVIEW flag.

      Data subjects have an unconditional right of access to their own data;
      data-subject role requests are approved immediately.

  Layer 3 — ColombiaHabeasDataFilter
      (Colombia Habeas Data Law 1581/2012 + Decree 1377/2013 + SIC circular)
      Controls access to personal data for controllers operating in Colombia
      or processing data of Colombian data subjects.

      Art. 7 of Law 1581/2012 identifies sensitive data categories — including
      health, biometric, political opinion, sexual orientation, and religious
      beliefs — and requires explicit, prior consent before any processing.
      Processing sensitive data without consent is denied.

      Art. 4(c) of Law 1581/2012 establishes prior, express, and informed
      consent as the primary legal basis for processing personal data.
      Non-data-subject, non-regulator requests without consent or legitimate
      interest are denied.

      Decree 1377/2013 Art. 10 requires the data owner's written authorisation
      before transmitting financial or credit data to third parties.  Processing
      financial data without explicit consent is denied.

      Data subjects have an unconditional right of access to their own data;
      data-subject role requests are approved immediately.

  Layer 4 — LatAmCrossBorderFilter (Ibero-American Data Protection Network)
      Enforces cross-border personal-data transfer requirements applicable to
      transfers originating in Argentina, Chile, or Colombia.

      The Ibero-American Data Protection Network (Red Iberoamericana de
      Protección de Datos) and LGPD cross-recognition establish a regional
      adequacy framework.  Transfers within the adequate-jurisdiction set
      (AR, CL, CO, MX, PE, UY, BR) satisfy adequacy requirements and are
      approved.

      Transfers to non-adequate countries are permitted when the controller
      has implemented recognised contractual safeguards (standard contractual
      clauses, binding corporate rules, or equivalent mechanisms).

      Transfers to non-adequate destinations without safeguards are denied
      with jurisdiction-specific citations:
        - Argentina source: LPDP Art. 12 (adequate protection required)
        - Chile source:     Law 19.628 Art. 26 (equivalent protection required)
        - Colombia source:  Law 1581/2012 Art. 26 (SIC authorisation required)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LatAmContext:
    """
    Carries all per-request attributes needed by the four Latin America
    filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    jurisdiction is a 2-letter ISO country code for the governing law:
        "AR" (Argentina), "CL" (Chile), "CO" (Colombia)

    role describes the requesting party's position:
        "data_controller", "data_processor", "data_subject", "regulator"
    """

    user_id: str
    jurisdiction: str               # "AR", "CL", "CO"
    role: str                       # "data_controller", "data_processor", "data_subject", "regulator"
    has_explicit_consent: bool = False
    has_legitimate_interest: bool = False
    involves_sensitive_data: bool = False
    is_automated_decision: bool = False
    has_human_review: bool = True
    has_dpia: bool = False          # Data Protection Impact Assessment
    is_cross_border_transfer: bool = False
    destination_country: str = ""  # ISO country code
    has_transfer_mechanism: bool = False
    involves_minor: bool = False
    has_parental_consent: bool = False
    is_financial_data: bool = False


@dataclass(frozen=True)
class LatAmDocument:
    """
    Immutable document descriptor carrying all attributes needed for Latin
    America compliance evaluation across the four filter layers.

    doc_type describes the category of document:
        "personal_data_record", "health_record", "financial_record",
        "biometric_record", "consent_form", "transfer_agreement"
    """

    content: str
    document_id: str
    doc_type: str = "personal_data_record"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: str               # "APPROVED", "DENIED", "REQUIRES_HUMAN_REVIEW"
    reason: str
    regulation_citation: str
    requires_logging: bool = True

    @property
    def is_denied(self) -> bool:
        """True only when the decision is DENIED.

        REQUIRES_HUMAN_REVIEW does not stop the pipeline.
        """
        return self.decision == "DENIED"


# ---------------------------------------------------------------------------
# Layer 1: ArgentinaPersonalDataFilter
#          Argentina LPDP 25.326 + AAIP Resolution 47/2018
# ---------------------------------------------------------------------------

class ArgentinaPersonalDataFilter:
    """
    Enforces Argentina Personal Data Protection Law 25.326 (LPDP) and AAIP
    Resolution 47/2018 for access to personal data held or processed by
    controllers operating in Argentina or processing data of Argentine data
    subjects.

    Art. 7 restricts collection, use, or disclosure of sensitive personal data
    — including health data, biometric data, ethnic or racial origin, political
    opinions, trade-union membership, and religious or philosophical beliefs —
    to situations where the data subject has provided express written consent.
    Processing sensitive data without explicit consent is denied.

    Art. 5 requires that the data subject give prior informed consent before
    any processing of their personal data.  Requests that satisfy neither
    consent nor legitimate interest — unless the requesting party is the data
    subject or a regulator — are denied.

    Art. 12 requires parental or guardian authorisation before processing
    personal data belonging to minors.  Processing a minor's data without
    parental consent is denied.

    Data subjects have an unconditional right of access to their own personal
    data.  Data-subject role requests are approved immediately.
    """

    LAYER_NAME = "ARGENTINA_LPDP"

    def evaluate(self, context: LatAmContext, document: LatAmDocument) -> FilterResult:
        """
        Evaluate Argentina LPDP 25.326 requirements.

        Evaluation order:
          1. Sensitive data + no explicit consent (Art. 7) — DENIED.
          2. No consent and no legitimate interest for non-data-subject /
             non-regulator (Art. 5) — DENIED.
          3. Minor's data + no parental consent (Art. 12) — DENIED.
          4. Data subject self-access — APPROVED immediately.
          5. Otherwise — APPROVED.
        """
        # Art. 7: Sensitive personal data requires express written consent.
        if context.involves_sensitive_data and not context.has_explicit_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Argentina LPDP Art. 7: Sensitive personal data requires "
                    "express written consent"
                ),
                regulation_citation="Argentina LPDP 25.326 Art. 7",
            )

        # Art. 5: Personal data processing requires prior informed consent.
        if (
            not context.has_explicit_consent
            and not context.has_legitimate_interest
            and context.role not in {"data_subject", "regulator"}
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Argentina LPDP Art. 5: Personal data processing requires "
                    "prior informed consent"
                ),
                regulation_citation="Argentina LPDP 25.326 Art. 5",
            )

        # Art. 12: Processing data of minors requires parental authorisation.
        if context.involves_minor and not context.has_parental_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Argentina LPDP Art. 12: Processing data of minors requires "
                    "parental authorization"
                ),
                regulation_citation="Argentina LPDP 25.326 Art. 12",
            )

        # Data subjects have unconditional access to their own data.
        if context.role == "data_subject":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Argentina LPDP: Data subjects have right of access to own data",
                regulation_citation="Argentina LPDP 25.326",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Argentina LPDP access check passed",
            regulation_citation="Argentina LPDP 25.326",
        )


# ---------------------------------------------------------------------------
# Layer 2: ChilePersonalDataFilter
#          Chile Law 19.628 + Law 21.719 (2024 reform)
# ---------------------------------------------------------------------------

class ChilePersonalDataFilter:
    """
    Enforces Chile Personal Data Protection Law 19.628 and the 2024 reform
    introduced by Law 21.719 for access to personal data held or processed
    by controllers operating in Chile or processing data of Chilean data
    subjects.

    Art. 4 of Law 19.628 requires that personal data be processed only with
    the consent of the data owner or pursuant to a legal authorisation.
    Non-data-subject, non-regulator requests without consent or legitimate
    interest are denied.

    Art. 2(g) of Law 19.628 classifies a special category of sensitive
    personal data whose processing requires the explicit consent of its
    owner.  Processing sensitive data without explicit consent is denied.

    Law 21.719 Art. 16 grants data subjects the right to obtain human review
    of automated decisions that produce significant legal or similarly
    significant effects.  Automated decisions without a human-review pathway
    trigger escalation to REQUIRES_HUMAN_REVIEW; they are not denied outright.

    Data subjects have an unconditional right of access to their own personal
    data.  Data-subject role requests are approved immediately.
    """

    LAYER_NAME = "CHILE_LAW_19628_21719"

    def evaluate(self, context: LatAmContext, document: LatAmDocument) -> FilterResult:
        """
        Evaluate Chile Law 19.628 and Law 21.719 requirements.

        Evaluation order:
          1. No consent and no legitimate interest for non-data-subject /
             non-regulator (Law 19.628 Art. 4) — DENIED.
          2. Sensitive data + no explicit consent
             (Law 19.628 Art. 2(g)) — DENIED.
          3. Data subject self-access — APPROVED immediately.
          4. Automated decision + no human review
             (Law 21.719 Art. 16) — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — APPROVED.
        """
        # Art. 4: Personal data processing requires consent or legal authorisation.
        if (
            not context.has_explicit_consent
            and not context.has_legitimate_interest
            and context.role not in {"data_subject", "regulator"}
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Chile Law 19.628 Art. 4: Personal data processing requires "
                    "consent or legal authorization"
                ),
                regulation_citation="Chile Law 19.628 Art. 4",
            )

        # Art. 2(g): Sensitive data requires explicit consent of data owner.
        if context.involves_sensitive_data and not context.has_explicit_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Chile Law 19.628 Art. 2(g): Sensitive data requires "
                    "explicit consent of data owner"
                ),
                regulation_citation="Chile Law 19.628 Art. 2(g)",
            )

        # Data subjects have unconditional access to their own data.
        if context.role == "data_subject":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Chile Law 19.628: Data subjects have right of access to own data",
                regulation_citation="Chile Law 19.628 + Law 21.719",
            )

        # Law 21.719 Art. 16: Automated decisions require human review option.
        if context.is_automated_decision and not context.has_human_review:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Chile Law 21.719 Art. 16: Automated decisions with significant "
                    "effects require right to human review"
                ),
                regulation_citation="Chile Law 21.719 Art. 16",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Chile data protection access check passed",
            regulation_citation="Chile Law 19.628 + Law 21.719",
        )


# ---------------------------------------------------------------------------
# Layer 3: ColombiaHabeasDataFilter
#          Colombia Law 1581/2012 + Decree 1377/2013 + SIC circular
# ---------------------------------------------------------------------------

class ColombiaHabeasDataFilter:
    """
    Enforces Colombia Habeas Data Law 1581/2012, Decree 1377/2013, and SIC
    circulars for access to personal data held or processed by controllers
    operating in Colombia or processing data of Colombian data subjects.

    Art. 7 of Law 1581/2012 defines categories of sensitive personal data —
    including health, biometric, political opinion, trade-union membership,
    sexual orientation, religious beliefs, and judicial history — and requires
    explicit, prior consent before any processing.  Processing sensitive data
    without consent is denied.

    Art. 4(c) of Law 1581/2012 establishes prior, express, and informed consent
    as the primary legal basis for all personal data processing.
    Non-data-subject, non-regulator requests without consent or legitimate
    interest are denied.

    Decree 1377/2013 Art. 10 requires the data owner's written authorisation
    before financial or credit data may be transmitted to third parties.
    Processing financial data without explicit consent is denied.

    Data subjects have an unconditional right of access to their own personal
    data.  Data-subject role requests are approved immediately.
    """

    LAYER_NAME = "COLOMBIA_LAW_1581_DECREE_1377"

    def evaluate(self, context: LatAmContext, document: LatAmDocument) -> FilterResult:
        """
        Evaluate Colombia Law 1581/2012 and Decree 1377/2013 requirements.

        Evaluation order:
          1. Sensitive data + no explicit consent
             (Law 1581/2012 Art. 7) — DENIED.
          2. No consent and no legitimate interest for non-data-subject /
             non-regulator (Law 1581/2012 Art. 4(c)) — DENIED.
          3. Financial data + no explicit consent
             (Decree 1377/2013 Art. 10) — DENIED.
          4. Data subject self-access — APPROVED immediately.
          5. Otherwise — APPROVED.
        """
        # Art. 7: Sensitive personal data requires explicit and prior consent.
        if context.involves_sensitive_data and not context.has_explicit_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Colombia Law 1581/2012 Art. 7: Sensitive data requires "
                    "explicit and prior consent"
                ),
                regulation_citation="Colombia Law 1581/2012 Art. 7",
            )

        # Art. 4(c): Processing requires prior, express, and informed consent.
        if (
            not context.has_explicit_consent
            and not context.has_legitimate_interest
            and context.role not in {"data_subject", "regulator"}
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Colombia Law 1581/2012 Art. 4(c): Processing requires prior, "
                    "express, and informed consent"
                ),
                regulation_citation="Colombia Law 1581/2012 Art. 4(c)",
            )

        # Decree 1377/2013 Art. 10: Financial data transmission requires
        # data owner authorisation.
        if context.is_financial_data and not context.has_explicit_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Colombia Decree 1377/2013 Art. 10: Financial data transmission "
                    "requires data owner authorization"
                ),
                regulation_citation="Colombia Decree 1377/2013 Art. 10",
            )

        # Data subjects have unconditional access to their own data.
        if context.role == "data_subject":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Colombia Law 1581/2012: Data subjects have right of access to own data",
                regulation_citation="Colombia Law 1581/2012 + Decree 1377/2013",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Colombia Habeas Data access check passed",
            regulation_citation="Colombia Law 1581/2012 + Decree 1377/2013",
        )


# ---------------------------------------------------------------------------
# Layer 4: LatAmCrossBorderFilter — Ibero-American Data Protection Network
# ---------------------------------------------------------------------------

class LatAmCrossBorderFilter:
    """
    Enforces cross-border personal-data transfer requirements applicable to
    transfers originating in Argentina, Chile, or Colombia.

    The Ibero-American Data Protection Network (Red Iberoamericana de
    Protección de Datos) and Brazil's LGPD cross-recognition establish a
    regional adequacy framework for Latin American countries.  Transfers to
    countries in the adequate-jurisdiction set are approved.

    Transfers to non-adequate countries are permitted when the controller
    has implemented a recognised transfer mechanism such as standard
    contractual clauses, binding corporate rules, or an equivalent approved
    code of conduct.

    Transfers to non-adequate destinations without a recognised mechanism
    are denied with jurisdiction-specific citations:
      - Argentina source: LPDP Art. 12 (adequate protection required)
      - Chile source:     Law 19.628 Art. 26 (equivalent protection required)
      - Colombia source:  Law 1581/2012 Art. 26 (SIC authorisation or
                          adequate protection required)

    Jurisdiction-agnostic sources receive a generic LatAm denial.
    """

    LAYER_NAME = "LATAM_CROSS_BORDER"

    _ADEQUATE_COUNTRIES = frozenset({"AR", "CL", "CO", "MX", "PE", "UY", "BR"})

    def evaluate(self, context: LatAmContext, document: LatAmDocument) -> FilterResult:
        """
        Evaluate Latin American cross-border transfer requirements.

        Evaluation order:
          1. No transfer involved — APPROVED immediately.
          2. Destination country is in the adequate set — APPROVED (regional
             adequacy).
          3. Transfer mechanism present — APPROVED (contractual safeguards).
          4. No mechanism — jurisdiction-specific DENIED.
        """
        # No cross-border transfer: layer does not apply.
        if not context.is_cross_border_transfer:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="No cross-border transfer involved",
                regulation_citation="Ibero-American Data Protection Network",
            )

        # Destination country satisfies regional adequacy.
        if context.destination_country in self._ADEQUATE_COUNTRIES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    "Ibero-American Data Protection Network: adequate jurisdiction"
                ),
                regulation_citation="Ibero-American Data Protection Network",
            )

        # Transfer mechanism (contractual or binding rules) present.
        if context.has_transfer_mechanism:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    "Contractual safeguards satisfy cross-border transfer "
                    "requirements"
                ),
                regulation_citation="Ibero-American Data Protection Network",
            )

        # No mechanism — deny with jurisdiction-specific citation.
        if context.jurisdiction == "AR":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Argentina LPDP Art. 12: Transfer only to countries with "
                    "adequate protection"
                ),
                regulation_citation="Argentina LPDP 25.326 Art. 12",
            )

        if context.jurisdiction == "CL":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Chile Law 19.628 Art. 26: Transfer requires equivalent "
                    "level of protection"
                ),
                regulation_citation="Chile Law 19.628 Art. 26",
            )

        if context.jurisdiction == "CO":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Colombia Law 1581/2012 Art. 26: International transfer "
                    "requires SIC authorization or adequate protection"
                ),
                regulation_citation="Colombia Law 1581/2012 Art. 26",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="DENIED",
            reason=(
                "LatAm: Cross-border transfer requires adequate safeguards"
            ),
            regulation_citation="Ibero-American Data Protection Network",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class LatAmAuditRecord:
    """
    Captures the full decision trail for a Latin America RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - Argentina LPDP 25.326 audit and data-subject rights obligations.
      - Chile Law 19.628 record-keeping requirements.
      - Colombia Law 1581/2012 data-processing activity documentation.
      - Ibero-American cross-border transfer documentation requirements.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping.
    """

    event: str
    user_id: str
    jurisdiction: str
    documents_in: int
    documents_out: int
    decisions: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": self.event,
            "user_id": self.user_id,
            "jurisdiction": self.jurisdiction,
            "documents_in": self.documents_in,
            "documents_out": self.documents_out,
            "decisions": self.decisions,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class LatAmRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms
    operating in the Latin American data-protection regulatory environment.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do not
    stop the pipeline — those documents are included in the result set but
    flagged for human oversight.  Only documents that receive a DENIED result
    from any layer are excluded from the returned set.

    Layers in order:
      1. ArgentinaPersonalDataFilter  — LPDP 25.326 Art. 5/7/12
      2. ChilePersonalDataFilter      — Law 19.628 Art. 2(g)/4 + Law 21.719 Art. 16
      3. ColombiaHabeasDataFilter     — Law 1581/2012 Art. 4(c)/7 + Decree 1377/2013 Art. 10
      4. LatAmCrossBorderFilter       — Ibero-American Data Protection Network

    Audit records are generated for every retrieval event regardless of
    outcome, providing a complete access trail for multi-jurisdiction
    regulatory audits.
    """

    def __init__(self) -> None:
        self._layers = [
            ArgentinaPersonalDataFilter(),
            ChilePersonalDataFilter(),
            ColombiaHabeasDataFilter(),
            LatAmCrossBorderFilter(),
        ]

    def filter_documents(
        self,
        context: LatAmContext,
        documents: List[LatAmDocument],
    ) -> List[LatAmDocument]:
        """
        Return a list of documents that pass (or are flagged but not denied by)
        all four filter layers.

        Documents denied on any layer are excluded from the result.  Documents
        that receive REQUIRES_HUMAN_REVIEW on any layer are included, as that
        decision does not constitute a denial.
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

    def filter_documents_with_audit(
        self,
        context: LatAmContext,
        documents: List[LatAmDocument],
    ) -> LatAmAuditRecord:
        """
        Evaluate all documents and return a LatAmAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support
        multi-jurisdiction compliance auditing.
        """
        documents_out = 0
        all_decisions: List[dict] = []

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
                if result.decision == "REQUIRES_HUMAN_REVIEW" and final_decision == "APPROVED":
                    final_decision = "REQUIRES_HUMAN_REVIEW"

            if allow:
                documents_out += 1

            all_decisions.append(
                {
                    "document_id": doc.document_id,
                    "final_decision": final_decision,
                    "layer_results": layer_results,
                }
            )

        return LatAmAuditRecord(
            event="LATAM_RAG_RETRIEVAL",
            user_id=context.user_id,
            jurisdiction=context.jurisdiction,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )
