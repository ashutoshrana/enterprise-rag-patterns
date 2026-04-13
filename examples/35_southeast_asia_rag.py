"""
Southeast Asia RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating in the Southeast Asian data-protection regulatory
environment.  Four independent filter layers run sequentially; a document
must pass all four to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | HR and payroll management platforms (Thailand)           | Thailand PDPA B.E. 2562 (2019)           |
  | Healthcare data systems (Indonesia)                      | Indonesia UU PDP No. 27/2022             |
  | E-government portals (Vietnam)                           | Vietnam Decree 13/2023 on Personal Data  |
  | Fintech credit platforms (multi-jurisdiction)            | PDPA / UU PDP / Decree 13               |
  | Cross-border B2B data exchange platforms                 | ASEAN Data Governance Framework          |
  | EdTech platforms serving SEA markets                     | PDPA §20 / UU PDP Art. 20               |
  | Telemedicine platforms operating in TH/ID/VN             | PDPA §19 / UU PDP Art. 20               |
  | IoT data-aggregation platforms                           | Vietnam Cybersecurity Law No. 24/2018    |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — ThailandPDPAFilter (Thailand PDPA B.E. 2562 (2019))
      Controls access to personal data under Thailand's Personal Data
      Protection Act, the primary data protection statute in Thailand.

      §19 prohibits collection, use, or disclosure of sensitive personal
      data — including health data, biometric data, and racial/ethnic origin —
      without explicit consent from the data subject.  Sensitive data
      processing without explicit consent is denied at this layer.

      §20 requires parental consent before processing personal data belonging
      to minors.  Processing data of a minor without parental consent is denied.

      §24 requires that personal data be collected only with consent or a
      recognised legitimate interest.  Requests lacking both triggers a denial
      unless the requesting party is the data subject themselves.

      §30 grants data subjects the right to access their own personal data at
      any time, independent of any consent or legitimate-interest requirement.
      Data-subject self-access requests are approved immediately.

  Layer 2 — IndonesiaPDPFilter (Indonesia UU PDP No. 27/2022)
      Controls access to personal data under Indonesia's Personal Data
      Protection Law, enacted October 2022 and in full effect from 2024.

      Art. 20 requires explicit consent before processing sensitive personal
      data, defined to include health/medical data, financial information,
      and biometric data.  Processing without explicit consent is denied.

      Art. 16 establishes that all personal-data processing requires a valid
      legal basis: consent, contractual necessity, legitimate interest,
      vital interest, or public task.  Processing without a legal basis is
      denied.

      Art. 34 requires that data subjects retain the right to human
      intervention in automated decisions that significantly affect them.
      Automated decisions without a human-review pathway are escalated,
      not denied, so the pipeline continues with a REQUIRES_HUMAN_REVIEW
      flag.

      Data subjects accessing their own data are approved immediately under
      the data-subject rights provisions of UU PDP.

  Layer 3 — VietnamCybersecurityFilter
      (Vietnam Cybersecurity Law No. 24/2018 + Decree 13/2023)
      Controls access under Vietnam's data-protection framework, combining
      the overarching Cybersecurity Law with the dedicated personal-data
      protection Decree issued under it.

      Decree 13/2023 Art. 8 identifies categories of sensitive personal data
      — including health, biometric, political views, and sexual orientation —
      and requires explicit consent before processing.  Processing sensitive
      data without consent is denied.

      Decree 13/2023 Art. 5 establishes consent as the primary legal basis
      for personal-data processing in Vietnam.  Non-data-subject, non-regulator
      requests lacking consent are denied.

      The Cybersecurity Law grants regulatory authorities full access to
      data for lawful enforcement purposes; regulator-role requests are
      approved immediately.

  Layer 4 — SEAsiaCrossBorderFilter (ASEAN Data Governance Framework)
      Enforces cross-border data transfer requirements applicable to
      data transfers originating in Thailand, Indonesia, or Vietnam.

      Cross-border transfers within the ASEAN adequate-jurisdiction set
      (TH, ID, VN, SG, MY, PH) satisfy adequacy requirements under each
      jurisdiction's framework and are approved.

      Transfers to countries outside the adequate set are permitted when the
      controller has implemented a recognised transfer mechanism (standard
      contractual clauses, binding corporate rules, or approved codes of
      conduct).

      Transfers to non-adequate destinations without a transfer mechanism
      are denied with jurisdiction-specific citations:
        - Thailand source: PDPA §28
        - Indonesia source: UU PDP Art. 50
        - Vietnam source: Decree 13/2023 Art. 25
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SEAsiaContext:
    """
    Carries all per-request attributes needed by the four SEAsia filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    jurisdiction is a 2-letter ISO country code for the governing law:
        "TH" (Thailand), "ID" (Indonesia), "VN" (Vietnam)

    role describes the requesting party's position:
        "data_controller", "data_processor", "data_subject", "regulator"
    """

    user_id: str
    jurisdiction: str               # "TH", "ID", "VN"
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


@dataclass(frozen=True)
class SEAsiaDocument:
    """
    Immutable document descriptor carrying all attributes needed for SEAsia
    compliance evaluation across the four filter layers.

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
# Layer 1: ThailandPDPAFilter — Thailand PDPA B.E. 2562 (2019)
# ---------------------------------------------------------------------------

class ThailandPDPAFilter:
    """
    Enforces Thailand Personal Data Protection Act B.E. 2562 (2019) for
    access to personal data held or processed by controllers operating in
    Thailand or processing data of Thai data subjects.

    §19 restricts collection, use, or disclosure of sensitive personal data
    (health, biometric, racial/ethnic origin, political opinion, and related
    categories) to situations where the data subject has given explicit consent.
    Processing sensitive data without explicit consent is denied.

    §20 requires that controllers obtain verifiable parental or guardian
    consent before processing personal data belonging to minors.  Processing
    a minor's data without parental consent is denied.

    §24 establishes the lawful bases for collecting personal data: consent
    or legitimate interest (among others).  Requests that satisfy neither
    basis — unless submitted by the data subject — are denied.

    §30 grants data subjects the right to access their own personal data
    without restriction.  Data-subject role requests are approved immediately.
    """

    LAYER_NAME = "THAILAND_PDPA"

    def evaluate(self, context: SEAsiaContext, document: SEAsiaDocument) -> FilterResult:
        """
        Evaluate Thailand PDPA requirements.

        Evaluation order:
          1. Sensitive data + no explicit consent (§19) — DENIED.
          2. Minor's data + no parental consent (§20) — DENIED.
          3. Data subject self-access (§30) — APPROVED immediately.
          4. No consent and no legitimate interest (§24) — DENIED.
          5. Otherwise — APPROVED.
        """
        # §19: Sensitive personal data requires explicit consent.
        if context.involves_sensitive_data and not context.has_explicit_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Thailand PDPA §19: Sensitive personal data requires "
                    "explicit consent"
                ),
                regulation_citation="Thailand PDPA B.E. 2562 (2019) §19",
            )

        # §20: Minor's data requires parental consent.
        if context.involves_minor and not context.has_parental_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Thailand PDPA §20: Processing data of minors requires "
                    "parental consent"
                ),
                regulation_citation="Thailand PDPA B.E. 2562 (2019) §20",
            )

        # §30: Data subjects have an unconditional right of access to their own data.
        if context.role == "data_subject":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Thailand PDPA §30: Data subjects have right of access to own data",
                regulation_citation="Thailand PDPA B.E. 2562 (2019) §30",
            )

        # §24: Personal data collection requires consent or legitimate interest.
        if not context.has_explicit_consent and not context.has_legitimate_interest:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Thailand PDPA §24: Personal data collection requires "
                    "consent or legitimate interest"
                ),
                regulation_citation="Thailand PDPA B.E. 2562 (2019) §24",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Thailand PDPA access check passed",
            regulation_citation="Thailand PDPA B.E. 2562 (2019)",
        )


# ---------------------------------------------------------------------------
# Layer 2: IndonesiaPDPFilter — Indonesia UU PDP No. 27/2022
# ---------------------------------------------------------------------------

class IndonesiaPDPFilter:
    """
    Enforces Indonesia Personal Data Protection Law (UU PDP) No. 27/2022
    for access to personal data processed by controllers operating in
    Indonesia or processing data of Indonesian data subjects.

    Art. 20 defines categories of sensitive personal data — including health,
    financial, biometric, and genetic data — and requires explicit consent
    before any processing.  Processing sensitive data without consent is denied.

    Art. 16 establishes the lawful bases for personal-data processing.
    Processing without a recognised legal basis (consent, contractual
    necessity, legitimate interest, vital interest, or public task) is denied.

    Art. 34 grants data subjects the right to object to fully automated
    decisions that significantly affect them and to request human intervention.
    Automated decisions without a human-review pathway trigger escalation to
    human oversight, but are not denied outright.

    Data subjects accessing their own data are approved immediately under the
    data-subject access rights of UU PDP.
    """

    LAYER_NAME = "INDONESIA_UU_PDP"

    def evaluate(self, context: SEAsiaContext, document: SEAsiaDocument) -> FilterResult:
        """
        Evaluate Indonesia UU PDP requirements.

        Evaluation order:
          1. Sensitive data + no explicit consent (Art. 20) — DENIED.
          2. Data subject self-access — APPROVED immediately.
          3. No consent and no legitimate interest (Art. 16) — DENIED.
          4. Automated decision + no human review (Art. 34) — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — APPROVED.
        """
        # Art. 20: Sensitive personal data requires explicit consent.
        if context.involves_sensitive_data and not context.has_explicit_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Indonesia UU PDP Art. 20: Sensitive personal data requires "
                    "explicit consent"
                ),
                regulation_citation="Indonesia UU PDP No. 27/2022 Art. 20",
            )

        # Data subjects may access their own data without further restriction.
        if context.role == "data_subject":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Indonesia UU PDP: Data subject access rights apply",
                regulation_citation="Indonesia UU PDP No. 27/2022",
            )

        # Art. 16: Processing requires a valid legal basis.
        if not context.has_explicit_consent and not context.has_legitimate_interest:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Indonesia UU PDP Art. 16: Personal data processing requires "
                    "legal basis"
                ),
                regulation_citation="Indonesia UU PDP No. 27/2022 Art. 16",
            )

        # Art. 34: Automated decisions require human intervention option.
        if context.is_automated_decision and not context.has_human_review:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Indonesia UU PDP Art. 34: Automated decisions require "
                    "human intervention option"
                ),
                regulation_citation="Indonesia UU PDP No. 27/2022 Art. 34",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Indonesia UU PDP access check passed",
            regulation_citation="Indonesia UU PDP No. 27/2022",
        )


# ---------------------------------------------------------------------------
# Layer 3: VietnamCybersecurityFilter
#          Vietnam Cybersecurity Law No. 24/2018 + Decree 13/2023
# ---------------------------------------------------------------------------

class VietnamCybersecurityFilter:
    """
    Enforces Vietnam's data-protection framework, combining the Cybersecurity
    Law No. 24/2018 with Decree 13/2023 on Personal Data Protection, for
    access to personal data of Vietnamese data subjects.

    Decree 13/2023 Art. 8 identifies sensitive personal data categories —
    health, biometric, political views, religious beliefs, sexual orientation,
    and criminal history — and requires explicit consent before processing.
    Sensitive data processing without consent is denied.

    Decree 13/2023 Art. 5 establishes consent of the data subject as the
    primary legal basis for all personal-data processing in Vietnam.
    Non-data-subject, non-regulator requests without consent are denied.

    The Cybersecurity Law grants competent regulatory authorities full access
    to data for cybersecurity enforcement and investigation purposes.
    Regulator-role requests are approved immediately.
    """

    LAYER_NAME = "VIETNAM_CYBERSECURITY_DECREE_13"

    def evaluate(self, context: SEAsiaContext, document: SEAsiaDocument) -> FilterResult:
        """
        Evaluate Vietnam Cybersecurity Law and Decree 13/2023 requirements.

        Evaluation order:
          1. Sensitive data + no explicit consent (Decree 13 Art. 8) — DENIED.
          2. Regulator role — APPROVED immediately (Cybersecurity Law).
          3. No consent + non-data-subject + non-regulator (Decree 13 Art. 5) — DENIED.
          4. Otherwise — APPROVED.
        """
        # Decree 13 Art. 8: Sensitive personal data requires explicit consent.
        if context.involves_sensitive_data and not context.has_explicit_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Vietnam Decree 13/2023 Art. 8: Sensitive personal data "
                    "requires explicit consent"
                ),
                regulation_citation="Vietnam Decree 13/2023 Art. 8",
            )

        # Cybersecurity Law: Regulatory access is permitted without restriction.
        if context.role == "regulator":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Vietnam Cybersecurity Law: Regulatory access permitted",
                regulation_citation="Vietnam Cybersecurity Law No. 24/2018",
            )

        # Decree 13 Art. 5: Processing requires data-subject consent.
        if (
            not context.has_explicit_consent
            and context.role != "data_subject"
            and context.role != "regulator"
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Vietnam Decree 13/2023 Art. 5: Processing requires consent "
                    "of data subject"
                ),
                regulation_citation="Vietnam Decree 13/2023 Art. 5",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Vietnam data protection access check passed",
            regulation_citation="Vietnam Decree 13/2023 on Personal Data Protection",
        )


# ---------------------------------------------------------------------------
# Layer 4: SEAsiaCrossBorderFilter — ASEAN Data Governance Framework
# ---------------------------------------------------------------------------

class SEAsiaCrossBorderFilter:
    """
    Enforces cross-border personal-data transfer requirements applicable to
    transfers originating in Thailand, Indonesia, or Vietnam.

    The ASEAN Data Governance Framework recognises member states with
    comparable data protection regimes as adequate destinations.  Transfers
    within the adequate set are approved without additional safeguards.

    Transfers to non-adequate countries are permitted when the data controller
    has implemented a recognised transfer mechanism: standard contractual
    clauses, binding corporate rules, or an approved code of conduct.

    Transfers to non-adequate destinations without a recognised mechanism
    are denied with jurisdiction-specific citations:
      - Thailand source (PDPA §28): adequate protection required
      - Indonesia source (UU PDP Art. 50): adequate protection required
      - Vietnam source (Decree 13/2023 Art. 25): MOIC approval required

    Jurisdiction-agnostic sources receive a generic ASEAN denial.
    """

    LAYER_NAME = "SEASIA_CROSS_BORDER"

    _ADEQUATE_COUNTRIES = frozenset({"TH", "ID", "VN", "SG", "MY", "PH"})

    def evaluate(self, context: SEAsiaContext, document: SEAsiaDocument) -> FilterResult:
        """
        Evaluate cross-border transfer requirements.

        Evaluation order:
          1. No transfer involved — APPROVED immediately.
          2. Destination is in the adequate set — APPROVED (ASEAN adequacy).
          3. Transfer mechanism present — APPROVED (contractual safeguards).
          4. No mechanism — jurisdiction-specific DENIED.
        """
        # No cross-border transfer: layer does not apply.
        if not context.is_cross_border_transfer:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="No cross-border transfer involved",
                regulation_citation="ASEAN Data Governance Framework",
            )

        # Destination country satisfies adequacy.
        if context.destination_country in self._ADEQUATE_COUNTRIES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    "ASEAN Data Governance Framework: adequate jurisdiction"
                ),
                regulation_citation="ASEAN Data Governance Framework",
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
                regulation_citation="ASEAN Data Governance Framework",
            )

        # No mechanism — deny with jurisdiction-specific citation.
        if context.jurisdiction == "TH":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Thailand PDPA §28: Cross-border transfer requires "
                    "adequate protection"
                ),
                regulation_citation="Thailand PDPA B.E. 2562 (2019) §28",
            )

        if context.jurisdiction == "ID":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Indonesia UU PDP Art. 50: Cross-border transfer requires "
                    "adequate protection"
                ),
                regulation_citation="Indonesia UU PDP No. 27/2022 Art. 50",
            )

        if context.jurisdiction == "VN":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Vietnam Decree 13/2023 Art. 25: Cross-border transfer "
                    "requires MOIC approval"
                ),
                regulation_citation="Vietnam Decree 13/2023 Art. 25",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="DENIED",
            reason=(
                "SEAsia: Cross-border transfer requires adequate safeguards "
                "or mechanism"
            ),
            regulation_citation="ASEAN Data Governance Framework",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class SEAsiaAuditRecord:
    """
    Captures the full decision trail for a Southeast Asia RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - Thailand PDPA audit and data-subject rights obligations.
      - Indonesia UU PDP record-keeping requirements.
      - Vietnam Decree 13/2023 data-processing activity records.
      - ASEAN cross-border transfer documentation requirements.

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

class SEAsiaRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms
    operating in the Southeast Asian data-protection regulatory environment.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do not
    stop the pipeline — those documents are included in the result set but
    flagged for human oversight.  Only documents that receive a DENIED result
    from any layer are excluded from the returned set.

    Layers in order:
      1. ThailandPDPAFilter         — PDPA B.E. 2562 §19/§20/§24/§30
      2. IndonesiaPDPFilter         — UU PDP No. 27/2022 Art. 16/20/34
      3. VietnamCybersecurityFilter — Cybersecurity Law + Decree 13/2023
      4. SEAsiaCrossBorderFilter    — ASEAN Data Governance Framework

    Audit records are generated for every retrieval event regardless of
    outcome, providing a complete access trail for multi-jurisdiction
    regulatory audits.
    """

    def __init__(self) -> None:
        self._layers = [
            ThailandPDPAFilter(),
            IndonesiaPDPFilter(),
            VietnamCybersecurityFilter(),
            SEAsiaCrossBorderFilter(),
        ]

    def filter_documents(
        self,
        context: SEAsiaContext,
        documents: List[SEAsiaDocument],
    ) -> List[SEAsiaDocument]:
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
        context: SEAsiaContext,
        documents: List[SEAsiaDocument],
    ) -> SEAsiaAuditRecord:
        """
        Evaluate all documents and return a SEAsiaAuditRecord summarising
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

        return SEAsiaAuditRecord(
            event="SEASIA_RAG_RETRIEVAL",
            user_id=context.user_id,
            jurisdiction=context.jurisdiction,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )
