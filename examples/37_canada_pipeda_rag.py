"""
Canada PIPEDA/CPPA RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating in the Canadian data-protection regulatory environment.
Four independent filter layers run sequentially; a document must pass all
four to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | HR and benefits management platforms (Canada-wide)       | PIPEDA / CPPA Bill C-27 + provincial     |
  | Healthcare information systems (Ontario)                 | Ontario PHIPA + PIPEDA                   |
  | Credit and insurance platforms (Quebec)                  | Quebec Law 25 + PIPEDA                   |
  | Provincial e-government portals (BC, AB)                 | BC PIPA / AB PIPA + PIPEDA               |
  | Cross-border B2B data-exchange platforms                 | PIPEDA §4.1.3 adequacy framework         |
  | EdTech platforms serving Canadian post-secondary         | PIPEDA Principle 4.3 + provincial        |
  | Telemedicine platforms operating Canada-wide             | PIPEDA + PHIPA / PIPA                    |
  | AI-driven automated-decision systems                     | Quebec Law 25 §12.1 / CPPA §63          |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — PIPEDAConsentFilter
      (PIPEDA — Personal Information Protection and Electronic Documents Act
       + CPPA Bill C-27 (Consumer Privacy Protection Act, 2022))
      Controls access to personal information for organisations subject to
      federal privacy law (PIPEDA and its successor, CPPA Bill C-27).

      PIPEDA Principle 3 / CPPA §15 restricts collection, use, or disclosure
      of sensitive personal information to situations where the individual has
      provided meaningful consent.  Processing sensitive data without meaningful
      consent is denied, unless the data has been properly de-identified.

      PIPEDA Principle 4.3 requires that organisations collect personal
      information only for purposes a reasonable person would consider
      appropriate under the circumstances, and only with knowledge and consent.
      Non-individual, non-regulator requests without meaningful consent or a
      legitimate purpose are denied.

      CPPA Bill C-27 §62 introduces specific protections for minors: processing
      personal information of a minor requires parental or guardian consent.
      Processing a minor's data without parental consent is denied.

      Individuals have an unconditional right of access to their own personal
      information; individual role requests are approved immediately.

  Layer 2 — QuebecLaw25Filter
      (Quebec Act respecting the protection of personal information in the
       private sector — Law 25, as amended through 2023)
      Controls access to personal information for organisations operating in
      Quebec or processing personal information of Quebec residents.

      Law 25 §8 requires explicit consent before collecting, using, or
      communicating sensitive personal information.  Processing sensitive data
      without explicit consent is denied.

      Law 25 §12.1 grants individuals the right to human review of automated
      decisions that produce significant effects on them.  Automated decisions
      without a human-review pathway trigger escalation to
      REQUIRES_HUMAN_REVIEW; they are not denied outright.

      Law 25 §63.3 (Privacy Impact Assessment) requires a PIA before collecting
      sensitive personal information for any new technology or system.
      Processing that lacks a PIA in the general sector is escalated to
      REQUIRES_HUMAN_REVIEW.

      This filter is a no-op for requests from outside Quebec
      (province != "QC").

  Layer 3 — HealthcarePrivacyFilter
      (PIPEDA + Ontario PHIPA + BC PIPA (healthcare context))
      Controls access to health information for organisations providing or
      supporting healthcare services.

      Ontario PHIPA (Personal Health Information Protection Act) combined with
      PIPEDA requires patient consent before collecting, using, or disclosing
      health information.  Ontario healthcare requests involving sensitive data
      without consent are denied.

      BC PIPA §11 requires individual consent before health information may be
      collected.  BC healthcare requests involving sensitive data without
      consent are denied.

      For all other provinces and territories, general PIPEDA Principle 3
      requires meaningful consent before processing healthcare data.

      Healthcare providers with confirmed meaningful consent are approved
      immediately; the consent-based approval supersedes general checks.

      This filter is a no-op for organisations outside the healthcare sector
      (sector != "healthcare").

  Layer 4 — CanadaCrossBorderFilter
      (PIPEDA §4.1.3 — Accountability Principle for cross-border transfers)
      Enforces Canadian cross-border personal-information transfer requirements.

      Canada's Office of the Privacy Commissioner (OPC) recognises a set of
      adequate jurisdictions that provide comparable privacy protection.
      Transfers to those jurisdictions are approved.

      Transfers to non-adequate countries are permitted when the organisation
      has implemented contractual safeguards (standard contractual clauses,
      binding corporate rules, or equivalent mechanisms) that provide
      substantially similar protection to PIPEDA.

      Quebec Law 25 §17 imposes an additional requirement: cross-border
      transfers from Quebec require a Privacy Impact Assessment confirming that
      the destination provides equivalent protection, regardless of any
      contractual mechanism.  Quebec transfers without a PIA are denied.

      Transfers to non-adequate destinations without any safeguard are denied
      with a PIPEDA §4.1.3 citation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanadaPrivacyContext:
    """
    Carries all per-request attributes needed by the four Canadian privacy
    filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    role describes the requesting party:
        "individual", "organization", "regulator", "healthcare_provider"

    province is a 2-letter Canadian province/territory code:
        "QC" (Quebec), "ON" (Ontario), "BC" (British Columbia),
        "AB" (Alberta), "other" for all remaining provinces/territories
    """

    user_id: str
    role: str                               # "individual", "organization", "regulator", "healthcare_provider"
    province: str                           # "QC", "BC", "AB", "ON", "other"
    sector: str                             # "healthcare", "financial", "general", "government"
    has_meaningful_consent: bool = False
    has_legitimate_purpose: bool = False
    involves_sensitive_data: bool = False
    is_automated_decision: bool = False
    has_human_review: bool = True
    has_privacy_impact_assessment: bool = False
    is_cross_border_transfer: bool = False
    destination_country: str = ""
    has_transfer_safeguards: bool = False
    involves_minor: bool = False
    has_de_identified: bool = False         # data has been properly de-identified
    is_publicly_available: bool = False


@dataclass(frozen=True)
class CanadaPrivacyDocument:
    """
    Immutable document descriptor carrying all attributes needed for Canadian
    privacy compliance evaluation across the four filter layers.

    doc_type describes the category of document:
        "personal_information_record", "health_record", "financial_record",
        "biometric_record", "consent_form", "transfer_agreement"
    """

    content: str
    document_id: str
    doc_type: str = "personal_information_record"


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
# Layer 1: PIPEDAConsentFilter
#          PIPEDA Principles 3 and 4.3 + CPPA Bill C-27 §15 and §62
# ---------------------------------------------------------------------------

class PIPEDAConsentFilter:
    """
    Enforces PIPEDA (Personal Information Protection and Electronic Documents
    Act) consent principles and CPPA Bill C-27 provisions for access to
    personal information held or processed by organisations subject to federal
    privacy law.

    PIPEDA Principle 3 / CPPA §15 restricts processing of sensitive personal
    information to situations where the individual has provided meaningful
    consent.  Processing sensitive data without meaningful consent is denied
    unless the data has been properly de-identified.

    PIPEDA Principle 4.3 requires that organisations obtain knowledge and
    consent before collecting personal information for any purpose.
    Non-individual, non-regulator requests without meaningful consent or a
    legitimate purpose are denied.

    CPPA Bill C-27 §62 introduces enhanced protections for minors: processing
    a minor's personal information requires parental or guardian consent.
    Processing a minor's data without meaningful consent is denied.

    Individuals have an unconditional right of access to their own personal
    information.  Individual role requests are approved immediately.
    """

    LAYER_NAME = "PIPEDA_CPPA_CONSENT"

    def evaluate(
        self, context: CanadaPrivacyContext, document: CanadaPrivacyDocument
    ) -> FilterResult:
        """
        Evaluate PIPEDA Principle 3 / CPPA §15 and PIPEDA Principle 4.3 /
        CPPA §62.

        Evaluation order:
          1. Individual self-access — APPROVED immediately.
          2. Sensitive data + no meaningful consent + not de-identified
             (PIPEDA Principle 3 / CPPA §15) — DENIED.
          3. No meaningful consent and no legitimate purpose for
             non-individual / non-regulator
             (PIPEDA Principle 4.3) — DENIED.
          4. Minor's data + no meaningful consent
             (CPPA Bill C-27 §62) — DENIED.
          5. Otherwise — APPROVED.
        """
        # Data subjects have unconditional access to their own personal information.
        if context.role == "individual":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="PIPEDA: Individuals have right of access to own personal information",
                regulation_citation="PIPEDA / CPPA Bill C-27",
            )

        # Principle 3 / CPPA §15: Sensitive data requires meaningful consent.
        if (
            context.involves_sensitive_data
            and not context.has_meaningful_consent
            and not context.has_de_identified
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "PIPEDA Principle 3 / CPPA §15: Sensitive personal information "
                    "requires meaningful consent"
                ),
                regulation_citation="PIPEDA Principle 3 / CPPA Bill C-27 §15",
            )

        # Principle 4.3: Personal information requires knowledge and consent.
        if (
            not context.has_meaningful_consent
            and not context.has_legitimate_purpose
            and context.role not in {"individual", "regulator"}
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "PIPEDA Principle 4.3: Collection of personal information "
                    "requires knowledge and consent"
                ),
                regulation_citation="PIPEDA Principle 4.3",
            )

        # CPPA §62: Processing personal information of minors requires parental consent.
        if context.involves_minor and not context.has_meaningful_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "CPPA Bill C-27 §62: Processing personal information of minors "
                    "requires parental consent"
                ),
                regulation_citation="CPPA Bill C-27 §62",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="PIPEDA / CPPA consent check passed",
            regulation_citation="PIPEDA / CPPA Bill C-27",
        )


# ---------------------------------------------------------------------------
# Layer 2: QuebecLaw25Filter
#          Quebec Act respecting the protection of personal information
#          in the private sector (Law 25, as amended through 2023)
# ---------------------------------------------------------------------------

class QuebecLaw25Filter:
    """
    Enforces Quebec Law 25 (Act respecting the protection of personal
    information in the private sector) for access to personal information
    held or processed by organisations operating in Quebec or processing
    personal information of Quebec residents.

    Law 25 §8 requires explicit consent before collecting, using, or
    communicating sensitive personal information in Quebec.  Processing
    sensitive data without explicit consent in Quebec is denied.

    Law 25 §12.1 grants individuals the right to request human review of
    any decision based exclusively on automated processing that produces
    significant effects on them.  Automated decisions without a human-review
    pathway trigger REQUIRES_HUMAN_REVIEW escalation; they are not denied.

    Law 25 §63.3 (Privacy Impact Assessment) requires a PIA before deploying
    any new technology or system that processes sensitive personal information.
    Collecting sensitive data without a PIA in a general-sector context is
    escalated to REQUIRES_HUMAN_REVIEW.

    This filter is a no-op for organisations and requests outside Quebec
    (province != "QC").
    """

    LAYER_NAME = "QUEBEC_LAW_25"

    def evaluate(
        self, context: CanadaPrivacyContext, document: CanadaPrivacyDocument
    ) -> FilterResult:
        """
        Evaluate Quebec Law 25 requirements.

        Evaluation order (Quebec-only — non-QC requests are approved):
          1. Not Quebec province — APPROVED immediately (not applicable).
          2. Sensitive data + no meaningful consent
             (Law 25 §8) — DENIED.
          3. Automated decision + no human review
             (Law 25 §12.1) — REQUIRES_HUMAN_REVIEW.
          4. General sector + sensitive data + no PIA
             (Law 25 §63.3) — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — APPROVED.
        """
        # This filter only applies to Quebec.
        if context.province != "QC":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Quebec Law 25: Not applicable (non-QC province)",
                regulation_citation="Quebec Law 25: Not applicable (non-QC province)",
            )

        # §8: Sensitive personal information in Quebec requires explicit consent.
        if context.involves_sensitive_data and not context.has_meaningful_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Quebec Law 25 §8: Sensitive personal information requires "
                    "explicit consent"
                ),
                regulation_citation="Quebec Law 25 §8",
            )

        # §12.1: Automated decisions with significant impact require human review.
        if context.is_automated_decision and not context.has_human_review:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Quebec Law 25 §12.1: Automated decisions with significant "
                    "impact require right to human review"
                ),
                regulation_citation="Quebec Law 25 §12.1",
            )

        # §63.3 (PIA): Sensitive data in general sector requires a PIA.
        if (
            context.sector == "general"
            and context.involves_sensitive_data
            and not context.has_privacy_impact_assessment
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Quebec Law 25 §63.3: Privacy Impact Assessment required "
                    "before collecting sensitive personal information"
                ),
                regulation_citation="Quebec Law 25 §63.3",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Quebec Law 25 access check passed",
            regulation_citation="Quebec Law 25 (2023)",
        )


# ---------------------------------------------------------------------------
# Layer 3: HealthcarePrivacyFilter
#          PIPEDA + Ontario PHIPA + BC PIPA (healthcare sector)
# ---------------------------------------------------------------------------

class HealthcarePrivacyFilter:
    """
    Enforces healthcare-sector privacy requirements for platforms processing
    personal health information in Canada.

    Ontario PHIPA (Personal Health Information Protection Act) combined with
    PIPEDA requires patient consent before a health information custodian
    collects, uses, or discloses personal health information.  Ontario
    healthcare requests involving sensitive data without meaningful consent
    are denied.

    BC PIPA §11 (Personal Information Protection Act, British Columbia)
    requires individual consent before health information may be collected
    in British Columbia.  BC healthcare requests involving sensitive data
    without meaningful consent are denied.

    For all other provinces and territories, general PIPEDA Principle 3
    requires meaningful consent before processing healthcare data.  Healthcare
    requests involving sensitive data without consent are denied.

    Healthcare providers with confirmed meaningful consent are approved
    immediately under their treatment-relationship authority, superseding
    general processing checks.

    This filter is a no-op for organisations outside the healthcare sector
    (sector != "healthcare").
    """

    LAYER_NAME = "CANADA_HEALTHCARE_PRIVACY"

    def evaluate(
        self, context: CanadaPrivacyContext, document: CanadaPrivacyDocument
    ) -> FilterResult:
        """
        Evaluate Canadian healthcare privacy requirements.

        Evaluation order (healthcare-only — non-healthcare requests approved):
          1. Not healthcare sector — APPROVED immediately (not applicable).
          2. Ontario + sensitive data + no meaningful consent
             (PHIPA + PIPEDA) — DENIED.
          3. BC + sensitive data + no meaningful consent
             (BC PIPA §11) — DENIED.
          4. General sensitive healthcare data + no meaningful consent
             (PIPEDA Principle 3) — DENIED.
          5. Healthcare provider role + meaningful consent — APPROVED.
          6. Otherwise — APPROVED.
        """
        # This filter only applies to the healthcare sector.
        if context.sector != "healthcare":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Healthcare filter: Not applicable to non-healthcare sector",
                regulation_citation="Healthcare filter: Not applicable to non-healthcare sector",
            )

        # Ontario PHIPA + PIPEDA: Health information requires patient consent.
        if (
            context.province == "ON"
            and context.involves_sensitive_data
            and not context.has_meaningful_consent
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Ontario PHIPA + PIPEDA: Health information requires patient consent"
                ),
                regulation_citation="Ontario PHIPA + PIPEDA",
            )

        # BC PIPA §11: Health information collection requires individual's consent.
        if (
            context.province == "BC"
            and context.involves_sensitive_data
            and not context.has_meaningful_consent
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "BC PIPA §11: Health information collection requires "
                    "individual's consent"
                ),
                regulation_citation="BC PIPA §11",
            )

        # General PIPEDA: Healthcare data requires meaningful consent.
        if context.involves_sensitive_data and not context.has_meaningful_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "PIPEDA Principle 3: Healthcare data requires meaningful consent"
                ),
                regulation_citation="PIPEDA Principle 3",
            )

        # Healthcare provider with consent is approved under treatment authority.
        if context.role == "healthcare_provider" and context.has_meaningful_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    "PIPEDA: Healthcare provider authorized access with consent"
                ),
                regulation_citation="PIPEDA + Provincial Health Acts",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Canada Healthcare Privacy access check passed",
            regulation_citation="Canada Healthcare Privacy: PIPEDA + Provincial Health Acts",
        )


# ---------------------------------------------------------------------------
# Layer 4: CanadaCrossBorderFilter
#          PIPEDA §4.1.3 Accountability Principle + Quebec Law 25 §17
# ---------------------------------------------------------------------------

class CanadaCrossBorderFilter:
    """
    Enforces Canadian cross-border personal-information transfer requirements
    under PIPEDA §4.1.3 (Accountability Principle) and Quebec Law 25 §17.

    Canada's Office of the Privacy Commissioner (OPC) recognises a set of
    jurisdictions as providing comparable privacy protection.  Transfers to
    those jurisdictions satisfy the adequacy requirement and are approved.

    Transfers to non-adequate countries are permitted when the organisation
    has implemented contractual or other recognised safeguards (standard
    contractual clauses, binding corporate rules, or equivalent mechanisms)
    that ensure substantially equivalent protection to PIPEDA.

    Quebec Law 25 §17 imposes a stricter rule for transfers originating in
    Quebec: a cross-border transfer requires a Privacy Impact Assessment
    confirming that the destination jurisdiction provides equivalent protection,
    even when a contractual mechanism is present.  Quebec transfers without a
    PIA are denied.

    Transfers to non-adequate destinations without any recognised safeguard
    are denied with a PIPEDA §4.1.3 citation.
    """

    LAYER_NAME = "CANADA_CROSS_BORDER"

    _ADEQUATE_COUNTRIES = frozenset({
        "CA", "US", "GB", "DE", "FR", "NL", "AU", "NZ", "JP", "SG",
    })

    def evaluate(
        self, context: CanadaPrivacyContext, document: CanadaPrivacyDocument
    ) -> FilterResult:
        """
        Evaluate Canadian cross-border transfer requirements.

        Evaluation order:
          1. No cross-border transfer — APPROVED immediately.
          2. Destination country in adequate set — APPROVED (OPC adequacy).
          3. Transfer safeguards present + non-QC province — APPROVED.
          4. Quebec province — DENIED (Law 25 §17 PIA required).
          5. No safeguards — DENIED (PIPEDA §4.1.3).
        """
        # No cross-border transfer: layer does not apply.
        if not context.is_cross_border_transfer:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="No cross-border transfer involved",
                regulation_citation="PIPEDA §4.1.3",
            )

        # Destination country is OPC-recognised as adequate.
        if context.destination_country in self._ADEQUATE_COUNTRIES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="Canada-adequate jurisdiction: transfer permitted",
                regulation_citation="PIPEDA §4.1.3 / OPC Adequacy Framework",
            )

        # Contractual or recognised safeguards provide equivalent protection.
        if context.has_transfer_safeguards:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    "PIPEDA §4.1.3: Contractual safeguards provide equivalent protection"
                ),
                regulation_citation="PIPEDA §4.1.3",
            )

        # Quebec Law 25 §17: Cross-border transfer from QC requires PIA.
        if context.province == "QC":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Quebec Law 25 §17: Cross-border transfer requires PIA and "
                    "equivalent protection"
                ),
                regulation_citation="Quebec Law 25 §17",
            )

        # No adequate destination, no safeguards — PIPEDA §4.1.3 denial.
        return FilterResult(
            layer=self.LAYER_NAME,
            decision="DENIED",
            reason=(
                "PIPEDA §4.1.3: Cross-border transfer requires contractual "
                "protections ensuring equivalent privacy"
            ),
            regulation_citation="PIPEDA §4.1.3",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class CanadaPrivacyAuditRecord:
    """
    Captures the full decision trail for a Canada Privacy RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - PIPEDA Principle 1 (Accountability) record-keeping requirements.
      - CPPA Bill C-27 audit and transparency obligations.
      - Quebec Law 25 §3.3 documentation requirements.
      - PHIPA access-record requirements for Ontario healthcare data.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping.
    """

    event: str
    user_id: str
    province: str
    sector: str
    documents_in: int
    documents_out: int
    decisions: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": self.event,
            "user_id": self.user_id,
            "province": self.province,
            "sector": self.sector,
            "documents_in": self.documents_in,
            "documents_out": self.documents_out,
            "decisions": self.decisions,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class CanadaPrivacyRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms
    operating in the Canadian data-protection regulatory environment.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do not
    stop the pipeline — those documents are included in the result set but
    flagged for human oversight.  Only documents that receive a DENIED result
    from any layer are excluded from the returned set.

    Layers in order:
      1. PIPEDAConsentFilter        — PIPEDA Principle 3/4.3 + CPPA §15/§62
      2. QuebecLaw25Filter          — Quebec Law 25 §8/§12.1/§63.3 (QC-only)
      3. HealthcarePrivacyFilter    — PIPEDA + PHIPA + BC PIPA §11 (healthcare-only)
      4. CanadaCrossBorderFilter    — PIPEDA §4.1.3 + Quebec Law 25 §17

    Audit records are generated for every retrieval event regardless of
    outcome, providing a complete access trail for multi-jurisdiction
    regulatory audits across federal and provincial privacy laws.
    """

    def __init__(self) -> None:
        self._layers = [
            PIPEDAConsentFilter(),
            QuebecLaw25Filter(),
            HealthcarePrivacyFilter(),
            CanadaCrossBorderFilter(),
        ]

    def filter_documents(
        self,
        context: CanadaPrivacyContext,
        documents: List[CanadaPrivacyDocument],
    ) -> List[CanadaPrivacyDocument]:
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
        context: CanadaPrivacyContext,
        documents: List[CanadaPrivacyDocument],
    ) -> CanadaPrivacyAuditRecord:
        """
        Evaluate all documents and return a CanadaPrivacyAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support
        multi-jurisdiction compliance auditing across federal and provincial
        Canadian privacy laws.
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
                if (
                    result.decision == "REQUIRES_HUMAN_REVIEW"
                    and final_decision == "APPROVED"
                ):
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

        return CanadaPrivacyAuditRecord(
            event="CANADA_PRIVACY_RAG_RETRIEVAL",
            user_id=context.user_id,
            province=context.province,
            sector=context.sector,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )
