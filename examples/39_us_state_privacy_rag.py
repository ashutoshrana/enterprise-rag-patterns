"""
US State Privacy Laws RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms subject to US state-level consumer privacy laws.  Four
independent filter layers run sequentially; a document must pass all
four to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | Consumer data analytics platforms                        | Colorado CPA — CRS §6-1-1301 et seq.     |
  | Ad-tech and targeted advertising systems                 | Virginia CDPA — Va. Code §59.1-571       |
  | Data brokerage and resale platforms                      | Texas TDPSA — Tex. Bus. & Com. Code §541 |
  | Multi-state SaaS consumer applications                   | CTDPA — Conn. PA 22-15                   |
  | Healthcare AI assistants (non-HIPAA scope)               | CPA / CDPA / TDPSA sensitive-data rules  |
  | Biometric identification and access control systems      | CPA §6-1-1303(19); CDPA §59.1-578(A)    |
  | Precision location and geofencing platforms              | TDPSA §541.101; CPA §6-1-1303(19)       |
  | Automated decision-making and profiling engines          | CDPA §59.1-579; CTDPA §14               |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — ColoradoCPAFilter
      (Colorado Privacy Act
       CRS §6-1-1301 et seq., effective July 1, 2023)
      Controls access to documents containing personal data subject to
      the Colorado Privacy Act.  The CPA grants Colorado consumers rights
      to access, correct, delete, and port their personal data, and
      imposes consent, opt-out, and data minimisation obligations on
      controllers and processors.

      CRS §6-1-1303(19) defines a broad "sensitive data" category
      encompassing biometric, health, precise geolocation, racial or
      ethnic origin, sexual orientation, citizenship, and similar data.
      Processing sensitive data without consumer consent is denied.

      CRS §6-1-1306(1)(a)(IV) requires controllers to offer consumers an
      opt-out right before using personal data for automated profiling in
      connection with consequential decisions.  Automated profiling without
      an opt-out mechanism is escalated to REQUIRES_HUMAN_REVIEW.

      CRS §6-1-1306(1)(a)(III) prohibits selling personal data without
      offering consumers an opt-out right.  Sale-of-data documents without
      an opt-out mechanism are denied.

  Layer 2 — VirginiaVCDPAFilter
      (Virginia Consumer Data Protection Act
       Va. Code §59.1-571 et seq., effective January 1, 2023)
      Controls access to documents containing personal data subject to
      Virginia's CDPA (also referred to as the VCDPA).  The CDPA grants
      Virginia consumers rights to access, correct, delete, port, and opt
      out of certain uses of their personal data.

      Va. Code §59.1-578(A) requires affirmative opt-in consent before a
      controller may process sensitive data.  Sensitive data categories
      include biometric, health, precise geolocation, racial or ethnic
      origin, religious beliefs, sexual orientation, citizenship, and
      mental health data.  Processing sensitive data without opt-in consent
      is denied.

      Va. Code §59.1-579 requires controllers that process personal data
      for automated decisions with legal or similarly significant effects
      to provide consumers with a right to appeal and, if requested, to
      obtain human review.  Automated decision pipelines with significant
      effects that lack human review availability are escalated to
      REQUIRES_HUMAN_REVIEW.

      Va. Code §59.1-578(A)(3) prohibits processing personal data for
      targeted advertising without offering consumers an opt-out right.
      Targeted advertising without an opt-out mechanism is denied.

  Layer 3 — TexasTDPSAFilter
      (Texas Data Privacy and Security Act
       Tex. Bus. & Com. Code §541 et seq., effective July 1, 2024)
      Controls access to documents containing personal data subject to
      the Texas TDPSA.  Texas extends comprehensive consumer privacy
      rights including access, correction, deletion, portability, and
      opt-out rights for sale, targeted advertising, and profiling.

      Tex. Bus. & Com. Code §541.101 requires express consent before
      processing sensitive personal data.  Sensitive categories include
      biometric, health, precise geolocation, racial or ethnic origin,
      religious beliefs, sexual orientation, citizenship, and mental
      health data.  Processing sensitive data without consent is denied.

      §541.052(a)(2) prohibits selling sensitive data without offering
      consumers an opt-out right.  Sale-of-data documents for sensitive
      data categories without an opt-out mechanism are denied.

      §541.101(b) prohibits processing the personal data of consumers
      known to be under age thirteen without verifiable parental consent.
      Documents flagged for minor data processing are denied.

  Layer 4 — USStatePrivacyCrossBorderFilter
      (Cross-state applicability of US state privacy laws
       CCPA Cal. Civ. Code §1798.100; CRS §6-1-1302; Va. Code §59.1-572;
       Tex. Bus. & Com. Code §541.002; Conn. PA 22-15)
      Controls cross-state data flows involving consumers from multiple
      US jurisdictions, applying the most protective applicable state law
      to each consumer's data.

      California's CCPA (as amended by the CPRA) requires CCPA compliance
      for personal data of California residents regardless of where the
      controller is located.  Documents involving California consumer data
      without confirmed CCPA compliance are denied.

      Colorado, Virginia, Texas, and Connecticut state privacy laws all
      impose consent requirements for sensitive and biometric data that
      travel across state lines.  Documents involving sensitive or biometric
      data from residents of those states without state-specific consent
      are denied.

      Connecticut's Act Concerning Personal Data Privacy and Online
      Monitoring (Conn. PA 22-15) §14 requires controllers that use
      automated decision-making for consequential purposes to offer
      Connecticut consumers an opt-out right.  Automated decision pipelines
      involving Connecticut consumers without an opt-out mechanism are
      escalated to REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class USStatePrivacyContext:
    """
    Carries all per-request attributes needed by the four US state privacy
    law filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    role describes the requesting entity:
        "data_controller", "data_processor", "consumer", "admin",
        "analytics_platform", "ad_tech_platform"

    All boolean flags default to False to enforce a deny-by-default posture;
    callers must explicitly set flags that grant access.
    """

    user_id: str
    role: str = "data_controller"

    # Layer 1 — Colorado CPA
    # (also re-used by Layers 2–4 for data-type checks)
    data_type: str = ""  # "sensitive", "biometric", "health",
    # "precise_geolocation", "racial_origin",
    # "sexual_orientation", "citizenship",
    # "racial_ethnic", "religious",
    # "mental_health", "standard"
    opt_out_offered: bool = False
    automated_profiling: bool = False
    sale_of_data: bool = False

    # Layer 2 — Virginia CDPA
    automated_decision: bool = False
    legal_or_significant_effect: bool = False
    human_review_available: bool = False
    targeted_advertising: bool = False

    # Layer 3 — Texas TDPSA
    minor_data: bool = False

    # Layer 4 — Cross-border / multi-state
    consumer_state: str = ""  # "California", "Colorado", "Virginia",
    # "Texas", "Connecticut", or other
    ccpa_compliant: bool = False
    state_consent_obtained: bool = False


@dataclass(frozen=True)
class USStatePrivacyDocument:
    """
    Immutable document descriptor carrying all attributes needed for US
    state privacy law compliance evaluation across the four filter layers.

    doc_type describes the category of document:
        "consumer_profile", "biometric_record", "health_record",
        "location_record", "ad_targeting_record", "analytics_record",
        "automated_decision_record", "sale_record", "minor_data_record"
    """

    content: str
    document_id: str
    doc_type: str = "consumer_profile"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: str  # "APPROVED", "DENIED", "REQUIRES_HUMAN_REVIEW"
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
# Layer 1: ColoradoCPAFilter
#          Colorado Privacy Act
#          CRS §6-1-1301 et seq., effective July 1, 2023
# ---------------------------------------------------------------------------


class ColoradoCPAFilter:
    """
    Enforces Colorado Privacy Act (CPA) requirements under CRS §6-1-1301
    et seq., effective July 1, 2023.

    The CPA grants Colorado consumers rights to access, correct, delete,
    and port their personal data, and imposes consent, opt-out, and data
    minimisation obligations on controllers and processors that conduct
    business in Colorado or produce products or services targeted to
    Colorado residents.

    CRS §6-1-1303(19) defines sensitive data broadly to include biometric
    identifiers, health data, precise geolocation, racial or ethnic origin,
    sexual orientation, citizenship or immigration status, and similar
    categories.  Processing sensitive data without consumer consent is
    denied under the CPA's opt-in consent requirement for sensitive data.

    CRS §6-1-1306(1)(a)(IV) requires controllers to offer consumers an
    opt-out right before using personal data for automated profiling in
    connection with decisions that produce legal or similarly significant
    effects.  Automated profiling pipelines that lack an opt-out mechanism
    are escalated to REQUIRES_HUMAN_REVIEW.

    CRS §6-1-1306(1)(a)(III) prohibits the sale of personal data without
    offering consumers an opt-out right.  Sale-of-data documents that
    lack an opt-out mechanism are denied.

    Documents that do not trigger any of the above conditions are approved
    under the general CPA compliance framework.
    """

    LAYER_NAME = "COLORADO_CPA"

    _SENSITIVE_DATA_TYPES = frozenset(
        {
            "sensitive",
            "biometric",
            "health",
            "precise_geolocation",
            "racial_origin",
            "sexual_orientation",
            "citizenship",
        }
    )

    def evaluate(self, context: USStatePrivacyContext, document: USStatePrivacyDocument) -> FilterResult:
        """
        Evaluate Colorado CPA requirements under CRS §6-1-1301 et seq.

        Evaluation order:
          1. Sensitive data type (§6-1-1303(19)) — DENIED.
          2. Automated profiling without opt-out (§6-1-1306(1)(a)(IV))
             — REQUIRES_HUMAN_REVIEW.
          3. Sale of personal data without opt-out (§6-1-1306(1)(a)(III))
             — DENIED.
          4. Otherwise — APPROVED under CRS §6-1-1301.
        """
        # §6-1-1303(19): Sensitive data requires opt-in consent.
        if context.data_type in self._SENSITIVE_DATA_TYPES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=("Colorado CPA CRS §6-1-1303(19): Sensitive data requires consent before processing"),
                regulation_citation="CRS §6-1-1303(19)",
            )

        # §6-1-1306(1)(a)(IV): Automated profiling for consequential decisions
        # requires an opt-out right.
        if context.automated_profiling and not context.opt_out_offered:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Colorado CPA CRS §6-1-1306(1)(a)(IV): Automated profiling for "
                    "consequential decisions requires opt-out right — human review required"
                ),
                regulation_citation="CRS §6-1-1306(1)(a)(IV)",
            )

        # §6-1-1306(1)(a)(III): Sale of personal data requires opt-out right.
        if context.sale_of_data and not context.opt_out_offered:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Colorado CPA CRS §6-1-1306(1)(a)(III): Sale of personal data "
                    "requires opt-out right — opt-out not offered"
                ),
                regulation_citation="CRS §6-1-1306(1)(a)(III)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="CRS §6-1-1301 Colorado Privacy Act — compliant",
            regulation_citation="CRS §6-1-1301",
        )


# ---------------------------------------------------------------------------
# Layer 2: VirginiaVCDPAFilter
#          Virginia Consumer Data Protection Act
#          Va. Code §59.1-571 et seq., effective January 1, 2023
# ---------------------------------------------------------------------------


class VirginiaVCDPAFilter:
    """
    Enforces Virginia Consumer Data Protection Act (CDPA / VCDPA) requirements
    under Va. Code §59.1-571 et seq., effective January 1, 2023.

    The CDPA applies to persons that conduct business in Virginia or produce
    products or services targeted to Virginia residents and that control or
    process personal data of at least 100,000 Virginia consumers annually,
    or derive more than fifty percent of gross revenue from the sale of
    personal data and control or process the data of at least 25,000 consumers.

    Va. Code §59.1-578(A) requires affirmative opt-in consent before a
    controller may process sensitive data.  Sensitive data under the CDPA
    includes biometric, health, precise geolocation, racial or ethnic origin,
    religious beliefs, sexual orientation, citizenship, and mental health data.
    Processing sensitive data without opt-in consent is denied.

    Va. Code §59.1-579 requires controllers that process personal data for
    automated decisions with legal or similarly significant effects to provide
    consumers with the right to obtain human review of such decisions.
    Automated decision pipelines with significant effects that do not make
    human review available are escalated to REQUIRES_HUMAN_REVIEW.

    Va. Code §59.1-578(A)(3) prohibits processing personal data for targeted
    advertising without offering consumers an opt-out right.  Targeted
    advertising without an opt-out mechanism is denied.

    Documents that do not trigger any of the above conditions are approved
    under the general CDPA compliance framework.
    """

    LAYER_NAME = "VIRGINIA_VCDPA"

    _SENSITIVE_DATA_TYPES = frozenset(
        {
            "sensitive",
            "biometric",
            "health",
            "precise_geolocation",
            "racial_ethnic",
            "religious",
            "sexual_orientation",
            "citizenship",
            "mental_health",
        }
    )

    def evaluate(self, context: USStatePrivacyContext, document: USStatePrivacyDocument) -> FilterResult:
        """
        Evaluate Virginia CDPA requirements under Va. Code §59.1-571 et seq.

        Evaluation order:
          1. Sensitive data type (§59.1-578(A)) — DENIED.
          2. Automated decision with significant effect and no human review
             (§59.1-579) — REQUIRES_HUMAN_REVIEW.
          3. Targeted advertising without opt-out (§59.1-578(A)(3)) — DENIED.
          4. Otherwise — APPROVED under Va. Code §59.1-571 VCDPA.
        """
        # §59.1-578(A): Sensitive data requires opt-in consent.
        if context.data_type in self._SENSITIVE_DATA_TYPES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Virginia CDPA Va. Code §59.1-578(A): Sensitive data requires opt-in consent before processing"
                ),
                regulation_citation="Va. Code §59.1-578(A)",
            )

        # §59.1-579: Automated decisions with legal or significant effects
        # require human review availability.
        if context.automated_decision and context.legal_or_significant_effect and not context.human_review_available:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Virginia CDPA Va. Code §59.1-579: Automated decisions with "
                    "legal or similarly significant effects require human review right"
                ),
                regulation_citation="Va. Code §59.1-579",
            )

        # §59.1-578(A)(3): Targeted advertising requires opt-out right.
        if context.targeted_advertising and not context.opt_out_offered:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Virginia CDPA Va. Code §59.1-578(A)(3): Targeted advertising "
                    "requires opt-out right — opt-out not offered"
                ),
                regulation_citation="Va. Code §59.1-578(A)(3)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Va. Code §59.1-571 VCDPA — compliant",
            regulation_citation="Va. Code §59.1-571",
        )


# ---------------------------------------------------------------------------
# Layer 3: TexasTDPSAFilter
#          Texas Data Privacy and Security Act
#          Tex. Bus. & Com. Code §541 et seq., effective July 1, 2024
# ---------------------------------------------------------------------------


class TexasTDPSAFilter:
    """
    Enforces Texas Data Privacy and Security Act (TDPSA) requirements under
    Tex. Bus. & Com. Code §541 et seq., effective July 1, 2024.

    The TDPSA applies to persons that conduct business in Texas or produce
    products or services consumed by Texas residents and that process or
    engage in the sale of personal data.  The TDPSA notably removes minimum
    consumer thresholds, making it broader in scope than comparable state laws.

    Tex. Bus. & Com. Code §541.101 requires express consent before processing
    sensitive personal data.  Sensitive data under the TDPSA includes biometric,
    health, precise geolocation, racial or ethnic origin, religious beliefs,
    sexual orientation, citizenship, and mental health data.  Processing
    sensitive data without consent is denied.

    §541.052(a)(2) prohibits selling personal data of any category without
    offering consumers an opt-out right.  Sale-of-data documents for sensitive
    data categories without an opt-out mechanism are denied.

    §541.101(b) prohibits processing the personal data of consumers known to
    be under age thirteen without verifiable parental consent, consistent with
    COPPA obligations.  Documents flagged for minor data processing are denied.

    Documents that do not trigger any of the above conditions are approved
    under the general TDPSA compliance framework.
    """

    LAYER_NAME = "TEXAS_TDPSA"

    _SENSITIVE_DATA_TYPES = frozenset(
        {
            "sensitive",
            "biometric",
            "health",
            "precise_geolocation",
            "racial_ethnic",
            "religious",
            "sexual_orientation",
            "citizenship",
            "mental_health",
        }
    )

    def evaluate(self, context: USStatePrivacyContext, document: USStatePrivacyDocument) -> FilterResult:
        """
        Evaluate Texas TDPSA requirements under Tex. Bus. & Com. Code §541.

        Evaluation order:
          1. Sensitive data type (§541.101) — DENIED.
          2. Sale of data without opt-out (§541.052(a)(2)) — DENIED.
          3. Minor data processing (§541.101(b)) — DENIED.
          4. Otherwise — APPROVED under Tex. Bus. & Com. Code §541.
        """
        # §541.101: Sensitive data requires express consent.
        if context.data_type in self._SENSITIVE_DATA_TYPES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Texas TDPSA Tex. Bus. & Com. Code §541.101: Sensitive data requires consent before processing"
                ),
                regulation_citation="Tex. Bus. & Com. Code §541.101",
            )

        # §541.052(a)(2): Sale of personal data requires opt-out right.
        if context.sale_of_data and not context.opt_out_offered:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=("Texas TDPSA §541.052(a)(2): Sale of sensitive data opt-out required — opt-out not offered"),
                regulation_citation="§541.052(a)(2)",
            )

        # §541.101(b): Processing data of consumers under 13 requires parental consent.
        if context.minor_data:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Texas TDPSA §541.101(b): Processing data of consumers under 13 "
                    "prohibited without verifiable parental consent"
                ),
                regulation_citation="§541.101(b)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Tex. Bus. & Com. Code §541 TDPSA — compliant",
            regulation_citation="Tex. Bus. & Com. Code §541",
        )


# ---------------------------------------------------------------------------
# Layer 4: USStatePrivacyCrossBorderFilter
#          Cross-state applicability of US state privacy laws
#          CCPA Cal. Civ. Code §1798.140; CRS §6-1-1302; Va. Code §59.1-572;
#          Tex. Bus. & Com. Code §541.002; Conn. PA 22-15
# ---------------------------------------------------------------------------


class USStatePrivacyCrossBorderFilter:
    """
    Enforces cross-state applicability of US consumer privacy laws under
    CCPA Cal. Civ. Code §1798.140, CRS §6-1-1302, Va. Code §59.1-572,
    Tex. Bus. & Com. Code §541.002, and Conn. PA 22-15.

    Each US state privacy law applies based on consumer residency rather
    than controller location.  Controllers must apply the law of the
    consumer's home state to that consumer's data, regardless of where
    the data is processed or stored.  This filter layer evaluates the
    consumer's state of residence and applies the most relevant state
    compliance check.

    California's CCPA (Cal. Civ. Code §1798.100 et seq., as amended by
    the CPRA) applies to personal data of California residents.  Documents
    involving California consumer data without confirmed CCPA compliance
    are denied.  California privacy rights include access, deletion,
    correction, portability, and opt-out of sale, sharing, and sensitive
    data processing.

    Colorado, Virginia, Texas, and Connecticut state privacy laws all
    require state-specific consent for processing sensitive or biometric
    data of residents.  Documents involving sensitive or biometric data
    from residents of those states without confirmed state-specific consent
    are denied.

    Connecticut's Act Concerning Personal Data Privacy and Online Monitoring
    (Conn. PA 22-15) §14 requires controllers that use personal data for
    automated decision-making for consequential purposes to offer Connecticut
    consumers an opt-out right.  Automated decision pipelines involving
    Connecticut consumers without an opt-out mechanism are escalated to
    REQUIRES_HUMAN_REVIEW.

    Documents that do not trigger any of the above conditions are approved
    with a multi-state privacy compliance citation.
    """

    LAYER_NAME = "US_STATE_CROSS_BORDER"

    _STATE_SENSITIVE_TYPES = frozenset({"sensitive", "biometric"})
    _CONSENT_REQUIRED_STATES = frozenset({"Colorado", "Virginia", "Texas", "Connecticut"})

    def evaluate(self, context: USStatePrivacyContext, document: USStatePrivacyDocument) -> FilterResult:
        """
        Evaluate cross-state US privacy law applicability.

        Evaluation order:
          1. California consumer data without CCPA compliance
             (Cal. Civ. Code §1798.100) — DENIED.
          2. Sensitive/biometric data from CPA/CDPA/TDPSA/CTDPA states
             without state consent (CRS §6-1-1302; Va. Code §59.1-572;
             Tex. §541.002; Conn. PA 22-15) — DENIED.
          3. Connecticut consumer with automated decision and no opt-out
             (Conn. PA 22-15 §14) — REQUIRES_HUMAN_REVIEW.
          4. Otherwise — APPROVED under multi-state privacy framework.
        """
        # Cal. Civ. Code §1798.100: CCPA compliance required for CA residents.
        if context.consumer_state == "California" and not context.ccpa_compliant:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "California CCPA Cal. Civ. Code §1798.100: CCPA compliance "
                    "required for California residents — compliance not confirmed"
                ),
                regulation_citation="Cal. Civ. Code §1798.100",
            )

        # State-specific consent for sensitive/biometric data.
        if (
            context.consumer_state in self._CONSENT_REQUIRED_STATES
            and context.data_type in self._STATE_SENSITIVE_TYPES
            and not context.state_consent_obtained
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    f"State privacy law: State-specific consent required for "
                    f"sensitive data processing for {context.consumer_state} residents "
                    f"under applicable state privacy law"
                ),
                regulation_citation=(
                    "State-specific consent required for sensitive data under applicable state privacy law"
                ),
            )

        # Conn. PA 22-15 §14: Connecticut automated decision opt-out required.
        if context.consumer_state == "Connecticut" and context.automated_decision and not context.opt_out_offered:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Connecticut CTDPA Conn. PA 22-15 §14: Automated decision "
                    "opt-out required for Connecticut residents — opt-out not offered"
                ),
                regulation_citation="Conn. PA 22-15 §14",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Multi-state privacy compliance — CPA/VCDPA/TDPSA/CTDPA",
            regulation_citation="CCPA §1798.140; CRS §6-1-1302; Va. Code §59.1-572; Tex. §541.002",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------


@dataclass
class USStatePrivacyAuditRecord:
    """
    Captures the full decision trail for a US State Privacy RAG retrieval
    event.

    This record should be persisted to an immutable audit log to satisfy:
      - Colorado CPA data-processing record-keeping obligations.
      - Virginia CDPA controller accountability requirements.
      - Texas TDPSA data protection assessment documentation.
      - Connecticut CTDPA records of processing activities.
      - CCPA/CPRA audit and compliance verification obligations.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping purposes.
    """

    event: str
    user_id: str
    role: str
    data_type: str
    consumer_state: str
    documents_in: int
    documents_out: int
    decisions: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": self.event,
            "user_id": self.user_id,
            "role": self.role,
            "data_type": self.data_type,
            "consumer_state": self.consumer_state,
            "documents_in": self.documents_in,
            "documents_out": self.documents_out,
            "decisions": self.decisions,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class USStatePrivacyRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms subject
    to US state consumer privacy laws.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do
    not stop the pipeline — those documents are included in the result set
    but flagged for human oversight.  Only documents that receive a DENIED
    result from any layer are excluded from the returned set.

    Layers in order:
      1. ColoradoCPAFilter             — CRS §6-1-1303(19); §6-1-1306(1)(a)(III)/(IV)
      2. VirginiaVCDPAFilter           — Va. Code §59.1-578(A); §59.1-579; §59.1-578(A)(3)
      3. TexasTDPSAFilter              — Tex. §541.101; §541.052(a)(2); §541.101(b)
      4. USStatePrivacyCrossBorderFilter — Cal. Civ. Code §1798.100; CRS §6-1-1302;
                                          Va. Code §59.1-572; Tex. §541.002; Conn. PA 22-15

    Audit records are generated for every retrieval event regardless of
    outcome, providing a complete access trail for state AG enforcement,
    FTC oversight, and internal data protection assessments.
    """

    def __init__(self) -> None:
        self._layers = [
            ColoradoCPAFilter(),
            VirginiaVCDPAFilter(),
            TexasTDPSAFilter(),
            USStatePrivacyCrossBorderFilter(),
        ]

    def filter_documents(
        self,
        context: USStatePrivacyContext,
        documents: list[USStatePrivacyDocument],
    ) -> list[USStatePrivacyDocument]:
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
        context: USStatePrivacyContext,
        documents: list[USStatePrivacyDocument],
    ) -> USStatePrivacyAuditRecord:
        """
        Evaluate all documents and return a USStatePrivacyAuditRecord
        summarising the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support state AG
        enforcement and internal compliance audit obligations.
        """
        documents_out = 0
        all_decisions: list[dict] = []

        for doc in documents:
            layer_results: list[dict] = []
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

        return USStatePrivacyAuditRecord(
            event="US_STATE_PRIVACY_RAG_RETRIEVAL",
            user_id=context.user_id,
            role=context.role,
            data_type=context.data_type,
            consumer_state=context.consumer_state,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("US State Privacy Laws RAG Pipeline — Demo")
    print("=" * 70)

    pipeline = USStatePrivacyRAGPipeline()

    # ------------------------------------------------------------------
    # Demo 1: Colorado CPA blocks sensitive data without consent (§6-1-1303(19))
    # ------------------------------------------------------------------
    print("\n[Demo 1] Colorado CPA blocks biometric data processing (CRS §6-1-1303(19))")
    ctx_cpa = USStatePrivacyContext(
        user_id="analytics-sys",
        role="analytics_platform",
        data_type="biometric",  # sensitive category — requires consent
    )
    doc_cpa = USStatePrivacyDocument(
        content="Employee biometric access record",
        document_id="bio-doc-001",
        doc_type="biometric_record",
    )
    cpa_result = ColoradoCPAFilter().evaluate(ctx_cpa, doc_cpa)
    print(f"  Decision : {cpa_result.decision}")
    print(f"  Reason   : {cpa_result.reason}")
    print(f"  Citation : {cpa_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 2: Virginia CDPA blocks targeted advertising without opt-out
    # ------------------------------------------------------------------
    print("\n[Demo 2] Virginia CDPA blocks targeted advertising without opt-out (§59.1-578(A)(3))")
    ctx_vcdpa = USStatePrivacyContext(
        user_id="ad-platform-001",
        role="ad_tech_platform",
        targeted_advertising=True,
        opt_out_offered=False,
    )
    doc_vcdpa = USStatePrivacyDocument(
        content="Consumer ad targeting profile",
        document_id="ad-doc-001",
        doc_type="ad_targeting_record",
    )
    vcdpa_result = VirginiaVCDPAFilter().evaluate(ctx_vcdpa, doc_vcdpa)
    print(f"  Decision : {vcdpa_result.decision}")
    print(f"  Reason   : {vcdpa_result.reason}")
    print(f"  Citation : {vcdpa_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 3: Texas TDPSA blocks minor data processing (§541.101(b))
    # ------------------------------------------------------------------
    print("\n[Demo 3] Texas TDPSA blocks minor data processing (§541.101(b))")
    ctx_tdpsa = USStatePrivacyContext(
        user_id="data-collector-001",
        role="data_controller",
        minor_data=True,
    )
    doc_tdpsa = USStatePrivacyDocument(
        content="Child consumer profile",
        document_id="minor-doc-001",
        doc_type="minor_data_record",
    )
    tdpsa_result = TexasTDPSAFilter().evaluate(ctx_tdpsa, doc_tdpsa)
    print(f"  Decision : {tdpsa_result.decision}")
    print(f"  Reason   : {tdpsa_result.reason}")
    print(f"  Citation : {tdpsa_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 4: Cross-border blocks California consumer data without CCPA
    # ------------------------------------------------------------------
    print("\n[Demo 4] Cross-border blocks CA consumer without CCPA compliance (§1798.100)")
    ctx_cross = USStatePrivacyContext(
        user_id="platform-001",
        role="data_controller",
        consumer_state="California",
        ccpa_compliant=False,
    )
    doc_cross = USStatePrivacyDocument(
        content="California consumer personal data record",
        document_id="ca-doc-001",
        doc_type="consumer_profile",
    )
    cross_result = USStatePrivacyCrossBorderFilter().evaluate(ctx_cross, doc_cross)
    print(f"  Decision : {cross_result.decision}")
    print(f"  Reason   : {cross_result.reason}")
    print(f"  Citation : {cross_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 5: Full pipeline — compliant standard-data request passes all layers
    # ------------------------------------------------------------------
    print("\n[Demo 5] Full pipeline — compliant standard data request passes all layers")
    ctx_compliant = USStatePrivacyContext(
        user_id="crm-sys-001",
        role="data_controller",
        data_type="standard",
        opt_out_offered=True,
        sale_of_data=False,
        automated_profiling=False,
        targeted_advertising=False,
        minor_data=False,
        consumer_state="",
        ccpa_compliant=True,
        state_consent_obtained=True,
    )
    docs_compliant = [
        USStatePrivacyDocument(
            content="Standard consumer contact record",
            document_id=f"standard-{i}",
            doc_type="consumer_profile",
        )
        for i in range(3)
    ]
    passed = pipeline.filter_documents(ctx_compliant, docs_compliant)
    print(f"  Documents in  : {len(docs_compliant)}")
    print(f"  Documents out : {len(passed)}")
    print(f"  All passed    : {len(passed) == len(docs_compliant)}")

    print("\n" + "=" * 70)
    print("Demo complete.")
    print("=" * 70)
