"""
US Healthcare AI RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
AI platforms subject to US healthcare regulations governing Software as a
Medical Device (SaMD), electronic health record interoperability, CMS payer
rules, and cross-border protected health information (PHI) transfers.  Four
independent filter layers run sequentially; a document must pass all four
to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | AI-assisted clinical decision support systems            | FDA 21 CFR Part 820; SaMD Guidance       |
  | AI/ML-based Software as a Medical Device (SaMD)         | FDA AI/ML Action Plan 2021; 21 CFR §814  |
  | EHR-integrated RAG and AI analytics platforms           | ONC 21st Century Cures Act 45 CFR §170   |
  | Patient data access and interoperability platforms       | ONC Information Blocking Rule 45 CFR §171|
  | CMS-regulated health plan AI systems                     | CMS Final Rule 85 FR 25510               |
  | AI-assisted prior authorization platforms                | CMS Prior Auth Rule 88 FR 82510          |
  | Medicare Advantage AI coverage determination systems     | CMS Medicare Advantage AI policy         |
  | Cross-border PHI transfer and analytics platforms        | HIPAA 45 CFR §164; FDA MedWatch 21 CFR   |
  | EU-US health data exchange platforms                     | EU Health Data Space Regulation 2024     |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — FDASaMDFilter
      (FDA Software as a Medical Device guidance; 21 CFR Part 820 Quality
       Management System; FDA AI/ML Action Plan 2021; 21st Century Cures
       Act §3060, enacted December 13, 2016)
      Controls access to documents involving AI/ML-based Software as a
      Medical Device (SaMD) requiring FDA premarket review, quality
      management system documentation, and predetermined change control
      plans for adaptive algorithms.

      21 CFR §814.1 (Premarket Approval — PMA): Class III SaMD presents the
      highest risk of patient harm and requires FDA Premarket Approval (PMA)
      before clinical deployment.  Documents involving Class III or Class IIb
      SaMD without confirmed PMA are denied.

      21 CFR §807.87 (510(k) Premarket Notification): Class II SaMD requires
      FDA 510(k) clearance demonstrating substantial equivalence to a
      predicate device before clinical use.  Documents involving Class IIa or
      Class II SaMD without confirmed 510(k) clearance are denied.

      FDA AI/ML Action Plan 2021 (Predetermined Change Control Plan — PCCP):
      AI/ML-based SaMD that learns and adapts over time requires a
      Predetermined Change Control Plan (PCCP) documenting the types of
      modifications the algorithm may undergo and the associated performance
      boundaries.  Documents involving AI/ML SaMD without a confirmed PCCP
      are escalated to REQUIRES_HUMAN_REVIEW.

      21 CFR Part 820 (Quality Management System — QMS): All SaMD
      manufacturers must establish and maintain a Quality Management System
      (QMS) encompassing design controls, production and process controls,
      corrective and preventive actions (CAPA), and complaint handling.
      Documents involving any class of SaMD without confirmed QMS
      documentation are denied.

  Layer 2 — ONCCuresActFilter
      (ONC 21st Century Cures Act Final Rule — 45 CFR Part 170;
       ONC Information Blocking Rule — 45 CFR §171)
      Controls access to documents involving certified EHR technology and
      electronic health information (EHI) interoperability, information
      blocking prohibitions, patient data access rights, and AI-based
      clinical decision support transparency requirements.

      45 CFR §170.215 (HL7 FHIR R4 API): Certified EHR Technology (CEHRT)
      must support HL7 FHIR Release 4 (R4) APIs to enable patient and third-
      party access to electronic health information.  Documents involving EHR
      data without confirmed FHIR R4 compliance are denied.

      45 CFR §171.103 (Information Blocking Prohibition): Health IT
      developers, Health Information Networks/Exchanges (HIN/E), and
      providers are prohibited from engaging in practices that interfere with
      access, exchange, or use of electronic health information.  Violations
      carry civil monetary penalties up to $1 million per violation.
      Documents flagging information blocking are denied.

      45 CFR §171.301 (Patient Access Timeliness): Patient requests for
      access to their electronic health information must not be unreasonably
      delayed; information blocking exceptions require meeting strict
      conditions.  Documents flagging delayed patient data access without
      meeting an exception are denied.

      21st Century Cures Act §3060 (AI Clinical Decision Support
      Transparency): AI-based clinical decision support (CDS) tools must
      provide a transparent basis for recommendations, including the source,
      logic, and evidence underpinning any AI-generated clinical
      recommendation.  Documents involving EHR-integrated AI CDS without
      confirmed transparency documentation are escalated to
      REQUIRES_HUMAN_REVIEW.

  Layer 3 — CMSInteroperabilityFilter
      (CMS Interoperability and Patient Access Final Rule — 85 FR 25510;
       CMS Interoperability and Prior Authorization Final Rule — 88 FR 82510)
      Controls access to documents involving CMS-regulated payer Patient
      Access APIs, Provider Directory APIs, AI-assisted prior authorization,
      and AI-driven Medicare Advantage coverage determination systems.

      CMS Final Rule 85 FR 25510 (Patient Access API): CMS-regulated payers
      (MA, Medicaid, CHIP, QHP issuers) must implement a FHIR R4-based
      Patient Access API by July 1, 2021, giving members access to their
      claims, clinical, and formulary data.  Documents involving CMS-covered
      payers without a confirmed Patient Access API are denied.

      CMS Prior Authorization Rule 88 FR 82510 (Human Review Pathway):
      AI-assisted prior authorization decisions must include a human review
      pathway to ensure beneficiary protections and clinical appropriateness.
      Documents involving AI-generated prior authorization without a human
      review pathway are denied.

      CMS Final Rule 85 FR 25510 (Provider Directory API): CMS-regulated
      payers must also implement a FHIR R4-based Provider Directory API for
      provider lookup.  Documents involving CMS-covered payers without a
      confirmed Provider Directory API are escalated to
      REQUIRES_HUMAN_REVIEW.

      CMS Medicare Advantage AI Policy (Clinical Criteria for Coverage
      Determinations): AI-assisted coverage determinations in Medicare
      Advantage plans must be based on documented clinical criteria that
      align with CMS guidelines and the individual enrollee's circumstances.
      Documents involving Medicare Advantage AI coverage determinations
      without documented clinical criteria are denied.

  Layer 4 — HealthcareAICrossBorderFilter
      (HIPAA 45 CFR §164 — Privacy Rule; HIPAA 45 CFR §164.514(b) — Safe
       Harbor De-identification; FDA 21 CFR §803 — Medical Device Reporting;
       EU Health Data Space Regulation (EHDS) 2024)
      Controls cross-border PHI transfers, HIPAA authorization and TPO
      exceptions, sanctions screening for prohibited PHI destinations,
      FDA MedWatch adverse event reporting obligations, and EU Health Data
      Space secondary use authorization requirements.

      45 CFR §164.502 (HIPAA Minimum Necessary — PHI Disclosure): PHI
      disclosure requires valid patient authorization unless the disclosure
      is for treatment, payment, or health care operations (TPO).  Documents
      involving PHI without authorization or a TPO basis are denied.

      45 CFR §164.514(b) + HIPAA Safe Harbor: Transfer of PHI to
      jurisdictions without HIPAA-equivalent protections (Russia, China,
      Iran, North Korea) is prohibited.  Documents directing PHI to those
      jurisdictions are denied.

      21 CFR §803 (FDA MedWatch — Medical Device Adverse Event Reporting):
      Serious adverse events involving SaMD must be reported to FDA via
      MedWatch within 30 days of becoming aware of the event.  Documents
      flagging adverse events without a confirmed MedWatch report are
      escalated to REQUIRES_HUMAN_REVIEW.

      EU Health Data Space Regulation (EHDS) 2024: Cross-border secondary
      use of EU health data requires authorization under the EHDS secondary
      use framework.  Documents involving EU health data without confirmed
      EHDS compliance are escalated to REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HealthcareAIContext:
    """
    Carries all per-request attributes needed by the four US healthcare AI
    regulatory filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    institution_type describes the requesting healthcare entity:
        "hospital", "health_plan", "device_manufacturer", "ehr_vendor",
        "health_information_exchange", "clinical_lab", "general"

    All boolean flags default to False to enforce a deny-by-default posture;
    callers must explicitly set flags that grant access.
    """

    institution_type: str
    is_cms_covered_payer: bool = False
    has_fda_clearance: bool = False
    hipaa_covered_entity: bool = True


@dataclass(frozen=True)
class HealthcareAIDocument:
    """
    Immutable document descriptor carrying all attributes needed for US
    healthcare AI regulatory compliance evaluation across the four
    filter layers.

    data_classification describes the sensitivity level:
        "public", "internal", "confidential", "restricted", "general"

    clinical_context lists applicable clinical or regulatory contexts:
        ["samd", "ehr", "prior_auth", "clinical_decision_support", "phi"]
    """

    doc_id: str
    data_classification: str = "general"
    contains_phi: bool = False
    clinical_context: list = field(default_factory=list)

    # Layer 1 — FDA SaMD fields
    samd_class: str = ""
    fda_premarket_approval: bool = False
    fda_510k_cleared: bool = False
    ai_ml_samd: bool = False
    predetermined_change_control_plan: bool = False
    quality_management_system: bool = False

    # Layer 2 — ONC 21st Century Cures Act fields
    ehr_data: bool = False
    fhir_r4_compliant: bool = False
    information_blocking: bool = False
    patient_data_access_request: bool = False
    access_provided_within_timelimit: bool = False
    ai_clinical_decision_support: bool = False
    cds_transparency_documented: bool = False

    # Layer 3 — CMS Interoperability fields
    cms_covered_payer: bool = False
    patient_access_api_implemented: bool = False
    prior_authorization_required: bool = False
    ai_pa_decision: bool = False
    human_review_available: bool = False
    provider_directory_api: bool = False
    medicare_advantage: bool = False
    ai_coverage_determination: bool = False
    clinical_criteria_documented: bool = False

    # Layer 4 — Cross-border PHI fields
    phi: bool = False
    hipaa_authorization: bool = False
    treatment_payment_operations: bool = False
    destination_country: str = ""
    adverse_event: bool = False
    medwatch_report_filed: bool = False
    eu_health_data: bool = False
    ehds_compliant: bool = False


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
# Layer 1: FDASaMDFilter
#          FDA Software as a Medical Device (SaMD) guidance
#          21 CFR Part 820 — Quality Management System
#          FDA AI/ML Action Plan 2021
#          21st Century Cures Act §3060
# ---------------------------------------------------------------------------


class FDASaMDFilter:
    """
    Enforces FDA Software as a Medical Device (SaMD) regulatory requirements
    under 21 CFR Part 820, the FDA AI/ML Action Plan 2021, and the
    21st Century Cures Act §3060.

    21 CFR §814.1 (Premarket Approval — PMA): Class III and Class IIb SaMD
    presents the highest risk of patient harm; FDA Premarket Approval (PMA)
    is required before clinical deployment.  Documents involving high-risk
    SaMD without confirmed PMA are denied.

    21 CFR §807.87 (510(k) Premarket Notification): Class IIa and Class II
    SaMD requires FDA 510(k) clearance demonstrating substantial equivalence
    to a legally marketed predicate device.  Documents involving moderate-
    risk SaMD without confirmed 510(k) clearance are denied.

    FDA AI/ML Action Plan 2021 (Predetermined Change Control Plan — PCCP):
    AI/ML-based SaMD that adapts through learning requires a PCCP documenting
    the planned algorithm modifications and performance boundaries.  Documents
    involving AI/ML SaMD without a confirmed PCCP are escalated to
    REQUIRES_HUMAN_REVIEW.

    21 CFR Part 820 (Quality Management System — QMS): All SaMD manufacturers
    must maintain a QMS covering design controls, production controls, CAPA,
    and complaint handling.  Documents involving any class of SaMD without
    confirmed QMS documentation are denied.

    Documents that do not trigger any of the above conditions are approved
    under the general FDA SaMD regulatory framework.
    """

    LAYER_NAME = "FDA_SAMD"

    def evaluate(self, context: HealthcareAIContext, document: HealthcareAIDocument) -> FilterResult:
        """
        Evaluate FDA SaMD regulatory requirements under 21 CFR Part 820.

        Evaluation order:
          1. Class III/IIb SaMD without FDA PMA (21 CFR §814.1) — DENIED.
          2. Class IIa/II SaMD without FDA 510(k) clearance
             (21 CFR §807.87) — DENIED.
          3. AI/ML SaMD without PCCP (FDA AI/ML Action Plan 2021) —
             REQUIRES_HUMAN_REVIEW.
          4. Any SaMD class without QMS documentation
             (21 CFR Part 820) — DENIED.
          5. Otherwise — APPROVED under FDA SaMD regulatory framework.
        """
        # 21 CFR §814.1: Class III/IIb SaMD requires PMA before clinical
        # deployment.
        if document.samd_class in ("III", "IIb") and not document.fda_premarket_approval:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "21 CFR §814.1: Class III SaMD requires FDA Premarket Approval "
                    "(PMA) before clinical deployment"
                ),
                regulation_citation="21 CFR §814.1; 21 CFR Part 820",
            )

        # 21 CFR §807.87: Class IIa/II SaMD requires 510(k) clearance.
        if document.samd_class in ("IIa", "II") and not document.fda_510k_cleared:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "21 CFR §807.87: Class II SaMD requires FDA 510(k) clearance "
                    "before clinical use"
                ),
                regulation_citation="21 CFR §807.87; 21 CFR Part 807",
            )

        # FDA AI/ML Action Plan 2021: AI/ML-based SaMD requires PCCP.
        if document.ai_ml_samd and not document.predetermined_change_control_plan:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "FDA AI/ML Action Plan 2021: AI/ML-based SaMD requires predetermined "
                    "change control plan (PCCP) documenting algorithm modification boundaries"
                ),
                regulation_citation="FDA AI/ML Action Plan 2021; 21st Century Cures Act §3060",
            )

        # 21 CFR Part 820: All SaMD classes require a Quality Management System.
        if document.samd_class in ("III", "IIb", "IIa", "II") and not document.quality_management_system:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "21 CFR Part 820: SaMD manufacturers must maintain Quality Management "
                    "System documentation"
                ),
                regulation_citation="21 CFR Part 820",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="FDA SaMD regulatory framework 21 CFR Part 820 — compliant",
            regulation_citation="21 CFR Part 820; FDA AI/ML Action Plan 2021",
        )


# ---------------------------------------------------------------------------
# Layer 2: ONCCuresActFilter
#          ONC 21st Century Cures Act Final Rule — 45 CFR Part 170
#          ONC Information Blocking Rule — 45 CFR §171
# ---------------------------------------------------------------------------


class ONCCuresActFilter:
    """
    Enforces the ONC 21st Century Cures Act Final Rule (45 CFR Part 170) and
    the ONC Information Blocking Rule (45 CFR §171).

    45 CFR §170.215 (HL7 FHIR R4 API): Certified EHR Technology (CEHRT) must
    support HL7 FHIR Release 4 APIs enabling patient and third-party access
    to electronic health information.  Documents involving EHR data without
    confirmed FHIR R4 compliance are denied.

    45 CFR §171.103 (Information Blocking Prohibition): Health IT developers,
    Health Information Networks/Exchanges (HIN/E), and providers are
    prohibited from engaging in practices that unreasonably restrict access,
    exchange, or use of electronic health information.  Civil monetary
    penalties may reach $1 million per violation.  Documents flagging
    information blocking are denied.

    45 CFR §171.301 (Patient Access Timeliness): Patient requests for access
    to electronic health information must not be unreasonably delayed;
    information blocking exception conditions must be fully met.  Documents
    flagging delayed patient data access without an applicable exception
    are denied.

    21st Century Cures Act §3060 (AI CDS Transparency): AI-based clinical
    decision support tools must provide a transparent basis for
    recommendations.  Documents involving EHR-integrated AI CDS without
    confirmed transparency documentation are escalated to
    REQUIRES_HUMAN_REVIEW.

    Documents that do not trigger any of the above conditions are approved
    under the general ONC 21st Century Cures Act compliance framework.
    """

    LAYER_NAME = "ONC_CURES_ACT"

    def evaluate(self, context: HealthcareAIContext, document: HealthcareAIDocument) -> FilterResult:
        """
        Evaluate ONC 21st Century Cures Act and Information Blocking requirements.

        Evaluation order:
          1. EHR data without FHIR R4 compliance (45 CFR §170.215) — DENIED.
          2. Information blocking (45 CFR §171.103) — DENIED.
          3. Patient access request with delayed access
             (45 CFR §171.301) — DENIED.
          4. EHR + AI CDS without transparency documentation
             (21st Century Cures Act §3060) — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — APPROVED under ONC 21st Century Cures Act.
        """
        # 45 CFR §170.215: CEHRT must support HL7 FHIR R4 API.
        if document.ehr_data and not document.fhir_r4_compliant:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "45 CFR §170.215: Certified EHR Technology must support HL7 FHIR R4 "
                    "API for patient data access"
                ),
                regulation_citation="45 CFR §170.215; 21st Century Cures Act",
            )

        # 45 CFR §171.103: Information blocking is prohibited.
        if document.information_blocking:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "45 CFR §171.103: Information blocking by health IT developers, "
                    "HIN/E, or providers is prohibited with civil monetary penalties "
                    "up to $1M per violation"
                ),
                regulation_citation="45 CFR §171.103; 21st Century Cures Act §3022",
            )

        # 45 CFR §171.301: Patient access must not be unreasonably delayed.
        if document.patient_data_access_request and not document.access_provided_within_timelimit:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "45 CFR §171.301: Patient access to EHI must not be unreasonably "
                    "delayed (information blocking exception requires meeting conditions)"
                ),
                regulation_citation="45 CFR §171.301; 45 CFR §171.202",
            )

        # 21st Century Cures Act §3060: AI CDS must provide transparent basis.
        if document.ehr_data and document.ai_clinical_decision_support and not document.cds_transparency_documented:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "21st Century Cures Act §3060: AI-based CDS tools must provide "
                    "transparent basis for recommendations (source, logic, evidence)"
                ),
                regulation_citation="21st Century Cures Act §3060; 45 CFR §170.315(b)(11)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="ONC 21st Century Cures Act 45 CFR Part 170/171 — compliant",
            regulation_citation="45 CFR Part 170; 45 CFR Part 171",
        )


# ---------------------------------------------------------------------------
# Layer 3: CMSInteroperabilityFilter
#          CMS Interoperability and Patient Access Final Rule — 85 FR 25510
#          CMS Interoperability and Prior Authorization Final Rule — 88 FR 82510
# ---------------------------------------------------------------------------


class CMSInteroperabilityFilter:
    """
    Enforces the CMS Interoperability and Patient Access Final Rule
    (85 FR 25510) and the CMS Interoperability and Prior Authorization
    Final Rule (88 FR 82510).

    CMS Final Rule 85 FR 25510 (Patient Access API): CMS-regulated payers
    must implement a FHIR R4-based Patient Access API by July 1, 2021,
    enabling beneficiaries to access their claims, clinical, and formulary
    data via third-party applications.  Documents involving CMS-covered
    payers without a confirmed Patient Access API implementation are denied.

    CMS Prior Authorization Rule 88 FR 82510 (Human Review Pathway):
    AI-assisted prior authorization decisions must include a human review
    pathway to protect beneficiaries and ensure clinical appropriateness.
    Documents involving AI-generated prior authorization decisions without
    a human review pathway are denied.

    CMS Final Rule 85 FR 25510 (Provider Directory API): CMS-regulated
    payers must also implement a FHIR R4-based Provider Directory API for
    provider lookup and directory information.  Documents involving
    CMS-covered payers without a confirmed Provider Directory API are
    escalated to REQUIRES_HUMAN_REVIEW.

    CMS Medicare Advantage AI Policy (Clinical Criteria Documentation):
    AI-assisted coverage determinations in Medicare Advantage plans must
    use documented clinical criteria aligning with CMS guidelines and
    individual enrollee circumstances.  Documents involving Medicare
    Advantage AI coverage determinations without documented clinical
    criteria are denied.

    Documents that do not trigger any of the above conditions are approved
    under the general CMS Interoperability Rule compliance framework.
    """

    LAYER_NAME = "CMS_INTEROPERABILITY"

    def evaluate(self, context: HealthcareAIContext, document: HealthcareAIDocument) -> FilterResult:
        """
        Evaluate CMS Interoperability and Prior Authorization requirements.

        Evaluation order:
          1. CMS-covered payer without Patient Access API
             (85 FR 25510) — DENIED.
          2. AI prior authorization without human review pathway
             (88 FR 82510) — DENIED.
          3. CMS-covered payer without Provider Directory API
             (85 FR 25510) — REQUIRES_HUMAN_REVIEW.
          4. Medicare Advantage AI coverage determination without clinical
             criteria documented (CMS MA AI policy) — DENIED.
          5. Otherwise — APPROVED under CMS Interoperability Rule.
        """
        # 85 FR 25510: CMS-regulated payers must implement Patient Access API.
        if document.cms_covered_payer and not document.patient_access_api_implemented:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "CMS Final Rule 85 FR 25510: CMS-regulated payers must implement "
                    "Patient Access API (FHIR R4) by July 1, 2021"
                ),
                regulation_citation="CMS Final Rule 85 FR 25510; 42 CFR §422.119",
            )

        # 88 FR 82510: AI-assisted PA decisions require human review pathway.
        if document.prior_authorization_required and document.ai_pa_decision and not document.human_review_available:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "CMS Prior Auth Rule 88 FR 82510: AI-assisted prior authorization "
                    "decisions must include human review pathway"
                ),
                regulation_citation="CMS Final Rule 88 FR 82510; 42 CFR §422.568",
            )

        # 85 FR 25510: CMS-regulated payers must implement Provider Directory API.
        if document.cms_covered_payer and not document.provider_directory_api:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "CMS Final Rule: CMS-regulated payers must implement Provider "
                    "Directory API (FHIR R4) for provider lookup"
                ),
                regulation_citation="CMS Final Rule 85 FR 25510; 42 CFR §422.120",
            )

        # CMS MA AI policy: AI coverage determinations require documented clinical
        # criteria.
        if (
            document.medicare_advantage
            and document.ai_coverage_determination
            and not document.clinical_criteria_documented
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "CMS Medicare Advantage AI policy: AI-assisted coverage determinations "
                    "require documented clinical criteria matching CMS guidelines"
                ),
                regulation_citation="CMS Medicare Advantage AI policy; 42 CFR §422.101",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="CMS Interoperability Rule 85 FR 25510 — compliant",
            regulation_citation="CMS Final Rule 85 FR 25510; 88 FR 82510",
        )


# ---------------------------------------------------------------------------
# Layer 4: HealthcareAICrossBorderFilter
#          HIPAA Privacy Rule — 45 CFR §164
#          HIPAA Safe Harbor De-identification — 45 CFR §164.514(b)
#          FDA Medical Device Reporting — 21 CFR §803
#          EU Health Data Space Regulation (EHDS) 2024
# ---------------------------------------------------------------------------


class HealthcareAICrossBorderFilter:
    """
    Enforces HIPAA Privacy Rule requirements (45 CFR §164), HIPAA Safe Harbor
    de-identification and cross-border transfer restrictions
    (45 CFR §164.514(b)), FDA MedWatch adverse event reporting obligations
    (21 CFR §803), and EU Health Data Space (EHDS) secondary use authorization
    requirements (EHDS Regulation 2024).

    45 CFR §164.502 (HIPAA Minimum Necessary — PHI Disclosure): PHI
    disclosure requires valid patient authorization unless the disclosure is
    for treatment, payment, or health care operations (TPO).  Documents
    involving PHI without authorization or a valid TPO basis are denied.

    45 CFR §164.514(b) + HIPAA Safe Harbor: Transfer of PHI to jurisdictions
    lacking HIPAA-equivalent protections (Russia, China, Iran, North Korea)
    poses unacceptable risk of unauthorized disclosure and is prohibited.
    Documents directing PHI to those jurisdictions are denied.

    21 CFR §803 (FDA MedWatch — Medical Device Adverse Event Reporting):
    Serious adverse events involving SaMD must be reported to FDA via
    MedWatch within 30 days.  Documents flagging adverse events without
    a confirmed MedWatch report are escalated to REQUIRES_HUMAN_REVIEW.

    EU Health Data Space Regulation (EHDS) 2024: Cross-border secondary use
    of EU health data requires authorization from the responsible health data
    access body under the EHDS secondary use framework.  Documents involving
    EU health data without confirmed EHDS compliance are escalated to
    REQUIRES_HUMAN_REVIEW.

    Documents that do not trigger any of the above conditions are approved
    under the general HIPAA/FDA/EHDS healthcare cross-border framework.
    """

    LAYER_NAME = "HEALTHCARE_AI_CROSS_BORDER"

    _PHI_PROHIBITED_COUNTRIES = frozenset({"Russia", "China", "Iran", "North Korea"})

    def evaluate(self, context: HealthcareAIContext, document: HealthcareAIDocument) -> FilterResult:
        """
        Evaluate HIPAA, FDA MedWatch, and EHDS cross-border requirements.

        Evaluation order:
          1. PHI without HIPAA authorization or TPO basis
             (45 CFR §164.502) — DENIED.
          2. PHI transfer to sanctioned/non-HIPAA jurisdiction
             (45 CFR §164.514(b)) — DENIED.
          3. Adverse event without MedWatch report filed
             (21 CFR §803) — REQUIRES_HUMAN_REVIEW.
          4. EU health data without EHDS compliance
             (EHDS 2024) — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — APPROVED under HIPAA/FDA/EHDS framework.
        """
        # 45 CFR §164.502: PHI disclosure requires authorization or TPO.
        if document.phi and not document.hipaa_authorization and not document.treatment_payment_operations:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "45 CFR §164.502: PHI disclosure requires patient authorization "
                    "unless for TPO (treatment, payment, operations)"
                ),
                regulation_citation="45 CFR §164.502; HIPAA Privacy Rule",
            )

        # 45 CFR §164.514(b) + HIPAA Safe Harbor: PHI transfer to non-HIPAA
        # jurisdictions is prohibited.
        if document.destination_country in self._PHI_PROHIBITED_COUNTRIES and document.phi:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "45 CFR §164.514(b) + HIPAA Safe Harbor: PHI transfer to "
                    "non-HIPAA jurisdictions without adequate protections prohibited"
                ),
                regulation_citation="45 CFR §164.514(b); HIPAA Safe Harbor",
            )

        # 21 CFR §803: Adverse events involving SaMD require MedWatch report.
        if document.adverse_event and not document.medwatch_report_filed:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "21 CFR §803: Serious adverse events involving SaMD must be "
                    "reported to FDA via MedWatch within 30 days"
                ),
                regulation_citation="21 CFR §803; FDA MedWatch",
            )

        # EHDS 2024: EU health data secondary use requires EHDS authorization.
        if document.eu_health_data and not document.ehds_compliant:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "EU Health Data Space Regulation (EHDS) 2024: Cross-border health "
                    "data requires EHDS secondary use authorization"
                ),
                regulation_citation="EU Health Data Space Regulation (EHDS) 2024",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="HIPAA/FDA/EHDS healthcare cross-border — compliant",
            regulation_citation="45 CFR §164.502; 21 CFR §803; EHDS 2024",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------


@dataclass
class HealthcareAIAuditRecord:
    """
    Captures the full decision trail for a Healthcare AI RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - HIPAA Privacy Rule audit requirements under 45 CFR §164.530(j).
      - FDA 21 CFR Part 820 design history file and complaint records.
      - ONC 21st Century Cures Act EHR access log obligations.
      - CMS audit trail requirements for prior authorization and coverage
        determinations.
      - EU Health Data Space Regulation secondary use logging.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping purposes.
    """

    event: str
    institution_type: str
    is_cms_covered_payer: bool
    hipaa_covered_entity: bool
    documents_in: int
    documents_out: int
    decisions: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": self.event,
            "institution_type": self.institution_type,
            "is_cms_covered_payer": self.is_cms_covered_payer,
            "hipaa_covered_entity": self.hipaa_covered_entity,
            "documents_in": self.documents_in,
            "documents_out": self.documents_out,
            "decisions": self.decisions,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class HealthcareAIRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms subject
    to US healthcare AI regulations.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do
    not stop the pipeline — those documents are included in the result set
    but flagged for human oversight.  Only documents that receive a DENIED
    result from any layer are excluded from the returned set.

    Layers in order:
      1. FDASaMDFilter              — 21 CFR §814.1 PMA; §807.87 510(k);
                                      FDA AI/ML PCCP; 21 CFR Part 820 QMS
      2. ONCCuresActFilter          — 45 CFR §170.215 FHIR R4; §171.103
                                      information blocking; §171.301 access;
                                      21st Century Cures Act §3060 AI CDS
      3. CMSInteroperabilityFilter  — 85 FR 25510 Patient Access API;
                                      88 FR 82510 prior auth human review;
                                      Provider Directory API; MA AI criteria
      4. HealthcareAICrossBorderFilter — 45 CFR §164.502 PHI authorization;
                                         §164.514(b) Safe Harbor; 21 CFR §803
                                         MedWatch; EHDS 2024

    Audit records are generated for every retrieval event regardless of
    outcome, providing a complete access trail for HIPAA compliance review,
    FDA inspection, ONC certification audit, and CMS examination.
    """

    def __init__(self) -> None:
        self._layers = [
            FDASaMDFilter(),
            ONCCuresActFilter(),
            CMSInteroperabilityFilter(),
            HealthcareAICrossBorderFilter(),
        ]

    def filter_documents(
        self,
        context: HealthcareAIContext,
        documents: list[HealthcareAIDocument],
    ) -> list[HealthcareAIDocument]:
        """
        Return a list of documents that pass (or are flagged but not denied
        by) all four filter layers.

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
        context: HealthcareAIContext,
        documents: list[HealthcareAIDocument],
    ) -> HealthcareAIAuditRecord:
        """
        Evaluate all documents and return a HealthcareAIAuditRecord
        summarising the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support HIPAA
        audit, FDA inspection, ONC certification review, and CMS examination.
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
                    "document_id": doc.doc_id,
                    "final_decision": final_decision,
                    "layer_results": layer_results,
                }
            )

        return HealthcareAIAuditRecord(
            event="HEALTHCARE_AI_RAG_RETRIEVAL",
            institution_type=context.institution_type,
            is_cms_covered_payer=context.is_cms_covered_payer,
            hipaa_covered_entity=context.hipaa_covered_entity,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("US Healthcare AI RAG Pipeline — Demo")
    print("=" * 70)

    pipeline = HealthcareAIRAGPipeline()

    # ------------------------------------------------------------------
    # Demo 1: FDA 21 CFR §814.1 blocks Class III SaMD without PMA
    # ------------------------------------------------------------------
    print("\n[Demo 1] FDA 21 CFR §814.1 blocks Class III SaMD without PMA")
    ctx_fda = HealthcareAIContext(institution_type="device_manufacturer", has_fda_clearance=False)
    doc_fda = HealthcareAIDocument(
        doc_id="samd-class-iii-001",
        data_classification="restricted",
        samd_class="III",
        fda_premarket_approval=False,
        quality_management_system=True,
    )
    fda_result = FDASaMDFilter().evaluate(ctx_fda, doc_fda)
    print(f"  Decision : {fda_result.decision}")
    print(f"  Reason   : {fda_result.reason}")
    print(f"  Citation : {fda_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 2: ONC Cures Act blocks EHR data without FHIR R4 compliance
    # ------------------------------------------------------------------
    print("\n[Demo 2] ONC Cures Act 45 CFR §170.215 blocks EHR data without FHIR R4")
    ctx_onc = HealthcareAIContext(institution_type="ehr_vendor", hipaa_covered_entity=True)
    doc_onc = HealthcareAIDocument(
        doc_id="ehr-data-001",
        data_classification="confidential",
        ehr_data=True,
        fhir_r4_compliant=False,
    )
    onc_result = ONCCuresActFilter().evaluate(ctx_onc, doc_onc)
    print(f"  Decision : {onc_result.decision}")
    print(f"  Reason   : {onc_result.reason}")
    print(f"  Citation : {onc_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 3: CMS blocks AI prior auth without human review pathway
    # ------------------------------------------------------------------
    print("\n[Demo 3] CMS 88 FR 82510 blocks AI prior authorization without human review")
    ctx_cms = HealthcareAIContext(institution_type="health_plan", is_cms_covered_payer=True)
    doc_cms = HealthcareAIDocument(
        doc_id="prior-auth-ai-001",
        data_classification="confidential",
        cms_covered_payer=True,
        patient_access_api_implemented=True,
        provider_directory_api=True,
        prior_authorization_required=True,
        ai_pa_decision=True,
        human_review_available=False,
    )
    cms_result = CMSInteroperabilityFilter().evaluate(ctx_cms, doc_cms)
    print(f"  Decision : {cms_result.decision}")
    print(f"  Reason   : {cms_result.reason}")
    print(f"  Citation : {cms_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 4: HIPAA blocks PHI without authorization or TPO
    # ------------------------------------------------------------------
    print("\n[Demo 4] HIPAA 45 CFR §164.502 blocks PHI without authorization or TPO")
    ctx_hipaa = HealthcareAIContext(institution_type="hospital", hipaa_covered_entity=True)
    doc_hipaa = HealthcareAIDocument(
        doc_id="phi-no-auth-001",
        data_classification="restricted",
        phi=True,
        hipaa_authorization=False,
        treatment_payment_operations=False,
    )
    hipaa_result = HealthcareAICrossBorderFilter().evaluate(ctx_hipaa, doc_hipaa)
    print(f"  Decision : {hipaa_result.decision}")
    print(f"  Reason   : {hipaa_result.reason}")
    print(f"  Citation : {hipaa_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 5: Full pipeline — compliant document passes all four layers
    # ------------------------------------------------------------------
    print("\n[Demo 5] Full pipeline — fully compliant document passes all four layers")
    ctx_full = HealthcareAIContext(
        institution_type="health_plan",
        is_cms_covered_payer=True,
        has_fda_clearance=True,
        hipaa_covered_entity=True,
    )
    doc_full = HealthcareAIDocument(
        doc_id="compliant-doc-001",
        data_classification="internal",
    )
    result_full = pipeline.filter_documents(ctx_full, [doc_full])
    print("  Documents in  : 1")
    print(f"  Documents out : {len(result_full)}")
    print(f"  Outcome       : {'PASSED' if len(result_full) == 1 else 'BLOCKED'}")

    # ------------------------------------------------------------------
    # Demo 6: Audit record with a blocked document
    # ------------------------------------------------------------------
    print("\n[Demo 6] Audit record for a blocked Class III SaMD document")
    audit_record = pipeline.filter_documents_with_audit(ctx_fda, [doc_fda])
    log = audit_record.to_audit_log()
    print(f"  Event         : {log['event']}")
    print(f"  Documents in  : {log['documents_in']}")
    print(f"  Documents out : {log['documents_out']}")
    print(f"  Final decision: {log['decisions'][0]['final_decision']}")
