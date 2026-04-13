"""
Telecommunications Regulatory RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating in the United States telecommunications regulatory
environment.  Four independent filter layers run sequentially; a document
must pass all four to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | Carrier customer-service AI assistants                   | FCC CPNI — 47 U.S.C. §222 / 47 CFR §64  |
  | Telecom marketing automation platforms                   | TCPA — 47 U.S.C. §227 / 47 CFR §64      |
  | Lawful-intercept compliance systems                      | CALEA — 47 U.S.C. §§1001-1010            |
  | International roaming / cross-border data platforms      | FCC §214; CLOUD Act 18 U.S.C. §2713      |
  | Robocall / autodialer compliance tools                   | TCPA — FCC 2012 Order / FCC 2024 Order   |
  | Network analytics and fraud-detection platforms          | CPNI §222(d) + CALEA §1002               |
  | Government-facing carrier reporting systems              | CALEA §1002; CLOUD Act §2713             |
  | IoT device connectivity management platforms             | TCPA §227(b) + FCC Rules                 |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — FCCCPNIFilter
      (FCC Customer Proprietary Network Information
       47 U.S.C. §222; 47 CFR Part 64 Subpart U)
      Controls access to Customer Proprietary Network Information (CPNI),
      which encompasses information about a subscriber's use of a
      telecommunications service — call detail records, location data,
      network access data, and similar derived information.

      47 U.S.C. §222(c)(1) restricts carrier use and disclosure of CPNI to
      the provision of the underlying telecommunications service, including
      billing and repair, without customer opt-in approval.  Using CPNI for
      any purpose outside billing, repair, or direct service support requires
      opt-in consent and is denied when that consent is absent.

      Third-party sharing of CPNI is explicitly prohibited by §222(c)(1)
      unless the customer has provided opt-in consent.  Documents flagged for
      third-party sharing without consent are denied.

      §222(c)(3) creates a conditional regime for marketing use of CPNI: the
      carrier's own affiliates may use CPNI for marketing with customer
      opt-out; non-affiliate third-party marketing always requires opt-in.
      Marketing-use documents are escalated to REQUIRES_HUMAN_REVIEW so that
      the appropriate opt-in/opt-out determination can be made by a
      human reviewer.

      §222(d) carves out CPNI use that is necessary for the provision of
      services; compliant CPNI records that do not trigger any of the above
      conditions are approved under this provision.

  Layer 2 — TCPAComplianceFilter
      (Telephone Consumer Protection Act
       47 U.S.C. §227; 47 CFR Part 64 Subpart L; FCC Rules)
      Controls access to communications records and contact lists in
      automated telephony and messaging platforms.

      §227(b)(1)(A) prohibits the use of automated telephone dialing
      systems (autodialers), artificial or prerecorded voices, and robocalls
      to wireless numbers without prior express written consent.  Contact
      records flagged for robocall, autodialer, or prerecorded-voice
      delivery without consent are denied.

      §227(b)(1)(A) and the FCC 2012 Order (In re Rules and Regulations
      Implementing the TCPA) extend the prior express written consent
      requirement to text messages sent via autodialer.  SMS contact records
      without consent are denied.

      §227(c)(5) creates a private right of action for subscribers on the
      National Do Not Call Registry.  Contact records bearing a DNC registry
      flag are denied.

      47 CFR §64.1200(c)(1) restricts calls to the hours between 8 AM and
      9 PM local time at the called party's location.  Records specifying a
      calling time outside this window are denied.

  Layer 3 — CALEAWiretapFilter
      (Communications Assistance for Law Enforcement Act
       47 U.S.C. §§1001-1010; 47 CFR Part 9)
      Controls access to intercept-related telecommunications records,
      enforcing the statutory requirements for lawful interception and
      carrier compliance obligations.

      18 U.S.C. §2511 (Wiretap Act) makes it a federal crime to intercept
      wire, oral, or electronic communications without a court order.  Records
      flagged as content intercepts or call records obtained without a
      court order are denied.

      18 U.S.C. §3121 (Pen Register Act) requires a court order before
      installing or using a pen register or trap-and-trace device.
      Pen-register records without a pen-register court order are denied.

      47 U.S.C. §1002 requires covered carriers to maintain CALEA-compliant
      intercept capability.  Records originating from a carrier that has not
      certified CALEA compliance are escalated to REQUIRES_HUMAN_REVIEW for
      manual verification before release.

  Layer 4 — TelecoCrossBorderFilter
      (Cross-border telecommunications data transfer
       FCC International Section 214; ITU-T X.1051;
       CLOUD Act 18 U.S.C. §2713)
      Controls the international transfer of telecommunications data,
      enforcing FCC international service authorisation, OFAC sanctions,
      and CLOUD Act mutual-legal-assistance obligations.

      FCC Order FCC 21-114 revoked China Telecom's Section 214 authorisation
      due to national security concerns.  Documents routed through or destined
      for China, Russia, Iran, or North Korea are denied pursuant to
      FCC 21-114 and applicable OFAC sanctions programmes.

      CALEA 47 U.S.C. §1004 prohibits export of lawful-intercept capability
      outside the United States.  Records flagged as lawful-intercept data
      destined for any non-US country are denied.

      47 U.S.C. §214 requires FCC authorisation before providing
      international telecommunications service.  International service
      operations without a Section 214 licence are escalated to
      REQUIRES_HUMAN_REVIEW for licensing verification.

      Remaining cross-border transfers are approved with a CLOUD Act
      mutual-legal-assistance citation confirming the data is subject to
      US law and the MLAT framework.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TelecomRegulatoryContext:
    """
    Carries all per-request attributes needed by the four US telecommunications
    regulatory filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    role describes the requesting entity:
        "carrier_agent", "customer", "law_enforcement", "regulator",
        "third_party", "affiliate"

    All boolean flags default to False to enforce a deny-by-default posture;
    callers must explicitly set flags that grant access.
    """

    user_id: str
    role: str                                   # "carrier_agent", "customer", "law_enforcement",
                                                # "regulator", "third_party", "affiliate"
    carrier_id: str = ""
    customer_id: str = ""

    # CPNI — Layer 1
    data_type: str = ""                         # "cpni", "pen_register", "lawful_intercept", etc.
    purpose: str = ""                           # "billing", "repair", "support", "marketing", etc.
    third_party_sharing: bool = False
    marketing_use: bool = False

    # TCPA — Layer 2
    contact_method: str = ""                    # "robocall", "autodialer", "prerecorded", "sms",
                                                #  "manual", "human_agent"
    prior_express_consent: bool = False
    do_not_call_registry: bool = False
    calling_time_hour: int | None = None        # 0-23, local time of called party

    # CALEA — Layer 3
    intercept_type: str = ""                    # "content", "call_records", "pen_register"
    court_order: bool = False
    pen_register_order: bool = False
    calea_compliance_certified: bool = True     # default True; set False to trigger review

    # Cross-border — Layer 4
    destination_country: str = "US"
    international_service: bool = False
    section_214_license: bool = True            # default True; set False to trigger review


@dataclass(frozen=True)
class TelecomRegulatoryDocument:
    """
    Immutable document descriptor carrying all attributes needed for US
    telecommunications regulatory compliance evaluation across the four
    filter layers.

    doc_type describes the category of document:
        "cpni_record", "contact_record", "intercept_record", "pen_register_record",
        "call_detail_record", "network_usage_record", "marketing_list",
        "lawful_intercept_capability", "transfer_agreement"
    """

    content: str
    document_id: str
    doc_type: str = "cpni_record"


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
# Layer 1: FCCCPNIFilter
#          FCC Customer Proprietary Network Information
#          47 U.S.C. §222; 47 CFR Part 64 Subpart U
# ---------------------------------------------------------------------------

class FCCCPNIFilter:
    """
    Enforces FCC Customer Proprietary Network Information (CPNI) requirements
    under 47 U.S.C. §222 and 47 CFR Part 64 Subpart U.

    CPNI encompasses a customer's telecommunications usage information —
    call detail records, calling patterns, location data, and network
    access information — which carriers collect through their service
    relationship and are obligated to protect.

    47 U.S.C. §222(c)(1) restricts carrier use and disclosure of CPNI to
    the provision of the underlying telecommunications service, billing,
    and repair, without separate customer opt-in approval.  Processing CPNI
    for any purpose outside these permitted categories without opt-in
    consent is denied.

    §222(c)(1) also prohibits third-party sharing of CPNI without opt-in
    consent.  Documents flagged for third-party sharing without consent
    are denied.

    §222(c)(3) creates a conditional marketing regime: affiliates may use
    CPNI for marketing with customer opt-out approval, while non-affiliate
    third parties require opt-in.  Marketing-use documents are escalated to
    REQUIRES_HUMAN_REVIEW to allow a human reviewer to determine the
    appropriate opt-in or opt-out obligation.

    §222(d) permits CPNI use that is necessary for the provision of
    telecommunications services.  Compliant CPNI records that satisfy
    one of the permitted purposes are approved under this provision.
    """

    LAYER_NAME = "FCC_CPNI"

    _PERMITTED_PURPOSES = frozenset({"billing", "repair", "support"})

    def evaluate(
        self, context: TelecomRegulatoryContext, document: TelecomRegulatoryDocument
    ) -> FilterResult:
        """
        Evaluate FCC CPNI requirements under 47 U.S.C. §222.

        Evaluation order (CPNI records only — non-CPNI records pass through):
          1. Not a CPNI data type — APPROVED immediately (not applicable).
          2. CPNI + purpose not in permitted set + no opt-in consent
             (§222(c)(1)) — DENIED.
          3. CPNI + third_party_sharing without consent
             (§222(c)(1)) — DENIED.
          4. CPNI + marketing_use
             (§222(c)(3)) — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — APPROVED under §222(d).
        """
        # This filter only applies to CPNI data.
        if context.data_type != "cpni":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="FCC CPNI: Not applicable (non-CPNI data type)",
                regulation_citation="47 U.S.C. §222(d)",
            )

        # §222(c)(1): CPNI use restricted to billing, repair, and support without opt-in.
        if context.purpose not in self._PERMITTED_PURPOSES and not context.prior_express_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "FCC CPNI 47 U.S.C. §222(c)(1): CPNI use restricted to billing, "
                    "repair, and support without opt-in consent"
                ),
                regulation_citation="47 U.S.C. §222(c)(1)",
            )

        # §222(c)(1): Third-party sharing of CPNI requires opt-in consent.
        if context.third_party_sharing and not context.prior_express_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "FCC CPNI 47 U.S.C. §222(c)(1): Third-party sharing of CPNI "
                    "requires opt-in consent"
                ),
                regulation_citation="47 U.S.C. §222(c)(1)",
            )

        # §222(c)(3): Marketing use of CPNI requires human review for opt-in/opt-out determination.
        if context.marketing_use:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "FCC CPNI 47 U.S.C. §222(c)(3): Marketing use of CPNI requires "
                    "opt-in or opt-out determination based on affiliate status"
                ),
                regulation_citation="47 U.S.C. §222(c)(3)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="FCC CPNI: Permitted use under §222(d) — billing, repair, or support",
            regulation_citation="47 U.S.C. §222(d)",
        )


# ---------------------------------------------------------------------------
# Layer 2: TCPAComplianceFilter
#          Telephone Consumer Protection Act
#          47 U.S.C. §227; 47 CFR Part 64 Subpart L; FCC Rules
# ---------------------------------------------------------------------------

class TCPAComplianceFilter:
    """
    Enforces Telephone Consumer Protection Act (TCPA) requirements under
    47 U.S.C. §227 and 47 CFR Part 64 Subpart L.

    The TCPA restricts the use of automated telephone dialing systems,
    artificial or prerecorded voices, and text messaging to protect
    consumers from unwanted solicitation and harassment.

    §227(b)(1)(A) prohibits automated calls — including robocalls, autodialer
    calls, and prerecorded voice messages — to wireless numbers without
    prior express written consent.  Contact records flagged for these methods
    without consent are denied.

    §227(b)(1)(A) and the FCC 2012 Order extend the prior express written
    consent requirement to text messages sent via autodialer.  SMS records
    without consent are denied.

    §227(c)(5) creates private liability for calls to numbers registered on
    the National Do Not Call Registry.  Contact records bearing a DNC flag
    are denied regardless of consent.

    47 CFR §64.1200(c)(1) restricts outbound calls to the hours between
    8 AM and 9 PM local time at the called party's location.  Records
    specifying a calling time outside this window are denied.

    Contact records using manual human-agent methods or bearing explicit
    prior express consent that do not trigger any of the above conditions
    are approved.
    """

    LAYER_NAME = "TCPA_COMPLIANCE"

    _AUTOMATED_METHODS = frozenset({"robocall", "autodialer", "prerecorded"})

    def evaluate(
        self, context: TelecomRegulatoryContext, document: TelecomRegulatoryDocument
    ) -> FilterResult:
        """
        Evaluate TCPA requirements under 47 U.S.C. §227.

        Evaluation order (contact-method records only):
          1. Automated/prerecorded method + no prior express consent
             (§227(b)(1)(A)) — DENIED.
          2. SMS + no prior express consent
             (§227(b)(1)(A) + FCC 2012 Order) — DENIED.
          3. DNC registry flag present
             (§227(c)(5)) — DENIED.
          4. Calling time outside 8 AM – 9 PM local
             (47 CFR §64.1200(c)(1)) — DENIED.
          5. Otherwise — APPROVED.
        """
        # §227(b)(1)(A): Automated calls to wireless require prior express written consent.
        if (
            context.contact_method in self._AUTOMATED_METHODS
            and not context.prior_express_consent
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "TCPA 47 U.S.C. §227(b)(1)(A): Automated calls to wireless numbers "
                    "require prior express written consent"
                ),
                regulation_citation="47 U.S.C. §227(b)(1)(A)",
            )

        # §227(b)(1)(A) + FCC 2012 Order: SMS messages via autodialer require prior express consent.
        if context.contact_method == "sms" and not context.prior_express_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "TCPA 47 U.S.C. §227(b)(1)(A): Text messages require prior express "
                    "written consent per FCC 2012 Order"
                ),
                regulation_citation="47 U.S.C. §227(b)(1)(A); FCC 2012 Order",
            )

        # §227(c)(5): National Do Not Call Registry violation.
        if context.do_not_call_registry:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "TCPA 47 U.S.C. §227(c)(5): Contact is on the National "
                    "Do Not Call Registry"
                ),
                regulation_citation="47 U.S.C. §227(c)(5)",
            )

        # 47 CFR §64.1200(c)(1): Calls restricted to 8 AM – 9 PM local time.
        if context.calling_time_hour is not None and not (
            8 <= context.calling_time_hour <= 21
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "TCPA 47 CFR §64.1200(c)(1): Calls permitted only between "
                    "8 AM and 9 PM local time at the called party's location"
                ),
                regulation_citation="47 CFR §64.1200(c)(1)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="TCPA compliance check passed",
            regulation_citation="47 U.S.C. §227",
        )


# ---------------------------------------------------------------------------
# Layer 3: CALEAWiretapFilter
#          Communications Assistance for Law Enforcement Act
#          47 U.S.C. §§1001-1010; 47 CFR Part 9
# ---------------------------------------------------------------------------

class CALEAWiretapFilter:
    """
    Enforces Communications Assistance for Law Enforcement Act (CALEA)
    and Wiretap Act requirements under 47 U.S.C. §§1001-1010 and
    47 CFR Part 9.

    CALEA requires covered telecommunications carriers to build and maintain
    technical capabilities enabling lawful interception by law enforcement
    pursuant to court authorisation.  The Wiretap Act and Pen Register Act
    impose separate criminal prohibitions on unauthorised interception.

    18 U.S.C. §2511 (Wiretap Act) makes it a federal crime to intercept
    wire, oral, or electronic communications without a valid court order.
    Documents flagged as content intercepts or call records acquired through
    interception without a court order are denied.

    18 U.S.C. §3121 (Pen Register Act) requires a separate court order
    before pen register data may be collected or accessed.  Pen-register
    records without the requisite court order are denied.

    47 U.S.C. §1002 requires covered carriers to ensure their equipment and
    facilities support lawful-interception assistance.  Records from a
    carrier that has not certified CALEA compliance are escalated to
    REQUIRES_HUMAN_REVIEW to allow manual verification before the data
    is released.

    Records that do not involve intercept or pen-register data, or that are
    accompanied by the required court authorisation, are approved.
    """

    LAYER_NAME = "CALEA_WIRETAP"

    _WIRETAP_INTERCEPT_TYPES = frozenset({"content", "call_records"})

    def evaluate(
        self, context: TelecomRegulatoryContext, document: TelecomRegulatoryDocument
    ) -> FilterResult:
        """
        Evaluate CALEA and Wiretap Act requirements.

        Evaluation order:
          1. Content or call-record intercept without court order
             (18 U.S.C. §2511) — DENIED.
          2. Pen register data without pen-register court order
             (18 U.S.C. §3121) — DENIED.
          3. CALEA compliance not certified
             (47 U.S.C. §1002) — REQUIRES_HUMAN_REVIEW.
          4. Otherwise — APPROVED.
        """
        # 18 U.S.C. §2511: Content intercept and call-record interception require court order.
        if (
            context.intercept_type in self._WIRETAP_INTERCEPT_TYPES
            and not context.court_order
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "CALEA / Wiretap Act 18 U.S.C. §2511: Interception of wire or "
                    "electronic communications without a court order is prohibited"
                ),
                regulation_citation="18 U.S.C. §2511",
            )

        # 18 U.S.C. §3121: Pen register access requires a pen-register court order.
        if context.data_type == "pen_register" and not context.pen_register_order:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Pen Register Act 18 U.S.C. §3121: Pen register access requires "
                    "a court order"
                ),
                regulation_citation="18 U.S.C. §3121",
            )

        # 47 U.S.C. §1002: Carrier must maintain CALEA compliance capability.
        if context.calea_compliance_certified is False:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "CALEA 47 U.S.C. §1002: Carrier has not certified CALEA compliance "
                    "capability — manual verification required"
                ),
                regulation_citation="47 U.S.C. §1002",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="CALEA / Wiretap Act compliance check passed",
            regulation_citation="47 U.S.C. §§1001-1010",
        )


# ---------------------------------------------------------------------------
# Layer 4: TelecoCrossBorderFilter
#          Cross-border telecommunications data transfer
#          FCC International Section 214; ITU-T X.1051;
#          CLOUD Act 18 U.S.C. §2713
# ---------------------------------------------------------------------------

class TelecoCrossBorderFilter:
    """
    Enforces cross-border telecommunications data transfer requirements
    under FCC International Section 214, ITU-T X.1051, and the CLOUD Act
    (18 U.S.C. §2713).

    FCC Order FCC 21-114 revoked China Telecom Americas' Section 214
    authorisation based on national security concerns arising from the
    company's obligations under Chinese law.  Similar FCC orders have
    addressed Russian and Iranian carriers.  OFAC sanctions programmes
    independently prohibit transactions with entities in sanctioned
    jurisdictions.  Transfers routed to or through China, Russia, Iran, or
    North Korea are denied.

    CALEA 47 U.S.C. §1004 prohibits carriers from deploying systems that
    would allow a foreign government to conduct electronic surveillance of
    US communications without the approval of US authorities.  Exporting
    lawful-intercept data outside the United States is denied under this
    provision.

    47 U.S.C. §214 requires FCC authorisation (a "Section 214 license")
    before a carrier may provide international telecommunications service.
    International service operations without a confirmed Section 214 license
    are escalated to REQUIRES_HUMAN_REVIEW for licensing verification.

    Remaining international transfers are approved with a CLOUD Act mutual-
    legal-assistance citation, confirming that US-held data remains subject
    to US law and the MLAT framework regardless of where it is stored.
    """

    LAYER_NAME = "TELECO_CROSS_BORDER"

    _RESTRICTED_COUNTRIES = frozenset({"China", "Russia", "Iran", "North Korea"})

    def evaluate(
        self, context: TelecomRegulatoryContext, document: TelecomRegulatoryDocument
    ) -> FilterResult:
        """
        Evaluate cross-border telecommunications transfer requirements.

        Evaluation order:
          1. Destination in restricted jurisdiction
             (FCC 21-114; OFAC sanctions) — DENIED.
          2. Lawful-intercept data destined for non-US country
             (CALEA 47 U.S.C. §1004) — DENIED.
          3. International service without Section 214 license
             (47 U.S.C. §214) — REQUIRES_HUMAN_REVIEW.
          4. Otherwise — APPROVED under CLOUD Act MLAT framework.
        """
        # FCC 21-114 / OFAC: Transfers to restricted jurisdictions are denied.
        if context.destination_country in self._RESTRICTED_COUNTRIES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "FCC Order FCC 21-114 / OFAC sanctions: Transfer to restricted "
                    f"jurisdiction ({context.destination_country}) is prohibited"
                ),
                regulation_citation="FCC Order FCC 21-114; OFAC Sanctions",
            )

        # CALEA §1004: Lawful-intercept data cannot be exported outside the US.
        if (
            context.data_type == "lawful_intercept"
            and context.destination_country != "US"
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "CALEA 47 U.S.C. §1004: Lawful-intercept capability and data "
                    "cannot be exported outside the United States"
                ),
                regulation_citation="47 U.S.C. §1004",
            )

        # 47 U.S.C. §214: International service requires Section 214 authorisation.
        if context.section_214_license is False and context.international_service:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "FCC 47 U.S.C. §214: International telecommunications service "
                    "requires Section 214 authorisation — licensing verification required"
                ),
                regulation_citation="47 U.S.C. §214",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason=(
                "Cross-border transfer approved — CLOUD Act mutual legal assistance "
                "framework applies"
            ),
            regulation_citation="CLOUD Act 18 U.S.C. §2713",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class TelecomRegulatoryAuditRecord:
    """
    Captures the full decision trail for a Telecommunications Regulatory RAG
    retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - FCC CPNI annual reporting and safeguards requirements (47 CFR §64.2009).
      - TCPA record-keeping obligations for consent documentation.
      - CALEA audit-trail requirements for lawful-intercept access.
      - FCC §214 international authorisation compliance records.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping purposes.
    """

    event: str
    user_id: str
    carrier_id: str
    data_type: str
    purpose: str
    documents_in: int
    documents_out: int
    decisions: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": self.event,
            "user_id": self.user_id,
            "carrier_id": self.carrier_id,
            "data_type": self.data_type,
            "purpose": self.purpose,
            "documents_in": self.documents_in,
            "documents_out": self.documents_out,
            "decisions": self.decisions,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class TelecomRegulatoryRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for telecommunications
    platforms operating in the United States regulatory environment.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do
    not stop the pipeline — those documents are included in the result set
    but flagged for human oversight.  Only documents that receive a DENIED
    result from any layer are excluded from the returned set.

    Layers in order:
      1. FCCCPNIFilter          — 47 U.S.C. §222(c)(1)/(c)(3)/(d)
      2. TCPAComplianceFilter   — 47 U.S.C. §227(b)(1)(A)/(c)(5);
                                  47 CFR §64.1200(c)(1)
      3. CALEAWiretapFilter     — 18 U.S.C. §2511/§3121; 47 U.S.C. §1002
      4. TelecoCrossBorderFilter — FCC 21-114; 47 U.S.C. §1004/§214;
                                   CLOUD Act 18 U.S.C. §2713

    Audit records are generated for every retrieval event regardless of
    outcome, providing a complete access trail for FCC, DOJ, and FTC
    regulatory audits.
    """

    def __init__(self) -> None:
        self._layers = [
            FCCCPNIFilter(),
            TCPAComplianceFilter(),
            CALEAWiretapFilter(),
            TelecoCrossBorderFilter(),
        ]

    def filter_documents(
        self,
        context: TelecomRegulatoryContext,
        documents: List[TelecomRegulatoryDocument],
    ) -> List[TelecomRegulatoryDocument]:
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
        context: TelecomRegulatoryContext,
        documents: List[TelecomRegulatoryDocument],
    ) -> TelecomRegulatoryAuditRecord:
        """
        Evaluate all documents and return a TelecomRegulatoryAuditRecord
        summarising the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support FCC, DOJ,
        and FTC regulatory auditing obligations.
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

        return TelecomRegulatoryAuditRecord(
            event="TELECOM_REGULATORY_RAG_RETRIEVAL",
            user_id=context.user_id,
            carrier_id=context.carrier_id,
            data_type=context.data_type,
            purpose=context.purpose,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Telecommunications Regulatory RAG Pipeline — Demo")
    print("=" * 70)

    pipeline = TelecomRegulatoryRAGPipeline()

    # ------------------------------------------------------------------
    # Demo 1: CPNI blocked for non-billing use without consent
    # ------------------------------------------------------------------
    print("\n[Demo 1] CPNI blocked for non-billing use (§222(c)(1))")
    ctx_cpni = TelecomRegulatoryContext(
        user_id="agent-001",
        role="carrier_agent",
        carrier_id="carrier-alpha",
        data_type="cpni",
        purpose="analytics",               # not billing/repair/support
        prior_express_consent=False,
    )
    doc_cpni = TelecomRegulatoryDocument(
        content="Customer call usage profile",
        document_id="cpni-doc-001",
        doc_type="cpni_record",
    )
    cpni_result = FCCCPNIFilter().evaluate(ctx_cpni, doc_cpni)
    print(f"  Decision : {cpni_result.decision}")
    print(f"  Reason   : {cpni_result.reason}")
    print(f"  Citation : {cpni_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 2: TCPA blocks autodialer call without consent
    # ------------------------------------------------------------------
    print("\n[Demo 2] TCPA blocks autodialer call without consent (§227(b)(1)(A))")
    ctx_tcpa = TelecomRegulatoryContext(
        user_id="marketing-sys",
        role="carrier_agent",
        carrier_id="carrier-alpha",
        contact_method="autodialer",
        prior_express_consent=False,
    )
    doc_tcpa = TelecomRegulatoryDocument(
        content="Customer wireless contact record",
        document_id="contact-doc-001",
        doc_type="contact_record",
    )
    tcpa_result = TCPAComplianceFilter().evaluate(ctx_tcpa, doc_tcpa)
    print(f"  Decision : {tcpa_result.decision}")
    print(f"  Reason   : {tcpa_result.reason}")
    print(f"  Citation : {tcpa_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 3: CALEA blocks content intercept without court order
    # ------------------------------------------------------------------
    print("\n[Demo 3] CALEA blocks content intercept without court order (18 U.S.C. §2511)")
    ctx_calea = TelecomRegulatoryContext(
        user_id="le-agent-007",
        role="law_enforcement",
        carrier_id="carrier-beta",
        intercept_type="content",
        court_order=False,
    )
    doc_calea = TelecomRegulatoryDocument(
        content="Intercepted call content",
        document_id="intercept-doc-001",
        doc_type="intercept_record",
    )
    calea_result = CALEAWiretapFilter().evaluate(ctx_calea, doc_calea)
    print(f"  Decision : {calea_result.decision}")
    print(f"  Reason   : {calea_result.reason}")
    print(f"  Citation : {calea_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 4: Cross-border blocks China routing (FCC 21-114)
    # ------------------------------------------------------------------
    print("\n[Demo 4] Cross-border blocks China routing (FCC Order FCC 21-114)")
    ctx_cross = TelecomRegulatoryContext(
        user_id="router-001",
        role="carrier_agent",
        carrier_id="carrier-gamma",
        destination_country="China",
        international_service=True,
        section_214_license=True,
    )
    doc_cross = TelecomRegulatoryDocument(
        content="Network routing record via China Telecom",
        document_id="routing-doc-001",
        doc_type="network_usage_record",
    )
    cross_result = TelecoCrossBorderFilter().evaluate(ctx_cross, doc_cross)
    print(f"  Decision : {cross_result.decision}")
    print(f"  Reason   : {cross_result.reason}")
    print(f"  Citation : {cross_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 5: Full pipeline — compliant billing request passes all layers
    # ------------------------------------------------------------------
    print("\n[Demo 5] Full pipeline — compliant billing CPNI request passes all layers")
    ctx_compliant = TelecomRegulatoryContext(
        user_id="billing-sys",
        role="carrier_agent",
        carrier_id="carrier-alpha",
        data_type="cpni",
        purpose="billing",
        prior_express_consent=False,
        destination_country="US",
        calea_compliance_certified=True,
        section_214_license=True,
    )
    docs_compliant = [
        TelecomRegulatoryDocument(
            content="Customer billing record",
            document_id=f"billing-{i}",
            doc_type="cpni_record",
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
