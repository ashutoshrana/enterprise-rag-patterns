"""
Telecommunications / FCC CPNI Compliance RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pre-filter for platforms
that process documents related to telecommunications services, customer data
handling, emergency service routing, and cross-border carrier operations.  Four
independent filter layers run sequentially; a document must pass all four to be
returned to the caller.

Commercial use cases:

  +------------------------------------------------------------------+-----------------------------------------------+
  | Platform / Product                                               | Applicable Regulation(s)                      |
  +------------------------------------------------------------------+-----------------------------------------------+
  | Telecom CRM and customer data analytics platforms                | FCC 47 CFR Part 64 CPNI; TCPA 47 U.S.C. §227 |
  | Customer proprietary network information management systems      | 47 CFR §64.2007 CPNI consent; §64.2011        |
  | Outbound call center and robocall compliance platforms           | TCPA §227; 47 CFR §64.1200 DNC registry       |
  | VoIP and cloud communications compliance systems                 | FCC Order 05-116 E911; FCC 20-100 RAY BAUM'S  |
  | Multi-line telephone system (MLTS) management platforms         | 47 U.S.C. §1471 Kari's Law; FCC 21-86 988    |
  | Wireless carrier location and emergency routing systems          | FCC 20-100 RAY BAUM'S Act §506 dispatchable   |
  | International carrier interconnect compliance platforms          | 47 U.S.C. §214 Section 214 authorization      |
  | Submarine cable and cable landing system management              | 47 U.S.C. §35 cable landing license           |
  | Sanctions screening for telecom service provisioning             | OFAC telecom sanctions; FCC Covered List       |
  | AI/ML-powered telecom document retrieval and analysis            | FCC CPNI; TCPA; OFAC; FCC Covered List        |
  +------------------------------------------------------------------+-----------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — FCCCPNIFilter
      (Customer Proprietary Network Information — FCC 47 CFR Part 64;
       administered by the Federal Communications Commission)
      Controls access to documents describing the use or disclosure of customer
      proprietary network information (CPNI), enforcing FCC CPNI consent, opt-out,
      opt-in, third-party safeguard, and retention requirements.

      47 CFR §64.2007 — CPNI Consent (Opt-Out for Existing Customers):
      Telecommunications carriers may use CPNI to market services within the
      customer's existing service category without affirmative consent, provided
      that the customer has not opted out.  Documents describing CPNI disclosure or
      use without customer consent or a valid opt-out on file are denied as violating
      the baseline CPNI consent standard under 47 CFR §64.2007.

      47 CFR §64.2005(b) — CPNI for Marketing Outside Existing Service (Opt-In):
      Telecommunications carriers that wish to use a customer's CPNI to market
      services outside the customer's existing service category must obtain the
      customer's affirmative opt-in consent.  Documents describing such cross-category
      CPNI marketing without confirmed opt-in consent are denied.

      47 CFR §64.2011 — Third-Party CPNI Disclosure Safeguards:
      Carriers that disclose CPNI to third parties must have implemented the FCC's
      required CPNI safeguards under 47 CFR §64.2011, including proprietary network
      information protection procedures.  Documents describing third-party CPNI
      disclosure without confirmed safeguards in place are denied.

      CPNI Data Retention — 2-Year Business Record Retention:
      FCC rules require carriers to retain CPNI-related records for a minimum period
      sufficient to support FCC investigations.  CPNI records retained beyond two
      years without a documented business need or regulatory hold require human
      review to determine whether continued retention is justified and appropriately
      secured.

  Layer 2 — TelecomPrivacyFilter
      (TCPA Automated Calling + State Telecom Privacy;
       administered by the FCC, FTC, and state public utility commissions)
      Controls access to documents describing automated calling and texting programs,
      Do-Not-Call compliance, call recording consent, and text marketing practices,
      enforcing TCPA, FCC DNC registry, California CPUC, and CTIA compliance.

      TCPA 47 U.S.C. §227 — Prior Express Written Consent for Automated Calls/Texts:
      The Telephone Consumer Protection Act (TCPA) prohibits initiating automated
      telephone calls (including robocalls and auto-dialed text messages) to a mobile
      telephone number without the called party's prior express written consent.
      Documents describing automated call or text campaigns without prior express
      written consent on file are denied as violating TCPA 47 U.S.C. §227.

      47 CFR §64.1200 — National Do-Not-Call Registry:
      FCC rules under 47 CFR §64.1200 implement the National Do-Not-Call (DNC)
      Registry maintained by the FTC.  Telemarketers and telephone solicitors are
      prohibited from calling or texting numbers on the DNC registry unless an
      established business relationship or applicable exemption applies.  Documents
      describing robocalls or solicitations to registry numbers without DNC scrubbing
      are denied.

      California CPUC General Order 107-B — Two-Party Call Recording Consent:
      California is a two-party (all-party) consent state under the California
      Invasion of Privacy Act (CIPA, Penal Code §632).  The California CPUC General
      Order 107-B applies to telephone communications and requires that all parties
      to a call consent to recording.  Documents describing call recording in California
      without two-party consent are denied.

      TCPA / CAN-SPAM / CTIA — Text Marketing Compliance:
      Text message marketing programs must comply with the TCPA, the CAN-SPAM Act
      (for email-to-SMS), and CTIA Messaging Principles and Best Practices, including
      opt-in capture, opt-out honoring, and required disclosures.  Documents describing
      text marketing programs without confirmed CTIA compliance require human review.

  Layer 3 — FCC911Filter
      (FCC 911 and Emergency Service Compliance;
       administered by the Federal Communications Commission)
      Controls access to documents describing VoIP, wireless, multi-line telephone
      system (MLTS), and 988 Suicide & Crisis Lifeline routing compliance, enforcing
      FCC E911, RAY BAUM'S Act, Kari's Law, and FCC 21-86 requirements.

      FCC Order 05-116 — VoIP E911 Geographic Routing:
      The FCC's First E911 Order (FCC 05-116) requires interconnected VoIP providers
      to provide E911 service with automatic location information (ALI) and routing to
      the geographically appropriate Public Safety Answering Point (PSAP).  Documents
      describing VoIP services without confirmed E911 geographic routing capability
      are denied.

      FCC 20-100 — RAY BAUM'S Act §506 Dispatchable Location:
      The FCC's Implementing RAY BAUM'S Act Order (FCC 20-100) requires wireless
      carriers and certain VoIP providers to transmit dispatchable location information
      with 911 calls, enabling first responders to locate callers who cannot speak or
      do not know their location.  Documents describing wireless carrier 911 services
      without dispatchable location capability are denied.

      47 U.S.C. §1471 — Kari's Law (MLTS On-Site Notification):
      Kari's Law (47 U.S.C. §1471), enacted in 2018, requires that multi-line
      telephone systems (MLTS) allow users to dial 911 directly without a prefix or
      access code, and that the system provide simultaneous on-site notification (e.g.,
      to a front desk or security station) when a 911 call is placed.  Documents
      describing MLTS deployments without Kari's Law on-site notification capability
      are denied.

      FCC 21-86 — 988 Suicide & Crisis Lifeline Routing Compliance:
      The FCC's 988 Order (FCC 21-86) designates 988 as the three-digit dialing code
      for the National Suicide Prevention Lifeline and requires telecommunications
      providers to route 988 calls to the appropriate Lifeline center.  Documents
      describing crisis line routing without confirmed FCC 21-86 compliance require
      human review.

  Layer 4 — TelecomCrossBorderFilter
      (FCC International + OFAC Sanctions + FCC Covered List;
       administered by the FCC, OFAC, and the National Telecommunications and
       Information Administration)
      Controls access to documents involving telecom services to OFAC-sanctioned
      countries, international carrier authorization, cable landing licenses, and
      deployment of FCC Covered List equipment, enforcing OFAC sanctions, FCC Section
      214, cable landing license, and supply chain security requirements.

      OFAC Telecom Sanctions — Sanctioned Country Service Provision:
      The Office of Foreign Assets Control (OFAC) administers sanctions programs that
      prohibit providing telecommunications services to certain sanctioned countries,
      including North Korea (KP), Iran (IR), Cuba (CU), Syria (SY), and Belarus (BY),
      unless a specific OFAC license or regulatory authorization applies.  Documents
      describing telecom service provisioning to OFAC-sanctioned countries without a
      confirmed license are denied.

      47 U.S.C. §214 — FCC Section 214 International Carrier Authorization:
      Section 214 of the Communications Act requires telecommunications carriers to
      obtain FCC authorization before constructing, acquiring, or operating
      international transmission facilities or services.  International carriers
      operating without FCC Section 214 authorization are in violation of federal
      telecommunications law.  Documents describing international carrier operations
      without confirmed Section 214 authorization are denied.

      47 U.S.C. §35 — Cable Landing License (CN/RU Restricted):
      The Cable Landing License Act (47 U.S.C. §35) requires FCC approval for the
      construction and operation of submarine cables landing in the United States.
      The FCC has imposed conditions on or denied cable landing applications involving
      Chinese (CN) and Russian (RU) entities due to national security concerns.
      Documents describing cable landing projects involving CN or RU without FCC
      approval are denied.

      FCC Covered List — Covered Equipment Without Rip-and-Replace Waiver:
      The FCC's Covered List identifies communications equipment and services posing
      an unacceptable national security risk under the Secure and Trusted Communications
      Networks Act of 2019, including equipment from Huawei, ZTE, Hikvision, Dahua,
      and Hytera.  Deploying Covered List equipment in a network without a rip-and-
      replace waiver requires human review to determine whether the deployment is
      permissible under the FCC's supply chain security framework.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: OFAC-sanctioned countries for telecommunications service provisioning.
#: Providing telecom services to these countries without a license is denied.
OFAC_TELECOM_SANCTIONED: frozenset[str] = frozenset({"KP", "IR", "CU", "SY", "BY"})

#: Countries for which cable landing requires heightened FCC scrutiny.
#: Cable landing projects involving these countries require FCC approval.
CABLE_RESTRICTED: frozenset[str] = frozenset({"CN", "RU"})

#: Equipment vendors on the FCC Covered List under the Secure and Trusted
#: Communications Networks Act of 2019.
FCC_COVERED_LIST: frozenset[str] = frozenset({"Huawei", "ZTE", "Hikvision", "Dahua", "Hytera"})


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document.

    Fields
    ------
    decision     : "PERMITTED", "DENIED", "REQUIRES_HUMAN_REVIEW"
    regulation   : Short citation string (e.g. "47 CFR §64.2007")
    reason       : Human-readable explanation of the decision
    filter_name  : Name of the filter that produced this result
    """

    decision: str
    regulation: str
    reason: str
    filter_name: str

    @property
    def is_denied(self) -> bool:
        """Return True only when decision is exactly ``"DENIED"``."""
        return self.decision == "DENIED"


# ---------------------------------------------------------------------------
# Layer 1 — FCCCPNIFilter
#            Customer Proprietary Network Information (47 CFR Part 64)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FCCCPNIFilter:
    """Enforces FCC Customer Proprietary Network Information (CPNI) requirements.

    47 CFR §64.2007: CPNI disclosure without customer consent or opt-out → DENIED.

    47 CFR §64.2005(b): CPNI marketing outside existing service without
    opt-in consent → DENIED.

    47 CFR §64.2011: Third-party CPNI disclosure without CPNI safeguards → DENIED.

    CPNI Retention: CPNI records retained beyond 2 years without documented
    business need → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "FCCCPNIFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate FCC CPNI requirements for *doc*.

        Evaluation order
        ----------------
        1. cpni_consent_obtained is False → DENIED
           (47 CFR §64.2007 CPNI consent or opt-out requirement).
        2. marketing_existing_service is False and cpni_opt_in is False → DENIED
           (47 CFR §64.2005(b) opt-in for cross-category CPNI marketing).
        3. third_party_disclosure is True and third_party_safeguards is False → DENIED
           (47 CFR §64.2011 third-party CPNI safeguards requirement).
        4. cpni_retention_years > 2 → REQUIRES_HUMAN_REVIEW
           (CPNI data retention beyond 2-year limit without documented need).
        5. Otherwise → PERMITTED.
        """
        # 47 CFR §64.2007 — CPNI Consent or Opt-Out
        if not doc.get("cpni_consent_obtained", True):
            return FilterResult(
                decision="DENIED",
                regulation="47 CFR §64.2007 (CPNI Consent)",
                reason=(
                    "FCC 47 CFR §64.2007: CPNI disclosure or use described without customer "
                    "consent or a valid opt-out on file. Telecommunications carriers are required "
                    "to obtain customer approval before using or disclosing Customer Proprietary "
                    "Network Information (CPNI). Under the FCC's opt-out framework, carriers may "
                    "use CPNI for marketing within the customer's existing service category only "
                    "if the customer has been notified and has not opted out. Disclosing or using "
                    "CPNI without consent or a valid opt-out violates 47 CFR §64.2007."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 47 CFR §64.2005(b) — CPNI Marketing Outside Existing Service (Opt-In Required)
        if not doc.get("marketing_existing_service", True) and not doc.get("cpni_opt_in", False):
            return FilterResult(
                decision="DENIED",
                regulation="47 CFR §64.2005(b) (CPNI Opt-In)",
                reason=(
                    "FCC 47 CFR §64.2005(b): CPNI used for marketing outside the customer's "
                    "existing service category without confirmed affirmative opt-in consent. "
                    "The FCC's CPNI rules require carriers to obtain affirmative opt-in consent "
                    "before using a customer's CPNI to market services in service categories that "
                    "the customer does not already subscribe to with that carrier. Cross-category "
                    "CPNI marketing without opt-in consent violates 47 CFR §64.2005(b)."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 47 CFR §64.2011 — Third-Party CPNI Disclosure Without Safeguards
        if doc.get("third_party_disclosure", False) and not doc.get("third_party_safeguards", False):
            return FilterResult(
                decision="DENIED",
                regulation="47 CFR §64.2011 (CPNI Third-Party Safeguards)",
                reason=(
                    "FCC 47 CFR §64.2011: CPNI disclosed to a third party without the required "
                    "FCC CPNI safeguards in place. Telecommunications carriers that disclose "
                    "Customer Proprietary Network Information to third parties must implement "
                    "proprietary network information protection procedures as required by 47 CFR "
                    "§64.2011, including confidentiality agreements, access controls, and CPNI "
                    "training for third-party personnel. Third-party CPNI disclosure without "
                    "these safeguards violates the FCC's CPNI framework."
                ),
                filter_name=self.FILTER_NAME,
            )

        # CPNI Retention — Beyond 2 Years Without Documented Business Need
        if doc.get("cpni_retention_years", 0) > 2:
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="FCC CPNI Data Retention (2-Year Limit)",
                reason=(
                    "FCC CPNI Rules: CPNI records are retained beyond the standard 2-year "
                    "retention period without a documented business need or regulatory hold. "
                    "FCC rules require carriers to maintain CPNI-related records for a minimum "
                    "period sufficient to support enforcement investigations; retention beyond "
                    "two years without documented justification increases privacy risk and may "
                    "conflict with state privacy laws. Human review is required to determine "
                    "whether continued retention is justified, appropriately secured, and "
                    "consistent with applicable data minimization requirements."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="47 CFR Part 64 (CPNI)",
            reason=(
                "Document satisfies FCC CPNI requirements under 47 CFR Part 64, including "
                "customer consent or opt-out, opt-in for cross-category marketing, third-party "
                "disclosure safeguards, and CPNI data retention compliance."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 2 — TelecomPrivacyFilter
#            TCPA + State Telecom Privacy
#            (TCPA 47 U.S.C. §227; 47 CFR §64.1200; CA CPUC GO 107-B)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TelecomPrivacyFilter:
    """Enforces TCPA and state telecom privacy requirements.

    TCPA 47 U.S.C. §227: Automated calls/texts without prior express written
    consent → DENIED.

    47 CFR §64.1200: Robocall to DNC-registered number without DNC scrubbing
    → DENIED.

    California CPUC General Order 107-B: Call recording without two-party
    consent → DENIED.

    TCPA/CAN-SPAM/CTIA: Text marketing without CTIA compliance
    → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "TelecomPrivacyFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate TCPA and state telecom privacy requirements for *doc*.

        Evaluation order
        ----------------
        1. prior_express_consent is False → DENIED
           (TCPA 47 U.S.C. §227 prior express written consent for automated calls/texts).
        2. do_not_call_scrubbed is False → DENIED
           (47 CFR §64.1200 National Do-Not-Call Registry compliance).
        3. california_recording is True and two_party_consent is False → DENIED
           (California CPUC General Order 107-B two-party call recording consent).
        4. text_marketing is True and ctia_compliant is False → REQUIRES_HUMAN_REVIEW
           (TCPA/CAN-SPAM/CTIA text marketing compliance).
        5. Otherwise → PERMITTED.
        """
        # TCPA 47 U.S.C. §227 — Prior Express Written Consent for Automated Calls/Texts
        if not doc.get("prior_express_consent", True):
            return FilterResult(
                decision="DENIED",
                regulation="TCPA 47 U.S.C. §227 (Prior Express Consent)",
                reason=(
                    "TCPA 47 U.S.C. §227: Automated telephone calls or text messages described "
                    "without prior express written consent of the called party. The Telephone "
                    "Consumer Protection Act prohibits initiating any automated telephone call "
                    "(including calls using an automatic telephone dialing system or a prerecorded "
                    "voice) and automated text messages to a mobile telephone number unless the "
                    "recipient has given prior express written consent. Initiating automated "
                    "communications without such consent violates TCPA §227(b)(1)(A)."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 47 CFR §64.1200 — National Do-Not-Call Registry
        if not doc.get("do_not_call_scrubbed", True):
            return FilterResult(
                decision="DENIED",
                regulation="47 CFR §64.1200 (National Do-Not-Call Registry)",
                reason=(
                    "FCC 47 CFR §64.1200: Robocall or telephone solicitation described without "
                    "confirmed National Do-Not-Call (DNC) Registry scrubbing. Under 47 CFR "
                    "§64.1200 and the FTC's Telemarketing Sales Rule, telemarketers and telephone "
                    "solicitors are prohibited from calling numbers registered on the National "
                    "DNC Registry unless an established business relationship, prior express "
                    "written consent, or another applicable exemption applies. Initiating "
                    "solicitation calls without DNC registry scrubbing violates federal "
                    "telemarketing law."
                ),
                filter_name=self.FILTER_NAME,
            )

        # California CPUC General Order 107-B — Two-Party Call Recording Consent
        if doc.get("california_recording", False) and not doc.get("two_party_consent", False):
            return FilterResult(
                decision="DENIED",
                regulation="California CPUC GO 107-B (Two-Party Consent)",
                reason=(
                    "California CPUC General Order 107-B / California Invasion of Privacy Act "
                    "(CIPA, Penal Code §632): Call recording in California described without "
                    "two-party consent. California is an all-party consent state — all parties "
                    "to a telephone conversation must consent to the recording. The California "
                    "CPUC General Order 107-B applies to telephone communications conducted "
                    "through California telecommunications networks. Recording a call without "
                    "all-party consent violates California Penal Code §632 and may give rise "
                    "to civil penalties under CIPA."
                ),
                filter_name=self.FILTER_NAME,
            )

        # TCPA / CAN-SPAM / CTIA — Text Marketing Without CTIA Compliance
        if doc.get("text_marketing", False) and not doc.get("ctia_compliant", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="TCPA/CAN-SPAM/CTIA (Text Marketing Compliance)",
                reason=(
                    "TCPA/CAN-SPAM/CTIA: Text marketing program described without confirmed CTIA "
                    "Messaging Principles and Best Practices compliance. Commercial text message "
                    "marketing programs must comply with the TCPA (opt-in capture, opt-out "
                    "honoring), the CAN-SPAM Act where applicable (email-to-SMS), and CTIA "
                    "Messaging Principles and Best Practices including required program "
                    "disclosures, STOP opt-out commands, and message content standards. Human "
                    "review is required to verify CTIA compliance before the text marketing "
                    "program is authorized."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="TCPA 47 U.S.C. §227; 47 CFR §64.1200; CA CPUC GO 107-B",
            reason=(
                "Document satisfies TCPA automated calling consent, National Do-Not-Call "
                "Registry compliance, California two-party call recording consent, and "
                "CTIA text marketing compliance requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 3 — FCC911Filter
#            FCC 911 and Emergency Service Compliance
#            (FCC Order 05-116; FCC 20-100; 47 U.S.C. §1471; FCC 21-86)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FCC911Filter:
    """Enforces FCC 911 and emergency service compliance requirements.

    FCC Order 05-116: VoIP provider without E911 geographic routing → DENIED.

    FCC 20-100 (RAY BAUM'S Act §506): Wireless carrier without dispatchable
    location → DENIED.

    47 U.S.C. §1471 (Kari's Law): MLTS without on-site 911 notification → DENIED.

    FCC 21-86: 988 Suicide & Crisis Lifeline routing without FCC compliance
    → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "FCC911Filter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate FCC 911 and emergency service compliance requirements for *doc*.

        Evaluation order
        ----------------
        1. voip_e911_routing is False → DENIED
           (FCC Order 05-116 VoIP E911 geographic routing requirement).
        2. wireless_dispatchable_location is False → DENIED
           (FCC 20-100 RAY BAUM'S Act §506 dispatchable location for wireless carriers).
        3. mlts_system is True and karis_law_compliant is False → DENIED
           (47 U.S.C. §1471 Kari's Law MLTS on-site 911 notification).
        4. crisis_line_routing is True and fcc_988_compliant is False → REQUIRES_HUMAN_REVIEW
           (FCC 21-86 988 Suicide & Crisis Lifeline routing compliance).
        5. Otherwise → PERMITTED.
        """
        # FCC Order 05-116 — VoIP E911 Geographic Routing
        if not doc.get("voip_e911_routing", True):
            return FilterResult(
                decision="DENIED",
                regulation="FCC Order 05-116 (VoIP E911)",
                reason=(
                    "FCC Order 05-116 (First E911 Order): VoIP telecommunications service "
                    "described without confirmed E911 geographic routing capability. The FCC's "
                    "First E911 Order requires interconnected VoIP providers to transmit "
                    "automatic location information (ALI) and route 911 calls to the "
                    "geographically appropriate Public Safety Answering Point (PSAP). VoIP "
                    "providers that cannot provide E911 service with accurate geographic routing "
                    "are violating FCC Order 05-116 and are required to prominently notify "
                    "customers of E911 limitations prior to activation."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FCC 20-100 — RAY BAUM'S Act §506 Dispatchable Location
        if not doc.get("wireless_dispatchable_location", True):
            return FilterResult(
                decision="DENIED",
                regulation="FCC 20-100 RAY BAUM'S Act §506 (Dispatchable Location)",
                reason=(
                    "FCC 20-100 (Implementing RAY BAUM'S Act Order): Wireless carrier 911 service "
                    "described without dispatchable location information capability. RAY BAUM'S Act "
                    "§506 and the FCC's implementing order (FCC 20-100) require that wireless "
                    "carriers and covered VoIP providers transmit dispatchable location information "
                    "— the street address, floor level, and suite or apartment number — with all "
                    "911 calls to enable first responders to locate callers who cannot communicate "
                    "their location. Failure to provide dispatchable location violates FCC 20-100."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 47 U.S.C. §1471 — Kari's Law (MLTS On-Site 911 Notification)
        if doc.get("mlts_system", False) and not doc.get("karis_law_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="47 U.S.C. §1471 (Kari's Law)",
                reason=(
                    "Kari's Law (47 U.S.C. §1471): Multi-line telephone system (MLTS) deployment "
                    "described without Kari's Law on-site 911 notification compliance. Kari's Law, "
                    "enacted in 2018 and effective since February 2020, requires that MLTS systems "
                    "allow users to dial 911 directly without a prefix or access code, and that the "
                    "system provide simultaneous on-site notification (e.g., to a front desk, "
                    "security station, or building management office) when a 911 call is placed. "
                    "Deploying an MLTS that does not comply with Kari's Law requirements violates "
                    "47 U.S.C. §1471."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FCC 21-86 — 988 Suicide & Crisis Lifeline Routing Compliance
        if doc.get("crisis_line_routing", False) and not doc.get("fcc_988_compliant", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="FCC 21-86 (988 Suicide & Crisis Lifeline)",
                reason=(
                    "FCC 21-86 (988 Order): Crisis line routing described without confirmed FCC "
                    "21-86 compliance. The FCC's 988 Order designates 988 as the three-digit dialing "
                    "code for the National Suicide Prevention Lifeline and requires all "
                    "telecommunications carriers, interconnected VoIP providers, and one-way VoIP "
                    "providers to route 988 calls to the appropriate Lifeline center. Human review "
                    "is required to verify that 988 routing has been implemented in compliance with "
                    "FCC 21-86 and that crisis line calls are being correctly routed."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="FCC Order 05-116; FCC 20-100; 47 U.S.C. §1471; FCC 21-86",
            reason=(
                "Document satisfies FCC 911 and emergency service compliance requirements, "
                "including VoIP E911 geographic routing, wireless dispatchable location, "
                "Kari's Law MLTS on-site notification, and 988 crisis line routing compliance."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 4 — TelecomCrossBorderFilter
#            FCC International + OFAC Sanctions + FCC Covered List
#            (OFAC; 47 U.S.C. §214; 47 U.S.C. §35; Secure Networks Act)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TelecomCrossBorderFilter:
    """Enforces FCC international authorization, OFAC sanctions, and supply chain requirements.

    OFAC Telecom Sanctions: Telecom service to OFAC-sanctioned country
    (KP/IR/CU/SY/BY) without license → DENIED.

    47 U.S.C. §214: International carrier without FCC Section 214
    authorization → DENIED.

    47 U.S.C. §35: Cable landing to CN/RU without FCC approval → DENIED.

    FCC Covered List: Covered equipment (Huawei/ZTE/Hikvision/Dahua/Hytera)
    in network without rip-and-replace waiver → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "TelecomCrossBorderFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate FCC international, OFAC, and supply chain requirements for *doc*.

        Evaluation order
        ----------------
        1. destination_country in OFAC_TELECOM_SANCTIONED → DENIED
           (OFAC sanctions prohibiting telecom services to sanctioned countries).
        2. international_carrier is True and fcc_214_authorization is False → DENIED
           (47 U.S.C. §214 FCC Section 214 international carrier authorization).
        3. cable_landing is True and destination_country in CABLE_RESTRICTED → DENIED
           (47 U.S.C. §35 cable landing license for CN/RU-involved projects).
        4. covered_list_equipment is in FCC_COVERED_LIST → REQUIRES_HUMAN_REVIEW
           (FCC Covered List equipment without rip-and-replace waiver).
        5. Otherwise → PERMITTED.
        """
        destination_country = doc.get("destination_country", "")
        covered_list_equipment = doc.get("covered_list_equipment", "")

        # OFAC Telecom Sanctions — Sanctioned Country Service Provision
        if destination_country in OFAC_TELECOM_SANCTIONED:
            return FilterResult(
                decision="DENIED",
                regulation="OFAC Telecom Sanctions (Sanctioned Country)",
                reason=(
                    f"OFAC Telecom Sanctions: Telecommunications service provision described to "
                    f"OFAC-sanctioned country '{destination_country}' without a confirmed OFAC "
                    f"license or authorization. OFAC sanctions programs prohibit U.S. persons "
                    f"and entities from providing telecommunications services to North Korea (KP), "
                    f"Iran (IR), Cuba (CU), Syria (SY), and Belarus (BY) without a specific OFAC "
                    f"license or applicable regulatory authorization. Providing telecom services to "
                    f"sanctioned countries without authorization violates OFAC regulations and may "
                    f"result in civil and criminal penalties."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 47 U.S.C. §214 — FCC Section 214 International Carrier Authorization
        if doc.get("international_carrier", False) and not doc.get("fcc_214_authorization", False):
            return FilterResult(
                decision="DENIED",
                regulation="47 U.S.C. §214 (FCC Section 214 Authorization)",
                reason=(
                    "FCC 47 U.S.C. §214: International carrier operations described without a "
                    "confirmed FCC Section 214 authorization. Section 214 of the Communications "
                    "Act of 1934 requires telecommunications carriers to obtain FCC authorization "
                    "before constructing, acquiring, or operating lines or facilities for the "
                    "transmission of interstate or foreign communications. International carriers "
                    "that operate without Section 214 authorization are in violation of federal "
                    "telecommunications law and subject to FCC enforcement action."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 47 U.S.C. §35 — Cable Landing License (CN/RU Restricted Countries)
        if doc.get("cable_landing", False) and destination_country in CABLE_RESTRICTED:
            return FilterResult(
                decision="DENIED",
                regulation="47 U.S.C. §35 (Cable Landing License)",
                reason=(
                    f"FCC 47 U.S.C. §35 (Cable Landing License Act): Submarine cable landing "
                    f"project involving '{destination_country}' described without FCC cable landing "
                    f"license approval. The Cable Landing License Act requires FCC approval for the "
                    f"construction and operation of submarine cables landing in the United States. "
                    f"The FCC has imposed conditions on or denied applications involving Chinese "
                    f"(CN) and Russian (RU) entities due to national security concerns raised by "
                    f"the interagency Team Telecom review process. Cable landing projects involving "
                    f"CN or RU require affirmative FCC approval before proceeding."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FCC Covered List — Covered Equipment Without Rip-and-Replace Waiver
        if covered_list_equipment in FCC_COVERED_LIST:
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="FCC Covered List (Secure Networks Act)",
                reason=(
                    f"FCC Covered List (Secure and Trusted Communications Networks Act of 2019): "
                    f"Network deployment described using covered equipment from '{covered_list_equipment}', "
                    f"which appears on the FCC's Covered List of communications equipment and "
                    f"services posing an unacceptable national security risk. The Secure Networks "
                    f"Act prohibits the use of Universal Service Fund money to purchase covered "
                    f"equipment and establishes a reimbursement program for eligible carriers to "
                    f"remove and replace such equipment. Human review is required to determine "
                    f"whether a rip-and-replace waiver or reimbursement authorization applies."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="OFAC; 47 U.S.C. §214; 47 U.S.C. §35; FCC Covered List",
            reason=(
                "Document satisfies FCC international authorization, OFAC telecom sanctions "
                "screening, cable landing license, and FCC Covered List supply chain security "
                "requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def run_pipeline(doc: dict) -> list[FilterResult]:
    """Run all four telecom FCC CPNI compliance filter layers against *doc*.

    Returns a list of FilterResult objects, one per layer evaluated.  The
    pipeline short-circuits on the first DENIED decision; subsequent filters
    are not evaluated for denied documents.
    """
    filters = [
        FCCCPNIFilter(),
        TelecomPrivacyFilter(),
        FCC911Filter(),
        TelecomCrossBorderFilter(),
    ]
    results: list[FilterResult] = []
    for flt in filters:
        result = flt.filter(doc)
        results.append(result)
        if result.is_denied:
            break
    return results


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Telecommunications / FCC CPNI Compliance RAG Pipeline — Demo ===\n")

    # --- CPNI without consent ---
    doc_no_cpni_consent = {
        "doc_id": "fcc-001",
        "cpni_consent_obtained": False,
    }
    print("Document: CPNI disclosed without customer consent")
    for r in run_pipeline(doc_no_cpni_consent):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Automated calls without TCPA consent ---
    doc_no_tcpa_consent = {
        "doc_id": "fcc-002",
        "cpni_consent_obtained": True,
        "prior_express_consent": False,
    }
    print("Document: Automated calls without prior express consent")
    for r in run_pipeline(doc_no_tcpa_consent):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- VoIP without E911 routing ---
    doc_no_e911 = {
        "doc_id": "fcc-003",
        "cpni_consent_obtained": True,
        "prior_express_consent": True,
        "do_not_call_scrubbed": True,
        "voip_e911_routing": False,
    }
    print("Document: VoIP service without E911 geographic routing")
    for r in run_pipeline(doc_no_e911):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Telecom service to sanctioned country ---
    doc_sanctioned_country = {
        "doc_id": "fcc-004",
        "cpni_consent_obtained": True,
        "prior_express_consent": True,
        "do_not_call_scrubbed": True,
        "voip_e911_routing": True,
        "wireless_dispatchable_location": True,
        "destination_country": "KP",
    }
    print("Document: Telecom service to OFAC-sanctioned country (KP)")
    for r in run_pipeline(doc_sanctioned_country):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- CPNI retention review ---
    doc_cpni_retention = {
        "doc_id": "fcc-005",
        "cpni_consent_obtained": True,
        "cpni_retention_years": 4,
    }
    print("Document: CPNI records retained 4 years (REQUIRES_HUMAN_REVIEW)")
    for r in run_pipeline(doc_cpni_retention):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Fully compliant telecom document ---
    doc_compliant = {
        "doc_id": "fcc-006",
        "cpni_consent_obtained": True,
        "marketing_existing_service": True,
        "cpni_opt_in": True,
        "third_party_disclosure": False,
        "third_party_safeguards": True,
        "cpni_retention_years": 1,
        "prior_express_consent": True,
        "do_not_call_scrubbed": True,
        "california_recording": False,
        "two_party_consent": True,
        "text_marketing": False,
        "ctia_compliant": True,
        "voip_e911_routing": True,
        "wireless_dispatchable_location": True,
        "mlts_system": False,
        "karis_law_compliant": True,
        "crisis_line_routing": False,
        "fcc_988_compliant": True,
        "destination_country": "CA",
        "international_carrier": False,
        "fcc_214_authorization": True,
        "cable_landing": False,
        "covered_list_equipment": "",
    }
    print("Document: Fully compliant telecom document")
    for r in run_pipeline(doc_compliant):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()
