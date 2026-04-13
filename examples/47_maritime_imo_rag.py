"""
Maritime / Shipping IMO Compliance RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pre-filter for platforms
that process documents related to maritime shipping, vessel operations, port facility
management, seafarer certification, and cross-border vessel movements.  Four
independent filter layers run sequentially; a document must pass all four to be
returned to the caller.

Commercial use cases:

  +------------------------------------------------------------------+-----------------------------------------------+
  | Platform / Product                                               | Applicable Regulation(s)                      |
  +------------------------------------------------------------------+-----------------------------------------------+
  | Vessel fleet management and operations compliance systems        | SOLAS Chapter I, III; ISM Code DOC/SMC        |
  | Ship safety management system (SMS) document platforms          | ISM Code 9 CFR §13.120; IMO Res. A.741(18)   |
  | Marine pollution prevention compliance systems                  | MARPOL Annex I, VI; MEPC.176(58) Tier III     |
  | Bunkering and fuel management platforms                         | MARPOL Annex VI Reg. 14 sulfur limits         |
  | Ship and port security management systems                       | ISPS Code Part A; SOLAS Chapter XI-2          |
  | Port facility management and security compliance platforms      | ISPS Code Part B; PFSP approval requirements  |
  | Sanctions screening and vessel tracking systems                 | OFAC SDN List; Paris/Tokyo MOU PSC            |
  | US customs advance arrival notification systems                 | 33 CFR §160.212 CBP 96-hour NOA requirements  |
  | AI/ML-powered maritime document retrieval and analysis          | IMO SOLAS 1974 as amended; MARPOL 73/78       |
  | Seafarer certification and STCW compliance platforms            | STCW 78 as amended; ISM Code §6 SMS           |
  +------------------------------------------------------------------+-----------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — IMOSafetyFilter
      (SOLAS Safety Requirements — SOLAS Chapter I, III; ISM Code;
       administered by the International Maritime Organization and flag states)
      Controls access to documents related to vessel safety certificates, life-saving
      appliance certification, safety management system compliance, and ISM Code
      audit currency, enforcing safety certificate requirements for vessels operating
      in international waters.

      SOLAS Chapter I — Safety Certificate: Every ship engaged in international
      voyages must hold a valid SOLAS Chapter I Safety Certificate (Passenger Ship
      Safety Certificate, Cargo Ship Safety Construction Certificate, or equivalent)
      issued or recognized by the flag state administration.  Documents describing
      vessel operations without a valid SOLAS Chapter I Safety Certificate are denied.

      ISM Code — Document of Compliance (DOC) and Safety Management Certificate
      (SMC): The International Safety Management Code (ISM Code, adopted under
      SOLAS Chapter IX) requires that every shipping company hold a Document of
      Compliance (DOC) issued by the flag state, and that every vessel hold a Safety
      Management Certificate (SMC) verifying that the vessel's Safety Management
      System (SMS) meets ISM Code requirements.  Documents describing vessel
      operations without confirmed ISM Code DOC and SMC are denied.

      SOLAS Chapter III — Life-Saving Appliances (LSA) Certificate: Passenger
      vessels must hold a SOLAS Chapter III life-saving appliance certificate
      confirming that all required life jackets, lifeboats, rescue boats, and
      pyrotechnic equipment have been inspected and certified.  Passenger vessel
      documents without a valid LSA certificate are denied.

      ISM Code §3.1 — Annual ISM Audit: The ISM Code requires periodic verification
      audits of the Safety Management System.  A vessel whose ISM audit is overdue
      by more than five years requires human review to determine whether an interim
      certificate has been issued and whether continued operation is authorized.

  Layer 2 — MARPOLFilter
      (Marine Pollution Prevention — MARPOL 73/78 Annexes I and VI;
       administered by the International Maritime Organization and flag states)
      Controls access to documents describing vessel discharges, fuel compliance,
      and emissions in Emission Control Areas (ECAs), enforcing pollution prevention
      certificate requirements and fuel quality standards under MARPOL.

      MARPOL Annex I — International Oil Pollution Prevention (IOPP) Certificate:
      Every ship of 400 gross tonnage and above and every oil tanker of 150 gross
      tonnage and above must hold a valid MARPOL Annex I International Oil Pollution
      Prevention (IOPP) Certificate issued under Reg. 7 of MARPOL Annex I.
      Documents describing vessel operations without a valid IOPP Certificate are
      denied.

      MARPOL Annex I Reg. 17 — Oil Record Book (ORB): Every ship must maintain an
      Oil Record Book (ORB) recording all operations involving the discharge of oily
      water or bilge water.  Documents describing oily water discharge operations
      without Oil Record Book entries are denied as failing to meet the mandatory
      recording requirement under MARPOL Annex I Reg. 17.

      MARPOL Annex VI Reg. 13 Tier III — NOx Emission Certificate: Ships with
      marine diesel engines installed on or after 1 January 2016 operating in a NOx
      Tier III Emission Control Area (ECA-NOx, including North American and US
      Caribbean ECAs) must comply with Tier III NOx emission limits and hold a valid
      Tier III NOx Technical Code certification.  Post-2016 vessels operating in an
      ECA without a Tier III NOx certificate are denied.

      MARPOL Annex VI Reg. 14 — Sulfur Content: The global sulfur limit for marine
      fuel oil outside ECAs is 0.50% m/m (effective 1 January 2020, IMO 2020).
      Documents describing vessel operations with fuel sulfur content exceeding 0.50%
      m/m without an approved equivalent arrangement (scrubber exhaust gas cleaning
      system) require human review to determine compliance pathway.

  Layer 3 — ISPSFilter
      (International Ship and Port Facility Security Code — ISPS Code, SOLAS Ch. XI-2;
       administered by the International Maritime Organization, flag states, and
       SOLAS contracting governments)
      Controls access to documents related to vessel and port facility security
      certifications, ship security plans, port facility security plans, and security
      level escalations, enforcing ISPS Code security certification requirements.

      ISPS Code Part A §19.1 — International Ship Security Certificate (ISSC):
      Every ship required to comply with the ISPS Code must hold a valid International
      Ship Security Certificate (ISSC) issued or verified by the flag state
      Administration, confirming that the Ship Security Assessment (SSA) has been
      conducted and that the Ship Security Plan (SSP) meets ISPS Code requirements.
      Documents describing vessel operations without a valid ISSC are denied.

      ISPS Code Part A §9.4 — Ship Security Plan (SSP) Flag State Approval:
      Every ship subject to the ISPS Code must have a Ship Security Plan (SSP)
      approved by the flag state Administration.  Documents describing vessel security
      operations with a SSP that has not received flag state approval are denied.

      ISPS Code Part B §16 — Port Facility Security Plan (PFSP):
      Every port facility handling ships engaged in international voyages must have a
      Port Facility Security Plan (PFSP) approved by the SOLAS contracting government
      in whose territory the port facility is located.  Documents describing port
      facility operations without an approved PFSP are denied.

      ISPS Code §9.1 — Security Level 3 Maritime Security Communication:
      When Security Level 3 is declared (a specific threat of a security incident
      is probable or imminent), the Ship Security Officer must communicate maritime
      security information to the nearest coastal state authority.  Documents
      describing Security Level 3 conditions without confirmation that the required
      maritime security communication has been made require human review.

  Layer 4 — MaritimeCrossBorderFilter
      (Port State Control + OFAC Sanctions + US CBP Advance Notice;
       administered by the Paris MOU, Tokyo MOU, USCG, CBP, and OFAC)
      Controls access to documents involving vessel calls at PSC-deficient ports,
      vessels flagged under OFAC-sanctioned flag states, crew from OFAC-restricted
      nationalities, and vessel advance notice of arrival requirements for US waters,
      enforcing port state control, sanctions screening, and US customs requirements.

      Paris/Tokyo MOU — Port State Control Deficient Ports: Port State Control
      organizations under the Paris MOU and Tokyo MOU publish lists of ports with
      known deficiencies in maritime safety and security enforcement.  Documents
      describing vessel calls at PSC-deficient ports without prior clearance are
      denied as presenting unacceptable regulatory and safety risk under Paris MOU
      Memorandum of Understanding provisions.

      OFAC SDN List — Sanctioned Flag States: Vessels flagged under OFAC-designated
      sanctioned flag states — including the Democratic People's Republic of Korea
      (KP), the Islamic Republic of Iran (IR), the Syrian Arab Republic (SY), and
      Cuba (CU) — are subject to broad OFAC sanctions under the North Korea
      Sanctions Regulations, Iran Sanctions, and related programs.  Documents
      describing operations involving vessels under OFAC-sanctioned flag states are
      denied.

      OFAC SDN Crew Nationalities: Crew members who are nationals of OFAC-restricted
      countries (KP: North Korea, IR: Iran) are subject to OFAC-administered sanctions
      and may require an OFAC license before payments or services are provided.
      Documents describing vessel operations with crew from OFAC-restricted
      nationalities without a confirmed OFAC license are denied.

      33 CFR §160.212 — CBP 96-Hour Advance Notice of Arrival (NOA): Vessels
      arriving in US waters must submit an advance notice of arrival (NOA) to US
      Customs and Border Protection (CBP) at least 96 hours before entering a US
      port.  Documents describing vessel entry into US waters without confirmation
      that the 96-hour CBP NOA has been submitted require human review.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Ports identified as deficient by Paris MOU or Tokyo MOU Port State Control.
#: Vessels calling these ports without prior PSC clearance are denied.
PSC_DEFICIENT_PORTS: frozenset[str] = frozenset(
    {"Bandar_Abbas", "Bushehr", "Wonsan", "Nampo", "Tartus"}
)

#: OFAC-sanctioned flag states under active broad-based sanctions programs.
#: Vessels flagged under these states are denied.
OFAC_SANCTIONED_FLAG_STATES: frozenset[str] = frozenset({"KP", "IR", "SY", "CU"})

#: Crew nationalities subject to OFAC restrictions requiring license review.
OFAC_CREW_NATIONALITIES: frozenset[str] = frozenset({"KP", "IR"})


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document.

    Fields
    ------
    decision     : "PERMITTED", "DENIED", "REQUIRES_HUMAN_REVIEW"
    regulation   : Short citation string (e.g. "SOLAS Chapter I")
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
# Layer 1 — IMOSafetyFilter
#            SOLAS Safety Requirements (SOLAS Ch. I, III; ISM Code)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IMOSafetyFilter:
    """Enforces IMO SOLAS and ISM Code safety certificate requirements.

    SOLAS Chapter I: Vessel without SOLAS Chapter I Safety Certificate → DENIED.

    ISM Code DOC/SMC: Vessel without ISM Code Document of Compliance and
    Safety Management Certificate → DENIED.

    SOLAS Chapter III: Passenger vessel without life-saving appliance
    certificate → DENIED.

    ISM Code §3.1: ISM audit overdue (> 5 years) → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "IMOSafetyFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate SOLAS and ISM Code safety requirements for *doc*.

        Evaluation order
        ----------------
        1. Vessel without solas_certificate → DENIED
           (SOLAS Chapter I Safety Certificate).
        2. Vessel without ism_doc_smc → DENIED
           (ISM Code Document of Compliance / Safety Management Certificate).
        3. Passenger vessel (vessel_type == "passenger") without lsa_cert → DENIED
           (SOLAS Chapter III life-saving appliances certificate).
        4. ism_audit_years > 5 → REQUIRES_HUMAN_REVIEW
           (ISM Code periodic audit overdue).
        5. Otherwise → PERMITTED.
        """
        vessel_type = doc.get("vessel_type", "")
        is_passenger = vessel_type == "passenger"

        # SOLAS Chapter I — Safety Certificate
        if not doc.get("solas_certificate", False):
            return FilterResult(
                decision="DENIED",
                regulation="SOLAS Chapter I",
                reason=(
                    "IMO SOLAS Chapter I: Vessel operations described without a valid SOLAS "
                    "Chapter I Safety Certificate. Every ship engaged in international voyages "
                    "must hold a current Safety Certificate (Passenger Ship Safety Certificate, "
                    "Cargo Ship Safety Construction Certificate, or Cargo Ship Safety Equipment "
                    "Certificate as applicable) issued or recognized by the flag state "
                    "administration under the authority of SOLAS Chapter I. Operating in "
                    "international waters without a valid SOLAS Chapter I certificate is "
                    "prohibited under international maritime law."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ISM Code — Document of Compliance (DOC) and Safety Management Certificate (SMC)
        if not doc.get("ism_doc_smc", False):
            return FilterResult(
                decision="DENIED",
                regulation="ISM Code (SOLAS Chapter IX)",
                reason=(
                    "IMO ISM Code (SOLAS Chapter IX): Vessel operations described without a "
                    "confirmed ISM Code Document of Compliance (DOC) and Safety Management "
                    "Certificate (SMC). The International Safety Management Code requires that "
                    "every shipping company hold a DOC issued by the flag state and that every "
                    "vessel hold an SMC verifying that the vessel's Safety Management System "
                    "(SMS) has been audited and found to comply with the ISM Code. Operating "
                    "without valid DOC and SMC constitutes a SOLAS Chapter IX violation."
                ),
                filter_name=self.FILTER_NAME,
            )

        # SOLAS Chapter III — Passenger Vessel Life-Saving Appliances Certificate
        if is_passenger and not doc.get("lsa_cert", False):
            return FilterResult(
                decision="DENIED",
                regulation="SOLAS Chapter III",
                reason=(
                    "IMO SOLAS Chapter III: Passenger vessel operations described without a "
                    "valid life-saving appliance (LSA) certificate under SOLAS Chapter III. "
                    "Passenger ships must hold a current LSA certificate confirming that all "
                    "required life jackets, immersion suits, lifeboats, rescue boats, line-throwing "
                    "appliances, and pyrotechnic equipment have been inspected and certified in "
                    "accordance with the LSA Code. Operating a passenger vessel without a valid "
                    "LSA certificate is a SOLAS Chapter III violation."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ISM Code — ISM Audit Overdue (> 5 years)
        if doc.get("ism_audit_years", 0) > 5:
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="ISM Code §3.1 (Audit Currency)",
                reason=(
                    "IMO ISM Code §3.1: Vessel ISM audit is overdue; last audit recorded more "
                    "than 5 years ago. The ISM Code requires periodic verification audits of the "
                    "Safety Management System by the flag state Administration or a recognized "
                    "organization. An overdue ISM audit may indicate an expired or lapsed SMC. "
                    "Human review is required to determine whether an interim certificate has "
                    "been issued and whether continued vessel operation is currently authorized."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="SOLAS Chapter I, III; ISM Code",
            reason=(
                "Document satisfies IMO SOLAS and ISM Code safety certificate requirements, "
                "including SOLAS Chapter I Safety Certificate, ISM Code DOC/SMC, and applicable "
                "life-saving appliance certification."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 2 — MARPOLFilter
#            Marine Pollution Prevention (MARPOL 73/78 Annexes I and VI)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MARPOLFilter:
    """Enforces MARPOL marine pollution prevention certificate requirements.

    MARPOL Annex I: Vessel without IOPP Certificate → DENIED.

    MARPOL Annex I Reg. 17: Oily water discharge without Oil Record Book
    entries → DENIED.

    MARPOL Annex VI Reg. 13 Tier III: Post-2016 vessel in ECA without Tier III
    NOx certificate → DENIED.

    MARPOL Annex VI Reg. 14: Fuel sulfur content > 0.5% m/m without equivalent
    arrangement → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "MARPOLFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate MARPOL pollution prevention requirements for *doc*.

        Evaluation order
        ----------------
        1. Vessel without iopp_certificate → DENIED
           (MARPOL Annex I International Oil Pollution Prevention Certificate).
        2. Oily water discharge without oil_record_book → DENIED
           (MARPOL Annex I Reg. 17 Oil Record Book requirement).
        3. vessel_build_year >= 2016 operating in ECA without nox_tier3_cert → DENIED
           (MARPOL Annex VI Reg. 13 Tier III NOx Technical Code).
        4. fuel_sulfur_pct > 0.5 → REQUIRES_HUMAN_REVIEW
           (MARPOL Annex VI Reg. 14 IMO 2020 sulfur limit).
        5. Otherwise → PERMITTED.
        """
        vessel_build_year = doc.get("vessel_build_year", 2000)
        is_post_2016 = vessel_build_year >= 2016
        in_eca = doc.get("in_eca", False)

        # MARPOL Annex I — IOPP Certificate
        if not doc.get("iopp_certificate", False):
            return FilterResult(
                decision="DENIED",
                regulation="MARPOL Annex I (IOPP Certificate)",
                reason=(
                    "IMO MARPOL Annex I: Vessel operations described without a valid "
                    "International Oil Pollution Prevention (IOPP) Certificate. Every ship of "
                    "400 gross tonnage and above, and every oil tanker of 150 gross tonnage and "
                    "above, engaged on voyages to ports or offshore terminals under the jurisdiction "
                    "of other MARPOL parties must hold a valid IOPP Certificate issued under "
                    "MARPOL Annex I Regulation 7. Operating without a valid IOPP Certificate "
                    "constitutes a violation of MARPOL 73/78 Annex I."
                ),
                filter_name=self.FILTER_NAME,
            )

        # MARPOL Annex I Reg. 17 — Oil Record Book
        if not doc.get("oil_record_book", False):
            return FilterResult(
                decision="DENIED",
                regulation="MARPOL Annex I Reg. 17 (Oil Record Book)",
                reason=(
                    "IMO MARPOL Annex I Regulation 17: Oily water discharge operations described "
                    "without Oil Record Book (ORB) entries. Every ship of 400 gross tonnage and "
                    "above must maintain an Oil Record Book Part I (Machinery Space Operations) "
                    "in which all operations involving the discharge of oily water, including "
                    "overboard discharge with approved equipment and disposal to reception "
                    "facilities, must be recorded. Oily water discharge without ORB entries "
                    "constitutes a violation of MARPOL Annex I Reg. 17."
                ),
                filter_name=self.FILTER_NAME,
            )

        # MARPOL Annex VI Reg. 13 Tier III — NOx Certificate for Post-2016 Vessels in ECA
        if is_post_2016 and in_eca and not doc.get("nox_tier3_cert", False):
            return FilterResult(
                decision="DENIED",
                regulation="MARPOL Annex VI Reg. 13 (Tier III NOx)",
                reason=(
                    "IMO MARPOL Annex VI Regulation 13: Post-2016 vessel operating in an NOx "
                    "Tier III Emission Control Area (ECA-NOx) without a valid Tier III NOx "
                    "Technical Code certification. Marine diesel engines installed on or after "
                    "1 January 2016 that operate in designated Tier III ECAs (including the "
                    "North American ECA and the US Caribbean Sea ECA) must comply with MARPOL "
                    "Annex VI Tier III NOx emission limits (< 3.4 g/kWh at n < 130 rpm) and "
                    "hold a valid Tier III NOx Technical Code certificate."
                ),
                filter_name=self.FILTER_NAME,
            )

        # MARPOL Annex VI Reg. 14 — Sulfur Content (IMO 2020 Global Cap)
        if doc.get("fuel_sulfur_pct", 0) > 0.5:
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="MARPOL Annex VI Reg. 14 (Sulfur Limit)",
                reason=(
                    "IMO MARPOL Annex VI Regulation 14: Vessel fuel sulfur content exceeds the "
                    "global 0.50% m/m sulfur cap (IMO 2020, effective 1 January 2020). Outside "
                    "of designated Emission Control Areas, the maximum allowable sulfur content "
                    "in fuel oil used on board ships is 0.50% m/m. Vessels exceeding this limit "
                    "must have an approved equivalent arrangement such as an exhaust gas cleaning "
                    "system (scrubber) approved under MARPOL Annex VI Reg. 4. Human review is "
                    "required to verify the approved compliance pathway."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="MARPOL Annex I, VI",
            reason=(
                "Document satisfies MARPOL marine pollution prevention requirements under "
                "MARPOL 73/78 Annexes I and VI, including IOPP Certificate, Oil Record Book, "
                "NOx Tier III certification, and fuel sulfur content compliance."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 3 — ISPSFilter
#            International Ship and Port Facility Security Code
#            (ISPS Code, SOLAS Chapter XI-2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ISPSFilter:
    """Enforces ISPS Code ship and port facility security certificate requirements.

    ISPS Code §19.1: Vessel without International Ship Security Certificate
    (ISSC) → DENIED.

    ISPS Code §9.4: Ship Security Plan (SSP) not approved by flag state → DENIED.

    ISPS Code §16: Port facility without approved Port Facility Security Plan
    (PFSP) → DENIED.

    ISPS Code §9.1: Security Level 3 without maritime security communication
    to coastal state → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "ISPSFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate ISPS Code security certificate requirements for *doc*.

        Evaluation order
        ----------------
        1. Vessel without issc_certificate → DENIED
           (ISPS Code Part A §19.1 International Ship Security Certificate).
        2. Vessel SSP not flag-state-approved (ssp_approved=False) → DENIED
           (ISPS Code Part A §9.4 Ship Security Plan approval).
        3. facility_type == "port" without pfsp_approved → DENIED
           (ISPS Code Part B §16 Port Facility Security Plan approval).
        4. security_level == 3 without maritime_security_communication → REQUIRES_HUMAN_REVIEW
           (ISPS Code §9.1 Security Level 3 coastal state notification).
        5. Otherwise → PERMITTED.
        """
        facility_type = doc.get("facility_type", "")
        is_port = facility_type == "port"
        security_level = doc.get("security_level", 1)

        # ISPS Code Part A §19.1 — International Ship Security Certificate (ISSC)
        if not doc.get("issc_certificate", False):
            return FilterResult(
                decision="DENIED",
                regulation="ISPS Code Part A §19.1 (ISSC)",
                reason=(
                    "IMO ISPS Code Part A §19.1: Vessel operations described without a valid "
                    "International Ship Security Certificate (ISSC). Every ship required to comply "
                    "with the ISPS Code must hold a valid ISSC issued or verified by the flag "
                    "state Administration under SOLAS Chapter XI-2, confirming that the Ship "
                    "Security Assessment (SSA) has been conducted and that the Ship Security Plan "
                    "(SSP) has been implemented and verified. Operating without a valid ISSC "
                    "constitutes a violation of SOLAS Chapter XI-2 and the ISPS Code."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ISPS Code Part A §9.4 — Ship Security Plan (SSP) Flag State Approval
        if not doc.get("ssp_approved", False):
            return FilterResult(
                decision="DENIED",
                regulation="ISPS Code Part A §9.4 (SSP Approval)",
                reason=(
                    "IMO ISPS Code Part A §9.4: Vessel security operations described with a Ship "
                    "Security Plan (SSP) that has not received flag state Administration approval. "
                    "Every ship subject to the ISPS Code must have an SSP approved by the flag "
                    "state Administration (or a recognized security organization acting on its "
                    "behalf) before the plan is implemented. The SSP must address security threats "
                    "at all three ISPS security levels, including access control, restricted area "
                    "monitoring, and security incident response procedures."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ISPS Code Part B §16 — Port Facility Security Plan (PFSP) Approval
        if is_port and not doc.get("pfsp_approved", False):
            return FilterResult(
                decision="DENIED",
                regulation="ISPS Code Part B §16 (PFSP Approval)",
                reason=(
                    "IMO ISPS Code Part B §16: Port facility operations described without an "
                    "approved Port Facility Security Plan (PFSP). Every port facility that handles "
                    "ships engaged on international voyages must have a PFSP approved by the SOLAS "
                    "contracting government in whose territory the port facility is located, "
                    "following a Port Facility Security Assessment (PFSA). The PFSP must address "
                    "security threats at all three ISPS security levels and include procedures for "
                    "restricted area access, cargo and ship's stores handling, and security "
                    "incident response."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ISPS Code §9.1 — Security Level 3 Maritime Security Communication
        if security_level == 3 and not doc.get("maritime_security_communication", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="ISPS Code §9.1 (Security Level 3)",
                reason=(
                    "IMO ISPS Code §9.1: Security Level 3 declared without confirmation that "
                    "the required maritime security communication has been made to the nearest "
                    "coastal state authority. When Security Level 3 is in force (a specific, "
                    "credible threat of a security incident is probable or imminent), the Ship "
                    "Security Officer is required to inform the relevant authorities and to "
                    "communicate maritime security information as directed. Human review is "
                    "required to verify that the coastal state notification obligation has been "
                    "discharged and that appropriate security response measures are in place."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="ISPS Code (SOLAS Chapter XI-2)",
            reason=(
                "Document satisfies ISPS Code ship and port facility security requirements, "
                "including ISSC certification, SSP flag state approval, PFSP approval, and "
                "security level communication requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 4 — MaritimeCrossBorderFilter
#            Port State Control + OFAC Sanctions + US CBP Advance Notice
#            (Paris/Tokyo MOU; OFAC SDN; 33 CFR §160.212)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MaritimeCrossBorderFilter:
    """Enforces Port State Control, OFAC sanctions, and CBP advance notice requirements.

    Paris/Tokyo MOU: Vessel calling PSC-deficient port without clearance → DENIED.

    OFAC SDN Flag State: Vessel flagged under OFAC-sanctioned flag state → DENIED.

    OFAC Crew Nationality: Crew from OFAC-restricted nationality without
    license → DENIED.

    33 CFR §160.212: Vessel in US waters without CBP 96-hour NOA submitted
    → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "MaritimeCrossBorderFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate Port State Control, OFAC sanctions, and CBP NOA requirements for *doc*.

        Evaluation order
        ----------------
        1. port_name in PSC_DEFICIENT_PORTS without psc_clearance → DENIED
           (Paris/Tokyo MOU Port State Control deficient port).
        2. flag_state in OFAC_SANCTIONED_FLAG_STATES → DENIED
           (OFAC SDN-listed flag state sanctions).
        3. crew_nationality in OFAC_CREW_NATIONALITIES without ofac_license → DENIED
           (OFAC crew nationality restriction requiring license).
        4. us_waters=True without cbp_noa_submitted → REQUIRES_HUMAN_REVIEW
           (33 CFR §160.212 CBP 96-hour advance notice of arrival).
        5. Otherwise → PERMITTED.
        """
        port_name = doc.get("port_name", "")
        flag_state = doc.get("flag_state", "")
        crew_nationality = doc.get("crew_nationality", "")

        # Paris/Tokyo MOU — PSC Deficient Port
        if port_name in PSC_DEFICIENT_PORTS and not doc.get("psc_clearance", False):
            return FilterResult(
                decision="DENIED",
                regulation="Paris/Tokyo MOU Port State Control",
                reason=(
                    f"Paris/Tokyo MOU Port State Control: Vessel call at PSC-deficient port "
                    f"'{port_name}' without prior Port State Control clearance. The Paris MOU "
                    f"and Tokyo MOU Port State Control regimes publish lists of ports with known "
                    f"deficiencies in maritime safety, security, and pollution prevention "
                    f"enforcement. Vessel calls at PSC-deficient ports require advance clearance "
                    f"to mitigate the risk of vessel detention, certificate invalidation, and "
                    f"maritime safety incidents. Proceeding without clearance is denied."
                ),
                filter_name=self.FILTER_NAME,
            )

        # OFAC SDN — Sanctioned Flag State
        if flag_state in OFAC_SANCTIONED_FLAG_STATES:
            return FilterResult(
                decision="DENIED",
                regulation="OFAC SDN (Sanctioned Flag State)",
                reason=(
                    f"OFAC Sanctions: Vessel is flagged under OFAC-designated sanctioned flag "
                    f"state '{flag_state}'. Vessels registered under the Democratic People's "
                    f"Republic of Korea (KP), the Islamic Republic of Iran (IR), the Syrian Arab "
                    f"Republic (SY), or Cuba (CU) are subject to broad OFAC sanctions under the "
                    f"North Korea Sanctions Regulations (31 CFR Part 510), Iran Sanctions (31 CFR "
                    f"Part 560), and related OFAC programs. Providing services to, or processing "
                    f"transactions involving, vessels under sanctioned flag states is prohibited "
                    f"without a specific OFAC license."
                ),
                filter_name=self.FILTER_NAME,
            )

        # OFAC SDN — Crew Nationality Requiring OFAC License
        if crew_nationality in OFAC_CREW_NATIONALITIES and not doc.get("ofac_license", False):
            return FilterResult(
                decision="DENIED",
                regulation="OFAC Crew Nationality Restrictions",
                reason=(
                    f"OFAC Crew Nationality Restrictions: Vessel crew includes nationals of "
                    f"OFAC-restricted country '{crew_nationality}' without a confirmed OFAC "
                    f"license. Crew members who are nationals of North Korea (KP) or Iran (IR) "
                    f"are subject to OFAC sanctions that may restrict payments for wages, "
                    f"crew services, and related transactions. An OFAC specific license or "
                    f"applicable general license must be confirmed before processing transactions "
                    f"involving crew from OFAC-restricted nationalities."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 33 CFR §160.212 — CBP 96-Hour Advance Notice of Arrival (NOA)
        if doc.get("us_waters", False) and not doc.get("cbp_noa_submitted", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="33 CFR §160.212 (CBP 96-Hour NOA)",
                reason=(
                    "US CBP 33 CFR §160.212: Vessel is entering US waters without confirmation "
                    "that the required 96-hour advance notice of arrival (NOA) has been submitted "
                    "to US Customs and Border Protection (CBP). Under 33 CFR §160.212 and the "
                    "Maritime Transportation Security Act (MTSA), vessels arriving in US waters "
                    "must electronically submit an NOA at least 96 hours before entering a US "
                    "port. Failure to submit the required NOA may result in vessel boarding, "
                    "denial of entry, and civil penalties under 33 CFR §160.111. Human review "
                    "is required to verify NOA submission status."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="Paris/Tokyo MOU PSC; OFAC; 33 CFR §160.212",
            reason=(
                "Document satisfies Port State Control, OFAC sanctions screening, and US CBP "
                "advance notice of arrival requirements. Vessel port calls, flag state, crew "
                "nationalities, and US waters entry comply with applicable regulations."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def run_pipeline(doc: dict) -> list[FilterResult]:
    """Run all four maritime IMO compliance filter layers against *doc*.

    Returns a list of FilterResult objects, one per layer evaluated.  The
    pipeline short-circuits on the first DENIED decision; subsequent filters
    are not evaluated for denied documents.
    """
    filters = [
        IMOSafetyFilter(),
        MARPOLFilter(),
        ISPSFilter(),
        MaritimeCrossBorderFilter(),
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
    print("=== Maritime / Shipping IMO Compliance RAG Pipeline — Demo ===\n")

    # --- Vessel without SOLAS certificate ---
    doc_no_solas = {
        "doc_id": "imo-001",
        "vessel_type": "cargo",
        "solas_certificate": False,
    }
    print("Document: Vessel without SOLAS Chapter I Safety Certificate")
    for r in run_pipeline(doc_no_solas):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Vessel without IOPP Certificate ---
    doc_no_iopp = {
        "doc_id": "imo-002",
        "solas_certificate": True,
        "ism_doc_smc": True,
        "iopp_certificate": False,
    }
    print("Document: Vessel without IOPP Certificate")
    for r in run_pipeline(doc_no_iopp):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Vessel without ISSC ---
    doc_no_issc = {
        "doc_id": "imo-003",
        "solas_certificate": True,
        "ism_doc_smc": True,
        "iopp_certificate": True,
        "oil_record_book": True,
        "issc_certificate": False,
    }
    print("Document: Vessel without ISSC")
    for r in run_pipeline(doc_no_issc):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Vessel flagged under OFAC-sanctioned state ---
    doc_sanctioned = {
        "doc_id": "imo-004",
        "solas_certificate": True,
        "ism_doc_smc": True,
        "iopp_certificate": True,
        "oil_record_book": True,
        "issc_certificate": True,
        "ssp_approved": True,
        "flag_state": "KP",
    }
    print("Document: Vessel flagged under OFAC-sanctioned flag state (KP)")
    for r in run_pipeline(doc_sanctioned):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- ISM audit overdue (REQUIRES_HUMAN_REVIEW) ---
    doc_audit_overdue = {
        "doc_id": "imo-005",
        "solas_certificate": True,
        "ism_doc_smc": True,
        "ism_audit_years": 7,
    }
    print("Document: Vessel with ISM audit overdue (7 years)")
    for r in run_pipeline(doc_audit_overdue):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Fully compliant vessel document ---
    doc_compliant = {
        "doc_id": "imo-006",
        # Layer 1 — IMO Safety
        "vessel_type": "cargo",
        "solas_certificate": True,
        "ism_doc_smc": True,
        "lsa_cert": True,
        "ism_audit_years": 2,
        # Layer 2 — MARPOL
        "iopp_certificate": True,
        "oil_record_book": True,
        "vessel_build_year": 2018,
        "in_eca": True,
        "nox_tier3_cert": True,
        "fuel_sulfur_pct": 0.1,
        # Layer 3 — ISPS
        "issc_certificate": True,
        "ssp_approved": True,
        "facility_type": "vessel",
        "pfsp_approved": True,
        "security_level": 1,
        # Layer 4 — Cross-border
        "port_name": "Rotterdam",
        "flag_state": "NO",
        "crew_nationality": "PH",
        "us_waters": True,
        "cbp_noa_submitted": True,
    }
    print("Document: Fully compliant vessel document")
    for r in run_pipeline(doc_compliant):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()
