"""
Defense / Aerospace Export Control RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pre-filter for platforms
that process documents related to defense technology, aerospace systems, dual-use
exports, and cross-border military cooperation.  Four independent filter layers
run sequentially; a document must pass all four to be returned to the caller.

Commercial use cases:

  +------------------------------------------------------------------+-----------------------------------------------+
  | Platform / Product                                               | Applicable Regulation(s)                      |
  +------------------------------------------------------------------+-----------------------------------------------+
  | Defense contractor document management and collaboration         | ITAR 22 CFR Parts 120-130; DSP-5 licensing    |
  | Aerospace manufacturing and technical data repositories          | ITAR USML Categories I–XXI; §120.10           |
  | Dual-use technology licensing and trade compliance systems       | EAR 15 CFR Parts 730-774; ECCN/CCL            |
  | AI/ML-powered export screening and end-use verification          | EAR §744.21 Military End Use; BIS Entity List |
  | Semiconductor and advanced computing compliance platforms        | BIS Oct 2023 semiconductor rule; §734.9 FDPR  |
  | Defense M&A and investment screening systems                     | CFIUS 50 U.S.C. §4565; 31 CFR Part 800       |
  | TID US Business transaction management platforms                 | FIRRMA §800.248 TID; §800.212 covered txns   |
  | NATO/Five Eyes classified information sharing platforms          | NATO MC 0049/15; UKUSA Agreement FVEY        |
  | Defense industrial base data protection systems                  | NSPM-33 Research Security; EO 13873          |
  | Joint military technology development and foreign disclosure     | DoD Directive 5230.11                        |
  +------------------------------------------------------------------+-----------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — ITARFilter
      (International Traffic in Arms Regulations — 22 CFR Parts 120-130;
       administered by the U.S. Department of State Directorate of Defense
       Trade Controls (DDTC))
      Controls access to documents containing USML-listed technical data,
      defense services, controlled electronic transmissions to foreign
      nationals, and classified defense data, enforcing license requirements,
      exemption analysis, and clearance-level verification.

      22 CFR §120.6 USML + §120.10 Technical Data: USML-listed technical
      data (defense articles in USML Categories I–VIII: firearms, artillery,
      ammunition, warships, tanks/military vehicles, aircraft/spacecraft)
      transmitted without a valid export license constitutes an unauthorized
      export.  Documents containing USML-listed technical data without an
      export license are denied.

      22 CFR §120.9 Defense Services + §123.1 Export License: Defense
      services — assisting a foreign person in the design, development,
      engineering, manufacture, or operation of defense articles — require
      a DSP-5 export license when provided to foreign persons.  Documents
      describing defense services to foreign persons without DSP-5
      authorization are denied.

      22 CFR §125.4 Exemptions Analysis: Controlled technical data in
      electronic transmission to foreign nationals must qualify for a
      recognized ITAR exemption (e.g., §125.4(b)(1) U.S. government
      information, §125.4(b)(9) educational exemption) to be transmitted
      without a license.  Documents transmitting controlled technical data
      electronically to foreign nationals without a valid exemption are
      denied.

      22 CFR §120.11 Classified Information + DoD 5220.22-M: Classified
      defense data must carry proper DoD security classification markings
      consistent with DoD 5220.22-M (National Industrial Security Program
      Operating Manual — NISPOM).  Documents containing classified defense
      data without proper clearance-level markings are escalated to
      REQUIRES_HUMAN_REVIEW.

  Layer 2 — EARFilter
      (Export Administration Regulations — 15 CFR Parts 730-774;
       administered by the U.S. Department of Commerce Bureau of Industry
       and Security (BIS))
      Controls access to documents involving Commerce Control List items
      destined for military end use in controlled countries, exports to
      Entity List entities, advanced computing / semiconductor-related
      exports subject to the October 2023 BIS rule, and items subject to
      the Foreign Direct Product Rule applicable to Huawei affiliates.

      15 CFR §744.21 Military End Use (MEU) Controls: Items on the
      Commerce Control List (CCL) with an Export Control Classification
      Number (ECCN) that require a BIS license for military end use in
      designated countries (China/CN, Russia/RU, Venezuela/VE, Myanmar/MM,
      Belarus/BY) may not be exported without BIS license authorization.
      Documents describing such items to MEU countries without a BIS
      license are denied.

      15 CFR §744.11 Entity List: Items subject to the EAR may not be
      exported, reexported, or transferred to entities on the BIS Entity
      List without a specific BIS authorization.  Documents involving
      Entity List entities in dual-use technology transfers without BIS
      authorization are denied.

      BIS October 2023 Advanced Computing / Semiconductor Export Controls
      (15 CFR §744.23): Items subject to the EAR that fall within the
      October 2023 BIS advanced computing and semiconductor manufacturing
      export controls may not be exported to China or Russia or North Korea
      without a BIS license.  Documents describing covered semiconductor
      exports to CN/RU/KP without a license are denied.

      15 CFR §734.9 Foreign Direct Product Rule (FDPR) — Huawei: Items
      produced abroad using U.S. technology or software subject to the FDPR
      applicable to Huawei Technologies and its affiliates (the Huawei
      Entity List FDPR) require compliance review before transfer.
      Documents involving items subject to the Huawei FDPR are escalated to
      REQUIRES_HUMAN_REVIEW.

  Layer 3 — CFIUSDefenseFilter
      (Committee on Foreign Investment in the United States — CFIUS;
       authority under FIRRMA 50 U.S.C. §4565; regulations at 31 CFR
       Part 800, administered by the U.S. Treasury Department)
      Controls access to documents involving acquisition of U.S. defense
      contractors by foreign entities, TID US Business transactions with
      covered foreign persons, foreign access to sensitive government
      contract data, and mandatory declaration obligations for minority
      investments in TID US Businesses.

      50 U.S.C. §4565 + 31 CFR Part 800 — Acquisition of Defense
      Contractor: Foreign acquisition of a U.S. business that provides
      products or services to the U.S. military or intelligence community
      requires a CFIUS filing.  Documents describing such acquisitions
      without a CFIUS filing or clearance are denied.

      31 CFR §800.248 TID + §800.212 Covered Transaction — TID US
      Business: Transactions involving TID US Businesses (businesses that
      produce, design, test, manufacture, or develop Critical Technology,
      Critical Infrastructure, or Sensitive Personal Data) with covered
      foreign persons from CN/RU/KP require CFIUS clearance.  Documents
      describing such covered transactions without CFIUS clearance are
      denied.

      FIRRMA Pilot Program + §800.215 Control — Sensitive Government
      Contract Data: Access by a foreign entity to sensitive U.S. government
      contract data (including classified contracts and those involving
      critical technology) without CFIUS clearance constitutes a covered
      control transaction.  Documents granting such access without CFIUS
      clearance are denied.

      31 CFR §800.401 Mandatory Declarations — Minority Investment in TID:
      Minority investments in TID US Businesses by covered foreign persons
      from CN/RU/KP may trigger mandatory CFIUS declaration obligations.
      Documents describing such investments without a CFIUS declaration are
      escalated to REQUIRES_HUMAN_REVIEW.

  Layer 4 — DefenseCrossBorderFilter
      (NATO Security Policy MC 0049/15; UKUSA Agreement / Five Eyes (FVEY)
       sharing protocols; NSPM-33 Research Security; Executive Order 13873;
       DoD Directive 5230.11 Disclosure of Classified Military Information
       to Foreign Governments and International Organizations)
      Controls access to documents involving NATO-classified information
      sharing, Five Eyes intelligence data, defense industrial base data
      transfers to adversarial nations, and joint military technology
      development with non-treaty nations.

      NATO Security Policy MC 0049/15 — NATO Classified Information:
      NATO-classified information (NATO CONFIDENTIAL and above) may only be
      shared with entities holding NATO security clearance and need-to-know
      under MC 0049/15 Security Within the North Atlantic Treaty
      Organisation.  Documents containing NATO-classified information shared
      without NATO clearance and need-to-know are denied.

      UKUSA Agreement / FVEY Sharing Protocols — Five Eyes Intelligence:
      Intelligence data originating from Five Eyes (FVEY) partners (US, UK,
      CA, AU, NZ) may only be shared within FVEY member states absent a
      specific bilateral intelligence sharing agreement.  Documents sharing
      FVEY intelligence data with non-FVEY partners without a bilateral
      agreement are denied.

      NSPM-33 Research Security + EO 13873 — Defense Industrial Base Data
      to Adversarial Nations: Defense industrial base data — including
      technology and research with military applications — may not be
      transferred to adversarial nations (CN/RU/KP/IR/CU/SY) under
      National Security Presidential Memorandum 33 research security
      requirements and Executive Order 13873 supply-chain security
      controls.  Documents transmitting defense industrial base data to
      adversarial nations are denied.

      DoD Directive 5230.11 — Foreign Disclosure of Classified Military
      Information: Disclosure of classified military information to foreign
      governments or international organizations requires approval through
      the DoD foreign disclosure framework under DoDD 5230.11.  Documents
      describing joint military technology development with non-treaty
      nations without DoD foreign disclosure approval are escalated to
      REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Nations subject to EAR §744.21 Military End Use controls.
MEU_COUNTRIES: frozenset[str] = frozenset({"CN", "RU", "VE", "MM", "BY"})

#: Nations subject to the BIS October 2023 advanced computing / semiconductor
#: export controls (15 CFR §744.23).
SEMICONDUCTOR_CONTROL_COUNTRIES: frozenset[str] = frozenset({"CN", "RU", "KP"})

#: Nations treated as covered foreign persons for CFIUS TID US Business
#: mandatory declarations and covered transaction review (CN/RU/KP).
CFIUS_COVERED_NATIONS: frozenset[str] = frozenset({"CN", "RU", "KP"})

#: Nations treated as adversarial for defense industrial base data transfers
#: under NSPM-33 and EO 13873.
DEFENSE_ADVERSARIAL_NATIONS: frozenset[str] = frozenset({"CN", "RU", "KP", "IR", "CU", "SY"})

#: Five Eyes (FVEY) member nation codes eligible to receive FVEY intelligence
#: data under the UKUSA Agreement without an additional bilateral agreement.
FVEY_MEMBERS: frozenset[str] = frozenset({"US", "GB", "CA", "AU", "NZ"})


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document.

    Fields
    ------
    decision     : "PERMITTED", "DENIED", "REQUIRES_HUMAN_REVIEW", or "REDACTED"
    regulation   : Short citation string (e.g. "22 CFR §120.6 USML")
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
# Layer 1 — ITARFilter
#            International Traffic in Arms Regulations (22 CFR Parts 120-130)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ITARFilter:
    """Enforces ITAR export controls for defense-related technical data.

    22 CFR §120.6 USML + §120.10 Technical Data: USML-listed technical data
    (Categories I–VIII: firearms, artillery, ammunition, warships, tanks/
    military vehicles, aircraft/spacecraft) without export license → DENIED.

    22 CFR §120.9 Defense Services + §123.1 Export License: Defense services
    provided to foreign persons without DSP-5 authorization → DENIED.

    22 CFR §125.4 Exemptions Analysis: Controlled technical data in electronic
    transmission to foreign nationals without a valid exemption → DENIED.

    22 CFR §120.11 Classified Information + DoD 5220.22-M: Classified defense
    data without proper clearance-level markings → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "ITARFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate ITAR export controls for *doc*.

        Evaluation order
        ----------------
        1. USML-listed technical data without export license → DENIED
           (22 CFR §120.6 USML + §120.10 technical data).
        2. Defense services to foreign persons without DSP-5 authorization →
           DENIED (22 CFR §120.9 defense services + §123.1 export license).
        3. Controlled technical data in electronic transmission to foreign
           nationals without valid exemption → DENIED
           (22 CFR §125.4 exemptions analysis).
        4. Classified defense data without proper clearance-level marking →
           REQUIRES_HUMAN_REVIEW
           (22 CFR §120.11 + DoD 5220.22-M NISPOM).
        5. Otherwise → PERMITTED.
        """
        is_usml_technical_data = doc.get("is_usml_technical_data", False)
        is_defense_service_to_foreign = doc.get("is_defense_service_to_foreign_person", False)
        is_controlled_electronic_transmission = doc.get("is_controlled_electronic_transmission", False)
        is_classified_defense_data = doc.get("is_classified_defense_data", False)

        # 22 CFR §120.6 USML + §120.10 Technical Data
        if is_usml_technical_data and not doc.get("itar_export_license", False):
            return FilterResult(
                decision="DENIED",
                regulation="22 CFR §120.6 USML + §120.10",
                reason=(
                    "ITAR 22 CFR §120.6 / §120.10: USML-listed technical data transmitted "
                    "without a valid ITAR export license. Defense articles listed in USML "
                    "Categories I (firearms), II (artillery), III (ammunition), VI (warships), "
                    "VII (tanks/military vehicles), and VIII (aircraft/spacecraft) require "
                    "State Department DDTC export license authorization prior to transmission "
                    "to foreign persons or outside the United States."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 22 CFR §120.9 Defense Services + §123.1 Export License
        if is_defense_service_to_foreign and not doc.get("dsp5_authorization", False):
            return FilterResult(
                decision="DENIED",
                regulation="22 CFR §120.9 + §123.1 DSP-5",
                reason=(
                    "ITAR 22 CFR §120.9 / §123.1: Defense services provided to foreign persons "
                    "without DSP-5 export license authorization. Defense services — including "
                    "assisting a foreign person in the design, development, engineering, "
                    "manufacture, production, assembly, testing, repair, maintenance, or "
                    "operation of a defense article — require a DDTC DSP-5 license."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 22 CFR §125.4 Exemptions Analysis
        if is_controlled_electronic_transmission and not doc.get("itar_exemption_applies", False):
            return FilterResult(
                decision="DENIED",
                regulation="22 CFR §125.4",
                reason=(
                    "ITAR 22 CFR §125.4: Controlled technical data in electronic transmission "
                    "to foreign nationals does not qualify for a recognized ITAR exemption. "
                    "Exemptions under §125.4 (e.g., §125.4(b)(1) U.S. government information, "
                    "§125.4(b)(9) educational exemption) do not apply to this transmission; "
                    "a DDTC export license is required."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 22 CFR §120.11 Classified Information + DoD 5220.22-M
        if is_classified_defense_data and not doc.get("proper_classification_markings", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="22 CFR §120.11 + DoD 5220.22-M NISPOM",
                reason=(
                    "ITAR 22 CFR §120.11 / DoD 5220.22-M: Classified defense data detected "
                    "without proper DoD security classification markings. The National "
                    "Industrial Security Program Operating Manual (NISPOM) requires that "
                    "classified defense information carry accurate classification markings "
                    "and be handled in accordance with the applicable security clearance level."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="ITAR 22 CFR Parts 120-130",
            reason=(
                "Document satisfies ITAR export control requirements under "
                "22 CFR Parts 120-130 for defense technical data and services."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 2 — EARFilter
#            Export Administration Regulations (15 CFR Parts 730-774)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EARFilter:
    """Enforces EAR dual-use export controls and BIS license requirements.

    15 CFR §744.21 Military End Use (MEU): CCL items requiring license for
    MEU in CN/RU/VE/MM/BY without BIS license → DENIED.

    15 CFR §744.11 Entity List: Dual-use technology to Entity List entity
    without BIS authorization → DENIED.

    BIS Oct 2023 §744.23 Semiconductor Controls: Covered semiconductor/
    advanced computing exports to CN/RU/KP without license → DENIED.

    15 CFR §734.9 FDPR — Huawei: Items subject to Huawei FDPR without
    compliance review → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "EARFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate EAR dual-use export controls for *doc*.

        Evaluation order
        ----------------
        1. CCL item requiring MEU license to CN/RU/VE/MM/BY without BIS
           license → DENIED (15 CFR §744.21 Military End Use).
        2. Dual-use technology to Entity List entity without BIS
           authorization → DENIED (15 CFR §744.11 Entity List).
        3. Covered semiconductor/advanced computing export to CN/RU/KP
           without license → DENIED (BIS Oct 2023 §744.23).
        4. Item subject to Huawei FDPR without compliance review →
           REQUIRES_HUMAN_REVIEW (15 CFR §734.9 FDPR).
        5. Otherwise → PERMITTED.
        """
        destination = doc.get("destination_country", "")
        is_ccl_meu_item = doc.get("is_ccl_military_end_use_item", False)
        is_entity_list_recipient = doc.get("is_entity_list_recipient", False)
        is_semiconductor_item = doc.get("is_advanced_computing_semiconductor_item", False)
        is_huawei_fdpr_subject = doc.get("is_huawei_fdpr_subject", False)

        # 15 CFR §744.21 Military End Use
        if is_ccl_meu_item and destination in MEU_COUNTRIES and not doc.get("bis_meu_license", False):
            return FilterResult(
                decision="DENIED",
                regulation="15 CFR §744.21 Military End Use",
                reason=(
                    f"EAR 15 CFR §744.21: CCL item requiring military end-use license destined "
                    f"for '{destination}' (Military End Use country) without BIS license "
                    f"authorization. EAR §744.21 prohibits export, reexport, or transfer of "
                    f"items subject to the EAR for military end use in China (CN), Russia (RU), "
                    f"Venezuela (VE), Myanmar (MM), or Belarus (BY) without a BIS license."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 15 CFR §744.11 Entity List
        if is_entity_list_recipient and not doc.get("bis_entity_list_authorization", False):
            return FilterResult(
                decision="DENIED",
                regulation="15 CFR §744.11 Entity List",
                reason=(
                    "EAR 15 CFR §744.11: Dual-use technology export to an entity on the BIS "
                    "Entity List without specific BIS authorization. The Entity List identifies "
                    "foreign parties that are prohibited from receiving items subject to the EAR "
                    "without a BIS license; a license exception does not apply."
                ),
                filter_name=self.FILTER_NAME,
            )

        # BIS Oct 2023 §744.23 Advanced Computing / Semiconductor Controls
        if is_semiconductor_item and destination in SEMICONDUCTOR_CONTROL_COUNTRIES and not doc.get(
            "bis_semiconductor_license", False
        ):
            return FilterResult(
                decision="DENIED",
                regulation="15 CFR §744.23 (BIS Oct 2023 Semiconductor Rule)",
                reason=(
                    f"EAR 15 CFR §744.23: Covered advanced computing or semiconductor "
                    f"manufacturing item destined for '{destination}' without BIS license. "
                    f"The October 2023 BIS semiconductor export controls restrict export of "
                    f"advanced computing items, semiconductor manufacturing equipment, and "
                    f"related technology to China (CN), Russia (RU), and North Korea (KP) "
                    f"without Bureau of Industry and Security license authorization."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 15 CFR §734.9 FDPR — Huawei
        if is_huawei_fdpr_subject and not doc.get("huawei_fdpr_compliance_reviewed", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="15 CFR §734.9 FDPR (Huawei)",
                reason=(
                    "EAR 15 CFR §734.9 FDPR: Item subject to the Foreign Direct Product Rule "
                    "applicable to Huawei Technologies and its affiliates has not undergone "
                    "FDPR compliance review. The Huawei Entity List FDPR extends U.S. export "
                    "control jurisdiction to foreign-produced items that are a direct product "
                    "of U.S.-origin technology or software listed on the Commerce Control List."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="EAR 15 CFR Parts 730-774",
            reason=(
                "Document satisfies EAR dual-use export control requirements under "
                "15 CFR Parts 730-774 including CCL, Entity List, and semiconductor controls."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 3 — CFIUSDefenseFilter
#            CFIUS National Security Review for Defense-Related Transactions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CFIUSDefenseFilter:
    """Enforces CFIUS national security review for defense-related transactions.

    50 U.S.C. §4565 + 31 CFR Part 800: Acquisition of U.S. defense contractor
    by foreign entity without CFIUS filing → DENIED.

    31 CFR §800.248 TID + §800.212 Covered Transaction: TID US Business
    transaction with CN/RU/KP covered entity without CFIUS clearance → DENIED.

    FIRRMA Pilot Program + §800.215 Control: Access to sensitive U.S.
    government contract data by foreign entity without CFIUS clearance → DENIED.

    31 CFR §800.401 Mandatory Declarations: Minority investment in TID US
    Business by covered foreign person without CFIUS declaration →
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "CFIUSDefenseFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate CFIUS national security controls for *doc*.

        Evaluation order
        ----------------
        1. Acquisition of U.S. defense contractor by foreign entity without
           CFIUS filing → DENIED (50 U.S.C. §4565 + 31 CFR Part 800).
        2. TID US Business transaction with CN/RU/KP covered entity without
           CFIUS clearance → DENIED (31 CFR §800.248 TID + §800.212).
        3. Access to sensitive U.S. government contract data by foreign
           entity without CFIUS clearance → DENIED
           (FIRRMA Pilot Program + §800.215 Control).
        4. Minority investment in TID US Business by covered foreign person
           without CFIUS declaration → REQUIRES_HUMAN_REVIEW
           (31 CFR §800.401 Mandatory Declarations).
        5. Otherwise → PERMITTED.
        """
        investor_country = doc.get("investor_country", "")
        is_defense_contractor_acquisition = doc.get("is_defense_contractor_acquisition", False)
        is_tid_us_business_transaction = doc.get("is_tid_us_business_transaction", False)
        is_sensitive_gov_contract_access = doc.get("is_sensitive_gov_contract_data_access", False)
        is_tid_minority_investment = doc.get("is_tid_minority_investment", False)

        # 50 U.S.C. §4565 + 31 CFR Part 800 — Defense Contractor Acquisition
        if is_defense_contractor_acquisition and not doc.get("cfius_filing_complete", False):
            return FilterResult(
                decision="DENIED",
                regulation="50 U.S.C. §4565 + 31 CFR Part 800",
                reason=(
                    "CFIUS 50 U.S.C. §4565 / 31 CFR Part 800: Acquisition of a U.S. defense "
                    "contractor by a foreign entity without a completed CFIUS filing. Foreign "
                    "acquisitions of businesses providing products or services to the U.S. "
                    "military or intelligence community require CFIUS national security review "
                    "and clearance before the transaction can proceed."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 31 CFR §800.248 TID + §800.212 Covered Transaction
        if (
            is_tid_us_business_transaction
            and investor_country in CFIUS_COVERED_NATIONS
            and not doc.get("cfius_tid_clearance", False)
        ):
            return FilterResult(
                decision="DENIED",
                regulation="31 CFR §800.248 TID + §800.212",
                reason=(
                    f"CFIUS 31 CFR §800.248 / §800.212: TID US Business transaction with "
                    f"covered foreign person from '{investor_country}' (CN/RU/KP) without "
                    f"CFIUS clearance. Transactions involving TID US Businesses — those that "
                    f"produce, design, test, manufacture, fabricate, or develop items or "
                    f"services in Critical Technology, Critical Infrastructure, or Sensitive "
                    f"Personal Data — with covered foreign persons require CFIUS clearance "
                    f"under FIRRMA."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FIRRMA Pilot Program + §800.215 Control — Sensitive Gov Contract Data
        if is_sensitive_gov_contract_access and not doc.get("cfius_gov_contract_clearance", False):
            return FilterResult(
                decision="DENIED",
                regulation="FIRRMA Pilot Program + 31 CFR §800.215",
                reason=(
                    "CFIUS FIRRMA / 31 CFR §800.215: Foreign entity access to sensitive U.S. "
                    "government contract data without CFIUS clearance. Access by a foreign "
                    "entity to classified government contracts or contracts involving critical "
                    "technology constitutes a covered transaction under the FIRRMA Pilot "
                    "Program and requires CFIUS national security clearance."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 31 CFR §800.401 Mandatory Declarations — Minority Investment in TID
        if (
            is_tid_minority_investment
            and investor_country in CFIUS_COVERED_NATIONS
            and not doc.get("cfius_mandatory_declaration_filed", False)
        ):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="31 CFR §800.401 Mandatory Declarations",
                reason=(
                    f"CFIUS 31 CFR §800.401: Minority investment in TID US Business by covered "
                    f"foreign person from '{investor_country}' (CN/RU/KP) without a mandatory "
                    f"CFIUS declaration. FIRRMA requires mandatory declarations for certain "
                    f"minority investments by covered foreign persons in TID US Businesses; "
                    f"failure to file triggers civil monetary penalties."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="CFIUS 50 U.S.C. §4565; 31 CFR Part 800",
            reason=(
                "Document satisfies CFIUS national security review requirements under "
                "50 U.S.C. §4565 and 31 CFR Part 800 for defense-related transactions."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 4 — DefenseCrossBorderFilter
#            Defense Technology Cross-Border Data and Cooperation Controls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DefenseCrossBorderFilter:
    """Enforces defense technology cross-border data and cooperation controls.

    NATO Security Policy MC 0049/15: NATO-classified information without NATO
    clearance and need-to-know → DENIED.

    UKUSA Agreement / FVEY Protocols: FVEY intelligence data to non-FVEY
    partner without bilateral agreement → DENIED.

    NSPM-33 + EO 13873: Defense industrial base data to adversarial nations
    (CN/RU/KP/IR/CU/SY) → DENIED.

    DoD Directive 5230.11: Joint military technology development with non-
    treaty nation without DoD foreign disclosure approval →
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "DefenseCrossBorderFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate defense cross-border data and cooperation controls for *doc*.

        Evaluation order
        ----------------
        1. NATO-classified information without NATO clearance and need-to-know
           → DENIED (NATO Security Policy MC 0049/15).
        2. FVEY intelligence data to non-FVEY partner without bilateral
           agreement → DENIED (UKUSA Agreement + FVEY protocols).
        3. Defense industrial base data to adversarial nation
           (CN/RU/KP/IR/CU/SY) → DENIED (NSPM-33 + EO 13873).
        4. Joint military technology development with non-treaty nation
           without DoD foreign disclosure approval → REQUIRES_HUMAN_REVIEW
           (DoD Directive 5230.11).
        5. Otherwise → PERMITTED.
        """
        recipient_country = doc.get("recipient_country", "")
        is_nato_classified = doc.get("is_nato_classified_information", False)
        is_fvey_intelligence = doc.get("is_fvey_intelligence_data", False)
        is_defense_industrial_base_data = doc.get("is_defense_industrial_base_data", False)
        is_joint_military_tech_dev = doc.get("is_joint_military_technology_development", False)

        # NATO Security Policy MC 0049/15
        if is_nato_classified and not doc.get("nato_clearance_and_need_to_know", False):
            return FilterResult(
                decision="DENIED",
                regulation="NATO Security Policy MC 0049/15",
                reason=(
                    "NATO MC 0049/15: NATO-classified information shared without NATO security "
                    "clearance and need-to-know verification. NATO Security Policy MC 0049/15 "
                    "requires that NATO CONFIDENTIAL and above information be shared only with "
                    "personnel holding the appropriate NATO security clearance and a verified "
                    "need-to-know within the NATO security framework."
                ),
                filter_name=self.FILTER_NAME,
            )

        # UKUSA Agreement / FVEY Protocols
        if is_fvey_intelligence and recipient_country not in FVEY_MEMBERS and not doc.get(
            "bilateral_intelligence_agreement", False
        ):
            return FilterResult(
                decision="DENIED",
                regulation="UKUSA Agreement / FVEY Sharing Protocols",
                reason=(
                    f"UKUSA Agreement / FVEY: Five Eyes intelligence data shared with "
                    f"non-FVEY partner '{recipient_country}' without a bilateral intelligence "
                    f"sharing agreement. FVEY intelligence data (US/UK/CA/AU/NZ) may only be "
                    f"shared with non-FVEY nations under a specific bilateral agreement that "
                    f"establishes appropriate security standards and handling requirements."
                ),
                filter_name=self.FILTER_NAME,
            )

        # NSPM-33 Research Security + EO 13873
        if is_defense_industrial_base_data and recipient_country in DEFENSE_ADVERSARIAL_NATIONS:
            return FilterResult(
                decision="DENIED",
                regulation="NSPM-33 Research Security + EO 13873",
                reason=(
                    f"NSPM-33 / EO 13873: Defense industrial base data transmitted to "
                    f"adversarial nation '{recipient_country}'. National Security Presidential "
                    f"Memorandum 33 research security requirements and Executive Order 13873 "
                    f"supply-chain security controls prohibit transfer of defense industrial "
                    f"base data — including technology and research with military applications "
                    f"— to adversarial nations: CN, RU, KP, IR, CU, and SY."
                ),
                filter_name=self.FILTER_NAME,
            )

        # DoD Directive 5230.11 — Foreign Disclosure of Classified Military Info
        if is_joint_military_tech_dev and not doc.get("dod_foreign_disclosure_approval", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="DoD Directive 5230.11",
                reason=(
                    "DoD Directive 5230.11: Joint military technology development with a "
                    "non-treaty nation without DoD foreign disclosure approval. DoDD 5230.11 "
                    "requires that disclosure of classified military information to foreign "
                    "governments and international organizations be approved through the DoD "
                    "foreign disclosure framework prior to any release or collaborative "
                    "development activity."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="NATO MC 0049/15; UKUSA/FVEY; NSPM-33; DoDD 5230.11",
            reason=(
                "Document satisfies defense cross-border data transfer and cooperation "
                "controls under NATO, FVEY, NSPM-33, and DoD foreign disclosure requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def run_pipeline(doc: dict) -> list[FilterResult]:
    """Run all four defense / export control filter layers against *doc*.

    Returns a list of FilterResult objects, one per layer evaluated.  The
    pipeline short-circuits on the first DENIED decision; subsequent filters
    are not evaluated for denied documents.
    """
    filters = [
        ITARFilter(),
        EARFilter(),
        CFIUSDefenseFilter(),
        DefenseCrossBorderFilter(),
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
    print("=== Defense / Aerospace Export Control RAG Pipeline — Demo ===\n")

    # --- USML technical data without export license ---
    doc_usml_no_license = {
        "doc_id": "itar-001",
        "is_usml_technical_data": True,
        "itar_export_license": False,
    }
    print("Document: USML-listed technical data without ITAR export license")
    for r in run_pipeline(doc_usml_no_license):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- CCL item destined for China (MEU country) without BIS license ---
    doc_meu_china = {
        "doc_id": "ear-002",
        "is_ccl_military_end_use_item": True,
        "destination_country": "CN",
        "bis_meu_license": False,
    }
    print("Document: CCL military end-use item destined for China without BIS license")
    for r in run_pipeline(doc_meu_china):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Defense contractor acquisition by foreign entity without CFIUS ---
    doc_cfius_no_filing = {
        "doc_id": "cfius-003",
        "is_defense_contractor_acquisition": True,
        "cfius_filing_complete": False,
    }
    print("Document: Defense contractor acquisition without CFIUS filing")
    for r in run_pipeline(doc_cfius_no_filing):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Defense industrial base data to Russia ---
    doc_russia_dib = {
        "doc_id": "cross-004",
        "is_defense_industrial_base_data": True,
        "recipient_country": "RU",
    }
    print("Document: Defense industrial base data to Russia (adversarial nation)")
    for r in run_pipeline(doc_russia_dib):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Classified defense data without proper markings (REQUIRES_HUMAN_REVIEW) ---
    doc_classified_no_markings = {
        "doc_id": "itar-005",
        "is_classified_defense_data": True,
        "proper_classification_markings": False,
    }
    print("Document: Classified defense data without proper NISPOM markings")
    for r in run_pipeline(doc_classified_no_markings):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Fully compliant defense document ---
    doc_compliant = {
        "doc_id": "compliant-006",
        # Layer 1 — ITAR
        "is_usml_technical_data": True,
        "itar_export_license": True,
        "is_defense_service_to_foreign_person": True,
        "dsp5_authorization": True,
        "is_controlled_electronic_transmission": True,
        "itar_exemption_applies": True,
        "is_classified_defense_data": True,
        "proper_classification_markings": True,
        # Layer 2 — EAR
        "is_ccl_military_end_use_item": True,
        "destination_country": "GB",
        "bis_meu_license": True,
        "is_entity_list_recipient": False,
        "is_advanced_computing_semiconductor_item": False,
        "is_huawei_fdpr_subject": False,
        # Layer 3 — CFIUS
        "is_defense_contractor_acquisition": False,
        "is_tid_us_business_transaction": False,
        "is_sensitive_gov_contract_data_access": False,
        "is_tid_minority_investment": False,
        # Layer 4 — Cross-border
        "is_nato_classified_information": False,
        "is_fvey_intelligence_data": False,
        "is_defense_industrial_base_data": False,
        "is_joint_military_technology_development": False,
    }
    print("Document: Fully compliant defense document")
    for r in run_pipeline(doc_compliant):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()
    print("Demo complete.")
